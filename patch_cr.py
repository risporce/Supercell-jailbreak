import struct
from macholib.MachO import MachO

imports_dest = 0

def patch_all_pointers(all_ptr_addrs, file_handle):
	sorted_addrs = sorted(all_ptr_addrs)
	for idx, addr in enumerate(sorted_addrs):
		file_handle.seek(addr)

		if idx < len(sorted_addrs) - 1:
			next_offset = (sorted_addrs[idx + 1] - addr) // 4
		else:
			next_offset = 0  # End of chain

		# Read existing pointer
		raw_data = file_handle.read(8)
		ptr_value = int.from_bytes(raw_data, 'little')

		bind = (ptr_value >> 63) & 0x1
		reserved = (ptr_value >> 32) & 0x7FFFF
		addend = (ptr_value >> 24) & 0xFF
		ordinal = ptr_value & 0xFFFFFF

		updated_ptr_str = f"{bind:01b}{next_offset:012b}{reserved:019b}{addend:08b}{ordinal:024b}"
		updated_ptr_value = int(updated_ptr_str, 2)

		file_handle.seek(addr)
		file_handle.write(struct.pack("<Q", updated_ptr_value))


def parse_or_patch_chained_starts_in_segment(f, fixups_base, starts_offset, segment_offset, new_page_starts=0):
	base_address = fixups_base + starts_offset + segment_offset
	header_fmt = "<IHHQIH"
	header_size = struct.calcsize(header_fmt)
	
	f.seek(base_address)
	header_data = f.read(header_size)

	size, page_size, pointer_format, segment_vm_offset, max_valid_pointer, page_count = struct.unpack(header_fmt, header_data)

	page_start_fmt = f"<{page_count}H"
	page_start_size = struct.calcsize(page_start_fmt)

	f.seek(base_address + header_size)
	page_start_data = f.read(page_start_size)

	page_starts = struct.unpack(page_start_fmt, page_start_data)


	if new_page_starts:
		print(f"Old page_starts: {page_starts}")
		page_starts = new_page_starts
		print(f"Overriding with {page_starts}")
		f.seek(base_address + header_size)
		page_start_data = struct.pack(page_start_fmt, *page_starts)
		f.write(page_start_data)
		print(f"Overwrote page_starts @ {hex(base_address + header_size)} with {page_starts}")


	return {
		"size": size,
		"page_size": page_size,
		"pointer_format": pointer_format,
		"segment_vm_offset": segment_vm_offset,
		"max_valid_pointer": max_valid_pointer,
		"page_count": page_count,
		"page_starts": page_starts
	}

def parse_chained_starts_in_image(f, fixups_base, starts_offset):
	base_address = fixups_base + starts_offset
	f.seek(base_address)
	seg_count_data = f.read(4)
	seg_count = struct.unpack("<I", seg_count_data)[0]
	f.seek(base_address + 4)
	seg_info_offsets_data = f.read(seg_count * 4)
	seg_info_offsets = struct.unpack(f"<{seg_count}I", seg_info_offsets_data)
	segments = []
	for i, offset in enumerate(seg_info_offsets):
		segments.append(offset)
	return {
		"seg_count": seg_count,
		"seg_info_offsets": segments
	}

def parse_chained_pointers_in_segment(f, fixups_base, segment_info, segment_file_offset, header):
	pointers = {}
	page_start = segment_info["page_starts"][0] 	#We want to use the 0th page in the GOT segment here.

	pointer_offset = segment_file_offset + page_start
	
	print(f"\nParsing pointers in page 0, starting at file offset: {hex(pointer_offset)}")
	
	while True:
		f.seek(pointer_offset)
		data = f.read(8)
		
		if len(data) != 8:
			print("Unexpected EOF or read error at offset", hex(pointer_offset))
			break

		ptr_value = struct.unpack("<Q", data)[0]
		ptr_str = format(ptr_value, '064b')
		
		bind = ptr_str[0]
		next_offset = int(ptr_str[1:13], 2)
		if bind == '0':
			"""
			struct dyld_chained_ptr_64_rebase
			{
				uint64_t    target    : 36,
				uint64_t	high8     :  8,
				uint64_t	reserved  :  7,
				uint64_t	next      : 12,
				uint64_t	bind      :  1;
			};
			"""
			ptr_type = "Rebase"
			reserved = ptr_str[13:20]
			high8 = ptr_str[20:28]
			target = ptr_str[28:]
		else:
			""""
			struct dyld_chained_ptr_64_bind {
				uint64_t ordinal : 24;
				uint64_t addend : 8; 
				uint64_t reserved : 19;
				uint64_t next : 12;
				uint64_t bind : 1; 
			};
			"""
			ptr_type = "Bind"
			reserved = ptr_str[13:32]
			addend = ptr_str[32:40]
			ordinal = ptr_str[40:]
			import_addr = header['imports_offset'] + fixups_base + (int(ordinal, 2)*4)
			f.seek(import_addr)
			import_data = f.read(4)
			"""
			struct dyld_chained_import
			{
				uint32_t    lib_ordinal :  8,
							weak_import :  1,
							name_offset : 23;
			};
			"""
		pointers[pointer_offset]={
			"type": ptr_type,
			"bind": bind,
			"next_offset": next_offset,
			"reserved": reserved,
			"high8": high8 if bind == '0' else None,
			"target": target if bind == '0' else None,
			"addend": addend if bind == '1' else None,
			"ordinal": ordinal if bind == '1' else None
		}
		if next_offset == 0:
			break  # Last pointer in this chain
		else:
			pointer_offset += next_offset * 4

	return pointers

def find_next_offset(got_addr, chained_ptr_old_addrs, bi_addrs):
	candidates = [addr for addr in chained_ptr_old_addrs if addr > got_addr] + \
				 [addr for addr in bi_addrs if addr > got_addr]

	if not candidates:
		return 0

	closest = min(candidates)
	return closest - got_addr


def main_patching(symbol_end_addr, header, fixups_base, imports_table, chained_ptrs):
	global imports_dest
	import_table_size = len(imports_table) + 1
	chained_ptr_old_addrs = sorted(chained_ptrs.keys())

	with open("bi.txt", 'r') as f:
		bi_lines = [line.strip().split(';') for line in f]
	print(f"First_bi_line: {bi_lines[0]}")
	bi_addrs = sorted(int(line[3]) for line in bi_lines)
	count = 0
	with open("test_copy", 'r+b') as f:
		for line in bi_lines:
			got_addr = int(line[3])
			symbol_name = line[4]
			if count <= 10:
				print(f"Symbol_end_addr: {hex(symbol_end_addr)}")
				count += 1
			f.seek(symbol_end_addr - 4)
			symbol_start_addr = symbol_end_addr
			symbol_end_addr = write_symbol(symbol_name, symbol_end_addr, f)
			lib_ordinal_int = int(line[5])

			f.seek(got_addr)

			next_offset = find_next_offset(got_addr, chained_ptr_old_addrs, bi_addrs)

			# Convert offset into 4-byte units if it's not the end of the chain
			if next_offset != 0:
				next_offset //= 4

			if next_offset < 0:
				raise RuntimeError("Next offset is negative. Something went wrong.")

			# Prepare import table entry
			ordinal = import_table_size -1
			name_offset_int = symbol_start_addr - (fixups_base + header['symbols_offset'])

			name_offset = format(name_offset_int, '023b')
			weak_import = '0'
			lib_ordinal = format(lib_ordinal_int, '08b')

			new_import_str = f"{name_offset}{weak_import}{lib_ordinal}"
			imports_table.append((imports_table[-1][0] + 4, new_import_str))


			import_table_size += 1
			bind = 1
			reserved = 0
			addend = 0

			ptr_str = f"{bind:01b}{next_offset:012b}{reserved:019b}{addend:08b}{ordinal:024b}"
			ptr_value = int(ptr_str, 2)

			f.write(struct.pack("<Q", ptr_value))
			
		all_ptr_addrs = chained_ptr_old_addrs + bi_addrs
		print(f"Writing {len(imports_table)} new imports")
		first_import = imports_table[0][1]
		print(f"First import: {first_import}")
		patch_all_pointers(all_ptr_addrs, f)
		imports_dest =symbol_end_addr
		write_import_table(f, imports_table, header, fixups_base, imports_dest)

	return import_table_size

		
def write_symbol(symbol_name, symbol_addr, f):
	f.seek(symbol_addr)
	symbol_name = symbol_name + '\x00'
	f.write(symbol_name.encode('utf-8'))
	return f.tell()

def get_all_symbols(f, header, fixups_base):
	f.seek(header['symbols_offset'] + fixups_base + 1)
	num_symbols = 0
	symbol_names = []
	while True:
		try:
			symbol_name = read_null_terminated_string(f)
			if len(symbol_name) == 0:
				break
			num_symbols += 1
			symbol_names.append(symbol_name)
		except:
			break
	return num_symbols, symbol_names, f.tell() - 1

def read_null_terminated_string(f):
	s = ""
	while True:
		c = f.read(1)
		if c == b'\x00' or c == b'':
			break
		s += c.decode('utf-8')
	return s

def parse_chained_fixups_header(f, file_offset):
	header_fmt = "<7I"
	header_size = struct.calcsize(header_fmt)
	f.seek(file_offset)
	header_data = f.read(header_size)
	if len(header_data) != header_size:
		print("Error: Could not read the entire header at offset ", hex(file_offset))
		return None
	fields = struct.unpack(header_fmt, header_data)
	header = {
	"fixups_version": fields[0],
	"starts_offset": fields[1],
	"imports_offset": fields[2],
	"symbols_offset": fields[3],
	"imports_count": fields[4],
	"imports_format": fields[5],
	"symbols_format": fields[6],
	}
	return header

def parse_import_table(f, fixups_base, header):
	imports = []
	imports_table_offset = fixups_base + header['imports_offset']
	print(f"Found imports table offset: {hex(imports_table_offset)}")
	for import_idx in range(header['imports_count']):
		import_entry_offset = imports_table_offset + (import_idx * 4)
		f.seek(import_entry_offset)
		import_data = f.read(4)

		if len(import_data) != 4:
			print(f"Failed to read import entry at {hex(import_entry_offset)}")
			continue

		import_value = struct.unpack("<I", import_data)[0]
		import_str = format(import_value, '032b')
		if import_idx < 10:
			import_str_readable = f"Name offset: {int(import_str[0:23], 2)}, Weak import: {int(import_str[23], 2)}, Lib ordinal: {int(import_str[24:], 2)}"
			print(f"Read {import_str_readable} from {hex(import_entry_offset)}")
		"""
		struct dyld_chained_import
		{
			uint32_t    lib_ordinal :  8,
						weak_import :  1,
						name_offset : 23;
		};
		"""
		imports.append((import_entry_offset, import_str))
	return imports
	
def update_fixups_header(f, header, fixups_base, imports_count):
	imports_count = imports_count - 1
	imports_off = imports_dest - fixups_base
	print(f"Imports offset: {imports_off}")
	header_fmt = "<7I"
	f.seek(fixups_base)
	header_data = struct.pack(header_fmt, header['fixups_version'], header['starts_offset'], imports_off, header['symbols_offset'], imports_count, header['imports_format'], header['symbols_format'])
	f.write(header_data)

def write_import_table(f, imports_table, header, fixups_base, destination):
	print(f"Writing imports table at {hex(destination)}")
	for importss_entry in imports_table[:10]:
		imports_entry_readable = (
			f"Name offset: {int(importss_entry[1][0:23], 2)}, "
			f"Weak import: {int(importss_entry[1][23], 2)}, "
			f"Lib ordinal: {int(importss_entry[1][24:], 2)}"
		)
		print(f"Writing {imports_entry_readable} to {hex(importss_entry[0])}")

	for idx, import_entry in enumerate(imports_table):
		import_value = int(import_entry[1], 2)
		entry_offset = destination + (idx * 4)
		f.seek(entry_offset)
		f.write(struct.pack("<I", import_value))

def update_lcs(f, original_fixups_base, relocate_by=0):
	binary = MachO("test_copy")
	current_offset = 0
	trie_move_by = 0x10000
	for header in binary.headers:
		current_offset += header.header._size_
		for cmd in header.commands:
			load_cmd = cmd[0]
			if load_cmd.get_cmd_name() == "LC_DYLD_CHAINED_FIXUPS":
				print(f"[*] Found LC_DYLD_CHAINED_FIXUPS at {hex(current_offset)}")

				# Read and update dataoff
				f.seek(current_offset + 8)
				old_dataoff = struct.unpack("<I", f.read(4))[0]
				fixups_new_offset = old_dataoff - relocate_by
				f.seek(current_offset + 8)
				f.write(struct.pack("<I", fixups_new_offset))
				print(f"[+] LC_DYLD_CHAINED_FIXUPS dataoff updated from {hex(old_dataoff)} to {hex(fixups_new_offset)}")

				# Read datasize
				f.seek(current_offset + 12)
				datasize = struct.unpack("<I", f.read(4))[0]
				print(f"[*] LC_DYLD_CHAINED_FIXUPS datasize: {hex(datasize)}")

				#Update datasize
				new_datasize = datasize + trie_move_by
				f.seek(current_offset + 12)
				f.write(struct.pack("<I", new_datasize))
				print(f"[+] LC_DYLD_CHAINED_FIXUPS datasize updated from {hex(datasize)} to {hex(new_datasize)}")
				# Physically relocate fixups data
				f.seek(old_dataoff)
				fixups_data = f.read(datasize)

				f.seek(old_dataoff)
				f.write(b'\x00' * datasize)
				print(f"[+] Old fixups data location {hex(old_dataoff)} cleared.")

				f.seek(fixups_new_offset)
				f.write(fixups_data)
				print(f"[+] Fixups data relocated from {hex(old_dataoff)} to {hex(fixups_new_offset)}")

			elif load_cmd.get_cmd_name() == "LC_DYLD_EXPORTS_TRIE":
				print(f"[*] Found LC_DYLD_EXPORTS_TRIE at {hex(current_offset)}")
				# Read and update offset
				f.seek(current_offset + 8)
				old_offset = struct.unpack("<I", f.read(4))[0]
				print(f"[*] LC_DYLD_EXPORTS_TRIE old offset: {hex(old_offset)}")
				old_data_size = struct.unpack("<I", f.read(4))[0]
				print(f"[*] LC_DYLD_EXPORTS_TRIE old data size: {hex(old_data_size)}")

				trie_new_offset = old_offset + trie_move_by
				f.seek(current_offset + 8)
				f.write(struct.pack("<I", trie_new_offset))
				print(f"[+] LC_DYLD_EXPORTS_TRIE offset updated from {hex(old_offset)} to {hex(trie_new_offset)}")

				new_data_size = old_data_size - trie_move_by
				if new_data_size < 0:
					raise RuntimeError("New data size is negative. Something went wrong.")
				f.seek(current_offset + 12)
				f.write(struct.pack("<I", new_data_size))
				print(f"[+] LC_DYLD_EXPORTS_TRIE data size updated from {hex(old_data_size)} to {hex(new_data_size)}")

				f.seek(old_offset)
				trie_data = f.read(old_data_size)

				f.seek(old_offset)
				f.write(b'\x00' * old_data_size)
				print(f"[+] Old trie data location {hex(old_offset)} cleared.")

				f.seek(trie_new_offset)
				f.write(trie_data)

				print(f"[+] Trie data relocated from {hex(old_offset)} to {hex(trie_new_offset)}")
			elif load_cmd.get_cmd_name() == "LC_LOAD_DYLIB":
				print(f"[*] Found LC_LOAD_DYLIB at {hex(current_offset)}")
				name_offset = cmd[1].name
				f.seek(current_offset + name_offset)
				if read_null_terminated_string(f) == "@rpath/scrollx.framework/scrollx":
					print(f"[*] Found scrollx loader at {hex(f.tell())}")
					f.seek(current_offset)
					scroll_loader_patch_bytes = bytearray.fromhex("180000804000000018000000010000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000")
					f.write(scroll_loader_patch_bytes)
					print(f"[+] Patched scrollx loader at {hex(f.tell())}")
				return fixups_new_offset, trie_new_offset
			
			current_offset += load_cmd.cmdsize
	raise RuntimeError("LC_DYLD_CHAINED_FIXUPS command not found.")

def get_new_page_starts(segment_info):
    return [0] + list(segment_info['page_starts'][1:segment_info['page_count']])


def main():
	clash_royale_path = input("Enter the path to the Clash Royale binary: ")
	with open(clash_royale_path, 'r+b') as f:
		original_fixups_base = 0xddc000 #offset of chained fixups header
		fixups_base, trie_new_offset = update_lcs(f, original_fixups_base)
		header = parse_chained_fixups_header(f, fixups_base)
		chained_starts_image = parse_chained_starts_in_image(f, fixups_base, header['starts_offset'])
		print(f"Found {chained_starts_image['seg_count']} segments")
		print(f"Segment offsets: {chained_starts_image['seg_info_offsets']}")
		segment_info = parse_or_patch_chained_starts_in_segment(f, fixups_base, header['starts_offset'], chained_starts_image['seg_info_offsets'][2])
		print(f"Segment info: {segment_info}")
		pointers = parse_chained_pointers_in_segment(f, fixups_base, segment_info, segment_info['segment_vm_offset'], header)
		print(f"Found {len(pointers.items())} pointers")
		new_page_starts = get_new_page_starts(segment_info)
		parse_or_patch_chained_starts_in_segment(f, fixups_base, header['starts_offset'], chained_starts_image['seg_info_offsets'][2], new_page_starts)

		imports = parse_import_table(f, fixups_base, header)
		import_table_size = len(imports)
		num_symbols, symbol_names, symbol_end_addr = get_all_symbols(f, header, fixups_base)
		import_table_size = main_patching(symbol_end_addr, header, fixups_base, imports, pointers)	
		update_fixups_header(f, header, fixups_base, import_table_size)
		print("Done patching")

if __name__ == "__main__":
	main()