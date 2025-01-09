# decrypted bi.txt parsing 

# see https://github.com/frida/frida for installation instruction on your computer (use option 1 with only pip commands to execute)
# see https://frida.re/docs/ios/ for installation instruction on your jailbroken iOS device
from datetime import datetime
import argparse, struct, sys, frida, platform, subprocess, time
#pip install macholib, needs to install this library
from macholib.MachO import MachO
import os
import zipfile
import shutil
import struct


parser = argparse.ArgumentParser()
parser.add_argument('--game', help='The game name you want to patch, enter its exact binary filename as string ex: "laser", "Clash of Clans", "Clash_Royale"')
parser.add_argument('--mac', action='store_true', help='Use your Mac with apple M series chip to patch the app, requires you to install the IPA and disable a few protections including SIP')
parser.add_argument('--rebuild', action='store_true', help='Rebuild ipa, xd.')
game_code_name = {
    "Hay Day": "soil",
    "Clash_Royale": "scroll",
    "laser": "laser",
    "Squad": "squad",
    "Clash of Clans": "magic",
    "Boom Beach": "reef",
}

#protector bi.txt
VALUE_SEPARATOR = ";"
INIT_INDICATOR = 10
V0_INDICATOR = 0
V5_INDICATOR = 5
POINTER_SIZE = 8
SYMBOL_TABLE_INFO_LENGTH = 16
#binary
BINARY_BASE_ADDRESS = 0x100_000_000
lazyBindingFixingAddress = None # hd 1.63.204 //0x2461fe8
stringTableFixingAddress = None #String Table Address found in mach-o header in linkedit # hd 1.63.204 after mh_execute_header //0x267246e
symbolTableStartAddress = None # hd 1.63.204 after mh_execute_header //0x2662220
stringTableStartAddress = None # hd 1.63.204 //0x26713a8
startCountingAddress = None #= stringTableFixingAddress - stringTableStartAddress
exportOff = None # hd 1.63.204 //0x2473080
exportSize = None # hd 1.63.204 //0x1bdcc8
newExportOff = None # hd 1.63.204 //0x2473850
newExportSize = None # hd 1.63.204 //0x1bd4f8
newLazyBindingSize = None
lc_dyld_info_onlyStartAddress = None
nameOffset = None
####
decrypted_bi = None
fileToOpen = None
protectorLoaderPatchBytes = None
### protector loader
protectorLoaderStartAddress = None # hd 1.63.204 //0x1348s



class IPARepacker:
    def __init__(self, ipa_path, output_dir="unpacked_ipa", new_macho_path=None, output_ipa):
        
        #C:\Users\rldv1\Desktop>py sc_protector_file_parser.py --rebuild --game=laser
        #Enter the path to the IPA file (or use DragnDrop)> C:\Users\rldv1\Downloads\com.supercell.laser_59.197.ipa
        
        self.ipa_path = ipa_path
        self.output_dir = output_dir
        self.macho_name = new_macho_path
        self.output_ipa = output_ipa
        self.payload_dir = os.path.join(self.output_dir, "Payload")
        self.app_path = None
        print("Simple IPARepacker for risporce/Supercell-jailbreak by rldv1 <3")
    
    def _progress(self, p, current, total, file):
        percent = round((current / total) * 100, 1)
        t = f"[{p.upper()} - {percent}%] Current: {file[-(os.get_terminal_size().columns - 32):]}" # <-- необходимо заполнить точно до кол-ва символов (columns) в консоли, так как иначе произойдет конфликт предыдущих строк1
        l = os.get_terminal_size().columns - len(t)
        t += "".join(" " for _ in range(l))
        print(t,end="\r",flush=True)
        if current == total: print(f"\n[{p.upper()}] Done.\n")
            
    def unpack(self):
        time.sleep(1.0) # some moment
        
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.makedirs(self.output_dir)
        with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
            total_files = len(ipa.namelist())
            for i, file in enumerate(ipa.namelist(), 1):
                ipa.extract(file, self.output_dir)
                self._progress("unpacking", i, total_files, file)
                
        apps = [f for f in os.listdir(self.payload_dir) if f.endswith('.app')] 
        if not apps:
            raise FileNotFoundError("[!!!] No .app directory found in Payload.")
        self.app_path = os.path.join(self.payload_dir, apps[0])
        with open(os.path.join(self.app_path, "IPAREPACKER"), 'w') as f: f.write("Respect our work, dont sell this IPA...\n\nhttps://github.com/risporce/Supercell-jailbreak\n\nt.me/risporce\nt.me/rldv1")
    
    def is_macho_encrypted(self, macho_path):
        # LC_ENCRYPTION_INFO_64 (или без _64 для арм32)
        
        with open(macho_path, 'rb') as f:
            f.seek(20)  # скип magic, cputype, cpusubtype
            ncmds = struct.unpack('<I', f.read(4))[0]
            f.seek(8, 1)  # скип sizeofcmds и флаги
            for _ in range(ncmds):
                cmd, cmdsize = struct.unpack('<II', f.read(8))
                print(f"[*] с: {hex(cmd)}")
                if cmd == 0x2C:
                    f.seek(8, 1) 
                    cryptid = struct.unpack('<I', f.read(4))[0]
                    return cryptid == 1
                f.seek(cmdsize - 8, 1)
        return False
        
    def remove_useless(self):
        # сносим барахло из под промона (bi, ii, прочие)
        targets = ["bi.txt", "ii.txt", "config-encrypt.txt"]
        for i in targets:
            ii = os.path.join(self.app_path, i)
            if os.path.exists(ii):
                print("[*] Removing", ii)
                os.remove(ii)
        frameworks_dir = os.path.join(self.app_path, "Frameworks")
        if not os.path.exists(frameworks_dir): return
        for item in os.listdir(frameworks_dir):
            item_path = os.path.join(frameworks_dir, item)
            if os.path.isdir(item_path) and item.endswith("x.framework"):
                shutil.rmtree(item_path)
                print("[*] Removing", item_path)
        
    def replace_macho(self):
        macho_name = os.path.basename(self.macho_name)
        macho_path = os.path.join(self.app_path, self.macho_name)
        if os.path.exists(macho_path):
            os.remove(macho_path)
        shutil.copy(self.macho_name, macho_path)
        os.chmod(macho_path, 0o755)
        
    def ensure_macho(self):
        
        print("[*] Checking Mach-O...")
        macho_path = os.path.join(self.app_path, fileToOpen)
        
        ENCRYPTED_STATE = self.is_macho_encrypted(macho_path)
        if os.path.exists(macho_path) and ENCRYPTED_STATE:
            print(f"[!!!] Mach-O is encrypted. Cannot proceed.\n\n------- What to do in this case?:\n1. Use tweaks like iGameGod/CrackerXI\n2. Download IPA from http://decrypt.day or 4PDA\n\n[!] Dont open an issue on github about this as the problem lies on your end!\n----------------\n")
            raise Exception
        elif not ENCRYPTED_STATE: print("[*] Mach-O is decrypted, continuing...")
        else:
            print("[*] Mach-O cant be found :/")
            raise Exception
        time.sleep(1.0) # some moment

    def pack(self):
        time.sleep(1.0) # some moment
        files = []
        for root, _, file_list in os.walk(self.output_dir):
            for file in file_list:
                files.append((root, file))
        total_files = len(files)
        with zipfile.ZipFile(self.output_ipa, 'w', zipfile.ZIP_DEFLATED) as ipa:
            for i, (root, file) in enumerate(files, 1):
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, self.output_dir)
                ipa.write(full_path, relative_path)
                self._progress("packing", i, total_files, file)
        shutil.rmtree(self.output_dir)





def getProtectorPatchBytes():
    global protectorLoaderPatchBytes
    four_or_five_letters_codename = ["laser", "Clash of Clans", "Squad", "Clash Mini", "Boom Beach", "Hay Day"]
    if fileToOpen in four_or_five_letters_codename:
        protectorLoaderPatchBytes = bytearray.fromhex("180000803800000018000000010000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000")
    elif fileToOpen == "Clash_Royale":
        protectorLoaderPatchBytes = bytearray.fromhex("180000804000000018000000010000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000")

def is_arm_mac():
    if platform.system() == "Darwin":
        architecture = platform.machine()
        return architecture == "arm64"
    return False
    
def check_sip():
    sip_status = subprocess.check_output(["csrutil", "status"], text=True).strip().lower()
    if "disabled" in sip_status:
        return True
    elif "error getting variable" in sip_status: 
        print("[*] boot-args is not exists in nvram?????")
        return False
    else:
        print("[WARN] SIP is enabled! Unable to use your macbook to patch...")
        return False
    return False #something crazy happened again, so we forcibly think that sip is turned on
def check_security_args():
    try:
        boot_args = subprocess.check_output(["nvram", "boot-args"], text=True).strip()
        
        # Setting these args disables almost all security features on macOS, Frida can now work without the need for code-signing free as a fish in water
        required_args = [
            "arm64e_preview_abi",
            "thid_should_crash=0",
            "tss_should_crash=0",
            "amfi_get_out_of_my_way=1"
        ]
        
        if all(arg in boot_args for arg in required_args):
            return True
        else:
            print('[*] You do not have the required boot-args, install them with the command: sudo nvram boot-args="arm64e_preview_abi thid_should_crash=0 tss_should_crash=0 amfi_get_out_of_my_way=1"')
            return False
    except subprocess.CalledProcessError:
        print("[ERROR] Failed to get boot args. SIP may be enabled.")
        return False


def setup():
    global lazyBindingFixingAddress
    global stringTableStartAddress
    global newLazyBindingSize
    global exportOff
    global exportSize
    global newExportOff
    global newExportSize
    global lc_dyld_info_onlyStartAddress
    global protectorLoaderStartAddress
    global nameOffset
    loader_found = False
    getProtectorPatchBytes()
    binary = MachO(fileToOpen)
    current_offset = 0
    for header in binary.headers:
        current_offset += header.header._size_
        for cmd in header.commands:
            load_cmd = cmd[0]
            #print(load_cmd.get_cmd_name())
            if load_cmd.get_cmd_name() == 'LC_DYLD_INFO_ONLY': # in clash royale new format this is inexistant so it will never enter here
                lazyBindingFixingAddress = cmd[1].lazy_bind_off
                newLazyBindingSize = cmd[1].lazy_bind_size + 1500 # what is this??? the size of the lazy binding section is not large enough to contain all the data,
                #                                                  it's usually missing about 150-200 bytes in every binary or a number close to that, so to be sure 
                #                                                  i always set it to a big number so that we are sure it'll always have enough room for all the data
                #                                                  but this may cause problems at some point, we never know, for now it's working
                exportOff = cmd[1].export_off
                exportSize = cmd[1].export_size
                newExportOff = exportOff + 2000 # if we enlarge the size of the lazy binding, a solution is to trim the size of the export table since it's not all used anyway
                newExportSize = exportSize - 2000
                lc_dyld_info_onlyStartAddress = current_offset
                print(f"[INFO] Found LC_DYLD_INFO_ONLY at offset at : {hex(current_offset)}")
            elif load_cmd.get_cmd_name() == 'LC_SYMTAB': # this is here in all format so far
                stringTableStartAddress = cmd[1].stroff
                find__mh_execute_header_strtab_and_symbtab_offset(cmd[1].stroff, cmd[1].strsize, cmd[1].symoff, cmd[1].nsyms)
            elif load_cmd.get_cmd_name() == 'LC_LOAD_DYLIB':
                if loader_found:
                    return
                # protector loader is always always the first one, so we can stop after it reached the first, this means
                nameOffset = cmd[1].name
                protectorLoaderStartAddress = current_offset
                print(f"[INFO] Found protector loader at: {hex(current_offset)}")
                loader_found = True
            current_offset += load_cmd.cmdsize
    


def find__mh_execute_header_strtab_and_symbtab_offset(strTableStartOffset, strTableLength, symTableStartOffset, symTableNbOffsets):
    global stringTableFixingAddress
    global symbolTableStartAddress
    global startCountingAddress
    search_string = "__mh_execute_header".encode()
    search_bytes_symbol = bytes.fromhex("0f0110000000000001000000") # mh_execute_header symbols data
    with open(fileToOpen, 'rb') as f:
        #string table index
        f.seek(strTableStartOffset)
        string_table = f.read(strTableLength)
        string_index = string_table.find(search_string)
        if string_index == -1:
            print(f"Error: {search_string} not found in that range")
            return None
        stringTableFixingAddress = string_index + strTableStartOffset + len(search_string) +1
        print(f"[INFO] Found string table fixing address at: {hex(lazyBindingFixingAddress)}")
        
        f.seek(symTableStartOffset)
        symbol_table = f.read(symTableNbOffsets * SYMBOL_TABLE_INFO_LENGTH)
        symbol_index = symbol_table.find(search_bytes_symbol)
        if string_index == -1:
            print(f"Error: {search_bytes_symbol} not found in that range")
            return None
        symbolTableStartAddress = symbol_index + symTableStartOffset + len(search_bytes_symbol)
        startCountingAddress = stringTableFixingAddress - stringTableStartAddress
        print(f"[INFO] Found symbol table start address at: {hex(symbolTableStartAddress)}")
    
    f.close()

def on_message(message, data):
    global decrypted_bi
    if message['type'] == 'send':
        decrypted_bi = message['payload']
        session.detach()
        lines = decrypted_bi.splitlines()
        mainFixing(lines)
        
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")


def removeProtectorLoader(binf):
    binf.seek(protectorLoaderStartAddress + nameOffset, 0)
    if read_null_terminated_string(binf) == f"@rpath/{game}x.framework/{game}x":
        binf.seek(protectorLoaderStartAddress, 0)
        binf.write(protectorLoaderPatchBytes)
        print("[INFO] removed protector loader")
    else:
        print("[WARNING] protector loader is not present in the executable, has it been removed already?")

def fixExport(binf):
    if lc_dyld_info_onlyStartAddress is not None:
        patch_size = struct.pack('<III', newLazyBindingSize, newExportOff, newExportSize)
        binf.seek(lc_dyld_info_onlyStartAddress + 36)
        binf.write(patch_size)

        binf.seek(exportOff, 0)
        data = binf.read(exportSize)
        binf.seek(exportOff, 0)
        binf.write(b'\x00' * exportSize)
        binf.seek(newExportOff, 0)
        binf.write(data)
        print("[INFO] fixed export functions data and size")

def uleb128Encode(number):
    stringResult = ""
    while True:
        byte = number & 0x7F
        number >>= 7
        if number != 0:
            byte |= 0x80
        stringResult += f'{byte:02x}'
        if number == 0:
            break
    return stringResult

def fixInitArray(binf, line):
    initArrayAddress = line[3]
    initArrayFunctionAddress = line[4]
    initArrayAddress = int(initArrayAddress) - BINARY_BASE_ADDRESS
    initArrayFunctionAddress = f'{int(initArrayFunctionAddress):x}'
    if len(initArrayFunctionAddress) % 2 != 0:
        initArrayFunctionAddress = "0" + initArrayFunctionAddress
    toBytes = bytearray.fromhex(initArrayFunctionAddress)
    toBytes.reverse()
    binf.seek(initArrayAddress, 0)
    binf.write(toBytes)


def fixLazyBindingSection(binf, starting_char, symbol_ordinal, function_string, function_data_and_name_length_additionned, pointer_bytes):
    classChar = "@"
    starting_byte = "72"
    classByteStart = "20" 
    if (int(symbol_ordinal) < 16):
        classByteStart = "1"
    classByte = f'{int(symbol_ordinal):x}'
    classBytes = classByteStart + classByte
    end_bytes = "9000"
    pointerString = uleb128Encode(int(pointer_bytes))
    functionFinalString = (classChar + starting_char + function_string)
    functionFinalString = (bytes(functionFinalString, 'utf-8') + b'\x00').hex()

    finalString = (starting_byte + pointerString + classBytes + functionFinalString + end_bytes)
    binf.seek(int(function_data_and_name_length_additionned) + lazyBindingFixingAddress, 0)
    binf.write(bytearray.fromhex(finalString))

def fixStringTable(binf, starting_char, function_string, stringIndexInStringTable):
    fixingString = starting_char + function_string
    finalString = (bytes(fixingString, 'utf-8') + b'\x00').hex()
    binf.seek(stringTableFixingAddress + stringIndexInStringTable, 0)
    binf.write(bytearray.fromhex(finalString))
    return stringIndexInStringTable + len(bytearray.fromhex(finalString))

def fixSymbolTable(binf, stringIndexInStringTable, symbol_ordinal, count, functionPointer = None):
    finalDataString = ""
    bytesAwayFromStringInStringTable = struct.pack("<I", startCountingAddress + int(stringIndexInStringTable))
    finalDataString+= bytesAwayFromStringInStringTable.hex() + "010000" + str(hex(int(symbol_ordinal))[2:].zfill(2)) + "0000000000000000"

    binf.seek(symbolTableStartAddress + (count * SYMBOL_TABLE_INFO_LENGTH), 0)
    binf.write(bytearray.fromhex(finalDataString))

def fixBinary(binf, biFile):
    count = 0
    stringIndexInStringTable = 0
    symbolTableDataIndex = 0
    for line in biFile:
        list_data = line.split(VALUE_SEPARATOR)
        if (int(list_data[2]) == INIT_INDICATOR):
            fixInitArray(binf, list_data)
        elif (int(list_data[2]) == V0_INDICATOR): # protector v0 where it is used in all supercell games except new clash royale
            startingChar = "_"
            symbolTableDataIndex = list_data[3] #this is true but seems like protector not optimized and put some null bytes which are not supposed to be here, which makes it needed to increase lazy binding array
            symbolName = list_data[5]
            symbolOrdinalPosition = list_data[6]
            pointerBytes = list_data[8]

            fixLazyBindingSection(binf, startingChar, symbolOrdinalPosition, symbolName, symbolTableDataIndex, pointerBytes)
            fixSymbolTable(binf, stringIndexInStringTable, symbolOrdinalPosition, count)
            stringIndexInStringTable = fixStringTable(binf, startingChar, symbolName, stringIndexInStringTable)

            count+=1
        elif (int(list_data[2]) == V5_INDICATOR): #new Clash Royale has this to 5, it's a different fix to apply
            # the thing i noticed is that we need to fix the symbol table and the string table but some minor modification from the code of v0, like it doesn't need the starting_char = "_", function names already have it
            functionPointer = int(list_data[3]) # refers to the got section, but why?
            symbolName = list_data[4]
            symbolOrdinalPosition = list_data[5]
            count+=1

def read_null_terminated_string(binf):
    string = b''
    while True:
        char = binf.read(1)
        if char == b'\x00' or not char:
            break
        string += char

    return string.decode('utf-8')


def main(game, mac):
    global session # frida script, needs to have a jailbroken ios device with frida-server installed. this is getting the necessary data in order to fix the binary
    
    if mac:
        if is_arm_mac() and check_sip() and check_security_args():
            print("[*] ARM-based macOS device detected, we try to use your host instead of a phone")
            
            device = frida.get_local_device()
            
            #correct pls if i indicated there something wrong, i only work on brawl stars and barely remember all this codenames
            game_app_name = {"laser": "Brawl Stars", "magic": "Clash of Clans", "reef": "Boom Beach", "squad": "Squad Busters", "soil": "Hay Day", "scroll": "Clash Royale"}
            subprocess.check_output(["open", f"/Applications/{game_app_name[game]}.app"], text=True).strip()
            try: 
                pid = int(subprocess.check_output(["pgrep", game], text=True).strip())
            except Exception as e:
                print("[!] Failed to catch process PID, if your target game is launched in the dock, you need to figure out why pgrep command is causing an error. (you didnt work out? open issue)")
                print("[*] Or just remove --mac from args to use iPhone")
                exit(1)
        else:
             print("[*] SIP is probably enabled, disable it or remove --mac from args to use iPhone")
             exit(1)
    else:
        device = frida.get_usb_device()
        pid = device.spawn([f"com.supercell.{game}"])
    
    
    session = device.attach(pid) # the address of protectorBase.add(0x0) can change any new build of protector supercell is shipping in their client, at this moment it's 0x429728
    if game == 'squad' or game == 'magic' or game == 'reef':
        script = session.create_script(f'''
            var protectorBase = Module.findBaseAddress("{game}x");
            var StringFunctionEmulation = protectorBase.add(0x292cec);
            function writeBLFunction(address, newFunctionAddress) {{
                Memory.patchCode(address, 8, code => {{
                    const Patcher = new Arm64Writer(code, {{pc: address}});
                    Patcher.putBlImm(newFunctionAddress);
                    Patcher.flush();
                }});
            }}

            writeBLFunction(protectorBase.add(0xadd20), StringFunctionEmulation)
            var unk;
            var encryptedInput;
            var decryptedOutput;
            var contentLength;
            
            var readEncryptedFilesContent = Interceptor.attach(protectorBase.add(0x29bba0), {{
                onEnter(args) {{
                    unk = args[0];
                    encryptedInput = args[1];
                    decryptedOutput = args[2];
                    contentLength = args[3].toInt32();
                }},
                onLeave : function(retval) {{
                    send(decryptedOutput.readUtf8String());
                    console.log(decryptedOutput.readUtf8String());
                }}
            }});
            ''')
    elif game == 'laser' or game == 'soil':
        script = session.create_script(f'''
            var protectorBase = Module.findBaseAddress("{game}x");
            var StringFunctionEmulation = protectorBase.add(0xfa80c);
            function writeBLFunction(address, newFunctionAddress) {{
                Memory.patchCode(address, 8, code => {{
                    const Patcher = new Arm64Writer(code, {{pc: address}});
                    Patcher.putBlImm(newFunctionAddress);
                    Patcher.flush();
                }});
            }}

            writeBLFunction(protectorBase.add(0x3f7d90), StringFunctionEmulation)
            var unk;
            var encryptedInput;
            var decryptedOutput;
            var contentLength;
            
            var readEncryptedFilesContent = Interceptor.attach(protectorBase.add(0x254b44), {{
                onEnter(args) {{
                    unk = args[0];
                    encryptedInput = args[1];
                    decryptedOutput = args[2];
                    contentLength = args[3].toInt32();
                }},
                onLeave : function(retval) {{
                    send(decryptedOutput.readUtf8String());
                    console.log(decryptedOutput.readUtf8String());
                }}
            }});
            ''')
        
    elif game == 'scroll':
        script = session.create_script(f'''
            var protectorBase = Module.findBaseAddress("{game}x");
            var StringFunctionEmulation = protectorBase.add(0x1b18d8);
            function writeBLFunction(address, newFunctionAddress) {{
                Memory.patchCode(address, 8, code => {{
                    const Patcher = new Arm64Writer(code, {{pc: address}});
                    Patcher.putBlImm(newFunctionAddress);
                    Patcher.flush();
                }});
            }}

            writeBLFunction(protectorBase.add(0x711a28), StringFunctionEmulation)
            var unk;
            var encryptedInput;
            var decryptedOutput;
            var contentLength;
            
            var readEncryptedFilesContent = Interceptor.attach(protectorBase.add(0xa72c0), {{
                onEnter(args) {{
                    unk = args[0];
                    encryptedInput = args[1];
                    decryptedOutput = args[2];
                    contentLength = args[3].toInt32();
                }},
                onLeave : function(retval) {{
                    send(decryptedOutput.readUtf8String());
                    console.log(decryptedOutput.readUtf8String());
                }}
            }});
            ''')
    else:
        script = session.create_script(f'''
        var protectorBase = Module.findBaseAddress("{game}x"); 
        var unk;
        var encryptedInput;
        var decryptedOutput;
        var contentLength;
        
        var readEncryptedFilesContent = Interceptor.attach(protectorBase.add(0x429728), {{
            onEnter(args) {{
                unk = args[0];
                encryptedInput = args[1];
                decryptedOutput = args[2];
                contentLength = args[3].toInt32();
            }},
            onLeave : function(retval) {{
                send(decryptedOutput.readUtf8String());
            }}
        }});
        ''')

    script.on('message', on_message)
    script.load()
    device.resume(pid)
    print("[INFO] setup done, don't exit, the computer can take up to a minute to exit frida session")
    sys.stdin.read()

start_time = datetime.now()
def mainFixing(biFile):
    with open(fileToOpen, 'r+b') as binf:
        removeProtectorLoader(binf)
        fixExport(binf) # in clash royale protector v5 this is non-existent, a check is in place to not fix it in case of cr
        fixBinary(binf, biFile)
        end_time = datetime.now()
        print("[SUCCESS] finished fixing binary file, you may now exit pressing CTRL+C")
        print('[DEBUG] Duration: {}'.format(end_time - start_time))

    if args.rebuild:
        repacker.replace_macho()
        repacker.pack()
    
    os._exit(0)
    
    
if __name__ == '__main__':
    args = parser.parse_args()
    fileToOpen = args.game
    game = game_code_name.get(fileToOpen)
    
    if args.rebuild:
        while 1:
            rebuild_path = input("Enter the path to the IPA file (or use DragnDrop)> ")
            if os.path.exists(rebuild_path): break
            else: print("[!] Invalid file path. Example: /Users/rldv1/Downloads/laser-27.269.ipa or laser-27.269.ipa")
                
        repacker = IPARepacker(rebuild_path, new_macho_path=fileToOpen, output_ipa="output.ipa")
        repacker.unpack()
        repacker.ensure_macho()
    
    setup()
    main(game, args.mac)
    
    
