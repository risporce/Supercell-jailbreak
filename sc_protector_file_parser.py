# decrypted bi.txt parsing 

# see https://github.com/frida/frida for installation instruction on your computer (use option 1 with only pip commands to execute)
# see https://frida.re/docs/ios/ for installation instruction on your jailbroken iOS device
import frida
import sys
from datetime import datetime
import struct
import argparse
#pip install machlib, needs to install this library
from macholib.MachO import MachO


parser = argparse.ArgumentParser()
parser.add_argument('--game', help='The game name you want to patch, enter its exact binary filename as string ex: "laser", "Clash of Clans", "Clash_Royale"')
game_code_name = {
    "Hay Day": "soil",
    "Clash_Royale": "scroll",
    "laser": "laser",
    "Squad Busters": "squad",
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
####
decrypted_bi = None
fileToOpen = None
protectorLoaderPatchBytes = None
### protector loader
protectorLoaderStartAddress = None # hd 1.63.204 //0x1348s

def getProtectorPatchBytes():
    global protectorLoaderPatchBytes
    four_or_five_letters_codename = ["laser", "Clash of Clans", "Squad", "Clash Mini", "Boom Beach", "Hay Day"]
    if fileToOpen in four_or_five_letters_codename:
        protectorLoaderPatchBytes = bytearray.fromhex("180000803800000018000000010000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000")
    elif fileToOpen == "Clash_Royale":
        protectorLoaderPatchBytes = bytearray.fromhex("180000804000000018000000010000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000")



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
                print(f"Found LC_DYLD_INFO_ONLY at offset at : {hex(current_offset)}")
            elif load_cmd.get_cmd_name() == 'LC_SYMTAB': # this is here in all format so far
                stringTableStartAddress = cmd[1].stroff
                find__mh_execute_header_strtab_and_symbtab_offset(cmd[1].stroff, cmd[1].strsize, cmd[1].symoff, cmd[1].nsyms)
            elif load_cmd.get_cmd_name() == 'LC_LOAD_DYLIB':
                if loader_found:
                    return
                # protector loader is always always the first one, so we can stop after it reached the first
                protectorLoaderStartAddress = current_offset
                print(f"Found protector loader at: {hex(current_offset)}")
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
        print(f"Found string table fixing address at: {hex(lazyBindingFixingAddress)}")
        
        f.seek(symTableStartOffset)
        symbol_table = f.read(symTableNbOffsets * SYMBOL_TABLE_INFO_LENGTH)
        symbol_index = symbol_table.find(search_bytes_symbol)
        if string_index == -1:
            print(f"Error: {search_bytes_symbol} not found in that range")
            return None
        symbolTableStartAddress = symbol_index + symTableStartOffset + len(search_bytes_symbol)
        startCountingAddress = stringTableFixingAddress - stringTableStartAddress
        print(f"Found symbol table start address at: {hex(symbolTableStartAddress)}")
    
    f.close()

def on_message(message, data):
    global decrypted_bi
    if message['type'] == 'send':
        decrypted_bi = message['payload']
        session.detach()
        lines = decrypted_bi.splitlines()
        mainFixing(lines)
        
    elif message['type'] == 'error':
        print(f"[-] {message['stack']}")


def removeProtectorLoader(binf):
    if protectorLoaderStartAddress is not None:
        binf.seek(protectorLoaderStartAddress, 0)
        binf.write(protectorLoaderPatchBytes)
        print("removed protector loader")
    else:
        print("protector loader already removed")

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
        print("fixed export functions data and size")


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


def fixLazyBindingSection(binf, starting_char, function_class, function_string, function_data_and_name_length_additionned, pointer_bytes):
    classChar = "@"
    starting_byte = "72"
    classByteStart = "20" 
    if (int(function_class) < 16):
        classByteStart = "1"
    classByte = f'{int(function_class):x}'
    classBytes = classByteStart + classByte
    end_bytes = "9000"
    pointerString = uleb128Encode(int(pointer_bytes))
    functionFinalString = (classChar + starting_char + function_string)
    functionFinalString = (bytes(functionFinalString, 'utf-8') + b'\x00').hex()

    finalString = (starting_byte + pointerString + classBytes + functionFinalString + end_bytes)
    binf.seek(int(function_data_and_name_length_additionned) + lazyBindingFixingAddress, 0)
    binf.write(bytearray.fromhex(finalString))

def fixStringTable(binf, starting_char, function_string, string_length_additionned_string_table_count):
    fixingString = starting_char + function_string
    finalString = (bytes(fixingString, 'utf-8') + b'\x00').hex()
    binf.seek(stringTableFixingAddress + string_length_additionned_string_table_count, 0)
    binf.write(bytearray.fromhex(finalString))
    return string_length_additionned_string_table_count + len(bytearray.fromhex(finalString))

def fixSymbolTable(binf, string_length_additionned_string_table_count, function_class, count, functionPointer = None):
    finalDataString = ""
    bytesAwayFromStringInStringTable = struct.pack("<I", startCountingAddress + int(string_length_additionned_string_table_count))
    finalDataString+= bytesAwayFromStringInStringTable.hex() + "010000" + str(hex(int(function_class))[2:].zfill(2)) + "0000000000000000"

    binf.seek(symbolTableStartAddress + (count * SYMBOL_TABLE_INFO_LENGTH), 0)
    binf.write(bytearray.fromhex(finalDataString))

def fixBinary(binf, biFile):
    count = 0
    stringLengthAdditionnedStringTableCount = 0
    functionDataAndNameLengthAdditionned = 0
    for line in biFile:
        list_data = line.split(VALUE_SEPARATOR)
        if (int(list_data[2]) == INIT_INDICATOR):
            fixInitArray(binf, list_data)
        elif (int(list_data[2]) == V0_INDICATOR): # protector v0 where it is used in all supercell games except new clash royale
            startingChar = "_"
            functionDataAndNameLengthAdditionned = list_data[3] #this is true but seems like protector not optimized and put some null bytes which are not supposed to be here, which makes it needed to increase lazy binding array
            functionString = list_data[5]
            functionClass = list_data[6]
            pointerBytes = list_data[8] 

            fixLazyBindingSection(binf, startingChar, functionClass, functionString, functionDataAndNameLengthAdditionned, pointerBytes)
            fixSymbolTable(binf, stringLengthAdditionnedStringTableCount, functionClass, count)
            stringLengthAdditionnedStringTableCount = fixStringTable(binf, startingChar, functionString, stringLengthAdditionnedStringTableCount)

            count+=1
        elif (int(list_data[2]) == V5_INDICATOR): #new Clash Royale has this to 5, it's a different fix to apply
            # the thing i noticed is that we need to fix the symbol table and the string table but some minor modification from the code of v0, like it doesn't need the starting_char = "_", function names already have it
            functionPointer = int(list_data[3]) # refers to the got section, but why?
            functionString = list_data[4]
            functionClass = list_data[5]
            count+=1


def main(game):
    global session # frida script, needs to have a jailbroken ios device with frida-server installed. this is getting the necessary data in order to fix the binary
    device = frida.get_usb_device()
    pid = device.spawn([f"com.supercell.{game}"])
    session = device.attach(pid) # the address of protectorBase.add(0x0) can change any new build of protector supercell is shipping in their client, at this moment it's 0x429728
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
    sys.stdin.read()

def mainFixing(biFile):
    with open(fileToOpen, 'r+b') as binf:
        start_time = datetime.now()
        removeProtectorLoader(binf)
        fixExport(binf) # in clash royale protector v5 this is non-existent, a check is in place to not fix it in case of cr
        fixBinary(binf, biFile)
        end_time = datetime.now()
        print("finished fixing binary file, you may now exit pressing CTRL+C")
        print('Duration: {}'.format(end_time - start_time))

if __name__ == '__main__':
    args = parser.parse_args()
    a = args.game
    fileToOpen = a
    a = game_code_name.get(fileToOpen)
    game = a
    setup()
    main(game)