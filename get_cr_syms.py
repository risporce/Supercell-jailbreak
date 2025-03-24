import frida
import sys
def main():
    global session # frida script, needs to have a jailbroken ios device with frida-server installed. this is getting the necessary data in order to fix the binary
    
    device = frida.get_usb_device()
    
    pid = device.spawn(['com.supercell.scroll'])
    session = device.attach(pid) # the address of protectorBase.add(0x0) can change any new build of protector supercell is shipping in their client

    script = session.create_script(f'''
    var protectorBase = Module.findBaseAddress("scrollx");
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

    script.on('message', on_message)
    script.load()
    device.resume(pid)
    print("[INFO] setup done, don't exit, the computer can take up to a minute to exit frida session")
    sys.stdin.read()

def on_message(message):
    global decrypted_bi
    if message['type'] == 'send':
        decrypted_bi = message['payload']
        session.detach()
        lines = decrypted_bi.splitlines()
        with open('bi.txt', 'w') as f:
            for line in lines:
                f.write(f"{line}\n")
        print("[INFO] bi.txt created")
        
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")