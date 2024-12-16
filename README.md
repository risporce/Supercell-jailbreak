# Supercell-jailbreak

## Notes: ##
# **No more ipas will be uploaded here**

So while other games are still easily fixable by the script with updated offset for the protector, Clash Royale on the other hand requires a rebuilding of LC_DYLD_CHAINED_FIXUPS. This will come to other games soon as they all will update to support iOS 14 as minimum eventually. IF but really IF i ever have the motivation to go throught the pain of trying again to fix iOS 14+ built executables and suceed, I will upload updated script here, otherwise **this repo is dead** or may update the script to support updated version of the protector.

## Script ##

### Status
| Game           | Working|
|----------------|--------|
| Brawl Stars    | ✅ Yes |
| Hay Day        | ✅ Yes |
| Squad Busters  | ✅ Yes |
| Boom Beach     | ✅ Yes |
| Clash of Clans | ✅ Yes |
| Clash Royale   | ❌ No  |

Note to every developer: I made this script while I had not the slightest idea of what Mach-O executables are, variable names are very unrepresentative and may be even misleading.

While I know now the real name Mach-o sections, names ...etc I didn't at the time, and I did not rewrite the whole script variable names just for this. It would be a waste of time.

So why am I opening this script now ? Well I start to be tired of having to quickly update all the time the ipas, it takes quite some time and motivation to do this, especially when games like Boom Beach have 5 optional updates in a couple days and forcing everyone to download the new version right away or they can't play.

Another reason is that I don't have time at all anymore to understand the protector and fix the data accordingly. Clash Royale switched to another format of data to be fixed, while it looks easier than the previous one, I don't have any time to spend into it. I open this script hoping another developer could continue, improve it, maybe finally making a dev tweak for Supercell games? It would be awesome!.

And lastly, for those who shown me their concerns about me modifying the IPA and that maybe I was maybe injecting malicious code, now you will see what was really the patch and be able to even do it yourself !


  ### Prequisites  
  -  **JAILBROKEN** iOS device
  -  Python 3 https://www.python.org/ (tested with 3.12): download for your OS 
  -  Frida https://github.com/frida/frida : `pip install frida` as well as `pip install frida-tools`. Setup frida-server on your iOS device (https://frida.re/docs/ios/#with-jailbreak) and execute the "Quick smoke-test" to ensure your environment is working. If you are stuck at "waiting USB device to appear, try to use with -H parameter https://github.com/frida/frida/issues/579#issuecomment-416574476"
  -  MachoLib https://macholib.readthedocs.io/en/latest/ : `pip install macholib`

  ### Usage with IPhone, IPad connected to your computer
  0. Download and extract zip or clone the repository `git clone https://github.com/risporce/Supercell-jailbreak.git` then `cd Supercell-jailbreak`
  1. Decrypt and extract the game IPA from your device and upload it to your computer. | Alternatively, download the decrypted IPA package from some site
  2. Connect your device to your computer via USB cable, make sure to trust your computer from your device.
  3. From your computer, use any zip unarchiver like PeaZip or 7Zip to extract the IPA
  4. Place the main executable file at the same directory as the script
  5. Open Terminal app, use the `cd` comamnd to open that folder in your terminal, example my files are in `C:\protector\Supercell-jailbreak` enter in terminal  (cd "C:\protector\Supercell-jailbreak")
  6. Execute this command in terminal: `python3 sc_protector_file_parser.py --game "replace this text under string to the executable file name, keep the quotes"`
  7. If you moved the main executable, put it back into the IPA and replace the original one.
  8. Compress the Payload folder into .zip and rename to .ipa
  9. Use your favorite method to install the .IPA
  10. Well it should work hopefully, enjoy!

  ### Usage with M chip series Mac
  0. Download and extract zip or clone the repository `git clone https://github.com/risporce/Supercell-jailbreak.git` then `cd Supercell-jailbreak`
  1. Decrypt and extract the game IPA from your device and upload it to your computer. |   Alternatively, download the decrypted IPA package from some site
  2. Install the IPA application on your Mac and disable protections such as SIP
  3. From your computer, use any zip unarchiver like PeaZip or 7Zip to extract the .ipa from step 1
  4. Place the main executable file at the same directory as the script
  5. Open Terminal app, use the `cd` comamnd to open that folder in your terminal, example my files are in `C:\protector\Supercell-jailbreak` enter in terminal  (cd "C:\protector\Supercell-jailbreak")
  6. Execute this command in terminal: `python3 sc_protector_file_parser.py --mac --game "replace this text under string to the executable file name, keep the quotes"`
  7. If you moved the main executable, put it back into the IPA and replace the original one.
  8. Compress the Payload folder into .zip and rename to .ipa
  9. Use your favorite method to install the .IPA
  10. Well it should work hopefully, enjoy!


## Troubleshooting

### Frida:

USB not recognized? try with Host instead https://github.com/frida/frida/issues/579#issuecomment-416574476

### Python:
 Missing packages even after installing them ? You may have multiples instances of Python installed on your system, use `python3 -m pip install package_name` where you replace package_name with the actual package name and run `python3 sc_protector_file_parser.py ...` (line from step 6)

 ### Crash after patching
Don't reinstall the IPA from step 1, make sure to replace the current executable in the folder with the patched one from the script, then compress back the Payload folder into .zip and rename to .ipa to make a whole new patched IPA and install with a tool like [Sideloadly](https://sideloadly.io/), [Trollstore](https://trollstore.app/) ...etc.



## Contact ##
The main way to contact me if you have any question is throught the following social medias:

Discord and Telegram: risporce

### Enjoy being able to play again supercell games! ###
This content is not affiliated with, endorsed, sponsored, or specifically approved by Supercell and Supercell is not responsible for it. For more information see: [Supercell's Fan Content Policy](https://supercell.com/en/fan-content-policy/) and also [Supercell's Term of Service](https://supercell.com/en/terms-of-service/)
