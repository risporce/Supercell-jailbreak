# Supercell-jailbreak

## Notes: ##
# **No more ipas will be uploaded here**

So while other games are still easily fixable by the script with updated offset for the protector, Clash Royale on the other hand requires a rebuilding of LC_DYLD_CHAINED_FIXUPS. This will come to other games soon as they all will update to support iOS 14 as minimum eventually. IF but really IF i ever have the motivation to go throught the pain of trying again to fix iOS 14+ built executables and suceed, I will upload updated script here, otherwise **this repo is dead** or may update the script to support updated version of the protector.

## Script ##

### Status
| Game           | Working|
|----------------|--------|
| Brawl Stars    | ❌ No  |
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
  3. Open Terminal app, use the `cd` command to open that folder in your terminal, example my files are in `C:\protector\Supercell-jailbreak` enter in terminal  (cd "C:\protector\Supercell-jailbreak")
  4. Execute this command in terminal: `python3 sc_protector_file_parser.py --rebuild --game "replace this text under string to the executable file name, keep the quotes"`. See Troubleshooting below to see what is the executable filename.
  
  When the prompt ask you to drag and drop the IPA, take the .ipa file with your mouse and directly drop it in the terminal, remove any spaces created. If your directory path contains special characters such as spaces, `éçà` ...etc. you must put quotes `"` between the path automatically written by your terminal. 

  5. Use your favorite method to install the output.ipa in the same directory as the script
  6. Well it should work hopefully, enjoy!

  ### Usage with M chip series Mac
  0. Download and extract zip or clone the repository `git clone https://github.com/risporce/Supercell-jailbreak.git` then `cd Supercell-jailbreak`
  1. Decrypt and extract the game IPA from your device and upload it to your computer. |   Alternatively, download the decrypted IPA package from some site
  2. Install the IPA application on your Mac and disable protections such as SIP
  3. Open Terminal app, use the `cd` command to open that folder in your terminal, example my files are in `C:\protector\Supercell-jailbreak` enter in terminal  (cd "C:\protector\Supercell-jailbreak")
  4. Execute this command in terminal: `python3 sc_protector_file_parser.py --mac --rebuild --game "replace this text under string to the executable file name, keep the quotes"`. See Troubleshooting below to see what is the executable filename.
  
   When the prompt ask you to drag and drop the IPA, take the .ipa file with your mouse and directly drop it in the terminal, remove any spaces created. If your directory path contains special characters such as spaces, `éçà` ...etc. you must put quotes `"` between the path automatically written by your terminal. 

  5. Use your favorite method to install the output.ipa in the same directory as the script
  6. Well it should work hopefully, enjoy!


## Troubleshooting

### What is the executable filename?
if you don't know what is the exact executable filename for the game, here's the list so you don't have to extract the ipa just to see what it's name.

Brawl Stars: laser

Squad Busters: Squad

Clash of Clans: Clash of Clans

Clash Royale: Clash_Royale

Hay Day: Hay Day

Boom Beach: Boom Beach


### Frida:


#### Frida Device
USB not recognized? Sometimes frida have difficulties getting the correct device to open via USB.
But before attempting this step, make sure you have trusted the device with the computer and that your device is charging, if not, then your cable is most likely broken.

If you have trusted the device and it's charging: in terminal execute this command:
`frida-ls-devices`
you should see a few devices including your iOS devices. If not try with Frida host parameters see below for more information

If you see your iOS device with `frida-ls-devices` then perfect, the script now support entering your device entering your device UUID to make the patch. Your device UUID appears as "Id" in the output of the `frida-ls-devices` command in the first column.
You can execute this command in terminal:

`python3 sc_protector_file_parser.py --rebuild --game "replace this text under string to the executable file name, keep the quotes" --device UUID` (replace UUID with the actual device UUID previously found.)


#### Frida Host

This is on the very last resort as it's extremely unstable even on my device it doesn't work but this method does work for others so give it a try if you are really struck.

1. Open your package manager and install NewTerm3 Beta (or another terminal of your choice). After that still from your iOS device open settings and start by making sure you are on the very same wifi as your computer, then in your network properties take note of the IP Address as you're gonna need it.

2. Open the previously downloaded terminal and execute these commands one after another: `su` ; then for the password type `alpine` if you have not changed the default password; then `frida-server -l 192.168.XX.XX` replace the "X's" with the actual ip address you previously noted from step 1. Normally nothing will output which is the expected behavior.

3. Now from your computer execute this command :

`python3 sc_protector_file_parser.py --rebuild --game "replace this text under string to the executable file name, keep the quotes" --host "192.168.XX.XX"` replace the "X's" with the actual ip address you previously noted from step 1.

Hopefully this should work, but if you get such error: `"Failed to spawn: unable to access process with pid 1 from the current user account"`, I don't have a solution for that right now, sorry. Try to fix your USB setup for better result.

### Python:
 Missing packages even after installing them ? You may have multiples instances of Python installed on your system, use `python3 -m pip install package_name` where you replace package_name with the actual package name and run `python3 sc_protector_file_parser.py ...` (line from step 6)

 ### Crash after patching
Don't reinstall the IPA from step 1, make sure to replace the current executable in the folder with the patched one from the script, then compress back the Payload folder into .zip and rename to .ipa to make a whole new patched IPA and install with a tool like [Sideloadly](https://sideloadly.io/), [Trollstore](https://trollstore.app/) ...etc.


## Contact ##
The main way to contact me if you have any question is throught the following social medias:

Discord and Telegram: risporce

### Enjoy being able to play again supercell games! ###
This content is not affiliated with, endorsed, sponsored, or specifically approved by Supercell and Supercell is not responsible for it. For more information see: [Supercell's Fan Content Policy](https://supercell.com/en/fan-content-policy/) and also [Supercell's Term of Service](https://supercell.com/en/terms-of-service/)
