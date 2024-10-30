# Supercell-jailbreak

## Notes: ##
# **No more ipas will be uploaded here**

So while other games are still easily fixable by the script with updated offset for the protector, Clash Royale on the other hand requires a rebuilding of LC_DYLD_CHAINED_FIXUPS. This will come to other games soon as they all will update to support iOS 14 as minimum eventually. IF but really IF i ever have the motivation to go throught the pain of trying again to fix iOS 14+ built executables and suceed, I will upload updated script here, otherwise **this repo is dead** or may update the script to support updated version of the protector.

## Script ##
### **Not working with the new Clash Royale update, they shipped updated protectors, each of them a different build and patched this method i was using to patch the games for more than a year**

Note to every developer: I made this script while I had not the slightest idea of what Mach-O executables are, variable names are very unrepresentative and may be even misleading.

While i know now the real name Mach-o sections, names ...etc i didn't at the time, and I did not rewrite the whole script variable names just for this. It would be a waste of time.

So why am i opening this script now ? Well I start to be tired of having to quickly update all the time the ipas, it takes quite some time and motivation to do this, especially when games like Boom Beach have 5 optional updates in a couple days and forcing everyone to download the new version right away or they can't play.

Another reason is that I don't have time at all anymore to understand the protector and fix the data accordingly. Clash Royale switched to another format of data to be fixed, while it looks easier than the previous one, I don't have any time to spend into it. I open this script hoping another developer could continue, improve it, maybe finally making a dev tweak for Supercell games? It would be awesome!.

And lastly, for those who shown me their concerns about me modifying the ipa and that maybe i was maybe injecting malicious code, now you will see what was really the patch and be able to even do it yourself !


  ### Prequisites  
  -  Python 3 https://www.python.org/ (tested with 3.12): download for your OS 
  -  Frida https://github.com/frida/frida : pip install frida and frida-server on your iOS device
  -  MachoLib https://macholib.readthedocs.io/en/latest/ : pip install macholib

  ### Usage
  1. Extract the game ipa and upload it to your computer
  2. Connect your device to your computer via USB cable
  3. From your computer, use any zip unarchiver like PeaZip or 7Zip to extract the IPA
  4. Place the main executable file at the same directory as the script
  5. In terminal, go to the directory of where your files are (cd path/to/folder)
  6. Execute this command: `python3 sc_protector_file_parser.py --game "replace this text under string to the executable file name, keep the quotes"`
  7. If you moved the main executable, put it back into the IPA and replace the original one.
  8. Compress the Payload folder into .zip and rename to .ipa
  9. Use your favorite method to install the .IPA
  10. Well it should work hopefully, enjoy!

## Contact ##
The main way to contact me if you have any question is throught the following social medias:

Discord and Telegram: risporce

### Enjoy being able to play again supercell games! ###
This content is not affiliated with, endorsed, sponsored, or specifically approved by Supercell and Supercell is not responsible for it. For more information see: [Supercell's Fan Content Policy](https://supercell.com/en/fan-content-policy/) and also [Supercell's Term of Service](https://supercell.com/en/terms-of-service/)
