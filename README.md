# Supercell-jailbreak

I didn't think I would have to mention it but recently all my dms has been about those `.ipas` being a mod/hack so to make things clear:

## THIS IS NOT A HACK OR A MOD and I DO NOT support development of exploits in Supercell games. This is just a simple patch to allow people on jailbroken IDevices to play Supercell games

## Notes: ##

I always try to update as fast as possible when an update is required

If you encounter a crash during playing, startup or whenever, open an issue or contact me with the crash logs, i will try to resolve the issue.


## Download ##

Since the main executable has been modified to apply the patches, the IPA needs to be resign by a tool like [Sideloadly](https://sideloadly.io/) or If your iOS supports [TrollStore](https://github.com/opa334/TrollStore) you can also use that, therefore installing with filza can cause the game to crash.

Clash of Clans 16.517.11 [https://www.mediafire.com/file/4q9y25tix82yocx/Clash_of_Clans16.517.11NoJb.ipa/file](https://www.mediafire.com/file/4q9y25tix82yocx/Clash_of_Clans16.517.11NoJb.ipa/file)

Brawl Stars 57.325 [https://www.mediafire.com/file/dtev6981ol4j7du/Brawl_Stars57.325NoJb.ipa/file](https://www.mediafire.com/file/dtev6981ol4j7du/Brawl_Stars57.325NoJb.ipa/file)

Clash Royale 8.254.22 : (new format, will take a lot of time to figure out new fix for it)

Hay Day 1.63.204 [https://www.mediafire.com/file/29xd5q0pmwnkdoz/Hay_Day1.63.204NoJb.ipa/file](https://www.mediafire.com/file/29xd5q0pmwnkdoz/Hay_Day1.63.204NoJb.ipa/file)

Boom Beach 54.70 [https://www.mediafire.com/file/ybxouicn544sgki/Boom_Beach54.70NoJb.ipa/file](https://www.mediafire.com/file/ybxouicn544sgki/Boom_Beach54.70NoJb.ipa/file)

Squad Busters 7.301: [https://www.mediafire.com/file/kez196oh07egkwf/Squad_Busters7.301NoJb.ipa/file](https://www.mediafire.com/file/kez196oh07egkwf/Squad_Busters7.301NoJb.ipa/file)

## Script ##
Note to every developer: I made this script while I had not the slightest idea of what Mach-O executables are, variable names are very unrepresentative and may be even misleading.

While i know now the real name Mach-o sections, names ...etc i didn't at the time, and I did not rewrite the whole script variable names just for this. It would be a waste of time.

So why am i opening this script now ? Well I start to be tired of having to quickly update all the time the ipas, it takes quite some time and motivation to do this, especially when games like Boom Beach have 5 optional updates in a couple days and forcing everyone to download the new version right away or they can't play.

Another reason is that I don't have time at all anymore to understand the protector and fix the data accordingly. Clash Royale switched to another format of data to be fixed, while it looks easier than the previous one, I don't have any time to spend into it. I open this script hoping another developer could continue, improve it, maybe finally making a dev tweak for Supercell games? It would be awesome!.

And lastly, for those who shown me their concerns about me modifying the ipa and that maybe i was maybe injecting malicious code, now you will see what was really the patch and be able to even do it yourself !


  ### Prequisites  
  -  Python 3 https://www.python.org/ (tested with 3.12): download for your OS 
  -  Frida https://github.com/frida/frida : pip install frida and frida-server on your iOS device
  -  MachoLib https://macholib.readthedocs.io/en/latest/ : pip install machlib

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

## FAQ ##

####  Why do you make it in form of an `.ipa` and not a `deb` tweak? ####
At this moment, i don't have enough information about the jailbreak detection to make a working `deb` tweak to patch the jailbreak detection

#### Is there a chance of getting banned from this? #### 
While I have never been banned from using modded `.ipas` which I do for 2 years already, other popular mods on android got massive player ban so I can only say USE THIS AT YOUR OWN RISK, i am not responsible if your account is getting banned. But hey, if you arrived here, it's because you couldn't play anyway right ;)

#### Why are in app purchases blocked ? ####
Any repackaged `.ipa` and the same applies for Android with repackaged `apks`, they has not been officially installed from the store and in app purchases are disabled. Hopefully with Supercell there is a workaround and it's to use their store here [https://store.supercell.com/](https://store.supercell.com/) to make purchases to your account (and it have a better value than the real game purchase)

#### The app doesn't work on Mac? ####
Supercell does not officially supports playing on MacOS computers, while some people have told me they managed to play on their Mac, It is possible that some of these `ipas` just doesn't work on MacOS and there's nothing i can do.

#### Bugs in the game: ####
I am not Supercell developer nor a game developer, i don't modify anything in the executable that can cause a crash/bug in the middle of the game, the protection I remove is only being done during the black screen state of the game. Therefore, i can't fix bugs that happens in the game, that's to Supercell to fix them.

#### The game reset it's progress every time I open it why? how to fix it? ####
At very rare occasion that even happens to me from time to time, singing methods just kind of mess up something in the installation and therefore the client seems to be unable to locate it's saved files.

A fix to this is to use Apps Manager (tigisoftware repo) locate your game in the list and press Wipe. Then delete and reinstall the game . This should fix the problem.

### Enjoy being able to play again supercell games! ###
This content is not affiliated with, endorsed, sponsored, or specifically approved by Supercell and Supercell is not responsible for it. For more information see: [Supercell's Fan Content Policy](https://supercell.com/en/fan-content-policy/) and also [Supercell's Term of Service](https://supercell.com/en/terms-of-service/)
