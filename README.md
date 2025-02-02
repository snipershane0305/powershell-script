This repository is for my powershell script that was made to configure a bunch of settings to improve the privacy and performance of windows and to keep these settings because windows loves reverting changes randomly.
This script changes ALOT so make sure this wont brick anything you need. You will need to set ExecutionPolicy to unrestricted with `Set-ExecutionPolicy unrestricted` and maybe add it to your exculsions in defender

Also check the wiki section for more information about these configurations. https://github.com/snipershane0305/powershell-script/wiki

Put the StartUpScript.ps1 file in `C:\Users\YOUR USERNAME HERE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` anything in this directory will start when windows boots and logins.

Then put the PowershellScript.ps1, memreduct.exe, and SetTimerResolution.exe into the "C:" directory or whatever drive windows is installed on

This will auto start every time you boot into windows, this script sets a bunch of settings and does some maintenance and improves privacy and security.

This may improve some system performance and network performance by setting more performant configurations and lowering the system resources at idle but you WONT see big performance impact in GAMES. 
video game performance is more impacted by your specific hardware and clock speeds. Consider overclocking/undervolting and better cooling solutions for better performance in GAMES!
