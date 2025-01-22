This repository is for my powershell script that was made to configure a bunch of settings to improve the privacy and performance for windows and to keep these settings because windows loves reverting changes randomly.
This script changes ALOT so make sure this wont brick anything you need.

Also check the wiki section for more information about these configurations. https://github.com/snipershane0305/powershell-script/wiki

put the StartUpScript.ps1 file in C:\Users\YOUR USERNAME HERE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup directory, anything in this directory will start when windows boots and logins

then put the PowershellScript.ps1, AppUpdate.ps1, memreduct.exe, SetTimerResolution.exe, and registry.reg into the "C:\" directory

The AppUpdate.ps1 file uses winget (package manager in windows) to update programs, consider changing the non dependincy programs and pin any you dont want to update, pinning a package makes a package bypass the "winget update --all" command

this will auto start every time you boot into windows, this script sets a bunch of settings and does some maintenance and improves privacy and security.
this may improve some system performance and network performance by setting more performant configurations and adding more overhead in windows but you WONT see big performance impact in GAMES. 
video game performance is more impacted by your specific hardware and clock speeds. consider overclocking/undervolting and better cooling solutions for better performance in GAMES!
