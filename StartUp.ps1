if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

write-host "updating system" -ForegroundColor red
winget source update
winget install Microsoft.VCRedist.2005.x64
winget install Microsoft.VCRedist.2008.x64
winget install Microsoft.VCRedist.2010.x64
winget install Microsoft.VCRedist.2012.x64
winget install Microsoft.VCRedist.2013.x64
winget install Microsoft.VCRedist.2015+.x64
winget install Microsoft.VCLibs.Desktop.14
winget install Microsoft.DotNet.Runtime.3_1
winget install Microsoft.DotNet.Runtime.5
winget install Microsoft.DotNet.Runtime.6
winget install Microsoft.DotNet.Runtime.7
winget install Microsoft.DotNet.Runtime.8
winget install Microsoft.DotNet.Runtime.Preview
winget install Microsoft.DotNet.DesktopRuntime.3_1
winget install Microsoft.DotNet.DesktopRuntime.5
winget install Microsoft.DotNet.DesktopRuntime.6
winget install Microsoft.DotNet.DesktopRuntime.7
winget install Microsoft.DotNet.DesktopRuntime.8
winget install Microsoft.DotNet.DesktopRuntime.Preview
winget install Microsoft.DotNet.AspNetCore.3_1
winget install Microsoft.DotNet.AspNetCore.5
winget install Microsoft.DotNet.AspNetCore.6
winget install Microsoft.DotNet.AspNetCore.7
winget install Microsoft.DotNet.AspNetCore.8
winget install Microsoft.DotNet.AspNetCore.Preview
winget install Microsoft.AppInstaller
winget install Logitech.OnboardMemoryManager
winget install Microsoft.PowerShell
winget install Alex313031.Thorium.AVX2
winget install 7zip.7zip
winget install Discord.Discord
winget install Guru3D.Afterburner
winget install Valve.Steam
winget install EclipseAdoptium.Temurin.21.JDK
winget install PrismLauncher.PrismLauncher
winget install OBSProject.OBSStudio
winget install Andersama.obs-asio
winget install Open-Shell.Open-Shell-Menu
winget install VideoLAN.VLC
winget install Spotify.Spotify
winget install PuTTY.PuTTY
winget install ebkr.r2modman
winget install BleachBit.BleachBit
winget install RevoUninstaller.RevoUninstaller
winget install IObit.IObitUnlocker
winget install Microsoft.Sysinternals.Autoruns
winget install OPAutoClicker.OPAutoClicker
winget install Ookla.Speedtest.CLI
winget install HandBrake.HandBrake
winget install Microsoft.Edge
winget install Microsoft.EdgeWebView2Runtime

write-host "cleaning system" -ForegroundColor red
cleanmgr.exe /d C: /VERYLOWDISK
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
Get-ChildItem -Path "C:\Windows\Temp\" *.* -Recurse | Remove-Item -Force -Recurse
Get-ChildItem -Path "$env:TEMP" *.* -Recurse | Remove-Item -Force -Recurse
C:\Users\me\AppData\Local\BleachBit\bleachbit_console.exe -c deepscan.backup deepscan.ds_store deepscan.thumbs_db deepscan.tmp deepscan.vim_swap_root deepscan.vim_swap_user google_chrome.cache google_chrome.cookies google_chrome.dom google_chrome.form_history google_chrome.history google_chrome.passwords google_chrome.search_engines google_chrome.session google_chrome.site_preferences google_chrome.sync google_chrome.vacuum google_earth.temporary_files google_toolbar.search_history internet_explorer.cache internet_explorer.cookies internet_explorer.downloads internet_explorer.forms internet_explorer.history internet_explorer.logs java.cache microsoft_edge.cache microsoft_edge.cookies microsoft_edge.dom microsoft_edge.form_history microsoft_edge.history microsoft_edge.passwords microsoft_edge.search_engines microsoft_edge.session microsoft_edge.site_preferences microsoft_edge.sync microsoft_edge.vacuum system.clipboard system.logs system.memory_dump system.muicache system.prefetch system.recycle_bin system.tmp system.updates teamviewer.logs teamviewer.mru windows_defender.backup windows_defender.history windows_defender.logs windows_defender.quarantine windows_defender.temp windows_explorer.mru windows_explorer.run windows_explorer.search_history windows_explorer.shellbags windows_explorer.thumbnails windows_media_player.cache windows_media_player.mru winrar.history winrar.temp winzip.mru wordpad.mru yahoo_messenger.cache yahoo_messenger.chat_logs yahoo_messenger.logs zoom.cache zoom.logs zoom.recordings

write-host "releasing memory" -ForegroundColor red
C:\memreduct.exe -clean:full

#paste newest powershell script here and change registry file location

write-host "Disabling powershell telemetry" -ForegroundColor red
[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine') #disables powershell 7 telemetry (sends data without benefit)

write-host "disabling hibernation" -ForegroundColor red
powercfg.exe /hibernate off #disables hiberation (writes memory to disk and saves power at cost of performance, only useful for laptops)

write-host "enabling memory compression" -ForegroundColor red
Enable-MMAgent -mc #enabled memory compression (saves some memory but takes cpu cycles to compress and uncompress the memory)

write-host "removing home and gallery from explorer" -ForegroundColor red
REG DELETE \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}\" /f
REG DELETE \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}\" /f
REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /f /v \"LaunchTo\" /t REG_DWORD /d \"1\"

write-host "applying fsutil settings" -ForegroundColor red
fsutil behavior set disablecompression 1  #disables ntfs compression
fsutil behavior set encryptpagingfile 0   #disables encryption on the pagefile.sys file which is disk space that is used as memory and is less performant
fsutil behavior set mftzone 4             #sets the mft zone to 800MB (the mft zone stores entries about everything about every file)
fsutil behavior set quotanotify 7200      #sets quota report to 2 hours
fsutil behavior set disabledeletenotify 0 #enables trim on disk
fsutil behavior set disableLastAccess 1   #disables last access time stamp on directories
fsutil behavior set disable8dot3 1        #unused file type

write-host "applying bcdedits" -ForegroundColor red
bcdedit /set useplatformtick yes    #uses a hardware timer for ticks which is most reliable
bcdedit /set disabledynamictick yes #disables platform tick from being dynamic which is more stable
bcdedit /set useplatformclock no    #disable use of platform clock which is less stable
bcdedit /set tscsyncpolicy enhanced #sets time stamp counter synchronization policy to enhanced
bcdedit /set MSI Default            #sets the use of interrupt type to message signaled interrupts which was added for PCI 2.2 which is newer than the old line based interrupts
bcdedit /set x2apicpolicy Enable    #uses the newer apic mode
bcdedit /deletevalue uselegacyapicmode | Out-Null #deletes old legacy apic mode
bcdedit /set usephysicaldestination no            #disables physical apic for x2apicpolicy
bcdedit /set usefirmwarepcisettings no            #disables BIOS PCI resources
bcdedit /set linearaddress57 OptOut
bcdedit /set nx OptIn                             #enables data execution prevention which improves security

write-host "applying network settings" -ForegroundColor red
netsh int tcp set global rss = enabled         #enables recieve side scaling which lets more than one cpu core handle tcp
netsh int tcp set global prr= enable           #helps a tcp connection from recovering from packet loss quicker for less latency
netsh int tcp set global initialRto=2000       #lowers initial retransmition timout which helps latency
netsh int tcp set global ecncapability= enable #ecncapability will only be used if both the client and server support it
netsh int tcp set global rsc= disable          #disables receive segment coalescing which makes small packets combine, this helps with computing many packets but at the cost of latency
netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2         #sets tcp congestion provider to bbr2 which is much newer and causes less packet loss
netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2       #sets tcp congestion provider to bbr2 which is much newer and causes less packet loss
netsh int tcp set supplemental Template=Compat CongestionProvider=bbr2           #sets tcp congestion provider to bbr2 which is much newer and causes less packet loss
netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2 #sets tcp congestion provider to bbr2 which is much newer and causes less packet loss
netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2   #sets tcp congestion provider to bbr2 which is much newer and causes less packet loss
netsh int ipv4 set dynamicport tcp start=1025 num=64511
netsh int ipv4 set dynamicport udp start=1025 num=64511
netsh int teredo set state disabled #disables teredo
Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled   #disables more coalescing
Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled #disables more coalescing
Set-NetOffloadGlobalSetting -Chimney Disabled #forces cpu to handle network instead of NIC
Enable-NetAdapterChecksumOffload -Name *      #forces cpu to handle network instead of NIC
Set-NetTCPSetting -SettingName InternetCustom -InitialCongestionWindow 10 #raises the initial congestion window which makes a tcp connection start with more bandwidth
Disable-NetAdapterLso -Name * #disables large send offload which uses NIC instead of cpu (using the cpu for handing network tasks can help latency if your cpu is strong enough)

write-host "setting dns" -ForegroundColor red
Set-DnsClientServerAddress -interfaceindex 1 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 2 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 3 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 4 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 5 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 6 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 7 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 8 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 9 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 10 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 11 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 12 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 13 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 14 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 15 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 16 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 17 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 18 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 19 -serveraddresses ("9.9.9.9","1.1.1.1")
Set-DnsClientServerAddress -interfaceindex 20 -serveraddresses ("9.9.9.9","1.1.1.1")

write-host "setting services" -ForegroundColor red
sc config DiagTrack start= disabled
sc config DispBrokerDesktopSvc start= disabled
sc config iphlpsvc start= disabled
sc config DsmSvc start= disabled
sc config Spooler start= disabled
sc config wlidsvc start= disabled
sc config RmSvc start= disabled
sc config MapsBroker start= disabled
sc config lmhosts start= disabled
sc config VSS start= disabled
sc config TokenBroker start= disabled
sc config DusmSvc start= demand
sc config Dhcp start= demand
sc config DPS start= demand
sc config ShellHWDetection start= demand
sc config SysMain start= demand
sc config Themes start= demand
sc config ProfSvc start=demand
sc config EventLog start= demand
sc config LanmanWorkstation start= demand
sc config UsoSvc start= demand
sc config WSearch start= demand
sc config CDPSvc start= demand
sc config edgeupdate start= demand
sc config PcaSvc start= demand
sc config StorSvc start= demand

write-host "applying registry file" -ForegroundColor red
reg import C:\registry.reg

write-host "done" -ForegroundColor red
pause