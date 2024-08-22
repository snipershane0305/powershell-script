write-host "must run with powershell 7" -ForegroundColor red
pause
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

write-host "Disabling powershell telemetry" -ForegroundColor red
[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine') #disables powershell 7 telemetry (sends data without benefit)

write-host "disabling hibernation" -ForegroundColor red
powercfg.exe /hibernate off #disables hiberation (writes memory to disk and saves power at cost of performance, only useful for laptops)

write-host "enabling memory compression" -ForegroundColor red
Enable-MMAgent -mc #enabled memory compression (saves some memory but takes cpu cycles to compress and uncompress the memory)

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

write-host "applying registry file" -ForegroundColor red
reg import .\registry.reg

write-host "done" -ForegroundColor red
pause
