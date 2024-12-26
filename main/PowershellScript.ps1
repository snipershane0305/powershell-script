if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
net stop wuauserv
net stop UsoSvc
net stop bits
net stop DoSvc
net stop sysmain
write-host "releasing memory" -ForegroundColor red
C:\memreduct.exe -clean:full
Start-Sleep -Seconds 10
taskkill /im memreduct.exe
write-host "setting timer resolution to 0.5" -ForegroundColor red #changes the timer resolution to a lower value for slightly lower latency
$process = "C:\SetTimerResolution.exe"
$flags = "--resolution 5050 --no-console"
start-process $process $flags

write-host "cleaning system" -ForegroundColor red
cleanmgr.exe /d C: /VERYLOWDISK
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
Get-ChildItem -Path "$env:TEMP" *.* -Recurse | Remove-Item -Force -Recurse
Get-ChildItem -Path "C:\Windows\Temp\" *.* -Recurse | Remove-Item -Force -Recurse

write-host "updating system" -ForegroundColor red
#updates microsoft defender
C:\"Program Files"\"Windows Defender"\MpCmdRun -SignatureUpdate
Update-MpSignature -UpdateSource MicrosoftUpdateServer
#starts needed windows update services
sc config wuauserv start= demand
sc config UsoSvc start= demand
sc config bits start=demand
net start bits
net start wuauserv  
net start usosvc
start-sleep -seconds 2
#runs windows update
Install-Module PSWindowsUpdate -Confirm:$false
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
start-sleep -seconds 2
net stop wuauserv
net stop UsoSvc
net stop bits

write-host "merging registry file" -ForegroundColor red
#merges the registry.reg registry file!
reg import c:\registry.reg

write-host "Disabling powershell telemetry" -ForegroundColor red
#disables powershell 7 telemetry (sends data without benefit)
[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')

write-host "removing home and gallery from explorer" -ForegroundColor red
REG DELETE \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}\" /f #removes buttons from explorer i dont use
REG DELETE \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}\" /f #removes buttons from explorer i dont use 
REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /f /v \"LaunchTo\" /t REG_DWORD /d \"1\" #removes buttons from explorer i dont use

write-host "disabling hibernation" -ForegroundColor red
powercfg.exe /hibernate off #disables hiberation (writes memory to disk and saves power at cost of performance, only useful for laptops)

write-host "enabling memory compression" -ForegroundColor red
Enable-MMAgent -mc #enabled memory compression (saves some memory but takes cpu cycles to compress and uncompress the memory)

write-host "applying fsutil settings" -ForegroundColor red
fsutil behavior set disablecompression 1 #disables ntfs compression which isnt effective
fsutil behavior set encryptpagingfile 0 #disables encryption on the pagefile.sys file which is disk space that is used as memory and is less performant
fsutil behavior set mftzone 4 #sets the mft zone to 800MB (the mft zone stores entries about everything about every file)
fsutil behavior set quotanotify 7200 #sets quota report to 2 hours
fsutil behavior set disabledeletenotify 0 #enables trim on disk
fsutil behavior set disableLastAccess 1 #disables last access time stamp on directories
fsutil behavior set disable8dot3 1 #unused

write-host "trimming C: drive" -ForegroundColor red
$systemDrive = (Get-WmiObject -Class Win32_OperatingSystem).SystemDrive
Optimize-Volume -DriveLetter $systemDrive -ReTrim
Optimize-Volume -DriveLetter $systemDrive -SlabConsolidate

write-host "applying bcdedits" -ForegroundColor red
bcdedit /set useplatformtick yes #uses a hardware timer for ticks which is most reliable
bcdedit /set disabledynamictick yes #disables platform tick from being dynamic which is more stable
bcdedit /set useplatformclock no #disable use of platform clock which is less stable
bcdedit /set tscsyncpolicy enhanced #sets time stamp counter synchronization policy to enhanced
bcdedit /set MSI Default #sets the use of interrupt type to message signaled interrupts which was added for PCI 2.2 which is newer than the old line based interrupts
bcdedit /set x2apicpolicy Enable #uses the newer apic mode
bcdedit /deletevalue uselegacyapicmode | Out-Null #deletes old legacy apic mode
bcdedit /set usephysicaldestination no #disables physical apic for x2apicpolicy
bcdedit /set usefirmwarepcisettings no #disables BIOS PCI resources
bcdedit /set linearaddress57 OptOut #disables 57 bit virtual memory and keeps it at 48 bit (you dont need 128 petabytes of virtual memory!)
bcdedit /set nx OptIn #enables data execution prevention which improves security

write-host "applying network settings" -ForegroundColor red
netsh int tcp set global rss = enabled #enables recieve side scaling which lets more than one core handle tcp
netsh int tcp set global prr= enable #helps a tcp connection from recovering from packet loss quicker for less latency
netsh int tcp set global nonsackrttresiliency=enabled #improves the reliability of tcp over high-latency networks
netsh int tcp set global ecncapability= enable #ecncapability will notify if there is congestion to help packet loss, will only be used if both the client and server support it
netsh int tcp set global rsc= disable #disables receive segment coalescing which makes small packets combine, this helps with computing many packets but at the cost of latency
netsh int teredo set state disabled #disables teredo (used for ipv6)
netsh int ipv4 set dynamicport tcp start=1025 num=64511 #sets the ports tcp can use
netsh int ipv4 set dynamicport udp start=1025 num=64511 #sets the ports tcp can use
netsh int tcp set supplemental template=internet enablecwndrestart= enabled #enables cwndreset which help the congestion window to change faster allowing for more through put quicker
netsh int tcp set supplemental template=custom enablecwndrestart= enabled #enables cwndreset which help the congestion window to change faster allowing for more through put quicker
netsh int tcp set supplemental template=compat enablecwndrestart= enabled #enables cwndreset which help the congestion window to change faster allowing for more through put quicker
netsh int tcp set supplemental template=datacenter enablecwndrestart= enabled #enables cwndreset which help the congestion window to change faster allowing for more through put quicker
netsh int tcp set supplemental Template=Internet CongestionProvider=ctcp #sets tcp congestion provider to ctcp which is better for latency and stability
netsh int tcp set supplemental Template=custom CongestionProvider=ctcp #sets tcp congestion provider to ctcp which is better for latency and stability
netsh int tcp set supplemental Template=compat CongestionProvider=ctcp #sets tcp congestion provider to ctcp which is better for latency and stability
netsh int tcp set supplemental Template=datacenter CongestionProvider=ctcp #sets tcp congestion provider to ctcp which is better for latency and stability

Set-NetTCPSetting -SettingName internet -minrto 300 #lowers initial retransmition timout which helps latency
Set-NetTCPSetting -SettingName Internetcustom -minrto 300 #lowers initial retransmition timout which helps latency
Set-NetTCPSetting -SettingName compat -minrto 300 #lowers initial retransmition timout which helps latency
Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled #unneeded feature
Set-NetTCPSetting -SettingName internetcustom -ScalingHeuristics disabled #unneeded feature
Set-NetTCPSetting -SettingName datacentercustom -ScalingHeuristics disabled #unneeded feature
Set-NetTCPSetting -SettingName compat -ScalingHeuristics disabled #unneeded feature
Set-NetTCPSetting -SettingName datacenter -ScalingHeuristics disabled #unneeded feature
Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2 #sets max retransmitions to 2!
Set-NetTCPSetting -SettingName internetcustom -MaxSynRetransmissions 2 #sets max retransmitions to 2!
Set-NetTCPSetting -SettingName datacentercustom -MaxSynRetransmissions 2 #sets max retransmitions to 2!
Set-NetTCPSetting -SettingName compat -MaxSynRetransmissions 2 #sets max retransmitions to 2!
Set-NetTCPSetting -SettingName datacenter -MaxSynRetransmissions 2 #sets max retransmitions to 2!
Set-NetTCPSetting -SettingName Internet -InitialCongestionWindow 10 #raises the initial congestion window which makes a tcp connection start with more bandwidth
Set-NetTCPSetting -SettingName Internetcustom -InitialCongestionWindow 10 #raises the initial congestion window which makes a tcp connection start with more bandwidth
Set-NetTCPSetting -SettingName datacenter -InitialCongestionWindow 10 #raises the initial congestion window which makes a tcp connection start with more bandwidth
Set-NetTCPSetting -SettingName datacenter -InitialCongestionWindow 10 #raises the initial congestion window which makes a tcp connection start with more bandwidth

Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled  #disables more coalescing
Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled #disables more coalescing
Set-NetOffloadGlobalSetting -Chimney Disabled #forces cpu to handle network instead of NIC
Enable-NetAdapterChecksumOffload -Name * #forces cpu to handle network instead of NIC
Disable-NetAdapterLso -Name * #disables large send offload which uses NIC instead of cpu (using the cpu for handing network tasks can help latency if your cpu is strong enough)

write-host "setting dns" -ForegroundColor red
#sets dns server to quad9's secure and ENC capatible dns
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
foreach ($adapter in $adapters) {
    $interfaceIndex = $adapter.ifIndex
    Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ServerAddresses "9.9.9.11"
}

write-host "setting defender settings" -ForegroundColor red
set-mppreference -CloudBlockLevel default #enables basic cloud based protection
set-mppreference -CloudExtendedTimeout 50 #blocks file for 50 seconds for the cloud to scan it
set-mppreference -AllowSwitchToAsyncInspection $true #performance optimization
set-mppreference -DisableArchiveScanning $false #enabled scanning of achived files
set-mppreference -DisableBehaviorMonitoring $false #enabled behaviormonitoring (realtime protection)
set-mppreference -DisableCatchupFullScan $true #disables force scan if it misses a scheduled scan
set-mppreference -DisableCatchupQuickScan $true #disables force scan if it misses a scheduled scan
set-mppreference -DisableEmailScanning $true #disables emailscanning
set-mppreference -DisableIOAVProtection $false #enables scanning of downloaded files
set-mppreference -DisableNetworkProtectionPerfTelemetry $true #disables the sending of performance data to microsoft
Set-MpPreference -DisableCoreServiceTelemetry $true #disables the sending of performance data to microsoft
set-mppreference -DisableRealtimeMonitoring $false #enables realtime monitoring
set-mppreference -DisableRemovableDriveScanning $false #enables scanning removable devives (like flash drives)
set-mppreference -DisableRestorePoint $true #disables defender creating restore points (i have never had a restore point fix an issue!)
set-mppreference -EnableLowCpuPriority $true #lowers the priority of defender
set-mppreference -EnableNetworkProtection enabled #enables network protection
set-mppreference -MAPSReporting 0 #disables the sending of data to microsoft (this doesnt disable MAPS!)
set-mppreference -RandomizeScheduleTaskTimes $false #disables random scans
set-mppreference -RemediationScheduleDay 8 #disables schedule scans
set-mppreference -ScanAvgCPULoadFactor 90 #allows defender to use 90% cpu usage when running a scan
set-mppreference -ScanOnlyIfIdleEnabled $false #disables scans when idle
set-mppreference -ScanParameters 1 #sets schedule scans to quick scans
set-mppreference -ScanScheduleDay 8 #disables schedule scans
set-mppreference -SubmitSamplesConsent 2 #disables sending samples to microsoft
#excludes some safe default paths to reduce defender scan time
Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\Temp\NVIDIA Corporation\NV_Cache"
Add-MpPreference -ExclusionPath $env:PROGRAMDATA"\NVIDIA Corporation\NV_Cache"
Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\AMD\DX9Cache"
Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\AMD\DxCache"
Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\AMD\DxcCache"
Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\AMD\OglCache"
Add-MpPreference -ExclusionPath $env:windir"\SoftwareDistribution\Datastore\Datastore.edb"
Add-MpPreference -ExclusionPath $env:windir"\SoftwareDistribution\Datastore\Logs\Edb*.jrs"
Add-MpPreference -ExclusionPath $env:windir"\SoftwareDistribution\Datastore\Logs\Edb.chk"
Add-MpPreference -ExclusionPath $env:windir"\SoftwareDistribution\Datastore\Logs\Tmp.edb"
Add-MpPreference -ExclusionPath $env:windir"\SoftwareDistribution\Datastore\Logs\*.log"
Add-MpPreference -ExclusionPath $env:windir"\Security\Database\*.edb"
Add-MpPreference -ExclusionPath $env:windir"\Security\Database\*.sdb"
Add-MpPreference -ExclusionPath $env:windir"\Security\Database\*.log"
Add-MpPreference -ExclusionPath $env:windir"\Security\Database\*.chk"
Add-MpPreference -ExclusionPath $env:windir"\Security\Database\*.jrs"
Add-MpPreference -ExclusionPath $env:windir"\Security\Database\*.xml"
Add-MpPreference -ExclusionPath $env:windir"\Security\Database\*.csv"
Add-MpPreference -ExclusionPath $env:windir"\Security\Database\*.cmtx"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\GroupPolicy\Machine\Registry.pol"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\GroupPolicy\Machine\Registry.tmp"
Add-MpPreference -ExclusionPath $env:userprofile"\NTUser.dat"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\sru\*.log"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\sru\*.dat"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\sru\*.chk"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\Configuration\MetaConfig.mof"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\winevt\Logs\*.evtx"
Add-MpPreference -ExclusionPath $env:windir"\apppatch\sysmain.sdb"
Add-MpPreference -ExclusionPath $env:windir"\EventLog\Data\lastalive?.dat"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\WindowsPowerShell\v1.0\Modules"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\Configuration\DSCStatusHistory.mof"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\Configuration\DSCEngineCache.mof"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\Configuration\DSCResourceStateCache.mof"
Add-MpPreference -ExclusionPath $env:SystemRoot"\System32\Configuration\ConfigurationStatus"
Add-MpPreference -ExclusionProcess ${env:ProgramFiles(x86)}"\Common Files\Steam\SteamService.exe"

write-host "setting services" -ForegroundColor red #all these sould be safe!
sc config DiagTrack start= disabled
sc config SSDPSRV start= disabled
sc config wbengine start= disabled
sc config dmwappushservice start= disabled
sc config lfsvc start= disabled
sc config DoSvc start= disabled
sc config iphlpsvc start= disabled
sc config logi_lamparray_service start= disabled
sc config edgeupdate start= disabled
sc config edgeupdatem start= disabled
sc config Spooler start= disabled
sc config DsmSvc start= disabled
sc config wercplsupport start= disabled
sc config RmSvc start= disabled
sc config RasMan start= disabled
sc config lmhosts start= disabled
sc config RemoteRegistry start= disabled
sc config SysMain start= disabled
sc config WerSvc start= disabled
sc config WSearch start= disabled
sc config MapsBroker start= disabled
sc config RasAuto start= disabled
sc config SessionEnv start= disabled
sc config TermService start= disabled
sc config UmRdpService start= disabled
sc config RetailDemo start= disabled
sc config RemoteAccess start= disabled
sc config EventSystem start= auto
sc config Dhcp start= auto
sc config nsi start= auto
sc config Power start= auto
sc config SamSs start= auto
sc config SENS start= auto
sc config ProfSvc start= auto
sc config Audiosrv start= auto
sc config AudioEndpointBuilder start= auto
sc config FontCache start= auto
sc config UserManager start= auto
sc config LanmanServer start= auto
sc config CryptSvc start= auto
sc config WlanSvc start= auto
sc config WwanSvc start= auto
sc config Wcmsvc start= demand
sc config AxInstSV start= demand
sc config DusmSvc start= demand
sc config AppReadiness start= demand
sc config ALG start= demand
sc config TokenBroker start= demand
sc config EventLog start= demand
sc config diagsvc start= demand
sc config bthserv start= demand
sc config AppMgmt start= demand
sc config wbengine start= demand
sc config PeerDistSvc start= demand
sc config COMSysApp start= demand
sc config VaultSvc start= demand
sc config Winmgmt start= demand
sc config DmEnrollmentSvc start= demand
sc config DPS start= demand
sc config TrkWks start= demand
sc config WdiServiceHost start= demand
sc config WdiSystemHost start= demand
sc config DialogBlockingService start= demand
sc config MSDTC start= demand
sc config EapHost start= demand
sc config fdPHost start= demand
sc config InventorySvc start= demand
sc config LxpSvc start= demand
sc config lltdsvc start= demand
sc config AppVClient start= demand
sc config cloudidsvc start= demand
sc config MSiSCSI start= demand
sc config MsKeyboardFilter start= demand
sc config swprv start= demand
sc config smphost start= demand
sc config InstallService start= demand
sc config DispBrokerDesktopSvc start= demand
sc config Netlogon start= demand
sc config Netman start= demand
sc config netprofm start= demand
sc config NlaSvc start= demand
sc config defragsvc start= demand
sc config WpcMonSvc start= demand
sc config PerfHost start= demand
sc config pla start= demand
sc config PlugPlay start= demand
sc config PrintNotify start= demand
sc config QWAVE start= demand
sc config TroubleshootingSvc start= demand
sc config seclogon start= demand
sc config RpcLocator start= demand
sc config SstpSvc start= demand
sc config shpamsvc start= demand
sc config ShellHWDetection start= demand
sc config SCPolicySvc start= demand
sc config SNMPTrap start= demand
sc config WiaRpc start= demand
sc config TieringEngineService start= demand
sc config TapiSrv start= demand
sc config Themes start= demand
sc config upnphost start= demand
sc config UevAgentService start= demand
sc config vds start= demand
sc config VSS start= demand
sc config WalletService start= demand
sc config SDRSVC start= demand
sc config wcncsvc start= demand
sc config Wecsvc start= demand
sc config WManSvc start= demand
sc config TrustedInstaller start= demand
sc config perceptionsimulation start= demand
sc config WpnService start= demand
sc config WinRM start= demand
sc config dot3svc start= demand
sc config AssignedAccessManagerSvc start= demand
sc config wmiApSrv start= demand
sc config LanmanWorkstation start= demand
sc config XblAuthManager start= demand
sc config XboxNetApiSvc start= demand
sc config tzautoupdate start= demand
sc config BthAvctpSvc start= demand
sc config BDESVC start= demand
sc config BTAGService start= demand
sc config camsvc start= demand
sc config autotimesvc start= demand
sc config CertPropSvc start= demand
sc config KeyIso start= demand
sc config CDPSvc start= demand
sc config DsSvc start= demand
sc config dcsvc start= demand
sc config DeviceAssociationService start= demand
sc config DeviceInstall start= demand
sc config DevQueryBroker start= demand
sc config DisplayEnhancementService start= demand
sc config EFS start= demand
sc config fhsvc start= demand
sc config FDResPub start= demand
sc config GameInputSvc start= demand
sc config GraphicsPerfSvc start= demand
sc config hidserv start= demand
sc config HvHost start= demand
sc config vmickvpexchange start= demand
sc config vmicguestinterface start= demand
sc config vmicshutdown start= demand
sc config vmicheartbeat start= demand
sc config vmicvmsession start= demand
sc config vmicrdv start= demand
sc config vmictimesync start= demand
sc config vmicvss start= demand
sc config IKEEXT start= demand
sc config SharedAccess start= demand
sc config IpxlatCfgSvc start= demand
sc config PolicyAgent start= demand
sc config KtmRm start= demand
sc config wlpasvc start= demand
sc config wlidsvc start= demand
sc config SmsRouter start= demand
sc config NaturalAuthentication start= demand
sc config NcdAutoSetup start= demand
sc config NcbService start= demand
sc config NcaSvc start= demand
sc config NetSetupSvc start= demand
sc config CscService start= demand
sc config SEMgrSvc start= demand
sc config PhoneSvc start= demand
sc config WPDBusEnum start= demand
sc config PcaSvc start= demand
sc config SensorDataService start= demand
sc config SensrSvc start= demand
sc config SensorService start= demand
sc config SCardSvr start= demand
sc config ScDeviceEnum start= demand
sc config svsvc start= demand
sc config StorSvc start= demand
sc config WarpJITSvc start= demand
sc config webthreatdefsvc start= demand
sc config WebClient start= demand
sc config WFDSConMgrSvc start= demand
sc config WbioSrvc start= demand
sc config FrameServer start= demand
sc config FrameServerMonitor start= demand
sc config WEPHOSTSVC start= demand
sc config StiSvc start= demand
sc config wisvc start= demand
sc config LicenseManager start= demand
sc config icssvc start= demand
sc config PushToInstall start= demand
sc config W32Time start= demand
sc config XboxGipSvc start= demand
sc config XblGameSave start= demand
write-host "done" -ForegroundColor red
#disables windows update services
net stop wuauserv
net stop UsoSvc
net stop bits
net stop DoSvc
net stop sysmain
sc config wuauserv start= disabled
sc config UsoSvc start= disabled
sc config bits start= disabled
sc config DoSvc start= disabled
sc config sysmain start= disabled
net stop wuauserv
net stop UsoSvc
net stop bits
net stop DoSvc
net stop sysmain
write-host "done" -ForegroundColor red
pause
