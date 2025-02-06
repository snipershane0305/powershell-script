#force opens powershell 7 as admin.
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

Import-Module ScheduledTasks
Import-Module NetAdapter
Import-Module NetTCPIP
Import-Module DnsClient

$updateservices = @(
"wuauserv"
"usosvc"
"bits"
)

$forcestopprocesses = @(
"ApplicationFrameHost*"
"dllhost*"
"SecurityHealthService*"
"WmiPrvSE*"
"taskhostw*"
)

$forcestopservices = @(
"AppXSvc"
"ClipSVC"
"smphost"
"LanmanServer"
"TokenBroker"
"DusmSvc"
"DeviceAssociationService"
"AssignedAccessManagerSvc"
"tzautoupdate"
"BITS"
"wbengine"
"PeerDistSvc"
"DiagTrack"
"DialogBlockingService"
"DisplayEnhancementService"
"DispBrokerDesktopSvc"
"MapsBroker"
"lfsvc"
"iphlpsvc"
"AppVClient"
"Spooler"
"RmSvc"
"RasAuto"
"RasMan"
"SessionEnv"
"TermService"
"UmRdpService"
"RemoteRegistry"
"RemoteAccess"
"shpamsvc"
"SSDPSRV"
"SysMain"
"SgrmBroker"
"lmhosts"
"UsoSvc"
"UevAgentService"
"VSS"
"SDRSVC"
"Sense"
"EventLog"
"WSearch"
"wuauserv"
"wmiApSrv"
"XboxGipSvc"
"XblAuthManager"
"XblGameSave"
"XboxNetApiSvc"
)

$disabledservices = @(
"AssignedAccessManagerSvc"
"tzautoupdate"
"BITS"
"wbengine"
"PeerDistSvc"
"DiagTrack"
"DialogBlockingService"
"DisplayEnhancementService"
"DispBrokerDesktopSvc"
"MapsBroker"
"lfsvc"
"iphlpsvc"
"AppVClient"
"Spooler"
"RmSvc"
"RasAuto"
"RasMan"
"SessionEnv"
"TermService"
"UmRdpService"
"RemoteRegistry"
"RemoteAccess"
"shpamsvc"
"SSDPSRV"
"SysMain"
"lmhosts"
"UsoSvc"
"UevAgentService"
"VSS"
"SDRSVC"
"EventLog"
"WSearch"
"wuauserv"
"wmiApSrv"
"XboxGipSvc"
"XblAuthManager"
"XblGameSave"
"XboxNetApiSvc"
)

$manualservices = @(
"AxInstSV"
"AppReadiness"
"Appinfo"
"ALG"
"AppMgmt"
"BthAvctpSvc"
"BDESVC"
"BTAGService"
"bthserv"
"camsvc"
"autotimesvc"
"CertPropSvc"
"KeyIso"
"COMSysApp"
"CDPSvc"
"VaultSvc"
"DsSvc"
"DusmSvc"
"dcsvc"
"DeviceAssociationService"
"DeviceInstall"
"DmEnrollmentSvc"
"dmwappushservice"
"DsmSvc"
"DevQueryBroker"
"diagsvc"
"DPS"
"WdiServiceHost"
"WdiSystemHost"
"MSDTC"
"EFS"
"EapHost"
"fhsvc"
"fdPHost"
"FDResPub"
"GameInputSvc"
"GraphicsPerfSvc"
"hidserv"
"IKEEXT"
"SharedAccess"
"IpxlatCfgSvc"
"PolicyAgent"
"KtmRm"
"LxpSvc"
"lltdsvc"
"wlpasvc"
"McpManagementService"
"wlidsvc"
"cloudidsvc"
"MSiSCSI"
"MsKeyboardFilter"
"swprv"
"smphost"
"InstallService"
"SmsRouter"
"NaturalAuthentication"
"Netlogon"
"NcdAutoSetup"
"NcbService"
"Netman"
"NcaSvc"
"netprofm"
"NlaSvc"
"NetSetupSvc"
"CscService"
"defragsvc"
"WpcMonSvc"
"SEMgrSvc"
"PerfHost"
"pla"
"PhoneSvc"
"PlugPlay"
"WPDBusEnum"
"PrintDeviceConfigurationService"
"PrintNotify"
"PrintScanBrokerService"
"wercplsupport"
"PcaSvc"
"QWAVE"
"TroubleshootingSvc"
"refsdedupsvc"
"RpcLocator"
"RetailDemo"
"seclogon"
"SstpSvc"
"SensorDataService"
"SensrSvc"
"SensorService"
"LanmanServer"
"SCardSvr"
"ScDeviceEnum"
"SCPolicySvc"
"SNMPTrap"
"svsvc"
"WiaRpc"
"StorSvc"
"TieringEngineService"
"TapiSrv"
"Themes"
"upnphost"
"vds"
"WalletService"
"WarpJITSvc"
"TokenBroker"
"webthreatdefsvc"
"WebClient"
"WFDSConMgrSvc"
"WbioSrvc"
"FrameServer"
"FrameServerMonitor"
"wcncsvc"
"WEPHOSTSVC"
"WerSvc"
"Wecsvc"
"StiSvc"
"wisvc"
"LicenseManager"
"WManSvc"
"icssvc"
"TrustedInstaller"
"perceptionsimulation"
"WpnService"
"PushToInstall"
"WinRM"
"W32Time"
"ApxSvc"
"WwanSvc"
)

$autoservices = @(
"EventSystem"
"CryptSvc"
"Dhcp"
"TrkWks"
"InventorySvc"
"LocalKdc"
"nsi"
"Power"
"ShellHWDetection"
"SENS"
"UserManager"
"ProfSvc"
"Audiosrv"
"AudioEndpointBuilder"
"Wcmsvc"
"FontCache"
"Winmgmt"
"dot3svc"
"WlanSvc"
"LanmanWorkstation"
)
Stop-Service $forcestopservices -force
Stop-Service $disabledservices -force
Get-Service -Name $autoservices -ErrorAction SilentlyContinue | Set-Service -StartupType automatic
Get-Service -Name $manualservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual
Get-Service -Name $disabledservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled
Stop-Service $forcestopservices -force
Stop-Service $disabledservices -force


######################################################
write-host "SYSTEM MAINTENANCE" -ForegroundColor white
######################################################


write-host "updating defender definitions" -ForegroundColor red
#updates microsoft defender
Update-MpSignature -UpdateSource MicrosoftUpdateServer
write-host "done" -ForegroundColor red

write-host "checking for windows udpates" -ForegroundColor red
#starts needed windows update services
Get-Service -Name $updateservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual
Start-Service $updateservices
start-sleep -seconds 2
#runs windows update
Install-Module -Name PSWindowsUpdate -Force
Import-Module PSWindowsUpdate
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
Get-WindowsUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
write-host "done" -ForegroundColor red
start-sleep -seconds 2
#stops update services
Stop-Service $updateservices
Get-Service -Name $updateservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled
Stop-Service $updateservices

write-host "starting defender quick scan" -ForegroundColor red
cd "${Env:ProgramFiles(x86)}\Windows Defender"
.\MpCmdRun.exe -scan -scantype 1
cd ~
write-host "done" -ForegroundColor red

write-host "trimming C: drive" -ForegroundColor red
$systemDrive = (Get-WmiObject -Class Win32_OperatingSystem).SystemDrive
Optimize-Volume -DriveLetter $systemDrive -ReTrim
Optimize-Volume -DriveLetter $systemDrive -SlabConsolidate

write-host "cleaning system" -ForegroundColor red
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
#clears temp folders
Get-ChildItem -Path "$env:TEMP" *.* -Recurse | Remove-Item -Force -Recurse
Get-ChildItem -Path "$env:windir\Temp\" *.* -Recurse | Remove-Item -Force -Recurse


########################################################
write-host "SYSTEM CONFIGURATION" -ForegroundColor white
########################################################


write-host "setting timer resolution to 0.5" -ForegroundColor red
$SetTimerResolution = "C:\SetTimerResolution.exe"
$resolution = "--resolution 5050 --no-console"
start-process $SetTimerResolution $resolution

write-host "Disabling powershell telemetry" -ForegroundColor red
#disables powershell 7 telemetry (sends data without benefit)
[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')

write-host "disabling hibernation" -ForegroundColor red
powercfg.exe /hibernate off #disables hiberation (writes memory to disk and saves power at cost of performance, only useful for laptops)

write-host "enabling memory compression" -ForegroundColor red
Enable-MMAgent -mc #enabled memory compression (saves some memory but takes cpu cycles to compress and uncompress the memory)

write-host "applying bcdedits" -ForegroundColor red
bcdedit /deletevalue disabledynamictick
bcdedit /deletevalue useplatformclock
bcdedit /deletevalue tscsyncpolicy
bcdedit /deletevalue MSI
bcdedit /deletevalue x2apicpolicy
bcdedit /deletevalue usephysicaldestination
bcdedit /set useplatformtick yes #uses a hardware timer for ticks which is most reliable
bcdedit /set disabledynamictick yes #disables platform tick from being dynamic which is a power saving feature
bcdedit /set useplatformclock no #disables HPET (high percision event timer) //#DANGEROUS!!//
bcdedit /set tscsyncpolicy enhanced #sets time stamp counter synchronization policy to enhanced
bcdedit /set MSI Default #sets the use of interrupt type to message signaled interrupts which was added for PCI 2.2 which is newer than the old line based interrupts
bcdedit /set x2apicpolicy Enable #uses the newer apic mode
bcdedit /set usephysicaldestination no #disables physical apic for x2apicpolicy
bcdedit /set nx OptIn #enables data execution prevention which improves security

write-host "applying fsutil settings" -ForegroundColor red
fsutil behavior set disabledeletenotify 0 #enables trim on disk
fsutil behavior set disableLastAccess 1 #disables last access time stamp on directories
fsutil behavior set disable8dot3 1 #unused

write-host "applying network settings" -ForegroundColor red
netsh int teredo set state disabled #disables teredo (used for ipv6)
netsh int tcp set global ecncapability=enable #ecncapability will notify if there is congestion to help packet loss, will only be used if both the client and server support it
netsh int tcp set global rsc=disable #disables receive segment coalescing which makes small packets combine, this helps with computing many packets but at the cost of latency
netsh int tcp set global nonsackrttresiliency=enabled #improves the reliability of tcp over high-latency networks
netsh int tcp set global maxsynretransmissions=2
netsh int tcp set security mpp=disabled
netsh int tcp set supplemental template=internet enablecwndrestart=enabled
netsh int tcp set supplemental template=custom enablecwndrestart=enabled
netsh int tcp set supplemental Template=Internet CongestionProvider=ctcp
netsh int tcp set supplemental Template=custom CongestionProvider=ctcp
Set-NetTCPSetting -SettingName internet -DelayedAckFrequency 2
Set-NetTCPSetting -SettingName Internetcustom -DelayedAckFrequency 2
Set-NetTCPSetting -SettingName internet -MemoryPressureProtection disabled
Set-NetTCPSetting -SettingName Internetcustom -MemoryPressureProtection disabled
Set-NetTCPSetting -SettingName internet -EcnCapability enabled
Set-NetTCPSetting -SettingName Internetcustom -EcnCapability enabled
Set-NetTCPSetting -SettingName internet -NonSackRttResiliency enabled
Set-NetTCPSetting -SettingName Internetcustom -NonSackRttResiliency enabled
Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2
Set-NetTCPSetting -SettingName internetcustom -MaxSynRetransmissions 2
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
set-mppreference -AllowSwitchToAsyncInspection $true #performance optimization
set-mppreference -DisableArchiveScanning $true
set-mppreference -DisableCatchupFullScan $true #disables force scan if it misses a scheduled scan
set-mppreference -DisableCatchupQuickScan $true #disables force scan if it misses a scheduled scan
set-mppreference -DisableEmailScanning $true #disables emailscanning
set-mppreference -DisableNetworkProtectionPerfTelemetry $true #disables the sending of performance data to microsoft
Set-MpPreference -DisableCoreServiceTelemetry $true #disables the sending of performance data to microsoft
set-mppreference -DisableRemovableDriveScanning $true
set-mppreference -DisableRestorePoint $true #disables defender creating restore points (i have never had a restore point fix an issue!)
set-mppreference -EnableLowCpuPriority $true #lowers the priority of defender
set-mppreference -EnableNetworkProtection disable #enables network protection
set-mppreference -MAPSReporting 0 #disables the sending of data to microsoft (this doesnt disable MAPS!)
set-mppreference -RandomizeScheduleTaskTimes $false #disables random scans
set-mppreference -RemediationScheduleDay 8 #disables schedule scans
set-mppreference -ScanAvgCPULoadFactor 5 #allows defender to use 5% cpu usage when running a scan
set-mppreference -ScanOnlyIfIdleEnabled $true
set-mppreference -ScanParameters 1 #sets schedule scans to quick scans
set-mppreference -ScanScheduleDay 8 #disables schedule scans
set-mppreference -SubmitSamplesConsent 2 #disables sending samples to microsoft
set-mppreference -DisableDatagramProcessing $true
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

write-host "changing registry settings" -ForegroundColor red
#registry changes
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type string -Value 10
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" -Force | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "CpuPriorityClass" -Type DWord -Value 4
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "IoPriority" -Type DWord -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 0x00000010
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 0x00000010
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "GlobalTimerResolutionRequests" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ThreadedDpcEnable" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "HeapDeCommitFreeBlockThreshold" -Type DWord -Value 0x00040000
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x0000002a
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Type String -Value False
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Clock Rate" -Type DWord -Value 0x00002710
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 8
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value High
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value High
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "disableClearType" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableAeroPeek" -Type DWord -Value 0
#Windows update
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
#network
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Name "FastSendDatagramThreshold" -Type DWord -Value 0x10000
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableConnectionRateLimiting" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Type DWord -Value 0x00000030
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type DWord -Value 0x00000064
#privacy
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type string -Value deny
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name "EnableActiveProbing" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Wifi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Wifi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
#disabling scheduled tasks
Disable-ScheduledTask -taskpath "\Microsoft\Windows\WindowsUpdate" -TaskName "Scheduled Start" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Windows Error Reporting" -TaskName "QueueReporting" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\User Profile Service" -TaskName "HiveUploadTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Maps" -TaskName "MapsUpdateTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "MareBackup" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "Microsoft Compatibility Appraiser Exp" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "StartupAppTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "PcaPatchDbTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Autochk" -TaskName "Proxy" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Customer Experience Improvement Program" -TaskName "Consolidator" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Customer Experience Improvement Program" -TaskName "UsbCeip" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\DiskDiagnostic" -TaskName "Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\DiskDiagnostic" -TaskName "Microsoft-Windows-DiskDiagnosticResolver" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Feedback\Siuf" -TaskName "DmClient" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Feedback\Siuf" -TaskName "DmClientOnScenarioDownload" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Windows Error Reporting" -TaskName "QueueReporting" | Out-Null
write-host "done" -ForegroundColor red


##################################################
write-host "SYSTEM CLEANUP" -ForegroundColor white
##################################################


write-host "stopping services and processes" -ForegroundColor red
#stops services i dont want running 
Stop-Service $forcestopservices -force
Stop-Service $disabledservices -force
Get-Service -Name $autoservices -ErrorAction SilentlyContinue | Set-Service -StartupType automatic
Get-Service -Name $manualservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual
Get-Service -Name $disabledservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled
Stop-Service $forcestopservices -force
Stop-Service $disabledservices -force
Get-Process -Name $forcestopprocesses -ErrorAction SilentlyContinue | Stop-Process -force

write-host "releasing memory" -ForegroundColor red
C:\memreduct.exe -clean:full
write-host "done" -ForegroundColor red
pause
