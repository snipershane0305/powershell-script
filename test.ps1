#force opens powershell 7 as admin.
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
$updateservices = @(
"wuauserv"
"usosvc"
"bits"
)
$forcestopprocesses = @(
"MoUsoCoreWorker*"
"SecurityHealthService*"
"unsecapp*"
"ApplicationFrameHost*"
"tiworker*"
"taskhostw*"
"dllhost*"
"dism*"
"WMI*"
)
$forcestopservices = @(
"wuauserv"
"usosvc"
"bits"
"sysmain"
)
$disabledservices = @(
"WSearch"
"SSDPSRV"
"SysMain"
"lmhosts"
"RasMan"
"RmSvc"
"Spooler"
"lfsvc"
"DispBrokerDesktopSvc"
"DisplayEnhancementService"
"bthserv"
)
$manualservices = @(
)
$autoservices = @(
)
write-host "updating system" -ForegroundColor red
#updates microsoft defender
C:\"Program Files"\"Windows Defender"\MpCmdRun -SignatureUpdate
Update-MpSignature -UpdateSource MicrosoftUpdateServer
#starts needed windows update services
Get-Service -Name $updateservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual
Start-Service $updateservices
start-sleep -seconds 3
#runs windows update
Install-Module PSWindowsUpdate -Confirm:$false
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
start-sleep -seconds 3
#stops update services
Stop-Service $updateservices
Get-Service -Name $updateservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled

write-host "starting defender quick scan" -ForegroundColor red
C:\"Program Files (x86)"\"Windows Defender"\MpCmdRun.exe -scan -scantype 1

write-host "trimming C: drive" -ForegroundColor red
$systemDrive = (Get-WmiObject -Class Win32_OperatingSystem).SystemDrive
Optimize-Volume -DriveLetter $systemDrive -ReTrim
Optimize-Volume -DriveLetter $systemDrive -SlabConsolidate

write-host "cleaning system" -ForegroundColor red
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
#clears temp folders
Get-ChildItem -Path "$env:TEMP" *.* -Recurse | Remove-Item -Force -Recurse
Get-ChildItem -Path "C:\Windows\Temp\" *.* -Recurse | Remove-Item -Force -Recurse




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

#registry changes
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "disableClearType" -Type DWord -Value 1

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableAeroPeek" -Type DWord -Value 0

Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type DWord -Value 0

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" -Force | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "CpuPriorityClass" -Type DWord -Value 4
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "IoPriority" -Type DWord -Value 3

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 16
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 16

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 0

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "GlobalTimerResolutionRequests" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ThreadedDpcEnable" -Type DWord -Value 1

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "HeapDeCommitFreeBlockThreshold" -Type DWord -Value 2498884

Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 42

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Type String -Value False
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Clock Rate" -Type DWord -Value 10000
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 8
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value High
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value High

#Windows update
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
#privacy

write-host "stopping services and processes" -ForegroundColor red
#stops services i dont want running
Stop-Service $forcestopservices
Get-Service -Name $forcestopservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled
Stop-Service $forcestopservices
Get-Service -Name $forcestopservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled
Get-Process -Name $forcestopprocesses -ErrorAction SilentlyContinue | Stop-Process -force

write-host "releasing memory" -ForegroundColor red
C:\memreduct.exe -clean:full
write-host "done" -ForegroundColor red
pause
