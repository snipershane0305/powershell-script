write-host "updating system" -ForegroundColor red
C:\"Program Files"\"Windows Defender"\MpCmdRun -SignatureUpdate #updates microsoft defender security
Update-MpSignature -UpdateSource MicrosoftUpdateServer
#runs windows update
sc config wuauserv start= demand
sc config UsoSvc start= demand
net start wuauserv  
net start usosvc
start-sleep -seconds 2
Install-Module PSWindowsUpdate -Confirm:$false
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
#runs windows update
write-host "running defender scan" -ForegroundColor red
C:\"Program Files"\"Windows Defender"\MpCmdRun -scan -ScanType 1
pause
