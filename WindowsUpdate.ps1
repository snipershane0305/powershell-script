write-host "updating system" -ForegroundColor red
#updates microsoft defender
C:\"Program Files"\"Windows Defender"\MpCmdRun -SignatureUpdate
Update-MpSignature -UpdateSource MicrosoftUpdateServer
#starts needed windows update services
sc config wuauserv start= demand
sc config UsoSvc start= demand
net start wuauserv  
net start usosvc
start-sleep -seconds 2
#runs windows update
Install-Module PSWindowsUpdate -Confirm:$false
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
