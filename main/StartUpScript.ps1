#put this in your startup folder
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
start-process pwsh.exe -WindowStyle Minimized "C:\AppUpdate.ps1"
start-process pwsh.exe -WindowStyle Minimized "C:\PowershellScript.ps1"
