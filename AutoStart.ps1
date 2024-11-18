if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
pwsh.exe -WindowStyle Minimized "C:\StartUp.ps1"
pwsh.exe -WindowStyle Minimized "C:\AppUpdate.ps1"
pwsh.exe -WindowStyle Minimized "C:\WindowsUpdate.ps1"