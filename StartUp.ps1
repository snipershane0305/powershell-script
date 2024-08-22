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
