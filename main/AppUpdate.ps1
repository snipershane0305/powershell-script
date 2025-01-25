winget pin add Microsoft.EdgeWebView2Runtime
winget pin add Microsoft.Edge
winget pin add Discord.Discord
winget pin add Logitech.GHUB
winget pin add Spotify.Spotify
winget source update
winget update --all --include-unknown
#important dependencies
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
#important dependencies
winget install Insecure.Npcap
winget install Microsoft.WindowsTerminal
winget install Microsoft.PowerShell
winget install Microsoft.AppInstaller
winget install 7zip.7zip
winget install VideoLAN.VLC
winget install WiresharkFoundation.Wireshark
winget install RevoUninstaller.RevoUninstaller
winget install PuTTY.PuTTY
winget install Open-Shell.Open-Shell-Menu
winget install Guru3D.Afterburner
winget install HandBrake.HandBrake
winget install OBSProject.OBSStudio
winget install Valve.Steam
winget install Andersama.obs-asio
winget install BleachBit.BleachBit
winget install PrismLauncher.PrismLauncher
winget install Alex313031.Thorium.AVX2
winget install EclipseAdoptium.Temurin.23.JRE
winget install EclipseAdoptium.Temurin.17.JRE
winget install EclipseAdoptium.Temurin.11.JRE
winget install EclipseAdoptium.Temurin.8.JRE
winget install pizzaboxer.Bloxstrap
winget install qBittorrent.qBittorrent
#stops processes and services
$services = @(
"VSS"
"msiserver"
"TrustedInstaller"
)
$processes = @(
"TiWorker*"
"VSSVC*"
"TrustedInstaller*"
"msiexec*"
)
Stop-Service $services -force
Get-Process -Name $processes -ErrorAction SilentlyContinue | Stop-Process -force
