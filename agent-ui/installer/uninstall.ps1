# ╔══════════════════════════════════════════════════════════════╗
# ║              SIEM Agent Uninstaller                         ║
# ╚══════════════════════════════════════════════════════════════╝

$installDir = "$env:LOCALAPPDATA\Programs\SIEM Agent"

Write-Host ""
Write-Host "Uninstalling SIEM Agent..." -ForegroundColor Yellow

# Stop running agent
Stop-Process -Name "agent-ui" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Remove files
if (Test-Path $installDir) {
    Remove-Item -Recurse -Force $installDir
    Write-Host "  ✅ Removed $installDir" -ForegroundColor Green
}

# Remove Desktop shortcut
$desktopLink = Join-Path ([Environment]::GetFolderPath("Desktop")) "SIEM Agent.lnk"
if (Test-Path $desktopLink) { Remove-Item $desktopLink -Force }
Write-Host "  ✅ Desktop shortcut removed" -ForegroundColor Green

# Remove Start Menu shortcut
$startMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "SIEM Agent"
if (Test-Path $startMenuDir) { Remove-Item -Recurse -Force $startMenuDir }
Write-Host "  ✅ Start Menu shortcut removed" -ForegroundColor Green

# Remove autorun registry key
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SIEMAgent" -ErrorAction SilentlyContinue
Write-Host "  ✅ Autorun registry key removed" -ForegroundColor Green

Write-Host ""
Write-Host "SIEM Agent was completely uninstalled." -ForegroundColor Cyan
Write-Host ""
