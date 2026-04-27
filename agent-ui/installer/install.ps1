# SIEM Agent Installer v3.0

$ErrorActionPreference = "Stop"

$installDir = "$env:LOCALAPPDATA\Programs\SIEM Agent"
$configDir  = "$env:APPDATA\SIEMAgent"
$exeSource  = Join-Path $PSScriptRoot "..\build\bin\agent-ui.exe"
$exeDest    = Join-Path $installDir "agent-ui.exe"
$configFile = Join-Path $configDir "agent_config.json"

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "     SIEM Agent Installer v3.0           " -ForegroundColor Cyan
Write-Host "     Security Event Monitoring           " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# -- 0. Check source binary
if (-not (Test-Path $exeSource)) {
    Write-Host "  X Binary not found: $exeSource" -ForegroundColor Red
    Write-Host "    Run 'wails build' first from the agent-ui folder." -ForegroundColor Yellow
    exit 1
}

# -- 1. Ask for Manager IP
Write-Host "  --- Configure SIEM Manager Connection ---" -ForegroundColor DarkCyan
Write-Host ""

$defaultIP = "localhost"
$managerIP = Read-Host "  Manager IP Address [$defaultIP]"
if ([string]::IsNullOrWhiteSpace($managerIP)) { $managerIP = $defaultIP }

$defaultPort = "50051"
$managerPort = Read-Host "  Manager gRPC Port  [$defaultPort]"
if ([string]::IsNullOrWhiteSpace($managerPort)) { $managerPort = $defaultPort }

$fullAddr = "${managerIP}:${managerPort}"
Write-Host ""
Write-Host "  -> Will connect to: $fullAddr" -ForegroundColor White
Write-Host ""

# -- 2. Stop any running agent
Write-Host "[1/6] Stopping any running agent..." -ForegroundColor Yellow
Stop-Process -Name "agent-ui" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Write-Host "      OK" -ForegroundColor Green

# -- 3. Create directories
Write-Host "[2/6] Creating directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $configDir  | Out-Null
Write-Host "      OK $installDir" -ForegroundColor Green

# -- 4. Copy executable
Write-Host "[3/6] Installing agent-ui.exe..." -ForegroundColor Yellow
Copy-Item -Path $exeSource -Destination $exeDest -Force
$sizeMB = [math]::Round((Get-Item $exeDest).Length / 1MB, 1)
Write-Host "      OK Copied ($sizeMB MB)" -ForegroundColor Green

# -- 5. Save configuration
Write-Host "[4/6] Saving configuration..." -ForegroundColor Yellow
$configObj = @{
    manager_ip  = $fullAddr
    file_paths  = @()
    syslog_port = 0
    win_events  = @("System", "Application", "Security")
}
$configObj | ConvertTo-Json -Depth 3 | Set-Content -Path $configFile -Encoding UTF8
Write-Host "      OK Config saved" -ForegroundColor Green
Write-Host "         Manager: $fullAddr" -ForegroundColor DarkGray
Write-Host "         Win Events: System, Application, Security" -ForegroundColor DarkGray

# -- 6. Create shortcuts
Write-Host "[5/6] Creating shortcuts..." -ForegroundColor Yellow
$WshShell = New-Object -ComObject WScript.Shell

$desktopLink = Join-Path ([Environment]::GetFolderPath("Desktop")) "SIEM Agent.lnk"
$shortcut = $WshShell.CreateShortcut($desktopLink)
$shortcut.TargetPath = $exeDest
$shortcut.WorkingDirectory = $installDir
$shortcut.Description = "SIEM Security Agent"
$shortcut.Save()
Write-Host "      OK Desktop shortcut" -ForegroundColor Green

$startMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "SIEM Agent"
New-Item -ItemType Directory -Force -Path $startMenuDir | Out-Null
$startLink = Join-Path $startMenuDir "SIEM Agent.lnk"
$shortcut2 = $WshShell.CreateShortcut($startLink)
$shortcut2.TargetPath = $exeDest
$shortcut2.WorkingDirectory = $installDir
$shortcut2.Description = "SIEM Security Agent"
$shortcut2.Save()
Write-Host "      OK Start Menu shortcut" -ForegroundColor Green

# -- 7. Register auto-start + launch background agent
Write-Host "[6/6] Configuring persistence and launching agent..." -ForegroundColor Yellow

$regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $regPath -Name "SIEMAgent" -Value ('"' + $exeDest + '" cli')
Write-Host "      OK Autorun registry key set" -ForegroundColor Green

Start-Process -FilePath $exeDest -ArgumentList "cli" -WindowStyle Hidden
Write-Host "      OK Agent launched in background" -ForegroundColor Green

# -- Done
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  SIEM Agent installed and running!      " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Install:    $installDir" -ForegroundColor White
Write-Host "  Config:     $configFile" -ForegroundColor White
Write-Host "  Manager:    $fullAddr" -ForegroundColor White
Write-Host "  Auto-start: Enabled (runs on every login)" -ForegroundColor White
Write-Host "  Status:     Running in background right now" -ForegroundColor White
Write-Host ""
Write-Host "  To open the GUI: double-click 'SIEM Agent' on Desktop." -ForegroundColor DarkGray
Write-Host "  To uninstall:    run .\uninstall.ps1" -ForegroundColor DarkGray
Write-Host ""
