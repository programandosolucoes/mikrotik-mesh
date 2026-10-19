<#
.SYNOPSIS
    Installs the MikroTik Mesh Daemon as a persistent background task on Windows (auto-restarts on boot).
#>

$BinPath = Resolve-Path "$PSScriptRoot\..\target\release\mkt-cli.exe" -ErrorAction SilentlyContinue

if (-not $BinPath -or -not (Test-Path $BinPath)) {
    Write-Error "mkt-cli.exe not found in target\release. Run 'cargo build --release' first."
    exit 1
}

$TaskName = "MikrotikMeshDaemon"
$Action = New-ScheduledTaskAction -Execute $BinPath -Argument "daemon --control 127.0.0.1:20560 --relay 0.0.0.0:443"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force

Write-Host "MikroTik Mesh Daemon task successfully registered on Windows!" -ForegroundColor Green
Write-Host "Starting task..."
Start-ScheduledTask -TaskName $TaskName
