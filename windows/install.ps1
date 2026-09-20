# ROCKET Shield — Windows installer
# Run in an elevated (Administrator) PowerShell prompt.

Write-Host "[*] Installing ROCKET Shield Windows agent..."

New-NetFirewallRule -DisplayName "RocketShield_ICMP_RateNote" `
    -Direction Inbound -Protocol ICMPv4 -Action Allow `
    -Description "ICMP allowed; flood detection handled by agent" -ErrorAction SilentlyContinue

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Python not found. Install Python 3.9+ from python.org first."
    exit 1
}

python -m pip install --upgrade psutil

$installDir = "C:\ProgramData\RocketShield"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item ".\windows_agent.py" -Destination $installDir -Force

$action = New-ScheduledTaskAction `
    -Execute "python" `
    -Argument "$installDir\windows_agent.py"

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName "RocketShieldAgent" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Force

Write-Host "[*] Installed. Starting now..."

Start-ScheduledTask -TaskName "RocketShieldAgent"

Write-Host "[*] Check status: Get-ScheduledTaskInfo -TaskName RocketShieldAgent"
Write-Host "[*] Blocked IPs appear as firewall rules named RocketShield_Block_<ip>"