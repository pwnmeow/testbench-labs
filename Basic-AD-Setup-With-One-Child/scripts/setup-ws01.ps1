# ============================================
# WS01 Setup Script
# Run this on Workstation 1
# Sets hostname to WS01 + Joins Domain
# pain becomes local admin
# ============================================

param(
    [string]$DCIP = "10.10.12.10",
    [string]$DomainName = "akatsuki.local"
)

$ErrorActionPreference = "Stop"

Write-Host @"

    ___    __         __             __    _    __          __
   /   |  / /______ _/ /________  __/ /__ (_)  / /   ____ _/ /_
  / /| | / //_/ __ `/ __/ ___/ / / / //_// /  / /   / __ `/ __ \
 / ___ |/ ,< / /_/ / /_(__  ) /_/ / ,< / /  / /___/ /_/ / /_/ /
/_/  |_/_/|_|\__,_/\__/____/\__,_/_/|_/_/  /_____/\__,_/_.___/

           WS01 Setup Script

"@ -ForegroundColor Red

$currentName = $env:COMPUTERNAME

Write-Host "Current hostname: $currentName" -ForegroundColor Cyan
Write-Host "Target hostname:  WS01" -ForegroundColor Cyan
Write-Host "DC IP:           $DCIP" -ForegroundColor Cyan
Write-Host "Domain:          $DomainName" -ForegroundColor Cyan
Write-Host ""

# ============================================
# Check if already joined
# ============================================
$cs = Get-WmiObject -Class Win32_ComputerSystem
if ($cs.PartOfDomain -and $cs.Domain -eq $DomainName) {
    Write-Host "Already joined to $DomainName!" -ForegroundColor Green

    # Make sure pain is local admin
    try {
        Add-LocalGroupMember -Group "Administrators" -Member "AKATSUKI\pain" -ErrorAction SilentlyContinue
        Write-Host "  pain added to local Administrators" -ForegroundColor Green
    } catch {
        Write-Host "  pain already in Administrators" -ForegroundColor Yellow
    }

    Write-Host @"

+----------------------------------------------------------+
|  WS01 Setup Complete!                                    |
|                                                          |
|  Login options:                                          |
|    AKATSUKI\orochimaru : Snake2024!   (low priv)         |
|    AKATSUKI\pain       : Password123! (local admin)      |
|    AKATSUKI\itachi     : Akatsuki123! (domain admin)     |
+----------------------------------------------------------+

"@ -ForegroundColor Green
    exit 0
}

# ============================================
# PHASE 1: Rename computer if needed
# ============================================
if ($currentName -ne "WS01") {
    Write-Host "=== Phase 1: Renaming computer to WS01 ===" -ForegroundColor Yellow
    Rename-Computer -NewName "WS01" -Force

    Write-Host @"

+----------------------------------------------------------+
|  Computer renamed to WS01!                               |
|  REBOOT REQUIRED - Run this script again after reboot   |
+----------------------------------------------------------+

"@ -ForegroundColor Green

    Write-Host "Rebooting in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Restart-Computer -Force
    exit 0
}

# ============================================
# PHASE 2: Configure DNS
# ============================================
Write-Host "=== Configuring DNS ===" -ForegroundColor Cyan

$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

if ($adapter) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($DCIP, "8.8.8.8")
    Write-Host "  DNS set to $DCIP" -ForegroundColor Green
} else {
    Write-Host "ERROR: No network adapter!" -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 3

# ============================================
# PHASE 3: Test DC connectivity
# ============================================
Write-Host ""
Write-Host "=== Testing DC Connectivity ===" -ForegroundColor Cyan

Write-Host "  Pinging DC..." -NoNewline
if (Test-Connection -ComputerName $DCIP -Count 2 -Quiet) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "Cannot reach DC at $DCIP!" -ForegroundColor Red
    exit 1
}

Write-Host "  Resolving $DomainName..." -NoNewline
try {
    Resolve-DnsName -Name $DomainName -ErrorAction Stop | Out-Null
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "Cannot resolve $DomainName - is DC setup complete?" -ForegroundColor Red
    exit 1
}

# ============================================
# PHASE 4: Disable Firewall
# ============================================
Write-Host ""
Write-Host "=== Disabling Firewall ===" -ForegroundColor Cyan
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Write-Host "  Firewall disabled" -ForegroundColor Green

# ============================================
# PHASE 5: Schedule pain as local admin
# ============================================
Write-Host ""
Write-Host "=== Scheduling pain as Local Admin ===" -ForegroundColor Cyan

$script = @'
Start-Sleep -Seconds 60
try {
    Add-LocalGroupMember -Group "Administrators" -Member "AKATSUKI\pain" -ErrorAction Stop
} catch {}
Unregister-ScheduledTask -TaskName "AddPainAdmin" -Confirm:$false -ErrorAction SilentlyContinue
'@
$script | Out-File "C:\Windows\Temp\add-pain.ps1" -Force

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Windows\Temp\add-pain.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "AddPainAdmin" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Host "  Scheduled task created" -ForegroundColor Green

# ============================================
# PHASE 6: Join Domain
# ============================================
Write-Host ""
Write-Host "=== Joining Domain ===" -ForegroundColor Cyan
Write-Host "Enter Domain Admin credentials:" -ForegroundColor Yellow

$cred = Get-Credential -Message "Domain Admin (AKATSUKI\Administrator)" -UserName "AKATSUKI\Administrator"

Write-Host "  Joining $DomainName..." -ForegroundColor Green

try {
    Add-Computer -DomainName $DomainName -Credential $cred -Force -Restart
} catch {
    Write-Host "  Trying with explicit DC..." -ForegroundColor Yellow
    Add-Computer -DomainName $DomainName -Server $DCIP -Credential $cred -Force -Restart
}

Write-Host @"

+----------------------------------------------------------+
|  Joining domain and restarting...                        |
|                                                          |
|  After reboot login as:                                  |
|    AKATSUKI\orochimaru : Snake2024!   (low priv)         |
|    AKATSUKI\pain       : Password123! (local admin)      |
+----------------------------------------------------------+

"@ -ForegroundColor Green
