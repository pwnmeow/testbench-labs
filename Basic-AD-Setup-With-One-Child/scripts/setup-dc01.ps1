# ============================================
# DC01 Setup Script
# Run this on the Windows Server
# Sets hostname to DC01 + Creates AD Forest
# ============================================

param(
    [string]$DCIP = "10.10.12.10",
    [string]$Gateway = "10.10.12.2",
    [string]$DomainName = "akatsuki.local",
    [string]$NetBIOS = "AKATSUKI"
)

$ErrorActionPreference = "Stop"

Write-Host @"

    ___    __         __             __    _    __          __
   /   |  / /______ _/ /________  __/ /__ (_)  / /   ____ _/ /_
  / /| | / //_/ __ `/ __/ ___/ / / / //_// /  / /   / __ `/ __ \
 / ___ |/ ,< / /_/ / /_(__  ) /_/ / ,< / /  / /___/ /_/ / /_/ /
/_/  |_/_/|_|\__,_/\__/____/\__,_/_/|_/_/  /_____/\__,_/_.___/

           DC01 Setup Script

"@ -ForegroundColor Red

# ============================================
# Check current state
# ============================================
$cs = Get-WmiObject -Class Win32_ComputerSystem
$currentName = $env:COMPUTERNAME

Write-Host "Current hostname: $currentName" -ForegroundColor Cyan
Write-Host "Target hostname:  DC01" -ForegroundColor Cyan
Write-Host "DC IP:           $DCIP" -ForegroundColor Cyan
Write-Host "Domain:          $DomainName" -ForegroundColor Cyan
Write-Host ""

# ============================================
# PHASE 1: Rename computer if needed
# ============================================
if ($currentName -ne "DC01") {
    Write-Host "=== Phase 1: Renaming computer to DC01 ===" -ForegroundColor Yellow
    Rename-Computer -NewName "DC01" -Force

    Write-Host @"

+----------------------------------------------------------+
|  Computer renamed to DC01!                               |
|  REBOOT REQUIRED - Run this script again after reboot   |
+----------------------------------------------------------+

"@ -ForegroundColor Green

    Write-Host "Rebooting in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Restart-Computer -Force
    exit 0
}

# ============================================
# PHASE 2: Check if already a DC
# ============================================
if ($cs.DomainRole -ge 4) {
    Write-Host "Already a Domain Controller! Running user creation..." -ForegroundColor Green

    # Create users inline
    Import-Module ActiveDirectory

    $ouPath = "OU=Shinobi,DC=akatsuki,DC=local"

    # Create OU
    try {
        Get-ADOrganizationalUnit -Identity $ouPath -ErrorAction Stop | Out-Null
        Write-Host "  Shinobi OU exists" -ForegroundColor Yellow
    } catch {
        New-ADOrganizationalUnit -Name "Shinobi" -Path "DC=akatsuki,DC=local"
        Write-Host "  Shinobi OU created" -ForegroundColor Green
    }

    # Create Users
    $users = @(
        @{ Name = "Itachi Uchiha"; Sam = "itachi"; Pass = "Akatsuki123!"; Admin = $true },
        @{ Name = "Nagato Uzumaki"; Sam = "pain"; Pass = "Password123!"; Admin = $false },
        @{ Name = "Kisame Hoshigaki"; Sam = "kisame"; Pass = "Password123!"; Admin = $false },
        @{ Name = "Deidara"; Sam = "deidara"; Pass = "Explosion789!"; Admin = $false },
        @{ Name = "Sasori"; Sam = "sasori"; Pass = "Puppet456!"; Admin = $false },
        @{ Name = "Orochimaru"; Sam = "orochimaru"; Pass = "Snake2024!"; Admin = $false }
    )

    foreach ($u in $users) {
        try {
            Get-ADUser -Identity $u.Sam -ErrorAction Stop | Out-Null
            Write-Host "  $($u.Sam) exists" -ForegroundColor Yellow
        } catch {
            $secPass = ConvertTo-SecureString $u.Pass -AsPlainText -Force
            New-ADUser -Name $u.Name -SamAccountName $u.Sam -UserPrincipalName "$($u.Sam)@$DomainName" `
                -Path $ouPath -AccountPassword $secPass -Enabled $true -PasswordNeverExpires $true
            Write-Host "  Created: $($u.Sam)" -ForegroundColor Green

            if ($u.Admin) {
                Add-ADGroupMember -Identity "Domain Admins" -Members $u.Sam
                Write-Host "    -> Domain Admin" -ForegroundColor Cyan
            }
        }
    }

    # Disable firewall
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

    Write-Host @"

+----------------------------------------------------------+
|  DC01 Setup Complete!                                    |
|                                                          |
|  Users:                                                  |
|    itachi     : Akatsuki123!  (Domain Admin)             |
|    pain       : Password123!  (Local Admin on WS01)      |
|    kisame     : Password123!  (shares pwd with pain)     |
|    deidara    : Explosion789!                            |
|    sasori     : Puppet456!                               |
|    orochimaru : Snake2024!    (Attacker start)           |
|                                                          |
|  Now run setup-ws01.ps1 and setup-ws02.ps1               |
+----------------------------------------------------------+

"@ -ForegroundColor Green
    exit 0
}

# ============================================
# PHASE 3: Set Static IP
# ============================================
Write-Host "=== Setting Static IP ===" -ForegroundColor Cyan

$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

if ($adapter) {
    Write-Host "  Adapter: $($adapter.Name)" -ForegroundColor Green

    Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $DCIP -PrefixLength 24 -DefaultGateway $Gateway -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @("127.0.0.1", "8.8.8.8")

    Write-Host "  IP set to $DCIP" -ForegroundColor Green
} else {
    Write-Host "ERROR: No network adapter!" -ForegroundColor Red
    exit 1
}

# ============================================
# PHASE 4: Install AD DS
# ============================================
Write-Host ""
Write-Host "=== Installing AD DS Role ===" -ForegroundColor Cyan

$adds = Get-WindowsFeature -Name AD-Domain-Services
if (-not $adds.Installed) {
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    Write-Host "  AD DS installed" -ForegroundColor Green
} else {
    Write-Host "  AD DS already installed" -ForegroundColor Yellow
}

# ============================================
# PHASE 5: Create Forest
# ============================================
Write-Host ""
Write-Host "=== Creating Forest: $DomainName ===" -ForegroundColor Cyan
Write-Host "  This will REBOOT!" -ForegroundColor Yellow

Import-Module ADDSDeployment

$SafeModePassword = ConvertTo-SecureString "Akatsuki123!" -AsPlainText -Force

Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetBIOS `
    -SafeModeAdministratorPassword $SafeModePassword `
    -InstallDns:$true `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -NoRebootOnCompletion:$false `
    -Force:$true

Write-Host @"

+----------------------------------------------------------+
|  DC01 is rebooting to complete AD setup!                 |
|                                                          |
|  After reboot:                                           |
|    1. Log in as AKATSUKI\Administrator (vagrant)         |
|    2. Run this script AGAIN to create users              |
+----------------------------------------------------------+

"@ -ForegroundColor Green
