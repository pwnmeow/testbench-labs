# ============================================
# Services Setup Script
# Run this on DC01 AFTER AD is configured
# Installs services for you to configure/misconfigure
# ============================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host @"

    ___    __         __             __    _    __          __
   /   |  / /______ _/ /________  __/ /__ (_)  / /   ____ _/ /_
  / /| | / //_/ __ `/ __/ ___/ / / / //_// /  / /   / __ `/ __ \
 / ___ |/ ,< / /_/ / /_(__  ) /_/ / ,< / /  / /___/ /_/ / /_/ /
/_/  |_/_/|_|\__,_/\__/____/\__,_/_/|_/_/  /_____/\__,_/_.___/

           Services Setup Script

"@ -ForegroundColor Red

Import-Module ActiveDirectory

# ============================================
# 1. CREATE SERVICE ACCOUNTS
# ============================================
Write-Host "=== [1/7] Creating Service Accounts ===" -ForegroundColor Cyan

$serviceAccounts = @(
    @{ Name = "svc_sql"; Pass = "ServicePass123!" },
    @{ Name = "svc_web"; Pass = "ServicePass123!" },
    @{ Name = "svc_backup"; Pass = "ServicePass123!" },
    @{ Name = "svc_ftp"; Pass = "ServicePass123!" }
)

foreach ($svc in $serviceAccounts) {
    try {
        Get-ADUser -Identity $svc.Name -ErrorAction Stop | Out-Null
        Write-Host "  $($svc.Name) already exists" -ForegroundColor Yellow
    } catch {
        $secPass = ConvertTo-SecureString $svc.Pass -AsPlainText -Force
        New-ADUser -Name $svc.Name -SamAccountName $svc.Name `
            -UserPrincipalName "$($svc.Name)@akatsuki.local" `
            -Path "OU=Shinobi,DC=akatsuki,DC=local" `
            -AccountPassword $secPass -Enabled $true `
            -PasswordNeverExpires $true `
            -Description "Service Account"
        Write-Host "  Created: $($svc.Name)" -ForegroundColor Green
    }
}

# ============================================
# 2. CREATE SMB FILE SHARES
# ============================================
Write-Host ""
Write-Host "=== [2/7] Creating SMB File Shares ===" -ForegroundColor Cyan

$shares = @(
    @{ Name = "Public"; Path = "C:\Shares\Public" },
    @{ Name = "IT"; Path = "C:\Shares\IT" },
    @{ Name = "HR"; Path = "C:\Shares\HR" },
    @{ Name = "Finance"; Path = "C:\Shares\Finance" },
    @{ Name = "Backup"; Path = "C:\Shares\Backup" }
)

foreach ($share in $shares) {
    New-Item -ItemType Directory -Path $share.Path -Force | Out-Null
    Remove-SmbShare -Name $share.Name -Force -ErrorAction SilentlyContinue
    New-SmbShare -Name $share.Name -Path $share.Path -FullAccess "Authenticated Users" | Out-Null
    Write-Host "  Created: \\DC01\$($share.Name)" -ForegroundColor Green
}

# ============================================
# 3. INSTALL IIS WEB SERVER
# ============================================
Write-Host ""
Write-Host "=== [3/7] Installing IIS Web Server ===" -ForegroundColor Cyan

$iis = Get-WindowsFeature -Name Web-Server
if (-not $iis.Installed) {
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools | Out-Null
    Write-Host "  IIS installed" -ForegroundColor Green
} else {
    Write-Host "  IIS already installed" -ForegroundColor Yellow
}

# ============================================
# 4. INSTALL FTP SERVER
# ============================================
Write-Host ""
Write-Host "=== [4/7] Installing FTP Server ===" -ForegroundColor Cyan

$ftp = Get-WindowsFeature -Name Web-Ftp-Server
if (-not $ftp.Installed) {
    Install-WindowsFeature -Name Web-Ftp-Server -IncludeAllSubFeature | Out-Null
    Write-Host "  FTP Server installed" -ForegroundColor Green
} else {
    Write-Host "  FTP already installed" -ForegroundColor Yellow
}

# ============================================
# 5. ENABLE WINRM
# ============================================
Write-Host ""
Write-Host "=== [5/7] Enabling WinRM ===" -ForegroundColor Cyan

Enable-PSRemoting -Force -SkipNetworkProfileCheck 2>$null | Out-Null
Write-Host "  WinRM enabled" -ForegroundColor Green

# ============================================
# 6. ENABLE RDP
# ============================================
Write-Host ""
Write-Host "=== [6/7] Enabling RDP ===" -ForegroundColor Cyan

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
Write-Host "  RDP enabled" -ForegroundColor Green

# ============================================
# 7. DOWNLOAD SQL SERVER EXPRESS (Optional)
# ============================================
Write-Host ""
Write-Host "=== [7/7] SQL Server Express ===" -ForegroundColor Cyan

$sqlInstallerPath = "C:\Installers\SQLServer"
New-Item -ItemType Directory -Path $sqlInstallerPath -Force | Out-Null

Write-Host "  SQL Server Express must be downloaded manually." -ForegroundColor Yellow
Write-Host "  Download from: https://www.microsoft.com/en-us/sql-server/sql-server-downloads" -ForegroundColor Yellow
Write-Host "  Place installer in: $sqlInstallerPath" -ForegroundColor Yellow

Write-Host ""
Write-Host @"
+------------------------------------------------------------------+
|  Services Setup Complete!                                        |
|                                                                  |
|  INSTALLED SERVICES:                                             |
|                                                                  |
|  [Service Accounts Created]                                      |
|    - svc_sql       : ServicePass123!                             |
|    - svc_web       : ServicePass123!                             |
|    - svc_backup    : ServicePass123!                             |
|    - svc_ftp       : ServicePass123!                             |
|                                                                  |
|  [SMB Shares]                                                    |
|    - \\DC01\Public                                               |
|    - \\DC01\IT                                                   |
|    - \\DC01\HR                                                   |
|    - \\DC01\Finance                                              |
|    - \\DC01\Backup                                               |
|                                                                  |
|  [Web Services]                                                  |
|    - IIS Web Server (http://DC01)                                |
|    - FTP Server                                                  |
|                                                                  |
|  [Remote Access]                                                 |
|    - WinRM enabled                                               |
|    - RDP enabled                                                 |
|                                                                  |
|  [TODO - Manual Install]                                         |
|    - SQL Server Express (download separately)                    |
|                                                                  |
+------------------------------------------------------------------+

THINGS YOU CAN NOW MISCONFIGURE FOR LEARNING:

1. SPNs on service accounts (Kerberoasting)
   Set-ADUser -Identity svc_sql -ServicePrincipalNames @{Add="MSSQLSvc/DC01:1433"}

2. Disable PreAuth (ASREP Roasting)
   Set-ADAccountControl -Identity svc_legacy -DoesNotRequirePreAuth `$true

3. Share Permissions (sensitive data exposure)
   Set share to Everyone:FullControl, add password files

4. Unconstrained Delegation
   Set-ADComputer -Identity WS01 -TrustedForDelegation `$true

5. Weak ACLs
   Give users GenericAll/WriteDACL on other objects

6. GPP Passwords
   Add cpassword to SYSVOL Group Policy files

7. DNS Admin abuse
   Add-ADGroupMember -Identity DnsAdmins -Members orochimaru

"@ -ForegroundColor Green
