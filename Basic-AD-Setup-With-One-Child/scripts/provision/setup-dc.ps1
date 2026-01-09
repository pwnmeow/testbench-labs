# Setup Domain Controller for Akatsuki Lab
# Domain: akatsuki.local
# Creates 5 Akatsuki-themed AD users

param(
    [string]$DomainName = "akatsuki.local",
    [string]$NetBIOSName = "AKATSUKI",
    [string]$DCIPAddress = "192.168.56.10"
)

$ErrorActionPreference = "Stop"
$SafeModePassword = ConvertTo-SecureString "Akatsuki123!" -AsPlainText -Force

# User passwords - varied for realism, with one shared pair for password spraying practice
$Passwords = @{
    "itachi"     = ConvertTo-SecureString "Akatsuki123!" -AsPlainText -Force    # Domain Admin
    "pain"       = ConvertTo-SecureString "Password123!" -AsPlainText -Force    # Shares with kisame (password spray)
    "kisame"     = ConvertTo-SecureString "Password123!" -AsPlainText -Force    # Shares with pain (password spray)
    "deidara"    = ConvertTo-SecureString "Explosion789!" -AsPlainText -Force   # Unique
    "sasori"     = ConvertTo-SecureString "Puppet456!" -AsPlainText -Force      # Unique
    "orochimaru" = ConvertTo-SecureString "Snake2024!" -AsPlainText -Force      # Attacker starting point
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Akatsuki Lab - Domain Controller Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Domain: $DomainName"
Write-Host "NetBIOS: $NetBIOSName"
Write-Host "DC IP: $DCIPAddress"
Write-Host ""

# Check if already a domain controller
$dcCheck = Get-WmiObject -Class Win32_ComputerSystem
if ($dcCheck.DomainRole -ge 4) {
    Write-Host "This machine is already a Domain Controller. Skipping AD DS installation." -ForegroundColor Yellow

    # Still create users if they don't exist
    Import-Module ActiveDirectory
    $usersOU = "OU=Shinobi,DC=akatsuki,DC=local"

    # Check if OU exists
    try {
        Get-ADOrganizationalUnit -Identity $usersOU -ErrorAction Stop
    } catch {
        Write-Host "Creating Shinobi OU..." -ForegroundColor Green
        New-ADOrganizationalUnit -Name "Shinobi" -Path "DC=akatsuki,DC=local"
    }

    # Create users - itachi is Domain Admin, orochimaru is low priv attacker starting point
    $users = @(
        @{Name="Itachi Uchiha"; SamAccountName="itachi"; Description="Sharingan Master - Domain Admin"; IsAdmin=$true},
        @{Name="Nagato Uzumaki"; SamAccountName="pain"; Description="Leader of Akatsuki - Local Admin on WS01"; IsAdmin=$false},
        @{Name="Kisame Hoshigaki"; SamAccountName="kisame"; Description="Monster of the Hidden Mist"; IsAdmin=$false},
        @{Name="Deidara"; SamAccountName="deidara"; Description="Explosion Artist"; IsAdmin=$false},
        @{Name="Sasori"; SamAccountName="sasori"; Description="Sasori of the Red Sand"; IsAdmin=$false},
        @{Name="Orochimaru"; SamAccountName="orochimaru"; Description="Low Privilege User - Attacker Starting Point"; IsAdmin=$false}
    )

    foreach ($user in $users) {
        try {
            Get-ADUser -Identity $user.SamAccountName -ErrorAction Stop
            Write-Host "User $($user.SamAccountName) already exists." -ForegroundColor Yellow
        } catch {
            # Get password from hashtable
            $pwd = $Passwords[$user.SamAccountName]
            Write-Host "Creating user: $($user.SamAccountName)" -ForegroundColor Green
            New-ADUser `
                -Name $user.Name `
                -SamAccountName $user.SamAccountName `
                -UserPrincipalName "$($user.SamAccountName)@$DomainName" `
                -Description $user.Description `
                -Path $usersOU `
                -AccountPassword $pwd `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -ChangePasswordAtLogon $false

            # Add itachi to Domain Admins
            if ($user.IsAdmin) {
                Write-Host "  Adding $($user.SamAccountName) to Domain Admins..." -ForegroundColor Cyan
                Add-ADGroupMember -Identity "Domain Admins" -Members $user.SamAccountName
            }
        }
    }

    Write-Host ""
    Write-Host "User setup complete!" -ForegroundColor Green
    exit 0
}

# Step 1: Configure Static IP
Write-Host "Step 1: Configuring static IP address..." -ForegroundColor Green
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "*Ethernet*" } | Select-Object -First 1

if ($adapter) {
    # Remove existing IP configuration
    Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

    # Set static IP
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $DCIPAddress -PrefixLength 24 -DefaultGateway "192.168.56.1" -ErrorAction SilentlyContinue

    # Set DNS to itself (will be DNS server)
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @("127.0.0.1", "8.8.8.8")

    Write-Host "  IP Address: $DCIPAddress configured" -ForegroundColor Green
} else {
    Write-Host "  Warning: Could not find network adapter" -ForegroundColor Yellow
}

# Step 2: Install AD DS Role
Write-Host "Step 2: Installing AD DS Role..." -ForegroundColor Green
$addsFeature = Get-WindowsFeature -Name AD-Domain-Services

if (-not $addsFeature.Installed) {
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    Write-Host "  AD DS Role installed" -ForegroundColor Green
} else {
    Write-Host "  AD DS Role already installed" -ForegroundColor Yellow
}

# Step 3: Promote to Domain Controller
Write-Host "Step 3: Promoting to Domain Controller..." -ForegroundColor Green
Write-Host "  Domain: $DomainName" -ForegroundColor Cyan
Write-Host "  NetBIOS: $NetBIOSName" -ForegroundColor Cyan

Import-Module ADDSDeployment

# Check if the forest already exists
$forestExists = $false
try {
    $forest = Get-ADForest -ErrorAction Stop
    $forestExists = $true
} catch {
    $forestExists = $false
}

if (-not $forestExists) {
    Write-Host "  Creating new forest..." -ForegroundColor Green

    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetBIOSName `
        -SafeModeAdministratorPassword $SafeModePassword `
        -InstallDns:$true `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -LogPath "C:\Windows\NTDS" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -NoRebootOnCompletion:$false `
        -Force:$true

    Write-Host "  Forest created. Server will reboot..." -ForegroundColor Green
} else {
    Write-Host "  Forest already exists. Skipping promotion." -ForegroundColor Yellow
}

# Note: After reboot, the user creation will happen via a scheduled task or on next vagrant provision
# For simplicity, we'll create a script that runs at next logon

$postRebootScript = @'
# Post-reboot script to create AD users
$ErrorActionPreference = "Stop"
$DomainName = "akatsuki.local"

# User passwords - varied for realism, with one shared pair for password spraying practice
$Passwords = @{
    "itachi"     = ConvertTo-SecureString "Akatsuki123!" -AsPlainText -Force    # Domain Admin
    "pain"       = ConvertTo-SecureString "Password123!" -AsPlainText -Force    # Shares with kisame (password spray)
    "kisame"     = ConvertTo-SecureString "Password123!" -AsPlainText -Force    # Shares with pain (password spray)
    "deidara"    = ConvertTo-SecureString "Explosion789!" -AsPlainText -Force   # Unique
    "sasori"     = ConvertTo-SecureString "Puppet456!" -AsPlainText -Force      # Unique
    "orochimaru" = ConvertTo-SecureString "Snake2024!" -AsPlainText -Force      # Attacker starting point
}

Start-Sleep -Seconds 60  # Wait for AD to be fully operational

Import-Module ActiveDirectory

# Create Shinobi OU
$usersOU = "OU=Shinobi,DC=akatsuki,DC=local"
try {
    Get-ADOrganizationalUnit -Identity $usersOU -ErrorAction Stop
} catch {
    New-ADOrganizationalUnit -Name "Shinobi" -Path "DC=akatsuki,DC=local"
}

# Create users - itachi is Domain Admin, orochimaru is low priv attacker starting point
$users = @(
    @{Name="Itachi Uchiha"; SamAccountName="itachi"; Description="Sharingan Master - Domain Admin"; IsAdmin=$true},
    @{Name="Nagato Uzumaki"; SamAccountName="pain"; Description="Leader of Akatsuki - Local Admin on WS01"; IsAdmin=$false},
    @{Name="Kisame Hoshigaki"; SamAccountName="kisame"; Description="Monster of the Hidden Mist"; IsAdmin=$false},
    @{Name="Deidara"; SamAccountName="deidara"; Description="Explosion Artist"; IsAdmin=$false},
    @{Name="Sasori"; SamAccountName="sasori"; Description="Sasori of the Red Sand"; IsAdmin=$false},
    @{Name="Orochimaru"; SamAccountName="orochimaru"; Description="Low Privilege User - Attacker Starting Point"; IsAdmin=$false}
)

foreach ($user in $users) {
    try {
        Get-ADUser -Identity $user.SamAccountName -ErrorAction Stop
    } catch {
        $pwd = $Passwords[$user.SamAccountName]
        New-ADUser `
            -Name $user.Name `
            -SamAccountName $user.SamAccountName `
            -UserPrincipalName "$($user.SamAccountName)@$DomainName" `
            -Description $user.Description `
            -Path $usersOU `
            -AccountPassword $pwd `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -ChangePasswordAtLogon $false

        # Add itachi to Domain Admins
        if ($user.IsAdmin) {
            Add-ADGroupMember -Identity "Domain Admins" -Members $user.SamAccountName
        }
    }
}

# Remove the scheduled task after completion
Unregister-ScheduledTask -TaskName "CreateADUsers" -Confirm:$false
'@

# Save and register the post-reboot script
$scriptPath = "C:\Scripts\create-ad-users.ps1"
New-Item -Path "C:\Scripts" -ItemType Directory -Force | Out-Null
$postRebootScript | Out-File -FilePath $scriptPath -Encoding UTF8 -Force

# Create scheduled task to run after reboot
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File $scriptPath"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "CreateADUsers" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Domain Controller Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Domain: $DomainName" -ForegroundColor Yellow
Write-Host "NetBIOS: $NetBIOSName" -ForegroundColor Yellow
Write-Host "DC IP: $DCIPAddress" -ForegroundColor Yellow
Write-Host ""
Write-Host "AD Users will be created after reboot:" -ForegroundColor Yellow
Write-Host "  - itachi (Domain Admin)      : Akatsuki123!" -ForegroundColor Red
Write-Host "  - pain (Local Admin on WS01) : Password123!" -ForegroundColor Magenta
Write-Host "  - kisame                     : Password123!  (shares with pain - password spray)" -ForegroundColor White
Write-Host "  - deidara                    : Explosion789!" -ForegroundColor White
Write-Host "  - sasori                     : Puppet456!" -ForegroundColor White
Write-Host "  - orochimaru (Low Priv)      : Snake2024!  (attacker starting point)" -ForegroundColor Gray
Write-Host ""
Write-Host "Lab Philosophy:" -ForegroundColor Cyan
Write-Host "  This is a CLEAN lab - no pre-configured vulnerabilities." -ForegroundColor Cyan
Write-Host "  Set up attack conditions as documented in AD-ATTACKS.md" -ForegroundColor Cyan
Write-Host ""
