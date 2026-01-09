# Join Windows 11 Workstation (WS02) to Akatsuki Domain
# WS02 is a CLEAN workstation - no pre-configured vulnerabilities
# Set up attack conditions manually as documented in AD-ATTACKS.md

param(
    [string]$DomainName = "akatsuki.local",
    [string]$DCIPAddress = "192.168.56.10"
)

$ErrorActionPreference = "Stop"
$DomainAdminUser = "AKATSUKI\Administrator"
$DomainAdminPassword = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($DomainAdminUser, $DomainAdminPassword)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Akatsuki Lab - WS02 Setup" -ForegroundColor Cyan
Write-Host "  (Clean Workstation)" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Domain: $DomainName"
Write-Host "DC IP: $DCIPAddress"
Write-Host ""

# Check if already domain joined
$computerSystem = Get-WmiObject -Class Win32_ComputerSystem
if ($computerSystem.PartOfDomain -and $computerSystem.Domain -eq $DomainName) {
    Write-Host "This machine is already joined to $DomainName" -ForegroundColor Yellow
    exit 0
}

# Step 1: Configure DNS to point to Domain Controller
Write-Host "Step 1: Configuring DNS..." -ForegroundColor Green
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "*Ethernet*" } | Select-Object -First 1

if ($adapter) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($DCIPAddress, "8.8.8.8")
    Write-Host "  DNS set to: $DCIPAddress" -ForegroundColor Green
} else {
    Write-Host "  Warning: Could not find network adapter. DNS not configured." -ForegroundColor Yellow
}

# Wait for DNS to propagate
Start-Sleep -Seconds 5

# Step 2: Test connectivity to Domain Controller
Write-Host "Step 2: Testing connectivity to DC..." -ForegroundColor Green

$maxRetries = 30
$retryCount = 0
$connected = $false

while (-not $connected -and $retryCount -lt $maxRetries) {
    try {
        $ping = Test-Connection -ComputerName $DCIPAddress -Count 1 -Quiet
        if ($ping) {
            # Also try to resolve the domain
            $resolve = Resolve-DnsName -Name $DomainName -ErrorAction SilentlyContinue
            if ($resolve) {
                $connected = $true
                Write-Host "  Successfully connected to DC and resolved domain" -ForegroundColor Green
            }
        }
    } catch {
        # Ignore and retry
    }

    if (-not $connected) {
        $retryCount++
        Write-Host "  Waiting for DC... (attempt $retryCount of $maxRetries)" -ForegroundColor Yellow
        Start-Sleep -Seconds 10
    }
}

if (-not $connected) {
    Write-Host "  ERROR: Could not connect to Domain Controller!" -ForegroundColor Red
    Write-Host "  Make sure DC01 is running and fully configured." -ForegroundColor Red
    exit 1
}

# Step 3: Post-reboot verification (CLEAN setup - no pre-configured vulnerabilities)
Write-Host "Step 3: Setting up clean workstation (no pre-configured attacks)..." -ForegroundColor Green

$postRebootScript = @'
# Post-reboot script for WS02 - CLEAN SETUP
# No local admins added, no cached credentials
# Configure attack conditions manually as documented in AD-ATTACKS.md
$ErrorActionPreference = "SilentlyContinue"

Start-Sleep -Seconds 30  # Wait for domain services

Write-Host "WS02 is ready - clean state with no pre-configured vulnerabilities" -ForegroundColor Green
Write-Host ""
Write-Host "To set up attack conditions, see AD-ATTACKS.md for:" -ForegroundColor Cyan
Write-Host "  - Adding local admins" -ForegroundColor White
Write-Host "  - Caching credentials (RDP as high-priv user)" -ForegroundColor White
Write-Host "  - Enabling WDigest" -ForegroundColor White
Write-Host "  - Configuring delegation" -ForegroundColor White
Write-Host "  - etc." -ForegroundColor White

# Remove the scheduled task after completion
Unregister-ScheduledTask -TaskName "SetupWS02" -Confirm:$false -ErrorAction SilentlyContinue
'@

# Save and register the post-reboot script
$scriptPath = "C:\Scripts\setup-ws02.ps1"
New-Item -Path "C:\Scripts" -ItemType Directory -Force | Out-Null
$postRebootScript | Out-File -FilePath $scriptPath -Encoding UTF8 -Force

# Create scheduled task to run after reboot
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File $scriptPath"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "SetupWS02" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
Write-Host "  Scheduled itachi setup for after reboot" -ForegroundColor Green

# Step 4: Join the domain
Write-Host "Step 4: Joining domain $DomainName..." -ForegroundColor Green

try {
    Add-Computer -DomainName $DomainName -Credential $Credential -Force -Restart
    Write-Host "  Successfully joined domain. Computer will restart..." -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Failed to join domain!" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red

    # Try alternative method with explicit DC
    Write-Host "  Trying alternative method..." -ForegroundColor Yellow
    try {
        Add-Computer -DomainName $DomainName -Server $DCIPAddress -Credential $Credential -Force -Restart
        Write-Host "  Successfully joined domain. Computer will restart..." -ForegroundColor Green
    } catch {
        Write-Host "  Alternative method also failed: $_" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WS02 Setup Complete!" -ForegroundColor Cyan
Write-Host "  (Clean Workstation)" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "WS02 Configuration:" -ForegroundColor Yellow
Write-Host "  IP: 192.168.56.12" -ForegroundColor White
Write-Host "  State: CLEAN - no pre-configured vulnerabilities" -ForegroundColor Green
Write-Host ""
Write-Host "To practice attacks on WS02, configure vulnerabilities" -ForegroundColor Cyan
Write-Host "as documented in AD-ATTACKS.md:" -ForegroundColor Cyan
Write-Host "  - RDP as itachi to cache domain admin creds" -ForegroundColor White
Write-Host "  - Add local admin: Add-LocalGroupMember -Group 'Administrators' -Member 'AKATSUKI\\itachi'" -ForegroundColor White
Write-Host "  - Enable WDigest for plaintext passwords" -ForegroundColor White
Write-Host ""
