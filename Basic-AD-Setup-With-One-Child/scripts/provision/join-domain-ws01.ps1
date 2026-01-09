# Join Windows 11 Workstation to Akatsuki Domain

param(
    [string]$DomainName = "akatsuki.local",
    [string]$DCIPAddress = "192.168.56.10"
)

$ErrorActionPreference = "Stop"
$DomainAdminUser = "AKATSUKI\Administrator"
$DomainAdminPassword = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($DomainAdminUser, $DomainAdminPassword)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Akatsuki Lab - Domain Join Setup" -ForegroundColor Cyan
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

# Step 3: Create post-reboot script to add pain as local admin
Write-Host "Step 3: Setting up local admin configuration..." -ForegroundColor Green

$postRebootScript = @'
# Post-reboot script to add pain as local administrator
$ErrorActionPreference = "SilentlyContinue"

Start-Sleep -Seconds 30  # Wait for domain services

# Add AKATSUKI\pain to local Administrators group
try {
    Add-LocalGroupMember -Group "Administrators" -Member "AKATSUKI\pain" -ErrorAction Stop
    Write-Host "Added pain as local administrator" -ForegroundColor Green
} catch {
    # May already exist or other error
    Write-Host "Note: Could not add pain to Administrators (may already exist): $_" -ForegroundColor Yellow
}

# Remove the scheduled task after completion
Unregister-ScheduledTask -TaskName "SetupLocalAdmin" -Confirm:$false -ErrorAction SilentlyContinue
'@

# Save and register the post-reboot script
$scriptPath = "C:\Scripts\setup-local-admin.ps1"
New-Item -Path "C:\Scripts" -ItemType Directory -Force | Out-Null
$postRebootScript | Out-File -FilePath $scriptPath -Encoding UTF8 -Force

# Create scheduled task to run after reboot
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File $scriptPath"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "SetupLocalAdmin" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
Write-Host "  Scheduled pain to be added as local admin after reboot" -ForegroundColor Green

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
Write-Host "  WS01 Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "WS01 Configuration:" -ForegroundColor Yellow
Write-Host "  Local Admin: pain" -ForegroundColor Magenta
Write-Host "  IP: 192.168.56.11" -ForegroundColor White
Write-Host ""
Write-Host "Domain Credentials:" -ForegroundColor Yellow
Write-Host "  itachi (Domain Admin)      : Akatsuki123!" -ForegroundColor Red
Write-Host "  pain (Local Admin WS01)    : Password123!" -ForegroundColor Magenta
Write-Host "  kisame                     : Password123! (shares with pain)" -ForegroundColor White
Write-Host "  deidara                    : Explosion789!" -ForegroundColor White
Write-Host "  sasori                     : Puppet456!" -ForegroundColor White
Write-Host "  orochimaru (Low Priv)      : Snake2024!" -ForegroundColor Gray
Write-Host ""
Write-Host "Lab Philosophy:" -ForegroundColor Cyan
Write-Host "  See AD-ATTACKS.md for attack setup instructions" -ForegroundColor Cyan
Write-Host ""
