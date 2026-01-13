# Setup WinRM for Vagrant/Packer communication
# This script runs during first logon via autounattend.xml

$ErrorActionPreference = "SilentlyContinue"

Write-Host "Configuring WinRM..."

# Enable WinRM
winrm quickconfig -q
winrm quickconfig -transport:http

# Configure WinRM settings
winrm set winrm/config '@{MaxTimeoutms="7200000"}'
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="2048"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/client/auth '@{Basic="true"}'

# Disable firewall for lab environment
netsh advfirewall set allprofiles state off

# Set WinRM service to auto-start
Set-Service -Name WinRM -StartupType Automatic
Restart-Service WinRM

# Disable network location wizard
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" -Force | Out-Null

# Set network profile to Private
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue

Write-Host "WinRM configuration complete!"
