# Akatsuki AD Lab - Setup & Usage Guide

A purposefully vulnerable Active Directory lab environment for learning offensive and defensive security techniques.

---

## Quick Start

```bash
# 1. Build the base boxes (one-time)
cd packer
packer build windows-server-2022.pkr.hcl
packer build windows-11.pkr.hcl

# 2. Start the Domain Controller
cd ../vagrant
vagrant up dc01

# 3. Wait for DC to fully configure (reboot + user creation)
# Check status: vagrant ssh dc01 -c "Get-ADUser -Filter *"

# 4. Start workstations
vagrant up ws01
vagrant up ws02
```

---

## Architecture

```
                         ┌──────────────────────────────────────────────┐
                         │           AKATSUKI.LOCAL DOMAIN              │
                         │              192.168.56.0/24                 │
                         │         (Isolated Private Network)           │
                         └──────────────────────────────────────────────┘
                                            │
            ┌───────────────────────────────┼───────────────────────────┐
            │                               │                           │
            ▼                               ▼                           ▼
┌───────────────────────┐     ┌───────────────────────┐     ┌───────────────────────┐
│        DC01           │     │        WS01           │     │        WS02           │
│   192.168.56.10       │     │   192.168.56.11       │     │   192.168.56.12       │
│                       │     │                       │     │                       │
│ Windows Server 2022   │     │    Windows 11         │     │    Windows 11         │
│ Domain Controller     │     │    Workstation        │     │    Workstation        │
│ DNS Server            │     │                       │     │                       │
│                       │     │ Local Admin: pain     │     │ Local Admin: (none)   │
│ All domain users      │     │                       │     │ CLEAN STATE           │
└───────────────────────┘     └───────────────────────┘     └───────────────────────┘
        │                               │                           │
        │                               │                           │
        └───────────────────────────────┴───────────────────────────┘
                                        │
                              ┌─────────┴─────────┐
                              │   Your Host /     │
                              │   Kali Attack Box │
                              │  192.168.56.100   │
                              └───────────────────┘
```

---

## Network Configuration

| Setting | Value |
|---------|-------|
| Network Name | `akatsuki_lab` |
| Subnet | `192.168.56.0/24` |
| Netmask | `255.255.255.0` |
| Gateway | `192.168.56.1` |
| DNS Server | `192.168.56.10` (DC01) |

### Machine IPs

| Machine | IP Address | RDP Port (Host) | WinRM Port (Host) |
|---------|------------|-----------------|-------------------|
| DC01 | 192.168.56.10 | 33890 | 59850 |
| WS01 | 192.168.56.11 | 33891 | 59851 |
| WS02 | 192.168.56.12 | 33892 | 59852 |

---

## Domain Users

| Username | Full Name | Password | Role | Notes |
|----------|-----------|----------|------|-------|
| `Administrator` | Built-in Admin | `vagrant` | Domain Admin | Default Vagrant account |
| `itachi` | Itachi Uchiha | `Akatsuki123!` | Domain Admin | Member of Domain Admins |
| `pain` | Nagato Uzumaki | `Password123!` | Local Admin (WS01) | Standard domain user |
| `kisame` | Kisame Hoshigaki | `Password123!` | Standard User | **Shares password with pain** |
| `deidara` | Deidara | `Explosion789!` | Standard User | Unique password |
| `sasori` | Sasori | `Puppet456!` | Standard User | Unique password |
| `orochimaru` | Orochimaru | `Snake2024!` | Low Privilege | Attacker starting point |

### Password Strategy

- **itachi**: Strong unique password (Domain Admin)
- **pain & kisame**: Share `Password123!` - enables password spraying practice
- **deidara, sasori**: Unique passwords
- **orochimaru**: Known low-privilege starting point for attack chains

---

## Lab Philosophy: Clean State

This lab starts in a **hardened default state** with no pre-configured vulnerabilities:

| Security Control | Default State |
|-----------------|---------------|
| Kerberos Pre-auth | Enabled (all users) |
| SPNs on users | None configured |
| Delegation | Not configured |
| SMB Signing | Enabled on DC |
| LSA Protection | Not enabled* |
| WDigest | Disabled |
| Cached Credentials | None (no high-priv logins on workstations) |
| Special ACLs | None configured |

*LSA Protection can be enabled as a hardening exercise

### Why Clean State?

Instead of pre-configuring vulnerable states, you **set up each vulnerability yourself**. This teaches you:

1. **What makes attacks possible** - You configure the weakness
2. **How to detect misconfigurations** - You know what to look for
3. **Defense in depth** - Remove the config, attack stops working

See [AD-ATTACKS.md](AD-ATTACKS.md) for setup instructions for each attack.

---

## Vagrant Commands

### Basic Operations

```bash
# Start machines
vagrant up dc01              # Domain Controller (start first!)
vagrant up ws01              # Workstation 1
vagrant up ws02              # Workstation 2

# Stop machines (preserve state)
vagrant halt dc01 ws01 ws02

# Destroy and recreate (clean slate)
vagrant destroy dc01 -f
vagrant up dc01

# Check status
vagrant status

# SSH/WinRM into machines
vagrant ssh dc01             # PowerShell session
vagrant rdp dc01             # RDP session (if vagrant-rdp plugin installed)
```

### Provisioning

```bash
# Re-run provisioning scripts
vagrant provision dc01
vagrant provision ws01

# Reload (restart + re-provision)
vagrant reload dc01 --provision
```

### Snapshots (VMware/VirtualBox)

```bash
# Take snapshot before testing
vagrant snapshot save dc01 clean-state
vagrant snapshot save ws01 clean-state

# Restore after testing
vagrant snapshot restore dc01 clean-state
vagrant snapshot restore ws01 clean-state

# List snapshots
vagrant snapshot list dc01
```

---

## Connecting to the Lab

### From Host Machine

**RDP (GUI access):**
```bash
# DC01
rdesktop localhost:33890 -u Administrator -p vagrant
# Or use your RDP client: localhost:33890

# WS01
rdesktop localhost:33891 -u AKATSUKI\\pain -p 'Password123!'

# WS02
rdesktop localhost:33892 -u AKATSUKI\\orochimaru -p 'Snake2024!'
```

**WinRM (PowerShell):**
```bash
# Using Evil-WinRM from Kali
evil-winrm -i 192.168.56.10 -u Administrator -p vagrant
evil-winrm -i 192.168.56.11 -u pain -p 'Password123!'

# Using PowerShell from Windows
Enter-PSSession -ComputerName 192.168.56.10 -Credential (Get-Credential)
```

### From Kali/Attack Machine

Add Kali to the same network (192.168.56.0/24):

**Option 1: Vagrant Kali box** (uncomment in Vagrantfile)
```ruby
# Already included in Vagrantfile - just uncomment
config.vm.define "kali" ...
```

**Option 2: Existing Kali VM**
```bash
# Add network adapter with IP 192.168.56.100
# Set DNS to 192.168.56.10
```

**Option 3: Docker**
```bash
docker run -it --network host kalilinux/kali-rolling
```

---

## Attack Scenarios

### Scenario 1: Password Spraying (Pre-configured)

The lab is ready for this attack out of the box.

```bash
# From Kali
crackmapexec smb 192.168.56.10 -u users.txt -p 'Password123!' --continue-on-success

# Expected: pain and kisame will authenticate
```

### Scenario 2: Kerberoasting (Requires Setup)

```powershell
# On DC01 - Create vulnerable service account
$password = ConvertTo-SecureString "SQLServicePass123!" -AsPlainText -Force
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" -AccountPassword $password -Enabled $true -Path "OU=Shinobi,DC=akatsuki,DC=local" -PasswordNeverExpires $true
Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/dc01.akatsuki.local:1433"}
```

```bash
# From Kali - Attack
GetUserSPNs.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 192.168.56.10 -request
```

### Scenario 3: LSASS Credential Dump (Requires Setup)

```powershell
# On WS02 - RDP as itachi to cache credentials
# Then from local admin, run mimikatz
mimikatz # sekurlsa::logonpasswords
```

See [AD-ATTACKS.md](AD-ATTACKS.md) for complete attack documentation.

---

## Troubleshooting

### DC Won't Start / AD Not Working

```powershell
# Check AD DS status
Get-Service NTDS, DNS, Netlogon

# Check if domain is ready
Get-ADDomain

# Check users exist
Get-ADUser -Filter * | Select SamAccountName
```

### Workstation Can't Join Domain

```powershell
# Check DNS
nslookup akatsuki.local 192.168.56.10

# Check connectivity
Test-Connection 192.168.56.10

# Check firewall
Test-NetConnection 192.168.56.10 -Port 389
```

### WinRM Not Working

```powershell
# On target machine
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Check service
Get-Service WinRM
```

### Network Connectivity Issues

```bash
# Check VMs are on same network
vagrant ssh dc01 -c "ipconfig"
vagrant ssh ws01 -c "ipconfig"

# Ping between VMs
vagrant ssh ws01 -c "ping 192.168.56.10"
```

---

## Resetting the Lab

### Quick Reset (Keep Base)

```bash
# Destroy workstations only
vagrant destroy ws01 ws02 -f
vagrant up ws01 ws02
```

### Full Reset

```bash
# Destroy everything
vagrant destroy -f

# Recreate
vagrant up dc01
# Wait for DC to complete...
vagrant up ws01 ws02
```

### Reset to Clean State (Snapshots)

```bash
# If you took snapshots
vagrant snapshot restore dc01 clean-state
vagrant snapshot restore ws01 clean-state
vagrant snapshot restore ws02 clean-state
```

---

## Lab Customization

### Adding More Workstations

Add to `Vagrantfile`:

```ruby
config.vm.define "ws03", autostart: false do |ws|
  ws.vm.box = "akatsuki-lab/windows-11"
  ws.vm.hostname = "WS03"
  ws.vm.network "private_network", ip: "192.168.56.13", netmask: "255.255.255.0"
  # ... rest of config
end
```

### Adding More Users

On DC01:

```powershell
$password = ConvertTo-SecureString "NewUserPass!" -AsPlainText -Force
New-ADUser -Name "New User" -SamAccountName "newuser" -AccountPassword $password -Enabled $true -Path "OU=Shinobi,DC=akatsuki,DC=local"
```

### Adding Child Domain

See separate guide for child domain configuration (CHILD.akatsuki.local).

---

## Files Structure

```
Basic-AD-Setup-With-One-Child/
├── docs/
│   ├── LAB.md              # This file - Lab setup guide
│   └── AD-ATTACKS.md       # Attack documentation
├── packer/
│   ├── windows-server-2022.pkr.hcl   # Server base box
│   └── windows-11.pkr.hcl            # Workstation base box
├── vagrant/
│   └── Vagrantfile         # VM definitions
├── scripts/
│   └── provision/
│       ├── setup-dc.ps1           # DC provisioning
│       ├── join-domain-ws01.ps1   # WS01 domain join
│       └── join-domain-ws02.ps1   # WS02 domain join
├── answer_files/           # Windows unattended install
└── boxes/                  # Built Vagrant boxes (gitignored)
```

---

## Requirements

### Software

- Vagrant 2.3+
- VMware Desktop (or VirtualBox)
- Packer 1.9+ (for building base boxes)
- ~50GB disk space (for boxes and VMs)
- 16GB+ RAM recommended (4GB per VM)

### Vagrant Plugins

```bash
# For VMware
vagrant plugin install vagrant-vmware-desktop

# For VirtualBox (if using)
# No additional plugins needed

# Optional: RDP support
vagrant plugin install vagrant-rdp
```

---

## Security Warning

This lab is intentionally vulnerable. **DO NOT**:

- Expose to the internet
- Connect to production networks
- Use on shared/public networks

The private network (`192.168.56.0/24`) should only be accessible from your host machine.

---

## References

- [AD-ATTACKS.md](AD-ATTACKS.md) - Attack documentation and setup
- [Vagrant Documentation](https://developer.hashicorp.com/vagrant/docs)
- [Packer Documentation](https://developer.hashicorp.com/packer/docs)
