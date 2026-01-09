# Akatsuki AD Lab

A fully automated Active Directory lab environment for security testing, penetration testing practice, and red team training.

```
     ___    __         __             __   _    __          __
    /   |  / /______ _/ /________  __/ /__(_)  / /   ____ _/ /_
   / /| | / //_/ __ `/ __/ ___/ / / / //_/ /  / /   / __ `/ __ \
  / ___ |/ ,< / /_/ / /_(__  ) /_/ / ,< / /  / /___/ /_/ / /_/ /
 /_/  |_/_/|_|\__,_/\__/____/\__,_/_/|_/_/  /_____/\__,_/_.___/

                    akatsuki.local
```

---

## Lab Architecture

```
                         ┌─────────────────────┐
                         │        DC01         │
                         │   192.168.56.10     │
                         │  Domain Controller  │
                         │  Windows Server 2022│
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
           ┌────────┴────────┐ ┌────┴────┐ ┌────────┴────────┐
           │      WS01       │ │         │ │      WS02       │
           │  192.168.56.11  │ │ Network │ │  192.168.56.12  │
           │   Windows 11    │ │         │ │   Windows 11    │
           │ Local Admin:    │ │         │ │ Local Admin:    │
           │     pain        │ │         │ │    itachi (DA)  │
           │                 │ │         │ │ (creds cached)  │
           │ Initial Target  │ │         │ │ Lateral Target  │
           └─────────────────┘ └─────────┘ └─────────────────┘
```

---

## Quick Start

### Prerequisites

1. **VMware Workstation Pro** (with VMware Utility for Vagrant)
2. **Vagrant** with VMware plugin
3. **Packer** for building VM images
4. **Python 3.8+**

```bash
# Install Vagrant VMware plugin
vagrant plugin install vagrant-vmware-desktop

# Install Python dependencies
pip install -r requirements.txt
```

### Launch the Lab

```bash
# Run the lab manager
python scripts/lab-manager.py
```

The lab manager provides an interactive menu:

```
=== Akatsuki Lab Manager ===

[1] Download ISOs
[2] Build Vagrant Boxes (Packer)
[3] Start Lab
[4] Destroy Lab
[5] Status
[0] Exit
```

### Manual Launch (Alternative)

```bash
# Build Packer boxes first (if not using lab-manager)
cd packer
packer build -var "iso_path=../iso/windows_server_2022.iso" windows-server-2022.pkr.hcl
packer build -var "iso_path=../iso/windows_11_24h2.iso" windows-11.pkr.hcl

# Start VMs with Vagrant
cd ../vagrant
vagrant up dc01      # Start Domain Controller first
vagrant up ws01      # Start Workstation 1
vagrant up ws02      # Start Workstation 2
```

---

## Domain Information

| Property | Value |
|----------|-------|
| **Domain Name** | akatsuki.local |
| **NetBIOS Name** | AKATSUKI |
| **Domain Functional Level** | Windows Server 2022 |
| **Forest Functional Level** | Windows Server 2022 |

---

## Network Configuration

| Machine | Hostname | IP Address | RDP Port | WinRM Port |
|---------|----------|------------|----------|------------|
| Domain Controller | DC01 | 192.168.56.10 | 33890 | 59850 |
| Workstation 1 | WS01 | 192.168.56.11 | 33891 | 59851 |
| Workstation 2 | WS02 | 192.168.56.12 | 33892 | 59852 |

### Connecting via RDP

```bash
# From host machine
# DC01
rdesktop 127.0.0.1:33890
# or
xfreerdp /v:127.0.0.1:33890 /u:AKATSUKI\\itachi /p:Akatsuki123!

# WS01
xfreerdp /v:127.0.0.1:33891 /u:AKATSUKI\\orochimaru /p:Password123!

# WS02
xfreerdp /v:127.0.0.1:33892 /u:AKATSUKI\\itachi /p:Akatsuki123!
```

---

## User Accounts

### Domain Users

| Username | Full Name | Role | Password | Notes |
|----------|-----------|------|----------|-------|
| `itachi` | Itachi Uchiha | **Domain Admin** | `Akatsuki123!` | Full domain control |
| `pain` | Nagato Uzumaki | Domain User | `Password123!` | Local admin on WS01 |
| `kisame` | Kisame Hoshigaki | Domain User | `Password123!` | Standard user |
| `deidara` | Deidara | Domain User | `Password123!` | Standard user |
| `sasori` | Sasori | Domain User | `Password123!` | Standard user |
| `orochimaru` | Orochimaru | **Low Privilege** | `Password123!` | Ideal starting point |

### Local Accounts

| Machine | Username | Password | Notes |
|---------|----------|----------|-------|
| All | `vagrant` | `vagrant` | Local admin, WinRM access |
| DC01 | `Administrator` | `vagrant` | Built-in admin |

### Local Admin Rights

| Machine | User with Local Admin |
|---------|----------------------|
| WS01 | `AKATSUKI\pain` |
| WS02 | `AKATSUKI\itachi` (Domain Admin) |

---

## Attack Scenarios

### Scenario 1: Full Attack Chain

```
orochimaru@WS01 (low priv)
         │
         ▼ [Local Privilege Escalation]
   pain@WS01 (local admin)
         │
         ▼ [Credential Dump - mimikatz]
         ▼ [Lateral Movement - PtH/WMI/PSRemoting]
   Access to WS02
         │
         ▼ [Dump itachi's cached credentials]
   itachi creds (Domain Admin)
         │
         ▼ [DCSync / Golden Ticket]
   FULL DOMAIN COMPROMISE
```

### Scenario 2: Kerberoasting

1. Login as any domain user
2. Request TGS tickets for service accounts
3. Crack offline with hashcat/john

### Scenario 3: NTLM Relay

1. Set up Responder on attacker machine
2. Capture NTLM hashes
3. Relay to WS01/WS02 for code execution

### Scenario 4: BloodHound Enumeration

1. Run SharpHound collector
2. Import data into BloodHound
3. Find shortest path to Domain Admin

---

## Project Structure

```
Basic-AD-Setup-With-One-Child/
├── README.md                         # This file
├── requirements.txt                  # Python dependencies
├── iso/                              # Windows ISO files (download here)
├── boxes/                            # Packer output (Vagrant boxes)
├── docs/
│   └── AD-ATTACKS.md                 # AD attack reference guide
├── scripts/
│   ├── lab-manager.py                # Main CLI tool
│   └── provision/
│       ├── setup-dc.ps1              # DC setup script
│       ├── join-domain-ws01.ps1      # WS01 domain join
│       ├── join-domain-ws02.ps1      # WS02 domain join
│       ├── setup-winrm.ps1           # WinRM configuration
│       └── bypass-tpm.reg            # Win11 TPM bypass
├── packer/
│   ├── windows-server-2022.pkr.hcl   # Server Packer template
│   ├── windows-11.pkr.hcl            # Win11 Packer template
│   └── vagrantfile-windows.template  # Vagrant template
├── vagrant/
│   └── Vagrantfile                   # VM orchestration
└── answer_files/
    ├── server2022/
    │   └── autounattend.xml          # Server unattended install
    └── win11/
        └── autounattend.xml          # Win11 unattended install
```

---

## VM Specifications

| Property | DC01 | WS01 | WS02 |
|----------|------|------|------|
| **OS** | Windows Server 2022 | Windows 11 | Windows 11 |
| **RAM** | 8 GB | 8 GB | 8 GB |
| **vCPUs** | 2 | 2 | 2 |
| **Disk** | 60 GB | 60 GB | 60 GB |
| **Network** | NAT + Host-Only | NAT + Host-Only | NAT + Host-Only |

**Total Requirements:** ~24 GB RAM, 180 GB disk space

---

## Useful Commands

### Vagrant Management

```bash
cd vagrant

# Start all VMs
vagrant up

# Start specific VM
vagrant up dc01
vagrant up ws01
vagrant up ws02

# Check status
vagrant status

# SSH/WinRM into VM
vagrant winrm dc01

# Stop VMs
vagrant halt

# Destroy VMs
vagrant destroy -f

# Rebuild specific VM
vagrant destroy ws01 -f && vagrant up ws01
```

### Common Attack Commands

```powershell
# From WS01 as local admin (pain)

# Dump credentials
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# Find domain admins
net group "Domain Admins" /domain

# Check local admins
net localgroup administrators

# Test lateral movement
Test-NetConnection -ComputerName WS02 -Port 445
Enter-PSSession -ComputerName WS02 -Credential (Get-Credential)
```

```bash
# From Kali/Attack machine

# CrackMapExec enumeration
crackmapexec smb 192.168.56.10-12 -u orochimaru -p 'Password123!'

# PSExec with credentials
psexec.py AKATSUKI/pain:'Password123!'@192.168.56.12

# DCSync
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.10
```

---

## Troubleshooting

### VMs won't start

```bash
# Check VMware services
sudo /etc/init.d/vmware start

# Verify Vagrant plugin
vagrant plugin list | grep vmware
```

### Domain join fails

```powershell
# On workstation, verify DNS
nslookup akatsuki.local

# Test DC connectivity
Test-NetConnection -ComputerName 192.168.56.10 -Port 389

# Check firewall
Get-NetFirewallProfile | Select Name, Enabled
```

### WinRM connection issues

```powershell
# On target machine
winrm quickconfig
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

---

## Security Notice

This lab is designed for **authorized security testing and educational purposes only**.

- Do NOT use these techniques on systems without explicit permission
- This lab intentionally contains security misconfigurations
- Keep this lab isolated from production networks
- Credentials are intentionally weak for testing purposes

---

## Additional Resources

- [docs/AD-ATTACKS.md](docs/AD-ATTACKS.md) - Comprehensive AD attack reference
- [HackTricks AD Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [The Hacker Recipes](https://www.thehacker.recipes/)

---

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is for educational purposes. Use responsibly.
