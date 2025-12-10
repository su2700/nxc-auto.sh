# NXC Auto Enumeration Script

A comprehensive automated enumeration script using NetExec (nxc) for Active Directory and infrastructure reconnaissance with intelligent credential detection, OS-aware targeting, and extensive Impacket integration.

## Description

`nxc-auto.sh` is an all-in-one bash script that automates extensive enumeration of Windows domains and Linux systems. It performs credential validation across multiple protocols and services, enumerates users/groups, identifies vulnerabilities, and extracts sensitive information from LDAP, SMB, MSSQL, SSH, FTP, VNC, NFS, WMI, WinRM, and RPC services.

**Latest Features:**
- 🎯 **OS-Aware Enumeration** - Separate Linux (`-o l`) and Windows (`-o w`) modes
- 🔧 **Impacket Integration** - Comprehensive Impacket tool suggestions (40+ commands)
- � **RDP Support** - Credential validation and xfreerdp3 connection commands
- 📋 **User List Extraction** - Auto-creates `rpcuserlist.txt` from RPC enumeration
- �️ **SMB Signing Detection** - Identifies relay attack opportunities
- 🔑 **Kerbrute Integration** - Password spraying and user validation suggestions
- 🎭 **DACL Enumeration** - Administrator ACE and DCSync rights detection
- 📡 **SSH Suggestions** - Ready-to-use SSH/SCP commands with StrictHostKeyChecking disabled

## Prerequisites

- **NetExec (nxc)** - The main tool used for enumeration
- **bash** - Bash shell
- **unbuffer** - For buffered output (usually part of expect package)
- **Impacket** - For secretsdump, rpcdump, and other tools
- **rpcclient** - For RPC enumeration
- **ldapsearch** - For LDAP queries (optional)
- **xfreerdp3** - For RDP connections (optional)
- **kerbrute** - For Kerberos attacks (optional)

### Installation

Install NetExec:
```bash
pip install netexec
# or
apt-get install netexec
```

Install dependencies:
```bash
apt-get install expect impacket-scripts smbclient ldap-utils freerdp3-x11
```

## Usage

```bash
./nxc-auto.sh -i IP [-u USER] [-p PASSWORD] [-d DOMAIN] [-H HASH] [-o OS_TYPE]
```

### Parameters

- `-i IP` - **Required** - Target IP address or hostname
- `-u USER` - Username for authentication (optional for anonymous checks)
- `-p PASSWORD` - Password for the user
- `-d DOMAIN` - Domain name (e.g., spookysec.local)
- `-H HASH` - NTLM hash for pass-the-hash attacks
- `-o OS_TYPE` - Target OS type: `w`/`windows` (default) or `l`/`linux`
- `-h` - Show help message

### Examples

**Anonymous enumeration (Windows):**
```bash
./nxc-auto.sh -i 10.64.182.102
```

**Linux target enumeration:**
```bash
./nxc-auto.sh -i 10.67.185.163 -o l -u aubreanna -p 'bubb13guM!@#123'
```

**Windows with credentials:**
```bash
./nxc-auto.sh -i 10.64.182.102 -u svc-admin -p 'management2005' -d spookysec.local
```

**Pass-the-hash:**
```bash
./nxc-auto.sh -i 10.64.182.102 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c -d spookysec.local
```

**Username only (null password attempts):**
```bash
./nxc-auto.sh -i 10.64.182.102 -u svc-admin -d spookysec.local
```

## Output Structure

All results are saved in the `nxc-enum/` directory:

```
nxc-enum/
├── ldap/
│   ├── domain-sid.txt
│   ├── active-users.txt
│   ├── admin-count-users.txt
│   ├── admin-ace.txt (NEW)
│   ├── dcsync-rights.txt (NEW)
│   ├── password-not-required.txt
│   ├── trusted-for-delegation.txt
│   ├── kerberoasting.txt
│   ├── asreproasting.txt
│   ├── domain-controllers.txt
│   ├── gmsa.txt
│   ├── maq.txt
│   ├── adcs.txt
│   ├── desc-users.txt
│   └── ldap-checker.txt
└── smb/
    ├── shares.txt
    ├── users.txt
    ├── rpc-enumdomusers.txt (NEW)
    ├── lookupsid-anonymous.txt (NEW)
    ├── logged-users.txt
    ├── rid-bruteforce.txt
    ├── domain-groups.txt
    ├── local-groups.txt
    ├── pw-policy.txt
    ├── spider-plus.txt
    ├── zerologon.txt
    ├── mssql-info.txt
    ├── ssh-credentials.txt (NEW)
    ├── ssh-whoami.txt (NEW)
    ├── rdp-credentials.txt (NEW)
    ├── ftp-credentials.txt
    ├── nfs-shares.txt
    ├── sam-hashes.txt
    ├── lsa-secrets.txt
    └── ntds-dump.txt

Additional files in current directory:
├── rpcuserlist.txt (NEW) - Clean username list for attacks
├── kerberoasting.txt - Kerberoast hashes
└── asreproasting.txt - AS-REP hashes
```

## Features

### OS-Aware Enumeration

**Linux Mode (`-o l`):**
- SSH credential validation and command execution
- FTP enumeration
- Basic SMB (Samba) checks
- NFS enumeration
- **Skips:** All Windows-specific checks (LDAP, AD, RPC, WinRM, MSSQL, Kerberos)

**Windows Mode (`-o w` or default):**
- Full Active Directory enumeration
- LDAP/AD attacks (Kerberoasting, AS-REP roasting)
- RPC/WinRM/MSSQL enumeration
- SMB signing detection
- DACL enumeration
- Zerologon detection

### Impacket Tools Integration

**With Credentials:**
- 40+ ready-to-use Impacket commands
- Credential dumping (secretsdump variants)
- Remote execution (psexec, wmiexec, smbexec, dcomexec, atexec)
- Kerberos attacks (GetNPUsers, GetUserSPNs, getTGT, getST)
- SMB/File operations (smbclient, smbserver, lookupsid, reg)
- LDAP enumeration (GetADUsers, GetADComputers, dacledit, findDelegation)
- MSSQL attacks
- Network attacks (ntlmrelayx, rpcdump, samrdump)
- Ticket manipulation (ticketConverter, ticketer)

**Without Credentials (Anonymous):**
- User enumeration (lookupsid, samrdump, GetNPUsers)
- Network enumeration (rpcdump, netview)
- SMB enumeration (smbclient anonymous)
- NTLM relay setup
- SMB server for file transfer

### Anonymous/Guest Access Detection
- **Guest Access Check** - Attempts guest login (with or without domain)
- **Anonymous SMB** - Tests null session access with share enumeration
- **Anonymous LDAP** - Tests anonymous LDAP binds
- **Anonymous FTP** - Tests anonymous FTP access
- **Anonymous RPC** - lookupsid.py, GetNPUsers.py, samrdump.py, enum4linux
- **Smart Suggestions** - Only shows commands when shares/resources are actually accessible

### Credential Validation
- SMB (with share enumeration and signing detection)
- LDAP
- RDP (NEW)
- WinRM
- RPC (with anonymous fallback using `-N` flag)
- MSSQL
- SSH (with connection suggestions)
- FTP
- VNC
- WMI

### User & Group Enumeration
- Domain users via SMB and LDAP
- **RPC user extraction** - Auto-creates `rpcuserlist.txt` with clean usernames
- Active users via LDAP
- Admin users (admin-count)
- Logged-on users
- RID bruteforce enumeration
- Domain groups
- Local groups

### LDAP-Specific Enumeration
- Domain SID retrieval
- Kerberoastable users (with hash cracking suggestions)
- AS-REP Roastable users (with hash cracking suggestions)
- Password not required accounts
- Trusted for delegation accounts
- Domain controllers list
- GMSA (Group Managed Service Accounts) passwords
- ADCS templates
- User descriptions
- LDAP channel binding checker
- Machine Account Quota (MAQ)
- **Administrator ACE** - Shows who can modify Administrator account (NEW)
- **DCSync Rights** - Shows who can dump domain credentials (NEW)

### SMB-Specific Enumeration
- Shared directories with writable share detection
- **SMB Signing Detection** - Identifies relay attack opportunities (NEW)
- Password policy
- SAM hashes dump
- LSA secrets dump
- NTDS database dump
- Share spidering (find interesting files) - with 60s timeout
- Zerologon vulnerability check - **with exploitation guidance**
- Antivirus detection

### SSH Enumeration (Linux/Windows)
- Credential validation
- Command execution testing
- **Connection suggestions** with sshpass and StrictHostKeyChecking disabled (NEW)
- SCP file transfer commands

### RDP Enumeration (Windows)
- Credential validation (NEW)
- **xfreerdp3 connection commands** with proper syntax (NEW)
- rdesktop alternative suggestions

### Remote Code Execution Testing
- SMB command execution
- SMB PowerShell execution
- WMI command execution
- WinRM command execution
- SSH command execution
- MSSQL command execution (xp_dirtree, sp_databases)

### Vulnerability Detection & Exploitation

#### Zerologon (CVE-2020-1472)
When detected, the script provides:
- ⚠️ Critical vulnerability warning
- 📋 Step-by-step exploitation commands
- 🔧 Password restoration instructions
- 🚨 Warnings about domain breakage

#### Kerberoasting & AS-REP Roasting
When hashes are found:
- 🔍 Automatic hash type detection (etype 23, 17, 18)
- 💻 Ready-to-use John the Ripper commands
- 🔨 Ready-to-use Hashcat commands with correct modes

## Intelligent Features

### Automatic User List Creation

After RPC enumeration, the script creates `rpcuserlist.txt`:
```
[+] Extracted 17 usernames to: rpcuserlist.txt

[+] Suggested attacks with this user list:

# 1. Password spraying with NetExec:
nxc smb 10.64.182.102 -u rpcuserlist.txt -p 'Password123' --continue-on-success

# 2. Password spraying with kerbrute:
kerbrute passwordspray -d spookysec.local --dc 10.64.182.102 rpcuserlist.txt 'Password123'

# 3. AS-REP roasting (no password needed):
GetNPUsers.py spookysec.local/ -usersfile rpcuserlist.txt -no-pass -dc-ip 10.64.182.102

# 4. Validate usernames with kerbrute:
kerbrute userenum -d spookysec.local --dc 10.64.182.102 rpcuserlist.txt
```

### SMB Signing Detection

**When SMB signing is ENABLED:**
```
[!] SMB Signing is ENABLED
[+] Impact:
  - NTLM relay attacks are NOT possible
  - Man-in-the-middle attacks are prevented

[+] What you CAN still do:
# 1. Password Spraying
# 2. Kerberoasting
# 3. AS-REP Roasting
# 4. User enumeration
# 5. Vulnerability checks (Zerologon, PetitPotam)
# 6. LDAP enumeration and BloodHound
```

**When SMB signing is DISABLED:**
```
[!] SMB Signing is DISABLED - NTLM relay attacks possible!
[+] Exploitation suggestions:
  ntlmrelayx.py -tf targets.txt -smb2support
  ntlmrelayx.py -t ldap://10.64.182.102 --escalate-user lowpriv
```

### Smart Command Suggestions

The script automatically suggests actionable commands based on discovered access:

**SSH Access:**
```bash
[+] SSH access successful! Connect with:
ssh -o StrictHostKeyChecking=no aubreanna@10.67.185.163

# Or with password in command (less secure):
sshpass -p 'bubb13guM!@#123' ssh -o StrictHostKeyChecking=no aubreanna@10.67.185.163

# Copy files from remote:
scp -o StrictHostKeyChecking=no aubreanna@10.67.185.163:/path/to/file .
```

**RDP Access:**
```bash
[+] RDP access successful! Connect with:
xfreerdp3 /v:10.64.182.102 /u:spookysec.local\\svc-admin /p:'management2005' /cert:ignore /clipboard /dynamic-resolution

# Or with rdesktop:
rdesktop -u svc-admin -p 'management2005' -d spookysec.local 10.64.182.102
```

**Writable Shares:**
```bash
[!] WRITABLE SHARES DETECTED - POTENTIAL PRIVILEGE ESCALATION!
[+] Exploitation suggestions:
  # Upload malicious files, backdoors, or scripts
  smbclient -U 'domain/user%pass' //10.64.182.102/SYSVOL
```

### Timeout Protection

The script includes intelligent timeouts to prevent hanging:
- **FTP checks**: 5 seconds
- **LDAP anonymous**: 5 seconds
- **Spider Plus**: 60 seconds
- **Zerologon**: 30 seconds
- **RPC**: Uses `-N` flag for null password (no prompts)

## Color Codes

- **Cyan (`\033[96m`)** - Standard information headers
- **Red (`\033[91m`)** - Module-specific enumeration or critical warnings
- **Green (`\033[92m`)** - Successful access and suggested commands
- **Yellow (`\033[93m`)** - Warnings and skipped checks

## Security Notes

### Credentials

- Script works with or without credentials
- Anonymous checks are performed first
- Username-only mode attempts null password authentication
- Use service accounts or authorized test accounts
- Supports both password and hash-based authentication

### Dangerous Operations

**Enabled by default:**
- Kerberoasting (with hash extraction)
- AS-REP Roasting (with hash extraction)
- LSA secrets dump
- NTDS dump
- Administrator ACE enumeration
- DCSync rights enumeration

**Zerologon Warning:**
- ⚠️ Will break the domain if not restored properly
- Only use in authorized testing environments
- Follow restoration steps carefully

## OSCP Exam Compliance

### ✅ **This Script is OSCP COMPLIANT**

This script is **fully allowed** in the OSCP exam as it performs **enumeration only** and does not auto-exploit vulnerabilities.

### Why It's OSCP-Safe

**OSCP Exam Rules:**
> "You may use any tools, scripts, or exploits as long as you understand what they do and can explain them."

This script:
- ✅ **Enumeration Only** - Discovers information, doesn't exploit
- ✅ **Manual Exploitation Required** - Only suggests commands, doesn't run them
- ✅ **No Auto-Exploitation** - You must manually execute all attacks
- ✅ **Transparent** - Bash script, easy to read and understand
- ✅ **Time Saver** - Automates tedious enumeration, not exploitation

### What the Script Does (ALLOWED)

**Passive/Active Reconnaissance:**
- ✅ User/group enumeration
- ✅ Share enumeration
- ✅ Service detection and validation
- ✅ Credential validation (tests if creds work)
- ✅ SMB signing detection
- ✅ Password policy enumeration
- ✅ DACL enumeration (reads permissions)

**Hash Extraction (Manual Cracking Required):**
- ✅ Kerberoasting hash **extraction** (you crack manually)
- ✅ AS-REP roasting hash **extraction** (you crack manually)
- ✅ Saves hashes to files for manual cracking

**Vulnerability Detection (Not Exploitation):**
- ✅ Zerologon **detection** (doesn't exploit, just checks)
- ✅ Writable share **detection** (doesn't upload files)
- ✅ DCSync rights **detection** (doesn't dump credentials)

### What You Must Do Manually (OSCP Requirement)

The script **suggests** these commands, but **YOU** must run them:

```bash
# Hash cracking (manual)
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoasting.txt
hashcat -m 13100 kerberoasting.txt rockyou.txt

# Credential dumping (manual)
impacket-secretsdump domain/user:pass@10.10.10.100

# Remote execution (manual)
impacket-psexec domain/user:pass@10.10.10.100
impacket-wmiexec domain/user:pass@10.10.10.100

# Connecting to services (manual)
xfreerdp3 /v:10.10.10.100 /u:user /p:pass
ssh user@10.10.10.100
```

### What the Script Does NOT Do

- ❌ Doesn't automatically crack passwords
- ❌ Doesn't automatically exploit vulnerabilities
- ❌ Doesn't automatically escalate privileges
- ❌ Doesn't automatically dump credentials
- ❌ Doesn't automatically execute commands
- ❌ Doesn't automatically create backdoors
- ❌ Doesn't use Metasploit (no restrictions)

### How to Use in OSCP Exam

**1. Initial Enumeration (Automated):**
```bash
# Run comprehensive enumeration
./nxc-auto.sh -i 10.10.10.100 -d domain.local

# With credentials
./nxc-auto.sh -i 10.10.10.100 -u user -p 'password' -d domain.local
```

**2. Review Output (Manual):**
- Read the enumeration results
- Review suggested commands
- Understand what each tool does
- Identify attack vectors

**3. Execute Attacks (Manual):**
```bash
# Example: Script found Kerberoastable users
# YOU manually crack the hashes
john --wordlist=rockyou.txt kerberoasting.txt

# Example: Script validated credentials
# YOU manually execute commands
impacket-psexec domain/user:pass@10.10.10.100
```

**4. Document Everything:**
- Save enumeration output for your report
- Screenshot successful exploits
- Explain your methodology

### OSCP Exam Benefits

**Time Management:**
- ⏱️ Saves hours on repetitive enumeration
- 🎯 Lets you focus on exploitation and privilege escalation
- 📋 Provides comprehensive recon in minutes

**Comprehensive Coverage:**
- 🔍 Checks all common services (SMB, LDAP, RDP, SSH, etc.)
- 🎭 Tests multiple authentication methods
- 🚨 Identifies vulnerabilities automatically

**Actionable Output:**
- 💡 Suggests next steps based on findings
- 📝 Provides ready-to-use commands
- 🗂️ Organizes results in structured files

### Important Notes for OSCP

1. **Understand the Output** - Know what each enumeration technique does
2. **Manual Exploitation** - Always execute suggested commands yourself
3. **Document Findings** - Save all output for your exam report
4. **Explain Your Work** - Be able to explain each enumeration step
5. **No Auto-Exploitation** - This is enumeration, not exploitation

### Example OSCP Workflow

```bash
# 1. Initial scan
nmap -p- -A 10.10.10.100

# 2. Run nxc-auto.sh for comprehensive enumeration
./nxc-auto.sh -i 10.10.10.100

# 3. Review results and identify attack vectors
cat nxc-enum/ldap/kerberoasting.txt
cat rpcuserlist.txt

# 4. Manual exploitation
john --wordlist=rockyou.txt kerberoasting.txt
impacket-psexec domain/crackeduser:crackedpass@10.10.10.100

# 5. Privilege escalation (manual)
# ... your manual exploitation continues
```

### Recommendation

**YES - Use this script in your OSCP exam!**

It's a **legitimate enumeration tool** that:
- ✅ Complies with OSCP exam rules
- ✅ Saves valuable time during the exam
- ✅ Provides comprehensive reconnaissance
- ✅ Suggests exploitation paths (doesn't execute them)
- ✅ Helps you focus on actual exploitation and privilege escalation

This is **exactly the type of automation** that's allowed and encouraged in OSCP - it's intelligent enumeration, not auto-exploitation! 🎯



## Troubleshooting

### "nxc: error: unrecognized arguments"

Some flags may vary depending on your nxc version. Check available options:
```bash
nxc ldap --help
nxc smb --help
```

### Connection Errors

Verify network connectivity:
```bash
ping [IP]
nmap -p 22,389,445,3389,5985 [IP]
```

### Permission Denied

Ensure the provided credentials have sufficient privileges:
```bash
nxc smb [IP] -u [USER] -p [PASSWD] -d [DOMAIN]
```

### RPC Password Prompts

The script now handles this with `-N` flag for rpcclient when no password is provided.

### LDAP Module Crashes

LDAP modules (maq, adcs, etc.) require valid credentials. The script now skips them when only username is provided.

## Advanced Usage

### Linux Target Enumeration

```bash
# Full Linux enumeration
./nxc-auto.sh -i 10.67.185.163 -o l -u user -p 'password'

# Anonymous Linux checks
./nxc-auto.sh -i 10.67.185.163 -o l
```

### Exporting Results

All output is automatically saved to text files. You can parse results:
```bash
grep "DOMAIN" nxc-enum/ldap/active-users.txt
grep "\[+\]" nxc-enum/smb/sam-hashes.txt
cat rpcuserlist.txt  # Clean username list
```

### Hash Cracking

Kerberoast and AS-REP hashes are automatically saved:
```bash
# The script suggests the correct hashcat mode based on encryption type
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoasting.txt
hashcat -m 13100 kerberoasting.txt /usr/share/wordlists/rockyou.txt
```

### Using the RPC User List

```bash
# Password spraying
nxc smb 10.64.182.102 -u rpcuserlist.txt -p 'Password123' --continue-on-success

# Kerbrute
kerbrute passwordspray -d domain.local --dc 10.64.182.102 rpcuserlist.txt 'Password123'

# AS-REP roasting
GetNPUsers.py domain.local/ -usersfile rpcuserlist.txt -no-pass -dc-ip 10.64.182.102
```

## References

- [NetExec (nxc) Documentation](https://www.netexec.wiki/)
- [Active Directory Exploitation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [Zerologon Explanation](https://www.secura.com/blog/zero-logon)
- [Impacket Tools](https://github.com/fortra/impacket)
- [Kerbrute](https://github.com/ropnop/kerbrute)

## License

This script is provided as-is for authorized security testing purposes only.

## Disclaimer

Unauthorized access to computer systems is illegal. Ensure you have written permission before using this script. The author assumes no liability for misuse or damage caused by this script.

## Changelog

### Latest Updates (v2.0)
- ✅ **OS-aware enumeration** - Linux (`-o l`) and Windows (`-o w`) modes
- ✅ **Impacket integration** - 40+ tool suggestions with/without credentials
- ✅ **RDP support** - Credential validation and xfreerdp3 commands
- ✅ **User list extraction** - Auto-creates `rpcuserlist.txt` from RPC enumeration
- ✅ **SMB signing detection** - Identifies relay attack opportunities
- ✅ **Kerbrute integration** - Password spraying and user validation suggestions
- ✅ **DACL enumeration** - Administrator ACE and DCSync rights detection
- ✅ **SSH suggestions** - Ready-to-use SSH/SCP commands with StrictHostKeyChecking disabled
- ✅ **Improved credential handling** - Username-only mode with null password attempts
- ✅ **No password prompts** - RPC uses `-N` flag for anonymous access
- ✅ **LDAP module protection** - Requires credentials to prevent crashes
- ✅ **Writable share detection** - Highlights privilege escalation opportunities
- ✅ **Remote execution suggestions** - wmiexec, psexec, smbexec based on admin access

### Previous Updates (v1.0)
- ✅ Command-line argument parsing (`-i`, `-u`, `-p`, `-d`, `-H`)
- ✅ Smart anonymous/guest access detection with actionable suggestions
- ✅ NFS enumeration with mount command suggestions
- ✅ LDAP anonymous access detection with ldapsearch commands
- ✅ Zerologon vulnerability detection with exploitation guidance
- ✅ Kerberoasting/AS-REP roasting with automatic hash type detection
- ✅ Intelligent timeouts to prevent script hanging
- ✅ Share-based success detection (no false positives)
