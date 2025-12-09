# NXC Auto Enumeration Script

A comprehensive automated enumeration script using NetExec (nxc) for Active Directory and infrastructure reconnaissance with intelligent credential detection and actionable command suggestions.

## Description

`nxc-auto.sh` is an all-in-one bash script that automates extensive enumeration of Windows domains and systems. It performs credential validation across multiple protocols and services, enumerates users/groups, identifies vulnerabilities, and extracts sensitive information from LDAP, SMB, MSSQL, SSH, FTP, VNC, NFS, WMI, WinRM, and RPC services.

**New Features:**
- 🎯 **Smart Access Detection** - Automatically detects anonymous/guest access and suggests login commands
- 📋 **Actionable Suggestions** - Provides ready-to-use commands for discovered shares and services
- ⚡ **Intelligent Timeouts** - Prevents hanging on slow operations (FTP, LDAP, spider_plus, Zerologon)
- 🚨 **Vulnerability Alerts** - Detects and provides exploitation steps for critical vulnerabilities like Zerologon
- 🔍 **NFS Support** - Enumerates and suggests mount commands for NFS shares

## Prerequisites

- **NetExec (nxc)** - The main tool used for enumeration
- **bash** - Bash shell
- **unbuffer** - For buffered output (usually part of expect package)
- **Impacket** - For secretsdump, rpcdump, and other tools
- **rpcclient** - For RPC enumeration
- **ldapsearch** - For LDAP queries (optional)

### Installation

Install NetExec:
```bash
pip install netexec
# or
apt-get install netexec
```

Install dependencies:
```bash
apt-get install expect impacket-scripts smbclient ldap-utils
```

## Usage

```bash
./nxc-auto.sh -i IP [-u USER] [-p PASSWORD] [-d DOMAIN] [-H HASH]
```

### Parameters

- `-i IP` - **Required** - Target IP address or hostname
- `-u USER` - Username for authentication (optional for anonymous checks)
- `-p PASSWORD` - Password for the user
- `-d DOMAIN` - Domain name (e.g., fusion.corp)
- `-H HASH` - NTLM hash for pass-the-hash attacks
- `-h` - Show help message

### Examples

**Anonymous enumeration:**
```bash
./nxc-auto.sh -i 10.67.166.62
```

**With domain (enables guest access check):**
```bash
./nxc-auto.sh -i 10.67.166.62 -d fusion.corp
```

**With credentials:**
```bash
./nxc-auto.sh -i 10.67.166.62 -u jmurphy -p 'u8WC3!kLsgw=#bRY' -d fusion.corp
```

**Pass-the-hash:**
```bash
./nxc-auto.sh -i 10.67.166.62 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c -d fusion.corp
```

## Output Structure

All results are saved in the `nxc-enum/` directory:

```
nxc-enum/
├── ldap/
│   ├── domain-sid.txt
│   ├── active-users.txt
│   ├── admin-count-users.txt
│   ├── password-not-required.txt
│   ├── trusted-for-delegation.txt
│   ├── kerberoasting.txt
│   ├── asreproasting.txt
│   ├── domain-controllers.txt
│   ├── gmsa.txt
│   ├── maq.txt
│   ├── adcs.txt
│   ├── desc-users.txt
│   ├── ldap-checker.txt
│   └── anti_virus.txt
└── smb/
    ├── shares.txt
    ├── users.txt
    ├── logged-users.txt
    ├── rid-bruteforce.txt
    ├── domain-groups.txt
    ├── local-groups.txt
    ├── pw-policy.txt
    ├── spider-plus.txt
    ├── zerologon.txt
    ├── mssql-info.txt
    ├── mssql-xp-dirtree.txt
    ├── mssql-databases.txt
    ├── ssh-credentials.txt
    ├── ssh-whoami.txt
    ├── ftp-credentials.txt
    ├── ftp-shares.txt
    ├── nfs-shares.txt
    ├── vnc-credentials.txt
    ├── wmi-credentials.txt
    ├── wmi-whoami.txt
    ├── sam-hashes.txt
    ├── lsa-secrets.txt
    └── ntds-dump.txt
```

## Features

### Anonymous/Guest Access Detection
- **Guest Access Check** - Attempts guest login (with or without domain)
- **Anonymous SMB** - Tests null session access
- **Anonymous LDAP** - Tests anonymous LDAP binds
- **Anonymous FTP** - Tests anonymous FTP access
- **Smart Suggestions** - Only shows commands when shares/resources are actually accessible

### Credential Validation
- SMB (with share enumeration)
- LDAP
- WinRM
- RPC (with anonymous fallback)
- MSSQL
- SSH
- FTP
- VNC
- WMI

### User & Group Enumeration
- Domain users via SMB and LDAP
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

### SMB-Specific Enumeration
- Shared directories
- Password policy
- SAM hashes dump
- LSA secrets dump
- NTDS database dump
- Share spidering (find interesting files) - with 60s timeout
- Zerologon vulnerability check - **with exploitation guidance**
- Antivirus detection

### NFS Enumeration
- NFS share discovery
- Permission detection
- Automatic mount command suggestions

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

### Smart Command Suggestions

The script automatically suggests actionable commands based on discovered access:

**Anonymous SMB Access:**
```bash
[+] Anonymous SMB access successful! Suggested commands:
rpcclient -U '' -N 10.67.166.62
smbclient -U '' -N //10.67.166.62/IPC$
smbclient -U '' -N //10.67.166.62/NETLOGON
```

**Guest SMB Access:**
```bash
[+] Guest SMB access successful! Suggested commands:
rpcclient -U 'guest%' 10.67.166.62
smbclient -U 'guest%' //10.67.166.62/Users
```

**Anonymous LDAP Access:**
```bash
[+] Anonymous LDAP access successful! Suggested commands:
ldapsearch -x -H ldap://10.67.166.62 -b "DC=fusion,DC=corp" -s sub "(objectClass=*)" | tee ldap-dump.txt
ldapsearch -x -H ldap://10.67.166.62 -b "DC=fusion,DC=corp" "(objectClass=user)" | tee ldap-users.txt
```

**NFS Shares:**
```bash
[+] NFS shares found! Suggested mount commands:
sudo mount -t nfs 10.67.166.62:/users /mnt/nfs
# Or with specific version: sudo mount -t nfs -o vers=3 10.67.166.62:/users /mnt/nfs
```

**Valid Credentials (with Admin access):**
```bash
[+] Valid credentials for smb! Suggested command:
[+] Admin access (Pwn3d!) detected - tools below will work!
impacket-psexec fusion.corp/jmurphy:password@10.67.166.62
impacket-smbexec fusion.corp/jmurphy:password@10.67.166.62

[+] Suggested connections:
smbclient -U 'fusion.corp/jmurphy%password' //10.67.166.62/ADMIN$
smbclient -U 'fusion.corp/jmurphy%password' //10.67.166.62/C$
```

### Timeout Protection

The script includes intelligent timeouts to prevent hanging:
- **FTP checks**: 5 seconds
- **LDAP anonymous**: 5 seconds
- **Spider Plus**: 60 seconds
- **Zerologon**: 30 seconds
- **RPC**: Anonymous with no password prompt

## Color Codes

- **Cyan (`\033[96m`)** - Standard information headers
- **Red (`\033[91m`)** - Module-specific enumeration or critical warnings
- **Green (`\033[92m`)** - Successful access and suggested commands
- **Yellow (`\033[93m`)** - Warnings and skipped checks

## Security Notes

### Credentials

- Script works with or without credentials
- Anonymous checks are performed first
- Use service accounts or authorized test accounts
- Supports both password and hash-based authentication

### Dangerous Operations

**Enabled by default:**
- Kerberoasting (with hash extraction)
- AS-REP Roasting (with hash extraction)
- LSA secrets dump
- NTDS dump (previously disabled, now enabled)

**Zerologon Warning:**
- ⚠️ Will break the domain if not restored properly
- Only use in authorized testing environments
- Follow restoration steps carefully

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
nmap -p 389,445,5985 [IP]
```

### Permission Denied

Ensure the provided credentials have sufficient privileges:
```bash
nxc smb [IP] -u [USER] -p [PASSWD] -d [DOMAIN]
```

### RPC Password Prompts

If you see password prompts during anonymous enumeration, the script now handles this with `-N` flag for rpcclient.

## Advanced Usage

### Running Specific Sections

To run only LDAP enumeration:
```bash
grep -A 100 "LDAP Module Enumeration" nxc-auto.sh | bash
```

### Exporting Results

All output is automatically saved to text files. You can parse results:
```bash
grep "FUSION" nxc-enum/ldap/active-users.txt
grep "\[+\]" nxc-enum/smb/sam-hashes.txt
```

### Hash Cracking

Kerberoast and AS-REP hashes are automatically saved to `kerberoasting.txt` and `asreproasting.txt`:
```bash
# The script suggests the correct hashcat mode based on encryption type
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoasting.txt
hashcat -m 13100 kerberoasting.txt /usr/share/wordlists/rockyou.txt
```

### Combining with Other Tools

Use the output files with other tools:
```bash
# Extract usernames
grep -oP '(?<=\s)\w+(?=\s+20\d{2})' nxc-enum/smb/users.txt

# Extract hashes for cracking
grep ":" nxc-enum/smb/sam-hashes.txt | cut -d: -f1,4
```

## References

- [NetExec (nxc) Documentation](https://www.netexec.wiki/)
- [Active Directory Exploitation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [Zerologon Explanation](https://www.secura.com/blog/zero-logon)
- [Impacket Tools](https://github.com/fortra/impacket)

## License

This script is provided as-is for authorized security testing purposes only.

## Disclaimer

Unauthorized access to computer systems is illegal. Ensure you have written permission before using this script. The author assumes no liability for misuse or damage caused by this script.

## Changelog

### Latest Updates
- ✅ Added command-line argument parsing (`-i`, `-u`, `-p`, `-d`, `-H`)
- ✅ Smart anonymous/guest access detection with actionable suggestions
- ✅ NFS enumeration with mount command suggestions
- ✅ LDAP anonymous access detection with ldapsearch commands
- ✅ Zerologon vulnerability detection with exploitation guidance
- ✅ Kerberoasting/AS-REP roasting with automatic hash type detection
- ✅ Intelligent timeouts to prevent script hanging
- ✅ RPC anonymous access with no password prompts
- ✅ LSA secrets dump added
- ✅ NTDS dump enabled (previously disabled)
- ✅ Share-based success detection (no false positives)
