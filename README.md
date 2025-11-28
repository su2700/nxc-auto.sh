# NXC Auto Enumeration Script

A comprehensive automated enumeration script using NetExec (nxc) for Active Directory and infrastructure reconnaissance.

## Description

`nxc-auto.sh` is an all-in-one bash script that automates extensive enumeration of Windows domains and systems. It performs credential validation across multiple protocols and services, enumerates users/groups, identifies vulnerabilities, and extracts sensitive information from LDAP, SMB, MSSQL, SSH, FTP, VNC, NFS, WMI, WinRM, and RPC services.

## Prerequisites

- **NetExec (nxc)** - The main tool used for enumeration
- **bash** - Bash shell
- **unbuffer** - For buffered output (usually part of expect package)

### Installation

Install NetExec:
```bash
pip install netexec
# or
apt-get install netexec
```

Install unbuffer:
```bash
apt-get install expect
```

## Usage

```bash
./nxc-auto.sh [IP] [USER] [PASSWD] [DOMAIN]
```

### Parameters

- `IP` - Target IP address or hostname
- `USER` - Valid domain username for authentication
- `PASSWD` - Password for the user
- `DOMAIN` - Domain name (e.g., fusion.corp)

### Example

```bash
./nxc-auto.sh 10.65.167.164 lparker 'password123' fusion.corp
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
│   ├── kerberoastable.txt
│   ├── asreproastable.txt
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
    ├── enum-lsass.txt
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
    └── ntds-dump.txt
```

## Features

### Credential Validation
- SMB
- LDAP
- WinRM
- RPC
- MSSQL
- SSH
- FTP
- VNC

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
- Kerberoastable users
- AS-REP Roastable users
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
- NTDS database dump
- Share spidering (find interesting files)
- LSASS protection enumeration
- Zerologon vulnerability check
- Antivirus detection

### Remote Code Execution Testing
- SMB command execution
- SMB PowerShell execution
- WMI command execution
- WinRM command execution
- SSH command execution
- MSSQL command execution (xp_dirtree, sp_databases)

### Additional Services
- NFS share enumeration
- MSSQL database enumeration
- VNC access testing

## Color Codes

- **Cyan (`\033[96m`)** - Standard information headers
- **Red (`\033[91m`)** - Module-specific enumeration or exploitation attempts

## Security Notes

### OSCP Compliance

The script includes commented-out commands for potentially dangerous operations:
- Kerberoasting
- AS-REP Roasting
- Trusted for Delegation exploitation
- ACE enumeration (daclread)
- DCSync exploitation

These are intentionally disabled to comply with OSCP exam restrictions. Uncomment only in authorized environments.

### Credentials

- Ensure the provided credentials have appropriate permissions
- Use a service account or user with sufficient privileges
- Recommended: Domain user or Domain Admin account

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

## License

This script is provided as-is for authorized security testing purposes only.

## Disclaimer

Unauthorized access to computer systems is illegal. Ensure you have written permission before using this script. The author assumes no liability for misuse or damage caused by this script.
