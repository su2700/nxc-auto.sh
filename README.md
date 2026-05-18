# NXC Auto Enumeration Script (Refactored)

A professional, modular automated enumeration script leveraging **NetExec (nxc)** for Active Directory and infrastructure reconnaissance. Features intelligent credential detection, OS-aware targeting, and extensive Impacket integration.

## Description

`nxc-auto.sh` is a high-performance Bash script that automates extensive enumeration of Windows domains and Linux systems. It performs credential validation across multiple protocols, identifies vulnerabilities, and suggests actionable exploitation paths.

**Refactored v2.0 Features:**
- 🏗️ **Modular Architecture** - Restructured into logical, single-responsibility functions.
- 📜 **Standardized Logging** - Professional terminal output with color-coded status and actionable suggestions.
- 🛡️ **Robust Execution** - Implements `set -uo pipefail` for safer variable and pipe handling.
- 📂 **Structured Output** - Automatically organizes results into protocol-specific directories (`nxc-enum/smb/`, `nxc-enum/ldap/`).
- 🎯 **OS-Aware Enumeration** - Separate modules for Linux (`-o l`) and Windows (`-o w`).
- 🔑 **Credential Promotion** - Automatically adopts validated credentials for subsequent deep-dive scans.
- 📋 **User List Extraction** - Auto-extracts usernames from RPC/SID bruteforce for downstream attacks.

## Prerequisites

- **NetExec (nxc)** - The primary engine
- **bash** (v4+)
- **unbuffer** (part of `expect` package) - For real-time terminal coloring in logs
- **Impacket** - For `lookupsid`, `secretsdump`, etc.
- **rpcclient** & **smbclient** - For RPC and SMB enumeration

### Installation

```bash
# Clone the repository
git clone https://github.com/su2700/nxc-auto.sh.git
cd nxc-auto.sh

# Make the script executable
chmod +x nxc-auto.sh
```

### Kali Linux Quick Start

If you are using Kali Linux, you can install the necessary system dependencies and tools:

```bash
# Install system dependencies
sudo apt update && sudo apt install -y \
    netexec \
    impacket-scripts \
    expect \
    smbclient \
    ldap-utils \
    enum4linux \
    enum4linux-ng \
    nfs-common \
    pipx

# Install ldapdomaindump via pipx (Recommended)
pipx install ldapdomaindump
pipx ensurepath
```

### Dependency Verification

Run this command to verify all required tools are installed properly:

```bash
for tool in nxc unbuffer impacket-secretsdump rpcclient smbclient ldapsearch enum4linux enum4linux-ng ldapdomaindump showmount rpcinfo kerbrute certipy; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "✅ FOUND: $tool"
    else
        echo -e "❌ NOT FOUND: $tool"
    fi
done
```

#### Optional: Kerbrute
`kerbrute` is highly recommended for user validation and password spraying. If you don't have it, you can install it via:

```bash
# Download the latest release (example for Linux amd64)
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O kerbrute
chmod +x kerbrute
sudo mv kerbrute /usr/local/bin/
```

### Global Access (Recommended)

To run `nxc-auto.sh` from any directory, you can add it to your system PATH.

#### Option 1: Create a symbolic link (Easiest)
This allows you to run the script using the command `nxc-auto`.

```bash
sudo ln -s "$(pwd)/nxc-auto.sh" /usr/local/bin/nxc-auto
```

#### Option 2: Add to .bashrc or .zshrc
Add the script's directory to your PATH variable.

```bash
# For Bash
echo "export PATH=\$PATH:$(pwd)" >> ~/.bashrc
source ~/.bashrc

# For Zsh
echo "export PATH=\$PATH:$(pwd)" >> ~/.zshrc
source ~/.zshrc
```

Now you can run the script from anywhere using:
```bash
nxc-auto.sh -i <IP>
```

## Usage

```bash
./nxc-auto.sh -i <IP> [-u USER] [-p PASSWORD] [-d DOMAIN] [-H HASH] [-o OS_TYPE]
```

### Examples

**Anonymous enumeration (Windows):**
```bash
./nxc-auto.sh -i 10.10.10.100
```

**Authenticated Windows scan:**
```bash
./nxc-auto.sh -i 10.10.10.100 -u svc-admin -p 'management2005' -d spookysec.local
```

**Linux target enumeration:**
```bash
./nxc-auto.sh -i 10.10.10.200 -o l -u user -p 'password'
```

## Output Structure

Results are stored in the `nxc-enum/` directory:

```
nxc-enum/
├── valid_credentials.txt     # All successfully validated credentials
├── potential_credentials.txt   # Accounts requiring password changes
├── ldap/
│   ├── anonymous-bind.txt
│   ├── naming-contexts.txt
│   ├── authenticated-ldap.txt
│   ├── kerberoasting.txt
│   └── asreproast.txt
└── smb/
    ├── guest-access.txt
    ├── anonymous-access.txt
    ├── lookupsid-anonymous.txt
    ├── users_YYYYMMDD.txt    # Extracted username list
    ├── authenticated-smb.txt
    └── nfs-showmount.txt
```

## Professional Standards

### Logging & Suggestions
The script doesn't just dump data; it provides **Smart Suggestions** based on findings:
- `[SUGGESTION] Accessible shares found! Try: smbclient -N -L //IP`
- `[SUGGESTION] SMB Signing is DISABLED - NTLM relay attacks possible!`
- `[SUGGESTION] ADMIN ACCESS DETECTED (Pwn3d!) - Try impacket-secretsdump`

### Security & Integrity
- **Credential Protection:** Credentials are used for validation but never stored in cleartext outside the local `nxc-enum` directory.
- **Dependency Validation:** The script verifies all required tools exist in `$PATH` before starting.

## OSCP Compliance

✅ **This script is FULLY OSCP COMPLIANT.**

It performs **enumeration only**. It does not auto-exploit, auto-crack, or auto-escalate. It suggests commands (like `secretsdump` or `ntlmrelayx`), but the user must manually execute them.

## License

This script is provided for authorized security testing purposes only.

---
*Maintained with professional engineering standards for the modern penetration tester.*
