# NXC Auto Enumeration Script (Refactored)

A professional, modular automated enumeration script leveraging **NetExec (nxc)** for Active Directory and infrastructure reconnaissance. Features intelligent credential detection, OS-aware targeting, and extensive Impacket integration.

---

### 🚀 **NEW: Python Version (`nxc-auto.py`)**
A new **Python 3** version is now available and is the **recommended** way to run this tool.
- ⚡ **Asynchronous Execution:** Uses `asyncio` for parallel port scanning and multi-protocol enumeration, making it significantly faster than the Bash version.
- 🛠️ **Robust Error Handling:** Better handling of timeouts, schema mismatches, and parsing errors.
- 🐍 **Native Logic:** Cleaner parsing of tool outputs (shares, users, etc.) using Python's regex engine.

---

## Description

`nxc-auto` automates extensive enumeration of Windows domains and Linux systems. It performs credential validation across multiple protocols, identifies vulnerabilities, and suggests actionable exploitation paths.

**Core Features:**
- 🏗️ **Modular Architecture** - Restructured into logical, single-responsibility functions.
- 📜 **Standardized Logging** - Professional terminal output with color-coded status and actionable suggestions.
- 📂 **Structured Output** - Automatically organizes results into protocol-specific directories (`nxc-enum/smb/`, `nxc-enum/ldap/`).
- 🎯 **OS-Aware Enumeration** - Separate modules for Linux and Windows (auto-detected).
- 🔑 **Credential Promotion** - Automatically adopts validated credentials for subsequent deep-dive scans.
- 📋 **User List Extraction** - Auto-extracts usernames from RPC/SID bruteforce for downstream attacks.

## Prerequisites

- **Python 3.7+** (for the Python version)
- **NetExec (nxc)** - The primary engine
- **Impacket** - For `lookupsid`, `secretsdump`, etc.
- **rpcclient** & **smbclient** - For RPC and SMB enumeration

## Installation

```bash
# Clone the repository
git clone https://github.com/su2700/nxc-auto.sh.git
cd nxc-auto.sh

# The script is ready to use!
```

## Global Access (Recommended)

To run `nxc-auto` from any directory on Linux, set up symbolic links for both versions.

### Option 1: Symbolic Links (Recommended)
This allows you to run the scripts from anywhere using the designated command names.

```bash
# 1. Make scripts executable
chmod +x nxc-auto.py nxc-auto.sh

# 2. Set up Python version command (nxc-auto-py)
sudo ln -s "$(pwd)/nxc-auto.py" /usr/local/bin/nxc-auto-py

# 3. Set up Bash version command (nxc-auto)
sudo ln -s "$(pwd)/nxc-auto.sh" /usr/local/bin/nxc-auto
```

### Usage After Setup
- **Python:** `nxc-auto-py -i <IP>`
- **Bash:** `nxc-auto -i <IP>`

### Option 2: Shell Aliases
Add these to your `~/.bashrc` or `~/.zshrc` file:

```bash
alias nxc-auto-py='python3 /path/to/nxc-auto.sh/nxc-auto.py'
alias nxc-auto='/path/to/nxc-auto.sh/nxc-auto.sh'
```

### Option 3: Add to PATH
Add the script's directory to your system PATH:

```bash
# Add this to ~/.bashrc or ~/.zshrc
export PATH="$PATH:/path/to/nxc-auto.sh"
```

### Kali Linux Quick Start

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

## Usage

### 🐍 Python Version (Recommended)
```bash
python3 nxc-auto.py -i <IP> [-u USER] [-p PASSWORD] [-d DOMAIN] [-H HASH] [-o OS_TYPE]
```

### 🐚 Bash Version
```bash
./nxc-auto.sh -i <IP> [-u USER] [-p PASSWORD] [-d DOMAIN] [-H HASH] [-o OS_TYPE]
```

### Examples

**Anonymous enumeration (Windows):**
```bash
python3 nxc-auto.py -i 10.10.10.100
```

**Authenticated Windows scan:**
```bash
python3 nxc-auto.py -i 10.10.10.100 -u svc-admin -p 'management2005' -d spookysec.local
```

**Linux target enumeration:**
```bash
python3 nxc-auto.py -i 10.10.10.200 -o l -u user -p 'password'
```

## Output Structure

Results are stored in the `nxc-enum/` directory:

```
nxc-enum/
├── valid_credentials.txt     # All successfully validated credentials
├── potential_credentials.txt   # Accounts requiring password changes
├── ldap/
│   └── ...
└── smb/
    ├── users_YYYYMMDD.txt    # Extracted username list
    └── ...
```

## Professional Standards

### Logging & Suggestions
The script doesn't just dump data; it provides **Smart Suggestions** based on findings:
- `[SUGGESTION] Accessible shares found! Try: smbclient -N -L //IP`
- `[SUGGESTION] SMB Signing is DISABLED - NTLM relay attacks possible!`
- `[SUGGESTION] ADMIN ACCESS DETECTED (Pwn3d!) - Try impacket-secretsdump`

## OSCP Compliance

✅ **This script is FULLY OSCP COMPLIANT.**

It performs **enumeration only**. It does not auto-exploit, auto-crack, or auto-escalate. It suggests commands (like `secretsdump` or `ntlmrelayx`), but the user must manually execute them.

## License

This script is provided for authorized security testing purposes only.

---
*Maintained with professional engineering standards for the modern penetration tester.*
