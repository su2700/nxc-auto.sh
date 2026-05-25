# Gemini Project Context: nxc-auto.sh

## Project Overview
`nxc-auto` is a professional, modular automated enumeration tool designed for penetration testing and Active Directory reconnaissance. It serves as a wrapper and orchestrator for **NetExec (nxc)**, providing an intelligent, "ADHD-friendly" interface for infrastructure security assessments.

The project contains two primary implementations:
1.  **`nxc-auto.py` (Recommended):** An asynchronous Python 3 version that uses `asyncio` for parallel port scanning and multi-protocol enumeration. It is faster and more robust than the original shell script.
2.  **`nxc-auto.sh`:** A comprehensive Bash version that follows similar logic but is restricted to sequential execution.

### Key Features
- **Intelligent OS Detection:** Automatically identifies target OS (Windows vs. Linux) to tailor enumeration modules.
- **Credential Promotion:** Successfully validated credentials are automatically adopted for subsequent deep-dive scans.
- **Structured Output:** Results are organized into protocol-specific subdirectories under `nxc-enum/`.
- **Actionable Suggestions:** Based on findings (e.g., SMB signing disabled), the tool provides copy-pasteable commands for next steps.
- **OSCP Compliance:** Focuses strictly on enumeration and reconnaissance; it does not perform automated exploitation or privilege escalation.

---

## Technical Stack & Dependencies
- **Core Engine:** [NetExec (nxc)](https://github.com/PennyWise8/NetExec)
- **Primary Languages:** Python 3.7+ (Asynchronous), Bash
- **System Dependencies (Kali/Linux):**
    - `impacket-scripts` (lookupsid, secretsdump, etc.)
    - `smbclient` / `rpcclient`
    - `ldap-utils`
    - `enum4linux` / `enum4linux-ng`
    - `nfs-common`
    - `ldapdomaindump` (via pipx)

---

## Usage & Commands

### Running Enumeration
The tool requires a target IP address as the minimum input.

**Python Version:**
```bash
python3 nxc-auto.py -i <IP> [-u USER] [-p PASSWORD] [-d DOMAIN] [-H HASH] [-o OS_TYPE]
```

**Bash Version:**
```bash
./nxc-auto.sh -i <IP> [-u USER] [-p PASSWORD] [-d DOMAIN] [-H HASH] [-o OS_TYPE]
```

### Setup & Global Access
To make the tools accessible globally:
```bash
# Example symbolic link setup
sudo ln -s "$(pwd)/nxc-auto.py" /usr/local/bin/nxc-auto-py
sudo ln -s "$(pwd)/nxc-auto.sh" /usr/local/bin/nxc-auto
```

---

## Development Conventions

### Code Structure
- **Modular Functions:** Logic is broken down into single-responsibility functions (e.g., `enum_smb`, `detect_target_info`).
- **Asynchronous Patterns:** The Python version prioritizes `asyncio.gather` for parallel port checks and service discovery.
- **State Management:** Uses a global `State` class (in Python) or global variables (in Bash) to track discovery data across modules.

### Logging & UI
- **Color Coding:** Standardized terminal colors for Info (Cyan), Success (Green), Warning (Yellow), and Error (Red).
- **Sectioning:** Large output is organized into visual "sections" for easier scanning during time-sensitive assessments.

### Performance & Safety
- **Timeouts:** All remote tool calls should have sensible timeouts (default 15-30s) to prevent hanging during scans.
- **No-Destruction Policy:** Do not implement auto-fix logic that could disrupt target services (e.g., clearing remote logs).
- **Tool Check:** Always verify dependencies using `check_dependencies` before execution.
- **Cross-Platform Compatibility:** The codebase has been audited for Linux compatibility (LF line endings, proper shebangs, and no hardcoded local user paths). It is optimized for Kali Linux and other Debian-based security distributions.
