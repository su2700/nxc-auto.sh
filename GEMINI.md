# GEMINI.md - nxc-auto.sh Project Context

## Project Overview
`nxc-auto.sh` is a professional, modular automated enumeration script designed for penetration testing. It leverages **NetExec (nxc)** and other industry-standard tools to perform comprehensive reconnaissance of infrastructure and Active Directory environments.

### Core Features
- **Modular Design:** Protocol-specific enumeration modules (SMB, LDAP, etc.).
- **OS-Aware:** Tailors enumeration logic based on the target OS (Windows or Linux).
- **Smart Suggestions:** Provides actionable commands (like `rpcclient` top 10) when access is gained.
- **Credential Promotion:** Automatically uses discovered credentials for deeper scans.

## Building and Running
As a Bash-based project, no "build" step is required. Ensure dependencies like `netexec`, `impacket`, and `smbclient` are installed.

### Key Commands
- **Run Enumeration:** `./nxc-auto.sh -i <IP> [-u <USER>] [-p <PASS>] [-d <DOMAIN>]`
- **Linux Mode:** `./nxc-auto.sh -i <IP> -o l`
- **Help:** `./nxc-auto.sh -h`

## Development Conventions
- **Standardized Logging:** Use `log_info`, `log_success`, `log_warning`, and `log_error`.
- **Modularity:** New protocols should be added as separate functions (e.g., `enum_rdp`).
- **User Guidance:** Always provide "next step" suggestions when a vulnerability or access point is found.
- **Strict Variable Handling:** Always quote variables to prevent word splitting.
- **Output Management:** All results are stored in the `nxc-enum/` directory.
