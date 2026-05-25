#!/usr/bin/env python3
import asyncio
import argparse
import os
import sys
import socket
import re
import subprocess
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
        "nikto": "sudo apt update && sudo apt install nikto -y",
        "curl": "sudo apt update && sudo apt install curl -y",
    }
    
    missing_tools = []
    install_cmds = []
    
    for tool, install_cmd in tools.items():
        # Check if tool exists in PATH
        proc = await asyncio.create_subprocess_exec(
            "which", tool,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await proc.wait()
        if proc.returncode != 0:
            # Special check for impacket tools
            if tool.startswith("impacket-"):
                alt_tool = tool.replace("impacket-", "") + ".py"
                proc_alt = await asyncio.create_subprocess_exec(
                    "which", alt_tool,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                await proc_alt.wait()
                if proc_alt.returncode == 0:
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
        
        choice = input(f"{Colors.BYELLOW}⚠️  Some enumeration modules will fail. Do you want to continue anyway? [y/N]: {Colors.NC}")
        if choice.lower() != 'y':
            log_error("Exiting. Please install missing dependencies.")
            sys.exit(1)
    else:
        log_success("All essential tools are installed!")

def update_hosts_file(domain, full_host, ip):
    if not domain or domain == ip:
        return

    # Check /etc/hosts (simplified version of bash logic)
    try:
        with open("/etc/hosts", "r") as f:
            hosts_content = f.read()
    except:
        return

    existing_entry = False
    for line in hosts_content.splitlines():
        if domain in line and ip in line:
            existing_entry = True
            break
            
    if existing_entry:
        log_info(f"Domain '{domain}' already exists in /etc/hosts with correct IP")
        return

    log_warning(f"Domain '{domain}' not found in /etc/hosts or points to wrong IP.")
    hosts_entry = f"{ip} {full_host} {domain}" if full_host else f"{ip} {domain}"
    
    choice = input(f"\n{Colors.BYELLOW}❓ Do you want to add '{Colors.BWHITE}{hosts_entry}{Colors.NC}{Colors.BYELLOW}' to /etc/hosts? [y/N]: {Colors.NC}")
    if choice.lower() == 'y':
        cmd = f"echo '{hosts_entry}' | sudo tee -a /etc/hosts >/dev/null"
        subprocess.run(cmd, shell=True)
        log_success("Added/Updated /etc/hosts")
    else:
        log_info("Skipping /etc/hosts update")

async def detect_target_info():
    log_info(f"Attempting to auto-detect target OS and Domain for {State.IP}...")
    
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

        if not State.DOMAIN:
            domain_match = re.search(r'domain:([^\s\)]+)', out)
            name_match = re.search(r'name:([^\s\)]+)', out)
            if domain_match:
                State.DOMAIN = domain_match.group(1).strip()
                log_success(f"Auto-discovered domain: {Colors.BWHITE}{State.DOMAIN}{Colors.NC}")
                full_host = f"{name_match.group(1)}.{State.DOMAIN}" if name_match else ""
                update_hosts_file(State.DOMAIN, full_host, State.IP)
        return

    # Priority 2: LDAP (Port 389)
    if 389 in open_ports:
        State.OS_TYPE = "windows"
        log_success(f"Auto-detected OS: {Colors.BWHITE}Windows{Colors.NC} (via LDAP)")
        if not State.DOMAIN:
            rc, out = await async_run_cmd(["nxc", "ldap", State.IP, "--timeout", "5"])
            domain_match = re.search(r'domain:([^\s\)]+)', out)
            if domain_match:
                State.DOMAIN = domain_match.group(1).strip()
                log_success(f"Auto-discovered domain: {Colors.BWHITE}{State.DOMAIN}{Colors.NC} (via LDAP)")
                update_hosts_file(State.DOMAIN, "", State.IP)
        return

    # Priority 3: RDP (Port 3389)
    if 3389 in open_ports:
        State.OS_TYPE = "windows"
        log_success(f"Auto-detected OS: {Colors.BWHITE}Windows{Colors.NC} (via RDP)")
        return

    # Priority 4: SSH (Port 22)
    if 22 in open_ports:
        State.OS_TYPE = "linux"
        log_success(f"Auto-detected OS: {Colors.BWHITE}Linux{Colors.NC} (via SSH)")
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
            
    return out

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
        # Check Guest and Null Session
        log_info("Checking Guest access...")
        cmd = ["nxc", "smb", State.IP, "-u", "guest", "-p", "", "--shares"]
        if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
        await check_and_suggest("smb", cmd)
        
        log_info("Checking Anonymous access...")
        cmd = ["nxc", "smb", State.IP, "-u", "", "-p", "", "--shares"]
        if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
        await check_and_suggest("smb", cmd)
    else:
        # Authenticated
        cmd = ["nxc", "smb", State.IP, "-u", State.USER]
        if State.PASS: cmd.extend(["-p", State.PASS])
        if State.HASH: cmd.extend(["-H", State.HASH])
        if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
        cmd.append("--shares")
        await check_and_suggest("smb", cmd)

async def enum_ldap(anonymous=True):
    if not await check_port(State.IP, 389, "LDAP"): return
    log_section(f"LDAP Enumeration ({'Anonymous' if anonymous else 'Authenticated'})")
    
    if anonymous:
        cmd = ["nxc", "ldap", State.IP, "-u", "", "-p", "", "--timeout", "15"]
        await check_and_suggest("ldap", cmd)
        
        # Add guest check
        cmd = ["nxc", "ldap", State.IP, "-u", "guest", "-p", "", "--timeout", "15"]
        if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
        await check_and_suggest("ldap", cmd)
    else:
        cmd = ["nxc", "ldap", State.IP, "-u", State.USER]
        if State.PASS: cmd.extend(["-p", State.PASS])
        if State.HASH: cmd.extend(["-H", State.HASH])
        if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
        cmd.extend(["--users", "--groups", "--admin-count", "--timeout", "15"])
        await check_and_suggest("ldap", cmd)

async def enum_rpc():
    log_section("RPC Enumeration")
    if not State.USER:
        log_warning("Skipping RPC Enumeration (no username supplied)")
        return
        
    # rpcclient checks
    if State.PASS:
        rpc_arg = f"-U '{State.DOMAIN}\\{State.USER}%{State.PASS}'"
    elif State.HASH:
        rpc_arg = f"-U '{State.DOMAIN}\\{State.USER}' --pw-nt-hash {State.HASH}"
    else:
        rpc_arg = f"-U '{State.DOMAIN}\\{State.USER}%'"

    log_info("Enumerating domain users via rpcclient...")
    cmd = ["rpcclient", State.IP, "-c", "enumdomusers"]
    # We use subprocess.run for rpcclient as it needs complex quoting
    full_cmd = f"rpcclient {rpc_arg} {State.IP} -c 'enumdomusers'"
    rc, out = await async_run_cmd(["bash", "-c", full_cmd])
    print(out)
    
    log_info("Enumerating domain groups via rpcclient...")
    full_cmd = f"rpcclient {rpc_arg} {State.IP} -c 'enumdomgroups'"
    rc, out = await async_run_cmd(["bash", "-c", full_cmd])
    print(out)

async def enum_nfs():
    if not await check_port(State.IP, 2049, "NFS"): return
    log_section("NFS Enumeration")
    await async_run_cmd(["nxc", "nfs", State.IP, "--shares"])
    await async_run_cmd(["showmount", "-e", State.IP])

async def enum_ftp():
    if not await check_port(State.IP, 21, "FTP"): return
    log_section("FTP Enumeration")
    await async_run_cmd(["nxc", "ftp", State.IP, "-u", "anonymous", "-p", "anonymous"])

async def enum_rdp():
    if not await check_port(State.IP, 3389, "RDP"): return
    log_section("RDP Enumeration")
    if State.USER:
        cmd = ["nxc", "rdp", State.IP, "-u", State.USER]
        if State.PASS: cmd.extend(["-p", State.PASS])
        if State.HASH: cmd.extend(["-H", State.HASH])
        if State.DOMAIN: cmd.extend(["-d", State.DOMAIN])
        await check_and_suggest("rdp", cmd)

async def async_run_cmd(cmd: List[str], timeout: int = 300) -> Tuple[int, str]:
    """Runs a shell command asynchronously and returns return code and output."""
    log_cmd(" ".join(cmd))
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return process.returncode, stdout.decode('utf-8', errors='ignore')
        except asyncio.TimeoutError:
            process.kill()
            return -1, "Command timed out"
    except Exception as e:
        return -2, str(e)

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
    
    args = parser.parse_args()
    State.IP = args.ip
    State.USER = args.user
    State.PASS = args.password
    State.DOMAIN = args.domain
    State.HASH = args.hash
    
    if args.os in ['w', 'windows']:
        State.OS_TYPE = "windows"
    elif args.os in ['l', 'linux']:
        State.OS_TYPE = "linux"
        
    return args

async def main():
    print_banner()
    args = parse_args()
    
    # Create enumeration directory
    os.makedirs(State.ENUM_DIR, exist_ok=True)
    for sub in ['smb', 'ldap', 'http']:
        os.makedirs(os.path.join(State.ENUM_DIR, sub), exist_ok=True)
        
    await check_dependencies()
    
    log_section("Target Configuration")
    log_info(f"Target IP: {Colors.BWHITE}{State.IP}{Colors.NC}")
    
    await check_target_alive(State.IP)
    
    # Discovery
    if not State.OS_TYPE or not State.DOMAIN:
        await detect_target_info()
    
    log_info(f"Target OS Type: {Colors.BWHITE}{State.OS_TYPE}{Colors.NC}")
    if State.DOMAIN:
        log_info(f"Target Domain: {Colors.BWHITE}{State.DOMAIN}{Colors.NC}")

    # Initialize files
    with open(State.VALID_CREDS_FILE, "w") as f: pass
    with open(State.POTENTIAL_CREDS_FILE, "w") as f: pass

    # Phase 1: Anonymous Enumeration
    if not State.USER:
        # Run SMB and LDAP anonymous checks in parallel
        await asyncio.gather(
            enum_smb(anonymous=True),
            enum_ldap(anonymous=True)
        )
        
        # Try to promote any found creds
        if promote_verified_creds():
            log_success("Successfully promoted discovered credentials!")
            
    # Phase 2: Authenticated Enumeration (if we have creds)
    if State.USER:
        log_section("Authenticated Enumeration")
        # Run these in sequence or selective parallel
        if State.OS_TYPE == "windows":
            await enum_smb(anonymous=False)
            await enum_ldap(anonymous=False)
            await enum_rpc()
            await enum_rdp()
        else:
            await enum_smb(anonymous=False) # Samba on Linux
            
    # Phase 3: Other Services (Parallel)
    log_section("Additional Service Checks")
    await asyncio.gather(
        enum_nfs(),
        enum_ftp()
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
