#!/bin/bash

BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color

echo -e "${CYAN}This script was brought to you by atomtables and swaroop for CPC under MCA/EAMS...${NC}"
read -t 5
# Read expected users from user input until an empty line is entered
echo "Enter the expected(including admin) users, one per line. Press Enter on an empty line when finished:"
EXPECTED_USERS=()
while read -r USER && [ -n "$USER" ]; do
    EXPECTED_USERS+=("$USER")
done

echo "Enter the admin users, one per line. Press Enter on an empty line when finished:"
ADMIN_USERS=()
while read -r USER && [ -n "$USER" ]; do
    ADMIN_USERS+=("$USER")
done

# Get a list of local users on the system
ALL_USERS=($(cat /etc/passwd | grep '/home' | cut -d: -f1))

# Check for unexpected users
for USER in "${ALL_USERS[@]}"; do
    if [[ ! " ${EXPECTED_USERS[@]} " =~ " ${USER} " ]]; then
        echo -e "${RED}User '${USER}' is not in the expected list."
	      read -p "Delete user? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || continue
	      ./deleteuser.sh "${USER}"
    fi
done

# Check for users that shouldnt have admin
for USER in "${ALL_USERS[@]}"; do
    if [[ ${ADMIN_USERS[@]} =~ $USER ]]
    then
        if groups "$USER" | grep -q '\bsudo\b'; then
            echo -e "${GREEN}User '${USER}' has admin privileges, which should be correct.${NC}"
        else
      	    read -p "Give admin to ${USER}? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || continue
            sudo adduser $USER sudo
            echo "Gave admin to '$USER'"
        fi
    else
        if groups "$USER" | grep -q '\bsudo\b'; then
            read -p "Remove admin from ${USER}? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || continue
            sudo deluser $USER sudo
            echo "Removed admin from '$USER'"
        else
      	    echo -e "${GREEN}User '${USER}' does not have admin privileges, which should be correct.${NC}"
        fi
    fi
done
