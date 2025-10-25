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

# Get the current username
current_user=$(whoami)
echo -e "${YELLOW}Running under ${current_user}.${NC}"

# Get a list of all local users in /etc/passwd
ALL_USERS=($(awk -F: '/\/home/ {print $1}' /etc/passwd))

# Remove the current user from the list
ALL_USERS=(${ALL_USERS[@]/$current_user})
echo -e "${MAGENTA}Changing passwords for:\n${ALL_USERS}${NC}"

# Prompt for the new password
echo -ne "${YELLOW}Enter the new password for all users: ${BLUE}"
read new_password

# Change passwords for all users
for user in "${ALL_USERS[@]}"; do
    echo -e "${BLUE}Changing password for ${user}...${NC}"
    echo "$user:$new_password" | sudo chpasswd
done

echo "Passwords changed for all users except $current_user."
