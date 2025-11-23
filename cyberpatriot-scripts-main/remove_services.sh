#!/bin/bash

# --- Configuration ---
WHITELIST_FILE="whitelist_of_services.txt"

# --- Colors for readability ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root.${NC}"
   exit 1
fi

# --- Check for Whitelist File ---
if [[ ! -f "$WHITELIST_FILE" ]]; then
    echo -e "${RED}Error: Could not find $WHITELIST_FILE.${NC}"
    echo "Please create this file and paste your service names in it."
    exit 1
fi

echo -e "${GREEN}Loading whitelist from $WHITELIST_FILE...${NC}"

# Load whitelist into an Associative Array for fast lookup
declare -A WHITELIST_MAP
while read -r service; do
    # Skip empty lines or comments
    [[ -z "$service" || "$service" =~ ^# ]] && continue
    # Trim whitespace
    clean_service=$(echo "$service" | tr -d '[:space:]')
    WHITELIST_MAP["$clean_service"]=1
done < "$WHITELIST_FILE"

echo -e "${GREEN}Scanning enabled system services...${NC}"
echo "----------------------------------------------------"

# Get list of all enabled services
# We filter for 'enabled' because those start at boot.
ENABLED_SERVICES=$(systemctl list-unit-files --type=service --state=enabled --no-legend | awk '{print $1}' | sed 's/\.service$//' | sort)

for service in $ENABLED_SERVICES; do
    
    # Handle services with @ (like getty@tty1), strip the instance identifier for checking
    base_service=$(echo "$service" | sed 's/@.*$//')

    # Check if the service exists in our Whitelist Map
    if [[ ${WHITELIST_MAP[$base_service]} ]]; then
        # It is whitelisted, do nothing and move on (comment out next line to see them)
        # echo -e "[OK] $service is whitelisted."
        continue
    else
        # --- FOUND A ROGUE SERVICE ---
        echo -e "\n${RED}[!] SUSPICIOUS SERVICE FOUND: $service ${NC}"
        
        # Try to identify what package owns it to help the user decide
        service_path=$(systemctl show -p FragmentPath "$service.service" | cut -d= -f2)
        package_name=$(dpkg -S "$service_path" 2>/dev/null | cut -d: -f1)
        
        if [[ -n "$package_name" ]]; then
            echo -e "    Owned by package: ${YELLOW}$package_name${NC}"
        else
            echo -e "    ${YELLOW}No package owner found (might be a standalone script or virus).${NC}"
        fi

        # --- The Interaction ---
        read -p "Do you want to REMOVE this service? (y/n): " choice
        case "$choice" in 
            y|Y)
                if [[ -n "$package_name" ]]; then
                    echo -e "Purging package $package_name..."
                    apt-get purge -y "$package_name"
                else
                    echo -e "Disabling and stopping service manually..."
                    systemctl disable --now "$service.service"
                    rm "$service_path" 2>/dev/null
                fi
                echo -e "${GREEN}Removed/Disabled $service.${NC}"
                ;;
            *)
                echo -e "${YELLOW}Skipping $service.${NC}"
                ;;
        esac
    fi
done

echo -e "\n----------------------------------------------------"
echo -e "${GREEN}Scan complete. Run 'apt autoremove' to clean up dependencies if you removed packages.${NC}"
