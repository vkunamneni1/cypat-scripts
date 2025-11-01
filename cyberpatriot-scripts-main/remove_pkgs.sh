#!/bin/bash
# CyberPatriot Interactive Package Remover
#
# This script reads from 'blacklist_of_pkgs.txt' and cross-references it
# with installed packages. It then asks you which packages to remove.

# --- Configuration ---
BLACKLIST_FILE="blacklist_of_pkgs.txt"
set -eo pipefail

# --- Helper Functions ---
log() { echo -e "\n[+] $1"; }
warn() { echo -e "[!] $1"; }

# --- Root Check ---
if [[ $(id -u) -ne 0 ]]; then
  echo "This script must be run as root (use sudo)." >&2
  exit 1
fi

# --- Check for Blacklist File ---
if [[ ! -f "$BLACKLIST_FILE" ]]; then
    warn "BLACKLIST_FILE '$BLACKLIST_FILE' not found."
    warn "Please make sure it's in the same directory as this script."
    exit 1
fi

# --- Step 1: Get Whitelist from User ---
log "Enter the packages from the blacklist you need to KEEP (whitelist)."
echo "Separate packages with a space (e.g., nmap wireshark metasploit-framework):"
read -r WHITELIST_INPUT
# Add spaces around for easier matching, so 'nmap' doesn't match 'nmap-common'
WHITELIST=" $WHITELIST_INPUT "

# --- Step 2: Get Installed and Blacklisted Packages ---
log "Checking for installed packages... (this may take a moment)"

# Get a list of all installed packages
INSTALLED_PKGS=$(dpkg-query -W -f='${Package}\n' 2>/dev/null | sort)

# Get the list of all blacklisted packages
BLACKLISTED_PKGS=$(cat "$BLACKLIST_FILE" | sort)

# Find the intersection: packages that are BOTH installed AND on the blacklist
mapfile -t POTENTIAL_REMOVE < <(comm -12 <(echo "$INSTALLED_PKGS") <(echo "$BLACKLISTED_PKGS"))

# --- Step 3: Iterate and Ask for Removal ---
declare -a REMOVED_PKGS

if [[ ${#POTENTIAL_REMOVE[@]} -eq 0 ]]; then
    log "No prohibited packages from the list are installed. Good job!"
    exit 0
fi

log "Found ${#POTENTIAL_REMOVE[@]} prohibited packages. Reviewing for removal..."

for pkg in "${POTENTIAL_REMOVE[@]}"; do
    # Check if the package is on the user's whitelist
    if [[ "$WHITELIST" == *" $pkg "* ]]; then
        log "Ignoring whitelisted package: $pkg"
        continue
    fi

    # Ask the user for confirmation
    read -p "[?] Found prohibited package: '$pkg'. Remove? (y/N): " choice
    case "$choice" in
        y|Y)
            log "Removing $pkg..."
            apt-get purge -y "$pkg"
            REMOVED_PKGS+=("$pkg")
            ;;
        *)
            log "Skipping $pkg."
            ;;
    esac
done

# --- Step 4: Final Cleanup ---
if [[ ${#REMOVED_PKGS[@]} -gt 0 ]]; then
    log "Running 'apt autoremove' to clean up dependencies..."
    apt-get autoremove -y
    log "Removed ${#REMOVED_PKGS[@]} packages."
else
    log "No packages were removed."
fi

log "Package review complete."
