#!/bin/bash
# CyberPatriot Interactive Service Remover
#
# This script finds all enabled services and compares them against a
# master "known good" whitelist. It will then ask you to purge anything
# that is NOT on the whitelist.

# --- Configuration ---
# This is the master whitelist you provided.
# I added 'sshd' because it's critical for remote access and was missing.
MASTER_WHITELIST=" acpid alsa-utils anacron apparmor apport avahi-daemon bluetooth bootmisc.sh brltty ccsclient checkfs.sh checkroot-bootclean.sh checkroot.sh console-setup console-setup.sh cron cups cups-browsed dbus dns-clean gdm3 grub-common hddtemp hostname.sh hwclock.sh irqbalance kerneloops keyboard-setup keyboard-setup.sh killprocs kmod lightdm lm-sensors mountall-bootclean.sh mountall.sh mountdevsubfs.sh mountkernfs.sh mountnfs-bootclean.sh mountnfs.sh networking network-manager ondemand openbsd-inetd open-vm-tools plymouth plymouth-log pppd-dns procps rc.local resolvconf rsync rsyslog saned sendsigs speech-dispatcher thermald udev ufw umountfs umountnfs.sh umountroot unattended-upgrades urandom uuidd vmware-tools vmware-tools-thinprint whoopsie x11-common sshd ssh "

set -eo pipefail

# --- Helper Functions ---
log() { echo -e "\n[+] $1"; }
warn() { echo -e "[!] $1"; }

# --- Root Check ---
if [[ $(id -u) -ne 0 ]]; then
  echo "This script must be run as root (use sudo)." >&2
  exit 1
fi

# --- Step 1: Get User Purge List ---
log "The script has a master whitelist of known-good services."
echo "Are there any services ON THIS WHITELIST you want to remove?"
echo "Example: If you don't need printing or bluetooth, type: cups cups-browsed bluetooth"
read -r USER_PURGE_INPUT
USER_PURGE_LIST=" $USER_PURGE_INPUT "

# --- Step 2: Get Enabled System Services ---
log "Finding all enabled services on the system..."
# Get all enabled services, remove .service, strip @ instances, and sort uniquely
mapfile -t ENABLED_SERVICES < <(systemctl list-unit-files --type=service --state=enabled | awk '{print $1}' | sed 's/\.service$//' | sed 's/@.*$//' | sort -u)

# --- Step 3: Iterate and Ask for Removal ---
declare -a REMOVED_PKGS

for service in "${ENABLED_SERVICES[@]}"; do
    
    # Clean service name for comparison
    service_clean=$(echo "$service" | sed 's/@.*$//')
    
    # Check if the service is on the master whitelist
    if [[ "$MASTER_WHITELIST" == *" $service_clean "* ]]; then
        # It's on the whitelist. Now check if the user *wants* to remove it.
        if [[ "$USER_PURGE_LIST" == *" $service_clean "* ]]; {
            warn "Service '$service' is whitelisted but you asked to remove it."
            read -p "[?] Confirm removal of '$service'? (y/N): " choice
            case "$choice" in
                y|Y)
                    # User confirmed, find the package and purge
                    pkg=$(dpkg-query -S "$(systemctl show -p FragmentPath "$service.service" | cut -d= -f2)" | cut -d: -f1)
                    if [[ -n "$pkg" ]]; then
                        log "Purging $pkg (for $service)..."
                        apt-get purge -y "$pkg"
                        REMOVED_PKGS+=("$pkg")
                    else
                        log "Stopping/disabling $service (could not find package)..."
                        systemctl disable --now "$service.service" 2>/dev/null || true
                    fi
                    ;;
                *)
                    log "Skipping $service."
                    ;;
            esac
        }
        else
            # On whitelist and not in user purge list, so we keep it.
            log "Keeping whitelisted service: $service"
        fi
    else
        # --- Not on the master whitelist, HIGHLY suspicious ---
        warn "Service '$service' is enabled but NOT on the master whitelist."
        read -p "[?] Remove this unauthorized service? (Y/n): " choice
        case "$choice" in
            n|N)
                log "Skipping $service."
                ;;
            *)
                # Default is YES. Find package and purge.
                pkg=$(dpkg-query -S "$(systemctl show -p FragmentPath "$service.service" | cut -d= -f2)" 2>/dev/null | cut -d: -f1)
                if [[ -n "$pkg" ]]; then
                    log "Purging $pkg (for $service)..."
                    apt-get purge -y "$pkg"
                    REMOVED_PKGS+=("$pkg")
                else
                    log "Stopping/disabling $service (could not find package)..."
                    systemctl disable --now "$service.service" 2>/dev/null || true
                fi
                ;;
        esac
    fi
done

# --- Step 4: Final Cleanup ---
if [[ ${#REMOVED_PKGS[@]} -gt 0 ]]; then
    log "Running 'apt autoremove' to clean up dependencies..."
    apt-get autoremove -y
    log "Removed ${#REMOVED_PKGS[@]} packages."
else
    log "No packages were removed."
fi

log "Service review complete."
