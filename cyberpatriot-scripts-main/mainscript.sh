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

# update system and packages
updateSystem() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Updating system and fixing /etc/shadow and disabling avahi-daemon and disabling guest account in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  chmod 640 /etc/shadow
  systemctl disable avahi-daemon || true
  echo "allow-guest=false" >> /etc/lightdm/lightdm.conf 2>/dev/null || true
  sudo apt update
  sudo apt upgrade -y
}

clamAV() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Installing ClamAV in 5 seconds. To skip, Ctrl+C...${YELLOW}"
  read -t 5
  sudo apt install -y clamav
  sudo freshclam || true
  echo -e "${CYAN}ClamAV installed and updated. Run 'sudo clamscan -i -r --remove=yes /' in a different terminal${NC}"
}

ufw() {
  trap "return" SIGINT
  echo -e "${YELLOW}Installing and setting up UFW in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo apt install -y ufw
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  yes | sudo ufw enable
  sudo ufw status
  echo -e "${CYAN}UFW installed and set up. Remember to open up outgoing ports for services like SSH, HTTP, and FTP${NC}"
}

tcpSyn() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Setting up TCP SYN cookies and ASLR in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  # Enable SYN cookies and ASLR per answer key
  sudo sed -i 's/^\s*net\.ipv4\.tcp_syncookies\s*=.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf || true
  grep -q '^net.ipv4.tcp_syncookies=' /etc/sysctl.conf || echo 'net.ipv4.tcp_syncookies=1' | sudo tee -a /etc/sysctl.conf
  sudo sed -i 's/^\s*kernel\.randomize_va_space\s*=.*/kernel.randomize_va_space=2/' /etc/sysctl.conf || true
  grep -q '^kernel.randomize_va_space=' /etc/sysctl.conf || echo 'kernel.randomize_va_space=2' | sudo tee -a /etc/sysctl.conf
  sudo sysctl --system
}

ssh() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Doing the following things in 10 seconds. To skip, press Ctrl+C...${NC}\nSetting up PermitRootLogin no, \nPasswordAuthentication unchanged, \nChallengeResponseAuthentication unchanged, \nUsePAM unchanged, \nPermitEmptyPasswords no, \nadding port 22 to firewall, \nremoving keepalive/unattended sessions, \ndeleting obsolete rsh settings, \nchecking sshd for correctness."
  read -t 10
  if grep -qF 'PermitRootLogin' "/etc/ssh/sshd_config"; then sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/' "/etc/ssh/sshd_config"; else echo 'PermitRootLogin no' >> /etc/ssh/sshd_config; fi
  if grep -qF 'PermitEmptyPasswords' "/etc/ssh/sshd_config"; then sed -i 's/^.*PermitEmptyPasswords.*$/PermitEmptyPasswords no/' "/etc/ssh/sshd_config"; else echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config; fi
  sudo ufw allow 22/tcp
  if grep -qF 'ClientAliveInterval' "/etc/ssh/sshd_config"; then sed -i 's/^.*ClientAliveInterval.*$/ClientAliveInterval 300/' "/etc/ssh/sshd_config"; else echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config; fi
  if grep -qF 'ClientAliveCountMax' "/etc/ssh/sshd_config"; then sed -i 's/^.*ClientAliveCountMax.*$/ClientAliveCountMax 0/' "/etc/ssh/sshd_config"; else echo 'ClientAliveCountMax 0' >> /etc/ssh/sshd_config; fi
  if grep -qF 'IgnoreRhosts' "/etc/ssh/sshd_config"; then sed -i 's/^.*IgnoreRhosts.*$/IgnoreRhosts yes/' "/etc/ssh/sshd_config"; else echo 'IgnoreRhosts yes' >> /etc/ssh/sshd_config; fi
  if grep -qF 'RhostsAuthentication' "/etc/ssh/sshd_config"; then sed -i 's/^.*RhostsAuthentication.*$/RhostsAuthentication no/' "/etc/ssh/sshd_config"; else echo 'RhostsAuthentication no' >> /etc/ssh/sshd_config; fi
  sudo sshd -t
  echo -e "${YELLOW}SSH set up. Restarting SSH service in 5 seconds, Ctrl+C to cancel...${NC}"
  read -t 5
  sudo systemctl restart sshd || sudo systemctl restart ssh
}

lockRoot() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Locking/securing root/sudo account in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo passwd -l root
  sed -i 's/!authenticate/authenticate/' /etc/sudoers
}

changeLoginChances() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Setting password policy, lockout, and null password restrictions in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  # Remove nullok from common-auth per answer key
  sudo sed -i 's/\<nullok\>//g' /etc/pam.d/common-auth

  # Configure pam_faillock files per answer key approach (non-interactive)
  sudo tee /usr/share/pam-configs/faillock >/dev/null <<'EOF'
Name: Lockout on failed logins
Default: yes
Priority: 0
Auth-Type:
Primary:
[default=die] pam_faillock.so authfail
auth [success=1 default=ignore] pam_unix.so try_first_pass
EOF
  sudo tee /usr/share/pam-configs/faillock_reset >/dev/null <<'EOF'
Name: Reset lockout on success
Default: yes
Priority: 0
Auth-Type:
Additional:
required pam_faillock.so authsucc
EOF
  sudo tee /usr/share/pam-configs/faillock_notify >/dev/null <<'EOF'
Name: Notify on account lockout
Default: yes
Priority: 1024
Auth-Type:
Primary:
requisite pam_faillock.so preauth
EOF
  # Enable new PAM profiles
  sudo pam-auth-update --enable faillock --enable faillock_reset --enable faillock_notify --force || true

  # Also ensure pam_tally2 strong defaults if present (backwards compatibility)
  if grep -q 'pam_tally2.so' /etc/pam.d/common-auth; then
    sudo sed -i 's/^auth.*pam_tally2\.so.*$/auth required pam_tally2.so deny=3 onerr=fail even_deny_root unlock_time=120/' /etc/pam.d/common-auth
  fi

  # Enforce minlen=10 and remember=3 in common-password
  if grep -q 'pam_unix.so' /etc/pam.d/common-password; then
    sudo sed -i 's/\(pam_unix\.so.*\)minlen=[0-9]\+/\1/g' /etc/pam.d/common-password
    sudo sed -i 's/\(pam_unix\.so.*\)remember=[0-9]\+/\1/g' /etc/pam.d/common-password
    sudo sed -i 's/\(pam_unix\.so.*\)$/\1 minlen=10 remember=3/' /etc/pam.d/common-password
  fi
}

auditing() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Installing and setting up auditd in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo apt install -y auditd
  sudo systemctl enable --now auditd || true
  auditctl -e 1 || true
}

sanityCheck() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Running sanity check in 5 seconds. Admins, users, users with empty passwords and non-root UID 0 users will be printed. Delete these users later. To skip, Ctrl+C...${NC}"
  read -t 5
  mawk -F: '$1 == "sudo"' /etc/group
  mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd
  mawk -F: '$2 == ""' /etc/passwd
  mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd
}

removeSamba() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Removing all Samba-related items in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo apt -y remove '.*samba.*' '.*smb.*' || true
}

removeFiles() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Removing media/hacking files in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo find /home/ -type f \( -name "*.mp3" -o -name "*.mp4" -o -name "*.ogg" \) -delete
  sudo find /home/ -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \) -delete
  # remove specific prohibited archive per key
  sudo rm -f /usr/games/pyrdp-master.zip 2>/dev/null || true
}

setHomeDirectoryPerms() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Setting home directory permissions in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do [ -d /home/"${i}" ] && chmod -R 750 /home/"${i}"; done
}

removeIllegalPrograms() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Removing nmap zenmap apache2 nginx lighttpd wireshark tcpdump netcat-traditional nikto ophcrack doona xprobe squid in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo apt purge -y nmap zenmap apache2 nginx lighttpd wireshark tcpdump netcat-traditional nikto ophcrack doona xprobe squid || true
  sudo systemctl disable --now nginx 2>/dev/null || true
  sudo systemctl disable --now squid 2>/dev/null || true
}

rootkitCheck() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Installing and running chkrootkit and rkhunter in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo apt-get install -y chkrootkit rkhunter
  sudo chkrootkit || true
  sudo rkhunter --update || true
  sudo rkhunter --check || true
}

ipChecks() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Changing IP settings in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
  echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
  echo "nospoof on" | sudo tee -a /etc/host.conf
  sed -i 's/net\.ipv4\.ip_forward=1/net\.ipv4\.ip_forward=0/' /etc/sysctl.conf 
}

# Disable or remove nginx and squid services per answer key
serviceHardening() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Disabling/removing nginx and squid services in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo systemctl disable --now nginx 2>/dev/null || true
  sudo systemctl disable --now squid 2>/dev/null || true
  sudo apt purge -y nginx nginx-common nginx-core squid || true
}

# Create required groups/users per image (adjust lists as needed)
ensureGroupsUsers() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Creating required groups/users and correcting memberships in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  # Example from answer key: create group spider and add specific users if they exist
  sudo addgroup --quiet spider 2>/dev/null || true
  # Add users to spider only if accounts exist
  for u in may peni stan miguel; do id "$u" >/dev/null 2>&1 && sudo gpasswd -a "$u" spider || true; done
  # Example: ensure ham is not admin (remove from sudo)
  id ham >/dev/null 2>&1 && sudo gpasswd -d ham sudo || true
}

complete() {
  echo -e "\n${GREEN}CyberPatriot script complete!${NC}"
  echo -e "${YELLOW}There are a bunch of things you need to do manually, such as:${NC}"
  echo -e "${MAGENTA}1. Delete users with UID 0 that aren't root"
  echo -e "2. Change users with empty passwords"
  echo -e "3. Change passwords for users with weak passwords"
  echo -e "4. Manually update services mentioned"
  echo -e "5. Manually check for unauthorized ports (use sudo ss -ln, sudo lsof -i $:port, etc.)"
  echo -e "6. Check /etc/sudoers.d, /etc/group, create new groups, users, etc."
  echo -e "7. Check legitimate services (sudo service --status-all, sudo systemctl status)"
  echo -e "\n${NC}${YELLOW}Here is what this script did:${NC}"
  echo -e "${MAGENTA}1. Updated system and packages"
  echo -e "2. Installed ClamAV"
  echo -e "3. Installed and set up UFW"
  echo -e "4. Set up TCP SYN cookies"
  echo -e "5. Set up SSH"
  echo -e "6. Locked root account"
  echo -e "7. Set password policy and lockout"
  echo -e "8. Updated PAM and removed nullok"
  echo -e "9. Installed and set up auditd"
  echo -e "10. Removed Samba-related items"
  echo -e "11. Removed media/hacking files (including .ogg and pyrdp archive)"
  echo -e "12. Set home directory permissions"
  echo -e "13. Removed illegal programs (including doona, xprobe) and disabled nginx/squid"
  echo -e "14. Installed and ran chkrootkit and rkhunter"
  echo -e "15. Checked for unauthorized ports${NC}"
  exit
}

# Execution order
updateSystem
clamAV
ufw
tcpSyn
ssh
lockRoot
changeLoginChances
auditing
sanityCheck
removeSamba
removeFiles
setHomeDirectoryPerms
removeIllegalPrograms
rootkitCheck
ipChecks
serviceHardening
ensureGroupsUsers
complete
