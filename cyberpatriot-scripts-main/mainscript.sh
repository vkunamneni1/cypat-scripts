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
  systemctl disable avahi-daemon
  echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
  sudo apt update
  sudo apt upgrade
}

clamAV() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Installing ClamAV in 5 seconds. To skip, Ctrl+C...${YELLOW}"
  read -t 5
  sudo apt install clamav
  sudo freshclam
  echo -e "${CYAN}ClamAV installed and updated. Run 'sudo clamscan -i -r --remove=yes /' in a different terminal${NC}"
}

ufw() {
  trap "return" SIGINT
  echo -e "${YELLOW}Installing and setting up UFW in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo apt install ufw
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw enable
  sudo ufw status
  echo -e "${CYAN}UFW installed and set up. Remember to open up outgoing ports for services like SSH, HTTP, and FTP${NC}"
}

tcpSyn() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Setting up TCP SYN cookies in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo sysctl -w net.ipv4.tcp_syncookies=1
}

ssh() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Doing the following things in 10 seconds. To skip, press Ctrl+C...${NC}\nSetting up PermitRootLogin no, \nPasswordAuthentication unchanged, \nChallengeResponseAuthentication unchanged, \nUsePAM unchanged, \nPermitEmptyPasswords no, \nadding port 22 to firewall, \nremoving keepalive/unattended sessions, \ndeleting obsolete rsh settings, \nchecking sshd for correctness."
  read -t 10
  if grep -qF 'PermitRootLogin' "/etc/ssh/sshd_config"; then sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/' "/etc/ssh/sshd_config"; else echo 'PermitRootLogin no' >> /etc/ssh/sshd_config; fi
  if grep -qF 'PermitEmptyPasswords' "/etc/ssh/sshd_config"; then sed -i 's/^.*PermitEmptyPasswords.*$/PermitEmptyPasswords no/' "/etc/ssh/sshd_config"; else echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config; fi
  sudo ufw allow from 202.54.1.5/29 to any port 22
  if grep -qF 'ClientAliveInterval' "/etc/ssh/sshd_config"; then sed -i 's/^.*ClientAliveInterval.*$/ClientAliveInterval 300/' "/etc/ssh/sshd_config"; else echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config; fi
  if grep -qF 'ClientAliveCountMax' "/etc/ssh/sshd_config"; then sed -i 's/^.*ClientAliveCountMax.*$/ClientAliveCountMax 0/' "/etc/ssh/sshd_config"; else echo 'ClientAliveCountMax 0' >> /etc/ssh/sshd_config; fi
  if grep -qF 'IgnoreRhosts' "/etc/ssh/sshd_config"; then sed -i 's/^.*IgnoreRhosts.*$/IgnoreRhosts yes/' "/etc/ssh/sshd_config"; else echo 'IgnoreRhosts yes' >> /etc/ssh/sshd_config; fi
  if grep -qF 'RhostsAuthentication' "/etc/ssh/sshd_config"; then sed -i 's/^.*RhostsAuthentication.*$/RhostsAuthentication no/' "/etc/ssh/sshd_config"; else echo 'RhostsAuthentication no' >> /etc/ssh/sshd_config; fi
  sudo sshd -t
  echo -e "${YELLOW}SSH set up. Restarting SSH service in 5 seconds, Ctrl+C to cancel...${NC}"
  read -t 5
  sudo systemctl restart sshd
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
  echo -e "${YELLOW}Changing the following in 5 seconds. To skip, Ctrl+C...\nPASS_MAX_DAYS 90\nPASS_MIN_DAYS 10\nPASS_WARN_AGE 7\nauth required pam_tally2.so deny=3 onerr=fail even_deny_root unlock_time=120${NC}"
  read -t 5
  sudo sed -i 's/^auth.*required.*pam_tally2.so.*deny=5.*onerr=fail.*even_deny_root.*$/auth required pam_tally2.so deny=3 onerr=fail even_deny_root unlock_time=120/' /etc/pam.d/common-auth
  sudo sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
}

updatePam() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Updating PAM (and installing cracklib) in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' >> /etc/pam.d/common-auth
  sudo apt install libpam-cracklib
  sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5 minlen=8/' /etc/pam.d/common-password
  sed -i 's/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
}

auditing() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Installing and setting up auditd in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo apt install auditd
  auditctl -e 1
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
  sudo apt remove .*samba.* .*smb.*
}

removeFiles() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Removing media/hacking files in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo find /home/ -type f \( -name "*.mp3" -o -name "*.mp4" \) -delete
  sudo find /home/ -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \) -delete
}

setHomeDirectoryPerms() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Setting home directory permissions in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do [ -d /home/"${i}" ] && chmod -R 750 /home/"${i}"; done
}

removeIllegalPrograms() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Removing nmap zenmap apache2 nginx lighttpd wireshark tcpdump netcat-traditional nikto ophcrack in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo apt remove nmap
  sudo apt remove zenmap
  sudo apt remove apache2
  sudo apt remove nginx
  sudo apt remove lighttpd
  sudo apt remove wireshark
  sudo apt remove tcpdump
  sudo apt remove netcat-traditional
  sudo apt remove nikto
  sudo apt remove ophcrack
}

rootkitCheck() {
  trap 'return' SIGINT
  echo -e "${YELLOW}Installing and running chkrootkit and rkhunter in 5 seconds. To skip, Ctrl+C...${NC}"
  read -t 5
  sudo apt-get install chkrootkit rkhunter
  sudo chkrootkit
  sudo rkhunter --update
  sudo rkhunter --check
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
  echo -e "7. Changed login tallies (PAM)"
  echo -e "8. Updated PAM"
  echo -e "9. Installed and set up auditd"
  echo -e "10. Removed Samba-related items"
  echo -e "11. Removed media/hacking files"
  echo -e "12. Set home directory permissions"
  echo -e "13. Removed illegal programs"
  echo -e "14. Installed and ran chkrootkit and rkhunter"
  echo -e "15. Checked for unauthorized ports${NC}"
  exit
}

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
setHomeDirectoryPerms
removeIllegalPrograms
rootkitCheck
ipChecks
complete
