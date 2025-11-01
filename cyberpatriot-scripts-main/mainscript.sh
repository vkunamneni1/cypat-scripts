#!/bin/bash
# CyberPatriot Ubuntu 22 hardening script (Comet Assistant enhanced)
# Applies answer key mitigations AND advanced CIS/konstruktoid hardening.
# Focus areas: sudo, permissions, firewall, SSH, sysctl, updates, services, auditd.
# USER-SPECIFIC changes (add/remove users, groups, admin) are in py_userscript.py
set -euo pipefail
IFS=$'\n\t'

log() { echo -e "\n[+] $1"; }
warn() { echo -e "[!] $1"; }
run() { echo ">$ $*"; eval "$@"; }

require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
  fi
}

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then cp -an "$f"{,.bak.$(date +%s)}; fi
}

# 1) Accounts and groups — GENERAL hardening
accounts_hardening() {
  log "Accounts: locking root and accounts with empty passwords."
  # Lock root account (Mint Key #10)
  passwd -l root || true

  # Lock accounts with empty passwords (CIS 7.2.2)
  log "Locking accounts with empty passwords..."
  for user in $(awk -F: '($2 == "") { print $1 }' /etc/shadow); do
      log "  -> Locking user: $user"
      passwd -l "$user"
  done
}

# 2) Sudoers tightening
sudo_hardening() {
  log "Sudo: require pty, set logfile, and remove NOPASSWD."
  backup_file /etc/sudoers
  # (CIS 5.2.2 & konstruktoid)
  if ! grep -q '^Defaults.*use_pty' /etc/sudoers; then echo 'Defaults    use_pty' >> /etc/sudoers; fi
  # (CIS 5.2.3 / Ubuntu Key #9)
  if ! grep -q '^Defaults.*logfile=' /etc/sudoers; then echo 'Defaults    logfile="/var/log/sudo.log"' >> /etc/sudoers; fi
  # (CIS 5.2.7)
  log "Restricting 'su' command to 'sudo' group"
  sed -i -E "s/^[#\s]*auth\s+required\s+pam_wheel.so/auth\t\trequired\t\tpam_wheel.so group=sudo/g" /etc/pam.d/su

  # Remove NOPASSWD from drop-ins
  if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do
      [[ -f "$f" ]] || continue
      backup_file "$f"
      sed -ri 's/NOPASSWD:ALL/PASSWD:ALL/g' "$f" || true
    done
  fi
}

# 3) File permissions fixes
permission_fixes() {
  log "Permissions: fix core system file permissions."
  # (CIS 7.1 & Ubuntu Key #14)
  chmod 644 /etc/passwd && chown root:root /etc/passwd
  chmod 640 /etc/shadow && chown root:shadow /etc/shadow
  chmod 644 /etc/group && chown root:root /etc/group
  chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow
  chmod 644 /etc/passwd- && chown root:root /etc/passwd-
  chmod 644 /etc/group- && chown root:root /etc/group-
  chmod 640 /etc/shadow- && chown root:shadow /etc/shadow-
  chmod 640 /etc/gshadow- && chown root:shadow /etc/gshadow-
  
  # Home directories 750 (CIS 7.2.9)
  for d in /home/*; do
    [[ -d "$d" ]] || continue
    chmod 750 "$d" || true
  done
}

# 4) Sysctl networking security
sysctl_hardening() {
  log "Sysctl: hardening network kernel parameters."
  
  cat > /etc/sysctl.d/99-cis-hardening.conf <<'EOF'
# CIS Benchmark & CyberPatriot Hardening

# CIS 3.3.1.18 & Ubuntu Key #11 & Mint Key #16: Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# CIS 3.3.1.1 & Ubuntu Key #12: Disable IPv4 forwarding
net.ipv4.ip_forward = 0

# Mint Key #15 & CIS 1.5.1: Enable Address space layout randomization
kernel.randomize_va_space = 2

# CIS 3.3.1.4 & 3.3.1.5: Disable packet redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# CIS 3.3.1.8 & 3.3.1.9: Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# CIS 3.3.1.10: Disable secure ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# CIS 3.3.1.16 & 3.3.1.17: Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# CIS 3.3.1.12 & 3.3.1.13: Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# CIS 3.3.2.7 & 3.3.2.8: Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
  
  sysctl --system >/dev/null 2>&1 || true
}

# 5) UFW firewall enable
ufw_enable() {
  log "Firewall: enable UFW with sane defaults and allow SSH."
  if command -v ufw >/dev/null 2>&1; then
    # (CIS 4.1.3, 4.1.4, 4.1.5)
    ufw --force default deny incoming || true
    ufw --force default allow outgoing || true
    ufw default deny routed || true
    
    # Allow critical services (at least SSH)
    ufw allow 22/tcp || true
    
    # (CIS 4.1.2 & Ubuntu Key #13 & Practice Key #8)
    yes | ufw enable || true
  else
    warn "UFW not installed; skipping."
  fi
}

# 6) SSH security per AK
ssh_hardening() {
  log "SSH: disable root login and tighten settings."
  local f=/etc/ssh/sshd_config
  backup_file "$f"
  
  # (CIS 5.1.20 & Ubuntu Key #24 & Practice Key #16)
  grep -q '^\s*PermitRootLogin' "$f" && sed -ri 's/^\s*PermitRootLogin.*/PermitRootLogin no/' "$f" || echo 'PermitRootLogin no' >> "$f"
  # (CIS 5.1.19)
  grep -q '^\s*PermitEmptyPasswords' "$f" && sed -ri 's/^\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$f" || echo 'PermitEmptyPasswords no' >> "$f"
  # (CIS 5.1.7)
  grep -q '^\s*ClientAliveInterval' "$f" && sed -ri 's/^\s*ClientAliveInterval.*/ClientAliveInterval 300/' "$f" || echo 'ClientAliveInterval 300' >> "$f"
  grep -q '^\s*ClientAliveCountMax' "$f" && sed -ri 's/^\s*ClientAliveCountMax.*/ClientAliveCountMax 0/' "$f" || echo 'ClientAliveCountMax 0' >> "$f"
  # (CIS 5.1.14)
  grep -q '^\s*LogLevel' "$f" && sed -ri 's/^\s*LogLevel.*/LogLevel VERBOSE/' "$f" || echo 'LogLevel VERBOSE' >> "$f"
  # (CIS 5.1.16)
  grep -q '^\s*MaxAuthTries' "$f" && sed -ri 's/^\s*MaxAuthTries.*/MaxAuthTries 4/' "$f" || echo 'MaxAuthTries 4' >> "$f"
  # (CIS 5.1.18)
  grep -q '^\s*MaxStartups' "$f" && sed -ri 's/^\s*MaxStartups.*/MaxStartups 10:30:60/' "$f" || echo 'MaxStartups 10:30:60' >> "$f"
  # (CIS 5.1.5)
  grep -q '^\s*Banner' "$f" && sed -ri 's|^\s*Banner.*|Banner /etc/issue.net|' "$f" || echo 'Banner /etc/issue.net' >> "$f"
  
  # (CIS 1.6.3 / Ubuntu Key #24)
  echo "Authorized use only. All activity may be monitored." > /etc/issue.net
  chmod 644 /etc/issue.net
  
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
}

# 7) Updates configuration (auto-check daily)
updates_daily_check() {
  log "Updates: configure periodic apt check daily (Ubuntu Key #18, Practice Key #10)."
  mkdir -p /etc/apt/apt.conf.d
  # (Ubuntu Key #18 & Mint Key #20)
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  cat > /etc/apt/apt.conf.d/10periodic-check <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "7";
EOF
}

# 8) Services: disable insecure services
services_hardening() {
  log "Services: disable unauthorized services from answer keys."
  # (Ubuntu Key #17 & Mint Key - Penalty #1)
  systemctl disable --now vsftpd 2>/dev/null || true
  # (Ubuntu Key #16 / Mint Key #18 / Practice Key #9)
  systemctl disable --now nginx 2>/dev/null || true
  # (Mint Key #19)
  systemctl disable --now squid 2>/dev/null || true
  # (CIS 2.1.2)
  systemctl disable --now avahi-daemon.service avahi-daemon.socket 2>/dev/null || true
}

# 9) Media cleanup
media_cleanup() {
  log "Media: remove prohibited files from answer keys."
  # (Ubuntu Key #21 / Practice Key #13)
  if [[ -d /home/linda/Music ]]; then
    rm -f /home/linda/Music/*.mp3 2>/dev/null || true
  fi
  # (Mint Key #22)
  if [[ -d /home/steve/Music ]]; then
    find /home/steve/Music -name "*.ogg" -type f -delete 2>/dev/null || true
  fi
  # (Mint Key #23)
  rm -f /usr/games/pyrdp-master.zip 2>/dev/null || true
}

# 10) Update System
system_update() {
    log "System Updates: running apt-get update and upgrade."
    apt-get update
    # (Ubuntu Key #19, #20 / Mint Key #21 / Practice Key #11, #12)
    apt-get full-upgrade -y
}

# 11) NEW: Remove Prohibited Software (from Answer Keys)
remove_prohibited_software() {
  log "Software: removing prohibited software from answer keys."
  # (Ubuntu Key #22)
  apt-get purge -y aisleriot 2>/dev/null || true
  # (Mint Key #24)
  apt-get purge -y doona xprobe 2>/dev/null || true
  # (Practice Key #14, #15)
  apt-get purge -y ophcrack wireshark 2>/dev/null || true
  # (CIS 2.2.4)
  apt-get purge -y telnet 2>/dev/null || true
  # (CIS 2.2.2)
  apt-get purge -y rsh-client 2>/dev/null || true
  
  apt-get autoremove -y 2>/dev/null || true
}

# 12) NEW: Remove Backdoors (from Answer Keys)
remove_backdoors() {
  log "Backdoors: removing known backdoors from answer keys."
  # (Ubuntu Key #23 & Practice Key #23: Netcat backdoor)
  pkill -f "nc.traditional -l -p 1337" 2>/dev/null || true
  sed -i '/nc.traditional/d' /etc/crontab 2>/dev/null || true
  rm -f /usr/bin/nc.traditional 2>/dev/null || true

  # (Mint Key #26: Zod backdoor)
  pkill -f "kneelB4zod.py" 2>/dev/null || true
  rm -rf /usr/share/zod 2>/dev/null || true
}

# 13) NEW: Install & Configure AppArmor (CIS)
harden_apparmor() {
    log "AppArmor: Installing and enabling AppArmor (CIS 1.3.1)."
    apt-get install -y apparmor apparmor-utils 2>/dev/null || true
    systemctl unmask apparmor.service 2>/dev/null || true
    systemctl --now enable apparmor.service 2>/dev/null || true
}

# 14) NEW: Configure auditd (CIS)
configure_auditd() {
    log "Auditd: Installing and configuring auditd rules (CIS 6.2)."
    apt-get install -y auditd audispd-plugins 2>/dev/null || true
    
    # (CIS 6.2.1.3)
    if grep -qE "^\s*GRUB_CMDLINE_LINUX" /etc/default/grub; then
        if ! grep -q "audit=1" /etc/default/grub; then
            sed -i -E 's/^(GRUB_CMDLINE_LINUX=".*)"/\1 audit=1"/' /etc/default/grub
            update-grub 2>/dev/null || true
        fi
    else
        echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
        update-grub 2>/dev/null || true
    fi
    
    # (CIS 6.2.2)
    backup_file /etc/audit/auditd.conf
    sed -i -E "s/^[#\s]*max_log_file\s*=.*/max_log_file = 100/g" /etc/audit/auditd.conf
    sed -i -E "s/^[#\s]*max_log_file_action\s*=.*/max_log_file_action = keep_logs/g" /etc/audit/auditd.conf
    sed -i -E "s/^[#\s]*space_left_action\s*=.*/space_left_action = syslog/g" /etc/audit/auditd.conf
    sed -i -E "s/^[#\s]*admin_space_left_action\s*=.*/admin_space_left_action = halt/g" /etc/audit/auditd.conf
    
    # (CIS 6.2.3)
    cat > /etc/audit/rules.d/99-cis.rules <<'EOF'
# CIS Audit Rules
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-w /etc/localtime -p wa -k time-change
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k kernel_modules
-e 2
EOF
    # (CIS 6.2.1.2)
    systemctl unmask auditd.service 2>/dev/null || true
    systemctl --now enable auditd.service 2>/dev/null || true
    augenrules --load 2>/dev/null || true
}

# 15) NEW: Kernel Module Hardening (CIS & konstruktoid)
kernel_module_hardening() {
    log "Kernel Modules: Disabling unused modules."
    # (CIS 1.1.1)
    echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
    echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf
    echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf
    echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf
    
    # (konstruktoid)
    echo "install bluetooth /bin/true" > /etc/modprobe.d/bluetooth.conf
    echo "install floppy /bin/true" > /etc/modprobe.d/floppy.conf
    echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf
    echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf
    echo "install rds /bin/true" > /etc/modprobe.d/rds.conf
    echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf
}

# 16) NEW: Systemd Hardening (konstruktoid)
systemd_hardening() {
    log "Systemd: Hardening journald, logind, and system configs."
    
    backup_file /etc/systemd/journald.conf
    cat > /etc/systemd/journald.conf <<'EOF'
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=no
MaxLevelStore=warning
EOF
    systemctl restart systemd-journald 2>/dev/null || true

    backup_file /etc/systemd/logind.conf
    cat > /etc/systemd/logind.conf <<'EOF'
[Login]
IdleAction=lock
IdleActionSec=15min
KillUserProcesses=yes
RemoveIPC=yes
EOF
    systemctl restart systemd-logind 2>/dev/null || true

    backup_file /etc/systemd/system.conf
    backup_file /etc/systemd/user.conf
    sed -ri 's/^\s*#?\s*DumpCore\s*=.*/DumpCore=no/' /etc/systemd/system.conf
    sed -ri 's/^\s*#?\s*DefaultLimitCORE\s*=.*/DefaultLimitCORE=0/' /etc/systemd/system.conf
    sed -ri 's/^\s*#?\s*CrashShell\s*=.*/CrashShell=no/' /etc/systemd/system.conf
    
    sed -ri 's/^\s*#?\s*DumpCore\s*=.*/DumpCore=no/' /etc/systemd/user.conf
    sed -ri 's/^\s*#?\s*DefaultLimitCORE\s*=.*/DefaultLimitCORE=0/' /etc/systemd/user.conf
}

main() {
  require_root
  
  log "--- Applying Answer Key & CIS Hardening ---"
  
  # Run updates first to get latest packages
  system_update
  
  # Remove prohibited items
  remove_prohibited_software
  media_cleanup
  remove_backdoors
  
  # Harden services and OS
  services_hardening
  accounts_hardening
  sudo_hardening
  permission_fixes
  # pam_policy function removed - run py_authscript.py instead
  sysctl_hardening
  ufw_enable
  ssh_hardening
  updates_daily_check
  
  # NEW Functions from CIS/konstruktoid
  kernel_module_hardening
  systemd_hardening
  harden_apparmor
  configure_auditd
  
  log "--- Script Finished ---"
  warn "This script does NOT run PAM/password hardening."
  warn "Run 'python3 py_authscript.py' to apply auth policies."
  warn "This script does NOT run interactive user/group management."
  warn "Run 'python3 py_userscript.py' to manage users based on the README."
  warn "Review output for errors."
  warn "A REBOOT is required to apply kernel (GRUB) and immutable auditd rules."
}

main "$@"
