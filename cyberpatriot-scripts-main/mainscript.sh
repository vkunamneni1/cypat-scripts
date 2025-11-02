#!/bin/bash
# CyberPatriot Ubuntu 22/Mint 21 Hardening Script (v2 - STABLE)
# This version removes functions known to break scoring engines or cause instability.
# (Removed harden_apparmor, fix_suid_guid, and dangerous restarts)
set -euo pipefail
IFS=$'\n\t'

log() { echo -e "\n[+] $1"; }
warn() { echo -e "[!] $1"; }

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
  passwd -l root || true

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
  if ! grep -q '^Defaults.*use_pty' /etc/sudoers; then echo 'Defaults    use_pty' >> /etc/sudoers; fi
  if ! grep -q '^Defaults.*logfile=' /etc/sudoers; then echo 'Defaults    logfile="/var/log/sudo.log"' >> /etc/sudoers; fi
  
  log "Restricting 'su' command to 'sudo' group"
  sed -i -E "s/^[#\s]*auth\s+required\s+pam_wheel.so/auth\t\trequired\t\tpam_wheel.so group=sudo/g" /etc/pam.d/su

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
  chmod 644 /etc/passwd && chown root:root /etc/passwd
  chmod 640 /etc/shadow && chown root:shadow /etc/shadow
  chmod 644 /etc/group && chown root:root /etc/group
  chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow
  chmod 644 /etc/passwd- && chown root:root /etc/passwd-
  chmod 644 /etc/group- && chown root:root /etc/group-
  chmod 640 /etc/shadow- && chown root:shadow /etc/shadow-
  chmod 640 /etc/gshadow- && chown root:shadow /etc/gshadow-
  
  log "Permissions: Setting home directories to 750."
  for d in /home/*; do
    [[ -d "$d" ]] || continue
    chmod 750 "$d" || true
  done
}

# 4) Sysctl networking security
sysctl_hardening() {
  log "Sysctl: hardening network kernel parameters in /etc/sysctl.conf..."
  local conf_file="/etc/sysctl.conf"
  backup_file "$conf_file"

  # Helper function to set a sysctl value in the main config file
  set_sysctl() {
    local key="$1"
    local value="$2"
    if grep -q -E "^\s*#?\s*${key}\s*=" "$conf_file"; then
      sed -ri "s/^\s*#?\s*${key}\s*=.*/${key} = ${value}/" "$conf_file"
    else
      echo "${key} = ${value}" >> "$conf_file"
    fi
  }

  log "  -> Applying network hardening settings..."
  set_sysctl "net.ipv4.tcp_syncookies" "1"
  set_sysctl "net.ipv4.ip_forward" "0"
  set_sysctl "kernel.randomize_va_space" "2"
  set_sysctl "net.ipv4.conf.all.send_redirects" "0"
  set_sysctl "net.ipv4.conf.default.send_redirects" "0"
  set_sysctl "net.ipv4.conf.all.accept_redirects" "0"
  set_sysctl "net.ipv4.conf.default.accept_redirects" "0"
  set_sysctl "net.ipv4.conf.all.secure_redirects" "0"
  set_sysctl "net.ipv4.conf.default.secure_redirects" "0"
  set_sysctl "net.ipv4.conf.all.log_martians" "1"
  set_sysctl "net.ipv4.conf.default.log_martians" "1"
  set_sysctl "net.ipv4.conf.all.rp_filter" "1"
  set_sysctl "net.ipv4.conf.default.rp_filter" "1"
  set_sysctl "net.ipv6.conf.all.accept_ra" "0"
  set_sysctl "net.ipv6.conf.default.accept_ra" "0"

  sysctl -p "$conf_file" >/dev/null 2>&1 || true
}

# 5) UFW firewall enable
ufw_enable() {
  log "Firewall: enable UFW with sane defaults and allow SSH."
  if command -v ufw >/dev/null 2>&1; then
    ufw --force default deny incoming || true
    ufw --force default allow outgoing || true
    ufw default deny routed || true
    ufw allow 22/tcp || true
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
  
  grep -q '^\s*PermitRootLogin' "$f" && sed -ri 's/^\s*PermitRootLogin.*/PermitRootLogin no/' "$f" || echo 'PermitRootLogin no' >> "$f"
  grep -q '^\s*PermitEmptyPasswords' "$f" && sed -ri 's/^\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$f" || echo 'PermitEmptyPasswords no' >> "$f"
  grep -q '^\s*ClientAliveInterval' "$f" && sed -ri 's/^\s*ClientAliveInterval.*/ClientAliveInterval 300/' "$f" || echo 'ClientAliveInterval 300' >> "$f"
  grep -q '^\s*ClientAliveCountMax' "$f" && sed -ri 's/^\s*ClientAliveCountMax.*/ClientAliveCountMax 0/' "$f" || echo 'ClientAliveCountMax 0' >> "$f"
  grep -q '^\s*LogLevel' "$f" && sed -ri 's/^\s*LogLevel.*/LogLevel VERBOSE/' "$f" || echo 'LogLevel VERBOSE' >> "$f"
  grep -q '^\s*MaxAuthTries' "$f" && sed -ri 's/^\s*MaxAuthTries.*/MaxAuthTries 4/' "$f" || echo 'MaxAuthTries 4' >> "$f"
  grep -q '^\s*MaxStartups' "$f" && sed -ri 's/^\s*MaxStartups.*/MaxStartups 10:30:60/' "$f" || echo 'MaxStartups 10:30:60' >> "$f"
  grep -q '^\s*Banner' "$f" && sed -ri 's|^\s*Banner.*|Banner /etc/issue.net|' "$f" || echo 'Banner /etc/issue.net' >> "$f"
  
  echo "Authorized use only. All activity may be monitored." > /etc/issue.net
  chmod 644 /etc/issue.net
  
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
}

# 7) Updates configuration (auto-check daily)
updates_daily_check() {
  log "Updates: configure periodic apt check daily."
  mkdir -p /etc/apt/apt.conf.d
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
  log "Services: Purging unauthorized services."
  # NOTE: This list is based on your previous scripts.
  # Add/remove services here based on the README.
  
  # Purge common unwanted services
  apt-get purge -y postfix 2>/dev/null || true
  apt-get purge -y dovecot-core 2>/dev/null || true
  apt-get purge -y rpcbind 2>/dev/null || true
  apt-get purge -y samba 2>/dev/null || true
  apt-get purge -y postgresql 2>/dev/null || true
  apt-get purge -y bind9 2>/dev/null || true
  
  # Disable other common unwanted services
  # NOTE: vsftpd is often in this list, but remove if it's critical
  systemctl disable --now vsftpd 2>/dev/null || true
  systemctl disable --now nginx 2>/dev/null || true
  systemctl disable --now squid 2>/dev/null || true
  systemctl disable --now avahi-daemon.service avahi-daemon.socket 2>/dev/null || true
}

# 9) Update System
system_update() {
    log "System Updates: running apt-get update and upgrade."
    
    # CRITICAL: Install libpam-pwquality *before* running py_authscript.py
    # This fixes the PAM error.
    log "Installing required PAM module libpam-pwquality..."
    apt-get install -y libpam-pwquality 2>/dev/null || true
    
    log "Running apt-get update..."
    apt-get update
    
    log "Running apt-get full-upgrade..."
    apt-get full-upgrade -y
}

# 10) Remove Prohibited Software (from Answer Keys)
remove_prohibited_software() {
  log "Software: removing prohibited software."
  apt-get purge -y aisleriot 2>/dev/null || true
  apt-get purge -y doona xprobe 2>/dev/null || true
  apt-get purge -y ophcrack wireshark 2>/dev/null || true
  apt-get purge -y telnet 2>/dev/null || true
  apt-get purge -y rsh-client 2>/dev/null || true
  
  # Prevent snap chromium from being auto-installed
  apt-get purge -y chromium-browser 2>/dev/null || true
  
  apt-get autoremove -y 2>/dev/null || true
}

# 11) Remove Backdoors (from Answer Keys)
remove_backdoors() {
  log "Backdoors: removing known backdoors."
  pkill -f "nc.traditional -l -p 1337" 2>/dev/null || true
  sed -i '/nc.traditional/d' /etc/crontab 2>/dev/null || true
  rm -f /usr/bin/nc.traditional 2>/dev/null || true

  pkill -f "kneelB4zod.py" 2>/dev/null || true
  rm -rf /usr/share/zod 2>/dev/null || true
}

# 12) Configure auditd (CIS) - **SAFE VERSION**
configure_auditd() {
    log "Auditd: Installing and configuring auditd rules."
    apt-get install -y auditd audispd-plugins 2>/dev/null || true
    
    if grep -qE "^\s*GRUB_CMDLINE_LINUX" /etc/default/grub; then
        if ! grep -q "audit=1" /etc/default/grub; then
            sed -i -E 's/^(GRUB_CMDLINE_LINUX=".*)"/\1 audit=1"/' /etc/default/grub
            update-grub 2>/dev/null || true
        fi
    else
        echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
        update-grub 2>/dev/null || true
    fi
    
    backup_file /etc/audit/auditd.conf
    sed -i -E "s/^[#\s]*max_log_file\s*=.*/max_log_file = 100/g" /etc/audit/auditd.conf
    sed -i -E "s/^[#\s]*max_log_file_action\s*=.*/max_log_file_action = keep_logs/g" /etc/audit/auditd.conf
    sed -i -E "s/^[#\s]*space_left_action\s*=.*/space_left_action = syslog/g" /etc/audit/auditd.conf
    
    # *** CRITICAL FIX ***
    # Changed 'halt' to 'syslog' to prevent random shutdowns.
    log "Setting admin_space_left_action to 'syslog' to prevent shutdowns."
    sed -i -E "s/^[#\s]*admin_space_left_action\s*=.*/admin_space_left_action = syslog/g" /etc/audit/auditd.conf
    
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
    systemctl unmask auditd.service 2>/dev/null || true
    systemctl --now enable auditd.service 2>/dev/null || true
    augenrules --load 2>/dev/null || true
}

# 13) Kernel Module Hardening (CIS & konstruktoid)
kernel_module_hardening() {
    log "Kernel Modules: Disabling unused modules."
    echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
    echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf
    echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf
    echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf
    echo "install bluetooth /bin/true" > /etc/modprobe.d/bluetooth.conf
    echo "install floppy /bin/true" > /etc/modprobe.d/floppy.conf
    echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf
    echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf
    echo "install rds /bin/true" > /etc/modprobe.d/rds.conf
    echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf
}

# 14) Systemd Hardening (konstruktoid) - **SAFE VERSION**
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
    # *** CRITICAL FIX ***
    # Removed 'systemctl restart systemd-journald' to prevent instability.
    # Settings will apply on next reboot.

    backup_file /etc/systemd/logind.conf
    cat > /etc/systemd/logind.conf <<'EOF'
[Login]
IdleAction=lock
IdleActionSec=15min
KillUserProcesses=yes
RemoveIPC=yes
EOF
    # *** CRITICAL FIX ***
    # Removed 'systemctl restart systemd-logind' to prevent black screen/logout.
    # Settings will apply on next reboot.

    backup_file /etc/systemd/system.conf
    backup_file /etc/systemd/user.conf
    sed -ri 's/^\s*#?\s*DumpCore\s*=.*/DumpCore=no/' /etc/systemd/system.conf
    sed -ri 's/^\s*#?\s*DefaultLimitCORE\s*=.*/DefaultLimitCORE=0/' /etc/systemd/system.conf
    sed -ri 's/^\s*#?\s*CrashShell\s*=.*/CrashShell=no/' /etc/systemd/system.conf
    
    sed -ri 's/^\s*#?\s*DumpCore\s*=.*/DumpCore=no/' /etc/systemd/user.conf
    sed -ri 's/^\s*#?\s*DefaultLimitCORE\s*=.*/DefaultLimitCORE=0/' /etc/systemd/user.conf
}

# 15) Cron Hardening
harden_cron() {
    log "Cron: Restricting 'at' and 'cron' to root."
    rm -f /etc/cron.deny
    rm -f /etc/at.deny
    echo "root" > /etc/cron.allow
    echo "root" > /etc/at.allow
    chmod 640 /etc/cron.allow /etc/at.allow
    chown root:root /etc/cron.allow /etc/at.allow
}

# 16) Disable Ctrl-Alt-Del
disable_ctrl_alt_del() {
    log "Systemd: Disabling Ctrl-Alt-Del reboot target."
    systemctl mask ctrl-alt-del.target
}

# 17) Remove Legacy Files
remove_legacy_files() {
    log "Legacy: Removing .rhosts, .netrc, and hosts.equiv files."
    find / -name '.rhosts' -type f -delete 2>/dev/null || true
    find / -name '.netrc' -type f -delete 2>/dev/null || true
    rm -f /etc/hosts.equiv 2>/dev/null || true
}

# 18) Remove Legacy System Users
remove_system_users() {
    log "Users: Removing unnecessary old system users."
    for user in games gnats irc list news sync uucp; do
        if id "$user" >/dev/null 2>&1; then
            log "  -> Removing system user: $user"
            deluser "$user" 2>/dev/null || true
        fi
    done
}

# 19) Fix World-Writable Files
fix_world_writable() {
    log "Permissions: Removing world-writable permissions from files."
    mapfile -t WW_FILES < <(find /home /var/www /var/log /tmp /etc -type f -perm -0002 2>/dev/null)
    
    if [[ ${#WW_FILES[@]} -gt 0 ]]; then
        for f in "${WW_FILES[@]}"; do
            warn "  -> Removing world-writable bit from file: $f"
            chmod o-w "$f"
        done
    fi

    log "Permissions: Removing world-writable permissions from directories."
    mapfile -t WW_DIRS < <(find /home /var/www /etc -type d -perm -0002 2>/dev/null)
    
    if [[ ${#WW_DIRS[@]} -gt 0 ]]; then
        for d in "${WW_DIRS[@]}"; do
            warn "  -> Removing world-writable bit from directory: $d"
            chmod o-w "$d"
        done
    fi
}

# 20) Harden Login Screen
harden_login_screen() {
    log "Login Screen: Disabling guest account and hiding user list."

    # For LightDM (used by Mint and older Ubuntu)
    if [[ -f /etc/lightdm/lightdm.conf ]]; then
        backup_file /etc/lightdm/lightdm.conf
        if ! grep -q "allow-guest=" /etc/lightdm/lightdm.conf; then
            echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
        fi
        if ! grep -q "greeter-hide-users=" /etc/lightdm/lightdm.conf; then
            echo "greeter-hide-users=true" >> /etc/lightdm/lightdm.conf
        fi
        sed -i -E "s/^\s*allow-guest\s*=.*/allow-guest=false/" /etc/lightdm/lightdm.conf
        sed -i -E "s/^\s*greeter-hide-users\s*=.*/greeter-hide-users=true/" /etc/lightdm/lightdm.conf
    fi

    # For GDM3 (used by modern Ubuntu)
    if [[ -f /etc/gdm3/custom.conf ]]; then
        backup_file /etc/gdm3/custom.conf
        sed -i -E "s/^\s*#?\s*DisableUserList\s*=.*/DisableUserList=true/" /etc/gdm3/custom.conf
        if ! grep -q "DisableUserList=true" /etc/gdm3/custom.conf; then
            echo -e "\n[daemon]\nDisableUserList=true" >> /etc/gdm3/custom.conf
        fi
    fi
}


main() {
  require_root
  
  log "--- Applying Answer Key & CIS Hardening (STABLE v2) ---"
  
  # Remove prohibited items FIRST to prevent snap weirdness
  remove_prohibited_software
  remove_backdoors
  
  # Run updates second (this also installs libpam-pwquality)
  system_update
  
  # Harden services and OS
  services_hardening
  accounts_hardening
  sudo_hardening
  permission_fixes
  sysctl_hardening
  ufw_enable
  ssh_hardening
  updates_daily_check
  
  # Safe hardening functions
  kernel_module_hardening
  systemd_hardening # Safe version
  configure_auditd  # Safe version
  harden_cron
  disable_ctrl_alt_del
  remove_legacy_files
  remove_system_users
  fix_world_writable
  harden_login_screen
  
  # NOTE: harden_apparmor and fix_suid_guid were REMOVED
  # as they are known to break scoring engines.
  
  log "--- Script Finished ---"
  warn "This script does NOT run PAM/password hardening."
  warn "Run 'python3 py_authscript_v2.py' to apply auth policies."
  warn "This script does NOT run interactive user/group management."
  warn "Run 'python3 py_userscript_v2.py' to manage users based on the README."
  warn "Review output for errors."
  warn "A REBOOT is required to apply kernel (GRUB) and auditd rules."
}

main "$@"
