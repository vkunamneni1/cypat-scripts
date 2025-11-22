#!/bin/bash
# CyberPatriot Ubuntu 22/Mint 21 Hardening Script (v4 - MASTER)
#
# Merges v3 stable automation with the full CIS Benchmark recommendations.
# EXCLUDES: Time Sync (2.3) and advanced PAM password rules (5.3.3.x)
#
# - Audits run at the end and save reports to ~/Desktop/AUDIT_REPORTS
# - Scoring-engine-safe: NO AppArmor, NO auto-SUID removal.
# - Stable: NO random reboots or logouts.
# - Installs AIDE, debsums, and required PAM modules.
#
set -euo pipefail
IFS=$'\n\t'

log() { echo -e "\n[+] $1"; }
warn() { echo -e "[!] $1"; }

# Find the primary user's desktop to save reports
PRIMARY_USER=$(awk -F: '($3 >= 1000) && ($1 != "nobody") {print $1}' /etc/passwd | head -n 1)
REPORT_DIR="/home/$PRIMARY_USER/Desktop/AUDIT_REPORTS"
if [[ -z "$PRIMARY_USER" ]]; then
    warn "Could not find a primary user (UID >= 1000). Audit reports will be saved to /root/AUDIT_REPORTS."
    REPORT_DIR="/root/AUDIT_REPORTS"
fi

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
  
  log "Setting root shell to nologin."
  usermod -s /usr/sbin/nologin root || true

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
  
  # NEW: Restrict ptrace (CIS 1.5.2)
  set_sysctl "kernel.yama.ptrace_scope" "1"

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
  # Set banner (CIS 1.6.3 / 5.1.5)
  grep -q '^\s*Banner' "$f" && sed -ri 's|^\s*Banner.*|Banner /etc/issue.net|' "$f" || echo 'Banner /etc/issue.net' >> "$f"
  
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
  
  # Purge common unwanted services
  apt-get purge -y postfix dovecot-core rpcbind samba postgresql bind9 \
                   autofs isc-dhcp-server dnsmasq slapd nfs-kernel-server \
                   nis rsync snmpd tftpd-hpa xinetd xserver-common \
                   2>/dev/null || true
  
  # Disable other common unwanted services
  systemctl disable --now vsftpd 2>/dev/null || true
  systemctl disable --now nginx 2>/dev/null || true
  systemctl disable --now squid 2>/dev/null || true
  systemctl disable --now avahi-daemon.service avahi-daemon.socket 2>/dev/null || true
  
  # Disable apport (CIS 1.5.5)
  systemctl disable --now apport.service 2>/dev/null || true
}

# 9) Update System
system_update() {
    log "System Updates: running apt-get update and upgrade."
    
    # Install required security packages from CIS/checklist
    log "Installing required PAM/Audit modules: libpam-pwquality, libpam-tmpdin, libpam-usb, debsums, aide, aide-common..."
    apt-get install -y libpam-pwquality libpam-tmpdin libpam-usb debsums aide aide-common 2>/dev/null || true
    
    log "Running apt-get update..."
    apt-get update
    
    log "Running apt-get full-upgrade..."
    apt-get full-upgrade -y
}

# 10) Remove Prohibited Software
remove_prohibited_software() {
  log "Software: removing prohibited software."
  apt-get purge -y aisleriot doona xprobe ophcrack wireshark \
                   telnet rsh-client chromium-browser \
                   nis talk ldap-utils ftp prelink \
                   2>/dev/null || true
  
  apt-get autoremove -y 2>/dev/null || true
}

# 11) Remove Backdoors
remove_backdoors() {
  log "Backdoors: removing known backdoors."
  pkill -f "nc.traditional -l -p 1337" 2>/dev/null || true
  sed -i '/nc.traditional/d' /etc/crontab 2>/dev/null || true
  rm -f /usr/bin/nc.traditional 2>/dev/null || true

  pkill -f "kneelB4zod.py" 2>/dev/null || true
  rm -rf /usr/share/zod 2>/dev/null || true
}

# 12) Configure auditd (CIS) - SAFE VERSION
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
    log "Setting admin_space_left_action to 'syslog' to prevent shutdowns."
    sed -i -E "s/^[#\s]*admin_space_left_action\s*=.*/admin_space_left_action = syslog/g" /etc/audit/auditd.conf
    
    cat > /etc/audit/rules.d/99-cis.rules <<'EOF'
# CIS Audit Rules (v3 Master)
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

# 13) Kernel Module Hardening
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

# 14) Systemd Hardening - SAFE VERSION
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

    backup_file /etc/systemd/logind.conf
    cat > /etc/systemd/logind.conf <<'EOF'
[Login]
IdleAction=lock
IdleActionSec=15min
KillUserProcesses=yes
RemoveIPC=yes
EOF

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
    log "Login Screen: Disabling guest, hiding user list, setting banner, and locking."

    local banner_msg="Authorized users only. All activity may be monitored."

    # For LightDM (used by Mint and older Ubuntu)
    if [[ -f /etc/lightdm/lightdm.conf ]]; then
        backup_file /etc/lightdm/lightdm.conf
        sed -i -E "s/^\s*allow-guest\s*=.*/allow-guest=false/" /etc/lightdm/lightdm.conf
        sed -i -E "s/^\s*greeter-hide-users\s*=.*/greeter-hide-users=true/" /etc/lightdm.conf
        
        if ! grep -q "allow-guest=false" /etc/lightdm/lightdm.conf; then
            echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
        fi
        if ! grep -q "greeter-hide-users=true" /etc/lightdm/lightdm.conf; then
            echo "greeter-hide-users=true" >> /etc/lightdm/lightdm.conf
        fi
    fi

    # For GDM3 (used by modern Ubuntu)
    if command -v gsettings >/dev/null 2>&1; then
        log "  -> Applying GDM settings..."
        # (CIS 1.7.3) Disable user list
        gsettings set org.gnome.login-screen disable-user-list true 2>/dev/null || warn "gsettings: Could not set disable-user-list"
        # (CIS 1.7.2) Set login banner
        gsettings set org.gnome.login-screen banner-message-enable true 2>/dev/null || warn "gsettings: Could not set banner-message-enable"
        gsettings set org.gnome.login-screen banner-message-text "$banner_msg" 2>/dev/null || warn "gsettings: Could not set banner-message-text"
        # (CIS 1.7.4) Set screen lock
        gsettings set org.gnome.desktop.session idle-delay 900 2>/dev/null || warn "gsettings: Could not set idle-delay"
        gsettings set org.gnome.desktop.screensaver lock-delay 5 2>/dev/null || warn "gsettings: Could not set lock-delay"
    else
        warn "gsettings command not found. Skipping GDM hardening."
    fi
    
    # (CIS 1.7.10) Disable XDMCP
    if [[ -f /etc/gdm3/custom.conf ]]; then
        backup_file /etc/gdm3/custom.conf
        if ! grep -q "\[xdmcp\]" /etc/gdm3/custom.conf; then
            echo -e "\n[xdmcp]\nEnable=false" >> /etc/gdm3/custom.conf
        else
            sed -i -E "s/^\s*Enable\s*=.*/Enable=false/" /etc/gdm3/custom.conf
        fi
    fi
}

# 21) NEW: Harden /etc/securetty (from checklist)
harden_securetty() {
    log "Hardening /etc/securetty to only allow root login on tty1."
    if [[ -f /etc/securetty ]]; then
        backup_file /etc/securetty
        echo "tty1" > /etc/securetty
        chmod 600 /etc/securetty
        chown root:root /etc/securetty
    else
        log "  -> /etc/securetty not found, skipping."
    fi
}

# 22) NEW: Harden /etc/hosts.allow and /etc/hosts.deny (from checklist)
harden_host_access() {
    log "Hardening host access files (hosts.allow, hosts.deny)."
    
    backup_file /etc/hosts.deny
    echo "ALL: ALL" > /etc/hosts.deny
    
    backup_file /etc/hosts.allow
    echo "sshd: ALL" > /etc/hosts.allow
    
    chmod 644 /etc/hosts.allow /etc/hosts.deny
    chown root:root /etc/hosts.allow /etc/hosts.deny
}

# 23) NEW: Set Default Umask (CIS 5.4.2.6, 5.4.3.3)
harden_umask() {
    log "Setting secure default umask (027)."
    
    # For /etc/login.defs (affects useradd)
    backup_file /etc/login.defs
    sed -i -E "s/^\s*UMASK\s+.*/UMASK\t\t027/" /etc/login.defs
    if ! grep -q "UMASK" /etc/login.defs; then
        echo "UMASK 027" >> /etc/login.defs
    fi
    
    # For /etc/profile (affects login shells)
    backup_file /etc/profile
    echo "umask 027" > /etc/profile.d/99-umask.sh
    chmod 644 /etc/profile.d/99-umask.sh
    chown root:root /etc/profile.d/99-umask.sh
}

# 24) NEW: Set Shell TMOUT (CIS 5.4.3.2)
harden_shell_timeout() {
    log "Setting global shell timeout (TMOUT=900)."
    cat > /etc/profile.d/99-timeout.sh <<'EOF'
# (CIS 5.4.3.2) Auto-logout after 15 minutes of inactivity
TMOUT=900
readonly TMOUT
export TMOUT
EOF
    chmod 644 /etc/profile.d/99-timeout.sh
    chown root:root /etc/profile.d/99-timeout.sh
}

# 25) NEW: Configure AIDE (CIS 6.3)
harden_aide() {
    log "Configuring AIDE file integrity monitor..."
    if ! command -v aide >/dev/null 2>&1; then
        warn "AIDE not installed. Skipping."
        return
    fi
    
    log "  -> Initializing AIDE database (this will take a few minutes)..."
    aideinit -y -f || true # -f to force, -y for non-interactive
    
    log "  -> Installing new AIDE database..."
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    else
        warn "AIDE database generation failed. Skipping."
        return
    fi

    log "  -> Configuring AIDE to monitor audit tools (CIS 6.3.3)..."
    echo -e "\n# (CIS 6.3.3) Monitor audit tools\n/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512\n/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512\n/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512\n/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512\n/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512\n/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512\n" >> /etc/aide/aide.conf

    log "  -> Enabling AIDE daily check timer (CIS 6.3.2)..."
    systemctl enable --now aidecheck.timer 2>/dev/null || true
}

# 26) NEW: Run System Audits
run_system_audits() {
    log "Running system audits... Reports will be saved to $REPORT_DIR"
    mkdir -p "$REPORT_DIR"
    chown "$PRIMARY_USER":"$PRIMARY_USER" "$REPORT_DIR" 2>/dev/null || true

    log "  -> Finding world-writable files (CIS 7.1.11)..."
    (df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002) > "$REPORT_DIR/world_writable_files.txt" 2>/dev/null
    
    log "  -> Finding unowned/ungrouped files (CIS 7.1.12)..."
    (df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser) > "$REPORT_DIR/unowned_files.txt" 2>/dev/null
    (df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup) > "$REPORT_DIR/ungrouped_files.txt" 2>/dev/null

    log "  -> Finding SUID/SGID files (CIS 7.1.13)..."
    (df --local -P | awk {'if (NR!=1)print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000) > "$REPORT_DIR/suid_files.txt" 2>/dev/null
    (df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000) > "$REPORT_DIR/sgid_files.txt" 2>/dev/null

    log "  -> Finding modified config files..."
    (dpkg-query -W -f='${Conffiles}\n' '*' | awk 'OFS="  "{print $2,$1}' | md5sum -c 2>/dev/null | awk -F': ' '$2 !~ /OK/{print $1}') > "$REPORT_DIR/modified_config_files.txt" 2>/dev/null

    log "  -> Listing manually installed packages..."
    apt-mark showmanual > "$REPORT_DIR/manually_installed_packages.txt" 2>/dev/null

    log "  -> Checking package integrity with debsums..."
    debsums -ac > "$REPORT_DIR/package_integrity_report.txt" 2>/dev/null

    log "  -> Listing listening ports (CIS 2.1.22)..."
    (echo "--- ss (new) ---"; ss -tulpn; echo -e "\n--- netstat (old) ---"; netstat -tulpn) > "$REPORT_DIR/listening_ports.txt" 2>/dev/null
    
    log "  -> Saving MOTD/Issue files..."
    (echo "--- /etc/issue ---"; cat /etc/issue; echo -e "\n--- /etc/issue.net ---"; cat /etc/issue.net; echo -e "\n--- /etc/motd ---"; cat /etc/motd) > "$REPORT_DIR/motd_and_issue_files.txt" 2>/dev/null

    log "  -> Checking root PATH integrity (CIS 5.4.2.5)..."
    (echo "$PATH" | grep -q "::" && echo "FAIL: Root PATH contains empty directory (::)" || echo "PASS: No empty directory in root PATH") > "$REPORT_DIR/root_path_integrity.txt"
    (echo "$PATH" | grep -q ":$" && echo "FAIL: Root PATH contains trailing colon (:)" || echo "PASS: No trailing colon in root PATH") >> "$REPORT_DIR/root_path_integrity.txt"
    (echo "$PATH" | tr ":" "\n" | grep "^\.$" && echo "FAIL: Root PATH contains current directory (.)" || echo "PASS: No current directory in root PATH") >> "$REPORT_DIR/root_path_integrity.txt"

    chown -R "$PRIMARY_USER":"$PRIMARY_USER" "$REPORT_DIR" 2>/dev/null || true
    log "Audit reports saved to $REPORT_DIR"
}

main() {
  require_root
  
  log "--- Applying Answer Key & CIS Hardening (MASTER v4) ---"
  
  # Remove prohibited items FIRST to prevent snap weirdness
  remove_prohibited_software
  remove_backdoors
  
  # Run updates second (this also installs new PAM/audit/AIDE packages)
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
  systemd_hardening       # Safe version
  configure_auditd        # Safe version
  harden_cron
  disable_ctrl_alt_del
  remove_legacy_files
  remove_system_users
  fix_world_writable
  harden_login_screen
  
  # New hardening steps from CIS/checklist
  # harden_banners
  harden_securetty
  harden_host_access
  harden_umask
  harden_shell_timeout
  harden_aide
  
  # NOTE: harden_apparmor and fix_suid_guid were REMOVED
  # as they are known to break scoring engines.
  
  # Run all audits LAST to report on the final state
  run_system_audits
  
  log "--- Script Finished ---"
  warn "This script does NOT run advanced PAM password rules (complexity, history)."
  warn "Run 'python3 py_authscript_master.py' to apply base auth policies."
  warn "This script does NOT run interactive user/group management."
  warn "Run 'python3 py_userscript_master.py' to manage users based on the README."
  warn "Review output for errors."
  warn "A REBOOT is required to apply kernel (GRUB) and auditd rules."
}

main "$@"
