#!/bin/bash
# CyberPatriot Ubuntu 22 hardening script (Comet Assistant enhanced)
# Applies answer key mitigations excluding prohibited install/remove exceptions per README.
# Focus areas: accounts, sudo, permissions, PAM, firewall, SSH, sysctl, updates.
set -euo pipefail
IFS=$'\n\t'

log() { echo -e "[+] $1"; }
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

# 1) Accounts and groups — remove unauthorized, fix admin, set passwords placeholder
accounts_hardening() {
  log "Accounts: locking root, ensuring unauthorized users removed (manual list), and fixing admin group."
  # Lock root account
  passwd -l root || true

  # Example from answer key narrative: ensure specific user not admin (adapt lists as needed)
  if getent group sudo >/dev/null; then
    for u in ham cornelius; do
      if id "$u" >/dev/null 2>&1; then gpasswd -d "$u" sudo || true; fi
    done
  fi

  # Add user to group example (pioneers/mariya in AK). Use conditional presence only.
  if getent group pioneers >/dev/null 2>&1; then
    id mariya >/dev/null 2>&1 && gpasswd -a mariya pioneers || true
  fi

  # Remove explicitly unauthorized user from AK (eli). Do not delete built-in/system accounts.
  if id eli >/dev/null 2>&1; then deluser --remove-home eli || true; fi

  # Password change placeholders (interactive changes are image-specific). Use chage for policy (below).
}

# 2) Sudoers tightening
sudo_hardening() {
  log "Sudo: audit members and require pty and secure path." 
  backup_file /etc/sudoers
  # Ensure secure defaults
  if ! grep -q '^Defaults.*requiretty' /etc/sudoers; then echo 'Defaults    requiretty' >> /etc/sudoers; fi
  if ! grep -q '^Defaults.*use_pty' /etc/sudoers; then echo 'Defaults    use_pty' >> /etc/sudoers; fi
  # Avoid insults/leaks
  sed -ri 's/^\s*Defaults\s+!?(visiblepw).*/Defaults \!visiblepw/' /etc/sudoers || true
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
  log "Permissions: fix /etc/shadow and home directory permissions."
  chmod 640 /etc/shadow 2>/dev/null || true
  chown root:shadow /etc/shadow 2>/dev/null || true
  # Home directories 750 per common CP guidance
  for d in /home/*; do
    [[ -d "$d" ]] || continue
    chmod 750 "$d" || true
  done
}

# 4) PAM and password policy
pam_policy() {
  log "PAM: set min password length, null passwords disallowed, and account lockout scaffolding."
  # login.defs min days = 2
  backup_file /etc/login.defs
  if grep -q '^\s*PASS_MIN_DAYS' /etc/login.defs; then
    sed -ri 's/^\s*PASS_MIN_DAYS\s+.*/PASS_MIN_DAYS   2/' /etc/login.defs
  else
    echo 'PASS_MIN_DAYS   2' >> /etc/login.defs
  fi

  # pwquality minlen=10
  backup_file /etc/pam.d/common-password
  if grep -q '^password\s+requisite\s+pam_pwquality.so' /etc/pam.d/common-password; then
    if grep -q 'minlen=' /etc/pam.d/common-password; then
      sed -ri 's/(pam_pwquality\.so[^#]*)(minlen=)[0-9]+/\110/' /etc/pam.d/common-password
    else
      sed -ri 's/(pam_pwquality\.so[^#]*retry=3)(.*)/\1 minlen=10\2/' /etc/pam.d/common-password
    fi
  else
    echo 'password requisite pam_pwquality.so retry=3 minlen=10' >> /etc/pam.d/common-password
  fi

  # Remove nullok from common-auth
  backup_file /etc/pam.d/common-auth
  sed -ri 's/\bnullok\b//g' /etc/pam.d/common-auth || true

  # faillock configuration files as per AK (create but do not enable by default without pam-auth-update interaction)
  mkdir -p /usr/share/pam-configs
  cat > /usr/share/pam-configs/faillock <<'EOF'
Name: Enforce failed login attempt counter
Default: no
Priority: 0
Auth-Type: Primary
Auth:
 [default=die] pam_faillock.so authfail
 sufficient pam_faillock.so authsucc
EOF
  cat > /usr/share/pam-configs/faillock_notify <<'EOF'
Name: Notify on failed login attempts
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
 requisite pam_faillock.so preauth
EOF
}

# 5) Sysctl networking security
sysctl_hardening() {
  log "Sysctl: enable TCP SYN cookies and disable IPv4 forwarding."
  backup_file /etc/sysctl.conf
  if grep -q '^\s*net\.ipv4\.tcp_syncookies' /etc/sysctl.conf; then
    sed -ri 's/^\s*net\.ipv4\.tcp_syncookies\s*=.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf
  else
    echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.conf
  fi
  if grep -q '^\s*net\.ipv4\.ip_forward' /etc/sysctl.conf; then
    sed -ri 's/^\s*net\.ipv4\.ip_forward\s*=.*/net.ipv4.ip_forward=0/' /etc/sysctl.conf
  else
    echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf
  fi
  sysctl --system >/dev/null 2>&1 || true
}

# 6) UFW firewall enable (no package install here; assume present per README exception rules)
ufw_enable() {
  log "Firewall: enable UFW with sane defaults and allow SSH."
  if command -v ufw >/dev/null 2>&1; then
    ufw --force default deny incoming || true
    ufw --force default allow outgoing || true
    ufw allow 22/tcp || true
    yes | ufw enable || true
  else
    warn "UFW not installed; skipping per exceptions (no installs)."
  fi
}

# 7) SSH security per AK
ssh_hardening() {
  log "SSH: disable root login and tighten settings."
  local f=/etc/ssh/sshd_config
  backup_file "$f"
  grep -q '^\s*PermitRootLogin' "$f" && sed -ri 's/^\s*PermitRootLogin.*/PermitRootLogin no/' "$f" || echo 'PermitRootLogin no' >> "$f"
  grep -q '^\s*PermitEmptyPasswords' "$f" && sed -ri 's/^\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$f" || echo 'PermitEmptyPasswords no' >> "$f"
  grep -q '^\s*ClientAliveInterval' "$f" && sed -ri 's/^\s*ClientAliveInterval.*/ClientAliveInterval 300/' "$f" || echo 'ClientAliveInterval 300' >> "$f"
  grep -q '^\s*ClientAliveCountMax' "$f" && sed -ri 's/^\s*ClientAliveCountMax.*/ClientAliveCountMax 0/' "$f" || echo 'ClientAliveCountMax 0' >> "$f"
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
}

# 8) Updates configuration (auto-check daily) — GUI setting mirrored via unattended-upgrades periodics
updates_daily_check() {
  log "Updates: configure periodic apt update to check daily."
  mkdir -p /etc/apt/apt.conf.d
  cat > /etc/apt/apt.conf.d/10periodic-check <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "7";
EOF
}

# 9) Services: disable insecure services (but avoid removing required exceptions per README)
services_hardening() {
  log "Services: disable FTP (vsftpd) and nginx if present; keep critical/required ones."
  systemctl disable --now vsftpd 2>/dev/null || true
  systemctl disable --now nginx 2>/dev/null || true
}

# 10) Media cleanup example from AK (mp3 in linda)
media_cleanup() {
  log "Media: remove prohibited MP3s from user home if present (linda)."
  if [[ -d /home/linda/Music ]]; then
    rm -f /home/linda/Music/*.mp3 2>/dev/null || true
  fi
}

main() {
  require_root
  accounts_hardening
  sudo_hardening
  permission_fixes
  pam_policy
  sysctl_hardening
  ufw_enable
  ssh_hardening
  updates_daily_check
  services_hardening
  media_cleanup
  log "Completed CyberPatriot Ubuntu 22 hardening (answer key aligned, installs/removals excepted)."
}

main "$@"
