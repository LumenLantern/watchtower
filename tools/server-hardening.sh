#!/usr/bin/env bash
# =============================================================================
# WATCHTOWER Server Hardening Baseline
# Linux server hardening script — applies common security configurations
#
# Usage: sudo ./server-hardening.sh [--dry-run] [--verbose]
# Tested on: Ubuntu 22.04/24.04, Debian 12
#
# This script is intentionally conservative. Review each section before running.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

DRY_RUN=false
VERBOSE=false
LOG_FILE="/var/log/watchtower-hardening-$(date +%Y%m%d-%H%M%S).log"

usage() {
    echo "Usage: sudo $0 [--dry-run] [--verbose]"
    echo "  --dry-run   Show what would be changed without applying"
    echo "  --verbose   Show detailed output"
    exit 1
}

for arg in "$@"; do
    case $arg in
        --dry-run)  DRY_RUN=true ;;
        --verbose)  VERBOSE=true ;;
        -h|--help)  usage ;;
    esac
done

log() { echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[-]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${RED}[-]${NC} $1"; }

run() {
    if $DRY_RUN; then
        warn "DRY RUN: $*"
    else
        "$@"
    fi
}

# --- Pre-flight checks ---
if [[ $EUID -ne 0 ]] && ! $DRY_RUN; then
    err "This script must be run as root (or use --dry-run)"
    exit 1
fi

echo "============================================="
echo "  WATCHTOWER Server Hardening Baseline"
echo "  $(date)"
echo "  Dry run: $DRY_RUN"
echo "============================================="
echo

# =============================================================================
# 1. SYSTEM UPDATES
# =============================================================================
log "Section 1: System Updates"

run apt-get update -qq
run apt-get upgrade -y -qq
run apt-get install -y -qq unattended-upgrades fail2ban ufw apparmor \
    auditd audispd-plugins aide libpam-pwquality

# Enable automatic security updates
if ! $DRY_RUN; then
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    log "Automatic security updates enabled"
fi

# =============================================================================
# 2. SSH HARDENING
# =============================================================================
log "Section 2: SSH Hardening"

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_HARDENED="/etc/ssh/sshd_config.d/99-watchtower-hardening.conf"

if ! $DRY_RUN; then
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"

    cat > "$SSHD_HARDENED" <<'EOF'
# WATCHTOWER SSH Hardening
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no
Protocol 2
LoginGraceTime 30
EOF
    log "SSH hardened (config at $SSHD_HARDENED)"
    warn "IMPORTANT: Ensure you have SSH key access before restarting sshd!"
fi

# =============================================================================
# 3. FIREWALL (UFW)
# =============================================================================
log "Section 3: Firewall Configuration"

run ufw default deny incoming
run ufw default allow outgoing
run ufw allow ssh
run ufw --force enable 2>/dev/null || true
log "UFW enabled — only SSH allowed inbound"

# =============================================================================
# 4. FAIL2BAN
# =============================================================================
log "Section 4: Fail2Ban"

if ! $DRY_RUN; then
    cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
banaction = ufw

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
EOF
    run systemctl enable fail2ban
    run systemctl restart fail2ban
    log "Fail2Ban configured for SSH"
fi

# =============================================================================
# 5. KERNEL HARDENING (sysctl)
# =============================================================================
log "Section 5: Kernel Hardening"

if ! $DRY_RUN; then
    cat > /etc/sysctl.d/99-watchtower-hardening.conf <<'EOF'
# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# Disable core dumps
fs.suid_dumpable = 0

# Randomize VA space
kernel.randomize_va_space = 2

# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointers
kernel.kptr_restrict = 2
EOF
    run sysctl --system -q
    log "Kernel parameters hardened"
fi

# =============================================================================
# 6. FILE PERMISSIONS
# =============================================================================
log "Section 6: File Permissions"

run chmod 700 /root
run chmod 600 /etc/crontab
run chmod 600 /etc/ssh/sshd_config
run chmod 700 /etc/cron.d
run chmod 700 /etc/cron.daily
run chmod 700 /etc/cron.hourly
run chmod 700 /etc/cron.weekly
run chmod 700 /etc/cron.monthly

# =============================================================================
# 7. AUDIT LOGGING
# =============================================================================
log "Section 7: Audit Configuration"

if ! $DRY_RUN; then
    cat > /etc/audit/rules.d/watchtower.rules <<'EOF'
# Monitor auth files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers

# Monitor SSH config
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Log all commands run as root
-a always,exit -F arch=b64 -F euid=0 -S execve -k root_commands
EOF
    run systemctl enable auditd
    run systemctl restart auditd
    log "Audit rules applied"
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo
echo "============================================="
echo "  Hardening Complete"
echo "============================================="
log "Log saved to: $LOG_FILE"
warn "Review changes and restart SSH when ready:"
warn "  systemctl restart sshd"
echo
echo "Sections applied:"
echo "  [1] System updates & auto-upgrades"
echo "  [2] SSH hardening"
echo "  [3] UFW firewall"
echo "  [4] Fail2Ban"
echo "  [5] Kernel sysctl hardening"
echo "  [6] File permissions"
echo "  [7] Audit logging"
echo
