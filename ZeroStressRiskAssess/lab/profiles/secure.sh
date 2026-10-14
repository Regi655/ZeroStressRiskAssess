#!/usr/bin/env bash
#
# SECURE profile - executed ONCE while building the image (NEVER on the host).
#
# A hardened configuration that must PASS the assessment (overall risk LOW).
# Each block maps to a ZeroStressRiskAssess check:
#   updates            fully updated + automatic security updates
#   accounts           a single administrator, strong password, no unused accounts
#   sudo               through the sudo group only, WITH password, command logging
#   SSH                keys only, no root login, few attempts, modern algorithms only
#   firewall           nftables: SSH is the only inbound service (rules loaded at startup, see entrypoint.sh)
#   hardening          legal banner, password ageing, restrictive umask
# FAKE password (used only by sudo; SSH accepts keys only): dev / Secure-Lab-2026-q7

set -euo pipefail
[ "${LAB_BUILD:-}" = 1 ] || { echo "This script must run ONLY while building the lab container image." >&2; exit 1; }

# --- updates
# The package lists of the base layer may be stale (Docker reuses it from cache): refresh them.
apt-get update
apt-get upgrade -y
apt-get install -y --no-install-recommends unattended-upgrades nftables
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF

# --- accounts: the image's 'ubuntu' user is not needed and is removed
id ubuntu >/dev/null 2>&1 && userdel -r ubuntu 2>/dev/null || true
# Password ageing and hashing are configured BEFORE creating the user so that they apply to it
sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/; s/^UMASK.*/UMASK           027/' /etc/login.defs
grep -q '^SHA_CRYPT_MIN_ROUNDS' /etc/login.defs || printf 'SHA_CRYPT_MIN_ROUNDS 10000\nSHA_CRYPT_MAX_ROUNDS 100000\n' >> /etc/login.defs
useradd -m -s /bin/bash -G sudo dev
echo 'dev:Secure-Lab-2026-q7' | chpasswd
chage -M 365 -m 1 dev
chmod 750 /home/dev

# --- sudo: password required (default), dedicated pty and command log
tmp=$(mktemp)
cat > "$tmp" <<'CONF'
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=5
CONF
visudo -cf "$tmp" >/dev/null
install -m 0440 -o root -g root "$tmp" /etc/sudoers.d/10-secure
rm -f "$tmp"

# --- SSH: "00-" prefix because sshd keeps the FIRST value it reads, overriding the default files
cat > /etc/ssh/sshd_config.d/00-secure.conf <<'CONF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthenticationMethods publickey
AllowUsers dev
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
Banner /etc/issue.net
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
CONF
mkdir -p /run/sshd && sshd -t   # syntax check: a mistake fails the build instead of producing an sshd that does not start

# --- firewall: only SSH is allowed in, everything else is dropped
# NOTE: on a real host this file starts with "flush ruleset". Not here: it would also remove the rules
# Docker installs in the container for its embedded DNS (127.0.0.11), breaking name resolution (and apt).
# Only our own table is flushed.
cat > /etc/nftables.conf <<'CONF'
#!/usr/sbin/nft -f
table inet filter
flush table inet filter
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto { icmp, ipv6-icmp } accept
    tcp dport 22 ct state new limit rate 30/minute accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output priority 0; policy accept; }
}
CONF

# --- legal banner (users are informed that the system is private and monitored)
printf 'Private system. Access is restricted to authorised personnel; all activity is logged.\n' \
  | tee /etc/issue /etc/issue.net >/dev/null
