#!/usr/bin/env bash
#
# MEDIA profile - executed ONCE while building the image (NEVER on the host).
#
# A neglected server: up to date, but configured in a hurry and never reviewed. Nothing exploitable
# by anyone without effort (no CRITICO findings), but several ALTO and MEDIO issues:
#   - FTP for system users without encryption (passwords travel in clear text) and no firewall;
#   - SSH with password login and many authentication attempts, X11Forwarding;
#   - a passwordless sudo rule for a script, a world-writable upload directory;
#   - automatic updates disabled.
# Expected risk: ALTO.
# FAKE credentials: dev / dev2020 (member of sudo)

set -euo pipefail
[ "${LAB_BUILD:-}" = 1 ] || { echo "Questo script va eseguito SOLO nel build del container del laboratorio." >&2; exit 1; }

# The package lists of the base layer may be stale (Docker reuses it from cache): refresh them.
apt-get update
apt-get upgrade -y
apt-get install -y --no-install-recommends vsftpd

useradd -m -s /bin/bash -G sudo dev
echo 'dev:dev2020' | chpasswd

# SSH: password login, many attempts, X11
cat > /etc/ssh/sshd_config.d/00-lab.conf <<'CONF'
PasswordAuthentication yes
MaxAuthTries 10
X11Forwarding yes
CONF

# FTP for local users, without TLS and without chroot
cat > /etc/vsftpd.conf <<'CONF'
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=NO
ssl_enable=NO
pasv_enable=NO
seccomp_sandbox=NO
secure_chroot_dir=/var/run/vsftpd/empty
CONF

# sudo: a passwordless script "for convenience" (application restart).
# systemctl is deliberately avoided: a pager opened as root leads to a shell (GTFOBins), which the tool
# correctly rates CRITICO. A root-owned script not writable by others is a lesser issue.
printf '#!/bin/sh\necho "riavvio di app (laboratorio)"\n' > /usr/local/bin/riavvia-app
chmod 755 /usr/local/bin/riavvia-app
tmp=$(mktemp)
echo 'dev ALL=(root) NOPASSWD: /usr/local/bin/riavvia-app' > "$tmp"
visudo -cf "$tmp" >/dev/null
install -m 0440 -o root -g root "$tmp" /etc/sudoers.d/90-app
rm -f "$tmp"

# Application: world-writable upload directory (no sticky bit)
mkdir -p /srv/app/upload
chmod 777 /srv/app/upload

# Automatic updates disabled
apt-get remove -y unattended-upgrades 2>/dev/null || true
