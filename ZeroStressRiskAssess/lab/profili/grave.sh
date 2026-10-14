#!/usr/bin/env bash
#
# GRAVE profile - executed ONCE while building the image (NEVER on the host).
#
# A machine with deliberately severe misconfigurations: passwordless accounts and sudo, SSH and FTP
# open to everyone, loose permissions, outdated packages. Expected risk: CRITICO.
# All passwords and data are fake. Nothing here affects the host.

set -euo pipefail
[ "${LAB_BUILD:-}" = 1 ] || { echo "Questo script va eseguito SOLO nel build del container del laboratorio." >&2; exit 1; }

apt-get install -y --no-install-recommends vsftpd

# ----------------------------------------------------------------------
# Users
# ----------------------------------------------------------------------
# 1) guest: empty password
useradd -m -s /bin/bash guest
passwd -d guest >/dev/null

# 2) dev: weak password that never expires.
#    The UID is assigned by useradd rather than hard-coded: ubuntu:24.04 already ships the 'ubuntu' user
#    (UID 1000) and guest takes the next free one, so a fixed UID such as 1001 may already be in use
#    and break the build.
useradd -m -s /bin/bash dev
echo 'dev:dev2020' | chpasswd
chage -M 99999 dev
DEV_UID=$(id -u dev)

# 3) dev2: same UID as dev. Two accounts sharing a UID are the same identity for the kernel; this
#    typically results from careless migrations and must be reported by an audit.
#    -o allows the duplicate UID.
useradd -o -u "$DEV_UID" -g dev -m -s /bin/bash dev2
echo 'dev2:welcome1' | chpasswd

# 4) root with a weak password (accepted by SSH, see below)
echo 'root:Passw0rd' | chpasswd

# ----------------------------------------------------------------------
# sudo: no password for user dev
# ----------------------------------------------------------------------
# The file is validated with visudo before installation: a syntax error in /etc/sudoers.d
# would break sudo for every user.
tmp=$(mktemp)
cat > "$tmp" <<'EOF'
Defaults:dev !authenticate
dev ALL=(ALL:ALL) ALL
EOF
visudo -cf "$tmp" >/dev/null
install -m 0440 -o root -g root "$tmp" /etc/sudoers.d/90-lab
rm -f "$tmp"

# ----------------------------------------------------------------------
# SSH: permissive configuration
# ----------------------------------------------------------------------
# "00-" prefix: sshd keeps the FIRST value it reads, so this file overrides the defaults.
cat > /etc/ssh/sshd_config.d/00-lab.conf <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 10
X11Forwarding yes
EOF

# ----------------------------------------------------------------------
# FTP: anonymous access with uploads enabled
# ----------------------------------------------------------------------
mkdir -p /srv/ftp/pub /srv/ftp/upload
chown root:root /srv/ftp
chmod 755 /srv/ftp
chmod 777 /srv/ftp/pub /srv/ftp/upload

cat > /etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
no_anon_password=YES
anon_root=/srv/ftp
anon_upload_enable=YES
anon_mkdir_write_enable=YES
local_enable=YES
write_enable=YES
pasv_enable=NO
seccomp_sandbox=NO
secure_chroot_dir=/var/run/vsftpd/empty
EOF

# ----------------------------------------------------------------------
# Permissions and secrets left behind (all fake)
# ----------------------------------------------------------------------
# World-writable application directory containing a world-readable and world-writable
# credentials file
mkdir -p /opt/app
cat > /opt/app/db.env <<'EOF'
DB_HOST=db.interno.lab
DB_USER=app
DB_PASSWORD=finta-password-123
EOF
chmod 777 /opt/app
chmod 666 /opt/app/db.env

# Private SSH key without passphrase, readable by everyone (644)
mkdir -p /home/dev/.ssh
ssh-keygen -q -t ed25519 -N '' -C 'dev@lab' -f /home/dev/.ssh/id_ed25519
chmod 644 /home/dev/.ssh/id_ed25519
chown -R dev:dev /home/dev/.ssh

# Password recorded in the shell history
echo 'mysql -u root -pFintaPassword123 -h db.interno.lab' > /home/dev/.bash_history
chown dev:dev /home/dev/.bash_history

# dev2 home directory open to everyone
chmod 777 /home/dev2

# Hidden directory with a file inside, in a temporary location
mkdir -p /var/tmp/.cache-x
echo "file di laboratorio: cartella nascosta da trovare" > /var/tmp/.cache-x/nota.txt

# ----------------------------------------------------------------------
# EICAR test file for ClamAV (standard, harmless test string)
# ----------------------------------------------------------------------
for f in /home/dev/eicar_test.txt /srv/ftp/upload/eicar_test.txt; do
  cat > "$f" <<'EICAR'
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
EICAR
done
chown dev:dev /home/dev/eicar_test.txt
