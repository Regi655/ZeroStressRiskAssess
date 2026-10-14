# Risk assessment — 172.28.10.10

|         |                                                                                                                              |
|---------|------------------------------------------------------------------------------------------------------------------------------|
| Date    | 2026-10-14 22:31                                                                                                             |
| System  | Ubuntu 24.04 LTS (kernel 6.18.44-fc-v114) — **container**                                                                    |
| Mode    | remote over SSH (dev@172.28.10.10, auth publickey)                                                                           |
| Sources | native checks (accounts, sudo, SSH, permissions, services, kernel...), nmap + NSE scripts, ssh-audit, Lynis (portable) 3.1.8 |
| Tool    | ZeroStressRiskAssess 1.0.0                                                                                                   |

## Overall risk: **CRITICAL**

20 problems: 4 critical, 9 high, 2 medium, 5 low. The overall risk is that of the most severe problem.

## Risk matrix (impact x likelihood)

Each cell: number of problems, risk level, problem IDs (see the table). "-" = no problems.

| Impact \ Likelihood | 1 Rare         | 2 Unlikely                    | 3 Possible                         | 4 Likely        | 5 Almost certain    |
|---------------------|----------------|-------------------------------|------------------------------------|-----------------|---------------------|
| **5 Total**         | -              | **1** HIGH: R13               | **2** CRITICAL: R03, R04           | -               | **1** CRITICAL: R01 |
| **4 Severe**        | -              | -                             | **7** HIGH: R05, R06, R07, R08 ... | -               | **1** CRITICAL: R02 |
| **3 Significant**   | -              | **1** MEDIUM: R14             | -                                  | **1** HIGH: R12 | -                   |
| **2 Limited**       | **1** LOW: R20 | **4** LOW: R16, R17, R18, R19 | **1** MEDIUM: R15                  | -               | -                   |
| **1 Minimal**       | -              | -                             | -                                  | -               | -                   |

## Risk table

Sorted by risk. *Rationale* explains the likelihood: where the weakness is exploited from and what the tool verified (e.g. whether the port is reachable from the controller).

| ID  | Risk     | Level    | Problem                                                                                                                                 | Impact        | Likelihood       | Rationale                                                                                      | Remediation                                                                                                                                                    |
|-----|----------|----------|-----------------------------------------------------------------------------------------------------------------------------------------|---------------|------------------|------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| R01 | 25 (5x5) | CRITICAL | SSH login without password (accounts: guest)                                                                                            | 5 Total       | 5 Almost certain | from the network: port 22 reachable from the controller                                        | PermitEmptyPasswords no in sshd\_config and a password (or passwd -l to lock it) for every account without a password.                                         |
| R02 | 20 (4x5) | CRITICAL | Anonymous FTP with file upload by anyone                                                                                                | 4 Severe      | 5 Almost certain | from the network: port 21 reachable from the controller                                        | In vsftpd: anonymous\_enable=NO. If anonymous FTP is really needed: anon\_upload\_enable=NO, anon\_mkdir\_write\_enable=NO and directories with mode 755.      |
| R03 | 15 (5x3) | CRITICAL | Defaults !authenticate: sudo never asks for a password                                                                                  | 5 Total       | 3 Possible       | with an account on the machine                                                                 | Remove NOPASSWD/!authenticate and programs that spawn a shell; keep env\_reset (visudo).                                                                       |
| R04 | 15 (5x3) | CRITICAL | SSH allows direct root login with a password (PermitRootLogin yes)                                                                      | 5 Total       | 3 Possible       | from the network: port 22 reachable from the controller                                        | PermitRootLogin prohibit-password (or no) and log in as a regular user + sudo.                                                                                 |
| R05 | 12 (4x3) | HIGH     | SSH private key readable by others: /home/dev/.ssh/id\_ed25519                                                                          | 4 Severe      | 3 Possible       | with an account on the machine                                                                 | chmod 600 on the key; if others could read it, consider it stolen and replace it.                                                                              |
| R06 | 12 (4x3) | HIGH     | Home directory of 'dev2' writable by everyone                                                                                           | 4 Severe      | 3 Possible       | with an account on the machine                                                                 | chmod o-w on the directory (or chmod +t if it must remain shared, like /tmp).                                                                                  |
| R07 | 12 (4x3) | HIGH     | World-writable directory without sticky bit                                                                                             | 4 Severe      | 3 Possible       | with an account on the machine                                                                 | chmod o-w on the directory (or chmod +t if it must remain shared, like /tmp).                                                                                  |
| R08 | 12 (4x3) | HIGH     | Credentials file writable by everyone                                                                                                   | 4 Severe      | 3 Possible       | with an account on the machine                                                                 | chmod 600 (or 640 with the service group) and change the credentials if exposed.                                                                               |
| R09 | 12 (4x3) | HIGH     | 32 security updates not installed (including critical components: libc-bin, libc6, openssh-client, openssh-server, openssh-sftp-server) | 4 Severe      | 3 Possible       | public vulnerabilities already fixed by the vendor: ready-made exploits exist for many of them | sudo apt update && sudo apt upgrade; then restart the services or the machine if required.                                                                     |
| R10 | 12 (4x3) | HIGH     | Network-exposed service on port 21 (ftp vsftpd 3.0.5)                                                                                   | 4 Severe      | 3 Possible       | from the network: port 21 reachable from the controller                                        | FTP sends passwords in clear text: replace it with SFTP (already provided by SSH) or enable FTPS (ssl\_enable=YES in vsftpd); if it is not needed, disable it. |
| R11 | 12 (4x3) | HIGH     | SSH accepts password authentication (PasswordAuthentication yes)                                                                        | 4 Severe      | 3 Possible       | from the network: port 22 reachable from the controller                                        | Key-only login: PasswordAuthentication no (after copying the keys with ssh-copy-id).                                                                           |
| R12 | 12 (3x4) | HIGH     | No active firewall and services reachable besides SSH: 21/tcp                                                                           | 3 Significant | 4 Likely         | from the network: port 21 reachable from the controller                                        | Enable a firewall (ufw default deny incoming; ufw allow ssh) and open only the required ports.                                                                 |
| R13 | 10 (5x2) | HIGH     | 'dev' can run any command as root                                                                                                       | 5 Total       | 2 Unlikely       | with an account on the machine                                                                 | Normal for an administrator: verify that the user must be one and uses a strong password.                                                                      |
| R14 | 6 (3x2)  | MEDIUM   | UID 1002 shared by several accounts                                                                                                     | 3 Significant | 2 Unlikely       | with an account on the machine                                                                 | One UID per person; /usr/sbin/nologin as the shell of service accounts (usermod -s).                                                                           |
| R15 | 6 (2x3)  | MEDIUM   | FTP: local users not confined to their home directory (chroot\_local\_user=NO)                                                          | 2 Limited     | 3 Possible       | with an account on the machine                                                                 | chroot\_local\_user=YES in vsftpd.conf.                                                                                                                        |
| R16 | 4 (2x2)  | LOW      | Lynis hardening suggestions (13)                                                                                                        | 2 Limited     | 2 Unlikely       | with an account on the machine                                                                 | Configuration improvements, not urgent problems: the list with the Lynis IDs is in the lynis section.                                                          |
| R17 | 4 (2x2)  | LOW      | SSH: X11Forwarding enabled                                                                                                              | 2 Limited     | 2 Unlikely       | from the network: port 22 reachable from the controller                                        | X11Forwarding no, MaxAuthTries 3-4, LogLevel INFO or VERBOSE.                                                                                                  |
| R18 | 4 (2x2)  | LOW      | SSH: MaxAuthTries 10 (above the default of 6)                                                                                           | 2 Limited     | 2 Unlikely       | from the network: port 22 reachable from the controller                                        | X11Forwarding no, MaxAuthTries 3-4, LogLevel INFO or VERBOSE.                                                                                                  |
| R19 | 4 (2x2)  | LOW      | Automatic security updates not enabled                                                                                                  | 2 Limited     | 2 Unlikely       | with an account on the machine                                                                 | sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades.                                                                       |
| R20 | 2 (2x1)  | LOW      | Account files modified in the last 7 days                                                                                               | 2 Limited     | 1 Rare           | only by someone who is already an administrator                                                | Verify that the recent account changes were made by authorised people.                                                                                         |

The evidence for each problem is in the appendix (every finding points to its R..).

## Method

**Risk = Impact x Likelihood**, each from 1 to 5 (risk from 1 to 25).

| Impact        | Meaning                                                                           |
|---------------|-----------------------------------------------------------------------------------|
| 5 Total       | full control of the machine (root) or of all its data                             |
| 4 Severe      | root reachable by a local user, credential theft, control of an important service |
| 3 Significant | access to data or to a non-critical service, tampering with application data      |
| 2 Limited     | information useful for an attack, or a weakened defence                           |
| 1 Minimal     | best practice not followed, no direct damage                                      |

| Likelihood       | Meaning                                                                                                                      |
|------------------|------------------------------------------------------------------------------------------------------------------------------|
| 5 Almost certain | exploitable by anyone who reaches the machine over the network, without credentials, with common tools; or already happening |
| 4 Likely         | exploitable from the network with little effort (guessable password, known technique)                                        |
| 3 Possible       | requires any account on the machine                                                                                          |
| 2 Unlikely       | requires special conditions: traffic interception, physical access, a second flaw                                            |
| 1 Rare           | requires being an administrator already, or is theoretical                                                                   |

Levels: **CRITICAL** 15-25, **HIGH** 10-14, **MEDIUM** 5-9, **LOW** 1-4.

- Impact depends on the type of weakness (rules in `zerostressriskassess/risk.py`).
- Likelihood starts from how the weakness is exploited (network, local account, interception, physical access) and is adjusted with what the tool measured: a network weakness on a port that nmap could NOT reach from the controller drops by 2; a CVE in the CISA KEV catalogue (actively exploited) rises to 5.
- Findings describing the same weakness (e.g. anonymous FTP seen by nmap, by the configuration and by directory permissions) form a single problem, with the others as evidence.
- "(estimate)": no specific rule, impact and likelihood derive from the finding severity.

## Checks performed

A *skipped* or *error* check verified NOTHING: the reason is in the Notes column.

| Check       | Status  | Duration (s) | Findings | Notes                                                                      |
|-------------|---------|-------------:|---------:|----------------------------------------------------------------------------|
| nmap        | ok      |            0 |        3 |                                                                            |
| ssh_audit   | ok      |            0 |        2 |                                                                            |
| accounts    | ok      |            0 |        4 |                                                                            |
| sudoers     | ok      |            0 |        3 |                                                                            |
| sshd        | ok      |            0 |        5 |                                                                            |
| permissions | ok      |            0 |        6 |                                                                            |
| persistence | ok      |            0 |        1 |                                                                            |
| integrity   | ok      |            3 |        0 |                                                                            |
| services    | ok      |            0 |        0 |                                                                            |
| listeners   | ok      |            0 |        1 |                                                                            |
| firewall    | ok      |            0 |        1 |                                                                            |
| hardening   | ok      |            0 |        1 |                                                                            |
| containers  | skipped |            0 |        1 | Docker not present                                                         |
| dns         | skipped |            0 |        1 | No DNS server listening on port 53                                         |
| mysql       | skipped |            0 |        1 | No MySQL/MariaDB server running                                            |
| ftp         | ok      |            0 |        4 |                                                                            |
| updates     | ok      |            4 |        3 |                                                                            |
| cve         | skipped |            0 |        1 | grype not installed on the controller (see README, Requirements section)   |
| platform    | ok      |            0 |        1 |                                                                            |
| lynis       | ok      |           38 |       19 |                                                                            |
| clamav      | error   |           40 |        2 | ClamAV signatures not updated: the target cannot reach database.clamav.net |

Tools installed and removed on the target:

- `clamav`: to be installed
- `clamav`: installation rc=0
- `clamav,clamav-base,clamav-freshclam,cron,cron-daemon-common,libargon2-1,libbrotli1,libclamav12,libcryptsetup12,libcurl4t64,libdevmapper1.02.1,libfdisk1,libicu74,libjson-c5,libkmod2,libldap2,libmspack0t64,libnghttp2-14,libpopt0,libpsl5t64,librtmp1,libsasl2-2,libsasl2-modules-db,libssh-4,libsystemd-shared,libxml2,logrotate,systemd,systemd-dev`: removal rc=0

## Appendix: findings of each check

The evidence cited in the table. Finding severity: critical, high, medium, low, info.

### nmap

- `F001` [medium] Open port 21/tcp: ftp vsftpd 3.0.5 -> R10 - `FTP: clear-text credentials`
- `F002` [medium] Anonymous FTP allowed (21/tcp) -> R02 - `Anyone can read the published files without a password. Verify that this is intended and that no confidential data is exposed (in vsftpd: anonymous_enable=NO). The file list cannot be read from here (PASV failed: 550 Permission denied.), so it is NOT possible to tell whether writable directories [...]`
- `F003` [info] Open port 22/tcp: ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.19

### ssh_audit

- `F004` [info] ssh-audit: 17 DEFAULT algorithms flagged as improvable - `curve25519-sha256, curve25519-sha256@libssh.org, diffie-hellman-group-exchange-sha256, diffie-hellman-group14-sha256, diffie-hellman-group16-sha512, diffie-hellman-group18-sha512, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521, ecdsa-sha2-nistp256, hmac-sha1, hmac-sha1-etm@openssh.com [...]`
- `F005` [info] SSH server: SSH-2.0-OpenSSH\_9.6p1 Ubuntu-3ubuntu13.19

### accounts

- `F008` [critical] Account 'guest' with an empty password in /etc/shadow -> R01 - `Login without a password.`
- `F006` [medium] UID 1002 shared by several accounts -> R14 - `dev, dev2`
- `F009` [low] Account files modified in the last 7 days -> R20 - `/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow`
- `F007` [info] Users with interactive login: ubuntu, guest, dev, dev2

### sudoers

- `F010` [high] Defaults !authenticate: sudo never asks for a password -> R03 - `/etc/sudoers.d/90-lab: Defaults:dev !authenticate`
- `F011` [medium] 'dev' can run any command as root -> R13 - `/etc/sudoers.d/90-lab: dev = (ALL:ALL) ALL`
- `F012` [info] Members of group sudo: none

### sshd

- `F013` [critical] SSH accepts empty passwords (PermitEmptyPasswords yes) -> R01 - `Anyone with a passwordless account can log in without a password.`
- `F014` [high] SSH allows direct root login with a password (PermitRootLogin yes) -> R04 - `Recommended: 'prohibit-password' or 'no'.`
- `F015` [medium] SSH accepts password authentication (PasswordAuthentication yes) -> R11 - `Public keys only are recommended, especially when SSH is reachable from the Internet.`
- `F016` [low] SSH: X11Forwarding enabled -> R17 - `Useful only when remote graphical applications are needed.`
- `F017` [low] SSH: MaxAuthTries 10 (above the default of 6) -> R18

### permissions

- `F018` [critical] SSH private key readable by others: /home/dev/.ssh/id\_ed25519 -> R05 - `mode=644`
- `F019` [high] Home directory of 'dev2' writable by everyone -> R06 - `/home/dev2`
- `F020` [high] World-writable directory without sticky bit -> R07 - `/opt/app`
- `F021` [high] World-writable directory without sticky bit -> R02 - `/srv/ftp/upload`
- `F022` [high] World-writable directory without sticky bit -> R02 - `/srv/ftp/pub`
- `F023` [high] Credentials file writable by everyone -> R08 - `/opt/app/db.env`

### persistence

- `F024` [info] authorized SSH keys for 'dev' (1) - `/home/dev/.ssh/authorized_keys: 256 SHA256:nGVconH+2YBbDc+AKjTxeqfjPthRANUVIxwyqeDFi6M zerostressriskassess-lab (ED25519)`

### listeners

- `F025` [info] Listening on the network: 21/tcp vsftpd, 22/tcp sshd

### firewall

- `F026` [high] No active firewall and services reachable besides SSH: 21/tcp -> R12 - `No rules in ufw/firewalld/nftables/iptables.`

### hardening

- `F027` [info] Target is a container: kernel parameters, auditing and clock belong to the host - `The values read are the host's: they must be checked there.`

### containers

- `F028` [info] Docker not present

### dns

- `F029` [info] No DNS server listening on port 53

### mysql

- `F030` [info] No MySQL/MariaDB server running

### ftp

- `F031` [high] FTP: the anonymous user can WRITE to the server -> R02 - `anon_upload_enable=YES, anon_mkdir_write_enable=YES with write_enable=YES; writable directories under /srv/ftp: /srv/ftp/upload, /srv/ftp/pub. Anyone can upload files without a password: a drop point for malware or illegal material in the name of the server owner.`
- `F032` [medium] FTP: system users with clear-text passwords (local\_enable=YES, ssl\_enable=NO) -> R10 - `The passwords travelling unencrypted are those of the system accounts: whoever intercepts the traffic can then log in over SSH too. Enable ssl_enable or use SFTP.`
- `F033` [low] FTP: local users not confined to their home directory (chroot\_local\_user=NO) -> R15 - `Over FTP they can browse the whole readable filesystem.`
- `F034` [info] vsftpd: configuration read from /etc/vsftpd.conf

### updates

- `F035` [high] 32 security updates not installed (including critical components: libc-bin, libc6, openssh-client, openssh-server, openssh-sftp-server) -> R09 - `coreutils, diffutils, dpkg, gcc-14-base, gpgv, gzip, libattr1, libbz2-1.0, libc-bin, libc6, libgcc-s1, libgcrypt20, libgnutls30t64, liblzma5, libncursesw6, libp11-kit0, libpam-modules, libpam-modules-bin, libpam-runtime, libpam0g`
- `F037` [low] Automatic security updates not enabled -> R19 - `Recommended: unattended-upgrades (apt) or dnf-automatic (dnf).`
- `F036` [info] Upgradable packages: 56, of which security: 32

### cve

- `F038` [info] grype not installed on the controller (see README, Requirements section)

### platform

- `F039` [info] Target is a container: disk encryption and Secure Boot concern the host

### lynis

- `F044` [low] Configure password hashing rounds in /etc/login.defs -> R16 - `AUTH-9230`
- `F045` [low] Install a PAM module for password strength testing like pam\_cracklib or pam\_passwdqc or libpam-passwdqc -> R16 - `AUTH-9262`
- `F046` [low] When possible set expire dates for all password protected accounts -> R16 - `AUTH-9282`
- `F047` [low] Look at the locked accounts and consider removing them -> R16 - `AUTH-9284`
- `F048` [low] Configure minimum password age in /etc/login.defs (+1 similar) -> R16 - `AUTH-9286: Configure minimum password age in /etc/login.defs; Configure maximum password age in /etc/login.defs`
- `F049` [low] Check DNS configuration for the dns domain name -> R16 - `NAME-4028`
- `F050` [low] Install debsums utility for the verification of packages with known good database. -> R16 - `PKGS-7370`
- `F051` [low] Install package apt-show-versions for patch management purposes -> R16 - `PKGS-7394`
- `F052` [low] Add a legal banner to /etc/issue, to warn unauthorized users -> R16 - `BANN-7126`
- `F053` [low] Add legal banner to /etc/issue.net, to warn unauthorized users -> R16 - `BANN-7130`
- `F054` [low] Install a file integrity tool to monitor changes to critical and sensitive files -> R16 - `FINT-4350`
- `F055` [low] Determine if automation tools are present for system management -> R16 - `TOOL-5002`
- `F056` [low] Consider restricting file permissions \[See screen output or log file\] -> R16 - `FILE-7524`
- `F040` [info] Multiple accounts found with same UID (already covered by the 'accounts' check) - `AUTH-9208`
- `F041` [info] Found accounts without password (already covered by the 'accounts' check) - `AUTH-9283`
- `F042` [info] Found one or more vulnerable packages. (already covered by the 'updates' check) - `PKGS-7392`
- `F043` [info] Lynis hardening index: 60/100 - `Share of Lynis tests passed: a configuration indicator, not a risk measure.`
- `F057` [info] 19 Lynis tests not applicable in a container (they concern the host) - `Kernel, boot, syslog, partitions, drivers: in a container they belong to the host. BOOT-5180, BOOT-5264, KRNL-5788, KRNL-5820, FILE-6310, USB-1000, STRG-1846, NETW-3200, LOGG-2130, LOGG-2138, ACCT-9622, ACCT-9626, ACCT-9628, KRNL-6000`
- `F058` [info] 6 Lynis suggestions not repeated: already covered by our own checks - `AUTH-9328 (hardening), PKGS-7392 (updates), PKGS-7420 (updates), SSH-7408 (sshd), HOME-9304 (permissions), HOME-9306 (permissions)`

### clamav

- `F059` [info] ClamAV signatures not updated: the target cannot reach database.clamav.net - `solve host name ERROR: Wed Oct 14 20:31:11 2026 -> check_for_new_database_version: Failed to find daily database using server https://database.clamav.net. ERROR: Wed Oct 14 20:31:11 2026 -> Update failed for database: daily ERROR: Database update process failed: HTTP GET failed ERROR: Update failed.`
- `F060` [info] ClamAV NOT run: no antivirus signatures available on the target - `The antivirus check was not performed (the report does not state 'no malware'). The target must reach database.clamav.net, or an internal mirror configured in freshclam.conf.`

---
The results are automatically collected indicators, not verdicts: every problem must be verified before acting on it.