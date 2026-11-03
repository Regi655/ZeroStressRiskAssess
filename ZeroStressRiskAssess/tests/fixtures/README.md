# Test fixtures

Command output used by the tests. Each file states where it comes from:

- **real**: copied from runs on lab virtual machines, Docker labs, the development sandbox or a laptop;
- **synthetic**: written by hand in the real format, for a case the machines did not show.

When a check gets a real target wrong, the right fix is to add here the real output that caused the
problem, plus a test that reproduces it.

| File | Origin | Command |
|---|---|---|
| ss_weak.txt | real (weak VM) | `ss -tulpn` |
| ss_clean.txt | real (clean VM) | `ss -tulpn` |
| apt_dist_upgrade_vm.txt | real (new-package lines) + synthetic (upgrade lines) | `apt-get -s dist-upgrade` |
| apt_upgrade_vm.txt | synthetic, with the real list of held-back packages | `apt-get -s upgrade` |
| passwd_weak.txt / shadow_weak.txt | synthetic, rebuilt from the weak-target preparation script (fake hashes) | `/etc/passwd`, awk on `/etc/shadow` |
| sshd_T_weak.txt | synthetic (OpenSSH 8.9 defaults + the lab drop-in) | `sshd -T` |
| iptables_empty.txt | synthetic (default policies) | `iptables -S` |
| lynis_report.dat | synthetic, with real IDs and texts from Lynis reports | `/var/log/lynis-report.dat` |
| chkrootkit_laptop.txt | real (Ubuntu 26.04 laptop, chkrootkit 0.58b: WARNING: prefix, "[From Debian package: …]", false INFECTED on coreutils; Wi-Fi interface name generalised to wlan0) | `chkrootkit -q` |
| chkrootkit_weak.txt / chkrootkit_clean.txt | real (weak and clean Ubuntu 22.04 VMs, chkrootkit 0.55; the weak VM's preparation script path renamed) | `chkrootkit -q` |
| chkrootkit_sandbox_tmp.txt | real: chkrootkit 0.58b in the development sandbox, working paths replaced with /tmp/work | `chkrootkit -q` |
| chkrootkit_container_overlay.txt | real: chkrootkit 0.58b in the Docker lab (overlayfs): chkdirs "Possible LKM Trojan" plus its BTRFS notice | `chkrootkit -q` |
| rkhunter_laptop.txt | real (Ubuntu 26.04 laptop, multi-line warnings; owner name generalised to user) | `rkhunter --check --rwo` |
| named_checkconf_ns1.txt / _ns2.txt | real (BIND 9.18.39, ISP lab configurations) | `named-checkconf -p` |
| named_checkconf_ubuntu_default.txt | real (stock configuration of the Ubuntu 24.04 bind9 package) | `named-checkconf -p` |
| ss_no_ptrace.txt / ps_no_ptrace.txt | real: `ss -Htulpn` and `ps` as root WITHOUT CAP_SYS_PTRACE (as in Docker), BIND running as user bind | `capsh --drop=cap_sys_ptrace` |
| mariadb_{default,lab}_*.tsv | real: MariaDB 10.11.14, stock and lab configuration | queries of the mysql check |
| mysql8_{default,lab}_*.tsv | real: MySQL 8.0.46, same | queries of the mysql check |
| mysql_greeting_*.bin | real: first packet sent by the two servers | TCP socket on 3306 |
| mysql_greeting_mysql8_notls.bin | real: MySQL 8.0 greeting with an empty `tls_version` | TCP socket on 3306 |
| ss_e_no_ptrace.txt / ps_uid_named.txt | real: `ss -tulpne` without CAP_SYS_PTRACE (uid: visible), `ps` with uid | capsh |
| ns1_061_report.json | real: report of ns1 from the ISP lab, version 0.6.1 | zerostressriskassess |
| getcap_sandbox.txt | real: capabilities set in the sandbox (python3 cap_setuid, tar cap_dac_read_search...) | `getcap` |
| getcap_laptop.txt | rebuilt from the real laptop report (real paths and capabilities) | `getcap` |
| docker_inspect_sandbox.txt / ufw_status_active.txt | real: 7 Docker 29 containers and an active UFW | `docker inspect --format`, `ufw status` |
| platform_vm_sandbox.txt | real: the sandbox VM (BIOS, unencrypted disk) | platform.py script |
| hardening_sandbox_vm.txt | real: the hardening check script in the sandbox VM (no systemd) | hardening.py script |
| dns_wire.json | real: bytes of the BIND 9.18.39 and Unbound 1.19.2 answers (recursion, version.bind, AXFR) | recorded with dnsprobe |
| nmap_nse_weak.xml / nmap_nse_ok.xml | real: nmap 7.94 with NSE scripts against vsftpd, nginx, Redis, memcached, misconfigured and then fixed | `nmap -sV --script ... -oX` |
| nmap_nse_tls.xml | real: ssl-enum-ciphers/ssl-dh-params on nginx with TLS 1.0 and 1024-bit DH, smb2-security-mode on Samba | same |
| nmap_ftp_no_pasv.xml | real: ftp-anon against vsftpd with the Rocky lab configuration (pasv_enable=NO: "PASV failed") | `nmap --script ftp-anon -oX` |
| sshaudit_default.json / sshaudit_weak.json | real: ssh-audit 3.9.0 on Ubuntu's OpenSSH 9.6, stock and with weak algorithms added | `ssh-audit -j --skip-rate-test` |
| vsftpd_rocky_lab.conf | real: vsftpd.conf of the Rocky lab | lab preparation script |
| vsftpd_ubuntu_default.conf | real: file of the Ubuntu 24.04 vsftpd package | `apt-get download vsftpd` |
| rocky_092_report.json | real: report of the Rocky lab, version 0.9.2 | zerostressriskassess |
| rocky_0110_report.json | real: report of the Rocky lab, version 0.11.0 (portable Lynis, quick ClamAV) | zerostressriskassess |
| lynis_318_laptop_report.dat | real: Lynis 3.1.8 (official repository) run in portable mode in the sandbox | `lynis audit system --report-file` |
| vercmp_real.json | real: 590 version comparisons performed by rpm 4.18.2 and dpkg 1.22.6 | `rpm.ver`, `dpkg --compare-versions` |
| inventory_ubuntu_sandbox.txt | real: INVENTORY script on the sandbox Ubuntu 24.04 (reduced) | zerostressriskassess/cve.py |
| rocky_dnf_check_update.txt | real: updates available on the Rocky lab | `dnf -q check-update` |
| rocky_grype_only_fixed.txt | real: the 48 CVEs with a fix seen only by Grype (comparison with Trivy) | `tools/compare_cve.py --details` |

Notes on the data:

- Personal data in the laptop fixtures (user name, site and application names) has been replaced with generic
  names (`user`, `site.example`, `.app-electron`): the output format is the real one.
- Machine identifiers are replaced too: Lynis `hostid`/`hostid2` with zeros of the same length, MAC addresses of
  the sandbox VM with locally administered ones (`02:00:00:00:00:01`, `02:00:00:00:00:02`).
- The tool was originally written with an Italian interface. In the recorded reports (`*_report.json`) the
  finding titles and texts produced by the tool have been translated to the current English wording, so that
  they match the rules of the current version; values, IDs, paths and the raw output of external programs are
  unchanged. Likewise, the Docker container names and the synthetic account names were translated.
