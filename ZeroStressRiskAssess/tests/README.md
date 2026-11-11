# Tests

    python3 -m unittest discover -s tests -t .

No virtual machine and no connection needed: the checks run against a **fake target** (`fakes.py`:
`FakeRemote` answers commands with recorded output) or really run the shell scripts on the test machine
(`LocalRemote`, `zerostressriskassess.ssh_client.Local`). The output in `fixtures/` is mostly **real**,
recorded on labs and real machines (the origin of each file is in `fixtures/README.md`): when a check gets a
real target wrong, the output that caused the error is added together with a test that reproduces it.

| File | What it verifies |
|---|---|
| test_risk.py | impact × likelihood model (also on a real report), measured exposure, CVEs and KEV, Markdown/HTML report, command line, lab consistency, local execution |
| test_correlation.py | findings of the same defect merged into one problem (real reports), MITRE/CIS references |
| test_cve.py | version comparison identical to the real rpm/dpkg, CVEs fixable now / waiting / without a fix, SBOMs for Grype and Trivy, merge of the two, refusal of the compromised Trivy release |
| test_integration.py | the whole assessment from the connection to the report on disk (mode 600, order, table) |
| test_lynis_portable.py | REAL copy, checksum verification, run and deletion of Lynis (needs root, otherwise skipped) |
| test_hardening.py | kernel parameters, mounts, login.defs, promiscuous interfaces |
| test_dns.py, test_mysql.py | DNS roles and controller probes; MySQL/MariaDB (accounts, TLS, server greeting) |
| test_capabilities_docker_platform.py | file capabilities, Docker, disk encryption and Secure Boot |
| test_nse_sshaudit_ftp.py | nmap NSE scripts, ssh-audit, FTP |
| test_vm_cases.py, test_laptop.py, test_docker_lab.py, test_rocky_lab.py, test_rocky_0110.py | cases found on VMs, a laptop and Docker labs (false positives fixed), including chkrootkit and rkhunter output |
| test_permissions_integrity_report.py, test_sudoers.py, test_cleanup.py | permissions, integrity, sudo, progress of long commands, tool texts never masked by mistake |
| test_console.py | mascot banner and the interactive `zsra` console |
| test_web.py | web interface: command line built from the form, detached runs, secrets kept off argv and logs, access token, every page (Streamlit `AppTest`, skipped without Streamlit) |
| test_portal.py | upload to the ZeroStressRiskAssessWeb portal: a stub of its API (token, check, added/duplicate, hash), HTTPS-only rule, no redirects, TLS with a private authority (`--ca-file`), configuration file mode 600, `zsra --upload` / `--no-upload` / exit code 4 |
| test_recover.py | `--recover` removes only the tools zsra installed and their dependencies, not packages that appeared meanwhile |
| test_lint.py, test_smoke.py | pyflakes, import of every module, every check survives unexpected output |
