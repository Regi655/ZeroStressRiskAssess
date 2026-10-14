# Valutazione del rischio — 172.28.10.10

|           |                                                                                                                                                 |
|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| Data      | 2026-10-14 14:52                                                                                                                                |
| Sistema   | Ubuntu 24.04.5 LTS (kernel 7.0.0-38-generic) — **container**                                                                                    |
| Modalità  | remota via SSH (dev@172.28.10.10, accesso publickey)                                                                                            |
| Fonti     | controlli nativi (account, sudo, SSH, permessi, servizi, kernel...), nmap + script NSE, ssh-audit, Grype (CVE), Lynis (portatile) 3.1.8, ClamAV |
| Strumento | ZeroStressRiskAssess 1.0.0                                                                                                                      |

## Rischio complessivo: **CRITICO**

21 problemi: 4 critico, 8 alto, 2 medio, 7 basso. Il rischio complessivo è quello del problema più grave.

## Matrice del rischio (impatto x probabilità)

Ogni casella: numero di problemi, livello di rischio, ID dei problemi (vedi tabella). "-" = nessun problema.

| Impatto \ Probabilità | 1 Rara           | 2 Improbabile                       | 3 Possibile                        | 4 Probabile     | 5 Quasi certa      |
|-----------------------|------------------|-------------------------------------|------------------------------------|-----------------|--------------------|
| **5 Totale**          | -                | **1** ALTO: R12                     | **2** CRITICO: R03, R04            | -               | **1** CRITICO: R01 |
| **4 Grave**           | -                | -                                   | **6** ALTO: R05, R06, R07, R08 ... | -               | **1** CRITICO: R02 |
| **3 Significativo**   | -                | **1** MEDIO: R13                    | -                                  | **1** ALTO: R11 | -                  |
| **2 Limitato**        | **1** BASSO: R20 | **5** BASSO: R15, R16, R17, R18 ... | **1** MEDIO: R14                   | -               | -                  |
| **1 Minimo**          | **1** BASSO: R21 | -                                   | -                                  | -               | -                  |

## Tabella dei rischi

Ordinata per rischio. *Perché* spiega la probabilità: da dove si sfrutta il difetto e cosa ha verificato il tool (es. porta raggiungibile o no dal controller).

| ID  | Rischio  | Livello | Problema                                                                         | Impatto         | Probabilità   | Perché                                            | Correzione                                                                                                                                          |
|-----|----------|---------|----------------------------------------------------------------------------------|-----------------|---------------|---------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| R01 | 25 (5x5) | CRITICO | Accesso SSH senza password (account: guest)                                      | 5 Totale        | 5 Quasi certa | dalla rete: porta 22 raggiungibile dal controller | PermitEmptyPasswords no in sshd\_config e una password (o passwd -l per bloccarlo) per ogni account senza password.                                 |
| R02 | 20 (4x5) | CRITICO | FTP anonimo con caricamento di file da parte di chiunque                         | 4 Grave         | 5 Quasi certa | dalla rete: porta 21 raggiungibile dal controller | In vsftpd: anonymous\_enable=NO. Se l'FTP anonimo serve davvero: anon\_upload\_enable=NO, anon\_mkdir\_write\_enable=NO e cartelle a 755.           |
| R03 | 15 (5x3) | CRITICO | Defaults !authenticate: sudo non chiede mai la password                          | 5 Totale        | 3 Possibile   | con un account sulla macchina                     | Togliere NOPASSWD/!authenticate e i programmi che aprono una shell; lasciare env\_reset (visudo).                                                   |
| R04 | 15 (5x3) | CRITICO | SSH consente il login diretto come root con password (PermitRootLogin yes)       | 5 Totale        | 3 Possibile   | dalla rete: porta 22 raggiungibile dal controller | PermitRootLogin prohibit-password (o no) e accesso come utente normale + sudo.                                                                      |
| R05 | 12 (4x3) | ALTO    | Chiave privata SSH leggibile da altri: /home/dev/.ssh/id\_ed25519                | 4 Grave         | 3 Possibile   | con un account sulla macchina                     | chmod 600 sulla chiave; se altri l'hanno potuta leggere, considerarla rubata e sostituirla.                                                         |
| R06 | 12 (4x3) | ALTO    | Cartella personale di 'dev2' scrivibile da chiunque                              | 4 Grave         | 3 Possibile   | con un account sulla macchina                     | chmod o-w sulla cartella (o chmod +t se deve restare condivisa, come /tmp).                                                                         |
| R07 | 12 (4x3) | ALTO    | Cartella scrivibile da chiunque senza sticky bit                                 | 4 Grave         | 3 Possibile   | con un account sulla macchina                     | chmod o-w sulla cartella (o chmod +t se deve restare condivisa, come /tmp).                                                                         |
| R08 | 12 (4x3) | ALTO    | File con credenziali scrivibile da chiunque                                      | 4 Grave         | 3 Possibile   | con un account sulla macchina                     | chmod 600 (o 640 con il gruppo del servizio) e cambiare le credenziali se esposte.                                                                  |
| R09 | 12 (4x3) | ALTO    | Servizio esposto in rete sulla porta 21 (ftp vsftpd 3.0.5)                       | 4 Grave         | 3 Possibile   | dalla rete: porta 21 raggiungibile dal controller | FTP manda le password in chiaro: sostituirlo con SFTP (già offerto da SSH) o attivare FTPS (ssl\_enable=YES in vsftpd); se non serve, disattivarlo. |
| R10 | 12 (4x3) | ALTO    | SSH accetta l'autenticazione con password (PasswordAuthentication yes)           | 4 Grave         | 3 Possibile   | dalla rete: porta 22 raggiungibile dal controller | Accesso solo con chiavi: PasswordAuthentication no (dopo aver copiato le chiavi con ssh-copy-id).                                                   |
| R11 | 12 (3x4) | ALTO    | Nessun firewall attivo e servizi raggiungibili oltre a SSH: 21/tcp               | 3 Significativo | 4 Probabile   | dalla rete: porta 21 raggiungibile dal controller | Attivare un firewall (ufw default deny incoming; ufw allow ssh) e aprire solo le porte necessarie.                                                  |
| R12 | 10 (5x2) | ALTO    | 'dev' può eseguire qualsiasi comando come root                                   | 5 Totale        | 2 Improbabile | con un account sulla macchina                     | Normale per un amministratore: verificare che l'utente debba esserlo e che usi una password robusta.                                                |
| R13 | 6 (3x2)  | MEDIO   | UID 1002 condiviso da più account                                                | 3 Significativo | 2 Improbabile | con un account sulla macchina                     | Un UID per persona; shell /usr/sbin/nologin per gli account di servizio (usermod -s).                                                               |
| R14 | 6 (2x3)  | MEDIO   | FTP: utenti locali non confinati nella propria cartella (chroot\_local\_user=NO) | 2 Limitato      | 3 Possibile   | con un account sulla macchina                     | chroot\_local\_user=YES in vsftpd.conf.                                                                                                             |
| R15 | 4 (2x2)  | BASSO   | Consigli di hardening di Lynis (13)                                              | 2 Limitato      | 2 Improbabile | con un account sulla macchina                     | Miglioramenti di configurazione, non problemi urgenti: l'elenco con gli ID di Lynis è nella sezione lynis.                                          |
| R16 | 4 (2x2)  | BASSO   | SSH: X11Forwarding attivo                                                        | 2 Limitato      | 2 Improbabile | dalla rete: porta 22 raggiungibile dal controller | X11Forwarding no, MaxAuthTries 3-4, LogLevel INFO o VERBOSE.                                                                                        |
| R17 | 4 (2x2)  | BASSO   | SSH: MaxAuthTries 10 (oltre il valore predefinito 6)                             | 2 Limitato      | 2 Improbabile | dalla rete: porta 22 raggiungibile dal controller | X11Forwarding no, MaxAuthTries 3-4, LogLevel INFO o VERBOSE.                                                                                        |
| R18 | 4 (2x2)  | BASSO   | 2 aggiornamenti non di sicurezza da installare                                   | 2 Limitato      | 2 Improbabile | con un account sulla macchina                     | sudo apt update && sudo apt upgrade (non urgenti: correggono difetti, non vulnerabilità).                                                           |
| R19 | 4 (2x2)  | BASSO   | Aggiornamenti automatici di sicurezza non attivi                                 | 2 Limitato      | 2 Improbabile | con un account sulla macchina                     | sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades.                                                            |
| R20 | 2 (2x1)  | BASSO   | File di account modificati negli ultimi 7 giorni                                 | 2 Limitato      | 1 Rara        | solo da chi è già amministratore                  | Verificare che le modifiche recenti agli account siano state fatte da chi è autorizzato.                                                            |
| R21 | 1 (1x1)  | BASSO   | File di test antivirus EICAR (innocuo)                                           | 1 Minimo        | 1 Rara        | solo da chi è già amministratore                  | Nessuna azione: è il file di prova degli antivirus. Rimuoverlo se non serve più.                                                                    |

Le prove di ogni problema sono nell'appendice (ogni segnalazione indica il suo R..).

## Metodo

**Rischio = Impatto x Probabilità**, ciascuno da 1 a 5 (rischio da 1 a 25).

| Impatto         | Significato                                                                                                 |
|-----------------|-------------------------------------------------------------------------------------------------------------|
| 5 Totale        | controllo completo della macchina (root) o di tutti i suoi dati                                             |
| 4 Grave         | accesso come root possibile per un utente locale, furto di credenziali, controllo di un servizio importante |
| 3 Significativo | accesso a dati o a un servizio non critico, alterazione di dati di un'applicazione                          |
| 2 Limitato      | informazioni utili a un attacco o una difesa indebolita                                                     |
| 1 Minimo        | buona pratica non seguita, nessun danno diretto                                                             |

| Probabilità   | Significato                                                                                                         |
|---------------|---------------------------------------------------------------------------------------------------------------------|
| 5 Quasi certa | sfruttabile da chiunque raggiunga la macchina in rete, senza credenziali, con strumenti comuni; oppure già in corso |
| 4 Probabile   | sfruttabile dalla rete con poco sforzo (password da indovinare, tecnica nota)                                       |
| 3 Possibile   | serve un account qualsiasi sulla macchina                                                                           |
| 2 Improbabile | servono condizioni particolari: intercettare il traffico, accesso fisico, un secondo difetto                        |
| 1 Rara        | serve essere già amministratori, oppure è teorica                                                                   |

Livelli: **CRITICO** 15-25, **ALTO** 10-14, **MEDIO** 5-9, **BASSO** 1-4.

- L'impatto dipende dal tipo di difetto (regole in `zerostressriskassess/risk.py`).
- La probabilità parte da come si sfrutta il difetto (rete, account locale, intercettazione, accesso fisico) ed è corretta con ciò che il tool ha misurato: un difetto di rete su una porta che nmap NON ha raggiunto dal controller scende di 2; una CVE nel catalogo CISA KEV (sfruttata attivamente) sale a 5.
- Le segnalazioni che descrivono lo stesso difetto (es. FTP anonimo visto da nmap, dalla configurazione e dai permessi delle cartelle) sono un solo problema, con le altre come prove.
- "(stima)": nessuna regola specifica, impatto e probabilità derivano dalla gravità della segnalazione.

## Controlli eseguiti

Un controllo *skipped* o *error* NON ha verificato nulla: il motivo è nella colonna Note.

| Controllo   | Stato   | Durata (s) | Segnalazioni | Note                                        |
|-------------|---------|-----------:|-------------:|---------------------------------------------|
| nmap        | ok      |          1 |            3 |                                             |
| ssh_audit   | ok      |          0 |            2 |                                             |
| accounts    | ok      |          0 |            4 |                                             |
| sudoers     | ok      |          0 |            3 |                                             |
| sshd        | ok      |          0 |            5 |                                             |
| permissions | ok      |          1 |            6 |                                             |
| persistence | ok      |          1 |            1 |                                             |
| integrity   | ok      |          4 |            0 |                                             |
| services    | ok      |          0 |            0 |                                             |
| listeners   | ok      |          0 |            1 |                                             |
| firewall    | ok      |          0 |            1 |                                             |
| hardening   | ok      |          0 |            1 |                                             |
| containers  | skipped |          0 |            1 | Docker non presente                         |
| dns         | skipped |          0 |            1 | Nessun server DNS in ascolto sulla porta 53 |
| mysql       | skipped |          0 |            1 | Nessun server MySQL/MariaDB in esecuzione   |
| ftp         | ok      |          0 |            4 |                                             |
| updates     | ok      |         14 |            2 |                                             |
| cve         | ok      |         11 |            1 |                                             |
| platform    | ok      |          0 |            1 |                                             |
| lynis       | ok      |         60 |           18 |                                             |
| clamav      | ok      |         83 |            3 |                                             |

Strumenti installati e rimossi sul target:

- `clamav`: da installare
- `clamav`: installazione rc=0
- `clamav,clamav-base,clamav-freshclam,cron,cron-daemon-common,libargon2-1,libclamav12,libcryptsetup12,libdevmapper1.02.1,libfdisk1,libicu74,libjson-c5,libkmod2,libmspack0t64,libpopt0,libsystemd-shared,libxml2,logrotate,systemd,systemd-dev`: rimozione rc=0

## Appendice: segnalazioni dei singoli controlli

Le prove citate nella tabella. Gravità della segnalazione: critical, high, medium, low, info.

### nmap

- `F001` [medium] Porta aperta 21/tcp: ftp vsftpd 3.0.5 -> R09 - `FTP: credenziali in chiaro`
- `F002` [medium] FTP anonimo consentito (21/tcp) -> R02 - `Chiunque legge i file pubblicati senza password. Verificare che sia voluto e che non ci siano dati riservati (in vsftpd: anonymous_enable=NO). Da qui l'elenco dei file non si legge (PASV failed: 550 Permission denied.), quindi NON si può dire se ci sono cartelle scrivibili: lo verifica lo scanner [...]`
- `F003` [info] Porta aperta 22/tcp: ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.19

### ssh_audit

- `F004` [info] ssh-audit: 12 algoritmi DI SERIE segnalati come migliorabili - `diffie-hellman-group14-sha256, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521, ecdsa-sha2-nistp256, hmac-sha1, hmac-sha1-etm@openssh.com, hmac-sha2-256, hmac-sha2-512, umac-128@openssh.com, umac-64-etm@openssh.com, umac-64@openssh.com. Hardening oltre i valori predefiniti (es. guide di [...]`
- `F005` [info] Server SSH: SSH-2.0-OpenSSH\_9.6p1 Ubuntu-3ubuntu13.19

### accounts

- `F008` [critical] Account 'guest' con password vuota in /etc/shadow -> R01 - `Accesso senza password.`
- `F006` [medium] UID 1002 condiviso da più account -> R13 - `dev, dev2`
- `F009` [low] File di account modificati negli ultimi 7 giorni -> R20 - `/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow`
- `F007` [info] Utenti con login interattivo: ubuntu, guest, dev, dev2

### sudoers

- `F010` [high] Defaults !authenticate: sudo non chiede mai la password -> R03 - `/etc/sudoers.d/90-lab: Defaults:dev !authenticate`
- `F011` [medium] 'dev' può eseguire qualsiasi comando come root -> R12 - `/etc/sudoers.d/90-lab: dev = (ALL:ALL) ALL`
- `F012` [info] Membri del gruppo sudo: ubuntu

### sshd

- `F013` [critical] SSH accetta password vuote (PermitEmptyPasswords yes) -> R01 - `Chi ha un account senza password entra senza password.`
- `F014` [high] SSH consente il login diretto come root con password (PermitRootLogin yes) -> R04 - `Consigliato 'prohibit-password' o 'no'.`
- `F015` [medium] SSH accetta l'autenticazione con password (PasswordAuthentication yes) -> R10 - `Consigliate le sole chiavi pubbliche, soprattutto con SSH raggiungibile da Internet.`
- `F016` [low] SSH: X11Forwarding attivo -> R16 - `Utile solo se servono applicazioni grafiche remote.`
- `F017` [low] SSH: MaxAuthTries 10 (oltre il valore predefinito 6) -> R17

### permissions

- `F018` [critical] Chiave privata SSH leggibile da altri: /home/dev/.ssh/id\_ed25519 -> R05 - `mode=644`
- `F019` [high] Cartella personale di 'dev2' scrivibile da chiunque -> R06 - `/home/dev2`
- `F020` [high] Cartella scrivibile da chiunque senza sticky bit -> R07 - `/opt/app`
- `F021` [high] Cartella scrivibile da chiunque senza sticky bit -> R02 - `/srv/ftp/pub`
- `F022` [high] Cartella scrivibile da chiunque senza sticky bit -> R02 - `/srv/ftp/upload`
- `F023` [high] File con credenziali scrivibile da chiunque -> R08 - `/opt/app/db.env`

### persistence

- `F024` [info] chiavi SSH autorizzate per 'dev' (1) - `/home/dev/.ssh/authorized_keys: 256 SHA256:M457lZLZjdkdudKY6f8YbHnELNMcdYyNnR5Ub7r/Z5k zerostressriskassess-lab (ED25519)`

### listeners

- `F025` [info] In ascolto sulla rete: 21/tcp vsftpd, 22/tcp sshd

### firewall

- `F026` [high] Nessun firewall attivo e servizi raggiungibili oltre a SSH: 21/tcp -> R11 - `Nessuna regola in ufw/firewalld/nftables/iptables.`

### hardening

- `F027` [info] Target in un container: parametri del kernel, audit e orologio sono della macchina ospite - `I valori letti sono quelli dell'host: vanno controllati lì.`

### containers

- `F028` [info] Docker non presente

### dns

- `F029` [info] Nessun server DNS in ascolto sulla porta 53

### mysql

- `F030` [info] Nessun server MySQL/MariaDB in esecuzione

### ftp

- `F031` [high] FTP: l'utente anonimo può SCRIVERE sul server -> R02 - `anon_upload_enable=YES, anon_mkdir_write_enable=YES con write_enable=YES; cartelle scrivibili sotto /srv/ftp: /srv/ftp/pub, /srv/ftp/upload. Chiunque, senza password, carica file: deposito di malware o di materiale illecito a nome del proprietario del server.`
- `F032` [medium] FTP: utenti del sistema con password in chiaro (local\_enable=YES, ssl\_enable=NO) -> R09 - `Le password che viaggiano senza cifratura sono quelle degli account del sistema: chi intercetta il traffico può poi entrare anche via SSH. Attivare ssl_enable o usare SFTP.`
- `F033` [low] FTP: utenti locali non confinati nella propria cartella (chroot\_local\_user=NO) -> R14 - `Via FTP possono navigare tutto il file system leggibile.`
- `F034` [info] vsftpd: configurazione letta da /etc/vsftpd.conf

### updates

- `F035` [low] 2 aggiornamenti non di sicurezza da installare -> R18 - `libaudit-common, libaudit1`
- `F036` [low] Aggiornamenti automatici di sicurezza non attivi -> R19 - `Consigliato unattended-upgrades (apt) o dnf-automatic (dnf).`

### cve

- `F037` [info] 218 CVE senza correzione dalla distribuzione - `Nessun aggiornamento le risolve oggi: spesso la distribuzione le ha valutate di impatto minimo o le corregge più avanti. Per gravità: medium 201, low 17`

### platform

- `F038` [info] Target in un container: cifratura del disco e Secure Boot riguardano l'host

### lynis

- `F042` [low] Configure password hashing rounds in /etc/login.defs -> R15 - `AUTH-9230`
- `F043` [low] Install a PAM module for password strength testing like pam\_cracklib or pam\_passwdqc or libpam-passwdqc -> R15 - `AUTH-9262`
- `F044` [low] When possible set expire dates for all password protected accounts -> R15 - `AUTH-9282`
- `F045` [low] Look at the locked accounts and consider removing them -> R15 - `AUTH-9284`
- `F046` [low] Configure minimum password age in /etc/login.defs (+1 simili) -> R15 - `AUTH-9286: Configure minimum password age in /etc/login.defs; Configure maximum password age in /etc/login.defs`
- `F047` [low] Check DNS configuration for the dns domain name -> R15 - `NAME-4028`
- `F048` [low] Install debsums utility for the verification of packages with known good database. -> R15 - `PKGS-7370`
- `F049` [low] Install package apt-show-versions for patch management purposes -> R15 - `PKGS-7394`
- `F050` [low] Add a legal banner to /etc/issue, to warn unauthorized users -> R15 - `BANN-7126`
- `F051` [low] Add legal banner to /etc/issue.net, to warn unauthorized users -> R15 - `BANN-7130`
- `F052` [low] Install a file integrity tool to monitor changes to critical and sensitive files -> R15 - `FINT-4350`
- `F053` [low] Determine if automation tools are present for system management -> R15 - `TOOL-5002`
- `F054` [low] Consider restricting file permissions \[See screen output or log file\] -> R15 - `FILE-7524`
- `F039` [info] Multiple accounts found with same UID (già coperto dallo scanner 'accounts') - `AUTH-9208`
- `F040` [info] Found accounts without password (già coperto dallo scanner 'accounts') - `AUTH-9283`
- `F041` [info] Hardening index di Lynis: 59/100 - `Quota di controlli di Lynis superati: un indicatore di configurazione, non una misura del rischio.`
- `F055` [info] 19 controlli di Lynis non applicabili in un container (riguardano l'host) - `Kernel, avvio, syslog, partizioni, driver: in un container sono quelli della macchina ospite. BOOT-5180, BOOT-5264, KRNL-5788, KRNL-5820, FILE-6310, USB-1000, STRG-1846, NETW-3200, LOGG-2130, LOGG-2138, ACCT-9622, ACCT-9626, ACCT-9628, KRNL-6000`
- `F056` [info] 6 suggerimenti di Lynis non ripetuti: già coperti dai nostri scanner - `AUTH-9328 (hardening), PKGS-7420 (updates), FIRE-4590 (firewall), SSH-7408 (sshd), HOME-9304 (permissions), HOME-9306 (permissions)`

### clamav

- `F057` [low] File di test antivirus EICAR (innocuo) -> R21 - `/home/dev/eicar_test.txt: è il file standard per verificare che un antivirus funzioni, non un malware. Se nessuno l'ha messo lì apposta, qualcuno sta provando l'antivirus o il caricamento di file.`
- `F058` [low] File di test antivirus EICAR (innocuo) -> R21 - `/srv/ftp/upload/eicar_test.txt: è il file standard per verificare che un antivirus funzioni, non un malware. Se nessuno l'ha messo lì apposta, qualcuno sta provando l'antivirus o il caricamento di file.`
- `F059` [info] ClamAV in modalità standard: analizzate solo le cartelle a rischio - `/tmp /var/tmp /dev/shm /home /root /etc /usr/local /opt /var/www /srv /usr/bin /usr/sbin /bin /sbin. Per tutto il disco: --clamav-full.`

---
I risultati sono indizi raccolti automaticamente, non verdetti: ogni problema va verificato prima di intervenire.