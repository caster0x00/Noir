# Noir: JunOS Security Inspector

JunOS configuration analyzer to find security misconfigurations and vulnerabilities.

![Cover art by Magama Bazarov](graphics/caster-noir-cover.png)

**Noir** – is a Juniper configuration audit tool that inspects JunOS systems for vulnerabilities and security misconfigurations. Its main feature is that Noir only reads the configuration, performing security analysis without running exploits, brute force attacks, or other external actions.

**Noir is suitable for all JunOS-based equipment**; it is not locked to specific device models such as QFX, MX, and others.

# Disclaimer

This tool is designed specifically for security engineers and network engineers to assess the security level of their own Juniper equipment. Before using **Noir**, you must have special permissions to analyze configurations. 
You must also ensure that using this tool does not violate the local security policy of the organization where the equipment is located. 
The author of the tool is not responsible for any incorrect or illegal use of the tool.

**Noir is not a tool for conducting attacks** and does not include brute force, vulnerability exploitation, or any other penetration testing behavior.

# Features

**Noir** performs a security audit of the JunOS configuration using standalone modules:

- **System Information:** Determines the hostname, JunOS version, author, and time of the last commit, and checks for the presence of a root password;
- **Users Enumeration:** Analysis of accounts, UIDs, user classes, and the presence of passwords or SSH keys. Checks the type of hash used, identifies inactive and default accounts, absence of passwords or keys, use of weak DSA keys. Also analyzes `login-class` and displays warnings if command restrictions (`allow/deny commands`) are not set;
- **Login Security Assessment:** Analyzes JunOS login policies. Checks login attempt restriction settings (`tries`, `backoff`, `lockout`), evaluates password policy, length, expiration, reuse, and change type, and determines the presence of mandatory banners. If there are no restrictions or policies, warnings are displayed about the risk of brute-force attacks, weak passwords, and access security violations;
- **AAA:** Audit JunOS authentication and logging mechanisms. Analyze the authentication order, identifying the absence of external methods (RADIUS/TACACS+) or incorrect authentication priority. Also analyzes the accounting block, checking logging events and directions, and evaluates syslog settings to ensure that login operations and administrator commands are logged;
- **Checking Management Interfaces:** Evaluates the protection of JunOS management interfaces. Identifies ACLs and source restrictions for SSH, HTTPS, HTTP, Telnet, and NETCONF. If there is no input filter or address restrictions, it reports unrestricted access to the management plane. Also analyzes control plane filters (`lo0`), identifying insecure services and the absence of ACLs, which increases the risk of remote control without access control;
- **Remote Access Configuration:** Analyzes JunOS management protocol parameters. It checks the configuration of SSH, Telnet, Web Management, and NETCONF, evaluating their security parameters. For SSH, it analyzes SFTP support, protocol version, root login permission, password usage, timeouts, session limits, and identifies weak cryptographic algorithms in use;
- **CVE Search Module:** Performs vulnerability analysis for a specific version of JunOS using the NVD database. It normalizes and processes the JunOS version number structure, matches the current version with the ranges specified in CPE and vulnerability descriptions, and determines whether the system is vulnerable to each of them. The module also displays a color-coded summary of the number of vulnerabilities at different levels and supports filtering by severity level.

# How to Install

Starting with Python 3.11 and Debian-based systems, direct calls to `pip install` are prohibited due to the [Externally Managed Environment (PEP 668) policy.](https://peps.python.org/pep-0668/)
This is necessary to avoid package conflicts. So Noir is installed either via [pipx](https://github.com/pypa/pipx) or using `venv`

```bash
:~$ sudo apt install pipx
:~$ pipx ensurepath
:~$ git clone https://github.com/caster0x00/Noir
:~$ cd Noir
:~/Noir$ pipx install .
:~/Noir$ noir -h
```

If `pipx` is unavailable, you can install Noir manually in a virtual environment:

```bash
:~$ git clone https://github.com/caster0x00/Noir
:~$ cd Noir
:~/Noir$ python3 -m venv venv
:~/Noir$ source venv/bin/activate
(venv):~/Noir$ pip install .
(venv):~/Noir$ noir -h
```

# How to Use

## Intro

**Noir** – this is a JunOS configuration analysis tool that works as an XML parser for configuration representations.
JunOS supports several configuration display formats, but the XML variant is the most convenient for analyzing the configuration structure.

The tool has a help function, so all commands and parameters can be viewed using the `-h` flag:

```bash
:~$ noir -h
:~$ noir mode -h
:~$ noir cve -h
```

> Noir supports subcommand-specific help (e.g., `mode hot`, `cve cold`) with custom descriptions of arguments and examples.

## Hot Mode

In this mode, the tool connects to JunOS remotely using the SSH protocol, using the [netmiko](https://github.com/ktbyers/netmiko) library.
It obtains the configuration via the `show configuration | display xml | no-more` command and performs a live configuration audit.

Two authentication methods are supported:

- Password authentication;
- SSH key-based authentication.

The password and passphrase for the SSH key are requested via [getpass](https://docs.python.org/3/library/getpass.html), which ensures that they are entered securely without being displayed on the screen or stored in memory.

```bash
:~$ noir mode hot 192.168.0.105 memphis
[*] Mode: Hot
    Target Device: 192.168.0.105
    Transport: SSH

[?] SSH password for memphis@192.168.0.105: 
[+] SSH connection successful: memphis@192.168.0.105
[*] Extracting system configuration
```
> Authentication using the `memphis` account password

```bash
:~$ noir mode hot 192.168.0.105 caster ~/.ssh/jun_caster_ed25519
[*] Mode: Hot
    Target Device: 192.168.0.105
    Transport: SSH

[?] Passphrase for key /home/caster/.ssh/jun_caster_ed25519 (leave empty if none): 
[+] SSH connection successful: caster@192.168.0.105
[*] Extracting system configuration
```
> Authentication using the `caster` account SSH key

After connecting, Noir will receive the configuration, analyze it, and generate a security report.

> To use Noir, all you need is an account with RO (read-only) privileges, which prevents the tool from making any changes to the JunOS hardware configuration.

## Cold Mode

In this mode, Noir analyzes the local JunOS configuration XML file:

```bash
:~$ noir mode cold SW1.xml
[*] Mode: Cold
    Input File: SW1.xml
    File Size: 10.6 KB

[*] Performing configuration security analysis
```

Next, Noir parses the configuration, extracts the JunOS version, and performs all internal checks similar to hot mode.

> Cold mode is particularly useful for audit and compliance teams working with archived configurations or without network access to equipment.

## CVE Search

In this mode, the tool works as a vulnerability parser based on CVE, matching JunOS versions with known vulnerabilities published in NVD. This allows you to quickly identify potential vulnerabilities associated with the version of the system you are using.

3 search modes are supported:

1. CVE Hot Mode (SSH)

   The tool connects to the device, extracts the JunOS version, and checks it against the CVE database:

   ```bash
   :~$ noir cve hot 192.168.0.105 memphis
   ```

2. CVE Cold Mode (XML)

   You can specify a saved configuration or a file containing only the line with the JunOS version:

   ```bash
   :~$ noir cve cold SW1.xml
   ```

3. Checking any version

   You can check absolutely any version of JunOS you want:

   ```bash
   :~$ noir cve version 24.4R1.9
   ```

# Demonstration of JunOS Configuration Analysis

Demonstration of Juniper equipment configuration analysis. Hot mode is used.

![](graphics/caster-noir-config-demo.gif)

> ```bash
> caster@kali:~$ noir mode hot 192.168.0.105 memphis
> [*] Mode: Hot
>     Target Device: 192.168.0.105
>     Transport: SSH
> 
> [?] SSH password for memphis@192.168.0.105: 
> [+] SSH connection successful: memphis@192.168.0.105
> [*] Extracting system configuration
> [!] Performing configuration security analysis
> 
> [*] System Information
> 
>     Device Hostname: JuniperSwitch
>     Installed JunOS Version: 25.2R1.9
>     Last Commit by: root
>     Last Commit Time: 2025-10-13 13:15:24 UTC
>     Root Password: configured
> 
> [*] Users Enumeration
> 
> [*] caster
>     UID: 2001
>     Class: super-user
>     Password: none
>     SSH Keys: total=1 (ed25519=1)
>     [!] SSH-only access — ensure keys are from trusted sources.
>     [!] Login class 'super-user' not defined or has no restrictions.
> 
> [*] memphis
>     UID: 2000
>     Class: super-user
>     Password: present
>     Hash: SHA-512 ($6)
>     SSH Keys: total=0
>     [!] Login class 'super-user' not defined or has no restrictions.
> 
> [*] Login Security Assessment
> 
> [*] Retry Options
>     Tries before disconnect: 3
>     Backoff threshold: 3
>     Backoff factor: 5
>     Minimum time: 20 sec
>     Lockout period: 300 sec
> 
> [*] Password Policy
>     Minimum length: 12
>     Maximum length: 32
>     Maximum lifetime: 90 days
>     [!] Very long maximum lifetime — consider forcing periodic rotation.
>     Minimum changes: 2
>     Minimum reuse distance: 5
>     Change type: character-sets
> 
> [*] Login Banners
>     Login announcement: set
>     Login message: set
>     [!] Login announcement present — ensure it contains legal notice only.
>     [!] MOTD message set — review content for sensitive information.
> 
> [*] Authentication, Authorization & Accounting (AAA)
> 
> [*] Authentication Order
>     Order: password
>     [!] Only local authentication is configured.
>     [!] No external AAA methods are used.
> 
> [*] RADIUS Servers
>     Configured: No
> 
> [*] TACACS+ Servers
>     Configured: No
> 
> [*] Accounting
>     Configured: No
>     [!] AAA accounting is not configured.
>     [!] User logins and actions are not being logged.
> 
> [*] Syslog Auditing for AAA
>     Syslog Config: present
>     File: interactive-commands
>     File: messages
> 
> [*] Checking Management Interfaces
> 
> [*] fxp0
>     Input Filter: none
>     [!] No firewall filter applied — interface exposed to unrestricted access.
> 
> [*] Control Plane (lo0)
>     Input Filter: none
>     Allowed Sources: none (unrestricted)
>     [!] No input ACL applied to lo0 — control plane traffic unrestricted.
>     [!] Apply input ACL to restrict SSH/HTTPS to trusted sources.
> 
> [+] Checking the Remote Access Configuration
> 
> [*] SSH Settings
>     Enabled: Yes
>     SFTP Server: disabled
>     Protocol Version: v2
>     Root Login: allow
>     [!] Root login is allowed over SSH.
>     Password Authentication: enabled
>     [!] Password-based authentication is enabled.
>     TCP Forwarding: disabled (default)
>     Idle Timeout: 300 seconds
>     Alive Count Max: 3
>     Session Limit: 10
>     Rate Limit: 5 connections/min
>     Max Pre-Auth Packets: 5000
>     [!] High SSH pre-auth packet limit (5000) — consider lowering it.
>     Max Sessions per Connection: 50
>     [!] High session-per-connection limit (50) — restrict if unnecessary.
>     Ciphers / MACs / KEX: Ciphers: aes128-cbc, aes256-cbc, 3des-cbc; MACs: hmac-md5, hmac-sha1; KEX: dh-group1-sha1, dh-group14-sha1, group-exchange-sha1
>     [!] Weak SSH algorithms detected: 3des-cbc, aes128-cbc, aes256-cbc, dh-group1-sha1, dh-group14-sha1, group-exchange-sha1, hmac-md5, hmac-sha1
> 
> [*] Telnet
>     Enabled: No
> 
> [*] Web Management
>     HTTP: enabled
>     [!] HTTP access is enabled — avoid plain-text management connections.
>     HTTPS: enabled
> 
> [*] NETCONF
>     Enabled over SSH: No
> 
> [*] Configuration security analysis completed
> [*] Tip: Use "noir cve version 25.2R1.9" to check for known vulnerabilities
> ```

# CVE Vulnerability Search Demonstration

Demonstration of CVE search for JunOS version `24.4R1.9`

![](graphics/caster-noir-cve-demo.gif)

> ```bash
> caster@kali:~$ noir cve version 24.4R1.9
> 
> CRIT: 0 | HIGH: 4 | MED: 10 | LOW: 0 | UNK: 0
> 
> CVE ID            SEV    CVSS  PUBLISHED 
> CVE-2025-30661    HIGH    7.3  2025-07-11
> CVE-2025-52954    HIGH    7.8  2025-07-11
> CVE-2025-59964    HIGH    7.5  2025-10-09
> CVE-2025-60004    HIGH    7.5  2025-10-09
> CVE-2025-52949    MED     6.5  2025-07-11
> CVE-2025-52951    MED     5.8  2025-07-11
> CVE-2025-52953    MED     6.5  2025-07-11
> CVE-2025-52963    MED     5.5  2025-07-11
> CVE-2025-52985    MED     5.3  2025-07-11
> CVE-2025-52986    MED     5.5  2025-07-11
> CVE-2025-52989    MED     5.1  2025-07-11
> CVE-2025-52961    MED     6.5  2025-10-09
> CVE-2025-60006    MED     5.3  2025-10-09
> CVE-2025-60010    MED     5.4  2025-10-09
> ```

# Copyright & License

Copyright (c) 2025 Magama Bazarov.
This project is licensed under the MIT License.

This project is not affiliated with or endorsed by Juniper Networks, Inc.

All Juniper trademarks and product names are the property of their respective owners.

# WIP

- [ ] Add network protocol inspection, routing, redundancy, and others;
- [ ] Add link-layer security checks for Juniper switches

# Outro

If you have any suggestions or find any bugs, feel free to create issues in the repository or contact me:
magamabazarov@mailbox.org
