#!/usr/bin/env python3

# Copyright (c) 2025 Mahama Bazarov
# Licensed under the MIT License
# This project is not affiliated with or endorsed by Juniper Networks, Inc.

import argparse, sys, re, os, colorama
from colorama import Fore, Style
from netmiko import ConnectHandler
from getpass import getpass
from modules.system import cve, systeminfo, users, aaa, loginsecurity, management, remoteaccess # import noir modules for audit

colorama.init(autoreset=True)

def banner():
    # print tool banner and meta info
    banner = r"""
        _   __      _     
       / | / /___  (_)____
      /  |/ / __ \/ / ___/
     / /|  / /_/ / / /    
    /_/ |_/\____/_/_/                                    
"""
    print("    " + banner)
    print("    " + "Noir: " + Style.RESET_ALL + "JunOS Security Inspector")
    print("    " + "Developer: " + Style.RESET_ALL + "Mahama Bazarov (Caster)")
    print("    " + "Contact: " + Style.RESET_ALL + "mahamabazarov@mailbox.org")
    print("    " + "Version: " + Style.RESET_ALL + "1.0.0")
    print("    " + "Documentation & Usage: " + Style.RESET_ALL + "https://github.com/caster0x00/Noir")
    print()

def connect_ssh(ip, user, password=None, port=22, key_file=None, key_passphrase=None):
    # establish SSH connection via netmiko (password or ssh key)
    device = {}
    device["device_type"] = "juniper_junos"
    device["ip"] = ip
    device["username"] = user
    device["port"] = port

    # use ssh key-based authentication if provided
    if key_file:
        key_path = os.path.expanduser(key_file)

        if not os.path.exists(key_path):
            print(Fore.RED + f"[!] SSH key not found: {key_path}")
            print(Fore.YELLOW + "    Hint: provide path to the private key (not .pub)")
            sys.exit(1)

        device["use_keys"] = True
        device["key_file"] = key_path

        if key_passphrase:
            device["passphrase"] = key_passphrase

    # otherwise use password authentication
    else:
        if not password:
            print(Fore.RED + "[!] No authentication method provided.")
            sys.exit(1)

        device["password"] = password
        device["use_keys"] = False

    try:
        conn = ConnectHandler(**device)
        print(Fore.GREEN + f"[+] SSH connection successful: {user}@{ip}")
        return conn
    except Exception as e:
        print(Fore.RED + f"[!] SSH connection failed: {e}")
        sys.exit(1)

def normalize_auth_and_prompt(args):
    # handle authentication input and prompt user if needed
    key_file = args.key
    key_passphrase = None

    # if private key path provided, check and ask for passphrase
    if key_file:
        key_file = os.path.expanduser(key_file)

        if not os.path.exists(key_file):
            print(Fore.RED + f"[!] SSH key file not found: {key_file}")
            sys.exit(1)

        prompt = f"[?] Passphrase for key {key_file} (leave empty if none): "
        entered = getpass(prompt)

        if entered:
            key_passphrase = entered
        else:
            key_passphrase = None

        return None, key_file, key_passphrase

    # otherwise ask for SSH password securely
    password = getpass(f"[?] SSH password for {args.user}@{args.ip}: ")
    return password, None, None

def load_text_file(path):
    # safely read text file content
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(Fore.RED + f"[!] Failed to read file: {e}")
        sys.exit(1)

def extract_junos_version(xml_text):
    # extract JunOS version string from XML
    if not xml_text:
        return ""
    match = re.search(r"<version>\s*([^<\s]+)\s*</version>", xml_text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    
    return ""

def run_system_checks(xml_text):
    # execute all audit modules
    print(Fore.YELLOW + "[*] Performing configuration security analysis\n")

    systeminfo.check(xml_text) # system information
    users.check(xml_text) # users enumeration, uid, classes, passwords, etc
    loginsecurity.check(xml_text) # login security analysis
    aaa.check(xml_text) # aaa/radius/tacacs+ audit
    management.check(xml_text) # management interfaces analysis, searching for filters
    remoteaccess.check(xml_text) # ssh/telnet/netconf/web audit, ssh hardening

    print(Fore.GREEN + "\n[OK] Configuration security analysis completed")
    version = extract_junos_version(xml_text)
    if version:
        print(f"[Tip] To check for vulnerabilities, run: noir cve version {version}")

def run_cve_version_check(version):
    # validate version string and run CVE lookup
    if not version:
        print(Fore.RED + "[!] Could not detect JunOS version.")
        sys.exit(1)
    cve.run(version)

def run_mode_hot(args):
    # connect to device and run full configuration audit
    print(Fore.YELLOW + "[*] Mode: Hot")
    print("    Target Device: " + Fore.WHITE + args.ip)
    print("    Transport: " + Fore.WHITE + "SSH")
    print()

    password, key_file, key_passphrase = normalize_auth_and_prompt(args)
    
    conn = connect_ssh(
        args.ip,
        args.user,
        password=password,
        port=args.port,
        key_file=key_file,
        key_passphrase=key_passphrase
    )

    print(Fore.YELLOW + "[*] Extracting system configuration")
    xml_conf = conn.send_command("show configuration | display xml | no-more")

    conn.disconnect()
    run_system_checks(xml_conf)

def run_mode_cold(args):
    # run audit from saved local XML file
    size_kb = os.path.getsize(args.xml) / 1024
    print(Fore.CYAN + "[*] Mode: Cold")
    print("    Input File: " + Fore.WHITE + args.xml)
    print("    File Size: " + Fore.WHITE + f"{size_kb:.1f} KB")
    print()

    xml_conf = load_text_file(args.xml)
    run_system_checks(xml_conf)

def run_cve_hot(args):
    # perform live CVE lookup via SSH
    print(f"[*] CVE Search for: {args.ip}")
    password, key_file, key_passphrase = normalize_auth_and_prompt(args)
    conn = connect_ssh(
        args.ip,
        args.user,
        password=password,
        port=args.port,
        key_file=key_file,
        key_passphrase=key_passphrase
    )
    xml_conf = conn.send_command("show configuration | display xml | no-more")
    version = extract_junos_version(xml_conf)
    if version:
        print(Fore.YELLOW + f"[!] Detected JunOS Version: {version}")
    if not version:
        xml_ver = conn.send_command("show version | display xml | no-more")
        version = extract_junos_version(xml_ver)

    conn.disconnect()
    run_cve_version_check(version)

def run_cve_cold(args):
    # run CVE check from local XML or version file
    size_kb = os.path.getsize(args.xml) / 1024
    print(f"[+] CVE Search: {args.xml} ({size_kb:.1f} KB)\n")

    text = load_text_file(args.xml)
    version = extract_junos_version(text)

    if not version:
        stripped = text.strip()
        if re.match(r"^\d{2}\.\d[^\s]+$", stripped):
            version = stripped

    run_cve_version_check(version)

def run_cve_direct(args):
    # run CVE lookup for specific version string
    print("[+] Search for CVEs for a specific version\n")
    version = args.version.strip()
    run_cve_version_check(version)

# main func, parsing arguments
def main():
    banner()

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    # configuration audit modes
    mode = sub.add_parser("mode", help="Run configuration security checks")
    mode_sub = mode.add_subparsers(dest="mode_type", required=True)
    # hot mode operation
    hot = mode_sub.add_parser("hot", help="Connect to device via SSH and analyze configuration")
    hot.add_argument("ip", help="Specify JunOS IP Address")
    hot.add_argument("user", help="SSH Username")
    hot.add_argument("key", nargs="?", default=None, help="Path to private SSH key (optional)")
    hot.add_argument("port", nargs="?", type=int, default=22, help="SSH port (default: 22)")
    hot.set_defaults(func=run_mode_hot)

    cold = mode_sub.add_parser("cold", help="Analyze local JunOS XML configuration file")
    cold.add_argument("xml", help="Path to saved JunOS configuration file in XML format")
    cold.set_defaults(func=run_mode_cold)

    # CVE
    cve_cmd = sub.add_parser("cve", help="Check JunOS version against known CVEs")
    cve_sub = cve_cmd.add_subparsers(dest="cve_type", required=True)
    # cold mode operation
    cve_hot = cve_sub.add_parser("hot", help="Perform live CVE check via SSH connection")
    cve_hot.add_argument("ip", help="Specify JunOS IP Address")
    cve_hot.add_argument("user", help="SSH Username")
    cve_hot.add_argument("key", nargs="?", default=None, help="Path to private SSH key (optional)")
    cve_hot.add_argument("port", nargs="?", type=int, default=22, help="SSH port (default: 22)")
    cve_hot.set_defaults(func=run_cve_hot)

    cve_cold = cve_sub.add_parser("cold", help="Check CVEs from local XML or version file")
    cve_cold.add_argument("xml", help="Path to local JunOS XML or plain text file containing version")
    cve_cold.set_defaults(func=run_cve_cold)

    cve_ver = cve_sub.add_parser("version", help="Check CVEs for a specific JunOS version")
    cve_ver.add_argument("version", help="JunOS version string, e.g. 24.4R1.9")
    cve_ver.set_defaults(func=run_cve_direct)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()