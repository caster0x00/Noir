# Copyright (c) 2025 Magama Bazarov
# Licensed under the MIT License
# This project is not affiliated with or endorsed by Juniper Networks, Inc.

import xml.etree.ElementTree as ET
from colorama import Fore, Style, init

init(autoreset=True)

def get_text(element):
    # safely extract text or value from XML node
    if element is None:
        return ""

    if element.text:
        text_value = element.text.strip()
        if text_value != "":
            return text_value

    if element.attrib:
        for val in element.attrib.values():
            if val.strip() != "":
                return val.strip()

    return ""

def service_enabled(system_block, path):
    # universal recursive service detector
    if system_block is None:
        return False

    found = system_block.findall(".//services/" + path)
    return len(found) > 0

def show_value(key, value, indent=2, color=None):
    # print aligned key: value with controlled color
    padding = " " * (indent * 2)
    key_colored = Fore.CYAN + key + Style.RESET_ALL

    if not value or str(value).strip() == "":
        text_value = "N/A"
        color = Style.DIM
    else:
        text_value = str(value).strip()

    if color is None:
        color = Style.RESET_ALL

    print(padding + key_colored + ": " + color + text_value + Style.RESET_ALL)

def show_warning(message, critical=False, indent=2):
    # print colored warning line
    padding = " " * (indent * 2)
    mark = Fore.RED + "[!]" if critical else Fore.YELLOW + "[!]"
    print(padding + mark + Style.RESET_ALL + " " + message)

# SSH audit
def analyze_ssh(system_block):
    print(Fore.MAGENTA + "[*] SSH Settings" + Style.RESET_ALL)
    ssh_block = system_block.find("services/ssh")

    if ssh_block is None:
        show_value("Enabled", "No", color=Fore.RED)
        print()
        return

    show_value("Enabled", "Yes", color=Fore.GREEN)

    # SFTP server
    if ssh_block.find("sftp-server"):
        show_value("SFTP Server", "enabled", color=Fore.RED)
        show_warning("SFTP server is enabled — disable if file transfers are not required.")
    else:
        show_value("SFTP Server", "disabled", color=Fore.GREEN)

    # Protocol version
    proto = get_text(ssh_block.find("protocol-version"))
    if proto:
        color = Fore.GREEN if proto.strip().lower() == "v2" else Fore.RED
        show_value("Protocol Version", proto, color=color)
    else:
        show_value("Protocol Version", "v2 (default)", color=Style.DIM)

    # Root login
    root_login = get_text(ssh_block.find("root-login"))
    if root_login:
        color = Fore.RED if "allow" in root_login.lower() else Fore.GREEN
        show_value("Root Login", root_login, color=color)
        if "allow" in root_login.lower():
            show_warning("Root login is allowed over SSH.", critical=True)
    else:
        show_value("Root Login", "deny-password (default)", color=Style.DIM)

    # Password authentication
    auth_order = get_text(system_block.find("authentication-order"))
    if not auth_order:
        auth_order = "password (default)"

    if "password" in auth_order.lower():
        show_value("Password Authentication", "enabled", color=Fore.RED)
        show_warning("Password-based authentication is enabled.", critical=True)
    else:
        show_value("Password Authentication", "disabled", color=Fore.GREEN)

    # TCP forwarding
    if ssh_block.find("allow-tcp-forwarding"):
        show_value("TCP Forwarding", "enabled", color=Fore.RED)
        show_warning("TCP forwarding is enabled — may allow lateral movement.", critical=True)
    else:
        show_value("TCP Forwarding", "disabled (default)", color=Fore.GREEN)

    # Idle timeout
    idle = get_text(ssh_block.find("client-alive-interval"))
    if idle:
        show_value("Idle Timeout", idle + " seconds")
        try:
            idle_value = int(idle)
            if idle_value > 700:
                show_warning("Long SSH idle timeout (" + str(idle_value) + " seconds) — consider reducing to 5–10 minutes.")
        except:
            pass
    else:
        show_value("Idle Timeout", "N/A", color=Style.DIM)

    # Alive count max
    alive = get_text(ssh_block.find("client-alive-count-max"))
    if alive:
        show_value("Alive Count Max", alive)
        try:
            alive_value = int(alive)
            if alive_value > 10:
                show_warning("Unusually high Alive Count Max (" + str(alive_value) + ") — may delay session timeout.")
        except:
            pass
    else:
        show_value("Alive Count Max", "N/A", color=Style.DIM)

    # Session limit
    session_limit = get_text(ssh_block.find("connection-limit"))
    if session_limit:
        show_value("Session Limit", session_limit)
        try:
            limit_value = int(session_limit)
            if limit_value > 10:
                show_warning("High SSH session limit (" + str(limit_value) + ") — consider restricting concurrent sessions.")
        except:
            pass
    else:
        show_value("Session Limit", "N/A", color=Style.DIM)

    # Rate limit
    rate_limit = get_text(ssh_block.find("rate-limit"))
    if rate_limit:
        show_value("Rate Limit", rate_limit + " connections/min")
        try:
            rate_value = int(rate_limit)
            if rate_value > 15:
                show_warning("High SSH rate limit (" + str(rate_value) + " connections/min) — may indicate misconfiguration.")
        except:
            pass
    else:
        show_value("Rate Limit", "N/A", color=Style.DIM)

    # Pre-auth packets
    preauth = get_text(ssh_block.find("max-pre-authentication-packets"))
    if preauth:
        show_value("Max Pre-Auth Packets", preauth)
        try:
            preauth_value = int(preauth)
            if preauth_value > 1000:
                show_warning("High SSH pre-auth packet limit (" + str(preauth_value) + ") — consider lowering it.")
        except:
            pass
    else:
        show_value("Max Pre-Auth Packets", "N/A", color=Style.DIM)

    # Sessions per connection
    max_sessions = get_text(ssh_block.find("max-sessions-per-connection"))
    if max_sessions:
        show_value("Max Sessions per Connection", max_sessions)
        try:
            sess_value = int(max_sessions)
            if sess_value > 30:
                show_warning("High session-per-connection limit (" + str(sess_value) + ") — restrict if unnecessary.")
        except:
            pass
    else:
        show_value("Max Sessions per Connection", "N/A", color=Style.DIM)

    # Crypto
    cipher_list = [get_text(el).lower() for el in ssh_block.findall("ciphers") if get_text(el)]
    mac_list = [get_text(el).lower() for el in ssh_block.findall("macs") if get_text(el)]
    kex_list = [get_text(el).lower() for el in ssh_block.findall("key-exchange") if get_text(el)]

    if cipher_list or mac_list or kex_list:
        parts = []
        parts.append("Ciphers: " + (", ".join(cipher_list) if cipher_list else "default"))
        parts.append("MACs: " + (", ".join(mac_list) if mac_list else "default"))
        parts.append("KEX: " + (", ".join(kex_list) if kex_list else "default"))
        summary = "; ".join(parts)
    else:
        summary = "default (vendor-default-settings)"

    show_value("Ciphers / MACs / KEX", summary)

    weak_ciphers = {"3des-cbc", "aes128-cbc", "aes256-cbc"}
    weak_macs = {"hmac-md5", "hmac-sha1"}
    weak_kex = {"dh-group1-sha1", "dh-group14-sha1", "group-exchange-sha1"}

    weak_found = []

    for c in cipher_list:
        if c in weak_ciphers:
            weak_found.append(c)

    for m in mac_list:
        if m in weak_macs:
            weak_found.append(m)

    for k in kex_list:
        if k in weak_kex:
            weak_found.append(k)

    if len(weak_found) > 0:
        joined = ", ".join(sorted(set(weak_found)))
        show_warning("Weak SSH algorithms detected: " + joined, critical=True)

    print()

# Telnet
def analyze_telnet(system_block):
    print(Fore.MAGENTA + "[*] Telnet" + Style.RESET_ALL)

    if service_enabled(system_block, "telnet"):
        show_value("Enabled", "Yes", color=Fore.RED)
        show_warning("Telnet is an unencrypted protocol and should be disabled.", critical=True)
    else:
        show_value("Enabled", "No", color=Fore.GREEN)

    print()

# HTTP/HTTPS (J-Web)
def analyze_web_management(system_block):
    print(Fore.MAGENTA + "[*] Web Management" + Style.RESET_ALL)
    web = system_block.find("services/web-management")

    if web is None:
        show_value("HTTP", "disabled", color=Fore.GREEN)
        show_value("HTTPS", "disabled", color=Fore.GREEN)
        print()
        return

    # detect http and https both inside <web-management> or <undocumented>
    http = web.find(".//http")
    https = web.find(".//https")

    if http is not None:
        show_value("HTTP", "enabled", color=Fore.RED)
        show_warning("HTTP access is enabled — avoid plain-text management connections.", critical=True)
    else:
        show_value("HTTP", "disabled", color=Fore.GREEN)

    if https is not None:
        show_value("HTTPS", "enabled", color=Fore.GREEN)
    else:
        show_value("HTTPS", "disabled", color=Fore.RED)

    print()

# Netconf
def analyze_netconf(system_block):
    print(Fore.MAGENTA + "[*] NETCONF" + Style.RESET_ALL)

    if service_enabled(system_block, "netconf/ssh"):
        show_value("Enabled over SSH", "Yes", color=Fore.RED)
        show_warning("NETCONF over SSH is active — ensure it's restricted to trusted hosts.")
    else:
        show_value("Enabled over SSH", "No", color=Fore.GREEN)

def analyze_remote_access(xml_text):
    try:
        xml_root = ET.fromstring(xml_text)
        config_block = xml_root.find(".//configuration")
        system_block = config_block.find("system")

        print(Style.BRIGHT + "[*] Remote Access Configuration")
        print ()
        analyze_ssh(system_block)
        analyze_telnet(system_block)
        analyze_web_management(system_block)
        analyze_netconf(system_block)

    except ET.ParseError as parse_error:
        print()
        print(Fore.RED + "[*] Remote Access Configuration" + Style.RESET_ALL)
        print("  [!] Invalid or malformed XML input")
        print("      Reason:", Fore.RED + str(parse_error) + Style.RESET_ALL)
        print()

    except Exception as error:
        print()
        print(Fore.RED + "[*] Remote Access Configuration" + Style.RESET_ALL)
        print("  [!] Failed to analyze remote access settings")
        print("      Reason:", Fore.RED + str(error) + Style.RESET_ALL)
        print()

def check(xml_text):
    analyze_remote_access(xml_text)