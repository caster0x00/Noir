# Copyright (c) 2025 Magama Bazarov
# Licensed under the MIT License
# This project is not affiliated with or endorsed by Juniper Networks, Inc.

import xml.etree.ElementTree as ET
from colorama import Fore, Style, init

init(autoreset=True)

def get_text(element):
    # safely extract text from XML
    if element is None:
        return ""
    if element.text is not None:
        value = element.text.strip()
        if value != "":
            return value
    return ""

def show_value(key, value, indent=2, color=None):
    # print aligned key:value pair
    padding = " " * (indent * 2)
    key_colored = Fore.CYAN + key + Style.RESET_ALL

    if value is None or str(value).strip() == "":
        text_value = "N/A"
        effective_color = Style.DIM
    else:
        text_value = str(value).strip()
        effective_color = color if color else Style.RESET_ALL

    print(padding + key_colored + ": " + effective_color + text_value + Style.RESET_ALL)

def show_warning(message, critical=False, indent=2):
    # print warning with colored [!]
    padding = " " * (indent * 2)
    mark = Fore.RED + "[!]" if critical else Fore.YELLOW + "[!]"
    print(padding + mark + Style.RESET_ALL + " " + message)

def analyze_system_info(xml_text):
    # analyze system information and metadata
    try:
        root = ET.fromstring(xml_text)
        config = root.find(".//configuration")

        print(Style.BRIGHT + "[*] System Information")
        print()

        if config is None:
            print("  N/A")
            print()
            return

        # gather system fields
        version = get_text(config.find("version"))
        hostname = get_text(config.find("system/host-name"))

        if version == "":
            version = "N/A"

        if hostname == "":
            hostname = "N/A"

        # commit attributes
        commit_user = "N/A"
        commit_time = "N/A"

        for name, value in config.attrib.items():
            if name.endswith("commit-user"):
                commit_user = value
            if name.endswith("commit-localtime"):
                commit_time = value

        # root password detection
        root_auth = config.find("system/root-authentication/encrypted-password")
        root_password_set = False

        if root_auth is not None:
            text_value = get_text(root_auth)
            if text_value != "":
                root_password_set = True

        # show basic info
        show_value("Device Hostname", hostname)
        show_value("Installed JunOS Version", version)
        show_value("Last Commit by", commit_user)
        show_value("Last Commit Time", commit_time)

        if root_password_set:
            show_value("Root Password", "configured", color=Fore.GREEN)
        else:
            show_value("Root Password", "not set", color=Fore.RED)
            show_warning("Root password not configured — device may be accessible with default credentials.", critical=True)

        print()

    except ET.ParseError as parse_error:
        print()
        print(Fore.RED + "[*] System Information" + Style.RESET_ALL)
        print("  [!] Invalid or malformed XML input")
        print("      Reason:", Fore.RED + str(parse_error) + Style.RESET_ALL)
        print()

    except Exception as error:
        print()
        print(Fore.RED + "[*] System Information" + Style.RESET_ALL)
        print("  [!] Failed to analyze configuration")
        print("      Reason:", Fore.RED + str(error) + Style.RESET_ALL)
        print()

def check(xml_text):
    analyze_system_info(xml_text)