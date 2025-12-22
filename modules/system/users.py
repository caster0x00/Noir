# Copyright (c) 2025 Magama Bazarov
# Licensed under the MIT License
# This project is not affiliated with or endorsed by Juniper Networks, Inc.

import xml.etree.ElementTree as ET
from colorama import Fore, Style, init

init(autoreset=True)

# common default usernames. they are often used for brute force attacks
default_usernames = {"juniper", "junos", "root", "admin", "jadmin", "jumphost", "guest", "administrator", "r00t", "engineer", "noc", "chassis"}

def get_text(element):
    # safely extract text from XML element
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
    # print colored warning line
    padding = " " * (indent * 2)
    mark = Fore.RED + "[!]" if critical else Fore.YELLOW + "[!]"
    print(padding + mark + Style.RESET_ALL + " " + message)

def is_inactive_user(user_element):
    # detect if user has "inactive" attribute
    for attr in user_element.attrib.keys():
        if attr.endswith("inactive"):
            return True
    return False

def detect_hash_type(encrypted_value):
    # identify password hash algorithm
    if not encrypted_value:
        return "none", "warn"

    value = encrypted_value.strip()

    if value.startswith(("$1$", "$apr1$")):
        return "MD5 ($1) — insecure", "bad"

    if value.startswith("$5$"):
        return "SHA-256 ($5)", "ok"

    if value.startswith("$6$"):
        return "SHA-512 ($6)", "ok"

    if value.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt ($2*)", "ok"

    return "unknown", "bad"

def count_ssh_keys(user_element):
    # count SSH keys by type
    auth_block = user_element.find("authentication")

    key_types = {"ed25519": 0, "ecdsa": 0, "rsa": 0, "dsa": 0}

    if auth_block is not None:
        for tag, name in [
            ("ssh-ed25519", "ed25519"),
            ("ssh-ecdsa", "ecdsa"),
            ("ssh-rsa", "rsa"),
            ("ssh-dsa", "dsa")
        ]:
            count = len(auth_block.findall(tag))
            key_types[name] = count

    total = sum(key_types.values())

    details = []
    for k, c in key_types.items():
        if c > 0:
            details.append(k + "=" + str(c))

    if details:
        summary = "total=" + str(total) + " (" + ", ".join(details) + ")"
    else:
        summary = "total=" + str(total)

    return total, key_types, summary

def gather_login_classes(config_block):
    # collect login classes with allow/deny rules
    classes = {}
    system_login = config_block.find("system/login")

    if system_login is None:
        return classes

    for class_el in system_login.findall("class"):
        name_el = class_el.find("name")
        if name_el is None or not name_el.text:
            continue

        name = name_el.text.strip()

        allow_cmds = []
        deny_cmds = []

        for allow_el in class_el.findall("allow-commands"):
            cmd = get_text(allow_el)
            if cmd != "":
                allow_cmds.append(cmd)

        for deny_el in class_el.findall("deny-commands"):
            cmd = get_text(deny_el)
            if cmd != "":
                deny_cmds.append(cmd)

        entry = {}
        entry["has_allow"] = len(allow_cmds) > 0
        entry["has_deny"] = len(deny_cmds) > 0
        entry["allow_patterns"] = allow_cmds
        entry["deny_patterns"] = deny_cmds

        classes[name] = entry

    return classes

def check_class_restrictions(class_name, classes_map, indent=2):
    # warn if class has no command restrictions
    class_info = classes_map.get(class_name)

    if class_info is None:
        show_warning(
            "Login class '" + class_name + "' not defined or has no restrictions.",
            indent=indent
        )
        return

    if not class_info["has_allow"] and not class_info["has_deny"]:
        show_warning(
            "Login class '" + class_name + "' has no allow/deny commands (unrestricted access).",
            indent=indent
        )

def analyze_user(user_element, config_block, classes_map):
    # analyze single user entry
    name = get_text(user_element.find("name"))
    uid = get_text(user_element.find("uid"))
    user_class = get_text(user_element.find("class"))
    inactive = is_inactive_user(user_element)

    auth_el = user_element.find("authentication/encrypted-password")
    encrypted_value = get_text(auth_el)

    total_keys, key_types, key_summary = count_ssh_keys(user_element)
    hash_desc, hash_status = detect_hash_type(encrypted_value)

    print(Fore.MAGENTA + "[*] " + name + Style.RESET_ALL)

    show_value("UID", uid)
    show_value("Class", user_class)

    # password presence
    if encrypted_value == "":
        show_value("Password", "none", color=Fore.RED)
    else:
        show_value("Password", "present", color=Fore.GREEN)
        show_value("Hash", hash_desc)

    # ssh key details
    show_value("SSH Keys", key_summary)

    # inactive marker
    if inactive:
        show_warning("User account is inactive.", indent=2)

    # risk: default usernames
    if name.lower() in default_usernames:
        show_warning("Default username detected — consider renaming.", indent=2)

    # risk: no credentials at all
    if encrypted_value == "" and total_keys == 0:
        show_warning("User has no credentials (no password and no SSH keys).", critical=True, indent=2)

    # weak or unknown hash type
    if hash_status == "bad":
        show_warning("Insecure or unknown password hash algorithm.", critical=True, indent=2)

    # weak SSH key types
    if key_types.get("dsa", 0) > 0:
        show_warning("Weak SSH key type detected (DSA).", critical=True, indent=2)

    # no password (SSH-only)
    if encrypted_value == "" and total_keys > 0:
        show_warning("SSH-only access — ensure keys are from trusted sources.", indent=2)

    # check class restrictions
    if user_class != "":
        check_class_restrictions(user_class, classes_map, indent=2)

    print()

def analyze_users(xml_text):
    # main function to analyze all local users
    try:
        root = ET.fromstring(xml_text)
        config = root.find(".//configuration")

        print(Style.BRIGHT + "[*] Users Enumeration")
        print()

        if config is None:
            print("  N/A")
            print()
            return

        users = config.findall(".//system/login/user")
        if len(users) == 0:
            show_value("Users", "none", color=Style.DIM)
            print()
            return

        classes_map = gather_login_classes(config)

        for user_el in users:
            analyze_user(user_el, config, classes_map)

    except ET.ParseError as parse_error:
        print()
        print(Fore.RED + "[*] Users Enumeration" + Style.RESET_ALL)
        print("  [!] Invalid or malformed XML input")
        print("      Reason:", Fore.RED + str(parse_error) + Style.RESET_ALL)
        print()

    except Exception as error:
        print()
        print(Fore.RED + "[*] Users Enumeration" + Style.RESET_ALL)
        print("  [!] Failed to analyze user configuration")
        print("      Reason:", Fore.RED + str(error) + Style.RESET_ALL)
        print()

def check(xml_text):
    analyze_users(xml_text)
