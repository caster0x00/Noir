# Copyright (c) 2025 Magama Bazarov
# Licensed under the MIT License
# This project is not affiliated with or endorsed by Juniper Networks, Inc.

import xml.etree.ElementTree as ET
from colorama import Fore, Style, init

init(autoreset=True)

def get_text(element):
    # safely extract text content from XML node

    if element is None:
        return ""
    
    if element.text:
        text_value = element.text.strip()
        if text_value != "":
            return text_value
    return ""

def get_int(element):
    # convert XML text to integer if possible
    text_value = get_text(element)
    try:
        return int(text_value)
    except Exception:
        return None

def show_value(key, value, indent=2, color=None):
    # human-readable key: value pair with optional color
    padding = " " * (indent * 2)
    key_colored = Fore.CYAN + key + Style.RESET_ALL

    if value is None or str(value).strip() == "":
        value_text = "N/A"
        color = Style.DIM
    else:
        value_text = str(value).strip()

    if color is None:
        color = Style.RESET_ALL

    print(padding + key_colored + ": " + color + value_text + Style.RESET_ALL)

def show_warning(message, critical=False, indent=2):
    # print warning line with [!] marker
    padding = " " * (indent * 2)
    mark = Fore.RED + "[!]" if critical else Fore.YELLOW + "[!]"
    print(padding + mark + Style.RESET_ALL + " " + message)

# Login security audit
def analyze_login_security(xml_text):
    try:
        xml_root = ET.fromstring(xml_text)
        system = xml_root.find("configuration/system")

        print(Fore.WHITE + Style.BRIGHT + "[*] Login Security Assessment" + Style.RESET_ALL)
        print()

        if system is None:
            show_warning("No <system> block found in configuration.", critical=True)
            print()
            return

        # Retry Options
        print(Fore.MAGENTA + "[*] Retry Options" + Style.RESET_ALL)
        retry = system.find("login/retry-options")

        if retry is None:
            # shows N/A + 2 warnings
            show_value("Tries before disconnect", "N/A")
            show_value("Backoff threshold", "N/A")
            show_value("Backoff factor", "N/A")
            show_value("Minimum time", "N/A")
            show_value("Lockout period", "N/A")
            show_warning("Login retry options not configured.", critical=True)
            show_warning("Without retry limits, attackers can attempt passwords indefinitely (brute-force risk).")
            print()
        else:
            tries = get_int(retry.find("tries-before-disconnect"))
            backoff_threshold = get_int(retry.find("backoff-threshold"))
            backoff_factor = get_int(retry.find("backoff-factor"))
            minimum_time = get_int(retry.find("minimum-time"))
            lockout_period = get_int(retry.find("lockout-period"))

            show_value("Tries before disconnect", tries if tries is not None else "N/A")
            show_value("Backoff threshold", backoff_threshold if backoff_threshold is not None else "N/A")
            show_value("Backoff factor", backoff_factor if backoff_factor is not None else "N/A")

            if minimum_time is not None:
                show_value("Minimum time", str(minimum_time) + " sec")
                try:
                    if minimum_time < 10:
                        show_warning("Minimum time is very short — brute-force mitigation may be ineffective.")
                except Exception:
                    pass
            else:
                show_value("Minimum time", "N/A")

            if lockout_period is not None:
                show_value("Lockout period", str(lockout_period) + " sec")
                try:
                    if lockout_period < 60:
                        show_warning("Short lockout period — users may retry too quickly.")
                except Exception:
                    pass
            else:
                show_value("Lockout period", "N/A")

            print()

        # Password Policy
        print(Fore.MAGENTA + "[*] Password Policy" + Style.RESET_ALL)
        password = system.find("login/password")

        if password is None:
            show_value("Minimum length", "N/A")
            show_value("Maximum length", "N/A")
            show_value("Maximum lifetime", "N/A")
            show_value("Minimum changes", "N/A")
            show_value("Minimum reuse distance", "N/A")
            show_value("Change type", "N/A")
            show_warning("No password policy is configured.", critical=True)
            show_warning("Without enforced password rules, weak or reused credentials can be set by users.")
            show_warning("This is critical if local accounts are used for SSH or console access.")
            print()
        else:
            min_length = get_int(password.find("minimum-length"))
            max_length = get_int(password.find("maximum-length"))
            max_lifetime = get_int(password.find("maximum-lifetime"))
            min_changes = get_int(password.find("minimum-changes"))
            reuse_distance = get_int(password.find("minimum-reuse"))
            change_type = get_text(password.find("change-type"))

            # Minimum length
            if min_length is not None:
                color = Fore.GREEN if min_length >= 12 else Fore.RED
                show_value("Minimum length", min_length, color=color)
                if min_length < 8:
                    show_warning("Password minimum length below 8 — weak passwords allowed.", critical=True)
                elif min_length < 12:
                    show_warning("Minimum length below 12 — consider increasing for stronger passwords.")
            else:
                show_value("Minimum length", "N/A")
                show_warning("No minimum password length configured.", critical=True)

            show_value("Maximum length", max_length if max_length is not None else "N/A")

            if max_lifetime is not None:
                show_value("Maximum lifetime", str(max_lifetime) + " days")
                try:
                    if max_lifetime > 30:
                        show_warning("Very long maximum lifetime — consider forcing periodic rotation.", critical=True)
                except Exception:
                    pass
            else:
                show_value("Maximum lifetime", "N/A")

            # Minimum changes
            if min_changes is not None:
                show_value("Minimum changes", min_changes)
                if min_changes < 3:
                    show_warning("Minimum changes value below 3 — users can quickly reuse old passwords.", critical=True)
                elif min_changes == 3:
                    show_warning("Minimum changes set to 3 — acceptable but could be stricter.")
            else:
                show_value("Minimum changes", "N/A")
                show_warning("Minimum changes not set — users may cycle passwords easily.")

            # Minimum reuse
            if reuse_distance is not None:
                show_value("Minimum reuse distance", reuse_distance)
                if reuse_distance < 3:
                    show_warning("Minimum reuse distance below 3 — recent passwords can be reused.", critical=True)
                elif reuse_distance < 5:
                    show_warning("Minimum reuse distance below 5 — consider increasing to harden policy.")
            else:
                show_value("Minimum reuse distance", "N/A")
                show_warning("No password reuse restriction detected.", critical=True)

            # Change type
            show_value("Change type", change_type if change_type else "N/A")
            if not change_type:
                show_warning("Change type not configured — password complexity may not be enforced.", critical=True)
            else:
                ct = change_type.lower()
                if ct == "character-sets":
                    show_warning("Change type 'character-sets' — counts number of character types (recommended).")
                elif ct == "set-transitions":
                    show_warning("Change type 'set-transitions' — counts changes between character types (weaker).", critical=True)
                else:
                    show_warning("Unknown change type value — review configuration.", critical=True)
            print()

        # Login Banners
        print(Fore.MAGENTA + "[*] Login Banners" + Style.RESET_ALL)
        announcement = get_text(system.find("login/announcement"))
        motd = get_text(system.find("login/message"))

        has_announcement = bool(announcement)
        has_motd = bool(motd)

        show_value("Login announcement", "set" if has_announcement else "not set",
                   color=(Fore.GREEN if has_announcement else Fore.RED))
        show_value("Login message", "set" if has_motd else "not set",
                   color=(Fore.GREEN if has_motd else Fore.RED))

        if not has_announcement:
            show_warning("No login announcement configured — legal access disclaimer missing.")
        else:
            show_warning("Login announcement present — ensure it contains legal notice only.")

        if has_motd:
            show_warning("MOTD message set — review content for sensitive information.")

        print()

    except ET.ParseError as parse_error:
        print()
        print(Fore.RED + "[*] Login Security Assessment" + Style.RESET_ALL)
        print("  [!] Invalid or malformed XML input")
        print("      Reason:", Fore.RED + str(parse_error) + Style.RESET_ALL)
        print()

    except Exception as error:
        print()
        print(Fore.RED + "[*] Login Security Assessment" + Style.RESET_ALL)
        print("  [!] Failed to analyze login security configuration")
        print("      Reason:", Fore.RED + str(error) + Style.RESET_ALL)
        print()
        
def check(xml_text):
    analyze_login_security(xml_text)