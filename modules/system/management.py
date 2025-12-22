# Copyright (c) 2025 Magama Bazarov
# Licensed under the MIT License
# This project is not affiliated with or endorsed by Juniper Networks, Inc.

import xml.etree.ElementTree as ET
from colorama import Fore, Style, init

init(autoreset=True)

# common mgmt interface names
mgmt_interfaces_names = {"fxp0", "me0", "em0", "em1", "vme", "ge-0/0/0"} # ge-0/0/0 for SRX

def get_text(element):
    # safely extract text from XML element
    if element is None:
        return ""

    if element.text is not None:
        text_value = element.text.strip()
        if text_value != "":
            return text_value

    return ""

def get_texts(elements):
    # extract list of non-empty text values
    values = []
    for el in elements:
        val = get_text(el)
        if val != "":
            values.append(val)
    return values

def show_value(key, value, indent=2, color=None):
    # print aligned key:value pair with color
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


def parse_firewall_filters(config_block):
    # build dictionary of filters and their terms
    filters = {}

    inet_family = config_block.find("firewall/family/inet")
    if inet_family is None:
        return filters

    for filter_el in inet_family.findall("filter"):
        filter_name = get_text(filter_el.find("name"))
        if filter_name == "":
            continue

        terms = []
        for term_el in filter_el.findall("term"):
            from_block = term_el.find("from")
            if from_block is None:
                continue

            ports = []
            ports += get_texts(from_block.findall("port"))
            ports += get_texts(from_block.findall("destination-port"))
            ports = [p.lower() for p in ports]

            sources = get_texts(from_block.findall("source-address/name"))

            entry = {}
            entry["ports"] = ports
            entry["sources"] = sources
            terms.append(entry)

        filters[filter_name] = terms

    return filters

def evaluate_filter(filter_name, filters):
    # evaluate which mgmt ports and sources are allowed
    result = {}
    result["sources"] = set()
    result["ssh"] = False
    result["https"] = False
    result["http"] = False
    result["telnet"] = False
    result["netconf"] = False

    if not filter_name:
        return result

    terms = filters.get(filter_name)
    if terms is None:
        return result

    mgmt_ports = {"ssh", "22", "https", "443", "http", "80", "telnet", "23", "netconf", "830"}

    for term in terms:
        ports = term["ports"]
        sources = term["sources"]

        match_found = False
        for port in ports:
            if port in mgmt_ports:
                match_found = True
                break

        if match_found:
            for src in sources:
                result["sources"].add(src)

        for port in ports:
            if port in {"ssh", "22"}: # ssh
                result["ssh"] = True
            if port in {"https", "443"}: # j-web (https)
                result["https"] = True
            if port in {"http", "80"}: # j-web (http)
                result["http"] = True
            if port in {"telnet", "23"}: # telnet (insecure)
                result["telnet"] = True
            if port in {"netconf", "830"}: # netconf over ssh
                result["netconf"] = True

    return result

def analyze_management_interface(interface_el, filters):
    # analyze single management interface (fxp0, me0, etc.)
    interface_name = get_text(interface_el.find("name"))

    print(Fore.MAGENTA + "[*] " + interface_name + Style.RESET_ALL)

    unit_el = interface_el.find("unit")
    if unit_el is None:
        show_value("Address Family", "missing", color=Fore.RED)
        show_warning("No unit configuration found — interface may be inactive.")
        print()
        return

    inet_el = unit_el.find("family/inet")
    if inet_el is None:
        show_value("Address Family", "no IPv4 configuration", color=Style.DIM)
        print()
        return

    filter_el = inet_el.find("filter/input/filter-name")
    filter_name = get_text(filter_el)
    if filter_name == "":
        show_value("Input Filter", "none", color=Fore.RED)
        show_warning("No firewall filter applied — interface exposed to unrestricted access.", critical=True)
        print()
        return

    show_value("Input Filter", filter_name, color=Fore.GREEN)

    result = evaluate_filter(filter_name, filters)
    sources = result["sources"]

    if len(sources) > 0:
        sources_text = ", ".join(sorted(sources))
        show_value("Allowed Sources", sources_text, color=Fore.GREEN)
    else:
        show_value("Allowed Sources", "none (unrestricted)", color=Fore.RED)
        show_warning("No source-address restriction for management access.", critical=True)

    # service visibility
    if result["ssh"]:
        show_value("SSH", "allowed", color=Fore.GREEN)
    if result["https"]:
        show_value("HTTPS", "allowed", color=Fore.GREEN)
    if result["http"]:
        show_value("HTTP", "allowed", color=Fore.RED)
        show_warning("HTTP access is unencrypted — avoid enabling it.", critical=True)
    if result["telnet"]:
        show_value("Telnet", "allowed", color=Fore.RED)
        show_warning("Telnet is insecure — should be disabled.", critical=True)
    if result["netconf"]:
        show_value("NETCONF", "allowed", color=Fore.YELLOW)
        show_warning("NETCONF access permitted — ensure limited to automation or trusted hosts.")

    print()

def analyze_control_plane(config_block, filters):
    # analyze protection of lo0 (control plane)
    interfaces = config_block.findall("interfaces/interface")

    print(Fore.MAGENTA + "[*] Control Plane (lo0)" + Style.RESET_ALL)

    found_lo0 = False

    for iface in interfaces:
        name = get_text(iface.find("name"))
        if name != "lo0":
            continue

        found_lo0 = True
        unit_el = iface.find("unit")
        inet_el = None

        if unit_el is not None:
            inet_el = unit_el.find("family/inet")

        if inet_el is None:
            show_value("Input Filter", "none", color=Fore.RED)
            show_warning("lo0 has no IPv4 family — control plane unprotected.", critical=True)
            print()
            return

        filter_el = inet_el.find("filter/input/filter-name")
        filter_name = get_text(filter_el)

        if filter_name == "":
            show_value("Input Filter", "none", color=Fore.RED)
            show_value("Allowed Sources", "none (unrestricted)", color=Fore.RED)
            show_warning("No input ACL applied to lo0 — control plane traffic unrestricted.", critical=True)
            show_warning("Apply input ACL to restrict SSH/HTTPS to trusted sources.")
            print()
            return

        show_value("Input Filter", filter_name, color=Fore.GREEN)

        result = evaluate_filter(filter_name, filters)
        sources = result["sources"]

        if len(sources) > 0:
            sources_text = ", ".join(sorted(sources))
            show_value("Allowed Sources", sources_text, color=Fore.GREEN)
        else:
            show_value("Allowed Sources", "none (unrestricted)", color=Fore.RED)
            show_warning("No source restriction for control plane traffic.", critical=True)

        # permitted management protocols
        if result["ssh"]:
            show_value("SSH", "allowed", color=Fore.GREEN)
        if result["https"]:
            show_value("HTTPS", "allowed", color=Fore.GREEN)
        if result["http"]:
            show_value("HTTP", "allowed", color=Fore.RED)
            show_warning("HTTP permitted on control plane — disable plain text management.", critical=True)
        if result["telnet"]:
            show_value("Telnet", "allowed", color=Fore.RED)
            show_warning("Telnet permitted on control plane — insecure protocol.", critical=True)
        if result["netconf"]:
            show_value("NETCONF", "allowed", color=Fore.YELLOW)
            show_warning("NETCONF permitted — limit access to automation systems.")

        print()

    if not found_lo0:
        show_value("Interface", "lo0", color=Fore.CYAN)
        show_value("Input Filter", "none", color=Fore.RED)
        show_value("Allowed Sources", "none (unrestricted)", color=Fore.RED)
        show_warning("Control plane (lo0) not found or unprotected.", critical=True)
        print()

def analyze_management_security(xml_text):
    try:
        root = ET.fromstring(xml_text)
        config = root.find(".//configuration")

        print(Style.BRIGHT + "[*] Management Interfaces Security")
        print()

        if config is None:
            print("  N/A")
            print()
            return

        filters = parse_firewall_filters(config)

        interfaces = config.findall("interfaces/interface")

        # analyze each management interface separately
        for iface in interfaces:
            name = get_text(iface.find("name"))
            if name in mgmt_interfaces_names:
                analyze_management_interface(iface, filters)

        # analyze lo0 (control plane)
        analyze_control_plane(config, filters)

    except ET.ParseError as parse_error:
        print()
        print(Fore.RED + "[*] Management Interfaces Security" + Style.RESET_ALL)
        print("  [!] Invalid or malformed XML input")
        print("      Reason:", Fore.RED + str(parse_error) + Style.RESET_ALL)
        print()

    except Exception as error:
        print()
        print(Fore.RED + "[*] Management Interfaces Security" + Style.RESET_ALL)
        print("  [!] Failed to analyze management configuration")
        print("      Reason:", Fore.RED + str(error) + Style.RESET_ALL)
        print()

def check(xml_text):
    analyze_management_security(xml_text)