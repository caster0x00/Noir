# Copyright (c) 2025 Mahama Bazarov
# Licensed under the MIT License
# This project is not affiliated with or endorsed by Juniper Networks, Inc.

import xml.etree.ElementTree as ET
from colorama import Fore, Style, init

init(autoreset=True)

def get_text(element):
    # safely extract text or attribute value from XML node
    if element is None:
        return ""

    if element.text is not None:
        text_value = element.text.strip()
        if text_value != "":
            return text_value

    if element.attrib:
        for value in element.attrib.values():
            if value.strip() != "":
                return value.strip()

    return ""

def show_value(key, value, indent=2, color=None):
    # print aligned key: value with controlled color
    padding = " " * (indent * 2)
    key_colored = Fore.CYAN + key + Style.RESET_ALL

    if value is None:
        text_value = "N/A"
        chosen_color = Style.DIM
    else:
        text_str = str(value).strip()
        if text_str == "":
            text_value = "N/A"
            chosen_color = Style.DIM
        else:
            text_value = text_str
            if color is None:
                chosen_color = Style.RESET_ALL
            else:
                chosen_color = color

    print(padding + key_colored + ": " + chosen_color + text_value + Style.RESET_ALL)

def show_warning(message, critical=False, indent=2):
    # print colored warning line
    padding = " " * (indent * 2)
    if critical:
        mark = Fore.RED + "[!]"
    else:
        mark = Fore.YELLOW + "[!]"
    print(padding + mark + Style.RESET_ALL + " " + message)

def parse_auth_order(system_block):
    # collect authentication-order methods
    methods = []

    if system_block is None:
        return methods

    for el in system_block.findall("authentication-order"):
        value = get_text(el).lower()
        if value != "":
            methods.append(value)

    if len(methods) == 0:
        # JunOS defaults to local password if not specified
        methods.append("password (default)")

    return methods

def parse_aaa_servers(system_block, tag_name):
    # parse generic AAA servers (radius-server or tacplus-server)
    servers = []

    if system_block is None:
        return servers

    for el in system_block.findall(tag_name):
        ip_value = get_text(el.find("name"))
        secret_value = get_text(el.find("secret"))
        timeout_value = get_text(el.find("timeout"))
        retry_value = get_text(el.find("retry"))
        source_value = get_text(el.find("source-address"))
        port_value = get_text(el.find("port"))

        server = {}
        server["ip"] = ip_value
        server["secret_set"] = False
        if secret_value != "":
            server["secret_set"] = True

        server["timeout"] = timeout_value
        server["retry"] = retry_value
        server["source"] = source_value
        server["port"] = port_value

        servers.append(server)

    return servers

def parse_accounting(system_block):
    # parse <accounting> block under <system> (XML)
    result = {}
    result["enabled"] = False
    result["events"] = []
    result["destination"] = None

    if system_block is None:
        return result

    accounting = system_block.find("accounting")
    if accounting is None:
        return result

    result["enabled"] = True

    for ev in accounting.findall("events"):
        name = get_text(ev)
        if name != "":
            result["events"].append(name)

    dest_el = accounting.find("destination")
    if dest_el is not None:
        names = []
        for child in list(dest_el):
            tag_name = child.tag.split("}")[-1]
            names.append(tag_name)
        if len(names) > 0:
            result["destination"] = ", ".join(names)

    return result

def parse_syslog(system_block):
    # parse minimal syslog info needed for AAA auditing
    syslog_info = []
    if system_block is None:
        return syslog_info

    syslog_el = system_block.find("syslog")
    if syslog_el is None:
        return syslog_info

    for file_el in syslog_el.findall("file"):
        file_name = get_text(file_el.find("name"))

        contents = []
        for c in file_el.findall("contents"):
            contents_name = get_text(c.find("name"))
            if contents_name != "":
                contents.append(contents_name)

        levels = []
        for sub in file_el.findall("contents/*"):
            level_name = sub.tag.split("}")[-1]
            levels.append(level_name)

        entry = {}
        entry["file"] = file_name
        entry["contents"] = contents
        entry["levels"] = levels
        syslog_info.append(entry)

    return syslog_info

def has_local_users_with_passwords(system_block):
    # detect presence of local users with encrypted (hashed) passwords
    if system_block is None:
        return False

    users = system_block.findall("login/user")
    for user in users:
        enc = user.find("authentication/encrypted-password")
        if enc is not None:
            return True

    return False

# authentication order (password|radius|tacacs)
def analyze_auth_order(system_block):
    print ()
    print(Fore.MAGENTA + "[*] Authentication Order" + Style.RESET_ALL)

    methods = parse_auth_order(system_block)
    show_value("Order", ", ".join(methods))

    only_local = False
    if len(methods) == 1:
        if methods[0] == "password" or methods[0] == "password (default)":
            only_local = True

    if only_local:
        show_warning("Only local authentication is configured.", critical=True)
        show_warning("No external AAA methods are used.", critical=True)

    # check password vs external ordering
    has_password = False
    if "password" in methods:
        has_password = True
    if "password (default)" in methods:
        has_password = True

    has_external = False
    if "radius" in methods or "tacplus" in methods:
        has_external = True

    if has_password and has_external:
        password_index = None
        if "password" in methods:
            password_index = methods.index("password")
        if password_index is None:
            if "password (default)" in methods:
                password_index = methods.index("password (default)")

        first_external_index = None
        positions = []
        if "radius" in methods:
            positions.append(methods.index("radius"))
        if "tacplus" in methods:
            positions.append(methods.index("tacplus"))

        if len(positions) > 0:
            first_external_index = min(positions)

        if password_index is not None and first_external_index is not None:
            if password_index < first_external_index:
                show_warning("Local 'password' is placed before external AAA — may allow bypass.")

    # verify fallback when external AAA fails
    if not has_password:
        if has_local_users_with_passwords(system_block):
            show_warning("Local users exist but 'password' is missing in authentication-order — fallback will fail.", critical=True)
        else:
            show_warning("No local fallback configured — AAA outage may lock out administrators.", critical=True)

    print()
    return methods

# RADIUS servers
def analyze_radius(system_block, auth_methods):
    print(Fore.MAGENTA + "[*] RADIUS Servers" + Style.RESET_ALL)

    servers = parse_aaa_servers(system_block, "radius-server")

    if len(servers) == 0:
        show_value("Configured", "No", color=Fore.RED)
        print()
        return servers

    show_value("Configured", "Yes", color=Fore.GREEN)

    for srv in servers:
        ip_value = srv.get("ip")
        if ip_value is None or ip_value.strip() == "":
            ip_value = "N/A"

        source_value = srv.get("source")
        if source_value is None or source_value.strip() == "":
            source_display = "not set"
        else:
            source_display = source_value

        secret_flag = srv.get("secret_set")
        if secret_flag:
            secret_display = "set"
        else:
            secret_display = "not set"

        timeout_display = srv.get("timeout")
        if timeout_display is None or timeout_display.strip() == "":
            timeout_display = "default"

        retry_display = srv.get("retry")
        if retry_display is None or retry_display.strip() == "":
            retry_display = "default"

        show_value("Server", ip_value)
        show_value("Source", source_display)
        show_value("Secret", secret_display)
        show_value("Timeout", timeout_display)
        show_value("Retry", retry_display)

        if not secret_flag:
            show_warning("RADIUS server " + ip_value + " has no shared secret.", critical=True)

        print()

    # servers configured but not referenced in auth-order
    if "radius" not in auth_methods:
        show_warning("RADIUS servers are configured but 'radius' is not in authentication-order.", critical=True)

    return servers

# TACACS+ Servers
def analyze_tacacs(system_block, auth_methods):
    print(Fore.MAGENTA + "[*] TACACS+ Servers" + Style.RESET_ALL)

    servers = parse_aaa_servers(system_block, "tacplus-server")

    if len(servers) == 0:
        show_value("Configured", "No", color=Fore.RED)
        print()
        return servers

    show_value("Configured", "Yes", color=Fore.GREEN)

    for srv in servers:
        ip_value = srv.get("ip")
        if ip_value is None or ip_value.strip() == "":
            ip_value = "N/A"

        source_value = srv.get("source")
        if source_value is None or source_value.strip() == "":
            source_display = "not set"
        else:
            source_display = source_value

        secret_flag = srv.get("secret_set")
        if secret_flag:
            secret_display = "set"
        else:
            secret_display = "not set"

        port_value = srv.get("port")
        if port_value is None or port_value.strip() == "":
            port_display = "49"
        else:
            port_display = port_value

        timeout_display = srv.get("timeout")
        if timeout_display is None or timeout_display.strip() == "":
            timeout_display = "default"

        show_value("Server", ip_value)
        show_value("Source", source_display)
        show_value("Secret", secret_display)
        show_value("Port", port_display)
        show_value("Timeout", timeout_display)

        if not secret_flag:
            show_warning("TACACS+ server " + ip_value + " has no shared secret.", critical=True)

        print()

    # servers configured but not referenced in auth-order
    if "tacplus" not in auth_methods:
        show_warning("TACACS+ servers are configured but 'tacplus' is not in authentication-order.", critical=True)

    return servers

def analyze_accounting(system_block):
    print(Fore.MAGENTA + "[*] Accounting" + Style.RESET_ALL)

    # accounting
    acc = parse_accounting(system_block)

    if not acc["enabled"]:
        show_value("Configured", "No", color=Fore.RED)
        show_warning("AAA accounting is not configured.", critical=True)
        show_warning("User logins and actions are not being logged.")
        print()
        return acc

    show_value("Configured", "Yes", color=Fore.GREEN)

    if len(acc["events"]) == 0:
        show_value("Events", "none")
    else:
        show_value("Events", ", ".join(acc["events"]))

    if acc["destination"] is None or acc["destination"].strip() == "":
        show_value("Destination", "none")
    else:
        show_value("Destination", acc["destination"])

    if len(acc["events"]) == 0:
        show_warning("Accounting is enabled but no events are defined.", critical=True)

    if acc["destination"] is None or acc["destination"].strip() == "":
        show_warning("Accounting is enabled but no destination is configured.", critical=True)

    print()
    return acc

# Syslog audit
def analyze_syslog_auditing(system_block):
    print(Fore.MAGENTA + "[*] Syslog Auditing for AAA" + Style.RESET_ALL)

    files = parse_syslog(system_block)

    if len(files) == 0:
        show_value("Syslog Config", "absent", color=Fore.RED)
        show_warning("No syslog configuration detected — AAA activity may not be logged.", critical=True)
        print()
        return

    show_value("Syslog Config", "present", color=Fore.GREEN)

    has_auth_info = False
    has_interactive = False

    for f in files:
        file_name = f.get("file")
        if file_name is None:
            file_name = ""

        contents = f.get("contents")
        if contents is None:
            contents = []

        levels = f.get("levels")
        if levels is None:
            levels = []

        # show minimal per-file line for visibility
        show_value("File", file_name if file_name != "" else "N/A", color=Style.DIM)

        # detect authorization events at info level
        if "authorization" in contents and "info" in levels:
            has_auth_info = True

        # detect interactive-commands logging
        if "interactive-commands" in file_name or "interactive-commands" in contents:
            has_interactive = True

    if not has_auth_info:
        show_warning("Syslog does not record authorization at 'info' level — login events may be missing.")

    if not has_interactive:
        show_warning("Syslog does not record interactive-commands — command activity may be missing from audit logs.")

    print()

# Detect duplicate IPs across AAA definitions
def warn_on_duplicate_server_ips(radius_servers, tacacs_servers):
    ips = []

    for s in radius_servers:
        ip_value = s.get("ip")
        if ip_value is not None and ip_value.strip() != "":
            ips.append(ip_value)

    for s in tacacs_servers:
        ip_value = s.get("ip")
        if ip_value is not None and ip_value.strip() != "":
            ips.append(ip_value)

    duplicates = set()
    for ip_value in ips:
        count = ips.count(ip_value)
        if count > 1:
            duplicates.add(ip_value)

    for ip_value in sorted(duplicates):
        show_warning("Duplicate AAA server definition detected for " + ip_value + ".", critical=True)

### AAA configs audit
def analyze_aaa(xml_text):
    try:
        root = ET.fromstring(xml_text)
        config = root.find(".//configuration")
        system_block = None
        if config is not None:
            system_block = config.find("system")

        print(Fore.WHITE + Style.BRIGHT + "[*] Authentication, Authorization & Accounting (AAA)" + Style.RESET_ALL)

        auth_methods = analyze_auth_order(system_block)
        radius_servers = analyze_radius(system_block, auth_methods)
        tacacs_servers = analyze_tacacs(system_block, auth_methods)
        analyze_accounting(system_block)
        warn_on_duplicate_server_ips(radius_servers, tacacs_servers)
        analyze_syslog_auditing(system_block)

    except ET.ParseError as parse_error:
        print()
        print(Fore.RED + "[*] Authentication, Authorization & Accounting" + Style.RESET_ALL)
        print("  [!] Invalid or malformed XML input")
        print("      Reason:", Fore.RED + str(parse_error) + Style.RESET_ALL)
        print()

    except Exception as error:
        print()
        print(Fore.RED + "[*] Authentication, Authorization & Accounting" + Style.RESET_ALL)
        print("  [!] Failed to analyze AAA configuration")
        print("      Reason:", Fore.RED + str(error) + Style.RESET_ALL)
        print()

def check(xml_text):
    analyze_aaa(xml_text)