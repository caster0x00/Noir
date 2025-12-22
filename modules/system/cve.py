# Copyright (c) 2025 Magama Bazarov
# Licensed under the MIT License
# This project is not affiliated with or endorsed by Juniper Networks, Inc.

import re, time, requests
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any, Set

from colorama import Fore, Style, init

init(autoreset=True)

def paint(role: str, text: str) -> str:
    # simple role-based color mapping for terminal output
    # roles: crit/fail/warn/ok/info/label/value
    role_value = role or ""
    role_value = role_value.lower()

    if role_value == "crit":
        return Fore.RED + text + Style.RESET_ALL

    if role_value == "fail":
        return Fore.RED + text + Style.RESET_ALL

    if role_value == "warn":
        return Fore.YELLOW + text + Style.RESET_ALL

    if role_value == "ok":
        return Fore.GREEN + text + Style.RESET_ALL

    if role_value == "info":
        return Fore.CYAN + text + Style.RESET_ALL

    if role_value == "label":
        return Fore.CYAN + text + Style.RESET_ALL

    if role_value == "value":
        return Style.BRIGHT + text + Style.RESET_ALL

    return text

# regex to strip ANSI sequences from visible length calculations
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# NVD v2.0 URL
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# large page to reduce pagination (2000)
RESULTS_PER_PAGE = 2000

# spacing between columns in console table
GUTTER = 2

# token type for parsed version suffixes (e.g., ('R', 3), ('S', 1))
Token = Tuple[str, int]

@dataclass(frozen=True)
class JunosVersion:
    # model of a Junos version: YY.M suffix tokens and optional build
    # examples:
    #   21.2R3-S1.4         → year=21, minor=2, tokens=[('R',3),('S',1)], build=4
    #   21.2                → year=21, minor=2, tokens=[],               build=None
    year: int
    minor: int
    tokens: List[Token]
    build: Optional[int] = None

    @staticmethod
    def parse(version_str: str):
        # parse textual Junos version into structured parts
        if not version_str:
            return None

        s = version_str.strip()

        # basic form: "YY.M..." where M is a single digit
        m = re.match(r"^(\d{2})\.(\d)(.*)$", s)

        if not m:
            # allow "YY.M" without further suffixes
            m2 = re.match(r"^(\d{2})\.(\d)$", s)
            if m2:
                return JunosVersion(int(m2.group(1)), int(m2.group(2)), [], None)
            return None

        year = int(m.group(1))
        minor = int(m.group(2))
        rest = m.group(3)

        # optional build at the very end: ".<digits>"
        build = None
        mb = re.search(r"\.(\d+)$", rest)
        if mb:
            build = int(mb.group(1))
            rest = rest[:mb.start()]

        # normalize underscore to hyphen (e.g., X12_D34 → X12-D34)
        rest = rest.replace("_", "-")

        # extract letter-number tokens: R3, S1, X12, D34 ...
        tokens: List[Token] = []
        for mt in re.finditer(r"([A-Za-z])\s*(\d+)", rest):
            letter = mt.group(1).upper()
            number = int(mt.group(2))
            tokens.append((letter, number))

        return JunosVersion(year, minor, tokens, build)

    def classify_track(self):
        # classify track family
        # "bare"    - no tokens
        # "xtrain"  - X-train based builds (tokens begin with 'X')
        # "modern"  - releases with tokens but not X-train
        if not self.tokens:
            return "bare"

        first = self.tokens[0][0]

        if first == "X":
            return "xtrain"

        return "modern"

def compare_junos(a: JunosVersion, b: JunosVersion):
    # compare two JunosVersion instances
    # returns:
    #   -1 if a < b
    #    0 if a == b
    #    1 if a > b
    #    None when comparison is undefined across tracks
    #
    # order by:
    # 1) year (major)
    # 2) minor
    # 3) track kind (bare / modern / xtrain); xtrain vs others → undefined (None)
    # 4) if both R* (release): R number, then optional S number, then build
    # 5) if one has R and the other does not: the R build is considered "newer"
    # 6) if neither has tokens: compare by build only (if present)
    # 7) if both xtrain: compare X, then optional D, then build
    #
    # Notes:
    # - We return None when we cannot establish a strict order (e.g., xtrain vs modern).
    # - This mirrors the original logic exactly, but with explicit steps and comments.

    # compare year (major field) first
    if a.year != b.year:
        if a.year < b.year:
            return -1
        return 1

    # then compare minor
    if a.minor != b.minor:
        if a.minor < b.minor:
            return -1
        return 1

    # determine track
    kind_a = a.classify_track()
    kind_b = b.classify_track()

    # if kinds differ and one is xtrain, comparison is undefined
    if kind_a != kind_b:
        if kind_a == "xtrain" or kind_b == "xtrain":
            return None

    tokens_a = a.tokens
    tokens_b = b.tokens

    # both are R* type releases (e.g., R3, R4-S2)
    both_release = False
    if tokens_a and tokens_b:
        if tokens_a[0][0] == "R" and tokens_b[0][0] == "R":
            both_release = True

    if both_release:
        # compare R number first (R3 vs R4)
        r_a = tokens_a[0][1]
        r_b = tokens_b[0][1]

        if r_a != r_b:
            if r_a < r_b:
                return -1
            return 1

        # compare S number if present on either side (R3-S1 vs R3-S2)
        s_a = None
        s_b = None

        for t, n in tokens_a:
            if t == "S":
                s_a = n
                break

        for t, n in tokens_b:
            if t == "S":
                s_b = n
                break

        # if any S exists, we must decide using S
        if s_a is not None or s_b is not None:
            if s_a is None:
                # a has no S but b has S → a considered "older"
                return -1

            if s_b is None:
                # b has no S but a has S → a considered "newer"
                return 1

            if s_a != s_b:
                if s_a < s_b:
                    return -1
                return 1

        # finally check build numbers if any
        if a.build is not None or b.build is not None:
            if a.build is None:
                # a has no build, b has build → a is "older"
                return -1

            if b.build is None:
                # b has no build, a has build → a is "newer"
                return 1

            if a.build < b.build:
                # explicit build comparison, lower means "older"
                return -1

            if a.build > b.build:
                return 1

        # everything equal at R/S/build granularity
        return 0

    # if a has R but b has no tokens → consider a "newer"
    if tokens_a and tokens_a[0][0] == "R" and not tokens_b:
        return 1

    # if b has R but a has no tokens → consider b "newer", so a < b
    if tokens_b and tokens_b[0][0] == "R" and not tokens_a:
        return -1

    # neither has tokens → compare by build only
    if not tokens_a and not tokens_b:
        if a.build is None and b.build is None:
            return 0

        if a.build is None:
            return -1

        if b.build is None:
            return 1

        if a.build < b.build:
            return -1

        if a.build > b.build:
            return 1

        return 0

    # xtrain vs xtrain comparison: compare X first, then D, then build
    if kind_a == "xtrain" and kind_b == "xtrain":
        x_a = None
        x_b = None

        for t, n in tokens_a:
            if t == "X":
                x_a = n
                break

        for t, n in tokens_b:
            if t == "X":
                x_b = n
                break

        # if X levels differ but one is missing, we cannot order → None
        if x_a != x_b:
            if x_a is None or x_b is None:
                return None

            if x_a < x_b:
                return -1

            return 1

        # compare D levels if present (e.g., X12-D34)
        d_a = None
        d_b = None

        for t, n in tokens_a:
            if t == "D":
                d_a = n
                break

        for t, n in tokens_b:
            if t == "D":
                d_b = n
                break

        if d_a is None and d_b is None:
            # both have no D → fall through to build
            pass
        elif d_a is None:
            # a has no D, b has D → a considered "older"
            return -1
        elif d_b is None:
            # b has no D, a has D → a considered "newer"
            return 1
        else:
            # both have D → compare numbers
            if d_a < d_b:
                return -1

            if d_a > d_b:
                return 1

        # finally compare build if any
        if a.build is not None or b.build is not None:
            if a.build is None:
                return -1

            if b.build is None:
                return 1

            if a.build < b.build:
                return -1

            if a.build > b.build:
                return 1

        # everything equal within xtrain
        return 0

    # undefined comparison for mixed non-xtrain tokens or any case not covered
    return None

def in_range(cur: JunosVersion, s_in: Optional[JunosVersion], s_ex: Optional[JunosVersion], e_in: Optional[JunosVersion], e_ex: Optional[JunosVersion]):
    # check if cur is within a version range with inclusive/exclusive endpoints
    # return False if comparison is undefined at any boundary
    if s_in is not None:
        cmp_val = compare_junos(cur, s_in)
        if cmp_val is None:
            return False
        if cmp_val < 0:
            return False

    if s_ex is not None:
        cmp_val = compare_junos(cur, s_ex)
        if cmp_val is None:
            return False
        if cmp_val <= 0:
            return False

    if e_in is not None:
        cmp_val = compare_junos(cur, e_in)
        if cmp_val is None:
            return False
        if cmp_val > 0:
            return False

    if e_ex is not None:
        cmp_val = compare_junos(cur, e_ex)
        if cmp_val is None:
            return False
        if cmp_val >= 0:
            return False

    return True

# OSC-8 hyperlink sequences need special stripping for width calculations
OSC8_BEL = re.compile(r"\x1b]8;;.*?\x07")
OSC8_ST = re.compile(r"\x1b]8;;.*?\x1b\\")

# remove OSC-8 sequences so visible length is correct
def strip_osc8(s: str):
    tmp = OSC8_BEL.sub("", s)
    tmp = OSC8_ST.sub("", tmp)
    return tmp

# compute printable width without ANSI and OSC-8
def visible_len(s: str):
    raw = strip_osc8(s)
    no_ansi = ANSI_RE.sub("", raw)
    return len(no_ansi)

# right-pad to given width, ignoring ANSI codes for length
def pad_r(s: str, width: int):
    length = visible_len(s)
    pad_len = width - length
    if pad_len < 0:
        pad_len = 0
    return s + " " * pad_len

# left-pad to given width, ignoring ANSI codes for length
def pad_l(s: str, width: int):
    length = visible_len(s)
    pad_len = width - length
    if pad_len < 0:
        pad_len = 0
    return " " * pad_len + s

# format cvss score as 0.1 or N/A
def fmt_cvss(x: Any):
    try:
        value = float(x)
        return f"{value:0.1f}"
    except Exception:
        return "N/A"
    
# return clickable hyperlink (OSC-8 sequence) for supported terminals
def term_link(text: str, url: str):
    return f"\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\"

# heuristics to parse range phrases from vuln descriptions
range_patterns = []
range_patterns.append((re.compile(r"before\s+(\d{2}\.\d[^\s,;)]*)", re.I), "end_excl"))
range_patterns.append((re.compile(r"prior to\s+(\d{2}\.\d[^\s,;)]*)", re.I), "end_excl"))
range_patterns.append((re.compile(r"through\s+(\d{2}\.\d[^\s,;)]*)", re.I), "end_incl"))
range_patterns.append((re.compile(r"(?:from|since)\s+(\d{2}\.\d[^\s,;)]*)\s+(?:to|until)\s+(\d{2}\.\d[^\s,;)]*)", re.I), "between_incl"))

# extract version range hints from free text (fallback when CPE lacks ranges)
def extract_ranges(text: str):
    s = text or ""
    out: List[dict] = []

    for rx, kind in range_patterns:
        for m in rx.finditer(s):
            if kind == "end_excl":
                out.append({"versionEndExcluding": m.group(1)})
            elif kind == "end_incl":
                out.append({"versionEndIncluding": m.group(1)})
            else:
                out.append({
                    "versionStartIncluding": m.group(1),
                    "versionEndIncluding": m.group(2)
                })

    return out

# helper to parse a single range edge if present
def parse_edge(vs: Optional[str]):
    if not vs:
        return None
    return JunosVersion.parse(vs)

def is_affected(current_version: str, vi: dict):
    # decide if given current_version falls into a version item vi
    # vi may specify exact version via criteria or a set of range fields
    cur = JunosVersion.parse(current_version)

    if not cur:
        return False

    start_incl = parse_edge(vi.get("versionStartIncluding"))
    start_excl = parse_edge(vi.get("versionStartExcluding"))
    end_incl = parse_edge(vi.get("versionEndIncluding"))
    end_excl = parse_edge(vi.get("versionEndExcluding"))

    # if no range fields are present, try to match exact version from criteria
    if not start_incl and not start_excl and not end_incl and not end_excl:
        crit = vi.get("criteria", "")
        m = re.search(r":junos(?:_evolved)?:([\w\.\-]+)", crit)

        if not m:
            return False

        exact = JunosVersion.parse(m.group(1))

        if not exact:
            return False

        cmp_val = compare_junos(cur, exact)
        return cmp_val == 0

    # otherwise use range-based check
    try:
        return in_range(cur, start_incl, start_excl, end_incl, end_excl)
    except Exception:
        # any comparison failure yields "not affected"
        return False

def nvd_get(params: Dict[str, Any], timeout: int):
    # wrapper over requests.get with mild retry on rate limiting or transient errors
    headers = {}

    attempt = 0
    backoff = 1.0

    while True:
        attempt = attempt + 1

        resp = requests.get(NVD_URL, params=params, headers=headers, timeout=timeout)

        if 200 <= resp.status_code < 300:
            return resp.json()

        # retry a few times on rate limit or common transient server errors
        if resp.status_code in (429, 502, 503, 504):
            if attempt >= 3:
                resp.raise_for_status()

            time.sleep(backoff)
            backoff = backoff * 2.0
            continue

        # for other codes fail immediately
        resp.raise_for_status()

def looks_like_junos(item: Dict[str, Any], include_evolved: bool):
    # quick filter to see if CVE targets Junos/Junos Evolved
    cve = item.get("cve", item)

    # prefer CPE-based decision when nodes exist
    configs = cve.get("configurations", [])
    for cfg in configs:
        nodes = cfg.get("nodes", [])
        for node in nodes:
            matches = node.get("cpeMatch", [])
            for match in matches:
                crit = match.get("criteria", "")
                if ":juniper:junos" in crit:
                    return True
                if include_evolved and ":juniper:junos_evolved" in crit:
                    return True

    # fallback check in English description
    desc = ""
    descriptions = cve.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value") or ""
            break

    desc = desc.lower()
    return "junos os" in desc

def affected_ranges(item: Dict[str, Any], include_evolved: bool):
    # collect range objects from CPE matches; fallback to parsing description
    out: List[dict] = []
    cve = item.get("cve", item)

    configs = cve.get("configurations", [])
    for cfg in configs:
        nodes = cfg.get("nodes", [])
        for node in nodes:
            matches = node.get("cpeMatch", [])
            for match in matches:
                crit = match.get("criteria", "")
                is_junos = ":juniper:junos" in crit
                is_evolved = ":juniper:junos_evolved" in crit

                if is_junos or (include_evolved and is_evolved):
                    entry = {}
                    entry["criteria"] = crit
                    entry["versionStartIncluding"] = match.get("versionStartIncluding")
                    entry["versionStartExcluding"] = match.get("versionStartExcluding")
                    entry["versionEndIncluding"] = match.get("versionEndIncluding")
                    entry["versionEndExcluding"] = match.get("versionEndExcluding")
                    out.append(entry)

    if out:
        return out

    # if no CPE ranges, try to infer from description text
    desc = ""
    descriptions = cve.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value") or ""
            break

    parsed = extract_ranges(desc)
    if parsed:
        return parsed

    return out

# normalize CVSS data to (severity, score) from any present metric schema
def cvss_summary(item: Dict[str, Any]):
    c = item.get("cve", item)
    metrics = c.get("metrics", {})

    # prefer v3.1
    if "cvssMetricV31" in metrics:
        d = metrics["cvssMetricV31"][0]["cvssData"]
        sev = d.get("baseSeverity", "UNKNOWN")
        score = d.get("baseScore", "N/A")
        return sev, str(score)

    # then v3.0
    if "cvssMetricV30" in metrics:
        d = metrics["cvssMetricV30"][0]["cvssData"]
        sev = d.get("baseSeverity", "UNKNOWN")
        score = d.get("baseScore", "N/A")
        return sev, str(score)

    # then v2.0 (derive severity from score)
    if "cvssMetricV2" in metrics:
        d = metrics["cvssMetricV2"][0]["cvssData"]
        try:
            score_f = float(d.get("baseScore", 0))
        except Exception:
            score_f = 0.0

        sev = "LOW"
        if score_f >= 9:
            sev = "CRITICAL"
        elif score_f >= 7:
            sev = "HIGH"
        elif score_f >= 4:
            sev = "MEDIUM"

        return sev, str(score_f)

    # unknown metric schema
    return "UNKNOWN", "N/A"

# used to sort by severity rank then by publication date
sev_rank = {}
sev_rank["CRITICAL"] = 0
sev_rank["HIGH"] = 1
sev_rank["MEDIUM"] = 2
sev_rank["LOW"] = 3
sev_rank["UNKNOWN"] = 4

def key_tuple(m: Dict[str, Any]):
    # build a stable sort key without lambda
    sev = m.get("severity", "UNKNOWN")
    rank = sev_rank.get(sev, 4)

    pub = m.get("published")
    if not pub:
        pub = ""

    return (rank, pub)

# fetch CVEs from NVD and filter those affecting the given version
# respects optional severity filter and junos_evolved toggle
def scan(version: str, severities: Optional[List[str]] = None, include_evolved: bool = False, keywords: str = "junos", max_results: int = 4000, timeout: int = 30):
    # normalize severity filter to uppercase set
    severity_filter = None
    if severities:
        severity_filter = set()
        for s in severities:
            if s is not None:
                severity_filter.add(s.upper())

    start_index = 0
    fetched_count = 0
    total_results = 0

    seen_ids: Set[str] = set()
    matches: List[Dict[str, Any]] = []

    while fetched_count < max_results:
        params = {}
        params["keywordSearch"] = keywords
        params["startIndex"] = start_index
        params["resultsPerPage"] = RESULTS_PER_PAGE

        try:
            data = nvd_get(params, timeout)
        except requests.exceptions.RequestException:
            # network failure or rate-limit after retries
            break

        items = data.get("vulnerabilities", [])
        try:
            total_results = int(data.get("totalResults", 0))
        except Exception:
            total_results = 0

        if not items:
            break

        for item in items:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            if not cve_id:
                # skip malformed entries
                continue

            if cve_id in seen_ids:
                # skip duplicates across pages
                continue

            seen_ids.add(cve_id)

            # quick filter for Junos context
            if not looks_like_junos(item, include_evolved):
                continue

            # collect version ranges and check if current version is affected
            ranges = affected_ranges(item, include_evolved)

            if not ranges:
                # no ranges at all → skip
                continue

            is_match = False
            for r in ranges:
                if is_affected(version, r):
                    is_match = True
                    break

            if not is_match:
                continue

            # extract severity/score in unified form
            sev, score = cvss_summary(item)

            if severity_filter is not None:
                if sev.upper() not in severity_filter:
                    continue

            # append displayed fields only
            row = {}
            row["cve_id"] = cve_id
            row["severity"] = sev.upper()
            row["cvss_score"] = score
            row["published"] = cve.get("published")
            matches.append(row)

        fetched_count = fetched_count + len(items)
        start_index = start_index + RESULTS_PER_PAGE

        # stop when coverage satisfied
        if start_index >= total_results:
            break

        if fetched_count >= max_results:
            break

        # be polite to NVD API (something like avoiding blocking)
        time.sleep(1.0)

    # aggregate counters by severity for summary line
    counters = {}
    counters["CRITICAL"] = 0
    counters["HIGH"] = 0
    counters["MEDIUM"] = 0
    counters["LOW"] = 0
    counters["UNKNOWN"] = 0

    for m in matches:
        sev = m.get("severity", "UNKNOWN")
        if sev not in counters:
            counters[sev] = 0
        counters[sev] = counters[sev] + 1

    result = {}
    result["version"] = version
    result["matches"] = matches
    result["counters"] = counters
    result["total_seen"] = total_results

    return result

def sev_tag(sev: str):
    # convert severity string to a short colored tag
    sev_u = sev or "UNKNOWN"
    sev_u = sev_u.upper()

    if sev_u == "CRITICAL":
        return paint("crit", "CRIT")

    if sev_u == "HIGH":
        return paint("fail", "HIGH")

    if sev_u == "MEDIUM":
        return paint("warn", "MED")

    if sev_u == "LOW":
        return paint("info", "LOW")

    return paint("value", "UNK")

def count_seg(label: str, n: int):
    # format "LABEL: N" with label-specific color
    role_map = {}
    role_map["CRIT"] = "crit"
    role_map["HIGH"] = "fail"
    role_map["MED"] = "warn"
    role_map["LOW"] = "info"
    role_map["UNK"] = "value"

    role = role_map[label]
    return paint(role, label) + ": " + paint("value", str(n))

def render_summary(result: Dict[str, Any]):
    # print two-line summary for the current scan result
    version = result.get("version", "-")
    matches = result.get("matches", [])
    cnt = result.get("counters", {})

    c_crit = cnt.get("CRITICAL", 0)
    c_high = cnt.get("HIGH", 0)
    c_med = cnt.get("MEDIUM", 0)
    c_low = cnt.get("LOW", 0)
    c_unk = cnt.get("UNKNOWN", 0)

    line1 = (
        paint("label", "Target JunOS Version:") + " " + paint("value", version)
        + "    "
        + paint("label", "Matched CVEs:") + " " + paint("value", str(len(matches)))
    )

    parts = []
    parts.append(count_seg("CRIT", c_crit))
    parts.append(count_seg("HIGH", c_high))
    parts.append(count_seg("MED", c_med))
    parts.append(count_seg("LOW", c_low))
    parts.append(count_seg("UNK", c_unk))

    line2 = " | ".join(parts)

    print(line1)
    print(line2)
    print()

# render list of CVEs as a small console table with stable column widths
def render_cve(rows: List[Dict[str, Any]]):
    # compute CVE ID column width without generator
    max_id_len = 14
    for m in rows:
        cve_id = m.get("cve_id", "")
        length = len(cve_id)
        if length > max_id_len:
            max_id_len = length

    id_w = max_id_len + 2
    if id_w < 16:
        id_w = 16
    if id_w > 22:
        id_w = 22

    sev_w = 5
    cvss_w = 4
    pub_w = 10
    sep = " " * GUTTER

    head = (
        pad_r(paint("label", "CVE ID"), id_w) + sep +
        pad_r(paint("label", "SEV"), sev_w) + sep +
        pad_r(paint("label", "CVSS"), cvss_w) + sep +
        pad_r(paint("label", "PUBLISHED"), pub_w)
    )

    print(head)

    for m in rows:
        cve_id = m.get("cve_id", "")
        link = term_link(cve_id, "https://nvd.nist.gov/vuln/detail/" + cve_id)

        sev_t = sev_tag(m.get("severity", "UNKNOWN"))
        cvss = fmt_cvss(m.get("cvss_score", "N/A"))

        published = m.get("published")
        if not published:
            published = "-"
        published = published[:10]

        line = (
            pad_r(paint("info", link), id_w) + sep +
            pad_r(sev_t, sev_w) + sep +
            pad_l(paint("value", cvss), cvss_w) + sep +
            pad_r(paint("value", published), pub_w)
        )

        print(line)

# Perform CVE scan and optionally render summary/table output
def run(version: str, severities: Optional[List[str]] = None, include_evolved: bool = False, render_output: bool = True):
    result = scan(version, severities=severities, include_evolved=include_evolved)

    if render_output:
        render_summary(result)

        rows = result.get("matches", [])
        rows = sorted(rows, key=key_tuple)

        if rows:
            render_cve(rows)
        else:
            print(paint("ok", "[*] No known CVEs found for this JunOS version"))
            print()

    return result.get("matches", [])