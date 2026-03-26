#!/usr/bin/env python3
"""
FortiGate ACL Parser and Pentesting Analyzer
=============================================
Parses FortiGate firewall configurations, expands all groups/objects,
and generates an HTML report with pentesting analysis.

No external dependencies.

Usage: python3 fortigate_acl_parser.py <config_file> [output.html]
"""

import sys
import os
import re
import base64
from collections import OrderedDict


# ─── Parsing ────────────────────────────────────────────────────────────────

def tokenize_value(s):
    """Parse a FortiGate config value string into individual tokens.
    Handles quoted strings, unquoted words, and escaped characters."""
    tokens = []
    i = 0
    s = s.strip()
    while i < len(s):
        if s[i] == '"':
            j = i + 1
            while j < len(s) and s[j] != '"':
                if s[j] == '\\':
                    j += 1
                j += 1
            tokens.append(s[i + 1:j])
            i = j + 1
        elif s[i].isspace():
            i += 1
        else:
            j = i
            while j < len(s) and not s[j].isspace() and s[j] != '"':
                j += 1
            tokens.append(s[i:j])
            i = j
    return tokens


def parse_config(text):
    """Parse a FortiGate configuration into sections.
    Uses a stack-based approach to handle VDOM configs (nested sections).
    Returns {section_name: OrderedDict{entry_id: {key: [values]}}}"""
    sections = {}
    stack = []  # list of [section_name, current_entry_or_None]
    current_vdom = None

    for line in text.split('\n'):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        m = re.match(r'^config\s+(.+)$', stripped)
        if m:
            section = m.group(1).strip()
            stack.append([section, None])
            if section not in sections:
                sections[section] = OrderedDict()
            continue

        if stripped == 'end':
            if stack:
                popped = stack.pop()
                if popped[0] == 'vdom':
                    current_vdom = None
            continue

        if not stack:
            continue

        m = re.match(r'^edit\s+(.+)$', stripped)
        if m:
            entry_id = m.group(1).strip().strip('"')
            section_name = stack[-1][0]
            if section_name == 'vdom':
                current_vdom = entry_id
            entry = OrderedDict()
            # In multi-VDOM configs, make policy IDs unique per VDOM
            actual_id = entry_id
            if current_vdom and section_name == 'firewall policy':
                entry['vdom'] = [current_vdom]
                actual_id = f"[{current_vdom}] {entry_id}"
            sections[section_name][actual_id] = entry
            stack[-1][1] = entry
            continue

        if stripped == 'next':
            stack[-1][1] = None
            continue

        m = re.match(r'^set\s+(\S+)\s+(.*)', stripped)
        if m and stack[-1][1] is not None:
            stack[-1][1][m.group(1)] = tokenize_value(m.group(2))
            continue

    return sections


# ─── Object Resolution ──────────────────────────────────────────────────────

def netmask_to_cidr(netmask):
    """Convert dotted netmask to CIDR prefix length."""
    try:
        binary = ''.join(f'{int(p):08b}' for p in netmask.split('.'))
        if len(binary) != 32:
            return None
        return str(binary.index('0')) if '0' in binary else '32'
    except Exception:
        return None


def format_address_obj(name, obj):
    """Format a single address object into a readable string."""
    if not obj:
        return name
    if name.lower() in ('all', 'none'):
        return name

    addr_type = obj.get('type', [''])[0] if 'type' in obj else ''

    if 'subnet' in obj:
        parts = obj['subnet']
        if len(parts) >= 2:
            cidr = netmask_to_cidr(parts[1])
            if cidr:
                return f"{parts[0]}/{cidr}"
            return f"{parts[0]} {parts[1]}"
        return ' '.join(parts)
    if addr_type == 'fqdn' or 'fqdn' in obj:
        return obj.get('fqdn', [name])[0]
    if addr_type == 'wildcard-fqdn' or 'wildcard-fqdn' in obj:
        return obj.get('wildcard-fqdn', [name])[0]
    if addr_type == 'iprange' or ('start-ip' in obj and 'end-ip' in obj):
        return f"{obj.get('start-ip', ['?'])[0]} - {obj.get('end-ip', ['?'])[0]}"
    if addr_type == 'geography' and 'country' in obj:
        return f"GEO:{obj['country'][0]}"
    return name


def expand_addresses(names, addresses, address_groups, depth=0):
    """Expand address names, resolving groups recursively.
    Returns [(original_name, [resolved_values])]"""
    if depth > 10:
        return [(n, [n]) for n in names]
    results = []
    for name in names:
        if name in address_groups:
            members = address_groups[name].get('member', [])
            expanded = []
            for member in members:
                for _, vals in expand_addresses([member], addresses, address_groups, depth + 1):
                    expanded.extend(vals)
            results.append((name, expanded if expanded else [name]))
        elif name in addresses:
            results.append((name, [format_address_obj(name, addresses[name])]))
        else:
            results.append((name, [name]))
    return results


def format_service_obj(name, obj):
    """Format a single service object into a readable string."""
    if not obj:
        return name
    if name.upper() in ('ALL', 'ALL_TCP', 'ALL_UDP', 'ALL_ICMP'):
        return name
    details = []
    if 'tcp-portrange' in obj:
        for port in obj['tcp-portrange']:
            details.append(f"TCP/{port}")
    if 'udp-portrange' in obj:
        for port in obj['udp-portrange']:
            details.append(f"UDP/{port}")
    if 'sctp-portrange' in obj:
        for port in obj['sctp-portrange']:
            details.append(f"SCTP/{port}")
    if 'protocol' in obj:
        proto = obj['protocol'][0]
        if proto == 'ICMP':
            icmp_t = obj.get('icmptype', [''])[0]
            details.append(f"ICMP/{icmp_t}" if icmp_t else "ICMP")
        elif proto == 'ICMP6':
            details.append("ICMPv6")
        elif proto == 'IP' and 'protocol-number' in obj:
            details.append(f"IP/{obj['protocol-number'][0]}")
        elif not details:
            details.append(proto)
    if details:
        return ', '.join(details)
    return name


def expand_services(names, services, service_groups, depth=0):
    """Expand service names, resolving groups recursively.
    Returns [(original_name, [resolved_values])]"""
    if depth > 10:
        return [(n, [n]) for n in names]
    results = []
    for name in names:
        if name in service_groups:
            members = service_groups[name].get('member', [])
            expanded = []
            for member in members:
                for _, vals in expand_services([member], services, service_groups, depth + 1):
                    expanded.extend(vals)
            results.append((name, expanded if expanded else [name]))
        elif name in services:
            results.append((name, [format_service_obj(name, services[name])]))
        else:
            results.append((name, [name]))
    return results


def expand_schedule(name, schedules):
    """Expand a schedule name to readable details."""
    if not name or name.lower() in ('always', 'none'):
        return name if name else ''
    if name in schedules:
        s = schedules[name]
        parts = []
        if 'day' in s:
            parts.append('Days: ' + ','.join(s['day']))
        if 'start' in s:
            parts.append(f"{s['start'][0]}")
        if 'end' in s:
            parts.append(f"-{s['end'][0]}")
        if parts:
            return f"{name} ({' '.join(parts)})"
    return name


# ─── Analysis ───────────────────────────────────────────────────────────────

MGMT_PROTOCOLS = {'SSH', 'TELNET', 'SNMP', 'RDP', 'VNC', 'SMB', 'SAMBA',
                  'HTTPS', 'HTTP'}  # HTTPS/HTTP for management interfaces
MGMT_PROTOCOLS_STRICT = {'SSH', 'TELNET', 'SNMP', 'RDP', 'VNC', 'SMB', 'SAMBA'}
INSECURE_PROTOCOLS = {'TELNET', 'FTP', 'TFTP', 'HTTP', 'SNMP'}
HIGH_RISK_SERVICES = {'ALL', 'ALL_TCP', 'ALL_UDP', 'ALL_ICMP'}


def get_all_service_names(svc_names, service_groups, depth=0):
    """Flatten service names including group members."""
    if depth > 10:
        return set(svc_names)
    result = set()
    for name in svc_names:
        if name in service_groups:
            members = service_groups[name].get('member', [])
            result.update(get_all_service_names(members, service_groups, depth + 1))
        else:
            result.add(name)
    return result


def analyze_policies(policies, addresses, address_groups, services, service_groups):
    """Analyze firewall policies for pentesting findings.
    Returns [(severity, rule_id, title, detail)]"""
    findings = []

    for rule_id, rule in policies.items():
        action = rule.get('action', ['deny'])[0].lower()
        src_addrs = rule.get('srcaddr', [])
        dst_addrs = rule.get('dstaddr', [])
        svc_names = rule.get('service', [])
        schedule = rule.get('schedule', [''])[0] if 'schedule' in rule else ''
        status = rule.get('status', ['enable'])[0].lower()
        name = rule.get('name', [''])[0] if 'name' in rule else ''
        comments = rule.get('comments', [''])[0] if 'comments' in rule else ''
        if not comments:
            comments = rule.get('comment', [''])[0] if 'comment' in rule else ''
        logtraffic = rule.get('logtraffic', [''])[0].lower() if 'logtraffic' in rule else ''
        srcintf = rule.get('srcintf', [''])[0] if 'srcintf' in rule else ''
        dstintf = rule.get('dstintf', [''])[0] if 'dstintf' in rule else ''

        src_is_all = any(a.lower() == 'all' for a in src_addrs)
        dst_is_all = any(a.lower() == 'all' for a in dst_addrs)
        svc_is_all = any(s.upper() in HIGH_RISK_SERVICES for s in svc_names)
        is_disabled = status == 'disable'

        flat_svcs = get_all_service_names(svc_names, service_groups)

        # ── STRONG ──

        if action == 'accept' and src_is_all and dst_is_all and svc_is_all:
            findings.append(('STRONG', rule_id,
                'Any-Any-Any ACCEPT rule',
                'Source=all, Destination=all, Service=ALL with action ACCEPT. '
                'This rule permits all traffic between the specified interfaces and '
                'effectively disables the firewall for this path. '
                'This should almost never exist in production.'))

        elif action == 'accept' and src_is_all and dst_is_all:
            findings.append(('STRONG', rule_id,
                'Any-to-Any ACCEPT',
                f'Source=all, Destination=all with ACCEPT (Services: {", ".join(svc_names)}). '
                'Both source and destination are completely unrestricted, violating least-privilege.'))

        if action == 'accept' and svc_is_all and not (src_is_all and dst_is_all):
            findings.append(('STRONG', rule_id,
                'ACCEPT with ALL services',
                'Service=ALL with action ACCEPT. All protocols and ports are permitted. '
                'This should be restricted to only the services actually required.'))

        if action == 'accept' and not is_disabled and logtraffic in ('', 'disable'):
            findings.append(('STRONG', rule_id,
                'No traffic logging on ACCEPT rule',
                'This ACCEPT rule has logging disabled or not configured. '
                'Without logging, malicious activity cannot be detected or investigated. '
                'All ACCEPT rules should log traffic at minimum.'))

        if is_disabled:
            findings.append(('STRONG', rule_id,
                'Disabled rule still in configuration',
                f'Rule {rule_id} is disabled but remains in the config. '
                'Disabled rules are configuration debt and risk accidental re-enablement. '
                'Remove rules that are no longer needed.'))

        # ── WEAK ──

        if action == 'accept' and not is_disabled:
            utm_profiles = ['av-profile', 'ips-sensor', 'webfilter-profile',
                            'ssl-ssh-profile', 'dnsfilter-profile', 'application-list']
            missing_utm = [p for p in utm_profiles if p not in rule]
            if len(missing_utm) == len(utm_profiles):
                findings.append(('WEAK', rule_id,
                    'No security inspection profiles configured',
                    'This ACCEPT rule has zero UTM profiles (no AV, IPS, web filter, '
                    'SSL inspection, DNS filter, or application control). Traffic is '
                    'not inspected for threats.'))
            elif len(missing_utm) >= 4:
                findings.append(('WEAK', rule_id,
                    f'Minimal security profiles (missing {len(missing_utm)} of {len(utm_profiles)})',
                    f'Missing: {", ".join(missing_utm)}. '
                    'Consider enabling additional security inspection.'))

        if action == 'accept' and not is_disabled:
            if src_is_all and not dst_is_all:
                findings.append(('WEAK', rule_id,
                    'Unrestricted source (any)',
                    'Source address is "all" — any host can reach the destination. '
                    'Consider restricting to known source ranges.'))
            elif dst_is_all and not src_is_all:
                findings.append(('WEAK', rule_id,
                    'Unrestricted destination (any)',
                    'Destination address is "all" — source can reach any host. '
                    'Consider restricting to required destinations.'))

        if action == 'accept' and not name and not comments:
            findings.append(('WEAK', rule_id,
                'Undocumented rule (no name or comment)',
                'This rule has no name and no comment. Undocumented rules are '
                'difficult to audit and maintain. Every rule should have a '
                'documented business justification.'))
        elif action == 'accept' and not comments and name:
            findings.append(('WEAK', rule_id,
                'No comment/description on rule',
                f'Rule "{name}" has no comment. Rules should document '
                'the business purpose for audit and review.'))

        if (action == 'accept' and schedule.lower() in ('always', '')
                and (src_is_all or dst_is_all or svc_is_all) and not is_disabled):
            findings.append(('WEAK', rule_id,
                'Broad rule with no time restriction',
                'This permissive ACCEPT rule uses schedule "always" or no schedule. '
                'Consider time-based restrictions if 24/7 access is not required.'))

        # ── MANUAL ──

        mgmt_found = flat_svcs & MGMT_PROTOCOLS_STRICT
        if mgmt_found and action == 'accept' and not is_disabled:
            findings.append(('MANUAL', rule_id,
                f'Management protocol access: {", ".join(sorted(mgmt_found))}',
                'This rule permits management protocols. Verify source addresses '
                'are restricted to authorized management stations only. '
                'Management access from untrusted zones is high risk.'))

        insecure_found = flat_svcs & INSECURE_PROTOCOLS
        if insecure_found and action == 'accept' and not is_disabled:
            findings.append(('MANUAL', rule_id,
                f'Cleartext protocol access: {", ".join(sorted(insecure_found))}',
                'This rule permits protocols that transmit data in cleartext. '
                'Verify encrypted alternatives (HTTPS, SFTP, SSH, SNMPv3) are not feasible. '
                'Cleartext protocols expose credentials and data to interception.'))

        total_refs = len(src_addrs) + len(dst_addrs) + len(svc_names)
        if total_refs > 8 and action == 'accept':
            findings.append(('MANUAL', rule_id,
                f'Complex rule ({total_refs} object references)',
                'This rule references many addresses/services. Complex rules are harder '
                'to audit and more likely to contain unintended access. Consider '
                'simplifying or splitting into more specific rules.'))

        if action == 'deny':
            findings.append(('MANUAL', rule_id,
                'Explicit deny rule — verify ordering',
                'FortiGate processes rules top-to-bottom. Verify this deny rule '
                'appears BEFORE any broader accept rules matching the same traffic. '
                'A deny rule after a matching accept rule is ineffective.'))

        if action == 'ipsec':
            findings.append(('MANUAL', rule_id,
                'IPsec VPN policy',
                'Review VPN encryption algorithms, authentication methods, and peer '
                'identity validation. Ensure strong cryptographic parameters.'))

        if (srcintf and dstintf and srcintf != dstintf
                and action == 'accept' and not is_disabled):
            findings.append(('MANUAL', rule_id,
                f'Cross-zone: {srcintf} \u2192 {dstintf}',
                f'Traffic permitted from {srcintf} to {dstintf}. Verify this '
                'cross-zone access aligns with segmentation policy.'))

        vpn_keywords = ['vpn', 'ipsec', 'ssl.', 'tunnel', 'tun']
        src_vpn = any(k in srcintf.lower() for k in vpn_keywords) if srcintf else False
        dst_vpn = any(k in dstintf.lower() for k in vpn_keywords) if dstintf else False
        if (src_vpn or dst_vpn) and action == 'accept' and not is_disabled:
            vpn_if = srcintf if src_vpn else dstintf
            findings.append(('MANUAL', rule_id,
                f'VPN interface: {vpn_if}',
                f'Rule involves VPN interface "{vpn_if}". Review VPN user '
                'authentication, authorization, and split tunneling config.'))

        if 'internet-service' in rule and action == 'accept':
            findings.append(('MANUAL', rule_id,
                'Internet Service Database (ISDB) rule',
                'This rule uses FortiGuard Internet Service definitions instead of '
                'traditional address objects. Verify ISDB entries match intended scope. '
                'ISDB definitions are updated by FortiGuard and may change.'))

        # Check for broad subnets in expanded addresses
        for addr_name in src_addrs + dst_addrs:
            if addr_name in addresses:
                obj = addresses[addr_name]
                if 'subnet' in obj and len(obj['subnet']) >= 2:
                    cidr = netmask_to_cidr(obj['subnet'][1])
                    if cidr and int(cidr) <= 16 and action == 'accept':
                        findings.append(('MANUAL', rule_id,
                            f'Very broad subnet: {obj["subnet"][0]}/{cidr}',
                            f'Address "{addr_name}" is a /{cidr} or larger. '
                            'Verify this broad network scope is intentional.'))
                        break

    # ── Global checks ──

    rule_ids = list(policies.keys())
    if rule_ids:
        last_rule = policies[rule_ids[-1]]
        last_action = last_rule.get('action', [''])[0].lower()
        if last_action == 'accept':
            last_src = last_rule.get('srcaddr', [])
            last_dst = last_rule.get('dstaddr', [])
            if any(a.lower() == 'all' for a in last_src) and any(a.lower() == 'all' for a in last_dst):
                findings.append(('STRONG', 'GLOBAL',
                    'Explicit any-any accept as last rule negates implicit deny',
                    'The last rule is an any-any ACCEPT, which matches all traffic '
                    'that no previous rule matched. This defeats the implicit deny. '
                    'Review whether this catch-all is intentional.'))

    total_rules = len(policies)
    if total_rules > 50:
        findings.append(('WEAK', 'GLOBAL',
            f'Large ruleset ({total_rules} rules)',
            f'The firewall has {total_rules} rules. Large rulesets are '
            'difficult to audit. Consider consolidation and cleanup.'))

    # Shadowing check
    seen_broad = []
    for rule_id, rule in policies.items():
        action = rule.get('action', [''])[0].lower()
        if action != 'accept':
            continue
        srcif = rule.get('srcintf', [''])[0]
        dstif = rule.get('dstintf', [''])[0]
        src_all = any(a.lower() == 'all' for a in rule.get('srcaddr', []))
        dst_all = any(a.lower() == 'all' for a in rule.get('dstaddr', []))
        svc_all = any(s.upper() in HIGH_RISK_SERVICES for s in rule.get('service', []))

        if src_all and dst_all and svc_all:
            for later_id, later_rule in list(policies.items()):
                if later_id == rule_id:
                    continue
                # Only check rules that come AFTER this one
                found_current = False
                for rid in policies:
                    if rid == rule_id:
                        found_current = True
                        continue
                    if found_current and rid == later_id:
                        later_srcif = later_rule.get('srcintf', [''])[0]
                        later_dstif = later_rule.get('dstintf', [''])[0]
                        later_action = later_rule.get('action', [''])[0].lower()
                        if (later_srcif == srcif and later_dstif == dstif
                                and later_action in ('accept', 'deny')):
                            findings.append(('STRONG', later_id,
                                f'Possibly shadowed by rule {rule_id}',
                                f'Rule {rule_id} is a broader any-any-ALL ACCEPT on the same '
                                f'interfaces ({srcif}\u2192{dstif}). Rule {later_id} may never '
                                'match because the broader rule fires first.'))
                        break
            break  # Only check the first any-any-all rule

    return findings


# ─── HTML Helpers ────────────────────────────────────────────────────────────

def esc(s):
    """HTML-escape a string."""
    return (str(s)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;'))


def render_expanded_html(expanded_list):
    """Render expanded address/service list as HTML."""
    parts = []
    for group_name, values in expanded_list:
        if len(values) == 1 and values[0] == group_name:
            parts.append(f'<span class="obj-name">{esc(group_name)}</span>')
        elif len(values) == 1 and group_name.lower() in ('all', 'none'):
            parts.append(f'<span class="obj-builtin">{esc(values[0])}</span>')
        elif len(values) == 1:
            parts.append(f'<span class="obj-resolved" title="{esc(group_name)}">'
                         f'{esc(values[0])}</span>')
        else:
            items = ''.join(f'<li>{esc(v)}</li>' for v in values)
            parts.append(
                f'<div class="grp">'
                f'<span class="grp-label">{esc(group_name)}</span>'
                f'<ul>{items}</ul></div>')
    return '<br>'.join(parts) if parts else '\u2014'


def render_expanded_plain(expanded_list):
    """Render expanded list as plain text for markdown."""
    parts = []
    for group_name, values in expanded_list:
        if len(values) == 1:
            parts.append(values[0])
        else:
            parts.append(f"{group_name}: [{', '.join(values)}]")
    return '; '.join(parts) if parts else '\u2014'


# ─── HTML Generation ────────────────────────────────────────────────────────

CSS = """
:root {
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --fg: #c9d1d9; --fg2: #8b949e; --border: #30363d;
    --accent: #58a6ff; --red: #f85149; --orange: #d29922;
    --green: #3fb950; --yellow: #e3b341; --purple: #bc8cff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'SF Mono','Cascadia Code','Fira Code','Consolas',monospace;
    font-size: 12px; background: var(--bg); color: var(--fg);
    padding: 24px; line-height: 1.5;
}
h1 { font-size: 22px; color: var(--accent); margin-bottom: 4px; }
.sub { color: var(--fg2); margin-bottom: 20px; font-size: 13px; }
.stats {
    display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap;
}
.sbox {
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 6px; padding: 12px 18px; min-width: 110px;
}
.sbox .v { font-size: 26px; font-weight: 700; color: var(--accent); }
.sbox .l {
    font-size: 10px; color: var(--fg2); text-transform: uppercase;
    letter-spacing: .5px;
}
.sbox.ss .v { color: var(--red); }
.sbox.sw .v { color: var(--orange); }
.sbox.sm .v { color: var(--purple); }

.legend {
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 15px; margin-bottom: 20px;
    display: flex; gap: 20px; flex-wrap: wrap; font-size: 11px;
}
.legend-i { display: flex; align-items: center; gap: 6px; }
.legend-s {
    width: 14px; height: 14px; border-radius: 3px; display: inline-block;
}

.fbar {
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 15px; margin-bottom: 12px;
    display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
}
.fbar label {
    color: var(--fg2); font-size: 10px; text-transform: uppercase;
    letter-spacing: .5px;
}
.fbar input, .fbar select {
    background: var(--bg3); border: 1px solid var(--border);
    color: var(--fg); padding: 5px 10px; border-radius: 4px;
    font-family: inherit; font-size: 12px;
}
.fbar input:focus, .fbar select:focus {
    outline: none; border-color: var(--accent);
}

.tc {
    overflow-x: auto; overflow-y: auto; max-height: 75vh;
    margin-bottom: 30px; border: 1px solid var(--border); border-radius: 6px;
}
table { border-collapse: collapse; width: 100%; }
thead { position: sticky; top: 0; z-index: 2; }
th {
    background: var(--bg3); color: var(--accent); font-weight: 600;
    text-transform: uppercase; font-size: 10px; letter-spacing: .7px;
    padding: 10px 12px; text-align: left;
    border-bottom: 2px solid var(--border); white-space: nowrap;
    cursor: pointer; user-select: none;
}
th:hover { background: #2d333b; }
th.sorted-asc::after { content: " \\25B2"; font-size: 8px; }
th.sorted-desc::after { content: " \\25BC"; font-size: 8px; }
td {
    padding: 8px 12px; border-bottom: 1px solid var(--border);
    vertical-align: top; max-width: 320px; word-wrap: break-word;
}
tr:hover { background: rgba(88,166,255,.05); }
.row-dis { opacity: .45; }
.row-deny td:first-child { box-shadow: inset 3px 0 0 var(--red); }
.row-acc td:first-child { box-shadow: inset 3px 0 0 var(--green); }
.c-id { font-weight: 700; color: var(--accent); white-space: nowrap; }
.c-empty { color: #333; text-align: center; }
.c-warn { background: rgba(210,153,34,.1); color: var(--orange); font-weight: 600; }
.c-acc { color: var(--green); font-weight: 600; }
.c-deny { color: var(--red); font-weight: 600; }
.c-dis { color: var(--red); font-weight: 600; }
.c-cp { padding: 4px 6px; width: 32px; }

.grp { margin-bottom: 3px; }
.grp-label { color: var(--yellow); font-weight: 600; font-size: 11px; }
.grp ul { list-style: none; padding-left: 10px; margin: 1px 0; }
.grp li { color: var(--fg); font-size: 11px; line-height: 1.4; }
.grp li::before { content: "\\2192  "; color: var(--fg2); }
.obj-name { color: var(--fg); }
.obj-resolved { color: var(--fg); }
.obj-builtin { color: var(--orange); font-weight: 600; }

.cpbtn {
    background: var(--bg3); border: 1px solid var(--border);
    color: var(--fg2); border-radius: 4px; cursor: pointer;
    padding: 2px 6px; font-size: 11px; transition: .15s;
}
.cpbtn:hover { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.cpbtn.ok { background: var(--green); border-color: var(--green); color: var(--bg); }

.stitle {
    font-size: 18px; color: var(--accent); margin: 30px 0 12px;
    padding-bottom: 6px; border-bottom: 1px solid var(--border);
}
.finding {
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 6px; padding: 12px 15px; margin-bottom: 8px;
    border-left: 3px solid var(--border);
}
.f-strong { border-left-color: var(--red); }
.f-weak { border-left-color: var(--orange); }
.f-manual { border-left-color: var(--purple); }
.f-hdr {
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 5px; flex-wrap: wrap;
}
.badge {
    font-size: 10px; font-weight: 700; padding: 2px 8px;
    border-radius: 3px; letter-spacing: .5px; white-space: nowrap;
}
.b-strong { background: var(--red); color: #fff; }
.b-weak { background: var(--orange); color: #000; }
.b-manual { background: var(--purple); color: #000; }
.f-rule { color: var(--fg2); font-size: 11px; white-space: nowrap; }
.f-title { color: var(--fg); font-weight: 600; font-size: 13px; }
.f-detail { color: var(--fg2); font-size: 12px; line-height: 1.6; }
.ff {
    display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap;
}
.ffb {
    background: var(--bg3); border: 1px solid var(--border);
    color: var(--fg2); padding: 5px 12px; border-radius: 4px;
    cursor: pointer; font-family: inherit; font-size: 12px;
}
.ffb:hover { border-color: var(--accent); color: var(--fg); }
.ffb.active { background: var(--accent); color: var(--bg); border-color: var(--accent); }
"""

JS = r"""
function b64dec(s){
    var b=Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)});
    return new TextDecoder().decode(b);
}
function copyMd(btn){
    var md=b64dec(btn.getAttribute('data-md'));
    if(navigator.clipboard){
        navigator.clipboard.writeText(md).then(function(){ok(btn)}).catch(function(){fb(md,btn)});
    }else{fb(md,btn)}
}
function fb(t,btn){
    var a=document.createElement('textarea');a.value=t;
    a.style.cssText='position:fixed;left:-9999px';
    document.body.appendChild(a);a.select();
    document.execCommand('copy');document.body.removeChild(a);ok(btn);
}
function ok(btn){
    btn.classList.add('ok');btn.textContent='\u2713';
    setTimeout(function(){btn.classList.remove('ok');btn.textContent='\uD83D\uDCCB'},1200);
}
function filterTable(){
    var s=document.getElementById('si').value.toLowerCase();
    var a=document.getElementById('af').value;
    var d=document.getElementById('sd').checked;
    var rows=document.querySelectorAll('#rt tbody tr');
    var vis=0;
    rows.forEach(function(r){
        var t=r.textContent.toLowerCase();
        var isDis=r.classList.contains('row-dis');
        var act=r.getAttribute('data-action')||'';
        var show=(!s||t.indexOf(s)>=0)&&(!a||act===a)&&(d||!isDis);
        r.style.display=show?'':'none';
        if(show)vis++;
    });
    document.getElementById('vcnt').textContent=vis;
}
function sortTable(ci){
    var t=document.getElementById('rt'),tb=t.querySelector('tbody');
    var rows=Array.from(tb.querySelectorAll('tr'));
    var th=t.querySelectorAll('th')[ci];
    var asc=!th.classList.contains('sorted-asc');
    t.querySelectorAll('th').forEach(function(h){h.classList.remove('sorted-asc','sorted-desc')});
    th.classList.add(asc?'sorted-asc':'sorted-desc');
    rows.sort(function(a,b){
        var va=a.cells[ci].textContent.trim(),vb=b.cells[ci].textContent.trim();
        if(ci===0){va=parseInt(va)||0;vb=parseInt(vb)||0;return asc?va-vb:vb-va}
        return asc?va.localeCompare(vb):vb.localeCompare(va);
    });
    rows.forEach(function(r){tb.appendChild(r)});
}
function filterFindings(sev,btn){
    document.querySelectorAll('.finding').forEach(function(f){
        f.style.display=(sev==='all'||f.classList.contains('f-'+sev))?'':'none';
    });
    document.querySelectorAll('.ffb').forEach(function(b){b.classList.remove('active')});
    btn.classList.add('active');
}
"""


def generate_html(policies, findings, sections, filename):
    """Generate the complete HTML report."""
    addresses = sections.get('firewall address', {})
    address_groups = sections.get('firewall addrgrp', {})
    services_custom = sections.get('firewall service custom', {})
    service_groups = sections.get('firewall service group', {})
    schedules = {**sections.get('firewall schedule recurring', {}),
                 **sections.get('firewall schedule onetime', {})}

    # ── Determine columns ──
    priority = [
        'name', 'status', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr',
        'action', 'service', 'schedule', 'nat', 'logtraffic', 'logtraffic-start',
        'comments', 'av-profile', 'ips-sensor', 'webfilter-profile',
        'ssl-ssh-profile', 'dnsfilter-profile', 'application-list',
        'capture-packet', 'auto-asic-offload', 'groups',
        'poolname', 'label', 'global-label',
    ]
    all_keys = OrderedDict()
    for p in priority:
        all_keys[p] = True
    for rule in policies.values():
        for k in rule:
            if k != 'uuid':
                all_keys[k] = True

    # Only show columns with data
    has_data = set()
    for rule in policies.values():
        for k in rule:
            if k != 'uuid':
                has_data.add(k)
    display_cols = [k for k in all_keys if k in has_data]

    expandable_addr = {'srcaddr', 'dstaddr', 'srcaddr6', 'dstaddr6'}
    expandable_svc = {'service'}
    expandable_sched = {'schedule'}

    # ── Build table rows ──
    rows_html = []
    for rule_id, rule in policies.items():
        action = rule.get('action', [''])[0].lower()
        status = rule.get('status', ['enable'])[0].lower()
        is_disabled = status == 'disable'

        row_cls = 'row-dis' if is_disabled else ('row-deny' if action == 'deny' else
                  'row-acc' if action == 'accept' else '')

        md_lines = [f"## Rule {rule_id}", ""]
        rule_name = rule.get('name', [''])[0] if 'name' in rule else ''
        if rule_name:
            md_lines[0] += f' \u2014 {rule_name}'
        md_lines.extend(["| Property | Value |", "|----------|-------|"])
        md_lines.append(f"| **ID** | {rule_id} |")

        cells = []
        for col in display_cols:
            values = rule.get(col, [])
            if not values:
                cells.append('<td class="c-empty">\u2014</td>')
                md_lines.append(f"| **{col}** | \u2014 |")
                continue

            cell_cls = ''
            if col in expandable_addr:
                expanded = expand_addresses(values, addresses, address_groups)
                content = render_expanded_html(expanded)
                plain = render_expanded_plain(expanded)
                if any(v.lower() == 'all' for v in values):
                    cell_cls = 'c-warn'
            elif col in expandable_svc:
                expanded = expand_services(values, services_custom, service_groups)
                content = render_expanded_html(expanded)
                plain = render_expanded_plain(expanded)
                if any(v.upper() in HIGH_RISK_SERVICES for v in values):
                    cell_cls = 'c-warn'
            elif col in expandable_sched:
                exp = expand_schedule(values[0], schedules)
                content = esc(exp)
                plain = exp
            elif col == 'action':
                v = values[0]
                content = esc(v)
                plain = v
                cell_cls = 'c-acc' if v.lower() == 'accept' else (
                    'c-deny' if v.lower() == 'deny' else '')
            elif col == 'status':
                v = values[0]
                content = esc(v)
                plain = v
                if v.lower() == 'disable':
                    cell_cls = 'c-dis'
            elif col == 'logtraffic':
                v = values[0]
                content = esc(v)
                plain = v
                if v.lower() in ('disable', ''):
                    cell_cls = 'c-warn'
            else:
                plain = ' '.join(values)
                content = esc(plain)

            cls_attr = f' class="{cell_cls}"' if cell_cls else ''
            cells.append(f'<td{cls_attr}>{content}</td>')
            md_plain = plain.replace('|', '\\|')
            md_lines.append(f"| **{col}** | {md_plain} |")

        md_text = '\n'.join(md_lines)
        md_b64 = base64.b64encode(md_text.encode('utf-8')).decode('ascii')

        copy_cell = (f'<td class="c-cp">'
                     f'<button class="cpbtn" onclick="copyMd(this)" '
                     f'data-md="{md_b64}" title="Copy as Markdown">'
                     f'\U0001f4cb</button></td>')

        rc = f' class="{row_cls}"' if row_cls else ''
        row = (f'<tr{rc} data-action="{esc(action)}">'
               f'<td class="c-id">{esc(rule_id)}</td>'
               f'{copy_cell}'
               f'{"".join(cells)}</tr>')
        rows_html.append(row)

    # ── Build findings HTML ──
    sev_order = {'STRONG': 0, 'WEAK': 1, 'MANUAL': 2}
    sorted_findings = sorted(findings, key=lambda f: (sev_order.get(f[0], 9), str(f[1])))

    findings_parts = []
    for sev, rid, title, detail in sorted_findings:
        sc = sev.lower()
        findings_parts.append(
            f'<div class="finding f-{sc}">'
            f'<div class="f-hdr">'
            f'<span class="badge b-{sc}">{sev}</span>'
            f'<span class="f-rule">Rule {esc(str(rid))}</span>'
            f'<span class="f-title">{esc(title)}</span>'
            f'</div>'
            f'<div class="f-detail">{esc(detail)}</div>'
            f'</div>')

    # ── Stats ──
    total = len(policies)
    accept_n = sum(1 for r in policies.values() if r.get('action', [''])[0].lower() == 'accept')
    deny_n = sum(1 for r in policies.values() if r.get('action', [''])[0].lower() == 'deny')
    disabled_n = sum(1 for r in policies.values() if r.get('status', ['enable'])[0].lower() == 'disable')
    strong_n = sum(1 for f in findings if f[0] == 'STRONG')
    weak_n = sum(1 for f in findings if f[0] == 'WEAK')
    manual_n = sum(1 for f in findings if f[0] == 'MANUAL')

    # ── Column headers ──
    col_hdrs = ''.join(
        f'<th onclick="sortTable({i + 2})">{esc(col)}</th>'
        for i, col in enumerate(display_cols))

    # ── Assemble HTML ──
    html_parts = []
    html_parts.append(f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FortiGate ACL Analysis \u2014 {esc(filename)}</title>
<style>{CSS}</style>
</head>
<body>
<h1>FortiGate ACL Analysis</h1>
<div class="sub">{esc(filename)} \u2014 {total} rules \u2014 {len(findings)} findings</div>

<div class="stats">
<div class="sbox"><div class="v">{total}</div><div class="l">Total Rules</div></div>
<div class="sbox"><div class="v">{accept_n}</div><div class="l">Accept</div></div>
<div class="sbox"><div class="v">{deny_n}</div><div class="l">Deny</div></div>
<div class="sbox"><div class="v">{disabled_n}</div><div class="l">Disabled</div></div>
<div class="sbox ss"><div class="v">{strong_n}</div><div class="l">Strong</div></div>
<div class="sbox sw"><div class="v">{weak_n}</div><div class="l">Weak</div></div>
<div class="sbox sm"><div class="v">{manual_n}</div><div class="l">Manual</div></div>
</div>

<div class="legend">
<div class="legend-i"><span class="legend-s" style="background:var(--red)"></span><b>STRONG</b> \u2014 Definite finding, raise it</div>
<div class="legend-i"><span class="legend-s" style="background:var(--orange)"></span><b>WEAK</b> \u2014 Likely issue, needs context</div>
<div class="legend-i"><span class="legend-s" style="background:var(--purple)"></span><b>MANUAL</b> \u2014 Pentester must review</div>
</div>

<h2 class="stitle">Firewall Rules</h2>

<div class="fbar">
<label>Search:</label>
<input type="text" id="si" placeholder="Filter\u2026" oninput="filterTable()">
<label>Action:</label>
<select id="af" onchange="filterTable()">
<option value="">All</option>
<option value="accept">accept</option>
<option value="deny">deny</option>
<option value="ipsec">ipsec</option>
</select>
<label>Disabled:</label>
<input type="checkbox" id="sd" checked onchange="filterTable()">
<span style="color:var(--fg2);font-size:11px">Showing <span id="vcnt">{total}</span> rules</span>
</div>

<div class="tc">
<table id="rt">
<thead><tr>
<th onclick="sortTable(0)">ID</th>
<th>Copy</th>
{col_hdrs}
</tr></thead>
<tbody>
{"".join(rows_html)}
</tbody>
</table>
</div>

<h2 class="stitle">Pentesting Analysis ({len(findings)} findings)</h2>

<div class="ff">
<button class="ffb active" onclick="filterFindings('all',this)">All ({len(findings)})</button>
<button class="ffb" onclick="filterFindings('strong',this)">Strong ({strong_n})</button>
<button class="ffb" onclick="filterFindings('weak',this)">Weak ({weak_n})</button>
<button class="ffb" onclick="filterFindings('manual',this)">Manual ({manual_n})</button>
</div>

<div id="fc">
{"".join(findings_parts)}
</div>

<script>{JS}</script>
</body>
</html>''')

    return '\n'.join(html_parts)


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("FortiGate ACL Parser and Pentesting Analyzer")
        print("Usage: python3 fortigate_acl_parser.py <config_file> [output.html]")
        print()
        print("Parses FortiGate configurations, expands groups/objects,")
        print("and generates an HTML report with pentesting analysis.")
        sys.exit(1)

    config_file = sys.argv[1]
    if len(sys.argv) >= 3:
        output_file = sys.argv[2]
    else:
        base = os.path.splitext(os.path.basename(config_file))[0]
        output_file = base + '_acl_report.html'

    if not os.path.isfile(config_file):
        print(f"Error: File not found: {config_file}")
        sys.exit(1)

    print(f"[*] Reading {config_file}")
    with open(config_file, 'r', errors='replace') as f:
        text = f.read()

    print("[*] Parsing configuration...")
    sections = parse_config(text)

    policies = sections.get('firewall policy', OrderedDict())
    if not policies:
        print("[!] No 'config firewall policy' section found.")
        available = [s for s in sections if 'policy' in s.lower() or 'firewall' in s.lower()]
        if available:
            print(f"    Related sections found: {', '.join(available)}")
        else:
            print(f"    Sections found: {', '.join(list(sections.keys())[:20])}")
        sys.exit(1)

    addrs = sections.get('firewall address', {})
    agrps = sections.get('firewall addrgrp', {})
    svcs = sections.get('firewall service custom', {})
    sgrps = sections.get('firewall service group', {})

    print(f"    {len(policies)} policies, {len(addrs)} addresses, "
          f"{len(agrps)} address groups, {len(svcs)} services, {len(sgrps)} service groups")

    print("[*] Analyzing...")
    findings = analyze_policies(policies, addrs, agrps, svcs, sgrps)

    strong_n = sum(1 for f in findings if f[0] == 'STRONG')
    weak_n = sum(1 for f in findings if f[0] == 'WEAK')
    manual_n = sum(1 for f in findings if f[0] == 'MANUAL')

    print("[*] Generating HTML report...")
    html = generate_html(policies, findings, sections, os.path.basename(config_file))

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"[+] Report: {output_file}")
    print(f"    STRONG: {strong_n}  |  WEAK: {weak_n}  |  MANUAL: {manual_n}")


if __name__ == '__main__':
    main()
