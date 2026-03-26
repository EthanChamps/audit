#!/usr/bin/env python3
"""
FortiGate 100F ACL Extraction Script — Config File Parser
FortiOS 7.4.x

Parses a FortiGate configuration file (from 'show full-configuration' or
a GUI/CLI backup) and extracts firewall policies and all related objects,
outputting JSON, CSV, and a human-readable summary.

Supports both single-VDOM and multi-VDOM config files.

Usage:
    python3 fortigate_acl_extract.py config.conf
    python3 fortigate_acl_extract.py config.conf --vdom root
    python3 fortigate_acl_extract.py config.conf --output-dir ./export --no-ipv6
"""

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------
def tokenize(line: str) -> list:
    """
    Tokenize a single FortiOS CLI config line.

    Rules (from FortiOS config file spec):
      "quoted string"  -> token with quotes stripped
      ''               -> empty string token (FortiOS empty-value literal)
      unquoted word    -> token as-is (keywords, IPs, integers, enums)

    Examples:
      'set srcaddr "LAN" "DMZ"'        -> ['set', 'srcaddr', 'LAN', 'DMZ']
      'set ip 10.0.0.1 255.255.255.0'  -> ['set', 'ip', '10.0.0.1', '255.255.255.0']
      'set comments ''                 -> ['set', 'comments', '']
      'set action accept'              -> ['set', 'action', 'accept']
    """
    tokens = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c in (' ', '\t'):
            i += 1
        elif c == '"':
            # Double-quoted string — strip surrounding quotes
            j = i + 1
            while j < n and line[j] != '"':
                j += 1
            tokens.append(line[i + 1:j])
            i = j + 1  # skip closing "
        elif c == "'" and i + 1 < n and line[i + 1] == "'":
            # Empty string literal ''
            tokens.append('')
            i += 2
        else:
            # Unquoted token — ends at space, tab, or start of ''
            j = i
            while j < n and line[j] not in (' ', '\t', '"'):
                # Stop if we hit '' (two single quotes)
                if line[j] == "'" and j + 1 < n and line[j + 1] == "'":
                    break
                j += 1
            if j > i:
                tokens.append(line[i:j])
            i = j
    return tokens


# ---------------------------------------------------------------------------
# Config File Parser
# ---------------------------------------------------------------------------
def parse_header(filepath: str) -> dict:
    """
    Extract device metadata from the #config-version comment header.

    Format: #config-version=FGT100F-7.04-FW-build2360-231117:opmode=0:vdom=0:user=admin
    """
    info = {'vdom_enabled': False, 'model': None, 'version': None}
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#config-version='):
                    payload = line[len('#config-version='):]
                    parts = payload.split(':')
                    # First part: MODEL-VERSION-FW-buildNNNN-DATE
                    header_parts = parts[0].split('-')
                    if len(header_parts) >= 2:
                        info['model'] = header_parts[0]
                        # Version like "7.04" -> "7.0.4", but "5.6.2" stays as-is
                        raw_ver = header_parts[1]
                        if raw_ver and '.' in raw_ver:
                            major, minor = raw_ver.split('.', 1)
                            # Only expand if minor is a zero-padded number (e.g. "04")
                            if minor.isdigit() and len(minor) == 2 and minor[0] == '0':
                                info['version'] = f"{major}.{minor[0]}.{minor[1]}"
                            else:
                                info['version'] = raw_ver
                        else:
                            info['version'] = raw_ver
                    for part in parts[1:]:
                        if part.startswith('vdom='):
                            info['vdom_enabled'] = part.split('=', 1)[1] == '1'
                    break
    except Exception:
        pass
    return info


def parse_config_file(filepath: str) -> dict:
    """
    Parse a FortiGate config file and return all sections as a dict.

    Return structure:
        {
          'section_name'       : { edit_key: record_dict, ... },  # single-VDOM
          'section_name@vdom'  : { edit_key: record_dict, ... },  # multi-VDOM
        }

    Each record_dict contains field -> value mappings where:
      - Single value  -> str
      - Multi-value   -> list[str]   (e.g. set srcaddr "a" "b" -> ['a', 'b'])
      - Empty value   -> ''

    The edit key is stored in record['_key'] as well as being the dict key.

    Handles:
      - Arbitrary nesting (config inside edit inside config)
      - Multi-VDOM files (config global ... end + config vdom ... end)
      - config-objects (no edit/next, just set commands) -> ignored (no records)
    """
    # Stack frames — one per open 'config' block
    # Frame fields: section, records, key, record, is_vdom_table, is_global
    stack = []
    sections = {}    # label -> {edit_key: record}
    cur_vdom = None  # current VDOM context (set when inside a vdom 'edit' block)

    def _label(name):
        """Build a section label, appending @vdom when in multi-VDOM context."""
        return f"{name}@{cur_vdom}" if cur_vdom else name

    def _save(frame):
        """Persist completed frame records into the sections dict."""
        if not frame['records']:
            return
        if frame['is_vdom_table'] or frame['is_global']:
            return
        label = _label(frame['section'])
        if label not in sections:
            sections[label] = {}
        sections[label].update(frame['records'])

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue

            tokens = tokenize(line)
            if not tokens:
                continue

            cmd = tokens[0].lower()

            # ------------------------------------------------------------------
            if cmd == 'config':
                section = ' '.join(tokens[1:])
                stack.append({
                    'section':       section,
                    'records':       {},
                    'key':           None,
                    'record':        None,
                    'is_vdom_table': section == 'vdom',
                    'is_global':     section == 'global',
                })

            # ------------------------------------------------------------------
            elif cmd == 'edit':
                if not stack:
                    continue
                frame = stack[-1]
                edit_key = tokens[1] if len(tokens) > 1 else '_'
                # Track which VDOM we're entering
                if frame['is_vdom_table']:
                    cur_vdom = edit_key
                frame['key'] = edit_key
                frame['record'] = {'_key': edit_key}

            # ------------------------------------------------------------------
            elif cmd == 'set':
                if not stack:
                    continue
                frame = stack[-1]
                # Only store 'set' values when inside an edit block;
                # config-objects (set commands with no enclosing edit) are skipped.
                if frame['record'] is None or len(tokens) < 2:
                    continue
                field = tokens[1]
                vals = tokens[2:]
                if len(vals) == 0:
                    frame['record'][field] = ''
                elif len(vals) == 1:
                    frame['record'][field] = vals[0]
                else:
                    frame['record'][field] = vals

            # ------------------------------------------------------------------
            elif cmd == 'next':
                if not stack:
                    continue
                frame = stack[-1]
                # Save completed edit record
                if frame['record'] is not None and frame['key'] is not None:
                    frame['records'][frame['key']] = frame['record']
                    frame['record'] = None
                    frame['key'] = None
                # Exiting a VDOM edit block
                if frame['is_vdom_table']:
                    cur_vdom = None

            # ------------------------------------------------------------------
            elif cmd == 'end':
                if not stack:
                    continue
                frame = stack.pop()
                _save(frame)
                # Restore VDOM context if we're back inside a vdom table's edit block
                if stack and stack[-1]['is_vdom_table'] and stack[-1]['key']:
                    cur_vdom = stack[-1]['key']
                elif not any(f['is_vdom_table'] and f['key'] for f in stack):
                    cur_vdom = None

    return sections


# ---------------------------------------------------------------------------
# Section Lookup  (handles single-VDOM and multi-VDOM transparently)
# ---------------------------------------------------------------------------
def get_section(sections: dict, name: str, vdom: str = None) -> dict:
    """
    Retrieve records for a named config section.

    Search order:
      1. 'name@vdom'  — VDOM-specific (multi-VDOM file, vdom specified)
      2. 'name'       — non-tagged (single-VDOM file, always falls through here)
      3. Merge all    — merge every 'name@*' section (no vdom filter requested)

    Returns {} if not found.
    """
    # 1. Prefer VDOM-specific match
    if vdom:
        key = f"{name}@{vdom}"
        if key in sections:
            return sections[key]

    # 2. Direct (non-tagged) match — covers all single-VDOM configs
    if name in sections:
        return sections[name]

    # 3. Merge all matching VDOM variants when no filter specified.
    #    Use compound keys  "vdom:record_key"  to avoid collisions when
    #    multiple VDOMs each have an edit 1, edit 2, etc.
    if vdom is None:
        merged = {}
        for k, v in sections.items():
            if k.split('@')[0] == name:
                vdom_tag = k.split('@')[1] if '@' in k else ''
                for rec_key, record in v.items():
                    compound = f"{vdom_tag}:{rec_key}" if vdom_tag else rec_key
                    merged[compound] = record
        return merged

    return {}


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------
def val_str(v) -> str:
    """Render a field value (str, list, or None) as a plain string."""
    if isinstance(v, list):
        return ' '.join(str(x) for x in v)
    return str(v) if v is not None else ''


def names_str(v) -> str:
    """
    Render a multi-name field (srcaddr, service, srcintf, member, …)
    as a comma-separated string regardless of whether it's a str or list.
    """
    if isinstance(v, list):
        return ', '.join(str(x) for x in v if x != '')
    return str(v) if v else ''


def subnet_display(record: dict) -> str:
    """
    Format an address object's subnet field.
    The 'subnet' field is stored as ['ip', 'mask'] or 'ip mask' string.
    """
    subnet = record.get('subnet', '')
    if isinstance(subnet, list):
        return ' '.join(subnet)
    return str(subnet)


# ---------------------------------------------------------------------------
# Policy Flattening (for CSV output)
# ---------------------------------------------------------------------------
def flatten_policy(p: dict) -> dict:
    """Flatten a policy record dict into a single-level dict for CSV."""
    return {
        'policy_id':         val_str(p.get('_key', '')),
        'name':              val_str(p.get('name', '')),
        'status':            val_str(p.get('status', 'enable')),
        'action':            val_str(p.get('action', '')),
        'src_interfaces':    names_str(p.get('srcintf', '')),
        'dst_interfaces':    names_str(p.get('dstintf', '')),
        'src_addresses':     names_str(p.get('srcaddr', '')),
        'dst_addresses':     names_str(p.get('dstaddr', '')),
        'src_addr_negate':   val_str(p.get('srcaddr-negate', 'disable')),
        'dst_addr_negate':   val_str(p.get('dstaddr-negate', 'disable')),
        'services':          names_str(p.get('service', '')),
        'service_negate':    val_str(p.get('service-negate', 'disable')),
        'schedule':          val_str(p.get('schedule', 'always')),
        'nat':               val_str(p.get('nat', 'disable')),
        'logtraffic':        val_str(p.get('logtraffic', 'disable')),
        'utm_status':        val_str(p.get('utm-status', 'disable')),
        'av_profile':        val_str(p.get('av-profile', '')),
        'webfilter_profile': val_str(p.get('webfilter-profile', '')),
        'ips_sensor':        val_str(p.get('ips-sensor', '')),
        'ssl_ssh_profile':   val_str(p.get('ssl-ssh-profile', '')),
        'application_list':  val_str(p.get('application-list', '')),
        'comments':          val_str(p.get('comments', '')),
        'uuid':              val_str(p.get('uuid', '')),
    }


# ---------------------------------------------------------------------------
# Output Writers
# ---------------------------------------------------------------------------
def write_json(sections: dict, output_dir: Path):
    """Write each section to its own JSON file plus a combined export."""
    json_dir = output_dir / 'json'
    json_dir.mkdir(parents=True, exist_ok=True)

    for label, records in sections.items():
        safe = label.replace(' ', '_').replace('@', '_at_').replace('/', '_')
        with open(json_dir / f'{safe}.json', 'w', encoding='utf-8') as f:
            json.dump(list(records.values()), f, indent=2)

    combined = output_dir / 'acl_full_export.json'
    with open(combined, 'w', encoding='utf-8') as f:
        json.dump({k: list(v.values()) for k, v in sections.items()}, f, indent=2)

    print(f'[+] JSON per-section : {json_dir}/')
    print(f'[+] Combined export  : {combined}')


def write_policies_csv(policies: dict, output_dir: Path, filename: str):
    """Write flattened firewall policy records to a CSV file."""
    if not policies:
        print(f'[WARN]  No policies found — skipping {filename}')
        return
    csv_dir = output_dir / 'csv'
    csv_dir.mkdir(parents=True, exist_ok=True)
    rows = [flatten_policy(p) for p in policies.values()]
    out_file = csv_dir / filename
    with open(out_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f'[+] CSV              : {out_file}')


def write_summary(sections: dict, output_dir: Path,
                  filepath: str, info: dict, vdom: str):
    """Write a human-readable ACL summary report."""

    policies   = get_section(sections, 'firewall policy',         vdom)
    policies6  = get_section(sections, 'firewall policy6',        vdom)
    addresses  = get_section(sections, 'firewall address',        vdom)
    addrgrps   = get_section(sections, 'firewall addrgrp',        vdom)
    svc_custom = get_section(sections, 'firewall service custom', vdom)
    svc_grps   = get_section(sections, 'firewall service group',  vdom)

    out_file  = output_dir / 'acl_summary.txt'
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with open(out_file, 'w', encoding='utf-8') as f:
        def w(line=''):
            f.write(line + '\n')

        def negate_tag(record, field):
            return ' [NEGATE]' if val_str(record.get(field, '')) == 'enable' else ''

        def policy_sort_key(k):
            # Handles plain keys ('1') and compound keys ('root:1')
            last = str(k).rsplit(':', 1)[-1]
            return int(last) if last.isdigit() else 0

        # ------------------------------------------------------------------
        # Header
        # ------------------------------------------------------------------
        w('=' * 72)
        w('  FortiGate ACL Extraction Report')
        w(f'  Source    : {filepath}')
        w(f'  Model     : {info.get("model", "unknown")}')
        w(f'  FortiOS   : {info.get("version", "unknown")}')
        w(f'  VDOM mode : {"multi-VDOM" if info.get("vdom_enabled") else "single VDOM"}')
        w(f'  VDOM      : {vdom or "all"}')
        w(f'  Generated : {timestamp}')
        w('=' * 72)
        w()

        # ------------------------------------------------------------------
        # Section inventory
        # ------------------------------------------------------------------
        w('PARSED SECTIONS')
        w('-' * 40)
        for label in sorted(sections):
            w(f'  {label:<45} {len(sections[label]):>5} records')
        w()

        # ------------------------------------------------------------------
        # IPv4 Firewall Policies
        # ------------------------------------------------------------------
        w(f'FIREWALL POLICIES (IPv4) — {len(policies)} total')
        w('=' * 72)
        for key in sorted(policies, key=policy_sort_key):
            p = policies[key]
            w(f'\n  Policy #{p["_key"]} — {val_str(p.get("name", "(unnamed)"))}  '
              f'[{val_str(p.get("status", "enable"))}]')
            w(f'  {"Action":<18}: {val_str(p.get("action", "")).upper()}')
            w(f'  {"Src Interface":<18}: {names_str(p.get("srcintf", ""))}')
            w(f'  {"Dst Interface":<18}: {names_str(p.get("dstintf", ""))}')
            w(f'  {"Src Address":<18}: {names_str(p.get("srcaddr", ""))}'
              f'{negate_tag(p, "srcaddr-negate")}')
            w(f'  {"Dst Address":<18}: {names_str(p.get("dstaddr", ""))}'
              f'{negate_tag(p, "dstaddr-negate")}')
            w(f'  {"Service":<18}: {names_str(p.get("service", ""))}'
              f'{negate_tag(p, "service-negate")}')
            w(f'  {"Schedule":<18}: {val_str(p.get("schedule", "always"))}')
            w(f'  {"NAT":<18}: {val_str(p.get("nat", "disable"))}')
            w(f'  {"Log Traffic":<18}: {val_str(p.get("logtraffic", "disable"))}')
            # Security profiles (only shown when utm-status is enabled)
            if val_str(p.get('utm-status', '')) == 'enable':
                profiles = ', '.join(filter(None, [
                    val_str(p.get('av-profile', '')),
                    val_str(p.get('webfilter-profile', '')),
                    val_str(p.get('ips-sensor', '')),
                    val_str(p.get('application-list', '')),
                    val_str(p.get('ssl-ssh-profile', '')),
                ]))
                if profiles:
                    w(f'  {"UTM Profiles":<18}: {profiles}')
            comments = val_str(p.get('comments', ''))
            if comments:
                w(f'  {"Comment":<18}: {comments}')
            w(f'  {"UUID":<18}: {val_str(p.get("uuid", ""))}')
            w('  ' + '-' * 60)

        # ------------------------------------------------------------------
        # IPv6 Firewall Policies
        # ------------------------------------------------------------------
        if policies6:
            w()
            w(f'FIREWALL POLICIES (IPv6) — {len(policies6)} total')
            w('=' * 72)
            for key in sorted(policies6, key=policy_sort_key):
                p = policies6[key]
                w(f'\n  Policy #{p["_key"]} — {val_str(p.get("name", "(unnamed)"))}  '
                  f'[{val_str(p.get("status", "enable"))}]')
                w(f'  {"Action":<18}: {val_str(p.get("action", "")).upper()}')
                w(f'  {"Src Interface":<18}: {names_str(p.get("srcintf", ""))}')
                w(f'  {"Dst Interface":<18}: {names_str(p.get("dstintf", ""))}')
                w(f'  {"Src Address":<18}: {names_str(p.get("srcaddr", ""))}'
                  f'{negate_tag(p, "srcaddr-negate")}')
                w(f'  {"Dst Address":<18}: {names_str(p.get("dstaddr", ""))}'
                  f'{negate_tag(p, "dstaddr-negate")}')
                w(f'  {"Service":<18}: {names_str(p.get("service", ""))}'
                  f'{negate_tag(p, "service-negate")}')
                w(f'  {"Schedule":<18}: {val_str(p.get("schedule", "always"))}')
                w(f'  {"NAT":<18}: {val_str(p.get("nat", "disable"))}')
                w('  ' + '-' * 60)

        # ------------------------------------------------------------------
        # Address Objects
        # ------------------------------------------------------------------
        w()
        w(f'ADDRESS OBJECTS — {len(addresses)} total')
        w('=' * 72)
        for key, a in addresses.items():
            atype = val_str(a.get('type', 'ipmask'))
            name  = val_str(a.get('name', key))
            if atype == 'ipmask':
                value = subnet_display(a)
            elif atype == 'iprange':
                value = (f'{val_str(a.get("start-ip", ""))} – '
                         f'{val_str(a.get("end-ip", ""))}')
            elif atype == 'fqdn':
                value = val_str(a.get('fqdn', ''))
            elif atype == 'wildcard-fqdn':
                value = val_str(a.get('wildcard-fqdn', ''))
            elif atype == 'geography':
                value = f'Country: {val_str(a.get("country", ""))}'
            else:
                # Fallback — try subnet or fqdn
                value = subnet_display(a) or val_str(a.get('fqdn', ''))
            comment = val_str(a.get('comment', ''))
            suffix  = f'  # {comment}' if comment else ''
            w(f'  {name:<35} {atype:<16} {value}{suffix}')

        # ------------------------------------------------------------------
        # Address Groups
        # ------------------------------------------------------------------
        w()
        w(f'ADDRESS GROUPS — {len(addrgrps)} total')
        w('=' * 72)
        for key, g in addrgrps.items():
            name    = val_str(g.get('name', key))
            members = names_str(g.get('member', ''))
            comment = val_str(g.get('comment', ''))
            suffix  = f'  # {comment}' if comment else ''
            w(f'  {name:<35} Members: {members}{suffix}')

        # ------------------------------------------------------------------
        # Custom Services
        # ------------------------------------------------------------------
        w()
        w(f'CUSTOM SERVICES — {len(svc_custom)} total')
        w('=' * 72)
        for key, s in svc_custom.items():
            name  = val_str(s.get('name', key))
            proto = val_str(s.get('protocol', ''))
            parts = []
            tcp = val_str(s.get('tcp-portrange', ''))
            udp = val_str(s.get('udp-portrange', ''))
            if tcp:
                parts.append(f'TCP:{tcp}')
            if udp:
                parts.append(f'UDP:{udp}')
            if proto in ('ICMP', 'ICMP6'):
                parts.append(f'type={val_str(s.get("icmptype", "any"))}')
            if proto == 'IP':
                parts.append(f'proto={val_str(s.get("protocol-number", ""))}')
            w(f'  {name:<35} {proto:<16} {" ".join(parts)}')

        # ------------------------------------------------------------------
        # Service Groups
        # ------------------------------------------------------------------
        w()
        w(f'SERVICE GROUPS — {len(svc_grps)} total')
        w('=' * 72)
        for key, sg in svc_grps.items():
            name    = val_str(sg.get('name', key))
            members = names_str(sg.get('member', ''))
            w(f'  {name:<35} Members: {members}')

        w()
        w('=' * 72)
        w('  End of Report')
        w('=' * 72)

    print(f'[+] Summary          : {out_file}')


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description='Extract ACLs from a FortiGate 100F config file (FortiOS 7.4.x)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 fortigate_acl_extract.py fw_backup.conf
  python3 fortigate_acl_extract.py fw_backup.conf --vdom root
  python3 fortigate_acl_extract.py fw_backup.conf --output-dir ./export --no-ipv6
        """,
    )
    parser.add_argument('config_file',
                        help='FortiGate config file (backup or show full-configuration output)')
    parser.add_argument('--vdom', default=None,
                        help='Filter to a specific VDOM (default: include all VDOMs)')
    parser.add_argument('--output-dir', default='./fortigate_acl_export',
                        help='Directory for output files (default: ./fortigate_acl_export)')
    parser.add_argument('--no-ipv6', action='store_true',
                        help='Exclude IPv6 policy output')
    return parser.parse_args()


def main():
    args = parse_args()

    config_path = Path(args.config_file)
    if not config_path.exists():
        print(f'[ERROR] Config file not found: {config_path}')
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ---- Parse header ----
    info = parse_header(str(config_path))

    print(f'\n  FortiGate ACL Extractor — Config File Parser')
    print(f'  Source  : {config_path.resolve()}')
    print(f'  Model   : {info.get("model", "unknown")}')
    print(f'  FortiOS : {info.get("version", "unknown")}')
    print(f'  VDOMs   : {"multi-VDOM" if info.get("vdom_enabled") else "single VDOM"}')
    print(f'  Output  : {output_dir.resolve()}')

    # ---- Parse config ----
    print('\n[*] Parsing config file...')
    sections = parse_config_file(str(config_path))
    print(f'    {len(sections)} sections found:')
    for label in sorted(sections):
        print(f'      {label:<45} {len(sections[label]):>5} records')

    # ---- Retrieve policy sets ----
    vdom = args.vdom
    policies  = get_section(sections, 'firewall policy',  vdom)
    policies6 = get_section(sections, 'firewall policy6', vdom)
    print(f'\n    IPv4 policies : {len(policies)}')
    print(f'    IPv6 policies : {len(policies6)}')

    # ---- Write outputs ----
    print('\n[*] Writing output files...')
    write_json(sections, output_dir)
    write_policies_csv(policies, output_dir, 'policies_ipv4.csv')
    if not args.no_ipv6 and policies6:
        write_policies_csv(policies6, output_dir, 'policies_ipv6.csv')
    write_summary(sections, output_dir, str(config_path), info, vdom)

    print(f'\n[+] Done. All files in: {output_dir.resolve()}\n')


if __name__ == '__main__':
    main()
