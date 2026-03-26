#!/usr/bin/env python3
"""
FortiGate ACL Analyser — Webapp for Pen Testers
FortiOS 4.x – 7.4.x  |  Zero external dependencies

Upload a FortiGate config file and get instant security findings with
colour-coded policy tables, object resolution, and JSON/CSV export.

Usage:
    python3 fortigate_webapp.py                     # launch webapp on port 8080
    python3 fortigate_webapp.py --port 9090         # custom port
    python3 fortigate_webapp.py config.conf         # CLI mode (original)
"""

import argparse
import csv
import html as html_mod
import http.server
import io
import json
import os
import sys
import tempfile
import urllib.parse
import webbrowser
from datetime import datetime
from pathlib import Path

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

# ============================================================================
# PARSER  (copied from fortigate_acl_extract.py — battle-tested)
# ============================================================================

def tokenize(line: str) -> list:
    tokens = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c in (' ', '\t'):
            i += 1
        elif c == '"':
            j = i + 1
            while j < n and line[j] != '"':
                j += 1
            tokens.append(line[i + 1:j])
            i = j + 1
        elif c == "'" and i + 1 < n and line[i + 1] == "'":
            tokens.append('')
            i += 2
        else:
            j = i
            while j < n and line[j] not in (' ', '\t', '"'):
                if line[j] == "'" and j + 1 < n and line[j + 1] == "'":
                    break
                j += 1
            if j > i:
                tokens.append(line[i:j])
            i = j
    return tokens


def parse_header(filepath: str) -> dict:
    info = {'vdom_enabled': False, 'model': None, 'version': None}
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#config-version='):
                    payload = line[len('#config-version='):]
                    parts = payload.split(':')
                    header_parts = parts[0].split('-')
                    if len(header_parts) >= 2:
                        info['model'] = header_parts[0]
                        raw_ver = header_parts[1]
                        if raw_ver and '.' in raw_ver:
                            major, minor = raw_ver.split('.', 1)
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
    stack = []
    sections = {}
    cur_vdom = None

    def _label(name):
        return f"{name}@{cur_vdom}" if cur_vdom else name

    def _save(frame):
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

            if cmd == 'config':
                section = ' '.join(tokens[1:])
                stack.append({
                    'section': section, 'records': {},
                    'key': None, 'record': None,
                    'is_vdom_table': section == 'vdom',
                    'is_global': section == 'global',
                })
            elif cmd == 'edit':
                if not stack:
                    continue
                frame = stack[-1]
                edit_key = tokens[1] if len(tokens) > 1 else '_'
                if frame['is_vdom_table']:
                    cur_vdom = edit_key
                frame['key'] = edit_key
                frame['record'] = {'_key': edit_key}
            elif cmd == 'set':
                if not stack:
                    continue
                frame = stack[-1]
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
            elif cmd == 'next':
                if not stack:
                    continue
                frame = stack[-1]
                if frame['record'] is not None and frame['key'] is not None:
                    frame['records'][frame['key']] = frame['record']
                    frame['record'] = None
                    frame['key'] = None
                if frame['is_vdom_table']:
                    cur_vdom = None
            elif cmd == 'end':
                if not stack:
                    continue
                frame = stack.pop()
                _save(frame)
                if stack and stack[-1]['is_vdom_table'] and stack[-1]['key']:
                    cur_vdom = stack[-1]['key']
                elif not any(f['is_vdom_table'] and f['key'] for f in stack):
                    cur_vdom = None
    return sections


def get_section(sections: dict, name: str, vdom: str = None) -> dict:
    if vdom:
        key = f"{name}@{vdom}"
        if key in sections:
            return sections[key]
    if name in sections:
        return sections[name]
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


def val_str(v) -> str:
    if isinstance(v, list):
        return ' '.join(str(x) for x in v)
    return str(v) if v is not None else ''


def names_str(v) -> str:
    if isinstance(v, list):
        return ', '.join(str(x) for x in v if x != '')
    return str(v) if v else ''


def subnet_display(record: dict) -> str:
    subnet = record.get('subnet', '')
    if isinstance(subnet, list):
        return ' '.join(subnet)
    return str(subnet)


def flatten_policy(p: dict) -> dict:
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


# Pure enum/boolean keywords that stay unquoted in FortiOS config.
# Object names (addresses, interfaces, services, schedules) are always quoted
# even if they happen to be "all" or "always".
_UNQUOTED = frozenset({
    'enable', 'disable', 'accept', 'deny', 'reject', 'ipsec',
    'utm', 'nat', 'transparent',
})


def _needs_quote(val: str) -> bool:
    """Determine if a value needs quoting in FortiOS config syntax."""
    if not val:
        return True  # empty string → ''
    if val.lower() in _UNQUOTED:
        return False
    if val.isdigit():
        return False
    # IP address pattern (digits and dots/colons)
    if all(c in '0123456789.:/abcdef' for c in val.lower()):
        return False
    return True


def reconstruct_config_block(policy: dict) -> str:
    """Rebuild the FortiOS CLI config block from a parsed policy dict."""
    lines = [f'edit {policy.get("_key", "?")}']
    for field, value in policy.items():
        if field == '_key':
            continue
        if isinstance(value, list):
            quoted = ' '.join(f'"{v}"' for v in value)
            lines.append(f'    set {field} {quoted}')
        elif value == '':
            lines.append(f"    set {field} ''")
        elif _needs_quote(value):
            lines.append(f'    set {field} "{value}"')
        else:
            lines.append(f'    set {field} {value}')
    lines.append('next')
    return '\n'.join(lines)


# ============================================================================
# SECURITY FINDINGS ENGINE
# ============================================================================

FINDING_CHECKS = []


def finding(fn):
    """Register a security check function."""
    FINDING_CHECKS.append(fn)
    return fn


def _field_has(policy, field, value):
    """Check if a policy field contains a value (case-insensitive)."""
    v = policy.get(field, '')
    if isinstance(v, list):
        return any(str(x).lower() == value.lower() for x in v)
    return str(v).lower() == value.lower()


def _is_accept(p):
    return val_str(p.get('action', '')).lower() == 'accept'


def _is_enabled(p):
    return val_str(p.get('status', 'enable')).lower() != 'disable'


@finding
def check_permit_any_any_any(p):
    if _is_accept(p) and _is_enabled(p) \
       and _field_has(p, 'srcaddr', 'all') \
       and _field_has(p, 'dstaddr', 'all') \
       and _field_has(p, 'service', 'ALL'):
        return {
            'severity': 'critical',
            'title': 'ANY to ANY — ALL services',
            'desc': 'Permits ALL traffic from ANY source to ANY destination. '
                    'This effectively disables the firewall for matched interfaces.',
            'reason': 'Triggered when action=accept, srcaddr="all", dstaddr="all", and service="ALL" on an enabled rule.',
            'fix': 'set srcaddr <specific_address>\nset dstaddr <specific_address>\nset service <specific_services>',
        }


@finding
def check_any_source_any_service(p):
    if _is_accept(p) and _is_enabled(p) \
       and _field_has(p, 'srcaddr', 'all') \
       and _field_has(p, 'service', 'ALL') \
       and not _field_has(p, 'dstaddr', 'all'):
        return {
            'severity': 'high',
            'title': 'ANY source + ALL services',
            'desc': 'Accepts any service from any source. Restrict source addresses or services.',
            'reason': 'Triggered when action=accept, srcaddr="all", and service="ALL" (but dstaddr is restricted).',
            'fix': 'set srcaddr <specific_address>\nset service <specific_services>',
        }


@finding
def check_no_logging(p):
    if _is_accept(p) and _is_enabled(p):
        log = val_str(p.get('logtraffic', 'disable')).lower()
        if log in ('disable', ''):
            return {
                'severity': 'high',
                'title': 'Logging disabled',
                'desc': 'ACCEPT rule with no traffic logging. '
                        'Security events through this rule will not be recorded.',
                'reason': 'Triggered when action=accept and logtraffic is "disable" or not configured on an enabled rule.',
                'fix': 'set logtraffic all',
            }


@finding
def check_no_utm(p):
    if _is_accept(p) and _is_enabled(p):
        utm = val_str(p.get('utm-status', '')).lower()
        if utm != 'enable':
            av = val_str(p.get('av-profile', ''))
            ips = val_str(p.get('ips-sensor', ''))
            wf = val_str(p.get('webfilter-profile', ''))
            ssl = val_str(p.get('ssl-ssh-profile', ''))
            if not any([av, ips, wf, ssl]):
                return {
                    'severity': 'medium',
                    'title': 'No security profiles',
                    'desc': 'ACCEPT rule with no UTM inspection (AV, IPS, web filter). '
                            'Traffic passes uninspected.',
                    'reason': 'Triggered when action=accept and utm-status is not "enable", with no AV, IPS, web filter, or SSL inspection profiles assigned.',
                    'fix': 'set utm-status enable\nset av-profile "default"\nset ips-sensor "default"\nset webfilter-profile "default"\nset ssl-ssh-profile "certificate-inspection"',
                }


@finding
def check_all_services(p):
    if _is_accept(p) and _is_enabled(p) \
       and _field_has(p, 'service', 'ALL') \
       and not _field_has(p, 'srcaddr', 'all'):
        return {
            'severity': 'medium',
            'title': 'ALL services permitted',
            'desc': 'All services/ports allowed. Consider restricting to required services only.',
            'reason': 'Triggered when action=accept and service="ALL" (source address is restricted but all ports/protocols are open).',
            'fix': 'set service "HTTPS" "HTTP" "DNS"  # Replace with required services only',
        }


@finding
def check_any_source(p):
    if _is_accept(p) and _is_enabled(p) \
       and _field_has(p, 'srcaddr', 'all') \
       and not _field_has(p, 'service', 'ALL'):
        return {
            'severity': 'medium',
            'title': 'ANY source allowed',
            'desc': 'Accepts traffic from any source address. Consider restricting source IPs.',
            'reason': 'Triggered when action=accept and srcaddr="all" (service is restricted but any IP can reach it).',
            'fix': 'set srcaddr <specific_address_object>  # Replace "all" with defined address objects',
        }


@finding
def check_disabled_rule(p):
    if val_str(p.get('status', 'enable')).lower() == 'disable':
        return {
            'severity': 'medium',
            'title': 'Disabled rule',
            'desc': 'Rule exists but is disabled. May indicate config drift or '
                    'a decommissioned rule that should be cleaned up.',
            'reason': 'Triggered when status="disable". Disabled rules add clutter and may be re-enabled accidentally.',
            'fix': 'delete <policy_id>  # Remove the rule, or re-enable with: set status enable',
        }


@finding
def check_utm_only_logging(p):
    if _is_accept(p) and _is_enabled(p):
        log = val_str(p.get('logtraffic', '')).lower()
        if log == 'utm':
            return {
                'severity': 'medium',
                'title': 'UTM-only logging',
                'desc': 'Only UTM-triggered events are logged. '
                        'Consider logging all traffic for full visibility.',
                'reason': 'Triggered when action=accept and logtraffic="utm". Only security profile hits are logged, not all sessions.',
                'fix': 'set logtraffic all',
            }


@finding
def check_deny_rule(p):
    action = val_str(p.get('action', '')).lower()
    if action in ('deny', 'reject'):
        return {
            'severity': 'info',
            'title': 'Explicit DENY',
            'desc': 'Explicit deny/reject rule. Verify this is an intentional block.',
            'reason': 'Triggered when action="deny" or "reject". Flagged for review, not necessarily a misconfiguration.',
            'fix': 'No change needed if intentional. To convert: set action accept',
        }


def analyse_policy(policy: dict) -> list:
    findings = []
    for check_fn in FINDING_CHECKS:
        result = check_fn(policy)
        if result:
            findings.append(result)
    return findings


def analyse_all(policies: dict) -> dict:
    return {k: analyse_policy(v) for k, v in policies.items()}


# ============================================================================
# MULTIPART FORM PARSER  (stdlib only — no cgi module needed)
# ============================================================================

def parse_multipart(body: bytes, content_type: str) -> dict:
    """Parse multipart/form-data. Returns {field: str_or_dict}."""
    boundary = None
    for part in content_type.split(';'):
        part = part.strip()
        if part.startswith('boundary='):
            boundary = part[len('boundary='):].strip().strip('"').encode()
            break
    if not boundary:
        return {}
    fields = {}
    for section in body.split(b'--' + boundary):
        section = section.strip()
        if not section or section == b'--':
            continue
        if b'\r\n\r\n' in section:
            hdr, bdy = section.split(b'\r\n\r\n', 1)
        elif b'\n\n' in section:
            hdr, bdy = section.split(b'\n\n', 1)
        else:
            continue
        if bdy.endswith(b'\r\n'):
            bdy = bdy[:-2]
        hdr_str = hdr.decode('utf-8', errors='replace')
        name = filename = None
        for line in hdr_str.replace('\r\n', '\n').split('\n'):
            if 'name="' in line:
                name = line.split('name="')[1].split('"')[0]
            if 'filename="' in line:
                filename = line.split('filename="')[1].split('"')[0]
        if name:
            if filename:
                fields[name] = {'filename': filename, 'data': bdy}
            else:
                fields[name] = bdy.decode('utf-8', errors='replace').strip()
    return fields


# ============================================================================
# HTML / CSS / JS  (all embedded — zero external resources)
# ============================================================================

E = html_mod.escape  # shorthand for escaping user data

CSS = """
:root {
    --bg: #0d1117; --surface: #161b22; --card: #21262d; --border: #30363d;
    --text: #c9d1d9; --text-muted: #8b949e; --accent: #58a6ff;
    --critical: #f85149; --critical-bg: #3d1117;
    --high: #d29922; --high-bg: #3d2c12;
    --medium: #e3b341; --medium-bg: #3d3612;
    --info: #58a6ff; --info-bg: #12283d;
    --success: #3fb950;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif;
       background: var(--bg); color: var(--text); line-height: 1.5; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.container { max-width: 1400px; margin: 0 auto; padding: 20px; }
.header { background: var(--surface); border-bottom: 1px solid var(--border);
          padding: 16px 24px; margin-bottom: 24px; }
.header h1 { font-size: 20px; font-weight: 600; }
.header .meta { color: var(--text-muted); font-size: 13px; margin-top: 4px; }
.header .meta span { margin-right: 18px; }

/* Stats cards */
.stats { display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }
.stat-card { background: var(--card); border: 1px solid var(--border);
             border-radius: 8px; padding: 16px 20px; min-width: 140px; flex: 1; }
.stat-card .num { font-size: 28px; font-weight: 700; }
.stat-card .label { font-size: 12px; color: var(--text-muted); text-transform: uppercase;
                    letter-spacing: 0.5px; }
.stat-card.critical .num { color: var(--critical); }
.stat-card.high .num { color: var(--high); }
.stat-card.medium .num { color: var(--medium); }
.stat-card.info .num { color: var(--info); }
.stat-card.total .num { color: var(--accent); }

/* Findings summary */
.findings-box { background: var(--card); border: 1px solid var(--border);
                border-radius: 8px; padding: 20px; margin-bottom: 24px; }
.findings-box h2 { font-size: 16px; margin-bottom: 12px; }
.finding-item { padding: 6px 0; border-bottom: 1px solid var(--border);
                font-size: 13px; display: flex; align-items: center; gap: 8px; }
.finding-item:last-child { border-bottom: none; }

/* Severity pills */
.pill { display: inline-block; padding: 2px 8px; border-radius: 10px;
        font-size: 11px; font-weight: 600; text-transform: uppercase; }
.pill-critical { background: var(--critical); color: #fff; }
.pill-high { background: var(--high); color: #000; }
.pill-medium { background: var(--medium); color: #000; }
.pill-info { background: var(--info); color: #fff; }
.pill.copyable { cursor: pointer; transition: all 0.2s; position: relative; }
.pill.copyable:hover { opacity: 0.85; }
.pill.copied::after { content: ' \\2713'; }
.pill.copied { outline: 2px solid var(--success); }
.pill .tooltip { display: none; position: absolute; bottom: 130%; left: 50%;
    transform: translateX(-50%); background: #1a1a2e; border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 14px; width: 360px; font-size: 12px;
    font-weight: normal; text-transform: none; color: var(--text);
    line-height: 1.6; z-index: 100; box-shadow: 0 4px 16px rgba(0,0,0,0.6);
    white-space: normal; text-align: left; pointer-events: none; }
.pill .tooltip::after { content: ''; position: absolute; top: 100%; left: 50%;
    transform: translateX(-50%); border: 6px solid transparent;
    border-top-color: var(--border); }
.pill.copyable:hover .tooltip { display: block; }
.pill .tooltip b { color: var(--accent); }
.pill .tooltip code { background: var(--surface); padding: 2px 6px; border-radius: 3px;
    font-family: monospace; font-size: 11px; color: var(--success);
    display: inline-block; margin-top: 2px; white-space: pre-wrap; }

/* Policy table */
.table-wrap { overflow-x: auto; margin-bottom: 24px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: var(--surface); position: sticky; top: 0; padding: 10px 8px;
     text-align: left; font-weight: 600; border-bottom: 2px solid var(--border);
     white-space: nowrap; cursor: pointer; user-select: none; }
th:hover { color: var(--accent); }
td { padding: 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr.row-critical { background: var(--critical-bg); }
tr.row-high { background: var(--high-bg); }
tr.row-medium { background: var(--medium-bg); }
tr.row-info { background: var(--info-bg); }
td.action-accept { color: var(--success); font-weight: 600; }
td.action-deny { color: var(--critical); font-weight: 600; }
td.status-disable { color: var(--text-muted); font-style: italic; }
td.log-disable { color: var(--critical); }
td.log-all { color: var(--success); }

/* Collapsible details */
details { background: var(--card); border: 1px solid var(--border);
          border-radius: 8px; margin-bottom: 12px; }
summary { padding: 12px 16px; cursor: pointer; font-weight: 600; font-size: 14px; }
summary:hover { color: var(--accent); }
details .inner { padding: 0 16px 16px; }
details table { font-size: 12px; }

/* Upload page */
.upload-box { max-width: 520px; margin: 80px auto; background: var(--card);
              border: 1px solid var(--border); border-radius: 12px; padding: 40px; }
.upload-box h1 { font-size: 22px; margin-bottom: 6px; }
.upload-box p { color: var(--text-muted); font-size: 13px; margin-bottom: 20px; }
.upload-box label { display: block; font-size: 13px; font-weight: 600;
                    margin-bottom: 6px; }
.upload-box input[type=file],
.upload-box input[type=text] { width: 100%; padding: 10px; background: var(--surface);
    border: 1px solid var(--border); border-radius: 6px; color: var(--text);
    font-size: 13px; margin-bottom: 16px; }
.upload-box input[type=text] { font-family: monospace; }
.btn { display: inline-block; padding: 10px 24px; background: var(--accent);
       color: #fff; border: none; border-radius: 6px; font-size: 14px;
       font-weight: 600; cursor: pointer; text-decoration: none; }
.btn:hover { opacity: 0.9; text-decoration: none; }
.btn-sm { padding: 6px 14px; font-size: 12px; }
.export-bar { display: flex; gap: 8px; margin-bottom: 24px; }

/* Filter */
.filter-bar { margin-bottom: 12px; }
.filter-bar input { padding: 8px 12px; width: 300px; background: var(--surface);
    border: 1px solid var(--border); border-radius: 6px; color: var(--text);
    font-size: 13px; }
"""

JS = """
function sortTable(table, col) {
    var rows = Array.from(table.tBodies[0].rows);
    var asc = table.getAttribute('data-sort-col') == col
              && table.getAttribute('data-sort-dir') == 'asc' ? false : true;
    rows.sort(function(a, b) {
        var va = a.cells[col].textContent.trim();
        var vb = b.cells[col].textContent.trim();
        var na = parseFloat(va), nb = parseFloat(vb);
        if (!isNaN(na) && !isNaN(nb)) return asc ? na - nb : nb - na;
        return asc ? va.localeCompare(vb) : vb.localeCompare(va);
    });
    rows.forEach(function(r) { table.tBodies[0].appendChild(r); });
    table.setAttribute('data-sort-col', col);
    table.setAttribute('data-sort-dir', asc ? 'asc' : 'desc');
}
function initSort() {
    document.querySelectorAll('th[data-sortable]').forEach(function(th) {
        th.addEventListener('click', function() {
            sortTable(th.closest('table'), th.cellIndex);
        });
    });
}
function initFilter() {
    var inp = document.getElementById('policyFilter');
    if (!inp) return;
    inp.addEventListener('input', function() {
        var q = inp.value.toLowerCase();
        var rows = document.querySelectorAll('#policyTable tbody tr');
        rows.forEach(function(r) {
            r.style.display = r.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
        });
    });
}
function initCopy() {
    document.addEventListener('click', function(e) {
        var pill = e.target.closest('.copyable');
        if (!pill) return;
        var text = pill.getAttribute('data-config');
        if (!text) return;
        navigator.clipboard.writeText(text).then(function() {
            pill.classList.add('copied');
            setTimeout(function() { pill.classList.remove('copied'); }, 1500);
        });
    });
}
document.addEventListener('DOMContentLoaded', function() { initSort(); initFilter(); initCopy(); });
"""


# ============================================================================
# HTML GENERATION
# ============================================================================

def render_upload_page() -> str:
    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FortiGate ACL Analyser</title><style>{CSS}</style></head><body>
<div class="upload-box">
<h1>FortiGate ACL Analyser</h1>
<p>Upload a FortiGate config file (<code>show full-configuration</code> or backup export)
to analyse firewall policies and identify security findings.</p>
<form method="post" action="/upload" enctype="multipart/form-data">
<label for="config_file">Config file</label>
<input type="file" name="config_file" id="config_file" accept=".conf,.txt,.cfg,.bak" required>
<label for="vdom">VDOM filter <span style="font-weight:normal;color:var(--text-muted)">(optional — leave blank for all)</span></label>
<input type="text" name="vdom" id="vdom" placeholder="e.g. root">
<button type="submit" class="btn">Analyse</button>
</form>
</div></body></html>"""


def _severity_order(s):
    return {'critical': 0, 'high': 1, 'medium': 2, 'info': 3}.get(s, 9)


def _policy_sort_key(k):
    last = str(k).rsplit(':', 1)[-1]
    return int(last) if last.isdigit() else 0


def render_results_page(filename: str, info: dict, vdom: str,
                        sections: dict, policies: dict,
                        findings_map: dict) -> str:
    """Build the full results HTML page."""
    # ---- Aggregate stats ----
    total = len(policies)
    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'info': 0}
    for flist in findings_map.values():
        worst = None
        for f in flist:
            s = f['severity']
            if worst is None or _severity_order(s) < _severity_order(worst):
                worst = s
        if worst:
            sev_counts[worst] = sev_counts.get(worst, 0) + 1

    no_log_count = sum(1 for p in policies.values()
                       if _is_accept(p) and _is_enabled(p)
                       and val_str(p.get('logtraffic', 'disable')).lower() in ('disable', ''))

    # ---- Build HTML pieces ----
    h = []
    h.append(f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ACL Analysis — {E(filename)}</title>
<style>{CSS}</style></head><body>""")

    # Header
    model = E(info.get('model', 'unknown') or 'unknown')
    ver = E(info.get('version', 'unknown') or 'unknown')
    vdom_mode = 'multi-VDOM' if info.get('vdom_enabled') else 'single VDOM'
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    h.append(f"""<div class="header"><h1>FortiGate ACL Analysis</h1>
<div class="meta">
<span>File: <b>{E(filename)}</b></span>
<span>Model: <b>{model}</b></span>
<span>FortiOS: <b>{ver}</b></span>
<span>VDOM: <b>{E(vdom_mode)}</b>{f' &mdash; filtered: <b>{E(vdom)}</b>' if vdom else ''}</span>
<span>Generated: {ts}</span>
</div></div>""")

    h.append('<div class="container">')

    # Stats cards
    h.append('<div class="stats">')
    h.append(f'<div class="stat-card total"><div class="num">{total}</div>'
             f'<div class="label">Total Rules</div></div>')
    h.append(f'<div class="stat-card critical"><div class="num">{sev_counts["critical"]}</div>'
             f'<div class="label">Critical</div></div>')
    h.append(f'<div class="stat-card high"><div class="num">{sev_counts["high"]}</div>'
             f'<div class="label">High</div></div>')
    h.append(f'<div class="stat-card medium"><div class="num">{sev_counts["medium"]}</div>'
             f'<div class="label">Medium</div></div>')
    h.append(f'<div class="stat-card info"><div class="num">{sev_counts["info"]}</div>'
             f'<div class="label">Info</div></div>')
    h.append(f'<div class="stat-card"><div class="num" style="color:var(--critical)">'
             f'{no_log_count}</div><div class="label">No Logging</div></div>')
    h.append('</div>')

    # Export bar
    h.append('<div class="export-bar">'
             '<a class="btn btn-sm" href="/export/json">Export JSON</a>'
             '<a class="btn btn-sm" href="/export/csv">Export CSV</a>'
             '<a class="btn btn-sm" href="/">Upload Another</a>'
             '</div>')

    # ---- Findings summary ----
    all_findings = []
    for pk in sorted(policies, key=_policy_sort_key):
        p = policies[pk]
        pid = E(val_str(p.get('_key', pk)))
        pname = E(val_str(p.get('name', '')))
        for f in findings_map.get(pk, []):
            all_findings.append((f['severity'], pid, pname, f['title'], f['desc']))

    if all_findings:
        all_findings.sort(key=lambda x: _severity_order(x[0]))
        h.append('<div class="findings-box"><h2>Security Findings</h2>')
        for sev, pid, pname, title, desc in all_findings:
            h.append(f'<div class="finding-item">'
                     f'<span class="pill pill-{sev}">{sev}</span>'
                     f'<span><b>Policy #{pid}</b>'
                     f'{f" ({pname})" if pname else ""}'
                     f' &mdash; {E(title)}: {E(desc)}</span></div>')
        h.append('</div>')
    else:
        h.append('<div class="findings-box" style="border-color:var(--success)">'
                 '<h2 style="color:var(--success)">No Security Findings</h2>'
                 '<p style="color:var(--text-muted)">No policy-level issues detected. '
                 'Manual review is still recommended.</p></div>')

    # ---- Policy table ----
    h.append('<h2 style="margin-bottom:8px">Firewall Policies</h2>')
    h.append('<div class="filter-bar"><input id="policyFilter" '
             'placeholder="Filter policies..." type="text"></div>')
    h.append('<div class="table-wrap"><table id="policyTable">')
    cols = ['#', 'Name', 'Status', 'Action', 'Src Intf', 'Dst Intf',
            'Src Addr', 'Dst Addr', 'Service', 'NAT', 'Log', 'Findings']
    h.append('<thead><tr>')
    for c in cols:
        h.append(f'<th data-sortable>{c}</th>')
    h.append('</tr></thead><tbody>')

    for pk in sorted(policies, key=_policy_sort_key):
        p = policies[pk]
        fl = findings_map.get(pk, [])
        # Row class based on worst finding
        row_class = ''
        if fl:
            worst = min(fl, key=lambda f: _severity_order(f['severity']))['severity']
            row_class = f' class="row-{worst}"'

        pid = E(val_str(p.get('_key', pk)))
        name = E(val_str(p.get('name', '')))
        status = val_str(p.get('status', 'enable')).lower()
        action = val_str(p.get('action', '')).lower()
        log = val_str(p.get('logtraffic', 'disable')).lower()

        status_cls = ' class="status-disable"' if status == 'disable' else ''
        action_cls = f' class="action-{action}"' if action in ('accept', 'deny') else ''
        log_cls = ''
        if log == 'disable':
            log_cls = ' class="log-disable"'
        elif log == 'all':
            log_cls = ' class="log-all"'

        config_block = E(reconstruct_config_block(p)) if fl else ''
        pills = []
        for f in fl:
            tip = (f'<span class="tooltip">'
                   f'<b>Why:</b> {E(f["desc"])}<br>'
                   f'<b>Check:</b> {E(f.get("reason", ""))}<br>'
                   f'<b>Fix:</b> <code>{E(f.get("fix", ""))}</code>'
                   f'</span>')
            pills.append(
                f'<span class="pill pill-{f["severity"]} copyable" '
                f'data-config="{config_block}">'
                f'{E(f["title"])}{tip}</span>')
        findings_pills = ' '.join(pills)

        h.append(f'<tr{row_class}>'
                 f'<td>{pid}</td>'
                 f'<td>{name}</td>'
                 f'<td{status_cls}>{E(status)}</td>'
                 f'<td{action_cls}>{E(action.upper())}</td>'
                 f'<td>{E(names_str(p.get("srcintf", "")))}</td>'
                 f'<td>{E(names_str(p.get("dstintf", "")))}</td>'
                 f'<td>{E(names_str(p.get("srcaddr", "")))}</td>'
                 f'<td>{E(names_str(p.get("dstaddr", "")))}</td>'
                 f'<td>{E(names_str(p.get("service", "")))}</td>'
                 f'<td>{E(val_str(p.get("nat", "disable")))}</td>'
                 f'<td{log_cls}>{E(log)}</td>'
                 f'<td>{findings_pills}</td>'
                 f'</tr>')

    h.append('</tbody></table></div>')

    # ---- Reference sections (collapsible) ----
    # Addresses
    addresses = get_section(sections, 'firewall address', vdom)
    if addresses:
        h.append('<details><summary>Address Objects'
                 f' ({len(addresses)})</summary><div class="inner">')
        h.append('<table><thead><tr><th>Name</th><th>Type</th>'
                 '<th>Value</th><th>Comment</th></tr></thead><tbody>')
        for k, a in addresses.items():
            atype = val_str(a.get('type', 'ipmask'))
            aname = val_str(a.get('name', k))
            if atype == 'ipmask':
                aval = subnet_display(a)
            elif atype == 'iprange':
                aval = f'{val_str(a.get("start-ip",""))} – {val_str(a.get("end-ip",""))}'
            elif atype == 'fqdn':
                aval = val_str(a.get('fqdn', ''))
            elif atype == 'wildcard-fqdn':
                aval = val_str(a.get('wildcard-fqdn', ''))
            elif atype == 'geography':
                aval = f'Country: {val_str(a.get("country", ""))}'
            else:
                aval = subnet_display(a) or val_str(a.get('fqdn', ''))
            comment = val_str(a.get('comment', ''))
            h.append(f'<tr><td>{E(aname)}</td><td>{E(atype)}</td>'
                     f'<td>{E(aval)}</td><td>{E(comment)}</td></tr>')
        h.append('</tbody></table></div></details>')

    # Address groups
    addrgrps = get_section(sections, 'firewall addrgrp', vdom)
    if addrgrps:
        h.append('<details><summary>Address Groups'
                 f' ({len(addrgrps)})</summary><div class="inner">')
        h.append('<table><thead><tr><th>Group</th><th>Members</th>'
                 '<th>Comment</th></tr></thead><tbody>')
        for k, g in addrgrps.items():
            h.append(f'<tr><td>{E(val_str(g.get("name", k)))}</td>'
                     f'<td>{E(names_str(g.get("member", "")))}</td>'
                     f'<td>{E(val_str(g.get("comment", "")))}</td></tr>')
        h.append('</tbody></table></div></details>')

    # Services
    svc_custom = get_section(sections, 'firewall service custom', vdom)
    if svc_custom:
        h.append('<details><summary>Custom Services'
                 f' ({len(svc_custom)})</summary><div class="inner">')
        h.append('<table><thead><tr><th>Name</th><th>Protocol</th>'
                 '<th>Ports</th></tr></thead><tbody>')
        for k, s in svc_custom.items():
            proto = val_str(s.get('protocol', ''))
            tcp = val_str(s.get('tcp-portrange', ''))
            udp = val_str(s.get('udp-portrange', ''))
            parts = []
            if tcp:
                parts.append(f'TCP: {tcp}')
            if udp:
                parts.append(f'UDP: {udp}')
            if proto in ('ICMP', 'ICMP6'):
                parts.append(f'type={val_str(s.get("icmptype", "any"))}')
            if proto == 'IP':
                parts.append(f'proto={val_str(s.get("protocol-number", ""))}')
            h.append(f'<tr><td>{E(val_str(s.get("name", k)))}</td>'
                     f'<td>{E(proto)}</td><td>{E("  ".join(parts))}</td></tr>')
        h.append('</tbody></table></div></details>')

    # Service groups
    svc_grps = get_section(sections, 'firewall service group', vdom)
    if svc_grps:
        h.append('<details><summary>Service Groups'
                 f' ({len(svc_grps)})</summary><div class="inner">')
        h.append('<table><thead><tr><th>Group</th>'
                 '<th>Members</th></tr></thead><tbody>')
        for k, sg in svc_grps.items():
            h.append(f'<tr><td>{E(val_str(sg.get("name", k)))}</td>'
                     f'<td>{E(names_str(sg.get("member", "")))}</td></tr>')
        h.append('</tbody></table></div></details>')

    # VIPs
    vips = get_section(sections, 'firewall vip', vdom)
    if vips:
        h.append('<details><summary>Virtual IPs / NAT'
                 f' ({len(vips)})</summary><div class="inner">')
        h.append('<table><thead><tr><th>Name</th><th>Ext IP</th>'
                 '<th>Mapped IP</th><th>Port</th><th>Comment</th></tr></thead><tbody>')
        for k, v in vips.items():
            h.append(f'<tr><td>{E(val_str(v.get("name", k)))}</td>'
                     f'<td>{E(val_str(v.get("extip", "")))}</td>'
                     f'<td>{E(val_str(v.get("mappedip", "")))}</td>'
                     f'<td>{E(val_str(v.get("portforward", "")))}'
                     f' {E(val_str(v.get("extport", "")))}'
                     f' &rarr; {E(val_str(v.get("mappedport", "")))}</td>'
                     f'<td>{E(val_str(v.get("comment", "")))}</td></tr>')
        h.append('</tbody></table></div></details>')

    h.append('</div>')  # container
    h.append(f'<script>{JS}</script></body></html>')
    return '\n'.join(h)


# ============================================================================
# EXPORT GENERATORS
# ============================================================================

def generate_json_export(sections: dict) -> str:
    return json.dumps({k: list(v.values()) for k, v in sections.items()}, indent=2)


def generate_csv_export(policies: dict) -> str:
    if not policies:
        return ''
    output = io.StringIO()
    rows = [flatten_policy(p) for p in policies.values()]
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


# ============================================================================
# HTTP SERVER
# ============================================================================

class AppState:
    """Shared state for the single-user local server."""
    sections = {}
    policies = {}
    info = {}
    vdom = None
    filename = ''


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Quieter logging
        sys.stderr.write(f"  [{self.log_date_time_string()}] {fmt % args}\n")

    def _send_html(self, body: str, status: int = 200):
        data = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_download(self, data: str, filename: str, mime: str):
        raw = data.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', f'{mime}; charset=utf-8')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == '/':
            self._send_html(render_upload_page())
        elif path == '/export/json' and AppState.sections:
            self._send_download(generate_json_export(AppState.sections),
                                'fortigate_export.json', 'application/json')
        elif path == '/export/csv' and AppState.policies:
            self._send_download(generate_csv_export(AppState.policies),
                                'policies.csv', 'text/csv')
        elif path in ('/export/json', '/export/csv'):
            self._send_html('<p>No data loaded. <a href="/">Upload a config first.</a></p>', 400)
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != '/upload':
            self.send_error(404)
            return

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_UPLOAD_BYTES:
            self._send_html('<p>File too large (50 MB max). '
                            '<a href="/">Go back.</a></p>', 413)
            return

        body = self.rfile.read(content_length)
        content_type = self.headers.get('Content-Type', '')
        fields = parse_multipart(body, content_type)

        file_field = fields.get('config_file')
        if not file_field or not isinstance(file_field, dict):
            self._send_html('<p>No file uploaded. <a href="/">Go back.</a></p>', 400)
            return

        config_data = file_field['data']
        filename = file_field.get('filename', 'config.conf')
        vdom = fields.get('vdom', '') or None

        # Write to temp file for the parser
        fd, tmppath = tempfile.mkstemp(suffix='.conf')
        try:
            os.write(fd, config_data)
            os.close(fd)

            info = parse_header(tmppath)
            sections = parse_config_file(tmppath)
        finally:
            os.unlink(tmppath)

        policies = get_section(sections, 'firewall policy', vdom)
        findings_map = analyse_all(policies)

        # Store in AppState for export endpoints
        AppState.sections = sections
        AppState.policies = policies
        AppState.info = info
        AppState.vdom = vdom
        AppState.filename = filename

        page = render_results_page(filename, info, vdom, sections,
                                   policies, findings_map)
        self._send_html(page)


def serve(port: int = 8080, bind: str = '127.0.0.1', open_browser: bool = True):
    server = http.server.HTTPServer((bind, port), Handler)
    url = f'http://{bind}:{port}/'
    print(f'\n  FortiGate ACL Analyser')
    print(f'  Running at: {url}')
    print(f'  Press Ctrl+C to stop\n')
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n  Shutting down.')
        server.server_close()


# ============================================================================
# CLI MODE  (original file-based output)
# ============================================================================

def cli_write_json(sections, output_dir):
    json_dir = output_dir / 'json'
    json_dir.mkdir(parents=True, exist_ok=True)
    for label, records in sections.items():
        safe = label.replace(' ', '_').replace('@', '_at_').replace('/', '_')
        with open(json_dir / f'{safe}.json', 'w', encoding='utf-8') as f:
            json.dump(list(records.values()), f, indent=2)
    combined = output_dir / 'acl_full_export.json'
    with open(combined, 'w', encoding='utf-8') as f:
        json.dump({k: list(v.values()) for k, v in sections.items()}, f, indent=2)
    print(f'[+] JSON: {json_dir}/')


def cli_write_csv(policies, output_dir, filename):
    if not policies:
        return
    csv_dir = output_dir / 'csv'
    csv_dir.mkdir(parents=True, exist_ok=True)
    rows = [flatten_policy(p) for p in policies.values()]
    out_file = csv_dir / filename
    with open(out_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f'[+] CSV:  {out_file}')


def cli_mode(config_file, vdom, output_dir, no_ipv6):
    config_path = Path(config_file)
    if not config_path.exists():
        print(f'[ERROR] File not found: {config_path}')
        sys.exit(1)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    info = parse_header(str(config_path))
    print(f'\n  FortiGate ACL Extractor — CLI Mode')
    print(f'  Source: {config_path.resolve()}')
    print(f'  Model:  {info.get("model", "unknown")}')
    sections = parse_config_file(str(config_path))
    policies = get_section(sections, 'firewall policy', vdom)
    policies6 = get_section(sections, 'firewall policy6', vdom)
    print(f'  IPv4 policies: {len(policies)}')
    cli_write_json(sections, output_dir)
    cli_write_csv(policies, output_dir, 'policies_ipv4.csv')
    if not no_ipv6 and policies6:
        cli_write_csv(policies6, output_dir, 'policies_ipv6.csv')
    print(f'\n[+] Done: {output_dir.resolve()}\n')


# ============================================================================
# ENTRYPOINT
# ============================================================================

def main():
    # Dual-mode: if first arg looks like a file, run CLI; otherwise run webapp
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        parser = argparse.ArgumentParser(description='FortiGate ACL Extractor — CLI')
        parser.add_argument('config_file')
        parser.add_argument('--vdom', default=None)
        parser.add_argument('--output-dir', default='./fortigate_acl_export')
        parser.add_argument('--no-ipv6', action='store_true')
        args = parser.parse_args()
        cli_mode(args.config_file, args.vdom, args.output_dir, args.no_ipv6)
    else:
        parser = argparse.ArgumentParser(description='FortiGate ACL Analyser — Web UI')
        parser.add_argument('--port', type=int, default=8080)
        parser.add_argument('--bind', default='127.0.0.1')
        parser.add_argument('--no-browser', action='store_true')
        args = parser.parse_args()
        serve(port=args.port, bind=args.bind, open_browser=not args.no_browser)


if __name__ == '__main__':
    main()
