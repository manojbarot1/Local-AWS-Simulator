"""
rules.py
========

Structured routes, security-group rules and network-ACL rules.

Earlier versions stored these as free text (``"0.0.0.0/0 -> igw-local"``,
``"HTTP TCP 80 0.0.0.0/0"``), which looked right but could not be evaluated.
Everything is now stored as small dicts so the reachability analyzer and the
lab checks can reason about real behaviour. The parsers below still accept the
old text forms, so existing databases and the console's textarea inputs keep
working.

Shapes
------
route     {"destination": "0.0.0.0/0", "target": "igw-0abc..." | "local"}
sg rule   {"protocol": "tcp"|"udp"|"icmp"|"-1", "from_port": int|None,
           "to_port": int|None, "cidr": str|None, "source_group": str|None,
           "description": str}
nacl rule {"rule_number": int, "action": "allow"|"deny", "protocol": ...,
           "from_port": int|None, "to_port": int|None, "cidr": str, "egress": bool}
"""

from __future__ import annotations

import ipaddress
import json
import re

from errors import SimError

# Well-known service names the console accepts in rule text.
SERVICE_PORTS = {
    "SSH": ("tcp", 22), "HTTP": ("tcp", 80), "HTTPS": ("tcp", 443),
    "RDP": ("tcp", 3389), "MYSQL": ("tcp", 3306), "MYSQL/AURORA": ("tcp", 3306),
    "POSTGRES": ("tcp", 5432), "POSTGRESQL": ("tcp", 5432), "MSSQL": ("tcp", 1433),
    "DNS": ("udp", 53), "SMTP": ("tcp", 25), "NFS": ("tcp", 2049), "REDIS": ("tcp", 6379),
}
PROTOCOLS = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp", "ALL": "-1", "-1": "-1",
             "TCP/UDP/ICMP": "-1", "ANY": "-1"}
PROTO_NUMBERS = {"6": "tcp", "17": "udp", "1": "icmp", "-1": "-1"}


def loads_list(raw):
    try:
        val = json.loads(raw or "[]")
    except (ValueError, TypeError):
        return []
    return val if isinstance(val, list) else []


def is_cidr(text):
    try:
        ipaddress.ip_network(text, strict=False)
        return "/" in text
    except ValueError:
        return False


def cidr_contains(cidr, ip):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _ports(token):
    """'80' -> (80, 80); '1024-65535' -> (1024, 65535); 'ALL' -> (None, None)."""
    if token.upper() in ("ALL", "-1", "*"):
        return None, None
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", token)
    if not m:
        return False
    lo = int(m.group(1))
    hi = int(m.group(2) or lo)
    if not (0 <= lo <= hi <= 65535):
        return False
    return lo, hi


def normalise_protocol(p):
    p = str(p or "-1")
    return PROTO_NUMBERS.get(p, PROTOCOLS.get(p.upper(), p.lower()))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def parse_route(entry):
    """Accept a stored dict or the legacy ``"dest -> target"`` string."""
    if isinstance(entry, dict):
        return {"destination": entry.get("destination", ""), "target": entry.get("target", "")}
    text = str(entry)
    if "->" in text:
        dest, target = (x.strip() for x in text.split("->", 1))
    else:
        parts = text.split()
        dest, target = (parts + ["", ""])[:2]
    return {"destination": dest, "target": target}


def parse_routes(raw):
    return [parse_route(r) for r in (loads_list(raw) if isinstance(raw, str) or raw is None else raw)]


def route_text(route):
    return f"{route['destination']} → {route['target']}"


def longest_prefix_match(routes, ip):
    best = None
    for r in routes:
        try:
            net = ipaddress.ip_network(r["destination"], strict=False)
        except ValueError:
            continue
        if ipaddress.ip_address(ip) in net and (best is None or net.prefixlen > best[0]):
            best = (net.prefixlen, r)
    return best[1] if best else None


# ---------------------------------------------------------------------------
# Security-group rules
# ---------------------------------------------------------------------------

def parse_sg_rule(entry):
    """Parse a stored dict or a console text line into a structured rule.

    Accepted text: ``tcp 443 0.0.0.0/0``, ``HTTPS 0.0.0.0/0``,
    ``SSH TCP 22 10.0.0.0/8``, ``tcp 8000-8080 sg-0abc...``, ``ALL ALL self``.
    """
    if isinstance(entry, dict):
        rule = dict(entry)
        rule["protocol"] = normalise_protocol(rule.get("protocol"))
        rule.setdefault("from_port", None)
        rule.setdefault("to_port", None)
        rule.setdefault("cidr", None)
        rule.setdefault("source_group", None)
        rule.setdefault("description", "")
        return rule
    text = str(entry).strip()
    tokens = text.replace("(", " ").replace(")", " ").split()
    proto = None
    ports = None
    cidr = None
    group = None
    words = []
    for tok in tokens:
        up = tok.upper()
        if cidr is None and group is None and is_cidr(tok):
            cidr = str(ipaddress.ip_network(tok, strict=False))
        elif group is None and cidr is None and (tok.startswith("sg-") or tok.lower() == "self"):
            group = "self" if tok.lower() == "self" else tok
        elif proto is None and up in PROTOCOLS:
            proto = PROTOCOLS[up]
        elif ports is None and _ports(tok) is not False and proto is not None:
            ports = _ports(tok)
        elif up in SERVICE_PORTS and proto is None:
            proto, port = SERVICE_PORTS[up]
            ports = (port, port)
            words.append(tok)
        elif up not in PROTOCOLS and _ports(tok) is False:
            words.append(tok)
    if proto is None or (cidr is None and group is None):
        raise SimError(
            "InvalidParameterValue",
            f"Could not understand the rule '{text}'. Use: <protocol> <port or range> <CIDR or sg-id>, "
            "for example 'tcp 443 0.0.0.0/0' or 'HTTPS 0.0.0.0/0'.",
        )
    if proto == "-1":
        ports = (None, None)
    elif ports is None:
        if proto == "icmp":
            ports = (None, None)
        else:
            raise SimError("InvalidParameterValue", f"The rule '{text}' needs a port or port range for {proto}.")
    desc = " ".join(w for w in words if w.upper() not in ("SG", "DEFAULT"))
    return {"protocol": proto, "from_port": ports[0], "to_port": ports[1],
            "cidr": cidr, "source_group": group, "description": desc}


def parse_sg_rules(raw):
    items = loads_list(raw) if isinstance(raw, str) or raw is None else raw
    out = []
    for item in items:
        try:
            out.append(parse_sg_rule(item))
        except SimError:
            continue  # unparseable legacy text: ignore rather than crash a page
    return out


def sg_rule_text(rule):
    proto = "All traffic" if rule["protocol"] == "-1" else rule["protocol"].upper()
    if rule["protocol"] in ("-1", "icmp") or rule["from_port"] is None:
        port = ""
    elif rule["from_port"] == rule["to_port"]:
        port = f" {rule['from_port']}"
    else:
        port = f" {rule['from_port']}-{rule['to_port']}"
    peer = rule.get("cidr") or rule.get("source_group") or "?"
    return f"{proto}{port} · {peer}"


def sg_rule_key(rule):
    return (rule["protocol"], rule.get("from_port"), rule.get("to_port"),
            rule.get("cidr"), rule.get("source_group"))


def port_matches(rule, protocol, port):
    if rule["protocol"] == "-1":
        return True
    if rule["protocol"] != protocol:
        return False
    if protocol == "icmp" or rule.get("from_port") is None:
        return True
    return rule["from_port"] <= port <= rule["to_port"]


# ---------------------------------------------------------------------------
# Network-ACL rules
# ---------------------------------------------------------------------------

def parse_nacl_rule(entry):
    """``100 allow tcp 443 0.0.0.0/0 ingress`` (legacy ``100 ALLOW ALL`` works)."""
    if isinstance(entry, dict):
        rule = dict(entry)
        rule["protocol"] = normalise_protocol(rule.get("protocol"))
        rule["action"] = str(rule.get("action", "allow")).lower()
        rule.setdefault("from_port", None)
        rule.setdefault("to_port", None)
        rule.setdefault("cidr", "0.0.0.0/0")
        rule["egress"] = bool(rule.get("egress"))
        return rule
    text = str(entry).strip()
    tokens = text.split()
    if not tokens:
        raise SimError("InvalidParameterValue", "Empty network ACL rule.")
    num = tokens[0]
    if num == "*":
        return None  # the implicit deny is always applied; never stored
    if not num.isdigit() or not 1 <= int(num) <= 32766:
        raise SimError("InvalidParameterValue",
                       f"Rule '{text}' must start with a rule number between 1 and 32766.")
    rest = tokens[1:]
    action = None
    proto = None
    ports = (None, None)
    cidr = "0.0.0.0/0"
    egress = False
    for tok in rest:
        up = tok.upper()
        if up in ("ALLOW", "DENY") and action is None:
            action = up.lower()
        elif up in ("INGRESS", "INBOUND", "IN"):
            egress = False
        elif up in ("EGRESS", "OUTBOUND", "OUT"):
            egress = True
        elif is_cidr(tok):
            cidr = str(ipaddress.ip_network(tok, strict=False))
        elif proto is None and up in PROTOCOLS:
            proto = PROTOCOLS[up]
        elif up in SERVICE_PORTS and proto is None:
            proto, p = SERVICE_PORTS[up]
            ports = (p, p)
        elif _ports(tok) is not False and proto not in (None, "-1"):
            ports = _ports(tok)
    if action is None:
        raise SimError("InvalidParameterValue", f"Rule '{text}' needs ALLOW or DENY.")
    proto = proto or "-1"
    if proto == "-1":
        ports = (None, None)
    return {"rule_number": int(num), "action": action, "protocol": proto,
            "from_port": ports[0], "to_port": ports[1], "cidr": cidr, "egress": egress}


def parse_nacl_rules(raw):
    items = loads_list(raw) if isinstance(raw, str) or raw is None else raw
    out = []
    for item in items:
        try:
            rule = parse_nacl_rule(item)
        except SimError:
            continue
        if rule:
            out.append(rule)
    return sorted(out, key=lambda r: (r["egress"], r["rule_number"]))


def nacl_rule_text(rule):
    proto = "ALL" if rule["protocol"] == "-1" else rule["protocol"].upper()
    port = ""
    if rule["protocol"] not in ("-1", "icmp") and rule["from_port"] is not None:
        port = f" {rule['from_port']}" if rule["from_port"] == rule["to_port"] else f" {rule['from_port']}-{rule['to_port']}"
    return f"{rule['rule_number']} {rule['action'].upper()} {proto}{port} {rule['cidr']} {'out' if rule['egress'] else 'in'}"


def nacl_decision(rules, egress, protocol, port, ip):
    """Evaluate NACL rules in rule-number order, like AWS. Returns
    ``(allowed, rule_or_None)`` — ``None`` means the implicit deny matched."""
    for rule in sorted((r for r in rules if r["egress"] == egress), key=lambda r: r["rule_number"]):
        if not cidr_contains(rule["cidr"], ip):
            continue
        if rule["protocol"] != "-1" and rule["protocol"] != protocol:
            continue
        if rule["protocol"] not in ("-1", "icmp") and rule["from_port"] is not None and protocol != "icmp":
            if not rule["from_port"] <= port <= rule["to_port"]:
                continue
        return rule["action"] == "allow", rule
    return False, None


def nacl_allows_range(rules, egress, protocol, lo, hi, ip):
    """True when every port in [lo, hi] is allowed (used for ephemeral return
    traffic). Checks the boundaries and each rule edge inside the range."""
    probes = {lo, hi}
    for r in rules:
        for p in (r.get("from_port"), r.get("to_port")):
            if p is not None and lo <= p <= hi:
                probes.update({p, max(lo, p - 1), min(hi, p + 1)})
    return all(nacl_decision(rules, egress, protocol, p, ip)[0] for p in probes)
