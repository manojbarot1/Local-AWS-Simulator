"""
reachability.py
===============

"Why can't my instance reach the internet?" — a small Reachability Analyzer.

It walks the same components a packet crosses in a real VPC and reports each
hop: instance state, security groups (stateful), network ACLs (stateless, so
return traffic on ephemeral ports is checked too), the subnet's effective route
table (longest-prefix match), and the gateway the route points at (an internet
gateway needs a public IP on the instance; a NAT gateway needs a public subnet
of its own).
"""

from __future__ import annotations

import netmodel
import rules

INTERNET_IP = "93.184.216.34"   # stands in for "some host on the internet"
EPHEMERAL = (1024, 65535)


def _hop(component, ok, detail, rid=""):
    return {"component": component, "ok": bool(ok), "detail": detail, "id": rid}


def _sg_allows(sgs, direction, protocol, port, peer_ip, peer_sg_ids=()):
    col = "inbound_json" if direction == "ingress" else "outbound_json"
    for sg in sgs:
        for rule in rules.parse_sg_rules(sg[col]):
            if not rules.port_matches(rule, protocol, port):
                continue
            if rule.get("cidr") and rules.cidr_contains(rule["cidr"], peer_ip):
                return True, sg, rule
            group = rule.get("source_group")
            if group == "self" and sg["group_id"] in peer_sg_ids:
                return True, sg, rule
            if group and group in peer_sg_ids:
                return True, sg, rule
    return False, None, None


def _sg_hop(sgs, direction, protocol, port, peer_ip, peer_label, peer_sg_ids=()):
    names = ", ".join(s["group_id"] for s in sgs) or "none"
    ok, sg, rule = _sg_allows(sgs, direction, protocol, port, peer_ip, peer_sg_ids)
    what = "Security groups (outbound)" if direction == "egress" else "Security groups (inbound)"
    if ok:
        return _hop(what, True, f"{sg['group_id']} allows {rules.sg_rule_text(rule)}.", names)
    verb = "to" if direction == "egress" else "from"
    return _hop(what, False, f"No rule in [{names}] allows {protocol.upper()} {port} {verb} {peer_label}. "
                f"Add an {'outbound' if direction == 'egress' else 'inbound'} rule.", names)


def _nacl_hop(c, subnet, egress, protocol, port, peer_ip, peer_label):
    acl = netmodel.effective_nacl(c, subnet)
    acl_rules = rules.parse_nacl_rules(acl["rules_json"]) if acl else []
    allowed, rule = rules.nacl_decision(acl_rules, egress, protocol, port, peer_ip)
    label = f"Network ACL {'outbound' if egress else 'inbound'}"
    rid = acl["acl_id"] if acl else ""
    if allowed:
        return _hop(label, True, f"Rule {rule['rule_number']} ({rules.nacl_rule_text(rule)}) allows it.", rid)
    why = f"rule {rule['rule_number']} denies it" if rule else "no rule matches, so the implicit * DENY applies"
    return _hop(label, False, f"{protocol.upper()} {port} {'to' if egress else 'from'} {peer_label}: {why}.", rid)


def _nacl_return_hop(c, subnet, egress, protocol, peer_ip, peer_label):
    acl = netmodel.effective_nacl(c, subnet)
    acl_rules = rules.parse_nacl_rules(acl["rules_json"]) if acl else []
    label = f"Network ACL {'outbound' if egress else 'inbound'} (return traffic)"
    rid = acl["acl_id"] if acl else ""
    if protocol == "icmp" or rules.nacl_allows_range(acl_rules, egress, protocol, *EPHEMERAL, peer_ip):
        return _hop(label, True, f"Ephemeral ports 1024-65535 {'to' if egress else 'from'} {peer_label} are allowed.", rid)
    return _hop(label, False, "NACLs are stateless: replies use ephemeral ports 1024-65535, and this NACL "
                f"does not allow them {'to' if egress else 'from'} {peer_label}.", rid)


def _instance_hop(inst):
    running = inst["state"] == "running"
    return _hop("Instance", running, f"{inst['instance_id']} is {inst['state']}." +
                ("" if running else " Only running instances send or receive traffic."), inst["instance_id"])


def _route_to_internet(c, subnet, from_nat=False):
    """Hops for a subnet's path to 0.0.0.0/0. Returns (hops, kind) where kind is
    'igw', 'nat' or None."""
    rt, explicit = netmodel.effective_route_table(c, subnet)
    how = "explicitly associated" if explicit else "the VPC's main route table (no explicit association)"
    route = rules.longest_prefix_match(rules.parse_routes(rt["routes_json"]), INTERNET_IP) if rt else None
    prefix = "NAT subnet route" if from_nat else "Route table"
    rid = rt["route_table_id"] if rt else ""
    if not route or route["target"] == "local":
        return [_hop(prefix, False, f"{rid} ({how}) has no route for internet destinations. "
                     "Add 0.0.0.0/0 → an internet gateway (public subnet) or NAT gateway (private subnet).", rid)], None
    status, desc = netmodel.route_target_status(c, subnet["vpc_id"], route["target"])
    if status != "active":
        return [_hop(prefix, False, f"{rid}: route {rules.route_text(route)} is a blackhole ({desc}).", rid)], None
    hops = [_hop(prefix, True, f"{rid} ({how}) sends {route['destination']} → {route['target']} ({desc}).", rid)]
    if route["target"].startswith("igw-"):
        return hops, "igw"
    if route["target"].startswith("nat-"):
        return hops, "nat"
    return hops + [_hop("Gateway", False, f"{route['target']} does not lead to the internet.", route["target"])], None


def _nat_hops(c, nat_id):
    nat = c.execute("SELECT * FROM nat_gateways WHERE nat_id=?", (nat_id,)).fetchone()
    hops = []
    if nat["connectivity_type"] != "public":
        return [_hop("NAT gateway", False, f"{nat_id} is a private NAT gateway; it cannot reach the internet.", nat_id)]
    if not nat["allocation_id"]:
        return [_hop("NAT gateway", False, f"{nat_id} has no Elastic IP.", nat_id)]
    hops.append(_hop("NAT gateway", True, f"{nat_id} is available with Elastic IP {nat['allocation_id']}.", nat_id))
    nat_subnet = c.execute("SELECT * FROM subnets WHERE id=?", (nat["subnet_id"],)).fetchone()
    sub_hops, kind = _route_to_internet(c, nat_subnet, from_nat=True)
    hops += sub_hops
    if kind == "igw":
        hops.append(_hop("Internet gateway", True, f"The NAT gateway's subnet {nat_subnet['subnet_id']} is public.",
                         nat_subnet["subnet_id"]))
    elif kind == "nat":
        hops.append(_hop("NAT gateway", False, "The NAT gateway sits in a subnet that routes to another NAT gateway; "
                         "NAT gateways must live in a public subnet.", nat_id))
    else:
        hops.append(_hop("NAT gateway placement", False, "NAT gateways must be created in a public subnet "
                         "(one whose route table sends 0.0.0.0/0 to an internet gateway).", nat_subnet["subnet_id"]))
    return hops


def analyze(c, source_id, destination, protocol="tcp", port=443):
    """``destination`` is 'internet', 'from-internet' or an instance id."""
    protocol = rules.normalise_protocol(protocol)
    port = int(port or 0)
    src = netmodel.get(c, "instance", source_id)
    if destination == "from-internet":
        return _inbound_from_internet(c, src, protocol, port)
    if destination == "internet":
        return _outbound_to_internet(c, src, protocol, port)
    dst = netmodel.get(c, "instance", destination)
    return _instance_to_instance(c, src, dst, protocol, port)


def _finish(hops, title):
    ok = all(h["ok"] for h in hops)
    first_bad = next((h for h in hops if not h["ok"]), None)
    return {"reachable": ok, "title": title, "hops": hops,
            "summary": "Reachable ✓ — every hop allows the traffic." if ok
            else f"Not reachable — blocked at: {first_bad['component']}."}


def _outbound_to_internet(c, inst, protocol, port):
    title = f"{inst['instance_id']} → internet ({protocol.upper()} {port})"
    hops = [_instance_hop(inst)]
    subnet = netmodel.instance_subnet(c, inst)
    if not subnet:
        return _finish(hops + [_hop("Subnet", False, "The instance has no subnet.")], title)
    sgs = netmodel.instance_sgs(c, inst)
    hops.append(_sg_hop(sgs, "egress", protocol, port, INTERNET_IP, "the internet"))
    hops.append(_nacl_hop(c, subnet, True, protocol, port, INTERNET_IP, "the internet"))
    route_hops, kind = _route_to_internet(c, subnet)
    hops += route_hops
    if kind == "igw":
        if inst["public_ip"]:
            hops.append(_hop("Internet gateway", True, f"Translates private {inst['private_ip']} ↔ public {inst['public_ip']}."))
        else:
            hops.append(_hop("Public IPv4", False, "The instance has no public IPv4 address, so the internet gateway "
                             "cannot translate its traffic. Either enable auto-assign public IP / attach an Elastic IP, "
                             "or put it in a private subnet that routes through a NAT gateway."))
    elif kind == "nat":
        target = rules.longest_prefix_match(
            rules.parse_routes(netmodel.effective_route_table(c, subnet)[0]["routes_json"]), INTERNET_IP)["target"]
        hops += _nat_hops(c, target)
    hops.append(_nacl_return_hop(c, subnet, False, protocol, INTERNET_IP, "the internet"))
    return _finish(hops, title)


def _inbound_from_internet(c, inst, protocol, port):
    title = f"internet → {inst['instance_id']} ({protocol.upper()} {port})"
    hops = [_instance_hop(inst)]
    subnet = netmodel.instance_subnet(c, inst)
    if not subnet:
        return _finish(hops + [_hop("Subnet", False, "The instance has no subnet.")], title)
    if inst["public_ip"]:
        hops.append(_hop("Public IPv4", True, f"{inst['public_ip']} is mapped to {inst['private_ip']}."))
    else:
        hops.append(_hop("Public IPv4", False, "No public IPv4 address — nothing on the internet can address this "
                         "instance. Put a load balancer in front of it, or give it an Elastic IP in a public subnet."))
    route_hops, kind = _route_to_internet(c, subnet)
    if kind == "nat":
        route_hops.append(_hop("Inbound path", False, "The subnet routes internet traffic through a NAT gateway; NAT "
                               "only allows connections that start inside the VPC. This is a private subnet."))
    elif kind == "igw":
        route_hops[-1]["detail"] += " Replies can leave through the internet gateway."
    hops += route_hops
    hops.append(_nacl_hop(c, subnet, False, protocol, port, INTERNET_IP, "the internet"))
    hops.append(_sg_hop(netmodel.instance_sgs(c, inst), "ingress", protocol, port, INTERNET_IP, "0.0.0.0/0"))
    hops.append(_nacl_return_hop(c, subnet, True, protocol, INTERNET_IP, "the internet"))
    return _finish(hops, title)


def _instance_to_instance(c, src, dst, protocol, port):
    title = f"{src['instance_id']} → {dst['instance_id']} ({protocol.upper()} {port})"
    hops = [_instance_hop(src), _instance_hop(dst)]
    s_sub, d_sub = netmodel.instance_subnet(c, src), netmodel.instance_subnet(c, dst)
    if not s_sub or not d_sub:
        return _finish(hops + [_hop("Subnet", False, "Both instances need a subnet.")], title)
    if s_sub["vpc_id"] != d_sub["vpc_id"]:
        return _finish(hops + [_hop("Routing", False, "The instances are in different VPCs. Without VPC peering or a "
                                    "transit gateway there is no route between them.")], title)
    rt, _ = netmodel.effective_route_table(c, s_sub)
    route = rules.longest_prefix_match(rules.parse_routes(rt["routes_json"]), dst["private_ip"])
    hops.append(_hop("Route table", bool(route and route["target"] == "local"),
                     f"{dst['private_ip']} matches the local route {route['destination']} — delivered inside the VPC."
                     if route and route["target"] == "local" else "No local route matches the destination.",
                     rt["route_table_id"]))
    src_sgs, dst_sgs = netmodel.instance_sgs(c, src), netmodel.instance_sgs(c, dst)
    hops.append(_sg_hop(src_sgs, "egress", protocol, port, dst["private_ip"], dst["private_ip"],
                        [s["group_id"] for s in dst_sgs]))
    same_subnet = s_sub["id"] == d_sub["id"]
    if not same_subnet:
        hops.append(_nacl_hop(c, s_sub, True, protocol, port, dst["private_ip"], dst["private_ip"]))
        hops.append(_nacl_hop(c, d_sub, False, protocol, port, src["private_ip"], src["private_ip"]))
    hops.append(_sg_hop(dst_sgs, "ingress", protocol, port, src["private_ip"], src["private_ip"],
                        [s["group_id"] for s in src_sgs]))
    if not same_subnet:
        hops.append(_nacl_return_hop(c, d_sub, True, protocol, src["private_ip"], src["private_ip"]))
        hops.append(_nacl_return_hop(c, s_sub, False, protocol, dst["private_ip"], dst["private_ip"]))
    else:
        hops.append(_hop("Network ACLs", True, "Same subnet — traffic never crosses a network ACL boundary."))
    return _finish(hops, title)
