"""
netmodel.py
===========

VPC networking behaviour shared by the web console and the AWS API endpoint.

Both front-ends call these functions, so a rule enforced here (CIDR ranges,
dependency violations, IGW attachment, route targets, security-group rules)
behaves identically whether a student clicks a button or runs ``aws ec2 ...``.
Functions never commit; the caller owns the transaction.
"""

from __future__ import annotations

import ipaddress
import json

import db
import rules
from aws_fidelity import aws_id, azs_for, random_public_ip, validate_block
from errors import SimError, not_found, dependency


# ---------------------------------------------------------------------------
# Lookups (accept an AWS id, e.g. "vpc-0abc", or an internal row id)
# ---------------------------------------------------------------------------

_LOOKUP = {
    "vpc": ("vpcs", "vpc_id"), "subnet": ("subnets", "subnet_id"),
    "rtb": ("route_tables", "route_table_id"), "igw": ("internet_gateways", "igw_id"),
    "nat": ("nat_gateways", "nat_id"), "sg": ("security_groups", "group_id"),
    "acl": ("network_acls", "acl_id"), "eip": ("elastic_ips", "allocation_id"),
    "instance": ("ec2_instances", "instance_id"),
}


def get(c, kind, ref, required=True):
    table, col = _LOOKUP[kind]
    ref = "" if ref is None else str(ref).strip()
    row = None
    if ref.isdigit():
        row = c.execute(f"SELECT * FROM {table} WHERE id=?", (int(ref),)).fetchone()
    elif ref:
        row = c.execute(f"SELECT * FROM {table} WHERE {col}=?", (ref,)).fetchone()
    if row is None and required:
        raise not_found(kind, ref or "(none)")
    return row


def vpc_of(c, row):
    return c.execute("SELECT * FROM vpcs WHERE id=?", (row["vpc_id"],)).fetchone() if row and row["vpc_id"] else None


def default_vpc(c):
    return c.execute("SELECT * FROM vpcs WHERE is_default=1 ORDER BY id LIMIT 1").fetchone()


def main_route_table(c, vpc_row_id):
    return c.execute("SELECT * FROM route_tables WHERE vpc_id=? AND main_table=1 ORDER BY id LIMIT 1",
                     (vpc_row_id,)).fetchone()


def default_sg(c, vpc_row_id):
    return c.execute("SELECT * FROM security_groups WHERE vpc_id=? AND name='default'", (vpc_row_id,)).fetchone()


def default_nacl(c, vpc_row_id):
    return c.execute("SELECT * FROM network_acls WHERE vpc_id=? AND is_default=1 ORDER BY id LIMIT 1",
                     (vpc_row_id,)).fetchone()


def _tags(name, extra=None):
    tags = dict(extra or {})
    if name:
        tags.setdefault("Name", name)
    return json.dumps(tags)


# ---------------------------------------------------------------------------
# VPCs & subnets
# ---------------------------------------------------------------------------

def create_vpc(c, cidr, name="", tenancy="default", dns_support=True, dns_hostnames=True,
               account_id=None, tags=None):
    net = validate_block(cidr, "vpc")
    if tenancy not in ("default", "dedicated"):
        raise SimError("InvalidParameterValue", f"Value ({tenancy}) for parameter instanceTenancy is invalid.")
    vid = aws_id("vpc")
    c.execute(
        "INSERT INTO vpcs(vpc_id,name,cidr,tenancy,dns_support,dns_hostnames,region,account_id,tags_json,created_at,is_default) VALUES(?,?,?,?,?,?,?,?,?,?,0)",
        (vid, name or "", str(net), tenancy, int(bool(dns_support)), int(bool(dns_hostnames)),
         db.region(c), account_id or None, _tags(name, tags), db.now()))
    row = get(c, "vpc", vid)
    db.ensure_vpc_defaults(c, row)
    return row


def create_subnet(c, vpc, cidr, name="", az=None, map_public_ip=False, tags=None):
    net = validate_block(cidr, "subnet")
    vnet = ipaddress.ip_network(vpc["cidr"])
    if not net.subnet_of(vnet):
        raise SimError("InvalidSubnet.Range", f"The CIDR '{cidr}' is invalid for the VPC {vpc['vpc_id']} "
                       f"({vpc['cidr']}): a subnet must sit inside its VPC's range.")
    for s in c.execute("SELECT subnet_id, cidr FROM subnets WHERE vpc_id=?", (vpc["id"],)):
        if net.overlaps(ipaddress.ip_network(s["cidr"])):
            raise SimError("InvalidSubnet.Conflict", f"The CIDR '{cidr}' conflicts with another subnet "
                           f"({s['subnet_id']} {s['cidr']}).")
    zones = azs_for(db.region(c))
    az = az or zones[0]
    if az not in zones:
        raise SimError("InvalidParameterValue", f"Value ({az}) for parameter availabilityZone is invalid. "
                       f"Subnets can currently only be created in: {', '.join(zones)}.")
    sid = aws_id("subnet")
    c.execute(
        "INSERT INTO subnets(subnet_id,name,vpc_id,cidr,az,public_ipv4,map_public_ip,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (sid, name or "", vpc["id"], str(net), az, int(bool(map_public_ip)), int(bool(map_public_ip)),
         _tags(name, tags), db.now()))
    return get(c, "subnet", sid)


def available_ip_count(c, subnet):
    net = ipaddress.ip_network(subnet["cidr"])
    used = c.execute("SELECT COUNT(*) FROM ec2_instances WHERE subnet=? AND state!='terminated'",
                     (subnet["subnet_id"],)).fetchone()[0]
    return max(0, net.num_addresses - 5 - used)


def set_map_public_ip(c, subnet, enabled):
    c.execute("UPDATE subnets SET map_public_ip=?, public_ipv4=? WHERE id=?",
              (int(bool(enabled)), int(bool(enabled)), subnet["id"]))


def delete_vpc(c, vpc):
    deps = []
    counts = [
        ("subnets", "SELECT COUNT(*) FROM subnets WHERE vpc_id=?"),
        ("internet gateways attached", "SELECT COUNT(*) FROM internet_gateways WHERE vpc_id=?"),
        ("NAT gateways", "SELECT COUNT(*) FROM nat_gateways WHERE vpc_id=?"),
        ("non-default security groups", "SELECT COUNT(*) FROM security_groups WHERE vpc_id=? AND name!='default'"),
        ("custom route tables", "SELECT COUNT(*) FROM route_tables WHERE vpc_id=? AND main_table=0"),
        ("custom network ACLs", "SELECT COUNT(*) FROM network_acls WHERE vpc_id=? AND is_default=0"),
        ("VPC endpoints", "SELECT COUNT(*) FROM vpc_endpoints WHERE vpc_id=?"),
        ("load balancers", "SELECT COUNT(*) FROM load_balancers WHERE vpc_id=?"),
    ]
    for label, sql in counts:
        n = c.execute(sql, (vpc["id"],)).fetchone()[0]
        if n:
            deps.append(f"{n} {label}")
    n = c.execute("SELECT COUNT(*) FROM ec2_instances WHERE vpc=? AND state!='terminated'",
                  (vpc["vpc_id"],)).fetchone()[0]
    if n:
        deps.append(f"{n} instances")
    if deps:
        raise dependency("vpc", vpc["vpc_id"], "delete first: " + ", ".join(deps))
    # AWS removes the VPC's own defaults along with it.
    for table in ("route_tables", "security_groups", "network_acls"):
        c.execute(f"DELETE FROM {table} WHERE vpc_id=?", (vpc["id"],))
    c.execute("DELETE FROM vpcs WHERE id=?", (vpc["id"],))


def delete_subnet(c, subnet):
    deps = []
    n = c.execute("SELECT COUNT(*) FROM ec2_instances WHERE subnet=? AND state!='terminated'",
                  (subnet["subnet_id"],)).fetchone()[0]
    if n:
        deps.append(f"{n} instances")
    n = c.execute("SELECT COUNT(*) FROM nat_gateways WHERE subnet_id=?", (subnet["id"],)).fetchone()[0]
    if n:
        deps.append(f"{n} NAT gateways")
    if deps:
        raise dependency("subnet", subnet["subnet_id"], "delete first: " + ", ".join(deps))
    c.execute("DELETE FROM subnets WHERE id=?", (subnet["id"],))


# ---------------------------------------------------------------------------
# Internet gateways
# ---------------------------------------------------------------------------

def create_igw(c, name="", tags=None):
    gid = aws_id("igw")
    c.execute("INSERT INTO internet_gateways(igw_id,name,vpc_id,state,tags_json,created_at) VALUES(?,?,?,?,?,?)",
              (gid, name or "", None, "available", _tags(name, tags), db.now()))
    return get(c, "igw", gid)


def attach_igw(c, igw, vpc):
    if igw["vpc_id"]:
        if igw["vpc_id"] == vpc["id"]:
            raise SimError("Resource.AlreadyAssociated",
                           f"resource {igw['igw_id']} is already attached to network {vpc['vpc_id']}")
        raise SimError("Resource.AlreadyAssociated", f"resource {igw['igw_id']} is already attached to another network")
    other = c.execute("SELECT igw_id FROM internet_gateways WHERE vpc_id=?", (vpc["id"],)).fetchone()
    if other:
        raise SimError("InvalidParameterValue",
                       f"Network {vpc['vpc_id']} already has an internet gateway attached ({other[0]}).")
    c.execute("UPDATE internet_gateways SET vpc_id=? WHERE id=?", (vpc["id"], igw["id"]))


def detach_igw(c, igw, vpc=None):
    if not igw["vpc_id"] or (vpc is not None and igw["vpc_id"] != vpc["id"]):
        raise SimError("Gateway.NotAttached",
                       f"resource {igw['igw_id']} is not attached to network {vpc['vpc_id'] if vpc else ''}".strip())
    c.execute("UPDATE internet_gateways SET vpc_id=NULL WHERE id=?", (igw["id"],))


def delete_igw(c, igw):
    if igw["vpc_id"]:
        raise dependency("internetGateway", igw["igw_id"], "detach it from its VPC first")
    c.execute("DELETE FROM internet_gateways WHERE id=?", (igw["id"],))


# ---------------------------------------------------------------------------
# Elastic IPs & NAT gateways
# ---------------------------------------------------------------------------

def allocate_eip(c, name="", tags=None):
    alloc = aws_id("eipalloc")
    c.execute(
        "INSERT INTO elastic_ips(allocation_id,name,public_ip,domain,association,state,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (alloc, name or "", random_public_ip(), "vpc", "", "allocated", _tags(name, tags), db.now()))
    return get(c, "eip", alloc)


def associate_eip(c, eip, instance):
    if eip["association"] and eip["association"] != instance["instance_id"]:
        raise SimError("Resource.AlreadyAssociated", f"{eip['allocation_id']} is already associated with {eip['association']}.")
    c.execute("UPDATE elastic_ips SET association=?, state='associated' WHERE id=?",
              (instance["instance_id"], eip["id"]))
    c.execute("UPDATE ec2_instances SET public_ip=? WHERE id=?", (eip["public_ip"], instance["id"]))


def disassociate_eip(c, eip):
    if eip["association"] and eip["association"].startswith("i-"):
        c.execute("UPDATE ec2_instances SET public_ip='' WHERE instance_id=? AND public_ip=?",
                  (eip["association"], eip["public_ip"]))
    c.execute("UPDATE elastic_ips SET association='', state='allocated' WHERE id=?", (eip["id"],))


def release_eip(c, eip):
    if eip["association"]:
        raise SimError("InvalidIPAddress.InUse",
                       f"Address {eip['public_ip']} is in use by {eip['association']}; disassociate it first.")
    c.execute("DELETE FROM elastic_ips WHERE id=?", (eip["id"],))


def create_nat(c, subnet, name="", connectivity="public", allocation_id="", tags=None):
    if connectivity not in ("public", "private"):
        raise SimError("InvalidParameterValue", f"Invalid connectivity type '{connectivity}'.")
    eip = None
    if connectivity == "public":
        if allocation_id:
            eip = get(c, "eip", allocation_id)
            if eip["association"]:
                raise SimError("Resource.AlreadyAssociated", f"Elastic IP {allocation_id} is already associated.")
        else:
            # The console's "Allocate Elastic IP" button: a public NAT always needs one.
            eip = allocate_eip(c, f"{name or 'nat'}-eip")
    nid = aws_id("nat")
    c.execute(
        "INSERT INTO nat_gateways(nat_id,name,vpc_id,subnet_id,connectivity_type,allocation_id,state,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (nid, name or "", subnet["vpc_id"], subnet["id"], connectivity, eip["allocation_id"] if eip else "",
         "available", _tags(name, tags), db.now()))
    if eip:
        c.execute("UPDATE elastic_ips SET association=?, state='associated' WHERE id=?", (nid, eip["id"]))
    return get(c, "nat", nid)


def delete_nat(c, nat):
    # Deleting a NAT gateway disassociates — but does not release — its Elastic
    # IP, which keeps costing money: a classic surprise on the bill.
    # Routes pointing at it stay behind as blackholes, exactly like AWS.
    c.execute("UPDATE elastic_ips SET association='', state='allocated' WHERE association=?", (nat["nat_id"],))
    c.execute("DELETE FROM nat_gateways WHERE id=?", (nat["id"],))


# ---------------------------------------------------------------------------
# Route tables
# ---------------------------------------------------------------------------

def create_route_table(c, vpc, name="", tags=None):
    rid = aws_id("rtb")
    c.execute(
        "INSERT INTO route_tables(route_table_id,name,vpc_id,routes_json,main_table,tags_json,created_at) VALUES(?,?,?,?,?,?,?)",
        (rid, name or "", vpc["id"], json.dumps([{"destination": vpc["cidr"], "target": "local"}]), 0,
         _tags(name, tags), db.now()))
    return get(c, "rtb", rid)


def resolve_target(c, vpc, target):
    """Map a console/CLI route target to a gateway id in this VPC. Accepts
    real ids, gateway names and the shorthands 'igw' / 'nat'."""
    t = (target or "").strip()
    low = t.lower()
    if low == "local":
        return "local"
    if low in ("igw", "internet", "internet-gateway"):
        row = c.execute("SELECT igw_id FROM internet_gateways WHERE vpc_id=?", (vpc["id"],)).fetchone()
        if not row:
            raise SimError("InvalidParameterValue", f"VPC {vpc['vpc_id']} has no internet gateway attached.")
        return row[0]
    if low in ("nat", "nat-gateway"):
        rows = c.execute("SELECT nat_id FROM nat_gateways WHERE vpc_id=?", (vpc["id"],)).fetchall()
        if len(rows) != 1:
            raise SimError("InvalidParameterValue",
                           f"VPC {vpc['vpc_id']} has {len(rows)} NAT gateways; name one explicitly (nat-...).")
        return rows[0][0]
    if t.startswith("igw-"):
        igw = get(c, "igw", t)
        if igw["vpc_id"] != vpc["id"]:
            raise SimError("InvalidParameterValue",
                           f"route table and network gateway {t} belong to different networks "
                           "(attach the internet gateway to this VPC first)")
        return t
    if t.startswith("nat-"):
        nat = get(c, "nat", t)
        if nat["vpc_id"] != vpc["id"]:
            raise SimError("InvalidParameterValue", f"NAT gateway {t} is in a different VPC.")
        return t
    if t.startswith("vpce-"):
        return t
    by_name = c.execute("SELECT igw_id FROM internet_gateways WHERE name=? AND vpc_id=?", (t, vpc["id"])).fetchone() \
        or c.execute("SELECT nat_id FROM nat_gateways WHERE name=? AND vpc_id=?", (t, vpc["id"])).fetchone()
    if by_name:
        return by_name[0]
    raise SimError("InvalidParameterValue", f"Unknown route target '{t}'. Use an igw-/nat- id, a gateway name, 'igw' or 'nat'.")


def add_route(c, rt, destination, target):
    vpc = vpc_of(c, rt)
    try:
        dest = str(ipaddress.IPv4Network(destination.strip(), strict=True))
    except (ValueError, AttributeError):
        raise SimError("InvalidParameterValue", f"Value ({destination}) for parameter destinationCidrBlock is invalid.")
    routes = rules.parse_routes(rt["routes_json"])
    if any(r["destination"] == dest for r in routes):
        raise SimError("RouteAlreadyExists", f"The route identified by {dest} already exists.")
    tid = resolve_target(c, vpc, target)
    if tid == "local":
        raise SimError("InvalidParameterValue", "The local route is created automatically with the VPC.")
    routes.append({"destination": dest, "target": tid})
    c.execute("UPDATE route_tables SET routes_json=? WHERE id=?", (json.dumps(routes), rt["id"]))


def replace_route(c, rt, destination, target):
    delete_route(c, rt, destination)
    add_route(c, get(c, "rtb", rt["id"]), destination, target)


def delete_route(c, rt, destination):
    routes = rules.parse_routes(rt["routes_json"])
    match = [r for r in routes if r["destination"] == (destination or "").strip()]
    if not match:
        raise SimError("InvalidRoute.NotFound", f"no route with destination-cidr-block {destination} in route table {rt['route_table_id']}")
    if match[0]["target"] == "local":
        raise SimError("InvalidParameterValue", f"cannot remove local route {destination} in route table {rt['route_table_id']}")
    routes = [r for r in routes if r["destination"] != destination.strip()]
    c.execute("UPDATE route_tables SET routes_json=? WHERE id=?", (json.dumps(routes), rt["id"]))


def set_routes_from_text(c, rt, text):
    """Console helper: replace all non-local routes from 'dest -> target' lines."""
    keep = [r for r in rules.parse_routes(rt["routes_json"]) if r["target"] == "local"]
    c.execute("UPDATE route_tables SET routes_json=? WHERE id=?", (json.dumps(keep), rt["id"]))
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        route = rules.parse_route(line)
        if route["target"].lower() == "local":
            continue
        add_route(c, get(c, "rtb", rt["id"]), route["destination"], route["target"])


def associate_route_table(c, rt, subnet):
    if subnet["vpc_id"] != rt["vpc_id"]:
        raise SimError("InvalidParameterValue", f"Route table {rt['route_table_id']} and subnet {subnet['subnet_id']} belong to different networks.")
    assoc = aws_id("rtbassoc")
    c.execute("UPDATE subnets SET route_table_id=?, rt_assoc_id=? WHERE id=?", (rt["id"], assoc, subnet["id"]))
    return assoc


def disassociate_route_table(c, assoc_id):
    row = c.execute("SELECT id FROM subnets WHERE rt_assoc_id=?", (assoc_id,)).fetchone()
    if not row:
        raise not_found("assoc", assoc_id)
    c.execute("UPDATE subnets SET route_table_id=NULL, rt_assoc_id=NULL WHERE id=?", (row["id"],))


def delete_route_table(c, rt):
    if rt["main_table"]:
        raise dependency("routeTable", rt["route_table_id"], "it is the VPC's main route table")
    n = c.execute("SELECT COUNT(*) FROM subnets WHERE route_table_id=?", (rt["id"],)).fetchone()[0]
    if n:
        raise dependency("routeTable", rt["route_table_id"], f"associated with {n} subnet(s)")
    c.execute("DELETE FROM route_tables WHERE id=?", (rt["id"],))


def effective_route_table(c, subnet):
    """The explicitly associated route table, else the VPC's main one."""
    if subnet["route_table_id"]:
        rt = c.execute("SELECT * FROM route_tables WHERE id=?", (subnet["route_table_id"],)).fetchone()
        if rt:
            return rt, True
    return main_route_table(c, subnet["vpc_id"]), False


def route_target_status(c, vpc_row_id, target):
    """('active'|'blackhole', description) for a route target."""
    if target == "local":
        return "active", "local"
    if target.startswith("igw-"):
        igw = c.execute("SELECT * FROM internet_gateways WHERE igw_id=?", (target,)).fetchone()
        if igw and igw["vpc_id"] == vpc_row_id:
            return "active", "internet gateway"
        return "blackhole", "internet gateway missing or detached"
    if target.startswith("nat-"):
        nat = c.execute("SELECT * FROM nat_gateways WHERE nat_id=?", (target,)).fetchone()
        if nat and nat["state"] == "available":
            return "active", "NAT gateway"
        return "blackhole", "NAT gateway deleted"
    if target.startswith("vpce-"):
        return "active", "VPC endpoint"
    return "blackhole", "unknown target"


def subnet_is_public(c, subnet):
    """AWS's definition: the subnet's route table sends 0.0.0.0/0 to an
    internet gateway attached to the VPC."""
    rt, _ = effective_route_table(c, subnet)
    if not rt:
        return False
    route = rules.longest_prefix_match(rules.parse_routes(rt["routes_json"]), "0.0.0.0")
    if not route or not route["target"].startswith("igw-"):
        return False
    return route_target_status(c, subnet["vpc_id"], route["target"])[0] == "active"


# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

def create_sg(c, vpc, name, description="", inbound=None, outbound=None, tags=None):
    name = (name or "").strip()
    if not name:
        raise SimError("MissingParameter", "The request must contain the parameter groupName.")
    if name.lower().startswith("sg-"):
        raise SimError("InvalidParameterValue", "Group names may not be in the format sg-*.")
    if c.execute("SELECT 1 FROM security_groups WHERE vpc_id=? AND name=?", (vpc["id"], name)).fetchone():
        raise SimError("InvalidGroup.Duplicate", f"The security group '{name}' already exists for VPC '{vpc['vpc_id']}'")
    inbound = [rules.parse_sg_rule(x) for x in (inbound or [])]
    # New groups allow all outbound traffic unless told otherwise, like AWS.
    outbound = [rules.parse_sg_rule(x) for x in outbound] if outbound is not None else \
        [rules.parse_sg_rule("ALL ALL 0.0.0.0/0")]
    gid = aws_id("sg")
    c.execute(
        "INSERT INTO security_groups(group_id,name,description,vpc_id,inbound_json,outbound_json,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (gid, name, description or name, vpc["id"], json.dumps(inbound), json.dumps(outbound),
         _tags(name, tags), db.now()))
    return get(c, "sg", gid)


def modify_sg_rules(c, sg, direction, new_rules, revoke=False):
    col = "inbound_json" if direction == "ingress" else "outbound_json"
    current = rules.parse_sg_rules(sg[col])
    keys = {rules.sg_rule_key(r) for r in current}
    for rule in new_rules:
        rule = rules.parse_sg_rule(rule)
        k = rules.sg_rule_key(rule)
        if revoke:
            if k not in keys:
                raise SimError("InvalidPermission.NotFound",
                               "The specified rule does not exist in this security group.")
            current = [r for r in current if rules.sg_rule_key(r) != k]
            keys.discard(k)
        else:
            if k in keys:
                raise SimError("InvalidPermission.Duplicate",
                               f"the specified rule \"{rules.sg_rule_text(rule)}\" already exists")
            current.append(rule)
            keys.add(k)
    c.execute(f"UPDATE security_groups SET {col}=? WHERE id=?", (json.dumps(current), sg["id"]))


def delete_sg(c, sg):
    if sg["name"] == "default":
        raise SimError("CannotDelete", f"the specified group: \"{sg['group_id']}\" name: \"default\" cannot be deleted by a user")
    in_use = c.execute("SELECT instance_id FROM ec2_instances WHERE state!='terminated' AND (','||security_groups||',') LIKE ?",
                       (f"%,{sg['group_id']},%",)).fetchone()
    if in_use:
        raise SimError("DependencyViolation", f"resource {sg['group_id']} has a dependent object ({in_use[0]})")
    c.execute("DELETE FROM security_groups WHERE id=?", (sg["id"],))


# ---------------------------------------------------------------------------
# Network ACLs
# ---------------------------------------------------------------------------

def create_nacl(c, vpc, name="", rule_lines=None, tags=None):
    parsed = [r for r in (rules.parse_nacl_rule(x) for x in (rule_lines or []) if str(x).strip()) if r]
    aid = aws_id("acl")
    c.execute(
        "INSERT INTO network_acls(acl_id,name,vpc_id,rules_json,is_default,tags_json,created_at) VALUES(?,?,?,?,?,?,?)",
        (aid, name or "", vpc["id"], json.dumps(parsed), 0, _tags(name, tags), db.now()))
    return get(c, "acl", aid)


def associate_nacl(c, acl, subnet):
    if subnet["vpc_id"] != acl["vpc_id"]:
        raise SimError("InvalidParameterValue", "Network ACL and subnet belong to different VPCs.")
    c.execute("UPDATE subnets SET network_acl_id=? WHERE id=?", (None if acl["is_default"] else acl["id"], subnet["id"]))


def effective_nacl(c, subnet):
    if subnet["network_acl_id"]:
        row = c.execute("SELECT * FROM network_acls WHERE id=?", (subnet["network_acl_id"],)).fetchone()
        if row:
            return row
    return default_nacl(c, subnet["vpc_id"])


def delete_nacl(c, acl):
    if acl["is_default"]:
        raise SimError("InvalidParameterValue", f"cannot delete default network ACL {acl['acl_id']}")
    n = c.execute("SELECT COUNT(*) FROM subnets WHERE network_acl_id=?", (acl["id"],)).fetchone()[0]
    if n:
        raise dependency("networkAcl", acl["acl_id"], f"associated with {n} subnet(s)")
    c.execute("DELETE FROM network_acls WHERE id=?", (acl["id"],))


# ---------------------------------------------------------------------------
# Instances' network placement
# ---------------------------------------------------------------------------

def instance_sgs(c, inst):
    ids = [x for x in (inst["security_groups"] or "").split(",") if x]
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    return c.execute(f"SELECT * FROM security_groups WHERE group_id IN ({marks})", ids).fetchall()


def instance_subnet(c, inst):
    return c.execute("SELECT * FROM subnets WHERE subnet_id=?", (inst["subnet"] or "",)).fetchone()


def placement(c, subnet_ref=None, sg_refs=None):
    """Resolve where an instance lands, applying AWS defaults: no subnet means
    the default VPC's first default subnet; no security group means the VPC's
    default group. Returns (subnet_row, vpc_row, [sg_rows])."""
    if subnet_ref:
        subnet = get(c, "subnet", subnet_ref)
    else:
        dv = default_vpc(c)
        subnet = c.execute("SELECT * FROM subnets WHERE vpc_id=? AND default_for_az=1 ORDER BY id LIMIT 1",
                           (dv["id"],)).fetchone() if dv else None
        if subnet is None:
            raise SimError("VPCIdNotSpecified", "No default VPC for this user. Specify a subnet.")
    vpc = vpc_of(c, subnet)
    sgs = [get(c, "sg", ref) for ref in (sg_refs or []) if ref]
    for sg in sgs:
        if sg["vpc_id"] != vpc["id"]:
            raise SimError("InvalidParameter",
                           f"Security group {sg['group_id']} and subnet {subnet['subnet_id']} belong to different networks.")
    if not sgs:
        sgs = [default_sg(c, vpc["id"])]
    return subnet, vpc, sgs
