"""
EC2 over the AWS Query protocol.

Form-encoded ``Action=...`` requests in, XML in the
``http://ec2.amazonaws.com/doc/2016-11-15/`` namespace out. Element names
follow the botocore EC2 model exactly (otherwise the SDK silently parses an
empty result). All behaviour — validation, dependency checks, lifecycle — lives
in ``netmodel`` / ``ec2model`` and is shared with the web console.
"""

from __future__ import annotations

import json

import db
import ec2model
import netmodel
import rules
from aws_fidelity import AMI_CATALOG, azs_for, REGIONS
from errors import SimError, not_found

from .common import (
    OWNER, el, iso, boolstr, truthy, tags_of, tag_set, indexed, indexed_structs, filters,
    tag_spec, match_filters, stable_id, ec2_response,
)


def _check_ids(kind, wanted, found_ids):
    missing = [w for w in wanted if w not in found_ids]
    if missing:
        raise not_found(kind, missing[0])


def _select(rows, id_key, ids, attrs_fn, supported, flt, kind):
    if ids:
        _check_ids(kind, ids, {r[id_key] for r in rows})
        rows = [r for r in rows if r[id_key] in ids]
    return [r for r in rows if match_filters(attrs_fn(r), flt, supported)]


def _vpc_str(c, row_id):
    v = c.execute("SELECT vpc_id FROM vpcs WHERE id=?", (row_id,)).fetchone() if row_id else None
    return v[0] if v else ""


def _plain_tags(r):
    """Tags without the synthetic Name (for resources whose name isn't a tag)."""
    try:
        return json.loads(r["tags_json"] or "{}")
    except ValueError:
        return {}


# ---------------------------------------------------------------------------
# VPCs
# ---------------------------------------------------------------------------

def _vpc_xml(r):
    return (el("vpcId", r["vpc_id"]) + "<state>available</state>" + el("cidrBlock", r["cidr"]) +
            "<dhcpOptionsId>dopt-00000000</dhcpOptionsId>" + el("instanceTenancy", r["tenancy"] or "default") +
            "<cidrBlockAssociationSet><item>" + el("associationId", "vpc-cidr-assoc-" + r["vpc_id"][4:]) +
            el("cidrBlock", r["cidr"]) + "<cidrBlockState><state>associated</state></cidrBlockState></item>"
            "</cidrBlockAssociationSet>" + el("isDefault", boolstr(r["is_default"])) + el("ownerId", OWNER) +
            tag_set(r))


VPC_FILTERS = {"vpc-id", "cidr", "cidr-block-association.cidr-block", "is-default", "state", "dhcp-options-id", "owner-id"}


def describe_vpcs(c, p):
    rows = _select(c.execute("SELECT * FROM vpcs ORDER BY id").fetchall(), "vpc_id", indexed(p, "VpcId"),
                   lambda r: {"vpc-id": r["vpc_id"], "cidr": r["cidr"], "cidr-block-association.cidr-block": r["cidr"],
                              "is-default": boolstr(r["is_default"]), "state": "available",
                              "dhcp-options-id": "dopt-00000000", "owner-id": OWNER, "tags": tags_of(r)},
                   VPC_FILTERS, filters(p), "vpc")
    return "<vpcSet>" + "".join(f"<item>{_vpc_xml(r)}</item>" for r in rows) + "</vpcSet>"


def create_vpc(c, p):
    tags = tag_spec(p, "vpc")
    if "CidrBlock" not in p:
        raise SimError("MissingParameter", "The request must contain the parameter CidrBlock")
    r = netmodel.create_vpc(c, p["CidrBlock"], tags.get("Name", ""), p.get("InstanceTenancy", "default"), tags=tags)
    return f"<vpc>{_vpc_xml(r)}</vpc>"


def create_default_vpc(c, p):
    if netmodel.default_vpc(c):
        raise SimError("DefaultVpcAlreadyExists", "A Default VPC already exists for this account in this region.")
    db.seed_default_vpc(c)
    return f"<vpc>{_vpc_xml(netmodel.default_vpc(c))}</vpc>"


def delete_vpc(c, p):
    netmodel.delete_vpc(c, netmodel.get(c, "vpc", p.get("VpcId")))
    return "<return>true</return>"


def modify_vpc_attribute(c, p):
    vpc = netmodel.get(c, "vpc", p.get("VpcId"))
    if "EnableDnsSupport.Value" in p:
        c.execute("UPDATE vpcs SET dns_support=? WHERE id=?", (int(truthy(p["EnableDnsSupport.Value"])), vpc["id"]))
    if "EnableDnsHostnames.Value" in p:
        c.execute("UPDATE vpcs SET dns_hostnames=? WHERE id=?", (int(truthy(p["EnableDnsHostnames.Value"])), vpc["id"]))
    return "<return>true</return>"


def describe_vpc_attribute(c, p):
    vpc = netmodel.get(c, "vpc", p.get("VpcId"))
    attr = p.get("Attribute", "")
    val = {"enableDnsSupport": vpc["dns_support"], "enableDnsHostnames": vpc["dns_hostnames"]}.get(attr)
    if val is None:
        raise SimError("InvalidParameterValue", f"Value ({attr}) for parameter attribute is invalid.")
    return el("vpcId", vpc["vpc_id"]) + f"<{attr}><value>{boolstr(val)}</value></{attr}>"


# ---------------------------------------------------------------------------
# Subnets
# ---------------------------------------------------------------------------

def _subnet_xml(c, r):
    return (el("subnetId", r["subnet_id"]) + "<state>available</state>" + el("vpcId", _vpc_str(c, r["vpc_id"])) +
            el("cidrBlock", r["cidr"]) + el("availableIpAddressCount", netmodel.available_ip_count(c, r)) +
            el("availabilityZone", r["az"]) + el("availabilityZoneId", f"{r['az'][:-1]}-az{ord(r['az'][-1]) - 96}") +
            el("defaultForAz", boolstr(r["default_for_az"])) + el("mapPublicIpOnLaunch", boolstr(r["map_public_ip"])) +
            el("ownerId", OWNER) + el("subnetArn", f"arn:aws:ec2:{db.region(c)}:{OWNER}:subnet/{r['subnet_id']}") +
            tag_set(r))


SUBNET_FILTERS = {"subnet-id", "vpc-id", "cidr-block", "cidr", "availability-zone", "default-for-az",
                  "map-public-ip-on-launch", "state"}


def describe_subnets(c, p):
    vpcs = {v["id"]: v["vpc_id"] for v in c.execute("SELECT id, vpc_id FROM vpcs")}
    rows = _select(c.execute("SELECT * FROM subnets ORDER BY id").fetchall(), "subnet_id", indexed(p, "SubnetId"),
                   lambda r: {"subnet-id": r["subnet_id"], "vpc-id": vpcs.get(r["vpc_id"]), "cidr-block": r["cidr"],
                              "cidr": r["cidr"], "availability-zone": r["az"],
                              "default-for-az": boolstr(r["default_for_az"]),
                              "map-public-ip-on-launch": boolstr(r["map_public_ip"]), "state": "available",
                              "tags": tags_of(r)},
                   SUBNET_FILTERS, filters(p), "subnet")
    return "<subnetSet>" + "".join(f"<item>{_subnet_xml(c, r)}</item>" for r in rows) + "</subnetSet>"


def create_subnet(c, p):
    vpc = netmodel.get(c, "vpc", p.get("VpcId"))
    tags = tag_spec(p, "subnet")
    r = netmodel.create_subnet(c, vpc, p.get("CidrBlock", ""), tags.get("Name", ""), p.get("AvailabilityZone"), tags=tags)
    return f"<subnet>{_subnet_xml(c, r)}</subnet>"


def delete_subnet(c, p):
    netmodel.delete_subnet(c, netmodel.get(c, "subnet", p.get("SubnetId")))
    return "<return>true</return>"


def modify_subnet_attribute(c, p):
    subnet = netmodel.get(c, "subnet", p.get("SubnetId"))
    if "MapPublicIpOnLaunch.Value" in p:
        netmodel.set_map_public_ip(c, subnet, truthy(p["MapPublicIpOnLaunch.Value"]))
    return "<return>true</return>"


# ---------------------------------------------------------------------------
# Instances
# ---------------------------------------------------------------------------

def _instance_xml(r, sg_names):
    cfg = ec2model.config(r)
    net = cfg.get("network", {})
    ami = cfg.get("ami") or next((a for a in AMI_CATALOG if a["id"] == r["ami_id"]), {})
    state = r["state"]
    groups = "".join(f"<item>{el('groupId', g)}{el('groupName', sg_names.get(g, ''))}</item>"
                     for g in (r["security_groups"] or "").split(",") if g)
    root = ami.get("root_device", "/dev/xvda")
    windows = (r["os"] or "").lower() == "windows"
    return (
        el("instanceId", r["instance_id"]) + el("imageId", r["ami_id"]) +
        f"<instanceState><code>{ec2model.STATE_CODES.get(state, 16)}</code>{el('name', state)}</instanceState>" +
        el("privateDnsName", net.get("private_dns", "")) +
        el("dnsName", net.get("public_dns", "") if r["public_ip"] else "") +
        (el("keyName", r["key_name"]) if r["key_name"] else "") +
        "<amiLaunchIndex>0</amiLaunchIndex>" + el("instanceType", r["instance_type"]) +
        el("launchTime", iso(r["created_at"])) +
        f"<placement>{el('availabilityZone', net.get('availability_zone', ''))}<groupName/>"
        f"{el('tenancy', cfg.get('tenancy', 'default'))}</placement>" +
        ("<platform>windows</platform>" if windows else "") +
        "<monitoring><state>disabled</state></monitoring>" +
        el("subnetId", r["subnet"] or "") + el("vpcId", r["vpc"] or "") +
        el("privateIpAddress", r["private_ip"] or "") +
        (el("ipAddress", r["public_ip"]) if r["public_ip"] else "") +
        f"<groupSet>{groups}</groupSet>" +
        el("architecture", r["architecture"] or "x86_64") + "<rootDeviceType>ebs</rootDeviceType>" +
        el("rootDeviceName", root) +
        f"<blockDeviceMapping><item>{el('deviceName', root)}<ebs>{el('volumeId', stable_id('vol', r['instance_id']))}"
        f"<status>attached</status>{el('attachTime', iso(r['created_at']))}<deleteOnTermination>true</deleteOnTermination>"
        f"</ebs></item></blockDeviceMapping>" +
        "<virtualizationType>hvm</virtualizationType><hypervisor>xen</hypervisor>" +
        el("platformDetails", "Windows" if windows else "Linux/UNIX") +
        f"<metadataOptions><state>applied</state>{el('httpTokens', cfg.get('metadata_http_tokens', 'required'))}"
        "<httpEndpoint>enabled</httpEndpoint></metadataOptions>" +
        tag_set(r)
    )


INSTANCE_FILTERS = {"instance-id", "instance-state-name", "instance-state-code", "instance-type", "vpc-id",
                    "subnet-id", "image-id", "private-ip-address", "ip-address", "availability-zone",
                    "instance.group-id", "key-name", "platform", "architecture"}


def _instance_attrs(r):
    cfg = ec2model.config(r)
    return {"instance-id": r["instance_id"], "instance-state-name": r["state"],
            "instance-state-code": ec2model.STATE_CODES.get(r["state"], 16), "instance-type": r["instance_type"],
            "vpc-id": r["vpc"], "subnet-id": r["subnet"], "image-id": r["ami_id"], "private-ip-address": r["private_ip"],
            "ip-address": r["public_ip"] or None, "availability-zone": cfg.get("network", {}).get("availability_zone"),
            "instance.group-id": [g for g in (r["security_groups"] or "").split(",") if g],
            "key-name": r["key_name"] or None, "platform": "windows" if (r["os"] or "").lower() == "windows" else None,
            "architecture": r["architecture"], "tags": tags_of(r)}


def _sg_names(c):
    return {g["group_id"]: g["name"] for g in c.execute("SELECT group_id, name FROM security_groups")}


def _instances(c, p):
    return _select(c.execute("SELECT * FROM ec2_instances ORDER BY id").fetchall(), "instance_id",
                   indexed(p, "InstanceId"), _instance_attrs, INSTANCE_FILTERS, filters(p), "instance")


def describe_instances(c, p):
    names = _sg_names(c)
    res = "".join(
        f"<item>{el('reservationId', stable_id('r', r['instance_id']))}{el('ownerId', OWNER)}<groupSet/>"
        f"<instancesSet><item>{_instance_xml(r, names)}</item></instancesSet></item>" for r in _instances(c, p))
    return f"<reservationSet>{res}</reservationSet>"


def describe_instance_status(c, p):
    rows = _instances(c, p)
    if not truthy(p.get("IncludeAllInstances", "false")):
        rows = [r for r in rows if r["state"] == "running"]
    items = ""
    for r in rows:
        az = ec2model.config(r).get("network", {}).get("availability_zone", "")
        ok = "ok" if r["state"] == "running" else "not-applicable"
        items += (f"<item>{el('instanceId', r['instance_id'])}{el('availabilityZone', az)}"
                  f"<instanceState><code>{ec2model.STATE_CODES.get(r['state'], 16)}</code>{el('name', r['state'])}</instanceState>"
                  f"<systemStatus><status>{ok}</status></systemStatus><instanceStatus><status>{ok}</status></instanceStatus></item>")
    return f"<instanceStatusSet>{items}</instanceStatusSet>"


def run_instances(c, p):
    tags = tag_spec(p, "instance")
    ni = indexed_structs(p, "NetworkInterface")
    first_ni = ni[0] if ni else {}
    subnet_ref = p.get("SubnetId") or first_ni.get("SubnetId")
    public = truthy(first_ni["AssociatePublicIpAddress"]) if "AssociatePublicIpAddress" in first_ni else None
    sg_refs = indexed(p, "SecurityGroupId") or [v for k, v in first_ni.items() if k.startswith("SecurityGroupId.")]
    for name in indexed(p, "SecurityGroup"):
        row = c.execute("SELECT group_id FROM security_groups WHERE name=?", (name,)).fetchone()
        if not row:
            raise SimError("InvalidGroup.NotFound", f"The security group '{name}' does not exist")
        sg_refs.append(row[0])
    try:
        count = int(p.get("MaxCount") or p.get("MinCount") or 1)
    except ValueError:
        raise SimError("InvalidParameterValue", "MaxCount must be an integer.")
    bdm = indexed_structs(p, "BlockDeviceMapping")
    first_bdm = bdm[0] if bdm else {}
    ids = ec2model.launch(
        c, name=tags.get("Name", ""), ami_id=p.get("ImageId", ""), instance_type=p.get("InstanceType", "m1.small"),
        count=count, subnet_ref=subnet_ref, sg_refs=sg_refs, key_name=p.get("KeyName", ""), public_ip=public,
        root_size=first_bdm.get("Ebs.VolumeSize"), root_type=first_bdm.get("Ebs.VolumeType") or "gp3",
        encrypted=truthy(first_bdm.get("Ebs.Encrypted", "true")), tags=tags, source="cli",
        extra_config={"termination_protection": truthy(p.get("DisableApiTermination", "false")),
                      "user_data": p.get("UserData", "")})
    names = _sg_names(c)
    items = "".join(f"<item>{_instance_xml(netmodel.get(c, 'instance', i), names)}</item>" for i in ids)
    return (el("reservationId", stable_id("r", ids[0])) + el("ownerId", OWNER) + "<groupSet/>" +
            f"<instancesSet>{items}</instancesSet>")


def _state_change(c, p, action):
    ids = indexed(p, "InstanceId")
    if not ids:
        raise SimError("MissingParameter", "The request must contain the parameter InstanceId")
    rows = [netmodel.get(c, "instance", i) for i in ids]   # all-or-nothing, like AWS
    items = ""
    for row in rows:
        prev, new = ec2model.change_state(c, row, action)
        items += (f"<item>{el('instanceId', row['instance_id'])}"
                  f"<currentState><code>{ec2model.STATE_CODES.get(new, 16)}</code>{el('name', new)}</currentState>"
                  f"<previousState><code>{ec2model.STATE_CODES.get(prev, 16)}</code>{el('name', prev)}</previousState></item>")
    return f"<instancesSet>{items}</instancesSet>"


def start_instances(c, p):
    return _state_change(c, p, "start")


def stop_instances(c, p):
    return _state_change(c, p, "stop")


def terminate_instances(c, p):
    return _state_change(c, p, "terminate")


def reboot_instances(c, p):
    _state_change(c, p, "reboot")
    return "<return>true</return>"


def modify_instance_attribute(c, p):
    inst = netmodel.get(c, "instance", p.get("InstanceId"))
    if "DisableApiTermination.Value" in p:
        ec2model.set_termination_protection(c, inst, truthy(p["DisableApiTermination.Value"]))
    return "<return>true</return>"


def describe_instance_attribute(c, p):
    inst = netmodel.get(c, "instance", p.get("InstanceId"))
    if p.get("Attribute") != "disableApiTermination":
        raise SimError("InvalidParameterValue", "The simulator supports only the disableApiTermination attribute.")
    val = ec2model.config(inst).get("termination_protection")
    return el("instanceId", inst["instance_id"]) + f"<disableApiTermination><value>{boolstr(val)}</value></disableApiTermination>"


# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

def _perm_xml(rule, own_id):
    proto = rule["protocol"]
    ports = ""
    if proto == "icmp":
        ports = "<fromPort>-1</fromPort><toPort>-1</toPort>"
    elif proto != "-1" and rule.get("from_port") is not None:
        ports = el("fromPort", rule["from_port"]) + el("toPort", rule["to_port"])
    groups = ""
    if rule.get("source_group"):
        gid = own_id if rule["source_group"] == "self" else rule["source_group"]
        groups = f"<item>{el('userId', OWNER)}{el('groupId', gid)}</item>"
    ranges = ""
    if rule.get("cidr"):
        desc = el("description", rule["description"]) if rule.get("description") else ""
        ranges = f"<item>{el('cidrIp', rule['cidr'])}{desc}</item>"
    return (f"<item>{el('ipProtocol', proto)}{ports}<groups>{groups}</groups><ipRanges>{ranges}</ipRanges>"
            "<ipv6Ranges/><prefixListIds/></item>")


def _sg_xml(c, r):
    inbound = rules.parse_sg_rules(r["inbound_json"])
    outbound = rules.parse_sg_rules(r["outbound_json"])
    tags = _plain_tags(r)
    tagxml = "<tagSet>" + "".join(f"<item>{el('key', k)}{el('value', v)}</item>" for k, v in tags.items()) + "</tagSet>" if tags else ""
    return (el("ownerId", OWNER) + el("groupId", r["group_id"]) + el("groupName", r["name"]) +
            el("groupDescription", r["description"] or "") + el("vpcId", _vpc_str(c, r["vpc_id"])) +
            "<ipPermissions>" + "".join(_perm_xml(rule, r["group_id"]) for rule in inbound) + "</ipPermissions>" +
            "<ipPermissionsEgress>" + "".join(_perm_xml(rule, r["group_id"]) for rule in outbound) + "</ipPermissionsEgress>" +
            tagxml)


SG_FILTERS = {"group-id", "group-name", "vpc-id", "description"}


def describe_security_groups(c, p):
    vpcs = {v["id"]: v["vpc_id"] for v in c.execute("SELECT id, vpc_id FROM vpcs")}
    rows = c.execute("SELECT * FROM security_groups ORDER BY id").fetchall()
    names = indexed(p, "GroupName")
    if names:
        _check_ids("sg", names, {r["name"] for r in rows})
        rows = [r for r in rows if r["name"] in names]
    rows = _select(rows, "group_id", indexed(p, "GroupId"),
                   lambda r: {"group-id": r["group_id"], "group-name": r["name"], "vpc-id": vpcs.get(r["vpc_id"]),
                              "description": r["description"], "tags": _plain_tags(r)},
                   SG_FILTERS, filters(p), "sg")
    return "<securityGroupInfo>" + "".join(f"<item>{_sg_xml(c, r)}</item>" for r in rows) + "</securityGroupInfo>"


def create_security_group(c, p):
    vpc = netmodel.get(c, "vpc", p["VpcId"]) if p.get("VpcId") else netmodel.default_vpc(c)
    if vpc is None:
        raise SimError("VPCIdNotSpecified", "No default VPC for this user")
    sg = netmodel.create_sg(c, vpc, p.get("GroupName", ""), p.get("GroupDescription", ""))
    c.execute("UPDATE security_groups SET tags_json=? WHERE id=?", (json.dumps(tag_spec(p, "security-group")), sg["id"]))
    return el("return", "true") + el("groupId", sg["group_id"])


def _find_sg(c, p):
    if p.get("GroupId"):
        return netmodel.get(c, "sg", p["GroupId"])
    row = c.execute("SELECT * FROM security_groups WHERE name=?", (p.get("GroupName", ""),)).fetchone()
    if not row:
        raise not_found("sg", p.get("GroupName", ""))
    return row


def delete_security_group(c, p):
    netmodel.delete_sg(c, _find_sg(c, p))
    return "<return>true</return>"


def _permissions(p):
    """IpPermissions.N.* (and the legacy flat IpProtocol/FromPort/ToPort/CidrIp)."""
    perms = indexed_structs(p, "IpPermissions")
    if not perms and p.get("IpProtocol"):
        perms = [{"IpProtocol": p["IpProtocol"], "FromPort": p.get("FromPort"), "ToPort": p.get("ToPort"),
                  "IpRanges.1.CidrIp": p.get("CidrIp")}]
    out = []
    for perm in perms:
        proto = rules.normalise_protocol(perm.get("IpProtocol", "-1"))
        lo, hi = perm.get("FromPort"), perm.get("ToPort")
        lo = None if lo in (None, "", "-1") or proto in ("-1", "icmp") else int(lo)
        hi = None if hi in (None, "", "-1") or proto in ("-1", "icmp") else int(hi)
        peers = [(v, perm.get(k.replace("CidrIp", "Description"), "")) for k, v in perm.items()
                 if k.startswith("IpRanges.") and k.endswith(".CidrIp") and v]
        # botocore serialises UserIdGroupPairs under its wire name "Groups".
        groups = [v for k, v in perm.items() if k.startswith(("Groups.", "UserIdGroupPairs.")) and k.endswith(".GroupId")]
        for cidr, desc in peers:
            out.append({"protocol": proto, "from_port": lo, "to_port": hi, "cidr": cidr, "source_group": None,
                        "description": desc})
        for g in groups:
            out.append({"protocol": proto, "from_port": lo, "to_port": hi, "cidr": None, "source_group": g,
                        "description": ""})
    if not out:
        raise SimError("MissingParameter", "No IP permissions were specified.")
    return out


def _sg_modify(direction, revoke):
    def handler(c, p):
        netmodel.modify_sg_rules(c, _find_sg(c, p), direction, _permissions(p), revoke=revoke)
        return "<return>true</return>"
    return handler


# ---------------------------------------------------------------------------
# Route tables
# ---------------------------------------------------------------------------

def _rt_xml(c, r):
    routes = ""
    for rt in rules.parse_routes(r["routes_json"]):
        status, _ = netmodel.route_target_status(c, r["vpc_id"], rt["target"])
        tgt = el("natGatewayId", rt["target"]) if rt["target"].startswith("nat-") else el("gatewayId", rt["target"])
        origin = "CreateRouteTable" if rt["target"] == "local" else "CreateRoute"
        routes += f"<item>{el('destinationCidrBlock', rt['destination'])}{tgt}{el('state', status)}{el('origin', origin)}</item>"
    assoc = ""
    if r["main_table"]:
        assoc += (f"<item>{el('routeTableAssociationId', stable_id('rtbassoc', r['route_table_id']))}"
                  f"{el('routeTableId', r['route_table_id'])}<main>true</main>"
                  "<associationState><state>associated</state></associationState></item>")
    for s in c.execute("SELECT subnet_id, rt_assoc_id FROM subnets WHERE route_table_id=?", (r["id"],)):
        assoc += (f"<item>{el('routeTableAssociationId', s['rt_assoc_id'])}{el('routeTableId', r['route_table_id'])}"
                  f"{el('subnetId', s['subnet_id'])}<main>false</main>"
                  "<associationState><state>associated</state></associationState></item>")
    return (el("routeTableId", r["route_table_id"]) + el("vpcId", _vpc_str(c, r["vpc_id"])) +
            f"<routeSet>{routes}</routeSet><associationSet>{assoc}</associationSet>" + el("ownerId", OWNER) + tag_set(r))


RT_FILTERS = {"route-table-id", "vpc-id", "association.main", "association.subnet-id", "route.gateway-id",
              "route.nat-gateway-id", "route.destination-cidr-block"}


def describe_route_tables(c, p):
    vpcs = {v["id"]: v["vpc_id"] for v in c.execute("SELECT id, vpc_id FROM vpcs")}

    def attrs(r):
        routes = rules.parse_routes(r["routes_json"])
        subs = [s[0] for s in c.execute("SELECT subnet_id FROM subnets WHERE route_table_id=?", (r["id"],))]
        return {"route-table-id": r["route_table_id"], "vpc-id": vpcs.get(r["vpc_id"]),
                "association.main": boolstr(r["main_table"]), "association.subnet-id": subs,
                "route.gateway-id": [rt["target"] for rt in routes if not rt["target"].startswith("nat-")],
                "route.nat-gateway-id": [rt["target"] for rt in routes if rt["target"].startswith("nat-")],
                "route.destination-cidr-block": [rt["destination"] for rt in routes], "tags": tags_of(r)}
    rows = _select(c.execute("SELECT * FROM route_tables ORDER BY id").fetchall(), "route_table_id",
                   indexed(p, "RouteTableId"), attrs, RT_FILTERS, filters(p), "rtb")
    return "<routeTableSet>" + "".join(f"<item>{_rt_xml(c, r)}</item>" for r in rows) + "</routeTableSet>"


def create_route_table(c, p):
    tags = tag_spec(p, "route-table")
    rt = netmodel.create_route_table(c, netmodel.get(c, "vpc", p.get("VpcId")), tags.get("Name", ""), tags)
    return f"<routeTable>{_rt_xml(c, rt)}</routeTable>"


def delete_route_table(c, p):
    netmodel.delete_route_table(c, netmodel.get(c, "rtb", p.get("RouteTableId")))
    return "<return>true</return>"


def _route_target(p):
    return p.get("GatewayId") or p.get("NatGatewayId") or p.get("VpcEndpointId") or ""


def create_route(c, p):
    netmodel.add_route(c, netmodel.get(c, "rtb", p.get("RouteTableId")), p.get("DestinationCidrBlock", ""), _route_target(p))
    return "<return>true</return>"


def replace_route(c, p):
    netmodel.replace_route(c, netmodel.get(c, "rtb", p.get("RouteTableId")), p.get("DestinationCidrBlock", ""), _route_target(p))
    return "<return>true</return>"


def delete_route(c, p):
    netmodel.delete_route(c, netmodel.get(c, "rtb", p.get("RouteTableId")), p.get("DestinationCidrBlock", ""))
    return "<return>true</return>"


def associate_route_table(c, p):
    assoc = netmodel.associate_route_table(c, netmodel.get(c, "rtb", p.get("RouteTableId")),
                                           netmodel.get(c, "subnet", p.get("SubnetId")))
    return el("associationId", assoc) + "<associationState><state>associated</state></associationState>"


def disassociate_route_table(c, p):
    netmodel.disassociate_route_table(c, p.get("AssociationId", ""))
    return "<return>true</return>"


# ---------------------------------------------------------------------------
# Internet & NAT gateways, Elastic IPs
# ---------------------------------------------------------------------------

def _igw_xml(c, r):
    att = (f"<attachmentSet><item>{el('vpcId', _vpc_str(c, r['vpc_id']))}<state>available</state></item></attachmentSet>"
           if r["vpc_id"] else "<attachmentSet/>")
    return el("internetGatewayId", r["igw_id"]) + el("ownerId", OWNER) + att + tag_set(r)


def describe_internet_gateways(c, p):
    rows = _select(c.execute("SELECT * FROM internet_gateways ORDER BY id").fetchall(), "igw_id",
                   indexed(p, "InternetGatewayId"),
                   lambda r: {"internet-gateway-id": r["igw_id"], "attachment.vpc-id": _vpc_str(c, r["vpc_id"]) or None,
                              "attachment.state": "available" if r["vpc_id"] else None, "tags": tags_of(r)},
                   {"internet-gateway-id", "attachment.vpc-id", "attachment.state"}, filters(p), "igw")
    return "<internetGatewaySet>" + "".join(f"<item>{_igw_xml(c, r)}</item>" for r in rows) + "</internetGatewaySet>"


def create_internet_gateway(c, p):
    tags = tag_spec(p, "internet-gateway")
    return f"<internetGateway>{_igw_xml(c, netmodel.create_igw(c, tags.get('Name', ''), tags))}</internetGateway>"


def attach_internet_gateway(c, p):
    netmodel.attach_igw(c, netmodel.get(c, "igw", p.get("InternetGatewayId")), netmodel.get(c, "vpc", p.get("VpcId")))
    return "<return>true</return>"


def detach_internet_gateway(c, p):
    netmodel.detach_igw(c, netmodel.get(c, "igw", p.get("InternetGatewayId")), netmodel.get(c, "vpc", p.get("VpcId")))
    return "<return>true</return>"


def delete_internet_gateway(c, p):
    netmodel.delete_igw(c, netmodel.get(c, "igw", p.get("InternetGatewayId")))
    return "<return>true</return>"


def _nat_subnet_str(c, r):
    sub = c.execute("SELECT subnet_id FROM subnets WHERE id=?", (r["subnet_id"],)).fetchone()
    return sub[0] if sub else ""


def _nat_xml(c, r):
    eip = c.execute("SELECT * FROM elastic_ips WHERE allocation_id=?", (r["allocation_id"] or "",)).fetchone()
    addr = ""
    if eip:
        addr = (f"<natGatewayAddressSet><item>{el('allocationId', eip['allocation_id'])}"
                f"{el('publicIp', eip['public_ip'])}</item></natGatewayAddressSet>")
    return (el("natGatewayId", r["nat_id"]) + el("vpcId", _vpc_str(c, r["vpc_id"])) + el("subnetId", _nat_subnet_str(c, r)) +
            el("state", r["state"]) + el("connectivityType", r["connectivity_type"]) + el("createTime", iso(r["created_at"])) +
            addr + tag_set(r))


def describe_nat_gateways(c, p):
    rows = _select(c.execute("SELECT * FROM nat_gateways ORDER BY id").fetchall(), "nat_id", indexed(p, "NatGatewayId"),
                   lambda r: {"nat-gateway-id": r["nat_id"], "vpc-id": _vpc_str(c, r["vpc_id"]), "state": r["state"],
                              "subnet-id": _nat_subnet_str(c, r), "tags": tags_of(r)},
                   {"nat-gateway-id", "vpc-id", "state", "subnet-id"}, filters(p), "nat")
    return "<natGatewaySet>" + "".join(f"<item>{_nat_xml(c, r)}</item>" for r in rows) + "</natGatewaySet>"


def create_nat_gateway(c, p):
    tags = tag_spec(p, "natgateway")
    nat = netmodel.create_nat(c, netmodel.get(c, "subnet", p.get("SubnetId")), tags.get("Name", ""),
                              p.get("ConnectivityType", "public"), p.get("AllocationId", ""), tags)
    return f"<natGateway>{_nat_xml(c, nat)}</natGateway>"


def delete_nat_gateway(c, p):
    nat = netmodel.get(c, "nat", p.get("NatGatewayId"))
    netmodel.delete_nat(c, nat)
    return el("natGatewayId", nat["nat_id"])


def describe_addresses(c, p):
    rows = c.execute("SELECT * FROM elastic_ips ORDER BY id").fetchall()
    ids = indexed(p, "AllocationId")
    if ids:
        _check_ids("eip", ids, {r["allocation_id"] for r in rows})
        rows = [r for r in rows if r["allocation_id"] in ids]
    items = ""
    for r in rows:
        assoc = r["association"] or ""
        items += (f"<item>{el('publicIp', r['public_ip'])}{el('allocationId', r['allocation_id'])}{el('domain', r['domain'])}"
                  + (el("instanceId", assoc) if assoc.startswith("i-") else "")
                  + (el("associationId", stable_id("eipassoc", r["allocation_id"])) if assoc else "")
                  + tag_set(r) + "</item>")
    return f"<addressesSet>{items}</addressesSet>"


def allocate_address(c, p):
    tags = tag_spec(p, "elastic-ip")
    e = netmodel.allocate_eip(c, tags.get("Name", ""), tags)
    return el("publicIp", e["public_ip"]) + el("allocationId", e["allocation_id"]) + "<domain>vpc</domain>"


def release_address(c, p):
    netmodel.release_eip(c, netmodel.get(c, "eip", p.get("AllocationId")))
    return "<return>true</return>"


def associate_address(c, p):
    eip = netmodel.get(c, "eip", p.get("AllocationId"))
    netmodel.associate_eip(c, eip, netmodel.get(c, "instance", p.get("InstanceId")))
    return "<return>true</return>" + el("associationId", stable_id("eipassoc", eip["allocation_id"]))


def disassociate_address(c, p):
    assoc = p.get("AssociationId", "")
    for e in c.execute("SELECT * FROM elastic_ips WHERE association!=''").fetchall():
        if stable_id("eipassoc", e["allocation_id"]) == assoc:
            netmodel.disassociate_eip(c, e)
            return "<return>true</return>"
    raise not_found("assoc", assoc)


# ---------------------------------------------------------------------------
# Network ACLs
# ---------------------------------------------------------------------------

def _nacl_xml(c, r):
    entries = ""
    for rule in rules.parse_nacl_rules(r["rules_json"]):
        ports = ""
        if rule["protocol"] not in ("-1", "icmp") and rule["from_port"] is not None:
            ports = f"<portRange>{el('from', rule['from_port'])}{el('to', rule['to_port'])}</portRange>"
        proto = {"tcp": "6", "udp": "17", "icmp": "1"}.get(rule["protocol"], "-1")
        entries += (f"<item>{el('ruleNumber', rule['rule_number'])}{el('protocol', proto)}{el('ruleAction', rule['action'])}"
                    f"{el('egress', boolstr(rule['egress']))}{el('cidrBlock', rule['cidr'])}{ports}</item>")
    for egress in ("false", "true"):
        entries += (f"<item><ruleNumber>32767</ruleNumber><protocol>-1</protocol><ruleAction>deny</ruleAction>"
                    f"<egress>{egress}</egress><cidrBlock>0.0.0.0/0</cidrBlock></item>")
    subs = c.execute("SELECT subnet_id FROM subnets WHERE vpc_id=? AND (network_acl_id=? OR (network_acl_id IS NULL AND ?=1))",
                     (r["vpc_id"], r["id"], r["is_default"])).fetchall()
    assoc = "".join(f"<item>{el('networkAclAssociationId', stable_id('aclassoc', s[0]))}{el('networkAclId', r['acl_id'])}"
                    f"{el('subnetId', s[0])}</item>" for s in subs)
    return (el("networkAclId", r["acl_id"]) + el("vpcId", _vpc_str(c, r["vpc_id"])) + el("default", boolstr(r["is_default"])) +
            f"<entrySet>{entries}</entrySet><associationSet>{assoc}</associationSet>" + el("ownerId", OWNER) + tag_set(r))


def describe_network_acls(c, p):
    rows = _select(c.execute("SELECT * FROM network_acls ORDER BY id").fetchall(), "acl_id", indexed(p, "NetworkAclId"),
                   lambda r: {"network-acl-id": r["acl_id"], "vpc-id": _vpc_str(c, r["vpc_id"]),
                              "default": boolstr(r["is_default"]), "tags": tags_of(r)},
                   {"network-acl-id", "vpc-id", "default"}, filters(p), "acl")
    return "<networkAclSet>" + "".join(f"<item>{_nacl_xml(c, r)}</item>" for r in rows) + "</networkAclSet>"


def create_network_acl(c, p):
    tags = tag_spec(p, "network-acl")
    acl = netmodel.create_nacl(c, netmodel.get(c, "vpc", p.get("VpcId")), tags.get("Name", ""), [], tags)
    return f"<networkAcl>{_nacl_xml(c, acl)}</networkAcl>"


def delete_network_acl(c, p):
    netmodel.delete_nacl(c, netmodel.get(c, "acl", p.get("NetworkAclId")))
    return "<return>true</return>"


def create_network_acl_entry(c, p):
    acl = netmodel.get(c, "acl", p.get("NetworkAclId"))
    current = rules.parse_nacl_rules(acl["rules_json"])
    egress = truthy(p.get("Egress", "false"))
    try:
        num = int(p.get("RuleNumber", "0"))
    except ValueError:
        raise SimError("InvalidParameterValue", "RuleNumber must be an integer.")
    if not 1 <= num <= 32766:
        raise SimError("InvalidParameterValue", "RuleNumber must be between 1 and 32766.")
    if any(r["rule_number"] == num and r["egress"] == egress for r in current):
        raise SimError("NetworkAclEntryAlreadyExists", f"The network acl entry identified by {num} already exists.")
    proto = rules.normalise_protocol(p.get("Protocol", "-1"))
    ported = proto not in ("-1", "icmp")
    rule = {"rule_number": num, "action": p.get("RuleAction", "allow").lower(), "protocol": proto,
            "from_port": int(p["PortRange.From"]) if ported and p.get("PortRange.From") else None,
            "to_port": int(p["PortRange.To"]) if ported and p.get("PortRange.To") else None,
            "cidr": p.get("CidrBlock", "0.0.0.0/0"), "egress": egress}
    c.execute("UPDATE network_acls SET rules_json=? WHERE id=?", (json.dumps(current + [rule]), acl["id"]))
    return "<return>true</return>"


def delete_network_acl_entry(c, p):
    acl = netmodel.get(c, "acl", p.get("NetworkAclId"))
    egress = truthy(p.get("Egress", "false"))
    num = int(p.get("RuleNumber", "0") or 0)
    current = rules.parse_nacl_rules(acl["rules_json"])
    keep = [r for r in current if not (r["rule_number"] == num and r["egress"] == egress)]
    if len(keep) == len(current):
        raise SimError("InvalidNetworkAclEntry.NotFound", f"The network acl entry identified by {num} does not exist.")
    c.execute("UPDATE network_acls SET rules_json=? WHERE id=?", (json.dumps(keep), acl["id"]))
    return "<return>true</return>"


def replace_network_acl_association(c, p):
    acl = netmodel.get(c, "acl", p.get("NetworkAclId"))
    assoc = p.get("AssociationId", "")
    for s in c.execute("SELECT * FROM subnets WHERE vpc_id=?", (acl["vpc_id"],)).fetchall():
        if stable_id("aclassoc", s["subnet_id"]) == assoc:
            netmodel.associate_nacl(c, acl, s)
            return el("newAssociationId", stable_id("aclassoc", s["subnet_id"]))
    raise not_found("assoc", assoc)


# ---------------------------------------------------------------------------
# Tags & catalogue lookups
# ---------------------------------------------------------------------------

_TAGGABLE = {"vpc-": ("vpcs", "vpc_id"), "subnet-": ("subnets", "subnet_id"), "i-": ("ec2_instances", "instance_id"),
             "sg-": ("security_groups", "group_id"), "rtb-": ("route_tables", "route_table_id"),
             "igw-": ("internet_gateways", "igw_id"), "nat-": ("nat_gateways", "nat_id"),
             "acl-": ("network_acls", "acl_id"), "eipalloc-": ("elastic_ips", "allocation_id"),
             "vpce-": ("vpc_endpoints", "endpoint_id")}


def _tag_target(c, rid):
    for prefix, (table, col) in _TAGGABLE.items():
        if rid.startswith(prefix):
            row = c.execute(f"SELECT id, tags_json FROM {table} WHERE {col}=?", (rid,)).fetchone()
            if row:
                return table, row
    raise SimError("InvalidID", f"The ID '{rid}' is not valid")


def _tags_param(p):
    return {t["Key"]: t.get("Value", "") for t in indexed_structs(p, "Tag") if "Key" in t}


def create_tags(c, p):
    new = _tags_param(p)
    for rid in indexed(p, "ResourceId"):
        table, row = _tag_target(c, rid)
        tags = json.loads(row["tags_json"] or "{}")
        tags.update(new)
        c.execute(f"UPDATE {table} SET tags_json=? WHERE id=?", (json.dumps(tags), row["id"]))
        if "Name" in new and table != "security_groups":
            c.execute(f"UPDATE {table} SET name=? WHERE id=?", (new["Name"], row["id"]))
    return "<return>true</return>"


def delete_tags(c, p):
    gone = _tags_param(p)
    for rid in indexed(p, "ResourceId"):
        table, row = _tag_target(c, rid)
        tags = {k: v for k, v in json.loads(row["tags_json"] or "{}").items() if k not in gone}
        c.execute(f"UPDATE {table} SET tags_json=? WHERE id=?", (json.dumps(tags), row["id"]))
        if "Name" in gone and table != "security_groups":
            c.execute(f"UPDATE {table} SET name='' WHERE id=?", (row["id"],))
    return "<return>true</return>"


def describe_images(c, p):
    ids = indexed(p, "ImageId")
    if ids:
        _check_ids("ami", ids, {a["id"] for a in AMI_CATALOG})
    flt = filters(p)
    images = [a for a in AMI_CATALOG if (not ids or a["id"] in ids) and match_filters(
        {"image-id": a["id"], "name": a["name"], "architecture": a["arch"],
         "platform": "windows" if a["os"] == "Windows" else None, "state": "available", "description": a["description"]},
        flt, {"image-id", "name", "architecture", "platform", "state", "description"})]
    items = "".join(
        "<item>" + el("imageId", a["id"]) + "<imageState>available</imageState>" + el("architecture", a["arch"]) +
        el("name", a["name"]) + el("description", a["description"]) + "<imageType>machine</imageType>" +
        el("rootDeviceName", a["root_device"]) + "<rootDeviceType>ebs</rootDeviceType>" +
        el("virtualizationType", a["virtualization"]) + el("imageOwnerId", OWNER) + "<isPublic>true</isPublic>" +
        ("<platform>windows</platform>" if a["os"] == "Windows" else "") +
        el("platformDetails", "Windows" if a["os"] == "Windows" else "Linux/UNIX") + "</item>"
        for a in images)
    return f"<imagesSet>{items}</imagesSet>"


def describe_availability_zones(c, p):
    region = db.region(c)
    items = "".join(f"<item>{el('zoneName', z)}<zoneState>available</zoneState>{el('regionName', region)}"
                    f"{el('zoneId', f'{region}-az{i + 1}')}<zoneType>availability-zone</zoneType></item>"
                    for i, z in enumerate(azs_for(region)))
    return f"<availabilityZoneInfo>{items}</availabilityZoneInfo>"


def describe_regions(c, p):
    items = "".join(f"<item>{el('regionName', r)}{el('regionEndpoint', f'ec2.{r}.amazonaws.com')}"
                    "<optInStatus>opt-in-not-required</optInStatus></item>" for r in REGIONS)
    return f"<regionInfo>{items}</regionInfo>"


ACTIONS = {
    "DescribeVpcs": describe_vpcs, "CreateVpc": create_vpc, "DeleteVpc": delete_vpc,
    "CreateDefaultVpc": create_default_vpc,
    "ModifyVpcAttribute": modify_vpc_attribute, "DescribeVpcAttribute": describe_vpc_attribute,
    "DescribeSubnets": describe_subnets, "CreateSubnet": create_subnet, "DeleteSubnet": delete_subnet,
    "ModifySubnetAttribute": modify_subnet_attribute,
    "DescribeInstances": describe_instances, "DescribeInstanceStatus": describe_instance_status,
    "RunInstances": run_instances, "StartInstances": start_instances, "StopInstances": stop_instances,
    "RebootInstances": reboot_instances, "TerminateInstances": terminate_instances,
    "ModifyInstanceAttribute": modify_instance_attribute, "DescribeInstanceAttribute": describe_instance_attribute,
    "DescribeSecurityGroups": describe_security_groups, "CreateSecurityGroup": create_security_group,
    "DeleteSecurityGroup": delete_security_group,
    "AuthorizeSecurityGroupIngress": _sg_modify("ingress", False), "AuthorizeSecurityGroupEgress": _sg_modify("egress", False),
    "RevokeSecurityGroupIngress": _sg_modify("ingress", True), "RevokeSecurityGroupEgress": _sg_modify("egress", True),
    "DescribeRouteTables": describe_route_tables, "CreateRouteTable": create_route_table,
    "DeleteRouteTable": delete_route_table, "CreateRoute": create_route, "ReplaceRoute": replace_route,
    "DeleteRoute": delete_route, "AssociateRouteTable": associate_route_table,
    "DisassociateRouteTable": disassociate_route_table,
    "DescribeInternetGateways": describe_internet_gateways, "CreateInternetGateway": create_internet_gateway,
    "AttachInternetGateway": attach_internet_gateway, "DetachInternetGateway": detach_internet_gateway,
    "DeleteInternetGateway": delete_internet_gateway,
    "DescribeNatGateways": describe_nat_gateways, "CreateNatGateway": create_nat_gateway,
    "DeleteNatGateway": delete_nat_gateway,
    "DescribeAddresses": describe_addresses, "AllocateAddress": allocate_address, "ReleaseAddress": release_address,
    "AssociateAddress": associate_address, "DisassociateAddress": disassociate_address,
    "DescribeNetworkAcls": describe_network_acls, "CreateNetworkAcl": create_network_acl,
    "DeleteNetworkAcl": delete_network_acl, "CreateNetworkAclEntry": create_network_acl_entry,
    "DeleteNetworkAclEntry": delete_network_acl_entry,
    "ReplaceNetworkAclAssociation": replace_network_acl_association,
    "CreateTags": create_tags, "DeleteTags": delete_tags,
    "DescribeImages": describe_images, "DescribeAvailabilityZones": describe_availability_zones,
    "DescribeRegions": describe_regions,
}


def handle(c, params):
    action = params.get("Action", "")
    fn = ACTIONS.get(action)
    if not fn:
        raise SimError("InvalidAction", f"The action '{action}' is not supported by this local simulator yet. "
                       f"Supported EC2 actions: {', '.join(sorted(ACTIONS))}.")
    return ec2_response(action, fn(c, params))
