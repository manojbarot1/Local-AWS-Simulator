"""VPC console: networking resources, routing, security and the Reachability Analyzer."""

from __future__ import annotations

import json

from flask import Blueprint, render_template, request

import db
import netmodel
import reachability
import rules
from activity import cli, name_tag
from aws_fidelity import azs_for
from views import checked, console_tx, done, with_db

bp = Blueprint("network", __name__)


def _back(anchor):
    return lambda *a, **k: f"/network#{anchor}"


def _created(c, rid, label, anchor, command, action):
    return done(c, "ec2", action, rid, f"{label} {rid} created successfully.", command, f"/network?new={rid}#{anchor}")


@bp.route("/network")
@with_db
def network_home(c):
    vpc_names = {v["id"]: (v["name"] or v["vpc_id"]) for v in c.execute("SELECT id, name, vpc_id FROM vpcs")}
    subnets = []
    for s in c.execute("SELECT * FROM subnets ORDER BY vpc_id, id"):
        d = dict(s)
        rt, explicit = netmodel.effective_route_table(c, s)
        acl = netmodel.effective_nacl(c, s)
        d.update(vpc_name=vpc_names.get(s["vpc_id"]), public=netmodel.subnet_is_public(c, s),
                 rt_label=(rt["name"] or rt["route_table_id"]) if rt else "—", rt_explicit=explicit,
                 acl_label=(acl["name"] or acl["acl_id"]) if acl else "—",
                 free_ips=netmodel.available_ip_count(c, s))
        subnets.append(d)
    route_tables = []
    for r in c.execute("SELECT * FROM route_tables ORDER BY vpc_id, main_table DESC, id"):
        d = dict(r)
        d["vpc_name"] = vpc_names.get(r["vpc_id"])
        d["routes"] = [dict(x, status=netmodel.route_target_status(c, r["vpc_id"], x["target"])[0])
                       for x in rules.parse_routes(r["routes_json"])]
        d["routes_text"] = "\n".join(f"{x['destination']} -> {x['target']}" for x in d["routes"] if x["target"] != "local")
        d["subnets"] = [s["subnet_id"] for s in subnets if s["route_table_id"] == r["id"]]
        route_tables.append(d)
    sgs = []
    for g in c.execute("SELECT * FROM security_groups ORDER BY vpc_id, id"):
        d = dict(g)
        d["vpc_name"] = vpc_names.get(g["vpc_id"])
        d["inbound"] = rules.parse_sg_rules(g["inbound_json"])
        d["outbound"] = rules.parse_sg_rules(g["outbound_json"])
        d["inbound_text"] = [rules.sg_rule_text(x) for x in d["inbound"]]
        d["outbound_text"] = [rules.sg_rule_text(x) for x in d["outbound"]]
        d["inbound_edit"] = "\n".join(_sg_line(x) for x in d["inbound"])
        d["outbound_edit"] = "\n".join(_sg_line(x) for x in d["outbound"])
        sgs.append(d)
    acls = []
    for a in c.execute("SELECT * FROM network_acls ORDER BY vpc_id, is_default DESC, id"):
        d = dict(a)
        d["vpc_name"] = vpc_names.get(a["vpc_id"])
        parsed = rules.parse_nacl_rules(a["rules_json"])
        d["rules_text"] = [rules.nacl_rule_text(x) for x in parsed]
        d["rules_edit"] = "\n".join(_nacl_line(x) for x in parsed)
        d["subnets"] = [s["subnet_id"] for s in subnets if (s["network_acl_id"] == a["id"]) or
                        (a["is_default"] and not s["network_acl_id"] and s["vpc_id"] == a["vpc_id"])]
        acls.append(d)
    data = {
        "vpcs": [dict(r) for r in c.execute("SELECT * FROM vpcs ORDER BY is_default DESC, id DESC")],
        "subnets": subnets, "route_tables": route_tables, "sgs": sgs, "acls": acls,
        "igws": [dict(r) for r in c.execute("SELECT i.*,v.name vpc_name,v.vpc_id vpc_ref FROM internet_gateways i LEFT JOIN vpcs v ON v.id=i.vpc_id ORDER BY i.id DESC")],
        "nats": [dict(r) for r in c.execute("SELECT n.*,v.name vpc_name,s.name subnet_name,s.subnet_id subnet_ref,e.public_ip FROM nat_gateways n JOIN vpcs v ON v.id=n.vpc_id JOIN subnets s ON s.id=n.subnet_id LEFT JOIN elastic_ips e ON e.allocation_id=n.allocation_id ORDER BY n.id DESC")],
        "eips": [dict(r) for r in c.execute("SELECT * FROM elastic_ips ORDER BY id DESC")],
        "lbs": [dict(r) for r in c.execute("SELECT l.*,v.name vpc_name FROM load_balancers l LEFT JOIN vpcs v ON v.id=l.vpc_id ORDER BY l.id DESC")],
        "endpoints": [dict(r) for r in c.execute("SELECT e.*,v.name vpc_name FROM vpc_endpoints e JOIN vpcs v ON v.id=e.vpc_id ORDER BY e.id DESC")],
        "instances": [dict(r) for r in c.execute("SELECT instance_id, name FROM ec2_instances WHERE state!='terminated' ORDER BY id DESC")],
    }
    counts = {k: c.execute(f"SELECT COUNT(*) FROM {k}").fetchone()[0] for k in ("vpcs", "subnets", "route_tables", "security_groups")}
    return render_template("network.html", data=data, counts=counts, region=db.region(c), azs=azs_for(db.region(c)),
                           has_default=netmodel.default_vpc(c) is not None)


def _sg_line(r):
    peer = r.get("cidr") or r.get("source_group")
    if r["protocol"] == "-1":
        return f"all all {peer}"
    port = "" if r.get("from_port") is None else (str(r["from_port"]) if r["from_port"] == r["to_port"] else f"{r['from_port']}-{r['to_port']}")
    return f"{r['protocol']} {port} {peer}".replace("  ", " ")


def _nacl_line(r):
    port = ""
    if r["protocol"] not in ("-1", "icmp") and r.get("from_port") is not None:
        port = f" {r['from_port']}" if r["from_port"] == r["to_port"] else f" {r['from_port']}-{r['to_port']}"
    proto = "all" if r["protocol"] == "-1" else r["protocol"]
    return f"{r['rule_number']} {r['action']} {proto}{port} {r['cidr']} {'egress' if r['egress'] else 'ingress'}"


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

@bp.route("/network/vpc/create", methods=["POST"])
@console_tx(fail=_back("vpcs"))
def create_vpc(c):
    f = request.form
    name = f.get("name", "").strip()
    row = netmodel.create_vpc(c, f.get("cidr", ""), name, f.get("tenancy", "default"), checked("dns_support"),
                              checked("dns_hostnames"), f.get("account_id") or None)
    return _created(c, row["vpc_id"], "VPC", "vpcs",
                    cli("ec2 create-vpc", ("--cidr-block", row["cidr"]), name_tag("vpc", name)), "CreateVpc")


@bp.route("/network/vpc/create-default", methods=["POST"])
@console_tx(fail=_back("vpcs"))
def create_default_vpc(c):
    from errors import SimError
    if netmodel.default_vpc(c):
        raise SimError("DefaultVpcAlreadyExists", "A Default VPC already exists for this account in this region.")
    db.seed_default_vpc(c)
    vpc = netmodel.default_vpc(c)
    return _created(c, vpc["vpc_id"], "Default VPC", "vpcs", cli("ec2 create-default-vpc"), "CreateDefaultVpc")


@bp.route("/network/subnet/create", methods=["POST"])
@console_tx(fail=_back("subnets"))
def create_subnet(c):
    f = request.form
    vpc = netmodel.get(c, "vpc", f.get("vpc_id"))
    name = f.get("name", "").strip()
    row = netmodel.create_subnet(c, vpc, f.get("cidr", ""), name, f.get("az") or None, checked("map_public_ip"))
    command = cli("ec2 create-subnet", ("--vpc-id", vpc["vpc_id"]), ("--cidr-block", row["cidr"]),
                  ("--availability-zone", row["az"]), name_tag("subnet", name))
    if row["map_public_ip"]:
        command += f" && aws ec2 modify-subnet-attribute --subnet-id {row['subnet_id']} --map-public-ip-on-launch"
    return _created(c, row["subnet_id"], "Subnet", "subnets", command, "CreateSubnet")


@bp.route("/network/subnet/<int:sid>/settings", methods=["POST"])
@console_tx(fail=_back("subnets"))
def subnet_settings(c, sid):
    subnet = netmodel.get(c, "subnet", sid)
    f = request.form
    commands = []
    if "map_public_ip" in f:
        on = f.get("map_public_ip") == "1"
        netmodel.set_map_public_ip(c, subnet, on)
        commands.append(cli("ec2 modify-subnet-attribute", ("--subnet-id", subnet["subnet_id"]),
                            "--map-public-ip-on-launch" if on else "--no-map-public-ip-on-launch"))
    if "route_table_id" in f:
        rt_ref = f.get("route_table_id")
        if rt_ref == "main":
            if subnet["rt_assoc_id"]:
                commands.append(cli("ec2 disassociate-route-table", ("--association-id", subnet["rt_assoc_id"])))
                netmodel.disassociate_route_table(c, subnet["rt_assoc_id"])
        else:
            rt = netmodel.get(c, "rtb", rt_ref)
            netmodel.associate_route_table(c, rt, subnet)
            commands.append(cli("ec2 associate-route-table", ("--route-table-id", rt["route_table_id"]),
                                ("--subnet-id", subnet["subnet_id"])))
    if "network_acl_id" in f:
        acl = netmodel.get(c, "acl", f.get("network_acl_id"))
        netmodel.associate_nacl(c, acl, subnet)
        commands.append(cli("ec2 replace-network-acl-association", ("--association-id", "aclassoc-..."),
                            ("--network-acl-id", acl["acl_id"])))
    return done(c, "ec2", "ModifySubnet", subnet["subnet_id"], f"Subnet {subnet['subnet_id']} updated.",
                " && ".join(commands), f"/network?new={subnet['subnet_id']}#subnets")


@bp.route("/network/route-table/create", methods=["POST"])
@console_tx(fail=_back("route-tables"))
def create_route_table(c):
    f = request.form
    vpc = netmodel.get(c, "vpc", f.get("vpc_id"))
    name = f.get("name", "").strip()
    rt = netmodel.create_route_table(c, vpc, name)
    netmodel.set_routes_from_text(c, rt, f.get("routes", ""))
    commands = [cli("ec2 create-route-table", ("--vpc-id", vpc["vpc_id"]), name_tag("route-table", name))]
    for route in rules.parse_routes(netmodel.get(c, "rtb", rt["id"])["routes_json"]):
        if route["target"] != "local":
            flag = "--nat-gateway-id" if route["target"].startswith("nat-") else "--gateway-id"
            commands.append(cli("ec2 create-route", ("--route-table-id", rt["route_table_id"]),
                                ("--destination-cidr-block", route["destination"]), (flag, route["target"])))
    for sref in f.getlist("subnet_ids"):
        subnet = netmodel.get(c, "subnet", sref)
        netmodel.associate_route_table(c, rt, subnet)
        commands.append(cli("ec2 associate-route-table", ("--route-table-id", rt["route_table_id"]),
                            ("--subnet-id", subnet["subnet_id"])))
    return _created(c, rt["route_table_id"], "Route table", "route-tables", " && ".join(commands), "CreateRouteTable")


@bp.route("/network/route-table/<int:rid>/routes", methods=["POST"])
@console_tx(fail=_back("route-tables"))
def edit_routes(c, rid):
    rt = netmodel.get(c, "rtb", rid)
    netmodel.set_routes_from_text(c, rt, request.form.get("routes", ""))
    return done(c, "ec2", "ReplaceRoutes", rt["route_table_id"], f"Routes for {rt['route_table_id']} saved.",
                cli("ec2 create-route", ("--route-table-id", rt["route_table_id"]),
                    ("--destination-cidr-block", "0.0.0.0/0"), ("--gateway-id", "igw-...")),
                f"/network?new={rt['route_table_id']}#route-tables")


@bp.route("/network/igw/create", methods=["POST"])
@console_tx(fail=_back("internet-gateways"))
def create_igw(c):
    f = request.form
    name = f.get("name", "").strip()
    igw = netmodel.create_igw(c, name)
    commands = [cli("ec2 create-internet-gateway", name_tag("internet-gateway", name))]
    if f.get("vpc_id"):
        vpc = netmodel.get(c, "vpc", f.get("vpc_id"))
        netmodel.attach_igw(c, igw, vpc)
        commands.append(cli("ec2 attach-internet-gateway", ("--internet-gateway-id", igw["igw_id"]), ("--vpc-id", vpc["vpc_id"])))
    return _created(c, igw["igw_id"], "Internet gateway", "internet-gateways", " && ".join(commands), "CreateInternetGateway")


@bp.route("/network/igw/<int:gid>/<op>", methods=["POST"])
@console_tx(fail=_back("internet-gateways"))
def igw_attachment(c, gid, op):
    igw = netmodel.get(c, "igw", gid)
    if op == "attach":
        vpc = netmodel.get(c, "vpc", request.form.get("vpc_id"))
        netmodel.attach_igw(c, igw, vpc)
        command = cli("ec2 attach-internet-gateway", ("--internet-gateway-id", igw["igw_id"]), ("--vpc-id", vpc["vpc_id"]))
    else:
        vpc = netmodel.vpc_of(c, igw)
        netmodel.detach_igw(c, igw)
        command = cli("ec2 detach-internet-gateway", ("--internet-gateway-id", igw["igw_id"]),
                      ("--vpc-id", vpc["vpc_id"] if vpc else ""))
    return done(c, "ec2", "AttachInternetGateway" if op == "attach" else "DetachInternetGateway", igw["igw_id"],
                f"Internet gateway {igw['igw_id']} {op}ed.", command, "/network#internet-gateways")


@bp.route("/network/nat/create", methods=["POST"])
@console_tx(fail=_back("nat-gateways"))
def create_nat(c):
    f = request.form
    subnet = netmodel.get(c, "subnet", f.get("subnet_id"))
    name = f.get("name", "").strip()
    nat = netmodel.create_nat(c, subnet, name, f.get("connectivity_type", "public"), f.get("allocation_id", ""))
    command = cli("ec2 create-nat-gateway", ("--subnet-id", subnet["subnet_id"]),
                  ("--allocation-id", nat["allocation_id"] or None), name_tag("natgateway", name))
    if nat["connectivity_type"] == "public" and not f.get("allocation_id"):
        command = "aws ec2 allocate-address && " + command
    return _created(c, nat["nat_id"], "NAT gateway", "nat-gateways", command, "CreateNatGateway")


@bp.route("/network/security-group/create", methods=["POST"])
@console_tx(fail=_back("security-groups"))
def create_sg(c):
    f = request.form
    vpc = netmodel.get(c, "vpc", f.get("vpc_id"))
    inbound = [x.strip() for x in f.get("inbound", "").splitlines() if x.strip()]
    outbound = [x.strip() for x in f.get("outbound", "").splitlines() if x.strip()]
    sg = netmodel.create_sg(c, vpc, f.get("name", ""), f.get("description", "").strip(), inbound, outbound)
    commands = [cli("ec2 create-security-group", ("--group-name", sg["name"]),
                    ("--description", sg["description"]), ("--vpc-id", vpc["vpc_id"]))]
    for r in rules.parse_sg_rules(sg["inbound_json"]):
        commands.append(_authorize_cli(sg["group_id"], r))
    return _created(c, sg["group_id"], "Security group", "security-groups", " && ".join(commands), "CreateSecurityGroup")


def _authorize_cli(gid, r, direction="ingress"):
    args = [("--group-id", gid), ("--protocol", r["protocol"] if r["protocol"] != "-1" else "all")]
    if r.get("from_port") is not None:
        args.append(("--port", str(r["from_port"]) if r["from_port"] == r["to_port"] else f"{r['from_port']}-{r['to_port']}"))
    args.append(("--cidr", r["cidr"]) if r.get("cidr") else ("--source-group", r.get("source_group")))
    return cli(f"ec2 authorize-security-group-{direction}", *args)


@bp.route("/network/security-group/<int:gid>/rules", methods=["POST"])
@console_tx(fail=_back("security-groups"))
def edit_sg_rules(c, gid):
    sg = netmodel.get(c, "sg", gid)
    f = request.form
    inbound = [rules.parse_sg_rule(x) for x in f.get("inbound", "").splitlines() if x.strip()]
    outbound = [rules.parse_sg_rule(x) for x in f.get("outbound", "").splitlines() if x.strip()]
    c.execute("UPDATE security_groups SET inbound_json=?, outbound_json=? WHERE id=?",
              (json.dumps(inbound), json.dumps(outbound), sg["id"]))
    command = " && ".join(_authorize_cli(sg["group_id"], r) for r in inbound) or \
        cli("ec2 revoke-security-group-ingress", ("--group-id", sg["group_id"]), ("--ip-permissions", "..."))
    return done(c, "ec2", "ModifySecurityGroupRules", sg["group_id"], f"Rules for {sg['group_id']} saved.", command,
                f"/network?new={sg['group_id']}#security-groups")


@bp.route("/network/acl/create", methods=["POST"])
@console_tx(fail=_back("network-acls"))
def create_acl(c):
    f = request.form
    vpc = netmodel.get(c, "vpc", f.get("vpc_id"))
    name = f.get("name", "").strip()
    acl = netmodel.create_nacl(c, vpc, name, f.get("rules", "").splitlines())
    commands = [cli("ec2 create-network-acl", ("--vpc-id", vpc["vpc_id"]), name_tag("network-acl", name))]
    for r in rules.parse_nacl_rules(acl["rules_json"]):
        args = [("--network-acl-id", acl["acl_id"]), ("--rule-number", str(r["rule_number"])),
                ("--protocol", {"-1": "-1", "tcp": "6", "udp": "17", "icmp": "1"}.get(r["protocol"], "-1")),
                ("--rule-action", r["action"]), ("--cidr-block", r["cidr"]), "--egress" if r["egress"] else "--ingress"]
        if r.get("from_port") is not None:
            args.append(("--port-range", f"From={r['from_port']},To={r['to_port']}"))
        commands.append(cli("ec2 create-network-acl-entry", *args))
    for sref in f.getlist("subnet_ids"):
        netmodel.associate_nacl(c, acl, netmodel.get(c, "subnet", sref))
    return _created(c, acl["acl_id"], "Network ACL", "network-acls", " && ".join(commands), "CreateNetworkAcl")


@bp.route("/network/acl/<int:aid>/rules", methods=["POST"])
@console_tx(fail=_back("network-acls"))
def edit_acl_rules(c, aid):
    acl = netmodel.get(c, "acl", aid)
    parsed = [r for r in (rules.parse_nacl_rule(x) for x in request.form.get("rules", "").splitlines() if x.strip()) if r]
    c.execute("UPDATE network_acls SET rules_json=? WHERE id=?", (json.dumps(parsed), acl["id"]))
    return done(c, "ec2", "ReplaceNetworkAclEntries", acl["acl_id"], f"Rules for {acl['acl_id']} saved.",
                cli("ec2 replace-network-acl-entry", ("--network-acl-id", acl["acl_id"]), ("--rule-number", "100"), "..."),
                f"/network?new={acl['acl_id']}#network-acls")


@bp.route("/network/eip/create", methods=["POST"])
@console_tx(fail=_back("elastic-ips"))
def create_eip(c):
    f = request.form
    name = f.get("name", "").strip()
    eip = netmodel.allocate_eip(c, name)
    commands = [cli("ec2 allocate-address", ("--domain", "vpc"), name_tag("elastic-ip", name))]
    target = f.get("association", "").strip()
    if target:
        netmodel.associate_eip(c, eip, netmodel.get(c, "instance", target))
        commands.append(cli("ec2 associate-address", ("--allocation-id", eip["allocation_id"]), ("--instance-id", target)))
    return _created(c, eip["allocation_id"], "Elastic IP", "elastic-ips", " && ".join(commands), "AllocateAddress")


@bp.route("/network/eip/<int:eid>/disassociate", methods=["POST"])
@console_tx(fail=_back("elastic-ips"))
def disassociate_eip(c, eid):
    eip = netmodel.get(c, "eip", eid)
    if eip["association"].startswith("nat-"):
        from errors import SimError
        raise SimError("InvalidParameterValue", "This Elastic IP belongs to a NAT gateway; delete the NAT gateway instead.")
    netmodel.disassociate_eip(c, eip)
    return done(c, "ec2", "DisassociateAddress", eip["allocation_id"], f"{eip['public_ip']} disassociated.",
                cli("ec2 disassociate-address", ("--association-id", "eipassoc-...")), "/network#elastic-ips")


@bp.route("/network/lb/create", methods=["POST"])
@console_tx(fail=_back("load-balancers"))
def create_lb(c):
    from aws_fidelity import aws_id
    f = request.form
    name = f.get("name", "").strip()
    if not name:
        raise ValueError("Enter a load balancer name.")
    vpc = netmodel.get(c, "vpc", f.get("vpc_id")) if f.get("vpc_id") else None
    subnets = [netmodel.get(c, "subnet", s)["subnet_id"] for s in f.getlist("subnet_ids")]
    sgs = [netmodel.get(c, "sg", s)["group_id"] for s in f.getlist("security_group_ids")]
    rid = aws_id("lb")
    c.execute("INSERT INTO load_balancers(lb_id,name,lb_type,scheme,vpc_id,subnets_json,security_groups_json,state,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
              (rid, name, f.get("lb_type", "application"), f.get("scheme", "internet-facing"), vpc["id"] if vpc else None,
               json.dumps(subnets), json.dumps(sgs), "active", json.dumps({"Name": name}), db.now()))
    command = cli("elbv2 create-load-balancer", ("--name", name), ("--type", f.get("lb_type", "application")),
                  ("--scheme", f.get("scheme", "internet-facing")), ("--subnets", subnets or None),
                  ("--security-groups", sgs or None))
    return _created(c, rid, "Load balancer", "load-balancers", command, "CreateLoadBalancer")


@bp.route("/network/endpoint/create", methods=["POST"])
@console_tx(fail=_back("endpoints"))
def create_endpoint(c):
    from aws_fidelity import aws_id
    f = request.form
    vpc = netmodel.get(c, "vpc", f.get("vpc_id"))
    name, service = f.get("name", "").strip(), f.get("service_name", "").strip()
    if not service:
        raise ValueError("Enter the AWS service name, e.g. com.amazonaws.eu-central-1.s3")
    rid = aws_id("vpce")
    c.execute("INSERT INTO vpc_endpoints(endpoint_id,name,vpc_id,service_name,endpoint_type,route_tables_json,subnets_json,state,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
              (rid, name, vpc["id"], service, f.get("endpoint_type", "gateway"), "[]", "[]", "available",
               json.dumps({"Name": name}), db.now()))
    command = cli("ec2 create-vpc-endpoint", ("--vpc-id", vpc["vpc_id"]), ("--service-name", service),
                  ("--vpc-endpoint-type", f.get("endpoint_type", "gateway").title().replace("-", "")))
    return _created(c, rid, "VPC endpoint", "endpoints", command, "CreateVpcEndpoint")


# ---------------------------------------------------------------------------
# Delete (with AWS dependency rules)
# ---------------------------------------------------------------------------

DELETERS = {
    "vpc": ("vpc", netmodel.delete_vpc, "delete-vpc", "--vpc-id", "vpcs", "vpc_id"),
    "subnet": ("subnet", netmodel.delete_subnet, "delete-subnet", "--subnet-id", "subnets", "subnet_id"),
    "route-table": ("rtb", netmodel.delete_route_table, "delete-route-table", "--route-table-id", "route-tables", "route_table_id"),
    "igw": ("igw", netmodel.delete_igw, "delete-internet-gateway", "--internet-gateway-id", "internet-gateways", "igw_id"),
    "nat": ("nat", netmodel.delete_nat, "delete-nat-gateway", "--nat-gateway-id", "nat-gateways", "nat_id"),
    "security-group": ("sg", netmodel.delete_sg, "delete-security-group", "--group-id", "security-groups", "group_id"),
    "acl": ("acl", netmodel.delete_nacl, "delete-network-acl", "--network-acl-id", "network-acls", "acl_id"),
    "eip": ("eip", netmodel.release_eip, "release-address", "--allocation-id", "elastic-ips", "allocation_id"),
}


@bp.route("/network/delete/<resource>/<int:id>", methods=["POST"])
@console_tx(fail=lambda resource, id: f"/network#{DELETERS.get(resource, (0, 0, 0, 0, 'vpcs'))[4]}")
def delete_network_resource(c, resource, id):
    if resource in DELETERS:
        kind, fn, verb, flag, anchor, col = DELETERS[resource]
        row = netmodel.get(c, kind, id)
        fn(c, row)
        return done(c, "ec2", verb, row[col], f"{row[col]} deleted.", cli(f"ec2 {verb}", (flag, row[col])), f"/network#{anchor}")
    table = {"lb": ("load_balancers", "lb_id", "load-balancers"), "endpoint": ("vpc_endpoints", "endpoint_id", "endpoints")}.get(resource)
    if not table:
        raise ValueError(f"Unknown resource type {resource}")
    row = c.execute(f"SELECT * FROM {table[0]} WHERE id=?", (id,)).fetchone()
    if row:
        c.execute(f"DELETE FROM {table[0]} WHERE id=?", (id,))
        verb = "elbv2 delete-load-balancer" if resource == "lb" else "ec2 delete-vpc-endpoints"
        return done(c, "ec2", verb, row[table[1]], f"{row[table[1]]} deleted.", cli(verb, ("--id", row[table[1]])), f"/network#{table[2]}")
    return done(c, "ec2", "Delete", "", "Nothing to delete.", target=f"/network#{table[2]}")


# ---------------------------------------------------------------------------
# Reachability Analyzer
# ---------------------------------------------------------------------------

@bp.route("/network/reachability")
@with_db
def reachability_page(c):
    instances = [dict(r) for r in c.execute("SELECT instance_id, name, state, private_ip, public_ip FROM ec2_instances "
                                             "WHERE state!='terminated' ORDER BY id DESC")]
    args = request.args
    result = None
    error = None
    if args.get("source"):
        try:
            result = reachability.analyze(c, args["source"], args.get("destination", "internet"),
                                          args.get("protocol", "tcp"), int(args.get("port") or 443))
        except Exception as exc:   # noqa: BLE001 - show any analysis problem on the page
            error = getattr(exc, "message", str(exc))
    return render_template("reachability.html", instances=instances, result=result, error=error, args=args)
