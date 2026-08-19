"""
aws_api.py
==========

An AWS Query-protocol (EC2) endpoint so the real ``aws`` CLI and ``boto3``
work against this simulator:

    aws ec2 describe-vpcs   --endpoint-url http://localhost:8080/aws --region eu-central-1
    aws ec2 run-instances   --endpoint-url http://localhost:8080/aws ...

It reads and writes the *same* SQLite tables the web console uses, so a VPC you
create in the UI is visible from the CLI and vice-versa — one runtime,
two front-ends.

Protocol notes
--------------
EC2 uses the AWS *Query* protocol: an HTTP POST whose body is form-encoded
``Action=...&Version=...&Param=...`` and whose response is XML in the
``http://ec2.amazonaws.com/doc/2016-11-15/`` namespace. Signatures are ignored,
like every local emulator. Element names must match the botocore EC2 model
exactly or the SDK parses an empty result, so the builders below are precise.
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from xml.sax.saxutils import escape
from urllib.parse import unquote

from aws_fidelity import (
    aws_id,
    AMI_CATALOG,
    azs_for,
    allocate_private_ip,
    instance_type_spec,
    private_dns_name,
    public_dns_name,
    random_public_ip,
    internal_dns_suffix,
    DEFAULT_ACCOUNT_ID,
)

EC2_NS = "http://ec2.amazonaws.com/doc/2016-11-15/"
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"
OWNER = DEFAULT_ACCOUNT_ID


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _conn(db_path):
    c = sqlite3.connect(db_path)
    c.row_factory = sqlite3.Row
    return c


def _region(c):
    row = c.execute("SELECT value FROM settings WHERE key='region'").fetchone()
    return (row[0] if row and row[0] else "eu-central-1")


def _req_id():
    return str(uuid.uuid4())


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _tags_xml(tags_json):
    """Render a stored ``tags_json`` object as an EC2 ``<tagSet>``."""
    try:
        tags = json.loads(tags_json or "{}")
    except (ValueError, TypeError):
        tags = {}
    if not tags:
        return ""
    items = "".join(
        f"<item><key>{escape(str(k))}</key><value>{escape(str(v))}</value></item>"
        for k, v in tags.items()
    )
    return f"<tagSet>{items}</tagSet>"


def _envelope(action, inner):
    return (
        f'<{action}Response xmlns="{EC2_NS}">'
        f"<requestId>{_req_id()}</requestId>{inner}</{action}Response>"
    )


def _error(code, message, status=400):
    body = (
        f'<Response><Errors><Error><Code>{escape(code)}</Code>'
        f"<Message>{escape(message)}</Message></Error></Errors>"
        f"<RequestID>{_req_id()}</RequestID></Response>"
    )
    return body, status


def _s3_error(code, message, status=400, resource="/"):
    """Return the REST/XML error shape that botocore expects from S3."""
    return (
        f'<Error xmlns="{S3_NS}"><Code>{escape(code)}</Code>'
        f"<Message>{escape(message)}</Message><Resource>{escape(resource)}</Resource>"
        f"<RequestId>{_req_id()}</RequestId></Error>",
        status,
        {"Content-Type": "application/xml; charset=utf-8"},
    )


def _s3_xml(root, inner):
    return (
        f'<?xml version="1.0" encoding="UTF-8"?><{root} xmlns="{S3_NS}">'
        f"{inner}</{root}>",
        200,
        {"Content-Type": "application/xml; charset=utf-8"},
    )


def _form_tags(params):
    """Collect ``TagSpecification.N.Tag.M.{Key,Value}`` params into a dict."""
    tags = {}
    for key, val in params.items():
        m = key.endswith(".Key")
        if ".Tag." in key and key.endswith(".Key"):
            base = key[: -len(".Key")]
            value = params.get(base + ".Value", "")
            tags[val] = value
    return tags


# ---------------------------------------------------------------------------
# VPCs
# ---------------------------------------------------------------------------

def _vpc_item(r):
    return (
        "<item>"
        f"<vpcId>{r['vpc_id']}</vpcId>"
        "<state>available</state>"
        f"<cidrBlock>{r['cidr']}</cidrBlock>"
        "<dhcpOptionsId>dopt-00000000</dhcpOptionsId>"
        f"<instanceTenancy>{r['tenancy'] or 'default'}</instanceTenancy>"
        "<cidrBlockAssociationSet><item>"
        f"<associationId>vpc-cidr-assoc-{r['vpc_id'][4:]}</associationId>"
        f"<cidrBlock>{r['cidr']}</cidrBlock>"
        "<cidrBlockState><state>associated</state></cidrBlockState>"
        "</item></cidrBlockAssociationSet>"
        f"<isDefault>{'true' if r['name']=='default' else 'false'}</isDefault>"
        f"<ownerId>{OWNER}</ownerId>"
        f"{_tags_xml(r['tags_json'])}"
        "</item>"
    )


def describe_vpcs(c, params):
    rows = c.execute("SELECT * FROM vpcs ORDER BY id").fetchall()
    inner = "<vpcSet>" + "".join(_vpc_item(r) for r in rows) + "</vpcSet>"
    return _envelope("DescribeVpcs", inner), 200


def create_vpc(c, params):
    cidr = params.get("CidrBlock", "10.0.0.0/16")
    tags = _form_tags(params)
    name = tags.get("Name", "cli-vpc")
    vid = aws_id("vpc")
    now = datetime.now().isoformat(timespec="seconds")
    tags.setdefault("Name", name)
    c.execute(
        "INSERT INTO vpcs(vpc_id,name,cidr,tenancy,dns_support,dns_hostnames,region,account_id,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (vid, name, cidr, params.get("InstanceTenancy", "default"), 1, 1, _region(c), None, json.dumps(tags), now),
    )
    c.commit()
    r = c.execute("SELECT * FROM vpcs WHERE vpc_id=?", (vid,)).fetchone()
    return _envelope("CreateVpc", f"<vpc>{_vpc_item(r)[6:-7]}</vpc>"), 200


def delete_vpc(c, params):
    vid = params.get("VpcId", "")
    c.execute("DELETE FROM vpcs WHERE vpc_id=?", (vid,))
    c.commit()
    return _envelope("DeleteVpc", "<return>true</return>"), 200


# ---------------------------------------------------------------------------
# Subnets
# ---------------------------------------------------------------------------

def _subnet_item(c, r):
    vpc = c.execute("SELECT vpc_id FROM vpcs WHERE id=?", (r["vpc_id"],)).fetchone()
    vpc_str = vpc["vpc_id"] if vpc else "vpc-unknown"
    return (
        "<item>"
        f"<subnetId>{r['subnet_id']}</subnetId>"
        "<state>available</state>"
        f"<vpcId>{vpc_str}</vpcId>"
        f"<cidrBlock>{r['cidr']}</cidrBlock>"
        "<availableIpAddressCount>251</availableIpAddressCount>"
        f"<availabilityZone>{r['az'] or ''}</availabilityZone>"
        "<defaultForAz>false</defaultForAz>"
        f"<mapPublicIpOnLaunch>{'true' if r['map_public_ip'] else 'false'}</mapPublicIpOnLaunch>"
        f"<ownerId>{OWNER}</ownerId>"
        f"{_tags_xml(r['tags_json'])}"
        "</item>"
    )


def describe_subnets(c, params):
    rows = c.execute("SELECT * FROM subnets ORDER BY id").fetchall()
    inner = "<subnetSet>" + "".join(_subnet_item(c, r) for r in rows) + "</subnetSet>"
    return _envelope("DescribeSubnets", inner), 200


def create_subnet(c, params):
    vpc_str = params.get("VpcId", "")
    vpc = c.execute("SELECT id FROM vpcs WHERE vpc_id=?", (vpc_str,)).fetchone()
    if not vpc:
        return _error("InvalidVpcID.NotFound", f"The vpc ID '{vpc_str}' does not exist")
    cidr = params.get("CidrBlock", "10.0.1.0/24")
    az = params.get("AvailabilityZone") or azs_for(_region(c))[0]
    tags = _form_tags(params)
    name = tags.get("Name", "cli-subnet")
    sid = aws_id("subnet")
    now = datetime.now().isoformat(timespec="seconds")
    c.execute(
        "INSERT INTO subnets(subnet_id,name,vpc_id,cidr,az,public_ipv4,map_public_ip,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (sid, name, vpc["id"], cidr, az, 0, 0, json.dumps(tags or {"Name": name}), now),
    )
    c.commit()
    r = c.execute("SELECT * FROM subnets WHERE subnet_id=?", (sid,)).fetchone()
    return _envelope("CreateSubnet", f"<subnet>{_subnet_item(c, r)[6:-7]}</subnet>"), 200


def delete_subnet(c, params):
    c.execute("DELETE FROM subnets WHERE subnet_id=?", (params.get("SubnetId", ""),))
    c.commit()
    return _envelope("DeleteSubnet", "<return>true</return>"), 200


# ---------------------------------------------------------------------------
# Instances
# ---------------------------------------------------------------------------

def _instance_item(r):
    cfg = json.loads(r["config_json"] or "{}")
    net = cfg.get("network", {})
    state_map = {"pending": 0, "running": 16, "shutting-down": 32, "terminated": 48, "stopping": 64, "stopped": 80}
    code = state_map.get(r["state"], 16)
    priv_dns = net.get("private_dns", "")
    pub_dns = net.get("public_dns", "")
    az = net.get("availability_zone", "")
    return (
        "<item>"
        f"<instanceId>{r['instance_id']}</instanceId>"
        f"<imageId>{r['ami_id']}</imageId>"
        f"<instanceState><code>{code}</code><name>{r['state']}</name></instanceState>"
        f"<privateDnsName>{escape(priv_dns)}</privateDnsName>"
        f"<dnsName>{escape(pub_dns)}</dnsName>"
        f"<instanceType>{r['instance_type']}</instanceType>"
        f"<launchTime>{_now_iso()}</launchTime>"
        f"<placement><availabilityZone>{escape(az)}</availabilityZone><tenancy>{cfg.get('tenancy','default')}</tenancy></placement>"
        f"<privateIpAddress>{r['private_ip'] or ''}</privateIpAddress>"
        + (f"<ipAddress>{r['public_ip']}</ipAddress>" if r["public_ip"] else "")
        + f"<subnetId>{net.get('subnet','') or ''}</subnetId>"
        f"<architecture>{r['architecture'] or 'x86_64'}</architecture>"
        f"<rootDeviceType>ebs</rootDeviceType>"
        f"<virtualizationType>hvm</virtualizationType>"
        f"{_tags_xml(r['tags_json'])}"
        "</item>"
    )


def describe_instances(c, params):
    rows = c.execute("SELECT * FROM ec2_instances ORDER BY id").fetchall()
    # One reservation per instance keeps the mapping simple and valid.
    reservations = "".join(
        "<item>"
        f"<reservationId>r-{uuid.uuid4().hex[:17]}</reservationId>"
        f"<ownerId>{OWNER}</ownerId>"
        "<groupSet/>"
        f"<instancesSet>{_instance_item(r)}</instancesSet>"
        "</item>"
        for r in rows
    )
    return _envelope("DescribeInstances", f"<reservationSet>{reservations}</reservationSet>"), 200


def run_instances(c, params):
    image_id = params.get("ImageId", AMI_CATALOG[0]["id"])
    itype = params.get("InstanceType", "t3.micro")
    try:
        count = max(1, int(params.get("MinCount", params.get("MaxCount", "1"))))
    except ValueError:
        count = 1
    ami = next((a for a in AMI_CATALOG if a["id"] == image_id), AMI_CATALOG[0])
    region = _region(c)
    subnet_str = params.get("SubnetId", "")
    sub = c.execute("SELECT * FROM subnets WHERE subnet_id=?", (subnet_str,)).fetchone() if subnet_str else None
    cidr = sub["cidr"] if sub else "172.31.0.0/16"
    az = (sub["az"] if sub and sub["az"] else azs_for(region)[0])
    vpc_str = ""
    if sub:
        vrow = c.execute("SELECT vpc_id FROM vpcs WHERE id=?", (sub["vpc_id"],)).fetchone()
        vpc_str = vrow["vpc_id"] if vrow else ""
    used = [x[0] for x in c.execute("SELECT private_ip FROM ec2_instances WHERE private_ip IS NOT NULL").fetchall()]
    tags = _form_tags(params)
    name = tags.get("Name", "cli-instance")
    items = []
    now = datetime.now().isoformat(timespec="seconds")
    for _ in range(count):
        iid = aws_id("i")
        priv = allocate_private_ip(cidr, used)
        used.append(priv)
        assign_public = bool(sub and sub["map_public_ip"])
        pub = random_public_ip() if assign_public else ""
        inst_tags = dict(tags) if tags else {}
        inst_tags.setdefault("Name", name)
        cfg = {
            "ami": ami,
            "instance_type": instance_type_spec(itype),
            "network": {
                "vpc": vpc_str, "subnet": subnet_str, "public_ip": assign_public,
                "availability_zone": az,
                "private_dns": private_dns_name(priv, region),
                "public_dns": public_dns_name(pub, region) if pub else "",
            },
            "volumes": [{"device": ami.get("root_device", "/dev/sda1"), "type": "gp3",
                         "size_gib": 8, "encrypted": True}],
            "tenancy": "default",
            "source": "cli",
        }
        c.execute(
            "INSERT INTO ec2_instances(instance_id,name,state,os,ami_id,instance_type,vpc,subnet,security_groups,key_name,private_ip,public_ip,root_volume_gib,root_volume_type,encrypted,architecture,tags_json,config_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (iid, inst_tags.get("Name"), "running", ami["os"], image_id, itype, vpc_str, subnet_str, "",
             params.get("KeyName", ""), priv, pub, 8, "gp3", 1, ami["arch"],
             json.dumps(inst_tags), json.dumps(cfg), now),
        )
        r = c.execute("SELECT * FROM ec2_instances WHERE instance_id=?", (iid,)).fetchone()
        items.append(_instance_item(r))
    c.commit()
    inner = (
        f"<reservationId>r-{uuid.uuid4().hex[:17]}</reservationId>"
        f"<ownerId>{OWNER}</ownerId><groupSet/>"
        f"<instancesSet>{''.join(items)}</instancesSet>"
    )
    return _envelope("RunInstances", inner), 200


def _instance_state_change(c, params, new_state, action):
    ids = [v for k, v in params.items() if k.startswith("InstanceId")]
    changed = []
    for iid in ids:
        row = c.execute("SELECT state FROM ec2_instances WHERE instance_id=?", (iid,)).fetchone()
        prev = row["state"] if row else "running"
        c.execute("UPDATE ec2_instances SET state=? WHERE instance_id=?", (new_state, iid))
        changed.append((iid, prev, new_state))
    c.commit()
    code = {"running": 16, "stopped": 80, "terminated": 48}.get(new_state, 16)
    prev_code = {"running": 16, "stopped": 80, "terminated": 48, "pending": 0}
    items = "".join(
        f"<item><instanceId>{iid}</instanceId>"
        f"<currentState><code>{code}</code><name>{new_state}</name></currentState>"
        f"<previousState><code>{prev_code.get(p,16)}</code><name>{p}</name></previousState></item>"
        for iid, p, _ in changed
    )
    return _envelope(action, f"<instancesSet>{items}</instancesSet>"), 200


def start_instances(c, params):
    return _instance_state_change(c, params, "running", "StartInstances")


def stop_instances(c, params):
    return _instance_state_change(c, params, "stopped", "StopInstances")


def terminate_instances(c, params):
    return _instance_state_change(c, params, "terminated", "TerminateInstances")


# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

def _sg_item(c, r):
    vpc = c.execute("SELECT vpc_id FROM vpcs WHERE id=?", (r["vpc_id"],)).fetchone()
    return (
        "<item>"
        f"<ownerId>{OWNER}</ownerId>"
        f"<groupId>{r['group_id']}</groupId>"
        f"<groupName>{escape(r['name'])}</groupName>"
        f"<groupDescription>{escape(r['description'] or '')}</groupDescription>"
        f"<vpcId>{vpc['vpc_id'] if vpc else ''}</vpcId>"
        "<ipPermissions/>"
        "<ipPermissionsEgress/>"
        f"{_tags_xml(r['tags_json'])}"
        "</item>"
    )


def describe_security_groups(c, params):
    rows = c.execute("SELECT * FROM security_groups ORDER BY id").fetchall()
    inner = "<securityGroupInfo>" + "".join(_sg_item(c, r) for r in rows) + "</securityGroupInfo>"
    return _envelope("DescribeSecurityGroups", inner), 200


def create_security_group(c, params):
    vpc_str = params.get("VpcId", "")
    vpc = c.execute("SELECT id FROM vpcs WHERE vpc_id=?", (vpc_str,)).fetchone()
    if not vpc:
        return _error("InvalidVpcID.NotFound", f"The vpc ID '{vpc_str}' does not exist")
    gid = aws_id("sg")
    now = datetime.now().isoformat(timespec="seconds")
    c.execute(
        "INSERT INTO security_groups(group_id,name,description,vpc_id,inbound_json,outbound_json,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (gid, params.get("GroupName", "cli-sg"), params.get("GroupDescription", ""), vpc["id"],
         json.dumps([]), json.dumps([]), json.dumps({}), now),
    )
    c.commit()
    return _envelope("CreateSecurityGroup", f"<groupId>{gid}</groupId>"), 200


def delete_security_group(c, params):
    gid = params.get("GroupId", "")
    c.execute("DELETE FROM security_groups WHERE group_id=?", (gid,))
    c.commit()
    return _envelope("DeleteSecurityGroup", "<return>true</return>"), 200


# ---------------------------------------------------------------------------
# Route tables / gateways / addresses (describe-focused)
# ---------------------------------------------------------------------------

def describe_route_tables(c, params):
    rows = c.execute("SELECT rt.*, v.vpc_id v_str FROM route_tables rt JOIN vpcs v ON v.id=rt.vpc_id ORDER BY rt.id").fetchall()
    items = []
    for r in rows:
        try:
            routes = json.loads(r["routes_json"] or "[]")
        except (ValueError, TypeError):
            routes = []
        route_xml = "".join(
            f"<item><destinationCidrBlock>{escape(str(rt).split('->')[0].strip())}</destinationCidrBlock><state>active</state></item>"
            for rt in routes
        )
        items.append(
            "<item>"
            f"<routeTableId>{r['route_table_id']}</routeTableId>"
            f"<vpcId>{r['v_str']}</vpcId>"
            f"<routeSet>{route_xml}</routeSet>"
            "<associationSet/>"
            f"<ownerId>{OWNER}</ownerId>"
            f"{_tags_xml(r['tags_json'])}"
            "</item>"
        )
    return _envelope("DescribeRouteTables", f"<routeTableSet>{''.join(items)}</routeTableSet>"), 200


def describe_internet_gateways(c, params):
    rows = c.execute("SELECT ig.*, v.vpc_id v_str FROM internet_gateways ig LEFT JOIN vpcs v ON v.id=ig.vpc_id ORDER BY ig.id").fetchall()
    items = []
    for r in rows:
        att = (
            f"<attachmentSet><item><vpcId>{r['v_str']}</vpcId><state>available</state></item></attachmentSet>"
            if r["v_str"] else "<attachmentSet/>"
        )
        items.append(
            "<item>"
            f"<internetGatewayId>{r['igw_id']}</internetGatewayId>"
            f"<ownerId>{OWNER}</ownerId>"
            f"{att}{_tags_xml(r['tags_json'])}"
            "</item>"
        )
    return _envelope("DescribeInternetGateways", f"<internetGatewaySet>{''.join(items)}</internetGatewaySet>"), 200


def describe_nat_gateways(c, params):
    rows = c.execute("SELECT n.*, v.vpc_id v_str, s.subnet_id s_str FROM nat_gateways n JOIN vpcs v ON v.id=n.vpc_id JOIN subnets s ON s.id=n.subnet_id ORDER BY n.id").fetchall()
    items = "".join(
        "<item>"
        f"<natGatewayId>{r['nat_id']}</natGatewayId>"
        f"<vpcId>{r['v_str']}</vpcId>"
        f"<subnetId>{r['s_str']}</subnetId>"
        f"<state>{r['state']}</state>"
        f"<connectivityType>{r['connectivity_type']}</connectivityType>"
        f"{_tags_xml(r['tags_json'])}"
        "</item>"
        for r in rows
    )
    return _envelope("DescribeNatGateways", f"<natGatewaySet>{items}</natGatewaySet>"), 200


def describe_addresses(c, params):
    rows = c.execute("SELECT * FROM elastic_ips ORDER BY id").fetchall()
    items = "".join(
        "<item>"
        f"<publicIp>{r['public_ip']}</publicIp>"
        f"<allocationId>{r['allocation_id']}</allocationId>"
        f"<domain>{r['domain']}</domain>"
        f"{_tags_xml(r['tags_json'])}"
        "</item>"
        for r in rows
    )
    return _envelope("DescribeAddresses", f"<addressesSet>{items}</addressesSet>"), 200


def allocate_address(c, params):
    now = datetime.now().isoformat(timespec="seconds")
    alloc = aws_id("eipalloc")
    ip = random_public_ip()
    c.execute(
        "INSERT INTO elastic_ips(allocation_id,name,public_ip,domain,association,state,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (alloc, "cli-eip", ip, "vpc", "", "allocated", json.dumps({}), now),
    )
    c.commit()
    return _envelope("AllocateAddress", f"<publicIp>{ip}</publicIp><allocationId>{alloc}</allocationId><domain>vpc</domain>"), 200


# ---------------------------------------------------------------------------
# Catalogue lookups
# ---------------------------------------------------------------------------

def describe_images(c, params):
    items = "".join(
        "<item>"
        f"<imageId>{a['id']}</imageId>"
        "<imageState>available</imageState>"
        f"<architecture>{a['arch']}</architecture>"
        f"<name>{escape(a['name'])}</name>"
        f"<description>{escape(a['description'])}</description>"
        "<imageType>machine</imageType>"
        f"<rootDeviceName>{a['root_device']}</rootDeviceName>"
        f"<rootDeviceType>ebs</rootDeviceType>"
        f"<virtualizationType>{a['virtualization']}</virtualizationType>"
        f"<ownerId>{OWNER}</ownerId>"
        "<isPublic>true</isPublic>"
        f"<platformDetails>{escape(a['os'])}</platformDetails>"
        "</item>"
        for a in AMI_CATALOG
    )
    return _envelope("DescribeImages", f"<imagesSet>{items}</imagesSet>"), 200


def describe_availability_zones(c, params):
    region = _region(c)
    items = "".join(
        "<item>"
        f"<zoneName>{z}</zoneName>"
        "<zoneState>available</zoneState>"
        f"<regionName>{region}</regionName>"
        f"<zoneId>{region}-az{i+1}</zoneId>"
        "</item>"
        for i, z in enumerate(azs_for(region))
    )
    return _envelope("DescribeAvailabilityZones", f"<availabilityZoneInfo>{items}</availabilityZoneInfo>"), 200


# ---------------------------------------------------------------------------
# S3 REST/XML API
# ---------------------------------------------------------------------------

def _s3_bucket(c, name):
    return c.execute("SELECT * FROM s3_buckets WHERE name=?", (name,)).fetchone()


def _s3_object_bytes(value):
    """Normalise rows created by either the text UI or the binary CLI API."""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def _s3_parts(request):
    """Return the bucket and URL-decoded key below the /aws endpoint prefix."""
    relative = request.path[len("/aws"):].lstrip("/")
    parts = relative.split("/", 1) if relative else []
    bucket = parts[0] if parts else ""
    key = unquote(parts[1]) if len(parts) == 2 else ""
    return bucket, key


def _s3_list_buckets(c):
    rows = c.execute("SELECT * FROM s3_buckets ORDER BY name").fetchall()
    buckets = "".join(
        "<Bucket>"
        f"<Name>{escape(r['name'])}</Name>"
        f"<CreationDate>{escape(r['created_at'].replace(' ', 'T'))}Z</CreationDate>"
        "</Bucket>"
        for r in rows
    )
    return _s3_xml(
        "ListAllMyBucketsResult",
        f"<Owner><ID>{OWNER}</ID><DisplayName>local</DisplayName></Owner><Buckets>{buckets}</Buckets>",
    )


def _s3_list_objects(c, bucket, prefix):
    rows = c.execute(
        "SELECT * FROM s3_objects WHERE bucket_id=? AND key LIKE ? ORDER BY key",
        (bucket["id"], f"{prefix}%"),
    ).fetchall()
    contents = "".join(
        "<Contents>"
        f"<Key>{escape(r['key'])}</Key>"
        f"<LastModified>{escape(r['created_at'].replace(' ', 'T'))}Z</LastModified>"
        f"<ETag>\"{uuid.uuid5(uuid.NAMESPACE_URL, bucket['name'] + '/' + r['key']).hex}\"</ETag>"
        f"<Size>{r['size_bytes']}</Size><StorageClass>{escape(r['storage_class'] or 'STANDARD')}</StorageClass>"
        "</Contents>"
        for r in rows
    )
    return _s3_xml(
        "ListBucketResult",
        f"<Name>{escape(bucket['name'])}</Name><Prefix>{escape(prefix)}</Prefix>"
        f"<KeyCount>{len(rows)}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>{contents}",
    )


def handle_s3(request, db_path):
    """Serve the minimal S3 REST contract used by `aws s3` and `aws s3api`.

    This deliberately covers the storage-lab lifecycle, not every S3 feature:
    list/create/delete buckets; list, put, get, head and delete objects; and
    GetBucketLocation. All operations use the same tables as the web console.
    """
    c = _conn(db_path)
    try:
        bucket_name, key = _s3_parts(request)
        if not bucket_name:
            if request.method == "GET":
                return _s3_list_buckets(c)
            return _s3_error("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)

        bucket = _s3_bucket(c, bucket_name)
        if request.method == "PUT" and not key and bucket is None:
            # CreateBucketConfiguration is a tiny XML body in the S3 protocol.
            # Extracting just LocationConstraint gives CLI-created buckets the
            # correct region while intentionally avoiding a full XML dependency.
            create_body = request.get_data(cache=True, as_text=True)
            location = re.search(r"<LocationConstraint[^>]*>([^<]+)</LocationConstraint>", create_body)
            region = (location.group(1) if location else None) or _region(c)
            c.execute(
                "INSERT INTO s3_buckets(name,region,versioning,public,encryption,created_at) VALUES(?,?,?,?,?,?)",
                (bucket_name, region, 0, 0, "SSE-S3", datetime.now().isoformat(timespec="seconds")),
            )
            c.commit()
            return "", 200, {"Location": f"/{bucket_name}"}
        if bucket is None:
            return _s3_error("NoSuchBucket", "The specified bucket does not exist", 404, f"/{bucket_name}")

        if not key:
            if request.method == "DELETE":
                has_objects = c.execute("SELECT 1 FROM s3_objects WHERE bucket_id=? LIMIT 1", (bucket["id"],)).fetchone()
                if has_objects:
                    return _s3_error("BucketNotEmpty", "The bucket you tried to delete is not empty", 409, f"/{bucket_name}")
                c.execute("DELETE FROM s3_buckets WHERE id=?", (bucket["id"],))
                c.commit()
                return "", 204, {}
            if request.method == "HEAD":
                return "", 200, {"x-amz-bucket-region": bucket["region"] or _region(c)}
            if request.method == "GET" and "location" in request.args:
                return _s3_xml("LocationConstraint", escape(bucket["region"] or _region(c)))
            if request.method == "GET":
                return _s3_list_objects(c, bucket, request.args.get("prefix", ""))
            return _s3_error("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)

        row = c.execute("SELECT * FROM s3_objects WHERE bucket_id=? AND key=?", (bucket["id"], key)).fetchone()
        if request.method == "PUT":
            body = request.get_data(cache=False)
            content_type = request.headers.get("Content-Type", "binary/octet-stream")
            now = datetime.now().isoformat(timespec="seconds")
            if row:
                c.execute(
                    "UPDATE s3_objects SET size_bytes=?, content_type=?, body=?, created_at=? WHERE id=?",
                    (len(body), content_type, body, now, row["id"]),
                )
            else:
                c.execute(
                    "INSERT INTO s3_objects(bucket_id,key,size_bytes,content_type,storage_class,body,created_at) VALUES(?,?,?,?,?,?,?)",
                    (bucket["id"], key, len(body), content_type, "STANDARD", body, now),
                )
            c.commit()
            return "", 200, {"ETag": f'"{uuid.uuid5(uuid.NAMESPACE_URL, bucket_name + "/" + key).hex}"'}
        if row is None:
            return _s3_error("NoSuchKey", "The specified key does not exist.", 404, f"/{bucket_name}/{key}")
        if request.method == "DELETE":
            c.execute("DELETE FROM s3_objects WHERE id=?", (row["id"],))
            c.commit()
            return "", 204, {}
        if request.method in {"GET", "HEAD"}:
            # Return the real body even for HEAD: Werkzeug strips it from the
            # response while keeping Content-Length, whereas returning b"" here
            # makes it recompute the header as 0 and head-object reports no size.
            body = _s3_object_bytes(row["body"])
            return body, 200, {
                "Content-Type": row["content_type"] or "binary/octet-stream",
                "Content-Length": str(row["size_bytes"]),
                "ETag": f'"{uuid.uuid5(uuid.NAMESPACE_URL, bucket_name + "/" + key).hex}"',
            }
        return _s3_error("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)
    except sqlite3.IntegrityError:
        return _s3_error("BucketAlreadyExists", "The requested bucket name is not available.", 409)
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

ACTIONS = {
    "DescribeVpcs": describe_vpcs,
    "CreateVpc": create_vpc,
    "DeleteVpc": delete_vpc,
    "DescribeSubnets": describe_subnets,
    "CreateSubnet": create_subnet,
    "DeleteSubnet": delete_subnet,
    "DescribeInstances": describe_instances,
    "RunInstances": run_instances,
    "StartInstances": start_instances,
    "StopInstances": stop_instances,
    "TerminateInstances": terminate_instances,
    "DescribeSecurityGroups": describe_security_groups,
    "CreateSecurityGroup": create_security_group,
    "DeleteSecurityGroup": delete_security_group,
    "DescribeRouteTables": describe_route_tables,
    "DescribeInternetGateways": describe_internet_gateways,
    "DescribeNatGateways": describe_nat_gateways,
    "DescribeAddresses": describe_addresses,
    "AllocateAddress": allocate_address,
    "DescribeImages": describe_images,
    "DescribeAvailabilityZones": describe_availability_zones,
}

# Actions the CLI sends that we accept as no-op successes so common wizards and
# waiters don't error out against the simulator.
NOOP_TRUE = {
    "CreateTags", "DeleteTags", "ModifyInstanceAttribute", "ModifyVpcAttribute",
    "ModifySubnetAttribute", "AttachInternetGateway", "DetachInternetGateway",
}


def is_query_request(request):
    """True when this looks like an AWS Query-protocol call rather than a
    browser hit — a POST carrying an ``Action`` field."""
    if request.method != "POST":
        return False
    return bool(request.form.get("Action") or request.args.get("Action"))


def is_aws_api_request(request):
    """True for either EC2 Query calls or S3 REST calls below `/aws`."""
    return request.path == "/aws" or request.path.startswith("/aws/")


def handle(request, db_path):
    """Entry point wired into the Flask app. Returns (body, status, headers)."""
    if not is_query_request(request):
        return handle_s3(request, db_path)

    params = {}
    params.update(request.args.to_dict(flat=True))
    params.update(request.form.to_dict(flat=True))
    action = params.get("Action", "")
    headers = {"Content-Type": "text/xml; charset=utf-8"}

    c = _conn(db_path)
    try:
        if action in ACTIONS:
            body, status = ACTIONS[action](c, params)
        elif action in NOOP_TRUE:
            body, status = _envelope(action, "<return>true</return>"), 200
        else:
            body, status = _error(
                "InvalidAction",
                f"The action '{action}' is not supported by this local simulator yet.",
                400,
            )
    except Exception as exc:  # keep the endpoint resilient for a teaching tool
        body, status = _error("InternalError", str(exc), 500)
    finally:
        c.close()
    return body, status, headers
