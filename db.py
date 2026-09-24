"""
db.py
=====

The single home of the SQLite schema.

* ``SCHEMA`` creates every table. ``migrate()`` adds columns and converts data
  from older databases in place, so upgrading never loses a user's environment.
* ``STATE_TABLES`` is the one ordered list (parents before children) that
  reset, snapshots and restore all use. Add a table here and every one of those
  features picks it up — previously the list was copied five times.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
from datetime import datetime

from aws_fidelity import (
    aws_id, azs_for, DEFAULT_VPC_CIDR, DEFAULT_SG_INBOUND, DEFAULT_SG_OUTBOUND,
    DEFAULT_NACL_RULES, DEFAULT_SUBNET_CIDRS,
)
import rules

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SIM_DB") or os.path.join(BASE, "simulator.db")

DEFAULT_REGION = "eu-central-1"

DEFAULT_POLICIES = [
    ("Restrict Regions", "Prevent use of unapproved AWS regions.", "Governance"),
    ("Protect CloudTrail", "Prevent workloads from disabling or modifying centralized audit logging.", "Security"),
    ("Prevent Account Leave", "Prevent member accounts from leaving the organization.", "Governance"),
    ("Deny Root Actions", "Baseline control to discourage direct root-user operations.", "Security"),
]

# Parents before children: restore inserts in this order, reset/restore delete
# in reverse.
STATE_TABLES = [
    "settings", "ous", "accounts", "policies", "policy_attachments",
    "vpcs", "route_tables", "network_acls", "subnets", "internet_gateways",
    "elastic_ips", "nat_gateways", "security_groups", "load_balancers",
    "vpc_endpoints", "ec2_instances",
    "s3_buckets", "s3_objects", "iam_users", "iam_roles", "iam_policies",
    "iam_policy_attachments", "lambda_functions", "dynamodb_tables",
    "dynamodb_items", "secrets",
]
# Tables a "Reset environment" leaves alone (built-in catalogue data).
RESET_KEEP = {"settings", "policies"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ous (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, parent_id INTEGER);
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL,
  account_id TEXT NOT NULL UNIQUE, ou_id INTEGER);
CREATE TABLE IF NOT EXISTS policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, category TEXT);
CREATE TABLE IF NOT EXISTS policy_attachments (policy_id INTEGER, target_type TEXT, target_id INTEGER);

CREATE TABLE IF NOT EXISTS vpcs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, vpc_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  cidr TEXT NOT NULL, tenancy TEXT DEFAULT 'default', dns_support INTEGER DEFAULT 1,
  dns_hostnames INTEGER DEFAULT 1, region TEXT, account_id INTEGER, tags_json TEXT,
  created_at TEXT NOT NULL, is_default INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS subnets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, subnet_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  vpc_id INTEGER NOT NULL, cidr TEXT NOT NULL, az TEXT, public_ipv4 INTEGER DEFAULT 0,
  map_public_ip INTEGER DEFAULT 0, route_table_id INTEGER, tags_json TEXT, created_at TEXT NOT NULL,
  rt_assoc_id TEXT, network_acl_id INTEGER, default_for_az INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS route_tables (
  id INTEGER PRIMARY KEY AUTOINCREMENT, route_table_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  vpc_id INTEGER NOT NULL, routes_json TEXT, main_table INTEGER DEFAULT 0, tags_json TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS internet_gateways (
  id INTEGER PRIMARY KEY AUTOINCREMENT, igw_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  vpc_id INTEGER, state TEXT DEFAULT 'available', tags_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nat_gateways (
  id INTEGER PRIMARY KEY AUTOINCREMENT, nat_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  vpc_id INTEGER NOT NULL, subnet_id INTEGER NOT NULL, connectivity_type TEXT DEFAULT 'public',
  allocation_id TEXT, state TEXT DEFAULT 'available', tags_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS security_groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  description TEXT, vpc_id INTEGER NOT NULL, inbound_json TEXT, outbound_json TEXT,
  tags_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS network_acls (
  id INTEGER PRIMARY KEY AUTOINCREMENT, acl_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  vpc_id INTEGER NOT NULL, rules_json TEXT, is_default INTEGER DEFAULT 0, tags_json TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS elastic_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT, allocation_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  public_ip TEXT NOT NULL, domain TEXT DEFAULT 'vpc', association TEXT, state TEXT DEFAULT 'allocated',
  tags_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS load_balancers (
  id INTEGER PRIMARY KEY AUTOINCREMENT, lb_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  lb_type TEXT DEFAULT 'application', scheme TEXT DEFAULT 'internet-facing', vpc_id INTEGER,
  subnets_json TEXT, security_groups_json TEXT, state TEXT DEFAULT 'active', tags_json TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS vpc_endpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  vpc_id INTEGER NOT NULL, service_name TEXT NOT NULL, endpoint_type TEXT DEFAULT 'gateway',
  route_tables_json TEXT, subnets_json TEXT, state TEXT DEFAULT 'available', tags_json TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ec2_instances (
  id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  state TEXT NOT NULL, os TEXT NOT NULL, ami_id TEXT NOT NULL, instance_type TEXT NOT NULL,
  vpc TEXT, subnet TEXT, security_groups TEXT, key_name TEXT, private_ip TEXT, public_ip TEXT,
  root_volume_gib INTEGER, root_volume_type TEXT, encrypted INTEGER DEFAULT 1, architecture TEXT,
  tags_json TEXT, config_json TEXT, created_at TEXT NOT NULL,
  target_state TEXT, transition_at TEXT);

CREATE TABLE IF NOT EXISTS s3_buckets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, region TEXT,
  versioning INTEGER DEFAULT 0, public INTEGER DEFAULT 0, encryption TEXT DEFAULT 'SSE-S3',
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS s3_objects (
  id INTEGER PRIMARY KEY AUTOINCREMENT, bucket_id INTEGER NOT NULL, key TEXT NOT NULL,
  size_bytes INTEGER DEFAULT 0, content_type TEXT, storage_class TEXT DEFAULT 'STANDARD',
  body TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS iam_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, arn TEXT NOT NULL,
  path TEXT DEFAULT '/', console_access INTEGER DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS iam_roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, arn TEXT NOT NULL,
  trusted_service TEXT, description TEXT, created_at TEXT NOT NULL, trust_policy TEXT);
CREATE TABLE IF NOT EXISTS iam_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, arn TEXT NOT NULL,
  document TEXT, description TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS iam_policy_attachments (
  id INTEGER PRIMARY KEY AUTOINCREMENT, policy_arn TEXT NOT NULL, principal_type TEXT NOT NULL,
  principal_name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lambda_functions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, arn TEXT NOT NULL,
  runtime TEXT, handler TEXT, memory_mb INTEGER DEFAULT 128, timeout_s INTEGER DEFAULT 3,
  description TEXT, code TEXT, created_at TEXT NOT NULL, role TEXT);
CREATE TABLE IF NOT EXISTS dynamodb_tables (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, arn TEXT NOT NULL,
  partition_key TEXT NOT NULL, partition_key_type TEXT DEFAULT 'S', sort_key TEXT,
  sort_key_type TEXT, billing_mode TEXT DEFAULT 'PAY_PER_REQUEST', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS dynamodb_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT, table_id INTEGER NOT NULL, item_json TEXT NOT NULL,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS secrets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, arn TEXT NOT NULL,
  description TEXT, secret_value TEXT, rotation_enabled INTEGER DEFAULT 0, created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, created_at TEXT NOT NULL,
  state_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lambda_invocations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, function_name TEXT NOT NULL, ts TEXT NOT NULL, source TEXT,
  status TEXT, duration_ms REAL, event TEXT, response TEXT, logs TEXT);
CREATE TABLE IF NOT EXISTS activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, source TEXT NOT NULL,
  service TEXT NOT NULL, action TEXT NOT NULL, resource TEXT, detail TEXT, cli TEXT,
  readonly INTEGER DEFAULT 0, status TEXT DEFAULT 'ok');
"""

# Columns added after the first public release: (table, column, declaration).
ADDED_COLUMNS = [
    ("vpcs", "is_default", "INTEGER DEFAULT 0"),
    ("subnets", "rt_assoc_id", "TEXT"),
    ("subnets", "network_acl_id", "INTEGER"),
    ("subnets", "default_for_az", "INTEGER DEFAULT 0"),
    ("ec2_instances", "target_state", "TEXT"),
    ("ec2_instances", "transition_at", "TEXT"),
    ("iam_roles", "trust_policy", "TEXT"),
    ("lambda_functions", "role", "TEXT"),
]


def now():
    return datetime.now().isoformat(timespec="seconds")


def connect(path=None):
    c = sqlite3.connect(path or DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def get_setting(c, key, default=""):
    row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row[0] if row and row[0] is not None else default


def set_setting(c, key, value):
    c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
              (key, str(value)))


def region(c):
    return get_setting(c, "region") or DEFAULT_REGION


# ---------------------------------------------------------------------------
# Initialisation & migration
# ---------------------------------------------------------------------------

def init(path=None):
    """Create/upgrade the schema and seed first-run data. Called once at start."""
    c = connect(path)
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        for table, col, decl in ADDED_COLUMNS:
            cols = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
            if col not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        if get_setting(c, "org_name", None) is None:
            set_setting(c, "org_name", "")
        if not get_setting(c, "region"):
            set_setting(c, "region", DEFAULT_REGION)
        if c.execute("SELECT COUNT(*) FROM policies").fetchone()[0] == 0:
            c.executemany("INSERT INTO policies(name,description,category) VALUES (?,?,?)", DEFAULT_POLICIES)
        migrate(c)
        c.commit()
    finally:
        c.close()


def migrate(c):
    """Idempotent data upgrades. Safe to run on every start and after a restore."""
    _dedupe_s3_objects(c)
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_s3_objects_key ON s3_objects(bucket_id, key)")

    # Mark the account's default VPC explicitly instead of relying on its name.
    if not c.execute("SELECT 1 FROM vpcs WHERE is_default=1").fetchone():
        row = c.execute("SELECT id FROM vpcs WHERE name='default' AND cidr=? ORDER BY id LIMIT 1",
                        (DEFAULT_VPC_CIDR,)).fetchone()
        if row:
            c.execute("UPDATE vpcs SET is_default=1 WHERE id=?", (row["id"],))

    # Free-text routes / rules -> structured dicts.
    for r in c.execute("SELECT id, routes_json FROM route_tables").fetchall():
        c.execute("UPDATE route_tables SET routes_json=? WHERE id=?",
                  (json.dumps(_upgrade_routes(c, r["id"], r["routes_json"])), r["id"]))
    for r in c.execute("SELECT id, inbound_json, outbound_json FROM security_groups").fetchall():
        c.execute("UPDATE security_groups SET inbound_json=?, outbound_json=? WHERE id=?",
                  (json.dumps(rules.parse_sg_rules(r["inbound_json"])),
                   json.dumps(rules.parse_sg_rules(r["outbound_json"])), r["id"]))
    for r in c.execute("SELECT id, rules_json FROM network_acls").fetchall():
        c.execute("UPDATE network_acls SET rules_json=? WHERE id=?",
                  (json.dumps(rules.parse_nacl_rules(r["rules_json"])), r["id"]))

    # Every VPC owns a main route table, a default security group and a default NACL.
    for v in c.execute("SELECT * FROM vpcs").fetchall():
        ensure_vpc_defaults(c, v)

    _upgrade_instance_refs(c)

    # Default VPC gets the default subnets + internet gateway real accounts have.
    if get_setting(c, "default_vpc_seeded", None) is None:
        if c.execute("SELECT COUNT(*) FROM vpcs").fetchone()[0] == 0:
            seed_default_vpc(c)
        else:
            dv = c.execute("SELECT * FROM vpcs WHERE is_default=1").fetchone()
            if dv and not c.execute("SELECT 1 FROM subnets WHERE vpc_id=?", (dv["id"],)).fetchone():
                _seed_default_vpc_contents(c, dv)
        set_setting(c, "default_vpc_seeded", "1")


def _dedupe_s3_objects(c):
    """Older console uploads could create two objects with the same key. Keep
    the newest so a unique index can enforce S3's one-key-one-object rule."""
    idx = c.execute("SELECT 1 FROM sqlite_master WHERE name='ux_s3_objects_key'").fetchone()
    if idx:
        return
    c.execute("""DELETE FROM s3_objects WHERE id NOT IN
                 (SELECT MAX(id) FROM s3_objects GROUP BY bucket_id, key)""")


def _upgrade_routes(c, rt_id, raw):
    rt = c.execute("SELECT vpc_id FROM route_tables WHERE id=?", (rt_id,)).fetchone()
    vpc = c.execute("SELECT * FROM vpcs WHERE id=?", (rt["vpc_id"],)).fetchone() if rt else None
    out = []
    for route in rules.parse_routes(raw):
        target = route["target"]
        low = target.lower()
        # Legacy placeholders ("igw", "igw-local", "nat") resolve to the VPC's
        # single gateway of that type when that is unambiguous.
        if vpc and low in ("igw", "igw-local", "internet", "internet-gateway"):
            igws = c.execute("SELECT igw_id FROM internet_gateways WHERE vpc_id=?", (vpc["id"],)).fetchall()
            target = igws[0][0] if len(igws) == 1 else target
        elif vpc and low in ("nat", "nat-local", "nat-gateway"):
            nats = c.execute("SELECT nat_id FROM nat_gateways WHERE vpc_id=?", (vpc["id"],)).fetchall()
            target = nats[0][0] if len(nats) == 1 else target
        out.append({"destination": route["destination"], "target": target})
    if vpc and not any(r["target"] == "local" for r in out):
        out.insert(0, {"destination": vpc["cidr"], "target": "local"})
    return out


def _upgrade_instance_refs(c):
    """Console launches stored internal row ids ("3") for vpc/subnet/security
    groups while the CLI stored AWS ids; normalise everything to AWS ids."""
    for inst in c.execute("SELECT id, vpc, subnet, security_groups FROM ec2_instances").fetchall():
        vpc, subnet, sgs = inst["vpc"] or "", inst["subnet"] or "", inst["security_groups"] or ""
        changed = False
        if subnet.isdigit():
            row = c.execute("SELECT subnet_id FROM subnets WHERE id=?", (int(subnet),)).fetchone()
            subnet = row[0] if row else ""
            changed = True
        if vpc.isdigit():
            row = c.execute("SELECT vpc_id FROM vpcs WHERE id=?", (int(vpc),)).fetchone()
            vpc = row[0] if row else ""
            changed = True
        if subnet and not vpc:
            row = c.execute("SELECT v.vpc_id FROM subnets s JOIN vpcs v ON v.id=s.vpc_id WHERE s.subnet_id=?",
                            (subnet,)).fetchone()
            vpc = row[0] if row else ""
            changed = True
        ids = [x for x in sgs.split(",") if x]
        if any(x.isdigit() for x in ids):
            new = []
            for x in ids:
                if x.isdigit():
                    row = c.execute("SELECT group_id FROM security_groups WHERE id=?", (int(x),)).fetchone()
                    if row:
                        new.append(row[0])
                else:
                    new.append(x)
            ids = new
            changed = True
        if not ids and vpc:
            row = c.execute("""SELECT sg.group_id FROM security_groups sg JOIN vpcs v ON v.id=sg.vpc_id
                               WHERE v.vpc_id=? AND sg.name='default'""", (vpc,)).fetchone()
            if row:
                ids = [row[0]]
                changed = True
        if changed:
            c.execute("UPDATE ec2_instances SET vpc=?, subnet=?, security_groups=? WHERE id=?",
                      (vpc, subnet, ",".join(ids), inst["id"]))


def ensure_vpc_defaults(c, vpc):
    """Create whatever the VPC is missing of: main route table (with the local
    route), default security group, default network ACL. AWS creates all three
    with every VPC."""
    ts = now()
    if not c.execute("SELECT 1 FROM route_tables WHERE vpc_id=? AND main_table=1", (vpc["id"],)).fetchone():
        c.execute(
            "INSERT INTO route_tables(route_table_id,name,vpc_id,routes_json,main_table,tags_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (aws_id("rtb"), "main", vpc["id"], json.dumps([{"destination": vpc["cidr"], "target": "local"}]),
             1, json.dumps({}), ts))
    if not c.execute("SELECT 1 FROM security_groups WHERE vpc_id=? AND name='default'", (vpc["id"],)).fetchone():
        c.execute(
            "INSERT INTO security_groups(group_id,name,description,vpc_id,inbound_json,outbound_json,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (aws_id("sg"), "default", "default VPC security group", vpc["id"],
             json.dumps([rules.parse_sg_rule(x) for x in DEFAULT_SG_INBOUND]),
             json.dumps([rules.parse_sg_rule(x) for x in DEFAULT_SG_OUTBOUND]), json.dumps({}), ts))
    if not c.execute("SELECT 1 FROM network_acls WHERE vpc_id=? AND is_default=1", (vpc["id"],)).fetchone():
        c.execute(
            "INSERT INTO network_acls(acl_id,name,vpc_id,rules_json,is_default,tags_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (aws_id("acl"), "default", vpc["id"], json.dumps(rules.parse_nacl_rules(DEFAULT_NACL_RULES)),
             1, json.dumps({}), ts))


def seed_default_vpc(c):
    """The default VPC every new AWS account/region starts with: 172.31.0.0/16,
    one public /20 subnet per AZ, an attached internet gateway and a 0.0.0.0/0
    route to it in the main route table."""
    vpc_id = aws_id("vpc")
    c.execute(
        "INSERT INTO vpcs(vpc_id,name,cidr,tenancy,dns_support,dns_hostnames,region,account_id,tags_json,created_at,is_default) VALUES(?,?,?,?,?,?,?,?,?,?,1)",
        (vpc_id, "default", DEFAULT_VPC_CIDR, "default", 1, 1, region(c), None, json.dumps({}), now()))
    vpc = c.execute("SELECT * FROM vpcs WHERE vpc_id=?", (vpc_id,)).fetchone()
    ensure_vpc_defaults(c, vpc)
    _seed_default_vpc_contents(c, vpc)


def _seed_default_vpc_contents(c, vpc):
    ts = now()
    igw = aws_id("igw")
    c.execute("INSERT INTO internet_gateways(igw_id,name,vpc_id,state,tags_json,created_at) VALUES(?,?,?,?,?,?)",
              (igw, "default-igw", vpc["id"], "available", json.dumps({}), ts))
    rt = c.execute("SELECT * FROM route_tables WHERE vpc_id=? AND main_table=1", (vpc["id"],)).fetchone()
    routes = rules.parse_routes(rt["routes_json"])
    if not any(r["destination"] == "0.0.0.0/0" for r in routes):
        routes.append({"destination": "0.0.0.0/0", "target": igw})
        c.execute("UPDATE route_tables SET routes_json=? WHERE id=?", (json.dumps(routes), rt["id"]))
    for az, cidr in zip(azs_for(region(c)), DEFAULT_SUBNET_CIDRS):
        c.execute(
            "INSERT INTO subnets(subnet_id,name,vpc_id,cidr,az,public_ipv4,map_public_ip,tags_json,created_at,default_for_az) VALUES(?,?,?,?,?,?,?,?,?,1)",
            (aws_id("subnet"), f"default-{az}", vpc["id"], cidr, az, 1, 1, json.dumps({}), ts))


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

def _encode(v):
    # CLI uploads store raw bytes; JSON needs them wrapped.
    if isinstance(v, bytes):
        return {"__b64__": base64.b64encode(v).decode("ascii")}
    return v


def _decode(v):
    if isinstance(v, dict) and "__b64__" in v:
        return base64.b64decode(v["__b64__"])
    return v


def dump_state(c):
    return {t: [{k: _encode(v) for k, v in dict(r).items()} for r in c.execute(f"SELECT * FROM {t}")]
            for t in STATE_TABLES}


def load_state(c, state):
    """Replace all simulator state with ``state`` (snapshots are preserved)."""
    for t in reversed(STATE_TABLES):
        c.execute(f"DELETE FROM {t}")
    for t in STATE_TABLES:
        rows = state.get(t) or []
        if not rows:
            continue
        known = {r[1] for r in c.execute(f"PRAGMA table_info({t})")}
        for r in rows:
            cols = [k for k in r if k in known]
            c.execute(f"INSERT INTO {t} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                      [_decode(r[k]) for k in cols])
    migrate(c)


def reset_state(c):
    for t in reversed(STATE_TABLES):
        if t not in RESET_KEEP:
            c.execute(f"DELETE FROM {t}")
    c.execute("DELETE FROM activity_log")
    c.execute("DELETE FROM lambda_invocations")
    set_setting(c, "org_name", "")
    set_setting(c, "region", DEFAULT_REGION)
    c.execute("DELETE FROM settings WHERE key='default_vpc_seeded'")
    migrate(c)
