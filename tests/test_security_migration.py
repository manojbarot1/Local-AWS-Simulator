"""Local-only protections, and upgrading a database created by the previous release."""

import json
import sqlite3

import app as app_module
import db
import labs


def test_cross_site_posts_are_refused(client):
    r = client.post("/network/vpc/create", data={"name": "x", "cidr": "10.0.0.0/16"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    r = client.post("/aws", data={"Action": "CreateVpc", "CidrBlock": "10.0.0.0/16"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    ok = client.post("/network/vpc/create", data={"name": "x", "cidr": "10.0.0.0/16"},
                     headers={"Origin": "http://localhost"})
    assert ok.status_code == 302


def test_foreign_host_names_are_refused(client):
    # DNS rebinding: attacker.example resolving to 127.0.0.1
    assert client.get("/login", headers={"Host": "attacker.example:8080"}).status_code == 403
    assert client.get("/login", headers={"Host": "127.0.0.1:8080"}).status_code == 200


LEGACY_SCHEMA = """
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE ous (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, parent_id INTEGER);
CREATE TABLE accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL, account_id TEXT NOT NULL UNIQUE, ou_id INTEGER);
CREATE TABLE policies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, category TEXT);
CREATE TABLE policy_attachments (policy_id INTEGER, target_type TEXT, target_id INTEGER);
CREATE TABLE vpcs (id INTEGER PRIMARY KEY AUTOINCREMENT, vpc_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, cidr TEXT NOT NULL, tenancy TEXT DEFAULT 'default', dns_support INTEGER DEFAULT 1, dns_hostnames INTEGER DEFAULT 1, region TEXT, account_id INTEGER, tags_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE subnets (id INTEGER PRIMARY KEY AUTOINCREMENT, subnet_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, vpc_id INTEGER NOT NULL, cidr TEXT NOT NULL, az TEXT, public_ipv4 INTEGER DEFAULT 0, map_public_ip INTEGER DEFAULT 0, route_table_id INTEGER, tags_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE route_tables (id INTEGER PRIMARY KEY AUTOINCREMENT, route_table_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, vpc_id INTEGER NOT NULL, routes_json TEXT, main_table INTEGER DEFAULT 0, tags_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE internet_gateways (id INTEGER PRIMARY KEY AUTOINCREMENT, igw_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, vpc_id INTEGER, state TEXT DEFAULT 'available', tags_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE security_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, description TEXT, vpc_id INTEGER NOT NULL, inbound_json TEXT, outbound_json TEXT, tags_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE network_acls (id INTEGER PRIMARY KEY AUTOINCREMENT, acl_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, vpc_id INTEGER NOT NULL, rules_json TEXT, is_default INTEGER DEFAULT 0, tags_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE ec2_instances (id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, state TEXT NOT NULL, os TEXT NOT NULL, ami_id TEXT NOT NULL, instance_type TEXT NOT NULL, vpc TEXT, subnet TEXT, security_groups TEXT, key_name TEXT, private_ip TEXT, public_ip TEXT, root_volume_gib INTEGER, root_volume_type TEXT, encrypted INTEGER DEFAULT 1, architecture TEXT, tags_json TEXT, config_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE s3_buckets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, region TEXT, versioning INTEGER DEFAULT 0, public INTEGER DEFAULT 0, encryption TEXT DEFAULT 'SSE-S3', created_at TEXT NOT NULL);
CREATE TABLE s3_objects (id INTEGER PRIMARY KEY AUTOINCREMENT, bucket_id INTEGER NOT NULL, key TEXT NOT NULL, size_bytes INTEGER DEFAULT 0, content_type TEXT, storage_class TEXT DEFAULT 'STANDARD', body TEXT, created_at TEXT NOT NULL);
"""


def test_upgrades_a_previous_release_database(tmp_path):
    path = str(tmp_path / "old.db")
    c = sqlite3.connect(path)
    c.executescript(LEGACY_SCHEMA)
    t = "2026-08-18T10:00:00"
    c.executemany("INSERT INTO settings VALUES (?,?)", [("org_name", "Acme"), ("region", "eu-central-1")])
    c.execute("INSERT INTO vpcs(vpc_id,name,cidr,created_at) VALUES('vpc-default000000000','default','172.31.0.0/16',?)", (t,))
    c.execute("INSERT INTO vpcs(vpc_id,name,cidr,created_at) VALUES('vpc-prod00000000000','prod','10.20.0.0/16',?)", (t,))
    c.execute("INSERT INTO route_tables(route_table_id,name,vpc_id,routes_json,main_table,created_at) VALUES('rtb-main','main',1,?,1,?)",
              (json.dumps(["172.31.0.0/16 -> local"]), t))
    c.execute("INSERT INTO subnets(subnet_id,name,vpc_id,cidr,az,map_public_ip,created_at) VALUES('subnet-pub','pub',2,'10.20.1.0/24','eu-central-1a',1,?)", (t,))
    c.execute("INSERT INTO internet_gateways(igw_id,name,vpc_id,created_at) VALUES('igw-prod','igw',2,?)", (t,))
    c.execute("INSERT INTO route_tables(route_table_id,name,vpc_id,routes_json,main_table,created_at) VALUES('rtb-pub','public',2,?,0,?)",
              (json.dumps(["0.0.0.0/0 -> igw-local"]), t))
    c.execute("INSERT INTO security_groups(group_id,name,description,vpc_id,inbound_json,outbound_json,created_at) VALUES('sg-web','web','',2,?,?,?)",
              (json.dumps(["HTTP TCP 80 0.0.0.0/0"]), json.dumps(["All TCP/UDP/ICMP 0.0.0.0/0"]), t))
    # Console launches used internal row ids; CLI launches used AWS ids.
    c.execute("INSERT INTO ec2_instances(instance_id,name,state,os,ami_id,instance_type,vpc,subnet,security_groups,private_ip,created_at,config_json) "
              "VALUES('i-console','web','running','Linux','ami-0e001c9271cf7f3b9','t3.small','2','1','1',"
              "'10.20.1.4',?,'{}')", (t,))
    c.execute("INSERT INTO s3_buckets(name,created_at) VALUES('b',?)", (t,))
    c.execute("INSERT INTO s3_objects(bucket_id,key,body,created_at) VALUES(1,'dup','old',?)", (t,))
    c.execute("INSERT INTO s3_objects(bucket_id,key,body,created_at) VALUES(1,'dup','new',?)", (t,))
    c.commit()
    c.close()

    app_module.create_app(path, testing=True)
    c = db.connect(path)
    assert c.execute("SELECT is_default FROM vpcs WHERE name='default'").fetchone()[0] == 1
    assert c.execute("SELECT COUNT(*) FROM subnets WHERE default_for_az=1").fetchone()[0] == 3
    routes = json.loads(c.execute("SELECT routes_json FROM route_tables WHERE route_table_id='rtb-pub'").fetchone()[0])
    assert {"destination": "0.0.0.0/0", "target": "igw-prod"} in routes   # legacy "igw-local" resolved
    sg = json.loads(c.execute("SELECT inbound_json FROM security_groups WHERE group_id='sg-web'").fetchone()[0])
    assert sg[0]["protocol"] == "tcp" and sg[0]["from_port"] == 80
    inst = c.execute("SELECT vpc, subnet, security_groups FROM ec2_instances").fetchone()
    assert tuple(inst) == ("vpc-prod00000000000", "subnet-pub", "sg-web")
    assert [r[0] for r in c.execute("SELECT body FROM s3_objects")] == ["new"]
    assert c.execute("SELECT COUNT(*) FROM route_tables WHERE main_table=1").fetchone()[0] == 2   # prod got a main RT
    # Upgrading twice is a no-op.
    app_module.create_app(path, testing=True)
    assert c.execute("SELECT COUNT(*) FROM subnets").fetchone()[0] == 4
    labs.evaluate_all(c)
    c.close()
