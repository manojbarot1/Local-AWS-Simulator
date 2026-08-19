from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, flash
import sqlite3
import json
from datetime import datetime
import os
import re
import random
import uuid

from aws_fidelity import (
    aws_id,
    AMI_CATALOG,
    EC2_INSTANCE_TYPES,
    instance_type_spec,
    azs_for,
    allocate_private_ip,
    private_dns_name,
    public_dns_name,
    random_public_ip,
    DEFAULT_VPC_CIDR,
    DEFAULT_SG_INBOUND,
    DEFAULT_SG_OUTBOUND,
    DEFAULT_NACL_RULES,
)
import aws_api
from services import services_bp, ensure_service_tables, service_counts

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "simulator.db")
app = Flask(__name__)
app.secret_key = "local-aws-simulator-phase1"

# Extra AWS service consoles (S3, IAM, Lambda, DynamoDB, Secrets Manager).
ensure_service_tables()
app.register_blueprint(services_bp)

DEFAULT_POLICIES = [
    ("Restrict Regions", "Prevent use of unapproved AWS regions.", "Governance"),
    ("Protect CloudTrail", "Prevent workloads from disabling or modifying centralized audit logging.", "Security"),
    ("Prevent Account Leave", "Prevent member accounts from leaving the organization.", "Governance"),
    ("Deny Root Actions", "Baseline control to discourage direct root-user operations.", "Security"),
]

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY, value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ous (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, parent_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT NOT NULL,
        account_id TEXT NOT NULL UNIQUE, ou_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, description TEXT, category TEXT
    );
    CREATE TABLE IF NOT EXISTS policy_attachments (
        policy_id INTEGER, target_type TEXT, target_id INTEGER
    );
    """)
    if c.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 0:
        c.execute("INSERT INTO settings VALUES ('org_name','')")
        c.execute("INSERT INTO settings VALUES ('region','eu-central-1')")
    if c.execute("SELECT COUNT(*) FROM policies").fetchone()[0] == 0:
        c.executemany("INSERT INTO policies(name,description,category) VALUES (?,?,?)", DEFAULT_POLICIES)
    c.commit(); c.close()

def logged_in():
    return session.get("user") == "demo"

@app.before_request
def setup():
    init_db()
    seed_default_network()
    # AWS Query API (CLI / boto3) is unauthenticated, like every local emulator.
    if aws_api.is_aws_api_request(request):
        return
    if request.endpoint not in ("login", "static") and not logged_in():
        return redirect(url_for("login"))


@app.route("/aws", defaults={"api_path": ""}, methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
@app.route("/aws/<path:api_path>", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
def aws_query_api(api_path):
    """AWS-compatible endpoint for the real `aws` CLI and boto3.

    EC2 uses the Query protocol; S3 uses its REST/XML protocol. Point tools at it with:
        --endpoint-url http://localhost:8080/aws
    It shares the simulator's SQLite state with the web console.
    """
    body, status, headers = aws_api.handle(request, DB)
    return Response(body, status=status, headers=headers)


def ensure_ec2_tables():
    db=sqlite3.connect(DB)
    db.execute("""CREATE TABLE IF NOT EXISTS ec2_instances (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instance_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        state TEXT NOT NULL,
        os TEXT NOT NULL,
        ami_id TEXT NOT NULL,
        instance_type TEXT NOT NULL,
        vpc TEXT,
        subnet TEXT,
        security_groups TEXT,
        key_name TEXT,
        private_ip TEXT,
        public_ip TEXT,
        root_volume_gib INTEGER,
        root_volume_type TEXT,
        encrypted INTEGER DEFAULT 1,
        architecture TEXT,
        tags_json TEXT,
        config_json TEXT,
        created_at TEXT NOT NULL
    )""")
    db.commit(); db.close()

ensure_ec2_tables()


def ensure_network_tables():
    c=sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS vpcs (
      id INTEGER PRIMARY KEY AUTOINCREMENT, vpc_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      cidr TEXT NOT NULL, tenancy TEXT DEFAULT 'default', dns_support INTEGER DEFAULT 1,
      dns_hostnames INTEGER DEFAULT 1, region TEXT, account_id INTEGER, tags_json TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS subnets (
      id INTEGER PRIMARY KEY AUTOINCREMENT, subnet_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      vpc_id INTEGER NOT NULL, cidr TEXT NOT NULL, az TEXT, public_ipv4 INTEGER DEFAULT 0,
      map_public_ip INTEGER DEFAULT 0, route_table_id INTEGER, tags_json TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS route_tables (
      id INTEGER PRIMARY KEY AUTOINCREMENT, route_table_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      vpc_id INTEGER NOT NULL, routes_json TEXT, main_table INTEGER DEFAULT 0, tags_json TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS internet_gateways (
      id INTEGER PRIMARY KEY AUTOINCREMENT, igw_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      vpc_id INTEGER, state TEXT DEFAULT 'available', tags_json TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS nat_gateways (
      id INTEGER PRIMARY KEY AUTOINCREMENT, nat_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      vpc_id INTEGER NOT NULL, subnet_id INTEGER NOT NULL, connectivity_type TEXT DEFAULT 'public',
      allocation_id TEXT, state TEXT DEFAULT 'available', tags_json TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS security_groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      description TEXT, vpc_id INTEGER NOT NULL, inbound_json TEXT, outbound_json TEXT,
      tags_json TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS network_acls (
      id INTEGER PRIMARY KEY AUTOINCREMENT, acl_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      vpc_id INTEGER NOT NULL, rules_json TEXT, is_default INTEGER DEFAULT 0, tags_json TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS elastic_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT, allocation_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      public_ip TEXT NOT NULL, domain TEXT DEFAULT 'vpc', association TEXT, state TEXT DEFAULT 'allocated',
      tags_json TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS load_balancers (
      id INTEGER PRIMARY KEY AUTOINCREMENT, lb_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      lb_type TEXT DEFAULT 'application', scheme TEXT DEFAULT 'internet-facing', vpc_id INTEGER,
      subnets_json TEXT, security_groups_json TEXT, state TEXT DEFAULT 'active', tags_json TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS vpc_endpoints (
      id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      vpc_id INTEGER NOT NULL, service_name TEXT NOT NULL, endpoint_type TEXT DEFAULT 'gateway',
      route_tables_json TEXT, subnets_json TEXT, state TEXT DEFAULT 'available', tags_json TEXT, created_at TEXT NOT NULL
    );
    """)
    c.commit(); c.close()

ensure_network_tables()


def net_id(prefix):
    # Real AWS-format ids (e.g. vpc-0a1b2c3d4e5f60718) instead of the old
    # vpc-local-<uuid> scheme that no AWS tool would accept.
    return aws_id(prefix)


def seed_default_network():
    """Auto-create the default VPC the way real AWS does, so a fresh environment
    is never empty. Only seeds when there are no VPCs, so it never fights user
    data or a restored snapshot."""
    c = db()
    try:
        if c.execute("SELECT COUNT(*) FROM vpcs").fetchone()[0] > 0:
            return
        region = (c.execute("SELECT value FROM settings WHERE key='region'").fetchone() or ["eu-central-1"])[0] or "eu-central-1"
        now = datetime.now().isoformat(timespec="seconds")
        vpc_id = aws_id("vpc")
        c.execute(
            "INSERT INTO vpcs(vpc_id,name,cidr,tenancy,dns_support,dns_hostnames,region,account_id,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (vpc_id, "default", DEFAULT_VPC_CIDR, "default", 1, 1, region, None, json.dumps({"Name": "default"}), now),
        )
        vpc_row = c.execute("SELECT id FROM vpcs WHERE vpc_id=?", (vpc_id,)).fetchone()["id"]
        # Main route table with the implicit local route.
        c.execute(
            "INSERT INTO route_tables(route_table_id,name,vpc_id,routes_json,main_table,tags_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (aws_id("rtb"), "main", vpc_row, json.dumps([f"{DEFAULT_VPC_CIDR} -> local"]), 1, json.dumps({"Name": "main"}), now),
        )
        # Default security group (allow self inbound, all outbound).
        c.execute(
            "INSERT INTO security_groups(group_id,name,description,vpc_id,inbound_json,outbound_json,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (aws_id("sg"), "default", "default VPC security group", vpc_row, json.dumps(DEFAULT_SG_INBOUND), json.dumps(DEFAULT_SG_OUTBOUND), json.dumps({}), now),
        )
        # Default network ACL (allow all both ways + implicit deny).
        c.execute(
            "INSERT INTO network_acls(acl_id,name,vpc_id,rules_json,is_default,tags_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (aws_id("acl"), "default", vpc_row, json.dumps(DEFAULT_NACL_RULES), 1, json.dumps({}), now),
        )
        c.commit()
    finally:
        c.close()

def resource_counts():
    c=db()
    names=['vpcs','subnets','route_tables','internet_gateways','nat_gateways','security_groups','network_acls','elastic_ips','load_balancers','vpc_endpoints','ec2_instances']
    out={n:c.execute(f'SELECT COUNT(*) FROM {n}').fetchone()[0] for n in names}
    c.close(); return out

@app.route('/network')
def network_home():
    c=db()
    data={
      'vpcs':[dict(r) for r in c.execute('SELECT * FROM vpcs ORDER BY id DESC').fetchall()],
      'subnets':[dict(r) for r in c.execute('SELECT s.*,v.name vpc_name FROM subnets s JOIN vpcs v ON v.id=s.vpc_id ORDER BY s.id DESC').fetchall()],
      'route_tables':[dict(r) for r in c.execute('SELECT r.*,v.name vpc_name FROM route_tables r JOIN vpcs v ON v.id=r.vpc_id ORDER BY r.id DESC').fetchall()],
      'igws':[dict(r) for r in c.execute('SELECT i.*,v.name vpc_name FROM internet_gateways i LEFT JOIN vpcs v ON v.id=i.vpc_id ORDER BY i.id DESC').fetchall()],
      'nats':[dict(r) for r in c.execute('SELECT n.*,v.name vpc_name,s.name subnet_name FROM nat_gateways n JOIN vpcs v ON v.id=n.vpc_id JOIN subnets s ON s.id=n.subnet_id ORDER BY n.id DESC').fetchall()],
      'sgs':[dict(r) for r in c.execute('SELECT s.*,v.name vpc_name FROM security_groups s JOIN vpcs v ON v.id=s.vpc_id ORDER BY s.id DESC').fetchall()],
      'acls':[dict(r) for r in c.execute('SELECT a.*,v.name vpc_name FROM network_acls a JOIN vpcs v ON v.id=a.vpc_id ORDER BY a.id DESC').fetchall()],
      'eips':[dict(r) for r in c.execute('SELECT * FROM elastic_ips ORDER BY id DESC').fetchall()],
      'lbs':[dict(r) for r in c.execute('SELECT l.*,v.name vpc_name FROM load_balancers l LEFT JOIN vpcs v ON v.id=l.vpc_id ORDER BY l.id DESC').fetchall()],
      'endpoints':[dict(r) for r in c.execute('SELECT e.*,v.name vpc_name FROM vpc_endpoints e JOIN vpcs v ON v.id=e.vpc_id ORDER BY e.id DESC').fetchall()],
    }
    c.close()
    return render_template('network.html', data=data, counts=resource_counts())

def _created(rid, label, anchor):
    """Post-create redirect: success banner + ?new=<id> so the row gets the
    AWS-console green highlight for a few seconds."""
    flash(f"{label} {rid} created successfully.", "success")
    return redirect(f"/network?new={rid}#{anchor}")

@app.route('/network/vpc/create', methods=['POST'])
def create_vpc():
    f=request.form; name=f.get('name','').strip(); cidr=f.get('cidr','10.0.0.0/16').strip()
    if name and cidr:
        rid=net_id('vpc')
        c=db(); c.execute('INSERT INTO vpcs(vpc_id,name,cidr,tenancy,dns_support,dns_hostnames,region,account_id,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
          (rid,name,cidr,f.get('tenancy','default'),1 if f.get('dns_support') else 0,1 if f.get('dns_hostnames') else 0,f.get('region','eu-central-1'),f.get('account_id') or None,json.dumps({'Name':name}),datetime.now().isoformat(timespec='seconds'))); c.commit(); c.close()
        return _created(rid,'VPC','vpcs')
    return redirect(url_for('network_home'))

@app.route('/network/subnet/create', methods=['POST'])
def create_subnet():
    f=request.form; name=f.get('name','').strip(); vpc=int(f.get('vpc_id')); cidr=f.get('cidr','').strip()
    if name and cidr:
        rid=net_id('subnet')
        c=db(); c.execute('INSERT INTO subnets(subnet_id,name,vpc_id,cidr,az,public_ipv4,map_public_ip,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
          (rid,name,vpc,cidr,f.get('az','eu-central-1a'),1 if f.get('public_ipv4') else 0,1 if f.get('map_public_ip') else 0,json.dumps({'Name':name}),datetime.now().isoformat(timespec='seconds'))); c.commit(); c.close()
        return _created(rid,'Subnet','subnets')
    return redirect(url_for('network_home'))

@app.route('/network/route-table/create', methods=['POST'])
def create_route_table():
    f=request.form; name=f.get('name','').strip(); vpc=int(f.get('vpc_id')); routes=f.get('routes','0.0.0.0/0 -> igw-local').strip()
    if name:
        rid=net_id('rtb')
        c=db(); c.execute('INSERT INTO route_tables(route_table_id,name,vpc_id,routes_json,main_table,tags_json,created_at) VALUES(?,?,?,?,?,?,?)',
          (rid,name,vpc,json.dumps([routes]),1 if f.get('main_table') else 0,json.dumps({'Name':name}),datetime.now().isoformat(timespec='seconds'))); c.commit(); c.close()
        return _created(rid,'Route table','route-tables')
    return redirect(url_for('network_home'))

@app.route('/network/igw/create', methods=['POST'])
def create_igw():
    f=request.form; name=f.get('name','').strip(); vpc=f.get('vpc_id') or None
    if name:
        rid=net_id('igw')
        c=db(); c.execute('INSERT INTO internet_gateways(igw_id,name,vpc_id,state,tags_json,created_at) VALUES(?,?,?,?,?,?)',(rid,name,int(vpc) if vpc else None,'available',json.dumps({'Name':name}),datetime.now().isoformat(timespec='seconds'))); c.commit(); c.close()
        return _created(rid,'Internet gateway','internet-gateways')
    return redirect(url_for('network_home'))

@app.route('/network/nat/create', methods=['POST'])
def create_nat():
    f=request.form; name=f.get('name','').strip(); vpc=int(f.get('vpc_id')); subnet=int(f.get('subnet_id'))
    if name:
        rid=net_id('nat')
        c=db(); c.execute('INSERT INTO nat_gateways(nat_id,name,vpc_id,subnet_id,connectivity_type,allocation_id,state,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(rid,name,vpc,subnet,f.get('connectivity_type','public'),f.get('allocation_id',''), 'available',json.dumps({'Name':name}),datetime.now().isoformat(timespec='seconds'))); c.commit(); c.close()
        return _created(rid,'NAT gateway','nat-gateways')
    return redirect(url_for('network_home'))

@app.route('/network/security-group/create', methods=['POST'])
def create_sg():
    f=request.form; name=f.get('name','').strip(); vpc=int(f.get('vpc_id')); desc=f.get('description','').strip()
    inbound=[x.strip() for x in f.get('inbound','').splitlines() if x.strip()]; outbound=[x.strip() for x in f.get('outbound','').splitlines() if x.strip()]
    if name:
        rid=net_id('sg')
        c=db(); c.execute('INSERT INTO security_groups(group_id,name,description,vpc_id,inbound_json,outbound_json,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?)',(rid,name,desc,vpc,json.dumps(inbound),json.dumps(outbound),json.dumps({'Name':name}),datetime.now().isoformat(timespec='seconds'))); c.commit(); c.close()
        return _created(rid,'Security group','security-groups')
    return redirect(url_for('network_home'))

@app.route('/network/acl/create', methods=['POST'])
def create_acl():
    f=request.form; name=f.get('name','').strip(); vpc=int(f.get('vpc_id'))
    if name:
        rid=net_id('acl')
        c=db(); c.execute('INSERT INTO network_acls(acl_id,name,vpc_id,rules_json,is_default,tags_json,created_at) VALUES(?,?,?,?,?,?,?)',(rid,name,vpc,json.dumps([f.get('rule','100 ALLOW ALL')]),1 if f.get('is_default') else 0,json.dumps({'Name':name}),datetime.now().isoformat(timespec='seconds'))); c.commit(); c.close()
        return _created(rid,'Network ACL','network-acls')
    return redirect(url_for('network_home'))

@app.route('/network/eip/create', methods=['POST'])
def create_eip():
    f=request.form; name=f.get('name','').strip()
    if name:
        rid=net_id('eipalloc')
        c=db(); c.execute('INSERT INTO elastic_ips(allocation_id,name,public_ip,domain,association,state,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?)',(rid,name,random_public_ip(),'vpc',f.get('association',''),'allocated',json.dumps({'Name':name}),datetime.now().isoformat(timespec='seconds'))); c.commit(); c.close()
        return _created(rid,'Elastic IP','elastic-ips')
    return redirect(url_for('network_home'))

@app.route('/network/lb/create', methods=['POST'])
def create_lb():
    f=request.form; name=f.get('name','').strip(); vpc=f.get('vpc_id') or None
    if name:
        rid=net_id('lb')
        c=db(); c.execute('INSERT INTO load_balancers(lb_id,name,lb_type,scheme,vpc_id,subnets_json,security_groups_json,state,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(rid,name,f.get('lb_type','application'),f.get('scheme','internet-facing'),int(vpc) if vpc else None,json.dumps([x for x in f.get('subnets','').split(',') if x]),json.dumps([x for x in f.get('security_groups','').split(',') if x]),'active',json.dumps({'Name':name}),datetime.now().isoformat(timespec='seconds'))); c.commit(); c.close()
        return _created(rid,'Load balancer','load-balancers')
    return redirect(url_for('network_home'))

@app.route('/network/endpoint/create', methods=['POST'])
def create_endpoint():
    f=request.form; name=f.get('name','').strip(); vpc=int(f.get('vpc_id')); service=f.get('service_name','').strip()
    if name and service:
        rid=net_id('vpce')
        c=db(); c.execute('INSERT INTO vpc_endpoints(endpoint_id,name,vpc_id,service_name,endpoint_type,route_tables_json,subnets_json,state,tags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(rid,name,vpc,service,f.get('endpoint_type','gateway'),json.dumps([]),json.dumps([]),'available',json.dumps({'Name':name}),datetime.now().isoformat(timespec='seconds'))); c.commit(); c.close()
        return _created(rid,'VPC endpoint','endpoints')
    return redirect(url_for('network_home'))

@app.route('/network/delete/<resource>/<int:id>', methods=['POST'])
def delete_network_resource(resource,id):
    allowed={'vpc':'vpcs','subnet':'subnets','route-table':'route_tables','igw':'internet_gateways','nat':'nat_gateways','security-group':'security_groups','acl':'network_acls','eip':'elastic_ips','lb':'load_balancers','endpoint':'vpc_endpoints'}
    table=allowed.get(resource)
    if table:
        c=db(); c.execute(f'DELETE FROM {table} WHERE id=?',(id,)); c.commit(); c.close()
    return redirect(url_for('network_home'))

# AMI catalogue comes from the fidelity module: real AWS-format image ids and
# metadata, same os/arch/name keys the templates already use.
EC2_AMIS = AMI_CATALOG
# Shared with the AWS Query endpoint via the fidelity module.
EC2_TYPES = EC2_INSTANCE_TYPES

@app.route("/compute")
def compute():
    if "user" not in session: return redirect(url_for("login"))
    db=sqlite3.connect(DB); db.row_factory=sqlite3.Row
    rows=[dict(r) for r in db.execute("SELECT * FROM ec2_instances ORDER BY id DESC").fetchall()]
    db.close()
    return render_template("compute.html", instances=rows)

@app.route("/compute/launch", methods=["GET","POST"])
def launch_instance():
    if "user" not in session: return redirect(url_for("login"))
    def form_context():
        c=db()
        ous=[dict(r) for r in c.execute("SELECT * FROM ous ORDER BY name").fetchall()]
        accounts=[dict(r) for r in c.execute("SELECT * FROM accounts ORDER BY name").fetchall()]
        vpcs=[dict(r) for r in c.execute("SELECT * FROM vpcs ORDER BY name").fetchall()]
        subnets=[dict(r) for r in c.execute("SELECT s.*,v.name vpc_name FROM subnets s JOIN vpcs v ON v.id=s.vpc_id ORDER BY s.name").fetchall()]
        sgs=[dict(r) for r in c.execute("SELECT sg.*,v.name vpc_name FROM security_groups sg JOIN vpcs v ON v.id=sg.vpc_id ORDER BY sg.name").fetchall()]
        c.close()
        return dict(ous=ous,accounts=accounts,vpcs=vpcs,subnets=subnets,sgs=sgs)
    if request.method=="GET":
        return render_template("launch_instance.html", amis=EC2_AMIS, types=EC2_TYPES, **form_context())
    form=request.form; errors=[]
    name=form.get("name","").strip(); ami_id=form.get("ami_id",""); itype=form.get("instance_type","")
    try: count=max(1,min(20,int(form.get("count","1") or 1)))
    except: count=1
    try: root_size=max(1,int(form.get("root_size","30") or 30))
    except: root_size=30
    if not name: errors.append("Enter an instance name.")
    ami=next((x for x in EC2_AMIS if x["id"]==ami_id),None)
    typ=next((x for x in EC2_TYPES if x[0]==itype),None)
    if not ami: errors.append("Select a valid AMI.")
    if not typ: errors.append("Select a valid instance type.")
    vpc_id=form.get("vpc_id") or ""; subnet_id=form.get("subnet_id") or ""; sg_ids=form.getlist("security_group_id")
    c=db(); selected_subnet=None; sg_rows=[]
    if subnet_id:
        selected_subnet=c.execute("SELECT s.*,v.name vpc_name FROM subnets s JOIN vpcs v ON v.id=s.vpc_id WHERE s.id=?",(subnet_id,)).fetchone()
        if not selected_subnet: errors.append("Selected subnet does not exist.")
        elif vpc_id and str(selected_subnet["vpc_id"]) != str(vpc_id): errors.append("Selected subnet does not belong to the selected VPC.")
    if sg_ids:
        placeholders=','.join('?'*len(sg_ids)); sg_rows=c.execute(f"SELECT * FROM security_groups WHERE id IN ({placeholders})",sg_ids).fetchall()
        if len(sg_rows)!=len(sg_ids): errors.append("One or more selected security groups do not exist.")
        if vpc_id and any(str(r["vpc_id"])!=str(vpc_id) for r in sg_rows): errors.append("Security groups must belong to the selected VPC.")
    c.close()
    if root_size < 8: errors.append("Root volume must be at least 8 GiB.")
    if not vpc_id and subnet_id: errors.append("Select a VPC when selecting a subnet.")
    if errors:
        return render_template("launch_instance.html", amis=EC2_AMIS, types=EC2_TYPES, errors=errors, form=form, **form_context())
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; created=[]
    # Region/AZ, CIDR-based private IPs and real EC2 DNS names.
    region=(c.execute("SELECT value FROM settings WHERE key='region'").fetchone() or ["eu-central-1"])[0] or "eu-central-1"
    subnet_cidr=selected_subnet["cidr"] if selected_subnet else DEFAULT_VPC_CIDR
    subnet_az=(selected_subnet["az"] if selected_subnet and selected_subnet["az"] else azs_for(region)[0])
    used_ips=[r[0] for r in c.execute("SELECT private_ip FROM ec2_instances WHERE private_ip IS NOT NULL").fetchall()]
    for n in range(count):
        iid=aws_id("i")
        private=allocate_private_ip(subnet_cidr, used_ips)
        used_ips.append(private)
        public=random_public_ip() if form.get("public_ip")=="on" else ""
        tags={"Name": name if count==1 else f"{name}-{n+1}", "Environment":form.get("environment","NonProduction")}
        config={"ami":ami,"instance_type":{"name":typ[0],"vcpus":typ[1],"memory_gib":typ[2],"network":typ[3]},"network":{"vpc":vpc_id,"subnet":subnet_id,"public_ip":form.get("public_ip")=="on","availability_zone":subnet_az,"private_dns":private_dns_name(private,region),"public_dns":public_dns_name(public,region) if public else ""},"security_groups":sg_ids,"key_name":form.get("key_name",""),"iam_profile":form.get("iam_profile",""),"monitoring":form.get("monitoring")=="on","termination_protection":form.get("termination_protection")=="on","metadata_http_tokens":form.get("metadata_http_tokens","required"),"user_data":form.get("user_data",""),"volumes":[{"device":ami.get("root_device","/dev/sda1"),"type":form.get("root_type","gp3"),"size_gib":root_size,"encrypted":form.get("encrypted")=="on"}],"placement_group":form.get("placement_group",""),"tenancy":form.get("tenancy","default")}
        c.execute("""INSERT INTO ec2_instances(instance_id,name,state,os,ami_id,instance_type,vpc,subnet,security_groups,key_name,private_ip,public_ip,root_volume_gib,root_volume_type,encrypted,architecture,tags_json,config_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(iid,tags["Name"],"running",ami["os"],ami_id,itype,vpc_id,subnet_id,",".join(sg_ids),form.get("key_name",""),private,public,root_size,form.get("root_type","gp3"),1 if form.get("encrypted")=="on" else 0,ami["arch"],json.dumps(tags),json.dumps(config),datetime.now().isoformat(timespec="seconds")))
        created.append(iid)
    c.commit(); c.close()
    flash(f"Successfully initiated launch of {len(created)} instance{'s' if len(created)>1 else ''} ({', '.join(created)})","success")
    return redirect(url_for("instance_detail",instance_id=created[0]))

@app.route("/compute/instance/<instance_id>")
def instance_detail(instance_id):
    if "user" not in session: return redirect(url_for("login"))
    db=sqlite3.connect(DB); db.row_factory=sqlite3.Row
    row=db.execute("SELECT * FROM ec2_instances WHERE instance_id=?",(instance_id,)).fetchone()
    db.close()
    if not row: return "Instance not found",404
    inst=dict(row); inst["tags"]=json.loads(inst["tags_json"] or "{}")
    cfg=json.loads(inst["config_json"] or "{}")
    # Normalize: instances created through the AWS CLI endpoint carry a minimal
    # config, so fill the keys the template renders from row data / the shared
    # type catalogue instead of crashing on missing attributes.
    if not isinstance(cfg.get("instance_type"), dict):
        cfg["instance_type"]=instance_type_spec(inst["instance_type"])
    if not cfg.get("volumes"):
        cfg["volumes"]=[{"device":"/dev/sda1","type":inst["root_volume_type"] or "gp3",
                         "size_gib":inst["root_volume_gib"] or 8,"encrypted":bool(inst["encrypted"])}]
    cfg.setdefault("network",{})
    inst["config"]=cfg
    return render_template("instance_detail.html",instance=inst)

@app.route("/compute/instance/<instance_id>/action", methods=["POST"])
def instance_action(instance_id):
    if "user" not in session: return redirect(url_for("login"))
    action=request.form.get("action")
    transitions={"start":"running","stop":"stopped","reboot":"running","terminate":"terminated"}
    if action in transitions:
        db=sqlite3.connect(DB); db.row_factory=sqlite3.Row
        row=db.execute("SELECT config_json FROM ec2_instances WHERE instance_id=?",(instance_id,)).fetchone()
        cfg=json.loads(row["config_json"] or "{}") if row else {}
        if action=="terminate" and cfg.get("termination_protection"):
            db.close()
            flash(f"Failed to terminate {instance_id}: termination protection is enabled. Disable it first.","error")
            return redirect(request.referrer or url_for("instance_detail",instance_id=instance_id))
        db.execute("UPDATE ec2_instances SET state=? WHERE instance_id=?",(transitions[action],instance_id))
        db.commit(); db.close()
        flash(f"Instance {instance_id}: {action} → {transitions[action]}","success")
    elif action=="toggle_protection":
        db=sqlite3.connect(DB); db.row_factory=sqlite3.Row
        row=db.execute("SELECT config_json FROM ec2_instances WHERE instance_id=?",(instance_id,)).fetchone()
        if row:
            cfg=json.loads(row["config_json"] or "{}")
            cfg["termination_protection"]=not cfg.get("termination_protection")
            db.execute("UPDATE ec2_instances SET config_json=? WHERE instance_id=?",(json.dumps(cfg),instance_id))
            db.commit()
            flash(f"Termination protection {'enabled' if cfg['termination_protection'] else 'disabled'} for {instance_id}","success")
        db.close()
    return redirect(request.referrer or url_for("instance_detail",instance_id=instance_id))

@app.route("/compute/instance/<instance_id>/delete", methods=["POST"])
def delete_instance(instance_id):
    """Remove a terminated instance from the list — the console equivalent of
    AWS's automatic cleanup of terminated instances."""
    if "user" not in session: return redirect(url_for("login"))
    db=sqlite3.connect(DB); db.row_factory=sqlite3.Row
    row=db.execute("SELECT state FROM ec2_instances WHERE instance_id=?",(instance_id,)).fetchone()
    if row and row["state"]=="terminated":
        db.execute("DELETE FROM ec2_instances WHERE instance_id=?",(instance_id,))
        db.commit()
        flash(f"Removed terminated instance {instance_id}","success")
    elif row:
        flash(f"{instance_id} is {row['state']} — terminate it before deleting.","error")
    db.close()
    return redirect(url_for("compute"))


# Labs are grouped into ordered categories and numbered in the intended
# learning sequence. Completion is always computed live from simulator state,
# so renumbering is safe — nothing persists lab ids.
LAB_CATEGORIES = [
    ("Foundation", "Landing-zone groundwork: organization, accounts and governance."),
    ("Networking", "VPC design: subnets, routing, gateways and egress patterns."),
    ("Compute", "EC2 workloads deployed onto the network you built."),
    ("Storage & Database", "Object storage and NoSQL data modelling."),
    ("Identity & Security", "IAM identities, least privilege and secret management."),
    ("Serverless", "Functions without servers."),
    ("Automation", "Drive the simulator with the real AWS CLI and SDKs."),
    ("Capstone", "Combine everything into coherent enterprise architectures."),
]

LABS = [
 # --- Foundation ---
 {"id":1,"category":"Foundation","title":"Build the Organization Foundation","level":"Beginner","time":"20 min","focus":"Organizations","console":"/organization","console_label":"Open Organizations","goal":"Create the first simulated AWS organization and establish the landing-zone skeleton.","steps":["Create an organization named Training Enterprise.","Use eu-central-1 as the primary region.","Create Security, Infrastructure, Production and NonProduction OUs."]},
 {"id":2,"category":"Foundation","title":"Create the Core Accounts","level":"Beginner","time":"20 min","focus":"Accounts","console":"/accounts","console_label":"Open Accounts","goal":"Model the standard shared-services accounts used by an enterprise landing zone.","steps":["Create Log Archive, Security Tooling and Network accounts.","Place them in sensible OUs.","Confirm the Accounts page shows the account-to-OU relationships."]},
 {"id":3,"category":"Foundation","title":"Govern the Landing Zone with SCPs","level":"Intermediate","time":"25 min","focus":"Security & Governance","console":"/policies","console_label":"Open Policies","goal":"Attach baseline preventive controls and verify the landing-zone governance score.","steps":["Attach Restrict Regions to an OU or account.","Attach Protect CloudTrail.","Attach Deny Root Actions.","Open Landing Zone Validation and reach 100%."]},
 # --- Networking ---
 {"id":4,"category":"Networking","title":"Build a VPC Foundation","level":"Beginner","time":"25 min","focus":"VPC","console":"/network","console_label":"Open VPC console","goal":"Create an isolated network with a production CIDR and supporting route table.","steps":["Create a new VPC using 10.20.0.0/16 (the auto-created default VPC does not count).","Create at least one route table associated with your VPC.","Review the VPC inventory page."]},
 {"id":5,"category":"Networking","title":"Create a Public Subnet","level":"Intermediate","time":"30 min","focus":"Networking","console":"/network","console_label":"Open VPC console","goal":"Create a public subnet and internet gateway inside the VPC.","steps":["Create a subnet inside your VPC using a non-overlapping CIDR such as 10.20.1.0/24.","Enable public IPv4 mapping.","Create and attach an Internet Gateway to the VPC."]},
 {"id":6,"category":"Networking","title":"Design a Private Subnet with NAT","level":"Intermediate","time":"35 min","focus":"Networking","console":"/network","console_label":"Open VPC console","goal":"Model the common private-subnet egress pattern used by application workloads.","steps":["Create a second subnet using a CIDR such as 10.20.2.0/24.","Create a NAT Gateway in the public subnet.","Create a route table for private workloads and document the intended 0.0.0.0/0 path through NAT."]},
 # --- Compute ---
 {"id":7,"category":"Compute","title":"Deploy a Linux Workload","level":"Intermediate","time":"30 min","focus":"EC2","console":"/compute/launch","console_label":"Launch EC2","goal":"Launch a simulated Linux EC2 instance into the network you created.","steps":["Launch Ubuntu Server 24.04 LTS.","Use t3.small or larger.","Select your VPC, a private subnet and a security group.","Enable encrypted gp3 storage."]},
 {"id":8,"category":"Compute","title":"Deploy a Windows Workload Securely","level":"Intermediate","time":"30 min","focus":"EC2 & Security","console":"/compute/launch","console_label":"Launch EC2","goal":"Launch a simulated Windows server while applying basic security controls.","steps":["Launch Windows Server 2022 or 2025.","Use a non-public/private subnet.","Use a security group and a key pair.","Enable termination protection and encrypted storage."]},
 # --- Storage & Database ---
 {"id":9,"category":"Storage & Database","title":"Build an S3 Storage Foundation","level":"Beginner","time":"25 min","focus":"S3","console":"/s3","console_label":"Open S3","goal":"Create a versioned bucket and organise objects with prefixes the way real S3 data lakes do.","steps":["Create a bucket with versioning enabled.","Upload at least two objects.","Use a prefix in at least one key, e.g. reports/2026/q3.txt, to model folders."]},
 {"id":10,"category":"Storage & Database","title":"Model a NoSQL Table in DynamoDB","level":"Intermediate","time":"30 min","focus":"DynamoDB","console":"/dynamodb","console_label":"Open DynamoDB","goal":"Design a table with a composite key and store items that use it.","steps":["Create a table with a partition key and a sort key (e.g. orderId + createdAt).","Put at least two items whose attributes include both key fields.","Review how the item view surfaces your key schema."]},
 # --- Identity & Security ---
 {"id":11,"category":"Identity & Security","title":"Establish the Identity Baseline","level":"Beginner","time":"25 min","focus":"IAM","console":"/iam","console_label":"Open IAM","goal":"Create the three IAM building blocks every account needs: a human user, a service role and a custom policy.","steps":["Create an IAM user with console access enabled.","Create a role trusted by ec2.amazonaws.com for instance workloads.","Create at least one customer-managed policy."]},
 {"id":12,"category":"Identity & Security","title":"Protect Application Credentials","level":"Intermediate","time":"20 min","focus":"Secrets Manager","console":"/secrets","console_label":"Open Secrets Manager","goal":"Store credentials the way production teams do: hierarchical names and rotation.","steps":["Store a secret using a hierarchical name such as prod/db/password.","Enable automatic rotation on it.","Reveal the value once to verify, then hide it again."]},
 # --- Serverless ---
 {"id":13,"category":"Serverless","title":"Deploy a Lambda Function","level":"Intermediate","time":"30 min","focus":"Lambda","console":"/lambda","console_label":"Open Lambda","goal":"Create a Python function sized for real work and test-invoke it.","steps":["Create a function using a python3.x runtime.","Give it at least 256 MB of memory.","Open the function and invoke it with a JSON test event.","Read the simulated execution log, including the REPORT line."]},
 # --- Automation ---
 {"id":14,"category":"Automation","title":"Drive AWS with the Real CLI","level":"Advanced","time":"40 min","focus":"AWS CLI / boto3","console":"/compute","console_label":"Open EC2 console","goal":"Use the actual aws CLI (or boto3) against the simulator's API endpoint and watch the results appear in this console.","steps":["Read docs/aws-cli-tutorial.md in the project repository and set up the 'local' CLI profile it describes.","Run: aws --profile local ec2 describe-vpcs (or add --endpoint-url http://localhost:8080/aws --region eu-central-1 to each command).","Create a VPC and subnet from the CLI.","Run an instance with: aws --profile local ec2 run-instances --image-id ami-0c7217cdde317cfec --instance-type t3.micro --subnet-id <your-subnet>","Refresh the EC2 Instances page and find the instance the CLI created."]},
 # --- Capstone ---
 {"id":15,"category":"Capstone","title":"Build a Two-Tier Application","level":"Advanced","time":"45 min","focus":"Architecture","console":"/network","console_label":"Open VPC console","goal":"Create the building blocks for a public application tier and private application tier.","steps":["Create public and private subnets in one VPC.","Create an Internet Gateway and NAT Gateway.","Create an Application Load Balancer spanning appropriate subnets.","Launch at least two simulated EC2 instances.","Open Architecture and inspect the relationships."]},
 {"id":16,"category":"Capstone","title":"Build a Serverless Data Pipeline","level":"Advanced","time":"50 min","focus":"S3 · Lambda · DynamoDB","console":"/lambda","console_label":"Open Lambda","goal":"Assemble the classic serverless ingestion pattern: objects land in S3, a function processes them, results go to DynamoDB, credentials live in Secrets Manager.","steps":["Create an S3 bucket for incoming data.","Create a DynamoDB table for processed records.","Create a Lambda function to represent the processor.","Create an IAM role trusted by lambda.amazonaws.com for it.","Store the downstream credentials in Secrets Manager."]},
 {"id":17,"category":"Capstone","title":"Enterprise Landing Zone Challenge","level":"Advanced","time":"60 min","focus":"Architecture Governance","console":"/architecture","console_label":"Open Architecture","goal":"Combine organization governance, shared accounts, networking, workloads, storage and identity into a coherent enterprise design.","steps":["Achieve 100% Landing Zone Validation.","Have the four core OUs and three shared accounts.","Create at least one production VPC with public and private subnets.","Create an IGW, NAT Gateway, route tables and security groups.","Deploy Linux and Windows simulated workloads.","Create an S3 bucket and an EC2 service role.","Use Architecture as your final design review."]},
]


def _lab_snapshot():
    """One read of everything the lab checks need. User-created resources are
    distinguished from the auto-seeded default VPC/route-table/SG so a fresh
    install starts with every lab incomplete."""
    c=db()
    def one(q,args=()): return c.execute(q,args).fetchone()[0]
    s={}
    s["org"]=one("SELECT value FROM settings WHERE key='org_name'")
    s["ous"]={r[0].lower() for r in c.execute("SELECT name FROM ous").fetchall()}
    s["acc"]={r[0].lower() for r in c.execute("SELECT name FROM accounts").fetchall()}
    s["attached"]={r[0].lower() for r in c.execute("SELECT DISTINCT p.name FROM policies p JOIN policy_attachments a ON a.policy_id=p.id").fetchall()}
    s["user_vpcs"]=one("SELECT COUNT(*) FROM vpcs WHERE name!='default'")
    s["user_rts"]=one("SELECT COUNT(*) FROM route_tables WHERE name!='main'")
    s["user_sgs"]=one("SELECT COUNT(*) FROM security_groups WHERE name!='default'")
    subs=c.execute("SELECT public_ipv4, map_public_ip FROM subnets").fetchall()
    s["subnets"]=len(subs); s["public_subnets"]=sum(1 for r in subs if r[0] or r[1])
    s["igw"]=one("SELECT COUNT(*) FROM internet_gateways"); s["nat"]=one("SELECT COUNT(*) FROM nat_gateways")
    s["lbs"]=one("SELECT COUNT(*) FROM load_balancers")
    s["linux"]=one("SELECT COUNT(*) FROM ec2_instances WHERE lower(os)='linux' AND state!='terminated'")
    s["windows"]=one("SELECT COUNT(*) FROM ec2_instances WHERE lower(os)='windows' AND state!='terminated'")
    s["instances"]=one("SELECT COUNT(*) FROM ec2_instances WHERE state!='terminated'")
    s["cli_instances"]=one("SELECT COUNT(*) FROM ec2_instances WHERE config_json LIKE '%\"source\": \"cli\"%' AND state!='terminated'")
    s["s3_versioned"]=one("SELECT COUNT(*) FROM s3_buckets WHERE versioning=1")
    s["s3_buckets"]=one("SELECT COUNT(*) FROM s3_buckets")
    s["s3_objects"]=one("SELECT COUNT(*) FROM s3_objects")
    s["s3_prefixed"]=one("SELECT COUNT(*) FROM s3_objects WHERE key LIKE '%/%'")
    s["ddb_sorted"]=one("SELECT COUNT(*) FROM dynamodb_tables WHERE sort_key IS NOT NULL AND sort_key!=''")
    s["ddb_tables"]=one("SELECT COUNT(*) FROM dynamodb_tables")
    s["ddb_items"]=one("SELECT COUNT(*) FROM dynamodb_items")
    s["iam_console_users"]=one("SELECT COUNT(*) FROM iam_users WHERE console_access=1")
    s["iam_roles_ec2"]=one("SELECT COUNT(*) FROM iam_roles WHERE trusted_service='ec2.amazonaws.com'")
    s["iam_roles_lambda"]=one("SELECT COUNT(*) FROM iam_roles WHERE trusted_service='lambda.amazonaws.com'")
    s["iam_policies"]=one("SELECT COUNT(*) FROM iam_policies")
    s["secrets_managed"]=one("SELECT COUNT(*) FROM secrets WHERE name LIKE '%/%' AND rotation_enabled=1")
    s["lambda_sized"]=one("SELECT COUNT(*) FROM lambda_functions WHERE runtime LIKE 'python%' AND memory_mb>=256")
    s["lambda_functions"]=one("SELECT COUNT(*) FROM lambda_functions")
    c.close()
    s["validation"]=(bool(s["org"]) and all(x in s["ous"] for x in ["security","infrastructure","production","nonproduction"])
                     and all(x in s["acc"] for x in ["log archive","security tooling","network"])
                     and all(x in s["attached"] for x in ["restrict regions","protect cloudtrail","deny root actions"]))
    return s


LAB_CHECKS = {
    1: lambda s: bool(s["org"]) and all(x in s["ous"] for x in ["security","infrastructure","production","nonproduction"]),
    2: lambda s: all(x in s["acc"] for x in ["log archive","security tooling","network"]),
    3: lambda s: all(x in s["attached"] for x in ["restrict regions","protect cloudtrail","deny root actions"]),
    4: lambda s: s["user_vpcs"]>0 and s["user_rts"]>0,
    5: lambda s: s["user_vpcs"]>0 and s["public_subnets"]>0 and s["igw"]>0,
    6: lambda s: s["subnets"]>=2 and s["nat"]>0,
    7: lambda s: s["linux"]>0,
    8: lambda s: s["windows"]>0,
    9: lambda s: s["s3_versioned"]>0 and s["s3_objects"]>=2 and s["s3_prefixed"]>0,
    10: lambda s: s["ddb_sorted"]>0 and s["ddb_items"]>=2,
    11: lambda s: s["iam_console_users"]>0 and s["iam_roles_ec2"]>0 and s["iam_policies"]>0,
    12: lambda s: s["secrets_managed"]>0,
    13: lambda s: s["lambda_sized"]>0,
    14: lambda s: s["cli_instances"]>0,
    15: lambda s: s["user_vpcs"]>0 and s["subnets"]>=2 and s["igw"]>0 and s["nat"]>0 and s["lbs"]>0 and s["instances"]>=2,
    16: lambda s: s["s3_buckets"]>0 and s["ddb_tables"]>0 and s["lambda_functions"]>0 and s["iam_roles_lambda"]>0 and s["secrets_managed"]>0,
    17: lambda s: (s["validation"] and s["user_vpcs"]>0 and s["subnets"]>=2 and s["igw"]>0 and s["nat"]>0
                   and s["user_sgs"]>0 and s["linux"]>0 and s["windows"]>0 and s["s3_buckets"]>0 and s["iam_roles_ec2"]>0),
}


def lab_state(lab_id, snapshot=None):
    s = snapshot or _lab_snapshot()
    check = LAB_CHECKS.get(lab_id)
    return bool(check and check(s))


@app.context_processor
def inject_lab_progress():
    """Lab progress for the header tab. Cheap COUNT queries on local SQLite."""
    if not logged_in():
        return {"lab_progress": None}
    try:
        s = _lab_snapshot()
        done = sum(1 for i in LAB_CHECKS if lab_state(i, s))
        return {"lab_progress": {"done": done, "total": len(LABS)}}
    except sqlite3.Error:
        return {"lab_progress": None}

@app.route("/labs")
def labs():
    snapshot=_lab_snapshot()
    by_cat={}
    for lab in LABS:
        lab=dict(lab); lab["complete"]=lab_state(lab["id"], snapshot)
        by_cat.setdefault(lab["category"],[]).append(lab)
    groups=[]
    for name,desc in LAB_CATEGORIES:
        items=by_cat.get(name,[])
        if items:
            groups.append({"name":name,"desc":desc,"labs":items,
                           "done":sum(1 for l in items if l["complete"]),"total":len(items)})
    total=len(LABS); done=sum(g["done"] for g in groups)
    return render_template("labs.html", groups=groups, done=done, total=total)

@app.route("/labs/<int:lab_id>")
def lab_detail(lab_id):
    lab=next((x for x in LABS if x["id"]==lab_id),None)
    if not lab: return "Lab not found",404
    return render_template("lab_detail.html", lab=lab, complete=lab_state(lab_id))

@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("username") == "demo" and request.form.get("password") == "demo":
            session["user"] = "demo"
            return redirect(url_for("dashboard"))
        error = "Invalid credentials. Use demo / demo."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

def counts():
    c=db()
    vals={
        "ous": c.execute("SELECT COUNT(*) FROM ous").fetchone()[0],
        "accounts": c.execute("SELECT COUNT(*) FROM accounts").fetchone()[0],
        "policies": c.execute("SELECT COUNT(*) FROM policies").fetchone()[0],
        "attached": c.execute("SELECT COUNT(*) FROM policy_attachments").fetchone()[0]
    }
    c.close(); return vals

@app.route("/dashboard")
def dashboard():
    c=db()
    org=c.execute("SELECT value FROM settings WHERE key='org_name'").fetchone()["value"]
    region=c.execute("SELECT value FROM settings WHERE key='region'").fetchone()["value"]
    c.close()
    
    c=db()
    latest_instances=[dict(r) for r in c.execute("SELECT instance_id,name,state,instance_type,os,private_ip FROM ec2_instances ORDER BY id DESC LIMIT 8").fetchall()]
    latest_vpcs=[dict(r) for r in c.execute("SELECT vpc_id,name,cidr,region FROM vpcs ORDER BY id DESC LIMIT 8").fetchall()]
    c.close()
    return render_template("dashboard.html", org=org, region=region, counts=counts(), resource_counts=resource_counts(), service_counts=service_counts(), latest_instances=latest_instances, latest_vpcs=latest_vpcs)

@app.route("/search")
def search():
    """Global resource search across every service, wired to the header
    search box — mirrors the AWS console's unified search."""
    q=request.args.get("q","").strip()
    groups=[]
    if q:
        like=f"%{q}%"
        c=db()
        def rows(sql): return c.execute(sql,(like,like)).fetchall()
        specs=[
            ("VPC","vpc",       "SELECT name,vpc_id id FROM vpcs WHERE name LIKE ? OR vpc_id LIKE ?", lambda r:f"/network?new={r['id']}#vpcs"),
            ("Subnets","subnet","SELECT name,subnet_id id FROM subnets WHERE name LIKE ? OR subnet_id LIKE ?", lambda r:f"/network?new={r['id']}#subnets"),
            ("Route tables","rtb","SELECT name,route_table_id id FROM route_tables WHERE name LIKE ? OR route_table_id LIKE ?", lambda r:f"/network?new={r['id']}#route-tables"),
            ("Internet gateways","igw","SELECT name,igw_id id FROM internet_gateways WHERE name LIKE ? OR igw_id LIKE ?", lambda r:f"/network?new={r['id']}#internet-gateways"),
            ("NAT gateways","nat","SELECT name,nat_id id FROM nat_gateways WHERE name LIKE ? OR nat_id LIKE ?", lambda r:f"/network?new={r['id']}#nat-gateways"),
            ("Security groups","sg","SELECT name,group_id id FROM security_groups WHERE name LIKE ? OR group_id LIKE ?", lambda r:f"/network?new={r['id']}#security-groups"),
            ("Network ACLs","acl","SELECT name,acl_id id FROM network_acls WHERE name LIKE ? OR acl_id LIKE ?", lambda r:f"/network?new={r['id']}#network-acls"),
            ("Elastic IPs","eip","SELECT name,allocation_id id FROM elastic_ips WHERE name LIKE ? OR allocation_id LIKE ?", lambda r:f"/network?new={r['id']}#elastic-ips"),
            ("Load balancers","lb","SELECT name,lb_id id FROM load_balancers WHERE name LIKE ? OR lb_id LIKE ?", lambda r:f"/network?new={r['id']}#load-balancers"),
            ("VPC endpoints","vpce","SELECT name,endpoint_id id FROM vpc_endpoints WHERE name LIKE ? OR endpoint_id LIKE ?", lambda r:f"/network?new={r['id']}#endpoints"),
            ("EC2 instances","ec2","SELECT name,instance_id id FROM ec2_instances WHERE name LIKE ? OR instance_id LIKE ?", lambda r:f"/compute/instance/{r['id']}"),
            ("S3 buckets","s3","SELECT name,name id FROM s3_buckets WHERE name LIKE ? OR name LIKE ?", lambda r:"/s3"),
            ("IAM users","iam","SELECT name,arn id FROM iam_users WHERE name LIKE ? OR arn LIKE ?", lambda r:"/iam"),
            ("IAM roles","iam","SELECT name,arn id FROM iam_roles WHERE name LIKE ? OR arn LIKE ?", lambda r:"/iam"),
            ("IAM policies","iam","SELECT name,arn id FROM iam_policies WHERE name LIKE ? OR arn LIKE ?", lambda r:"/iam"),
            ("Lambda functions","lambda","SELECT name,arn id FROM lambda_functions WHERE name LIKE ? OR arn LIKE ?", lambda r:"/lambda"),
            ("DynamoDB tables","ddb","SELECT name,arn id FROM dynamodb_tables WHERE name LIKE ? OR arn LIKE ?", lambda r:"/dynamodb"),
            ("Secrets","secret","SELECT name,arn id FROM secrets WHERE name LIKE ? OR arn LIKE ?", lambda r:"/secrets"),
            ("Accounts","org","SELECT name,account_id id FROM accounts WHERE name LIKE ? OR account_id LIKE ?", lambda r:"/accounts"),
            ("Organizational units","org","SELECT name,name id FROM ous WHERE name LIKE ? OR name LIKE ?", lambda r:"/ous"),
        ]
        for label,_,sql,link in specs:
            found=rows(sql)
            if found:
                groups.append({"label":label,"matches":[{"name":r["name"],"id":r["id"],"url":link(r)} for r in found]})
        c.close()
    total=sum(len(g["matches"]) for g in groups)
    return render_template("search.html", q=q, groups=groups, total=total)

@app.route("/organization", methods=["GET","POST"])
def organization():
    c=db()
    if request.method=="POST":
        name=request.form.get("org_name","").strip()
        region=request.form.get("region","eu-central-1")
        c.execute("UPDATE settings SET value=? WHERE key='org_name'",(name,))
        c.execute("UPDATE settings SET value=? WHERE key='region'",(region,))
        c.commit()
        return redirect(url_for("organization"))
    org=c.execute("SELECT value FROM settings WHERE key='org_name'").fetchone()["value"]
    region=c.execute("SELECT value FROM settings WHERE key='region'").fetchone()["value"]
    c.close()
    return render_template("organization.html", org=org, region=region)

@app.route("/ous", methods=["GET","POST"])
def ous():
    c=db()
    if request.method=="POST":
        name=request.form.get("name","").strip()
        parent=request.form.get("parent_id") or None
        if name: c.execute("INSERT INTO ous(name,parent_id) VALUES(?,?)",(name,parent)); c.commit()
        return redirect(url_for("ous"))
    rows=c.execute("SELECT * FROM ous ORDER BY name").fetchall()
    c.close()
    return render_template("ous.html", ous=rows)

@app.route("/ous/delete/<int:id>", methods=["POST"])
def delete_ou(id):
    c=db()
    c.execute("UPDATE accounts SET ou_id=NULL WHERE ou_id=?",(id,))
    c.execute("DELETE FROM ous WHERE id=?",(id,))
    c.commit(); c.close()
    return redirect(url_for("ous"))

@app.route("/accounts", methods=["GET","POST"])
def accounts():
    c=db()
    if request.method=="POST":
        name=request.form.get("name","").strip()
        email=request.form.get("email","").strip()
        ou=request.form.get("ou_id") or None
        if name and email:
            aid=str(random.randint(100000000000,999999999999))
            while c.execute("SELECT 1 FROM accounts WHERE account_id=?",(aid,)).fetchone():
                aid=str(random.randint(100000000000,999999999999))
            c.execute("INSERT INTO accounts(name,email,account_id,ou_id) VALUES(?,?,?,?)",(name,email,aid,ou))
            c.commit()
        return redirect(url_for("accounts"))
    rows=c.execute("""SELECT a.*, o.name ou_name FROM accounts a LEFT JOIN ous o ON a.ou_id=o.id ORDER BY a.name""").fetchall()
    ous_rows=c.execute("SELECT * FROM ous ORDER BY name").fetchall()
    c.close()
    return render_template("accounts.html", accounts=rows, ous=ous_rows)

@app.route("/accounts/delete/<int:id>", methods=["POST"])
def delete_account(id):
    c=db(); c.execute("DELETE FROM accounts WHERE id=?",(id,)); c.commit(); c.close()
    return redirect(url_for("accounts"))

@app.route("/policies")
def policies():
    c=db()
    rows=c.execute("SELECT * FROM policies ORDER BY category,name").fetchall()
    attachments=c.execute("""SELECT pa.policy_id,pa.target_type,pa.target_id,
        CASE WHEN pa.target_type='ou' THEN o.name ELSE a.name END target_name
        FROM policy_attachments pa
        LEFT JOIN ous o ON pa.target_type='ou' AND pa.target_id=o.id
        LEFT JOIN accounts a ON pa.target_type='account' AND pa.target_id=a.id""").fetchall()
    ous_rows=c.execute("SELECT * FROM ous ORDER BY name").fetchall()
    accounts_rows=c.execute("SELECT * FROM accounts ORDER BY name").fetchall()
    c.close()
    return render_template("policies.html", policies=rows, attachments=attachments, ous=ous_rows, accounts=accounts_rows)

@app.route("/policies/attach", methods=["POST"])
def attach_policy():
    pid=int(request.form["policy_id"])
    target_type=request.form["target_type"]
    target_id=int(request.form["target_id"])
    c=db()
    exists=c.execute("SELECT 1 FROM policy_attachments WHERE policy_id=? AND target_type=? AND target_id=?",(pid,target_type,target_id)).fetchone()
    if not exists:
        c.execute("INSERT INTO policy_attachments VALUES (?,?,?)",(pid,target_type,target_id)); c.commit()
    c.close(); return redirect(url_for("policies"))

@app.route("/policies/detach", methods=["POST"])
def detach_policy():
    c=db()
    c.execute("DELETE FROM policy_attachments WHERE policy_id=? AND target_type=? AND target_id=?",
              (request.form["policy_id"],request.form["target_type"],request.form["target_id"]))
    c.commit(); c.close(); return redirect(url_for("policies"))

@app.route("/validation")
def validation():
    c=db()
    org=c.execute("SELECT value FROM settings WHERE key='org_name'").fetchone()["value"]
    checks=[]
    checks.append(("Organization created", bool(org), "Create an organization name."))
    ou_names={r["name"].lower() for r in c.execute("SELECT name FROM ous")}
    for n in ["Security","Infrastructure","Production","NonProduction"]:
        checks.append((f"{n} OU exists", n.lower() in ou_names, f"Create the {n} OU."))
    acc_names={r["name"].lower() for r in c.execute("SELECT name FROM accounts")}
    checks.append(("Log Archive account", "log archive" in acc_names, "Create a Log Archive account."))
    checks.append(("Security Tooling account", "security tooling" in acc_names, "Create a Security Tooling account."))
    checks.append(("Network account", "network" in acc_names, "Create a Network account."))
    attached={r["name"].lower() for r in c.execute("""SELECT DISTINCT p.name FROM policies p
        JOIN policy_attachments a ON a.policy_id=p.id""")}
    checks.append(("Region restriction attached", "restrict regions" in attached, "Attach Restrict Regions to an appropriate OU."))
    checks.append(("CloudTrail protection attached", "protect cloudtrail" in attached, "Attach Protect CloudTrail to an appropriate OU."))
    checks.append(("Root protection attached", "deny root actions" in attached, "Attach Deny Root Actions to an appropriate OU."))
    score=round(sum(ok for _,ok,_ in checks)/len(checks)*100)
    c.close()
    return render_template("validation.html", checks=checks, score=score)

@app.route("/architecture")
def architecture():
    c=db()
    org=c.execute("SELECT value FROM settings WHERE key='org_name'").fetchone()["value"] or "Your Organization"
    ous_rows=[dict(r) for r in c.execute("SELECT * FROM ous ORDER BY name").fetchall()]
    accounts_rows=[dict(r) for r in c.execute("SELECT a.*,o.name ou_name FROM accounts a LEFT JOIN ous o ON a.ou_id=o.id ORDER BY a.name").fetchall()]
    vpcs=[dict(r) for r in c.execute("SELECT * FROM vpcs ORDER BY id").fetchall()]
    subnets=[dict(r) for r in c.execute("SELECT s.*,v.vpc_id vpc_ref,v.name vpc_name FROM subnets s JOIN vpcs v ON v.id=s.vpc_id ORDER BY s.id").fetchall()]
    rts=[dict(r) for r in c.execute("SELECT r.*,v.vpc_id vpc_ref,v.name vpc_name FROM route_tables r JOIN vpcs v ON v.id=r.vpc_id ORDER BY r.id").fetchall()]
    igws=[dict(r) for r in c.execute("SELECT i.*,v.vpc_id vpc_ref,v.name vpc_name FROM internet_gateways i LEFT JOIN vpcs v ON v.id=i.vpc_id ORDER BY i.id").fetchall()]
    nats=[dict(r) for r in c.execute("SELECT n.*,v.vpc_id vpc_ref,v.name vpc_name FROM nat_gateways n JOIN vpcs v ON v.id=n.vpc_id ORDER BY n.id").fetchall()]
    sgs=[dict(r) for r in c.execute("SELECT s.*,v.vpc_id vpc_ref,v.name vpc_name FROM security_groups s JOIN vpcs v ON v.id=s.vpc_id ORDER BY s.id").fetchall()]
    instances=[dict(r) for r in c.execute("SELECT * FROM ec2_instances ORDER BY id").fetchall()]
    c.close()
    return render_template("architecture.html", org=org, ous=ous_rows, accounts=accounts_rows, vpcs=vpcs, subnets=subnets, route_tables=rts, igws=igws, nats=nats, security_groups=sgs, instances=instances)

@app.route("/reset", methods=["POST"])
def reset():
    c=db()
    c.executescript("""
    DELETE FROM ous; DELETE FROM accounts; DELETE FROM policy_attachments; DELETE FROM ec2_instances;
    DELETE FROM subnets; DELETE FROM route_tables; DELETE FROM internet_gateways; DELETE FROM nat_gateways;
    DELETE FROM security_groups; DELETE FROM network_acls; DELETE FROM elastic_ips; DELETE FROM load_balancers; DELETE FROM vpc_endpoints; DELETE FROM vpcs;
    DELETE FROM s3_objects; DELETE FROM s3_buckets; DELETE FROM iam_users; DELETE FROM iam_roles; DELETE FROM iam_policies;
    DELETE FROM lambda_functions; DELETE FROM dynamodb_items; DELETE FROM dynamodb_tables; DELETE FROM secrets;
    UPDATE settings SET value='' WHERE key='org_name';
    UPDATE settings SET value='eu-central-1' WHERE key='region';
    """)
    c.commit(); c.close()
    return redirect(url_for("dashboard"))


@app.route("/snapshots")
def snapshots():
    if "user" not in session:
        return redirect(url_for("login"))
    db=sqlite3.connect(DB)
    db.row_factory=sqlite3.Row
    c=db.cursor()
    snaps=c.execute("SELECT id,name,created_at FROM snapshots ORDER BY id DESC").fetchall()
    c.close(); db.close()
    return render_template("snapshots.html", snapshots=[dict(x) for x in snaps])


def ensure_snapshot_table():
    db=sqlite3.connect(DB)
    db.execute("""CREATE TABLE IF NOT EXISTS snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        state_json TEXT NOT NULL
    )""")
    db.commit(); db.close()

ensure_snapshot_table()

def snapshot_state():
    """Capture the simulator's existing schema."""
    db=sqlite3.connect(DB)
    db.row_factory=sqlite3.Row
    c=db.cursor()
    state={}
    for t in ["settings","ous","accounts","policies","policy_attachments","vpcs","subnets","route_tables","internet_gateways","nat_gateways","security_groups","network_acls","elastic_ips","load_balancers","vpc_endpoints","ec2_instances","s3_buckets","s3_objects","iam_users","iam_roles","iam_policies","lambda_functions","dynamodb_tables","dynamodb_items","secrets"]:
        state[t]=[dict(r) for r in c.execute(f"SELECT * FROM {t}").fetchall()]
    c.close()
    db.close()
    return state

@app.route("/snapshots/create", methods=["POST"])
def create_snapshot():
    if "user" not in session:
        return redirect(url_for("login"))
    name=request.form.get("name","Untitled Snapshot").strip() or "Untitled Snapshot"
    state=snapshot_state()
    db=sqlite3.connect(DB)
    db.execute("INSERT INTO snapshots(name,created_at,state_json) VALUES(?,?,?)",
               (name,datetime.now().isoformat(timespec="seconds"),json.dumps(state)))
    db.commit(); db.close()
    return redirect(url_for("snapshots"))

@app.route("/snapshots/<int:sid>/restore", methods=["POST"])
def restore_snapshot(sid):
    if "user" not in session:
        return redirect(url_for("login"))
    db=sqlite3.connect(DB)
    db.row_factory=sqlite3.Row
    row=db.execute("SELECT name,state_json FROM snapshots WHERE id=?",(sid,)).fetchone()
    if not row:
        db.close()
        return "Snapshot not found",404

    state=json.loads(row[1])

    # Safety backup of current state before replacing it.
    current={}
    for t in ["settings","ous","accounts","policies","policy_attachments","vpcs","subnets","route_tables","internet_gateways","nat_gateways","security_groups","network_acls","elastic_ips","load_balancers","vpc_endpoints","ec2_instances","s3_buckets","s3_objects","iam_users","iam_roles","iam_policies","lambda_functions","dynamodb_tables","dynamodb_items","secrets"]:
        current[t]=[dict(r) for r in db.execute(f"SELECT * FROM {t}").fetchall()]
    db.execute(
        "INSERT INTO snapshots(name,created_at,state_json) VALUES(?,?,?)",
        (f"Auto-backup before restore: {row[0]}",
         datetime.now().isoformat(timespec="seconds"),json.dumps(current))
    )

    # Preserve snapshots; restore the actual simulator state only. Every state
    # table must be cleared before re-insert, children before parents, or the
    # snapshot's original primary keys collide with live rows.
    for t in ["policy_attachments","accounts","policies","ous","settings",
              "ec2_instances","vpc_endpoints","load_balancers","elastic_ips",
              "network_acls","security_groups","nat_gateways","internet_gateways",
              "route_tables","subnets","vpcs",
              "s3_objects","s3_buckets","iam_users","iam_roles","iam_policies",
              "lambda_functions","dynamodb_items","dynamodb_tables","secrets"]:
        db.execute(f"DELETE FROM {t}")

    for t in ["settings","ous","accounts","policies","policy_attachments","vpcs","subnets","route_tables","internet_gateways","nat_gateways","security_groups","network_acls","elastic_ips","load_balancers","vpc_endpoints","ec2_instances","s3_buckets","s3_objects","iam_users","iam_roles","iam_policies","lambda_functions","dynamodb_tables","dynamodb_items","secrets"]:
        rows=state.get(t,[])
        if not rows:
            continue
        cols=list(rows[0].keys())
        marks=",".join(["?"]*len(cols))
        for r in rows:
            db.execute(
                f"INSERT INTO {t} ({','.join(cols)}) VALUES ({marks})",
                [r.get(k) for k in cols]
            )

    db.commit()
    db.close()
    return redirect(url_for("snapshots"))

@app.route("/snapshots/<int:sid>/delete", methods=["POST"])
def delete_snapshot(sid):
    if "user" not in session:
        return redirect(url_for("login"))
    db=sqlite3.connect(DB); db.execute("DELETE FROM snapshots WHERE id=?",(sid,)); db.commit(); db.close()
    return redirect(url_for("snapshots"))

@app.route("/snapshots/<int:sid>/export")
def export_snapshot(sid):
    if "user" not in session:
        return redirect(url_for("login"))
    db=sqlite3.connect(DB); row=db.execute("SELECT name,created_at,state_json FROM snapshots WHERE id=?",(sid,)).fetchone(); db.close()
    if not row: return "Snapshot not found",404
    payload={"format":"local-aws-simulator-snapshot","version":1,"name":row[0],"created_at":row[1],"state":json.loads(row[2])}
    from flask import Response
    filename=re.sub(r'[^A-Za-z0-9._-]+','_',row[0]).strip('_') or "snapshot"
    return Response(json.dumps(payload,indent=2),mimetype="application/json",
                    headers={"Content-Disposition":f'attachment; filename="{filename}.json"'})

@app.route("/snapshots/import", methods=["POST"])
def import_snapshot():
    if "user" not in session:
        return redirect(url_for("login"))
    f=request.files.get("snapshot")
    if not f or not f.filename:
        return redirect(url_for("snapshots"))
    try:
        payload=json.load(f)
        state=payload["state"]
        name=payload.get("name") or os.path.splitext(f.filename)[0]
        # Store imported state as a snapshot, don't overwrite current environment.
        db=sqlite3.connect(DB)
        db.execute("INSERT INTO snapshots(name,created_at,state_json) VALUES(?,?,?)",
                   (f"Imported - {name}",datetime.now().isoformat(timespec="seconds"),json.dumps(state)))
        db.commit(); db.close()
    except Exception as e:
        return f"Invalid snapshot: {e}",400
    return redirect(url_for("snapshots"))

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=8080, debug=True)
