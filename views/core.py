"""Console home, sign-in, search, reset, AWS Organizations and landing-zone pages."""

from __future__ import annotations

import random

from flask import Blueprint, redirect, render_template, request, session, url_for

import activity
import db
import labs
import rules
from views import console_tx, done, with_db
from views.services import service_counts

bp = Blueprint("core", __name__)

RESOURCE_TABLES = ["vpcs", "subnets", "route_tables", "internet_gateways", "nat_gateways", "security_groups",
                   "network_acls", "elastic_ips", "load_balancers", "vpc_endpoints", "ec2_instances"]


def resource_counts(c):
    return {n: c.execute(f"SELECT COUNT(*) FROM {n}").fetchone()[0] for n in RESOURCE_TABLES}


@bp.route("/")
def index():
    return redirect(url_for("core.dashboard"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("username") == "demo" and request.form.get("password") == "demo":
            session["user"] = "demo"
            return redirect(url_for("core.dashboard"))
        error = "Invalid credentials. Use demo / demo."
    return render_template("login.html", error=error)


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("core.login"))


@bp.route("/dashboard")
@with_db
def dashboard(c):
    import costs
    counts = {
        "ous": c.execute("SELECT COUNT(*) FROM ous").fetchone()[0],
        "accounts": c.execute("SELECT COUNT(*) FROM accounts").fetchone()[0],
        "policies": c.execute("SELECT COUNT(*) FROM policies").fetchone()[0],
        "attached": c.execute("SELECT COUNT(*) FROM policy_attachments").fetchone()[0],
    }
    latest_instances = [dict(r) for r in c.execute(
        "SELECT instance_id,name,state,instance_type,os,private_ip FROM ec2_instances ORDER BY id DESC LIMIT 8")]
    latest_vpcs = [dict(r) for r in c.execute("SELECT vpc_id,name,cidr,region,is_default FROM vpcs ORDER BY id DESC LIMIT 8")]
    recent = [dict(r) for r in c.execute("SELECT * FROM activity_log WHERE readonly=0 ORDER BY id DESC LIMIT 6")]
    return render_template("dashboard.html", org=db.get_setting(c, "org_name"), region=db.region(c), counts=counts,
                           resource_counts=resource_counts(c), service_counts=service_counts(c),
                           latest_instances=latest_instances, latest_vpcs=latest_vpcs,
                           monthly_cost=costs.estimate(c)["total"], recent=recent)


@bp.route("/search")
@with_db
def search(c):
    """Global resource search across every service, wired to the header search box."""
    q = request.args.get("q", "").strip()
    groups = []
    if q:
        like = f"%{q}%"
        specs = [
            ("VPC", "SELECT name,vpc_id id FROM vpcs WHERE name LIKE ? OR vpc_id LIKE ?", lambda r: f"/network?new={r['id']}#vpcs"),
            ("Subnets", "SELECT name,subnet_id id FROM subnets WHERE name LIKE ? OR subnet_id LIKE ?", lambda r: f"/network?new={r['id']}#subnets"),
            ("Route tables", "SELECT name,route_table_id id FROM route_tables WHERE name LIKE ? OR route_table_id LIKE ?", lambda r: f"/network?new={r['id']}#route-tables"),
            ("Internet gateways", "SELECT name,igw_id id FROM internet_gateways WHERE name LIKE ? OR igw_id LIKE ?", lambda r: f"/network?new={r['id']}#internet-gateways"),
            ("NAT gateways", "SELECT name,nat_id id FROM nat_gateways WHERE name LIKE ? OR nat_id LIKE ?", lambda r: f"/network?new={r['id']}#nat-gateways"),
            ("Security groups", "SELECT name,group_id id FROM security_groups WHERE name LIKE ? OR group_id LIKE ?", lambda r: f"/network?new={r['id']}#security-groups"),
            ("Network ACLs", "SELECT name,acl_id id FROM network_acls WHERE name LIKE ? OR acl_id LIKE ?", lambda r: f"/network?new={r['id']}#network-acls"),
            ("Elastic IPs", "SELECT name,allocation_id id FROM elastic_ips WHERE name LIKE ? OR allocation_id LIKE ?", lambda r: f"/network?new={r['id']}#elastic-ips"),
            ("Load balancers", "SELECT name,lb_id id FROM load_balancers WHERE name LIKE ? OR lb_id LIKE ?", lambda r: f"/network?new={r['id']}#load-balancers"),
            ("VPC endpoints", "SELECT name,endpoint_id id FROM vpc_endpoints WHERE name LIKE ? OR endpoint_id LIKE ?", lambda r: f"/network?new={r['id']}#endpoints"),
            ("EC2 instances", "SELECT name,instance_id id FROM ec2_instances WHERE name LIKE ? OR instance_id LIKE ?", lambda r: f"/compute/instance/{r['id']}"),
            ("S3 buckets", "SELECT name,id bid,name id FROM s3_buckets WHERE name LIKE ? OR name LIKE ?", lambda r: f"/s3/{r['bid']}"),
            ("IAM users", "SELECT name,arn id FROM iam_users WHERE name LIKE ? OR arn LIKE ?", lambda r: "/iam"),
            ("IAM roles", "SELECT name,arn id FROM iam_roles WHERE name LIKE ? OR arn LIKE ?", lambda r: "/iam"),
            ("IAM policies", "SELECT name,arn id FROM iam_policies WHERE name LIKE ? OR arn LIKE ?", lambda r: "/iam"),
            ("Lambda functions", "SELECT name,id fid,arn id FROM lambda_functions WHERE name LIKE ? OR arn LIKE ?", lambda r: f"/lambda/{r['fid']}"),
            ("DynamoDB tables", "SELECT name,id tid,arn id FROM dynamodb_tables WHERE name LIKE ? OR arn LIKE ?", lambda r: f"/dynamodb/{r['tid']}"),
            ("Secrets", "SELECT name,arn id FROM secrets WHERE name LIKE ? OR arn LIKE ?", lambda r: "/secrets"),
            ("Accounts", "SELECT name,account_id id FROM accounts WHERE name LIKE ? OR account_id LIKE ?", lambda r: "/accounts"),
            ("Organizational units", "SELECT name,name id FROM ous WHERE name LIKE ? OR name LIKE ?", lambda r: "/ous"),
        ]
        for label, sql, link in specs:
            found = c.execute(sql, (like, like)).fetchall()
            if found:
                groups.append({"label": label, "matches": [{"name": r["name"], "id": r["id"], "url": link(r)} for r in found]})
    total = sum(len(g["matches"]) for g in groups)
    return render_template("search.html", q=q, groups=groups, total=total)


@bp.route("/reset", methods=["POST"])
@console_tx(fail="/dashboard")
def reset(c):
    db.reset_state(c)
    return done(c, "sim", "ResetEnvironment", "", "Environment reset. A fresh default VPC was created.", target="/dashboard")


# ---------------------------------------------------------------------------
# AWS Organizations
# ---------------------------------------------------------------------------

@bp.route("/organization", methods=["GET", "POST"])
@console_tx(fail="/organization")
def organization(c):
    if request.method == "POST":
        name = request.form.get("org_name", "").strip()
        region = request.form.get("region", db.DEFAULT_REGION)
        db.set_setting(c, "org_name", name)
        db.set_setting(c, "region", region)
        return done(c, "organizations", "CreateOrganization", name, f"Organization {name} saved.",
                    activity.cli("organizations create-organization", ("--feature-set", "ALL")), "/organization")
    return render_template("organization.html", org=db.get_setting(c, "org_name"), region=db.region(c))


@bp.route("/ous", methods=["GET", "POST"])
@console_tx(fail="/ous")
def ous(c):
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        parent = request.form.get("parent_id") or None
        if name:
            c.execute("INSERT INTO ous(name,parent_id) VALUES(?,?)", (name, parent))
            return done(c, "organizations", "CreateOrganizationalUnit", name, f"OU {name} created.",
                        activity.cli("organizations create-organizational-unit", ("--parent-id", "r-root"), ("--name", name)), "/ous")
        return redirect(url_for("core.ous"))
    rows = c.execute("SELECT o.*, p.name parent_name FROM ous o LEFT JOIN ous p ON p.id=o.parent_id ORDER BY o.name").fetchall()
    return render_template("ous.html", ous=rows)


@bp.route("/ous/delete/<int:id>", methods=["POST"])
@console_tx(fail="/ous")
def delete_ou(c, id):
    c.execute("UPDATE accounts SET ou_id=NULL WHERE ou_id=?", (id,))
    c.execute("DELETE FROM policy_attachments WHERE target_type='ou' AND target_id=?", (id,))
    c.execute("DELETE FROM ous WHERE id=?", (id,))
    return redirect(url_for("core.ous"))


@bp.route("/accounts", methods=["GET", "POST"])
@console_tx(fail="/accounts")
def accounts(c):
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        ou = request.form.get("ou_id") or None
        if name and email:
            aid = str(random.randint(100000000000, 999999999999))
            while c.execute("SELECT 1 FROM accounts WHERE account_id=?", (aid,)).fetchone():
                aid = str(random.randint(100000000000, 999999999999))
            c.execute("INSERT INTO accounts(name,email,account_id,ou_id) VALUES(?,?,?,?)", (name, email, aid, ou))
            return done(c, "organizations", "CreateAccount", aid, f"Account {name} ({aid}) created.",
                        activity.cli("organizations create-account", ("--email", email), ("--account-name", name)), "/accounts")
        return redirect(url_for("core.accounts"))
    rows = c.execute("SELECT a.*, o.name ou_name FROM accounts a LEFT JOIN ous o ON a.ou_id=o.id ORDER BY a.name").fetchall()
    return render_template("accounts.html", accounts=rows, ous=c.execute("SELECT * FROM ous ORDER BY name").fetchall())


@bp.route("/accounts/delete/<int:id>", methods=["POST"])
@console_tx(fail="/accounts")
def delete_account(c, id):
    c.execute("DELETE FROM policy_attachments WHERE target_type='account' AND target_id=?", (id,))
    c.execute("DELETE FROM accounts WHERE id=?", (id,))
    return redirect(url_for("core.accounts"))


@bp.route("/policies")
@with_db
def policies(c):
    rows = c.execute("SELECT * FROM policies ORDER BY category,name").fetchall()
    attachments = c.execute("""SELECT pa.policy_id,pa.target_type,pa.target_id,
        CASE WHEN pa.target_type='ou' THEN o.name ELSE a.name END target_name
        FROM policy_attachments pa
        LEFT JOIN ous o ON pa.target_type='ou' AND pa.target_id=o.id
        LEFT JOIN accounts a ON pa.target_type='account' AND pa.target_id=a.id""").fetchall()
    return render_template("policies.html", policies=rows, attachments=attachments,
                           ous=c.execute("SELECT * FROM ous ORDER BY name").fetchall(),
                           accounts=c.execute("SELECT * FROM accounts ORDER BY name").fetchall())


@bp.route("/policies/attach", methods=["POST"])
@console_tx(fail="/policies")
def attach_policy(c):
    pid = int(request.form["policy_id"])
    target_type = request.form["target_type"]
    target_id = int(request.form["target_id"])
    if not c.execute("SELECT 1 FROM policy_attachments WHERE policy_id=? AND target_type=? AND target_id=?",
                     (pid, target_type, target_id)).fetchone():
        c.execute("INSERT INTO policy_attachments VALUES (?,?,?)", (pid, target_type, target_id))
    name = c.execute("SELECT name FROM policies WHERE id=?", (pid,)).fetchone()[0]
    return done(c, "organizations", "AttachPolicy", name, f"{name} attached.",
                activity.cli("organizations attach-policy", ("--policy-id", f"p-{pid:08d}"),
                             ("--target-id", f"{'ou-root' if target_type == 'ou' else 'account'}-{target_id}")), "/policies")


@bp.route("/policies/detach", methods=["POST"])
@console_tx(fail="/policies")
def detach_policy(c):
    c.execute("DELETE FROM policy_attachments WHERE policy_id=? AND target_type=? AND target_id=?",
              (request.form["policy_id"], request.form["target_type"], request.form["target_id"]))
    return redirect(url_for("core.policies"))


@bp.route("/validation")
@with_db
def validation(c):
    w = labs.World(c)
    checks = [("Organization created", bool(w.org), "Create an organization name.")]
    for n in labs.CORE_OUS:
        checks.append((f"{n} OU exists", n.lower() in w.ous, f"Create the {n} OU."))
    for n in labs.CORE_ACCOUNTS:
        checks.append((f"{n} account", n.lower() in w.accounts, f"Create a {n} account."))
    for n, label in zip(labs.CORE_SCPS, ["Region restriction", "CloudTrail protection", "Root protection"]):
        checks.append((f"{label} attached", n.lower() in w.attached, f"Attach {n} to an appropriate OU."))
    score = round(sum(ok for _, ok, _ in checks) / len(checks) * 100)
    return render_template("validation.html", checks=checks, score=score)


@bp.route("/architecture")
@with_db
def architecture(c):
    import netmodel
    org = db.get_setting(c, "org_name") or "Your Organization"
    ous_rows = [dict(r) for r in c.execute("SELECT * FROM ous ORDER BY name")]
    accounts_rows = [dict(r) for r in c.execute(
        "SELECT a.*,o.name ou_name FROM accounts a LEFT JOIN ous o ON a.ou_id=o.id ORDER BY a.name")]
    vpcs = [dict(r) for r in c.execute("SELECT * FROM vpcs ORDER BY is_default, id")]
    subnets = []
    for s in c.execute("SELECT s.*,v.vpc_id vpc_ref,v.name vpc_name FROM subnets s JOIN vpcs v ON v.id=s.vpc_id ORDER BY s.id"):
        d = dict(s)
        d["public"] = netmodel.subnet_is_public(c, s)
        rt, _ = netmodel.effective_route_table(c, s)
        d["rt_name"] = (rt["name"] or rt["route_table_id"]) if rt else ""
        subnets.append(d)
    rts = []
    for r in c.execute("SELECT r.*,v.vpc_id vpc_ref,v.name vpc_name FROM route_tables r JOIN vpcs v ON v.id=r.vpc_id ORDER BY r.id"):
        d = dict(r)
        d["routes"] = [rules.route_text(x) for x in rules.parse_routes(r["routes_json"])]
        rts.append(d)
    igws = [dict(r) for r in c.execute("SELECT i.*,v.vpc_id vpc_ref,v.name vpc_name FROM internet_gateways i LEFT JOIN vpcs v ON v.id=i.vpc_id ORDER BY i.id")]
    nats = [dict(r) for r in c.execute("SELECT n.*,v.vpc_id vpc_ref,v.name vpc_name,s.subnet_id subnet_ref FROM nat_gateways n JOIN vpcs v ON v.id=n.vpc_id JOIN subnets s ON s.id=n.subnet_id ORDER BY n.id")]
    sgs = [dict(r) for r in c.execute("SELECT s.*,v.vpc_id vpc_ref,v.name vpc_name FROM security_groups s JOIN vpcs v ON v.id=s.vpc_id ORDER BY s.id")]
    instances = [dict(r) for r in c.execute("SELECT * FROM ec2_instances WHERE state!='terminated' ORDER BY id")]
    return render_template("architecture.html", org=org, ous=ous_rows, accounts=accounts_rows, vpcs=vpcs, subnets=subnets,
                           route_tables=rts, igws=igws, nats=nats, security_groups=sgs, instances=instances)
