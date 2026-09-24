"""
labs.py
=======

The training labs and their step-by-step completion checks.

Every checkable step has its own check that returns ``(ok, detail)``; the
detail tells the student what is still missing ("Missing OUs: Production").
A lab is complete when all of its checkable steps pass. Steps with no check
(e.g. "review the page") are shown as guidance only.

Checks read live simulator state through ``World`` and use the same routing
logic as the Reachability Analyzer, so "public subnet" means what AWS means:
its route table sends 0.0.0.0/0 to an attached internet gateway.
"""

from __future__ import annotations

import json
from functools import cached_property

import activity
import netmodel
import rules

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

CORE_OUS = ["Security", "Infrastructure", "Production", "NonProduction"]
CORE_ACCOUNTS = ["Log Archive", "Security Tooling", "Network"]
CORE_SCPS = ["Restrict Regions", "Protect CloudTrail", "Deny Root Actions"]
SMALL_TYPES = {"t3.nano", "t3.micro"}


class World:
    """Lazily computed view of simulator state for the lab checks."""

    def __init__(self, c):
        self.c = c

    def q(self, sql, args=()):
        return self.c.execute(sql, args).fetchall()

    def one(self, sql, args=()):
        return self.c.execute(sql, args).fetchone()[0]

    @cached_property
    def org(self):
        row = self.c.execute("SELECT value FROM settings WHERE key='org_name'").fetchone()
        return row[0] if row else ""

    @cached_property
    def region(self):
        row = self.c.execute("SELECT value FROM settings WHERE key='region'").fetchone()
        return row[0] if row else ""

    @cached_property
    def ous(self):
        return {r["name"].lower() for r in self.q("SELECT name FROM ous")}

    @cached_property
    def accounts(self):
        return {r["name"].lower(): r for r in self.q("SELECT * FROM accounts")}

    @cached_property
    def attached(self):
        return {r[0].lower() for r in self.q(
            "SELECT DISTINCT p.name FROM policies p JOIN policy_attachments a ON a.policy_id=p.id")}

    @cached_property
    def user_vpcs(self):
        return self.q("SELECT * FROM vpcs WHERE is_default=0 ORDER BY id")

    @cached_property
    def subnets(self):
        """Subnets in user VPCs, each annotated with public/private."""
        ids = {v["id"] for v in self.user_vpcs}
        out = []
        for s in self.q("SELECT * FROM subnets ORDER BY id"):
            if s["vpc_id"] in ids:
                d = dict(s)
                d["public"] = netmodel.subnet_is_public(self.c, s)
                d["row"] = s
                out.append(d)
        return out

    def subnets_in(self, vpc):
        return [s for s in self.subnets if s["vpc_id"] == vpc["id"]]

    @cached_property
    def igw_attached_vpcs(self):
        return {r[0] for r in self.q("SELECT vpc_id FROM internet_gateways WHERE vpc_id IS NOT NULL")}

    @cached_property
    def nats(self):
        return self.q("SELECT * FROM nat_gateways")

    def private_with_nat(self, vpc=None):
        """Private subnets whose default route goes to a NAT gateway that sits
        in a public subnet — the complete private-egress pattern."""
        out = []
        for s in self.subnets:
            if s["public"] or (vpc is not None and s["vpc_id"] != vpc["id"]):
                continue
            rt, _ = netmodel.effective_route_table(self.c, s["row"])
            route = rules.longest_prefix_match(rules.parse_routes(rt["routes_json"]), "8.8.8.8") if rt else None
            if not route or not route["target"].startswith("nat-"):
                continue
            nat = next((n for n in self.nats if n["nat_id"] == route["target"]), None)
            nat_subnet = next((x for x in self.subnets if nat and x["id"] == nat["subnet_id"]), None)
            if nat_subnet and nat_subnet["public"]:
                out.append(s)
        return out

    @cached_property
    def instances(self):
        out = []
        for i in self.q("SELECT * FROM ec2_instances WHERE state!='terminated' ORDER BY id"):
            d = dict(i)
            d["config"] = json.loads(i["config_json"] or "{}")
            d["subnet_row"] = next((s for s in self.subnets if s["subnet_id"] == i["subnet"]), None)
            d["sg_ids"] = [x for x in (i["security_groups"] or "").split(",") if x]
            out.append(d)
        return out

    @cached_property
    def default_sg_ids(self):
        return {r[0] for r in self.q("SELECT group_id FROM security_groups WHERE name='default'")}

    @cached_property
    def user_sgs(self):
        return self.q("SELECT * FROM security_groups WHERE name!='default'")

    def custom_sg(self, inst):
        return any(g not in self.default_sg_ids for g in inst["sg_ids"])

    def in_private_subnet(self, inst):
        return bool(inst["subnet_row"]) and not inst["subnet_row"]["public"]

    @cached_property
    def custom_route_tables(self):
        ids = {v["id"] for v in self.user_vpcs}
        return [r for r in self.q("SELECT * FROM route_tables WHERE main_table=0") if r["vpc_id"] in ids]


# ---------------------------------------------------------------------------
# Reusable checks. Each returns (ok, detail).
# ---------------------------------------------------------------------------

def _missing(label, wanted, have):
    miss = [w for w in wanted if w.lower() not in have]
    return (not miss, f"Missing {label}: {', '.join(miss)}." if miss else f"All {label} present.")


def chk_org(w):
    return bool(w.org), f"Organization: {w.org}." if w.org else "Set an organization name on the Organization page."


def chk_region(w):
    return w.region == "eu-central-1", f"Primary region is {w.region or 'not set'}."


def chk_ous(w):
    return _missing("OUs", CORE_OUS, w.ous)


def chk_accounts(w):
    return _missing("accounts", CORE_ACCOUNTS, set(w.accounts))


def chk_accounts_placed(w):
    unplaced = [a for a in CORE_ACCOUNTS if a.lower() in w.accounts and not w.accounts[a.lower()]["ou_id"]]
    if any(a.lower() not in w.accounts for a in CORE_ACCOUNTS):
        return False, "Create the three core accounts first."
    return not unplaced, "Every core account is in an OU." if not unplaced else f"Not in an OU yet: {', '.join(unplaced)}."


def chk_scp(name):
    def check(w):
        ok = name.lower() in w.attached
        return ok, f"{name} is attached." if ok else f"Attach {name} to an OU or account on the Policies page."
    return check


def chk_validation(w):
    parts = [chk_org(w), chk_ous(w), chk_accounts(w)] + [chk_scp(n)(w) for n in CORE_SCPS]
    done = sum(1 for ok, _ in parts if ok)
    return done == len(parts), f"Landing Zone Validation: {round(done / len(parts) * 100)}%."


def chk_user_vpc(w):
    if not w.user_vpcs:
        return False, "Only the default VPC exists. Create your own VPC."
    return True, f"Your VPC: {w.user_vpcs[-1]['vpc_id']} ({w.user_vpcs[-1]['cidr']})."


def chk_custom_rt(w):
    ok = bool(w.custom_route_tables)
    return ok, "Custom route table present." if ok else "Create a route table in your VPC (the main one is created for you)."


def chk_subnet_autopublic(w):
    ok = any(s["map_public_ip"] for s in w.subnets)
    return ok, "A subnet auto-assigns public IPv4." if ok else "Enable auto-assign public IPv4 on a subnet in your VPC."


def chk_igw_attached(w):
    ok = any(v["id"] in w.igw_attached_vpcs for v in w.user_vpcs)
    return ok, "An internet gateway is attached to your VPC." if ok else "Create an internet gateway and attach it to your VPC."


def chk_public_subnet(w):
    pub = [s for s in w.subnets if s["public"]]
    if pub:
        return True, f"{pub[0]['subnet_id']} routes 0.0.0.0/0 to an internet gateway."
    return False, "No subnet routes 0.0.0.0/0 to an attached internet gateway yet. Add that route to a route table " \
                  "and associate the table with your public subnet."


def chk_two_subnets(w):
    n = len(w.subnets)
    return n >= 2, f"{n} subnet(s) in your VPCs."


def chk_nat_in_public(w):
    pub_ids = {s["id"] for s in w.subnets if s["public"]}
    if not w.nats:
        return False, "Create a NAT gateway."
    ok = any(n["subnet_id"] in pub_ids for n in w.nats)
    return ok, "The NAT gateway is in a public subnet." if ok else \
        "Your NAT gateway is not in a public subnet — NAT gateways need a route to an internet gateway."


def chk_private_nat_route(w):
    subs = w.private_with_nat()
    if subs:
        return True, f"{subs[0]['subnet_id']} is private and egresses through a NAT gateway."
    return False, "Associate a route table with 0.0.0.0/0 → your NAT gateway to the private subnet."


def _instance_check(os_name, predicate, ok_msg, fail_msg):
    def check(w):
        cands = [i for i in w.instances if (i["os"] or "").lower() == os_name]
        if not cands:
            return False, f"Launch a {os_name.title()} instance first."
        hit = next((i for i in cands if predicate(w, i)), None)
        return (True, ok_msg.format(i=hit)) if hit else (False, fail_msg)
    return check


def _ami_name(i):
    return (i["config"].get("ami") or {}).get("name", "")


LINUX_STEPS = [
    ("Launch Ubuntu Server 24.04 LTS.",
     _instance_check("linux", lambda w, i: "Ubuntu Server 24.04" in _ami_name(i), "{i[instance_id]} runs Ubuntu 24.04.",
                     "None of your Linux instances use an Ubuntu Server 24.04 LTS AMI.")),
    ("Use t3.small or larger.",
     _instance_check("linux", lambda w, i: i["instance_type"] not in SMALL_TYPES, "{i[instance_id]} is {i[instance_type]}.",
                     "Use t3.small or a larger instance type.")),
    ("Place it in a private subnet of your VPC with a security group you created.",
     _instance_check("linux", lambda w, i: w.in_private_subnet(i) and w.custom_sg(i),
                     "{i[instance_id]} is in a private subnet with a custom security group.",
                     "Launch into a private subnet of your own VPC and attach a security group you created.")),
    ("Enable encrypted gp3 storage.",
     _instance_check("linux", lambda w, i: i["encrypted"] and i["root_volume_type"] == "gp3",
                     "{i[instance_id]} has an encrypted gp3 root volume.", "Use an encrypted gp3 root volume.")),
]

WINDOWS_STEPS = [
    ("Launch Windows Server 2022 or 2025.",
     _instance_check("windows", lambda w, i: any(v in _ami_name(i) for v in ("2022", "2025")),
                     "{i[instance_id]} runs a current Windows Server.", "Use the Windows Server 2022 or 2025 AMI.")),
    ("Use a private subnet — no public IP.",
     _instance_check("windows", lambda w, i: w.in_private_subnet(i) and not i["public_ip"],
                     "{i[instance_id]} is private.", "Launch into a private subnet without a public IP.")),
    ("Use a security group you created and a key pair.",
     _instance_check("windows", lambda w, i: w.custom_sg(i) and bool(i["key_name"]),
                     "{i[instance_id]} has a custom security group and key pair.",
                     "Attach a security group you created and set a key pair name.")),
    ("Enable termination protection and encrypted storage.",
     _instance_check("windows", lambda w, i: i["config"].get("termination_protection") and i["encrypted"],
                     "{i[instance_id]} is protected and encrypted.",
                     "Enable termination protection and encrypted storage.")),
]


def chk(sql_count, ok_msg, fail_msg, minimum=1):
    def check(w):
        n = w.one(sql_count)
        return n >= minimum, (ok_msg if n >= minimum else fail_msg).format(n=n)
    return check


def chk_activity(action, source=None, ok="", fail=""):
    def check(w):
        hit = activity.has(w.c, action, source)
        return hit, ok if hit else fail
    return check


def chk_linux(w):
    ok = any((i["os"] or "").lower() == "linux" for i in w.instances)
    return ok, "A Linux instance is running." if ok else "Launch a Linux instance."


def chk_windows(w):
    ok = any((i["os"] or "").lower() == "windows" for i in w.instances)
    return ok, "A Windows instance is running." if ok else "Launch a Windows instance."


def chk_prod_vpc(w):
    for v in w.user_vpcs:
        subs = w.subnets_in(v)
        if any(s["public"] for s in subs) and w.private_with_nat(v):
            return True, f"{v['vpc_id']} has a public subnet and a NAT-backed private subnet."
    return False, "Build one VPC with a public subnet (route to IGW) and a private subnet (route to NAT)."


def chk_alb(w):
    ok = w.one("SELECT COUNT(*) FROM load_balancers WHERE lb_type='application'") > 0
    return ok, "Application Load Balancer present." if ok else "Create an application load balancer."


def chk_two_instances(w):
    n = len(w.instances)
    return n >= 2, f"{n} instance(s) launched."


def chk_user_sg(w):
    ok = bool(w.user_sgs)
    return ok, "Custom security group present." if ok else "Create at least one security group of your own."


# ---------------------------------------------------------------------------
# Lab catalogue. Steps: (text, check or None).
# ---------------------------------------------------------------------------

S3_VERSIONED = chk("SELECT COUNT(*) FROM s3_buckets WHERE versioning=1", "Versioned bucket present.",
                   "Create a bucket with versioning enabled.")
LABS = [
    {"id": 1, "category": "Foundation", "title": "Build the Organization Foundation", "level": "Beginner",
     "time": "20 min", "focus": "Organizations", "console": "/organization", "console_label": "Open Organizations",
     "goal": "Create the first simulated AWS organization and establish the landing-zone skeleton.",
     "steps": [("Create an organization named Training Enterprise.", chk_org),
               ("Use eu-central-1 as the primary region.", chk_region),
               ("Create Security, Infrastructure, Production and NonProduction OUs.", chk_ous)]},
    {"id": 2, "category": "Foundation", "title": "Create the Core Accounts", "level": "Beginner", "time": "20 min",
     "focus": "Accounts", "console": "/accounts", "console_label": "Open Accounts",
     "goal": "Model the standard shared-services accounts used by an enterprise landing zone.",
     "steps": [("Create Log Archive, Security Tooling and Network accounts.", chk_accounts),
               ("Place each of them in an OU.", chk_accounts_placed),
               ("Confirm the Accounts page shows the account-to-OU relationships.", None)]},
    {"id": 3, "category": "Foundation", "title": "Govern the Landing Zone with SCPs", "level": "Intermediate",
     "time": "25 min", "focus": "Security & Governance", "console": "/policies", "console_label": "Open Policies",
     "goal": "Attach baseline preventive controls and verify the landing-zone governance score.",
     "steps": [("Attach Restrict Regions to an OU or account.", chk_scp("Restrict Regions")),
               ("Attach Protect CloudTrail.", chk_scp("Protect CloudTrail")),
               ("Attach Deny Root Actions.", chk_scp("Deny Root Actions")),
               ("Open Landing Zone Validation and reach 100%.", chk_validation)]},
    {"id": 4, "category": "Networking", "title": "Build a VPC Foundation", "level": "Beginner", "time": "25 min",
     "focus": "VPC", "console": "/network", "console_label": "Open VPC console",
     "goal": "Create an isolated network with a production CIDR and supporting route table.",
     "steps": [("Create a new VPC using 10.20.0.0/16 (the auto-created default VPC does not count).", chk_user_vpc),
               ("Create a route table in your VPC, in addition to the main route table AWS creates for you.", chk_custom_rt),
               ("Review the VPC inventory page.", None)]},
    {"id": 5, "category": "Networking", "title": "Create a Public Subnet", "level": "Intermediate", "time": "30 min",
     "focus": "Networking", "console": "/network", "console_label": "Open VPC console",
     "goal": "Make a subnet genuinely public: auto-assigned public IPs plus a default route to an internet gateway.",
     "steps": [("Create a subnet inside your VPC, e.g. 10.20.1.0/24, with auto-assign public IPv4 enabled.", chk_subnet_autopublic),
               ("Create an internet gateway and attach it to the VPC.", chk_igw_attached),
               ("Add 0.0.0.0/0 → the internet gateway to a route table and associate it with the subnet.", chk_public_subnet)]},
    {"id": 6, "category": "Networking", "title": "Design a Private Subnet with NAT", "level": "Intermediate",
     "time": "35 min", "focus": "Networking", "console": "/network", "console_label": "Open VPC console",
     "goal": "Model the common private-subnet egress pattern used by application workloads.",
     "steps": [("Create a second subnet, e.g. 10.20.2.0/24.", chk_two_subnets),
               ("Create a NAT gateway in the public subnet.", chk_nat_in_public),
               ("Route the private subnet's 0.0.0.0/0 through the NAT gateway (its own route table).", chk_private_nat_route),
               ("Use Reachability to confirm a private instance can reach the internet.", None)]},
    {"id": 7, "category": "Compute", "title": "Deploy a Linux Workload", "level": "Intermediate", "time": "30 min",
     "focus": "EC2", "console": "/compute/launch", "console_label": "Launch EC2",
     "goal": "Launch a simulated Linux EC2 instance into the network you created.", "steps": LINUX_STEPS},
    {"id": 8, "category": "Compute", "title": "Deploy a Windows Workload Securely", "level": "Intermediate",
     "time": "30 min", "focus": "EC2 & Security", "console": "/compute/launch", "console_label": "Launch EC2",
     "goal": "Launch a simulated Windows server while applying basic security controls.", "steps": WINDOWS_STEPS},
    {"id": 9, "category": "Storage & Database", "title": "Build an S3 Storage Foundation", "level": "Beginner",
     "time": "25 min", "focus": "S3", "console": "/s3", "console_label": "Open S3",
     "goal": "Create a versioned bucket and organise objects with prefixes the way real S3 data lakes do.",
     "steps": [("Create a bucket with versioning enabled.", S3_VERSIONED),
               ("Upload at least two objects.", chk("SELECT COUNT(*) FROM s3_objects", "{n} objects stored.",
                                                    "Upload at least two objects ({n} so far).", 2)),
               ("Use a prefix in at least one key, e.g. reports/2026/q3.txt, to model folders.",
                chk("SELECT COUNT(*) FROM s3_objects WHERE instr(key,'/')>0", "Prefixed key present.",
                    "Upload an object whose key contains a '/'."))]},
    {"id": 10, "category": "Storage & Database", "title": "Model a NoSQL Table in DynamoDB", "level": "Intermediate",
     "time": "30 min", "focus": "DynamoDB", "console": "/dynamodb", "console_label": "Open DynamoDB",
     "goal": "Design a table with a composite key and store items that use it.",
     "steps": [("Create a table with a partition key and a sort key (e.g. orderId + createdAt).",
                chk("SELECT COUNT(*) FROM dynamodb_tables WHERE sort_key IS NOT NULL AND sort_key!=''",
                    "Composite-key table present.", "Create a table that has a sort key.")),
               ("Put at least two items whose attributes include both key fields.", None),
               ("Review how the item view surfaces your key schema.", None)]},
    {"id": 11, "category": "Identity & Security", "title": "Establish the Identity Baseline", "level": "Beginner",
     "time": "25 min", "focus": "IAM", "console": "/iam", "console_label": "Open IAM",
     "goal": "Create the three IAM building blocks every account needs: a human user, a service role and a custom policy.",
     "steps": [("Create an IAM user with console access enabled.",
                chk("SELECT COUNT(*) FROM iam_users WHERE console_access=1", "Console user present.",
                    "Create a user with console access.")),
               ("Create a role trusted by ec2.amazonaws.com for instance workloads.",
                chk("SELECT COUNT(*) FROM iam_roles WHERE trusted_service='ec2.amazonaws.com'", "EC2 role present.",
                    "Create a role whose trusted service is ec2.amazonaws.com.")),
               ("Create at least one customer-managed policy.",
                chk("SELECT COUNT(*) FROM iam_policies", "Customer policy present.", "Create a policy."))]},
    {"id": 12, "category": "Identity & Security", "title": "Protect Application Credentials", "level": "Intermediate",
     "time": "20 min", "focus": "Secrets Manager", "console": "/secrets", "console_label": "Open Secrets Manager",
     "goal": "Store credentials the way production teams do: hierarchical names and rotation.",
     "steps": [("Store a secret using a hierarchical name such as prod/db/password.",
                chk("SELECT COUNT(*) FROM secrets WHERE instr(name,'/')>0", "Hierarchical secret present.",
                    "Use a name containing '/' such as prod/db/password.")),
               ("Enable automatic rotation on it.",
                chk("SELECT COUNT(*) FROM secrets WHERE instr(name,'/')>0 AND rotation_enabled=1",
                    "Rotation enabled.", "Enable rotation on the hierarchical secret.")),
               ("Retrieve the value once to verify it (console Reveal or get-secret-value).",
                chk_activity("GetSecretValue", ok="Secret value retrieved.", fail="Reveal the secret value once.")),
               ("Hide it again.", None)]},
    {"id": 13, "category": "Serverless", "title": "Deploy a Lambda Function", "level": "Intermediate",
     "time": "30 min", "focus": "Lambda", "console": "/lambda", "console_label": "Open Lambda",
     "goal": "Create a Python function sized for real work and run it — the simulator executes Python handlers for real.",
     "steps": [("Create a function using a python3.x runtime.",
                chk("SELECT COUNT(*) FROM lambda_functions WHERE runtime LIKE 'python%'", "Python function present.",
                    "Create a function with a python3.x runtime.")),
               ("Give it at least 256 MB of memory.",
                chk("SELECT COUNT(*) FROM lambda_functions WHERE runtime LIKE 'python%' AND memory_mb>=256",
                    "Memory is 256 MB or more.", "Set memory to at least 256 MB.")),
               ("Open the function and invoke it with a JSON test event.",
                chk_activity("Invoke", ok="Function invoked.", fail="Invoke the function once.")),
               ("Read the execution log, including the REPORT line.", None)]},
    {"id": 14, "category": "Automation", "title": "Drive AWS with the Real CLI", "level": "Advanced", "time": "40 min",
     "focus": "AWS CLI / boto3", "console": "/activity", "console_label": "Open Activity log",
     "goal": "Use the actual aws CLI (or boto3) against the simulator's API endpoint and watch the results appear in this console.",
     "steps": [("Set up the 'local' CLI profile from docs/aws-cli-tutorial.md and run: aws --profile local sts get-caller-identity",
                chk_activity("GetCallerIdentity", "cli", "The simulator saw your CLI.", "Run aws --profile local sts get-caller-identity.")),
               ("Run: aws --profile local ec2 describe-vpcs",
                chk_activity("DescribeVpcs", "cli", "describe-vpcs received.", "Run ec2 describe-vpcs from the CLI.")),
               ("Create a VPC and a subnet from the CLI.",
                lambda w: (activity.has(w.c, "CreateVpc", "cli") and activity.has(w.c, "CreateSubnet", "cli"),
                           "Created from the CLI." if activity.has(w.c, "CreateVpc", "cli") and activity.has(w.c, "CreateSubnet", "cli")
                           else "Run ec2 create-vpc and ec2 create-subnet from the CLI.")),
               ("Run an instance: aws --profile local ec2 run-instances --image-id ami-0c7217cdde317cfec --instance-type t3.micro --subnet-id <your-subnet>",
                chk("SELECT COUNT(*) FROM ec2_instances WHERE config_json LIKE '%\"source\": \"cli\"%' AND state!='terminated'",
                    "CLI-launched instance present.", "Launch an instance with ec2 run-instances.")),
               ("Open the Activity log and compare each CLI call with the console equivalent.", None)]},
    {"id": 15, "category": "Capstone", "title": "Build a Two-Tier Application", "level": "Advanced", "time": "45 min",
     "focus": "Architecture", "console": "/network", "console_label": "Open VPC console",
     "goal": "Create the building blocks for a public web tier and a private application tier.",
     "steps": [("Create public and private subnets in one VPC, with an internet gateway and a NAT gateway.", chk_prod_vpc),
               ("Create an Application Load Balancer spanning the public subnets.", chk_alb),
               ("Launch at least two simulated EC2 instances.", chk_two_instances),
               ("Open Architecture and inspect the relationships.", None)]},
    {"id": 16, "category": "Capstone", "title": "Build a Serverless Data Pipeline", "level": "Advanced", "time": "50 min",
     "focus": "S3 · Lambda · DynamoDB", "console": "/lambda", "console_label": "Open Lambda",
     "goal": "Assemble the classic serverless ingestion pattern: objects land in S3, a function processes them, results go to DynamoDB, credentials live in Secrets Manager. Every step also works from the CLI.",
     "steps": [("Create an S3 bucket for incoming data.",
                chk("SELECT COUNT(*) FROM s3_buckets", "Bucket present.", "Create a bucket.")),
               ("Create a DynamoDB table for processed records.",
                chk("SELECT COUNT(*) FROM dynamodb_tables", "Table present.", "Create a table.")),
               ("Create a Lambda function to represent the processor.",
                chk("SELECT COUNT(*) FROM lambda_functions", "Function present.", "Create a function.")),
               ("Create an IAM role trusted by lambda.amazonaws.com for it.",
                chk("SELECT COUNT(*) FROM iam_roles WHERE trusted_service='lambda.amazonaws.com'", "Lambda role present.",
                    "Create a role trusted by lambda.amazonaws.com.")),
               ("Store the downstream credentials in Secrets Manager (hierarchical name, rotation on).",
                chk("SELECT COUNT(*) FROM secrets WHERE instr(name,'/')>0 AND rotation_enabled=1",
                    "Managed secret present.", "Store a hierarchical secret with rotation enabled."))]},
    {"id": 17, "category": "Capstone", "title": "Enterprise Landing Zone Challenge", "level": "Advanced", "time": "60 min",
     "focus": "Architecture Governance", "console": "/architecture", "console_label": "Open Architecture",
     "goal": "Combine organization governance, shared accounts, networking, workloads, storage and identity into a coherent enterprise design.",
     "steps": [("Achieve 100% Landing Zone Validation (four core OUs, three shared accounts, three SCPs).", chk_validation),
               ("Create a production VPC with a public subnet and a NAT-backed private subnet.", chk_prod_vpc),
               ("Create security groups of your own.", chk_user_sg),
               ("Deploy a Linux workload.", chk_linux),
               ("Deploy a Windows workload.", chk_windows),
               ("Create an S3 bucket.", chk("SELECT COUNT(*) FROM s3_buckets", "Bucket present.", "Create a bucket.")),
               ("Create an EC2 service role.",
                chk("SELECT COUNT(*) FROM iam_roles WHERE trusted_service='ec2.amazonaws.com'", "EC2 role present.",
                    "Create a role trusted by ec2.amazonaws.com.")),
               ("Use Architecture and Costs as your final design review.", None)]},
]


def _ddb_items_check(w):
    for t in w.q("SELECT * FROM dynamodb_tables WHERE sort_key IS NOT NULL AND sort_key!=''"):
        n = 0
        for r in w.q("SELECT item_json FROM dynamodb_items WHERE table_id=?", (t["id"],)):
            item = json.loads(r["item_json"])
            if t["partition_key"] in item and t["sort_key"] in item:
                n += 1
        if n >= 2:
            return True, f"{t['name']} holds {n} items with both key attributes."
    return False, "Put two items that contain both the partition key and the sort key attributes."


LABS[9]["steps"][1] = (LABS[9]["steps"][1][0], _ddb_items_check)


def evaluate(c, lab):
    """Step results for one lab: list of {text, checked, ok, detail} and totals."""
    w = World(c)
    return _evaluate(w, lab)


def _evaluate(w, lab):
    steps = []
    for text, check in lab["steps"]:
        if check is None:
            steps.append({"text": text, "checked": False, "ok": None, "detail": ""})
            continue
        ok, detail = check(w)
        steps.append({"text": text, "checked": True, "ok": bool(ok), "detail": detail})
    checked = [s for s in steps if s["checked"]]
    done = sum(1 for s in checked if s["ok"])
    return {"steps": steps, "done": done, "total": len(checked), "complete": done == len(checked)}


def evaluate_all(c):
    w = World(c)
    return {lab["id"]: _evaluate(w, lab) for lab in LABS}


def get(lab_id):
    return next((x for x in LABS if x["id"] == lab_id), None)
