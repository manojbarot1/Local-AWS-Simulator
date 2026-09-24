"""
Build a realistic demo environment — used for the README screenshots, and handy
for exploring the simulator without doing every lab first.

    python tools/demo_seed.py demo.db          # needs boto3 (requirements-dev.txt)
    SIM_DB=demo.db python app.py

Half of it is created through the web console and half through boto3 against
the API endpoint, so the Activity log shows both sources.
"""

from __future__ import annotations

import json
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import boto3  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

import app as app_module  # noqa: E402
import db  # noqa: E402
import ec2model  # noqa: E402

UBUNTU = "ami-0e001c9271cf7f3b9"
AL2023 = "ami-0c7217cdde317cfec"
WINDOWS = "ami-0f9c44e98edf38a2b"

LAMBDA_CODE = '''import json


def lambda_handler(event, context):
    """Validate an incoming order and compute its total."""
    items = event.get("items", [])
    total = round(sum(i["price"] * i["qty"] for i in items), 2)
    print(f"order {event.get('orderId')} has {len(items)} line(s), total {total}")
    return {"statusCode": 200, "body": json.dumps({"orderId": event.get("orderId"), "total": total})}
'''


def row_id(sql, *args):
    c = db.connect()
    try:
        return c.execute(sql, args).fetchone()[0]
    finally:
        c.close()


def main(path):
    if os.path.exists(path):
        os.remove(path)
    ec2model.TRANSITION_SECONDS = 0
    application = app_module.create_app(os.path.abspath(path), testing=True)
    srv = make_server("127.0.0.1", 0, application, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    aws = lambda svc: boto3.client(svc, endpoint_url=f"http://127.0.0.1:{srv.server_port}/aws",  # noqa: E731
                                   region_name="eu-central-1", aws_access_key_id="test", aws_secret_access_key="test")
    web = application.test_client()
    with web.session_transaction() as s:
        s["user"] = "demo"

    def post(url, **data):
        r = web.post(url, data=data)
        assert r.status_code in (200, 302), (url, r.status_code)
        return r

    # --- Organization (console) -------------------------------------------------
    post("/organization", org_name="Training Enterprise", region="eu-central-1")
    for ou in ["Security", "Infrastructure", "Production", "NonProduction"]:
        post("/ous", name=ou)
    ou = {n: row_id("SELECT id FROM ous WHERE name=?", n) for n in ["Security", "Infrastructure", "Production"]}
    post("/accounts", name="Log Archive", email="log-archive@example.local", ou_id=ou["Security"])
    post("/accounts", name="Security Tooling", email="security@example.local", ou_id=ou["Security"])
    post("/accounts", name="Network", email="network@example.local", ou_id=ou["Infrastructure"])
    for name in ["Restrict Regions", "Protect CloudTrail", "Deny Root Actions"]:
        post("/policies/attach", policy_id=row_id("SELECT id FROM policies WHERE name=?", name),
             target_type="ou", target_id=ou["Production"])

    # --- Two-tier network (console) ---------------------------------------------
    post("/network/vpc/create", name="prod-vpc", cidr="10.20.0.0/16", dns_support="on", dns_hostnames="on")
    vpc = row_id("SELECT id FROM vpcs WHERE name='prod-vpc'")
    for name, cidr, az, public in [("public-a", "10.20.1.0/24", "eu-central-1a", True),
                                   ("public-b", "10.20.2.0/24", "eu-central-1b", True),
                                   ("private-app-a", "10.20.11.0/24", "eu-central-1a", False),
                                   ("private-app-b", "10.20.12.0/24", "eu-central-1b", False)]:
        data = dict(name=name, vpc_id=vpc, cidr=cidr, az=az)
        if public:
            data["map_public_ip"] = "on"
        post("/network/subnet/create", **data)
    sub = {n: row_id("SELECT id FROM subnets WHERE name=?", n) for n in ["public-a", "public-b", "private-app-a", "private-app-b"]}
    post("/network/igw/create", name="prod-igw", vpc_id=vpc)
    r = web.post("/network/route-table/create", data={"name": "public-rt", "vpc_id": vpc, "routes": "0.0.0.0/0 -> igw",
                                                      "subnet_ids": [sub["public-a"], sub["public-b"]]})
    assert r.status_code == 302
    post("/network/nat/create", name="prod-nat-a", subnet_id=sub["public-a"], connectivity_type="public")
    web.post("/network/route-table/create", data={"name": "private-rt", "vpc_id": vpc, "routes": "0.0.0.0/0 -> nat",
                                                  "subnet_ids": [sub["private-app-a"], sub["private-app-b"]]})
    post("/network/security-group/create", name="web-sg", vpc_id=vpc, description="Public web tier",
         inbound="HTTPS 0.0.0.0/0\nHTTP 0.0.0.0/0", outbound="all all 0.0.0.0/0")
    web_sg = row_id("SELECT group_id FROM security_groups WHERE name='web-sg'")
    post("/network/security-group/create", name="app-sg", vpc_id=vpc, description="Private application tier",
         inbound=f"tcp 8080 {web_sg}", outbound="all all 0.0.0.0/0")
    app_sg = row_id("SELECT group_id FROM security_groups WHERE name='app-sg'")
    post("/network/security-group/create", name="db-sg", vpc_id=vpc, description="Database tier",
         inbound=f"tcp 5432 {app_sg}", outbound="all all 0.0.0.0/0")
    web.post("/network/lb/create", data={"name": "web-alb", "vpc_id": vpc, "lb_type": "application",
                                         "scheme": "internet-facing", "subnet_ids": [sub["public-a"], sub["public-b"]],
                                         "security_group_ids": [row_id("SELECT id FROM security_groups WHERE name='web-sg'")]})
    post("/network/endpoint/create", name="s3-gateway", vpc_id=vpc, service_name="com.amazonaws.eu-central-1.s3",
         endpoint_type="gateway")

    # --- Instances (console + CLI) ----------------------------------------------
    subnet_id = {n: row_id("SELECT subnet_id FROM subnets WHERE name=?", n) for n in sub}
    for name, ami, itype, s, sg, extra in [
        ("web-1", UBUNTU, "t3.small", "public-a", web_sg, {"public_ip": "on"}),
        ("web-2", UBUNTU, "t3.small", "public-b", web_sg, {"public_ip": "on"}),
        ("app-1", UBUNTU, "m6i.large", "private-app-a", app_sg, {}),
        ("dc-1", WINDOWS, "t3.large", "private-app-b", app_sg, {"termination_protection": "on", "key_name": "prod-windows-key"}),
    ]:
        vpc_str = row_id("SELECT vpc_id FROM vpcs WHERE id=?", vpc)
        web.post("/compute/launch", data=dict(name=name, ami_id=ami, instance_type=itype, vpc_id=vpc_str,
                                              subnet_id=subnet_id[s], security_group_id=sg, encrypted="on",
                                              root_type="gp3", **extra))
    ec2 = aws("ec2")
    ec2.run_instances(ImageId=AL2023, InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=subnet_id["private-app-b"],
                      SecurityGroupIds=[app_sg], TagSpecifications=[{"ResourceType": "instance",
                                                                     "Tags": [{"Key": "Name", "Value": "batch-worker"}]}])
    ec2.describe_vpcs()
    aws("sts").get_caller_identity()
    bastion = ec2.run_instances(ImageId=AL2023, InstanceType="t3.nano", MinCount=1, MaxCount=1,
                                TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "old-bastion"}]}])
    ec2.stop_instances(InstanceIds=[bastion["Instances"][0]["InstanceId"]])
    ec2.allocate_address(Domain="vpc", TagSpecifications=[{"ResourceType": "elastic-ip",
                                                           "Tags": [{"Key": "Name", "Value": "forgotten-eip"}]}])

    # --- Storage, identity, serverless (CLI) ------------------------------------
    s3 = aws("s3")
    s3.create_bucket(Bucket="training-enterprise-data", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    s3.put_bucket_versioning(Bucket="training-enterprise-data", VersioningConfiguration={"Status": "Enabled"})
    for key, body in [("raw/orders/2026-09-23.json", {"orders": 142}), ("raw/orders/2026-09-24.json", {"orders": 97}),
                      ("reports/2026/q3-summary.txt", "Q3 revenue up 12%"), ("README.txt", "Landing zone data lake")]:
        s3.put_object(Bucket="training-enterprise-data", Key=key,
                      Body=(json.dumps(body) if isinstance(body, dict) else body).encode())
    iam = aws("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="training-only")
    trust = lambda svc: json.dumps({"Version": "2012-10-17", "Statement": [  # noqa: E731
        {"Effect": "Allow", "Principal": {"Service": svc}, "Action": "sts:AssumeRole"}]})
    iam.create_role(RoleName="app-ec2-role", AssumeRolePolicyDocument=trust("ec2.amazonaws.com"))
    role = iam.create_role(RoleName="order-processor-role", AssumeRolePolicyDocument=trust("lambda.amazonaws.com"))["Role"]["Arn"]
    pol = iam.create_policy(PolicyName="OrdersTableWrite", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:UpdateItem"],
         "Resource": "arn:aws:dynamodb:eu-central-1:000000000000:table/Orders"}]}))["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="order-processor-role", PolicyArn=pol)
    iam.attach_role_policy(RoleName="order-processor-role",
                           PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    ddb = aws("dynamodb")
    ddb.create_table(TableName="Orders", BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "customerId", "AttributeType": "S"},
                                           {"AttributeName": "createdAt", "AttributeType": "S"}],
                     KeySchema=[{"AttributeName": "customerId", "KeyType": "HASH"},
                                {"AttributeName": "createdAt", "KeyType": "RANGE"}])
    for cust, ts, total, status in [("c-1001", "2026-09-23T10:02:00Z", "42.50", "PAID"),
                                    ("c-1001", "2026-09-24T08:15:00Z", "19.99", "NEW"),
                                    ("c-2044", "2026-09-24T09:40:00Z", "310.00", "SHIPPED")]:
        ddb.put_item(TableName="Orders", Item={"customerId": {"S": cust}, "createdAt": {"S": ts},
                                               "total": {"N": total}, "status": {"S": status}})
    sm = aws("secretsmanager")
    sm.create_secret(Name="prod/orders/db-password", SecretString=json.dumps({"username": "orders", "password": "not-real"}),
                     Description="Orders database credentials")
    sm.rotate_secret(SecretId="prod/orders/db-password", RotationRules={"AutomaticallyAfterDays": 30})
    post("/lambda/create", name="order-processor", runtime="python3.12", handler="lambda_function.lambda_handler",
         memory_mb="256", timeout_s="10", role=role, description="Validates orders and computes totals", code=LAMBDA_CODE)
    fid = row_id("SELECT id FROM lambda_functions WHERE name='order-processor'")
    aws("lambda").invoke(FunctionName="order-processor", Payload=json.dumps(
        {"orderId": "o-77", "items": [{"sku": "A1", "price": 12.5, "qty": 2}]}).encode())
    post(f"/lambda/{fid}/invoke", payload=json.dumps({"orderId": "o-78", "items": [
        {"sku": "B7", "price": 19.99, "qty": 1}, {"sku": "C3", "price": 4.25, "qty": 4}]}, indent=2))

    post("/snapshots/create", name="Two-tier baseline")
    srv.shutdown()
    print(f"Demo environment written to {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo.db")
