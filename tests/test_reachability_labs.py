"""Reachability Analyzer verdicts, step-level lab checks, costs and Terraform export."""

import pytest

import db
import costs
import labs
import reachability
import terraform_export

UBUNTU = "ami-0e001c9271cf7f3b9"
WINDOWS = "ami-0f9c44e98edf38a2b"


@pytest.fixture
def two_tier(aws):
    """VPC with a public subnet (IGW) and a private subnet (NAT), one instance in each."""
    ec2 = aws("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]
    pub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.0/24")["Subnet"]["SubnetId"]
    priv = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.2.0/24")["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=pub, MapPublicIpOnLaunch={"Value": True})
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    pub_rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=pub_rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=pub_rt, SubnetId=pub)
    web_sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    app_sg = ec2.create_security_group(GroupName="app", Description="app", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=web_sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.authorize_security_group_ingress(GroupId=app_sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "UserIdGroupPairs": [{"GroupId": web_sg}]}])
    web = ec2.run_instances(ImageId=UBUNTU, InstanceType="t3.small", MinCount=1, MaxCount=1, SubnetId=pub,
                            SecurityGroupIds=[web_sg])["Instances"][0]["InstanceId"]
    app = ec2.run_instances(ImageId=UBUNTU, InstanceType="t3.small", MinCount=1, MaxCount=1, SubnetId=priv,
                            SecurityGroupIds=[app_sg], KeyName="k")["Instances"][0]["InstanceId"]
    return dict(ec2=ec2, vpc=vpc, pub=pub, priv=priv, igw=igw, web=web, app=app, web_sg=web_sg, app_sg=app_sg)


def analyze(*args):
    c = db.connect()
    try:
        return reachability.analyze(c, *args)
    finally:
        c.close()


def blocked_at(result):
    return next(h["component"] for h in result["hops"] if not h["ok"])


def test_public_instance_reaches_internet(two_tier):
    r = analyze(two_tier["web"], "internet", "tcp", 443)
    assert r["reachable"], r


def test_private_instance_needs_a_nat(two_tier):
    ec2 = two_tier["ec2"]
    r = analyze(two_tier["app"], "internet", "tcp", 443)
    assert not r["reachable"] and blocked_at(r) == "Route table"
    alloc = ec2.allocate_address(Domain="vpc")["AllocationId"]
    nat = ec2.create_nat_gateway(SubnetId=two_tier["pub"], AllocationId=alloc)["NatGateway"]["NatGatewayId"]
    priv_rt = ec2.create_route_table(VpcId=two_tier["vpc"])["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=priv_rt, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat)
    ec2.associate_route_table(RouteTableId=priv_rt, SubnetId=two_tier["priv"])
    assert analyze(two_tier["app"], "internet", "tcp", 443)["reachable"]


def test_nat_in_private_subnet_does_not_work(two_tier):
    ec2 = two_tier["ec2"]
    nat = ec2.create_nat_gateway(SubnetId=two_tier["priv"])["NatGateway"]["NatGatewayId"]
    rt = ec2.create_route_table(VpcId=two_tier["vpc"])["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat)
    ec2.associate_route_table(RouteTableId=rt, SubnetId=two_tier["priv"])
    r = analyze(two_tier["app"], "internet", "tcp", 443)
    assert not r["reachable"]


def test_inbound_rules_and_security_group_references(two_tier):
    assert analyze(two_tier["web"], "from-internet", "tcp", 443)["reachable"]
    r = analyze(two_tier["web"], "from-internet", "tcp", 22)
    assert not r["reachable"] and blocked_at(r) == "Security groups (inbound)"
    r = analyze(two_tier["app"], "from-internet", "tcp", 8080)
    assert not r["reachable"] and blocked_at(r) == "Public IPv4"
    assert analyze(two_tier["web"], two_tier["app"], "tcp", 8080)["reachable"]   # sg-to-sg reference
    r = analyze(two_tier["web"], two_tier["app"], "tcp", 5432)
    assert blocked_at(r) == "Security groups (inbound)"


def test_stateless_nacl_blocks_return_traffic(two_tier):
    ec2 = two_tier["ec2"]
    acl = ec2.create_network_acl(VpcId=two_tier["vpc"])["NetworkAcl"]["NetworkAclId"]
    ec2.create_network_acl_entry(NetworkAclId=acl, RuleNumber=100, Protocol="-1", RuleAction="allow",
                                 Egress=True, CidrBlock="0.0.0.0/0")
    ec2.create_network_acl_entry(NetworkAclId=acl, RuleNumber=100, Protocol="6", RuleAction="allow",
                                 Egress=False, CidrBlock="0.0.0.0/0", PortRange={"From": 443, "To": 443})
    assoc = next(a for n in ec2.describe_network_acls()["NetworkAcls"] for a in n["Associations"]
                 if a["SubnetId"] == two_tier["pub"])["NetworkAclAssociationId"]
    ec2.replace_network_acl_association(AssociationId=assoc, NetworkAclId=acl)
    r = analyze(two_tier["web"], "internet", "tcp", 443)
    assert not r["reachable"] and blocked_at(r).startswith("Network ACL inbound (return")


def test_stopped_instance_is_unreachable(two_tier):
    two_tier["ec2"].stop_instances(InstanceIds=[two_tier["web"]])
    r = analyze(two_tier["web"], "internet", "tcp", 443)
    assert blocked_at(r) == "Instance"


def evaluate(lab_id):
    c = db.connect()
    try:
        return labs.evaluate(c, labs.get(lab_id))
    finally:
        c.close()


def test_fresh_environment_completes_no_labs(app):
    c = db.connect()
    results = labs.evaluate_all(c)
    c.close()
    assert not any(r["complete"] for r in results.values())


def test_lab5_needs_real_routing(aws):
    ec2 = aws("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.0/24")["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=sub, MapPublicIpOnLaunch={"Value": True})
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    r = evaluate(5)
    assert [s["ok"] for s in r["steps"]] == [True, True, False]
    assert "0.0.0.0/0" in r["steps"][2]["detail"]
    rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=rt, SubnetId=sub)
    assert evaluate(5)["complete"]


def test_lab6_and_lab7_with_two_tier(two_tier):
    ec2 = two_tier["ec2"]
    assert not evaluate(6)["complete"]
    nat = ec2.create_nat_gateway(SubnetId=two_tier["pub"])["NatGateway"]["NatGatewayId"]
    rt = ec2.create_route_table(VpcId=two_tier["vpc"])["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat)
    ec2.associate_route_table(RouteTableId=rt, SubnetId=two_tier["priv"])
    assert evaluate(6)["complete"]
    lab7 = evaluate(7)
    assert lab7["complete"], lab7   # Ubuntu 24.04, t3.small, private subnet + custom SG, encrypted gp3


def test_lab1_hints_name_the_missing_ous(client):
    client.post("/organization", data={"org_name": "Training Enterprise", "region": "eu-central-1"})
    client.post("/ous", data={"name": "Security"})
    step = evaluate(1)["steps"][2]
    assert not step["ok"] and "Production" in step["detail"] and "Security" not in step["detail"]


def test_costs_teach_the_expensive_bits(two_tier):
    ec2 = two_tier["ec2"]
    ec2.create_nat_gateway(SubnetId=two_tier["pub"])
    ec2.allocate_address(Domain="vpc")
    c = db.connect()
    est = costs.estimate(c)
    c.close()
    services = est["by_service"]
    assert services["VPC"] == pytest.approx(0.052 * 730, abs=0.01)
    assert any("NAT gateway" in t for t in est["tips"]) and any("Elastic IP" in t for t in est["tips"])
    assert est["total"] > 50


def test_terraform_export_references_resources(two_tier):
    c = db.connect()
    hcl = terraform_export.export(c)
    c.close()
    assert 'resource "aws_vpc"' in hcl and "vpc_id                  = aws_vpc." in hcl
    assert 'resource "aws_route_table_association"' in hcl
    assert "gateway_id     = aws_internet_gateway." in hcl
    assert "security_groups = [aws_security_group." in hcl      # sg-to-sg reference kept as a reference
    assert "172.31.0.0/16" not in hcl                           # default VPC skipped
    assert hcl.count("{") == hcl.count("}")
