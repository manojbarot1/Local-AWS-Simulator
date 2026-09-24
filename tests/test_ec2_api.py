"""EC2 through real boto3: validation, filters, dependencies, routing, lifecycle."""

import time

import pytest
from botocore.exceptions import ClientError

import ec2model
from conftest import error_code

UBUNTU = "ami-0e001c9271cf7f3b9"
WINDOWS = "ami-0f9c44e98edf38a2b"


def tag(rtype, name):
    return [{"ResourceType": rtype, "Tags": [{"Key": "Name", "Value": name}]}]


@pytest.fixture
def ec2(aws):
    return aws("ec2")


def make_vpc(ec2, cidr="10.20.0.0/16", name="prod"):
    return ec2.create_vpc(CidrBlock=cidr, TagSpecifications=tag("vpc", name))["Vpc"]["VpcId"]


def test_default_vpc_looks_like_a_new_account(ec2):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
    assert len(vpcs) == 1 and vpcs[0]["CidrBlock"] == "172.31.0.0/16"
    subnets = ec2.describe_subnets(Filters=[{"Name": "default-for-az", "Values": ["true"]}])["Subnets"]
    assert len(subnets) == 3 and all(s["MapPublicIpOnLaunch"] for s in subnets)
    igws = ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vpcs[0]["VpcId"]]}])
    assert len(igws["InternetGateways"]) == 1


def test_describe_honours_ids_and_filters(ec2):
    a = make_vpc(ec2, "10.1.0.0/16", "a")
    make_vpc(ec2, "10.2.0.0/16", "b")
    assert [v["VpcId"] for v in ec2.describe_vpcs(VpcIds=[a])["Vpcs"]] == [a]
    assert len(ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": ["b"]}])["Vpcs"]) == 1
    assert len(ec2.describe_vpcs(Filters=[{"Name": "cidr", "Values": ["10.*"]}])["Vpcs"]) == 2
    with pytest.raises(ClientError) as e:
        ec2.describe_vpcs(VpcIds=["vpc-0000000000000000"])
    assert error_code(e) == "InvalidVpcID.NotFound"
    with pytest.raises(ClientError) as e:
        ec2.describe_vpcs(Filters=[{"Name": "bogus", "Values": ["x"]}])
    assert error_code(e) == "InvalidParameterValue"


def test_cidr_validation(ec2):
    for bad, code in [("banana", "InvalidParameterValue"), ("10.0.0.5/16", "InvalidParameterValue"),
                      ("10.0.0.0/8", "InvalidVpc.Range"), ("<x>/16", "InvalidParameterValue")]:
        with pytest.raises(ClientError) as e:
            ec2.create_vpc(CidrBlock=bad)
        assert error_code(e) == code, bad
    vpc = make_vpc(ec2)
    with pytest.raises(ClientError) as e:
        ec2.create_subnet(VpcId=vpc, CidrBlock="192.168.0.0/24")
    assert error_code(e) == "InvalidSubnet.Range"
    ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.0/24")
    with pytest.raises(ClientError) as e:
        ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.128/25")
    assert error_code(e) == "InvalidSubnet.Conflict"
    with pytest.raises(ClientError) as e:
        ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.9.0/24", AvailabilityZone="us-east-1a")
    assert error_code(e) == "InvalidParameterValue"


def test_new_vpc_gets_its_defaults(ec2):
    vpc = make_vpc(ec2)
    rts = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["RouteTables"]
    assert len(rts) == 1 and rts[0]["Associations"][0]["Main"] is True
    assert rts[0]["Routes"][0]["GatewayId"] == "local"
    sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["SecurityGroups"]
    assert [g["GroupName"] for g in sgs] == ["default"]
    acls = ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["NetworkAcls"]
    assert len(acls) == 1 and acls[0]["IsDefault"]


def test_dependency_violation_and_clean_delete(ec2):
    vpc = make_vpc(ec2)
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.0/24")["Subnet"]["SubnetId"]
    with pytest.raises(ClientError) as e:
        ec2.delete_vpc(VpcId=vpc)
    assert error_code(e) == "DependencyViolation"
    ec2.delete_subnet(SubnetId=sub)
    ec2.delete_vpc(VpcId=vpc)   # main RT / default SG / default NACL go with it
    assert vpc not in [v["VpcId"] for v in ec2.describe_vpcs()["Vpcs"]]
    assert not ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["SecurityGroups"]


def test_not_found_errors(ec2):
    cases = [(lambda: ec2.delete_vpc(VpcId="vpc-0123456789abcdef0"), "InvalidVpcID.NotFound"),
             (lambda: ec2.delete_subnet(SubnetId="subnet-0123456789abcdef0"), "InvalidSubnetID.NotFound"),
             (lambda: ec2.terminate_instances(InstanceIds=["i-0123456789abcdef0"]), "InvalidInstanceID.NotFound"),
             (lambda: ec2.delete_security_group(GroupId="sg-0123456789abcdef0"), "InvalidGroup.NotFound"),
             (lambda: ec2.run_instances(ImageId="ami-00000000", InstanceType="t3.micro", MinCount=1, MaxCount=1),
              "InvalidAMIID.NotFound")]
    for call, code in cases:
        with pytest.raises(ClientError) as e:
            call()
        assert error_code(e) == code


def test_igw_routes_and_associations(ec2):
    vpc = make_vpc(ec2)
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.0/24")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    with pytest.raises(ClientError) as e:   # not attached yet
        ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assert error_code(e) == "InvalidParameterValue"
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    with pytest.raises(ClientError) as e:
        ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    assert error_code(e) == "Resource.AlreadyAssociated"
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    with pytest.raises(ClientError) as e:
        ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assert error_code(e) == "RouteAlreadyExists"
    assoc = ec2.associate_route_table(RouteTableId=rt, SubnetId=sub)["AssociationId"]
    table = ec2.describe_route_tables(RouteTableIds=[rt])["RouteTables"][0]
    assert {r["DestinationCidrBlock"]: r["State"] for r in table["Routes"]} == {"10.20.0.0/16": "active", "0.0.0.0/0": "active"}
    assert table["Associations"][0]["SubnetId"] == sub
    with pytest.raises(ClientError) as e:
        ec2.delete_route_table(RouteTableId=rt)
    assert error_code(e) == "DependencyViolation"
    with pytest.raises(ClientError) as e:
        ec2.delete_internet_gateway(InternetGatewayId=igw)
    assert error_code(e) == "DependencyViolation"
    ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    table = ec2.describe_route_tables(RouteTableIds=[rt])["RouteTables"][0]
    assert [r["State"] for r in table["Routes"] if r["DestinationCidrBlock"] == "0.0.0.0/0"] == ["blackhole"]
    ec2.disassociate_route_table(AssociationId=assoc)
    ec2.delete_route_table(RouteTableId=rt)


def test_nat_gateway_gets_an_elastic_ip(ec2):
    vpc = make_vpc(ec2)
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.0/24")["Subnet"]["SubnetId"]
    alloc = ec2.allocate_address(Domain="vpc")["AllocationId"]
    nat = ec2.create_nat_gateway(SubnetId=sub, AllocationId=alloc)["NatGateway"]
    assert nat["NatGatewayAddresses"][0]["AllocationId"] == alloc
    with pytest.raises(ClientError) as e:
        ec2.release_address(AllocationId=alloc)
    assert error_code(e) == "InvalidIPAddress.InUse"
    ec2.delete_nat_gateway(NatGatewayId=nat["NatGatewayId"])
    ec2.release_address(AllocationId=alloc)


def test_security_group_rules(ec2):
    vpc = make_vpc(ec2)
    gid = ec2.create_security_group(GroupName="web", Description="web tier", VpcId=vpc)["GroupId"]
    perm = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[perm])
    with pytest.raises(ClientError) as e:
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[perm])
    assert error_code(e) == "InvalidPermission.Duplicate"
    g = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
    assert g["IpPermissions"][0]["FromPort"] == 443
    assert g["IpPermissionsEgress"][0]["IpProtocol"] == "-1"   # allow-all egress by default
    ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=[perm])
    with pytest.raises(ClientError) as e:
        ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=[perm])
    assert error_code(e) == "InvalidPermission.NotFound"
    default = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc]},
                                                    {"Name": "group-name", "Values": ["default"]}])["SecurityGroups"][0]
    with pytest.raises(ClientError) as e:
        ec2.delete_security_group(GroupId=default["GroupId"])
    assert error_code(e) == "CannotDelete"


def test_run_instances_placement_and_filters(ec2):
    vpc = make_vpc(ec2)
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.0/24")["Subnet"]["SubnetId"]
    gid = ec2.create_security_group(GroupName="app", Description="app", VpcId=vpc)["GroupId"]
    res = ec2.run_instances(ImageId=UBUNTU, InstanceType="t3.small", MinCount=2, MaxCount=2, SubnetId=sub,
                            SecurityGroupIds=[gid], TagSpecifications=tag("instance", "app"))
    ids = [i["InstanceId"] for i in res["Instances"]]
    inst = ec2.describe_instances(InstanceIds=ids)["Reservations"][0]["Instances"][0]
    assert inst["VpcId"] == vpc and inst["SubnetId"] == sub and inst["SecurityGroups"][0]["GroupId"] == gid
    assert inst["PrivateIpAddress"] == "10.20.1.4"      # first four addresses are AWS-reserved
    assert "PublicIpAddress" not in inst
    launch = inst["LaunchTime"]
    time.sleep(1.1)
    again = ec2.describe_instances(InstanceIds=[ids[0]])["Reservations"][0]["Instances"][0]
    assert again["LaunchTime"] == launch                 # no longer "now" on every call
    running = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}])
    assert running["Reservations"] == []
    by_subnet = ec2.describe_instances(Filters=[{"Name": "subnet-id", "Values": [sub]}])["Reservations"]
    assert len(by_subnet) == 2
    # Default placement: default VPC, public IP, default SG.
    d = ec2.run_instances(ImageId=UBUNTU, InstanceType="t3.micro", MinCount=1, MaxCount=1)["Instances"][0]
    assert d["PublicIpAddress"] and d["SecurityGroups"][0]["GroupName"] == "default"


def test_lifecycle_protection_and_public_ip(ec2):
    i = ec2.run_instances(ImageId=UBUNTU, InstanceType="t3.micro", MinCount=1, MaxCount=1,
                          DisableApiTermination=True)["Instances"][0]
    iid = i["InstanceId"]
    first_ip = i["PublicIpAddress"]
    with pytest.raises(ClientError) as e:
        ec2.terminate_instances(InstanceIds=[iid])
    assert error_code(e) == "OperationNotPermitted"
    ec2.stop_instances(InstanceIds=[iid])
    stopped = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    assert stopped["State"]["Name"] == "stopped" and "PublicIpAddress" not in stopped
    ec2.start_instances(InstanceIds=[iid])
    started = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    assert started["PublicIpAddress"]   # a new auto-assigned address (first was {first_ip})
    ec2.modify_instance_attribute(InstanceId=iid, DisableApiTermination={"Value": False})
    out = ec2.terminate_instances(InstanceIds=[iid])["TerminatingInstances"][0]
    assert out["CurrentState"]["Name"] == "terminated"
    with pytest.raises(ClientError) as e:
        ec2.start_instances(InstanceIds=[iid])
    assert error_code(e) == "IncorrectInstanceState"


def test_pending_state_and_waiter(ec2):
    ec2model.TRANSITION_SECONDS = 1
    try:
        iid = ec2.run_instances(ImageId=UBUNTU, InstanceType="t3.micro", MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
        state = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]["State"]["Name"]
        assert state == "pending"
        ec2.get_waiter("instance_running").wait(InstanceIds=[iid], WaiterConfig={"Delay": 1, "MaxAttempts": 10})
    finally:
        ec2model.TRANSITION_SECONDS = 0


def test_tags_and_modify_subnet(ec2):
    vpc = make_vpc(ec2)
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.0/24")["Subnet"]["SubnetId"]
    ec2.create_tags(Resources=[vpc, sub], Tags=[{"Key": "Env", "Value": "prod"}, {"Key": "Name", "Value": "renamed"}])
    assert len(ec2.describe_subnets(Filters=[{"Name": "tag:Env", "Values": ["prod"]}])["Subnets"]) == 1
    ec2.modify_subnet_attribute(SubnetId=sub, MapPublicIpOnLaunch={"Value": True})
    assert ec2.describe_subnets(SubnetIds=[sub])["Subnets"][0]["MapPublicIpOnLaunch"] is True
    ec2.delete_tags(Resources=[vpc], Tags=[{"Key": "Env"}])
    tags = {t["Key"] for t in ec2.describe_vpcs(VpcIds=[vpc])["Vpcs"][0].get("Tags", [])}
    assert "Env" not in tags


def test_unsupported_action_is_a_clear_error(ec2):
    with pytest.raises(ClientError) as e:
        ec2.describe_transit_gateways()
    assert error_code(e) == "InvalidAction"


def test_default_vpc_can_be_recreated(ec2):
    default = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"][0]["VpcId"]
    with pytest.raises(ClientError) as e:
        ec2.create_default_vpc()
    assert error_code(e) == "DefaultVpcAlreadyExists"
    for sub in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [default]}])["Subnets"]:
        ec2.delete_subnet(SubnetId=sub["SubnetId"])
    igw = ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [default]}])["InternetGateways"][0]
    ec2.detach_internet_gateway(InternetGatewayId=igw["InternetGatewayId"], VpcId=default)
    ec2.delete_internet_gateway(InternetGatewayId=igw["InternetGatewayId"])
    ec2.delete_vpc(VpcId=default)
    with pytest.raises(ClientError) as e:
        ec2.run_instances(ImageId=UBUNTU, InstanceType="t3.micro", MinCount=1, MaxCount=1)
    assert error_code(e) == "VPCIdNotSpecified"
    vpc = ec2.create_default_vpc()["Vpc"]
    assert vpc["IsDefault"] and vpc["CidrBlock"] == "172.31.0.0/16"
    assert ec2.run_instances(ImageId=UBUNTU, InstanceType="t3.micro", MinCount=1, MaxCount=1)["Instances"]
