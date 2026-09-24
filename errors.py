"""
errors.py
=========

One exception type for every rule the simulator enforces. Domain code raises
``SimError`` with the *real* AWS error code and message; the AWS API layer turns
it into the protocol-specific error body, and the web console turns it into a
red flash banner. That keeps both front-ends teaching the same lesson.
"""


class SimError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def not_found(kind, rid):
    """AWS-style ``Invalid<Kind>ID.NotFound`` error."""
    codes = {
        "vpc": ("InvalidVpcID.NotFound", "vpc ID"),
        "subnet": ("InvalidSubnetID.NotFound", "subnet ID"),
        "instance": ("InvalidInstanceID.NotFound", "instance ID"),
        "sg": ("InvalidGroup.NotFound", "security group"),
        "rtb": ("InvalidRouteTableID.NotFound", "route table ID"),
        "igw": ("InvalidInternetGatewayID.NotFound", "internetGateway ID"),
        "nat": ("NatGatewayNotFound", "NAT gateway ID"),
        "eip": ("InvalidAllocationID.NotFound", "allocation ID"),
        "acl": ("InvalidNetworkAclID.NotFound", "network ACL ID"),
        "ami": ("InvalidAMIID.NotFound", "image id"),
        "assoc": ("InvalidAssociationID.NotFound", "association ID"),
    }
    code, label = codes.get(kind, ("InvalidParameterValue", kind))
    return SimError(code, f"The {label} '{rid}' does not exist")


def dependency(kind, rid, detail=""):
    msg = f"The {kind} '{rid}' has dependencies and cannot be deleted."
    if detail:
        msg += f" ({detail})"
    return SimError("DependencyViolation", msg)
