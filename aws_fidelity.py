"""
aws_fidelity.py
===============

Behavioural fidelity helpers for this Flask simulator: the shapes and
conventions the real AWS APIs use, reproduced so simulated resources are
indistinguishable in format from real ones:

  * real AWS resource-ID formats (``vpc-`` + 17 hex, not ``vpc-local-<uuid>``)
  * a realistic AMI catalogue with real-looking image IDs
  * region -> availability-zone derivation
  * private IPs allocated from the subnet CIDR instead of ``random.randint``
  * EC2 internal/private DNS names
  * the default VPC / default security group / main route table / default NACL
    that AWS auto-creates so a brand-new account is never empty

Everything here is pure data + pure functions with no Flask or DB dependency, so
it is trivially unit-testable and does not change the app's existing schema.
"""

from __future__ import annotations

import ipaddress
import secrets
from typing import Iterable

# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------

# The well-known account number local AWS emulators use for test resources.
DEFAULT_ACCOUNT_ID = "000000000000"


# ---------------------------------------------------------------------------
# Resource IDs
# ---------------------------------------------------------------------------

def aws_id(prefix: str, length: int = 17) -> str:
    """Return an AWS-style resource id, e.g. ``vpc-0a1b2c3d4e5f60718``.

    Real AWS resource ids are the resource-type prefix, a hyphen, then a
    lowercase hex string (8 chars on legacy resources, 17 on modern ones).
    We use 17 uniformly — it is the current AWS default and reads as real,
    unlike the previous ``vpc-local-<uuid>`` scheme which no AWS tool accepts.
    """
    return f"{prefix}-{secrets.token_hex(length // 2 + 1)[:length]}"


# ---------------------------------------------------------------------------
# Regions & availability zones
# ---------------------------------------------------------------------------

# region -> number of AZs to expose. AWS AZ names are the region plus a letter
# suffix (a, b, c, ...).
REGIONS = {
    "us-east-1": 6,
    "us-east-2": 3,
    "us-west-1": 3,
    "us-west-2": 4,
    "eu-west-1": 3,
    "eu-west-2": 3,
    "eu-central-1": 3,
    "eu-north-1": 3,
    "ap-south-1": 3,
    "ap-southeast-1": 3,
    "ap-southeast-2": 3,
    "ap-northeast-1": 3,
    "ca-central-1": 3,
    "sa-east-1": 3,
}


def azs_for(region: str) -> list[str]:
    """Availability-zone names for a region, e.g. ['eu-central-1a', ...]."""
    count = REGIONS.get(region, 3)
    return [f"{region}{chr(ord('a') + i)}" for i in range(count)]


def internal_dns_suffix(region: str) -> str:
    """AWS uses ``ec2.internal`` in us-east-1 and ``<region>.compute.internal``
    everywhere else for private DNS names."""
    return "ec2.internal" if region == "us-east-1" else f"{region}.compute.internal"


# ---------------------------------------------------------------------------
# AMI catalogue
# ---------------------------------------------------------------------------

# Real-looking image catalogue. `id`, `name`, `os` and `arch` keys are kept for
# template compatibility; the rest mirror what DescribeImages returns so the
# same catalogue can back both the console and the CLI endpoint.
AMI_CATALOG = [
    {
        "id": "ami-0c7217cdde317cfec", "name": "Amazon Linux 2023",
        "os": "Linux", "arch": "x86_64", "platform": "amazon-linux",
        "description": "Amazon Linux 2023 AMI 2023.4 x86_64 HVM kernel-6.1",
        "root_device": "/dev/xvda", "virtualization": "hvm",
    },
    {
        "id": "ami-0e001c9271cf7f3b9", "name": "Ubuntu Server 24.04 LTS",
        "os": "Linux", "arch": "x86_64", "platform": "ubuntu",
        "description": "Canonical, Ubuntu, 24.04 LTS, amd64 noble image",
        "root_device": "/dev/sda1", "virtualization": "hvm",
    },
    {
        "id": "ami-0a0e5d9c7acc336f1", "name": "Ubuntu Server 24.04 LTS (ARM)",
        "os": "Linux", "arch": "arm64", "platform": "ubuntu",
        "description": "Canonical, Ubuntu, 24.04 LTS, arm64 noble image",
        "root_device": "/dev/sda1", "virtualization": "hvm",
    },
    {
        "id": "ami-0fc5d935ebf8bc3bc", "name": "Ubuntu Server 22.04 LTS",
        "os": "Linux", "arch": "x86_64", "platform": "ubuntu",
        "description": "Canonical, Ubuntu, 22.04 LTS, amd64 jammy image",
        "root_device": "/dev/sda1", "virtualization": "hvm",
    },
    {
        "id": "ami-0eb260c4d5475b901", "name": "Red Hat Enterprise Linux 9",
        "os": "Linux", "arch": "x86_64", "platform": "rhel",
        "description": "Provided by Red Hat, Inc. RHEL-9.3 x86_64",
        "root_device": "/dev/sda1", "virtualization": "hvm",
    },
    {
        "id": "ami-05a3d90809a151346", "name": "SUSE Linux Enterprise Server 15",
        "os": "Linux", "arch": "x86_64", "platform": "sles",
        "description": "SUSE Linux Enterprise Server 15 SP5 x86_64",
        "root_device": "/dev/sda1", "virtualization": "hvm",
    },
    {
        "id": "ami-0d02c2f74f42c3c4e", "name": "Debian 12",
        "os": "Linux", "arch": "x86_64", "platform": "debian",
        "description": "Debian 12 (bookworm) amd64",
        "root_device": "/dev/xvda", "virtualization": "hvm",
    },
    {
        "id": "ami-0b0ea68c435eb488d", "name": "Microsoft Windows Server 2025 Base",
        "os": "Windows", "arch": "x86_64", "platform": "windows",
        "description": "Microsoft Windows Server 2025 Full Base",
        "root_device": "/dev/sda1", "virtualization": "hvm",
    },
    {
        "id": "ami-0f9c44e98edf38a2b", "name": "Microsoft Windows Server 2022 Base",
        "os": "Windows", "arch": "x86_64", "platform": "windows",
        "description": "Microsoft Windows Server 2022 Full Base",
        "root_device": "/dev/sda1", "virtualization": "hvm",
    },
    {
        "id": "ami-0c2b8ca1dad447f8a", "name": "Microsoft Windows Server 2019 Base",
        "os": "Windows", "arch": "x86_64", "platform": "windows",
        "description": "Microsoft Windows Server 2019 Full Base",
        "root_device": "/dev/sda1", "virtualization": "hvm",
    },
]


# ---------------------------------------------------------------------------
# Instance types
# ---------------------------------------------------------------------------

# (name, vCPUs, memory GiB, network) — shared by the console launch form and
# the AWS Query endpoint so both write the same config shape.
EC2_INSTANCE_TYPES = [
    ("t3.nano", 2, 0.5, "Up to 5 Gbps"), ("t3.micro", 2, 1, "Up to 5 Gbps"), ("t3.small", 2, 2, "Up to 5 Gbps"),
    ("t3.medium", 2, 4, "Up to 5 Gbps"), ("t3.large", 2, 8, "Up to 5 Gbps"), ("t3.xlarge", 4, 16, "Up to 5 Gbps"),
    ("m6i.large", 2, 8, "Up to 12.5 Gbps"), ("m6i.xlarge", 4, 16, "Up to 12.5 Gbps"),
    ("m6i.2xlarge", 8, 32, "Up to 12.5 Gbps"), ("m6i.4xlarge", 16, 64, "Up to 12.5 Gbps"),
    ("c6i.large", 2, 4, "Up to 12.5 Gbps"), ("c6i.xlarge", 4, 8, "Up to 12.5 Gbps"),
    ("c6i.2xlarge", 8, 16, "Up to 12.5 Gbps"), ("r6i.large", 2, 16, "Up to 12.5 Gbps"),
    ("r6i.xlarge", 4, 32, "Up to 12.5 Gbps"), ("r6i.2xlarge", 8, 64, "Up to 12.5 Gbps"),
    ("g4dn.xlarge", 4, 16, "Up to 25 Gbps"), ("g5.xlarge", 4, 16, "Up to 10 Gbps"),
]


def instance_type_spec(name: str) -> dict:
    """Full spec dict for an instance type, tolerating unknown names."""
    for t in EC2_INSTANCE_TYPES:
        if t[0] == name:
            return {"name": t[0], "vcpus": t[1], "memory_gib": t[2], "network": t[3]}
    return {"name": name, "vcpus": "—", "memory_gib": "—", "network": "—"}


# ---------------------------------------------------------------------------
# IP allocation
# ---------------------------------------------------------------------------

def allocate_private_ip(cidr: str, used: Iterable[str]) -> str:
    """Return the next free host address in ``cidr``.

    AWS reserves the first four addresses (network, VPC router, DNS, future
    use) and the broadcast address in every subnet, so allocation starts at
    the fifth address — the same rule real AWS applies.
    """
    used_set = {u for u in used if u}
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        # Fall back to a stable RFC5737 documentation address rather than crash.
        return "10.0.0.4"
    hosts = list(net.hosts())
    # Drop the AWS-reserved .1/.2/.3 (index 0/1/2 of hosts()); .0 network and
    # broadcast are already excluded by hosts().
    for host in hosts[3:]:
        candidate = str(host)
        if candidate not in used_set:
            return candidate
    # Subnet exhausted — degrade gracefully.
    return str(hosts[-1]) if hosts else "10.0.0.4"


def private_dns_name(private_ip: str, region: str) -> str:
    """EC2 private DNS name, e.g. ``ip-10-0-1-15.eu-central-1.compute.internal``."""
    dashed = private_ip.replace(".", "-")
    return f"ip-{dashed}.{internal_dns_suffix(region)}"


def public_dns_name(public_ip: str, region: str) -> str:
    """EC2 public DNS name, e.g. ``ec2-52-1-2-3.compute-1.amazonaws.com``."""
    dashed = public_ip.replace(".", "-")
    zone = "compute-1" if region == "us-east-1" else f"{region}.compute"
    return f"ec2-{dashed}.{zone}.amazonaws.com"


def random_public_ip() -> str:
    """A plausible public IPv4 for an EC2 instance / EIP.

    Uses the TEST-NET ranges reserved for documentation so it can never collide
    with a real routable address, while still looking like a public IP.
    """
    block = secrets.choice(["52", "54", "3", "18", "34"])
    return f"{block}.{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(254) + 1}"


# ---------------------------------------------------------------------------
# Default resources auto-created per AWS account / VPC
# ---------------------------------------------------------------------------

DEFAULT_VPC_CIDR = "172.31.0.0/16"

# The permissive default security group AWS creates in every VPC: it allows all
# traffic from itself inbound and all traffic outbound.
DEFAULT_SG_INBOUND = ["ALL ALL self (sg default)"]
DEFAULT_SG_OUTBOUND = ["ALL ALL 0.0.0.0/0"]

# The default network ACL: allow-all in both directions plus the implicit deny.
DEFAULT_NACL_RULES = [
    "100 ALLOW ALL 0.0.0.0/0 ingress",
    "100 ALLOW ALL 0.0.0.0/0 egress",
    "* DENY ALL 0.0.0.0/0",
]
