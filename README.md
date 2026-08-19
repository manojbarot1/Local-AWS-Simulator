# Local AWS Simulator — Enterprise Network & Workload Lab

A local-only Python/Flask training simulator for AWS architecture and Landing Zone practice.

## What's new: high-fidelity AWS behaviour

This build makes the simulator behave much more like real AWS — without
Docker, Java, or any external runtime. The Flask app and all existing pages,
labs and Landing Zone features are unchanged; these are additive:

- **Real AWS resource IDs** — `vpc-0a1b2c3d4e5f60718`, `i-…`, `sg-…`, `subnet-…`
  instead of the old `vpc-local-<uuid>` scheme (see [`aws_fidelity.py`](aws_fidelity.py)).
- **Auto-created default network** — a default VPC, main route table, default
  security group and default network ACL exist out of the box, like a real account.
- **Realistic AMI catalogue, AZs, CIDR-allocated private IPs and EC2 DNS names**
  (`ip-10-20-1-15.eu-central-1.compute.internal`).
- **AWS CLI / boto3 compatibility** — an AWS Query-protocol endpoint at `/aws`
  lets the real `aws` CLI and `boto3` drive the simulator, sharing the same
  SQLite state as the web console (see [`aws_api.py`](aws_api.py)).
- **New service consoles** — S3, IAM, Lambda, DynamoDB and Secrets Manager,
  styled to match the existing AWS-console UI (see [`services.py`](services.py)).

### Using the AWS CLI / boto3 against the simulator

**Full tutorial: [docs/aws-cli-tutorial.md](docs/aws-cli-tutorial.md)** —
profile setup, a complete network + instance walkthrough, boto3 examples,
the supported-command matrix and troubleshooting.

Recommended one-time setup (AWS CLI v2.13+, keeps your real credentials untouched):

```bash
aws configure set profile.local.aws_access_key_id test
aws configure set profile.local.aws_secret_access_key test
aws configure set profile.local.region eu-central-1
aws configure set profile.local.endpoint_url http://localhost:8080/aws
```

Then:

```bash
aws --profile local ec2 describe-vpcs
aws --profile local ec2 create-vpc --cidr-block 10.20.0.0/16
aws --profile local ec2 run-instances \
    --image-id ami-0e001c9271cf7f3b9 --instance-type t3.small
```

```python
import boto3
ec2 = boto3.client("ec2", endpoint_url="http://localhost:8080/aws",
                   region_name="eu-central-1",
                   aws_access_key_id="test", aws_secret_access_key="test")
print(ec2.describe_vpcs()["Vpcs"])
```

Supported EC2 actions today: `Describe/Create/Delete` for VPCs, subnets,
security groups; `Run/Start/Stop/Terminate/DescribeInstances`; and
`DescribeRouteTables/InternetGateways/NatGateways/Addresses/Images/AvailabilityZones`,
plus `AllocateAddress`. S3 now supports the real REST/XML operations used by
`aws s3` and `aws s3api`: create/list/delete buckets and put/list/get/head/delete
objects. IAM, Lambda, DynamoDB and Secrets remain console-only for now. Anything
you create in the CLI shows up in the web console and vice-versa. `boto3` is only
needed to *drive* the CLI — the app itself needs only Flask.

## Login
- Username: `demo`
- Password: `demo`

## Run
```bash
cd local_aws_simulator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```
Open: http://127.0.0.1:8080

## Capabilities

### Landing Zone
- Organization
- Organizational Units
- Accounts
- SCP-style governance policies
- Landing Zone validation
- Backup & Restore

### Networking
The simulator models the core AWS VPC architecture. AWS calls this **VPC**; Azure uses **VNet**. In this AWS-focused simulator, VPC is the virtual network boundary.

- VPCs / CIDR blocks
- DNS support and hostnames
- Subnets and Availability Zones
- Public/private subnet modelling
- Route tables and routes
- Internet Gateways
- NAT Gateways
- Elastic IPs
- Security Groups
- Network ACLs
- VPC endpoints
- Application / Network / Gateway Load Balancer records

### Compute
- EC2 instances
- Linux and Windows AMI catalogue
- Instance types
- Key pairs
- VPC/subnet/security-group selection
- Basic placement and tenancy settings
- EBS root volumes and encryption
- IAM instance profile metadata
- Monitoring and termination protection flags
- User data
- Tags
- Start / Stop / Reboot / Terminate lifecycle simulation

### Architecture integration
The Architecture page is driven from the same SQLite state as the resource pages. Creating a VPC, subnet, gateway, route table, security group or EC2 instance makes it available to the graphical architecture view.

### Dashboard
The Dashboard aggregates simulated resource counts and recent resources across Organizations, VPC networking, EC2 and load balancing.

## Important
No AWS credentials are used. No AWS API calls are made. No real VM, VPC, subnet, IP address, disk or cloud service is created. Resources are local SQLite records only.

## Existing database
`simulator.db` is intentionally not tracked in git. Keep your existing
`simulator.db` in the application directory to preserve your environment — any
new tables are created automatically on startup, so upgrading never loses data.

## Lab Practices

The simulator includes a Training Labs section with 17 hands-on scenarios,
grouped into an ordered learning path:

**Foundation**
1. Build the Organization Foundation
2. Create the Core Accounts
3. Govern the Landing Zone with SCPs

**Networking**
4. Build a VPC Foundation
5. Create a Public Subnet
6. Design a Private Subnet with NAT

**Compute**
7. Deploy a Linux Workload
8. Deploy a Windows Workload Securely

**Storage & Database**
9. Build an S3 Storage Foundation
10. Model a NoSQL Table in DynamoDB

**Identity & Security**
11. Establish the Identity Baseline
12. Protect Application Credentials

**Serverless**
13. Deploy a Lambda Function

**Automation**
14. Drive AWS with the Real CLI (uses the `/aws` endpoint with the real `aws` CLI or boto3)

**Capstone**
15. Build a Two-Tier Application
16. Build a Serverless Data Pipeline
17. Enterprise Landing Zone Challenge

Each lab has objectives, tasks, architecture guidance, an automatic completion
check computed live from simulator state, and a direct link into the relevant
console. The auto-created default VPC does not count toward the networking
labs — you build your own.

## Credits & Attribution

Parts of this simulator's behaviour — realistic resource-ID formats, the
auto-created default network, and the local API-endpoint approach for CLI
compatibility — were inspired by the excellent open-source
**[Floci](https://github.com/floci-io/floci)** local cloud emulator ecosystem
(MIT licensed). If you want a full-fidelity, multi-cloud emulator rather than
a training simulator, use it directly. Thanks to its maintainers for keeping
it free.
