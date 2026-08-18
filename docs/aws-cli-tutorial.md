# Using the Real AWS CLI with the Local AWS Simulator

The simulator exposes a real AWS Query-protocol endpoint at:

```
http://localhost:8080/aws
```

The genuine `aws` CLI and `boto3` work against it, and everything you create
from the CLI appears instantly in the web console (and vice-versa) — both
front-ends share the same SQLite state. No AWS account is used, no real
resource is created, and signatures are accepted but never verified.

> This is the same workflow as Lab 14 — *Drive AWS with the Real CLI*.

---

## 1. Prerequisites

- The simulator running locally: `python3 app.py` → http://localhost:8080
- AWS CLI v2 (`aws --version`). Install per
  [AWS docs](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
  — the CLI itself is free and needs no AWS account.
- Optional: Python + `boto3` for the SDK examples.

## 2. One-time configuration

The CLI refuses to send requests without credentials, but the simulator never
checks them — any non-empty value works. The clean way is a dedicated profile
so your real AWS credentials (if any) are untouched:

```bash
aws configure set profile.local.aws_access_key_id test
aws configure set profile.local.aws_secret_access_key test
aws configure set profile.local.region eu-central-1
```

AWS CLI v2.13+ can also pin the endpoint into the profile, so you never have
to type `--endpoint-url` again:

```bash
aws configure set profile.local.endpoint_url http://localhost:8080/aws
```

Then every command is just:

```bash
aws --profile local ec2 describe-vpcs
```

If your CLI is older than v2.13, keep passing the endpoint per command:

```bash
aws ec2 describe-vpcs --endpoint-url http://localhost:8080/aws --profile local
```

Two gotchas seen in the wild:

- `aws configure --endpoint-url …` does **not** store the endpoint —
  `--endpoint-url` is a per-command flag, silently ignored by `configure`.
  Use `aws configure set profile.local.endpoint_url …` as above.
- If you leave *Default region name* empty during `aws configure`, every
  command will demand `--region`. Set it once in the profile instead.

Alternative: environment variables, no profile at all —

```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=eu-central-1
export AWS_ENDPOINT_URL=http://localhost:8080/aws
aws ec2 describe-vpcs
```

The examples below assume the `local` profile with a pinned endpoint.

## 3. First contact

```bash
aws --profile local ec2 describe-vpcs
```

A fresh simulator always answers with the auto-created default VPC
(`172.31.0.0/16`), exactly like a new AWS account:

```json
{
    "Vpcs": [
        {
            "VpcId": "vpc-4f070078ca1406781",
            "CidrBlock": "172.31.0.0/16",
            "IsDefault": true,
            ...
        }
    ]
}
```

Useful variations while learning:

```bash
# Compact table instead of JSON
aws --profile local ec2 describe-vpcs --output table

# Just the fields you care about
aws --profile local ec2 describe-vpcs \
    --query 'Vpcs[].{id:VpcId,cidr:CidrBlock,default:IsDefault}'

# What images and AZs does the simulator offer?
aws --profile local ec2 describe-images \
    --query 'Images[].{id:ImageId,name:Name,arch:Architecture}' --output table
aws --profile local ec2 describe-availability-zones
```

## 4. Build a network from the terminal

```bash
# 4.1 Create a VPC (tags work via --tag-specifications)
aws --profile local ec2 create-vpc \
    --cidr-block 10.30.0.0/16 \
    --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=cli-vpc}]'

# Note the VpcId from the output, e.g. vpc-0a1b2c3d4e5f60718
VPC_ID=$(aws --profile local ec2 describe-vpcs \
    --query 'Vpcs[?Tags[?Value==`cli-vpc`]].VpcId' --output text)

# 4.2 Create a subnet inside it
aws --profile local ec2 create-subnet \
    --vpc-id "$VPC_ID" \
    --cidr-block 10.30.1.0/24 \
    --availability-zone eu-central-1a \
    --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=cli-subnet}]'

SUBNET_ID=$(aws --profile local ec2 describe-subnets \
    --query 'Subnets[?CidrBlock==`10.30.1.0/24`].SubnetId' --output text)

# 4.3 A security group for the workload
aws --profile local ec2 create-security-group \
    --group-name cli-web-sg --description "web tier" --vpc-id "$VPC_ID"
```

Now open **http://localhost:8080/network** in the browser — the VPC, subnet
and security group you just created from the terminal are all there.

## 5. Launch and manage an instance

```bash
# Launch (image ids come from `describe-images` above)
aws --profile local ec2 run-instances \
    --image-id ami-0c7217cdde317cfec \
    --instance-type t3.micro \
    --subnet-id "$SUBNET_ID" \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=cli-web-1}]'

IID=$(aws --profile local ec2 describe-instances \
    --query 'Reservations[].Instances[?State.Name==`running`][].InstanceId' --output text)

# The instance got a private IP from your subnet's CIDR and a real DNS name
aws --profile local ec2 describe-instances \
    --query 'Reservations[].Instances[].{id:InstanceId,ip:PrivateIpAddress,dns:PrivateDnsName,state:State.Name}' \
    --output table

# Lifecycle
aws --profile local ec2 stop-instances      --instance-ids "$IID"
aws --profile local ec2 start-instances     --instance-ids "$IID"
aws --profile local ec2 terminate-instances --instance-ids "$IID"
```

Check **EC2 Instances** in the web console after each command — the state
changes in real time, and completing this flow also completes **Lab 14**.

## 6. The same thing in boto3

```python
import boto3

ec2 = boto3.client(
    "ec2",
    endpoint_url="http://localhost:8080/aws",
    region_name="eu-central-1",
    aws_access_key_id="test",
    aws_secret_access_key="test",
)

vpc = ec2.create_vpc(CidrBlock="10.40.0.0/16")["Vpc"]
sub = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.40.1.0/24")["Subnet"]
run = ec2.run_instances(
    ImageId="ami-0c7217cdde317cfec",
    InstanceType="t3.micro",
    MinCount=1, MaxCount=1,
    SubnetId=sub["SubnetId"],
)
inst = run["Instances"][0]
print(inst["InstanceId"], inst["PrivateIpAddress"], inst["PrivateDnsName"])
```

## 7. What the endpoint supports today

| Area | Working commands |
|---|---|
| VPC | `describe-vpcs`, `create-vpc`, `delete-vpc` |
| Subnets | `describe-subnets`, `create-subnet`, `delete-subnet` |
| Instances | `describe-instances`, `run-instances`, `start-instances`, `stop-instances`, `terminate-instances` |
| Security groups | `describe-security-groups`, `create-security-group`, `delete-security-group` |
| Route tables | `describe-route-tables` |
| Internet gateways | `describe-internet-gateways` |
| NAT gateways | `describe-nat-gateways` |
| Elastic IPs | `describe-addresses`, `allocate-address` |
| Images | `describe-images` |
| AZs | `describe-availability-zones` |

Accepted as harmless no-ops (so wizards and scripts don't break):
`create-tags`, `delete-tags`, `modify-instance-attribute`, `modify-vpc-attribute`,
`modify-subnet-attribute`, `attach-internet-gateway`, `detach-internet-gateway`.

Everything else returns a well-formed `InvalidAction` error. The S3, IAM,
Lambda, DynamoDB and Secrets Manager consoles are web-only for now — their
API protocols (REST/JSON) are different from EC2's Query protocol and are not
implemented yet.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Connection refused` / `Could not connect` | The simulator isn't running. Start it: `python3 app.py`, then retry. |
| `You must specify a region` | No region in your profile. `aws configure set profile.local.region eu-central-1` or pass `--region`. |
| `Unable to locate credentials` | Set any non-empty dummy values (section 2). They are never verified. |
| `InvalidAction` error | That command isn't implemented yet — see the support table above. |
| Command hits real AWS instead of the simulator | The endpoint wasn't applied. Verify with `aws configure list --profile local`, or pass `--endpoint-url http://localhost:8080/aws` explicitly. The `/aws` path suffix matters. |
| Resource missing in the web console | You're looking at a stale page — refresh. Both front-ends read the same database. |

## 9. How it works

`aws_api.py` implements the AWS *Query* protocol for EC2: the CLI POSTs
form-encoded `Action=…&Version=…` parameters, and the simulator answers with
XML in the `http://ec2.amazonaws.com/doc/2016-11-15/` namespace — the same
wire format real EC2 uses, which is why unmodified AWS tooling parses it.
Behavioural conventions (ID formats, default resources, reserved subnet IPs,
DNS name shapes) mirror what real AWS does, which is why unmodified tooling
accepts the responses. Requests are handled by the same Flask app that serves the
console, writing to the same `simulator.db` — which is why the two views can
never disagree, and why CLI-created resources are included in Backup & Restore
snapshots.
