# Using the Real AWS CLI with the Local AWS Simulator

The simulator exposes an AWS-compatible endpoint at:

```
http://localhost:8080/aws
```

The genuine `aws` CLI and `boto3` work against it, and everything you create
from the CLI appears instantly in the web console (and vice-versa) — both
front-ends share the same SQLite state. No AWS account is used, no real
resource is created, and signatures are accepted but never verified.

Supported services: **EC2/VPC, S3, IAM, STS, DynamoDB, Secrets Manager and
Lambda** (Python functions really execute). Every call you make shows up in the
console's **Activity & CLI log**.

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

Start with `aws --profile local sts get-caller-identity` — account
`000000000000` means you are talking to the simulator, not AWS.

A fresh simulator answers `describe-vpcs` with the auto-created default VPC
(`172.31.0.0/16`, one default subnet per AZ and an internet gateway), exactly
like a new AWS account:

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

## 5. Make the subnet public

A subnet is only *public* when its route table sends `0.0.0.0/0` to an
internet gateway attached to the VPC. The simulator enforces this — and the
console's **Reachability Analyzer** shows exactly which hop is missing.

```bash
IGW_ID=$(aws --profile local ec2 create-internet-gateway \
    --query InternetGateway.InternetGatewayId --output text)
aws --profile local ec2 attach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID"

RT_ID=$(aws --profile local ec2 create-route-table --vpc-id "$VPC_ID" \
    --query RouteTable.RouteTableId --output text)
aws --profile local ec2 create-route --route-table-id "$RT_ID" \
    --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID"
aws --profile local ec2 associate-route-table --route-table-id "$RT_ID" --subnet-id "$SUBNET_ID"
aws --profile local ec2 modify-subnet-attribute --subnet-id "$SUBNET_ID" --map-public-ip-on-launch

# Open HTTPS to the world
SG_ID=$(aws --profile local ec2 describe-security-groups \
    --filters Name=group-name,Values=cli-web-sg --query 'SecurityGroups[0].GroupId' --output text)
aws --profile local ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol tcp --port 443 --cidr 0.0.0.0/0
```

The simulator checks what AWS checks: CIDRs must be /16–/28 and subnets must
fit inside the VPC without overlapping (`InvalidSubnet.Range` /
`InvalidSubnet.Conflict`), you can't route to a gateway attached to another VPC,
and `delete-vpc` fails with `DependencyViolation` while anything is still in it.

## 6. Launch and manage an instance

```bash
# Launch (image ids come from `describe-images` above)
IID=$(aws --profile local ec2 run-instances \
    --image-id ami-0c7217cdde317cfec \
    --instance-type t3.micro \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$SG_ID" \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=cli-web-1}]' \
    --query 'Instances[0].InstanceId' --output text)

# New instances start "pending" and become "running" a few seconds later,
# so waiters behave like the real thing:
aws --profile local ec2 wait instance-running --instance-ids "$IID"

# Private IP from your subnet (first four addresses are reserved), a public IP
# because the subnet auto-assigns one, and real-looking DNS names
aws --profile local ec2 describe-instances --instance-ids "$IID" \
    --query 'Reservations[].Instances[].{id:InstanceId,ip:PrivateIpAddress,public:PublicIpAddress,state:State.Name}' \
    --output table

# Filters work, too
aws --profile local ec2 describe-instances --filters Name=instance-state-name,Values=running Name=tag:Name,Values=cli-*

# Lifecycle. Stopping releases the auto-assigned public IP; starting gets a new one.
aws --profile local ec2 stop-instances      --instance-ids "$IID"
aws --profile local ec2 start-instances     --instance-ids "$IID"
aws --profile local ec2 modify-instance-attribute --instance-id "$IID" --disable-api-termination
aws --profile local ec2 terminate-instances --instance-ids "$IID"   # -> OperationNotPermitted
aws --profile local ec2 modify-instance-attribute --instance-id "$IID" --no-disable-api-termination
aws --profile local ec2 terminate-instances --instance-ids "$IID"
```

Check **EC2 Instances** in the web console after each command — the state
changes in real time, and completing this flow also completes **Lab 14**.

## 7. The same thing in boto3

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
ec2.get_waiter("instance_running").wait(InstanceIds=[inst["InstanceId"]])
print(inst["InstanceId"], inst["PrivateIpAddress"], inst["PrivateDnsName"])
```

## 8. S3 from the terminal

S3 uses a REST/XML protocol rather than EC2's Query protocol, but it uses the
same local endpoint and profile. Buckets and objects written here appear in the
**S3** console immediately.

```bash
aws --profile local s3 mb s3://training-assets
aws --profile local s3api put-bucket-versioning --bucket training-assets \
    --versioning-configuration Status=Enabled

printf 'hello from the real AWS CLI\n' > welcome.txt
aws --profile local s3 cp welcome.txt s3://training-assets/labs/welcome.txt
aws --profile local s3 sync ./my-folder s3://training-assets/site/
aws --profile local s3 ls s3://training-assets/          # folders show as PRE
aws --profile local s3 ls s3://training-assets --recursive
aws --profile local s3 cp s3://training-assets/labs/welcome.txt -

aws --profile local s3api head-object --bucket training-assets --key labs/welcome.txt
aws --profile local s3 rb s3://training-assets           # BucketNotEmpty, like AWS
aws --profile local s3 rb s3://training-assets --force   # empties it first
```

Large files use multipart upload automatically (`aws s3 cp` switches above
8 MB), server-side copies (`s3 cp s3://a/x s3://b/y`, `s3 mv`) work, and
objects are stored as bytes so binary content round-trips exactly.

## 9. IAM, DynamoDB, Secrets Manager and Lambda

```bash
# IAM: a role Lambda can assume, plus a least-privilege policy
cat > trust.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF
aws --profile local iam create-role --role-name order-processor \
    --assume-role-policy-document file://trust.json
aws --profile local iam attach-role-policy --role-name order-processor \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# DynamoDB: composite key, queries and update expressions
aws --profile local dynamodb create-table --table-name Orders \
    --attribute-definitions AttributeName=customer,AttributeType=S AttributeName=ts,AttributeType=N \
    --key-schema AttributeName=customer,KeyType=HASH AttributeName=ts,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST
aws --profile local dynamodb put-item --table-name Orders \
    --item '{"customer":{"S":"c1"},"ts":{"N":"1"},"total":{"N":"10"}}'
aws --profile local dynamodb query --table-name Orders \
    --key-condition-expression "customer = :c" --expression-attribute-values '{":c":{"S":"c1"}}'
aws --profile local dynamodb update-item --table-name Orders \
    --key '{"customer":{"S":"c1"},"ts":{"N":"1"}}' \
    --update-expression "SET total = total + :n" --expression-attribute-values '{":n":{"N":"5"}}' \
    --return-values ALL_NEW

# Secrets Manager
aws --profile local secretsmanager create-secret --name prod/db/password --secret-string 'hunter2'
aws --profile local secretsmanager get-secret-value --secret-id prod/db/password

# Lambda: Python handlers really run, with your timeout enforced
cat > lambda_function.py <<'EOF'
def lambda_handler(event, context):
    print("adding", event)
    return {"sum": event["a"] + event["b"], "function": context.function_name}
EOF
zip function.zip lambda_function.py
aws --profile local lambda create-function --function-name adder --runtime python3.12 \
    --role arn:aws:iam::000000000000:role/order-processor \
    --handler lambda_function.lambda_handler --zip-file fileb://function.zip
aws --profile local lambda invoke --function-name adder \
    --cli-binary-format raw-in-base64-out --payload '{"a": 2, "b": 3}' \
    --log-type Tail --query LogResult --output text out.json | base64 -d
cat out.json    # {"sum": 5, "function": "adder"}
```

Like real Lambda, `create-function` fails unless the role exists and trusts
`lambda.amazonaws.com`. Non-Python runtimes are accepted but their invocations
are simulated. Set `SIM_LAMBDA_EXEC=0` to disable code execution entirely.

## 10. What the endpoint supports today

| Service | Working commands |
|---|---|
| STS | `get-caller-identity`, `assume-role` |
| VPC | `describe/create/delete-vpc`, `create-default-vpc`, `modify-vpc-attribute`, `describe-vpc-attribute` |
| Subnets | `describe/create/delete-subnet`, `modify-subnet-attribute` |
| Route tables | `describe/create/delete-route-table`, `create/replace/delete-route`, `associate/disassociate-route-table` |
| Internet gateways | `describe/create/delete-internet-gateway`, `attach/detach-internet-gateway` |
| NAT gateways | `describe/create/delete-nat-gateway` |
| Elastic IPs | `describe-addresses`, `allocate/release-address`, `associate/disassociate-address` |
| Security groups | `describe/create/delete-security-group`, `authorize/revoke-security-group-ingress/egress` |
| Network ACLs | `describe/create/delete-network-acl`, `create/delete-network-acl-entry`, `replace-network-acl-association` |
| Instances | `describe-instances`, `describe-instance-status`, `run/start/stop/reboot/terminate-instances`, `modify/describe-instance-attribute`, waiters |
| Tags & catalogue | `create-tags`, `delete-tags`, `describe-images`, `describe-availability-zones`, `describe-regions` |
| S3 | `s3 mb/rb/cp/mv/sync/ls/rm`, `s3api` buckets, objects, `list-objects(-v2)` with prefix/delimiter/pagination, multipart, copy, `delete-objects`, bucket versioning & location |
| IAM | users (+ login profiles), roles, customer policies, `attach/detach/list-attached-role/user-policies` |
| DynamoDB | `create/describe/list/delete-table`, `put/get/update/delete-item`, `query`, `scan`, `batch-write-item`, `batch-get-item` (key conditions, filter/condition/update/projection expressions) |
| Secrets Manager | `create-secret`, `get/put-secret-value`, `update/describe/list/delete-secret(s)`, `rotate-secret`, `cancel-rotate-secret` |
| Lambda | `create/get/list/delete-function`, `update-function-code/-configuration`, `invoke` (real Python execution, `--log-type Tail`) |

Describe calls honour `--*-ids` and `--filters` (including `tag:<key>` and
wildcards), and unknown IDs return the same `Invalid…ID.NotFound` errors AWS
does. Anything else returns a clear `InvalidAction` error listing what *is*
supported.

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Connection refused` / `Could not connect` | The simulator isn't running. Start it: `python3 app.py`, then retry. |
| `You must specify a region` | No region in your profile. `aws configure set profile.local.region eu-central-1` or pass `--region`. |
| `Unable to locate credentials` | Set any non-empty dummy values (section 2). They are never verified. |
| `InvalidAction` error | That command isn't implemented yet — the error lists the supported ones. |
| `VPCIdNotSpecified` on `run-instances` | No subnet given and the default VPC was deleted. Pass `--subnet-id`, or run `aws --profile local ec2 create-default-vpc`. |
| `DependencyViolation` | Working as intended — delete the dependent resources the message names first. |
| `403 Forbidden` | The simulator only answers on `localhost`/`127.0.0.1` and refuses cross-site browser requests. Use `http://localhost:8080/aws`, or set `SIM_ALLOWED_HOSTS` if you serve it under another name. |
| Command hits real AWS instead of the simulator | The endpoint wasn't applied. Verify with `aws configure list --profile local`, or pass `--endpoint-url http://localhost:8080/aws` explicitly. The `/aws` path suffix matters. |
| Resource missing in the web console | You're looking at a stale page — refresh. Both front-ends read the same database. |

## 12. How it works

The `aws_api/` package implements each service's real wire protocol: the EC2
and IAM/STS *Query* protocols (form-encoded `Action=…` in, XML out), S3's
REST/XML, the JSON protocol DynamoDB and Secrets Manager use (`X-Amz-Target`
header), and Lambda's REST-JSON. One URL serves them all; requests are routed
by the service name in the SigV4 credential scope of the `Authorization`
header. That is why unmodified AWS tooling accepts the responses.

The behaviour — CIDR rules, dependency checks, routing, the instance
lifecycle — lives in shared modules (`netmodel.py`, `ec2model.py`) that the web
console calls too, so a rule enforced from the CLI is enforced identically in
the browser. Both write to the same `simulator.db`, which is why the two views
can never disagree and why CLI-created resources are included in Backup &
Restore snapshots.
