#!/usr/bin/env bash
# End-to-end check with the real AWS CLI v2 against a running simulator.
#   python app.py &      # then:
#   bash tools/cli_smoke.sh [endpoint]
set -euo pipefail

export AWS_ENDPOINT_URL="${1:-http://localhost:8080/aws}"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=eu-central-1 AWS_PAGER=""
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
expect_error() {  # expect_error <code> <command...>
  local code=$1; shift
  if out=$("$@" 2>&1); then echo "expected $code, command succeeded: $*"; exit 1; fi
  grep -q "$code" <<<"$out" || { echo "expected $code, got: $out"; exit 1; }
  pass "rejects with $code"
}

echo "STS / EC2"
[ "$(aws sts get-caller-identity --query Account --output text)" = "000000000000" ] && pass "sts get-caller-identity"
VPC=$(aws ec2 create-vpc --cidr-block 10.30.0.0/16 --query Vpc.VpcId --output text) && pass "create-vpc $VPC"
expect_error InvalidParameterValue aws ec2 create-vpc --cidr-block banana
SUB=$(aws ec2 create-subnet --vpc-id "$VPC" --cidr-block 10.30.1.0/24 --query Subnet.SubnetId --output text) && pass "create-subnet"
expect_error InvalidSubnet.Range aws ec2 create-subnet --vpc-id "$VPC" --cidr-block 10.40.1.0/24
IGW=$(aws ec2 create-internet-gateway --query InternetGateway.InternetGatewayId --output text)
aws ec2 attach-internet-gateway --internet-gateway-id "$IGW" --vpc-id "$VPC" && pass "attach-internet-gateway"
RT=$(aws ec2 create-route-table --vpc-id "$VPC" --query RouteTable.RouteTableId --output text)
aws ec2 create-route --route-table-id "$RT" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW" >/dev/null && pass "create-route"
aws ec2 associate-route-table --route-table-id "$RT" --subnet-id "$SUB" >/dev/null && pass "associate-route-table"
SG=$(aws ec2 create-security-group --group-name web --description web --vpc-id "$VPC" --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 443 --cidr 0.0.0.0/0 >/dev/null && pass "authorize-security-group-ingress"
IID=$(aws ec2 run-instances --image-id ami-0c7217cdde317cfec --instance-type t3.micro --subnet-id "$SUB" \
      --security-group-ids "$SG" --query 'Instances[0].InstanceId' --output text) && pass "run-instances $IID"
aws ec2 wait instance-running --instance-ids "$IID" && pass "wait instance-running"
[ "$(aws ec2 describe-instances --filters Name=instance-state-name,Values=stopped --query 'length(Reservations)')" = "0" ] && pass "describe-instances filters"
expect_error DependencyViolation aws ec2 delete-vpc --vpc-id "$VPC"
aws ec2 terminate-instances --instance-ids "$IID" >/dev/null && pass "terminate-instances"

echo "S3"
echo hello > f.txt && mkdir -p tree/a && echo 1 > tree/a/x.txt && echo 2 > tree/y.txt
aws s3 mb s3://smoke-bucket >/dev/null && pass "s3 mb"
aws s3 cp f.txt s3://smoke-bucket/docs/f.txt >/dev/null && pass "s3 cp"
aws s3 sync tree s3://smoke-bucket/tree >/dev/null && pass "s3 sync"
[ "$(aws s3 ls s3://smoke-bucket/ | grep -c PRE)" = "2" ] && pass "s3 ls shows folders"
[ "$(aws s3 cp s3://smoke-bucket/docs/f.txt -)" = "hello" ] && pass "s3 cp to stdout"
expect_error BucketNotEmpty aws s3 rb s3://smoke-bucket
aws s3 rb s3://smoke-bucket --force >/dev/null && pass "s3 rb --force"

echo "DynamoDB / Secrets Manager / IAM / Lambda"
aws dynamodb create-table --table-name Orders --attribute-definitions AttributeName=id,AttributeType=S \
  --key-schema AttributeName=id,KeyType=HASH --billing-mode PAY_PER_REQUEST >/dev/null && pass "dynamodb create-table"
aws dynamodb put-item --table-name Orders --item '{"id":{"S":"1"},"total":{"N":"9.5"}}' && pass "dynamodb put-item"
[ "$(aws dynamodb get-item --table-name Orders --key '{"id":{"S":"1"}}' --query Item.total.N --output text)" = "9.5" ] && pass "dynamodb get-item"
aws secretsmanager create-secret --name prod/db/pw --secret-string s3cr3t >/dev/null && pass "secretsmanager create-secret"
[ "$(aws secretsmanager get-secret-value --secret-id prod/db/pw --query SecretString --output text)" = "s3cr3t" ] && pass "get-secret-value"
aws iam create-role --role-name fn --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null && pass "iam create-role"
printf 'def lambda_handler(e, c):\n    return {"sum": e["a"] + e["b"]}\n' > lambda_function.py
python3 -c "import zipfile; z = zipfile.ZipFile('fn.zip', 'w'); z.write('lambda_function.py'); z.close()"
aws lambda create-function --function-name adder --runtime python3.12 --role arn:aws:iam::000000000000:role/fn \
  --handler lambda_function.lambda_handler --zip-file fileb://fn.zip >/dev/null && pass "lambda create-function"
aws lambda invoke --function-name adder --cli-binary-format raw-in-base64-out --payload '{"a":2,"b":3}' out.json >/dev/null
[ "$(cat out.json)" = '{"sum": 5}' ] && pass "lambda invoke ran the handler"

echo "All CLI smoke checks passed."
