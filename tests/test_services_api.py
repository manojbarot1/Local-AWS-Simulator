"""STS, IAM, DynamoDB, Secrets Manager and Lambda through real boto3."""

import base64
import io
import json
import zipfile

import pytest
from botocore.exceptions import ClientError

from conftest import error_code

LAMBDA_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def test_sts_identity(aws):
    ident = aws("sts").get_caller_identity()
    assert ident["Account"] == "000000000000"


def test_iam_users_roles_policies(aws):
    iam = aws("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="x")
    assert [u["UserName"] for u in iam.list_users()["Users"]] == ["alice"]
    with pytest.raises(ClientError) as e:
        iam.create_user(UserName="alice")
    assert error_code(e) == "EntityAlreadyExists"
    role = iam.create_role(RoleName="fn-role", AssumeRolePolicyDocument=LAMBDA_TRUST)["Role"]
    assert role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["Service"] == "lambda.amazonaws.com"
    doc = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    arn = iam.create_policy(PolicyName="read", PolicyDocument=doc)["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="fn-role", PolicyArn=arn)
    assert iam.list_attached_role_policies(RoleName="fn-role")["AttachedPolicies"][0]["PolicyArn"] == arn
    with pytest.raises(ClientError) as e:
        iam.delete_role(RoleName="fn-role")
    assert error_code(e) == "DeleteConflict"
    iam.detach_role_policy(RoleName="fn-role", PolicyArn=arn)
    iam.delete_role(RoleName="fn-role")
    with pytest.raises(ClientError) as e:
        iam.get_role(RoleName="fn-role")
    assert error_code(e) == "NoSuchEntity"


def test_dynamodb_items_queries_and_updates(aws):
    ddb = aws("dynamodb")
    ddb.create_table(TableName="Orders", BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "customer", "AttributeType": "S"},
                                           {"AttributeName": "ts", "AttributeType": "N"}],
                     KeySchema=[{"AttributeName": "customer", "KeyType": "HASH"},
                                {"AttributeName": "ts", "KeyType": "RANGE"}])
    assert ddb.list_tables()["TableNames"] == ["Orders"]
    for ts, total in [(3, 30), (1, 10), (2, 20)]:
        ddb.put_item(TableName="Orders", Item={"customer": {"S": "c1"}, "ts": {"N": str(ts)},
                                               "total": {"N": str(total)}, "tags": {"L": [{"S": "new"}]}})
    ddb.put_item(TableName="Orders", Item={"customer": {"S": "c2"}, "ts": {"N": "1"}, "total": {"N": "5"}})
    with pytest.raises(ClientError) as e:
        ddb.put_item(TableName="Orders", Item={"customer": {"S": "c3"}})
    assert error_code(e) == "ValidationException"
    q = ddb.query(TableName="Orders", KeyConditionExpression="customer = :c AND ts BETWEEN :a AND :b",
                  ExpressionAttributeValues={":c": {"S": "c1"}, ":a": {"N": "1"}, ":b": {"N": "2"}})
    assert [i["ts"]["N"] for i in q["Items"]] == ["1", "2"]
    q = ddb.query(TableName="Orders", KeyConditionExpression="#c = :c", ScanIndexForward=False,
                  ExpressionAttributeNames={"#c": "customer"}, ExpressionAttributeValues={":c": {"S": "c1"}})
    assert [i["ts"]["N"] for i in q["Items"]] == ["3", "2", "1"]
    s = ddb.scan(TableName="Orders", FilterExpression="total > :t", ExpressionAttributeValues={":t": {"N": "15"}})
    assert s["Count"] == 2
    upd = ddb.update_item(TableName="Orders", Key={"customer": {"S": "c1"}, "ts": {"N": "1"}},
                          UpdateExpression="SET total = total + :inc, #s = :s REMOVE tags",
                          ExpressionAttributeNames={"#s": "status"},
                          ExpressionAttributeValues={":inc": {"N": "5"}, ":s": {"S": "PAID"}}, ReturnValues="ALL_NEW")
    assert upd["Attributes"]["total"]["N"] == "15" and "tags" not in upd["Attributes"]
    with pytest.raises(ClientError) as e:
        ddb.put_item(TableName="Orders", Item={"customer": {"S": "c2"}, "ts": {"N": "1"}},
                     ConditionExpression="attribute_not_exists(customer)")
    assert error_code(e) == "ConditionalCheckFailedException"
    got = ddb.get_item(TableName="Orders", Key={"customer": {"S": "c1"}, "ts": {"N": "1"}})["Item"]
    assert got["status"]["S"] == "PAID"
    page = ddb.scan(TableName="Orders", Limit=2)
    assert page["Count"] == 2 and "LastEvaluatedKey" in page
    rest = ddb.scan(TableName="Orders", ExclusiveStartKey=page["LastEvaluatedKey"])
    assert page["Count"] + rest["Count"] == 4
    ddb.delete_item(TableName="Orders", Key={"customer": {"S": "c2"}, "ts": {"N": "1"}})
    assert ddb.describe_table(TableName="Orders")["Table"]["ItemCount"] == 3
    with pytest.raises(ClientError) as e:
        ddb.describe_table(TableName="Nope")
    assert error_code(e) == "ResourceNotFoundException"


def test_secrets_manager(aws):
    sm = aws("secretsmanager")
    arn = sm.create_secret(Name="prod/db/password", SecretString="hunter2")["ARN"]
    assert sm.get_secret_value(SecretId="prod/db/password")["SecretString"] == "hunter2"
    sm.put_secret_value(SecretId=arn, SecretString="new")
    assert sm.get_secret_value(SecretId=arn)["SecretString"] == "new"
    sm.rotate_secret(SecretId=arn, RotationRules={"AutomaticallyAfterDays": 30})
    assert sm.describe_secret(SecretId=arn)["RotationEnabled"] is True
    assert [s["Name"] for s in sm.list_secrets()["SecretList"]] == ["prod/db/password"]
    with pytest.raises(ClientError) as e:
        sm.create_secret(Name="prod/db/password", SecretString="x")
    assert error_code(e) == "ResourceExistsException"
    sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
    with pytest.raises(ClientError) as e:
        sm.get_secret_value(SecretId=arn)
    assert error_code(e) == "ResourceNotFoundException"


def _zip(source, name="lambda_function.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, source)
    return buf.getvalue()


CODE = '''
import json
def lambda_handler(event, context):
    print("processing", event["n"])
    if event["n"] < 0:
        raise ValueError("negative")
    return {"double": event["n"] * 2, "fn": context.function_name, "mem": context.memory_limit_in_mb}
'''


def test_lambda_runs_python_for_real(aws):
    iam, lam = aws("iam"), aws("lambda")
    ec2_trust = LAMBDA_TRUST.replace("lambda.amazonaws.com", "ec2.amazonaws.com")
    bad_role = iam.create_role(RoleName="ec2-role", AssumeRolePolicyDocument=ec2_trust)["Role"]["Arn"]
    with pytest.raises(ClientError) as e:
        lam.create_function(FunctionName="doubler", Runtime="python3.12", Role=bad_role,
                            Handler="lambda_function.lambda_handler", Code={"ZipFile": _zip(CODE)})
    assert error_code(e) == "InvalidParameterValueException"
    role = iam.create_role(RoleName="fn-role", AssumeRolePolicyDocument=LAMBDA_TRUST)["Role"]["Arn"]
    cfg = lam.create_function(FunctionName="doubler", Runtime="python3.12", Role=role, MemorySize=256,
                              Handler="lambda_function.lambda_handler", Code={"ZipFile": _zip(CODE)})
    assert cfg["MemorySize"] == 256
    out = lam.invoke(FunctionName="doubler", Payload=json.dumps({"n": 21}), LogType="Tail")
    assert json.loads(out["Payload"].read()) == {"double": 42, "fn": "doubler", "mem": 256}
    assert "processing 21" in base64.b64decode(out["LogResult"]).decode()
    err = lam.invoke(FunctionName="doubler", Payload=json.dumps({"n": -1}))
    assert err["FunctionError"] == "Unhandled"
    assert json.loads(err["Payload"].read())["errorType"] == "ValueError"
    assert [f["FunctionName"] for f in lam.list_functions()["Functions"]] == ["doubler"]
    lam.delete_function(FunctionName="doubler")
    with pytest.raises(ClientError) as e:
        lam.get_function(FunctionName="doubler")
    assert error_code(e) == "ResourceNotFoundException"


def test_lambda_timeout_is_enforced(aws):
    iam, lam = aws("iam"), aws("lambda")
    role = iam.create_role(RoleName="fn-role", AssumeRolePolicyDocument=LAMBDA_TRUST)["Role"]["Arn"]
    slow = "import time\ndef handler(e, c):\n    time.sleep(5)\n"
    lam.create_function(FunctionName="slow", Runtime="python3.12", Role=role, Timeout=1,
                        Handler="index.handler", Code={"ZipFile": _zip(slow, "index.py")})
    out = lam.invoke(FunctionName="slow", Payload=b"{}")
    assert out["FunctionError"] == "Unhandled"
    assert "timed out" in json.loads(out["Payload"].read())["errorMessage"]


def test_activity_log_records_cli_calls(aws, client):
    aws("sts").get_caller_identity()
    aws("ec2").create_vpc(CidrBlock="10.9.0.0/16")
    page = client.get("/activity?reads=1").get_data(as_text=True)
    assert "GetCallerIdentity" in page and "aws ec2 create-vpc --cidr-block 10.9.0.0/16" in page
