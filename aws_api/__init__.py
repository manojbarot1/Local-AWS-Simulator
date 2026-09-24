"""
aws_api
=======

The AWS-compatible endpoint at ``/aws`` that the real ``aws`` CLI and boto3
talk to. One URL serves every supported service, as with any local emulator;
requests are routed by the service in the SigV4 credential scope
(``Credential=test/20260101/eu-central-1/<service>/aws4_request``), with
header/body fallbacks for unsigned requests:

=================  ================  =====================================
service            protocol          module
=================  ================  =====================================
ec2                query (EC2)       ``ec2``
iam, sts           query             ``iam``
s3                 rest-xml          ``s3``
dynamodb           json 1.0          ``dynamodb``
secretsmanager     json 1.1          ``secretsmanager``
lambda             rest-json         ``lambda_api``
=================  ================  =====================================

Signatures are not verified. Every call is recorded in the activity log with
the (approximate) CLI command that produced it. The endpoint shares SQLite
state with the web console.
"""

from __future__ import annotations

import json
import re

import activity
import db
import ec2model
from errors import SimError

from . import dynamodb, ec2, iam, lambda_api, s3, secretsmanager
from .common import (JSON_10, JSON_11, ec2_error, json_error, json_response, query_error)

_SCOPE = re.compile(r"Credential=[^/,]+/\d{8}/[^/]+/([^/]+)/aws4_request")
READ_PREFIXES = ("Describe", "Get", "List", "Head", "Scan", "Query", "BatchGet")


def is_aws_api_request(request):
    return request.path == "/aws" or request.path.startswith("/aws/")


def signing_service(request):
    m = _SCOPE.search(request.headers.get("Authorization", "")) or \
        _SCOPE.search("Credential=" + request.args.get("X-Amz-Credential", ""))
    return m.group(1) if m else None


def detect_service(request):
    svc = signing_service(request)
    if svc:
        return svc
    target = request.headers.get("X-Amz-Target", "")
    if target.startswith("DynamoDB_"):
        return "dynamodb"
    if target.startswith("secretsmanager."):
        return "secretsmanager"
    if request.path.startswith(lambda_api.PREFIX):
        return "lambda"
    if request.method == "POST" and (request.form.get("Action") or request.args.get("Action")):
        version = request.form.get("Version") or request.args.get("Version")
        return {"2010-05-08": "iam", "2011-06-15": "sts"}.get(version, "ec2")
    return "s3"


def _query_params(request):
    params = request.args.to_dict(flat=True)
    params.update(request.form.to_dict(flat=True))
    return params


def _resource_hint(params):
    for key in ("VpcId", "SubnetId", "InstanceId.1", "InstanceId", "GroupId", "RouteTableId", "InternetGatewayId",
                "NatGatewayId", "AllocationId", "NetworkAclId", "UserName", "RoleName", "PolicyArn", "PolicyName",
                "TableName", "SecretId", "Name", "FunctionName", "GroupName", "CidrBlock"):
        if params.get(key):
            return str(params[key])
    return ""


def handle(request, db_path=None):
    """Entry point wired into Flask. Returns (body, status, headers)."""
    service = detect_service(request)
    c = db.connect(db_path)
    action, resource, cli_cmd = "", "", ""
    try:
        ec2model.advance(c)
        if service in ("ec2", "iam", "sts"):
            params = _query_params(request)
            action = params.get("Action", "")
            resource = _resource_hint(params)
            cli_cmd = activity.from_query(service, params)
            try:
                if service == "ec2":
                    resp = ec2.handle(c, params)
                elif service == "iam":
                    resp = iam.handle_iam(c, params)
                else:
                    resp = iam.handle_sts(c, params)
            except SimError as err:
                c.rollback()
                resp = ec2_error(err) if service == "ec2" else query_error(
                    iam.IAM_NS if service == "iam" else iam.STS_NS, err)
        elif service in ("dynamodb", "secretsmanager"):
            action = request.headers.get("X-Amz-Target", "").split(".")[-1]
            headers = JSON_10 if service == "dynamodb" else JSON_11
            try:
                body = json.loads(request.get_data(as_text=True) or "{}")
            except ValueError:
                body = {}
            resource = _resource_hint(body)
            cli_cmd = activity.from_json(service, action, {k: v for k, v in body.items() if k != "SecretString"})
            try:
                mod = dynamodb if service == "dynamodb" else secretsmanager
                resp = json_response(mod.handle(c, action, body), headers)
            except SimError as err:
                c.rollback()
                resp = json_error(err, headers)
        elif service == "lambda":
            action, resource, resp = lambda_api.handle(c, request)
            if resp[1] >= 400:
                c.rollback()
            cli_cmd = activity.cli(f"lambda {activity.kebab(action)}", ("--function-name", resource or None))
        else:
            service = "s3"
            action, resp = s3.handle(c, request)
            if resp[1] >= 400:
                c.rollback()
            bucket, key = s3._parts(request)
            resource = f"s3://{bucket}/{key}" if key else (f"s3://{bucket}" if bucket else "")
            cli_cmd = activity.cli(f"s3api {activity.kebab(action)}", ("--bucket", bucket or None), ("--key", key or None))
        status = resp[1]
        activity.record(c, "cli", service, action or request.method, resource, "", cli_cmd,
                        readonly=action.startswith(READ_PREFIXES) or request.method in ("GET", "HEAD"),
                        status="ok" if status < 400 else "error")
        c.commit()
        return resp
    except Exception as exc:  # keep the endpoint resilient for a teaching tool
        c.rollback()
        err = SimError("InternalError", f"{type(exc).__name__}: {exc}", 500)
        if service in ("dynamodb", "secretsmanager"):
            return json_error(err)
        if service == "lambda":
            return lambda_api.error(err)
        if service == "s3":
            return s3.error(err)
        return ec2_error(err)
    finally:
        c.close()
