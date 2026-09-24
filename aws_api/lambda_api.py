"""
Lambda over its REST-JSON protocol (``/aws/2015-03-31/functions/...``).

``create-function`` accepts the usual zip package; the handler's source file is
extracted from it and stored, so ``invoke`` really runs Python functions (see
``lambda_runtime``). Like real Lambda, the execution role must exist and trust
``lambda.amazonaws.com``.
"""

from __future__ import annotations

import base64
import io
import json
import re
import zipfile

import db
import lambda_runtime
from aws_fidelity import DEFAULT_ACCOUNT_ID
from errors import SimError

from .common import iso

PREFIX = "/aws/2015-03-31/functions"
JSON = {"Content-Type": "application/json"}


def _err(code, msg, status):
    return SimError(code, msg, status)


def error(err):
    return json.dumps({"Type": "User", "message": err.message}), err.status, {**JSON, "x-amzn-ErrorType": err.code}


def _name(ref):
    # Accept a bare name, a full ARN or a partial ARN.
    ref = ref or ""
    if ref.startswith("arn:"):
        ref = ref.split(":function:", 1)[-1].split(":")[0]
    return ref


def get(c, ref):
    row = c.execute("SELECT * FROM lambda_functions WHERE name=?", (_name(ref),)).fetchone()
    if not row:
        raise _err("ResourceNotFoundException",
                   f"Function not found: arn:aws:lambda:{db.region(c)}:{DEFAULT_ACCOUNT_ID}:function:{_name(ref)}", 404)
    return row


def config(row):
    return {"FunctionName": row["name"], "FunctionArn": row["arn"], "Runtime": row["runtime"],
            "Role": row["role"] or "", "Handler": row["handler"], "CodeSize": len((row["code"] or "").encode()),
            "Description": row["description"] or "", "Timeout": row["timeout_s"], "MemorySize": row["memory_mb"],
            "LastModified": iso(row["created_at"]).replace("Z", "+0000"), "Version": "$LATEST",
            "State": "Active", "LastUpdateStatus": "Successful", "PackageType": "Zip",
            "Architectures": ["x86_64"], "EphemeralStorage": {"Size": 512},
            "TracingConfig": {"Mode": "PassThrough"}}


def _code_from_zip(b64, handler):
    try:
        data = base64.b64decode(b64)
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (ValueError, zipfile.BadZipFile):
        raise _err("InvalidParameterValueException", "Could not unzip uploaded file. Please check your file, then try to upload again.", 400)
    module = (handler or "").rpartition(".")[0].replace(".", "/") or "lambda_function"
    names = zf.namelist()
    wanted = f"{module}.py"
    if wanted not in names:
        py = [n for n in names if n.endswith(".py")]
        if len(py) != 1:
            raise _err("InvalidParameterValueException",
                       f"The handler file {wanted} was not found in the deployment package ({', '.join(names) or 'empty'}).", 400)
        wanted = py[0]
    return zf.read(wanted).decode("utf-8", errors="replace")


def _validate(c, runtime, role, memory, timeout):
    if runtime not in lambda_runtime.RUNTIMES:
        raise _err("InvalidParameterValueException",
                   f"Value {runtime} at 'runtime' failed to satisfy constraint: Member must satisfy enum value set: "
                   f"[{', '.join(lambda_runtime.RUNTIMES)}]", 400)
    if not 128 <= memory <= 10240:
        raise _err("InvalidParameterValueException", "MemorySize must be between 128 and 10240 MB.", 400)
    if not 1 <= timeout <= 900:
        raise _err("InvalidParameterValueException", "Timeout must be between 1 and 900 seconds.", 400)
    if role is not None:
        name = role.rsplit("/", 1)[-1]
        r = c.execute("SELECT * FROM iam_roles WHERE arn=? OR name=?", (role, name)).fetchone()
        if not r or r["trusted_service"] != "lambda.amazonaws.com":
            raise _err("InvalidParameterValueException",
                       "The role defined for the function cannot be assumed by Lambda. "
                       "Create a role whose trust policy allows lambda.amazonaws.com.", 400)


def create_function(c, name, runtime, handler, code, memory=128, timeout=3, description="", role=None):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name or ""):
        raise _err("InvalidParameterValueException", "Function name must be 1-64 letters, numbers, hyphens or underscores.", 400)
    _validate(c, runtime, role, memory, timeout)
    if c.execute("SELECT 1 FROM lambda_functions WHERE name=?", (name,)).fetchone():
        raise _err("ResourceConflictException", f"Function already exist: {name}", 409)
    arn = f"arn:aws:lambda:{db.region(c)}:{DEFAULT_ACCOUNT_ID}:function:{name}"
    c.execute("INSERT INTO lambda_functions(name,arn,runtime,handler,memory_mb,timeout_s,description,code,created_at,role) "
              "VALUES(?,?,?,?,?,?,?,?,?,?)", (name, arn, runtime, handler, memory, timeout, description, code, db.now(), role))
    return get(c, name)


def handle(c, request):
    """Returns (action, resource, (body, status, headers))."""
    rest = request.path[len(PREFIX):].strip("/")
    parts = rest.split("/") if rest else []
    m = request.method
    action, fname = "Lambda", parts[0] if parts else ""
    try:
        body = request.get_json(silent=True) or {}
        if not parts:
            if m == "POST":
                action = "CreateFunction"
                fname = body.get("FunctionName", "")
                handler = body.get("Handler", "lambda_function.lambda_handler")
                code_spec = body.get("Code") or {}
                if "ZipFile" not in code_spec:
                    raise _err("InvalidParameterValueException", "Provide the code as a zip file (--zip-file fileb://function.zip).", 400)
                code = _code_from_zip(code_spec["ZipFile"], handler)
                row = create_function(c, fname, body.get("Runtime", ""), handler, code, int(body.get("MemorySize") or 128),
                                      int(body.get("Timeout") or 3), body.get("Description", ""), body.get("Role", ""))
                return action, fname, (json.dumps(config(row)), 201, JSON)
            if m == "GET":
                rows = c.execute("SELECT * FROM lambda_functions ORDER BY name").fetchall()
                return "ListFunctions", "", (json.dumps({"Functions": [config(r) for r in rows]}), 200, JSON)
        sub = parts[1] if len(parts) > 1 else ""
        row = get(c, fname)
        if sub == "" and m == "GET":
            return "GetFunction", fname, (json.dumps({"Configuration": config(row),
                                                     "Code": {"RepositoryType": "S3", "Location": ""}}), 200, JSON)
        if sub == "" and m == "DELETE":
            c.execute("DELETE FROM lambda_functions WHERE id=?", (row["id"],))
            c.execute("DELETE FROM lambda_invocations WHERE function_name=?", (row["name"],))
            return "DeleteFunction", fname, ("", 204, {})
        if sub == "configuration" and m == "GET":
            return "GetFunctionConfiguration", fname, (json.dumps(config(row)), 200, JSON)
        if sub == "configuration" and m == "PUT":
            action = "UpdateFunctionConfiguration"
            memory = int(body.get("MemorySize") or row["memory_mb"])
            timeout = int(body.get("Timeout") or row["timeout_s"])
            runtime = body.get("Runtime") or row["runtime"]
            _validate(c, runtime, body.get("Role"), memory, timeout)
            c.execute("UPDATE lambda_functions SET memory_mb=?, timeout_s=?, runtime=?, handler=?, description=?, role=? WHERE id=?",
                      (memory, timeout, runtime, body.get("Handler") or row["handler"],
                       body.get("Description", row["description"]), body.get("Role") or row["role"], row["id"]))
            return action, fname, (json.dumps(config(get(c, fname))), 200, JSON)
        if sub == "code" and m == "PUT":
            action = "UpdateFunctionCode"
            if "ZipFile" not in body:
                raise _err("InvalidParameterValueException", "Provide --zip-file.", 400)
            c.execute("UPDATE lambda_functions SET code=? WHERE id=?", (_code_from_zip(body["ZipFile"], row["handler"]), row["id"]))
            return action, fname, (json.dumps(config(get(c, fname))), 200, JSON)
        if sub == "invocations" and m == "POST":
            action = "Invoke"
            raw = request.get_data(as_text=True) or "{}"
            try:
                event = json.loads(raw)
            except ValueError:
                raise _err("InvalidRequestContentException", "Could not parse request body into json.", 400)
            kind = request.headers.get("X-Amz-Invocation-Type", "RequestResponse")
            if kind == "DryRun":
                return action, fname, ("", 204, {})
            result = lambda_runtime.invoke(row, event)
            lambda_runtime.record(c, row["name"], "cli", event, result)
            if kind == "Event":
                return action, fname, ("", 202, {})
            headers = {**JSON, "X-Amz-Executed-Version": "$LATEST"}
            if result["status"] != "Success":
                headers["X-Amz-Function-Error"] = "Unhandled"
            if request.headers.get("X-Amz-Log-Type") == "Tail":
                tail = "\n".join(result["logs"]).encode()[-4096:]
                headers["X-Amz-Log-Result"] = base64.b64encode(tail).decode()
            return action, fname, (json.dumps(result["payload"]), 200, headers)
        raise _err("UnsupportedOperation", f"{m} {request.path} is not supported by the simulator.", 400)
    except SimError as err:
        return action, fname, error(err)
