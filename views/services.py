"""
Service consoles — S3, IAM, Lambda, DynamoDB and Secrets Manager.

Each console uses the same domain functions as the matching API module in
``aws_api``, so validation and behaviour are identical whether a resource is
created here or with ``aws s3 mb`` / ``aws iam create-role`` / etc.
"""

from __future__ import annotations

import json

from flask import Blueprint, Response, redirect, render_template, request, url_for

import db
import lambda_runtime
from activity import cli
from aws_api import dynamodb, iam, lambda_api, s3, secretsmanager
from errors import SimError
from views import checked, console_tx, done, form_int, with_db

bp = Blueprint("services", __name__)


def service_counts(c):
    """Resource counts for the dashboard tiles."""
    return {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in ("s3_buckets", "iam_users", "iam_roles", "lambda_functions", "dynamodb_tables", "secrets")}


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

@bp.route("/s3")
@with_db
def s3_home(c):
    rows = c.execute("SELECT b.*, (SELECT COUNT(*) FROM s3_objects o WHERE o.bucket_id=b.id) obj_count, "
                     "(SELECT COALESCE(SUM(size_bytes),0) FROM s3_objects o WHERE o.bucket_id=b.id) bytes "
                     "FROM s3_buckets b ORDER BY b.id DESC").fetchall()
    return render_template("s3.html", buckets=[dict(r) for r in rows])


@bp.route("/s3/create", methods=["POST"])
@console_tx(fail="/s3")
def s3_create(c):
    f = request.form
    name = f.get("name", "").strip().lower()
    s3.create_bucket(c, name, None, checked("versioning"), checked("public"), f.get("encryption", "SSE-S3"))
    command = cli("s3 mb", f"s3://{name}")
    if checked("versioning"):
        command += f" && aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled"
    return done(c, "s3", "CreateBucket", name, f"Bucket {name} created successfully.", command, url_for("services.s3_home", new=name))


def _bucket(c, bucket_id):
    b = c.execute("SELECT * FROM s3_buckets WHERE id=?", (bucket_id,)).fetchone()
    if not b:
        raise SimError("NoSuchBucket", "The specified bucket does not exist")
    return b


@bp.route("/s3/<int:bucket_id>")
@with_db
def s3_bucket(c, bucket_id):
    bucket = c.execute("SELECT * FROM s3_buckets WHERE id=?", (bucket_id,)).fetchone()
    if not bucket:
        return render_template("not_found.html", what="Bucket", ident=bucket_id), 404
    prefix = request.args.get("prefix", "")
    rows = c.execute("SELECT id, key, size_bytes, content_type, storage_class, created_at FROM s3_objects "
                     "WHERE bucket_id=? AND substr(key,1,?)=? ORDER BY key", (bucket_id, len(prefix), prefix)).fetchall()
    folders, objects = [], []
    for r in rows:
        rest = r["key"][len(prefix):]
        if "/" in rest:
            folder = prefix + rest.split("/", 1)[0] + "/"
            if folder not in folders:
                folders.append(folder)
        else:
            objects.append(dict(r))
    crumbs = []
    acc = ""
    for part in [p for p in prefix.split("/") if p]:
        acc += part + "/"
        crumbs.append((part, acc))
    return render_template("s3_bucket.html", bucket=dict(bucket), objects=objects, folders=folders, prefix=prefix,
                           crumbs=crumbs, total=c.execute("SELECT COUNT(*) FROM s3_objects WHERE bucket_id=?", (bucket_id,)).fetchone()[0])


@bp.route("/s3/<int:bucket_id>/object/create", methods=["POST"])
@console_tx(fail=lambda bucket_id: f"/s3/{bucket_id}")
def s3_object_create(c, bucket_id):
    f = request.form
    bucket = _bucket(c, bucket_id)
    key = f.get("key", "").strip().lstrip("/")
    if not key:
        raise SimError("InvalidArgument", "Enter an object key.")
    upload = request.files.get("file")
    if upload and upload.filename:
        data = upload.read()
        ctype = upload.mimetype or "binary/octet-stream"
    else:
        data = f.get("body", "").encode("utf-8")
        ctype = f.get("content_type", "text/plain") or "text/plain"
    existed = c.execute("SELECT 1 FROM s3_objects WHERE bucket_id=? AND key=?", (bucket_id, key)).fetchone()
    s3.put_object(c, bucket, key, data, ctype, f.get("storage_class", "STANDARD"))
    verb = "overwritten" if existed else "uploaded"
    return done(c, "s3", "PutObject", f"s3://{bucket['name']}/{key}", f"Object {key} {verb} ({len(data)} bytes).",
                cli("s3 cp", "./" + key.rsplit("/", 1)[-1], f"s3://{bucket['name']}/{key}"),
                url_for("services.s3_bucket", bucket_id=bucket_id, new=key))


@bp.route("/s3/<int:bucket_id>/object/<int:obj_id>/download")
@with_db
def s3_object_download(c, bucket_id, obj_id):
    row = c.execute("SELECT * FROM s3_objects WHERE id=? AND bucket_id=?", (obj_id, bucket_id)).fetchone()
    if not row:
        return "Not found", 404
    return Response(s3.body_bytes(row["body"]), mimetype=row["content_type"] or "application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{row["key"].rsplit("/", 1)[-1]}"'})


@bp.route("/s3/<int:bucket_id>/object/<int:obj_id>/delete", methods=["POST"])
@console_tx(fail=lambda bucket_id, obj_id: f"/s3/{bucket_id}")
def s3_object_delete(c, bucket_id, obj_id):
    bucket = _bucket(c, bucket_id)
    row = c.execute("SELECT key FROM s3_objects WHERE id=? AND bucket_id=?", (obj_id, bucket_id)).fetchone()
    c.execute("DELETE FROM s3_objects WHERE id=? AND bucket_id=?", (obj_id, bucket_id))
    key = row["key"] if row else ""
    return done(c, "s3", "DeleteObject", key, f"Deleted {key}.", cli("s3 rm", f"s3://{bucket['name']}/{key}"),
                request.referrer or url_for("services.s3_bucket", bucket_id=bucket_id))


@bp.route("/s3/<int:bucket_id>/empty", methods=["POST"])
@console_tx(fail="/s3")
def s3_empty(c, bucket_id):
    bucket = _bucket(c, bucket_id)
    n = c.execute("DELETE FROM s3_objects WHERE bucket_id=?", (bucket_id,)).rowcount
    return done(c, "s3", "DeleteObjects", bucket["name"], f"Emptied {bucket['name']} ({n} objects deleted).",
                cli("s3 rm", f"s3://{bucket['name']}", "--recursive"), "/s3")


@bp.route("/s3/<int:bucket_id>/versioning", methods=["POST"])
@console_tx(fail="/s3")
def s3_versioning(c, bucket_id):
    bucket = _bucket(c, bucket_id)
    on = not bucket["versioning"]
    c.execute("UPDATE s3_buckets SET versioning=? WHERE id=?", (int(on), bucket_id))
    return done(c, "s3", "PutBucketVersioning", bucket["name"], f"Versioning {'enabled' if on else 'suspended'} on {bucket['name']}.",
                cli("s3api put-bucket-versioning", ("--bucket", bucket["name"]),
                    ("--versioning-configuration", f"Status={'Enabled' if on else 'Suspended'}")),
                request.referrer or "/s3")


@bp.route("/s3/<int:bucket_id>/delete", methods=["POST"])
@console_tx(fail="/s3")
def s3_delete(c, bucket_id):
    bucket = _bucket(c, bucket_id)
    if c.execute("SELECT 1 FROM s3_objects WHERE bucket_id=? LIMIT 1", (bucket_id,)).fetchone():
        raise SimError("BucketNotEmpty", f"The bucket {bucket['name']} is not empty. Empty it first (like the real console).")
    c.execute("DELETE FROM s3_buckets WHERE id=?", (bucket_id,))
    return done(c, "s3", "DeleteBucket", bucket["name"], f"Bucket {bucket['name']} deleted.", cli("s3 rb", f"s3://{bucket['name']}"), "/s3")


# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------

@bp.route("/iam")
@with_db
def iam_home(c):
    users = [dict(r) for r in c.execute("SELECT * FROM iam_users ORDER BY name")]
    roles = [dict(r) for r in c.execute("SELECT * FROM iam_roles ORDER BY name")]
    policies = [dict(r) for r in c.execute("SELECT * FROM iam_policies ORDER BY name")]
    attachments = {}
    for a in c.execute("SELECT * FROM iam_policy_attachments ORDER BY id"):
        attachments.setdefault((a["principal_type"], a["principal_name"]), []).append(dict(a))
    for u in users:
        u["attached"] = attachments.get(("user", u["name"]), [])
    for r in roles:
        r["attached"] = attachments.get(("role", r["name"]), [])
    return render_template("iam.html", users=users, roles=roles, policies=policies,
                           managed=["arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                                    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                                    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"])


@bp.route("/iam/user/create", methods=["POST"])
@console_tx(fail="/iam")
def iam_user_create(c):
    name = request.form.get("name", "").strip()
    if not name:
        raise SimError("ValidationError", "Enter a user name.")
    iam.create_user(c, name, console_access=checked("console_access"))
    command = cli("iam create-user", ("--user-name", name))
    if checked("console_access"):
        command += f" && aws iam create-login-profile --user-name {name} --password '<initial-password>' --password-reset-required"
    return done(c, "iam", "CreateUser", name, f"IAM user {name} created successfully.", command, url_for("services.iam_home", new=name))


@bp.route("/iam/role/create", methods=["POST"])
@console_tx(fail="/iam")
def iam_role_create(c):
    name = request.form.get("name", "").strip()
    service = request.form.get("trusted_service", "ec2.amazonaws.com")
    if not name:
        raise SimError("ValidationError", "Enter a role name.")
    iam.create_role(c, name, iam.trust_policy_for(service), request.form.get("description", ""))
    return done(c, "iam", "CreateRole", name, f"IAM role {name} created successfully.",
                cli("iam create-role", ("--role-name", name), ("--assume-role-policy-document", "file://trust.json"))
                + f"   # trust.json allows {service}", url_for("services.iam_home", new=name))


@bp.route("/iam/policy/create", methods=["POST"])
@console_tx(fail="/iam")
def iam_policy_create(c):
    name = request.form.get("name", "").strip()
    if not name:
        raise SimError("ValidationError", "Enter a policy name.")
    doc = request.form.get("document", "").strip() or json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}, indent=2)
    iam.create_policy(c, name, doc, request.form.get("description", ""))
    return done(c, "iam", "CreatePolicy", name, f"IAM policy {name} created successfully.",
                cli("iam create-policy", ("--policy-name", name), ("--policy-document", "file://policy.json")),
                url_for("services.iam_home", new=name))


@bp.route("/iam/attach", methods=["POST"])
@console_tx(fail="/iam")
def iam_attach(c):
    kind, _, name = request.form.get("principal", "").partition(":")
    arn = request.form.get("policy_arn", "")
    if kind not in ("user", "role") or not name or not arn:
        raise SimError("ValidationError", "Choose a principal and a policy.")
    iam.attach(c, kind, name, arn)
    return done(c, "iam", f"Attach{kind.title()}Policy", name, f"Attached {arn.rsplit('/', 1)[-1]} to {kind} {name}.",
                cli(f"iam attach-{kind}-policy", (f"--{kind}-name", name), ("--policy-arn", arn)), "/iam")


@bp.route("/iam/attachment/<int:aid>/detach", methods=["POST"])
@console_tx(fail="/iam")
def iam_detach(c, aid):
    a = c.execute("SELECT * FROM iam_policy_attachments WHERE id=?", (aid,)).fetchone()
    if a:
        c.execute("DELETE FROM iam_policy_attachments WHERE id=?", (aid,))
        kind = a["principal_type"]
        return done(c, "iam", f"Detach{kind.title()}Policy", a["principal_name"], "Policy detached.",
                    cli(f"iam detach-{kind}-policy", (f"--{kind}-name", a["principal_name"]), ("--policy-arn", a["policy_arn"])), "/iam")
    return redirect("/iam")


@bp.route("/iam/<kind>/<int:rid>/delete", methods=["POST"])
@console_tx(fail="/iam")
def iam_delete(c, kind, rid):
    table = {"user": "iam_users", "role": "iam_roles", "policy": "iam_policies"}.get(kind)
    if not table:
        raise SimError("ValidationError", f"Unknown IAM type {kind}")
    row = c.execute(f"SELECT * FROM {table} WHERE id=?", (rid,)).fetchone()
    if not row:
        return redirect("/iam")
    if kind == "policy":
        used = c.execute("SELECT 1 FROM iam_policy_attachments WHERE policy_arn=?", (row["arn"],)).fetchone()
    else:
        used = c.execute("SELECT 1 FROM iam_policy_attachments WHERE principal_type=? AND principal_name=?",
                         (kind, row["name"])).fetchone()
    if used:
        raise SimError("DeleteConflict", f"Cannot delete {kind} {row['name']}: detach its policies first.")
    c.execute(f"DELETE FROM {table} WHERE id=?", (rid,))
    flag = {"user": ("--user-name", row["name"]), "role": ("--role-name", row["name"]), "policy": ("--policy-arn", row["arn"])}[kind]
    return done(c, "iam", f"Delete{kind.title()}", row["name"], f"{kind.title()} {row['name']} deleted.",
                cli(f"iam delete-{kind}", flag), "/iam")


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------

@bp.route("/lambda")
@with_db
def lambda_list(c):
    rows = [dict(r) for r in c.execute("SELECT * FROM lambda_functions ORDER BY id DESC")]
    roles = [dict(r) for r in c.execute("SELECT name, arn FROM iam_roles WHERE trusted_service='lambda.amazonaws.com' ORDER BY name")]
    return render_template("lambda.html", functions=rows, runtimes=lambda_runtime.RUNTIMES, roles=roles,
                           exec_enabled=lambda_runtime.ENABLED)


@bp.route("/lambda/create", methods=["POST"])
@console_tx(fail="/lambda")
def lambda_create(c):
    f = request.form
    name = f.get("name", "").strip()
    runtime = f.get("runtime", "python3.12")
    handler = f.get("handler", "").strip() or "lambda_function.lambda_handler"
    code = f.get("code", "")
    if not code.strip() and lambda_runtime.is_python(runtime):
        code = lambda_runtime.default_code(handler)
    memory = form_int("memory_mb", 128, 128, 10240, "Memory")
    timeout = form_int("timeout_s", 3, 1, 900, "Timeout")
    lambda_api.create_function(c, name, runtime, handler, code, memory, timeout, f.get("description", ""),
                               f.get("role") or None)
    fid = c.execute("SELECT id FROM lambda_functions WHERE name=?", (name,)).fetchone()[0]
    return done(c, "lambda", "CreateFunction", name, f"Function {name} created successfully.",
                cli("lambda create-function", ("--function-name", name), ("--runtime", runtime), ("--handler", handler),
                    ("--memory-size", str(memory)), ("--timeout", str(timeout)),
                    ("--role", f.get("role") or "arn:aws:iam::000000000000:role/<lambda-role>"),
                    ("--zip-file", "fileb://function.zip")),
                url_for("services.lambda_detail", fid=fid))


@bp.route("/lambda/<int:fid>")
@with_db
def lambda_detail(c, fid):
    fn = c.execute("SELECT * FROM lambda_functions WHERE id=?", (fid,)).fetchone()
    if not fn:
        return render_template("not_found.html", what="Function", ident=fid), 404
    return render_template("lambda_detail.html", fn=dict(fn), result=None, payload='{\n  "key": "value"\n}',
                           exec_enabled=lambda_runtime.ENABLED, invocations=_invocations(c, fn["name"]))


def _invocations(c, name):
    return [dict(r) for r in c.execute("SELECT * FROM lambda_invocations WHERE function_name=? ORDER BY id DESC LIMIT 10",
                                       (name,))]


@bp.route("/lambda/<int:fid>/invoke", methods=["POST"])
@console_tx(fail=lambda fid: f"/lambda/{fid}")
def lambda_invoke(c, fid):
    fn = c.execute("SELECT * FROM lambda_functions WHERE id=?", (fid,)).fetchone()
    if not fn:
        raise SimError("ResourceNotFoundException", "Function not found")
    payload = request.form.get("payload", "{}")
    try:
        event = json.loads(payload or "{}")
    except ValueError as exc:
        raise SimError("InvalidRequestContentException", f"The test event is not valid JSON: {exc}")
    try:
        result = lambda_runtime.invoke(fn, event)
    except ValueError as exc:
        raise SimError("InvalidParameterValueException", str(exc))
    lambda_runtime.record(c, fn["name"], "console", event, result)
    from activity import record
    record(c, "console", "lambda", "Invoke", fn["name"], result["status"],
           cli("lambda invoke", ("--function-name", fn["name"]), ("--payload", json.dumps(event, separators=(",", ":"))),
               ("--cli-binary-format", "raw-in-base64-out"), "response.json"))
    return render_template("lambda_detail.html", fn=dict(fn), result=result, payload=payload,
                           exec_enabled=lambda_runtime.ENABLED, invocations=_invocations(c, fn["name"]))


@bp.route("/lambda/<int:fid>/code", methods=["POST"])
@console_tx(fail=lambda fid: f"/lambda/{fid}")
def lambda_update_code(c, fid):
    fn = c.execute("SELECT * FROM lambda_functions WHERE id=?", (fid,)).fetchone()
    if not fn:
        raise SimError("ResourceNotFoundException", "Function not found")
    handler = request.form.get("handler", fn["handler"]).strip() or fn["handler"]
    c.execute("UPDATE lambda_functions SET code=?, handler=? WHERE id=?", (request.form.get("code", ""), handler, fid))
    return done(c, "lambda", "UpdateFunctionCode", fn["name"], "Code deployed.",
                cli("lambda update-function-code", ("--function-name", fn["name"]), ("--zip-file", "fileb://function.zip")),
                f"/lambda/{fid}")


@bp.route("/lambda/<int:fid>/delete", methods=["POST"])
@console_tx(fail="/lambda")
def lambda_delete(c, fid):
    fn = c.execute("SELECT name FROM lambda_functions WHERE id=?", (fid,)).fetchone()
    c.execute("DELETE FROM lambda_functions WHERE id=?", (fid,))
    name = fn["name"] if fn else ""
    c.execute("DELETE FROM lambda_invocations WHERE function_name=?", (name,))
    return done(c, "lambda", "DeleteFunction", name, f"Function {name} deleted.",
                cli("lambda delete-function", ("--function-name", name)), "/lambda")


# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------

@bp.route("/dynamodb")
@with_db
def dynamodb_home(c):
    rows = c.execute("SELECT t.*, (SELECT COUNT(*) FROM dynamodb_items i WHERE i.table_id=t.id) item_count "
                     "FROM dynamodb_tables t ORDER BY t.id DESC").fetchall()
    return render_template("dynamodb.html", tables=[dict(r) for r in rows])


@bp.route("/dynamodb/create", methods=["POST"])
@console_tx(fail="/dynamodb")
def dynamodb_create(c):
    f = request.form
    name, pk, sk = f.get("name", "").strip(), f.get("partition_key", "").strip(), f.get("sort_key", "").strip()
    if not pk:
        raise SimError("ValidationException", "Enter a partition key.")
    pkt, skt = f.get("partition_key_type", "S"), f.get("sort_key_type", "S")
    dynamodb.create_table(c, name, pk, pkt, sk or None, skt if sk else None, f.get("billing_mode", "PAY_PER_REQUEST"))
    defs = f"AttributeName={pk},AttributeType={pkt}" + (f" AttributeName={sk},AttributeType={skt}" if sk else "")
    keys = f"AttributeName={pk},KeyType=HASH" + (f" AttributeName={sk},KeyType=RANGE" if sk else "")
    command = (f"aws dynamodb create-table --table-name {name} --attribute-definitions {defs} "
               f"--key-schema {keys} --billing-mode {f.get('billing_mode', 'PAY_PER_REQUEST')}")
    if f.get("billing_mode") == "PROVISIONED":
        command += " --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5"
    return done(c, "dynamodb", "CreateTable", name, f"Table {name} created successfully.", command,
                url_for("services.dynamodb_home", new=name))


@bp.route("/dynamodb/<int:tid>")
@with_db
def dynamodb_table(c, tid):
    tbl = c.execute("SELECT * FROM dynamodb_tables WHERE id=?", (tid,)).fetchone()
    if not tbl:
        return render_template("not_found.html", what="Table", ident=tid), 404
    items = [{"id": r["id"], "item": json.loads(r["item_json"])}
             for r in c.execute("SELECT * FROM dynamodb_items WHERE table_id=? ORDER BY id DESC", (tid,))]
    pk_filter = request.args.get("pk", "").strip()
    if pk_filter:
        items = [i for i in items if str(i["item"].get(tbl["partition_key"])) == pk_filter]
        if tbl["sort_key"]:
            items.sort(key=lambda i: str(i["item"].get(tbl["sort_key"], "")))
    return render_template("dynamodb_table.html", table=dict(tbl), items=items, pk_filter=pk_filter)


@bp.route("/dynamodb/<int:tid>/item/create", methods=["POST"])
@console_tx(fail=lambda tid: f"/dynamodb/{tid}")
def dynamodb_item_create(c, tid):
    tbl = c.execute("SELECT * FROM dynamodb_tables WHERE id=?", (tid,)).fetchone()
    if not tbl:
        raise SimError("ResourceNotFoundException", "Table not found")
    raw = request.form.get("item_json", "").strip()
    try:
        item = json.loads(raw)
    except ValueError as exc:
        raise SimError("ValidationException", f"The item is not valid JSON: {exc}")
    if not isinstance(item, dict):
        raise SimError("ValidationException", "An item must be a JSON object.")
    old = dynamodb.put_item(c, tbl, item)
    return done(c, "dynamodb", "PutItem", tbl["name"], "Item replaced (same key)." if old else "Item created.",
                cli("dynamodb put-item", ("--table-name", tbl["name"]),
                    ("--item", json.dumps(dynamodb.item_to_av(item), separators=(",", ":")))),
                f"/dynamodb/{tid}")


@bp.route("/dynamodb/<int:tid>/item/<int:item_id>/delete", methods=["POST"])
@console_tx(fail=lambda tid, item_id: f"/dynamodb/{tid}")
def dynamodb_item_delete(c, tid, item_id):
    c.execute("DELETE FROM dynamodb_items WHERE id=? AND table_id=?", (item_id, tid))
    return redirect(url_for("services.dynamodb_table", tid=tid))


@bp.route("/dynamodb/<int:tid>/delete", methods=["POST"])
@console_tx(fail="/dynamodb")
def dynamodb_delete(c, tid):
    tbl = c.execute("SELECT name FROM dynamodb_tables WHERE id=?", (tid,)).fetchone()
    c.execute("DELETE FROM dynamodb_items WHERE table_id=?", (tid,))
    c.execute("DELETE FROM dynamodb_tables WHERE id=?", (tid,))
    name = tbl["name"] if tbl else ""
    return done(c, "dynamodb", "DeleteTable", name, f"Table {name} deleted.",
                cli("dynamodb delete-table", ("--table-name", name)), "/dynamodb")


# ---------------------------------------------------------------------------
# Secrets Manager
# ---------------------------------------------------------------------------

@bp.route("/secrets")
@console_tx(fail="/secrets")
def secrets_list(c):
    rows = [dict(r) for r in c.execute("SELECT * FROM secrets ORDER BY id DESC")]
    reveal = request.args.get("reveal", type=int)
    if reveal:
        row = next((r for r in rows if r["id"] == reveal), None)
        if row:
            from activity import record
            record(c, "console", "secretsmanager", "GetSecretValue", row["name"], "revealed in console",
                   cli("secretsmanager get-secret-value", ("--secret-id", row["name"])), readonly=True)
    return render_template("secrets.html", secrets=rows, reveal=reveal)


@bp.route("/secrets/create", methods=["POST"])
@console_tx(fail="/secrets")
def secrets_create(c):
    f = request.form
    name = f.get("name", "").strip()
    secretsmanager.create(c, name, f.get("secret_value", ""), f.get("description", ""), checked("rotation_enabled"))
    command = cli("secretsmanager create-secret", ("--name", name), ("--secret-string", "'<value>'"))
    if checked("rotation_enabled"):
        command += f" && aws secretsmanager rotate-secret --secret-id {name} --rotation-rules AutomaticallyAfterDays=30"
    return done(c, "secretsmanager", "CreateSecret", name, f"Secret {name} stored successfully.", command,
                url_for("services.secrets_list", new=name))


@bp.route("/secrets/<int:sid>/update", methods=["POST"])
@console_tx(fail="/secrets")
def secrets_update(c, sid):
    row = c.execute("SELECT name FROM secrets WHERE id=?", (sid,)).fetchone()
    c.execute("UPDATE secrets SET secret_value=? WHERE id=?", (request.form.get("secret_value", ""), sid))
    return done(c, "secretsmanager", "PutSecretValue", row["name"] if row else "", "Secret value updated.",
                cli("secretsmanager put-secret-value", ("--secret-id", row["name"] if row else ""), ("--secret-string", "'<value>'")),
                "/secrets")


@bp.route("/secrets/<int:sid>/rotation", methods=["POST"])
@console_tx(fail="/secrets")
def secrets_rotation(c, sid):
    row = c.execute("SELECT * FROM secrets WHERE id=?", (sid,)).fetchone()
    if not row:
        return redirect("/secrets")
    on = not row["rotation_enabled"]
    c.execute("UPDATE secrets SET rotation_enabled=? WHERE id=?", (int(on), sid))
    command = cli("secretsmanager rotate-secret", ("--secret-id", row["name"]), ("--rotation-rules", "AutomaticallyAfterDays=30")) \
        if on else cli("secretsmanager cancel-rotate-secret", ("--secret-id", row["name"]))
    return done(c, "secretsmanager", "RotateSecret" if on else "CancelRotateSecret", row["name"],
                f"Rotation {'enabled' if on else 'disabled'} for {row['name']}.", command, "/secrets")


@bp.route("/secrets/<int:sid>/delete", methods=["POST"])
@console_tx(fail="/secrets")
def secrets_delete(c, sid):
    row = c.execute("SELECT name FROM secrets WHERE id=?", (sid,)).fetchone()
    c.execute("DELETE FROM secrets WHERE id=?", (sid,))
    name = row["name"] if row else ""
    return done(c, "secretsmanager", "DeleteSecret", name, f"Secret {name} deleted.",
                cli("secretsmanager delete-secret", ("--secret-id", name), "--force-delete-without-recovery"), "/secrets")
