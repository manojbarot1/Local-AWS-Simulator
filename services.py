"""
services.py
===========

Additional AWS service consoles — S3, IAM, Lambda, DynamoDB and Secrets Manager —
added on top of the existing simulator without touching its original pages.

Everything lives in one Flask blueprint and one set of SQLite tables in the same
``simulator.db`` the rest of the app uses, so these services show up in Backup &
Restore snapshots and the reset flow just like the built-in ones. IDs, ARNs and
naming follow the AWS conventions in ``aws_fidelity``.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, session, flash

from aws_fidelity import aws_id, DEFAULT_ACCOUNT_ID

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "simulator.db")

services_bp = Blueprint("services", __name__)


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------

def _db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def _region(c):
    row = c.execute("SELECT value FROM settings WHERE key='region'").fetchone()
    return (row[0] if row and row[0] else "eu-central-1")


def _now():
    return datetime.now().isoformat(timespec="seconds")


def ensure_service_tables():
    c = _db()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS s3_buckets (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
          region TEXT, versioning INTEGER DEFAULT 0, public INTEGER DEFAULT 0,
          encryption TEXT DEFAULT 'SSE-S3', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS s3_objects (
          id INTEGER PRIMARY KEY AUTOINCREMENT, bucket_id INTEGER NOT NULL,
          key TEXT NOT NULL, size_bytes INTEGER DEFAULT 0, content_type TEXT,
          storage_class TEXT DEFAULT 'STANDARD', body TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS iam_users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
          arn TEXT NOT NULL, path TEXT DEFAULT '/', console_access INTEGER DEFAULT 0,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS iam_roles (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
          arn TEXT NOT NULL, trusted_service TEXT, description TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS iam_policies (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
          arn TEXT NOT NULL, document TEXT, description TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS lambda_functions (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
          arn TEXT NOT NULL, runtime TEXT, handler TEXT, memory_mb INTEGER DEFAULT 128,
          timeout_s INTEGER DEFAULT 3, description TEXT, code TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS dynamodb_tables (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
          arn TEXT NOT NULL, partition_key TEXT NOT NULL, partition_key_type TEXT DEFAULT 'S',
          sort_key TEXT, sort_key_type TEXT, billing_mode TEXT DEFAULT 'PAY_PER_REQUEST',
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS dynamodb_items (
          id INTEGER PRIMARY KEY AUTOINCREMENT, table_id INTEGER NOT NULL,
          item_json TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS secrets (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
          arn TEXT NOT NULL, description TEXT, secret_value TEXT,
          rotation_enabled INTEGER DEFAULT 0, created_at TEXT NOT NULL
        );
        """
    )
    c.commit()
    c.close()


def service_counts():
    """Resource counts for the dashboard tiles."""
    c = _db()
    names = {
        "s3_buckets": "s3_buckets", "iam_users": "iam_users", "iam_roles": "iam_roles",
        "lambda_functions": "lambda_functions", "dynamodb_tables": "dynamodb_tables",
        "secrets": "secrets",
    }
    out = {}
    for k, table in names.items():
        try:
            out[k] = c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.OperationalError:
            out[k] = 0
    c.close()
    return out


def _guard():
    return session.get("user") == "demo"


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

@services_bp.route("/s3")
def s3():
    if not _guard():
        return redirect(url_for("login"))
    c = _db()
    rows = c.execute(
        "SELECT b.*, (SELECT COUNT(*) FROM s3_objects o WHERE o.bucket_id=b.id) obj_count "
        "FROM s3_buckets b ORDER BY b.id DESC"
    ).fetchall()
    c.close()
    return render_template("s3.html", buckets=[dict(r) for r in rows])


@services_bp.route("/s3/create", methods=["POST"])
def s3_create():
    f = request.form
    name = f.get("name", "").strip().lower()
    if name:
        c = _db()
        exists = c.execute("SELECT 1 FROM s3_buckets WHERE name=?", (name,)).fetchone()
        if not exists:
            c.execute(
                "INSERT INTO s3_buckets(name,region,versioning,public,encryption,created_at) VALUES(?,?,?,?,?,?)",
                (name, _region(c), 1 if f.get("versioning") else 0, 1 if f.get("public") else 0,
                 f.get("encryption", "SSE-S3"), _now()),
            )
            c.commit()
            flash(f"Bucket {name} created successfully.", "success")
            c.close()
            return redirect(url_for("services.s3", new=name))
        c.close()
    return redirect(url_for("services.s3"))


@services_bp.route("/s3/<int:bucket_id>")
def s3_bucket(bucket_id):
    if not _guard():
        return redirect(url_for("login"))
    c = _db()
    bucket = c.execute("SELECT * FROM s3_buckets WHERE id=?", (bucket_id,)).fetchone()
    if not bucket:
        c.close()
        return "Bucket not found", 404
    objects = c.execute("SELECT * FROM s3_objects WHERE bucket_id=? ORDER BY key", (bucket_id,)).fetchall()
    c.close()
    return render_template("s3_bucket.html", bucket=dict(bucket), objects=[dict(r) for r in objects])


@services_bp.route("/s3/<int:bucket_id>/object/create", methods=["POST"])
def s3_object_create(bucket_id):
    f = request.form
    key = f.get("key", "").strip()
    if key:
        body = f.get("body", "")
        c = _db()
        c.execute(
            "INSERT INTO s3_objects(bucket_id,key,size_bytes,content_type,storage_class,body,created_at) VALUES(?,?,?,?,?,?,?)",
            (bucket_id, key, len(body.encode("utf-8")), f.get("content_type", "text/plain"),
             f.get("storage_class", "STANDARD"), body, _now()),
        )
        c.commit()
        c.close()
        flash(f"Object {key} uploaded successfully.", "success")
        return redirect(url_for("services.s3_bucket", bucket_id=bucket_id, new=key))
    return redirect(url_for("services.s3_bucket", bucket_id=bucket_id))


@services_bp.route("/s3/<int:bucket_id>/object/<int:obj_id>/delete", methods=["POST"])
def s3_object_delete(bucket_id, obj_id):
    c = _db()
    c.execute("DELETE FROM s3_objects WHERE id=? AND bucket_id=?", (obj_id, bucket_id))
    c.commit()
    c.close()
    return redirect(url_for("services.s3_bucket", bucket_id=bucket_id))


@services_bp.route("/s3/<int:bucket_id>/delete", methods=["POST"])
def s3_delete(bucket_id):
    c = _db()
    c.execute("DELETE FROM s3_objects WHERE bucket_id=?", (bucket_id,))
    c.execute("DELETE FROM s3_buckets WHERE id=?", (bucket_id,))
    c.commit()
    c.close()
    return redirect(url_for("services.s3"))


# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------

@services_bp.route("/iam")
def iam():
    if not _guard():
        return redirect(url_for("login"))
    c = _db()
    users = [dict(r) for r in c.execute("SELECT * FROM iam_users ORDER BY name").fetchall()]
    roles = [dict(r) for r in c.execute("SELECT * FROM iam_roles ORDER BY name").fetchall()]
    policies = [dict(r) for r in c.execute("SELECT * FROM iam_policies ORDER BY name").fetchall()]
    c.close()
    return render_template("iam.html", users=users, roles=roles, policies=policies)


@services_bp.route("/iam/user/create", methods=["POST"])
def iam_user_create():
    name = request.form.get("name", "").strip()
    if name:
        c = _db()
        if not c.execute("SELECT 1 FROM iam_users WHERE name=?", (name,)).fetchone():
            arn = f"arn:aws:iam::{DEFAULT_ACCOUNT_ID}:user/{name}"
            c.execute(
                "INSERT INTO iam_users(name,arn,path,console_access,created_at) VALUES(?,?,?,?,?)",
                (name, arn, "/", 1 if request.form.get("console_access") else 0, _now()),
            )
            c.commit()
            flash(f"IAM user {name} created successfully.", "success")
            c.close()
            return redirect(url_for("services.iam", new=name))
        c.close()
    return redirect(url_for("services.iam"))


@services_bp.route("/iam/role/create", methods=["POST"])
def iam_role_create():
    name = request.form.get("name", "").strip()
    if name:
        c = _db()
        if not c.execute("SELECT 1 FROM iam_roles WHERE name=?", (name,)).fetchone():
            arn = f"arn:aws:iam::{DEFAULT_ACCOUNT_ID}:role/{name}"
            c.execute(
                "INSERT INTO iam_roles(name,arn,trusted_service,description,created_at) VALUES(?,?,?,?,?)",
                (name, arn, request.form.get("trusted_service", "ec2.amazonaws.com"),
                 request.form.get("description", ""), _now()),
            )
            c.commit()
            flash(f"IAM role {name} created successfully.", "success")
            c.close()
            return redirect(url_for("services.iam", new=name))
        c.close()
    return redirect(url_for("services.iam"))


@services_bp.route("/iam/policy/create", methods=["POST"])
def iam_policy_create():
    name = request.form.get("name", "").strip()
    if name:
        c = _db()
        if not c.execute("SELECT 1 FROM iam_policies WHERE name=?", (name,)).fetchone():
            arn = f"arn:aws:iam::{DEFAULT_ACCOUNT_ID}:policy/{name}"
            doc = request.form.get("document", "").strip() or json.dumps(
                {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
                indent=2,
            )
            c.execute(
                "INSERT INTO iam_policies(name,arn,document,description,created_at) VALUES(?,?,?,?,?)",
                (name, arn, doc, request.form.get("description", ""), _now()),
            )
            c.commit()
            flash(f"IAM policy {name} created successfully.", "success")
            c.close()
            return redirect(url_for("services.iam", new=name))
        c.close()
    return redirect(url_for("services.iam"))


@services_bp.route("/iam/<kind>/<int:rid>/delete", methods=["POST"])
def iam_delete(kind, rid):
    table = {"user": "iam_users", "role": "iam_roles", "policy": "iam_policies"}.get(kind)
    if table:
        c = _db()
        c.execute(f"DELETE FROM {table} WHERE id=?", (rid,))
        c.commit()
        c.close()
    return redirect(url_for("services.iam"))


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------

LAMBDA_RUNTIMES = ["python3.12", "python3.11", "nodejs20.x", "nodejs18.x", "java21", "go1.x", "dotnet8", "ruby3.3"]


@services_bp.route("/lambda")
def lambda_list():
    if not _guard():
        return redirect(url_for("login"))
    c = _db()
    rows = [dict(r) for r in c.execute("SELECT * FROM lambda_functions ORDER BY id DESC").fetchall()]
    c.close()
    return render_template("lambda.html", functions=rows, runtimes=LAMBDA_RUNTIMES)


@services_bp.route("/lambda/create", methods=["POST"])
def lambda_create():
    f = request.form
    name = f.get("name", "").strip()
    if name:
        c = _db()
        if not c.execute("SELECT 1 FROM lambda_functions WHERE name=?", (name,)).fetchone():
            region = _region(c)
            arn = f"arn:aws:lambda:{region}:{DEFAULT_ACCOUNT_ID}:function:{name}"
            c.execute(
                "INSERT INTO lambda_functions(name,arn,runtime,handler,memory_mb,timeout_s,description,code,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (name, arn, f.get("runtime", "python3.12"), f.get("handler", "index.handler"),
                 int(f.get("memory_mb", "128") or 128), int(f.get("timeout_s", "3") or 3),
                 f.get("description", ""), f.get("code", ""), _now()),
            )
            c.commit()
            flash(f"Function {name} created successfully.", "success")
            c.close()
            return redirect(url_for("services.lambda_list", new=name))
        c.close()
    return redirect(url_for("services.lambda_list"))


@services_bp.route("/lambda/<int:fid>")
def lambda_detail(fid):
    if not _guard():
        return redirect(url_for("login"))
    c = _db()
    fn = c.execute("SELECT * FROM lambda_functions WHERE id=?", (fid,)).fetchone()
    c.close()
    if not fn:
        return "Function not found", 404
    return render_template("lambda_detail.html", fn=dict(fn), result=None)


@services_bp.route("/lambda/<int:fid>/invoke", methods=["POST"])
def lambda_invoke(fid):
    c = _db()
    fn = c.execute("SELECT * FROM lambda_functions WHERE id=?", (fid,)).fetchone()
    c.close()
    if not fn:
        return "Function not found", 404
    payload = request.form.get("payload", "{}")
    # Simulated invocation: echo a realistic response envelope + tailed log lines.
    try:
        parsed = json.loads(payload or "{}")
    except ValueError:
        parsed = {"raw": payload}
    request_id = aws_id("", 32).lstrip("-")
    result = {
        "statusCode": 200,
        "response": {"message": f"Hello from {fn['name']}", "event": parsed},
        "log": [
            f"START RequestId: {request_id} Version: $LATEST",
            f"Loading handler {fn['handler']} on {fn['runtime']}",
            "END RequestId: " + request_id,
            f"REPORT RequestId: {request_id}  Duration: 12.34 ms  "
            f"Billed Duration: 13 ms  Memory Size: {fn['memory_mb']} MB  Max Memory Used: 42 MB",
        ],
    }
    return render_template("lambda_detail.html", fn=dict(fn), result=result)


@services_bp.route("/lambda/<int:fid>/delete", methods=["POST"])
def lambda_delete(fid):
    c = _db()
    c.execute("DELETE FROM lambda_functions WHERE id=?", (fid,))
    c.commit()
    c.close()
    return redirect(url_for("services.lambda_list"))


# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------

@services_bp.route("/dynamodb")
def dynamodb():
    if not _guard():
        return redirect(url_for("login"))
    c = _db()
    rows = c.execute(
        "SELECT t.*, (SELECT COUNT(*) FROM dynamodb_items i WHERE i.table_id=t.id) item_count "
        "FROM dynamodb_tables t ORDER BY t.id DESC"
    ).fetchall()
    c.close()
    return render_template("dynamodb.html", tables=[dict(r) for r in rows])


@services_bp.route("/dynamodb/create", methods=["POST"])
def dynamodb_create():
    f = request.form
    name = f.get("name", "").strip()
    pk = f.get("partition_key", "").strip()
    if name and pk:
        c = _db()
        if not c.execute("SELECT 1 FROM dynamodb_tables WHERE name=?", (name,)).fetchone():
            region = _region(c)
            arn = f"arn:aws:dynamodb:{region}:{DEFAULT_ACCOUNT_ID}:table/{name}"
            c.execute(
                "INSERT INTO dynamodb_tables(name,arn,partition_key,partition_key_type,sort_key,sort_key_type,billing_mode,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (name, arn, pk, f.get("partition_key_type", "S"),
                 f.get("sort_key", "").strip() or None, f.get("sort_key_type", "S") if f.get("sort_key", "").strip() else None,
                 f.get("billing_mode", "PAY_PER_REQUEST"), _now()),
            )
            c.commit()
            flash(f"Table {name} created successfully.", "success")
            c.close()
            return redirect(url_for("services.dynamodb", new=name))
        c.close()
    return redirect(url_for("services.dynamodb"))


@services_bp.route("/dynamodb/<int:tid>")
def dynamodb_table(tid):
    if not _guard():
        return redirect(url_for("login"))
    c = _db()
    tbl = c.execute("SELECT * FROM dynamodb_tables WHERE id=?", (tid,)).fetchone()
    if not tbl:
        c.close()
        return "Table not found", 404
    items = c.execute("SELECT * FROM dynamodb_items WHERE table_id=? ORDER BY id DESC", (tid,)).fetchall()
    c.close()
    return render_template("dynamodb_table.html", table=dict(tbl),
                           items=[{"id": r["id"], "item": json.loads(r["item_json"])} for r in items])


@services_bp.route("/dynamodb/<int:tid>/item/create", methods=["POST"])
def dynamodb_item_create(tid):
    raw = request.form.get("item_json", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
            c = _db()
            c.execute("INSERT INTO dynamodb_items(table_id,item_json,created_at) VALUES(?,?,?)",
                      (tid, json.dumps(parsed), _now()))
            c.commit()
            c.close()
        except ValueError:
            pass
    return redirect(url_for("services.dynamodb_table", tid=tid))


@services_bp.route("/dynamodb/<int:tid>/item/<int:item_id>/delete", methods=["POST"])
def dynamodb_item_delete(tid, item_id):
    c = _db()
    c.execute("DELETE FROM dynamodb_items WHERE id=? AND table_id=?", (item_id, tid))
    c.commit()
    c.close()
    return redirect(url_for("services.dynamodb_table", tid=tid))


@services_bp.route("/dynamodb/<int:tid>/delete", methods=["POST"])
def dynamodb_delete(tid):
    c = _db()
    c.execute("DELETE FROM dynamodb_items WHERE table_id=?", (tid,))
    c.execute("DELETE FROM dynamodb_tables WHERE id=?", (tid,))
    c.commit()
    c.close()
    return redirect(url_for("services.dynamodb"))


# ---------------------------------------------------------------------------
# Secrets Manager
# ---------------------------------------------------------------------------

@services_bp.route("/secrets")
def secrets_list():
    if not _guard():
        return redirect(url_for("login"))
    c = _db()
    rows = [dict(r) for r in c.execute("SELECT * FROM secrets ORDER BY id DESC").fetchall()]
    c.close()
    reveal = request.args.get("reveal", type=int)
    return render_template("secrets.html", secrets=rows, reveal=reveal)


@services_bp.route("/secrets/create", methods=["POST"])
def secrets_create():
    f = request.form
    name = f.get("name", "").strip()
    if name:
        c = _db()
        if not c.execute("SELECT 1 FROM secrets WHERE name=?", (name,)).fetchone():
            region = _region(c)
            suffix = aws_id("", 6).lstrip("-")
            arn = f"arn:aws:secretsmanager:{region}:{DEFAULT_ACCOUNT_ID}:secret:{name}-{suffix}"
            c.execute(
                "INSERT INTO secrets(name,arn,description,secret_value,rotation_enabled,created_at) VALUES(?,?,?,?,?,?)",
                (name, arn, f.get("description", ""), f.get("secret_value", ""),
                 1 if f.get("rotation_enabled") else 0, _now()),
            )
            c.commit()
            flash(f"Secret {name} stored successfully.", "success")
            c.close()
            return redirect(url_for("services.secrets_list", new=name))
        c.close()
    return redirect(url_for("services.secrets_list"))


@services_bp.route("/secrets/<int:sid>/update", methods=["POST"])
def secrets_update(sid):
    c = _db()
    c.execute("UPDATE secrets SET secret_value=? WHERE id=?", (request.form.get("secret_value", ""), sid))
    c.commit()
    c.close()
    return redirect(url_for("services.secrets_list"))


@services_bp.route("/secrets/<int:sid>/delete", methods=["POST"])
def secrets_delete(sid):
    c = _db()
    c.execute("DELETE FROM secrets WHERE id=?", (sid,))
    c.commit()
    c.close()
    return redirect(url_for("services.secrets_list"))
