"""
Secrets Manager over the AWS JSON 1.1 protocol (``X-Amz-Target: secretsmanager.*``).

Shares the ``secrets`` table with the Secrets Manager console. Secrets can be
addressed by name or ARN, like the real service.
"""

from __future__ import annotations

import hashlib
import re

import db
from aws_fidelity import DEFAULT_ACCOUNT_ID, aws_id
from errors import SimError

from .common import epoch


def _err(code, msg):
    return SimError(code, msg, 400)


def _version(row):
    return hashlib.md5(f"{row['arn']}|{row['secret_value']}".encode()).hexdigest()[:8] + "-0000-4000-8000-000000000000"


def get(c, ref):
    ref = ref or ""
    row = c.execute("SELECT * FROM secrets WHERE name=? OR arn=?", (ref, ref)).fetchone()
    if row is None and ref.startswith("arn:"):
        # Partial ARN without the random 6-character suffix.
        row = c.execute("SELECT * FROM secrets WHERE arn LIKE ?", (ref + "-%",)).fetchone()
    if row is None:
        raise _err("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
    return row


def create(c, name, value="", description="", rotation=False):
    if not re.fullmatch(r"[A-Za-z0-9/_+=.@-]{1,512}", name or ""):
        raise _err("ValidationException", "Invalid name. Must be a valid name containing alphanumeric characters, "
                   "or any of the following: -/_+=.@!")
    if c.execute("SELECT 1 FROM secrets WHERE name=?", (name,)).fetchone():
        raise _err("ResourceExistsException", f"The operation failed because the secret {name} already exists.")
    suffix = aws_id("", 6).lstrip("-")
    arn = f"arn:aws:secretsmanager:{db.region(c)}:{DEFAULT_ACCOUNT_ID}:secret:{name}-{suffix}"
    c.execute("INSERT INTO secrets(name,arn,description,secret_value,rotation_enabled,created_at) VALUES(?,?,?,?,?,?)",
              (name, arn, description or "", value or "", int(bool(rotation)), db.now()))
    return get(c, name)


def _ref(row):
    return {"ARN": row["arn"], "Name": row["name"]}


def a_create(c, b):
    row = create(c, b.get("Name"), b.get("SecretString", ""), b.get("Description", ""))
    return {**_ref(row), "VersionId": _version(row)}


def a_get_value(c, b):
    row = get(c, b.get("SecretId"))
    return {**_ref(row), "VersionId": _version(row), "SecretString": row["secret_value"] or "",
            "VersionStages": ["AWSCURRENT"], "CreatedDate": epoch(row["created_at"])}


def a_put_value(c, b):
    row = get(c, b.get("SecretId"))
    c.execute("UPDATE secrets SET secret_value=? WHERE id=?", (b.get("SecretString", ""), row["id"]))
    row = get(c, row["name"])
    return {**_ref(row), "VersionId": _version(row), "VersionStages": ["AWSCURRENT"]}


def a_update(c, b):
    row = get(c, b.get("SecretId"))
    if "Description" in b:
        c.execute("UPDATE secrets SET description=? WHERE id=?", (b["Description"], row["id"]))
    if "SecretString" in b:
        c.execute("UPDATE secrets SET secret_value=? WHERE id=?", (b["SecretString"], row["id"]))
    row = get(c, row["name"])
    return {**_ref(row), "VersionId": _version(row)}


def _describe(row):
    out = {**_ref(row), "Description": row["description"] or "", "RotationEnabled": bool(row["rotation_enabled"]),
           "CreatedDate": epoch(row["created_at"]), "LastChangedDate": epoch(row["created_at"]),
           "VersionIdsToStages": {_version(row): ["AWSCURRENT"]}}
    if row["rotation_enabled"]:
        out["RotationRules"] = {"AutomaticallyAfterDays": 30}
    return out


def a_describe(c, b):
    return _describe(get(c, b.get("SecretId")))


def a_list(c, b):
    rows = c.execute("SELECT * FROM secrets ORDER BY name").fetchall()
    for f in b.get("Filters") or []:
        if f.get("Key") == "name":
            rows = [r for r in rows if any(r["name"].startswith(v) for v in f.get("Values", []))]
    return {"SecretList": [_describe(r) for r in rows]}


def a_delete(c, b):
    row = get(c, b.get("SecretId"))
    c.execute("DELETE FROM secrets WHERE id=?", (row["id"],))
    return {**_ref(row), "DeletionDate": epoch(db.now())}


def a_rotate(c, b):
    row = get(c, b.get("SecretId"))
    c.execute("UPDATE secrets SET rotation_enabled=1 WHERE id=?", (row["id"],))
    return {**_ref(row), "VersionId": _version(row)}


def a_cancel_rotation(c, b):
    row = get(c, b.get("SecretId"))
    c.execute("UPDATE secrets SET rotation_enabled=0 WHERE id=?", (row["id"],))
    return _ref(row)


ACTIONS = {
    "CreateSecret": a_create, "GetSecretValue": a_get_value, "PutSecretValue": a_put_value,
    "UpdateSecret": a_update, "DescribeSecret": a_describe, "ListSecrets": a_list, "DeleteSecret": a_delete,
    "RotateSecret": a_rotate, "CancelRotateSecret": a_cancel_rotation,
}


def handle(c, action, body):
    fn = ACTIONS.get(action)
    if not fn:
        raise _err("InvalidRequestException", f"The Secrets Manager operation '{action}' is not supported by the simulator. "
                   f"Supported: {', '.join(sorted(ACTIONS))}.")
    return fn(c, body)
