"""
activity.py
===========

A CloudTrail-style activity log that doubles as a CLI teacher.

Every console action is recorded together with the ``aws ...`` command that
does the same thing, and every call that arrives on the API endpoint is
recorded with the command that (approximately) produced it. The Activity page
shows both, so clicking through the console teaches the CLI.
"""

from __future__ import annotations

import json
import re
import shlex

import db

# Console-only features that have a real AWS CLI equivalent the simulator's
# endpoint does not implement yet — shown with a "real AWS" badge.
SIMULATOR_API_SERVICES = {"ec2", "s3", "s3api", "iam", "sts", "dynamodb", "secretsmanager", "lambda"}


def cli(command, *args):
    """Build a shell-safe command: cli("ec2 create-vpc", ("--cidr-block", "10.0.0.0/16"))."""
    parts = ["aws"] + command.split()
    for arg in args:
        if arg is None:
            continue
        if isinstance(arg, tuple):
            flag, value = arg
            if value is None or value == "" or value is False:
                continue
            parts.append(flag)
            if value is not True:
                if isinstance(value, (list, tuple)):
                    parts.extend(shlex.quote(str(v)) for v in value)
                    continue
                parts.append(shlex.quote(str(value)))
        else:
            parts.append(arg)
    return " ".join(parts)


def name_tag(resource_type, name):
    if not name:
        return None
    return ("--tag-specifications", f"ResourceType={resource_type},Tags=[{{Key=Name,Value={name}}}]")


def record(c, source, service, action, resource="", detail="", cli_cmd="", readonly=False, status="ok"):
    c.execute(
        "INSERT INTO activity_log(ts,source,service,action,resource,detail,cli,readonly,status) VALUES(?,?,?,?,?,?,?,?,?)",
        (db.now(), source, service, action, resource or "", detail or "", cli_cmd or "", int(bool(readonly)), status))
    # Keep the log bounded.
    c.execute("DELETE FROM activity_log WHERE id <= (SELECT MAX(id) FROM activity_log) - 5000")


def has(c, action, source=None, resource_like=None):
    sql = "SELECT 1 FROM activity_log WHERE action=? AND status='ok'"
    args = [action]
    if source:
        sql += " AND source=?"
        args.append(source)
    if resource_like:
        sql += " AND resource LIKE ?"
        args.append(resource_like)
    return c.execute(sql + " LIMIT 1", args).fetchone() is not None


def is_simulated(command):
    parts = (command or "").split()
    return len(parts) > 1 and parts[1] in SIMULATOR_API_SERVICES


# ---------------------------------------------------------------------------
# Reconstructing the CLI command for calls that arrived on the API endpoint
# ---------------------------------------------------------------------------

def kebab(name):
    return re.sub(r"(?<!^)(?=[A-Z][a-z])|(?<=[a-z0-9])(?=[A-Z])", "-", name).lower()


def _flag(param):
    # AWS CLI pluralises indexed list params: InstanceId.1 -> --instance-ids
    return "--" + kebab(param)


def from_query(service, params):
    """Approximate CLI for an EC2/IAM/STS Query-protocol call."""
    action = params.get("Action", "")
    args = []
    lists = {}
    for key, val in params.items():
        if key in ("Action", "Version") or key.startswith(("TagSpecification", "Filter")):
            continue
        m = re.fullmatch(r"([A-Za-z]+)\.(\d+)", key)
        if m:
            lists.setdefault(m.group(1), []).append(val)
            continue
        if "." in key:
            continue
        args.append((_flag(key), val))
    for base, vals in lists.items():
        args.append((_flag(base) + ("s" if not base.endswith("s") else ""), vals))
    return cli(f"{service} {kebab(action)}", *args)


def from_json(service, action, body):
    args = []
    for key, val in (body or {}).items():
        if key in ("ClientRequestToken",):   # SDK-generated, not typed by the user
            continue
        if isinstance(val, (dict, list)):
            val = json.dumps(val, separators=(",", ":"))
        args.append((_flag(key), val))
    return cli(f"{service} {kebab(action)}", *args)
