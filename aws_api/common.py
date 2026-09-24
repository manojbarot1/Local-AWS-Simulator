"""Shared helpers for the AWS protocol handlers: XML building, request
parameter parsing (indexed lists, filters) and protocol-specific errors."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from aws_fidelity import DEFAULT_ACCOUNT_ID
from errors import SimError

OWNER = DEFAULT_ACCOUNT_ID
EC2_NS = "http://ec2.amazonaws.com/doc/2016-11-15/"


def x(value):
    """XML-escape any value (None -> empty)."""
    return escape("" if value is None else str(value))


def el(tag, value):
    return f"<{tag}>{x(value)}</{tag}>"


def req_id():
    return str(uuid.uuid4())


def stable_id(prefix, seed, length=17):
    return f"{prefix}-{hashlib.sha1(seed.encode()).hexdigest()[:length]}"


def iso(ts):
    """Stored local ISO timestamp -> AWS UTC timestamp string."""
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", ""))
    except (TypeError, ValueError):
        dt = datetime.now()
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def epoch(ts):
    try:
        return datetime.fromisoformat(str(ts)).timestamp()
    except (TypeError, ValueError):
        return datetime.now().timestamp()


def boolstr(v):
    return "true" if v else "false"


def truthy(v):
    return str(v).lower() in ("true", "1", "yes")


def tags_of(row):
    try:
        tags = json.loads(row["tags_json"] or "{}")
    except (ValueError, TypeError, IndexError, KeyError):
        tags = {}
    if isinstance(tags, dict) and "Name" not in tags:
        try:
            if row["name"]:
                tags["Name"] = row["name"]
        except (IndexError, KeyError):
            pass
    return tags if isinstance(tags, dict) else {}


def tag_set(row):
    tags = tags_of(row)
    if not tags:
        return ""
    items = "".join(f"<item>{el('key', k)}{el('value', v)}</item>" for k, v in tags.items())
    return f"<tagSet>{items}</tagSet>"


# ---------------------------------------------------------------------------
# Query-protocol parameters
# ---------------------------------------------------------------------------

def indexed(params, base):
    """Collect ``Base.1``, ``Base.2`` ... in index order."""
    found = []
    for key, val in params.items():
        m = re.fullmatch(re.escape(base) + r"\.(\d+)", key)
        if m:
            found.append((int(m.group(1)), val))
    return [v for _, v in sorted(found)]


def indexed_structs(params, base):
    """``Base.N.Field`` (and deeper) -> list of dicts keyed by the rest of the path."""
    groups = {}
    prefix = base + "."
    for key, val in params.items():
        if not key.startswith(prefix):
            continue
        rest = key[len(prefix):]
        idx, _, field = rest.partition(".")
        if idx.isdigit() and field:
            groups.setdefault(int(idx), {})[field] = val
    return [groups[i] for i in sorted(groups)]


def filters(params):
    out = {}
    for f in indexed_structs(params, "Filter"):
        name = f.get("Name")
        if name:
            vals = [v for k, v in sorted(f.items(), key=lambda kv: kv[0]) if k.startswith("Value.")]
            out.setdefault(name, []).extend(vals)
    return out


def tag_spec(params, resource_type=None):
    """Tags from ``TagSpecification.N.Tag.M.Key/Value``."""
    tags = {}
    for spec in indexed_structs(params, "TagSpecification"):
        if resource_type and spec.get("ResourceType") not in (None, resource_type):
            continue
        keys = {}
        for k, v in spec.items():
            m = re.fullmatch(r"Tag\.(\d+)\.(Key|Value)", k)
            if m:
                keys.setdefault(int(m.group(1)), {})[m.group(2)] = v
        for i in sorted(keys):
            if "Key" in keys[i]:
                tags[keys[i]["Key"]] = keys[i].get("Value", "")
    return tags


def match_filters(attrs, flt, supported):
    """``attrs``: {filter-name: value or [values]}; tags handled via 'tags' key."""
    for name, wanted in flt.items():
        if name.startswith("tag:"):
            val = attrs.get("tags", {}).get(name[4:])
            have = [] if val is None else [val]
        elif name == "tag-key":
            have = list(attrs.get("tags", {}).keys())
        elif name == "tag-value":
            have = list(attrs.get("tags", {}).values())
        elif name in supported:
            v = attrs.get(name)
            have = v if isinstance(v, list) else ([] if v is None else [v])
        else:
            raise SimError("InvalidParameterValue",
                           f"The filter '{name}' is invalid. Supported here: {', '.join(sorted(supported))}, tag:<key>, tag-key.")
        have = [str(h) for h in have]
        if not any(fnmatch.fnmatchcase(h, w) for h in have for w in wanted):
            return False
    return True


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------

XML = {"Content-Type": "text/xml; charset=utf-8"}
JSON_10 = {"Content-Type": "application/x-amz-json-1.0"}
JSON_11 = {"Content-Type": "application/x-amz-json-1.1"}


def ec2_response(action, inner):
    return (f'<?xml version="1.0" encoding="UTF-8"?><{action}Response xmlns="{EC2_NS}">'
            f"<requestId>{req_id()}</requestId>{inner}</{action}Response>", 200, XML)


def ec2_error(err):
    body = (f'<?xml version="1.0" encoding="UTF-8"?><Response><Errors><Error>{el("Code", err.code)}'
            f'{el("Message", err.message)}</Error></Errors>{el("RequestID", req_id())}</Response>')
    return body, err.status, XML


def query_response(ns, action, inner):
    """IAM/STS style: <XResponse><XResult>...</XResult><ResponseMetadata>."""
    return (f'<{action}Response xmlns="{ns}"><{action}Result>{inner}</{action}Result>'
            f"<ResponseMetadata>{el('RequestId', req_id())}</ResponseMetadata></{action}Response>", 200, XML)


def query_error(ns, err):
    status = err.status if err.status != 400 or not err.code.startswith("NoSuch") else 404
    body = (f'<ErrorResponse xmlns="{ns}"><Error><Type>Sender</Type>{el("Code", err.code)}'
            f'{el("Message", err.message)}</Error>{el("RequestId", req_id())}</ErrorResponse>')
    return body, status, XML


def json_response(data, headers=JSON_10, status=200):
    return json.dumps(data, default=str), status, headers


def json_error(err, headers=JSON_10):
    body = {"__type": err.code, "message": err.message, "Message": err.message}
    return json.dumps(body), err.status, {**headers, "x-amzn-ErrorType": err.code}
