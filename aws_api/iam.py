"""
IAM and STS over the AWS Query protocol.

Shares the ``iam_users`` / ``iam_roles`` / ``iam_policies`` tables with the IAM
console. Policy documents are returned URL-encoded, as the real API does
(botocore decodes them back into dicts).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from urllib.parse import quote

import db
from aws_fidelity import DEFAULT_ACCOUNT_ID
from errors import SimError

from .common import el, iso, query_response

IAM_NS = "https://iam.amazonaws.com/doc/2010-05-08/"
STS_NS = "https://sts.amazonaws.com/doc/2011-06-15/"
ACCOUNT = DEFAULT_ACCOUNT_ID


def _uid(prefix, seed):
    return prefix + hashlib.sha1(seed.encode()).hexdigest()[:17].upper()


def trusted_service(doc_text):
    """First service principal in a trust policy, e.g. 'ec2.amazonaws.com'."""
    try:
        doc = json.loads(doc_text)
    except (TypeError, ValueError):
        raise SimError("MalformedPolicyDocument", "The assume role policy document is not valid JSON.")
    stmts = doc.get("Statement", [])
    stmts = stmts if isinstance(stmts, list) else [stmts]
    for s in stmts:
        svc = (s.get("Principal") or {}).get("Service") if isinstance(s.get("Principal"), dict) else None
        if isinstance(svc, list):
            svc = svc[0] if svc else None
        if svc:
            return svc
    return ""


def trust_policy_for(service):
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]})


def _require(p, key):
    if not p.get(key):
        raise SimError("ValidationError", f"1 validation error detected: Value null at '{key[0].lower() + key[1:]}' "
                       "failed to satisfy constraint: Member must not be null")
    return p[key]


def _no_such(kind, name):
    return SimError("NoSuchEntity", f"The {kind} with name {name} cannot be found.", 404)


# --- users -------------------------------------------------------------------

def _user_xml(r):
    return (el("Path", r["path"] or "/") + el("UserName", r["name"]) + el("UserId", _uid("AIDA", r["name"])) +
            el("Arn", r["arn"]) + el("CreateDate", iso(r["created_at"])))


def _get_user(c, name):
    r = c.execute("SELECT * FROM iam_users WHERE name=?", (name,)).fetchone()
    if not r:
        raise _no_such("user", name)
    return r


def create_user(c, name, path="/", console_access=False):
    if c.execute("SELECT 1 FROM iam_users WHERE name=?", (name,)).fetchone():
        raise SimError("EntityAlreadyExists", f"User with name {name} already exists.", 409)
    c.execute("INSERT INTO iam_users(name,arn,path,console_access,created_at) VALUES(?,?,?,?,?)",
              (name, f"arn:aws:iam::{ACCOUNT}:user{path.rstrip('/')}/{name}", path, int(bool(console_access)), db.now()))
    return _get_user(c, name)


def create_role(c, name, trust_doc, description=""):
    if c.execute("SELECT 1 FROM iam_roles WHERE name=?", (name,)).fetchone():
        raise SimError("EntityAlreadyExists", f"Role with name {name} already exists.", 409)
    c.execute("INSERT INTO iam_roles(name,arn,trusted_service,description,created_at,trust_policy) VALUES(?,?,?,?,?,?)",
              (name, f"arn:aws:iam::{ACCOUNT}:role/{name}", trusted_service(trust_doc), description, db.now(), trust_doc))
    return c.execute("SELECT * FROM iam_roles WHERE name=?", (name,)).fetchone()


def create_policy(c, name, document, description=""):
    try:
        json.loads(document)
    except (TypeError, ValueError):
        raise SimError("MalformedPolicyDocument", "The policy document is not valid JSON.")
    if c.execute("SELECT 1 FROM iam_policies WHERE name=?", (name,)).fetchone():
        raise SimError("EntityAlreadyExists", f"A policy called {name} already exists.", 409)
    c.execute("INSERT INTO iam_policies(name,arn,document,description,created_at) VALUES(?,?,?,?,?)",
              (name, f"arn:aws:iam::{ACCOUNT}:policy/{name}", document, description, db.now()))
    return c.execute("SELECT * FROM iam_policies WHERE name=?", (name,)).fetchone()


def a_create_user(c, p):
    return f"<User>{_user_xml(create_user(c, _require(p, 'UserName'), p.get('Path', '/')))}</User>"


def a_get_user(c, p):
    if not p.get("UserName"):
        return (f"<User>{el('UserId', ACCOUNT)}{el('Arn', f'arn:aws:iam::{ACCOUNT}:root')}"
                f"{el('CreateDate', iso(db.now()))}</User>")
    return f"<User>{_user_xml(_get_user(c, p['UserName']))}</User>"


def a_list_users(c, p):
    rows = c.execute("SELECT * FROM iam_users ORDER BY name").fetchall()
    return "<Users>" + "".join(f"<member>{_user_xml(r)}</member>" for r in rows) + "</Users><IsTruncated>false</IsTruncated>"


def a_delete_user(c, p):
    u = _get_user(c, _require(p, "UserName"))
    if c.execute("SELECT 1 FROM iam_policy_attachments WHERE principal_type='user' AND principal_name=?", (u["name"],)).fetchone():
        raise SimError("DeleteConflict", "Cannot delete entity, must detach all policies first.", 409)
    c.execute("DELETE FROM iam_users WHERE id=?", (u["id"],))
    return ""


def a_create_login_profile(c, p):
    u = _get_user(c, _require(p, "UserName"))
    if u["console_access"]:
        raise SimError("EntityAlreadyExists", f"Login Profile for user {u['name']} already exists.", 409)
    c.execute("UPDATE iam_users SET console_access=1 WHERE id=?", (u["id"],))
    return f"<LoginProfile>{el('UserName', u['name'])}{el('CreateDate', iso(db.now()))}" \
           "<PasswordResetRequired>false</PasswordResetRequired></LoginProfile>"


def a_delete_login_profile(c, p):
    u = _get_user(c, _require(p, "UserName"))
    c.execute("UPDATE iam_users SET console_access=0 WHERE id=?", (u["id"],))
    return ""


# --- roles -------------------------------------------------------------------

def _role_xml(r):
    trust = r["trust_policy"] or trust_policy_for(r["trusted_service"] or "ec2.amazonaws.com")
    return (el("Path", "/") + el("RoleName", r["name"]) + el("RoleId", _uid("AROA", r["name"])) + el("Arn", r["arn"]) +
            el("CreateDate", iso(r["created_at"])) + el("AssumeRolePolicyDocument", quote(trust)) +
            el("Description", r["description"] or "") + "<MaxSessionDuration>3600</MaxSessionDuration>")


def _get_role(c, name):
    r = c.execute("SELECT * FROM iam_roles WHERE name=?", (name,)).fetchone()
    if not r:
        raise _no_such("role", name)
    return r


def a_create_role(c, p):
    r = create_role(c, _require(p, "RoleName"), _require(p, "AssumeRolePolicyDocument"), p.get("Description", ""))
    return f"<Role>{_role_xml(r)}</Role>"


def a_get_role(c, p):
    return f"<Role>{_role_xml(_get_role(c, _require(p, 'RoleName')))}</Role>"


def a_list_roles(c, p):
    rows = c.execute("SELECT * FROM iam_roles ORDER BY name").fetchall()
    return "<Roles>" + "".join(f"<member>{_role_xml(r)}</member>" for r in rows) + "</Roles><IsTruncated>false</IsTruncated>"


def a_delete_role(c, p):
    r = _get_role(c, _require(p, "RoleName"))
    if c.execute("SELECT 1 FROM iam_policy_attachments WHERE principal_type='role' AND principal_name=?", (r["name"],)).fetchone():
        raise SimError("DeleteConflict", "Cannot delete entity, must detach all policies first.", 409)
    c.execute("DELETE FROM iam_roles WHERE id=?", (r["id"],))
    return ""


# --- policies ----------------------------------------------------------------

def _policy_xml(c, r):
    n = c.execute("SELECT COUNT(*) FROM iam_policy_attachments WHERE policy_arn=?", (r["arn"],)).fetchone()[0]
    return (el("PolicyName", r["name"]) + el("PolicyId", _uid("ANPA", r["name"])) + el("Arn", r["arn"]) + el("Path", "/") +
            el("DefaultVersionId", "v1") + el("AttachmentCount", n) + "<IsAttachable>true</IsAttachable>" +
            el("Description", r["description"] or "") + el("CreateDate", iso(r["created_at"])) +
            el("UpdateDate", iso(r["created_at"])))


def _get_policy(c, arn):
    r = c.execute("SELECT * FROM iam_policies WHERE arn=?", (arn,)).fetchone()
    if not r:
        raise SimError("NoSuchEntity", f"Policy {arn} does not exist or is not attachable.", 404)
    return r


def a_create_policy(c, p):
    r = create_policy(c, _require(p, "PolicyName"), _require(p, "PolicyDocument"), p.get("Description", ""))
    return f"<Policy>{_policy_xml(c, r)}</Policy>"


def a_get_policy(c, p):
    return f"<Policy>{_policy_xml(c, _get_policy(c, _require(p, 'PolicyArn')))}</Policy>"


def a_get_policy_version(c, p):
    r = _get_policy(c, _require(p, "PolicyArn"))
    return (f"<PolicyVersion>{el('Document', quote(r['document'] or '{}'))}{el('VersionId', 'v1')}"
            f"<IsDefaultVersion>true</IsDefaultVersion>{el('CreateDate', iso(r['created_at']))}</PolicyVersion>")


def a_list_policies(c, p):
    if p.get("Scope") == "AWS":
        rows = []
    else:
        rows = c.execute("SELECT * FROM iam_policies ORDER BY name").fetchall()
    return "<Policies>" + "".join(f"<member>{_policy_xml(c, r)}</member>" for r in rows) + \
        "</Policies><IsTruncated>false</IsTruncated>"


def a_delete_policy(c, p):
    r = _get_policy(c, _require(p, "PolicyArn"))
    if c.execute("SELECT 1 FROM iam_policy_attachments WHERE policy_arn=?", (r["arn"],)).fetchone():
        raise SimError("DeleteConflict", "Cannot delete a policy attached to entities.", 409)
    c.execute("DELETE FROM iam_policies WHERE id=?", (r["id"],))
    return ""


def attach(c, kind, principal, arn):
    if not arn.startswith("arn:aws:iam::aws:policy/"):
        _get_policy(c, arn)
    if not c.execute("SELECT 1 FROM iam_policy_attachments WHERE policy_arn=? AND principal_type=? AND principal_name=?",
                     (arn, kind, principal)).fetchone():
        c.execute("INSERT INTO iam_policy_attachments(policy_arn,principal_type,principal_name) VALUES(?,?,?)",
                  (arn, kind, principal))


def _attach(kind, detach=False):
    key = "RoleName" if kind == "role" else "UserName"

    def handler(c, p):
        name = _require(p, key)
        (_get_role if kind == "role" else _get_user)(c, name)
        arn = _require(p, "PolicyArn")
        if detach:
            cur = c.execute("DELETE FROM iam_policy_attachments WHERE policy_arn=? AND principal_type=? AND principal_name=?",
                            (arn, kind, name))
            if cur.rowcount == 0:
                raise SimError("NoSuchEntity", f"Policy {arn} was not found.", 404)
        else:
            attach(c, kind, name, arn)
        return ""
    return handler


def _list_attached(kind):
    key = "RoleName" if kind == "role" else "UserName"

    def handler(c, p):
        name = _require(p, key)
        (_get_role if kind == "role" else _get_user)(c, name)
        rows = c.execute("SELECT policy_arn FROM iam_policy_attachments WHERE principal_type=? AND principal_name=?",
                         (kind, name)).fetchall()
        items = "".join(f"<member>{el('PolicyName', r[0].rsplit('/', 1)[-1])}{el('PolicyArn', r[0])}</member>" for r in rows)
        return f"<AttachedPolicies>{items}</AttachedPolicies><IsTruncated>false</IsTruncated>"
    return handler


IAM_ACTIONS = {
    "CreateUser": a_create_user, "GetUser": a_get_user, "ListUsers": a_list_users, "DeleteUser": a_delete_user,
    "CreateLoginProfile": a_create_login_profile, "DeleteLoginProfile": a_delete_login_profile,
    "CreateRole": a_create_role, "GetRole": a_get_role, "ListRoles": a_list_roles, "DeleteRole": a_delete_role,
    "CreatePolicy": a_create_policy, "GetPolicy": a_get_policy, "GetPolicyVersion": a_get_policy_version,
    "ListPolicies": a_list_policies, "DeletePolicy": a_delete_policy,
    "AttachRolePolicy": _attach("role"), "DetachRolePolicy": _attach("role", True),
    "AttachUserPolicy": _attach("user"), "DetachUserPolicy": _attach("user", True),
    "ListAttachedRolePolicies": _list_attached("role"), "ListAttachedUserPolicies": _list_attached("user"),
}


def handle_iam(c, params):
    action = params.get("Action", "")
    fn = IAM_ACTIONS.get(action)
    if not fn:
        raise SimError("InvalidAction", f"The IAM action '{action}' is not supported by this simulator. "
                       f"Supported: {', '.join(sorted(IAM_ACTIONS))}.")
    return query_response(IAM_NS, action, fn(c, params))


# --- STS ---------------------------------------------------------------------

def handle_sts(c, params):
    action = params.get("Action", "")
    if action == "GetCallerIdentity":
        inner = el("Arn", f"arn:aws:iam::{ACCOUNT}:root") + el("UserId", ACCOUNT) + el("Account", ACCOUNT)
    elif action == "AssumeRole":
        arn = _require(params, "RoleArn")
        name = arn.rsplit("/", 1)[-1]
        _get_role(c, name)
        session = params.get("RoleSessionName", "session")
        inner = (f"<Credentials>{el('AccessKeyId', 'ASIA' + _uid('', session)[:16])}"
                 f"{el('SecretAccessKey', 'local-simulator-secret')}{el('SessionToken', 'local-simulator-token')}"
                 f"{el('Expiration', iso((datetime.now() + timedelta(hours=1)).isoformat()))}</Credentials>"
                 f"<AssumedRoleUser>{el('AssumedRoleId', _uid('AROA', name) + ':' + session)}"
                 f"{el('Arn', f'arn:aws:sts::{ACCOUNT}:assumed-role/{name}/{session}')}</AssumedRoleUser>")
    else:
        raise SimError("InvalidAction", f"The STS action '{action}' is not supported. Supported: GetCallerIdentity, AssumeRole.")
    return query_response(STS_NS, action, inner)
