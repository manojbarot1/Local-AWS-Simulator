"""
DynamoDB over the AWS JSON 1.0 protocol (``X-Amz-Target: DynamoDB_20120810.*``).

Items are stored as plain JSON (the console's format) and converted to and
from DynamoDB's typed AttributeValues ({"S": "..."}, {"N": "1"}) at the edge.
A small expression engine supports KeyConditionExpression, FilterExpression,
ConditionExpression, UpdateExpression (SET/REMOVE/ADD) and
ProjectionExpression with ``#name`` / ``:value`` placeholders.
"""

from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation

import db
from aws_fidelity import DEFAULT_ACCOUNT_ID
from errors import SimError

from .common import epoch

TYPES = {"S", "N", "B"}


def _err(code, msg):
    return SimError(code, msg, 400)


def _validation(msg):
    return _err("ValidationException", msg)


# ---------------------------------------------------------------------------
# AttributeValue <-> plain JSON
# ---------------------------------------------------------------------------

def _num(text):
    try:
        d = Decimal(str(text))
    except InvalidOperation:
        raise _validation(f"The parameter cannot be converted to a numeric value: {text}")
    return int(d) if d == d.to_integral_value() and "e" not in str(text).lower() and "." not in str(text) else float(d)


def from_av(av):
    if not isinstance(av, dict) or len(av) != 1:
        raise _validation("Supplied AttributeValue is empty, must contain exactly one of the supported datatypes")
    (t, v), = av.items()
    if t == "S":
        return v
    if t == "N":
        return _num(v)
    if t == "BOOL":
        return bool(v)
    if t == "NULL":
        return None
    if t == "L":
        return [from_av(x) for x in v]
    if t == "M":
        return {k: from_av(x) for k, x in v.items()}
    if t in ("SS", "NS", "BS", "B"):
        return {"__ddb__": {t: v}}
    raise _validation(f"Unknown AttributeValue type {t}")


def to_av(v):
    if isinstance(v, bool):
        return {"BOOL": v}
    if v is None:
        return {"NULL": True}
    if isinstance(v, (int, float)):
        return {"N": str(v)}
    if isinstance(v, str):
        return {"S": v}
    if isinstance(v, list):
        return {"L": [to_av(x) for x in v]}
    if isinstance(v, dict):
        if set(v) == {"__ddb__"}:
            return v["__ddb__"]
        return {"M": {k: to_av(x) for k, x in v.items()}}
    return {"S": str(v)}


def item_to_av(item):
    return {k: to_av(v) for k, v in item.items()}


def item_from_av(item):
    return {k: from_av(v) for k, v in (item or {}).items()}


def _type_of(v):
    if isinstance(v, bool) or v is None:
        return "?"
    if isinstance(v, (int, float)):
        return "N"
    if isinstance(v, str):
        return "S"
    if isinstance(v, dict) and "__ddb__" in v:
        return next(iter(v["__ddb__"]))
    return "?"


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(<>|<=|>=|=|<|>|\(|\)|,|\+|-|\[\d+\]|\.|:[A-Za-z0-9_]+|#[A-Za-z0-9_]+|[A-Za-z_][A-Za-z0-9_]*)")


def _tokens(text):
    out, pos = [], 0
    text = text or ""
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip():
                raise _validation(f"Invalid expression: syntax error near '{text[pos:pos + 12]}'")
            break
        out.append(m.group(1))
        pos = m.end()
    return out


class _Expr:
    def __init__(self, text, names, values):
        self.t = _tokens(text)
        self.i = 0
        self.names = names or {}
        self.values = {k: from_av(v) for k, v in (values or {}).items()}

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else None

    def take(self, expected=None):
        tok = self.peek()
        if tok is None or (expected and tok.upper() != expected):
            raise _validation(f"Invalid expression: expected {expected or 'more input'}, got {tok}")
        self.i += 1
        return tok

    def done(self):
        if self.peek() is not None:
            raise _validation(f"Invalid expression: unexpected token {self.peek()}")

    # paths
    def path(self):
        parts = [self._name(self.take())]
        while self.peek() == "." or (self.peek() or "").startswith("["):
            if self.take() == ".":
                parts.append(self._name(self.take()))
            else:
                parts.append(int(self.t[self.i - 1][1:-1]))
        return parts

    def _name(self, tok):
        if tok.startswith("#"):
            if tok not in self.names:
                raise _validation(f"An expression attribute name used in the document path is not defined; name: {tok}")
            return self.names[tok]
        return tok

    def value(self, tok):
        if tok not in self.values:
            raise _validation(f"An expression attribute value used in expression is not defined; attribute value: {tok}")
        return self.values[tok]

    # condition grammar
    def condition(self):
        node = self._and()
        while (self.peek() or "").upper() == "OR":
            self.take()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._not()
        while (self.peek() or "").upper() == "AND":
            self.take()
            node = ("and", node, self._not())
        return node

    def _not(self):
        if (self.peek() or "").upper() == "NOT":
            self.take()
            return ("not", self._not())
        return self._cmp()

    def _cmp(self):
        if self.peek() == "(":
            self.take()
            node = self.condition()
            self.take(")")
            return node
        fn = (self.peek() or "").lower()
        if fn in ("attribute_exists", "attribute_not_exists", "begins_with", "contains", "attribute_type") \
                and self.peek(1) == "(":
            self.take()
            self.take("(")
            args = [self.operand()]
            while self.peek() == ",":
                self.take()
                args.append(self.operand())
            self.take(")")
            return ("fn", fn, args)
        left = self.operand()
        op = (self.peek() or "").upper()
        if op in ("=", "<>", "<", "<=", ">", ">="):
            self.take()
            return ("cmp", op, left, self.operand())
        if op == "BETWEEN":
            self.take()
            lo = self.operand()
            self.take("AND")
            return ("between", left, lo, self.operand())
        if op == "IN":
            self.take()
            self.take("(")
            opts = [self.operand()]
            while self.peek() == ",":
                self.take()
                opts.append(self.operand())
            self.take(")")
            return ("in", left, opts)
        raise _validation(f"Invalid expression: expected a comparison after {left}")

    def operand(self):
        tok = self.peek()
        if tok is None:
            raise _validation("Invalid expression: unexpected end")
        if tok.startswith(":"):
            self.take()
            return ("val", self.value(tok))
        if tok.lower() == "size" and self.peek(1) == "(":
            self.take()
            self.take("(")
            p = self.path()
            self.take(")")
            return ("size", p)
        return ("path", self.path())


def _get_path(item, parts):
    cur = item
    for p in parts:
        if isinstance(p, int):
            if not isinstance(cur, list) or p >= len(cur):
                return _MISSING
            cur = cur[p]
        else:
            if not isinstance(cur, dict) or p not in cur:
                return _MISSING
            cur = cur[p]
    return cur


_MISSING = object()


def _eval_operand(item, node):
    kind = node[0]
    if kind == "val":
        return node[1]
    if kind == "path":
        return _get_path(item, node[1])
    if kind == "size":
        v = _get_path(item, node[1])
        return _MISSING if v is _MISSING else len(v) if hasattr(v, "__len__") else _MISSING
    raise _validation("bad operand")


def _cmp(a, op, b):
    if a is _MISSING or b is _MISSING:
        return op == "<>" and not (a is _MISSING and b is _MISSING)
    if isinstance(a, (int, float)) != isinstance(b, (int, float)) and op not in ("=", "<>"):
        return False
    try:
        return {"=": a == b, "<>": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    except TypeError:
        return False


def evaluate(node, item):
    kind = node[0]
    if kind == "or":
        return evaluate(node[1], item) or evaluate(node[2], item)
    if kind == "and":
        return evaluate(node[1], item) and evaluate(node[2], item)
    if kind == "not":
        return not evaluate(node[1], item)
    if kind == "cmp":
        return _cmp(_eval_operand(item, node[2]), node[1], _eval_operand(item, node[3]))
    if kind == "between":
        v = _eval_operand(item, node[1])
        return _cmp(v, ">=", _eval_operand(item, node[2])) and _cmp(v, "<=", _eval_operand(item, node[3]))
    if kind == "in":
        v = _eval_operand(item, node[1])
        return any(_cmp(v, "=", _eval_operand(item, o)) for o in node[2])
    if kind == "fn":
        fn, args = node[1], node[2]
        a = _eval_operand(item, args[0])
        if fn == "attribute_exists":
            return a is not _MISSING
        if fn == "attribute_not_exists":
            return a is _MISSING
        b = _eval_operand(item, args[1]) if len(args) > 1 else _MISSING
        if fn == "begins_with":
            return isinstance(a, str) and isinstance(b, str) and a.startswith(b)
        if fn == "contains":
            return a is not _MISSING and b is not _MISSING and (b in a if isinstance(a, (str, list)) else False)
        if fn == "attribute_type":
            return a is not _MISSING and next(iter(to_av(a))) == b
    raise _validation(f"Unsupported expression node {kind}")


def condition(text, names, values):
    if not text:
        return None
    e = _Expr(text, names, values)
    node = e.condition()
    e.done()
    return node


def apply_update(item, text, names, values):
    """Apply an UpdateExpression (SET / REMOVE / ADD) to ``item`` in place."""
    e = _Expr(text, names, values)
    section = None
    while e.peek() is not None:
        tok = e.peek().upper()
        if tok in ("SET", "REMOVE", "ADD", "DELETE"):
            section = e.take().upper()
            continue
        if tok == ",":
            e.take()
            continue
        if section == "SET":
            target = e.path()
            e.take("=")
            val = _update_value(e, item)
            _set_path(item, target, val)
        elif section == "REMOVE":
            _remove_path(item, e.path())
        elif section == "ADD":
            target = e.path()
            delta = _eval_operand(item, e.operand())
            cur = _get_path(item, target)
            if isinstance(delta, (int, float)):
                _set_path(item, target, (0 if cur is _MISSING else cur) + delta)
            else:
                raise _validation("ADD is supported for numbers only in the simulator")
        else:
            raise _validation(f"Invalid UpdateExpression near '{tok}'")


def _update_value(e, item):
    tok = (e.peek() or "").lower()
    if tok in ("if_not_exists", "list_append") and e.peek(1) == "(":
        e.take()
        e.take("(")
        a = e.operand()
        e.take(",")
        b = _update_value(e, item)
        e.take(")")
        if tok == "if_not_exists":
            cur = _eval_operand(item, a)
            val = b if cur is _MISSING else cur
        else:
            av = _eval_operand(item, a)
            val = (av if isinstance(av, list) else []) + (b if isinstance(b, list) else [])
    else:
        val = _eval_operand(item, e.operand())
    if e.peek() in ("+", "-"):
        op = e.take()
        rhs = _update_value(e, item)
        if not isinstance(val, (int, float)) or not isinstance(rhs, (int, float)):
            raise _validation("An operand in the update expression has an incorrect data type")
        val = val + rhs if op == "+" else val - rhs
    if val is _MISSING:
        raise _validation("The provided expression refers to an attribute that does not exist in the item")
    return val


def _set_path(item, parts, val):
    cur = item
    for p in parts[:-1]:
        cur = cur.setdefault(p, {}) if isinstance(p, str) else cur[p]
    if isinstance(parts[-1], int) and isinstance(cur, list):
        if parts[-1] < len(cur):
            cur[parts[-1]] = val
        else:
            cur.append(val)
    else:
        cur[parts[-1]] = val


def _remove_path(item, parts):
    cur = item
    for p in parts[:-1]:
        cur = _get_path(cur, [p])
        if cur is _MISSING:
            return
    if isinstance(cur, dict):
        cur.pop(parts[-1], None)
    elif isinstance(cur, list) and isinstance(parts[-1], int) and parts[-1] < len(cur):
        cur.pop(parts[-1])


def project(item, text, names):
    if not text:
        return item
    out = {}
    for part in text.split(","):
        e = _Expr(part.strip(), names, {})
        p = e.path()
        v = _get_path(item, p)
        if v is not _MISSING:
            _set_path(out, p, v)
    return out


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

def _table(c, name):
    t = c.execute("SELECT * FROM dynamodb_tables WHERE name=?", (name or "",)).fetchone()
    if not t:
        raise _err("ResourceNotFoundException", f"Requested resource not found: Table: {name} not found")
    return t


def _items(c, t):
    return [(r["id"], json.loads(r["item_json"])) for r in
            c.execute("SELECT id, item_json FROM dynamodb_items WHERE table_id=? ORDER BY id", (t["id"],))]


def _key_names(t):
    return [t["partition_key"]] + ([t["sort_key"]] if t["sort_key"] else [])


def _key_of(t, item):
    return tuple(item.get(k) for k in _key_names(t))


def _validate_key(t, key, full_item=False):
    names = _key_names(t)
    types = {t["partition_key"]: t["partition_key_type"] or "S"}
    if t["sort_key"]:
        types[t["sort_key"]] = t["sort_key_type"] or "S"
    for k in names:
        if k not in key:
            raise _validation("One or more parameter values were invalid: Missing the key "
                              f"{k} in the item" if full_item else "The provided key element does not match the schema")
        if _type_of(key[k]) != types[k]:
            raise _validation(f"One or more parameter values were invalid: Type mismatch for key {k} expected: "
                              f"{types[k]} actual: {_type_of(key[k])}")
    if not full_item and set(key) - set(names):
        raise _validation("The provided key element does not match the schema")


def _find(c, t, key):
    want = _key_of(t, key)
    for rid, item in _items(c, t):
        if _key_of(t, item) == want:
            return rid, item
    return None, None


def _describe(c, t, status="ACTIVE"):
    items = _items(c, t)
    keys = [{"AttributeName": t["partition_key"], "KeyType": "HASH"}]
    attrs = [{"AttributeName": t["partition_key"], "AttributeType": t["partition_key_type"] or "S"}]
    if t["sort_key"]:
        keys.append({"AttributeName": t["sort_key"], "KeyType": "RANGE"})
        attrs.append({"AttributeName": t["sort_key"], "AttributeType": t["sort_key_type"] or "S"})
    provisioned = (t["billing_mode"] or "") == "PROVISIONED"
    return {"TableName": t["name"], "TableStatus": status, "TableArn": t["arn"],
            "TableId": f"{t['id']:08d}-0000-4000-8000-000000000000", "KeySchema": keys,
            "AttributeDefinitions": attrs, "CreationDateTime": epoch(t["created_at"]),
            "ItemCount": len(items), "TableSizeBytes": sum(len(json.dumps(i)) for _, i in items),
            "BillingModeSummary": {"BillingMode": t["billing_mode"] or "PAY_PER_REQUEST"},
            "ProvisionedThroughput": {"ReadCapacityUnits": 5 if provisioned else 0,
                                      "WriteCapacityUnits": 5 if provisioned else 0, "NumberOfDecreasesToday": 0}}


def create_table(c, name, pk, pk_type="S", sk=None, sk_type=None, billing="PAY_PER_REQUEST"):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", name or ""):
        raise _validation("TableName must be 3-255 characters of letters, numbers, '_', '-' and '.'.")
    if c.execute("SELECT 1 FROM dynamodb_tables WHERE name=?", (name,)).fetchone():
        raise _err("ResourceInUseException", f"Table already exists: {name}")
    for typ in (pk_type, sk_type):
        if typ and typ not in TYPES:
            raise _validation(f"Invalid key attribute type {typ}; use S, N or B.")
    arn = f"arn:aws:dynamodb:{db.region(c)}:{DEFAULT_ACCOUNT_ID}:table/{name}"
    c.execute("INSERT INTO dynamodb_tables(name,arn,partition_key,partition_key_type,sort_key,sort_key_type,billing_mode,created_at) "
              "VALUES(?,?,?,?,?,?,?,?)", (name, arn, pk, pk_type or "S", sk or None, sk_type if sk else None, billing, db.now()))
    return _table(c, name)


def a_create_table(c, b):
    schema = b.get("KeySchema") or []
    defs = {d["AttributeName"]: d["AttributeType"] for d in b.get("AttributeDefinitions") or []}
    hash_ = next((k["AttributeName"] for k in schema if k.get("KeyType") == "HASH"), None)
    range_ = next((k["AttributeName"] for k in schema if k.get("KeyType") == "RANGE"), None)
    if not hash_:
        raise _validation("KeySchema must contain a HASH key.")
    for k in filter(None, (hash_, range_)):
        if k not in defs:
            raise _validation(f"One or more parameter values were invalid: Some index key attributes are not defined "
                              f"in AttributeDefinitions. Keys: [{k}]")
    t = create_table(c, b.get("TableName"), hash_, defs[hash_], range_, defs.get(range_),
                     b.get("BillingMode") or ("PROVISIONED" if b.get("ProvisionedThroughput") else "PAY_PER_REQUEST"))
    return {"TableDescription": _describe(c, t)}


def a_describe_table(c, b):
    return {"Table": _describe(c, _table(c, b.get("TableName")))}


def a_list_tables(c, b):
    names = [r[0] for r in c.execute("SELECT name FROM dynamodb_tables ORDER BY name")]
    start = b.get("ExclusiveStartTableName")
    if start:
        names = [n for n in names if n > start]
    limit = int(b.get("Limit") or 100)
    out = {"TableNames": names[:limit]}
    if len(names) > limit:
        out["LastEvaluatedTableName"] = names[limit - 1]
    return out


def a_delete_table(c, b):
    t = _table(c, b.get("TableName"))
    desc = _describe(c, t, "DELETING")
    c.execute("DELETE FROM dynamodb_items WHERE table_id=?", (t["id"],))
    c.execute("DELETE FROM dynamodb_tables WHERE id=?", (t["id"],))
    return {"TableDescription": desc}


# ---------------------------------------------------------------------------
# Items
# ---------------------------------------------------------------------------

def _check_condition(b, existing):
    node = condition(b.get("ConditionExpression"), b.get("ExpressionAttributeNames"), b.get("ExpressionAttributeValues"))
    if node is not None and not evaluate(node, existing or {}):
        raise _err("ConditionalCheckFailedException", "The conditional request failed")


def put_item(c, t, item):
    _validate_key(t, item, full_item=True)
    rid, old = _find(c, t, item)
    if rid:
        c.execute("UPDATE dynamodb_items SET item_json=? WHERE id=?", (json.dumps(item), rid))
    else:
        c.execute("INSERT INTO dynamodb_items(table_id,item_json,created_at) VALUES(?,?,?)",
                  (t["id"], json.dumps(item), db.now()))
    return old


def a_put_item(c, b):
    t = _table(c, b.get("TableName"))
    item = item_from_av(b.get("Item"))
    _validate_key(t, item, full_item=True)
    _, existing = _find(c, t, item)
    _check_condition(b, existing)
    old = put_item(c, t, item)
    return {"Attributes": item_to_av(old)} if b.get("ReturnValues") == "ALL_OLD" and old else {}


def a_get_item(c, b):
    t = _table(c, b.get("TableName"))
    key = item_from_av(b.get("Key"))
    _validate_key(t, key)
    _, item = _find(c, t, key)
    if item is None:
        return {}
    return {"Item": item_to_av(project(item, b.get("ProjectionExpression"), b.get("ExpressionAttributeNames")))}


def a_delete_item(c, b):
    t = _table(c, b.get("TableName"))
    key = item_from_av(b.get("Key"))
    _validate_key(t, key)
    rid, item = _find(c, t, key)
    _check_condition(b, item)
    if rid:
        c.execute("DELETE FROM dynamodb_items WHERE id=?", (rid,))
    return {"Attributes": item_to_av(item)} if b.get("ReturnValues") == "ALL_OLD" and item else {}


def a_update_item(c, b):
    t = _table(c, b.get("TableName"))
    key = item_from_av(b.get("Key"))
    _validate_key(t, key)
    rid, item = _find(c, t, key)
    _check_condition(b, item)
    old = json.loads(json.dumps(item)) if item else None
    new = dict(item) if item else dict(key)
    if b.get("UpdateExpression"):
        apply_update(new, b["UpdateExpression"], b.get("ExpressionAttributeNames"), b.get("ExpressionAttributeValues"))
    if _key_of(t, new) != _key_of(t, key):
        raise _validation("One or more parameter values were invalid: Cannot update attribute that is part of the key")
    if rid:
        c.execute("UPDATE dynamodb_items SET item_json=? WHERE id=?", (json.dumps(new), rid))
    else:
        c.execute("INSERT INTO dynamodb_items(table_id,item_json,created_at) VALUES(?,?,?)",
                  (t["id"], json.dumps(new), db.now()))
    rv = b.get("ReturnValues", "NONE")
    if rv == "ALL_NEW":
        return {"Attributes": item_to_av(new)}
    if rv == "ALL_OLD" and old:
        return {"Attributes": item_to_av(old)}
    if rv == "UPDATED_NEW":
        return {"Attributes": item_to_av({k: v for k, v in new.items() if not old or old.get(k) != v})}
    return {}


def _paginate(t, items, b):
    start = item_from_av(b["ExclusiveStartKey"]) if b.get("ExclusiveStartKey") else None
    if start:
        want = _key_of(t, start)
        for i, it in enumerate(items):
            if _key_of(t, it) == want:
                items = items[i + 1:]
                break
    limit = b.get("Limit")
    last = None
    if limit and len(items) > int(limit):
        items = items[:int(limit)]
        last = {k: items[-1][k] for k in _key_names(t)}
    return items, last


def _read(c, b, query):
    t = _table(c, b.get("TableName"))
    names, values = b.get("ExpressionAttributeNames"), b.get("ExpressionAttributeValues")
    items = [i for _, i in _items(c, t)]
    if query:
        if not b.get("KeyConditionExpression"):
            raise _validation("Either the KeyConditions or KeyConditionExpression parameter must be specified in the request.")
        key_node = condition(b["KeyConditionExpression"], names, values)
        items = [i for i in items if evaluate(key_node, i)]
        if t["sort_key"]:
            items.sort(key=lambda i: (i.get(t["sort_key"]) is None, i.get(t["sort_key"])))
        if b.get("ScanIndexForward") is False:
            items.reverse()
    scanned = len(items)
    items, last = _paginate(t, items, b)
    flt = condition(b.get("FilterExpression"), names, values)
    if flt is not None:
        items = [i for i in items if evaluate(flt, i)]
    out = {"Count": len(items), "ScannedCount": scanned}
    if b.get("Select") != "COUNT":
        out["Items"] = [item_to_av(project(i, b.get("ProjectionExpression"), names)) for i in items]
    if last:
        out["LastEvaluatedKey"] = item_to_av(last)
    return out


def a_scan(c, b):
    return _read(c, b, query=False)


def a_query(c, b):
    return _read(c, b, query=True)


def a_batch_write(c, b):
    for table_name, reqs in (b.get("RequestItems") or {}).items():
        t = _table(c, table_name)
        for r in reqs:
            if "PutRequest" in r:
                put_item(c, t, item_from_av(r["PutRequest"]["Item"]))
            elif "DeleteRequest" in r:
                key = item_from_av(r["DeleteRequest"]["Key"])
                rid, _ = _find(c, t, key)
                if rid:
                    c.execute("DELETE FROM dynamodb_items WHERE id=?", (rid,))
    return {"UnprocessedItems": {}}


def a_batch_get(c, b):
    out = {}
    for table_name, spec in (b.get("RequestItems") or {}).items():
        t = _table(c, table_name)
        found = []
        for k in spec.get("Keys", []):
            _, item = _find(c, t, item_from_av(k))
            if item is not None:
                found.append(item_to_av(project(item, spec.get("ProjectionExpression"), spec.get("ExpressionAttributeNames"))))
        out[table_name] = found
    return {"Responses": out, "UnprocessedKeys": {}}


ACTIONS = {
    "CreateTable": a_create_table, "DescribeTable": a_describe_table, "ListTables": a_list_tables,
    "DeleteTable": a_delete_table, "PutItem": a_put_item, "GetItem": a_get_item, "DeleteItem": a_delete_item,
    "UpdateItem": a_update_item, "Scan": a_scan, "Query": a_query, "BatchWriteItem": a_batch_write,
    "BatchGetItem": a_batch_get,
}


def handle(c, action, body):
    fn = ACTIONS.get(action)
    if not fn:
        raise _err("UnknownOperationException", f"The DynamoDB operation '{action}' is not supported by the simulator. "
                   f"Supported: {', '.join(sorted(ACTIONS))}.")
    return fn(c, body)
