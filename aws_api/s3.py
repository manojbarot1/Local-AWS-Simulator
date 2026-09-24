"""
S3 over its REST/XML protocol (path-style: ``/aws/<bucket>/<key>``).

Covers what ``aws s3`` (cp/sync/ls/rm/mb/rb/mv) and the common ``aws s3api``
calls need: buckets, objects, ListObjects v1/v2 with prefixes, delimiters and
pagination, multipart uploads (``aws s3 cp`` uses them above 8 MB), batch
delete, server-side copy and bucket versioning. It shares tables with the S3
console, so objects uploaded either way appear in both.
"""

from __future__ import annotations

import base64
import hashlib
import re
import uuid
from urllib.parse import unquote
from xml.sax.saxutils import unescape

import db
from errors import SimError

from .common import el, x, iso, req_id

S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"
XMLH = {"Content-Type": "application/xml"}
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")

# In-flight multipart uploads: upload_id -> {"bucket", "key", "parts", "content_type"}.
_UPLOADS: dict[str, dict] = {}


def validate_bucket_name(name):
    if not BUCKET_RE.match(name or "") or ".." in name or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", name):
        raise SimError("InvalidBucketName", "The specified bucket is not valid. Bucket names are 3-63 characters of "
                       "lowercase letters, numbers, dots and hyphens, and must start and end with a letter or number.")


def body_bytes(value):
    if value is None:
        return b""
    return value if isinstance(value, bytes) else str(value).encode("utf-8")


def etag(data):
    return hashlib.md5(data).hexdigest()


def _xml(root, inner, status=200, headers=None):
    return (f'<?xml version="1.0" encoding="UTF-8"?><{root} xmlns="{S3_NS}">{inner}</{root}>',
            status, {**XMLH, **(headers or {})})


def error(err, resource="/"):
    status = err.status
    if err.code in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
        status = 404
    elif err.code in ("BucketNotEmpty", "BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
        status = 409
    return (f'<?xml version="1.0" encoding="UTF-8"?><Error>{el("Code", err.code)}{el("Message", err.message)}'
            f'{el("Resource", resource)}{el("RequestId", req_id())}</Error>', status, XMLH)


def _parts(request):
    relative = request.path[len("/aws"):].lstrip("/")
    bucket, _, key = relative.partition("/")
    return bucket, unquote(key)


def _bucket(c, name):
    row = c.execute("SELECT * FROM s3_buckets WHERE name=?", (name,)).fetchone()
    if row is None:
        raise SimError("NoSuchBucket", "The specified bucket does not exist")
    return row


def create_bucket(c, name, region=None, versioning=False, public=False, encryption="SSE-S3"):
    validate_bucket_name(name)
    if c.execute("SELECT 1 FROM s3_buckets WHERE name=?", (name,)).fetchone():
        raise SimError("BucketAlreadyOwnedByYou",
                       "Your previous request to create the named bucket succeeded and you already own it.", 409)
    c.execute("INSERT INTO s3_buckets(name,region,versioning,public,encryption,created_at) VALUES(?,?,?,?,?,?)",
              (name, region or db.region(c), int(bool(versioning)), int(bool(public)), encryption, db.now()))


def put_object(c, bucket, key, data, content_type="binary/octet-stream", storage_class="STANDARD"):
    """Create or overwrite (S3 has exactly one current object per key)."""
    c.execute("""INSERT INTO s3_objects(bucket_id,key,size_bytes,content_type,storage_class,body,created_at)
                 VALUES(?,?,?,?,?,?,?)
                 ON CONFLICT(bucket_id,key) DO UPDATE SET size_bytes=excluded.size_bytes,
                   content_type=excluded.content_type, storage_class=excluded.storage_class,
                   body=excluded.body, created_at=excluded.created_at""",
              (bucket["id"], key, len(data), content_type, storage_class or "STANDARD", data, db.now()))


def _objects(c, bucket, prefix):
    rows = c.execute("SELECT id, key, size_bytes, storage_class, created_at, body FROM s3_objects "
                     "WHERE bucket_id=? AND substr(key,1,?)=? ORDER BY key",
                     (bucket["id"], len(prefix), prefix)).fetchall()
    return rows


def _list(c, bucket, args, v2):
    prefix = args.get("prefix", "")
    delimiter = args.get("delimiter", "")
    try:
        max_keys = max(0, min(1000, int(args.get("max-keys", 1000))))
    except ValueError:
        raise SimError("InvalidArgument", "max-keys must be an integer")
    if v2:
        token = args.get("continuation-token")
        start = base64.urlsafe_b64decode(token.encode()).decode() if token else args.get("start-after", "")
    else:
        start = args.get("marker", "")
    contents, prefixes, seen = [], [], set()
    truncated, last = False, None
    for r in _objects(c, bucket, prefix):
        key = r["key"]
        if start and key <= start:
            continue
        if delimiter:
            rest = key[len(prefix):]
            if delimiter in rest:
                cp = prefix + rest.split(delimiter, 1)[0] + delimiter
                if cp in seen or (start and cp <= start):
                    continue
                if len(contents) + len(prefixes) >= max_keys:
                    truncated = True
                    break
                seen.add(cp)
                prefixes.append(cp)
                last = cp
                continue
        if len(contents) + len(prefixes) >= max_keys:
            truncated = True
            break
        contents.append(r)
        last = key
    items = "".join(
        f"<Contents>{el('Key', r['key'])}{el('LastModified', iso(r['created_at']))}"
        f"<ETag>&quot;{etag(body_bytes(r['body']))}&quot;</ETag>{el('Size', r['size_bytes'])}"
        f"{el('StorageClass', r['storage_class'] or 'STANDARD')}</Contents>" for r in contents)
    items += "".join(f"<CommonPrefixes>{el('Prefix', p)}</CommonPrefixes>" for p in prefixes)
    head = f"{el('Name', bucket['name'])}{el('Prefix', prefix)}{el('MaxKeys', max_keys)}"
    if delimiter:
        head += el("Delimiter", delimiter)
    head += el("IsTruncated", "true" if truncated else "false")
    if v2:
        head += el("KeyCount", len(contents) + len(prefixes))
        if args.get("continuation-token"):
            head += el("ContinuationToken", args["continuation-token"])
        if truncated and last:
            head += el("NextContinuationToken", base64.urlsafe_b64encode(last.encode()).decode())
        if args.get("start-after"):
            head += el("StartAfter", args["start-after"])
    else:
        head += el("Marker", start)
        if truncated and last:
            head += el("NextMarker", last)
    return _xml("ListBucketResult", head + items)


def _list_buckets(c):
    rows = c.execute("SELECT * FROM s3_buckets ORDER BY name").fetchall()
    buckets = "".join(f"<Bucket>{el('Name', r['name'])}{el('CreationDate', iso(r['created_at']))}</Bucket>" for r in rows)
    return _xml("ListAllMyBucketsResult", f"<Owner><ID>000000000000</ID><DisplayName>local</DisplayName></Owner>"
                f"<Buckets>{buckets}</Buckets>")


def _delete_objects(c, bucket, body):
    keys = [unescape(k, {"&quot;": '"', "&apos;": "'"}) for k in re.findall(r"<Key>(.*?)</Key>", body, re.S)]
    quiet = "<Quiet>true</Quiet>" in body
    out = ""
    for key in keys:
        c.execute("DELETE FROM s3_objects WHERE bucket_id=? AND key=?", (bucket["id"], key))
        if not quiet:
            out += f"<Deleted>{el('Key', key)}</Deleted>"
    return _xml("DeleteResult", out)


def handle(c, request):
    """Returns (action, (body, status, headers))."""
    bucket_name, key = _parts(request)
    m, args = request.method, request.args
    resource = f"/{bucket_name}" + (f"/{key}" if key else "")
    if key:
        action = {"GET": "GetObject", "PUT": "PutObject", "DELETE": "DeleteObject", "HEAD": "HeadObject"}.get(m, m)
    elif bucket_name:
        action = {"GET": "ListObjects", "PUT": "CreateBucket", "DELETE": "DeleteBucket", "HEAD": "HeadBucket"}.get(m, m)
    else:
        action = "ListBuckets"
    try:
        if not bucket_name:
            if m == "GET":
                return action, _list_buckets(c)
            raise SimError("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)

        if not key:
            if m == "PUT" and "versioning" in args:
                action = "PutBucketVersioning"
                bucket = _bucket(c, bucket_name)
                status = re.search(r"<Status>(\w+)</Status>", request.get_data(as_text=True) or "")
                c.execute("UPDATE s3_buckets SET versioning=? WHERE id=?",
                          (1 if status and status.group(1) == "Enabled" else 0, bucket["id"]))
                return action, ("", 200, {})
            if m == "PUT":
                action = "CreateBucket"
                body = request.get_data(cache=True, as_text=True) or ""
                loc = re.search(r"<LocationConstraint[^>]*>([^<]+)</LocationConstraint>", body)
                create_bucket(c, bucket_name, loc.group(1) if loc else None)
                return action, ("", 200, {"Location": f"/{bucket_name}"})
            bucket = _bucket(c, bucket_name)
            if m == "DELETE":
                action = "DeleteBucket"
                if c.execute("SELECT 1 FROM s3_objects WHERE bucket_id=? LIMIT 1", (bucket["id"],)).fetchone():
                    raise SimError("BucketNotEmpty", "The bucket you tried to delete is not empty")
                c.execute("DELETE FROM s3_buckets WHERE id=?", (bucket["id"],))
                return action, ("", 204, {})
            if m == "HEAD":
                return "HeadBucket", ("", 200, {"x-amz-bucket-region": bucket["region"] or db.region(c)})
            if m == "POST" and "delete" in args:
                return "DeleteObjects", _delete_objects(c, bucket, request.get_data(as_text=True) or "")
            if m == "GET":
                if "location" in args:
                    region = bucket["region"] or db.region(c)
                    return "GetBucketLocation", _xml("LocationConstraint", x("" if region == "us-east-1" else region))
                if "versioning" in args:
                    status = el("Status", "Enabled") if bucket["versioning"] else ""
                    return "GetBucketVersioning", _xml("VersioningConfiguration", status)
                if "uploads" in args:
                    return "ListMultipartUploads", _xml("ListMultipartUploadsResult", el("Bucket", bucket_name))
                for unsupported in ("policy", "acl", "tagging", "cors", "website", "lifecycle", "encryption",
                                    "logging", "notification", "replication", "ownershipControls", "publicAccessBlock"):
                    if unsupported in args:
                        raise SimError("NotImplemented", f"Bucket {unsupported} configuration is not simulated.", 501)
                v2 = args.get("list-type") == "2"
                return ("ListObjectsV2" if v2 else "ListObjects"), _list(c, bucket, args, v2)
            raise SimError("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)

        bucket = _bucket(c, bucket_name)
        # Multipart uploads.
        if m == "POST" and "uploads" in args:
            upload_id = uuid.uuid4().hex
            _UPLOADS[upload_id] = {"bucket": bucket_name, "key": key, "parts": {},
                                   "content_type": request.headers.get("Content-Type", "binary/octet-stream")}
            return "CreateMultipartUpload", _xml("InitiateMultipartUploadResult",
                                                 el("Bucket", bucket_name) + el("Key", key) + el("UploadId", upload_id))
        if "uploadId" in args:
            upload = _UPLOADS.get(args["uploadId"])
            if not upload or upload["bucket"] != bucket_name or upload["key"] != key:
                raise SimError("NoSuchUpload", "The specified multipart upload does not exist.")
            if m == "PUT":
                data = request.get_data(cache=False)
                upload["parts"][int(args.get("partNumber", 1))] = data
                return "UploadPart", ("", 200, {"ETag": f'"{etag(data)}"'})
            if m == "DELETE":
                _UPLOADS.pop(args["uploadId"], None)
                return "AbortMultipartUpload", ("", 204, {})
            if m == "POST":
                parts = [upload["parts"][n] for n in sorted(upload["parts"])]
                data = b"".join(parts)
                put_object(c, bucket, key, data, upload["content_type"])
                _UPLOADS.pop(args["uploadId"], None)
                tag = hashlib.md5(b"".join(hashlib.md5(p).digest() for p in parts)).hexdigest() + f"-{len(parts)}"
                return "CompleteMultipartUpload", _xml("CompleteMultipartUploadResult",
                                                       el("Bucket", bucket_name) + el("Key", key) + f"<ETag>&quot;{tag}&quot;</ETag>")
            if m == "GET":
                items = "".join(f"<Part>{el('PartNumber', n)}<ETag>&quot;{etag(d)}&quot;</ETag>{el('Size', len(d))}</Part>"
                                for n, d in sorted(upload["parts"].items()))
                return "ListParts", _xml("ListPartsResult", el("Bucket", bucket_name) + el("Key", key) + items)

        if m == "PUT":
            source = request.headers.get("x-amz-copy-source")
            if source:
                src_bucket, _, src_key = unquote(source.split("?")[0]).lstrip("/").partition("/")
                sb = _bucket(c, src_bucket)
                row = c.execute("SELECT * FROM s3_objects WHERE bucket_id=? AND key=?", (sb["id"], src_key)).fetchone()
                if not row:
                    raise SimError("NoSuchKey", "The specified key does not exist.")
                data = body_bytes(row["body"])
                put_object(c, bucket, key, data, row["content_type"], row["storage_class"])
                return "CopyObject", _xml("CopyObjectResult", el("LastModified", iso(db.now())) +
                                          f"<ETag>&quot;{etag(data)}&quot;</ETag>")
            data = request.get_data(cache=False)
            put_object(c, bucket, key, data, request.headers.get("Content-Type", "binary/octet-stream"),
                       request.headers.get("x-amz-storage-class", "STANDARD"))
            return "PutObject", ("", 200, {"ETag": f'"{etag(data)}"'})

        row = c.execute("SELECT * FROM s3_objects WHERE bucket_id=? AND key=?", (bucket["id"], key)).fetchone()
        if m == "DELETE":
            # Deleting a missing key succeeds in S3.
            if row:
                c.execute("DELETE FROM s3_objects WHERE id=?", (row["id"],))
            return "DeleteObject", ("", 204, {})
        if row is None:
            raise SimError("NoSuchKey", "The specified key does not exist.")
        if m in ("GET", "HEAD"):
            # Return the real body even for HEAD: Werkzeug strips it while
            # keeping Content-Length, so head-object reports the right size.
            data = body_bytes(row["body"])
            return ("GetObject" if m == "GET" else "HeadObject"), (data, 200, {
                "Content-Type": row["content_type"] or "binary/octet-stream",
                "Content-Length": str(len(data)), "ETag": f'"{etag(data)}"',
                "Last-Modified": _http_date(row["created_at"]),
                "x-amz-storage-class": row["storage_class"] or "STANDARD"})
        raise SimError("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)
    except SimError as err:
        return action, error(err, resource)


def _http_date(ts):
    from datetime import datetime, timezone
    from email.utils import format_datetime
    try:
        dt = datetime.fromisoformat(str(ts)).astimezone(timezone.utc)
    except ValueError:
        dt = datetime.now(timezone.utc)
    return format_datetime(dt, usegmt=True)
