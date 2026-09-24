"""Web console: every page renders, domain errors become banners (not 500s),
console actions record their CLI equivalent, snapshots round-trip."""

import io
import json
import re

import pytest

import db

PAGES = ["/dashboard", "/organization", "/ous", "/accounts", "/policies", "/validation", "/architecture",
         "/network", "/network/reachability", "/compute", "/compute/launch", "/labs", "/labs/1", "/labs/17",
         "/s3", "/iam", "/lambda", "/dynamodb", "/secrets", "/snapshots", "/activity", "/activity?reads=1",
         "/costs", "/export/terraform", "/search?q=default"]


def test_login_required(app):
    anon = app.test_client()
    assert anon.get("/dashboard").status_code == 302
    r = anon.post("/login", data={"username": "demo", "password": "demo"})
    assert r.status_code == 302 and anon.get("/dashboard").status_code == 200


@pytest.mark.parametrize("path", PAGES)
def test_page_renders(client, path):
    r = client.get(path)
    assert r.status_code == 200, r.get_data(as_text=True)[:500]


def flashes(client):
    with client.session_transaction() as s:
        return [m for _, m in s.get("_flashes", [])]


def vpc_row(name):
    c = db.connect()
    try:
        return c.execute("SELECT * FROM vpcs WHERE name=?", (name,)).fetchone()
    finally:
        c.close()


def test_invalid_input_is_a_banner_not_a_500(client):
    for url, data in [("/network/vpc/create", {"name": "x", "cidr": "banana"}),
                      ("/network/subnet/create", {"name": "x", "cidr": "10.0.0.0/24"}),
                      ("/lambda/create", {"name": "fn", "runtime": "python3.12", "memory_mb": "abc"}),
                      ("/network/nat/create", {"name": "n"}),
                      ("/s3/create", {"name": "Bad_Name"})]:
        r = client.post(url, data=data)
        assert r.status_code == 302, url
    msgs = " ".join(flashes(client))
    for code in ("InvalidParameterValue", "InvalidSubnetID.NotFound", "InvalidBucketName"):
        assert code in msgs


def test_console_create_shows_cli_equivalent_and_logs_it(client):
    client.post("/network/vpc/create", data={"name": "prod", "cidr": "10.20.0.0/16", "dns_support": "on"})
    msgs = flashes(client)
    assert any(m.startswith("aws ec2 create-vpc --cidr-block 10.20.0.0/16") for m in msgs)
    page = client.get("/activity").get_data(as_text=True)
    assert "CreateVpc" in page and "Console" in page


def test_dependency_violation_in_console(client):
    client.post("/network/vpc/create", data={"name": "prod", "cidr": "10.20.0.0/16"})
    vpc = vpc_row("prod")
    client.post("/network/subnet/create", data={"name": "a", "vpc_id": vpc["id"], "cidr": "10.20.1.0/24"})
    client.post(f"/network/delete/vpc/{vpc['id']}")
    assert any("DependencyViolation" in m for m in flashes(client))
    assert vpc_row("prod") is not None


def test_public_subnet_wiring_in_console(client):
    client.post("/network/vpc/create", data={"name": "prod", "cidr": "10.20.0.0/16"})
    vpc = vpc_row("prod")
    client.post("/network/subnet/create", data={"name": "pub", "vpc_id": vpc["id"], "cidr": "10.20.1.0/24", "map_public_ip": "on"})
    client.post("/network/igw/create", data={"name": "igw", "vpc_id": vpc["id"]})
    c = db.connect()
    sub = c.execute("SELECT id FROM subnets WHERE name='pub'").fetchone()["id"]
    c.close()
    client.post("/network/route-table/create", data={"name": "public-rt", "vpc_id": vpc["id"],
                                                     "routes": "0.0.0.0/0 -> igw", "subnet_ids": [sub]})
    page = client.get("/network").get_data(as_text=True)
    assert re.search(r"<b>pub</b>.*?badge green\">Public", page, re.S)


def test_s3_console_overwrites_same_key_and_blocks_non_empty_delete(client):
    client.post("/s3/create", data={"name": "assets"})
    c = db.connect()
    bid = c.execute("SELECT id FROM s3_buckets WHERE name='assets'").fetchone()["id"]
    c.close()
    for body in ("one", "two"):
        client.post(f"/s3/{bid}/object/create", data={"key": "dup.txt", "body": body})
    client.post(f"/s3/{bid}/object/create", data={"key": "bin.dat", "file": (io.BytesIO(b"\x00\x01"), "bin.dat")},
                content_type="multipart/form-data")
    c = db.connect()
    rows = c.execute("SELECT key, body FROM s3_objects WHERE bucket_id=? ORDER BY key", (bid,)).fetchall()
    c.close()
    assert [(r["key"], bytes(r["body"]) if isinstance(r["body"], bytes) else r["body"].encode()) for r in rows] == \
        [("bin.dat", b"\x00\x01"), ("dup.txt", b"two")]
    client.post(f"/s3/{bid}/delete")
    assert any("BucketNotEmpty" in m for m in flashes(client))


def test_lambda_console_executes_python(client):
    client.post("/lambda/create", data={"name": "hello", "runtime": "python3.12", "memory_mb": "256",
                                        "handler": "lambda_function.lambda_handler"})
    c = db.connect()
    fid = c.execute("SELECT id FROM lambda_functions WHERE name='hello'").fetchone()["id"]
    c.close()
    page = client.post(f"/lambda/{fid}/invoke", data={"payload": '{"x": 1}'}).get_data(as_text=True)
    assert "Hello from hello" in page and "REPORT RequestId" in page and "Received event" in page


def test_secret_reveal_is_logged(client):
    client.post("/secrets/create", data={"name": "prod/db/password", "secret_value": "s3cret", "rotation_enabled": "on"})
    c = db.connect()
    sid = c.execute("SELECT id FROM secrets").fetchone()["id"]
    c.close()
    assert "s3cret" in client.get(f"/secrets?reveal={sid}").get_data(as_text=True)
    assert "GetSecretValue" in client.get("/activity?reads=1").get_data(as_text=True)


def test_snapshot_round_trip_with_binary_objects(client, aws):
    s3 = aws("s3")
    s3.create_bucket(Bucket="raw", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    s3.put_object(Bucket="raw", Key="b.bin", Body=b"\xff\x00binary")
    client.post("/snapshots/create", data={"name": "baseline"})
    client.post("/reset")
    assert s3.list_buckets()["Buckets"] == []
    c = db.connect()
    sid = c.execute("SELECT id FROM snapshots WHERE name='baseline'").fetchone()["id"]
    c.close()
    exported = client.get(f"/snapshots/{sid}/export")
    assert exported.status_code == 200 and json.loads(exported.data)["state"]["s3_objects"]
    client.post(f"/snapshots/{sid}/restore")
    assert s3.get_object(Bucket="raw", Key="b.bin")["Body"].read() == b"\xff\x00binary"
    # Import the exported file back as a new snapshot.
    client.post("/snapshots/import", data={"snapshot": (io.BytesIO(exported.data), "baseline.json")},
                content_type="multipart/form-data")
    c = db.connect()
    assert c.execute("SELECT COUNT(*) FROM snapshots WHERE name LIKE 'Imported%'").fetchone()[0] == 1
    c.close()


def test_reset_recreates_default_vpc(client):
    client.post("/network/vpc/create", data={"name": "prod", "cidr": "10.20.0.0/16"})
    client.post("/reset")
    c = db.connect()
    vpcs = c.execute("SELECT name, is_default FROM vpcs").fetchall()
    subnets = c.execute("SELECT COUNT(*) FROM subnets").fetchone()[0]
    c.close()
    assert [(v["name"], v["is_default"]) for v in vpcs] == [("default", 1)] and subnets == 3


def test_instance_launch_from_console(client):
    r = client.post("/compute/launch", data={"name": "web", "ami_id": "ami-0e001c9271cf7f3b9",
                                             "instance_type": "t3.small", "encrypted": "on"})
    assert r.status_code == 302
    iid = r.headers["Location"].rsplit("/", 1)[-1]
    page = client.get(f"/compute/instance/{iid}").get_data(as_text=True)
    assert "Public subnet" in page and "default" in page
    bad = client.post("/compute/launch", data={"name": "x", "ami_id": "ami-bogus", "instance_type": "t3.small"})
    assert bad.status_code == 200 and "InvalidAMIID.NotFound" in bad.get_data(as_text=True)
