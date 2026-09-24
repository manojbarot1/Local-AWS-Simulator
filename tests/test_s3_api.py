"""S3 through real boto3: buckets, listing semantics, multipart, copy, batch delete."""

import io

import pytest
from boto3.s3.transfer import TransferConfig
from botocore.exceptions import ClientError

from conftest import error_code


@pytest.fixture
def s3(aws):
    return aws("s3")


def test_bucket_lifecycle_and_errors(s3):
    s3.create_bucket(Bucket="data", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    assert [b["Name"] for b in s3.list_buckets()["Buckets"]] == ["data"]
    assert s3.get_bucket_location(Bucket="data")["LocationConstraint"] == "eu-central-1"
    with pytest.raises(ClientError) as e:
        s3.create_bucket(Bucket="data", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    assert error_code(e) == "BucketAlreadyOwnedByYou"
    with pytest.raises(ClientError) as e:
        s3.create_bucket(Bucket="Bad_Name", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    assert error_code(e) == "InvalidBucketName"
    s3.put_object(Bucket="data", Key="a.txt", Body=b"x")
    with pytest.raises(ClientError) as e:
        s3.delete_bucket(Bucket="data")
    assert error_code(e) == "BucketNotEmpty"
    s3.delete_object(Bucket="data", Key="a.txt")
    s3.delete_bucket(Bucket="data")
    with pytest.raises(ClientError) as e:
        s3.head_bucket(Bucket="data")
    assert e.value.response["Error"]["Code"] in ("404", "NoSuchBucket")


def test_objects_overwrite_and_metadata(s3):
    s3.create_bucket(Bucket="bucket-one", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    s3.put_object(Bucket="bucket-one", Key="k", Body=b"one", ContentType="text/plain")
    s3.put_object(Bucket="bucket-one", Key="k", Body=b"second")
    assert s3.list_objects_v2(Bucket="bucket-one")["KeyCount"] == 1
    obj = s3.get_object(Bucket="bucket-one", Key="k")
    assert obj["Body"].read() == b"second"
    head = s3.head_object(Bucket="bucket-one", Key="k")
    assert head["ContentLength"] == 6 and head["ETag"] == '"a9f0e61a137d86aa9db53465e0801612"'
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket="bucket-one", Key="missing")
    assert error_code(e) == "NoSuchKey"


def test_prefix_delimiter_and_pagination(s3):
    s3.create_bucket(Bucket="lake", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    for key in ["a/1.txt", "a/2.txt", "b/1.txt", "a_x", "abx", "top.txt"]:
        s3.put_object(Bucket="lake", Key=key, Body=b"-")
    listing = s3.list_objects_v2(Bucket="lake", Delimiter="/")
    assert [p["Prefix"] for p in listing["CommonPrefixes"]] == ["a/", "b/"]
    assert [o["Key"] for o in listing["Contents"]] == ["a_x", "abx", "top.txt"]
    # '_' is not a wildcard.
    assert [o["Key"] for o in s3.list_objects_v2(Bucket="lake", Prefix="a_")["Contents"]] == ["a_x"]
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket="lake", PaginationConfig={"PageSize": 2}):
        keys += [o["Key"] for o in page.get("Contents", [])]
    assert keys == sorted(["a/1.txt", "a/2.txt", "b/1.txt", "a_x", "abx", "top.txt"])
    v1 = s3.list_objects(Bucket="lake", Prefix="a/")
    assert [o["Key"] for o in v1["Contents"]] == ["a/1.txt", "a/2.txt"]


def test_multipart_copy_and_batch_delete(s3):
    s3.create_bucket(Bucket="big", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    data = bytes(range(256)) * 50_000      # 12.8 MB -> multipart with 5 MB parts
    s3.upload_fileobj(io.BytesIO(data), "big", "blob.bin",
                      Config=TransferConfig(multipart_threshold=5 * 1024 * 1024, multipart_chunksize=5 * 1024 * 1024))
    assert s3.head_object(Bucket="big", Key="blob.bin")["ContentLength"] == len(data)
    assert s3.get_object(Bucket="big", Key="blob.bin")["Body"].read() == data
    s3.copy_object(Bucket="big", Key="copy.bin", CopySource={"Bucket": "big", "Key": "blob.bin"})
    assert s3.head_object(Bucket="big", Key="copy.bin")["ContentLength"] == len(data)
    out = s3.delete_objects(Bucket="big", Delete={"Objects": [{"Key": "blob.bin"}, {"Key": "copy.bin"}]})
    assert sorted(d["Key"] for d in out["Deleted"]) == ["blob.bin", "copy.bin"]
    assert s3.list_objects_v2(Bucket="big")["KeyCount"] == 0


def test_versioning_configuration(s3):
    s3.create_bucket(Bucket="versioned", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    assert "Status" not in s3.get_bucket_versioning(Bucket="versioned")
    s3.put_bucket_versioning(Bucket="versioned", VersioningConfiguration={"Status": "Enabled"})
    assert s3.get_bucket_versioning(Bucket="versioned")["Status"] == "Enabled"
