"""Test fixtures: a fresh simulator per test, served on a real HTTP port so the
tests drive it with genuine boto3 clients — the same wire protocols the aws CLI
uses — plus a logged-in Flask test client for the console."""

from __future__ import annotations

import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import boto3  # noqa: E402
from botocore.config import Config  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

import app as app_module  # noqa: E402
import ec2model  # noqa: E402


@pytest.fixture
def app(tmp_path):
    ec2model.TRANSITION_SECONDS = 0
    return app_module.create_app(str(tmp_path / "sim.db"), testing=True)


@pytest.fixture
def client(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["user"] = "demo"
    return c


@pytest.fixture
def server(app):
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}/aws"
    srv.shutdown()


@pytest.fixture
def aws(server):
    """Factory: aws("ec2") -> boto3 client pointed at the simulator."""
    def make(service):
        return boto3.client(service, endpoint_url=server, region_name="eu-central-1",
                            aws_access_key_id="test", aws_secret_access_key="test",
                            config=Config(retries={"max_attempts": 1}, s3={"addressing_style": "path"}))
    return make


def error_code(exc_info):
    return exc_info.value.response["Error"]["Code"]
