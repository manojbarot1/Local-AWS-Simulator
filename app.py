"""
Local AWS Simulator — application entry point.

    python3 app.py            # http://127.0.0.1:8080  (login demo / demo)

Environment variables
---------------------
SIM_DB                  path of the SQLite database (default: ./simulator.db)
SIM_HOST / SIM_PORT     bind address (default 127.0.0.1:8080)
SIM_ALLOWED_HOSTS       extra host names the app answers to (comma-separated)
SIM_DEBUG=1             Flask debug mode with auto-reload
SIM_AUTOLOGIN=1         skip the demo sign-in (kiosk / screenshots)
SIM_TRANSITION_SECONDS  EC2 pending/stopping duration (default 5)
SIM_LAMBDA_EXEC=0       never execute Lambda code; always simulate
"""

from __future__ import annotations

import json
import os
import secrets
from urllib.parse import urlsplit

from flask import Flask, Response, abort, redirect, request, session, url_for

import aws_api
import db
import ec2model
import labs

BASE = os.path.dirname(os.path.abspath(__file__))
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _secret_key():
    """Stable per-install key so sessions survive restarts; never committed."""
    if os.environ.get("SIM_SECRET_KEY"):
        return os.environ["SIM_SECRET_KEY"]
    path = os.path.join(BASE, ".secret_key")
    try:
        with open(path) as fh:
            key = fh.read().strip()
            if key:
                return key
    except OSError:
        pass
    key = secrets.token_hex(32)
    try:
        with open(path, "w") as fh:
            fh.write(key)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def _host_name(netloc):
    """'localhost:8080' -> 'localhost', '[::1]:8080' -> '[::1]'."""
    netloc = netloc.lower()
    if netloc.startswith("["):
        return netloc.split("]")[0] + "]"
    return netloc.split(":")[0] if netloc.count(":") <= 1 else netloc


def create_app(db_path=None, testing=False):
    if db_path:
        db.DB_PATH = db_path
    db.init()

    app = Flask(__name__)
    app.secret_key = "test-key" if testing else _secret_key()
    app.config.update(TESTING=testing, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_HTTPONLY=True,
                      MAX_CONTENT_LENGTH=200 * 1024 * 1024)
    extra = {h.strip().lower() for h in os.environ.get("SIM_ALLOWED_HOSTS", "").split(",") if h.strip()}
    allowed_hosts = LOCAL_HOSTS | extra | ({os.environ["SIM_HOST"].lower()} if os.environ.get("SIM_HOST") else set())
    autologin = os.environ.get("SIM_AUTOLOGIN") == "1"

    app.jinja_env.filters["fromjson"] = lambda s: json.loads(s or "[]") if isinstance(s, str) else (s or [])

    from views import compute, core, labs as labs_views, network, services, snapshots, tools
    for module in (core, network, compute, labs_views, snapshots, tools, services):
        app.register_blueprint(module.bp)

    @app.before_request
    def guard():
        # 1. Only answer to local host names: defeats DNS-rebinding attacks from
        #    web pages that point their own domain at 127.0.0.1.
        if "*" not in allowed_hosts and _host_name(request.host) not in allowed_hosts:
            abort(403, "Host not allowed. Set SIM_ALLOWED_HOSTS to serve other host names.")
        # 2. Refuse cross-site state changes. Browsers always send Origin on
        #    cross-origin POSTs; the aws CLI and SDKs never do.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("Origin") or request.headers.get("Referer")
            if origin and origin != "null" and urlsplit(origin).netloc != request.host:
                abort(403, "Cross-site request refused.")
            if origin == "null":
                abort(403, "Cross-site request refused.")
        if aws_api.is_aws_api_request(request):
            return None  # the API is unauthenticated, like every local emulator
        if request.endpoint in ("core.login", "static"):
            return None
        if autologin:
            session["user"] = "demo"
        if session.get("user") != "demo":
            return redirect(url_for("core.login"))
        c = db.connect()
        try:
            ec2model.advance(c)
            c.commit()
        finally:
            c.close()
        return None

    @app.route("/aws", defaults={"api_path": ""}, methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
    @app.route("/aws/<path:api_path>", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
    def aws_endpoint(api_path):
        """AWS-compatible endpoint for the real ``aws`` CLI and boto3:
        ``--endpoint-url http://localhost:8080/aws``."""
        body, status, headers = aws_api.handle(request)
        return Response(body, status=status, headers=headers)

    @app.context_processor
    def inject_globals():
        if session.get("user") != "demo" or request.path.startswith("/aws"):
            return {"lab_progress": None}
        c = db.connect()
        try:
            results = labs.evaluate_all(c)
            return {"lab_progress": {"done": sum(1 for r in results.values() if r["complete"]), "total": len(results)},
                    "region": db.region(c)}
        finally:
            c.close()

    @app.errorhandler(403)
    def forbidden(err):
        return Response(f"403 Forbidden: {getattr(err, 'description', '')}", status=403, mimetype="text/plain")

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host=os.environ.get("SIM_HOST", "127.0.0.1"), port=int(os.environ.get("SIM_PORT", "8080")),
                    debug=os.environ.get("SIM_DEBUG") == "1")
