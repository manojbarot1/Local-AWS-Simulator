"""Backup & Restore: named snapshots of the whole simulator state."""

from __future__ import annotations

import json
import os
import re

from flask import Blueprint, Response, flash, redirect, render_template, request, url_for

import db
from errors import SimError
from views import console_tx, done, with_db

bp = Blueprint("snapshots", __name__)


@bp.route("/snapshots")
@with_db
def snapshots(c):
    snaps = [dict(x) for x in c.execute("SELECT id,name,created_at,length(state_json) size FROM snapshots ORDER BY id DESC")]
    return render_template("snapshots.html", snapshots=snaps)


@bp.route("/snapshots/create", methods=["POST"])
@console_tx(fail="/snapshots")
def create_snapshot(c):
    name = request.form.get("name", "").strip() or "Untitled Snapshot"
    c.execute("INSERT INTO snapshots(name,created_at,state_json) VALUES(?,?,?)",
              (name, db.now(), json.dumps(db.dump_state(c))))
    return done(c, "sim", "CreateSnapshot", name, f"Snapshot '{name}' saved.", target=url_for("snapshots.snapshots"))


@bp.route("/snapshots/<int:sid>/restore", methods=["POST"])
@console_tx(fail="/snapshots")
def restore_snapshot(c, sid):
    row = c.execute("SELECT name,state_json FROM snapshots WHERE id=?", (sid,)).fetchone()
    if not row:
        raise SimError("NotFound", "Snapshot not found.")
    # Safety backup of the current state before replacing it.
    c.execute("INSERT INTO snapshots(name,created_at,state_json) VALUES(?,?,?)",
              (f"Auto-backup before restore: {row['name']}", db.now(), json.dumps(db.dump_state(c))))
    db.load_state(c, json.loads(row["state_json"]))
    return done(c, "sim", "RestoreSnapshot", row["name"], f"Restored '{row['name']}'. The previous state was backed up.",
                target=url_for("snapshots.snapshots"))


@bp.route("/snapshots/<int:sid>/delete", methods=["POST"])
@console_tx(fail="/snapshots")
def delete_snapshot(c, sid):
    c.execute("DELETE FROM snapshots WHERE id=?", (sid,))
    return redirect(url_for("snapshots.snapshots"))


@bp.route("/snapshots/<int:sid>/export")
@with_db
def export_snapshot(c, sid):
    row = c.execute("SELECT name,created_at,state_json FROM snapshots WHERE id=?", (sid,)).fetchone()
    if not row:
        return "Snapshot not found", 404
    payload = {"format": "local-aws-simulator-snapshot", "version": 2, "name": row[0], "created_at": row[1],
               "state": json.loads(row[2])}
    filename = re.sub(r"[^A-Za-z0-9._-]+", "_", row[0]).strip("_") or "snapshot"
    return Response(json.dumps(payload, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{filename}.json"'})


@bp.route("/snapshots/import", methods=["POST"])
@console_tx(fail="/snapshots")
def import_snapshot(c):
    f = request.files.get("snapshot")
    if not f or not f.filename:
        return redirect(url_for("snapshots.snapshots"))
    try:
        payload = json.load(f)
        state = payload["state"]
        if not isinstance(state, dict) or not all(isinstance(v, list) for v in state.values()):
            raise ValueError("'state' must map table names to lists of rows")
    except (ValueError, KeyError, TypeError) as exc:
        flash(f"Invalid snapshot file: {exc}", "error")
        return redirect(url_for("snapshots.snapshots"))
    name = payload.get("name") or os.path.splitext(f.filename)[0]
    # Store it as a snapshot; restoring is a separate, explicit step.
    c.execute("INSERT INTO snapshots(name,created_at,state_json) VALUES(?,?,?)",
              (f"Imported - {name}", db.now(), json.dumps(state)))
    return done(c, "sim", "ImportSnapshot", name, f"Imported '{name}'. Restore it when you're ready.",
                target=url_for("snapshots.snapshots"))
