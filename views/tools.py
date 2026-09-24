"""Learning tools: activity log (console ↔ CLI), cost estimate and Terraform export."""

from __future__ import annotations

from flask import Blueprint, Response, render_template, request

import activity
import costs
import db
import terraform_export
from views import console_tx, done, with_db

bp = Blueprint("tools", __name__)


@bp.route("/activity")
@with_db
def activity_page(c):
    show_reads = request.args.get("reads") == "1"
    source = request.args.get("source", "")
    sql = "SELECT * FROM activity_log WHERE 1=1"
    args = []
    if not show_reads:
        sql += " AND readonly=0"
    if source in ("console", "cli"):
        sql += " AND source=?"
        args.append(source)
    rows = [dict(r) for r in c.execute(sql + " ORDER BY id DESC LIMIT 300", args)]
    for r in rows:
        r["simulated"] = activity.is_simulated(r["cli"])
    stats = {r["source"]: r["n"] for r in c.execute("SELECT source, COUNT(*) n FROM activity_log GROUP BY source")}
    return render_template("activity.html", rows=rows, show_reads=show_reads, source=source, stats=stats)


@bp.route("/activity/clear", methods=["POST"])
@console_tx(fail="/activity")
def clear_activity(c):
    c.execute("DELETE FROM activity_log")
    return done(c, "sim", "ClearActivity", "", "Activity log cleared.", target="/activity")


@bp.route("/costs")
@with_db
def costs_page(c):
    return render_template("costs.html", est=costs.estimate(c), region=db.region(c), as_of=costs.PRICES_AS_OF,
                           hours=costs.HOURS)


@bp.route("/export/terraform")
@with_db
def terraform_page(c):
    hcl = terraform_export.export(c)
    if request.args.get("download"):
        return Response(hcl, mimetype="text/plain", headers={"Content-Disposition": 'attachment; filename="main.tf"'})
    return render_template("terraform.html", hcl=hcl, lines=hcl.count("\n") + 1,
                           resources=hcl.count('resource "'))
