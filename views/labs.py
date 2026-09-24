"""Training labs: learning path overview and per-lab step feedback."""

from __future__ import annotations

from flask import Blueprint, render_template

import labs
from views import with_db

bp = Blueprint("labs", __name__)


@bp.route("/labs")
@with_db
def labs_home(c):
    results = labs.evaluate_all(c)
    by_cat = {}
    for lab in labs.LABS:
        r = results[lab["id"]]
        by_cat.setdefault(lab["category"], []).append(dict(lab, complete=r["complete"], done_steps=r["done"],
                                                            total_steps=r["total"]))
    groups = []
    for name, desc in labs.LAB_CATEGORIES:
        items = by_cat.get(name, [])
        if items:
            groups.append({"name": name, "desc": desc, "labs": items,
                           "done": sum(1 for x in items if x["complete"]), "total": len(items)})
    done = sum(g["done"] for g in groups)
    return render_template("labs.html", groups=groups, done=done, total=len(labs.LABS))


@bp.route("/labs/<int:lab_id>")
@with_db
def lab_detail(c, lab_id):
    lab = labs.get(lab_id)
    if not lab:
        return render_template("not_found.html", what="Lab", ident=lab_id), 404
    result = labs.evaluate(c, lab)
    nxt = labs.get(lab_id + 1)
    return render_template("lab_detail.html", lab=lab, result=result, complete=result["complete"], next_lab=nxt)
