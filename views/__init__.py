"""Web-console blueprints and the helpers they share.

``console_tx`` runs a view inside one SQLite transaction: domain rules raise
``SimError`` and the user sees the real AWS error code in a red banner instead
of a 500 page. ``done`` records the action in the activity log and shows the
equivalent AWS CLI command under the success banner.
"""

from __future__ import annotations

from functools import wraps

from flask import flash, redirect, request

import activity
import db
from errors import SimError


def console_tx(fail="/"):
    """Decorator: pass a DB connection as the first argument, commit on success,
    turn SimError / bad form input into a flash + redirect to ``fail``."""
    def deco(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            c = db.connect()
            try:
                resp = view(c, *args, **kwargs)
                c.commit()
                return resp
            except SimError as err:
                c.rollback()
                flash(f"{err.code}: {err.message}", "error")
            except (ValueError, TypeError, KeyError) as err:
                c.rollback()
                flash(f"InvalidParameterValue: {err}", "error")
            finally:
                c.close()
            target = fail(*args, **kwargs) if callable(fail) else fail
            return redirect(target or request.referrer or "/")
        return wrapper
    return deco


def with_db(view):
    """Decorator for read-only views."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        c = db.connect()
        try:
            return view(c, *args, **kwargs)
        finally:
            c.close()
    return wrapper


def done(c, service, action, resource, message, cli_cmd="", target=None):
    """Record a console action, flash success + CLI equivalent, redirect."""
    activity.record(c, "console", service, action, resource, message, cli_cmd)
    flash(message, "success")
    if cli_cmd:
        flash(cli_cmd, "cli")
    return redirect(target or request.referrer or "/")


def form_int(name, default, lo=None, hi=None, label=None):
    raw = (request.form.get(name) or "").strip()
    if not raw:
        return default
    try:
        val = int(raw)
    except ValueError:
        raise SimError("InvalidParameterValue", f"{label or name} must be a whole number (got '{raw}').")
    if (lo is not None and val < lo) or (hi is not None and val > hi):
        raise SimError("InvalidParameterValue", f"{label or name} must be between {lo} and {hi} (got {val}).")
    return val


def checked(name):
    return request.form.get(name) in ("on", "1", "true", "yes")
