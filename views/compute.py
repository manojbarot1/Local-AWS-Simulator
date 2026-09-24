"""EC2 console: instance list, launch wizard, instance detail and lifecycle actions."""

from __future__ import annotations

import json

from flask import Blueprint, redirect, render_template, request, url_for

import db
import ec2model
import netmodel
from activity import cli, name_tag
from aws_fidelity import AMI_CATALOG, EC2_INSTANCE_TYPES, instance_type_spec
from errors import SimError
from views import checked, console_tx, done, form_int, with_db

bp = Blueprint("compute", __name__)


@bp.route("/compute")
@with_db
def compute(c):
    rows = [dict(r) for r in c.execute("SELECT * FROM ec2_instances ORDER BY id DESC")]
    return render_template("compute.html", instances=rows,
                           transitioning=any(r["target_state"] for r in rows))


def _form_context(c):
    vpcs = [dict(r) for r in c.execute("SELECT * FROM vpcs ORDER BY is_default, name")]
    subnets = []
    for s in c.execute("SELECT s.*, v.vpc_id vpc_ref, v.name vpc_name FROM subnets s JOIN vpcs v ON v.id=s.vpc_id ORDER BY v.is_default, s.name"):
        d = dict(s)
        d["public"] = netmodel.subnet_is_public(c, s)
        subnets.append(d)
    sgs = [dict(r) for r in c.execute("SELECT sg.*, v.vpc_id vpc_ref, v.name vpc_name FROM security_groups sg "
                                      "JOIN vpcs v ON v.id=sg.vpc_id ORDER BY v.is_default, sg.name")]
    return dict(vpcs=vpcs, subnets=subnets, sgs=sgs, amis=AMI_CATALOG, types=EC2_INSTANCE_TYPES)


@bp.route("/compute/launch", methods=["GET"])
@with_db
def launch_instance(c):
    return render_template("launch_instance.html", form={}, **_form_context(c))


@bp.route("/compute/launch", methods=["POST"])
def launch_instance_post():
    c = db.connect()
    form = request.form
    try:
        name = form.get("name", "").strip()
        if not name:
            raise SimError("MissingParameter", "Enter an instance name.")
        vpc_ref = form.get("vpc_id") or ""
        subnet_ref = form.get("subnet_id") or None
        sg_refs = form.getlist("security_group_id")
        if subnet_ref and vpc_ref:
            subnet = netmodel.get(c, "subnet", subnet_ref)
            if netmodel.vpc_of(c, subnet)["vpc_id"] != vpc_ref:
                raise SimError("InvalidParameter", "The selected subnet does not belong to the selected VPC.")
        if vpc_ref and not subnet_ref:
            raise SimError("MissingParameter", "Select a subnet in the chosen VPC (or leave both empty for the default VPC).")
        count = form_int("count", 1, 1, 20, "Number of instances")
        root_size = form_int("root_size", None, 1, 16384, "Root volume size")
        tags = {"Environment": form.get("environment", "NonProduction")}
        ids = ec2model.launch(
            c, name=name, ami_id=form.get("ami_id", ""), instance_type=form.get("instance_type", ""), count=count,
            subnet_ref=subnet_ref, sg_refs=sg_refs, key_name=form.get("key_name", ""),
            public_ip=True if checked("public_ip") else (False if subnet_ref else None),
            root_size=root_size, root_type=form.get("root_type", "gp3"), encrypted=checked("encrypted"), tags=tags,
            extra_config={"iam_profile": form.get("iam_profile", ""), "monitoring": checked("monitoring"),
                          "termination_protection": checked("termination_protection"),
                          "metadata_http_tokens": form.get("metadata_http_tokens", "required"),
                          "user_data": form.get("user_data", ""), "placement_group": form.get("placement_group", "")})
        first = netmodel.get(c, "instance", ids[0])
        command = cli("ec2 run-instances", ("--image-id", first["ami_id"]), ("--instance-type", first["instance_type"]),
                      ("--count", str(count) if count > 1 else None), ("--subnet-id", first["subnet"]),
                      ("--security-group-ids", first["security_groups"].split(",")),
                      ("--key-name", first["key_name"] or None),
                      "--associate-public-ip-address" if checked("public_ip") else None,
                      "--disable-api-termination" if checked("termination_protection") else None,
                      ("--block-device-mappings",
                       f"DeviceName={json.loads(first['config_json'])['volumes'][0]['device']},"
                       f"Ebs={{VolumeSize={first['root_volume_gib']},VolumeType={first['root_volume_type']},"
                       f"Encrypted={'true' if first['encrypted'] else 'false'}}}"),
                      name_tag("instance", name))
        resp = done(c, "ec2", "RunInstances", ",".join(ids),
                    f"Successfully initiated launch of {len(ids)} instance{'s' if len(ids) > 1 else ''} ({', '.join(ids)})",
                    command, url_for("compute.instance_detail", instance_id=ids[0]))
        c.commit()
        return resp
    except SimError as err:
        c.rollback()
        return render_template("launch_instance.html", errors=[f"{err.code}: {err.message}"], form=form, **_form_context(c))
    finally:
        c.close()


@bp.route("/compute/instance/<instance_id>")
@with_db
def instance_detail(c, instance_id):
    row = c.execute("SELECT * FROM ec2_instances WHERE instance_id=?", (instance_id,)).fetchone()
    if not row:
        return render_template("not_found.html", what="Instance", ident=instance_id), 404
    inst = dict(row)
    inst["tags"] = json.loads(inst["tags_json"] or "{}")
    cfg = ec2model.config(row)
    if not isinstance(cfg.get("instance_type"), dict):
        cfg["instance_type"] = instance_type_spec(inst["instance_type"])
    if not cfg.get("volumes"):
        cfg["volumes"] = [{"device": "/dev/sda1", "type": inst["root_volume_type"] or "gp3",
                           "size_gib": inst["root_volume_gib"] or 8, "encrypted": bool(inst["encrypted"])}]
    cfg.setdefault("network", {})
    inst["config"] = cfg
    inst["sg_rows"] = [dict(s) for s in netmodel.instance_sgs(c, row)]
    subnet = netmodel.instance_subnet(c, row)
    inst["subnet_public"] = netmodel.subnet_is_public(c, subnet) if subnet else None
    inst["subnet_name"] = subnet["name"] if subnet else ""
    inst["eip"] = c.execute("SELECT allocation_id FROM elastic_ips WHERE association=?", (instance_id,)).fetchone()
    return render_template("instance_detail.html", instance=inst)


@bp.route("/compute/instance/<instance_id>/action", methods=["POST"])
@console_tx(fail=lambda instance_id: f"/compute/instance/{instance_id}")
def instance_action(c, instance_id):
    inst = netmodel.get(c, "instance", instance_id)
    action = request.form.get("action")
    back = request.referrer or url_for("compute.instance_detail", instance_id=instance_id)
    if action == "toggle_protection":
        on = not ec2model.config(inst).get("termination_protection")
        ec2model.set_termination_protection(c, inst, on)
        return done(c, "ec2", "ModifyInstanceAttribute", instance_id,
                    f"Termination protection {'enabled' if on else 'disabled'} for {instance_id}",
                    cli("ec2 modify-instance-attribute", ("--instance-id", instance_id),
                        "--disable-api-termination" if on else "--no-disable-api-termination"), back)
    if action not in ("start", "stop", "reboot", "terminate"):
        raise SimError("InvalidParameterValue", f"Unknown action {action}")
    prev, new = ec2model.change_state(c, inst, action)
    verb = {"start": "StartInstances", "stop": "StopInstances", "reboot": "RebootInstances", "terminate": "TerminateInstances"}[action]
    note = " Its auto-assigned public IP was released." if action == "stop" and inst["public_ip"] and new != prev else ""
    return done(c, "ec2", verb, instance_id, f"Instance {instance_id}: {prev} → {new}.{note}",
                cli(f"ec2 {action}-instances", ("--instance-ids", instance_id)), back)


@bp.route("/compute/instance/<instance_id>/delete", methods=["POST"])
@console_tx(fail="/compute")
def delete_instance(c, instance_id):
    """Remove a terminated instance from the list — the console equivalent of
    AWS's automatic cleanup of terminated instances."""
    row = netmodel.get(c, "instance", instance_id)
    if row["state"] != "terminated":
        raise SimError("IncorrectInstanceState", f"{instance_id} is {row['state']} — terminate it before removing it.")
    c.execute("DELETE FROM ec2_instances WHERE instance_id=?", (instance_id,))
    return done(c, "ec2", "RemoveTerminated", instance_id, f"Removed terminated instance {instance_id}", target="/compute")


@bp.route("/compute/instance/<instance_id>/state")
@with_db
def instance_state(c, instance_id):
    """Tiny JSON endpoint the instance pages poll while a transition runs."""
    row = c.execute("SELECT state, target_state, public_ip FROM ec2_instances WHERE instance_id=?", (instance_id,)).fetchone()
    return {"state": row["state"] if row else "unknown", "target": row["target_state"] if row else None}


@bp.route("/compute/instances")
def compute_alias():
    return redirect(url_for("compute.compute"))
