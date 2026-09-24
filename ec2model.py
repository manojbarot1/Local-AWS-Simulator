"""
ec2model.py
===========

EC2 instance behaviour shared by the console and the AWS API endpoint:
validation, placement, IP allocation and the instance lifecycle.

Lifecycle
---------
Instances move through the same intermediate states as real EC2
(``pending`` → ``running``, ``stopping`` → ``stopped``, ``shutting-down`` →
``terminated``). A transition stores its target state and a due time;
``advance()`` — run at the start of every request — completes transitions whose
time has passed, so ``aws ec2 wait instance-running`` behaves like the real
thing. ``SIM_TRANSITION_SECONDS=0`` makes transitions instant (used by tests).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta

import db
import netmodel
from aws_fidelity import (
    aws_id, AMI_CATALOG, EC2_INSTANCE_TYPES, instance_type_spec, allocate_private_ip,
    private_dns_name, public_dns_name, random_public_ip,
)
from errors import SimError

TRANSITION_SECONDS = float(os.environ.get("SIM_TRANSITION_SECONDS", "5"))

STATE_CODES = {"pending": 0, "running": 16, "shutting-down": 32, "terminated": 48,
               "stopping": 64, "stopped": 80}
EBS_VOLUME_TYPES = ("gp3", "gp2", "io1", "io2", "st1", "sc1")


def find_ami(ami_id):
    ami = next((a for a in AMI_CATALOG if a["id"] == ami_id), None)
    if not ami:
        raise SimError("InvalidAMIID.NotFound", f"The image id '[{ami_id}]' does not exist")
    return ami


def advance(c):
    """Complete transitions that are due. Cheap: one indexed UPDATE."""
    c.execute("""UPDATE ec2_instances SET state=target_state, target_state=NULL, transition_at=NULL
                 WHERE target_state IS NOT NULL AND transition_at <= ?""", (db.now(),))


def _begin(c, inst_id, interim, final):
    if TRANSITION_SECONDS <= 0:
        c.execute("UPDATE ec2_instances SET state=?, target_state=NULL, transition_at=NULL WHERE id=?",
                  (final, inst_id))
    else:
        due = (datetime.now() + timedelta(seconds=TRANSITION_SECONDS)).isoformat(timespec="seconds")
        c.execute("UPDATE ec2_instances SET state=?, target_state=?, transition_at=? WHERE id=?",
                  (interim, final, due, inst_id))


def launch(c, *, name, ami_id, instance_type, count=1, subnet_ref=None, sg_refs=None,
           key_name="", public_ip=None, root_size=None, root_type="gp3", encrypted=True,
           tags=None, extra_config=None, source="console"):
    ami = find_ami(ami_id)
    spec = next((t for t in EC2_INSTANCE_TYPES if t[0] == instance_type), None)
    if not spec:
        raise SimError("InvalidParameterValue", f"Invalid value '{instance_type}' for InstanceType.")
    if not 1 <= count <= 20:
        raise SimError("InstanceLimitExceeded", "You can launch between 1 and 20 instances per request in the simulator.")
    root_size = int(root_size or (30 if ami["os"] == "Windows" else 8))
    min_root = 30 if ami["os"] == "Windows" else 8
    if not min_root <= root_size <= 16384:
        raise SimError("InvalidBlockDeviceMapping",
                       f"Volume of size {root_size}GB is smaller than snapshot size {min_root}GB for {ami['name']}.")
    if root_type not in EBS_VOLUME_TYPES:
        raise SimError("InvalidParameterValue", f"Invalid volume type '{root_type}'.")
    subnet, vpc, sgs = netmodel.placement(c, subnet_ref, sg_refs)
    region = db.region(c)
    want_public = bool(subnet["map_public_ip"]) if public_ip is None else bool(public_ip)
    used = [r[0] for r in c.execute("SELECT private_ip FROM ec2_instances WHERE subnet=? AND state!='terminated'",
                                    (subnet["subnet_id"],))]
    created = []
    for n in range(count):
        iid = aws_id("i")
        priv = allocate_private_ip(subnet["cidr"], used)
        used.append(priv)
        pub = random_public_ip() if want_public else ""
        inst_tags = dict(tags or {})
        base = name or inst_tags.get("Name", "")
        if base:
            inst_tags["Name"] = base if count == 1 else f"{base}-{n + 1}"
        cfg = {
            "ami": ami, "instance_type": instance_type_spec(instance_type),
            "network": {"vpc": vpc["vpc_id"], "subnet": subnet["subnet_id"], "public_ip": want_public,
                        "availability_zone": subnet["az"], "private_dns": private_dns_name(priv, region),
                        "public_dns": public_dns_name(pub, region) if pub else ""},
            "volumes": [{"device": ami.get("root_device", "/dev/sda1"), "type": root_type,
                         "size_gib": root_size, "encrypted": bool(encrypted)}],
            "tenancy": vpc["tenancy"] or "default", "source": source,
            "termination_protection": False, "metadata_http_tokens": "required",
        }
        cfg.update(extra_config or {})
        c.execute(
            """INSERT INTO ec2_instances(instance_id,name,state,os,ami_id,instance_type,vpc,subnet,security_groups,
               key_name,private_ip,public_ip,root_volume_gib,root_volume_type,encrypted,architecture,tags_json,
               config_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (iid, inst_tags.get("Name", ""), "pending", ami["os"], ami_id, instance_type, vpc["vpc_id"],
             subnet["subnet_id"], ",".join(s["group_id"] for s in sgs), key_name or "", priv, pub, root_size,
             root_type, int(bool(encrypted)), ami["arch"], json.dumps(inst_tags), json.dumps(cfg), db.now()))
        row = netmodel.get(c, "instance", iid)
        _begin(c, row["id"], "pending", "running")
        created.append(iid)
    return created


def config(inst):
    try:
        return json.loads(inst["config_json"] or "{}")
    except ValueError:
        return {}


def _has_eip(c, inst):
    return c.execute("SELECT 1 FROM elastic_ips WHERE association=?", (inst["instance_id"],)).fetchone() is not None


def change_state(c, inst, action):
    """Apply start/stop/reboot/terminate. Returns (previous_state, new_state)."""
    state = inst["target_state"] or inst["state"]
    prev = inst["state"]
    iid = inst["instance_id"]
    if action == "terminate":
        if state == "terminated":
            return prev, prev
        if config(inst).get("termination_protection"):
            raise SimError("OperationNotPermitted",
                           f"The instance '{iid}' may not be terminated. Modify its 'disableApiTermination' "
                           "instance attribute and try again.")
        # Elastic IPs are disassociated but stay allocated (and billed).
        c.execute("UPDATE elastic_ips SET association='', state='allocated' WHERE association=?", (iid,))
        _begin(c, inst["id"], "shutting-down", "terminated")
    elif action == "stop":
        if state in ("stopped", "stopping"):
            return prev, prev
        if state in ("terminated", "shutting-down"):
            raise SimError("IncorrectInstanceState", f"The instance '{iid}' is not in a state from which it can be stopped.")
        # A stopped instance gives its auto-assigned public IP back to AWS.
        if not _has_eip(c, inst):
            c.execute("UPDATE ec2_instances SET public_ip='' WHERE id=?", (inst["id"],))
        _begin(c, inst["id"], "stopping", "stopped")
    elif action == "start":
        if state in ("running", "pending"):
            return prev, prev
        if state in ("terminated", "shutting-down"):
            raise SimError("IncorrectInstanceState", f"The instance '{iid}' is not in a state from which it can be started.")
        cfg = config(inst)
        if cfg.get("network", {}).get("public_ip") and not _has_eip(c, inst):
            pub = random_public_ip()
            cfg["network"]["public_dns"] = public_dns_name(pub, db.region(c))
            c.execute("UPDATE ec2_instances SET public_ip=?, config_json=? WHERE id=?",
                      (pub, json.dumps(cfg), inst["id"]))
        _begin(c, inst["id"], "pending", "running")
    elif action == "reboot":
        if state != "running":
            raise SimError("IncorrectInstanceState", f"The instance '{iid}' is not in a state from which it can be rebooted.")
        return prev, prev
    else:
        raise SimError("InvalidParameterValue", f"Unknown action {action}")
    now_row = netmodel.get(c, "instance", iid)
    return prev, now_row["state"]


def set_termination_protection(c, inst, enabled):
    cfg = config(inst)
    cfg["termination_protection"] = bool(enabled)
    c.execute("UPDATE ec2_instances SET config_json=? WHERE id=?", (json.dumps(cfg), inst["id"]))
