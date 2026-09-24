"""
costs.py
========

What would this environment cost on real AWS?

Approximate on-demand list prices for eu-central-1 (Frankfurt) in USD, 730
hours per month. They exclude data transfer, requests, free tiers, taxes and
discounts, and prices change — the goal is to teach *which* resources cost
money (a NAT gateway left running, an unattached Elastic IP, the disks of a
stopped instance), not to produce an invoice.
"""

from __future__ import annotations

import json

HOURS = 730
PRICES_AS_OF = "2026"

EC2_HOURLY = {
    "t3.nano": 0.006, "t3.micro": 0.012, "t3.small": 0.024, "t3.medium": 0.048,
    "t3.large": 0.096, "t3.xlarge": 0.192,
    "m6i.large": 0.115, "m6i.xlarge": 0.230, "m6i.2xlarge": 0.460, "m6i.4xlarge": 0.920,
    "c6i.large": 0.097, "c6i.xlarge": 0.194, "c6i.2xlarge": 0.388,
    "r6i.large": 0.152, "r6i.xlarge": 0.304, "r6i.2xlarge": 0.608,
    "g4dn.xlarge": 0.658, "g5.xlarge": 1.258,
}
WINDOWS_PER_VCPU_HOUR = 0.046      # licence-included surcharge (non-burstable)
WINDOWS_PER_VCPU_HOUR_T = 0.0092   # burstable families carry a smaller surcharge
EBS_GB_MONTH = {"gp3": 0.0952, "gp2": 0.119, "io1": 0.149, "io2": 0.149, "st1": 0.054, "sc1": 0.018}
NAT_HOURLY = 0.052
PUBLIC_IPV4_HOURLY = 0.005         # every public IPv4, in use or idle, since 2024
LB_HOURLY = {"application": 0.027, "network": 0.027, "gateway": 0.0135}
INTERFACE_ENDPOINT_HOURLY = 0.012  # per AZ; gateway endpoints are free
S3_GB_MONTH = 0.0245
SECRET_MONTH = 0.40


def _line(service, resource, name, monthly, note=""):
    return {"service": service, "resource": resource, "name": name, "monthly": round(monthly, 2), "note": note}


def estimate(c):
    lines = []
    for i in c.execute("SELECT * FROM ec2_instances WHERE state!='terminated'"):
        cfg = json.loads(i["config_json"] or "{}")
        vcpus = (cfg.get("instance_type") or {}).get("vcpus") or 2
        hourly = EC2_HOURLY.get(i["instance_type"], 0.1)
        if (i["os"] or "").lower() == "windows":
            rate = WINDOWS_PER_VCPU_HOUR_T if i["instance_type"].startswith("t") else WINDOWS_PER_VCPU_HOUR
            hourly += rate * (vcpus if isinstance(vcpus, int) else 2)
        running = i["state"] in ("running", "pending")
        lines.append(_line("EC2", i["instance_id"], i["name"], hourly * HOURS if running else 0,
                           f"{i['instance_type']} {i['os']}" + ("" if running else " — stopped: compute is free, disks are not")))
        for v in cfg.get("volumes") or [{"type": i["root_volume_type"], "size_gib": i["root_volume_gib"]}]:
            gb = v.get("size_gib") or 8
            lines.append(_line("EBS", i["instance_id"], f"{i['name']} root volume",
                               gb * EBS_GB_MONTH.get(v.get("type") or "gp3", 0.0952), f"{gb} GiB {v.get('type') or 'gp3'}"))
        if i["public_ip"] and running and not c.execute("SELECT 1 FROM elastic_ips WHERE association=?",
                                                        (i["instance_id"],)).fetchone():
            lines.append(_line("Public IPv4", i["instance_id"], f"{i['name']} public IP",
                               PUBLIC_IPV4_HOURLY * HOURS, "auto-assigned public IPv4"))
    for n in c.execute("SELECT * FROM nat_gateways"):
        lines.append(_line("VPC", n["nat_id"], n["name"] or "NAT gateway", NAT_HOURLY * HOURS,
                           "NAT gateway hourly charge, before per-GB processing"))
    for e in c.execute("SELECT * FROM elastic_ips"):
        idle = not e["association"]
        lines.append(_line("Public IPv4", e["allocation_id"], e["name"] or e["public_ip"], PUBLIC_IPV4_HOURLY * HOURS,
                           "Elastic IP — idle, release it if unused" if idle else f"Elastic IP on {e['association']}"))
    for lb in c.execute("SELECT * FROM load_balancers"):
        lines.append(_line("ELB", lb["lb_id"], lb["name"], LB_HOURLY.get(lb["lb_type"], 0.027) * HOURS,
                           f"{lb['lb_type']} load balancer hourly charge, before LCUs"))
    for ep in c.execute("SELECT * FROM vpc_endpoints"):
        if ep["endpoint_type"] == "interface":
            lines.append(_line("VPC", ep["endpoint_id"], ep["name"], INTERFACE_ENDPOINT_HOURLY * HOURS,
                               "interface endpoint, 1 AZ"))
    for b in c.execute("SELECT b.name, COALESCE(SUM(o.size_bytes),0) bytes FROM s3_buckets b "
                       "LEFT JOIN s3_objects o ON o.bucket_id=b.id GROUP BY b.id"):
        gb = b["bytes"] / 1024 ** 3
        lines.append(_line("S3", b["name"], b["name"], gb * S3_GB_MONTH, f"{b['bytes']} bytes stored"))
    for s in c.execute("SELECT name FROM secrets"):
        lines.append(_line("Secrets Manager", s["name"], s["name"], SECRET_MONTH, "per secret per month"))
    for t in c.execute("SELECT name FROM dynamodb_tables"):
        lines.append(_line("DynamoDB", t["name"], t["name"], 0, "on-demand: pay per request + storage"))
    for f in c.execute("SELECT name FROM lambda_functions"):
        lines.append(_line("Lambda", f["name"], f["name"], 0, "pay per request and GB-second"))

    by_service = {}
    for ln in lines:
        by_service[ln["service"]] = round(by_service.get(ln["service"], 0) + ln["monthly"], 2)
    total = round(sum(ln["monthly"] for ln in lines), 2)
    return {"total": total, "lines": sorted(lines, key=lambda x: -x["monthly"]),
            "by_service": dict(sorted(by_service.items(), key=lambda kv: -kv[1])), "tips": _tips(c, lines)}


def _tips(c, lines):
    tips = []
    nat = [ln for ln in lines if ln["resource"].startswith("nat-")]
    if nat:
        tips.append(f"{len(nat)} NAT gateway(s) cost about ${NAT_HOURLY * HOURS:.0f}/month each before traffic. "
                    "Share one per AZ, or use VPC gateway endpoints for S3/DynamoDB traffic.")
    idle = [ln for ln in lines if "idle" in ln["note"]]
    if idle:
        tips.append(f"{len(idle)} Elastic IP(s) are not associated with anything — release them.")
    stopped = c.execute("SELECT COUNT(*) FROM ec2_instances WHERE state='stopped'").fetchone()[0]
    if stopped:
        tips.append(f"{stopped} stopped instance(s) still pay for their EBS volumes. Terminate what you don't need.")
    return tips
