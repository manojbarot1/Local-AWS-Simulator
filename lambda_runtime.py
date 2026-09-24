"""
lambda_runtime.py
=================

Actually run Python Lambda functions.

The handler runs in a separate ``python -I`` process with the function's
timeout enforced, a Lambda-like ``context`` object, and stdout/stderr captured
as the log stream. Non-Python runtimes are still simulated (the response echoes
the event), because the simulator has no Node/Java/Go toolchain.

This executes code you typed into your own local simulator, on your own
machine — the same trust level as running a script. The web console and API
endpoint refuse cross-site and non-local requests (see ``app.py``), and
``SIM_LAMBDA_EXEC=0`` switches execution off entirely.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid

ENABLED = os.environ.get("SIM_LAMBDA_EXEC", "1") != "0"
MAX_TIMEOUT = 60
RUNTIMES = ["python3.13", "python3.12", "python3.11", "nodejs22.x", "nodejs20.x", "java21", "dotnet8",
            "ruby3.3", "provided.al2023"]


def default_code(handler):
    """Starter code whose function name matches the configured handler."""
    func = (handler or "lambda_function.lambda_handler").rpartition(".")[2] or "lambda_handler"
    return DEFAULT_PYTHON_CODE.replace("def handler(", f"def {func}(")

DEFAULT_PYTHON_CODE = '''import json


def handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    return {
        "statusCode": 200,
        "body": json.dumps({"message": f"Hello from {context.function_name}", "input": event}),
    }
'''

# Runs inside the child process: import the handler module, build a context,
# call it, and write the result (or the error) as JSON to the result file.
_BOOTSTRAP = r'''
import importlib, json, resource, sys, time, traceback
code_dir, module_name, func_name, result_path, fn_name, memory, timeout, request_id, arn = sys.argv[1:10]
sys.path.insert(0, code_dir)
deadline = time.time() + float(timeout)

class Context:
    function_name = fn_name
    function_version = "$LATEST"
    invoked_function_arn = arn
    memory_limit_in_mb = int(memory)
    aws_request_id = request_id
    log_group_name = "/aws/lambda/" + fn_name
    log_stream_name = time.strftime("%Y/%m/%d") + "/[$LATEST]" + request_id[:32]
    def get_remaining_time_in_millis(self):
        return max(0, int((deadline - time.time()) * 1000))

event = json.loads(sys.stdin.read() or "{}")
try:
    module = importlib.import_module(module_name)
    result = getattr(module, func_name)(event, Context())
    json.dumps(result)
    out = {"ok": True, "result": result}
except Exception as exc:
    tb = traceback.extract_tb(exc.__traceback__)
    out = {"ok": False, "errorType": type(exc).__name__, "errorMessage": str(exc),
           "stackTrace": [f"  File \"{f.filename}\", line {f.lineno}, in {f.name}" for f in tb[1:]]}
    traceback.print_exc()
sys.stdout.flush()
out["max_rss_kb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
with open(result_path, "w") as fh:
    json.dump(out, fh, default=str)
'''


def _split_handler(handler):
    module, _, func = (handler or "lambda_function.lambda_handler").rpartition(".")
    if not module or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_/]*", module) or not func.isidentifier():
        raise ValueError(f"Bad handler '{handler}'. Use <file>.<function>, e.g. lambda_function.lambda_handler")
    return module.replace("/", "."), func


def is_python(runtime):
    return (runtime or "").startswith("python")


def invoke(fn, event):
    """Run function row ``fn`` with ``event``. Returns a dict with keys:
    status ("Success"|"Unhandled"), payload, logs (list), duration_ms,
    billed_ms, max_memory_mb, request_id, executed (bool)."""
    request_id = str(uuid.uuid4())
    memory = int(fn["memory_mb"] or 128)
    timeout = max(1, min(int(fn["timeout_s"] or 3), MAX_TIMEOUT))
    header = f"START RequestId: {request_id} Version: $LATEST"

    if not (ENABLED and is_python(fn["runtime"]) and (fn["code"] or "").strip()):
        why = ("execution is disabled (SIM_LAMBDA_EXEC=0)" if not ENABLED else
               f"the {fn['runtime']} runtime is simulated" if not is_python(fn["runtime"]) else "the function has no code")
        payload = {"statusCode": 200, "body": json.dumps({"message": f"Hello from {fn['name']}", "input": event})}
        return _report(request_id, header, [f"[simulator] Not executed: {why}; returning a sample response."],
                       "Success", payload, 1.0, memory, 30, executed=False)

    module, func = _split_handler(fn["handler"])
    with tempfile.TemporaryDirectory(prefix="lambda-") as tmp:
        path = os.path.join(tmp, *module.split(".")) + ".py"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(fn["code"])
        result_path = os.path.join(tmp, "__result.json")
        env = {"PATH": "/usr/bin:/bin", "AWS_LAMBDA_FUNCTION_NAME": fn["name"],
               "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": str(memory), "AWS_REGION": "eu-central-1",
               "AWS_DEFAULT_REGION": "eu-central-1", "LAMBDA_TASK_ROOT": tmp, "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONUNBUFFERED": "1", "HOME": tmp, "TMPDIR": tmp}
        started = time.monotonic()
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-c", _BOOTSTRAP, tmp, module, func, result_path, fn["name"],
                 str(memory), str(timeout), request_id, fn["arn"]],
                input=json.dumps(event), capture_output=True, text=True, timeout=timeout, env=env, cwd=tmp)
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            proc = exc
            timed_out = True
        duration = (time.monotonic() - started) * 1000
        stdout = proc.stdout if isinstance(proc.stdout, str) else (proc.stdout or b"").decode(errors="replace")
        stderr = proc.stderr if isinstance(proc.stderr, str) else (proc.stderr or b"").decode(errors="replace")
        logs = [ln for ln in (stdout + stderr).splitlines()]
        if timed_out:
            logs.append(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {request_id} Task timed out after {timeout:.2f} seconds")
            payload = {"errorMessage": f"{time.strftime('%Y-%m-%dT%H:%M:%SZ')} {request_id} Task timed out after {timeout:.2f} seconds"}
            return _report(request_id, header, logs, "Unhandled", payload, timeout * 1000, memory, memory)
        try:
            with open(result_path) as fh:
                out = json.load(fh)
        except (OSError, ValueError):
            out = {"ok": False, "errorType": "Runtime.ExitError",
                   "errorMessage": f"RequestId: {request_id} Error: Runtime exited with error: exit status {proc.returncode}"}
    max_rss_mb = max(1, int(out.get("max_rss_kb") or 30720) // 1024)
    if out.get("ok"):
        return _report(request_id, header, logs, "Success", out["result"], duration, memory, max_rss_mb)
    payload = {k: out[k] for k in ("errorMessage", "errorType", "stackTrace") if k in out}
    return _report(request_id, header, logs, "Unhandled", payload, duration, memory, max_rss_mb)


def _report(request_id, header, logs, status, payload, duration, memory, max_mb, executed=True):
    billed = max(1, int(-(-duration // 1)))
    lines = [header] + logs + [
        f"END RequestId: {request_id}",
        f"REPORT RequestId: {request_id}\tDuration: {duration:.2f} ms\tBilled Duration: {billed} ms\t"
        f"Memory Size: {memory} MB\tMax Memory Used: {min(max_mb, memory)} MB",
    ]
    return {"status": status, "payload": payload, "logs": lines, "duration_ms": round(duration, 2),
            "billed_ms": billed, "max_memory_mb": min(max_mb, memory), "request_id": request_id,
            "executed": executed}


def record(c, fn_name, source, event, result):
    """Keep the last 20 invocations per function — the simulator's stand-in
    for the function's CloudWatch log group."""
    from datetime import datetime
    c.execute("INSERT INTO lambda_invocations(function_name,ts,source,status,duration_ms,event,response,logs) "
              "VALUES(?,?,?,?,?,?,?,?)",
              (fn_name, datetime.now().isoformat(timespec="seconds"), source, result["status"], result["duration_ms"],
               json.dumps(event), json.dumps(result["payload"], default=str), "\n".join(result["logs"])))
    c.execute("DELETE FROM lambda_invocations WHERE function_name=? AND id NOT IN "
              "(SELECT id FROM lambda_invocations WHERE function_name=? ORDER BY id DESC LIMIT 20)", (fn_name, fn_name))
