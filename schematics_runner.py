#!/usr/bin/env python3
"""
BIG-IP Next for Kubernetes 2.3 — cert-manager Schematics Lifecycle Runner

Manages a single IBM Schematics workspace for the cert_manager Terraform module.

Phases (preflight and setup always run):
  create   — create the Schematics workspace
  plan     — plan (validate) the workspace
  apply    — apply (provision) the workspace
  destroy  — destroy (deprovision) the workspace
  delete   — delete the workspace record from Schematics

Usage:
    python3 schematics_runner.py [path/to/terraform.tfvars] [options]

    --branch BRANCH     GitHub branch to deploy (default: main)
    --phases PHASE ...  Phases to run (default: all)
    --ws-id WS_ID       Existing workspace ID (required when create is not in --phases)
    --list              List workspaces matching this repo's name prefix and exit
    --resources         Print workspace resource list and exit
    --outputs           Print workspace output variables and exit

Prerequisites:
    ibmcloud CLI installed and authenticated:
        ibmcloud login --apikey YOUR_API_KEY -r REGION
    Schematics plugin:
        ibmcloud plugin install schematics
"""

import json
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

REPO_URL       = "https://github.com/f5devcentral/ibmcloud_schematics_bigip_next_for_kubernetes_2_3_cert_manager"
WS_NAME_PREFIX = "bnk-23-cert-manager"
TITLE          = "BIG-IP Next for Kubernetes 2.3 — cert-manager"
TFVARS_DEFAULT = "terraform.tfvars"
WS_JSON_PATH   = "workspace.json"
REPORT_DIR     = Path("test-reports")

# Polling / timeout constants (seconds)
POLL_INTERVAL = 30
JOB_TIMEOUT   = 18000   # 5 hours — apply and destroy can be long-running
READY_TIMEOUT = 300     # how long to wait for a workspace to become unlocked after creation

# Report / display column width used for separator lines and alignment
REPORT_WIDTH = 72

# Variable names whose values must not appear in plain-text output or logs
SECURE_VARS = {"ibmcloud_api_key", "bigip_password"}

# Schematics workspace statuses that indicate no background job is running.
# Any status outside this set means a job is still in progress.
TERMINAL_STATUSES = {"INACTIVE", "ACTIVE", "FAILED", "STOPPED", "DRAFT"}

VALID_PHASES = ["create", "plan", "apply", "destroy", "delete"]

# Output keys printed at the top of the report's Key Outputs section.
# All other outputs follow below a secondary separator.
KEY_OUTPUTS = [
    "cert_manager_namespace",
    "cert_manager_version",
]


# ── Low-level helpers ─────────────────────────────────────────────────────────

def tee(msg, lf=None):
    """Print msg to stdout and, if lf is provided, to the log file as well."""
    print(msg, flush=True)
    if lf:
        print(msg, file=lf, flush=True)


def run_cmd(cmd, lf=None, stream=False):
    """
    Execute a shell command and return (returncode, stdout, stderr).

    stream=False (default) — capture stdout/stderr silently; caller inspects
        the returned strings.  Used for commands whose output is consumed
        programmatically (JSON parsing, ID extraction, etc.).

    stream=True — line-buffer stdout+stderr to the terminal (and lf) in real
        time.  Used for long-running ibmcloud log commands where you want to
        see Terraform output as it arrives rather than waiting for the job to
        finish.  stderr is merged into stdout so the stream appears interleaved,
        matching what a user would see running the command directly.
    """
    if not stream:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return r.returncode, r.stdout, r.stderr

    proc = subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    buf = []
    for line in proc.stdout:
        print(line, end="", flush=True)
        if lf:
            print(line, end="", file=lf, flush=True)
        buf.append(line)
    proc.wait()
    return proc.returncode, "".join(buf), ""


def ibmcloud_json(cmd, lf=None):
    """
    Run an ibmcloud command with --output json appended and return parsed JSON.

    The raw JSON is written to lf so the log file always contains the
    machine-readable API response alongside the human-readable tee() messages.

    Raises RuntimeError if the command exits non-zero or the output is not
    valid JSON.
    """
    rc, out, err = run_cmd(f"{cmd} --output json")
    if lf and out.strip():
        print(out, file=lf, flush=True)
    if rc != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{(err or out).strip()}")
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Non-JSON output from: {cmd}\n{out}") from exc


# ── Section banner ────────────────────────────────────────────────────────────

def section(title, lf, width=REPORT_WIDTH):
    """Print a titled section banner to stdout and the log file."""
    bar = "─" * width
    tee(f"\n{bar}\n  {title}\n{bar}", lf)


# ── tfvars / workspace.json ───────────────────────────────────────────────────

def parse_tfvars(path):
    """
    Parse a terraform.tfvars file into a list of Schematics variable dicts.

    This is a deliberately simple line-by-line parser — it handles the flat
    key = value syntax used by this module's tfvars files.  It does not support
    HCL maps, lists, or heredocs.

    Each returned dict matches the shape expected by the Schematics variablestore:
        {"name": str, "value": str, "type": str, "secure": bool (optional)}

    Variables in SECURE_VARS get "secure": True so Schematics masks their
    values in logs and the web console.
    """
    variables = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r'^(\w+)\s*=\s*(.+)$', line)
            if not m:
                continue
            name, raw = m.group(1), m.group(2).strip()
            # Infer the Schematics type from the raw value rather than requiring
            # explicit HCL type annotations in the tfvars file
            if raw in ("true", "false"):
                entry = {"name": name, "value": raw, "type": "bool"}
            elif re.match(r'^-?\d+(\.\d+)?$', raw):
                entry = {"name": name, "value": raw, "type": "number"}
            else:
                # Strip surrounding double-quotes; Schematics stores the bare string
                entry = {"name": name, "value": raw.strip('"'), "type": "string"}
            if name in SECURE_VARS:
                entry["secure"] = True
            variables.append(entry)
    return variables


def ensure_ibmcloud_login(tfvars_path, lf=None):
    """
    Verify the ibmcloud CLI is authenticated; if not, auto-login using
    ibmcloud_api_key + ibmcloud_schematics_region from tfvars_path.

    Raises RuntimeError if the tfvars file is missing, the api key is blank,
    or `ibmcloud login` itself fails.
    """
    if shutil.which("ibmcloud") is None:
        raise RuntimeError(
            "ibmcloud CLI not found in PATH — install from "
            "https://cloud.ibm.com/docs/cli?topic=cli-install-ibmcloud-cli"
        )
    rc, _, _ = run_cmd("ibmcloud iam oauth-tokens")
    if rc == 0:
        tee("  ibmcloud CLI authenticated", lf)
        return
    tee("  Not authenticated — logging in with API key from tfvars", lf)
    if not Path(tfvars_path).exists():
        raise RuntimeError(
            f"{tfvars_path} not found — cannot auto-login. "
            "Run: ibmcloud login --apikey YOUR_API_KEY -r REGION"
        )
    tfvars_map = {v["name"]: v["value"] for v in parse_tfvars(tfvars_path)}
    api_key = tfvars_map.get("ibmcloud_api_key", "").strip()
    region  = tfvars_map.get("ibmcloud_schematics_region", "us-south").strip() or "us-south"
    if not api_key:
        raise RuntimeError(
            f"ibmcloud_api_key missing or empty in {tfvars_path}. "
            "Run: ibmcloud login --apikey YOUR_API_KEY -r REGION"
        )
    # -q suppresses the interactive account-selection prompt; the api key
    # uniquely identifies the account so no choice is needed.
    rc2, _, err2 = run_cmd(f"ibmcloud login --apikey {api_key} -r {region} -q", lf=lf)
    if rc2 != 0:
        raise RuntimeError(f"ibmcloud login failed: {err2.strip() or 'unknown error'}")
    tee(f"  Logged in to region {region}", lf)


def build_workspace_json(variables, ts_label, branch="main"):
    """
    Build and write the workspace.json payload consumed by:
        ibmcloud schematics workspace new --file workspace.json

    The workspace name embeds ts_label (a UTC timestamp string) so that
    concurrent test runs produce unique names without manual coordination.

    ibmcloud_schematics_region and ibmcloud_resource_group, if present in the
    tfvars, are hoisted into the workspace-level location/resource_group fields
    that Schematics requires in addition to the template variablestore.
    """
    var_map        = {v["name"]: v["value"] for v in variables}
    location       = var_map.get("ibmcloud_schematics_region", "us-south")
    resource_group = var_map.get("ibmcloud_resource_group", "default")
    ws = {
        "name": f"{WS_NAME_PREFIX}-test-{ts_label}",
        "type": ["terraform_v1.5"],
        "location": location,
        "description": f"Lifecycle runner — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "resource_group": resource_group,
        "template_repo": {
            "url": REPO_URL,
            "branch": branch,
        },
        "template_data": [{
            "folder": ".",
            "type": "terraform_v1.5",
            "variablestore": variables,
        }],
    }
    Path(WS_JSON_PATH).write_text(json.dumps(ws, indent=2))
    return ws


# ── Schematics polling ────────────────────────────────────────────────────────

def get_ws_info(ws_id):
    """
    Return (status, locked) for a workspace.

    Schematics exposes the workspace status in different fields depending on
    whether the workspace has ever been applied — we check both locations and
    fall back to "UNKNOWN" so callers never have to guard for None.

    Returns ("UNKNOWN", True) on any error so callers treat the workspace as
    unavailable rather than spinning indefinitely on a stale status.
    """
    try:
        data   = ibmcloud_json(f"ibmcloud schematics workspace get --id {ws_id}")
        status = (
            data.get("status")
            or data.get("workspace_status_msg", {}).get("status_code")
            or "UNKNOWN"
        )
        locked = data.get("workspace_status", {}).get("locked", False)
        return status, locked
    except Exception:
        return "UNKNOWN", True


def get_ws_status(ws_id):
    """Convenience wrapper — returns just the status string, discards locked."""
    status, _ = get_ws_info(ws_id)
    return status


def wait_for_workspace_ready(ws_id, lf, timeout=READY_TIMEOUT):
    """
    Block until the workspace reaches a non-locked terminal status.

    A newly created workspace goes through a brief initialisation period where
    it is locked and not yet INACTIVE.  Submitting a plan or apply before the
    workspace is ready returns a 409 conflict from Schematics.  This wait avoids
    that race so callers don't have to rely solely on the 409 retry in run_job().

    If the workspace does not become ready within `timeout` seconds we emit a
    warning and return the current status rather than aborting — run_job()'s own
    409 retry loop will handle any subsequent conflict.
    """
    start = time.time()
    while True:
        elapsed = int(time.time() - start)
        if elapsed > timeout:
            tee(f"\n  WARNING: workspace not ready after {timeout}s — proceeding anyway", lf)
            return get_ws_status(ws_id)
        status, locked = get_ws_info(ws_id)
        if status in {"INACTIVE", "ACTIVE", "FAILED"} and not locked:
            print()
            return status
        msg = f"  [ready] {elapsed}s  status={status}  locked={locked}"
        # Overwrite the same terminal line while waiting to keep output compact
        print(f"\r{msg:<76}", end="", flush=True)
        print(msg, file=lf, flush=True)
        time.sleep(10)


def poll_until_terminal(ws_id, label, lf, timeout=JOB_TIMEOUT):
    """
    Poll workspace status every POLL_INTERVAL seconds until a terminal status
    is reached or `timeout` seconds elapse.

    Returns (status, elapsed_seconds).  The caller is responsible for deciding
    whether the terminal status represents success or failure for its phase —
    e.g., apply expects "ACTIVE" while destroy expects "INACTIVE".
    """
    start = time.time()
    while True:
        elapsed = int(time.time() - start)
        if elapsed > timeout:
            return "TIMEOUT", elapsed
        status = get_ws_status(ws_id)
        if status in TERMINAL_STATUSES:
            print()
            return status, elapsed
        msg = f"  [{label}] {elapsed}s elapsed  status={status}"
        # Overwrite the same terminal line to avoid a wall of repetitive status lines
        print(f"\r{msg:<76}", end="", flush=True)
        print(msg, file=lf, flush=True)
        time.sleep(POLL_INTERVAL)


def stream_logs(ws_id, act_id, lf):
    """Tail the Schematics activity log to the terminal and log file."""
    run_cmd(
        f"ibmcloud schematics logs --id {ws_id} --act-id {act_id}",
        lf=lf, stream=True,
    )


def run_job(cmd, ws_id, label, lf, success_statuses, timeout=JOB_TIMEOUT):
    """
    Submit a Schematics job (plan / apply / destroy) and wait for completion.

    Flow:
      1. Submit the command.  If Schematics returns HTTP 409 (workspace is
         temporarily locked by a prior job that has not yet released its lock),
         back off 30 s and retry.  This is common when phases are chained rapidly
         and the API hasn't caught up between status transitions.
      2. Extract the activity ID from the JSON response so we can stream logs.
      3. Wait up to 120 s for the workspace status to change from its pre-
         submission value.  Without this brief wait, poll_until_terminal() would
         see the pre-submission status still in TERMINAL_STATUSES and return
         immediately before the job has actually started.
      4. Poll until a terminal status is reached.
      5. Stream the full activity log so the log file captures all Terraform
         output even when the job ran to completion before we began polling.

    Returns (passed, final_status, elapsed_seconds).
    """
    pre_status    = get_ws_status(ws_id)
    lock_deadline = time.time() + timeout
    attempt       = 0

    while True:
        attempt += 1
        rc, out, err = run_cmd(f"{cmd} --output json")
        combined = (out + err).lower()
        if rc == 0:
            break
        # 409 means the workspace is locked by a previous activity.  Retry within
        # the overall job timeout budget rather than failing hard on a transient lock.
        if ("409" in combined or "temporarily locked" in combined) and time.time() < lock_deadline:
            remaining = int(lock_deadline - time.time())
            tee(f"  Workspace locked (409) — retrying in 30s "
                f"(attempt {attempt}, {remaining}s remaining in budget)", lf)
            time.sleep(30)
            continue
        if out.strip():
            print(out, file=lf, flush=True)
        raise RuntimeError((err or out).strip())

    if out.strip():
        print(out, file=lf, flush=True)

    try:
        act_id = json.loads(out).get("activityid")
    except (json.JSONDecodeError, AttributeError):
        act_id = None

    tee(f"  Activity ID : {act_id or '(unavailable)'}", lf)

    t0 = time.time()
    if act_id:
        tee("  Waiting for activity to start...", lf)
        # Poll until the status changes from pre_status.  120 s is sufficient in
        # practice; if it times out, poll_until_terminal() still works correctly
        # because we check against TERMINAL_STATUSES rather than the pre-status.
        t_transition = time.time()
        while time.time() - t_transition < 120:
            if get_ws_status(ws_id) != pre_status:
                break
            time.sleep(5)

        tee("  Polling until activity completes...", lf)
        final_status, _ = poll_until_terminal(ws_id, label, lf, timeout=timeout)

        tee("  Fetching final logs...", lf)
        stream_logs(ws_id, act_id, lf)
        tee("", lf)
    else:
        # Some older Schematics API versions do not return an activity ID.
        # Fall back to pure status polling without log streaming.
        tee("  No activity ID returned — polling workspace status...", lf)
        final_status, _ = poll_until_terminal(ws_id, label, lf, timeout=timeout)

    elapsed = int(time.time() - t0)
    passed  = final_status in success_statuses
    return passed, final_status, elapsed


def fetch_outputs(ws_id, lf=None):
    """
    Retrieve Terraform output values from a Schematics workspace.

    The Schematics output API returns a list of template objects, each with an
    output_values list.  Each entry in output_values is a dict mapping output
    name to a metadata object:

        [{"output_values": [
            {"cert_manager_version": {"value": "1.14.5", "type": "string", "sensitive": false}}
        ]}]

    We flatten this into a simple {name: value} dict for use in the report.
    Returns {} on any error so callers treat missing outputs as non-fatal.
    """
    try:
        data  = ibmcloud_json(f"ibmcloud schematics output --id {ws_id}", lf)
        items = data if isinstance(data, list) else [data]
        out   = {}
        for template in items:
            for item in template.get("output_values", []):
                # Each item is {output_name: {value, type, sensitive}}
                for name, meta in item.items():
                    out[name] = meta.get("value", "") if isinstance(meta, dict) else meta
        return out
    except Exception as exc:
        if lf:
            tee(f"  WARNING: could not fetch outputs: {exc}", lf)
        return {}


# ── Report rendering ──────────────────────────────────────────────────────────

class Phase:
    """Lightweight record accumulating the result of one lifecycle phase."""
    __slots__ = ("name", "status", "duration", "error")

    def __init__(self, name):
        self.name     = name
        self.status   = "SKIP"   # overwritten to PASS/FAIL during execution
        self.duration = 0
        self.error    = None


def render_report(started_at, ws_id, ws_name, phases, outputs, overall):
    """
    Build the human-readable test report as a single string.

    KEY_OUTPUTS are printed first in the outputs section so the most important
    values are immediately visible without scrolling past long lists.  Any
    additional outputs follow below a secondary separator.
    """
    elapsed = int((datetime.now(timezone.utc) - started_at).total_seconds())
    sep = "=" * REPORT_WIDTH
    thn = "-" * REPORT_WIDTH
    lines = [
        "",
        sep,
        f"  {TITLE} — Schematics Lifecycle Runner Report",
        sep,
        f"  Started     {started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"  Workspace   {ws_name or 'not created'}",
        f"  WS ID       {ws_id   or 'not created'}",
        f"  Result      {overall}",
        f"  Total time  {elapsed}s  ({elapsed / 60:.1f} min)",
        thn,
        f"  {'Phase':<20} {'Result':<8} {'Duration':>10}",
        thn,
    ]
    for p in phases:
        lines.append(f"  {p.name:<20} {p.status:<8} {p.duration:>8}s")
        if p.error:
            lines.append(f"    !! {p.error}")

    if outputs:
        lines += [thn, "  Key Outputs", thn]
        printed = set()
        for key in KEY_OUTPUTS:
            val = outputs.get(key)
            if val is not None:
                lines.append(f"  {key}")
                lines.append(f"    {val}")
                printed.add(key)
        extras = {k: v for k, v in outputs.items() if k not in printed}
        if extras:
            lines.append(thn)
            for k, v in extras.items():
                lines.append(f"  {k}")
                lines.append(f"    {v}")

    lines += [sep, ""]
    return "\n".join(lines)


# ── Workspace info helpers ────────────────────────────────────────────────────

def _list_matching_workspaces():
    """
    Return (list_of_workspaces, error_string) for workspaces whose names begin
    with WS_NAME_PREFIX, sorted newest-first by name.

    The workspace name embeds a UTC timestamp (see build_workspace_json), so
    lexicographic descending order is equivalent to creation-time descending
    order — no additional date parsing is required.
    """
    rc, out, err = run_cmd("ibmcloud schematics workspace list --output json")
    if rc != 0:
        return None, (err or out).strip()
    try:
        data    = json.loads(out)
        ws_list = data.get("workspaces") if isinstance(data, dict) else data
        ws_list = ws_list or []
        matches = [
            w for w in ws_list
            if (w.get("name") or "").startswith(WS_NAME_PREFIX)
        ]
        matches.sort(key=lambda w: w.get("name", ""), reverse=True)
        return matches, None
    except json.JSONDecodeError as exc:
        return None, str(exc)


def _ws_status_str(w):
    """
    Extract status from a workspace list entry.

    The field location varies between Schematics API versions — check both.
    """
    return (
        w.get("status")
        or w.get("workspace_status_msg", {}).get("status_code")
        or "UNKNOWN"
    )


def show_workspace_list(tfvars_path):
    """Print a formatted table of workspaces matching WS_NAME_PREFIX and exit."""
    sep = "=" * REPORT_WIDTH
    thn = "─" * (REPORT_WIDTH - 4)

    print(f"\n{sep}")
    print(f"  {TITLE}")
    print(f"  Workspace prefix : {WS_NAME_PREFIX}")
    if tfvars_path:
        print(f"  tfvars           : {tfvars_path}")
    print(sep)

    matches, err = _list_matching_workspaces()
    if err:
        print(f"\n  ERROR: {err}\n{sep}\n")
        return 1

    print(f"\n  {thn}")
    if not matches:
        print(f"  (no workspaces found with prefix '{WS_NAME_PREFIX}')")
    else:
        for w in matches:
            status = _ws_status_str(w)
            print(f"  {status:<12}  {w.get('name', ''):<50}  {w.get('id', '')}")
    print(f"\n{sep}\n")
    return 0


def show_resources(ws_id):
    """Print the Terraform state resource list for a workspace and exit."""
    sep = "=" * REPORT_WIDTH
    print(f"\n{sep}")
    print(f"  Resources  —  {ws_id}")
    print(sep)

    rc, out, err = run_cmd(f"ibmcloud schematics state list --id {ws_id}")
    if rc != 0:
        print(f"\n  ERROR: {(err or out).strip()}\n{sep}\n")
        return 1
    if out.strip():
        for line in out.strip().splitlines():
            print(f"  {line}")
    else:
        print("  (no resources)")
    print(f"\n{sep}\n")
    return 0


def show_outputs(ws_id):
    """Print all workspace output variables and exit."""
    sep = "=" * REPORT_WIDTH
    print(f"\n{sep}")
    print(f"  Output Variables  —  {ws_id}")
    print(sep)

    outputs = fetch_outputs(ws_id)
    if not outputs:
        print("\n  (no outputs or workspace not yet applied)")
    else:
        print()
        for k, v in outputs.items():
            print(f"  {k}")
            print(f"    {v}")
    print(f"\n{sep}\n")
    return 0


def _resolve_ws_id(args_ws_id):
    """
    Return (ws_id, error_string).

    If --ws-id was supplied on the command line, use it directly.  Otherwise
    auto-detect by listing workspaces and picking the most recent match (newest
    name).  This lets --resources, --outputs, and non-create lifecycle runs
    work without requiring the user to copy-paste a workspace ID.
    """
    if args_ws_id:
        return args_ws_id, None
    matches, err = _list_matching_workspaces()
    if err:
        return None, err
    if not matches:
        return None, (
            f"No workspace with prefix '{WS_NAME_PREFIX}' found.\n"
            f"       Use --ws-id WS_ID or run --list to see available workspaces."
        )
    ws_id = matches[0].get("id")
    print(f"  Auto-detected workspace: {matches[0].get('name')}  ({ws_id})")
    return ws_id, None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description=f"{TITLE} — Schematics lifecycle runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "phases (in execution order):\n"
            "  create   create the Schematics workspace\n"
            "  plan     plan (validate) the workspace\n"
            "  apply    apply (provision) the workspace\n"
            "  destroy  destroy (deprovision) the workspace\n"
            "  delete   delete the workspace record\n"
        ),
    )
    parser.add_argument(
        "tfvars", nargs="?", default=TFVARS_DEFAULT,
        help="Path to terraform.tfvars (default: %(default)s)",
    )
    parser.add_argument("--branch", default="main",
                        help="GitHub branch to deploy (default: %(default)s)")
    parser.add_argument(
        "--phases", nargs="+", default=VALID_PHASES,
        choices=VALID_PHASES, metavar="PHASE",
        help="Phases to run (default: all). Choices: " + " ".join(VALID_PHASES),
    )
    parser.add_argument(
        "--ws-id", default=None, dest="ws_id", metavar="WS_ID",
        help="Existing workspace ID (required when 'create' is not in --phases)",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List workspaces matching this repo's name prefix and exit",
    )
    parser.add_argument(
        "--resources", action="store_true",
        help="Print workspace resource list and exit",
    )
    parser.add_argument(
        "--outputs", action="store_true",
        help="Print workspace output variables and exit",
    )
    args = parser.parse_args()

    # ── Early-exit info commands ──────────────────────────────────────────
    if args.list:
        try:
            ensure_ibmcloud_login(args.tfvars)
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1
        return show_workspace_list(args.tfvars)

    if args.resources or args.outputs:
        ws_id, err = _resolve_ws_id(args.ws_id)
        if err:
            print(f"ERROR: {err}")
            return 1
        try:
            ensure_ibmcloud_login(args.tfvars)
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1
        if args.resources:
            return show_resources(ws_id)
        return show_outputs(ws_id)

    # ── Lifecycle run ─────────────────────────────────────────────────────
    run         = set(args.phases)
    tfvars_path = args.tfvars
    branch      = args.branch

    # Guard against the common mistake of omitting --ws-id when skipping create
    needs_ws = run & {"plan", "apply", "destroy", "delete"}
    if "create" not in run and needs_ws and not args.ws_id:
        print(
            "ERROR: --ws-id is required when 'create' is not in --phases\n"
            "       Use --list to find the workspace ID."
        )
        return 1

    REPORT_DIR.mkdir(exist_ok=True)
    ts_label    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = REPORT_DIR / f"lifecycle_{ts_label}.txt"
    log_path    = REPORT_DIR / f"lifecycle_{ts_label}_logs.txt"

    started_at = datetime.now(timezone.utc)
    ws_id      = args.ws_id or None
    ws_name    = None
    phases     = []
    outputs    = {}
    overall    = "FAIL"

    with open(log_path, "w") as lf:

        def cleanup():
            """
            Best-effort destroy + delete invoked on SIGINT or unhandled exception.
            Errors are suppressed so the original failure is not masked.
            """
            if not ws_id:
                return
            tee(f"\n  Cleanup: destroying workspace {ws_id} ...", lf)
            run_cmd(f"ibmcloud schematics destroy --id {ws_id} --force", lf=lf, stream=True)
            poll_until_terminal(ws_id, "cleanup-destroy", lf, timeout=JOB_TIMEOUT)
            tee(f"  Cleanup: deleting workspace {ws_id} ...", lf)
            run_cmd(f"ibmcloud schematics workspace delete --id {ws_id} --force", lf=lf)

        def _sigint(sig, frame):
            tee("\n\nInterrupted — running cleanup...", lf)
            cleanup()
            report = render_report(started_at, ws_id, ws_name, phases, outputs, "INTERRUPTED")
            tee(report, lf)
            report_path.write_text(report)
            # Exit code 130 is the POSIX convention for Ctrl-C (128 + SIGINT=2)
            sys.exit(130)

        # Register after opening the log file so cleanup() can write to it
        signal.signal(signal.SIGINT, _sigint)

        # ── Preflight (always) ────────────────────────────────────────────
        section("PRE-FLIGHT — Check ibmcloud CLI login", lf)
        p = Phase("preflight")
        t0 = time.time()
        try:
            ensure_ibmcloud_login(tfvars_path, lf=lf)
            p.status = "PASS"
        except Exception as exc:
            p.status = "FAIL"
            p.error  = str(exc)
            tee(f"  ERROR: {exc}", lf)
        p.duration = int(time.time() - t0)
        phases.append(p)
        if p.status != "PASS":
            report = render_report(started_at, ws_id, ws_name, phases, outputs, "FAIL")
            tee(report, lf); report_path.write_text(report)
            return 1

        # ── Setup (always) ────────────────────────────────────────────────
        section("SETUP — Parse terraform.tfvars → workspace.json", lf)
        p = Phase("setup")
        t0 = time.time()
        try:
            if not Path(tfvars_path).exists():
                raise FileNotFoundError(
                    f"{tfvars_path} not found — "
                    "copy terraform.tfvars.example and fill in your values"
                )
            variables = parse_tfvars(tfvars_path)
            ws        = build_workspace_json(variables, ts_label, branch=branch)
            ws_name   = ws["name"]

            # If a workspace ID was supplied via --ws-id, resolve the real name
            # from the API so the report shows the correct display name rather
            # than the generated name we built for a potential create step
            if ws_id:
                try:
                    d = ibmcloud_json(f"ibmcloud schematics workspace get --id {ws_id}", lf)
                    ws_name = d.get("name", ws_id)
                except Exception:
                    ws_name = ws_id

            tee(f"  {len(variables)} variables parsed from {tfvars_path}", lf)
            tee(f"  Workspace name : {ws_name}", lf)
            tee(f"  Branch         : {branch}", lf)
            tee(f"  Location       : {ws['location']}", lf)
            tee(f"  Phases         : {' '.join(ph for ph in VALID_PHASES if ph in run)}", lf)
            if ws_id:
                tee(f"  WS ID (--ws-id): {ws_id}", lf)
            p.status = "PASS"
        except Exception as exc:
            p.status = "FAIL"
            p.error  = str(exc)
            tee(f"  ERROR: {exc}", lf)
        p.duration = int(time.time() - t0)
        phases.append(p)
        if p.status != "PASS":
            report = render_report(started_at, ws_id, ws_name, phases, outputs, "FAIL")
            tee(report, lf); report_path.write_text(report)
            return 1

        # ── Phase: create ─────────────────────────────────────────────────
        if "create" in run:
            section("PHASE — Create workspace", lf)
            p = Phase("create")
            t0 = time.time()
            try:
                rc, out, err = run_cmd(
                    f"ibmcloud schematics workspace new --file {WS_JSON_PATH} --output json"
                )
                if out.strip():
                    print(out, file=lf, flush=True)
                if rc != 0:
                    raise RuntimeError((err or out).strip())
                data  = json.loads(out)
                ws_id = data.get("id") or data.get("workspace_id")
                if not ws_id:
                    raise RuntimeError(f"workspace ID not in response: {out[:300]}")
                tee(f"  Workspace ID : {ws_id}", lf)
                tee("  Waiting for workspace to become ready...", lf)
                status = wait_for_workspace_ready(ws_id, lf)
                tee(f"  Ready status : {status}", lf)
                p.status = "PASS"
            except Exception as exc:
                p.status = "FAIL"
                p.error  = str(exc)
                tee(f"  ERROR: {exc}", lf)
            p.duration = int(time.time() - t0)
            phases.append(p)
            # Create is a hard prerequisite for all subsequent phases — abort early
            # rather than continuing with an invalid ws_id
            if p.status != "PASS":
                report = render_report(started_at, ws_id, ws_name, phases, outputs, "FAIL")
                tee(report, lf); report_path.write_text(report)
                return 1

        # ── Phase: plan ───────────────────────────────────────────────────
        p_plan = Phase("plan")
        if "plan" in run:
            section("PHASE — Plan workspace", lf)
            t0 = time.time()
            try:
                passed, final_status, elapsed = run_job(
                    cmd              = f"ibmcloud schematics plan --id {ws_id}",
                    ws_id            = ws_id,
                    label            = "plan",
                    lf               = lf,
                    success_statuses = {"INACTIVE", "ACTIVE"},
                    timeout          = JOB_TIMEOUT,
                )
                tee(f"  Final status : {final_status}  ({elapsed}s)", lf)
                p_plan.status = "PASS" if passed else "FAIL"
                if not passed:
                    p_plan.error = f"status after plan: {final_status}"
            except Exception as exc:
                p_plan.status = "FAIL"
                p_plan.error  = str(exc)
                tee(f"  ERROR: {exc}", lf)
            p_plan.duration = int(time.time() - t0)
        phases.append(p_plan)

        # ── Phase: apply ──────────────────────────────────────────────────
        p_apply = Phase("apply")
        if "apply" in run:
            if p_plan.status == "FAIL":
                # Don't attempt apply when plan failed — the Terraform config is
                # known-bad so apply would also fail and could leave partial resources
                p_apply.status = "SKIP"
                p_apply.error  = "skipped — plan failed"
            else:
                section("PHASE — Apply workspace", lf)
                t0 = time.time()
                try:
                    passed, final_status, elapsed = run_job(
                        cmd              = f"ibmcloud schematics apply --id {ws_id} --force",
                        ws_id            = ws_id,
                        label            = "apply",
                        lf               = lf,
                        success_statuses = {"ACTIVE"},
                        timeout          = JOB_TIMEOUT,
                    )
                    tee(f"  Final status : {final_status}  ({elapsed}s)", lf)
                    p_apply.status = "PASS" if passed else "FAIL"
                    if not passed:
                        p_apply.error = f"status after apply: {final_status}"
                    if p_apply.status == "PASS":
                        tee("  Fetching outputs...", lf)
                        outputs = fetch_outputs(ws_id, lf)
                except Exception as exc:
                    p_apply.status = "FAIL"
                    p_apply.error  = str(exc)
                    tee(f"  ERROR: {exc}", lf)
                p_apply.duration = int(time.time() - t0)
        phases.append(p_apply)

        # ── Phase: destroy ────────────────────────────────────────────────
        p_destroy = Phase("destroy")
        if "destroy" in run:
            pre = get_ws_status(ws_id) if ws_id else "UNKNOWN"
            if pre in {"INACTIVE", "DRAFT"}:
                # INACTIVE — workspace has never been applied (no managed resources)
                # DRAFT    — workspace was created but plan has not run yet
                # In both cases there is nothing for Terraform to destroy
                p_destroy.status = "SKIP"
                p_destroy.error  = f"no managed state (status={pre})"
            else:
                section("PHASE — Destroy workspace", lf)
                t0 = time.time()
                try:
                    passed, final_status, elapsed = run_job(
                        cmd              = f"ibmcloud schematics destroy --id {ws_id} --force",
                        ws_id            = ws_id,
                        label            = "destroy",
                        lf               = lf,
                        success_statuses = {"INACTIVE"},
                        timeout          = JOB_TIMEOUT,
                    )
                    tee(f"  Final status : {final_status}  ({elapsed}s)", lf)
                    p_destroy.status = "PASS" if passed else "FAIL"
                    if not passed:
                        p_destroy.error = f"status after destroy: {final_status}"
                except Exception as exc:
                    p_destroy.status = "FAIL"
                    p_destroy.error  = str(exc)
                    tee(f"  ERROR: {exc}", lf)
                p_destroy.duration = int(time.time() - t0)
        phases.append(p_destroy)

        # ── Phase: delete ─────────────────────────────────────────────────
        p_delete = Phase("delete")
        if "delete" in run and ws_id:
            section("PHASE — Delete workspace record", lf)
            t0 = time.time()
            try:
                rc, out, err = run_cmd(
                    f"ibmcloud schematics workspace delete --id {ws_id} --force"
                )
                if rc != 0:
                    raise RuntimeError((err or out).strip())
                tee("  Workspace record deleted", lf)
                p_delete.status = "PASS"
            except Exception as exc:
                p_delete.status = "FAIL"
                p_delete.error  = str(exc)
                tee(f"  ERROR: {exc}", lf)
            p_delete.duration = int(time.time() - t0)
        elif "delete" in run:
            p_delete.status = "SKIP"
            p_delete.error  = "no workspace ID — create was skipped"
        phases.append(p_delete)

        # ── Final report ──────────────────────────────────────────────────
        # Only phases that actually ran (not SKIP) contribute to the overall result
        all_run = [p for p in phases if p.status != "SKIP"]
        overall = "PASS" if all(p.status == "PASS" for p in all_run) else "FAIL"

        report = render_report(started_at, ws_id, ws_name, phases, outputs, overall)
        tee(report, lf)
        report_path.write_text(report)

        tee(f"  Log    : {log_path}", lf)
        tee(f"  Report : {report_path}", lf)

        return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
