#!/usr/bin/env bash
# AgentVM Milestone M4 ("For Coding Agents") Acceptance Script.
#
# Covers M4 acceptance table Rows 1-14 by default:
#   * Non-VM Rows 1-3 and Row 14 (host hygiene / zero-leak check) always run.
#   * Real-VM Rows 4-13 run when AGENTVM_REAL_VM=1; otherwise they print "没跑" and exit 2.
#   * Rows 15-17 (three source mutations) run via `--mutation <1|2|3>` inside an isolated
#     temporary copy of the repository so the working tree is never dirtied.
#
# Hard invariants:
#   * Never launches the desktop UI (.app, window, or bare AgentVM without a CLI subcommand).
#   * Runs the product with an isolated HOME / CFFIXED_USER_HOME and workspaces inside mktemp -d.
#   * Every host directory shared via `--mount` is a freshly created `mktemp -d` directory.
#   * Clones Debian 12 image cache into mktemp -d via `cp -c` and verifies source cache SHA-256 unchanged.
#   * Copies the built binary into mktemp -d and ad-hoc signs the copy with virtualization entitlement.
#   * Never exceeds 2 concurrent VirtualMachine processes; matches `com.apple.Virtualization.VirtualMachine`
#     strictly by process name (`comm`), never touching pre-existing foreign VMs/daemons.
#   * Never invokes real external agent CLIs (claude, codex, agy, vibe) or sets RELAY_REAL_AGENTS.
#   * Scrubs host home-directory and temporary paths from all output and recorded reports.
set -euo pipefail

MUTATION_ID=""
RECORD_REPORTS=0
OUT_DIR=""

usage() {
    cat >&2 <<'EOF'
Usage:
  Scripts/acceptance/m4-agent.sh [--out-dir <dir>]
  AGENTVM_REAL_VM=1 Scripts/acceptance/m4-agent.sh [--record] [--out-dir <dir>]
  AGENTVM_REAL_VM=1 Scripts/acceptance/m4-agent.sh --mutation <1|2|3>

Options:
  --record            Write acceptance outputs to reports/m4-agent.txt and reports/m4-agent.json
                      (requires AGENTVM_REAL_VM=1, all rows passing, and a clean git working tree)
  --out-dir <dir>     Write m4-agent.txt and m4-agent.json into <dir> without touching reports/
  --mutation <1|2|3>  Run M4 source-mutation check in a temporary copy of the repo (Row 15, 16, or 17):
                        1 (Row 15): comment out `mounts:` in ISO9660CloudInitBuilder -> Rows 2 & 4 must fail
                        2 (Row 16): revert HostPortForwardManager to 25 ms forced stream close -> Row 10 must fail
                        3 (Row 17): revert MCP agentvm_exec_command to local executeInGuest -> Row 5 must fail
                      Verifies repository working tree remains clean/unchanged before exiting.
  -h, --help          Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --record)
            RECORD_REPORTS=1
            shift
            ;;
        --out-dir)
            [[ $# -ge 2 ]] || { echo "ERROR: --out-dir requires a directory argument" >&2; exit 64; }
            OUT_DIR="$2"
            shift 2
            ;;
        --mutation)
            [[ $# -ge 2 ]] || { echo "ERROR: --mutation requires 1, 2, or 3" >&2; exit 64; }
            case "$2" in
                1|2|3) MUTATION_ID="$2" ;;
                *) echo "ERROR: --mutation must be 1, 2, or 3 (got '$2')" >&2; exit 64 ;;
            esac
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option '$1'" >&2
            usage
            exit 64
            ;;
    esac
done

CALLER_PWD="$(pwd)"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

exec /usr/bin/python3 - "$CALLER_PWD" "$ROOT_DIR" "$MUTATION_ID" "$RECORD_REPORTS" "$OUT_DIR" <<'PY'
# -*- coding: utf-8 -*-
from __future__ import annotations

import concurrent.futures
import datetime
import hashlib
import json
import os
import platform
import plistlib
import pwd
import re
import shlex
import shutil
import signal
import socket
import stat
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request

caller_pwd, root_dir, mutation_id, record_flag_str, out_dir_arg = sys.argv[1:6]
record_reports = record_flag_str == "1"
real_home = pwd.getpwuid(os.getuid()).pw_dir.rstrip("/")
caller_env_home = os.path.expanduser("~").rstrip("/")
real_vm_enabled = os.environ.get("AGENTVM_REAL_VM", "") == "1"

if mutation_id and record_reports:
    print("ERROR: --record cannot be combined with --mutation", file=sys.stderr)
    sys.exit(64)

if mutation_id and not real_vm_enabled:
    print(f"没跑 [Row {14 + int(mutation_id)}]: --mutation {mutation_id} 需要设置 AGENTVM_REAL_VM=1")
    sys.exit(2)

CMD_TIMEOUT_SEC = 300
BYTES_64_MIB = 64 * 1024 * 1024

CLI_SUBCOMMANDS = {
    "doctor", "init", "ps", "list", "image", "create", "run", "daemon", "events",
    "up", "boot", "start", "pause", "resume", "halt", "stop",
    "branch", "fork", "snapshot", "restore", "exec", "forward", "pcap", "policy",
    "plugin", "export-hcl", "export-html", "mcp", "help", "version",
}

EXPECTED_MCP_TOOLS = [
    "agentvm_list_fleet",
    "agentvm_create_vm",
    "agentvm_fork_cow_branch",
    "agentvm_exec_command",
    "agentvm_capture_snapshot",
    "agentvm_restore_snapshot",
    "agentvm_query_wiretap",
    "agentvm_set_firewall_preset",
    "agentvm_doctor",
]

# ---------------------------------------------------------------------------
# Output scrubbing, logging, and row accounting
# ---------------------------------------------------------------------------
raw_tmp_root = ""
tmp_root = ""
source_cache_dir = ""
passed_rows = 0
failed_rows = 0
unrun_rows = 0
row_outcomes: dict[int, dict[str, str]] = {}
transcript_lines: list[str] = []
metrics_record: dict[str, object] = {}


def scrub(text: str) -> str:
    out = text
    for needle, repl in (
        (tmp_root, "$TMP_ROOT"),
        (raw_tmp_root, "$TMP_ROOT"),
        (source_cache_dir, "$AGENTVM_IMAGE_CACHE"),
        (root_dir, "."),
        (caller_env_home, "$HOME"),
        (real_home, "$HOME"),
    ):
        if needle:
            out = out.replace(needle, repl)
    return out


def emit(msg: str) -> None:
    clean = scrub(msg)
    transcript_lines.append(clean)
    print(clean, flush=True)


def emit_err(msg: str) -> None:
    clean = scrub(msg)
    transcript_lines.append(clean)
    print(clean, file=sys.stderr, flush=True)


def pass_row(row: int, detail: str) -> None:
    global passed_rows
    passed_rows += 1
    clean_detail = scrub(detail)
    row_outcomes[row] = {"status": "PASS", "detail": clean_detail}
    emit(f"PASS [Row {row}]: {clean_detail}")


def fail_row(row: int, detail: str) -> None:
    global failed_rows
    failed_rows += 1
    clean_detail = scrub(detail)
    row_outcomes[row] = {"status": "FAIL", "detail": clean_detail}
    emit_err(f"FAIL [Row {row}]: {clean_detail}")


def unrun_row(row: int, detail: str) -> None:
    global unrun_rows
    unrun_rows += 1
    clean_detail = scrub(detail)
    row_outcomes[row] = {"status": "UNRUN", "detail": clean_detail}
    emit(f"没跑 [Row {row}]: {clean_detail}")


def git_porcelain(*paths: str) -> str:
    cmd = ["git", "--no-optional-locks", "status", "--porcelain"]
    if paths:
        cmd += ["--", *paths]
    p = subprocess.run(cmd, cwd=root_dir, capture_output=True, text=True, check=True)
    return p.stdout.strip()


if record_reports:
    if not real_vm_enabled:
        emit_err("REFUSED: --record requires AGENTVM_REAL_VM=1 so all M4 rows are genuinely executed.")
        sys.exit(2)
    dirty_tree = git_porcelain()
    if dirty_tree:
        emit_err("REFUSED: --record requires a clean git working tree before writing reports/:\n" + dirty_tree)
        sys.exit(1)

# ---------------------------------------------------------------------------
# Host process, cache SHA-256, and ~/Library hygiene helpers
# ---------------------------------------------------------------------------
def has_virtualization_entitlement(bin_path: str) -> bool:
    proc = subprocess.run(["codesign", "-d", "--entitlements", ":-", bin_path], capture_output=True)
    if proc.returncode != 0 or not proc.stdout:
        return False
    try:
        ent = plistlib.loads(proc.stdout)
    except Exception:
        return False
    return isinstance(ent, dict) and ent.get("com.apple.security.virtualization") is True


def list_vz_vm_pids() -> set[int]:
    """Match strictly by process name `com.apple.Virtualization.VirtualMachine` via `ps -o pid=,comm=`."""
    try:
        proc = subprocess.run(["ps", "-axww", "-o", "pid=,comm="], capture_output=True, text=True)
    except OSError:
        return set()
    if proc.returncode != 0:
        return set()
    pids: set[int] = set()
    for raw in proc.stdout.splitlines():
        parts = raw.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            if os.path.basename(parts[1].strip()) == "com.apple.Virtualization.VirtualMachine":
                pids.add(int(parts[0]))
    return pids


def list_host_agentvm_daemons(expected_bin: str = "") -> list[tuple[int, str, str]]:
    exp_real = os.path.realpath(expected_bin) if expected_bin else ""
    try:
        proc = subprocess.run(["ps", "-axww", "-o", "pid=,command="], capture_output=True, text=True)
    except OSError:
        return []
    if proc.returncode != 0:
        return []
    found = []
    for raw in proc.stdout.splitlines():
        line = raw.strip()
        if not line or "daemon" not in line or "--workspace" not in line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        try:
            tokens = shlex.split(parts[1])
        except ValueError:
            tokens = parts[1].split()
        if len(tokens) == 5 and tokens[1:4] == ["daemon", "run", "--workspace"] and tokens[4].startswith("/"):
            cp = subprocess.run(["ps", "-ww", "-p", str(pid), "-o", "comm="], capture_output=True, text=True)
            if cp.returncode == 0 and cp.stdout.strip():
                comm_real = os.path.realpath(cp.stdout.strip())
                if os.path.basename(comm_real).lower().startswith("agentvm") or (exp_real and comm_real == exp_real):
                    found.append((pid, comm_real, os.path.realpath(tokens[4])))
    return sorted(set(found))


def list_bin_processes(bin_path: str) -> list[tuple[int, str]]:
    if not bin_path:
        return []
    real_b = os.path.realpath(bin_path)
    my_pid = os.getpid()
    try:
        proc = subprocess.run(["ps", "-axww", "-o", "pid=,command="], capture_output=True, text=True)
    except OSError:
        return []
    if proc.returncode != 0:
        return []
    hits = []
    for raw in proc.stdout.splitlines():
        parts = raw.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            pid = int(parts[0])
            if pid != my_pid and (bin_path in parts[1] or real_b in parts[1]):
                hits.append((pid, parts[1]))
    return hits


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        while True:
            chunk = fp.read(4 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def snapshot_home_hygiene() -> dict:
    res = {"launch_agents": [], "preferences": [], "app_support": []}
    la = os.path.join(real_home, "Library", "LaunchAgents")
    if os.path.isdir(la):
        items = []
        for r, ds, fs in os.walk(la):
            for n in ds + fs:
                items.append(os.path.relpath(os.path.join(r, n), la))
        res["launch_agents"] = sorted(set(items))
    for key, sub in (("preferences", "Preferences"), ("app_support", "Application Support")):
        base = os.path.join(real_home, "Library", sub)
        if os.path.isdir(base):
            items = []
            for r, ds, fs in os.walk(base):
                for n in ds + fs:
                    if "agentvm" in n.lower():
                        items.append(os.path.relpath(os.path.join(r, n), base))
            res[key] = sorted(set(items))
    return res


def snapshot_cache_dir_with_hashes(cache_dir: str) -> dict:
    if not os.path.exists(cache_dir):
        return {"exists": False, "files": {}}
    files = {}
    for r, ds, fs in os.walk(cache_dir):
        ds.sort()
        for n in sorted(fs):
            full = os.path.join(r, n)
            rel = os.path.relpath(full, cache_dir)
            st = os.lstat(full)
            digest = sha256_file(full) if stat.S_ISREG(st.st_mode) else "non-regular"
            files[rel] = {
                "ino": int(st.st_ino),
                "size": int(st.st_size),
                "mode": int(st.st_mode),
                "sha256": digest,
            }
    return {"exists": True, "files": files}


def sweep_darwin_temp_symlinks(roots: list[str], remove: bool = True) -> list[str]:
    try:
        user_tmp = os.path.realpath(
            subprocess.check_output(["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"], text=True).strip()
        )
    except Exception:
        return []
    clean_roots = sorted({os.path.realpath(r).rstrip("/") for r in roots if r} | {r.rstrip("/") for r in roots if r})
    remaining = []
    if not clean_roots or not os.path.isdir(user_tmp):
        return []
    for name in sorted(os.listdir(user_tmp)):
        if not name.startswith("avm-"):
            continue
        full = os.path.join(user_tmp, name)
        if not os.path.islink(full):
            continue
        try:
            raw_target = os.readlink(full)
        except OSError:
            continue
        resolved = os.path.realpath(os.path.join(user_tmp, raw_target))
        if any(
            raw_target == rt or raw_target.startswith(rt + "/") or resolved == rt or resolved.startswith(rt + "/")
            for rt in clean_roots
        ):
            if remove:
                try:
                    os.unlink(full)
                except OSError:
                    remaining.append(full)
            else:
                remaining.append(full)
    return remaining


def collect_host_metadata() -> dict:
    def sysctl_str(name: str) -> str:
        p = subprocess.run(["/usr/sbin/sysctl", "-n", name], capture_output=True, text=True)
        return p.stdout.strip() if p.returncode == 0 else ""

    hw_model = sysctl_str("hw.model")
    brand = sysctl_str("machdep.cpu.brand_string")
    ncpu = sysctl_str("hw.ncpu")
    mem_bytes = sysctl_str("hw.memsize")
    mem_gib = round(int(mem_bytes) / (1024 ** 3), 1) if mem_bytes.isdigit() else 0
    sw_ver = subprocess.run(["/usr/bin/sw_vers", "-productVersion"], capture_output=True, text=True).stdout.strip()
    sw_build = subprocess.run(["/usr/bin/sw_vers", "-buildVersion"], capture_output=True, text=True).stdout.strip()
    up_out = subprocess.run(["/usr/bin/uptime"], capture_output=True, text=True).stdout.strip()
    head_sha = subprocess.run(
        ["git", "--no-optional-locks", "rev-parse", "--short", "HEAD"],
        cwd=root_dir,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return {
        "date": datetime.date.today().isoformat(),
        "commit": head_sha,
        "hwModel": hw_model,
        "cpuBrand": brand,
        "logicalCores": int(ncpu) if ncpu.isdigit() else 0,
        "memoryGiB": mem_gib,
        "macOSVersion": sw_ver,
        "macOSBuild": sw_build,
        "arch": platform.machine(),
        "uptime": up_out,
    }


raw_cache_env = os.environ.get("AGENTVM_IMAGE_CACHE", "").strip()
if raw_cache_env:
    if raw_cache_env == "~":
        source_cache_dir = real_home
    elif raw_cache_env.startswith("~/"):
        source_cache_dir = os.path.abspath(os.path.join(real_home, raw_cache_env[2:]))
    else:
        source_cache_dir = os.path.abspath(raw_cache_env)
else:
    source_cache_dir = os.path.join(real_home, "Library", "Caches", "AgentVM", "images")

user_bin_env = os.environ.get("AGENTVM_BIN", "").strip()
resolved_bin = ""
if user_bin_env and not mutation_id:
    cand = user_bin_env if os.path.isabs(user_bin_env) else (
        os.path.join(caller_pwd, user_bin_env)
        if os.path.exists(os.path.join(caller_pwd, user_bin_env))
        else os.path.join(root_dir, user_bin_env)
    )
    resolved_bin = os.path.realpath(cand)
    if not (os.path.isfile(resolved_bin) and os.access(resolved_bin, os.X_OK)):
        emit_err("ERROR: AGENTVM_BIN does not exist or is not executable.")
        sys.exit(1)
    if real_vm_enabled and not has_virtualization_entitlement(resolved_bin):
        emit_err("REFUSED: AGENTVM_BIN lacks com.apple.security.virtualization entitlement.")
        sys.exit(1)

baseline_vz_pids = list_vz_vm_pids()
baseline_daemons = list_host_agentvm_daemons(resolved_bin)
baseline_home = snapshot_home_hygiene()
cache_before = snapshot_cache_dir_with_hashes(source_cache_dir)

raw_tmp_root = tempfile.mkdtemp(prefix="avm_m4_agent_")
tmp_root = os.path.realpath(raw_tmp_root)
isolated_home = os.path.join(tmp_root, "home")
isolated_tmp = os.path.join(tmp_root, "tmp")
local_cache_dir = os.path.join(tmp_root, "image_cache")
bin_dir = os.path.join(tmp_root, "bin")
ws_offline = os.path.join(tmp_root, "ws_offline.agentvm")
ws_real = os.path.join(tmp_root, "ws_real.agentvm")
tracked_workspaces: list[str] = [ws_offline, ws_real]

os.makedirs(os.path.join(isolated_home, "Library", "Preferences"), exist_ok=True)
for d in (isolated_tmp, local_cache_dir, bin_dir):
    os.makedirs(d, exist_ok=True)


def extra_vz_pids() -> set[int]:
    return list_vz_vm_pids() - baseline_vz_pids


def wait_for_extra_vz_count(expected: int, timeout_sec: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() <= deadline:
        if len(extra_vz_pids()) == expected:
            return True
        time.sleep(0.15)
    return len(extra_vz_pids()) == expected


def check_vm_cap(limit: int = 2) -> int:
    cnt = len(extra_vz_pids())
    if cnt > limit:
        raise RuntimeError(f"Concurrent VM cap ({limit}) exceeded: {cnt} extra VirtualMachine PIDs active")
    return cnt


def swift_jobs_args() -> list[str]:
    j = os.environ.get("AGENTVM_BUILD_JOBS", "").strip()
    return ["-j", j] if j else []


def build_and_sign_binary(src_repo_dir: str, dest_name: str = "AgentVM", sign_for_vz: bool = False) -> str:
    b_env = dict(os.environ)
    b_env["HOME"] = isolated_home
    b_env["CFFIXED_USER_HOME"] = isolated_home
    bproc = subprocess.run(
        ["swift", "build", *swift_jobs_args(), "--product", "AgentVM"],
        cwd=src_repo_dir,
        env=b_env,
        capture_output=True,
        text=True,
    )
    if bproc.returncode != 0:
        combined = (bproc.stdout + "\n" + bproc.stderr).strip()
        err_out = combined if len(combined) <= 3000 else (combined[:1200] + "\n...\n" + combined[-1500:])
        raise RuntimeError(f"swift build --product AgentVM failed in {scrub(src_repo_dir)}:\n{err_out}")
    built = os.path.realpath(os.path.join(src_repo_dir, ".build", "debug", "AgentVM"))
    dst = os.path.join(bin_dir, dest_name)
    shutil.copy2(built, dst)
    os.chmod(dst, 0o755)
    if sign_for_vz:
        ent_plist = os.path.join(src_repo_dir, "Scripts", "entitlements.plist")
        cs = subprocess.run(
            ["codesign", "--force", "--sign", "-", "--entitlements", ent_plist, dst],
            capture_output=True,
            text=True,
        )
        if cs.returncode != 0 or not has_virtualization_entitlement(dst):
            raise RuntimeError(f"codesign failed on {scrub(dst)}: {cs.stderr}")
    return os.path.realpath(dst)


def isolated_env() -> dict[str, str]:
    env = dict(os.environ)
    for k in ("AGENTVM_WORKSPACE", "AGENTVM_REAL_VM", "AGENTVM_LANG", "RELAY_REAL_AGENTS", "RELAY_WORKER"):
        env.pop(k, None)
    env["HOME"] = isolated_home
    env["CFFIXED_USER_HOME"] = isolated_home
    env["TMPDIR"] = isolated_tmp
    env["AGENTVM_IMAGE_CACHE"] = local_cache_dir
    return env


def run_avm(args: list[str], timeout_sec: int = CMD_TIMEOUT_SEC, check: bool = True, bin_override: str = "") -> dict:
    exe = bin_override or resolved_bin
    host_args = args[: args.index("--")] if "--" in args else args
    if not any(tok in CLI_SUBCOMMANDS for tok in host_args):
        raise RuntimeError(f"REFUSED: command {args!r} has no CLI subcommand")
    env = isolated_env()
    t0 = time.perf_counter()
    proc = subprocess.run(
        ["/usr/bin/perl", "-e", f"alarm {int(timeout_sec)}; exec @ARGV", exe, *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout_sec + 10,
    )
    wall_ms = (time.perf_counter() - t0) * 1000.0
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"agentvm {' '.join(args)} exited {proc.returncode} ({wall_ms:.1f} ms):\n"
            f"STDOUT: {scrub(proc.stdout)}\nSTDERR: {scrub(proc.stderr)}"
        )
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "wallMs": wall_ms,
    }


def stage_image_cache_copy(bin_override: str = "") -> None:
    dst_raw = os.path.join(local_cache_dir, "debian-12-bookworm-arm64.raw")
    dst_idx = os.path.join(local_cache_dir, "catalog-index.json")
    if os.path.isfile(dst_raw) and os.path.isfile(dst_idx):
        return
    src_raw = os.path.join(source_cache_dir, "debian-12-bookworm-arm64.raw")
    src_idx = os.path.join(source_cache_dir, "catalog-index.json")
    if not (os.path.isfile(src_raw) and os.path.isfile(src_idx)):
        run_avm(
            ["--lang", "en", "--workspace", ws_real, "image", "pull", "debian-12-bookworm-arm64"],
            timeout_sec=900,
            bin_override=bin_override,
        )
    else:
        if subprocess.run(["/bin/cp", "-c", src_raw, dst_raw], capture_output=True).returncode != 0:
            shutil.copy2(src_raw, dst_raw)
        if subprocess.run(["/bin/cp", "-c", src_idx, dst_idx], capture_output=True).returncode != 0:
            shutil.copy2(src_idx, dst_idx)
        os.chmod(dst_raw, 0o444)


def reserve_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def is_port_listening(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return s.connect_ex(("127.0.0.1", port)) == 0


def stop_tracked_workspaces(bin_override: str = "") -> None:
    exe = bin_override or resolved_bin
    if exe and os.path.isfile(exe):
        for ws in list(tracked_workspaces):
            if os.path.exists(ws):
                try:
                    run_avm(["--lang", "en", "--workspace", ws, "daemon", "stop"], timeout_sec=65, check=False, bin_override=exe)
                except Exception:
                    pass
    ws_reals = {os.path.realpath(ws) for ws in tracked_workspaces if ws}
    for pid, _comm, d_ws in list_host_agentvm_daemons():
        if d_ws in ws_reals or d_ws.startswith(tmp_root + "/"):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    if exe:
        for pid, _cmd in list_bin_processes(exe):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    if real_vm_enabled:
        wait_for_extra_vz_count(0, timeout_sec=30.0)


cleanup_done = False


def cleanup_temp_tree(bin_override: str = "") -> None:
    global cleanup_done
    if cleanup_done:
        return
    cleanup_done = True
    stop_tracked_workspaces(bin_override=bin_override)
    sweep_darwin_temp_symlinks([tmp_root, raw_tmp_root], remove=True)
    for p in (tmp_root, raw_tmp_root):
        if p and os.path.exists(p):
            for r, ds, fs in os.walk(p):
                for n in ds + fs:
                    try:
                        os.chmod(os.path.join(r, n), 0o700)
                    except OSError:
                        pass
            shutil.rmtree(p, ignore_errors=True)


class MCPStdioSession:
    def __init__(self, bin_path: str, workspace: str) -> None:
        self.proc = subprocess.Popen(
            [bin_path, "--lang", "en", "--workspace", workspace, "mcp"],
            env=isolated_env(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._next_id = 1

    def request(self, method: str, params: dict | None = None) -> dict:
        req_id = self._next_id
        self._next_id += 1
        payload: dict[str, object] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"MCP server EOF on {method} (id={req_id}): {err}")
        return json.loads(line)

    def notify_initialized(self) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        self.proc.stdin.flush()

    def initialize(self) -> list[str]:
        init_resp = self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "m4-agent-acceptance", "version": "1.0.0"},
            },
        )
        if init_resp.get("result", {}).get("serverInfo", {}).get("name") != "agentvm-mcp":
            raise RuntimeError(f"Unexpected MCP initialize response: {init_resp}")
        self.notify_initialized()
        tools_resp = self.request("tools/list")
        return [t["name"] for t in tools_resp["result"]["tools"]]

    def call_tool(self, name: str, arguments: dict) -> tuple[bool, str]:
        resp = self.request("tools/call", {"name": name, "arguments": arguments})
        if "result" not in resp:
            raise RuntimeError(f"MCP JSON-RPC error for {name}: {resp}")
        res = resp["result"]
        text = "\n".join(item.get("text", "") for item in res.get("content", []))
        return bool(res.get("isError")), text

    def close(self) -> int:
        if self.proc.stdin:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        try:
            return self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# Reusable row check functions (shared by normal and --mutation modes)
# ---------------------------------------------------------------------------
def check_row1(ws: str, bin_override: str = "") -> tuple[bool, str]:
    run_avm(["--lang", "en", "--workspace", ws, "init"], bin_override=bin_override)
    valid_d1 = tempfile.mkdtemp(prefix="r1_d1_", dir=tmp_root)
    valid_d2 = tempfile.mkdtemp(prefix="r1_d2_", dir=tmp_root)
    reg_file = os.path.join(tmp_root, "r1_regular_file.txt")
    with open(reg_file, "w", encoding="utf-8") as fp:
        fp.write("not a directory\n")
    missing_dir = os.path.join(tmp_root, "r1_nonexistent_dir")

    cases = [
        ("m-bad", ["--mount", f"{missing_dir}:/workspace"], 1, missing_dir),
        ("m-file", ["--mount", f"{reg_file}:/workspace"], 1, reg_file),
        ("m-rel", ["--mount", f"{valid_d1}:relative"], 2, "relative"),
        ("m-nocolon", ["--mount", valid_d1], 2, ":"),
        ("m-suffix", ["--mount", f"{valid_d1}:/workspace:rw"], 2, ":rw"),
        ("m-dup", ["--mount", f"{valid_d1}:/workspace", "--mount", f"{valid_d2}:/workspace/"], 2, "/workspace"),
    ]
    observed_codes = []
    problems = []
    for vm_name, mount_args, exp_rc, exp_substr in cases:
        res = run_avm(["--lang", "en", "--workspace", ws, "create", vm_name, *mount_args], check=False, bin_override=bin_override)
        observed_codes.append(res["returncode"])
        if res["returncode"] != exp_rc:
            problems.append(f"{vm_name}: expected exit {exp_rc}, got {res['returncode']} (stderr={res['stderr'].strip()!r})")
        if exp_substr not in res["stderr"]:
            problems.append(f"{vm_name}: stderr missing {scrub(exp_substr)!r}: {scrub(res['stderr']).strip()!r}")

    vms = json.loads(run_avm(["--lang", "en", "--workspace", ws, "ps", "--json"], bin_override=bin_override)["stdout"])
    if vms:
        problems.append(f"ps --json not empty after rejected creates: {[v['spec']['name'] for v in vms]}")
    for sub in ("disks", "isos"):
        sub_path = os.path.join(ws, sub)
        leftovers = os.listdir(sub_path) if os.path.isdir(sub_path) else []
        if leftovers:
            problems.append(f"{sub}/ has leftover files: {leftovers}")

    if problems:
        return False, "; ".join(problems)
    return True, f"6 invalid --mount cases exited {observed_codes} with diagnostic stderr; 0 orphan VM records or disk/ISO files"


def check_row2(ws: str, bin_override: str = "") -> tuple[bool, str]:
    off_rw = tempfile.mkdtemp(prefix="r2_rw_", dir=tmp_root)
    off_ro = tempfile.mkdtemp(prefix="r2_ro_", dir=tmp_root)
    run_avm(
        ["--lang", "en", "--workspace", ws, "create", "m1", "--mount", f"{off_rw}:/workspace", "--mount", f"{off_ro}:/mnt/ro:ro"],
        bin_override=bin_override,
    )
    run_avm(["--lang", "en", "--workspace", ws, "branch", "m1", "m2"], bin_override=bin_override)
    run_avm(["--lang", "en", "--workspace", ws, "branch", "m1", "m3", "--no-mounts"], bin_override=bin_override)

    vms = {
        v["spec"]["name"]: v
        for v in json.loads(run_avm(["--lang", "en", "--workspace", ws, "ps", "--json"], bin_override=bin_override)["stdout"])
    }
    problems = []
    for name in ("m1", "m2"):
        mounts = vms[name]["spec"].get("virtioFSMounts", [])
        by_guest = {m["guestMountPoint"]: m for m in mounts}
        if set(by_guest.keys()) != {"/workspace", "/mnt/ro"}:
            problems.append(f"{name} virtioFSMounts={mounts}")
        elif by_guest["/workspace"]["readOnly"] is not False or by_guest["/mnt/ro"]["readOnly"] is not True:
            problems.append(f"{name} readOnly mismatch: {mounts}")

        ext_dir = tempfile.mkdtemp(prefix=f"r2_iso_{name}_", dir=tmp_root)
        iso_path = vms[name]["spec"]["cloudInitISOPath"]
        tp = subprocess.run(["/usr/bin/tar", "-xf", iso_path, "-C", ext_dir], capture_output=True, text=True)
        if tp.returncode != 0:
            problems.append(f"tar -xf {name} ISO failed: {tp.stderr}")
            continue
        ud = open(os.path.join(ext_dir, "user-data"), encoding="utf-8").read()
        for token in (
            "bootcmd:",
            "mkdir -p /workspace",
            "/mnt/ro",
            "mounts:",
            "virtiofs",
            "rw,nofail,x-systemd.before=local-fs.target",
            "ro,nofail,x-systemd.before=local-fs.target",
        ):
            if token not in ud:
                problems.append(f"{name} user-data missing {token!r}")

    if vms["m3"]["spec"].get("virtioFSMounts"):
        problems.append(f"m3 (--no-mounts) retained virtioFSMounts: {vms['m3']['spec']['virtioFSMounts']}")
    ext_m3 = tempfile.mkdtemp(prefix="r2_iso_m3_", dir=tmp_root)
    subprocess.run(["/usr/bin/tar", "-xf", vms["m3"]["spec"]["cloudInitISOPath"], "-C", ext_m3], check=True, capture_output=True)
    ud_m3 = open(os.path.join(ext_m3, "user-data"), encoding="utf-8").read()
    if "mounts:" in ud_m3 or "virtiofs" in ud_m3 or "/mnt/ro" in ud_m3:
        problems.append("m3 (--no-mounts) user-data still contains parent virtiofs/mounts entries")

    if problems:
        return False, "; ".join(problems)
    return (
        True,
        "m1 & branched m2 cidata user-data have /workspace + /mnt/ro bootcmd & rw/ro virtiofs mounts "
        "(x-systemd.before=local-fs.target); m3 (--no-mounts) stripped virtioFSMounts & mounts:",
    )


def check_row3(ws: str, bin_override: str = "") -> tuple[bool, str]:
    exe = bin_override or resolved_bin
    sess = MCPStdioSession(exe, ws)
    try:
        tools = sess.initialize()
        if tools != EXPECTED_MCP_TOOLS:
            return False, f"tools/list mismatch: {tools}"
        err_w, txt_w = sess.call_tool("agentvm_query_wiretap", {"limit": 5})
        err_f, txt_f = sess.call_tool("agentvm_set_firewall_preset", {"preset": "airgap"})
        err_e, txt_e = sess.call_tool("agentvm_exec_command", {"vmID": "m1", "executable": "uname", "arguments": ["-r"]})
    finally:
        mcp_rc = sess.close()

    problems = []
    if mcp_rc != 0:
        problems.append(f"mcp exited {mcp_rc}")
    if not err_w or "M5" not in txt_w or "SIMULATED" in txt_w:
        problems.append(f"query_wiretap unexpected: isError={err_w}, text={txt_w!r}")
    if not err_f or "M5" not in txt_f or "SIMULATED" in txt_f:
        problems.append(f"set_firewall_preset unexpected: isError={err_f}, text={txt_f!r}")
    if not err_e or "ERR_LIFECYCLE_STATE" not in txt_e or "SIMULATED" in txt_e:
        problems.append(f"stopped exec unexpected: isError={err_e}, text={txt_e!r}")
    if extra_vz_pids():
        problems.append(f"offline MCP check spawned VMs: {sorted(extra_vz_pids())}")
    if problems:
        return False, "; ".join(problems)
    return (
        True,
        "agentvm_query_wiretap & agentvm_set_firewall_preset returned isError=true (ERR_UNIMPLEMENTED_BEFORE_M5); "
        "stopped-VM agentvm_exec_command returned isError=true (ERR_LIFECYCLE_STATE), 0 simulated lines, 0 VMs",
    )


def check_row4(ws: str, rw_dir: str, ro_dir: str, bin_override: str = "") -> tuple[bool, str]:
    c_res = run_avm(
        [
            "--lang", "en", "--workspace", ws,
            "create", "t1",
            "--image", "debian-12-bookworm-arm64",
            "--disk-size", "8G",
            "--mount", f"{rw_dir}:/workspace",
            "--mount", f"{ro_dir}:/mnt/ro:ro",
        ],
        check=False,
        bin_override=bin_override,
    )
    if c_res["returncode"] != 0:
        return False, f"create t1 failed ({c_res['returncode']}): {c_res['stderr'].strip()}"
    u_res = run_avm(["--lang", "en", "--workspace", ws, "up", "t1"], check=False, bin_override=bin_override)
    if u_res["returncode"] != 0:
        return False, f"up t1 failed ({u_res['returncode']}): {u_res['stderr'].strip()}"
    check_vm_cap(2)

    m_ws = run_avm(
        ["--lang", "en", "--workspace", ws, "exec", "t1", "--", "findmnt", "-n", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", "/workspace"],
        check=False,
        bin_override=bin_override,
    )
    m_ro = run_avm(
        ["--lang", "en", "--workspace", ws, "exec", "t1", "--", "findmnt", "-n", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", "/mnt/ro"],
        check=False,
        bin_override=bin_override,
    )
    if m_ws["returncode"] != 0 or "virtiofs" not in m_ws["stdout"]:
        return False, f"/workspace not mounted as virtiofs (rc={m_ws['returncode']}, out={m_ws['stdout'].strip()!r})"
    if m_ro["returncode"] != 0 or "virtiofs" not in m_ro["stdout"] or "ro" not in m_ro["stdout"]:
        return False, f"/mnt/ro not mounted ro virtiofs (rc={m_ro['returncode']}, out={m_ro['stdout'].strip()!r})"
    return (
        True,
        f"up t1={u_res['wallMs']:.0f}ms; findmnt /workspace='{m_ws['stdout'].strip()}', /mnt/ro='{m_ro['stdout'].strip()}'",
    )


def check_row5(ws: str, bin_override: str = "") -> tuple[bool, str, str]:
    exe = bin_override or resolved_bin
    cli_u = run_avm(["--lang", "en", "--workspace", ws, "exec", "t1", "--", "uname", "-r"], bin_override=exe)
    cli_kernel = cli_u["stdout"].strip()
    sess = MCPStdioSession(exe, ws)
    try:
        tools = sess.initialize()
        err_lf, txt_lf = sess.call_tool("agentvm_list_fleet", {})
        err_ex, txt_ex = sess.call_tool("agentvm_exec_command", {"vmID": "t1", "executable": "uname", "arguments": ["-r"]})
    finally:
        mcp_rc = sess.close()

    if tools != EXPECTED_MCP_TOOLS:
        return False, f"tools/list mismatch: {tools}", cli_kernel
    if err_lf or "SIMULATED" in txt_lf:
        return False, f"agentvm_list_fleet failed: isError={err_lf}, text={txt_lf[:300]!r}", cli_kernel
    fleet = json.loads(txt_lf)
    t1_rec = next((v for v in fleet if v["spec"]["name"] == "t1"), None)
    if not t1_rec or t1_rec["telemetry"]["state"] != "running" or t1_rec["telemetry"]["simulated"] is not False:
        return False, f"agentvm_list_fleet t1 state invalid: {t1_rec}", cli_kernel
    expected_txt = f"exitCode=0\nstdout:\n{cli_kernel}\n\nstderr:\n"
    if err_ex or txt_ex != expected_txt or "SIMULATED" in txt_ex or mcp_rc != 0:
        return False, f"MCP exec failed: isError={err_ex}, mcp_rc={mcp_rc}, got={txt_ex!r}, expected={expected_txt!r}", cli_kernel
    return (
        True,
        f"tools/list=9 tools, list_fleet t1=running (simulated=false), MCP exec uname -r='{cli_kernel}' == CLI exec",
        cli_kernel,
    )


def start_guest_http_server_8000(ws: str, vm_name: str, bin_override: str = "") -> None:
    cmd = (
        "nohup python3 -m http.server 8000 --bind 127.0.0.1 --directory /workspace "
        ">/tmp/avm_http8000.log 2>&1 </dev/null & "
        "for i in $(seq 1 50); do "
        "python3 -c 'import socket; s=socket.create_connection((\"127.0.0.1\",8000),0.2); s.close()' 2>/dev/null && exit 0; "
        "sleep 0.1; done; exit 1"
    )
    run_avm(["--lang", "en", "--workspace", ws, "exec", vm_name, "--", "/bin/sh", "-c", cmd], bin_override=bin_override)


def check_row10_halfclose_only(ws: str, vm_name: str, bin_override: str = "") -> tuple[bool, str]:
    srv_cmd = (
        "cat >/tmp/delayed_srv.py <<'PY'\n"
        "import socket, time\n"
        "srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "srv.bind(('127.0.0.1', 8001))\n"
        "srv.listen(8)\n"
        "while True:\n"
        "    conn, _ = srv.accept()\n"
        "    chunks = []\n"
        "    while True:\n"
        "        b = conn.recv(4096)\n"
        "        if not b:\n"
        "            break\n"
        "        chunks.append(b)\n"
        "    req = b''.join(chunks)\n"
        "    time.sleep(0.10)\n"
        "    conn.sendall(b'DELAYED_REPLY_OK:' + req)\n"
        "    conn.close()\n"
        "PY\n"
        "nohup python3 -u /tmp/delayed_srv.py >/tmp/delayed8001.log 2>&1 </dev/null &\n"
        "for i in $(seq 1 50); do "
        "python3 -c 'import socket; s=socket.socket(); r=s.connect_ex((\"127.0.0.1\",8001)); s.close(); exit(0 if r==0 else 1)' && exit 0; "
        "sleep 0.05; done; exit 1"
    )
    run_avm(["--lang", "en", "--workspace", ws, "exec", vm_name, "--", "/bin/sh", "-c", srv_cmd], bin_override=bin_override)
    hc_port = reserve_free_port()
    f_res = run_avm(
        ["--lang", "en", "--workspace", ws, "forward", vm_name, f"{hc_port}:8001"],
        check=False,
        bin_override=bin_override,
    )
    if f_res["returncode"] != 0:
        return False, f"forward {hc_port}:8001 exited {f_res['returncode']}: {f_res['stderr'].strip()}"
    try:
        with socket.create_connection(("127.0.0.1", hc_port), timeout=5.0) as s:
            s.sendall(b"PING_M4")
            s.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
        reply = b"".join(chunks).decode("utf-8", errors="replace")
    except OSError as exc:
        return False, f"half-close socket error: {exc}"
    finally:
        run_avm(
            ["--lang", "en", "--workspace", ws, "forward", "stop", vm_name, str(hc_port)],
            check=False,
            bin_override=bin_override,
        )

    if reply != "DELAYED_REPLY_OK:PING_M4":
        return False, f"SHUT_WR + 100ms delayed reply truncated/mismatched: got {reply!r}"
    return True, f"SHUT_WR + 100ms delayed reply received intact ({reply!r})"


def parse_unittest_output(text: str) -> tuple[int, bool, list[tuple[str, str]]]:
    m = re.search(r"^Ran (\d+) tests? in [0-9.]+s$", text, flags=re.MULTILINE)
    count = int(m.group(1)) if m else -1
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    ok_tail = bool(lines) and (lines[-1] == "OK" or lines[-1].startswith("OK ("))
    cases = []
    for ln in text.splitlines():
        cm = re.match(r"^(test_[A-Za-z0-9_]+)\s+\(([^)]+)\)\s+\.\.\.\s+(\S+)\s*$", ln.strip())
        if cm:
            method_name, qual, status = cm.group(1), cm.group(2), cm.group(3)
            fq_name = qual if qual.endswith("." + method_name) else f"{qual}.{method_name}"
            cases.append((fq_name, status))
    return sorted(cases) if False else (count, ok_tail, sorted(cases))


# ---------------------------------------------------------------------------
# Source-Mutation Mode (`--mutation 1|2|3` -> Row 15, 16, or 17)
# ---------------------------------------------------------------------------
def create_temp_repo_copy(mid: str) -> str:
    mut_repo = os.path.join(tmp_root, f"repo_mut_{mid}")
    os.makedirs(mut_repo, exist_ok=True)
    ls_proc = subprocess.run(
        ["git", "--no-optional-locks", "ls-files", "-z"],
        cwd=root_dir,
        capture_output=True,
        check=True,
    )
    rel_paths = [p.decode("utf-8") for p in ls_proc.stdout.split(b"\0") if p]
    extra_script = os.path.join("Scripts", "acceptance", "m4-agent.sh")
    if extra_script not in rel_paths and os.path.isfile(os.path.join(root_dir, extra_script)):
        rel_paths.append(extra_script)
    for rel in rel_paths:
        src = os.path.join(root_dir, rel)
        if not os.path.exists(src) or os.path.isdir(src):
            continue
        dst = os.path.join(mut_repo, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
    return mut_repo


def run_mutation_mode(mid: str) -> int:
    row_num = 14 + int(mid)
    emit("==================================================================")
    emit(f" AgentVM Milestone M4 Mutation Check --mutation {mid} (Row {row_num})")
    emit("==================================================================")

    pre_sources = git_porcelain("Sources")
    if pre_sources:
        emit_err(f"REFUSED [Row {row_num}]: Sources/ is not clean before --mutation {mid}:\n{pre_sources}")
        return 1
    pre_all = git_porcelain()

    mut_bin = ""
    caught = False
    detail = ""
    try:
        mut_repo = create_temp_repo_copy(mid)
        if mid == "1":
            iso_file = os.path.join(mut_repo, "Sources", "AgentVMStorageCoW", "ISO9660CloudInitBuilder.swift")
            src = open(iso_file, encoding="utf-8").read()
            target = (
                '        if !nonEmptyMounts.isEmpty {\n'
                '            lines.append("mounts:")\n'
                '            for entry in nonEmptyMounts {\n'
                '                let renderedFields = entry.map { Self.yamlMountField($0) }.joined(separator: ", ")\n'
                '                lines.append("  - [\\(renderedFields)]")\n'
                '            }\n'
                '        }'
            )
            if target not in src:
                raise RuntimeError("Mutation 1 target block not found in ISO9660CloudInitBuilder.swift")
            patched = src.replace(target, "        // MUTATION 1: mounts: YAML output commented out", 1)
            open(iso_file, "w", encoding="utf-8").write(patched)

            mut_bin = build_and_sign_binary(mut_repo, dest_name="AgentVM-mut1", sign_for_vz=True)
            stage_image_cache_copy(bin_override=mut_bin)

            ws_m1_off = os.path.join(tmp_root, "ws_mut1_off.agentvm")
            ws_m1_vm = os.path.join(tmp_root, "ws_mut1_vm.agentvm")
            tracked_workspaces.extend([ws_m1_off, ws_m1_vm])
            run_avm(["--lang", "en", "--workspace", ws_m1_off, "init"], bin_override=mut_bin)
            r2_ok, r2_msg = check_row2(ws_m1_off, bin_override=mut_bin)

            rw_m1 = tempfile.mkdtemp(prefix="mut1_rw_", dir=tmp_root)
            ro_m1 = tempfile.mkdtemp(prefix="mut1_ro_", dir=tmp_root)
            r4_ok, r4_msg = check_row4(ws_m1_vm, rw_m1, ro_m1, bin_override=mut_bin)
            run_avm(["--lang", "en", "--workspace", ws_m1_vm, "halt", "t1"], check=False, bin_override=mut_bin)
            run_avm(["--lang", "en", "--workspace", ws_m1_vm, "daemon", "stop"], check=False, bin_override=mut_bin)

            caught = (not r2_ok) and (not r4_ok)
            detail = f"Row 2 ok={r2_ok} ({r2_msg}); Row 4 ok={r4_ok} ({r4_msg})"

        elif mid == "2":
            hpf_file = os.path.join(mut_repo, "Sources", "AgentVMVsockRPC", "HostPortForwardManager.swift")
            src = open(hpf_file, encoding="utf-8").read()
            target_eof = (
                "                } else if outcomeBox.didSeeCleanEOF {\n"
                "                    try? await vsockSession.halfClosePortForwardWrite(streamID: streamID)\n"
                "                }"
            )
            target_wait = (
                "                } else {\n"
                "                    clientSocket.shutdownWrite()\n"
                "                }\n"
                "            }\n\n"
                "            await group.waitForAll()\n"
                "        }\n\n"
                "        try? await vsockSession.closePortForwardStream(streamID: streamID)"
            )
            if src.count(target_eof) != 1 or src.count(target_wait) != 1:
                raise RuntimeError("Mutation 2 target blocks did not match uniquely in HostPortForwardManager.swift")
            patched = src.replace(
                target_eof,
                "                } else if outcomeBox.didSeeCleanEOF {\n"
                "                    // MUTATION 2: omit halfClosePortForwardWrite\n"
                "                }",
                1,
            ).replace(
                target_wait,
                "                } else {\n"
                "                    clientSocket.shutdownWrite()\n"
                "                }\n"
                "            }\n\n"
                "            _ = await group.next()\n"
                "            try? await Task.sleep(nanoseconds: 25_000_000)\n"
                "            try? await vsockSession.closePortForwardStream(streamID: streamID)\n"
                "            group.cancelAll()\n"
                "        }\n\n"
                "        try? await vsockSession.closePortForwardStream(streamID: streamID)",
                1,
            )
            open(hpf_file, "w", encoding="utf-8").write(patched)

            mut_bin = build_and_sign_binary(mut_repo, dest_name="AgentVM-mut2", sign_for_vz=True)
            stage_image_cache_copy(bin_override=mut_bin)

            ws_m2 = os.path.join(tmp_root, "ws_mut2.agentvm")
            tracked_workspaces.append(ws_m2)
            rw_m2 = tempfile.mkdtemp(prefix="mut2_rw_", dir=tmp_root)
            ro_m2 = tempfile.mkdtemp(prefix="mut2_ro_", dir=tmp_root)
            r4_ok, r4_msg = check_row4(ws_m2, rw_m2, ro_m2, bin_override=mut_bin)
            if not r4_ok:
                raise RuntimeError(f"Mutation 2 VM setup failed unexpectedly: {r4_msg}")
            r10_ok, r10_msg = check_row10_halfclose_only(ws_m2, "t1", bin_override=mut_bin)
            run_avm(["--lang", "en", "--workspace", ws_m2, "halt", "t1"], check=False, bin_override=mut_bin)
            run_avm(["--lang", "en", "--workspace", ws_m2, "daemon", "stop"], check=False, bin_override=mut_bin)

            caught = not r10_ok
            detail = f"Row 10 half-close 100ms check ok={r10_ok} ({r10_msg})"

        elif mid == "3":
            mcp_file = os.path.join(mut_repo, "Sources", "AgentVMCLIAndMCP", "AgentVMMCPServer.swift")
            src = open(mcp_file, encoding="utf-8").read()
            target_mcp = (
                "            let resolvedVMID = try await resolveMCPVMID(vmToken)\n\n"
                "            if isSimulation {\n"
                "                let res = try await coordinator.executeInGuest("
            )
            if target_mcp not in src:
                raise RuntimeError("Mutation 3 target block not found in AgentVMMCPServer.swift")
            patched = src.replace(
                target_mcp,
                "            let resolvedVMID = try await resolveMCPVMID(vmToken)\n\n"
                "            if isSimulation || !wsURL.path.isEmpty { // MUTATION 3: force local coordinator.executeInGuest\n"
                "                let res = try await coordinator.executeInGuest(",
                1,
            )
            open(mcp_file, "w", encoding="utf-8").write(patched)

            mut_bin = build_and_sign_binary(mut_repo, dest_name="AgentVM-mut3", sign_for_vz=True)
            stage_image_cache_copy(bin_override=mut_bin)

            ws_m3 = os.path.join(tmp_root, "ws_mut3.agentvm")
            tracked_workspaces.append(ws_m3)
            rw_m3 = tempfile.mkdtemp(prefix="mut3_rw_", dir=tmp_root)
            ro_m3 = tempfile.mkdtemp(prefix="mut3_ro_", dir=tmp_root)
            r4_ok, r4_msg = check_row4(ws_m3, rw_m3, ro_m3, bin_override=mut_bin)
            if not r4_ok:
                raise RuntimeError(f"Mutation 3 VM setup failed unexpectedly: {r4_msg}")
            r5_ok, r5_msg, _ = check_row5(ws_m3, bin_override=mut_bin)
            run_avm(["--lang", "en", "--workspace", ws_m3, "halt", "t1"], check=False, bin_override=mut_bin)
            run_avm(["--lang", "en", "--workspace", ws_m3, "daemon", "stop"], check=False, bin_override=mut_bin)

            caught = (not r5_ok) and ("ERR_VM_LOCKED" in r5_msg)
            detail = f"Row 5 MCP exec check ok={r5_ok} ({r5_msg})"
    except Exception as exc:
        detail = f"unexpected exception during --mutation {mid}: {exc}"
        caught = False
    finally:
        cleanup_temp_tree(bin_override=mut_bin)

    post_sources = git_porcelain("Sources")
    post_all = git_porcelain()
    vz_leaked = sorted(extra_vz_pids())
    daemons_leaked = sorted(set(list_host_agentvm_daemons(mut_bin)) - set(baseline_daemons))
    repo_clean_ok = (post_sources == "") and (post_all == pre_all)

    if caught and repo_clean_ok and not vz_leaked and not daemons_leaked:
        clean_note = "git status clean" if post_all == "" else "Sources/ clean and working tree unchanged"
        emit(f"PASS [Row {row_num}]: mutation {mid} caught ({detail}); temp repo removed, 0 leaked VMs/daemons, {clean_note}")
        return 0

    emit_err(
        f"FAIL [Row {row_num}]: caught={caught} ({detail}), repo_clean_ok={repo_clean_ok}, "
        f"vz_leaked={vz_leaked}, daemons_leaked={daemons_leaked}"
    )
    return 1


if mutation_id:
    sys.exit(run_mutation_mode(mutation_id))

# ---------------------------------------------------------------------------
# Standard M4 Acceptance Run (Rows 1-14)
# ---------------------------------------------------------------------------
script_start = time.perf_counter()
host_meta_start = collect_host_metadata()

emit("==================================================================")
emit(f" AgentVM Milestone M4 Acceptance Suite (AGENTVM_REAL_VM={int(real_vm_enabled)})")
emit(
    f" Host: {host_meta_start['hwModel']} ({host_meta_start['cpuBrand']}, "
    f"{host_meta_start['logicalCores']} cores, {host_meta_start['memoryGiB']} GiB), "
    f"macOS {host_meta_start['macOSVersion']} ({host_meta_start['macOSBuild']}), commit {host_meta_start['commit']}"
)
emit("==================================================================")

try:
    if not resolved_bin:
        resolved_bin = build_and_sign_binary(root_dir, dest_name="AgentVM", sign_for_vz=real_vm_enabled)

    # ---- Row 1 (Non-VM: create --mount validation) ----
    try:
        ok1, msg1 = check_row1(ws_offline)
        (pass_row if ok1 else fail_row)(1, msg1)
    except Exception as exc:
        fail_row(1, str(exc))

    # ---- Row 2 (Non-VM: offline cidata ISO mounts & branch / --no-mounts) ----
    try:
        ok2, msg2 = check_row2(ws_offline)
        (pass_row if ok2 else fail_row)(2, msg2)
    except Exception as exc:
        fail_row(2, str(exc))

    # ---- Row 3 (Non-VM: MCP offline gates for M5 tools & stopped VM exec) ----
    try:
        ok3, msg3 = check_row3(ws_offline)
        (pass_row if ok3 else fail_row)(3, msg3)
    except Exception as exc:
        fail_row(3, str(exc))

    if not real_vm_enabled:
        for r in range(4, 14):
            unrun_row(r, "未设置 AGENTVM_REAL_VM=1")
    else:
        stage_image_cache_copy()
        rw_dir = tempfile.mkdtemp(prefix="share_rw_", dir=tmp_root)
        ro_dir = tempfile.mkdtemp(prefix="share_ro_", dir=tmp_root)
        seed_ro_file = os.path.join(ro_dir, "seed-ro.txt")
        with open(seed_ro_file, "w", encoding="utf-8") as fp:
            fp.write("immutable-ro-seed-line\n")
        os.chmod(seed_ro_file, 0o644)
        seed_ro_sha_before = sha256_file(seed_ro_file)

        t1_ready = False
        cli_kernel = ""
        http_port = 0

        # ---- Row 4 (Real-VM: create --mount + up auto-mounts virtiofs) ----
        try:
            ok4, msg4 = check_row4(ws_real, rw_dir, ro_dir)
            if ok4:
                t1_ready = True
                pass_row(4, msg4)
            else:
                fail_row(4, msg4)
        except Exception as exc:
            fail_row(4, str(exc))

        # ---- Row 5 (Real-VM: MCP stdio tools/list, list_fleet, exec uname -r) ----
        if not t1_ready:
            fail_row(5, "prerequisite VM t1 from Row 4 is not running")
        else:
            try:
                ok5, msg5, cli_kernel = check_row5(ws_real)
                metrics_record["guestKernel"] = cli_kernel
                (pass_row if ok5 else fail_row)(5, msg5)
            except Exception as exc:
                fail_row(5, str(exc))

        # ---- Row 6 (Real-VM: MCP snapshot -> fork_cow_branch(bootImmediately=true) -> child exec -> restore) ----
        if not t1_ready:
            fail_row(6, "prerequisite VM t1 from Row 4 is not running")
        else:
            sess6 = MCPStdioSession(resolved_bin, ws_real)
            try:
                sess6.initialize()
                e0, tx0 = sess6.call_tool(
                    "agentvm_exec_command",
                    {"vmID": "t1", "executable": "/bin/sh", "arguments": ["-c", "printf 'v1\\n' > /root/mcp_probe.txt && sync"]},
                )
                assert not e0 and "exitCode=0" in tx0, f"seed v1 failed: {tx0}"

                e_sn, tx_sn = sess6.call_tool("agentvm_capture_snapshot", {"vmID": "t1", "title": "m4-row6"})
                assert not e_sn, f"capture_snapshot failed: {tx_sn}"
                m_sn = re.search(r"(snap-[0-9a-f]+)", tx_sn)
                assert m_sn, f"no snap-... ID in {tx_sn!r}"
                snap_id = m_sn.group(1)

                e1, tx1 = sess6.call_tool(
                    "agentvm_exec_command",
                    {"vmID": "t1", "executable": "/bin/sh", "arguments": ["-c", "printf 'v2\\n' > /root/mcp_probe.txt && sync"]},
                )
                assert not e1 and "exitCode=0" in tx1, f"write v2 failed: {tx1}"

                t_fk0 = time.perf_counter()
                e_fk, tx_fk = sess6.call_tool(
                    "agentvm_fork_cow_branch",
                    {"parentVMID": "t1", "branchName": "t1-child", "bootImmediately": True},
                )
                fk_s = time.perf_counter() - t_fk0
                assert not e_fk and "ERR_DAEMON_REQUIRED" not in tx_fk, f"fork_cow_branch failed: {tx_fk}"
                vm_cnt = check_vm_cap(2)

                d_st = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "daemon", "status", "--json"])["stdout"])
                held = sorted(v["spec"]["name"] for v in d_st["vms"])
                assert held == ["t1", "t1-child"], f"daemon held VMs mismatch: {held}"

                e_ch, tx_ch = sess6.call_tool(
                    "agentvm_exec_command",
                    {
                        "vmID": "t1-child",
                        "executable": "/bin/sh",
                        "arguments": ["-c", "uname -r && cat /root/mcp_probe.txt && findmnt -n -o FSTYPE /workspace"],
                    },
                )
                assert not e_ch and "v2" in tx_ch and "virtiofs" in tx_ch, f"child exec mismatch: {tx_ch!r}"

                # Halt t1-child before restoring t1 so concurrent VMs drops back to 1
                run_avm(["--lang", "en", "--workspace", ws_real, "halt", "t1-child"])

                t_rs0 = time.perf_counter()
                e_rs, tx_rs = sess6.call_tool("agentvm_restore_snapshot", {"snapshotID": snap_id})
                rs_s = time.perf_counter() - t_rs0
                assert not e_rs, f"restore_snapshot failed: {tx_rs}"

                e_af, tx_af = sess6.call_tool(
                    "agentvm_exec_command",
                    {
                        "vmID": "t1",
                        "executable": "/bin/sh",
                        "arguments": ["-c", "cat /root/mcp_probe.txt && findmnt -n -o FSTYPE /workspace"],
                    },
                )
                assert not e_af and "v1" in tx_af and "virtiofs" in tx_af, f"post-restore t1 check failed: {tx_af!r}"
                metrics_record["row6"] = {"mcpForkBootSec": round(fk_s, 2), "mcpRestoreSec": round(rs_s, 2)}
                pass_row(
                    6,
                    f"MCP capture_snapshot ({snap_id}) -> fork_cow_branch(bootImmediately=true, {fk_s:.2f}s, {vm_cnt} VMs) -> "
                    f"child exec (v2 + virtiofs) -> restore_snapshot ({rs_s:.2f}s, reverted to v1) all isError=false",
                )
            except Exception as exc:
                run_avm(["--lang", "en", "--workspace", ws_real, "halt", "t1-child"], check=False)
                fail_row(6, str(exc))
            finally:
                sess6.close()

        # ---- Row 7 (Real-VM: VirtioFS UID/chmod mapping & 64 MiB SHA-256 + R/W throughput) ----
        if not t1_ready:
            fail_row(7, "prerequisite VM t1 is not running")
        else:
            try:
                run_avm(["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", "touch", "/workspace/x_root"])
                run_avm(["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", "su", "-", "agent", "-c", "touch /workspace/x_agent"])
                run_avm(["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", "chmod", "0751", "/workspace/x_root"])

                host_uid = os.getuid()
                st_root = os.stat(os.path.join(rw_dir, "x_root"))
                st_agent = os.stat(os.path.join(rw_dir, "x_agent"))
                root_mode = stat.S_IMODE(st_root.st_mode)
                assert st_root.st_uid == host_uid and st_agent.st_uid == host_uid, (
                    f"UID mismatch: host={host_uid}, x_root={st_root.st_uid}, x_agent={st_agent.st_uid}"
                )
                assert root_mode == 0o751, f"x_root mode mismatch: {oct(root_mode)}"

                gw_py = (
                    "import hashlib, os, time\n"
                    f"buf = os.urandom({BYTES_64_MIB})\n"
                    "sha = hashlib.sha256(buf).hexdigest()\n"
                    "t0 = time.monotonic()\n"
                    "fd = os.open('/workspace/rand64_guest.bin', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)\n"
                    "mv = memoryview(buf)\n"
                    "off = 0\n"
                    "while off < len(buf):\n"
                    "    off += os.write(fd, mv[off:off + 4 * 1024 * 1024])\n"
                    "os.fsync(fd)\n"
                    "os.close(fd)\n"
                    "dt = time.monotonic() - t0\n"
                    "print(f'{sha} {dt:.4f} {64.0 / dt:.1f}')\n"
                )
                gw_out = run_avm(["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", "python3", "-c", gw_py])["stdout"].strip()
                gw_sha, gw_sec_s, gw_mibs_s = gw_out.split()
                host_gw_sha = sha256_file(os.path.join(rw_dir, "rand64_guest.bin"))
                assert gw_sha == host_gw_sha, f"64 MiB guest->host SHA-256 mismatch: {gw_sha} != {host_gw_sha}"

                host_seed_path = os.path.join(rw_dir, "rand64_host.bin")
                host_buf = os.urandom(BYTES_64_MIB)
                host_seed_sha = hashlib.sha256(host_buf).hexdigest()
                with open(host_seed_path, "wb") as fp:
                    fp.write(host_buf)
                    fp.flush()
                    os.fsync(fp.fileno())
                del host_buf

                gr_py = (
                    "import hashlib, time\n"
                    "t0 = time.monotonic()\n"
                    "h = hashlib.sha256()\n"
                    "tot = 0\n"
                    "with open('/workspace/rand64_host.bin', 'rb') as fp:\n"
                    "    while True:\n"
                    "        b = fp.read(4 * 1024 * 1024)\n"
                    "        if not b: break\n"
                    "        tot += len(b); h.update(b)\n"
                    "dt = time.monotonic() - t0\n"
                    "print(f'{h.hexdigest()} {dt:.4f} {(tot / 1048576.0) / dt:.1f} {tot}')\n"
                )
                gr_out = run_avm(["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", "python3", "-c", gr_py])["stdout"].strip()
                gr_sha, gr_sec_s, gr_mibs_s, gr_tot_s = gr_out.split()
                assert gr_sha == host_seed_sha and int(gr_tot_s) == BYTES_64_MIB, (
                    f"64 MiB host->guest SHA-256/size mismatch: {gr_sha} vs {host_seed_sha}, bytes={gr_tot_s}"
                )

                os.remove(os.path.join(rw_dir, "rand64_guest.bin"))
                os.remove(host_seed_path)
                metrics_record["row7VirtioFS"] = {
                    "write64MiBSec": float(gw_sec_s),
                    "write64MiBPerSec": float(gw_mibs_s),
                    "read64MiBSec": float(gr_sec_s),
                    "read64MiBPerSec": float(gr_mibs_s),
                }
                pass_row(
                    7,
                    f"x_root & x_agent host uid={host_uid} (== id -u), x_root mode=0751; "
                    f"64 MiB SHA-256 exact (write {gw_mibs_s} MiB/s, read {gr_mibs_s} MiB/s)",
                )
            except Exception as exc:
                fail_row(7, str(exc))

        # ---- Row 8 (Real-VM: VirtioFS read-only mount protection) ----
        if not t1_ready:
            fail_row(8, "prerequisite VM t1 is not running")
        else:
            try:
                ro_cmds = [
                    ["touch", "/mnt/ro/y"],
                    ["/bin/sh", "-c", "echo mutated >> /mnt/ro/seed-ro.txt"],
                    ["rm", "/mnt/ro/seed-ro.txt"],
                    ["/bin/sh", "-c", "mount -o remount,rw /mnt/ro && touch /mnt/ro/y_remount"],
                    ["/bin/sh", "-c", "mkdir -p /tmp/ro_try && mount -t virtiofs -o rw mnt-ro /tmp/ro_try && touch /tmp/ro_try/y_exp"],
                ]
                rcs = []
                for cmd in ro_cmds:
                    r = run_avm(["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", *cmd], check=False)
                    rcs.append(r["returncode"])
                run_avm(
                    [
                        "--lang", "en", "--workspace", ws_real, "exec", "t1", "--",
                        "/bin/sh", "-c",
                        "mount -o remount,ro /mnt/ro 2>/dev/null || true; umount /tmp/ro_try 2>/dev/null || true; rmdir /tmp/ro_try 2>/dev/null || true",
                    ],
                    check=False,
                )
                assert all(rc != 0 for rc in rcs), f"expected all RO write attempts non-zero, got {rcs}"
                ro_entries = sorted(os.listdir(ro_dir))
                seed_ro_sha_after = sha256_file(seed_ro_file)
                assert ro_entries == ["seed-ro.txt"], f"unexpected files in ro_dir: {ro_entries}"
                assert seed_ro_sha_after == seed_ro_sha_before, "seed-ro.txt SHA-256 mutated"
                pass_row(8, f"touch/append/rm/remount-rw/explicit-rw all failed (exit codes {rcs}); ro_dir unchanged")
            except Exception as exc:
                fail_row(8, str(exc))

        # ---- Row 9 (Real-VM: pre-boot error when host shared directory is deleted after halt) ----
        try:
            r9_dir = tempfile.mkdtemp(prefix="share_r9_", dir=tmp_root)
            run_avm(
                [
                    "--lang", "en", "--workspace", ws_real,
                    "create", "t9",
                    "--image", "debian-12-bookworm-arm64",
                    "--disk-size", "8G",
                    "--mount", f"{r9_dir}:/workspace",
                ]
            )
            run_avm(["--lang", "en", "--workspace", ws_real, "up", "t9"])
            check_vm_cap(2)
            run_avm(["--lang", "en", "--workspace", ws_real, "halt", "t9"])
            shutil.rmtree(r9_dir)

            up_miss = run_avm(["--lang", "en", "--workspace", ws_real, "up", "t9"], check=False)
            vms_r9 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "ps", "--json"])["stdout"])
            t9_state = next(v["telemetry"]["state"] for v in vms_r9 if v["spec"]["name"] == "t9")
            assert up_miss["returncode"] != 0, "up t9 with deleted shared dir unexpectedly exited 0"
            assert "ERR_SHARED_DIR_INVALID" in up_miss["stderr"] and r9_dir in up_miss["stderr"], (
                f"stderr missing ERR_SHARED_DIR_INVALID or path: {scrub(up_miss['stderr'])!r}"
            )
            assert t9_state == "stopped", f"expected t9 stopped, got {t9_state}"
            pass_row(
                9,
                f"up t9 after deleting shared dir exited {up_miss['returncode']} "
                "(ERR_SHARED_DIR_INVALID naming missing path); t9 remained stopped",
            )
        except Exception as exc:
            run_avm(["--lang", "en", "--workspace", ws_real, "halt", "t9"], check=False)
            fail_row(9, str(exc))

        # ---- Row 10 (Real-VM: port forwarding http.server, 64 MiB + concurrent exec, SHUT_WR 100ms, bind conflict) ----
        if not t1_ready:
            fail_row(10, "prerequisite VM t1 is not running")
        else:
            try:
                hello_path = os.path.join(rw_dir, "hello-m4.txt")
                with open(hello_path, "w", encoding="utf-8") as fp:
                    fp.write("hello-from-agentvm-m4\n")
                payload_path = os.path.join(rw_dir, "payload-64m.bin")
                h_src = hashlib.sha256()
                with open(payload_path, "wb") as fp:
                    for _ in range(64):
                        blk = os.urandom(1024 * 1024)
                        fp.write(blk)
                        h_src.update(blk)
                src_sha = h_src.hexdigest()

                start_guest_http_server_8000(ws_real, "t1")
                http_port = reserve_free_port()
                run_avm(["--lang", "en", "--workspace", ws_real, "forward", "t1", f"{http_port}:8000"])

                curl_dir = subprocess.run(
                    ["/usr/bin/curl", "-fsS", f"http://127.0.0.1:{http_port}/"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                assert curl_dir.returncode == 0, f"curl listing failed: {curl_dir.stderr}"
                assert "hello-m4.txt" in curl_dir.stdout and "payload-64m.bin" in curl_dir.stdout, "listing missing expected files"

                lat_samples_ms = []
                small_url = f"http://127.0.0.1:{http_port}/hello-m4.txt"
                for _ in range(50):
                    t0 = time.perf_counter()
                    with urllib.request.urlopen(small_url, timeout=5.0) as resp:
                        body = resp.read()
                        assert body == b"hello-from-agentvm-m4\n"
                    lat_samples_ms.append((time.perf_counter() - t0) * 1000.0)
                lat_samples_ms.sort()
                lat_med = statistics.median(lat_samples_ms)
                lat_p95 = lat_samples_ms[int(0.95 * (len(lat_samples_ms) - 1))]

                dl_path = os.path.join(tmp_root, "downloaded_64m.bin")

                def _download_64m() -> tuple[int, float, str]:
                    t0 = time.perf_counter()
                    cp = subprocess.run(
                        ["/usr/bin/curl", "-fsS", "-o", dl_path, f"http://127.0.0.1:{http_port}/payload-64m.bin"],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    if cp.returncode != 0:
                        raise RuntimeError(f"curl 64 MiB download failed: {cp.stderr}")
                    dt = time.perf_counter() - t0
                    return os.path.getsize(dl_path), dt, sha256_file(dl_path)

                def _concurrent_exec(idx: int) -> tuple[int, int, str]:
                    r = run_avm(["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", "uname", "-r"], check=False)
                    return idx, r["returncode"], r["stdout"].strip()

                with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                    dl_fut = pool.submit(_download_64m)
                    ex_futs = [pool.submit(_concurrent_exec, i) for i in range(1, 6)]
                    dl_bytes, dl_sec, dl_sha = dl_fut.result()
                    ex_res = [f.result() for f in ex_futs]

                assert dl_bytes == BYTES_64_MIB and dl_sha == src_sha, f"64 MiB download SHA-256 mismatch: {dl_sha} != {src_sha}"
                assert all(rc == 0 and out == cli_kernel for _, rc, out in ex_res), f"concurrent exec failure: {ex_res}"
                dl_mibs = 64.0 / dl_sec if dl_sec > 0 else 0.0

                hc_ok, hc_msg = check_row10_halfclose_only(ws_real, "t1")
                assert hc_ok, hc_msg

                dup = run_avm(["--lang", "en", "--workspace", ws_real, "forward", "t1", f"{http_port}:8000"], check=False)
                assert dup["returncode"] != 0 and "ERR_PORT_FORWARD_BIND" in dup["stderr"] and str(http_port) in dup["stderr"], (
                    f"duplicate forward did not fail with ERR_PORT_FORWARD_BIND: rc={dup['returncode']} err={dup['stderr']!r}"
                )

                fwd_list = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "forward", "list", "--vm", "t1", "--json"])["stdout"])
                assert any(item["hostPort"] == http_port for item in fwd_list), f"forward list missing {http_port}: {fwd_list}"

                os.remove(payload_path)
                os.remove(dl_path)
                metrics_record["row10PortForward"] = {
                    "latency50Count": 50,
                    "latencyMinMs": round(lat_samples_ms[0], 3),
                    "latencyMedianMs": round(lat_med, 3),
                    "latencyP95Ms": round(lat_p95, 3),
                    "latencyMaxMs": round(lat_samples_ms[-1], 3),
                    "download64MiBSec": round(dl_sec, 3),
                    "download64MiBPerSec": round(dl_mibs, 2),
                    "concurrentExecPassed": 5,
                }
                pass_row(
                    10,
                    f"curl listing ok; 64 MiB SHA-256 exact ({dl_mibs:.2f} MiB/s) with 5/5 concurrent exec ok; "
                    f"50x GET median={lat_med:.3f} ms (p95={lat_p95:.3f} ms); {hc_msg}; duplicate port exited {dup['returncode']} (ERR_PORT_FORWARD_BIND)",
                )
            except Exception as exc:
                fail_row(10, str(exc))

        # ---- Rows 11 & 12 (Real-VM: real stdlib Python project parity & agent-relay verify integration) ----
        proj_copy_dir = tempfile.mkdtemp(prefix="avm_m4_proj_", dir=tmp_root)
        t_relay_running = False
        sample_src = os.environ.get("AGENTVM_M4_SAMPLE_PROJECT", "").strip()
        if not sample_src:
            sample_src = os.path.join(real_home, ".agents", "skills", "code-review", "evals")
        relay_script = os.path.join(real_home, ".agents", "skills", "agent-relay", "scripts", "relay.sh")

        try:
            if not os.path.isdir(sample_src):
                raise RuntimeError(f"Sample project directory not found: {scrub(sample_src)}")
            shutil.copytree(
                sample_src,
                proj_copy_dir,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".DS_Store", ".relay"),
            )
            run_avm(
                [
                    "--lang", "en", "--workspace", ws_real,
                    "create", "t-relay",
                    "--image", "debian-12-bookworm-arm64",
                    "--disk-size", "8G",
                    "--mount", f"{proj_copy_dir}:/workspace",
                ]
            )
            run_avm(["--lang", "en", "--workspace", ws_real, "up", "t-relay"])
            t_relay_running = True
            check_vm_cap(2)

            host_ut = subprocess.run(
                [sys.executable, "-m", "unittest", "tests/test_cases.py", "tests/test_score.py", "-v"],
                cwd=proj_copy_dir,
                env=isolated_env(),
                capture_output=True,
                text=True,
                timeout=60,
            )
            host_combined = host_ut.stdout + "\n" + host_ut.stderr
            host_cnt, host_ok, host_cases = parse_unittest_output(host_combined)

            guest_ut = run_avm(
                [
                    "--lang", "en", "--workspace", ws_real,
                    "exec", "t-relay", "--",
                    "/bin/sh", "-c",
                    "cd /workspace && python3 -B -m unittest tests/test_cases.py tests/test_score.py -v",
                ],
                check=False,
            )
            guest_combined = guest_ut["stdout"] + "\n" + guest_ut["stderr"]
            guest_cnt, guest_ok, guest_cases = parse_unittest_output(guest_combined)

            assert host_ut.returncode == 0 and guest_ut["returncode"] == 0, (
                f"exit mismatch: host={host_ut.returncode}, guest={guest_ut['returncode']}"
            )
            assert host_ok and guest_ok and host_cnt > 0 and host_cnt == guest_cnt, (
                f"summary mismatch: host=(cnt={host_cnt}, ok={host_ok}), guest=(cnt={guest_cnt}, ok={guest_ok})"
            )
            assert host_cases == guest_cases and len(host_cases) == host_cnt, (
                f"per-test case mismatch: host={len(host_cases)}, guest={len(guest_cases)}"
            )
            metrics_record["row11RealProject"] = {
                "project": "code-review/evals (tests/test_cases.py + tests/test_score.py)",
                "hostExitCode": host_ut.returncode,
                "guestExitCode": guest_ut["returncode"],
                "passedTests": host_cnt,
            }
            pass_row(
                11,
                f"copied code-review/evals to fresh mktemp -d; host & guest both exited 0 with {host_cnt}/{host_cnt} passed tests identical",
            )
        except Exception as exc:
            fail_row(11, str(exc))

        # ---- Row 12 (Real-VM: agent-relay verify positive & negative cases) ----
        if not t_relay_running:
            fail_row(12, "prerequisite VM t-relay from Row 11 is not running")
        else:
            try:
                if not os.path.isfile(relay_script):
                    raise RuntimeError(f"relay.sh not found at {scrub(relay_script)}")
                relay_before_sha = sha256_file(relay_script)

                pos_proc = subprocess.run(
                    [
                        "/bin/bash", relay_script,
                        "verify", proj_copy_dir, "在沙箱里跑测试", "--",
                        resolved_bin, "--lang", "en", "--workspace", ws_real,
                        "exec", "t-relay", "--",
                        "/bin/sh", "-c",
                        "cd /workspace && python3 -B -m unittest tests/test_cases.py tests/test_score.py -v",
                    ],
                    env=isolated_env(),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                neg_proc = subprocess.run(
                    [
                        "/bin/bash", relay_script,
                        "verify", proj_copy_dir, "在沙箱里跑失败对照", "--",
                        resolved_bin, "--lang", "en", "--workspace", ws_real,
                        "exec", "t-relay", "--",
                        "python3", "-c", "import sys; sys.exit(7)",
                    ],
                    env=isolated_env(),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                relay_after_sha = sha256_file(relay_script)
                assert relay_before_sha == relay_after_sha, "relay.sh was modified!"

                log_md_path = os.path.join(proj_copy_dir, ".relay", "LOG.md")
                assert os.path.isfile(log_md_path), ".relay/LOG.md was not created"
                log_md = open(log_md_path, encoding="utf-8").read()
                headings = re.findall(r"^##\s+.+$", log_md, flags=re.MULTILINE)
                assert pos_proc.returncode == 0, f"positive relay.sh verify exited {pos_proc.returncode}: {pos_proc.stdout}\n{pos_proc.stderr}"
                assert neg_proc.returncode == 7, f"negative relay.sh verify exited {neg_proc.returncode} (expected 7)"
                assert len(headings) == 2, f"expected 2 entries in .relay/LOG.md, got {headings}"
                assert "01-verify: passed" in headings[0] and "02-verify: failed (exit 7)" in headings[1], (
                    f"unexpected LOG.md headings: {headings}"
                )
                assert "OK" in log_md and "在沙箱里跑测试" in log_md and "在沙箱里跑失败对照" in log_md, "LOG.md missing expected check/output text"
                pass_row(
                    12,
                    "relay.sh verify positive exited 0 & negative propagated exit 7; "
                    ".relay/LOG.md recorded 01-verify (passed) and 02-verify (failed exit 7); relay.sh untouched",
                )
            except Exception as exc:
                fail_row(12, str(exc))
            finally:
                run_avm(["--lang", "en", "--workspace", ws_real, "halt", "t-relay"], check=False)

        # ---- Row 13 (Real-VM: guest reboot restores BOTH VirtioFS mounts AND port forward on t1) ----
        if not t1_ready or http_port == 0:
            fail_row(13, "prerequisite VM t1 or HTTP port forward from Row 10 unavailable")
        else:
            try:
                boot_before = run_avm(
                    ["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", "cat", "/proc/sys/kernel/random/boot_id"]
                )["stdout"].strip()
                t_rb0 = time.perf_counter()
                run_avm(["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", "systemctl", "reboot"], check=False)
                time.sleep(2.0)

                boot_after = ""
                deadline = time.monotonic() + 90.0
                while time.monotonic() < deadline:
                    pr = run_avm(
                        ["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", "cat", "/proc/sys/kernel/random/boot_id"],
                        timeout_sec=15,
                        check=False,
                    )
                    cand = pr["stdout"].strip()
                    if pr["returncode"] == 0 and cand and cand != boot_before:
                        boot_after = cand
                        break
                    time.sleep(1.0)
                rb_sec = time.perf_counter() - t_rb0
                assert boot_after, "t1 did not reconnect with a new boot_id within 90s after systemctl reboot"

                m_ws_after = run_avm(
                    ["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", "findmnt", "-n", "-o", "TARGET,FSTYPE", "/workspace"]
                )["stdout"].strip()
                m_ro_after = run_avm(
                    ["--lang", "en", "--workspace", ws_real, "exec", "t1", "--", "findmnt", "-n", "-o", "TARGET,FSTYPE", "/mnt/ro"]
                )["stdout"].strip()
                assert "virtiofs" in m_ws_after and "virtiofs" in m_ro_after, (
                    f"mounts not restored after reboot: ws={m_ws_after!r}, ro={m_ro_after!r}"
                )

                # Restart http.server 8000 in guest WITHOUT re-running `agentvm forward`
                start_guest_http_server_8000(ws_real, "t1")
                curl_after = subprocess.run(
                    ["/usr/bin/curl", "-fsS", f"http://127.0.0.1:{http_port}/"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                assert curl_after.returncode == 0 and "hello-m4.txt" in curl_after.stdout, (
                    f"curl on original forward port {http_port} failed after reboot: rc={curl_after.returncode}"
                )

                run_avm(["--lang", "en", "--workspace", ws_real, "halt", "t1"])
                assert not is_port_listening(http_port), f"port {http_port} still listening after halt t1"
                run_avm(["--lang", "en", "--workspace", ws_real, "daemon", "stop"])
                metrics_record["row13Reboot"] = {"reconnectSec": round(rb_sec, 2)}
                pass_row(
                    13,
                    f"guest rebooted ({rb_sec:.2f}s, boot_id changed); /workspace & /mnt/ro remained virtiofs "
                    f"and original forward port {http_port} served directory listing without re-forwarding; halt released port",
                )
            except Exception as exc:
                fail_row(13, str(exc))

finally:
    # ---- Row 14 (Host zero-leak & cache SHA-256 hygiene check; regression suites live in `milestone 4`) ----
    stop_tracked_workspaces()
    iso_la_dir = os.path.join(isolated_home, "Library", "LaunchAgents")
    iso_la_clean = not (os.path.isdir(iso_la_dir) and os.listdir(iso_la_dir))

    deleted_tmp = tmp_root
    deleted_raw = raw_tmp_root
    cleanup_temp_tree()

    tmp_gone = (not os.path.exists(deleted_tmp)) and (not os.path.exists(deleted_raw))
    leftover_links = sweep_darwin_temp_symlinks([deleted_tmp, deleted_raw], remove=False)
    daemons_after = list_host_agentvm_daemons(resolved_bin)
    new_daemons = sorted(set(daemons_after) - set(baseline_daemons))
    leftover_bin_procs = list_bin_processes(resolved_bin)
    vz_extra_after = sorted(extra_vz_pids())
    home_after = snapshot_home_hygiene()
    new_home_items = {
        k: sorted(set(home_after[k]) - set(baseline_home[k]))
        for k in ("launch_agents", "preferences", "app_support")
    }
    try:
        lctl = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
        lctl_hits = (
            [ln.strip() for ln in lctl.stdout.splitlines() if "agentvm" in ln.lower()]
            if lctl.returncode == 0
            else ["launchctl_failed"]
        )
    except OSError:
        lctl_hits = ["launchctl_blocked"]
    cache_after = snapshot_cache_dir_with_hashes(source_cache_dir)
    cache_ok = cache_after == cache_before

    if (
        tmp_gone
        and not leftover_links
        and not new_daemons
        and not leftover_bin_procs
        and not vz_extra_after
        and iso_la_clean
        and all(not v for v in new_home_items.values())
        and not lctl_hits
        and cache_ok
    ):
        pass_row(
            14,
            "0 extra com.apple.Virtualization.VirtualMachine processes; 0 leaked daemons/MCP processes; "
            "temp dirs & avm-* symlinks removed; 0 new ~/Library items or launchctl entries; image cache SHA-256 unchanged",
        )
    else:
        fail_row(
            14,
            f"tmp_gone={tmp_gone}, links={leftover_links}, new_daemons={new_daemons}, bin_procs={leftover_bin_procs}, "
            f"vz_extra={vz_extra_after}, iso_la_clean={iso_la_clean}, home_diff={new_home_items}, "
            f"launchctl={lctl_hits}, cache_sha256_ok={cache_ok}",
        )

emit("INFO [Rows 15-17]: source-mutation checks skipped by default (pass --mutation 1|2|3 with AGENTVM_REAL_VM=1 to run)")

elapsed = time.perf_counter() - script_start
host_meta_end = collect_host_metadata()
emit("==================================================================")
emit(f" Summary: {passed_rows} passed, {failed_rows} failed, {unrun_rows} unrun (total {elapsed:.2f}s)")
emit("==================================================================")

json_payload = {
    "milestone": "M4",
    "script": "Scripts/acceptance/m4-agent.sh",
    "realVMEnabled": real_vm_enabled,
    "hostStart": host_meta_start,
    "hostEndUptime": host_meta_end["uptime"],
    "elapsedSeconds": round(elapsed, 2),
    "summary": {
        "passed": passed_rows,
        "failed": failed_rows,
        "unrun": unrun_rows,
    },
    "metrics": metrics_record,
    "rows": {str(k): v for k, v in sorted(row_outcomes.items())},
}
txt_output = "\n".join(transcript_lines) + "\n"
json_output = json.dumps(json_payload, indent=2, ensure_ascii=False) + "\n"

if out_dir_arg:
    os.makedirs(out_dir_arg, exist_ok=True)
    with open(os.path.join(out_dir_arg, "m4-agent.txt"), "w", encoding="utf-8") as fp:
        fp.write(txt_output)
    with open(os.path.join(out_dir_arg, "m4-agent.json"), "w", encoding="utf-8") as fp:
        fp.write(json_output)

if record_reports and failed_rows == 0 and unrun_rows == 0:
    post_dirty = git_porcelain()
    if post_dirty:
        emit_err("REFUSED: working tree became dirty during run; reports/ not modified:\n" + post_dirty)
        sys.exit(1)
    rep_dir = os.path.join(root_dir, "reports")
    os.makedirs(rep_dir, exist_ok=True)
    with open(os.path.join(rep_dir, "m4-agent.txt"), "w", encoding="utf-8") as fp:
        fp.write(txt_output)
    with open(os.path.join(rep_dir, "m4-agent.json"), "w", encoding="utf-8") as fp:
        fp.write(json_output)
    emit("Recorded reports/m4-agent.txt and reports/m4-agent.json")

if failed_rows > 0:
    sys.exit(1)
if unrun_rows > 0:
    sys.exit(2)
sys.exit(0)
PY
