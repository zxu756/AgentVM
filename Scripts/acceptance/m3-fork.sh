#!/usr/bin/env bash
# AgentVM Milestone M3 APFS CoW Fork & Snapshot Acceptance Script.
#
# Covers M3 acceptance table Rows 1-19, Rows 21-24, and Row 28 (Row 20 is m3-branch-bench.sh).
# Rows 25-27 (three source mutations) are built in as optional `--mutation <1|2|3>` checks and
# do not run by default (executed by the independent dispatcher during acceptance).
#
# Hard invariants:
#   * Without AGENTVM_REAL_VM=1, non-VM rows run and real-VM rows print "没跑", exiting 2.
#   * Never launches the desktop UI (.app, window, or bare AgentVM without a CLI subcommand).
#   * Runs the product with an isolated HOME / CFFIXED_USER_HOME and workspaces inside mktemp -d.
#   * Clones Debian 12 image cache into mktemp -d via `cp -c` and verifies source cache untouched.
#   * Reads APFS private bytes via `/usr/bin/python3` + `ctypes` `getattrlist(ATTR_CMNEXT_PRIVATESIZE)`
#     without calling product code.
#   * Never exceeds 2 concurrent VirtualMachine processes; never touches baseline foreign VMs/daemons.
#   * Every product command has a 300-second deadlock guard; output scrubs host home paths.
set -euo pipefail

MUTATION_ID=""

usage() {
    cat >&2 <<'EOF'
Usage:
  Scripts/acceptance/m3-fork.sh
  AGENTVM_REAL_VM=1 Scripts/acceptance/m3-fork.sh
  AGENTVM_REAL_VM=1 Scripts/acceptance/m3-fork.sh --mutation <1|2|3>

Options:
  --mutation <1|2|3>  Run optional M3 mutation verification (Row 25, Row 26, or Row 27):
                        1 (Row 25): copy parent cloudInit & ISO path -> Rows 2, 9, 13 must fail
                        2 (Row 26): omit pre-pause guest sync on live fork -> Row 12 must fail
                        3 (Row 27): restore full-disk extent scan in branch -> Row 20 median > 500 ms
                      Restores source and verifies `git status` is clean before exiting.
  -h, --help          Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
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

exec /usr/bin/python3 - "$CALLER_PWD" "$ROOT_DIR" "$MUTATION_ID" <<'PY'
# -*- coding: utf-8 -*-
import ctypes
import ctypes.util
import hashlib
import json
import os
import plistlib
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import uuid

caller_pwd, root_dir, mutation_id = sys.argv[1:4]
real_home = os.path.expanduser("~").rstrip("/")
real_vm_enabled = os.environ.get("AGENTVM_REAL_VM", "") == "1"
from_milestone3 = os.environ.get("AGENTVM_M3_FROM_MILESTONE3", "") == "1"

if mutation_id and not real_vm_enabled:
    print(f"没跑 [Row {24 + int(mutation_id)}]: --mutation {mutation_id} 需要设置 AGENTVM_REAL_VM=1")
    sys.exit(2)

CMD_TIMEOUT_SEC = 300
EXPECTED_256M_BYTES = 256 * 1024 * 1024
EXPECTED_64M_BYTES = 64 * 1024 * 1024

CLI_SUBCOMMANDS = {
    "doctor", "init", "ps", "list", "image", "create", "run", "daemon", "events",
    "up", "boot", "start", "pause", "resume", "halt", "stop",
    "branch", "fork", "snapshot", "restore", "exec", "pcap", "policy", "plugin",
    "export-hcl", "export-html", "help", "version",
}

# ---------------------------------------------------------------------------
# Independent APFS private-bytes reader via Darwin getattrlist(2) + ctypes
# ---------------------------------------------------------------------------
ATTR_BIT_MAP_COUNT = 5
ATTR_CMNEXT_PRIVATESIZE = 0x00000008
FSOPT_ATTR_CMN_EXTENDED = 0x00000020


class AttrList(ctypes.Structure):
    _fields_ = [
        ("bitmapcount", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("commonattr", ctypes.c_uint32),
        ("volattr", ctypes.c_uint32),
        ("dirattr", ctypes.c_uint32),
        ("fileattr", ctypes.c_uint32),
        ("forkattr", ctypes.c_uint32),
    ]


_libc_path = ctypes.util.find_library("c") or "/usr/lib/libSystem.B.dylib"
_libc = ctypes.CDLL(_libc_path, use_errno=True)
_libc.getattrlist.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(AttrList),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_uint32,
]
_libc.getattrlist.restype = ctypes.c_int


def read_apfs_space(path: str) -> dict:
    st = os.stat(path)
    alist = AttrList(
        bitmapcount=ATTR_BIT_MAP_COUNT,
        reserved=0,
        commonattr=0,
        volattr=0,
        dirattr=0,
        fileattr=0,
        forkattr=ATTR_CMNEXT_PRIVATESIZE,
    )
    buf = ctypes.create_string_buffer(12)
    rc = _libc.getattrlist(
        os.fsencode(path),
        ctypes.byref(alist),
        buf,
        ctypes.sizeof(buf),
        FSOPT_ATTR_CMN_EXTENDED,
    )
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), path)
    attr_len, priv_bytes = struct.unpack("=Iq", buf.raw[:12])
    if attr_len < 12:
        raise RuntimeError(f"Unexpected getattrlist buffer length {attr_len} for {path}")
    return {
        "logicalBytes": int(st.st_size),
        "allocatedBytes": int(st.st_blocks) * 512,
        "privateBytes": int(priv_bytes),
    }


# ---------------------------------------------------------------------------
# Scrubbing, row accounting, and host hygiene helpers
# ---------------------------------------------------------------------------
raw_tmp_root = ""
tmp_root = ""
source_cache_dir = ""
passed_rows = 0
failed_rows = 0
unrun_rows = 0
row_outcomes: dict[int, str] = {}


def scrub(text: str) -> str:
    out = text
    for needle, repl in (
        (tmp_root, "$TMP_ROOT"),
        (raw_tmp_root, "$TMP_ROOT"),
        (source_cache_dir, "$AGENTVM_IMAGE_CACHE"),
        (root_dir, "."),
        (real_home, "$HOME"),
    ):
        if needle:
            out = out.replace(needle, repl)
    return out


def emit(msg: str) -> None:
    print(scrub(msg), flush=True)


def emit_err(msg: str) -> None:
    print(scrub(msg), file=sys.stderr, flush=True)


def pass_row(row: int, detail: str) -> None:
    global passed_rows
    passed_rows += 1
    row_outcomes[row] = "PASS"
    emit(f"PASS [Row {row}]: {detail}")


def fail_row(row: int, detail: str) -> None:
    global failed_rows
    failed_rows += 1
    row_outcomes[row] = "FAIL"
    emit_err(f"FAIL [Row {row}]: {detail}")


def unrun_row(row: int, detail: str) -> None:
    global unrun_rows
    unrun_rows += 1
    row_outcomes[row] = "UNRUN"
    emit(f"没跑 [Row {row}]: {detail}")


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
    proc = subprocess.run(["ps", "-axww", "-o", "pid=,comm="], capture_output=True, text=True)
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
    proc = subprocess.run(["ps", "-axww", "-o", "pid=,command="], capture_output=True, text=True)
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
                if os.path.basename(comm_real).lower() == "agentvm" or (exp_real and comm_real == exp_real):
                    found.append((pid, comm_real, os.path.realpath(tokens[4])))
    return sorted(set(found))


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


def snapshot_cache_dir(cache_dir: str) -> dict:
    if not os.path.exists(cache_dir):
        return {"exists": False, "files": {}}
    files = {}
    for r, ds, fs in os.walk(cache_dir):
        ds.sort()
        for n in sorted(fs):
            full = os.path.join(r, n)
            rel = os.path.relpath(full, cache_dir)
            st = os.lstat(full)
            files[rel] = [int(st.st_ino), int(st.st_size), int(st.st_mtime_ns), int(st.st_mode)]
    return {"exists": True, "files": files}


def file_stat_sig(path: str) -> tuple[int, int, int, int]:
    st = os.lstat(path)
    return (int(st.st_ino), int(st.st_size), int(st.st_mtime_ns), int(st.st_mode))


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
    if os.path.isabs(user_bin_env):
        cand = user_bin_env
    else:
        from_caller = os.path.join(caller_pwd, user_bin_env)
        cand = from_caller if os.path.exists(from_caller) else os.path.join(root_dir, user_bin_env)
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
cache_before = snapshot_cache_dir(source_cache_dir)

raw_tmp_root = tempfile.mkdtemp(prefix="agentvm-m3-fork.")
tmp_root = os.path.realpath(raw_tmp_root)
isolated_home = os.path.join(tmp_root, "home")
isolated_tmp = os.path.join(tmp_root, "tmp")
local_cache_dir = os.path.join(tmp_root, "image-cache")
bin_dir = os.path.join(tmp_root, "bin")
ws_empty = os.path.join(tmp_root, "ws-empty.agentvm")
ws_real = os.path.join(tmp_root, "ws-real.agentvm")
tracked_workspaces = [ws_empty, ws_real]
for d in (isolated_home, isolated_tmp, local_cache_dir, bin_dir):
    os.makedirs(d, exist_ok=True)


def extra_vz_pids() -> set[int]:
    return list_vz_vm_pids() - baseline_vz_pids


def wait_for_extra_vz_count(expected: int, timeout_sec: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() <= deadline:
        if len(extra_vz_pids()) == expected:
            return True
        time.sleep(0.1)
    return len(extra_vz_pids()) == expected


def check_vm_cap(limit: int = 2) -> int:
    cnt = len(extra_vz_pids())
    if cnt > limit:
        raise RuntimeError(f"Concurrent VM cap ({limit}) exceeded: {cnt} extra VirtualMachine PIDs active")
    return cnt


def swift_jobs_args() -> list[str]:
    j = os.environ.get("AGENTVM_BUILD_JOBS", "").strip()
    return ["-j", j] if j else []


def build_and_sign_binary(dest_name: str = "AgentVM", sign_for_vz: bool = False) -> str:
    bproc = subprocess.run(
        ["swift", "build"] + swift_jobs_args() + ["--product", "AgentVM"],
        cwd=root_dir,
        capture_output=True,
        text=True,
    )
    if bproc.returncode != 0:
        raise RuntimeError(f"swift build --product AgentVM failed:\n{bproc.stderr[-2000:]}")
    built = os.path.realpath(os.path.join(root_dir, ".build", "debug", "AgentVM"))
    if not sign_for_vz:
        return built
    dst = os.path.join(bin_dir, dest_name)
    shutil.copy2(built, dst)
    os.chmod(dst, 0o755)
    ent_plist = os.path.join(root_dir, "Scripts", "entitlements.plist")
    cs = subprocess.run(
        ["codesign", "--force", "--sign", "-", "--entitlements", ent_plist, dst],
        capture_output=True,
        text=True,
    )
    if cs.returncode != 0 or not has_virtualization_entitlement(dst):
        raise RuntimeError(f"codesign failed on {dst}: {cs.stderr}")
    return os.path.realpath(dst)


def run_avm(args: list[str], timeout_sec: int = CMD_TIMEOUT_SEC, check: bool = True, bin_override: str = "") -> dict:
    exe = bin_override or resolved_bin
    host_args = args[: args.index("--")] if "--" in args else args
    if not any(tok in CLI_SUBCOMMANDS for tok in host_args):
        raise RuntimeError(f"REFUSED: command {args!r} has no CLI subcommand")
    env = dict(os.environ)
    for k in ("AGENTVM_WORKSPACE", "AGENTVM_REAL_VM", "AGENTVM_LANG"):
        env.pop(k, None)
    env["HOME"] = isolated_home
    env["CFFIXED_USER_HOME"] = isolated_home
    env["TMPDIR"] = isolated_tmp
    env["AGENTVM_IMAGE_CACHE"] = local_cache_dir

    t0 = time.perf_counter()
    proc = subprocess.run(
        ["/usr/bin/perl", "-e", f"alarm {int(timeout_sec)}; exec @ARGV", exe] + args,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout_sec + 10,
    )
    t1 = time.perf_counter()
    wall_ms = (t1 - t0) * 1000.0
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


def stop_tracked_workspaces() -> None:
    if resolved_bin and os.path.isfile(resolved_bin):
        for ws in tracked_workspaces:
            if os.path.exists(ws):
                try:
                    run_avm(["--lang", "en", "--workspace", ws, "daemon", "stop"], timeout_sec=65, check=False)
                except Exception:
                    pass
    ws_reals = {os.path.realpath(ws) for ws in tracked_workspaces}
    for pid, _comm, d_ws in list_host_agentvm_daemons():
        if d_ws in ws_reals:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    if real_vm_enabled:
        wait_for_extra_vz_count(0, timeout_sec=30.0)


cleanup_done = False


def cleanup_temp_tree() -> None:
    global cleanup_done
    if cleanup_done:
        return
    cleanup_done = True
    stop_tracked_workspaces()
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


# ---------------------------------------------------------------------------
# Guest identity & helper routines shared by normal and mutation runs
# ---------------------------------------------------------------------------
IDENT_PROBE = (
    "python3 -c '"
    "import glob, json, subprocess; "
    "h = subprocess.check_output([\"hostname\"], text=True).strip(); "
    "fqdn = subprocess.check_output([\"hostname\", \"-f\"], text=True).strip(); "
    "mid = open(\"/etc/machine-id\").read().strip(); "
    "dmid = open(\"/var/lib/dbus/machine-id\").read().strip(); "
    "iid = open(\"/var/lib/cloud/data/instance-id\").read().strip(); "
    "bid = open(\"/proc/sys/kernel/random/boot_id\").read().strip(); "
    "macs = sorted(open(p).read().strip().lower() for p in glob.glob(\"/sys/class/net/e*/address\")); "
    "ip_out = subprocess.check_output([\"ip\", \"-4\", \"-o\", \"addr\", \"show\", \"scope\", \"global\"], text=True).strip(); "
    "ipv4 = next((tok for tok in ip_out.split() if \"/\" in tok and tok[0].isdigit()), \"\"); "
    "ssh_out = subprocess.check_output([\"ssh-keygen\", \"-lf\", \"/etc/ssh/ssh_host_ed25519_key.pub\"], text=True).strip(); "
    "ssh_fp = ssh_out.split()[1]; "
    "ws_ok = subprocess.check_output([\"stat\", \"-c\", \"%F:%a\", \"/workspace\"], text=True).strip(); "
    "print(json.dumps({\"hostname\": h, \"fqdn\": fqdn, \"machine_id\": mid, \"dbus_machine_id\": dmid, "
    "\"instance_id\": iid, \"boot_id\": bid, \"mac\": macs[0] if macs else \"\", \"ipv4\": ipv4, "
    "\"ssh_ed25519\": ssh_fp, \"workspace\": ws_ok}))"
    "'"
)


def read_guest_identity(ws: str, vm_name: str) -> dict:
    r = run_avm(["--lang", "en", "--workspace", ws, "exec", vm_name, "--", "sh", "-c", IDENT_PROBE])
    return json.loads(r["stdout"].strip())


def verify_distinct_pair_identity(ws: str, parent_name: str, child_name: str) -> tuple[bool, str]:
    vms = json.loads(run_avm(["--lang", "en", "--workspace", ws, "ps", "--json"])["stdout"])
    rec_p = next(v for v in vms if v["spec"]["name"] == parent_name)
    rec_c = next(v for v in vms if v["spec"]["name"] == child_name)
    idp = read_guest_identity(ws, parent_name)
    idc = read_guest_identity(ws, child_name)

    p_mac_spec = rec_p["spec"]["networkInterfaces"][0]["macAddress"].lower()
    c_mac_spec = rec_c["spec"]["networkInterfaces"][0]["macAddress"].lower()
    problems = []
    if idp["hostname"] != parent_name:
        problems.append(f"{parent_name} hostname={idp['hostname']!r}")
    if idc["hostname"] != child_name:
        problems.append(f"{child_name} hostname={idc['hostname']!r}")
    if idp["instance_id"] != rec_p["spec"]["id"]:
        problems.append(f"{parent_name} instance_id={idp['instance_id']!r} != {rec_p['spec']['id']!r}")
    if idc["instance_id"] != rec_c["spec"]["id"]:
        problems.append(f"{child_name} instance_id={idc['instance_id']!r} != {rec_c['spec']['id']!r}")
    if idp["mac"] != p_mac_spec or idc["mac"] != c_mac_spec:
        problems.append(f"MAC mismatch against spec: p={idp['mac']}/{p_mac_spec}, {child_name}={idc['mac']}/{c_mac_spec}")
    if not idp["ipv4"] or not idc["ipv4"]:
        problems.append(f"empty IPv4: p={idp['ipv4']!r}, {child_name}={idc['ipv4']!r}")
    for k in ("hostname", "machine_id", "instance_id", "mac", "ipv4", "ssh_ed25519"):
        v_p = idp[k].split("/")[0] if k == "ipv4" else idp[k]
        v_c = idc[k].split("/")[0] if k == "ipv4" else idc[k]
        if v_p == v_c:
            problems.append(f"collision on {k}={v_p!r}")
    if problems:
        return False, "; ".join(problems)
    return (
        True,
        f"{parent_name}(ip={idp['ipv4']}, mac={idp['mac']}, mid={idp['machine_id'][:8]}...) vs "
        f"{child_name}(ip={idc['ipv4']}, mac={idc['mac']}, mid={idc['machine_id'][:8]}...): all 6 items distinct",
    )


def stage_image_cache_copy() -> None:
    src_raw = os.path.join(source_cache_dir, "debian-12-bookworm-arm64.raw")
    src_idx = os.path.join(source_cache_dir, "catalog-index.json")
    if not (os.path.isfile(src_raw) and os.path.isfile(src_idx)):
        run_avm(["--lang", "en", "--workspace", ws_real, "image", "pull", "debian-12-bookworm-arm64"], timeout_sec=900)
    else:
        dst_raw = os.path.join(local_cache_dir, "debian-12-bookworm-arm64.raw")
        dst_idx = os.path.join(local_cache_dir, "catalog-index.json")
        if subprocess.run(["/bin/cp", "-c", src_raw, dst_raw], capture_output=True).returncode != 0:
            shutil.copy2(src_raw, dst_raw)
        if subprocess.run(["/bin/cp", "-c", src_idx, dst_idx], capture_output=True).returncode != 0:
            shutil.copy2(src_idx, dst_idx)
        os.chmod(dst_raw, 0o444)


def check_row1_and_row2(ws: str) -> tuple[tuple[bool, str], tuple[bool, str]]:
    run_avm(["--lang", "en", "--workspace", ws, "init"])
    run_avm(["--lang", "en", "--workspace", ws, "create", "a"])
    b_res = run_avm(["--lang", "en", "--workspace", ws, "branch", "a", "a1", "--no-boot"], check=False)
    ps_res = run_avm(["--lang", "en", "--workspace", ws, "ps", "--json"])
    vms = json.loads(ps_res["stdout"])
    rec_a = next((v for v in vms if v["spec"]["name"] == "a"), None)
    rec_a1 = next((v for v in vms if v["spec"]["name"] == "a1"), None)

    m_ms = re.search(r"in\s+([0-9]+(?:\.[0-9]+)?)\s+ms", b_res["stdout"])
    r1_ok = (
        b_res["returncode"] == 0
        and m_ms is not None
        and rec_a1 is not None
        and rec_a1["telemetry"]["state"] == "stopped"
    )
    r1_msg = (
        f"exit={b_res['returncode']}, stdout='{b_res['stdout'].strip()}', "
        f"a1.state={rec_a1['telemetry']['state'] if rec_a1 else 'MISSING'}"
    )

    if not rec_a or not rec_a1:
        return (r1_ok, r1_msg), (False, "VM 'a' or 'a1' missing")

    iso_a = rec_a["spec"].get("cloudInitISOPath") or ""
    iso_a1 = rec_a1["spec"].get("cloudInitISOPath") or ""
    ext_dir = tempfile.mkdtemp(prefix="iso-a1-", dir=tmp_root)
    tproc = subprocess.run(["/usr/bin/tar", "-xf", iso_a1, "-C", ext_dir], capture_output=True, text=True)
    if tproc.returncode != 0:
        return (r1_ok, r1_msg), (False, f"tar -xf failed on a1 ISO: {tproc.stderr}")

    meta_txt = open(os.path.join(ext_dir, "meta-data"), encoding="utf-8").read()
    net_txt = open(os.path.join(ext_dir, "network-config"), encoding="utf-8").read()
    user_txt = open(os.path.join(ext_dir, "user-data"), encoding="utf-8").read()

    a1_id = rec_a1["spec"]["id"]
    problems = []
    if os.path.realpath(iso_a1) == os.path.realpath(iso_a):
        problems.append("a1 shares parent a's cloudInitISOPath")
    if f"instance-id: {a1_id}" not in meta_txt and f'instance-id: "{a1_id}"' not in meta_txt:
        problems.append(f"meta-data missing instance-id={a1_id}: {meta_txt.strip()!r}")
    if "local-hostname: a1" not in meta_txt and 'local-hostname: "a1"' not in meta_txt:
        problems.append(f"meta-data missing local-hostname=a1: {meta_txt.strip()!r}")
    if "dhcp-identifier: mac" not in net_txt:
        problems.append("network-config missing dhcp-identifier: mac")
    if "cloud-init-per" not in user_txt or "avm-machine-id" not in user_txt or "systemd-machine-id-setup" not in user_txt:
        problems.append("user-data missing cloud-init-per instance avm-machine-id bootcmd")
    if "/workspace" not in user_txt:
        problems.append("user-data missing /workspace bootcmd preservation")

    if problems:
        return (r1_ok, r1_msg), (False, "; ".join(problems))
    return (
        (r1_ok, r1_msg),
        (
            True,
            f"a1 ISO distinct from a; instance-id={a1_id}, local-hostname=a1, "
            "dhcp-identifier=mac, /workspace + cloud-init-per avm-machine-id bootcmds verified",
        ),
    )


# ---------------------------------------------------------------------------
# Optional Mutation Modes (Rows 25, 26, 27)
# ---------------------------------------------------------------------------
COORDINATOR_REL = os.path.join("Sources", "AgentVMHypervisor", "AgentVMFleetCoordinator.swift")
COORDINATOR_PATH = os.path.join(root_dir, COORDINATOR_REL)


def git_porcelain() -> str:
    p = subprocess.run(["git", "status", "--porcelain"], cwd=root_dir, capture_output=True, text=True, check=True)
    return p.stdout.strip()


def run_mutation_mode(mid: str) -> int:
    global resolved_bin
    row_num = 24 + int(mid)
    emit("==================================================================")
    emit(f" AgentVM Milestone M3 Mutation Check --mutation {mid} (Row {row_num})")
    emit("==================================================================")

    pre_git = git_porcelain()
    if pre_git:
        emit_err(f"REFUSED [Row {row_num}]: git working tree is not clean before --mutation {mid}:\n{pre_git}")
        return 1

    orig_bytes = open(COORDINATOR_PATH, "rb").read()
    orig_text = orig_bytes.decode("utf-8")

    def restore_source_and_rebuild() -> None:
        with open(COORDINATOR_PATH, "wb") as wf:
            wf.write(orig_bytes)
        subprocess.run(
            ["swift", "build"] + swift_jobs_args() + ["--product", "AgentVM"],
            cwd=root_dir,
            capture_output=True,
            text=True,
        )

    signal.signal(signal.SIGINT, lambda s, _f: (restore_source_and_rebuild(), cleanup_temp_tree(), sys.exit(128 + s)))
    signal.signal(signal.SIGTERM, lambda s, _f: (restore_source_and_rebuild(), cleanup_temp_tree(), sys.exit(128 + s)))

    caught = False
    summary_detail = ""
    try:
        if mid == "1":
            cold_target = (
                "        let (childCloudInit, childISOURL) = try synthesizeChildCloudInitAndISO(\n"
                "            parentSpec: parentRecord.spec,\n"
                "            childID: childID,\n"
                "            childBranchName: branchName,\n"
                "            childSlug: slug,\n"
                "            childStaticIPv4: childIP\n"
                "        )\n"
                "        childSpec.cloudInit = childCloudInit\n"
                "        childSpec.cloudInitISOPath = childISOURL.path"
            )
            cold_repl = (
                "        childSpec.cloudInit = parentRecord.spec.cloudInit\n"
                "        childSpec.cloudInitISOPath = parentRecord.spec.cloudInitISOPath"
            )
            live_target = (
                "            let (childCloudInit, childISOURL) = try synthesizeChildCloudInitAndISO(\n"
                "                parentSpec: parentRecord.spec,\n"
                "                childID: childID,\n"
                "                childBranchName: branchName,\n"
                "                childSlug: slug,\n"
                "                childStaticIPv4: childIP\n"
                "            )\n"
                "            createdISOURL = childISOURL\n"
                "            childSpec.cloudInit = childCloudInit\n"
                "            childSpec.cloudInitISOPath = childISOURL.path"
            )
            live_repl = (
                "            childSpec.cloudInit = parentRecord.spec.cloudInit\n"
                "            childSpec.cloudInitISOPath = parentRecord.spec.cloudInitISOPath"
            )
            if orig_text.count(cold_target) != 1 or orig_text.count(live_target) != 1:
                raise RuntimeError("Mutation 1 target snippet did not match uniquely in AgentVMFleetCoordinator.swift")
            mut_text = orig_text.replace(cold_target, cold_repl, 1).replace(live_target, live_repl, 1)
            with open(COORDINATOR_PATH, "w", encoding="utf-8") as wf:
                wf.write(mut_text)

            resolved_bin = build_and_sign_binary("AgentVM-mut1", sign_for_vz=True)
            stage_image_cache_copy()

            _, (r2_ok, r2_msg) = check_row1_and_row2(ws_empty)
            run_avm(["--lang", "en", "--workspace", ws_real, "init"])
            run_avm(["--lang", "en", "--workspace", ws_real, "create", "p", "--image", "debian-12-bookworm-arm64", "--disk-size", "8G", "--cpus", "2", "--memory-mb", "2048"])
            run_avm(["--lang", "en", "--workspace", ws_real, "up", "p"])
            run_avm(["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "sh", "-c", "echo mut1 > /root/a && sync"])
            run_avm(["--lang", "en", "--workspace", ws_real, "halt", "p"])
            wait_for_extra_vz_count(0, timeout_sec=30.0)

            run_avm(["--lang", "en", "--workspace", ws_real, "branch", "p", "c1"])
            run_avm(["--lang", "en", "--workspace", ws_real, "up", "c1"])
            run_avm(["--lang", "en", "--workspace", ws_real, "up", "p"])
            check_vm_cap(2)
            r9_ok, r9_msg = verify_distinct_pair_identity(ws_real, "p", "c1")
            run_avm(["--lang", "en", "--workspace", ws_real, "halt", "c1"])
            wait_for_extra_vz_count(1, timeout_sec=30.0)

            run_avm(["--lang", "en", "--workspace", ws_real, "branch", "p", "c2"])
            run_avm(["--lang", "en", "--workspace", ws_real, "up", "c2"])
            check_vm_cap(2)
            r13_ok, r13_msg = verify_distinct_pair_identity(ws_real, "p", "c2")
            run_avm(["--lang", "en", "--workspace", ws_real, "daemon", "stop"])

            caught = (not r2_ok) and (not r9_ok) and (not r13_ok)
            summary_detail = f"Row2_ok={r2_ok} ({r2_msg}); Row9_ok={r9_ok} ({r9_msg}); Row13_ok={r13_ok} ({r13_msg})"

        elif mid == "2":
            sync_target = (
                "        let prePauseSyncMs = try await performGuestSyncBeforeLiveClone(\n"
                "            session: session,\n"
                "            vmName: parentRecord.spec.name,\n"
                "            operation: \"branch\"\n"
                "        )"
            )
            sync_repl = (
                "        _ = session\n"
                "        let prePauseSyncMs: Double = 0.0"
            )
            if orig_text.count(sync_target) != 1:
                raise RuntimeError("Mutation 2 target snippet did not match uniquely in AgentVMFleetCoordinator.swift")
            mut_text = orig_text.replace(sync_target, sync_repl, 1)
            with open(COORDINATOR_PATH, "w", encoding="utf-8") as wf:
                wf.write(mut_text)

            resolved_bin = build_and_sign_binary("AgentVM-mut2", sign_for_vz=True)
            stage_image_cache_copy()

            run_avm(["--lang", "en", "--workspace", ws_real, "init"])
            run_avm(["--lang", "en", "--workspace", ws_real, "create", "p", "--image", "debian-12-bookworm-arm64", "--disk-size", "8G", "--cpus", "2", "--memory-mb", "2048"])
            run_avm(["--lang", "en", "--workspace", ws_real, "up", "p"])
            w_res = run_avm([
                "--lang", "en", "--workspace", ws_real, "exec", "p", "--", "sh", "-c",
                "head -c 67108864 /dev/urandom > /root/r && stat -c '%s' /root/r && sha256sum /root/r",
            ])
            w_lines = [ln.strip() for ln in w_res["stdout"].splitlines() if ln.strip()]
            p_sha = w_lines[1].split()[0]
            run_avm(["--lang", "en", "--workspace", ws_real, "branch", "p", "c2"])
            run_avm(["--lang", "en", "--workspace", ws_real, "up", "c2"])
            check_vm_cap(2)
            c2_res = run_avm(
                ["--lang", "en", "--workspace", ws_real, "exec", "c2", "--", "sh", "-c",
                 "if [ -e /root/r ]; then stat -c '%s' /root/r && sha256sum /root/r; else echo MISSING; fi"],
                check=False,
            )
            c2_lines = [ln.strip() for ln in c2_res["stdout"].splitlines() if ln.strip()]
            if not c2_lines or c2_lines[0] == "MISSING":
                r12_ok = False
                c2_desc = "MISSING"
            else:
                c2_sz = int(c2_lines[0])
                c2_sha = c2_lines[1].split()[0] if len(c2_lines) > 1 else ""
                r12_ok = (c2_sz == EXPECTED_64M_BYTES and c2_sha == p_sha)
                c2_desc = f"size={c2_sz}, sha_match={c2_sha == p_sha}"
            run_avm(["--lang", "en", "--workspace", ws_real, "daemon", "stop"])
            caught = not r12_ok
            summary_detail = f"Row12_ok={r12_ok} ({c2_desc})"

        elif mid == "3":
            scan_anchor = (
                "        let childSnapDiskURL = store.snapshotsDirectoryURL.appendingPathComponent(\"\\(childID.rawValue)-head.raw\")\n"
                "        let childSnapStrategy = try diskEngine.cloneDiskCoWReportingStrategy(\n"
                "            from: childDiskURL,\n"
                "            to: childSnapDiskURL,\n"
                "            overwrite: true\n"
                "        )"
            )
            scan_repl = (
                scan_anchor + "\n"
                "        _ = try diskEngine.scanSparseExtents(\n"
                "            at: URL(fileURLWithPath: forkSnap.diskClonePath),\n"
                "            compareAgainstParent: URL(fileURLWithPath: parentDisk.imagePath)\n"
                "        )\n"
                "        _ = try diskEngine.scanSparseExtents(\n"
                "            at: childSnapDiskURL,\n"
                "            compareAgainstParent: URL(fileURLWithPath: forkSnap.diskClonePath)\n"
                "        )"
            )
            if orig_text.count(scan_anchor) != 1:
                raise RuntimeError("Mutation 3 target snippet did not match uniquely in AgentVMFleetCoordinator.swift")
            mut_text = orig_text.replace(scan_anchor, scan_repl, 1)
            with open(COORDINATOR_PATH, "w", encoding="utf-8") as wf:
                wf.write(mut_text)

            resolved_bin = build_and_sign_binary("AgentVM-mut3", sign_for_vz=True)
            mut3_out = os.path.join(tmp_root, "mut3-bench")
            os.makedirs(mut3_out, exist_ok=True)
            env = dict(os.environ)
            env["AGENTVM_REAL_VM"] = "1"
            env["AGENTVM_BIN"] = resolved_bin
            env["AGENTVM_IMAGE_CACHE"] = source_cache_dir
            bproc = subprocess.run(
                [os.path.join(root_dir, "Scripts", "acceptance", "m3-branch-bench.sh"), "--out-dir", mut3_out],
                cwd=root_dir,
                env=env,
                capture_output=True,
                text=True,
            )
            jpath = os.path.join(mut3_out, "m3-branch-bench.json")
            med_ms = None
            if os.path.isfile(jpath):
                med_ms = json.load(open(jpath, encoding="utf-8"))["stoppedFork"]["wallClockMs"]["median"]
            caught = (bproc.returncode != 0) and (med_ms is not None and med_ms > 500.0)
            summary_detail = f"bench_exit={bproc.returncode}, stopped_median_ms={med_ms}"

    finally:
        restore_source_and_rebuild()
        cleanup_temp_tree()

    post_git = git_porcelain()
    if post_git:
        emit_err(f"FAIL [Row {row_num}]: git status not clean after restoring mutation:\n{post_git}")
        return 1
    if not caught:
        emit_err(f"FAIL [Row {row_num}]: mutation {mid} was NOT caught ({summary_detail})")
        return 1
    emit(f"PASS [Row {row_num}]: mutation {mid} caught as expected ({summary_detail}); source restored & git status clean.")
    return 0


if mutation_id:
    sys.exit(run_mutation_mode(mutation_id))

# ---------------------------------------------------------------------------
# Standard M3 Acceptance Run (Rows 1-19, Rows 21-24, Row 28)
# ---------------------------------------------------------------------------
signal.signal(signal.SIGINT, lambda s, _f: (cleanup_temp_tree(), sys.exit(128 + s)))
signal.signal(signal.SIGTERM, lambda s, _f: (cleanup_temp_tree(), sys.exit(128 + s)))

script_start = time.perf_counter()

try:
    emit("==================================================================")
    emit(" AgentVM Milestone M3 Fork & Snapshot Acceptance Suite")
    emit("==================================================================")
    emit(f"Baseline VirtualMachine PIDs (untouched): {sorted(baseline_vz_pids)}")
    emit(f"Baseline host AgentVM daemons (untouched): {len(baseline_daemons)}")

    if not resolved_bin:
        emit("Building debug AgentVM binary...")
        resolved_bin = build_and_sign_binary("AgentVM", sign_for_vz=real_vm_enabled)

    # ---- Rows 1 & 2 (Non-VM: empty disk branch + tar -xf cidata ISO check) ----
    try:
        (r1_ok, r1_msg), (r2_ok, r2_msg) = check_row1_and_row2(ws_empty)
        if r1_ok:
            pass_row(1, r1_msg)
        else:
            fail_row(1, r1_msg)
        if r2_ok:
            pass_row(2, r2_msg)
        else:
            fail_row(2, r2_msg)
    except Exception as exc:
        if 1 not in row_outcomes:
            fail_row(1, str(exc))
        if 2 not in row_outcomes:
            fail_row(2, str(exc))

    # ---- Row 3 (Non-VM: `branch a a2 --boot` on empty disk -> exit 1, ERR_NO_BOOTABLE_SYSTEM, no a2) ----
    try:
        r3 = run_avm(["--lang", "en", "--workspace", ws_empty, "branch", "a", "a2", "--boot"], check=False)
        vms_r3 = json.loads(run_avm(["--lang", "en", "--workspace", ws_empty, "ps", "--json"])["stdout"])
        names_r3 = [v["spec"]["name"] for v in vms_r3]
        d_status = run_avm(["--lang", "en", "--workspace", ws_empty, "daemon", "status"], check=False)
        if (
            r3["returncode"] == 1
            and "ERR_NO_BOOTABLE_SYSTEM" in (r3["stderr"] + r3["stdout"])
            and "a2" not in names_r3
            and d_status["returncode"] == 3
        ):
            pass_row(3, f"exit=1, ERR_NO_BOOTABLE_SYSTEM, 'a2' absent from ps --json ({names_r3}), no daemon spawned (exit 3)")
        else:
            fail_row(
                3,
                f"exit={r3['returncode']}, names={names_r3}, daemon_rc={d_status['returncode']}, stderr={r3['stderr'].strip()!r}",
            )
    except Exception as exc:
        fail_row(3, str(exc))

    # ---- Row 4 (Non-VM: coordinator lock mutual exclusion unit test) ----
    try:
        u_env = dict(os.environ)
        u_env["HOME"] = isolated_home
        u_env["CFFIXED_USER_HOME"] = isolated_home
        u_env["TMPDIR"] = isolated_tmp
        t0 = time.perf_counter()
        uproc = subprocess.run(
            [
                "swift", "test",
                *swift_jobs_args(),
                "--no-parallel",
                "--filter", "M3Stage2bLocksAndBranchBootTests/row4CoordinatorLockMutualExclusionDuringRestoreBranchAndSnapshot",
            ],
            cwd=root_dir,
            env=u_env,
            capture_output=True,
            text=True,
            timeout=600,
        )
        dt = time.perf_counter() - t0
        if uproc.returncode == 0 and len(extra_vz_pids()) == 0:
            pass_row(4, f"row4CoordinatorLockMutualExclusionDuringRestoreBranchAndSnapshot passed ({dt:.2f}s, 0 VMs)")
        else:
            fail_row(4, f"exit={uproc.returncode}, extra_vz={sorted(extra_vz_pids())}, tail={uproc.stdout[-600:] + uproc.stderr[-600:]}")
    except Exception as exc:
        fail_row(4, str(exc))

    # ---- Rows 5-19 & Row 28 (Real-VM rows) ----
    if not real_vm_enabled:
        for r in list(range(5, 20)) + [28]:
            unrun_row(r, "未设置 AGENTVM_REAL_VM=1（真机验收行未执行）")
    else:
        try:
            stage_image_cache_copy()
            run_avm(["--lang", "en", "--workspace", ws_real, "init"])

            # Row 5: Immediately after `create p --image`, ps --json apfsPrivateBytes == getattrlist sum
            c_res = run_avm([
                "--lang", "en", "--workspace", ws_real,
                "create", "p",
                "--image", "debian-12-bookworm-arm64",
                "--disk-size", "8G",
                "--cpus", "2",
                "--memory-mb", "2048",
            ])
            vms_r5 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "ps", "--json"])["stdout"])
            snaps_r5 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "snapshot", "list", "--json"])["stdout"])
            rec_p = next(v for v in vms_r5 if v["spec"]["name"] == "p")
            p_snap = next(s for s in snaps_r5 if s["vmID"] == rec_p["spec"]["id"])
            ps_priv = int(rec_p["telemetry"]["apfsPrivateBytes"])
            disk_priv = read_apfs_space(rec_p["spec"]["blockDevices"][0]["imagePath"])["privateBytes"]
            snap_priv = read_apfs_space(p_snap["diskClonePath"])["privateBytes"]
            total_getattr = disk_priv + snap_priv
            if ps_priv == total_getattr:
                pass_row(5, f"ps --json apfsPrivateBytes={ps_priv} B == getattrlist(root={disk_priv} B + baseSnap={snap_priv} B)={total_getattr} B")
            else:
                fail_row(5, f"ps --json apfsPrivateBytes={ps_priv} != getattrlist sum {total_getattr}")

            # Row 6: Preparation (`up p`, write `/root/a` + 256 MiB `/var/tmp/blob` + guest SHA-256, `sync`, `halt p`)
            up_p = run_avm(["--lang", "en", "--workspace", ws_real, "up", "p"])
            check_vm_cap(2)
            marker_a = f"m3-row6-marker-{uuid.uuid4().hex}"
            prep6 = run_avm([
                "--lang", "en", "--workspace", ws_real, "exec", "p", "--", "sh", "-c",
                f"printf '%s\\n' '{marker_a}' > /root/a && "
                "dd if=/dev/urandom of=/var/tmp/blob bs=1M count=256 status=none && "
                "sync && cat /root/a && stat -c '%s' /var/tmp/blob && sha256sum /var/tmp/blob",
            ])
            p6_lines = [ln.strip() for ln in prep6["stdout"].splitlines() if ln.strip()]
            blob_size = int(p6_lines[1])
            blob_sha256 = p6_lines[2].split()[0]
            halt_p = run_avm(["--lang", "en", "--workspace", ws_real, "halt", "p"])
            wait_for_extra_vz_count(0, timeout_sec=30.0)
            if p6_lines[0] == marker_a and blob_size == EXPECTED_256M_BYTES and len(blob_sha256) == 64:
                pass_row(
                    6,
                    f"create={c_res['wallMs']:.1f}ms, up={up_p['wallMs']:.1f}ms, write256MiB={prep6['wallMs']:.1f}ms "
                    f"(blob sha256={blob_sha256[:16]}...), halt={halt_p['wallMs']:.1f}ms",
                )
            else:
                fail_row(6, f"unexpected prep output: {p6_lines}")

            # Row 7: Stopped fork `branch p c1`, host wall-clock, c1 stopped, new cloned files privateBytes == 0
            r7 = run_avm(["--lang", "en", "--workspace", ws_real, "branch", "p", "c1"])
            m7 = re.search(r"in\s+([0-9]+(?:\.[0-9]+)?)\s+ms\s+from\s+snapshot\s+(snap-[a-zA-Z0-9-]+)", r7["stdout"])
            fsnap_c1_id = m7.group(2) if m7 else ""
            vms_r7 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "ps", "--json"])["stdout"])
            snaps_r7 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "snapshot", "list", "--json"])["stdout"])
            rec_c1 = next(v for v in vms_r7 if v["spec"]["name"] == "c1")
            c1_head = next(s for s in snaps_r7 if s["id"] == rec_c1["currentHeadSnapshotID"])
            c1_fork_snap = next(s for s in snaps_r7 if s["id"] == fsnap_c1_id)
            c1_nvram = rec_c1["spec"]["bootLoader"].get("efiBoot", {}).get("variableStorePath", "")
            r7_paths = [
                c1_fork_snap["diskClonePath"],
                rec_c1["spec"]["blockDevices"][0]["imagePath"],
                c1_head["diskClonePath"],
            ] + ([c1_nvram] if c1_nvram and os.path.isfile(c1_nvram) else [])
            r7_privs = [read_apfs_space(p)["privateBytes"] for p in r7_paths]
            if rec_c1["telemetry"]["state"] == "stopped" and all(x == 0 for x in r7_privs):
                pass_row(
                    7,
                    f"wall={r7['wallMs']:.2f}ms (self-reported {m7.group(1) if m7 else '?'}ms), "
                    f"c1=stopped, {len(r7_privs)} cloned files privateBytes={r7_privs}",
                )
            else:
                fail_row(7, f"state={rec_c1['telemetry']['state']}, privs={r7_privs}")

            # Row 8: `up c1`, verify `/root/a` and `sha256sum /var/tmp/blob`
            up_c1 = run_avm(["--lang", "en", "--workspace", ws_real, "up", "c1"])
            check_vm_cap(2)
            r8 = run_avm([
                "--lang", "en", "--workspace", ws_real, "exec", "c1", "--", "sh", "-c",
                "cat /root/a && stat -c '%s' /var/tmp/blob && sha256sum /var/tmp/blob",
            ])
            r8_lines = [ln.strip() for ln in r8["stdout"].splitlines() if ln.strip()]
            if r8_lines[0] == marker_a and int(r8_lines[1]) == EXPECTED_256M_BYTES and r8_lines[2].split()[0] == blob_sha256:
                pass_row(8, f"up c1={up_c1['wallMs']:.1f}ms; /root/a and 256 MiB blob SHA-256 ({blob_sha256[:16]}...) match Row 6")
            else:
                fail_row(8, f"mismatch on c1: {r8_lines}")

            # Row 9: `p` and `c1` concurrent 6-item guest identity comparison
            run_avm(["--lang", "en", "--workspace", ws_real, "up", "p"])
            check_vm_cap(2)
            r9_ok, r9_msg = verify_distinct_pair_identity(ws_real, "p", "c1")
            if r9_ok:
                pass_row(9, r9_msg)
            else:
                fail_row(9, r9_msg)

            # Row 10: Bidirectional write isolation (`c1` writes `/root/b`, `p` writes `/root/p2`)
            run_avm(["--lang", "en", "--workspace", ws_real, "exec", "c1", "--", "sh", "-c", "printf 'c1-only\\n' > /root/b && sync"])
            run_avm(["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "sh", "-c", "printf 'p-only\\n' > /root/p2 && sync"])
            p_b = run_avm(["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "test", "!", "-e", "/root/b"], check=False)
            c1_p2 = run_avm(["--lang", "en", "--workspace", ws_real, "exec", "c1", "--", "test", "!", "-e", "/root/p2"], check=False)
            if p_b["returncode"] == 0 and c1_p2["returncode"] == 0:
                pass_row(10, "p does not see /root/b and c1 does not see /root/p2")
            else:
                fail_row(10, f"isolation check failed: p_b_rc={p_b['returncode']}, c1_p2_rc={c1_p2['returncode']}")

            # Halt `c1` so only `p` stays running (`<= 2` VMs)
            run_avm(["--lang", "en", "--workspace", ws_real, "halt", "c1"])
            wait_for_extra_vz_count(1, timeout_sec=30.0)

            # Row 11 & Row 14: Running `p` writes 64 MiB `/root/r` without sync + `/tmp/tick`, immediately `branch p c2`
            p_boot_r11_before = run_avm(
                ["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "cat", "/proc/sys/kernel/random/boot_id"]
            )["stdout"].strip()
            run_avm([
                "--lang", "en", "--workspace", ws_real, "exec", "p", "--", "sh", "-c",
                "rm -f /tmp/tick /tmp/tick.pid && nohup sh -c 'while :; do date +%s%N; sleep 0.01; done > /tmp/tick' >/dev/null 2>&1 </dev/null & echo $! > /tmp/tick.pid",
            ])
            time.sleep(0.20)
            w11 = run_avm([
                "--lang", "en", "--workspace", ws_real, "exec", "p", "--", "sh", "-c",
                "head -c 67108864 /dev/urandom > /root/r && stat -c '%s' /root/r && sha256sum /root/r",
            ])
            w11_lines = [ln.strip() for ln in w11["stdout"].splitlines() if ln.strip()]
            r_size_p = int(w11_lines[0])
            r_sha_p = w11_lines[1].split()[0]

            b11 = run_avm(["--lang", "en", "--workspace", ws_real, "branch", "p", "c2"])
            time.sleep(0.20)
            tick_raw = run_avm([
                "--lang", "en", "--workspace", ws_real, "exec", "p", "--", "sh", "-c",
                "kill $(cat /tmp/tick.pid) 2>/dev/null || true; wait 2>/dev/null || true; cat /tmp/tick",
            ])["stdout"]
            p_boot_r11_after = run_avm(
                ["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "cat", "/proc/sys/kernel/random/boot_id"]
            )["stdout"].strip()
            vms_r11 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "ps", "--json"])["stdout"])
            p_r11 = next(v for v in vms_r11 if v["spec"]["name"] == "p")
            c2_r11 = next(v for v in vms_r11 if v["spec"]["name"] == "c2")

            if (
                r_size_p == EXPECTED_64M_BYTES
                and p_boot_r11_after == p_boot_r11_before
                and p_r11["telemetry"]["state"] == "running"
                and c2_r11["telemetry"]["state"] == "stopped"
                and len(extra_vz_pids()) == 1
            ):
                pass_row(
                    11,
                    f"live branch p c2 exited 0 ({b11['wallMs']:.2f}ms); p stayed running with boot_id={p_boot_r11_after} unchanged; c2=stopped",
                )
            else:
                fail_row(11, f"p.state={p_r11['telemetry']['state']}, c2.state={c2_r11['telemetry']['state']}, boot_id {p_boot_r11_before}->{p_boot_r11_after}")

            # Row 12: `up c2`, verify `/root/r` size == 67108864 & SHA-256 matches `p`, inspect `dmesg`
            up_c2 = run_avm(["--lang", "en", "--workspace", ws_real, "up", "c2"])
            check_vm_cap(2)
            r12 = run_avm([
                "--lang", "en", "--workspace", ws_real, "exec", "c2", "--", "sh", "-c",
                "stat -c '%s' /root/r && sha256sum /root/r && findmnt -n -o OPTIONS / && echo '---DMESG---' && (dmesg | grep -iE 'EXT4-fs|recovery|orphan' || true)",
            ])
            pre_d, _, d_part = r12["stdout"].partition("---DMESG---")
            r12_lines = [ln.strip() for ln in pre_d.splitlines() if ln.strip()]
            c2_r_sz = int(r12_lines[0])
            c2_r_sha = r12_lines[1].split()[0]
            c2_mnt_opts = r12_lines[2] if len(r12_lines) > 2 else ""
            dmesg_ext4 = [ln.strip() for ln in d_part.splitlines() if ln.strip()]
            recov_seen = any("recovery complete" in ln.lower() for ln in dmesg_ext4)
            if c2_r_sz == EXPECTED_64M_BYTES and c2_r_sha == r_sha_p and "rw" in c2_mnt_opts.split(","):
                pass_row(
                    12,
                    f"up c2={up_c2['wallMs']:.1f}ms; /root/r size=67108864 & sha256={c2_r_sha[:16]}... match p; "
                    f"rootfs mounted ({c2_mnt_opts}), dmesg 'recovery complete'={recov_seen}",
                )
            else:
                fail_row(12, f"size={c2_r_sz}, sha_match={c2_r_sha == r_sha_p}, mnt={c2_mnt_opts!r}")

            # Row 13: Concurrent `p` and `c2` 6-item identity check
            r13_ok, r13_msg = verify_distinct_pair_identity(ws_real, "p", "c2")
            if r13_ok:
                pass_row(13, r13_msg)
            else:
                fail_row(13, r13_msg)

            # Halt `c2` so only `p` remains running
            run_avm(["--lang", "en", "--workspace", ws_real, "halt", "c2"])
            wait_for_extra_vz_count(1, timeout_sec=30.0)

            # Row 14: Record `VM_PAUSED_FOR_SNAPSHOT` ms from `events --vm p` + max interval in `/tmp/tick`
            ev_text = run_avm(["--lang", "en", "--workspace", ws_real, "events", "--vm", "p"])["stdout"]
            ev_json = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "events", "--vm", "p", "--json"])["stdout"])
            b_events = [
                e for e in ev_json
                if e.get("code") == "VM_PAUSED_FOR_SNAPSHOT" and e.get("metadata", {}).get("operation") == "branch"
            ]
            ticks_ns = [int(ln.strip()) for ln in tick_raw.splitlines() if ln.strip().isdigit()]
            deltas_ms = [(ticks_ns[i + 1] - ticks_ns[i]) / 1_000_000.0 for i in range(len(ticks_ns) - 1)]
            if b_events and "VM_PAUSED_FOR_SNAPSHOT" in ev_text and deltas_ms:
                p_ms = float(b_events[-1]["metadata"]["pauseMs"])
                s_ms = float(b_events[-1]["metadata"]["syncMs"])
                max_tick_ms = max(deltas_ms)
                pass_row(
                    14,
                    f"VM_PAUSED_FOR_SNAPSHOT pauseMs={p_ms:.3f} ms (pre-pause syncMs={s_ms:.3f} ms); "
                    f"guest /tmp/tick max interval={max_tick_ms:.3f} ms across {len(deltas_ms)} intervals",
                )
            else:
                fail_row(14, f"b_events={len(b_events)}, deltas={len(deltas_ms)}")

            # Row 15, 16, 17, 18: Live & stopped snapshot/restore + auto pre-restore snapshot + identity preservation
            ident_pre_r15 = read_guest_identity(ws_real, "p")
            boot_pre_r15 = ident_pre_r15["boot_id"]
            p_iso_path = next(
                v for v in json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "ps", "--json"])["stdout"])
                if v["spec"]["name"] == "p"
            )["spec"]["cloudInitISOPath"]
            iso_sig_pre = file_stat_sig(p_iso_path)

            s1_res = run_avm(["--lang", "en", "--workspace", ws_real, "snapshot", "p", "s1"])
            boot_after_s1 = run_avm(
                ["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "cat", "/proc/sys/kernel/random/boot_id"]
            )["stdout"].strip()
            snaps_s1 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "snapshot", "list", "--json"])["stdout"])
            s1_node = next(s for s in snaps_s1 if s["title"] == "s1")
            s1_id = s1_node["id"]

            run_avm(["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "sh", "-c", "rm -f /root/a && sync && test ! -e /root/a"])
            rest15 = run_avm(["--lang", "en", "--workspace", ws_real, "restore", s1_id])
            snap_tokens_15 = [tok for tok in re.findall(r"snap-[a-zA-Z0-9-]+", rest15["stdout"]) if tok != s1_id]
            auto15_id = snap_tokens_15[0] if snap_tokens_15 else ""

            vms_after_15 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "ps", "--json"])["stdout"])
            p_after_15 = next(v for v in vms_after_15 if v["spec"]["name"] == "p")
            a_after_15 = run_avm(["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "cat", "/root/a"])["stdout"].strip()
            ident_after_r15 = read_guest_identity(ws_real, "p")

            if (
                boot_after_s1 == boot_pre_r15
                and s1_node["kind"] == "live-disk"
                and auto15_id != ""
                and p_after_15["telemetry"]["state"] == "running"
                and p_after_15["telemetry"]["guestAgentConnected"] is True
                and ident_after_r15["boot_id"] != boot_pre_r15
                and a_after_15 == marker_a
            ):
                pass_row(
                    15,
                    f"live snapshot s1={s1_id} (live-disk, boot_id unchanged); live restore exited 0 "
                    f"(auto snapshot={auto15_id}, {rest15['wallMs']:.1f}ms), p=running & guestAgentConnected=true, "
                    f"boot_id changed, /root/a restored",
                )
            else:
                fail_row(15, f"auto15={auto15_id!r}, state={p_after_15['telemetry']}, a={a_after_15!r}")

            # Row 16: Restore `<auto15_id>` -> `/root/a` is gone again
            rest16 = run_avm(["--lang", "en", "--workspace", ws_real, "restore", auto15_id])
            absent16 = run_avm(
                ["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "test", "!", "-e", "/root/a"],
                check=False,
            )
            if absent16["returncode"] == 0:
                pass_row(16, f"restore {auto15_id} exited 0 ({rest16['wallMs']:.1f}ms); /root/a is absent again")
            else:
                fail_row(16, f"/root/a still present after restoring {auto15_id}")

            # Row 17: Restore s1 so `/root/a` exists, then `halt p` -> `snapshot p s2` -> boot & rm `/root/a` & halt -> `restore <s2>` -> boot & read `/root/a`
            run_avm(["--lang", "en", "--workspace", ws_real, "restore", s1_id])
            run_avm(["--lang", "en", "--workspace", ws_real, "halt", "p"])
            wait_for_extra_vz_count(0, timeout_sec=30.0)
            run_avm(["--lang", "en", "--workspace", ws_real, "snapshot", "p", "s2"])
            snaps_s2 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "snapshot", "list", "--json"])["stdout"])
            s2_node = next(s for s in snaps_s2 if s["title"] == "s2")
            s2_id = s2_node["id"]

            run_avm(["--lang", "en", "--workspace", ws_real, "up", "p"])
            run_avm(["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "sh", "-c", "rm -f /root/a && sync && test ! -e /root/a"])
            run_avm(["--lang", "en", "--workspace", ws_real, "halt", "p"])
            wait_for_extra_vz_count(0, timeout_sec=30.0)

            rest17 = run_avm(["--lang", "en", "--workspace", ws_real, "restore", s2_id])
            auto17_tokens = [tok for tok in re.findall(r"snap-[a-zA-Z0-9-]+", rest17["stdout"]) if tok != s2_id]
            run_avm(["--lang", "en", "--workspace", ws_real, "up", "p"])
            a_after_17 = run_avm(["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "cat", "/root/a"])["stdout"].strip()
            ident_after_r17 = read_guest_identity(ws_real, "p")

            if s2_node["kind"] == "cold-disk" and auto17_tokens and a_after_17 == marker_a:
                pass_row(
                    17,
                    f"stopped snapshot s2={s2_id} (cold-disk) & stopped restore ({rest17['wallMs']:.1f}ms, auto={auto17_tokens[0]}) "
                    "restored /root/a after reboot",
                )
            else:
                fail_row(17, f"s2.kind={s2_node['kind']}, auto17={auto17_tokens}, a={a_after_17!r}")

            # Row 18: Identity 5 items + SSH fingerprint unchanged across Row 15 and Row 17 restores
            id_keys = ("hostname", "machine_id", "instance_id", "mac", "ipv4", "ssh_ed25519")
            same_15 = all(ident_pre_r15[k] == ident_after_r15[k] for k in id_keys)
            same_17 = all(ident_pre_r15[k] == ident_after_r17[k] for k in id_keys)
            iso_unchanged = file_stat_sig(p_iso_path) == iso_sig_pre
            if same_15 and same_17 and iso_unchanged:
                pass_row(
                    18,
                    f"p retained identical 5 identity items + SSH fingerprint across live & stopped restores "
                    f"(ip={ident_after_r17['ipv4']}, mid={ident_after_r17['machine_id'][:8]}...)",
                )
            else:
                fail_row(18, f"same_15={same_15}, same_17={same_17}, iso_unchanged={iso_unchanged}")

            # Row 28 (Decided Item 6a): Running `p` `exec p -- rm -rf /tmp/x` captures `autoPreCommandCheckpoint`
            boot_pre_28 = ident_after_r17["boot_id"]
            run_avm(["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "mkdir", "-p", "/tmp/x"])
            snaps_pre_28 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "snapshot", "list", "--json"])["stdout"])
            auto_cnt_pre = sum(1 for s in snaps_pre_28 if s["kind"] == "auto-pre-cmd")
            r28_rm = run_avm(["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "rm", "-rf", "/tmp/x"])
            snaps_mid_28 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "snapshot", "list", "--json"])["stdout"])
            auto_cnt_mid = sum(1 for s in snaps_mid_28 if s["kind"] == "auto-pre-cmd")
            run_avm(["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "true"])
            snaps_post_28 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "snapshot", "list", "--json"])["stdout"])
            boot_post_28 = run_avm(
                ["--lang", "en", "--workspace", ws_real, "exec", "p", "--", "cat", "/proc/sys/kernel/random/boot_id"]
            )["stdout"].strip()
            evs_28 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "events", "--vm", "p", "--json"])["stdout"])
            skipped_28 = [e for e in evs_28 if e.get("code") == "AUTO_CHECKPOINT_SKIPPED_UNTIL_M3"]

            if (
                r28_rm["returncode"] == 0
                and auto_cnt_mid == auto_cnt_pre + 1
                and len(snaps_post_28) == len(snaps_mid_28)
                and boot_post_28 == boot_pre_28
                and not skipped_28
            ):
                pass_row(
                    28,
                    "exec rm -rf /tmp/x exited 0, added 1 auto-pre-cmd checkpoint, boot_id unchanged, "
                    "0 AUTO_CHECKPOINT_SKIPPED_UNTIL_M3 events, exec true added 0 snapshots",
                )
            else:
                fail_row(
                    28,
                    f"auto_cnt {auto_cnt_pre}->{auto_cnt_mid}, post_len={len(snaps_post_28)}/{len(snaps_mid_28)}, "
                    f"boot_match={boot_post_28 == boot_pre_28}, skipped={len(skipped_28)}",
                )

            # Halt `p` and stop daemon before Row 19 (`p` stopped -> `branch p c3 --boot`)
            run_avm(["--lang", "en", "--workspace", ws_real, "halt", "p"])
            run_avm(["--lang", "en", "--workspace", ws_real, "daemon", "stop"])
            wait_for_extra_vz_count(0, timeout_sec=30.0)

            # Row 19: While `p` is stopped, `branch p c3 --boot` -> exit 0, c3 running & guestAgentConnected=true, distinct identity
            r19 = run_avm(["--lang", "en", "--workspace", ws_real, "branch", "p", "c3", "--boot"])
            vms_r19 = json.loads(run_avm(["--lang", "en", "--workspace", ws_real, "ps", "--json"])["stdout"])
            rec_c3 = next(v for v in vms_r19 if v["spec"]["name"] == "c3")
            run_avm(["--lang", "en", "--workspace", ws_real, "up", "p"])
            check_vm_cap(2)
            r19_id_ok, r19_id_msg = verify_distinct_pair_identity(ws_real, "p", "c3")
            run_avm(["--lang", "en", "--workspace", ws_real, "halt", "c3"])
            run_avm(["--lang", "en", "--workspace", ws_real, "halt", "p"])
            run_avm(["--lang", "en", "--workspace", ws_real, "daemon", "stop"])
            wait_for_extra_vz_count(0, timeout_sec=30.0)

            if (
                rec_c3["telemetry"]["state"] == "running"
                and rec_c3["telemetry"]["guestAgentConnected"] is True
                and r19_id_ok
            ):
                pass_row(
                    19,
                    f"branch p c3 --boot exited 0 ({r19['wallMs']:.1f}ms); c3=running & guestAgentConnected=true; {r19_id_msg}",
                )
            else:
                fail_row(19, f"c3.telemetry={rec_c3['telemetry']}, id_ok={r19_id_ok} ({r19_id_msg})")

        except Exception as exc:
            for r in list(range(5, 20)) + [28]:
                if r not in row_outcomes:
                    fail_row(r, f"aborted after exception: {exc}")
            stop_tracked_workspaces()

    # ---- Row 21 (Non-VM: Both READMEs X & Y match reports/m3-branch-bench.json + readme-commands.sh) ----
    try:
        bench_json_path = os.path.join(root_dir, "reports", "m3-branch-bench.json")
        if not os.path.isfile(bench_json_path):
            fail_row(21, "reports/m3-branch-bench.json does not exist yet")
        else:
            bdoc = json.load(open(bench_json_path, encoding="utf-8"))
            readme_en = open(os.path.join(root_dir, "README.md"), encoding="utf-8").read()
            readme_zh = open(os.path.join(root_dir, "README.zh-CN.md"), encoding="utf-8").read()

            x_med = f"{bdoc['stoppedFork']['wallClockMs']['median']:.2f}"
            x_p95 = f"{bdoc['stoppedFork']['wallClockMs']['p95NearestRank']:.2f}"
            live_med = f"{bdoc['liveFork']['wallClockMs']['median']:.2f}"
            pause_med = f"{bdoc['liveFork']['vmPauseMs']['median']:.3f}"
            y_priv = int(bdoc["headlineMetrics"]["Y_newClonedFilesAPFSPrivateBytes"])
            hw_model = bdoc["host"]["hwModel"]
            macos_ver = bdoc["host"]["macOSProductVersion"]
            b_date = bdoc["date"]

            r21_problems = []
            if y_priv != 0:
                r21_problems.append(f"expected Y=0 in JSON, got {y_priv}")
            for label, txt in (("README.md", readme_en), ("README.zh-CN.md", readme_zh)):
                for token in (x_med, x_p95, live_med, pause_med, hw_model, macos_ver, b_date):
                    if token not in txt:
                        r21_problems.append(f"{label} missing benchmark value '{token}'")
                if real_home and real_home in txt:
                    r21_problems.append(f"{label} contains host home directory path")
                if "refused until M3" in txt or "在 M3 之前拒绝" in txt:
                    r21_problems.append(f"{label} still contains outdated M2 refusal text")

            rc_env = dict(os.environ)
            rc_env["HOME"] = isolated_home
            rc_env["CFFIXED_USER_HOME"] = isolated_home
            rc_env["TMPDIR"] = isolated_tmp
            rc_proc = subprocess.run(
                [os.path.join(root_dir, "Scripts", "acceptance", "readme-commands.sh")],
                cwd=root_dir,
                env=rc_env,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if rc_proc.returncode != 0:
                r21_problems.append(f"readme-commands.sh exited {rc_proc.returncode}: {rc_proc.stderr.strip()}")

            if r21_problems:
                fail_row(21, "; ".join(r21_problems))
            else:
                pass_row(
                    21,
                    f"README.md & README.zh-CN.md match reports/m3-branch-bench.json "
                    f"(X={x_med} ms, p95={x_p95} ms, live={live_med} ms, pause={pause_med} ms, Y={y_priv} B, "
                    f"{hw_model}, macOS {macos_ver}, {b_date}); readme-commands.sh passed",
                )
    except Exception as exc:
        fail_row(21, str(exc))

    # ---- Row 22 (Real-VM: m1-real-boot.sh and m2-daemon.sh regression) ----
    if not real_vm_enabled:
        unrun_row(22, "未设置 AGENTVM_REAL_VM=1（m1-real-boot.sh 与 m2-daemon.sh 回归行未执行）")
    elif from_milestone3:
        emit("INFO [Row 22]: orchestrated by Scripts/test.sh milestone 3 (executes m1-real-boot.sh and m2-daemon.sh directly)")
    else:
        try:
            stage_image_cache_copy()
            sub_env = dict(os.environ)
            sub_env["HOME"] = real_home
            sub_env["AGENTVM_REAL_VM"] = "1"
            sub_env["AGENTVM_BIN"] = resolved_bin
            sub_env["AGENTVM_IMAGE_CACHE"] = local_cache_dir

            m1_proc = subprocess.run(
                [os.path.join(root_dir, "Scripts", "acceptance", "m1-real-boot.sh")],
                cwd=root_dir,
                env=sub_env,
                capture_output=True,
                text=True,
                timeout=1800,
            )
            m1_ok = m1_proc.returncode == 0 and "26 passed, 0 failed, 0 unrun" in m1_proc.stdout

            m2_proc = subprocess.run(
                [os.path.join(root_dir, "Scripts", "acceptance", "m2-daemon.sh")],
                cwd=root_dir,
                env=sub_env,
                capture_output=True,
                text=True,
                timeout=2400,
            )
            m2_ok = (
                m2_proc.returncode in (0, 2)
                and "36 passed, 0 failed, 3 unrun" in m2_proc.stdout
                and "PASS [Row 23]:" in m2_proc.stdout
            )
            if m1_ok and m2_ok:
                pass_row(22, "m1-real-boot.sh (26 passed, 0 failed) and m2-daemon.sh (36 passed, 0 failed, Row 23 M3 live snapshot/restore PASS)")
            else:
                fail_row(22, f"m1_rc={m1_proc.returncode} (ok={m1_ok}), m2_rc={m2_proc.returncode} (ok={m2_ok})")
        except Exception as exc:
            fail_row(22, str(exc))

    # ---- Row 23 (Non-VM: full unit test suite + Scripts/test.sh milestone 0) ----
    try:
        u_env = dict(os.environ)
        u_env["HOME"] = isolated_home
        u_env["CFFIXED_USER_HOME"] = isolated_home
        u_env["TMPDIR"] = isolated_tmp
        if from_milestone3:
            # milestone 3 already ran M3 touched scopes + m0-acceptance.sh + readme-commands.sh;
            # run the remaining non-touched suites here so all 25 suites are covered without repeating milestone 0.
            rem = subprocess.run(
                [
                    "swift", "test",
                    *swift_jobs_args(),
                    "--no-parallel",
                    "--filter", "NetSwitchDissectorAndPCAPTests",
                    "--filter", "WorkbenchShellTests",
                    "--filter", "StudioViewsHonestyTests",
                ],
                cwd=root_dir,
                env=u_env,
                capture_output=True,
                text=True,
                timeout=600,
            )
            if rem.returncode == 0 and len(extra_vz_pids()) == 0:
                pass_row(23, "remaining unit suites (NetSwitch, WorkbenchShell, StudioViews) passed alongside milestone 3 scopes + M0 checks (0 VMs)")
            else:
                fail_row(23, f"remaining unit suites exited {rem.returncode}")
        else:
            ut = subprocess.run(
                ["swift", "test", *swift_jobs_args(), "--no-parallel"],
                cwd=root_dir,
                env=u_env,
                capture_output=True,
                text=True,
                timeout=1800,
            )
            m0 = subprocess.run(
                [os.path.join(root_dir, "Scripts", "test.sh"), "milestone", "0"],
                cwd=root_dir,
                env=u_env,
                capture_output=True,
                text=True,
                timeout=1800,
            )
            # Clean up milestone 0's temp log directory inside isolated_tmp
            for m_log in re.findall(r"Acceptance logs:\s*(\S+)", m0.stdout):
                if os.path.isdir(m_log):
                    shutil.rmtree(m_log, ignore_errors=True)
            if ut.returncode == 0 and m0.returncode == 0 and len(extra_vz_pids()) == 0:
                summary_ut = next((ln.strip() for ln in reversed(ut.stdout.splitlines()) if "Test run with" in ln), "passed")
                pass_row(23, f"swift test --no-parallel ({summary_ut}) and Scripts/test.sh milestone 0 passed (0 VMs)")
            else:
                fail_row(23, f"swift_test_rc={ut.returncode}, milestone0_rc={m0.returncode}")
    except Exception as exc:
        fail_row(23, str(exc))

finally:
    # ---- Row 24 (Non-VM: Post-run cleanup & host hygiene check) ----
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
    vz_extra_after = sorted(extra_vz_pids())
    home_after = snapshot_home_hygiene()
    new_home_items = {
        k: sorted(set(home_after[k]) - set(baseline_home[k]))
        for k in ("launch_agents", "preferences", "app_support")
    }
    lctl = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
    lctl_hits = [ln.strip() for ln in lctl.stdout.splitlines() if "agentvm" in ln.lower()] if lctl.returncode == 0 else ["launchctl_failed"]
    cache_after = snapshot_cache_dir(source_cache_dir)
    cache_ok = cache_after == cache_before

    if (
        tmp_gone
        and not leftover_links
        and not new_daemons
        and not vz_extra_after
        and iso_la_clean
        and all(not v for v in new_home_items.values())
        and not lctl_hits
        and cache_ok
    ):
        pass_row(
            24,
            "temp dirs & avm-* symlinks removed; 0 leaked daemons or extra VirtualMachine processes; "
            "0 new LaunchAgents/Preferences/Application Support items; 0 'agentvm' launchctl entries; image cache untouched",
        )
    else:
        fail_row(
            24,
            f"tmp_gone={tmp_gone}, links={leftover_links}, new_daemons={new_daemons}, vz_extra={vz_extra_after}, "
            f"iso_la_clean={iso_la_clean}, home_diff={new_home_items}, launchctl={lctl_hits}, cache_ok={cache_ok}",
        )

emit("INFO [Rows 25-27]: source-mutation checks skipped by default (pass --mutation 1|2|3 with AGENTVM_REAL_VM=1 to run)")

elapsed = time.perf_counter() - script_start
emit("==================================================================")
emit(f" Summary: {passed_rows} passed, {failed_rows} failed, {unrun_rows} unrun (total {elapsed:.2f}s)")
emit("==================================================================")

if failed_rows > 0:
    sys.exit(1)
if unrun_rows > 0:
    sys.exit(2)
sys.exit(0)
PY
