#!/usr/bin/env bash
# AgentVM Milestone M3 APFS CoW Branch Benchmark Script (Acceptance Row 20, Appendix H).
#
# Measures:
#   1. 16 stopped APFS CoW forks (`agentvm branch p sc1..sc16`) on an 8 GiB Debian 12 disk
#      populated with 1 GiB of random guest data (`/var/tmp/bench-data.bin`) + marker (`/root/bench-marker`).
#   2. 16 live running APFS CoW forks (`agentvm branch p lc1..lc16`) while `p` is running under the
#      workspace daemon, recording host wall-clock, CLI self-reported ms, and daemon `VM_PAUSED_FOR_SNAPSHOT` ms.
#   3. APFS private bytes (`ATTR_CMNEXT_PRIVATESIZE` via `/usr/bin/python3` + `ctypes` `getattrlist(2)`,
#      zero product code) of every newly cloned file, plus `df -k` deltas before/after each batch.
#   4. Sequential boot (`up`), 6-item guest identity + marker verification, and `halt` across all 32
#      children (never exceeding 2 concurrent VMs), plus post-first-boot APFS private bytes per child.
#
# Without AGENTVM_REAL_VM=1, prints "没跑" and exits 2 immediately without creating anything.
# Pass --record to write `reports/m3-branch-bench.json` and `reports/m3-branch-bench.md`.
# Pass --out-dir <dir> to write `m3-branch-bench.json` and `m3-branch-bench.md` into <dir>.
set -euo pipefail

RECORD_REPORTS=0
OUT_DIR=""

usage() {
    cat >&2 <<'EOF'
Usage:
  AGENTVM_REAL_VM=1 Scripts/acceptance/m3-branch-bench.sh [--record] [--out-dir <dir>]

Options:
  --record         Write benchmark outputs to reports/m3-branch-bench.json and reports/m3-branch-bench.md
  --out-dir <dir>  Write m3-branch-bench.json and m3-branch-bench.md to <dir>
  -h, --help       Show this help text

Environment:
  AGENTVM_REAL_VM=1        Required to boot real VMs; without it, prints "没跑" and exits 2
  AGENTVM_BIN=<path>       Optional pre-built & entitled AgentVM binary
  AGENTVM_IMAGE_CACHE=<d>  Optional Debian 12 image cache directory (cloned read-only into temp dir)
  AGENTVM_BUILD_JOBS=N     Optional `-j N` passed to swift build
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

if [[ "${AGENTVM_REAL_VM:-}" != "1" ]]; then
    echo "没跑 [Row 20]: 未设置 AGENTVM_REAL_VM=1（M3 分叉基准未执行）"
    exit 2
fi

CALLER_PWD="$(pwd)"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

exec /usr/bin/python3 - "$CALLER_PWD" "$ROOT_DIR" "$RECORD_REPORTS" "$OUT_DIR" <<'PY'
# -*- coding: utf-8 -*-
from __future__ import annotations
import ctypes
import ctypes.util
import datetime
import hashlib
import json
import math
import os
import platform
import plistlib
import re
import shlex
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import uuid

caller_pwd, root_dir, record_flag_str, out_dir_arg = sys.argv[1:5]
record_reports = record_flag_str == "1"
real_home = os.path.expanduser("~").rstrip("/")

CMD_TIMEOUT_SEC = 300
STOPPED_FORK_COUNT = 16
LIVE_FORK_COUNT = 16
STOPPED_MEDIAN_THRESHOLD_MS = 500.0
EXPECTED_DISK_VIRTUAL_BYTES = 8 * 1024 * 1024 * 1024  # 8 GiB
EXPECTED_PAYLOAD_BYTES = 1024 * 1024 * 1024           # 1 GiB

CLI_SUBCOMMANDS = {
    "doctor", "init", "ps", "list", "image", "create", "run", "daemon", "events",
    "up", "boot", "start", "pause", "resume", "halt", "stop",
    "branch", "fork", "snapshot", "restore", "exec", "pcap", "policy", "plugin",
    "export-hcl", "export-html", "help", "version",
}

# ---------------------------------------------------------------------------
# Independent APFS private-bytes reader via Darwin getattrlist(2) + ctypes
# (No AgentVM product code imported or invoked.)
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
_libc.clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
_libc.clonefile.restype = ctypes.c_int


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
        raise RuntimeError(f"Unexpected getattrlist length {attr_len} for {path}")
    return {
        "logicalBytes": int(st.st_size),
        "allocatedBytes": int(st.st_blocks) * 512,
        "privateBytes": int(priv_bytes),
    }


def verify_apfs_privsize_probe(probe_dir: str) -> None:
    d = tempfile.mkdtemp(prefix="privprobe.", dir=probe_dir)
    try:
        src = os.path.join(d, "src.bin")
        c1 = os.path.join(d, "c1.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(256 * 1024))
            f.flush()
            os.fsync(f.fileno())
        s0 = read_apfs_space(src)
        if s0["privateBytes"] < 256 * 1024:
            raise RuntimeError(f"APFS probe failed on fresh file: {s0}")
        rc = _libc.clonefile(os.fsencode(src), os.fsencode(c1), 0)
        if rc != 0:
            err = ctypes.get_errno()
            raise RuntimeError(f"Benchmark requires APFS clonefile(2); errno={err} ({os.strerror(err)})")
        s1 = read_apfs_space(src)
        c1_s1 = read_apfs_space(c1)
        if s1["privateBytes"] != 0 or c1_s1["privateBytes"] != 0:
            raise RuntimeError(f"Expected 0 private bytes immediately after clonefile: src={s1}, c1={c1_s1}")
        with open(c1, "r+b") as f:
            f.seek(0)
            f.write(b"\x5A" * (64 * 1024))
            f.flush()
            os.fsync(f.fileno())
        c1_s2 = read_apfs_space(c1)
        if c1_s2["privateBytes"] == 0:
            raise RuntimeError(f"Expected non-zero private bytes after 64 KiB overwrite: {c1_s2}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Scrubbing, logging, statistics, and host process/hygiene helpers
# ---------------------------------------------------------------------------
raw_tmp_root = ""
tmp_root = ""
source_cache_dir = ""


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


def summarize_samples(values: list[float], ndigits: int = 2) -> dict:
    if not values:
        raise ValueError("Cannot summarize empty sample list")
    s = sorted(values)
    n = len(s)
    med = float(statistics.median(s))
    p95_idx = max(0, min(n - 1, math.ceil(0.95 * n) - 1))
    p95 = float(s[p95_idx])
    return {
        "count": n,
        "samples": [round(float(v), ndigits) for v in values],
        "min": round(float(s[0]), ndigits),
        "median": round(med, ndigits),
        "p95NearestRank": round(p95, ndigits),
        "max": round(float(s[-1]), ndigits),
    }


def summarize_int_samples(values: list[int]) -> dict:
    if not values:
        raise ValueError("Cannot summarize empty int sample list")
    s = sorted(int(v) for v in values)
    n = len(s)
    med_raw = statistics.median(s)
    med = int(round(med_raw))
    p95_idx = max(0, min(n - 1, math.ceil(0.95 * n) - 1))
    return {
        "count": n,
        "samples": [int(v) for v in values],
        "minBytes": int(s[0]),
        "medianBytes": med,
        "p95NearestRankBytes": int(s[p95_idx]),
        "maxBytes": int(s[-1]),
    }


def summarize_samples_safe(values: list[float], ndigits: int = 2):
    return summarize_samples(values, ndigits=ndigits) if values else None


def summarize_int_samples_safe(values: list[int]):
    return summarize_int_samples(values) if values else None


def read_host_loadavg() -> dict:
    try:
        sysctl_p = subprocess.run(["/usr/sbin/sysctl", "-n", "vm.loadavg"], capture_output=True, text=True)
        raw_vm = sysctl_p.stdout.strip() if sysctl_p.returncode == 0 else ""
    except OSError:
        raw_vm = ""
    nums = [float(tok) for tok in re.findall(r"[0-9]+(?:\.[0-9]+)?", raw_vm)]
    try:
        up_p = subprocess.run(["/usr/bin/uptime"], capture_output=True, text=True)
        raw_uptime = up_p.stdout.strip() if up_p.returncode == 0 else ""
    except OSError:
        raw_uptime = ""
    return {
        "load1m": nums[0] if len(nums) >= 1 else None,
        "load5m": nums[1] if len(nums) >= 2 else None,
        "load15m": nums[2] if len(nums) >= 3 else None,
        "sysctlVmLoadavg": raw_vm,
        "uptime": raw_uptime,
    }


def format_load_triplet(ld) -> str:
    if not ld or ld.get("load1m") is None:
        return "unknown"
    return f"{ld['load1m']:.2f} {ld['load5m']:.2f} {ld['load15m']:.2f}"


def prepare_isolated_home(home_dir: str) -> None:
    os.makedirs(os.path.join(home_dir, "Library", "Preferences"), exist_ok=True)


def record_failure(failures: list[dict], check: str, reason: str) -> None:
    clean_reason = scrub(reason)
    failures.append({"check": check, "reason": clean_reason})
    emit_err(f"CHECK FAILED [{check}]: {clean_reason}")


IPV4_UNIQUENESS_RULE = (
    "hostname, /etc/machine-id, instance-id, NIC MAC, and SSH ED25519 host key fingerprint must be "
    "pairwise distinct across all 33 VMs (parent p + 32 children); DHCP IPv4 is required to be distinct "
    "only among simultaneously running VMs (e.g., parent p and a concurrently booted child; also enforced "
    "by m3-fork.sh Rows 9, 13, and 19), while sequentially booted VMs after earlier VMs halt may legitimately "
    "reuse released DHCP leases and are recorded in sequentialIPv4LeaseReuses."
)


def verify_identities_across_fleet(
    p_ident,
    verified_children: list[dict],
    concurrent_ipv4_collisions: list[dict],
    max_concurrent_seen: int,
    post_boot_priv_stats,
    failures: list[dict],
) -> dict:
    all_identities = []
    if p_ident is not None:
        p_ipv4_bare = p_ident["ipv4"].split("/")[0] if p_ident.get("ipv4") else ""
        all_identities.append({
            "name": "p",
            "hostname": p_ident["hostname"],
            "machineID": p_ident["machine_id"],
            "instanceID": p_ident["instance_id"],
            "mac": p_ident["mac"],
            "ipv4Address": p_ipv4_bare,
            "sshEd25519Fingerprint": p_ident["ssh_ed25519"],
        })
    for c in verified_children:
        all_identities.append({
            "name": c["name"],
            "hostname": c["hostname"],
            "machineID": c["machineID"],
            "instanceID": c["instanceID"],
            "mac": c["mac"],
            "ipv4Address": c["ipv4Address"],
            "sshEd25519Fingerprint": c["sshEd25519Fingerprint"],
        })

    expected_children = STOPPED_FORK_COUNT + LIVE_FORK_COUNT
    if p_ident is None or len(verified_children) != expected_children:
        record_failure(
            failures,
            "childIdentity.bootCoverage",
            f"Expected parent 'p' + {expected_children} booted children, got parent={p_ident is not None}, children={len(verified_children)}",
        )

    distinct_flags = {}
    for field in ("hostname", "machineID", "instanceID", "mac", "sshEd25519Fingerprint"):
        seen = {}
        dups = []
        for it in all_identities:
            v = it[field]
            if v in seen:
                dups.append({"firstVM": seen[v], "secondVM": it["name"], "value": v})
            else:
                seen[v] = it["name"]
        distinct_flags[field] = (len(dups) == 0 and len(all_identities) == expected_children + 1)
        if dups:
            record_failure(
                failures,
                f"childIdentity.pairwiseUnique.{field}",
                f"Identity collision across {len(all_identities)} VMs on {field}: {dups}",
            )

    seen_ip = {}
    sequential_ipv4_reuses = []
    for it in all_identities:
        ip_val = it["ipv4Address"]
        if not ip_val:
            continue
        if ip_val in seen_ip:
            sequential_ipv4_reuses.append({
                "earlierVM": seen_ip[ip_val],
                "laterVM": it["name"],
                "ipv4Address": ip_val,
            })
        else:
            seen_ip[ip_val] = it["name"]

    unique_ipv4_count = len(seen_ip)

    return {
        "totalChildrenBooted": len(verified_children),
        "totalVMsComparedIncludingParent": len(all_identities),
        "maxConcurrentVMsObserved": max_concurrent_seen,
        "ipv4UniquenessRule": IPV4_UNIQUENESS_RULE,
        "allHostnamesPairwiseDistinct": distinct_flags["hostname"],
        "allMachineIDsPairwiseDistinct": distinct_flags["machineID"],
        "allInstanceIDsPairwiseDistinct": distinct_flags["instanceID"],
        "allMACsPairwiseDistinct": distinct_flags["mac"],
        "allSSHEd25519FingerprintsPairwiseDistinct": distinct_flags["sshEd25519Fingerprint"],
        "allConcurrentIPv4sPairwiseDistinct": len(concurrent_ipv4_collisions) == 0,
        "concurrentIPv4Collisions": concurrent_ipv4_collisions,
        "uniqueIPv4CountAcrossAllBootedVMs": unique_ipv4_count,
        "sequentialIPv4LeaseReuses": sequential_ipv4_reuses,
        "postFirstBootAndHaltRootDiskPrivateBytes": post_boot_priv_stats,
        "children": verified_children,
    }


def df_available_kb(path: str) -> int:
    proc = subprocess.run(["/bin/df", "-k", path], capture_output=True, text=True, check=True)
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    if len(lines) < 2:
        raise RuntimeError(f"Unexpected df -k output: {proc.stdout!r}")
    cols = lines[-1].split()
    # POSIX / macOS `df -k`: Filesystem 1024-blocks Used Available Capacity ...
    return int(cols[3])


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
    found: list[tuple[int, str, str]] = []
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


# Resolve image cache path before touching HOME
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

baseline_vz_pids = list_vz_vm_pids()
baseline_daemons = list_host_agentvm_daemons("")
cache_before = snapshot_cache_dir(source_cache_dir)

raw_tmp_root = tempfile.mkdtemp(prefix="agentvm-m3-bench.")
tmp_root = os.path.realpath(raw_tmp_root)
isolated_home = os.path.join(tmp_root, "home")
isolated_tmp = os.path.join(tmp_root, "tmp")
local_cache_dir = os.path.join(tmp_root, "image-cache")
bin_dir = os.path.join(tmp_root, "bin")
ws_path = os.path.join(tmp_root, "ws.agentvm")
prepare_isolated_home(isolated_home)
for d in (isolated_tmp, local_cache_dir, bin_dir):
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


max_concurrent_vms_seen = 0
failures: list[dict] = []


def check_vm_cap(limit: int = 2) -> int:
    global max_concurrent_vms_seen
    cnt = len(extra_vz_pids())
    if cnt > max_concurrent_vms_seen:
        max_concurrent_vms_seen = cnt
    if cnt > limit:
        record_failure(
            failures,
            "concurrentVMCap",
            f"Concurrent VM limit ({limit}) exceeded: {cnt} extra VirtualMachine PIDs active",
        )
    return cnt


def run_avm(args: list[str], timeout_sec: int = CMD_TIMEOUT_SEC, check: bool = True) -> dict:
    host_args = args[: args.index("--")] if "--" in args else args
    if not any(tok in CLI_SUBCOMMANDS for tok in host_args):
        raise RuntimeError(f"REFUSED: command {args!r} has no CLI subcommand and would launch desktop UI")
    env = dict(os.environ)
    for k in ("AGENTVM_WORKSPACE", "AGENTVM_REAL_VM", "AGENTVM_LANG"):
        env.pop(k, None)
    env["HOME"] = isolated_home
    env["CFFIXED_USER_HOME"] = isolated_home
    env["TMPDIR"] = isolated_tmp
    env["AGENTVM_IMAGE_CACHE"] = local_cache_dir

    t0 = time.perf_counter()
    proc = subprocess.run(
        ["/usr/bin/perl", "-e", f"alarm {int(timeout_sec)}; exec @ARGV", resolved_bin] + args,
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


cleanup_done = False


def cleanup() -> None:
    global cleanup_done
    if cleanup_done:
        return
    cleanup_done = True
    if resolved_bin and os.path.isfile(resolved_bin) and os.path.exists(ws_path):
        try:
            run_avm(["--lang", "en", "--workspace", ws_path, "daemon", "stop"], timeout_sec=65, check=False)
        except Exception:
            pass
    # Terminate any lingering daemon specifically serving ws_path
    ws_real = os.path.realpath(ws_path)
    for pid, comm_real, d_ws in list_host_agentvm_daemons(resolved_bin):
        if d_ws == ws_real and comm_real == resolved_bin:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    wait_for_extra_vz_count(0, timeout_sec=30.0)
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


def handle_sig(signum, _frame):
    cleanup()
    sys.exit(128 + signum)


signal.signal(signal.SIGINT, handle_sig)
signal.signal(signal.SIGTERM, handle_sig)

bench_start = time.perf_counter()
load_at_start = read_host_loadavg()
current_stage = "startup"

payload_sha256 = ""
p_disk_space_before = None
p_ident = None
p_boot_id_before = ""
p_boot_id_after = ""
stopped_df_before_kb = None
stopped_df_after_kb = None
stopped_records: list[dict] = []
live_df_before_kb = None
live_df_after_kb = None
live_records: list[dict] = []
verified_children: list[dict] = []
post_boot_priv_samples: list[int] = []
active_running_ipv4: dict[str, str] = {}
concurrent_ipv4_collisions: list[dict] = []

try:
    emit("==================================================================")
    emit(" AgentVM Milestone M3 APFS CoW Branch Benchmark (Row 20)")
    emit("==================================================================")
    emit(f"Baseline VirtualMachine PIDs (untouched): {sorted(baseline_vz_pids)}")
    emit(f"Baseline host AgentVM daemons (untouched): {len(baseline_daemons)}")
    emit(f"Host load average at start (1m/5m/15m): {format_load_triplet(load_at_start)}")

    if user_bin_env:
        if os.path.isabs(user_bin_env):
            cand = user_bin_env
        else:
            from_caller = os.path.join(caller_pwd, user_bin_env)
            cand = from_caller if os.path.exists(from_caller) else os.path.join(root_dir, user_bin_env)
        resolved_bin = os.path.realpath(cand)
        if not (os.path.isfile(resolved_bin) and os.access(resolved_bin, os.X_OK)):
            raise RuntimeError("AGENTVM_BIN does not exist or is not executable.")
        if not has_virtualization_entitlement(resolved_bin):
            raise RuntimeError("REFUSED: AGENTVM_BIN lacks com.apple.security.virtualization entitlement.")
        baseline_daemons = list_host_agentvm_daemons(resolved_bin)

    current_stage = "apfsProbe"
    verify_apfs_privsize_probe(tmp_root)

    # 1. Build & ad-hoc sign binary copy in $TMP_ROOT/bin if AGENTVM_BIN was not supplied
    current_stage = "buildAndSignBinary"
    if not resolved_bin:
        emit("Building debug AgentVM binary...")
        jobs_env = os.environ.get("AGENTVM_BUILD_JOBS", "").strip()
        build_cmd = ["swift", "build"]
        if jobs_env:
            build_cmd += ["-j", jobs_env]
        build_cmd += ["--product", "AgentVM"]
        bproc = subprocess.run(build_cmd, cwd=root_dir, capture_output=True, text=True)
        if bproc.returncode != 0:
            raise RuntimeError("swift build --product AgentVM failed:\n" + bproc.stderr[-2000:])
        built_debug = os.path.realpath(os.path.join(root_dir, ".build", "debug", "AgentVM"))
        signed_copy = os.path.join(bin_dir, "AgentVM")
        shutil.copy2(built_debug, signed_copy)
        os.chmod(signed_copy, 0o755)
        ent_plist = os.path.join(root_dir, "Scripts", "entitlements.plist")
        cs = subprocess.run(
            ["codesign", "--force", "--sign", "-", "--entitlements", ent_plist, signed_copy],
            capture_output=True,
            text=True,
        )
        if cs.returncode != 0 or not has_virtualization_entitlement(signed_copy):
            raise RuntimeError(f"codesign failed on temporary binary copy: {cs.stderr}")
        resolved_bin = os.path.realpath(signed_copy)
        baseline_daemons = list_host_agentvm_daemons(resolved_bin)

    # 2. Clone Debian 12 image cache into $TMP_ROOT/image-cache via APFS clonefile (`cp -c`)
    current_stage = "stageImageCache"
    src_raw = os.path.join(source_cache_dir, "debian-12-bookworm-arm64.raw")
    src_idx = os.path.join(source_cache_dir, "catalog-index.json")
    if not (os.path.isfile(src_raw) and os.path.isfile(src_idx)):
        emit("Cached Debian 12 image not found in AGENTVM_IMAGE_CACHE; pulling into temporary cache...")
        run_avm(["--lang", "en", "--workspace", ws_path, "image", "pull", "debian-12-bookworm-arm64"], timeout_sec=900)
    else:
        dst_raw = os.path.join(local_cache_dir, "debian-12-bookworm-arm64.raw")
        dst_idx = os.path.join(local_cache_dir, "catalog-index.json")
        if subprocess.run(["/bin/cp", "-c", src_raw, dst_raw], capture_output=True).returncode != 0:
            shutil.copy2(src_raw, dst_raw)
        if subprocess.run(["/bin/cp", "-c", src_idx, dst_idx], capture_output=True).returncode != 0:
            shutil.copy2(src_idx, dst_idx)
        os.chmod(dst_raw, 0o444)

    # 3. Prepare parent VM `p` (8 GiB disk, 2 vCPU, 2048 MiB RAM; write 1 GiB random data + marker, sync, halt)
    current_stage = "prepareParentVM"
    emit("\n[1/5] Preparing parent VM 'p' (8 GiB disk, 1 GiB random data + marker, sync, halt)...")
    run_avm(["--lang", "en", "--workspace", ws_path, "init"])
    run_avm([
        "--lang", "en", "--workspace", ws_path,
        "create", "p",
        "--image", "debian-12-bookworm-arm64",
        "--disk-size", "8G",
        "--cpus", "2",
        "--memory-mb", "2048",
    ])
    up_p_prep = run_avm(["--lang", "en", "--workspace", ws_path, "up", "p"])
    check_vm_cap(2)
    emit(f"  up p: {up_p_prep['wallMs']:.1f} ms")

    bench_marker = f"m3-bench-marker-{uuid.uuid4().hex}"
    prep_cmd = (
        f"printf '%s\\n' '{bench_marker}' > /root/bench-marker && "
        "dd if=/dev/urandom of=/var/tmp/bench-data.bin bs=1M count=1024 status=none && "
        "sync && "
        "stat -c '%s' /var/tmp/bench-data.bin && "
        "sha256sum /var/tmp/bench-data.bin"
    )
    prep_exec = run_avm(["--lang", "en", "--workspace", ws_path, "exec", "p", "--", "sh", "-c", prep_cmd])
    prep_lines = [ln.strip() for ln in prep_exec["stdout"].splitlines() if ln.strip()]
    payload_size = int(prep_lines[0])
    payload_sha256 = prep_lines[1].split()[0]
    if payload_size != EXPECTED_PAYLOAD_BYTES:
        record_failure(
            failures,
            "parentVM.payloadBytes",
            f"Expected 1 GiB payload ({EXPECTED_PAYLOAD_BYTES} B), got {payload_size}",
        )
    emit(f"  wrote 1 GiB payload ({payload_size} B, sha256={payload_sha256[:16]}...) in {prep_exec['wallMs']:.1f} ms")

    # Also read parent `p` identity while booted (or during live fork step); halt `p` first for stopped forks
    halt_p_prep = run_avm(["--lang", "en", "--workspace", ws_path, "halt", "p"])
    if not wait_for_extra_vz_count(0, timeout_sec=30.0):
        record_failure(failures, "parentVM.haltAfterPrep", "Parent VM 'p' process did not exit within 30s after halt")
    emit(f"  halt p: {halt_p_prep['wallMs']:.1f} ms")

    ps_initial = json.loads(run_avm(["--lang", "en", "--workspace", ws_path, "ps", "--json"])["stdout"])
    p_rec_initial = next(v for v in ps_initial if v["spec"]["name"] == "p")
    p_root_disk_path = p_rec_initial["spec"]["blockDevices"][0]["imagePath"]
    p_disk_space_before = read_apfs_space(p_root_disk_path)
    if p_disk_space_before["logicalBytes"] != EXPECTED_DISK_VIRTUAL_BYTES:
        record_failure(
            failures,
            "parentVM.virtualDiskBytes",
            f"Expected 8 GiB virtual disk ({EXPECTED_DISK_VIRTUAL_BYTES} B), got {p_disk_space_before['logicalBytes']}",
        )
    emit(
        f"  parent root disk before forks: virtual={p_disk_space_before['logicalBytes']} B, "
        f"allocated={p_disk_space_before['allocatedBytes']} B, private={p_disk_space_before['privateBytes']} B"
    )

    branch_re = re.compile(r"in\s+([0-9]+(?:\.[0-9]+)?)\s+ms\s+from\s+snapshot\s+(snap-[a-zA-Z0-9-]+)")

    def inspect_fork_new_files(child_name: str, fork_snap_id: str, mode_prefix: str) -> dict:
        vms = json.loads(run_avm(["--lang", "en", "--workspace", ws_path, "ps", "--json"])["stdout"])
        snaps = json.loads(run_avm(["--lang", "en", "--workspace", ws_path, "snapshot", "list", "--json"])["stdout"])
        child = next(v for v in vms if v["spec"]["name"] == child_name)
        if child["telemetry"]["state"] != "stopped":
            record_failure(
                failures,
                f"{mode_prefix}.childStoppedState.{child_name}",
                f"Expected newly forked child '{child_name}' to be stopped, got {child['telemetry']['state']}",
            )
        child_disk = child["spec"]["blockDevices"][0]["imagePath"]
        child_head_id = child["currentHeadSnapshotID"]
        child_head_snap = next(s for s in snaps if s["id"] == child_head_id)
        fork_snap = next(s for s in snaps if s["id"] == fork_snap_id)
        nvram_path = child["spec"]["bootLoader"].get("efiBoot", {}).get("variableStorePath", "")

        cloned_paths = {
            "parentForkSnapshotRaw": fork_snap["diskClonePath"],
            "childRootDiskRaw": child_disk,
            "childHeadSnapshotRaw": child_head_snap["diskClonePath"],
        }
        if nvram_path and os.path.isfile(nvram_path):
            cloned_paths["childNvram"] = nvram_path

        cloned_metrics = {k: read_apfs_space(p) for k, p in cloned_paths.items()}
        total_private = sum(m["privateBytes"] for m in cloned_metrics.values())
        iso_path = child["spec"].get("cloudInitISOPath") or ""
        mid_path = child["spec"].get("machineIdentifierPath") or ""
        iso_bytes = int(os.path.getsize(iso_path)) if iso_path and os.path.isfile(iso_path) else 0
        mid_bytes = int(os.path.getsize(mid_path)) if mid_path and os.path.isfile(mid_path) else 0

        return {
            "childVMID": child["spec"]["id"],
            "childExpectedMAC": child["spec"]["networkInterfaces"][0]["macAddress"].lower(),
            "childRootDiskPath": child_disk,
            "forkSnapshotID": fork_snap_id,
            "childHeadSnapshotID": child_head_id,
            "clonedFilesPrivateBytes": {k: m["privateBytes"] for k, m in cloned_metrics.items()},
            "totalClonedFilesPrivateBytes": int(total_private),
            "synthesizedNonCloneBytes": {
                "cidataISOBytes": iso_bytes,
                "machineIDBytes": mid_bytes,
            },
        }

    # 4. 16 stopped forks (`sc1` .. `sc16`)
    current_stage = "stoppedForks"
    emit(f"\n[2/5] Running {STOPPED_FORK_COUNT} stopped forks (sc1..sc{STOPPED_FORK_COUNT})...")
    stopped_df_before_kb = df_available_kb(tmp_root)
    for i in range(1, STOPPED_FORK_COUNT + 1):
        cname = f"sc{i}"
        df_b = df_available_kb(tmp_root)
        res = run_avm(["--lang", "en", "--workspace", ws_path, "branch", "p", cname])
        df_a = df_available_kb(tmp_root)
        check_vm_cap(2)
        if len(extra_vz_pids()) != 0:
            record_failure(
                failures,
                f"stoppedFork.noVMProcess.{cname}",
                f"Stopped fork '{cname}' unexpectedly started a VM process",
            )
        m = branch_re.search(res["stdout"])
        if not m:
            raise RuntimeError(f"Could not parse branch timing/snapshot from stdout: {res['stdout']!r}")
        rep_ms = float(m.group(1))
        fsnap_id = m.group(2)
        finfo = inspect_fork_new_files(cname, fsnap_id, "stoppedFork")
        if finfo["totalClonedFilesPrivateBytes"] != 0:
            record_failure(
                failures,
                f"stoppedFork.newClonedFilesPrivateBytes.{cname}",
                f"Stopped fork '{cname}' created cloned files with non-zero private bytes: {finfo['clonedFilesPrivateBytes']}",
            )
        stopped_records.append({
            "index": i,
            "childName": cname,
            "wallClockMs": round(res["wallMs"], 2),
            "selfReportedMs": round(rep_ms, 2),
            "dfBeforeKB": df_b,
            "dfAfterKB": df_a,
            "dfDeltaKB": df_b - df_a,
            **finfo,
        })
    stopped_df_after_kb = df_available_kb(tmp_root)
    stopped_wall_tmp = summarize_samples([r["wallClockMs"] for r in stopped_records])
    stopped_rep_tmp = summarize_samples([r["selfReportedMs"] for r in stopped_records])
    emit(
        f"  stopped forks (n={STOPPED_FORK_COUNT}): wall median={stopped_wall_tmp['median']:.2f} ms, "
        f"p95={stopped_wall_tmp['p95NearestRank']:.2f} ms, max={stopped_wall_tmp['max']:.2f} ms; "
        f"self-reported median={stopped_rep_tmp['median']:.2f} ms; "
        f"all cloned private bytes zero={all(r['totalClonedFilesPrivateBytes'] == 0 for r in stopped_records)}"
    )
    if stopped_wall_tmp["median"] > STOPPED_MEDIAN_THRESHOLD_MS:
        record_failure(
            failures,
            "stoppedFork.provisionalThresholdMedianMs",
            f"Stopped fork wall-clock median {stopped_wall_tmp['median']:.2f} ms exceeded provisional threshold {STOPPED_MEDIAN_THRESHOLD_MS:.1f} ms",
        )

    # 5. Boot `p`, read `p` identity + boot_id, and run 16 live forks (`lc1` .. `lc16`)
    current_stage = "liveForks"
    emit(f"\n[3/5] Booting 'p' and running {LIVE_FORK_COUNT} live forks (lc1..lc{LIVE_FORK_COUNT})...")
    run_avm(["--lang", "en", "--workspace", ws_path, "up", "p"])
    if check_vm_cap(2) != 1:
        record_failure(failures, "liveFork.parentRunningCount", "Expected exactly 1 running VM ('p') before live forks")

    ident_probe = (
        "python3 -c '"
        "import glob, json, os, subprocess; "
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
        "marker = open(\"/root/bench-marker\").read().strip(); "
        "bsize = os.path.getsize(\"/var/tmp/bench-data.bin\"); "
        "ws_stat = subprocess.check_output([\"stat\", \"-c\", \"%F:%a\", \"/workspace\"], text=True).strip(); "
        "print(json.dumps({\"hostname\": h, \"fqdn\": fqdn, \"machine_id\": mid, \"dbus_machine_id\": dmid, "
        "\"instance_id\": iid, \"boot_id\": bid, \"mac\": macs[0] if macs else \"\", \"ipv4\": ipv4, "
        "\"ssh_ed25519\": ssh_fp, \"marker\": marker, \"payloadBytes\": bsize, \"workspace\": ws_stat}))"
        "'"
    )

    p_ident = json.loads(run_avm(["--lang", "en", "--workspace", ws_path, "exec", "p", "--", "sh", "-c", ident_probe])["stdout"].strip())
    p_boot_id_before = p_ident["boot_id"]
    p_ipv4_while_running = p_ident["ipv4"].split("/")[0] if p_ident.get("ipv4") else ""
    if p_ipv4_while_running:
        active_running_ipv4["p"] = p_ipv4_while_running

    live_df_before_kb = df_available_kb(tmp_root)
    for i in range(1, LIVE_FORK_COUNT + 1):
        cname = f"lc{i}"
        df_b = df_available_kb(tmp_root)
        res = run_avm(["--lang", "en", "--workspace", ws_path, "branch", "p", cname])
        df_a = df_available_kb(tmp_root)
        if check_vm_cap(2) != 1:
            record_failure(
                failures,
                f"liveFork.activeVMCount.{cname}",
                f"Live fork '{cname}' changed active VM count from 1",
            )
        m = branch_re.search(res["stdout"])
        if not m:
            raise RuntimeError(f"Could not parse live branch timing/snapshot from stdout: {res['stdout']!r}")
        rep_ms = float(m.group(1))
        fsnap_id = m.group(2)
        finfo = inspect_fork_new_files(cname, fsnap_id, "liveFork")
        if finfo["totalClonedFilesPrivateBytes"] != 0:
            record_failure(
                failures,
                f"liveFork.newClonedFilesPrivateBytes.{cname}",
                f"Live fork '{cname}' created cloned files with non-zero private bytes: {finfo['clonedFilesPrivateBytes']}",
            )
        live_records.append({
            "index": i,
            "childName": cname,
            "wallClockMs": round(res["wallMs"], 2),
            "selfReportedMs": round(rep_ms, 2),
            "dfBeforeKB": df_b,
            "dfAfterKB": df_a,
            "dfDeltaKB": df_b - df_a,
            "vmPauseMs": None,
            "guestPrePauseSyncMs": None,
            **finfo,
        })
    live_df_after_kb = df_available_kb(tmp_root)

    p_boot_id_after = run_avm(
        ["--lang", "en", "--workspace", ws_path, "exec", "p", "--", "cat", "/proc/sys/kernel/random/boot_id"]
    )["stdout"].strip()
    if p_boot_id_after != p_boot_id_before:
        record_failure(
            failures,
            "liveFork.parentBootIDUnchanged",
            f"Parent 'p' boot_id changed across live forks: {p_boot_id_before} -> {p_boot_id_after}",
        )

    events_p = json.loads(run_avm(["--lang", "en", "--workspace", ws_path, "events", "--vm", "p", "--json"])["stdout"])
    pause_by_snap = {
        ev.get("metadata", {}).get("snapshotID", ""): ev.get("metadata", {})
        for ev in events_p
        if ev.get("code") == "VM_PAUSED_FOR_SNAPSHOT" and ev.get("metadata", {}).get("operation") == "branch"
    }
    for rec in live_records:
        meta = pause_by_snap.get(rec["forkSnapshotID"])
        if not meta:
            record_failure(
                failures,
                f"liveFork.vmPausedForSnapshotEvent.{rec['childName']}",
                f"Missing VM_PAUSED_FOR_SNAPSHOT event for live fork {rec['childName']} ({rec['forkSnapshotID']})",
            )
        else:
            rec["vmPauseMs"] = round(float(meta["pauseMs"]), 3)
            rec["guestPrePauseSyncMs"] = round(float(meta["syncMs"]), 3)

    live_wall_tmp = summarize_samples([r["wallClockMs"] for r in live_records])
    live_pause_vals = [r["vmPauseMs"] for r in live_records if r["vmPauseMs"] is not None]
    live_pause_tmp = summarize_samples_safe(live_pause_vals, ndigits=3)
    pause_med_str = f"{live_pause_tmp['median']:.3f} ms" if live_pause_tmp else "n/a"
    pause_p95_str = f"{live_pause_tmp['p95NearestRank']:.3f} ms" if live_pause_tmp else "n/a"
    emit(
        f"  live forks (n={LIVE_FORK_COUNT}): wall median={live_wall_tmp['median']:.2f} ms, "
        f"p95={live_wall_tmp['p95NearestRank']:.2f} ms; VM pause median={pause_med_str} "
        f"(p95={pause_p95_str}); all cloned private bytes zero={all(r['totalClonedFilesPrivateBytes'] == 0 for r in live_records)}"
    )

    run_avm(["--lang", "en", "--workspace", ws_path, "halt", "p"])
    active_running_ipv4.pop("p", None)
    if not wait_for_extra_vz_count(0, timeout_sec=30.0):
        record_failure(failures, "liveFork.parentHalt", "Parent 'p' did not stop within 30s after live forks")

    # 6. Sequentially boot all 32 children (`sc1..sc16`, `lc1..lc16`), verify identity + marker + payload, halt
    current_stage = "verifyChildren"
    all_fork_records = [("stopped", r) for r in stopped_records] + [("live", r) for r in live_records]
    emit(f"\n[4/5] Sequentially booting, verifying guest identity & marker, and halting all {len(all_fork_records)} children...")

    sha_spot_names = {"sc1", f"sc{STOPPED_FORK_COUNT}", "lc1", f"lc{LIVE_FORK_COUNT}"}

    for idx_all, (mode_label, frec) in enumerate(all_fork_records, start=1):
        cname = frec["childName"]
        current_stage = f"verifyChildren.{cname}"
        up_res = run_avm(["--lang", "en", "--workspace", ws_path, "up", cname])
        if check_vm_cap(2) != 1:
            record_failure(
                failures,
                f"childIdentity.{cname}.activeVMCount",
                f"Expected 1 active VM while verifying '{cname}'",
            )
        id_res = run_avm(["--lang", "en", "--workspace", ws_path, "exec", cname, "--", "sh", "-c", ident_probe])
        cid = json.loads(id_res["stdout"].strip())
        ipv4_bare = cid["ipv4"].split("/")[0] if cid.get("ipv4") else ""

        if ipv4_bare:
            for other_vm, other_ip in list(active_running_ipv4.items()):
                if other_vm != cname and other_ip == ipv4_bare:
                    col = {"activeVM": other_vm, "concurrentVM": cname, "ipv4Address": ipv4_bare}
                    concurrent_ipv4_collisions.append(col)
                    record_failure(
                        failures,
                        f"childIdentity.{cname}.concurrentIPv4Unique",
                        f"Simultaneously running VMs '{other_vm}' and '{cname}' shared IPv4 {ipv4_bare}",
                    )
            active_running_ipv4[cname] = ipv4_bare

        if cid["hostname"] != cname:
            record_failure(
                failures,
                f"childIdentity.{cname}.hostname",
                f"Child '{cname}' hostname mismatch: {cid['hostname']!r}",
            )
        if cid["machine_id"] != cid["dbus_machine_id"] or len(cid["machine_id"]) != 32:
            record_failure(
                failures,
                f"childIdentity.{cname}.machineID",
                f"Child '{cname}' invalid machine-id: {cid['machine_id']!r} / dbus={cid['dbus_machine_id']!r}",
            )
        if cid["instance_id"] != frec["childVMID"]:
            record_failure(
                failures,
                f"childIdentity.{cname}.instanceID",
                f"Child '{cname}' instance-id {cid['instance_id']!r} != {frec['childVMID']!r}",
            )
        if cid["mac"] != frec["childExpectedMAC"]:
            record_failure(
                failures,
                f"childIdentity.{cname}.mac",
                f"Child '{cname}' MAC {cid['mac']!r} != spec {frec['childExpectedMAC']!r}",
            )
        if not cid["ipv4"]:
            record_failure(
                failures,
                f"childIdentity.{cname}.ipv4NonEmpty",
                f"Child '{cname}' received empty IPv4 address",
            )
        if cid["marker"] != bench_marker:
            record_failure(
                failures,
                f"childIdentity.{cname}.marker",
                f"Child '{cname}' marker mismatch: {cid['marker']!r}",
            )
        if int(cid["payloadBytes"]) != EXPECTED_PAYLOAD_BYTES:
            record_failure(
                failures,
                f"childIdentity.{cname}.payloadBytes",
                f"Child '{cname}' payload size {cid['payloadBytes']} != {EXPECTED_PAYLOAD_BYTES}",
            )
        if cid["workspace"] != "directory:755":
            record_failure(
                failures,
                f"childIdentity.{cname}.workspaceMount",
                f"Child '{cname}' /workspace missing or wrong mode: {cid['workspace']!r}",
            )

        sha_verified = False
        if cname in sha_spot_names:
            sha_out = run_avm(
                ["--lang", "en", "--workspace", ws_path, "exec", cname, "--", "sha256sum", "/var/tmp/bench-data.bin"]
            )["stdout"].strip().split()[0]
            if sha_out != payload_sha256:
                record_failure(
                    failures,
                    f"childIdentity.{cname}.payloadSHA256",
                    f"Child '{cname}' 1 GiB SHA-256 mismatch: {sha_out} != {payload_sha256}",
                )
            else:
                sha_verified = True

        halt_res = run_avm(["--lang", "en", "--workspace", ws_path, "halt", cname])
        active_running_ipv4.pop(cname, None)
        if not wait_for_extra_vz_count(0, timeout_sec=30.0):
            record_failure(
                failures,
                f"childIdentity.{cname}.halt",
                f"Child '{cname}' VM process did not exit within 30s",
            )

        post_space = read_apfs_space(frec["childRootDiskPath"])
        post_boot_priv_samples.append(post_space["privateBytes"])

        verified_children.append({
            "order": idx_all,
            "forkMode": mode_label,
            "name": cname,
            "vmID": frec["childVMID"],
            "bootWallMs": round(up_res["wallMs"], 1),
            "haltWallMs": round(halt_res["wallMs"], 1),
            "hostname": cid["hostname"],
            "machineID": cid["machine_id"],
            "instanceID": cid["instance_id"],
            "mac": cid["mac"],
            "ipv4CIDR": cid["ipv4"],
            "ipv4Address": ipv4_bare,
            "sshEd25519Fingerprint": cid["ssh_ed25519"],
            "payloadSHA256Checked": sha_verified,
            "postFirstBootAndHaltPrivateBytes": post_space["privateBytes"],
        })
        emit(
            f"  [{idx_all:02d}/32] {cname} ({mode_label}): up={up_res['wallMs']:.0f}ms, "
            f"ip={cid['ipv4']}, mac={cid['mac']}, halt={halt_res['wallMs']:.0f}ms, "
            f"postBootPrivate={post_space['privateBytes']} B"
        )

    # Stop workspace daemon before final checks
    current_stage = "daemonStop"
    run_avm(["--lang", "en", "--workspace", ws_path, "daemon", "stop"])

except Exception as exc:
    record_failure(failures, current_stage, str(exc))
finally:
    cleanup()

load_at_end = read_host_loadavg()
emit(f"Host load average at end (1m/5m/15m): {format_load_triplet(load_at_end)}")

# Post-cleanup host verification (recorded into failures before writing JSON)
leftover_links = sweep_darwin_temp_symlinks([tmp_root, raw_tmp_root], remove=False)
extra_vz_after = extra_vz_pids()
daemons_after = set(list_host_agentvm_daemons(resolved_bin)) - set(baseline_daemons)
cache_after = snapshot_cache_dir(source_cache_dir)

if leftover_links or extra_vz_after or daemons_after or cache_after != cache_before:
    record_failure(
        failures,
        "postRunCleanupHygiene",
        f"links={leftover_links}, extra_vz={sorted(extra_vz_after)}, "
        f"new_daemons={sorted(daemons_after)}, cache_unchanged={cache_after == cache_before}",
    )

stopped_wall_stats = summarize_samples_safe([r["wallClockMs"] for r in stopped_records])
stopped_rep_stats = summarize_samples_safe([r["selfReportedMs"] for r in stopped_records])
live_wall_stats = summarize_samples_safe([r["wallClockMs"] for r in live_records])
live_rep_stats = summarize_samples_safe([r["selfReportedMs"] for r in live_records])
live_pause_stats = summarize_samples_safe(
    [r["vmPauseMs"] for r in live_records if r.get("vmPauseMs") is not None], ndigits=3
)
live_sync_stats = summarize_samples_safe(
    [r["guestPrePauseSyncMs"] for r in live_records if r.get("guestPrePauseSyncMs") is not None], ndigits=3
)
post_boot_priv_stats = summarize_int_samples_safe(post_boot_priv_samples)

identity_verification = verify_identities_across_fleet(
    p_ident=p_ident,
    verified_children=verified_children,
    concurrent_ipv4_collisions=concurrent_ipv4_collisions,
    max_concurrent_seen=max_concurrent_vms_seen,
    post_boot_priv_stats=post_boot_priv_stats,
    failures=failures,
)


def sysctl_str(key: str) -> str:
    p = subprocess.run(["/usr/sbin/sysctl", "-n", key], capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else "unknown"


hw_model = sysctl_str("hw.model")
cpu_brand = sysctl_str("machdep.cpu.brand_string")
phys_cores = int(sysctl_str("hw.physicalcpu") or "0")
log_cores = int(sysctl_str("hw.logicalcpu") or "0")
mem_bytes = int(sysctl_str("hw.memsize") or "0")
macos_ver = subprocess.check_output(["/usr/bin/sw_vers", "-productVersion"], text=True).strip()
macos_build = subprocess.check_output(["/usr/bin/sw_vers", "-buildVersion"], text=True).strip()
git_rev_proc = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=root_dir, capture_output=True, text=True)
git_commit = git_rev_proc.stdout.strip() if git_rev_proc.returncode == 0 else "unknown"
today_local = datetime.date.today().isoformat()
utc_now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

passed_threshold = (
    stopped_wall_stats is not None
    and len(stopped_records) == STOPPED_FORK_COUNT
    and stopped_wall_stats["median"] <= STOPPED_MEDIAN_THRESHOLD_MS
)
total_elapsed_sec = round(time.perf_counter() - bench_start, 2)


def clean_fork_sample(rec: dict, include_pause: bool) -> dict:
    d = {
        "index": rec["index"],
        "childName": rec["childName"],
        "childVMID": rec["childVMID"],
        "forkSnapshotID": rec["forkSnapshotID"],
        "childHeadSnapshotID": rec["childHeadSnapshotID"],
        "wallClockMs": rec["wallClockMs"],
        "selfReportedMs": rec["selfReportedMs"],
        "clonedFilesPrivateBytes": rec["clonedFilesPrivateBytes"],
        "totalClonedFilesPrivateBytes": rec["totalClonedFilesPrivateBytes"],
        "synthesizedNonCloneBytes": rec["synthesizedNonCloneBytes"],
        "dfBeforeKB": rec["dfBeforeKB"],
        "dfAfterKB": rec["dfAfterKB"],
        "dfDeltaKB": rec["dfDeltaKB"],
    }
    if include_pause:
        d["vmPauseMs"] = rec.get("vmPauseMs")
        d["guestPrePauseSyncMs"] = rec.get("guestPrePauseSyncMs")
    return d


all_clones_zero = (
    bool(stopped_records)
    and bool(live_records)
    and all(r["totalClonedFilesPrivateBytes"] == 0 for r in stopped_records)
    and all(r["totalClonedFilesPrivateBytes"] == 0 for r in live_records)
)
max_private_bytes_observed = max(
    [r["totalClonedFilesPrivateBytes"] for r in (stopped_records + live_records)],
    default=None,
)

bench_doc = {
    "schemaVersion": 1,
    "passed": len(failures) == 0,
    "failures": failures,
    "date": today_local,
    "measuredAtUTC": utc_now_iso,
    "script": "Scripts/acceptance/m3-branch-bench.sh",
    "gitCommit": git_commit,
    "totalElapsedSeconds": total_elapsed_sec,
    "host": {
        "hwModel": hw_model,
        "cpuBrand": cpu_brand,
        "physicalCores": phys_cores,
        "logicalCores": log_cores,
        "memoryBytes": mem_bytes,
        "memoryGiB": round(mem_bytes / (1024 ** 3)),
        "macOSProductVersion": macos_ver,
        "macOSBuildVersion": macos_build,
        "arch": platform.machine(),
        "filesystem": "APFS",
        "loadAverage": {
            "atStart": load_at_start,
            "atEnd": load_at_end,
        },
    },
    "parentVM": {
        "name": "p",
        "imageID": "debian-12-bookworm-arm64",
        "cpus": 2,
        "memoryMB": 2048,
        "virtualDiskBytes": EXPECTED_DISK_VIRTUAL_BYTES,
        "virtualDiskGiB": 8,
        "guestPayloadBytes": EXPECTED_PAYLOAD_BYTES,
        "guestPayloadGiB": 1,
        "guestPayloadDescription": "Debian 12 (bookworm) arm64 genericcloud rootfs expanded to 8 GiB + 1 GiB (/var/tmp/bench-data.bin) random bytes + marker file, synced",
        "guestPayloadSHA256": payload_sha256,
        "rootDiskAllocatedBytesBeforeFork": p_disk_space_before["allocatedBytes"] if p_disk_space_before else None,
        "rootDiskPrivateBytesBeforeFork": p_disk_space_before["privateBytes"] if p_disk_space_before else None,
        "ipv4CIDR": p_ident["ipv4"] if p_ident else None,
    },
    "headlineMetrics": {
        "X_stoppedForkWallClockMedianMs": stopped_wall_stats["median"] if stopped_wall_stats else None,
        "stoppedForkWallClockP95NearestRankMs": stopped_wall_stats["p95NearestRank"] if stopped_wall_stats else None,
        "liveForkWallClockMedianMs": live_wall_stats["median"] if live_wall_stats else None,
        "liveForkWallClockP95NearestRankMs": live_wall_stats["p95NearestRank"] if live_wall_stats else None,
        "liveForkVMPauseMedianMs": live_pause_stats["median"] if live_pause_stats else None,
        "liveForkVMPauseP95NearestRankMs": live_pause_stats["p95NearestRank"] if live_pause_stats else None,
        "Y_newClonedFilesAPFSPrivateBytes": 0 if all_clones_zero else max_private_bytes_observed,
        "postFirstBootAndHaltChildPrivateBytesMedian": post_boot_priv_stats["medianBytes"] if post_boot_priv_stats else None,
    },
    "stoppedFork": {
        "count": len(stopped_records),
        "expectedCount": STOPPED_FORK_COUNT,
        "wallClockMs": stopped_wall_stats,
        "selfReportedMs": stopped_rep_stats,
        "newClonedFilesPrivateBytes": {
            "measurementMethod": "Darwin getattrlist(2) ATTR_CMNEXT_PRIVATESIZE with FSOPT_ATTR_CMN_EXTENDED via /usr/bin/python3 ctypes (independent of product code); excludes APFS B-tree/inode metadata and newly synthesized cidata ISO / .machineid files",
            "perForkTotalPrivateBytesSamples": [r["totalClonedFilesPrivateBytes"] for r in stopped_records],
            "allZero": bool(stopped_records) and all(r["totalClonedFilesPrivateBytes"] == 0 for r in stopped_records),
            "totalPrivateBytesAcross16Forks": sum(r["totalClonedFilesPrivateBytes"] for r in stopped_records),
        },
        "dfAvailableKB": {
            "beforeKB": stopped_df_before_kb,
            "afterKB": stopped_df_after_kb,
            "deltaKB": (stopped_df_before_kb - stopped_df_after_kb) if (stopped_df_before_kb is not None and stopped_df_after_kb is not None) else None,
            "note": "Host-wide APFS volume df -k delta across 16 stopped forks; upper bound only when concurrent processes run on the host",
        },
        "provisionalThresholdMedianMs": STOPPED_MEDIAN_THRESHOLD_MS,
        "passedProvisionalThreshold": passed_threshold,
        "forks": [clean_fork_sample(r, include_pause=False) for r in stopped_records],
    },
    "liveFork": {
        "count": len(live_records),
        "expectedCount": LIVE_FORK_COUNT,
        "parentBootIDBefore": p_boot_id_before or None,
        "parentBootIDAfter": p_boot_id_after or None,
        "parentBootIDUnchanged": bool(p_boot_id_before and p_boot_id_after and p_boot_id_after == p_boot_id_before),
        "wallClockMs": live_wall_stats,
        "selfReportedMs": live_rep_stats,
        "vmPauseMs": live_pause_stats,
        "guestPrePauseSyncMs": live_sync_stats,
        "newClonedFilesPrivateBytes": {
            "perForkTotalPrivateBytesSamples": [r["totalClonedFilesPrivateBytes"] for r in live_records],
            "allZero": bool(live_records) and all(r["totalClonedFilesPrivateBytes"] == 0 for r in live_records),
            "totalPrivateBytesAcross16Forks": sum(r["totalClonedFilesPrivateBytes"] for r in live_records),
        },
        "dfAvailableKB": {
            "beforeKB": live_df_before_kb,
            "afterKB": live_df_after_kb,
            "deltaKB": (live_df_before_kb - live_df_after_kb) if (live_df_before_kb is not None and live_df_after_kb is not None) else None,
            "note": "Host-wide APFS volume df -k delta across 16 live forks; upper bound only when concurrent processes run on the host",
        },
        "forks": [clean_fork_sample(r, include_pause=True) for r in live_records],
    },
    "childIdentityAndBootVerification": identity_verification,
}

json_text = scrub(json.dumps(bench_doc, indent=2, ensure_ascii=False) + "\n")


def fmt_stat(stats_obj, key: str, spec: str = ".2f", suffix: str = " ms") -> str:
    if not stats_obj or stats_obj.get(key) is None:
        return "n/a"
    return f"{stats_obj[key]:{spec}}{suffix}"


iso_b_sample = stopped_records[0]["synthesizedNonCloneBytes"]["cidataISOBytes"] if stopped_records else "n/a"
mid_b_sample = stopped_records[0]["synthesizedNonCloneBytes"]["machineIDBytes"] if stopped_records else "n/a"
stopped_df_delta_str = (
    f"{stopped_df_before_kb - stopped_df_after_kb} KB"
    if (stopped_df_before_kb is not None and stopped_df_after_kb is not None)
    else "n/a"
)
live_df_delta_str = (
    f"{live_df_before_kb - live_df_after_kb} KB"
    if (live_df_before_kb is not None and live_df_after_kb is not None)
    else "n/a"
)
post_priv_str = (
    f"{post_boot_priv_stats['medianBytes']} B ({post_boot_priv_stats['medianBytes'] / (1024 * 1024):.2f} MiB)"
    if post_boot_priv_stats
    else "n/a"
)
post_priv_notes = (
    f"Median across {post_boot_priv_stats['count']} booted children (min `{post_boot_priv_stats['minBytes']} B`, p95 `{post_boot_priv_stats['p95NearestRankBytes']} B`)"
    if post_boot_priv_stats
    else "Not collected"
)
five_item_ok = all(
    identity_verification.get(k, False)
    for k in (
        "allHostnamesPairwiseDistinct",
        "allMachineIDsPairwiseDistinct",
        "allInstanceIDsPairwiseDistinct",
        "allMACsPairwiseDistinct",
        "allSSHEd25519FingerprintsPairwiseDistinct",
    )
)
ident_summary_val = (
    f"`{identity_verification['totalVMsComparedIncludingParent']} / 33 unique (5 items)`"
    if five_item_ok
    else "`FAILED`"
)
reuse_cnt = len(identity_verification["sequentialIPv4LeaseReuses"])
ident_notes = (
    f"`hostname`, `/etc/machine-id`, `instance-id`, NIC MAC, SSH ED25519 fingerprint pairwise distinct across 33 VMs; "
    f"concurrent IPv4 collisions `{len(identity_verification['concurrentIPv4Collisions'])}` "
    f"(unique sequential DHCP IPv4s `{identity_verification['uniqueIPv4CountAcrossAllBootedVMs']}/33`, sequential lease reuses `{reuse_cnt}`)"
)

md_lines = [
    "# AgentVM M3 APFS CoW Branch Benchmark (`m3-branch-bench`)",
    "",
    f"- **Status**: `{'PASS' if not failures else 'FAIL'}` (`{len(failures)}` failure(s))",
    f"- **Date**: `{today_local}` (`{utc_now_iso}`)",
    f"- **Script**: `Scripts/acceptance/m3-branch-bench.sh` (commit `{git_commit}`)",
    f"- **Host**: `{hw_model}` (`{cpu_brand}`, {phys_cores} cores, {round(mem_bytes / (1024 ** 3))} GiB RAM), macOS `{macos_ver}` (`{macos_build}`), APFS",
    f"- **Host load average (`1m 5m 15m`)**: start `{format_load_triplet(load_at_start)}` -> end `{format_load_triplet(load_at_end)}`",
    f"- **Parent VM (`p`)**: `debian-12-bookworm-arm64` expanded to `8 GiB` (`{EXPECTED_DISK_VIRTUAL_BYTES}` B), 2 vCPU, 2048 MiB RAM, populated with `1 GiB` (`{EXPECTED_PAYLOAD_BYTES}` B) random file `/var/tmp/bench-data.bin` + marker `/root/bench-marker`, `sync`ed",
    f"- **Max concurrent VMs observed**: `{max_concurrent_vms_seen}` (cap `<= 2`)",
    "",
    "## Summary Metrics",
    "",
    "| Metric | Value | Notes |",
    "|---|---:|---|",
    f"| **Stopped fork wall-clock median (`X`)** | **`{fmt_stat(stopped_wall_stats, 'median')}`** | {len(stopped_records)} runs of `agentvm branch p sc<i>` (min `{fmt_stat(stopped_wall_stats, 'min')}`, nearest-rank p95 `{fmt_stat(stopped_wall_stats, 'p95NearestRank')}`, max `{fmt_stat(stopped_wall_stats, 'max')}`; provisional threshold `<= {STOPPED_MEDIAN_THRESHOLD_MS:.0f} ms`) |",
    f"| Stopped fork CLI self-reported median | `{fmt_stat(stopped_rep_stats, 'median')}` | Lock acquired to SQLite commit (p95 `{fmt_stat(stopped_rep_stats, 'p95NearestRank')}`) |",
    f"| **Live running fork wall-clock median** | **`{fmt_stat(live_wall_stats, 'median')}`** | {len(live_records)} runs of `agentvm branch p lc<i>` via workspace daemon (min `{fmt_stat(live_wall_stats, 'min')}`, nearest-rank p95 `{fmt_stat(live_wall_stats, 'p95NearestRank')}`) |",
    f"| Live running fork VM pause median | `{fmt_stat(live_pause_stats, 'median', '.3f')}` | `VM_PAUSED_FOR_SNAPSHOT` (`pause` -> `clonefile` root disk & NVRAM -> `resume`; min `{fmt_stat(live_pause_stats, 'min', '.3f')}`, p95 `{fmt_stat(live_pause_stats, 'p95NearestRank', '.3f')}`) |",
    f"| Live running fork guest pre-pause `sync` median | `{fmt_stat(live_sync_stats, 'median', '.3f')}` | Guest `/bin/sync` via vsock before `pause` (p95 `{fmt_stat(live_sync_stats, 'p95NearestRank', '.3f')}`) |",
    f"| **New cloned files APFS private bytes (`Y`)** | **`{bench_doc['headlineMetrics']['Y_newClonedFilesAPFSPrivateBytes']} B`** | `getattrlist(ATTR_CMNEXT_PRIVATESIZE)` across all {len(stopped_records) + len(live_records)} forks (parent fork-point `.raw`, child root `.raw`, child head `.raw`, child `.nvram`); excludes APFS filesystem metadata & synthesized `cidata` ISO (`{iso_b_sample} B`) / `.machineid` (`{mid_b_sample} B`) |",
    f"| Volume `df -k` delta (16 stopped / 16 live forks) | `{stopped_df_delta_str}` / `{live_df_delta_str}` | Host-wide volume available-space delta (`dfBefore - dfAfter`); upper bound under concurrent host activity |",
    f"| Child root disk APFS private bytes after 1st boot + halt | `{post_priv_str}` | {post_priv_notes} |",
    f"| 32 children + parent identity verification | {ident_summary_val} | {ident_notes} |",
    "",
]
if failures:
    md_lines += [
        "## Failures",
        "",
        *[f"- **`{f['check']}`**: {f['reason']}" for f in failures],
        "",
    ]
md_text = scrub("\n".join(md_lines))

if real_home and (real_home in json_text or real_home in md_text):
    record_failure(failures, "outputPrivacyScrub", "Benchmark output still contained host home-directory path")
    bench_doc["passed"] = False
    bench_doc["failures"] = failures
    json_text = scrub(json.dumps(bench_doc, indent=2, ensure_ascii=False) + "\n")

target_dirs = []
if out_dir_arg:
    resolved_out_dir = out_dir_arg if os.path.isabs(out_dir_arg) else os.path.abspath(os.path.join(caller_pwd, out_dir_arg))
    os.makedirs(resolved_out_dir, exist_ok=True)
    target_dirs.append(resolved_out_dir)
if record_reports:
    rep_dir = os.path.join(root_dir, "reports")
    os.makedirs(rep_dir, exist_ok=True)
    target_dirs.append(rep_dir)

for tdir in target_dirs:
    jpath = os.path.join(tdir, "m3-branch-bench.json")
    mpath = os.path.join(tdir, "m3-branch-bench.md")
    with open(jpath, "w", encoding="utf-8") as jf:
        jf.write(json_text)
    with open(mpath, "w", encoding="utf-8") as mf:
        mf.write(md_text)
    emit(f"[5/5] Wrote benchmark artifacts: {jpath} and {mpath}")

if not target_dirs:
    emit("[5/5] Benchmark run completed in dry mode (pass --record to write reports/m3-branch-bench.{json,md}).")

if failures:
    for f in failures:
        emit_err(f"FAIL [Row 20] ({f['check']}): {f['reason']}")
    sys.exit(1)

emit(
    f"PASS [Row 20]: stopped median={stopped_wall_stats['median']:.2f} ms (p95={stopped_wall_stats['p95NearestRank']:.2f} ms), "
    f"live median={live_wall_stats['median']:.2f} ms (pause median={live_pause_stats['median']:.3f} ms), "
    f"cloned private bytes=0 B, 32/32 children booted & verified ({total_elapsed_sec:.1f}s)."
)
sys.exit(0)
PY
