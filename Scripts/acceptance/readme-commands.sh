#!/usr/bin/env bash
# Replays the commands that README.md and README.zh-CN.md actually contain.
#
# Nothing is hand-copied here: the commands, and the expected results written under them as `# -> ...`
# lines, are read out of the fenced ```bash blocks of the two READMEs. If a README changes, this check
# changes with it; if the two READMEs stop listing the same commands, it fails.
#
# Safety: every replayed command is an `agentvm <subcommand>` call run with HOME pointed at a temporary
# directory and a relative `--workspace` inside a temporary working directory. Lines that would launch
# the desktop UI, build the app bundle, or re-enter the test scripts are listed as SKIP and never run.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SWIFT_JOBS_ARGS=()
if [[ -n "${AGENTVM_BUILD_JOBS:-}" ]]; then
    SWIFT_JOBS_ARGS=(-j "$AGENTVM_BUILD_JOBS")
fi

swift build "${SWIFT_JOBS_ARGS[@]+"${SWIFT_JOBS_ARGS[@]}"}" --product AgentVM >/dev/null
AGENTVM_BIN="$ROOT_DIR/.build/debug/AgentVM"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agentvm-readme-check.XXXXXX")"
cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

echo "==> [readme-commands] Checking README.md & README.zh-CN.md for banned claims..."
if grep -nEi "sub-20|20\s*ms|20\s*毫秒|under 20|不到\s*20|wireshark-grade|wireshark\s*级|industrial-grade|工业级|hardware-isolated|硬件级隔离|硬件隔离|every outbound packet|每一帧出站" "$ROOT_DIR/README.md" "$ROOT_DIR/README.zh-CN.md"; then
    echo "FAIL: Found banned unverified claim in README files" >&2
    exit 1
fi
echo "PASS: Zero banned claims in README.md and README.zh-CN.md"

python3 - "$ROOT_DIR" "$AGENTVM_BIN" "$TMP_ROOT" <<'PY'
import os
import re
import shlex
import subprocess
import sys

root, binary, tmp_root = sys.argv[1], sys.argv[2], sys.argv[3]

READMES = [("README.md", "en"), ("README.zh-CN.md", "zh")]

# Subcommands that route the executable to its headless CLI. A command line without one of these would
# open the desktop UI, so it is rejected before anything is executed.
CLI_SUBCOMMANDS = {
    "doctor", "init", "ps", "list", "image", "create", "run", "daemon", "events",
    "up", "boot", "start", "pause", "resume", "halt", "stop",
    "branch", "fork", "snapshot", "restore", "exec", "pcap", "policy", "plugin", "export-hcl",
    "export-html", "help", "version",
}

# README lines that are documented but deliberately not executed by this script, with the reason.
SKIP_RULES = [
    (re.compile(r"^swift build --product AgentVM$"), "this script already built the product above"),
    (re.compile(r'^alias agentvm="\$\(pwd\)/\.build/debug/AgentVM"$'), "the replay substitutes the built binary for `agentvm`"),
    (re.compile(r"^\./Scripts/test\.sh (scope|milestone) .+$"), "test entry point; running it from here would recurse"),
    (re.compile(r"^AGENTVM_REAL_VM=1 \./Scripts/test\.sh milestone [123]( --record)?$"), "real-VM acceptance entry point; it boots guests and downloads an image, so the README replay never runs it"),
    (re.compile(r"^\./Scripts/acceptance/readme-commands\.sh$"), "this script itself"),
    (re.compile(r"^\./Scripts/build-app\.sh$"), "packaging step, builds the release .app bundle"),
    (re.compile(r"^open build/AgentVM\.app$"), "launches the desktop UI; no script may do that"),
    (re.compile(r"^\./build/AgentVM\.app/Contents/MacOS/AgentVM --demo$"), "launches the desktop UI; no script may do that"),
]

EXPECT_FAIL_PREFIXES = ("exits non-zero:", "非零退出码：")


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def extract(readme_name):
    """Return [(line_no, command, [expectation, ...])] from the ```bash blocks of one README."""
    entries = []
    in_block = False
    with open(os.path.join(root, readme_name), encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.rstrip("\n")
            stripped = line.strip()
            if stripped.startswith("```"):
                in_block = (not in_block) and stripped in ("```bash", "```sh", "```shell")
                continue
            if not in_block or not stripped:
                continue
            if stripped.startswith("# ->"):
                if not entries:
                    fail(f"{readme_name}:{line_no}: expectation line with no command above it")
                entries[-1][2].append(stripped[len("# ->"):].strip())
                continue
            if stripped.startswith("#"):
                continue
            entries.append((line_no, stripped, []))
    return entries


def normalise(command):
    return re.sub(r"--lang (en|zh)\b", "--lang <L>", command)


def matches_with_wildcards(expected, actual):
    """`...` in an expectation stands for any text; the pieces between must appear in order."""
    position = 0
    for piece in [p.strip() for p in expected.split("...")]:
        if not piece:
            continue
        found = actual.find(piece, position)
        if found < 0:
            return False
        position = found + len(piece)
    return True


all_entries = {name: extract(name) for name, _ in READMES}
for name, entries in all_entries.items():
    if not any(command.startswith("agentvm ") for _, command, _ in entries):
        fail(f"{name}: no `agentvm` command found in any ```bash block")

# The two READMEs must document the same commands (only the --lang value differs).
en_commands = [normalise(command) for _, command, _ in all_entries["README.md"]]
zh_commands = [normalise(command) for _, command, _ in all_entries["README.zh-CN.md"]]
if en_commands != zh_commands:
    print("FAIL: README.md and README.zh-CN.md do not list the same commands:", file=sys.stderr)
    for index in range(max(len(en_commands), len(zh_commands))):
        left = en_commands[index] if index < len(en_commands) else "<missing>"
        right = zh_commands[index] if index < len(zh_commands) else "<missing>"
        if left != right:
            print(f"  #{index + 1}\n    README.md:       {left}\n    README.zh-CN.md: {right}", file=sys.stderr)
    sys.exit(1)
print(f"PASS: README.md and README.zh-CN.md list the same {len(en_commands)} commands")

home = os.path.join(tmp_root, "home")
os.makedirs(home, exist_ok=True)
environment = dict(os.environ)
environment["HOME"] = home
environment["CFFIXED_USER_HOME"] = home
for variable in ("AGENTVM_WORKSPACE", "AGENTVM_REAL_VM", "AGENTVM_LANG"):
    environment.pop(variable, None)

for name, _ in READMES:
    workdir = os.path.join(tmp_root, "cwd-" + name.replace(".", "-"))
    os.makedirs(workdir, exist_ok=True)
    replayed = 0
    skipped = 0
    checked_expectations = 0
    print(f"==> [readme-commands] Replaying {name}")
    for line_no, command, expectations in all_entries[name]:
        where = f"{name}:{line_no}"
        if not command.startswith("agentvm "):
            reason = next((why for pattern, why in SKIP_RULES if pattern.match(command)), None)
            if reason is None:
                fail(f"{where}: `{command}` is in a README code block but this script neither replays nor explicitly skips it")
            if expectations:
                fail(f"{where}: `{command}` is skipped but has an expected-output line")
            print(f"SKIP ({reason}): {command}")
            skipped += 1
            continue

        arguments = shlex.split(command)[1:]
        host_arguments = arguments[: arguments.index("--")] if "--" in arguments else arguments
        if not any(token in CLI_SUBCOMMANDS for token in host_arguments):
            fail(f"{where}: `{command}` has no CLI subcommand and would open the desktop UI; refusing to run it")
        if "--workspace" not in host_arguments:
            fail(f"{where}: `{command}` has no --workspace and would touch the user's default workspace; refusing to run it")
        workspace = host_arguments[host_arguments.index("--workspace") + 1]
        if not workspace.startswith("./"):
            fail(f"{where}: --workspace `{workspace}` is not a relative ./ path; refusing to run it")

        result = subprocess.run(
            [binary] + arguments,
            cwd=workdir,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )
        combined = result.stdout + result.stderr
        wants_failure = any(expectation.startswith(EXPECT_FAIL_PREFIXES) for expectation in expectations)
        if wants_failure and result.returncode == 0:
            fail(f"{where}: `{command}` exited 0 but the README says it exits non-zero")
        if not wants_failure and result.returncode != 0:
            fail(f"{where}: `{command}` exited {result.returncode}; the README documents no failure here\n{combined}")
        for expectation in expectations:
            if expectation.startswith(EXPECT_FAIL_PREFIXES):
                text = expectation
                for prefix in EXPECT_FAIL_PREFIXES:
                    if text.startswith(prefix):
                        text = text[len(prefix):].strip()
                haystack = combined
            else:
                text = expectation
                haystack = result.stdout
            if not matches_with_wildcards(text, haystack):
                fail(f"{where}: `{command}`\n  README says:  {expectation}\n  actual output:\n{combined}")
            checked_expectations += 1
        replayed += 1
    print(f"PASS: {name}: replayed {replayed} agentvm commands, checked {checked_expectations} documented outputs, skipped {skipped} non-replayable lines")
PY

echo "ALL README COMMAND CHECKS PASSED."
