import AgentVMModels
import Foundation

// MARK: - Linux Guest Vsock Daemon & Systemd Bootstrap Generator

/// Generates the self-contained Linux Guest Agent (`agentvm-guestd.py`), `systemd` unit file
/// (`agentvm-guestd.service`), kernel `vmw_vsock_virtio_transport` autoload configuration, and `CloudInitWriteFile`
/// entries speaking the exact 24-byte `AVM1` (`0x41564D31`) binary wire protocol on `AF_VSOCK` port `1025`.
public struct GuestAgentBootstrapGenerator: Sendable, Hashable {
    public static let defaultVsockPort: UInt32 = VsockWireConstants.defaultGuestVsockPort
    public static let defaultDaemonGuestPath: String = "/usr/local/sbin/agentvm-guestd.py"
    public static let defaultSystemdUnitGuestPath: String = "/etc/systemd/system/agentvm-guestd.service"
    public static let defaultModulesLoadGuestPath: String = "/etc/modules-load.d/agentvm-vsock.conf"

    public var vsockPort: UInt32
    public var daemonPath: String
    public var systemdUnitPath: String
    public var modulesLoadPath: String
    public var heartbeatIntervalSeconds: Int
    public var defaultWorkspacePath: String

    public init(
        vsockPort: UInt32 = Self.defaultVsockPort,
        daemonPath: String = Self.defaultDaemonGuestPath,
        systemdUnitPath: String = Self.defaultSystemdUnitGuestPath,
        modulesLoadPath: String = Self.defaultModulesLoadGuestPath,
        heartbeatIntervalSeconds: Int = 5,
        defaultWorkspacePath: String = "/workspace"
    ) {
        self.vsockPort = vsockPort
        self.daemonPath = daemonPath
        self.systemdUnitPath = systemdUnitPath
        self.modulesLoadPath = modulesLoadPath
        self.heartbeatIntervalSeconds = max(1, heartbeatIntervalSeconds)
        self.defaultWorkspacePath = defaultWorkspacePath
    }

    // MARK: Cloud-Init Integration

    /// Produces the complete set of `CloudInitWriteFile` artifacts required to install and run `agentvm-guestd`
    /// inside an Ubuntu / Debian / Fedora Linux guest VM on first boot.
    public func cloudInitFiles() -> [CloudInitWriteFile] {
        [
            CloudInitWriteFile(
                guestPath: modulesLoadPath,
                permissionsOctal: "0644",
                owner: "root:root",
                content: kernelModulesConfig()
            ),
            CloudInitWriteFile(
                guestPath: daemonPath,
                permissionsOctal: "0755",
                owner: "root:root",
                content: pythonDaemonScript()
            ),
            CloudInitWriteFile(
                guestPath: systemdUnitPath,
                permissionsOctal: "0644",
                owner: "root:root",
                content: systemdServiceUnit()
            )
        ]
    }

    /// Shell commands executed during Cloud-Init `runcmd` stage to load `vsock` kernel modules and start `agentvm-guestd`.
    public func cloudInitRunCommands() -> [String] {
        let unitName = URL(fileURLWithPath: systemdUnitPath).lastPathComponent
        return [
            "mkdir -p \(defaultWorkspacePath)",
            "modprobe virtio_console || true",
            "modprobe vmw_vsock_virtio_transport || true",
            "systemctl daemon-reload",
            "systemctl enable --now serial-getty@hvc0.service || true",
            "sync",
            "systemctl enable --now \(unitName)"
        ]
    }

    /// Returns a copy of `spec` enriched with `agentvm-guestd` files and `runcmd` activation steps
    /// when `spec.injectGuestVsockAgent` is enabled, deduplicating by `guestPath`.
    public func applying(to spec: CloudInitSpec, includePythonAptPackage: Bool = false) -> CloudInitSpec {
        guard spec.injectGuestVsockAgent else { return spec }
        var updated = spec
        let existingPaths = Set(updated.writeFiles.map(\.guestPath))
        for file in cloudInitFiles() where !existingPaths.contains(file.guestPath) {
            updated.writeFiles.append(file)
        }
        let existingCommands = Set(updated.runCommands)
        for cmd in cloudInitRunCommands() where !existingCommands.contains(cmd) {
            updated.runCommands.append(cmd)
        }
        if includePythonAptPackage && !updated.aptPackages.contains("python3") {
            updated.aptPackages.append("python3")
        }
        return updated
    }

    /// Strips any previously persisted guest-bootstrap `writeFiles` and `runCommands` (including legacy
    /// v1.0–v1.3 entries) while keeping caller-supplied custom files and commands intact, then re-injects
    /// the current bootstrap version. Used when synthesizing a forked child VM's `CloudInitSpec`.
    public func refreshing(in spec: CloudInitSpec, includePythonAptPackage: Bool = false) -> CloudInitSpec {
        guard spec.injectGuestVsockAgent else { return spec }
        var stripped = spec
        let managedWritePaths: Set<String> = [
            modulesLoadPath,
            daemonPath,
            systemdUnitPath,
            Self.defaultModulesLoadGuestPath,
            Self.defaultDaemonGuestPath,
            Self.defaultSystemdUnitGuestPath,
            "/usr/local/bin/agentvm-guest-agent",
            "/etc/systemd/system/agentvm-guest-agent.service"
        ]
        stripped.writeFiles.removeAll { managedWritePaths.contains($0.guestPath) }

        var managedRunCommands = Set(cloudInitRunCommands())
        managedRunCommands.insert("mkdir -p /workspace")
        managedRunCommands.insert("modprobe virtio_vsock || modprobe vmw_vsock_virtio_transport || true")
        managedRunCommands.insert("systemctl enable --now agentvm-guestd.service")
        managedRunCommands.insert("systemctl enable --now agentvm-guest-agent.service")
        stripped.runCommands.removeAll { managedRunCommands.contains($0) }

        return applying(to: stripped, includePythonAptPackage: includePythonAptPackage)
    }

    // MARK: Systemd Service & Kernel Module Templates

    public func kernelModulesConfig() -> String {
        """
        # Autoloaded by systemd-modules-load.service for AgentVM VirtioSocket RPC & Console
        virtio_console
        vsock
        vmw_vsock_virtio_transport_common
        vmw_vsock_virtio_transport
        """ + "\n"
    }

    public func generateSystemdServiceUnit() -> String {
        systemdServiceUnit()
    }

    public func systemdServiceUnit() -> String {
        """
        [Unit]
        Description=AgentVM Multiplexed VirtioSocket Guest Daemon (AVM1 Protocol)
        Documentation=https://agentvm.local/docs/vsock-rpc
        After=systemd-modules-load.service local-fs.target network.target
        Wants=systemd-modules-load.service

        [Service]
        Type=simple
        User=root
        Group=root
        WorkingDirectory=-\(defaultWorkspacePath)
        ExecStartPre=-/bin/mkdir -p \(defaultWorkspacePath)
        ExecStartPre=-/sbin/modprobe virtio_console
        ExecStartPre=-/sbin/modprobe vmw_vsock_virtio_transport
        ExecStartPre=-/bin/sh -c '/bin/dmesg > /dev/hvc0 2>/dev/null || true'
        ExecStart=/usr/bin/python3 -u \(daemonPath) --port \(vsockPort) --heartbeat-interval \(heartbeatIntervalSeconds) --workspace \(defaultWorkspacePath)
        Restart=always
        RestartSec=1
        StandardOutput=journal
        StandardError=journal
        SyslogIdentifier=agentvm-guestd
        OOMScoreAdjust=-500
        LimitNOFILE=65536
        KillMode=process

        [Install]
        WantedBy=multi-user.target
        """ + "\n"
    }

    // MARK: Complete Linux Python 3 Guest Daemon ("agentvm-guestd.py")

    public func generatePythonDaemonScript() -> String {
        pythonDaemonScript()
    }

    public func pythonDaemonScript() -> String {
        #"""
        #!/usr/bin/env python3
        """
        agentvm-guestd.py — AgentVM Linux Sandbox VirtioSocket Multiplexed RPC Daemon
        Wire Protocol: AVM1 (0x41564D31), 24-byte Big-Endian Header + Payload + 4-byte IEEE CRC32 Trailer
        """

        import argparse
        import base64
        import errno
        import fcntl
        import hashlib
        import json
        import os
        import pty
        import pwd
        import select
        import signal
        import socket
        import stat
        import struct
        import subprocess
        import sys
        import tempfile
        import termios
        import threading
        import time
        import uuid
        import zlib

        # ---------------------------------------------------------------------------
        # AVM1 Binary Wire Protocol Constants
        # ---------------------------------------------------------------------------
        AVM1_MAGIC = 0x41564D31
        AVM1_VERSION = 1
        HEADER_STRUCT = struct.Struct(">IBBHIIII")  # 24 bytes exact
        CRC_STRUCT = struct.Struct(">I")            # 4 bytes IEEE 802.3 CRC-32 trailer
        LEN_PREFIX_STRUCT = struct.Struct(">I")     # 4 bytes uncompressed size inside FLAG_COMPRESSED

        DEFAULT_WINDOW_CREDIT = 262144
        WINDOW_UPDATE_THRESHOLD = 65536
        MAX_CHUNK_BYTES = 32768
        MAX_FRAME_PAYLOAD_BYTES = 32 * 1024 * 1024

        KILLPG_GRACE_SECONDS = 0.2
        KILLPG_POST_SIGKILL_WAIT_SECONDS = 0.2
        KILLPG_POLL_INTERVAL_SECONDS = 0.005

        # VsockChannelKind
        CHAN_CONTROL = 0
        CHAN_EXEC_PROCESS = 1
        CHAN_FILE_TRANSFER = 2
        CHAN_TCP_PORT_FORWARD = 3
        CHAN_TELEMETRY_HEARTBEAT = 4
        CHAN_INTERACTIVE_PTY = 5

        # VsockFrameFlags
        FLAG_SYN = 1 << 0
        FLAG_ACK = 1 << 1
        FLAG_FIN = 1 << 2
        FLAG_RST = 1 << 3
        FLAG_WINDOW_UPDATE = 1 << 4
        FLAG_COMPRESSED = 1 << 5
        FLAG_END_OF_MESSAGE = 1 << 6
        FLAG_ERROR_FRAME = 1 << 7

        # VsockPTYSubframeOpcode
        PTY_OP_STDIN = 0x01
        PTY_OP_RESIZE = 0x02
        PTY_OP_STDOUT = 0x03
        PTY_OP_OPEN = 0x04


        def ieee_crc32(data_bytes: bytes) -> int:
            return zlib.crc32(data_bytes) & 0xFFFFFFFF


        def encode_avm1_frame(
            channel: int,
            flags: int,
            stream_id: int,
            sequence: int,
            payload: bytes = b"",
            window_credit: int = DEFAULT_WINDOW_CREDIT,
            compress_if_beneficial: bool = False,
        ) -> bytes:
            effective_flags = flags
            wire_payload = payload

            if flags & FLAG_COMPRESSED:
                compressed = LEN_PREFIX_STRUCT.pack(len(payload)) + zlib.compress(payload, 6)
                wire_payload = compressed
            elif compress_if_beneficial and len(payload) >= 64:
                candidate = LEN_PREFIX_STRUCT.pack(len(payload)) + zlib.compress(payload, 6)
                if len(candidate) < len(payload):
                    wire_payload = candidate
                    effective_flags |= FLAG_COMPRESSED
                else:
                    effective_flags &= ~FLAG_COMPRESSED
            else:
                effective_flags &= ~FLAG_COMPRESSED

            crc = ieee_crc32(wire_payload)
            header = HEADER_STRUCT.pack(
                AVM1_MAGIC,
                AVM1_VERSION,
                channel & 0xFF,
                effective_flags & 0xFFFF,
                stream_id & 0xFFFFFFFF,
                sequence & 0xFFFFFFFF,
                window_credit & 0xFFFFFFFF,
                len(wire_payload) & 0xFFFFFFFF,
            )
            return header + wire_payload + CRC_STRUCT.pack(crc)


        class StreamFrameAccumulator:
            """Incremental stream reassembler for 24-byte AVM1 headers + payloads + 4-byte CRC32 trailers."""

            def __init__(self) -> None:
                self._buf = bytearray()

            def feed(self, chunk: bytes):
                if not chunk:
                    return []
                self._buf.extend(chunk)
                frames = []

                while len(self._buf) >= 4:
                    magic = LEN_PREFIX_STRUCT.unpack_from(self._buf, 0)[0]
                    if magic != AVM1_MAGIC:
                        raise ValueError(f"Invalid AVM1 magic: 0x{magic:08X}")
                    if len(self._buf) < HEADER_STRUCT.size:
                        break

                    (
                        _magic,
                        version,
                        channel,
                        flags,
                        stream_id,
                        seq_num,
                        window_credit,
                        wire_len,
                    ) = HEADER_STRUCT.unpack_from(self._buf, 0)

                    if version != AVM1_VERSION:
                        raise ValueError(f"Unsupported AVM1 version: {version}")
                    if wire_len > MAX_FRAME_PAYLOAD_BYTES + 1024:
                        raise ValueError(f"Excessive AVM1 payload length: {wire_len}")

                    total_size = HEADER_STRUCT.size + wire_len + CRC_STRUCT.size
                    if len(self._buf) < total_size:
                        break

                    payload_start = HEADER_STRUCT.size
                    payload_end = payload_start + wire_len
                    wire_payload = bytes(self._buf[payload_start:payload_end])
                    expected_crc = CRC_STRUCT.unpack_from(self._buf, payload_end)[0]
                    del self._buf[:total_size]

                    actual_crc = ieee_crc32(wire_payload)
                    if actual_crc != expected_crc:
                        raise ValueError(
                            f"AVM1 CRC32 mismatch (expected 0x{expected_crc:08X}, got 0x{actual_crc:08X})"
                        )

                    if flags & FLAG_COMPRESSED:
                        if len(wire_payload) < 4:
                            raise ValueError("Compressed AVM1 frame missing 4-byte size prefix")
                        orig_len = LEN_PREFIX_STRUCT.unpack_from(wire_payload, 0)[0]
                        if orig_len > MAX_FRAME_PAYLOAD_BYTES:
                            raise ValueError(f"Decompressed payload exceeds cap: {orig_len}")
                        logical_payload = zlib.decompress(wire_payload[4:])
                        if len(logical_payload) != orig_len:
                            raise ValueError("Decompressed length mismatch")
                    else:
                        logical_payload = wire_payload

                    frames.append(
                        {
                            "channel": channel,
                            "flags": flags,
                            "stream_id": stream_id,
                            "sequence": seq_num,
                            "window_credit": window_credit,
                            "payload": logical_payload,
                        }
                    )
                return frames


        # ---------------------------------------------------------------------------
        # Linux /proc Telemetry Sampler
        # ---------------------------------------------------------------------------
        class ProcTelemetryCollector:
            def __init__(self, proc_root: str = "/proc") -> None:
                self.proc_root = proc_root or "/proc"
                self._prev_cpu_total = None
                self._prev_cpu_idle = None
                self._page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

            def _proc_path(self, *parts: str) -> str:
                return os.path.join(self.proc_root, *parts)

            def _sample_cpu_jiffies(self):
                try:
                    with open(self._proc_path("stat"), "r", encoding="utf-8") as fh:
                        first = fh.readline()
                    tokens = first.split()
                    if len(tokens) < 5 or tokens[0] != "cpu":
                        return None
                    parts = [int(x) for x in tokens[1:]]
                    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
                    total = sum(parts)
                    return total, idle
                except Exception:
                    return None

            def collect_heartbeat(self) -> dict:
                uname = os.uname()
                hostname = uname.nodename or socket.gethostname()
                kernel_release = uname.release

                uptime_secs = 0.0
                try:
                    with open(self._proc_path("uptime"), "r", encoding="utf-8") as fh:
                        uptime_secs = float(fh.read().split()[0])
                except Exception:
                    pass

                load1, load5, load15 = (0.0, 0.0, 0.0)
                try:
                    load1, load5, load15 = os.getloadavg()
                except Exception:
                    pass

                cpu_usage_pct = None
                cpu_sample = self._sample_cpu_jiffies()
                if cpu_sample is not None:
                    cur_total, cur_idle = cpu_sample
                    if self._prev_cpu_total is not None and self._prev_cpu_idle is not None:
                        delta_total = cur_total - self._prev_cpu_total
                        delta_idle = cur_idle - self._prev_cpu_idle
                        if delta_total > 0:
                            cpu_usage_pct = min(
                                100.0,
                                max(0.0, ((delta_total - delta_idle) / float(delta_total)) * 100.0),
                            )
                    self._prev_cpu_total, self._prev_cpu_idle = cur_total, cur_idle

                mem_total = 0
                mem_avail = 0
                try:
                    with open(self._proc_path("meminfo"), "r", encoding="utf-8") as fh:
                        for line in fh:
                            if line.startswith("MemTotal:"):
                                mem_total = int(line.split()[1]) * 1024
                            elif line.startswith("MemAvailable:"):
                                mem_avail = int(line.split()[1]) * 1024
                except Exception:
                    pass

                root_used = 0
                root_total = 0
                try:
                    vfs = os.statvfs("/")
                    root_total = vfs.f_blocks * vfs.f_frsize
                    root_used = (vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize
                except Exception:
                    pass

                top_procs = self._collect_top_processes(uptime_secs)
                hb = {
                    "hostname": hostname,
                    "kernelRelease": kernel_release,
                    "uptimeSeconds": uptime_secs,
                    "loadAvg1": round(load1, 3),
                    "loadAvg5": round(load5, 3),
                    "loadAvg15": round(load15, 3),
                    "memTotalBytes": mem_total,
                    "memAvailableBytes": mem_avail,
                    "rootFilesystemUsedBytes": root_used,
                    "rootFilesystemTotalBytes": root_total,
                    "topProcesses": top_procs,
                    "reportedAt": time.time(),
                }
                if cpu_usage_pct is not None:
                    hb["cpuUsagePercent"] = cpu_usage_pct
                return hb

            def _collect_top_processes(self, uptime_secs: float):
                samples = []
                clk_tck = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
                try:
                    pids = [int(d) for d in os.listdir(self.proc_root) if d.isdigit()]
                except Exception:
                    return samples

                for pid in pids[:256]:
                    pid_str = str(pid)
                    try:
                        with open(self._proc_path(pid_str, "stat"), "r", encoding="utf-8", errors="replace") as fh:
                            raw_stat = fh.read()
                        rparen = raw_stat.rfind(")")
                        if rparen < 0:
                            continue
                        comm = raw_stat[raw_stat.find("(") + 1 : rparen]
                        fields = raw_stat[rparen + 2 :].split()
                        ppid = int(fields[1])
                        utime = int(fields[11])
                        stime = int(fields[12])
                        starttime = int(fields[19])
                        rss_pages = int(fields[21])
                        rss_bytes = max(0, rss_pages * self._page_size)

                        proc_elapsed = max(0.1, uptime_secs - (starttime / float(clk_tck)))
                        cpu_pct = round(min(100.0, ((utime + stime) / float(clk_tck)) / proc_elapsed * 100.0), 2)

                        uid = 0
                        proc_stat_info = os.stat(self._proc_path(pid_str))
                        uid = proc_stat_info.st_uid
                        try:
                            username = pwd.getpwuid(uid).pw_name
                        except KeyError:
                            username = str(uid)

                        cmdline = comm
                        try:
                            with open(self._proc_path(pid_str, "cmdline"), "rb") as cf:
                                raw_cmd = cf.read(256).replace(b"\x00", b" ").strip()
                                if raw_cmd:
                                    cmdline = raw_cmd.decode("utf-8", errors="replace")
                        except Exception:
                            pass

                        samples.append(
                            {
                                "pid": pid,
                                "ppid": ppid,
                                "user": username,
                                "cpuPercent": cpu_pct,
                                "rssBytes": rss_bytes,
                                "command": cmdline,
                            }
                        )
                    except Exception:
                        continue

                samples.sort(key=lambda item: (item["cpuPercent"], item["rssBytes"]), reverse=True)
                return samples[:8]


        def _terminate_pgroup_for_process(proc: subprocess.Popen, grace_sec: float = KILLPG_GRACE_SECONDS) -> None:
            if proc is None:
                return
            pgid = proc.pid
            if pgid is None or pgid <= 0:
                return

            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                try:
                    proc.poll()
                except Exception:
                    pass
                return
            except OSError:
                pass

            deadline = time.monotonic() + max(0.0, grace_sec)
            while True:
                try:
                    proc.poll()
                except Exception:
                    pass
                try:
                    os.killpg(pgid, 0)
                except ProcessLookupError:
                    return
                except PermissionError:
                    # On XNU/macOS, killpg(pgid, 0) transiently returns EPERM while dying members
                    # are in SZOMB/P_WEXIT before launchd/waitpid reaps them; keep polling until ESRCH.
                    pass
                except OSError:
                    return
                if time.monotonic() >= deadline:
                    break
                time.sleep(KILLPG_POLL_INTERVAL_SECONDS)

            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                try:
                    proc.poll()
                except Exception:
                    pass
                return
            except OSError:
                pass
            try:
                proc.kill()
            except Exception:
                pass

            kill_deadline = time.monotonic() + KILLPG_POST_SIGKILL_WAIT_SECONDS
            while time.monotonic() < kill_deadline:
                try:
                    proc.poll()
                except Exception:
                    pass
                try:
                    os.killpg(pgid, 0)
                except ProcessLookupError:
                    return
                except PermissionError:
                    pass
                except OSError:
                    return
                time.sleep(KILLPG_POLL_INTERVAL_SECONDS)


        class ExecStreamState:
            """Tracks a single multiplexed CHAN_EXEC_PROCESS stream and its child process group."""

            def __init__(self, stream_id: int) -> None:
                self.stream_id = stream_id
                self.lock = threading.Lock()
                self.term_lock = threading.Lock()
                self.proc = None
                self.cancelled = False
                self.terminated = False
                rfd, wfd = os.pipe()
                for fd in (rfd, wfd):
                    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
                self.wake_rfd = rfd
                self.wake_wfd = wfd

            def attach_process(self, proc: subprocess.Popen) -> bool:
                with self.lock:
                    self.proc = proc
                    already_cancelled = self.cancelled
                if already_cancelled:
                    self.terminate_process_group()
                    return False
                return True

            def wake(self) -> None:
                with self.lock:
                    wfd = self.wake_wfd
                if wfd >= 0:
                    try:
                        os.write(wfd, b"\x01")
                    except OSError:
                        pass

            def drain_wake(self) -> None:
                with self.lock:
                    rfd = self.wake_rfd
                if rfd >= 0:
                    try:
                        while os.read(rfd, 64):
                            pass
                    except OSError:
                        pass

            def mark_cancelled(self) -> None:
                with self.lock:
                    self.cancelled = True
                self.wake()

            def is_cancelled(self) -> bool:
                with self.lock:
                    return self.cancelled

            def wait_proc(self) -> int:
                with self.lock:
                    proc = self.proc
                if proc is None:
                    return 0
                try:
                    return proc.wait()
                except Exception:
                    return 0

            def terminate_process_group(self, grace_sec: float = KILLPG_GRACE_SECONDS) -> None:
                self.wake()
                with self.term_lock:
                    with self.lock:
                        if self.terminated:
                            return
                        proc = self.proc
                        if proc is None:
                            return
                        self.terminated = True
                    _terminate_pgroup_for_process(proc, grace_sec=grace_sec)

            def close_wake_pipe(self) -> None:
                with self.lock:
                    rfd, wfd = self.wake_rfd, self.wake_wfd
                    self.wake_rfd = -1
                    self.wake_wfd = -1
                for fd in (rfd, wfd):
                    if fd >= 0:
                        try:
                            os.close(fd)
                        except OSError:
                            pass


        # ---------------------------------------------------------------------------
        # Multiplexed Vsock Connection Session Handler
        # ---------------------------------------------------------------------------
        class GuestVsockConnectionSession:
            def __init__(
                self,
                conn: socket.socket,
                heartbeat_interval: int,
                default_workspace: str,
                proc_root: str = "/proc",
            ) -> None:
                self.conn = conn
                self.heartbeat_interval = heartbeat_interval
                self.default_workspace = default_workspace
                self.proc_root = proc_root or "/proc"
                self.write_lock = threading.Lock()
                self.state_lock = threading.Lock()
                self.closed = False

                self.seq_by_stream = {}
                self.peer_window = {}
                self.uncredited_rx = {}
                self.window_cond = threading.Condition(self.state_lock)

                self.active_execs = {}
                self.exec_req_buffers = {}
                self.file_pushes = {}
                self.tcp_bridges = {}
                self.pty_sessions = {}
                self.telemetry = ProcTelemetryCollector(proc_root=self.proc_root)

            def run(self) -> None:
                hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
                hb_thread.start()
                acc = StreamFrameAccumulator()
                try:
                    self._emit_heartbeat()
                    while not self.closed:
                        chunk = self.conn.recv(65536)
                        if not chunk:
                            break
                        for frame in acc.feed(chunk):
                            self._dispatch_frame(frame)
                except Exception as exc:
                    sys.stderr.write(f"[agentvm-guestd] session terminated: {exc}\n")
                finally:
                    self.shutdown()

            def shutdown(self) -> None:
                with self.state_lock:
                    if self.closed:
                        return
                    self.closed = True
                    exec_states = list(self.active_execs.values())
                    self.active_execs.clear()
                    self.exec_req_buffers.clear()
                    for st in exec_states:
                        st.mark_cancelled()
                    self.window_cond.notify_all()
                    bridges = list(self.tcp_bridges.values())
                    self.tcp_bridges.clear()
                    ptys = list(self.pty_sessions.values())
                    self.pty_sessions.clear()
                    pushes = list(self.file_pushes.values())
                    self.file_pushes.clear()

                for st in exec_states:
                    try:
                        st.terminate_process_group()
                    except Exception:
                        pass
                for sock in bridges:
                    try:
                        sock.close()
                    except Exception:
                        pass
                for master_fd, proc in ptys:
                    try:
                        os.close(master_fd)
                    except Exception:
                        pass
                    try:
                        _terminate_pgroup_for_process(proc)
                    except Exception:
                        pass
                for push in pushes:
                    try:
                        push["fp"].close()
                        os.unlink(push["tmp_path"])
                    except Exception:
                        pass
                try:
                    self.conn.close()
                except Exception:
                    pass

            def _next_seq(self, stream_id: int) -> int:
                with self.state_lock:
                    nxt = (self.seq_by_stream.get(stream_id, 0) + 1) & 0xFFFFFFFF
                    self.seq_by_stream[stream_id] = nxt
                    return nxt

            def send_frame(
                self,
                channel: int,
                flags: int,
                stream_id: int,
                payload: bytes = b"",
                window_credit: int = DEFAULT_WINDOW_CREDIT,
                compress: bool = False,
            ) -> None:
                if self.closed:
                    return
                seq = self._next_seq(stream_id)
                raw = encode_avm1_frame(
                    channel=channel,
                    flags=flags,
                    stream_id=stream_id,
                    sequence=seq,
                    payload=payload,
                    window_credit=window_credit,
                    compress_if_beneficial=compress,
                )
                with self.write_lock:
                    if not self.closed:
                        self.conn.sendall(raw)

            def send_chunked_flow_controlled(
                self,
                channel: int,
                stream_id: int,
                data: bytes,
                final_flags: int = FLAG_ACK,
                compress: bool = False,
            ) -> None:
                if not data:
                    self.send_frame(channel, final_flags, stream_id, b"", compress=False)
                    return

                offset = 0
                total = len(data)
                while offset < total and not self.closed:
                    with self.window_cond:
                        while not self.closed and self.peer_window.get(stream_id, DEFAULT_WINDOW_CREDIT) <= 0:
                            self.window_cond.wait(timeout=0.2)
                        if self.closed:
                            return
                        avail = self.peer_window.get(stream_id, DEFAULT_WINDOW_CREDIT)
                        take = min(total - offset, MAX_CHUNK_BYTES, max(1, avail))
                        self.peer_window[stream_id] = max(0, avail - take)

                    is_last = (offset + take) >= total
                    flags = final_flags if is_last else FLAG_ACK
                    self.send_frame(
                        channel=channel,
                        flags=flags,
                        stream_id=stream_id,
                        payload=data[offset : offset + take],
                        compress=compress,
                    )
                    offset += take

            def _account_rx_window(self, stream_id: int, channel: int, nbytes: int) -> None:
                if stream_id == 0 or nbytes <= 0:
                    return
                replenish = 0
                with self.state_lock:
                    cur = self.uncredited_rx.get(stream_id, 0) + nbytes
                    if cur >= WINDOW_UPDATE_THRESHOLD:
                        replenish = cur
                        self.uncredited_rx[stream_id] = 0
                    else:
                        self.uncredited_rx[stream_id] = cur
                if replenish > 0:
                    self.send_frame(
                        channel=channel,
                        flags=FLAG_WINDOW_UPDATE | FLAG_ACK,
                        stream_id=stream_id,
                        payload=b"",
                        window_credit=replenish,
                        compress=False,
                    )

            def _dispatch_frame(self, frame: dict) -> None:
                channel = frame["channel"]
                flags = frame["flags"]
                stream_id = frame["stream_id"]
                payload = frame["payload"]

                if flags & FLAG_WINDOW_UPDATE:
                    with self.window_cond:
                        cur = self.peer_window.get(stream_id, DEFAULT_WINDOW_CREDIT)
                        self.peer_window[stream_id] = cur + frame["window_credit"]
                        self.window_cond.notify_all()
                    if not payload and not (flags & (FLAG_FIN | FLAG_RST)):
                        return

                if flags & FLAG_SYN and stream_id != 0:
                    with self.state_lock:
                        self.peer_window.setdefault(stream_id, max(4096, frame["window_credit"]))

                self._account_rx_window(stream_id, channel, len(payload))

                if channel == CHAN_CONTROL:
                    self._on_control(payload)
                elif channel == CHAN_TELEMETRY_HEARTBEAT:
                    self._emit_heartbeat()
                elif channel == CHAN_EXEC_PROCESS:
                    if flags & FLAG_RST:
                        self._cancel_exec_stream(stream_id)
                    else:
                        req_bytes = None
                        exec_state = None
                        with self.state_lock:
                            if flags & FLAG_SYN:
                                self.exec_req_buffers[stream_id] = bytearray()
                            buf = self.exec_req_buffers.get(stream_id)
                            if buf is None and payload:
                                buf = bytearray()
                                self.exec_req_buffers[stream_id] = buf
                            if buf is not None and payload:
                                buf.extend(payload)
                            if (flags & FLAG_END_OF_MESSAGE) and buf is not None:
                                req_bytes = bytes(self.exec_req_buffers.pop(stream_id))
                                exec_state = ExecStreamState(stream_id)
                                self.active_execs[stream_id] = exec_state
                        if req_bytes is not None and exec_state is not None:
                            threading.Thread(
                                target=self._run_exec_request,
                                args=(stream_id, req_bytes, exec_state),
                                daemon=True,
                            ).start()
                elif channel == CHAN_FILE_TRANSFER:
                    self._on_file_transfer(stream_id, flags, payload)
                elif channel == CHAN_TCP_PORT_FORWARD:
                    self._on_port_forward(stream_id, flags, payload)
                elif channel == CHAN_INTERACTIVE_PTY:
                    self._on_interactive_pty(stream_id, flags, payload)

            def _on_control(self, payload: bytes) -> None:
                pong = {
                    "kind": "pong",
                    "agentVersion": "2",
                    "maxWindowBytes": DEFAULT_WINDOW_CREDIT,
                    "timestampUnix": time.time(),
                    "capabilities": ["exec", "pty", "file-sha256", "tcp-forward", "heartbeat", "zlib"],
                }
                self.send_frame(
                    CHAN_CONTROL,
                    FLAG_ACK | FLAG_END_OF_MESSAGE,
                    0,
                    json.dumps(pong).encode("utf-8"),
                )

            def _heartbeat_loop(self) -> None:
                while not self.closed:
                    time.sleep(self.heartbeat_interval)
                    if self.closed:
                        break
                    try:
                        self._emit_heartbeat()
                    except Exception:
                        break

            def _emit_heartbeat(self) -> None:
                hb = self.telemetry.collect_heartbeat()
                encoded = json.dumps(hb).encode("utf-8")
                self.send_frame(
                    CHAN_TELEMETRY_HEARTBEAT,
                    FLAG_ACK | FLAG_END_OF_MESSAGE,
                    0,
                    encoded,
                    compress=True,
                )

            # ---- Channel 1: Command Execution (subprocess / pty) ----
            def _cancel_exec_stream(self, stream_id: int) -> None:
                with self.window_cond:
                    self.exec_req_buffers.pop(stream_id, None)
                    exec_state = self.active_execs.get(stream_id)
                    if exec_state is not None:
                        exec_state.mark_cancelled()
                    self.window_cond.notify_all()
                if exec_state is not None:
                    exec_state.terminate_process_group()

            def _run_exec_request(
                self,
                stream_id: int,
                raw_json: bytes,
                exec_state: ExecStreamState = None,
            ) -> None:
                if exec_state is None:
                    exec_state = ExecStreamState(stream_id)
                    with self.state_lock:
                        self.active_execs[stream_id] = exec_state

                started = time.monotonic()
                try:
                    if self.closed or exec_state.is_cancelled():
                        return

                    req = json.loads(raw_json.decode("utf-8"))
                    req_id = req["id"]
                    cmd = [req["executable"]] + list(req.get("arguments", []))
                    cwd = req.get("workingDirectory") or self.default_workspace
                    if not os.path.isdir(cwd):
                        cwd = "/"

                    env = os.environ.copy()
                    env.update(req.get("environment") or {})
                    timeout_sec = max(0.1, float(req.get("timeoutSeconds", 300.0)))
                    run_as_user = req.get("runAsUser") or "root"
                    stdin_b64 = req.get("stdinPayload")
                    stdin_bytes = base64.b64decode(stdin_b64) if stdin_b64 else None
                    alloc_pty = bool(req.get("allocatePTY", False))

                    def demote_user():
                        if os.geteuid() == 0 and run_as_user and run_as_user != "root":
                            try:
                                pw = pwd.getpwnam(run_as_user)
                                try:
                                    os.initgroups(run_as_user, pw.pw_gid)
                                except Exception:
                                    pass
                                os.setgid(pw.pw_gid)
                                os.setuid(pw.pw_uid)
                            except KeyError:
                                pass

                    preexec = demote_user if (os.geteuid() == 0 and run_as_user and run_as_user != "root") else None
                    seq = 0
                    timed_out = False
                    exit_code = 0
                    deadline = started + timeout_sec

                    try:
                        if alloc_pty:
                            master_fd, slave_fd = pty.openpty()
                            rows = int(req.get("ptyRows", 36))
                            cols = int(req.get("ptyColumns", 120))
                            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                            try:
                                proc = subprocess.Popen(
                                    cmd,
                                    stdin=slave_fd,
                                    stdout=slave_fd,
                                    stderr=slave_fd,
                                    cwd=cwd,
                                    env=env,
                                    preexec_fn=preexec,
                                    start_new_session=True,
                                    close_fds=True,
                                )
                            finally:
                                try:
                                    os.close(slave_fd)
                                except OSError:
                                    pass

                            if not exec_state.attach_process(proc):
                                try:
                                    os.close(master_fd)
                                except OSError:
                                    pass
                                exec_state.wait_proc()
                                return

                            if stdin_bytes:
                                try:
                                    os.write(master_fd, stdin_bytes)
                                except OSError:
                                    pass

                            while True:
                                if self.closed or exec_state.is_cancelled():
                                    exec_state.terminate_process_group()
                                    break
                                rem = deadline - time.monotonic()
                                if rem <= 0:
                                    timed_out = True
                                    exec_state.terminate_process_group()
                                    break
                                watch_fds = [master_fd]
                                if exec_state.wake_rfd >= 0:
                                    watch_fds.append(exec_state.wake_rfd)
                                rlist, _, _ = select.select(watch_fds, [], [], min(0.1, rem))
                                if exec_state.wake_rfd in rlist:
                                    exec_state.drain_wake()
                                if master_fd in rlist:
                                    try:
                                        data = os.read(master_fd, 16384)
                                        if not data:
                                            break
                                        seq += 1
                                        if not self._emit_exec_chunk(
                                            stream_id, req_id, "stdout", seq, data, exec_state, deadline
                                        ):
                                            if deadline - time.monotonic() <= 0 and not self.closed and not exec_state.is_cancelled():
                                                timed_out = True
                                            exec_state.terminate_process_group()
                                            break
                                    except OSError:
                                        break
                                elif proc.poll() is not None:
                                    break
                            try:
                                os.close(master_fd)
                            except OSError:
                                pass
                            rc = exec_state.wait_proc()
                            exit_code = 124 if timed_out else (128 - rc if rc < 0 else rc)
                        else:
                            proc = subprocess.Popen(
                                cmd,
                                stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                cwd=cwd,
                                env=env,
                                preexec_fn=preexec,
                                start_new_session=True,
                            )
                            if not exec_state.attach_process(proc):
                                for pipe_obj in (proc.stdin, proc.stdout, proc.stderr):
                                    if pipe_obj is not None:
                                        try:
                                            pipe_obj.close()
                                        except Exception:
                                            pass
                                exec_state.wait_proc()
                                return

                            out_fd = proc.stdout.fileno()
                            err_fd = proc.stderr.fileno()
                            read_fds = {out_fd: ("stdout", proc.stdout), err_fd: ("stderr", proc.stderr)}
                            stdin_view = memoryview(stdin_bytes) if stdin_bytes else None
                            stdin_offset = 0
                            stdin_fd = None
                            if proc.stdin is not None:
                                if stdin_view is not None and len(stdin_view) > 0:
                                    stdin_fd = proc.stdin.fileno()
                                    fl = fcntl.fcntl(stdin_fd, fcntl.F_GETFL)
                                    fcntl.fcntl(stdin_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
                                else:
                                    proc.stdin.close()

                            while read_fds or stdin_fd is not None:
                                if self.closed or exec_state.is_cancelled():
                                    exec_state.terminate_process_group()
                                    break
                                rem = deadline - time.monotonic()
                                if rem <= 0:
                                    timed_out = True
                                    exec_state.terminate_process_group()
                                    break
                                r_candidates = list(read_fds.keys())
                                if exec_state.wake_rfd >= 0:
                                    r_candidates.append(exec_state.wake_rfd)
                                w_candidates = [stdin_fd] if stdin_fd is not None else []
                                rlist, wlist, _ = select.select(
                                    r_candidates, w_candidates, [], min(0.1, rem)
                                )
                                if exec_state.wake_rfd in rlist:
                                    exec_state.drain_wake()
                                    if self.closed or exec_state.is_cancelled():
                                        exec_state.terminate_process_group()
                                        break
                                if wlist and stdin_fd is not None and stdin_view is not None:
                                    try:
                                        written = os.write(stdin_fd, stdin_view[stdin_offset : stdin_offset + MAX_CHUNK_BYTES])
                                        stdin_offset += written
                                        if stdin_offset >= len(stdin_view):
                                            proc.stdin.close()
                                            stdin_fd = None
                                    except BlockingIOError:
                                        pass
                                    except OSError:
                                        try:
                                            proc.stdin.close()
                                        except Exception:
                                            pass
                                        stdin_fd = None
                                aborted_emit = False
                                for rfd in rlist:
                                    entry = read_fds.get(rfd)
                                    if entry is None:
                                        continue
                                    stream_label, pipe_obj = entry
                                    try:
                                        chunk = os.read(rfd, MAX_CHUNK_BYTES)
                                    except OSError:
                                        chunk = b""
                                    if not chunk:
                                        read_fds.pop(rfd, None)
                                        try:
                                            pipe_obj.close()
                                        except Exception:
                                            pass
                                    else:
                                        seq += 1
                                        if not self._emit_exec_chunk(
                                            stream_id, req_id, stream_label, seq, chunk, exec_state, deadline
                                        ):
                                            if deadline - time.monotonic() <= 0 and not self.closed and not exec_state.is_cancelled():
                                                timed_out = True
                                            exec_state.terminate_process_group()
                                            aborted_emit = True
                                            break
                                if aborted_emit:
                                    break

                            if stdin_fd is not None and proc.stdin is not None:
                                try:
                                    proc.stdin.close()
                                except Exception:
                                    pass
                            for _, (_, pipe_obj) in list(read_fds.items()):
                                try:
                                    pipe_obj.close()
                                except Exception:
                                    pass
                            rc = exec_state.wait_proc()
                            exit_code = 124 if timed_out else (128 - rc if rc < 0 else rc)
                    except FileNotFoundError as fnf:
                        if not self.closed and not exec_state.is_cancelled():
                            seq += 1
                            self._emit_exec_chunk(
                                stream_id, req_id, "stderr", seq, f"{fnf}\n".encode("utf-8"), exec_state, None
                            )
                        exit_code = 127
                    except Exception as exc:
                        if not self.closed and not exec_state.is_cancelled():
                            seq += 1
                            self._emit_exec_chunk(
                                stream_id, req_id, "stderr", seq, f"{exc}\n".encode("utf-8"), exec_state, None
                            )
                        exit_code = 1

                    if self.closed or exec_state.is_cancelled():
                        return

                    elapsed_ms = max(1, int((time.monotonic() - started) * 1000.0))
                    done = {
                        "requestID": req_id,
                        "exitCode": int(exit_code),
                        "durationMilliseconds": elapsed_ms,
                        "timedOut": timed_out,
                    }
                    self.send_frame(
                        CHAN_EXEC_PROCESS,
                        FLAG_FIN | FLAG_END_OF_MESSAGE,
                        stream_id,
                        json.dumps(done).encode("utf-8"),
                    )
                finally:
                    with self.state_lock:
                        if self.active_execs.get(stream_id) is exec_state:
                            self.active_execs.pop(stream_id, None)
                        self.peer_window.pop(stream_id, None)
                        self.uncredited_rx.pop(stream_id, None)
                    exec_state.close_wake_pipe()

            def _emit_exec_chunk(
                self,
                stream_id: int,
                req_id: str,
                stream_name: str,
                seq: int,
                data: bytes,
                exec_state: ExecStreamState = None,
                deadline: float = None,
            ) -> bool:
                if self.closed or (exec_state is not None and exec_state.is_cancelled()):
                    return False
                chunk_env = {
                    "requestID": req_id,
                    "stream": stream_name,
                    "sequence": seq,
                    "data": base64.b64encode(data).decode("ascii"),
                    "timestamp": time.time(),
                }
                encoded = json.dumps(chunk_env).encode("utf-8")
                cost = len(encoded)
                with self.window_cond:
                    while not self.closed and not (exec_state is not None and exec_state.is_cancelled()):
                        avail = self.peer_window.get(stream_id, DEFAULT_WINDOW_CREDIT)
                        if avail > 0:
                            self.peer_window[stream_id] = max(0, avail - cost)
                            break
                        wait_sec = 0.1
                        if deadline is not None:
                            rem = deadline - time.monotonic()
                            if rem <= 0:
                                return False
                            wait_sec = min(0.1, rem)
                        self.window_cond.wait(timeout=wait_sec)
                    if self.closed or (exec_state is not None and exec_state.is_cancelled()):
                        return False
                self.send_frame(
                    CHAN_EXEC_PROCESS,
                    FLAG_ACK,
                    stream_id,
                    encoded,
                    compress=True,
                )
                return True

            # ---- Channel 2: File Transfer with SHA-256 Verification ----
            def _on_file_transfer(self, stream_id: int, flags: int, payload: bytes) -> None:
                if flags & FLAG_SYN:
                    ctrl = json.loads(payload.decode("utf-8"))
                    phase = ctrl.get("phase")
                    if phase == "pushBegin":
                        manifest = ctrl["manifest"]
                        dst = manifest["destinationPath"]
                        parent = os.path.dirname(dst) or "/"
                        os.makedirs(parent, exist_ok=True)
                        fd, tmp_path = tempfile.mkstemp(prefix=".agentvm-", dir=parent)
                        self.file_pushes[stream_id] = {
                            "manifest": manifest,
                            "fp": os.fdopen(fd, "wb"),
                            "tmp_path": tmp_path,
                            "hasher": hashlib.sha256(),
                        }
                    elif phase == "pullRequest":
                        threading.Thread(
                            target=self._serve_file_pull,
                            args=(stream_id, ctrl.get("requestedPath", "")),
                            daemon=True,
                        ).start()
                    return

                ctx = self.file_pushes.get(stream_id)
                if not ctx:
                    return
                if payload:
                    ctx["fp"].write(payload)
                    ctx["hasher"].update(payload)

                if flags & (FLAG_END_OF_MESSAGE | FLAG_FIN):
                    self.file_pushes.pop(stream_id, None)
                    ctx["fp"].close()
                    manifest = ctx["manifest"]
                    actual_sha = ctx["hasher"].hexdigest()
                    expected_sha = manifest["sha256Hex"].lower()

                    if actual_sha.lower() != expected_sha:
                        try:
                            os.unlink(ctx["tmp_path"])
                        except OSError:
                            pass
                        err_env = {
                            "phase": "transferError",
                            "manifest": manifest,
                            "errorMessage": f"SHA-256 mismatch: expected {expected_sha}, got {actual_sha}",
                        }
                        self.send_frame(
                            CHAN_FILE_TRANSFER,
                            FLAG_ERROR_FRAME | FLAG_FIN | FLAG_END_OF_MESSAGE,
                            stream_id,
                            json.dumps(err_env).encode("utf-8"),
                        )
                        return

                    dst = manifest["destinationPath"]
                    os.chmod(ctx["tmp_path"], int(manifest.get("posixPermissions", 0o644)))
                    os.replace(ctx["tmp_path"], dst)
                    ok_env = {"phase": "transferVerified", "manifest": manifest}
                    self.send_frame(
                        CHAN_FILE_TRANSFER,
                        FLAG_FIN | FLAG_END_OF_MESSAGE,
                        stream_id,
                        json.dumps(ok_env).encode("utf-8"),
                    )

            def _serve_file_pull(self, stream_id: int, src_path: str) -> None:
                if not src_path or not os.path.isfile(src_path):
                    err = {
                        "phase": "transferError",
                        "requestedPath": src_path,
                        "errorMessage": f"ENOENT: {src_path}",
                    }
                    self.send_frame(
                        CHAN_FILE_TRANSFER,
                        FLAG_ERROR_FRAME | FLAG_FIN | FLAG_END_OF_MESSAGE,
                        stream_id,
                        json.dumps(err).encode("utf-8"),
                    )
                    return

                st = os.stat(src_path)
                hasher = hashlib.sha256()
                with open(src_path, "rb") as fh:
                    while True:
                        blk = fh.read(1048576)
                        if not blk:
                            break
                        hasher.update(blk)

                manifest = {
                    "id": str(uuid.uuid4()),
                    "direction": "guestToHost",
                    "sourcePath": src_path,
                    "destinationPath": src_path,
                    "totalBytes": st.st_size,
                    "sha256Hex": hasher.hexdigest(),
                    "posixPermissions": stat.S_IMODE(st.st_mode),
                    "modifiedTimestamp": int(st.st_mtime),
                }
                hdr_env = {"phase": "pullManifest", "manifest": manifest}
                self.send_frame(
                    CHAN_FILE_TRANSFER,
                    FLAG_SYN | FLAG_ACK,
                    stream_id,
                    json.dumps(hdr_env).encode("utf-8"),
                    compress=True,
                )

                with open(src_path, "rb") as fh:
                    raw_bytes = fh.read()
                self.send_chunked_flow_controlled(
                    channel=CHAN_FILE_TRANSFER,
                    stream_id=stream_id,
                    data=raw_bytes,
                    final_flags=FLAG_ACK | FLAG_FIN | FLAG_END_OF_MESSAGE,
                    compress=True,
                )

            # ---- Channel 3: Localhost TCP Port-Forward Bridge ----
            def _on_port_forward(self, stream_id: int, flags: int, payload: bytes) -> None:
                if flags & FLAG_SYN:
                    req = json.loads(payload.decode("utf-8"))
                    guest_port = int(req["guestPort"])
                    try:
                        tcp_sock = socket.create_connection(("127.0.0.1", guest_port), timeout=3.0)
                        tcp_sock.settimeout(None)
                        with self.state_lock:
                            self.tcp_bridges[stream_id] = tcp_sock
                        ack = {
                            "action": "connectAck",
                            "guestPort": guest_port,
                            "sourceAddress": req.get("sourceAddress", "127.0.0.1"),
                            "sourcePort": req.get("sourcePort", 0),
                        }
                        self.send_frame(
                            CHAN_TCP_PORT_FORWARD,
                            FLAG_SYN | FLAG_ACK,
                            stream_id,
                            json.dumps(ack).encode("utf-8"),
                        )
                        threading.Thread(
                            target=self._pump_tcp_to_vsock,
                            args=(stream_id, tcp_sock),
                            daemon=True,
                        ).start()
                    except Exception as exc:
                        fail = {
                            "action": "connectFailed",
                            "guestPort": guest_port,
                            "sourceAddress": "127.0.0.1",
                            "sourcePort": 0,
                            "errorDetail": str(exc),
                        }
                        self.send_frame(
                            CHAN_TCP_PORT_FORWARD,
                            FLAG_SYN | FLAG_ACK | FLAG_ERROR_FRAME,
                            stream_id,
                            json.dumps(fail).encode("utf-8"),
                        )
                    return

                with self.state_lock:
                    tcp_sock = self.tcp_bridges.get(stream_id)
                if not tcp_sock:
                    return

                if payload:
                    try:
                        tcp_sock.sendall(payload)
                    except OSError:
                        pass

                if flags & FLAG_RST:
                    with self.state_lock:
                        self.tcp_bridges.pop(stream_id, None)
                    try:
                        tcp_sock.close()
                    except OSError:
                        pass
                elif flags & FLAG_FIN:
                    try:
                        tcp_sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            def _pump_tcp_to_vsock(self, stream_id: int, tcp_sock: socket.socket) -> None:
                try:
                    while not self.closed:
                        data = tcp_sock.recv(MAX_CHUNK_BYTES)
                        if not data:
                            break
                        self.send_chunked_flow_controlled(
                            channel=CHAN_TCP_PORT_FORWARD,
                            stream_id=stream_id,
                            data=data,
                            final_flags=FLAG_ACK,
                            compress=False,
                        )
                except OSError:
                    pass
                finally:
                    with self.state_lock:
                        self.tcp_bridges.pop(stream_id, None)
                    try:
                        tcp_sock.close()
                    except OSError:
                        pass
                    self.send_frame(
                        CHAN_TCP_PORT_FORWARD,
                        FLAG_FIN | FLAG_END_OF_MESSAGE,
                        stream_id,
                        b"",
                    )

            # ---- Channel 5: Interactive PTY Shell ----
            def _on_interactive_pty(self, stream_id: int, flags: int, payload: bytes) -> None:
                if flags & (FLAG_FIN | FLAG_RST):
                    with self.state_lock:
                        entry = self.pty_sessions.pop(stream_id, None)
                    if entry:
                        master_fd, proc = entry
                        try:
                            os.close(master_fd)
                        except OSError:
                            pass
                        try:
                            _terminate_pgroup_for_process(proc)
                        except Exception:
                            pass
                    return

                if not payload:
                    return
                opcode = payload[0]
                body = payload[1:]

                if opcode == PTY_OP_OPEN:
                    cols, rows = (120, 36)
                    if len(body) >= 4:
                        cols, rows = struct.unpack(">HH", body[:4])
                    self._ensure_pty_session(stream_id, cols, rows)
                elif opcode == PTY_OP_RESIZE:
                    if len(body) >= 4:
                        cols, rows = struct.unpack(">HH", body[:4])
                        master_fd, _ = self._ensure_pty_session(stream_id, cols, rows)
                        try:
                            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                        except OSError:
                            pass
                elif opcode == PTY_OP_STDIN:
                    master_fd, _ = self._ensure_pty_session(stream_id, 120, 36)
                    try:
                        os.write(master_fd, body)
                    except OSError:
                        pass

            def _ensure_pty_session(self, stream_id: int, cols: int, rows: int):
                with self.state_lock:
                    existing = self.pty_sessions.get(stream_id)
                    if existing is not None:
                        return existing

                master_fd, slave_fd = pty.openpty()
                fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                shell = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
                env = os.environ.copy()
                env["TERM"] = "xterm-256color"
                proc = subprocess.Popen(
                    [shell, "-i"],
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    cwd=self.default_workspace if os.path.isdir(self.default_workspace) else "/",
                    env=env,
                    start_new_session=True,
                    close_fds=True,
                )
                os.close(slave_fd)

                with self.state_lock:
                    self.pty_sessions[stream_id] = (master_fd, proc)

                threading.Thread(
                    target=self._pump_pty_stdout,
                    args=(stream_id, master_fd),
                    daemon=True,
                ).start()
                return (master_fd, proc)

            def _pump_pty_stdout(self, stream_id: int, master_fd: int) -> None:
                try:
                    while not self.closed:
                        data = os.read(master_fd, 16384)
                        if not data:
                            break
                        framed = bytes([PTY_OP_STDOUT]) + data
                        self.send_frame(CHAN_INTERACTIVE_PTY, FLAG_ACK, stream_id, framed)
                except OSError:
                    pass
                finally:
                    self.send_frame(CHAN_INTERACTIVE_PTY, FLAG_FIN | FLAG_END_OF_MESSAGE, stream_id, b"")


        def create_listener_socket(vsock_port: int, tcp_fallback: str):
            if tcp_fallback:
                host, port_str = tcp_fallback.rsplit(":", 1)
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((host, int(port_str)))
                srv.listen(16)
                return srv

            af_vsock = getattr(socket, "AF_VSOCK", 40)
            cid_any = getattr(socket, "VMADDR_CID_ANY", 0xFFFFFFFF)
            srv = socket.socket(af_vsock, socket.SOCK_STREAM)
            srv.bind((cid_any, vsock_port))
            srv.listen(16)
            return srv


        def main() -> int:
            parser = argparse.ArgumentParser(description="AgentVM VirtioSocket Guest Daemon")
            parser.add_argument("--port", type=int, default=\#(vsockPort), help="AF_VSOCK port (default: \#(vsockPort))")
            parser.add_argument("--heartbeat-interval", type=int, default=\#(heartbeatIntervalSeconds))
            parser.add_argument("--workspace", type=str, default="\#(defaultWorkspacePath)")
            parser.add_argument("--proc-root", type=str, default="/proc", help="Path to procfs root (default: /proc)")
            parser.add_argument("--tcp-fallback", type=str, default="", help="Optional host:port TCP listener for testing")
            args = parser.parse_args()

            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
            srv = create_listener_socket(args.port, args.tcp_fallback)
            sys.stdout.write(f"[agentvm-guestd] listening on port {args.port}\n")
            sys.stdout.flush()

            while True:
                try:
                    conn, _addr = srv.accept()
                    session = GuestVsockConnectionSession(
                        conn=conn,
                        heartbeat_interval=args.heartbeat_interval,
                        default_workspace=args.workspace,
                        proc_root=args.proc_root,
                    )
                    threading.Thread(target=session.run, daemon=True).start()
                except KeyboardInterrupt:
                    break
                except Exception as exc:
                    sys.stderr.write(f"[agentvm-guestd] accept error: {exc}\n")
                    time.sleep(0.25)
            return 0


        if __name__ == "__main__":
            sys.exit(main())
        """# + "\n"
    }
}
