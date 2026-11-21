# AgentVM M3 APFS CoW Branch Benchmark (`m3-branch-bench`)

- **Status**: `PASS` (`0` failure(s))
- **Date**: `2026-11-21` (`2026-11-20T23:46:16Z`)
- **Script**: `Scripts/acceptance/m3-branch-bench.sh` (commit `5793108`)
- **Host**: `Mac16,10` (`Apple M4`, 10 cores, 16 GiB RAM), macOS `27.0.1` (`26A434`), APFS
- **Host load average (`1m 5m 15m`)**: start `1.77 2.24 2.39` -> end `1.98 2.53 2.51`
- **Parent VM (`p`)**: `debian-12-bookworm-arm64` expanded to `8 GiB` (`8589934592` B), 2 vCPU, 2048 MiB RAM, populated with `1 GiB` (`1073741824` B) random file `/var/tmp/bench-data.bin` + marker `/root/bench-marker`, `sync`ed
- **Max concurrent VMs observed**: `1` (cap `<= 2`)

## Summary Metrics

| Metric | Value | Notes |
|---|---:|---|
| **Stopped fork wall-clock median (`X`)** | **`32.49 ms`** | 16 runs of `agentvm branch p sc<i>` (min `26.48 ms`, nearest-rank p95 `58.26 ms`, max `58.26 ms`; provisional threshold `<= 500 ms`) |
| Stopped fork CLI self-reported median | `13.52 ms` | Lock acquired to SQLite commit (p95 `38.88 ms`) |
| **Live running fork wall-clock median** | **`115.31 ms`** | 16 runs of `agentvm branch p lc<i>` via workspace daemon (min `102.90 ms`, nearest-rank p95 `164.82 ms`) |
| Live running fork VM pause median | `0.603 ms` | `VM_PAUSED_FOR_SNAPSHOT` (`pause` -> `clonefile` root disk & NVRAM -> `resume`; min `0.571 ms`, p95 `0.796 ms`) |
| Live running fork guest pre-pause `sync` median | `1.004 ms` | Guest `/bin/sync` via vsock before `pause` (p95 `40.042 ms`) |
| **New cloned files APFS private bytes (`Y`)** | **`0 B`** | `getattrlist(ATTR_CMNEXT_PRIVATESIZE)` across all 32 forks (parent fork-point `.raw`, child root `.raw`, child head `.raw`, child `.nvram`); excludes APFS filesystem metadata & synthesized `cidata` ISO (`114688 B`) / `.machineid` (`70 B`) |
| Volume `df -k` delta (16 stopped / 16 live forks) | `7256 KB` / `7936 KB` | Host-wide volume available-space delta (`dfBefore - dfAfter`); upper bound under concurrent host activity |
| Child root disk APFS private bytes after 1st boot + halt | `6131712 B (5.85 MiB)` | Median across 32 booted children (min `5337088 B`, p95 `6922240 B`) |
| 32 children + parent identity verification | `33 / 33 unique (5 items)` | `hostname`, `/etc/machine-id`, `instance-id`, NIC MAC, SSH ED25519 fingerprint pairwise distinct across 33 VMs; concurrent IPv4 collisions `0` (unique sequential DHCP IPv4s `31/33`, sequential lease reuses `2`) |
