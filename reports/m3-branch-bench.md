# AgentVM M3 APFS CoW Branch Benchmark (`m3-branch-bench`)

- **Date**: `2026-11-21` (`2026-11-20T21:36:20Z`)
- **Script**: `Scripts/acceptance/m3-branch-bench.sh` (commit `5ee1b30`)
- **Host**: `Mac16,10` (`Apple M4`, 10 cores, 16 GiB RAM), macOS `27.0.1` (`26A434`), APFS
- **Parent VM (`p`)**: `debian-12-bookworm-arm64` expanded to `8 GiB` (`8589934592` B), 2 vCPU, 2048 MiB RAM, populated with `1 GiB` (`1073741824` B) random file `/var/tmp/bench-data.bin` + marker `/root/bench-marker`, `sync`ed
- **Max concurrent VMs observed**: `1` (cap `<= 2`)

## Summary Metrics

| Metric | Value | Notes |
|---|---:|---|
| **Stopped fork wall-clock median (`X`)** | **`206.43 ms`** | 16 runs of `agentvm branch p sc<i>` (min `38.49 ms`, nearest-rank p95 `8856.64 ms`, max `8856.64 ms`; provisional threshold `<= 500 ms`) |
| Stopped fork CLI self-reported median | `188.38 ms` | Lock acquired to SQLite commit (p95 `8835.84 ms`) |
| **Live running fork wall-clock median** | **`116.61 ms`** | 16 runs of `agentvm branch p lc<i>` via workspace daemon (min `108.48 ms`, nearest-rank p95 `196.11 ms`) |
| Live running fork VM pause median | `0.683 ms` | `VM_PAUSED_FOR_SNAPSHOT` (`pause` -> `clonefile` root disk & NVRAM -> `resume`; min `0.611 ms`, p95 `1.012 ms`) |
| Live running fork guest pre-pause `sync` median | `1.011 ms` | Guest `/bin/sync` via vsock before `pause` (p95 `57.923 ms`) |
| **New cloned files APFS private bytes (`Y`)** | **`0 B`** | `getattrlist(ATTR_CMNEXT_PRIVATESIZE)` across all 32 forks (parent fork-point `.raw`, child root `.raw`, child head `.raw`, child `.nvram`); excludes APFS filesystem metadata & synthesized `cidata` ISO (`114688 B`) / `.machineid` (`70 B`) |
| Volume `df -k` delta (16 stopped / 16 live forks) | `232900 KB` / `116352 KB` | Host-wide volume available-space delta (`dfBefore - dfAfter`); upper bound under concurrent host activity |
| Child root disk APFS private bytes after 1st boot + halt | `6154240 B` (`5.87 MiB`) | Median across 32 booted children (min `5345280 B`, p95 `6909952 B`) |
| 32 children + parent 6-item identity uniqueness | `33 / 33 unique` | `hostname`, `/etc/machine-id`, `instance-id`, NIC MAC, DHCP IPv4, SSH ED25519 fingerprint all pairwise distinct |
