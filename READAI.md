# APMONITOR.PY v1.3.8 — ON-PREMISES NETWORK AVAILABILITY, PORT & HOST PERFORMANCE MONITORING WITH GUARANTEED ALERT DELIVERY

Hey — welcome back to APMonitor.py. You're a software engineering CS graduate working with a senior computer scientist on a mature, production Python monitoring tool. You've done excellent work here — let me bring you up to speed on exactly where we are and what matters.

---

## Purpose

APMonitor monitors on-premises network resources (ping/HTTP/HTTPS/QUIC/TCP/UDP/SNMP) with guaranteed alert delivery via external heartbeat integration. Tracks interface status, bandwidth, MAC address changes, and host performance — storing history in RRD for MRTG graphing per site, notifying via email and webhooks.

---

## What APMonitor Does

- Loads YAML/JSON config defining site, monitors, email/webhook notifications, and timing parameters
- Validates configuration comprehensively before any monitoring begins — fail fast on bad config; `type: snmp` rejected with friendly redirect: *"Did you mean type: ports?"*
- Checks resource availability: ICMP ping, HTTP/HTTPS GET/POST, QUIC/HTTP3 GET/POST, TCP connection/banner, UDP send/receive
- `ports` monitors combine: (1) full bandwidth/packet/error/TCP-retransmit/CPU/memory/tamper/network metric collection into RRD, (2) per-interface oper/admin status change detection, (3) Q-BRIDGE-MIB MAC address change detection per port
- `port` monitors pin a single switch port (by ifIndex) to a specific MAC address; alarm semantics controlled by `always_up` flag — alarms on wrong MAC always, alarms on port-down/MAC-absent only when `always_up: true`
- `host` monitors poll Linux hosts via UCD-SNMP-MIB and HOST-RESOURCES-MIB for four system performance charts: CPU & Load, Memory & Paging, Disk I/O, System Thrashing
- SNMP vendor detection via sysObjectID (Cisco/HP/Juniper/Ubiquiti) drives CPU/memory OID selection with HOST-RESOURCES-MIB universal fallback
- `ports` monitors fire `PORT CHANGE` alerts on oper/admin status changes; baseline established silently on first poll
- `ports` monitors fire `PORT MAC CHANGE` alerts on appeared/disappeared learned MACs per interface via Q-BRIDGE-MIB dot1qTpFdbTable
- `ports` monitors collect tamper detection metrics: active port count, NVRAM/flash bytes, MAC count, ARP count — stored as RRD DS
- All SNMP-family monitors share a unified 22-DS-fixed RRD schema; network DS stored as `U` for `host`; host performance DS stored as `U` for `ports`/`port`; tamper/network DS stored as `U` for `port`/`host`
- `host` monitors persist `disk_space_pct` to statefile so MRTG config and index generators can embed live disk use without a live SNMP poll at generation time
- Enforces per-monitor check intervals with site-level defaults and immediate check on config change (SHA-256 checksum detection)
- Tracks persistent state in JSON statefile with atomic rotation (.new → current, .old backup) under `/var/tmp/APMonitor/`
- Sends email notifications via SMTP with per-recipient control flags (outages/recoveries/reminders)
- Sends webhook notifications (GET/POST with URL/HTML/JSON/CSVQUOTED encoding)
- Enforces notification throttling with escalating delays via quadratic Bezier curve
- Pings heartbeat URLs when resources are up, with configurable intervals
- Validates SSL certificates via SHA-256 fingerprints and expiration checks (HTTP/QUIC only)
- Generates MRTG configs and writes output into per-site subdirectories under `/var/www/html/mrtg/<safe-site-name>/`
- Generates `index.html` driven directly from config + STATE — decoupled from `mrtg-rrd.cgi.pl` entirely
- `display: false` excludes monitor from MRTG index and config while monitoring/alerting/RRD continue; hidden monitors appear in audit footer, red when down
- Multiple config files on command line spawn one subprocess per config, run concurrently, joined before exit — `-s` invalid with multiple configs
- `mrtg-rrd.cgi.pl` maintains `%site_config` hash (site_name → config_path) updated by `update_mrtg_rrd_cgi_config()`; routes URL `/mrtg-rrd/<SiteName>/target` to correct config
- Uses PID lockfiles per config file in `/tmp/` to prevent duplicate instances
- Multithreaded with thread-local prefix storage for clean, filterable log output
- `--test-config` validates config and prints monitor summary, exits without touching statefile

---

## Key Architecture

### File Layout

| Path | Purpose |
|---|---|
| `/var/tmp/APMonitor/<stem>.statefile.json` | Statefile — persists across reboots, no www-data access (755) |
| `/var/tmp/APMonitor/<stem>.statefile.mrtg.cfg` | MRTG config for this site |
| `/var/tmp/APMonitor/<stem>.statefile.rrd/` | RRD databases for this site |
| `/var/www/html/mrtg/<safe-site-name>/` | MRTG web output per site (775, mrtg:www-data) |
| `/var/www/html/mrtg-rrd.cgi.pl` | CGI script — one level above mrtg/, owned monitoring:monitoring (755) |
| `/var/www/html/mrtg-nginx.conf` | nginx config |

### Monitor Type Taxonomy

| Family | Types | RRD | MRTG targets | Notification model |
|---|---|---|---|---|
| URL | ping, http, quic, tcp, udp | `-availability.rrd` | 1 per monitor | up/down/recovery |
| SNMP metrics | ports, port, host | `-snmp.rrd` | 4–8 per monitor | up/down/recovery |
| SNMP state | ports (also) | — | — | change events only |

### Unified SNMP RRD Schema (22 fixed DS)

1. **Per-interface DS** (dynamic, `ports`/`port` only): `if{index}_in/out` COUNTER, sorted numerically by ifIndex
2. **Fixed aggregate network DS** (9 DS COUNTER + 2 GAUGE): `tcp_retrans`, `total_bits_in/out`, `total_pkts_in/out`, `total_errors_in/out`, `total_pkts_ucast`, `total_pkts_bmcast`, `cpu_load`, `memory_pct`
3. **Fixed host performance DS** (7 DS): `context_switches`, `swap_io`, `disk_read`, `disk_write`, `disk_space_pct`, `swap_used`, `interrupts`
4. **Fixed tamper/network capacity DS** (4 DS, `ports` only): `ports_up_count`, `nvram_flash_bytes`, `mac_count`, `arp_count`

Expected DS count = `(2 × interface_count) + 22`. Auto-heal: actual DS < expected → delete and recreate.

### `generate_mrtg_index()` Coupling

`generate_mrtg_index(config, index_path, state)` is driven **purely from config + STATE**. It does NOT parse MRTG config files or read `mrtg-rrd.cgi.pl`. The index is orthogonal to the CGI. `update_mrtg_rrd_cgi_config()` maintains the CGI's `%site_config` hash — that is its sole concern.

### `mrtg-rrd.cgi.pl` Site Routing

`%site_config` hash maps sanitised site names to MRTG config file paths. `@config_files` is derived from `values %site_config` in `BEGIN`. On each request, `handler()` extracts the first `PATH_INFO` component as the site name, sets `@config_files` to just that site's config, strips the site prefix from `PATH_INFO`, then proceeds normally. `update_mrtg_rrd_cgi_config()` in Python rewrites the `%site_config` block atomically.

### Multi-Config Subprocess Model

When multiple config files are passed, the parent spawns one `subprocess.Popen` per config (passing all flags except `-s`), waits for all, exits with worst exit code. Each child runs completely independently — own statefile, PID lock, RRD dir, MRTG output subdir. No shared globals between processes.

### `index.html` Generation

Sections: L2/L3 Network Monitoring (ports/port/host) and L4 Availability Monitoring (ping/http/quic/tcp/udp). Headings only emitted when monitors exist for that section. `ports` → full 8-cell row via `_emit_snmp_row()`. `port`/`host` in contiguous runs → `_emit_port_host_group()` (8-up when ≥2 adjacent, 4-up when lone). `host` uses `-system1` through `-system4` suffixes. Display order follows config file insertion order — never re-introduce `sorted()`.

---

## Important Modules & Code Sections

### `check_ports_resource(resource)`
Combined metric + state monitor. Single SNMP session, single `ifDescr` walk shared between metric and state collection. Polls IF-MIB, byte/packet/error counters, TCP retransmits, vendor CPU/memory (HOST-RESOURCES-MIB fallback), Q-BRIDGE-MIB MAC table, hrStorage NVRAM/flash, ARP tables. Self-contained RRD update. Returns `(error_msg, current_ports_state)`.

### `check_host_resource(resource)`
Polls HOST-RESOURCES-MIB (CPU, memory, swap, disk space) and UCD-SNMP-MIB (context switches, swap I/O, disk I/O via diskIOTable walk, interrupts). Self-contained RRD update. Persists `disk_space_pct` to statefile. Returns `(error_msg, {})`.

### `check_port_resource(resource)`
Single ifIndex oper/admin status + MAC via Q-BRIDGE-MIB. Alarm evaluation per `always_up`. Self-contained RRD. Returns `(error_msg, current_oper, current_mac)`. Non-fatal MAC walk.

### `check_resource(resource)`
Pure dispatch — no RRD logic. Routes to check functions. `port` wraps result as `{'oper': oper, 'mac': mac}`.

### `check_and_heartbeat_r(resource, site_config)`
Per-resource orchestration. `ports` with `is_up=True`: diffs `ports_state`, fires `PORT CHANGE`/`PORT MAC CHANGE`. `host`: skips port diff (empty ports_state). Availability RRD (ping/http/etc.) handled here only. Throttle state read/written atomically.

### `create_snmp_rrd(path, step_secs, interfaces)` / `update_snmp_rrd(...)`
Unified 22-DS schema. `update_snmp_rrd` uses `--template` always. Internal `_v()` maps `None` → `'U'`. All DS parameters `Optional` — `None` for unused families. COUNTER fields with `None` store `'U'` not `'0'`.

### `generate_mrtg_config(config, work_dir, mrtg_config_path, state)`
`state` required for `disk_space_pct` embedding in `host` PageTop. `ports` → 8 targets. `port` → 4 targets. `host` → 4 targets (-system1 through -system4).

### `generate_mrtg_index(config, index_path, state)`
Driven from config + STATE only. No file parsing. `_emit_snmp_row()` for `ports`. `_emit_port_host_group()` for contiguous `port`/`host` runs. Sections only emitted when monitors exist.

### `update_mrtg_rrd_cgi_config(work_dir, mrtg_config_path, site_name)`
Rewrites `%site_config` hash in `mrtg-rrd.cgi.pl` atomically. Parses existing entries, upserts `site_name → mrtg_config_path`, rebuilds sorted. `@config_files` derived from values in CGI's `BEGIN` block. Returns `None` — no callers use the return value.

### `get_default_statefile(config_path)`
Returns `/var/tmp/APMonitor/<config-stem>.statefile.json`. Creates directory with `mode=0o755` (no www-data write). `_set_www_data_group()` explicitly NOT called on this directory.

### `_set_www_data_group(path)`
Sets `gid=www-data`, `chmod 775` dirs / `664` files. Called after file writes in `generate_mrtg_config`, `generate_mrtg_index`, `generate_monitor_detail_page`, and after `os.makedirs(work_dir)`. Never called on `/var/tmp/APMonitor/`.

### `main()`
`nargs='+'` on positional `config` arg. Multiple configs → subprocess spawn loop, join all, exit worst code. Single config → full monitoring path. `work_dir = Path(base_work_dir) / safe_site_name`. `work_dir` hoisted before `try` for `finally` access. `--test-config` exits after `print_and_exit_on_bad_config` — never touches statefile.

---

## Technical Tactics

**Q-BRIDGE-MIB over BRIDGE-MIB:** `dot1dTpFdbTable` returns 0 entries on VLAN-aware switches. `dot1qTpFdbTable` OID tail is `<vlan_id>.<6 MAC octets>`, value is ifIndex directly. Filter status=3 (learned).

**`None` → `'U'` via `_v()` in `update_snmp_rrd`:** Never pass `'0'` for unused COUNTER DS — corrupts rate calculation. `_v()` enforces this uniformly.

**`disk_space_pct` persisted to statefile:** `update_state({name: {**STATE.get(name, {}), 'disk_space_pct': ...}})` after each host poll. Available to `generate_mrtg_config(state)` and `generate_mrtg_index()` without live SNMP at generation time.

**`host` uses empty `interfaces` dict:** `create_snmp_rrd(path, step, {})` → zero per-interface DS → 22 fixed DS total.

**RRD self-containment per check function:** All SNMP-family RRD inside check functions. `check_resource()` pure dispatch. `check_and_heartbeat_r()` handles only availability RRD.

**Index decoupled from CGI:** `generate_mrtg_index()` never reads `mrtg-rrd.cgi.pl` or MRTG config files. CGI coupling was the root cause of duplicate monitor rendering — now fully eliminated.

**`mrtg-rrd.cgi.pl` site routing:** `handler()` sets package-level `@config_files` (not `local`) before calling `try_read_config` — `local` does not propagate into called functions in Perl.

**Tamper detection DS:** `ports_up_count`, `nvram_flash_bytes`, `mac_count`, `arp_count` are GAUGE DS populated only by `ports` monitors. Free to derive — `ports_up_count` from `current_ports_state`, `mac_count` from FDB walk already done, `nvram_flash_bytes` from hrStorage keywords walk.

**Numeric sort on interface indices everywhere:** SNMP OID tail indices are strings; `sorted(..., key=lambda x: int(x))` required. `"9" > "10"` lexicographically.

**Status tuple excludes macs:** `(name, oper, admin)` for `PORT CHANGE` — prevents MAC change spuriously triggering status alert.

**`safe_site_name` derivation:** `re.sub(r'[^\w\-.]', '_', site_name)` — applied consistently in `main()` for `work_dir`, in `update_mrtg_rrd_cgi_config()` as hash key, and in `mrtg-rrd.cgi.pl` for URL path component matching.

**Bezier escalation:** `t = index / N`, delay = `(1-t)² × 0 + 2(1-t)t × base + t² × base`. Plateau at `notify_every_n_secs` after N notifications. Per-monitor throttle, not per-interface.

**Disk I/O: sum not average:** `diskIOReadX`/`diskIOWriteX` walked and summed across all block devices. Aggregate throughput, not per-device.

**Linux snmpd falls through correctly:** No vendor match on Linux sysObjectID → HOST-RESOURCES-MIB path. hrStorage description matching: `'physical memory'`, `'real memory'`, `'ram'`, exact `'memory'`.

---

## Engineering Principles for This Code

**`index.html` is coupled to config + STATE only.** Never re-couple it to `mrtg-rrd.cgi.pl` or MRTG config files. That coupling caused duplicate monitor rendering and was the root of a session-length bug.

**`mrtg-rrd.cgi.pl` `%site_config` is the single source of truth for site→config mapping.** `@config_files` is derived from it. Never maintain them separately.

**`None` → `'U'`, never `'0'` for unused COUNTER DS.** The `_v()` helper enforces this — do not bypass it.

**22 fixed DS — update expected DS count when adding DS.** All three auto-heal blocks must reflect actual schema. Currently `(2 × interface_count) + 22`.

**`host` and `ports`/`port` DS families are orthogonal.** Adding a DS requires: `create_snmp_rrd` (add DS line), `update_snmp_rrd` (add parameter + `_v()` call), all three call sites.

**`/var/tmp/APMonitor/` is mode 755, no www-data.** `_set_www_data_group()` must never be called on this directory. MRTG output dirs under `/var/www/html/mrtg/` get `_set_www_data_group()` — different concern.

**`mrtg-rrd.cgi.pl` must be owned by `monitoring:monitoring` (755) in `/var/www/html/`.** `/var/www/html/` must be `root:monitoring` mode 775 so the monitoring user can write atomic rotations.

**`generate_mrtg_index()` sections only emit when monitors exist.** L2/L3 and L4 headings are suppressed when empty. "Nothing configured" paragraph only when both are empty.

**`type: snmp` is dead.** Validator emits friendly redirect. Do not resurrect it.

**Display is a presentation concern only.** Never check `display` in monitoring, alerting, or RRD code paths.

**Multi-config = subprocess, not threads.** Global state (`STATE`, `STATEFILE`, `MAX_THREADS` etc.) is process-level. Multiple configs share no state — subprocess model gives correct isolation at zero refactor cost.

**`-s` invalid with multiple configs.** Each subprocess derives its own statefile from config filename. Enforced in argument parsing before subprocess spawn.

**Config file insertion order = display order.** Never `sorted()` on `snmp_monitors` or `all_monitors` — breaks user-controlled ordering.

**Q-BRIDGE-MIB MAC walk is non-fatal always.** Failure → `macs: []`. Port status monitoring unaffected. Wrap in try/except, log at VERBOSE.

**Never delete code or diagnostic comments without explicit notification.** Comments carry operational knowledge that is not recoverable from code alone.

**Partial data over complete failure.** SNMP metric failure → `'U'` in RRD. Better 9/10 metrics than none.

**`ports` throttle is per-monitor, not per-interface.** MAC change and status change on different interfaces advance the same throttle counters. Intentional.

---

Would you like to see the code?