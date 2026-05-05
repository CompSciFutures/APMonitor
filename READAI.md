# APMONITOR.PY v1.4.0 — ON-PREMISES NETWORK AVAILABILITY, PORT & HOST PERFORMANCE MONITORING WITH GUARANTEED ALERT DELIVERY

Hey — welcome back. You're a software engineering CS graduate working with a senior computer scientist on APMonitor.py, a mature production network monitoring tool. You've done excellent work here — let me bring you up to speed precisely.

---

## Purpose

APMonitor monitors on-premises network resources (ping/HTTP/HTTPS/QUIC/TCP/UDP/SNMP) with guaranteed alert delivery via external heartbeat integration. Tracks interface status, bandwidth, MAC changes, host performance, and packet size distribution — storing history in RRD for MRTG graphing, notifying via email and webhooks.

---

## What APMonitor Does

- Loads YAML/JSON config defining site, monitors, email/webhook notifications, and timing parameters
- Validates configuration comprehensively before any monitoring begins — fail fast on bad config; `type: snmp` rejected with friendly redirect: *"Did you mean type: ports?"*
- Checks resource availability: ICMP ping, HTTP/HTTPS GET/POST, QUIC/HTTP3 GET/POST, TCP connection/banner, UDP send/receive
- `ports` monitors combine: (1) full bandwidth/packet/error/TCP-retransmit/CPU/memory/tamper/network metric collection into RRD, (2) per-interface oper/admin status change detection, (3) Q-BRIDGE-MIB MAC address change detection per port
- `switch` monitors are identical to `ports` in polling and alerting, but generate 5 stacked per-interface MRTG charts (bandwidth/packets/bmcast/errors per port + RMON packet size distribution) via `ExtraArgs[]` directive in MRTG config
- `switch` monitors additionally collect RMON-MIB `etherStatsTable` packet size distribution (7 buckets: 64, 65–127, 128–255, 256–511, 512–1023, 1024–1518, jumbo) summed aggregate across all ports — 7 additional fixed COUNTER DS
- `port` monitors pin a single switch port (by ifIndex) to a specific MAC address; alarm semantics controlled by `always_up` flag
- `host` monitors poll Linux hosts via UCD-SNMP-MIB and HOST-RESOURCES-MIB for four system performance charts: CPU & Load, Memory & Paging, Disk I/O, System Thrashing
- SNMP vendor detection via sysObjectID (Cisco/HP/Juniper/Ubiquiti) drives CPU/memory OID selection with HOST-RESOURCES-MIB universal fallback
- `ports`/`switch` monitors fire `PORT CHANGE` alerts on oper/admin status changes; baseline established silently on first poll
- `ports`/`switch` monitors fire `PORT MAC CHANGE` alerts on appeared/disappeared learned MACs per interface via Q-BRIDGE-MIB dot1qTpFdbTable
- `ports`/`switch` monitors collect tamper detection metrics: active port count, NVRAM/flash bytes, MAC count, ARP count — stored as RRD DS
- All SNMP-family monitors share a unified **29-DS-fixed** RRD schema; network DS stored as `U` for `host`; host performance DS stored as `U` for `ports`/`port`/`switch`; tamper DS stored as `U` for `port`/`host`; RMON DS stored as `U` for `ports`/`port`/`host`
- `host` monitors persist `disk_space_pct` to statefile so MRTG config and index generators can embed live disk use without a live SNMP poll at generation time
- Detects config file changes via raw byte comparison against `.previous` cache; fires one-shot notification on change; silent on first run
- Enforces per-monitor check intervals with site-level defaults and immediate check on config change (SHA-256 checksum detection)
- Tracks persistent state in JSON statefile with atomic rotation (.new → current, .old backup) under `/var/tmp/APMonitor/`
- Sends email notifications via SMTP with per-recipient control flags (outages/recoveries/reminders)
- Sends webhook notifications (GET/POST with URL/HTML/JSON/CSVQUOTED encoding)
- Enforces notification throttling with escalating delays via quadratic Bezier curve
- Pings heartbeat URLs when resources are up, with configurable intervals
- Validates SSL certificates via SHA-256 fingerprints and expiration checks (HTTP/QUIC only)
- Generates MRTG configs and writes output into per-site subdirectories under `/var/www/html/mrtg/<safe-site-name>/`
- `switch` MRTG charts use `ExtraArgs[]` directive — `mrtg-rrd.cgi.pl` appends these verbatim to `RRDs::graph` — to render stacked AREA/STACK per-interface graphs; `noi,noo` Options suppresses default in/out lines
- `PageFoot[]` in switch MRTG targets renders per-interface or per-bucket colour legend table below each chart — handled natively by `do_html()` in `mrtg-rrd.cgi.pl`
- Generates `index.html` driven directly from config + STATE — decoupled from `mrtg-rrd.cgi.pl` entirely
- Generates per-monitor detail HTML pages for `ports`/`port`/`host` monitors with system info, interface table, LLDP/CDP neighbours, and MAC/IP/PTR hostname table
- `display: false` excludes monitor from MRTG index and config while monitoring/alerting/RRD continue; hidden monitors appear in audit footer, red when down
- Multiple config files on command line spawn one subprocess per config, run concurrently, joined before exit — `-s` invalid with multiple configs
- `mrtg-rrd.cgi.pl` maintains `%site_config` hash (site_name → config_path) updated by `update_mrtg_rrd_cgi_config()`; routes URL `/mrtg-rrd/<SiteName>/target` to correct config
- Uses PID lockfiles per config file in `/tmp/` to prevent duplicate instances
- Multithreaded with thread-local prefix storage for clean, filterable log output
- `--test-config` validates config and prints monitor summary, exits without touching statefile
- `fcgiwrap` configured with `StandardError=journal` via systemd drop-in so Perl CGI `warn` output reaches `journalctl -u fcgiwrap`

---

## Key Architecture

### File Layout

| Path | Purpose |
|---|---|
| `/var/tmp/APMonitor/<stem>.statefile.json` | Statefile — persists across reboots, no www-data access (755) |
| `/var/tmp/APMonitor/<stem>.statefile.mrtg.cfg` | MRTG config for this site |
| `/var/tmp/APMonitor/<stem>.statefile.rrd/` | RRD databases for this site |
| `/var/tmp/APMonitor/<config-filename>.previous` | Raw config bytes cache for change detection |
| `/var/www/html/mrtg/<safe-site-name>/` | MRTG web output per site (775, mrtg:www-data) |
| `/var/www/html/mrtg/<safe-site-name>/index.html` | Master monitoring index — generated by APMonitor |
| `/var/www/html/mrtg/<safe-site-name>/<type>-<name>-detail.html` | Per-monitor detail pages |
| `/var/www/html/mrtg-rrd.cgi.pl` | CGI script — one level above mrtg/, owned monitoring:monitoring (755) |
| `/etc/systemd/system/fcgiwrap.service.d/logging.conf` | fcgiwrap journald logging drop-in |

### Monitor Type Taxonomy

| Family | Types | RRD | MRTG targets | Notification model |
|---|---|---|---|---|
| URL | ping, http, quic, tcp, udp | `-availability.rrd` | 1 per monitor | up/down/recovery |
| SNMP metrics | ports, port, host, switch | `-snmp.rrd` | 4–8 per monitor | up/down/recovery |
| SNMP state | ports, switch (also) | — | — | change events only |

### Unified SNMP RRD Schema (29 fixed DS + 4 per interface)

1. **Per-interface DS quads** (dynamic, `ports`/`port`/`switch` only): `if{N}_in`, `if{N}_out`, `if{N}_bmcast`, `if{N}_errors` COUNTER — sorted numerically by ifIndex
2. **Fixed aggregate network DS** (9 DS): `tcp_retrans`, `total_bits_in/out`, `total_pkts_in/out`, `total_errors_in/out`, `total_pkts_ucast`, `total_pkts_bmcast` COUNTER
3. **System resource DS** (2 DS): `cpu_load`, `memory_pct` GAUGE
4. **Fixed host performance DS** (7 DS): `context_switches`, `swap_io`, `disk_read`, `disk_write` COUNTER; `disk_space_pct`, `swap_used` GAUGE; `interrupts` COUNTER
5. **Fixed tamper/network capacity DS** (4 DS, `ports`/`switch` only): `ports_up_count`, `nvram_flash_bytes`, `mac_count`, `arp_count` GAUGE
6. **Fixed RMON packet size distribution DS** (7 DS, `switch` only): `pkts_64`, `pkts_65_127`, `pkts_128_255`, `pkts_256_511`, `pkts_512_1023`, `pkts_1024_1518`, `pkts_jumbo` COUNTER

**Expected DS count = `(4 × interface_count) + 29`.** Auto-heal: actual DS < expected → delete and recreate RRD.

### `switch` vs `ports` Distinction

`switch` and `ports` use identical `check_ports_resource()`. Differentiated only in:
- MRTG config generation: `switch` → `_generate_switch_mrtg_targets()` (5 stacked charts); `ports` → 8 standard charts
- RMON collection: gated `if resource['type'] == 'switch'` inside `check_ports_resource()`
- `generate_mrtg_index()`: `switch` → `_emit_switch_row()` (5-cell grid); `ports` → `_emit_snmp_row()` (8-cell grid)

### `ExtraArgs[]` in MRTG Config / CGI

`_generate_switch_mrtg_targets()` emits `ExtraArgs[target]: DEF:...AREA:...STACK:...` directives. `mrtg-rrd.cgi.pl` `common_args()` appends these verbatim via `split(/\s+/, $target->{extraargs})` before `@{$target->{args}} = @args`. `noi,noo` in `Options[]` suppresses default AREA/LINE2 — ExtraArgs replaces them. Debug `warn` lines intentionally left in `common_args()` and `do_image()` — kept permanently as instrumentation.

### `generate_mrtg_index()` Coupling

Driven **purely from config + STATE**. Never reads `mrtg-rrd.cgi.pl` or MRTG config files. `update_mrtg_rrd_cgi_config()` maintains `%site_config` — that is its sole concern.

### Multi-Config Subprocess Model

Parent spawns one `subprocess.Popen` per config, waits for all, exits with worst exit code. Each child is completely independent — own statefile, PID lock, RRD dir, MRTG output subdir. No shared globals between processes.

---

## Important Modules & Code Sections

### `check_ports_resource(resource)`
Combined `ports`/`switch` metric + state monitor. Single SNMP session, single `ifDescr` walk shared across all collection. Polls IF-MIB byte/packet/error counters (per-interface quads + aggregate totals), TCP retransmits, vendor CPU/memory (HOST-RESOURCES-MIB fallback), Q-BRIDGE-MIB MAC table, hrStorage NVRAM/flash, ARP tables. For `switch` only: RMON etherStatsTable walk via `_rmon_sum()` helper. Self-contained RRD update. Returns `(error_msg, current_ports_state)`.

### `check_host_resource(resource)`
Polls HOST-RESOURCES-MIB (CPU, memory, swap, disk space) and UCD-SNMP-MIB (context switches, swap I/O, disk I/O via diskIOTable walk, interrupts). Persists `disk_space_pct` to statefile. Returns `(error_msg, {})`.

### `check_port_resource(resource)`
Single ifIndex oper/admin status + MAC via Q-BRIDGE-MIB. Alarm evaluation per `always_up`. Per-interface DS quad RRD (4 DS). Returns `(error_msg, current_oper, current_mac)`. Non-fatal MAC walk.

### `check_resource(resource)`
Pure dispatch — no RRD logic. Routes to check functions. `port` wraps result as `{'oper': oper, 'mac': mac}`.

### `check_and_heartbeat_r(resource, site_config)`
Per-resource orchestration. `ports`/`switch` with `is_up=True`: diffs `ports_state`, fires `PORT CHANGE`/`PORT MAC CHANGE`. `host`: skips port diff (empty ports_state). Availability RRD (ping/http/etc.) handled here only. Throttle state read/written atomically.

### `create_snmp_rrd(path, step_secs, interfaces)` / `update_snmp_rrd(...)`
Unified 29-DS-fixed schema. `update_snmp_rrd` uses `--template` always. Internal `_v()` maps `None` → `'U'`. All DS parameters `Optional` — `None` for unused families.

### `_generate_switch_mrtg_targets(mrtg_lines, safe_name, display_name, resource, rrd_path, ports_state, percentile)`
Standalone function (not nested) generating 5 MRTG target blocks for a switch. Inner `_stacked_chart()` handles the 4 per-interface stacked charts; explicit block at end handles `-pkt-size` RMON chart. Each target has `PageFoot[]` containing an HTML colour legend table. `ExtraArgs[]` carries all DEF/CDEF/AREA/STACK elements. `noi,noo` in `Options[]` suppresses default in/out.

### `_emit_switch_row(resource)` inside `generate_mrtg_index()`
Nested function (like `_emit_snmp_row`). Emits 5-cell `network-row` grid for switch monitors. `--cols-narrow: 3` for responsive layout.

### `collect_snmp_detail(session, vendor, interfaces, macs_by_ifindex, arp_by_mac)`
Collects sysName/Location/Contact, ifAlias, ifHighSpeed/ifSpeed, ENTITY-MIB slot resolution (with ifDescr pattern fallback), LLDP/CDP neighbours, DNS PTR lookups (capped at 50). Called from all three SNMP check functions. Returns detail dict stored in `STATE[name]['detail']`.

### `generate_monitor_detail_page(resource, detail, work_dir)`
Generates `{type}-{safe_name}-detail.html` with system info, interface table (ifIndex/slot/name/alias/speed/oper/admin/neighbour), and MAC/IP/hostname table. Atomic `.new`/`.old` rotation. Auto-refresh 95s.

### `check_config_changed_and_notify(config_path, config)`
Compares raw bytes against `.previous` file under `/var/tmp/APMonitor/`. First run: silent save. Change detected: saves current, builds `unified_diff`, fires one-shot notification via `outage_emails`/`outage_webhooks`. No throttling. Respects `alarms` flag.

### `generate_mrtg_config(config, work_dir, mrtg_config_path, state)`
`state` required for `disk_space_pct` in `host` PageTop. `switch` → `_generate_switch_mrtg_targets()`. `ports` → 8 targets. `port` → 4 targets. `host` → 4 targets (-system1 through -system4).

### `generate_mrtg_index(config, index_path, state)`
Driven from config + STATE only. No file parsing. `_emit_snmp_row()` for `ports`. `_emit_switch_row()` for `switch`. `_emit_port_host_group()` for contiguous `port`/`host` runs. Sections only emitted when monitors exist. `switch` counted in `snmp_count` verbose output.

### `main()`
`nargs='+'` on positional `config` arg. Multiple configs → subprocess spawn loop. Single config → full monitoring path. Config change detection runs after `print_and_exit_on_bad_config`, skipped for `--test-config`. `work_dir` hoisted before `try` for `finally` access. Detail page generation gated on `generate_mrtg_config` flag, runs post-poll in `finally` block.

---

## Technical Tactics

**`switch` reuses `check_ports_resource()` entirely.** No separate check function. Type differentiation via `resource['type'] == 'switch'` gate for RMON collection only. Everything else (FDB, ARP, metrics, RRD) is shared.

**Per-interface DS quads not pairs.** Schema change from v1.3.x: `if{N}_in/out` (2 DS) → `if{N}_in/out/bmcast/errors` (4 DS). Auto-heal expected count is `4 * N + 29`. Existing RRDs with `actual < expected` are deleted and recreated automatically.

**`ExtraArgs[]` is not standard MRTG.** It is a custom directive read by `mrtg-rrd.cgi.pl`'s generic `read_mrtg_config()` key-value parser and stored on `$target->{extraargs}`. `common_args()` appends it via `split(/\s+/, ...)` before caching args. The directive is entirely APMonitor-specific.

**RMON collection is aggregate not per-port.** Walk `etherStatsTable` column OIDs, sum all index values. 7 fixed COUNTER DS, switch-only. `_rmon_sum(oid)` is a nested helper inside the `if resource['type'] == 'switch'` block — uses closure over `session` and `prefix`.

**`None` → `'U'`, never `'0'` for unused COUNTER DS.** The `_v()` helper enforces this — do not bypass it. RMON DS pass `None` for non-switch types.

**`disk_space_pct` persisted to statefile.** `update_state({name: {**STATE.get(name, {}), 'disk_space_pct': ...}})` after each host poll. Available to `generate_mrtg_config(state)` and `generate_mrtg_index()` without live SNMP at generation time. Same pattern used for `detail` dict.

**Config change detection uses raw bytes not parsed content.** Binary comparison — catches YAML comment changes, whitespace changes, encoding changes. `difflib.unified_diff` on decoded lines for human-readable notification body. `.previous` saved under same directory as statefile.

**`fcgiwrap` `StandardError=journal` via Makefile.** `installmrtg` target writes `/etc/systemd/system/fcgiwrap.service.d/logging.conf`. `systemctl daemon-reload` in install sequence picks it up. Perl `warn` output now visible via `journalctl -u fcgiwrap`.

**Detail page generation runs post-poll in `finally`.** After all threads complete, iterates `config['monitors']` for `ports`/`port`/`host` types, reads `STATE[name]['detail']` (written by check functions during poll), generates HTML. Switch detail pages not currently generated — `switch` not in the post-poll type list.

**`PageFoot[]` is the right hook for switch legends.** `do_html()` in `mrtg-rrd.cgi.pl` already handles `$tgt->{pagefoot}` — emits it after the legend table. No CGI change needed. Python generates the HTML legend table and embeds it in `PageFoot[]` config directive.

**Q-BRIDGE-MIB over BRIDGE-MIB.** `dot1dTpFdbTable` returns 0 entries on VLAN-aware switches. `dot1qTpFdbTable` OID tail is `<vlan_id>.<6 MAC octets>`, value is ifIndex. Filter status=3 (learned).

**Numeric sort on interface indices everywhere.** SNMP OID tail indices are strings; `sorted(..., key=lambda x: int(x))` required. `"9" > "10"` lexicographically.

**Bezier escalation.** `t = index / N`, delay = `(1-t)² × 0 + 2(1-t)t × base + t² × base`. Plateau at `notify_every_n_secs` after N notifications. Per-monitor throttle, not per-interface.

---

## Engineering Principles for This Code

**`switch` and `ports` share one check function.** Never split them — the only divergence is RMON collection (gated by type) and MRTG presentation. Adding a new DS to the shared schema requires updating all three auto-heal expected counts AND all three `update_snmp_rrd` call sites.

**29 fixed DS — update expected DS count when adding DS.** All three auto-heal blocks (`check_ports_resource`, `check_port_resource`, `check_host_resource`) must reflect actual schema. Currently `4 × interface_count + 29`. Per-interface quads (not pairs) since v1.4.0.

**`ExtraArgs[]` is APMonitor-specific, not standard MRTG.** `mrtg-rrd.cgi.pl` `common_args()` appends it. The parser already stores any `key[target]: value` directive generically — `extraargs` is just one of those. If you add a new custom directive, same pattern applies.

**Debug `warn` lines in `mrtg-rrd.cgi.pl` are permanent instrumentation.** Do not remove. They are in `do_image()` and `common_args()`. `fcgiwrap` journald logging makes them observable.

**`index.html` is coupled to config + STATE only.** Never re-couple to `mrtg-rrd.cgi.pl` or MRTG config files. That coupling caused duplicate monitor rendering in a previous session.

**`None` → `'U'`, never `'0'` for unused COUNTER DS.** Never bypass `_v()`.

**`host` and SNMP DS families are orthogonal.** Adding a DS: `create_snmp_rrd` + `update_snmp_rrd` signature + `_v()` call + all three call sites. RMON DS are switch-only — other types pass `None`.

**`/var/tmp/APMonitor/` is mode 755, no www-data.** `_set_www_data_group()` must never be called on this directory. MRTG output dirs under `/var/www/html/mrtg/` get `_set_www_data_group()` — different concern.

**`type: snmp` is dead.** Validator emits friendly redirect. Do not resurrect it.

**`display` is presentation only.** Never check in monitoring, alerting, or RRD code paths.

**Multi-config = subprocess, not threads.** Global state is process-level. Subprocess model gives correct isolation at zero refactor cost.

**Config file insertion order = display order.** Never `sorted()` on monitor lists — breaks user-controlled ordering.

**Q-BRIDGE-MIB MAC walk is non-fatal always.** Failure → `macs: []`. Port status monitoring unaffected.

**Partial data over complete failure.** SNMP metric failure → `'U'` in RRD. Better 9/10 metrics than none.

**Never delete code or diagnostic comments without explicit notification.** Comments carry operational knowledge not recoverable from code alone.

**`ports` throttle is per-monitor, not per-interface.** MAC change and status change on different interfaces advance the same throttle counters. Intentional.

---

Would you like to see the code?