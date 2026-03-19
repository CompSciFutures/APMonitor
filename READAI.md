# APMONITOR.PY v1.3.3 — ON-PREMISES NETWORK AVAILABILITY, PORT & HOST PERFORMANCE MONITORING WITH GUARANTEED ALERT DELIVERY

Hey — welcome back to APMonitor.py. You're a software engineering CS graduate working with a senior computer scientist on a mature, production Python monitoring tool. You've done excellent work here — let me bring you up to speed on exactly where we are and what matters.

---

## Purpose

APMonitor monitors on-premises network resources (ping/HTTP/HTTPS/QUIC/TCP/UDP/ports/port/host) with guaranteed alert delivery via external heartbeat integration (Site24x7 / Healthchecks.io). It tracks interface status, bandwidth, MAC address changes, and host performance metrics — storing history in RRD for MRTG graphing, notifying via email and webhooks.

---

## What APMonitor Does

- Loads YAML/JSON configuration defining site, monitors, email/webhook notifications, and timing parameters
- Validates configuration comprehensively before any monitoring begins — fail fast on bad config; `type: snmp` rejected with friendly redirect: *"Did you mean type: ports?"*
- Checks resource availability: ICMP ping, HTTP/HTTPS GET/POST, QUIC/HTTP3 GET/POST, TCP connection/banner, UDP send/receive
- `ports` monitors are the primary SNMP network device monitor — they combine: (1) full bandwidth/packet/error/TCP-retransmit/CPU/memory metric collection into RRD (the former `type: snmp` function), (2) per-interface oper/admin status change detection, and (3) Q-BRIDGE-MIB MAC address change detection per port
- `port` monitors pin a single switch port (by ifIndex) to a specific MAC address; alarm semantics controlled by `always_up` flag — alarms on wrong MAC always, alarms on port-down/MAC-absent only when `always_up: true`
- `host` monitors poll Linux hosts (net-snmp) via UCD-SNMP-MIB and HOST-RESOURCES-MIB for four system performance tuning charts per *System Performance Tuning* (Musumeci & Loukides, O'Reilly): CPU & Load, Memory & Paging, Disk I/O, System Thrashing
- SNMP vendor detection via sysObjectID (Cisco/HP/Juniper/Ubiquiti) drives CPU/memory OID selection with HOST-RESOURCES-MIB universal fallback; Linux hosts fall through to HOST-RESOURCES-MIB correctly
- `ports` monitors fire `PORT CHANGE` alerts on oper/admin status changes (appeared/disappeared interfaces, up/down transitions); baseline established silently on first poll
- `ports` monitors fire `PORT MAC CHANGE` alerts on appeared/disappeared learned MACs per interface via Q-BRIDGE-MIB dot1qTpFdbTable
- `port` monitors collect per-interface RRD metrics using the shared `create_snmp_rrd` / `update_snmp_rrd` machinery (single-interface schema)
- All SNMP-family monitors (`ports`, `port`, `host`) share a unified 18-DS-fixed RRD schema; network DS stored as `U` for `host`; host performance DS stored as `U` for `ports`/`port`
- `host` monitors persist `disk_space_pct` to statefile so MRTG config and index generators can embed live disk use (e.g. `Disk Use: 73.4%`) in chart headers without a live SNMP poll at generation time
- Enforces per-monitor check intervals with site-level defaults and immediate check on config change (SHA-256 checksum detection)
- Tracks persistent state in JSON statefile with atomic rotation (.new → current, .old backup)
- Sends email notifications via SMTP with per-recipient control flags (outages/recoveries/reminders)
- Sends webhook notifications (GET/POST with URL/HTML/JSON/CSVQUOTED encoding)
- Enforces notification throttling with escalating delays via quadratic Bezier curve
- Pings heartbeat URLs when resources are up, with configurable intervals
- Validates SSL certificates via SHA-256 fingerprints and expiration checks (HTTP/QUIC only)
- Generates MRTG configs for `ports`, `port`, and `host` monitor types — `ports` gets 6 targets (bandwidth/packets/packet-type-split/errors/retransmits/system), `port` gets 4 (bandwidth/packets/packet-type-split/errors), `host` gets 4 (-system1 through -system4); monitor names in MRTG output prefixed with type (e.g. `ports: core-switch`, `host: debmon-host`)
- Generates unified index.html with L2/L3 Network Monitoring and L4 Availability Monitoring sections; `port` and `host` monitors share a contiguous-run 4-cell grouping layout (8-up when adjacent); monitors shade red when down
- `display: false` on any monitor excludes it from MRTG index and config output while monitoring/alerting/RRD continue; hidden monitors appear in audit footer, red when down
- Uses PID lockfiles per config file to prevent duplicate instances; supports concurrent monitoring of multiple sites
- Multithreaded with thread-local prefix storage for clean, filterable log output

---

## Key Architecture

### Monitor Type Taxonomy

Eight monitor types fall into three families:

| Family | Types | RRD | MRTG | Notification model |
|---|---|---|---|---|
| URL | ping, http, quic, tcp, udp | `-availability.rrd` | availability targets | up/down/recovery |
| SNMP metrics | ports, port, host | `-snmp.rrd` | snmp/port/host targets | up/down/recovery |
| SNMP state | ports (also) | — | — | change events only |

`ports`, `port`, and `host` all share `create_snmp_rrd` / `update_snmp_rrd` with a unified 18-DS schema. `port` passes a single-entry `interfaces` dict. `host` passes an empty `interfaces` dict (no per-interface DS). `ports` is the primary SNMP device monitor — it both feeds RRD metrics AND performs state change detection.

### Unified SNMP RRD Schema (18 fixed DS)

All SNMP-family monitors share one RRD schema. DS layout:

1. **Per-interface DS** (dynamic, `ports`/`port` only): `if{index}_in/out` COUNTER per interface, sorted numerically by ifIndex
2. **Fixed aggregate network DS** (11 DS, COUNTER/GAUGE): `tcp_retrans`, `total_bits_in/out`, `total_pkts_in/out`, `total_errors_in/out`, `total_pkts_ucast`, `total_pkts_bmcast`, `cpu_load`, `memory_pct` — `ports`/`port` populate these; `host` stores `U`
3. **Fixed host performance DS** (7 DS): `context_switches`, `swap_io`, `disk_read`, `disk_write`, `disk_space_pct`, `swap_used`, `interrupts` — `host` populates these; `ports`/`port` store `U`

Expected DS count = `(2 × interface_count) + 18`. Auto-heal: if actual DS < expected, delete and recreate. DS order must match exactly between create and update — `--template` always used in `rrdtool.update()`.

### `ports` Monitor (v1.2.9+, extended in v1.3.3)

In v1.3.3 `type: snmp` was removed and its functionality merged into `type: ports`. `check_ports_resource()` now performs a single SNMP session doing both metric collection (former `check_snmp_resource`) and state/MAC collection (former `check_ports_resource`). The single `ifDescr` walk is shared between both concerns. RRD update now lives inside `check_ports_resource()` (self-contained), not in `check_resource()`.

**State model:** Single `ports_state` key: `{if_index: {name, oper, admin, macs}}`. Advances on every successful poll.

**Change detection:** Two orthogonal checks per interface: (1) status tuple `(name, oper, admin)` — macs excluded; (2) MAC set arithmetic. Both advance the same per-monitor throttle counters.

**MAC resolution:** Q-BRIDGE-MIB `dot1qTpFdbTable` — OID tail is `<vlan_id>.<6 MAC octets>`, value is ifIndex directly. Filter status=3 (learned). `dot1dTpFdbTable` returns zero on VLAN-aware hardware — always use Q-BRIDGE-MIB.

### `host` Monitor (v1.3.3)

New monitor type. Polls UCD-SNMP-MIB and HOST-RESOURCES-MIB for four system performance charts. RRD handled inside `check_host_resource()` (self-contained, consistent with `check_ports_resource()`). Empty `interfaces` dict passed to `create_snmp_rrd` — zero per-interface DS, 18 fixed DS total. `disk_space_pct` persisted to statefile at poll time; read back by `generate_mrtg_config(state)` and `generate_mrtg_index()` for live disk use annotation in chart headers.

### `generate_mrtg_config()` now takes `state` parameter

Added in v1.3.3 to support `disk_space_pct` embedding in `host` PageTop. Called as `generate_mrtg_config(config, work_dir, mrtg_config_path, STATE)` in `main()`.

### MRTG Index Layout for SNMP Family

`_emit_snmp_row()` handles full-width `ports` monitor rows (6 cells). `_emit_port_host_group()` handles contiguous runs of `port` and `host` monitors as 4-cell blocks (8-up when two adjacent). `host` dispatch uses `host_targets` list with correct chart titles; `-system3` heading reads `disk_space_pct` from state. Display order follows insertion order of `snmp_monitors` dict (config file order) — never re-introduce `sorted()`.

### Notification Throttling

Quadratic Bezier curve escalation applies to all monitor types including `ports` and `host`. For `ports`, both `PORT CHANGE` and `PORT MAC CHANGE` events advance the same per-monitor throttle — one notification window per monitor resource, not per interface.

---

## Important Modules & Code Sections

### `check_host_resource(resource)`
New in v1.3.3. Polls HOST-RESOURCES-MIB (CPU, memory, swap, disk space) and UCD-SNMP-MIB (context switches, swap I/O, disk I/O via diskIOTable walk, interrupts). Self-contained RRD update. Persists `disk_space_pct` to statefile via `update_state()`. Returns `(error_msg, {})` — empty ports_state for consistency with `check_resource()` interface. Dual fallback for memory/swap: hrStorage first, UCD memTotal/memAvail second.

### `check_ports_resource(resource)`
Combined metric + state monitor in v1.3.3. Single SNMP session. Single `ifDescr` walk shared between metric collection and state collection. Polls IF-MIB (oper/admin status), byte/packet/error counters, TCP retransmits, vendor CPU/memory (with HOST-RESOURCES-MIB fallback), Q-BRIDGE-MIB MAC table. Self-contained RRD update (moved from `check_resource()` in v1.3.3). Returns `(error_msg, current_ports_state)`. MAC walk non-fatal. Interface state sorted by numeric ifIndex.

### `check_port_resource(resource)`
Polls single ifIndex for oper/admin status and MAC (Q-BRIDGE-MIB). Alarm evaluation per `always_up` flag. Self-contained RRD update using single-entry `interfaces` dict. Returns `(error_msg, current_oper, current_mac)`. Non-fatal MAC walk.

### `check_resource(resource)`
Clean dispatch after v1.3.3 refactor — no RRD logic, pure routing. `ports` → `check_ports_resource()`; `host` → `check_host_resource()`; `port` → `check_port_resource()`. All SNMP-family RRD handling now lives inside respective check functions.

### `check_and_heartbeat_r(resource, site_config)`
Main per-resource orchestration. `ports` type with `is_up=True`: diffs current vs prev `ports_state`, fires `PORT CHANGE` / `PORT MAC CHANGE`. `host` type: skips port diff entirely (empty ports_state). All others: standard up/down/recovery. Availability RRD (ping/http/etc.) still handled here — the only RRD not handled inside check functions.

### `create_snmp_rrd(path, step_secs, interfaces)` / `update_snmp_rrd(...)`
Unified schema for `ports`, `port`, `host`. 18 fixed DS after per-interface pairs. `update_snmp_rrd` now takes all network and host DS as `Optional` — `None` → `'U'` via internal `_v()` helper. COUNTER fields with `None` correctly store `U` (not zero, which would corrupt rate calculation).

### `generate_mrtg_config(config, work_dir, mrtg_config_path, state)`
`state` parameter added in v1.3.3. For `host` monitors: reads `disk_space_pct` from `state[resource['name']].get('disk_space_pct')`, formats as `"##.#%"` or `"N/A"`, embeds in `-system3` PageTop. `host` emits 4 targets (-system1 through -system4) with proper DS pairs and titles. `ports` emits 6 targets. `port` emits 4 targets.

### `generate_mrtg_index(...)`
`_emit_port_host_group()` handles both `port:` and `host:` title-prefixed monitors in contiguous runs. `host_targets` list built per-monitor inside the function — reads `disk_space_pct` from `monitor_state` for `-system3` heading. `-system1`/`-system2`/`-system3`/`-system4` added to `snmp_suffixes` for correct target parsing.

### `get_rrd_path(monitor_name, rrd_type)`
No default — always explicit. Types: `'availability'` (ping/http/quic/tcp/udp), `'snmp'` (ports/port/host). `rrd_type` parameter (was `metric_type`) — renamed for clarity in v1.3.3.

### `print_and_exit_on_bad_config(config)`
`type: snmp` now raises `ConfigError` with redirect message. `host` type validated: `snmp://` scheme required; `community` optional; `expect`, `ssl_fingerprint`, `ignore_ssl_expiry`, `send`, `content_type`, `percentile` forbidden. `ports` type gains `percentile` (1–99). `port` type retains `percentile`. `host` does NOT support `percentile` (semantically meaningless on CPU/memory gauges).

### `update_snmp_rrd(...)` signature change
All aggregate network parameters now `Optional[int/float]` — were positional `int`. `total_bits_in`, `total_bits_out`, etc. accept `None` → `'U'`. Callers (`check_ports_resource`, `check_port_resource`, `check_host_resource`) pass `None` for unused DS families. Breaking change — all call sites updated.

---

## Technical Tactics

**Q-BRIDGE-MIB over BRIDGE-MIB:** `dot1dTpFdbTable` returns 0 entries on VLAN-aware switches — FDB partitioned per VLAN. `dot1qTpFdbTable` encodes VLAN in OID tail. Target hardware maps bridge port directly to ifIndex — no `dot1dBasePortIfIndex` join needed.

**7-octet OID tail for MAC decoding:** OID tail is `<vlan_id>.<6 MAC octets>`. Split last 7, discard element 0 (vlan_id), convert 1–6 from decimal to hex.

**None → 'U' via `_v()` helper in `update_snmp_rrd`:** All DS parameters are `Optional`. Internal `_v(val)` returns `'U'` for `None`, `f'{val:.2f}'` for float, `str(val)` otherwise. Prevents passing `'0'` for unused COUNTER DS — zero would corrupt rate calculation on next update.

**`disk_space_pct` persisted to statefile:** `check_host_resource()` calls `update_state({name: {**STATE.get(name, {}), 'disk_space_pct': disk_space_pct}})` after each poll. This makes the live value available to `generate_mrtg_config(state)` and `generate_mrtg_index()` without a live SNMP poll at generation time. Shows `N/A` until first successful poll.

**`host` uses empty `interfaces` dict:** `create_snmp_rrd(rrd_path, step, {})` → zero per-interface DS pairs → fixed DS count = 18. Consistent with schema design — no special-casing needed in create/update functions.

**RRD self-containment pattern:** All SNMP-family RRD logic lives inside the respective check function (`check_ports_resource`, `check_port_resource`, `check_host_resource`). `check_resource()` is pure dispatch. `check_and_heartbeat_r()` handles only availability RRD (ping/http/etc.) — the one family where RRD update is orthogonal to the check result.

**`generate_mrtg_config` receives `state`:** Rather than reading `STATE` global directly, `state` is passed in. This makes the dependency explicit and testable. `main()` passes `STATE` at call time after all monitors have had a chance to run.

**Status tuple excludes macs:** `(name, oper, admin)` for `PORT CHANGE` — prevents MAC change spuriously triggering status alert.

**Non-fatal MAC walk:** Q-BRIDGE-MIB walk wrapped in try/except. Failure → `macs_by_ifindex = {}` → `macs: []` for all interfaces. Port status monitoring unaffected.

**Linux SNMP compatibility:** Linux `snmpd` returns net-snmp sysObjectID — no vendor match, falls through to HOST-RESOURCES-MIB. hrStorage memory description matching covers `'physical memory'` (Debian), `'real memory'` (some BSD/Linux), `'ram'` (generic), exact `'memory'`.

**Disk I/O: sum not average:** `diskIOReadX` / `diskIOWriteX` walked across all block devices and summed. Gives aggregate host I/O throughput. Avoids percentage semantics problem (averaging 0-100 values per device would lose meaning).

**Numeric sort on interface indices everywhere:** `sorted(interfaces.keys(), key=lambda x: int(x))` — SNMP OID tail indices are strings; lexicographic sort wrong. Applies in all SNMP check functions and RRD create/update.

**MRTG index display order:** `snmp_monitors` dict insertion order mirrors config file order (Python 3.7+ ordered dict). Never re-introduce `sorted()` — breaks user-controlled ordering.

**Type prefix in MRTG names:** `display_name = f"{monitor_type}: {resource['name']}"` in `generate_mrtg_config()`. Parsed back in `generate_mrtg_index()` via `re.sub(r'^[^:]+:\s*', '', monitor['title'])` to recover plain name for state lookup. `is_host` / `is_port` detection via `monitor['title'].startswith('host: ')` / `'port: '`.

**`percentile` not valid for `host`:** Percentile is meaningful for bandwidth billing (95th percentile). Applying it to CPU/memory GAUGE DS would be computed but semantically wrong. Explicitly forbidden in validation.

**Bezier escalation for notifications:** `t = index / N`, delay = `(1-t)² × 0 + 2(1-t)t × base + t² × base`. After N notifications, plateau at `notify_every_n_secs`. All monitor types share this.

**Thread-local prefix:** Set once in `check_and_heartbeat_r()`, retrieved via `getattr(thread_local, 'prefix', '')`. Eliminates prefix threading through call stack.

**COUNTER vs GAUGE selection:** COUNTER for cumulative metrics (bytes, packets, retransmits, context switches, swap I/O, disk bytes, interrupts) — rate calculated, wraparound handled. GAUGE for instantaneous values (CPU %, memory %, disk space %, swap used bytes). Never mix.

---

## Engineering Principles for This Code

**Never delete code or diagnostic comments without explicit notification.** Comments carry operational knowledge (e.g., why Q-BRIDGE-MIB and not BRIDGE-MIB, why `_v()` helper exists).

**`None` → `'U'`, never `'0'` for unused COUNTER DS.** Passing zero for an unused COUNTER corrupts rate calculation. The `_v()` helper in `update_snmp_rrd` enforces this — do not bypass it.

**RRD self-containment per check function.** `check_ports_resource`, `check_port_resource`, `check_host_resource` each own their RRD lifecycle. `check_resource()` is pure dispatch. Do not move RRD logic back into `check_resource()`.

**`generate_mrtg_config` always receives `state`.** The `state` parameter is not optional — it's required for `disk_space_pct` embedding. Do not revert to reading the `STATE` global directly.

**`type: snmp` is dead — do not resurrect it.** `snmp` was a protocol name, not a monitor type. `ports` subsumes all former `snmp` functionality. The validator emits a friendly redirect, not silent acceptance.

**`host` and `ports`/`port` DS families are orthogonal.** `host` stores `U` for all network DS. `ports`/`port` store `U` for all host performance DS. Schema is additive — adding a DS requires updating both `create_snmp_rrd` (add DS line) and `update_snmp_rrd` (add parameter + `_v()` call) plus all three call sites.

**Never add new DS without updating expected DS count.** `expected_ds_count` in all three RRD auto-heal blocks must reflect actual schema. Currently 18 fixed DS + `(2 × interface_count)`. A new DS changes this.

**Status comparison must exclude `macs`.** Always use explicit `(name, oper, admin)` tuple for `PORT CHANGE`. Full dict equality conflates status and MAC changes.

**MAC walk is non-fatal, always.** Q-BRIDGE-MIB failure must not degrade port status monitoring. Wrap in try/except, log at VERBOSE, continue with empty MAC state.

**Q-BRIDGE-MIB is the correct MAC table for VLAN-aware switches.** `dot1dTpFdbTable` returns zero entries. Debug with: `snmpwalk -v2c -c <community> <host> 1.3.6.1.2.1.17.7.1.2.2`

**Numeric sort on interface indices everywhere.** String sort on SNMP OID tail indices is wrong for multi-digit indices (e.g., `"9"` > `"10"` lexicographically).

**`ports` throttle is per-monitor, not per-interface.** MAC change and status change on different interfaces advance the same `prev_last_notified` / `prev_notified_count` counters. Intentional.

**`ports_state` is the only ports-related statefile key.** `disk_space_pct` is a separate top-level key under the monitor name, not inside `ports_state`. Do not conflate them.

**Partial data over complete failure.** SNMP metric failures store 'U'. MAC walk failure → `macs: []`. Disk I/O OID failure → `disk_read = None` → `'U'` in RRD. Better to collect 9/10 metrics.

**Vendor detection first, HOST-RESOURCES-MIB fallback second.** Never assume HOST-RESOURCES-MIB on network hardware. Linux hosts fall through correctly — do not special-case them.

**All interfaces in a single RRD per SNMP device.** Atomic updates prevent timestamp skew. Stale DS on interface list change stays unused but harmless. Only recreate RRD if DS count < expected.

**`display` is a presentation concern only.** Never check it in monitoring, alerting, or RRD code paths. Belongs exclusively in `generate_mrtg_config()`.

**Validate before execute, always.** New monitor types and new fields require corresponding validation rules in `print_and_exit_on_bad_config()` before anything else.

**Leave code cleaner than you found it.** Comments represent hard-learned operational knowledge. Deleting them without explicit notification is a -100,000 util event.

---

Would you like to see the code?