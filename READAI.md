# APMONITOR.PY v1.2.16 — ON-PREMISES NETWORK AVAILABILITY & PORT MONITORING WITH GUARANTEED ALERT DELIVERY

Hey — welcome to APMonitor.py. You're a software engineering CS graduate working with a senior computer scientist on a mature, production Python monitoring tool. You've done good work here — let me bring you up to speed on exactly where we are and what matters.

---

## Purpose

APMonitor monitors on-premises network resources (ping/HTTP/HTTPS/QUIC/TCP/UDP/SNMP/ports/port) with guaranteed alert delivery via external heartbeat integration (Site24x7 / Healthchecks.io). It tracks interface status, bandwidth, MAC address changes, and system metrics — storing history in RRD for MRTG graphing, notifying via email and webhooks.

---

## What APMonitor Does

- Loads YAML/JSON configuration defining site, monitors, email/webhook notifications, and timing parameters
- Validates configuration comprehensively before any monitoring begins — fail fast on bad config
- Checks resource availability: ICMP ping, HTTP/HTTPS GET/POST, QUIC/HTTP3 GET/POST, TCP connection/banner, UDP send/receive
- SNMP monitors auto-discover device interfaces via IF-MIB::ifDescr walk, poll per-interface byte/packet counters, aggregate totals, TCP retransmits, CPU/memory
- SNMP vendor detection via sysObjectID (Cisco/HP/Juniper/Ubiquiti) drives CPU/memory OID selection with HOST-RESOURCES-MIB universal fallback; Linux hosts fall through to HOST-RESOURCES-MIB correctly — `'real memory'` added alongside `'physical memory'` in hrStorage description matching for BSD/Linux compatibility
- `ports` monitors poll IF-MIB for per-interface oper/admin status changes via SNMPv2c
- `ports` monitors poll Q-BRIDGE-MIB (dot1qTpFdbTable) for learned MAC addresses per port — fires `PORT MAC CHANGE` alerts on appeared/disappeared MACs
- `ports` monitors fire `PORT CHANGE` alerts on oper/admin status changes (appeared/disappeared interfaces, up/down transitions)
- `ports` baseline established silently on first poll; all subsequent polls diff against committed baseline
- `port` monitors pin a single switch port (by ifIndex) to a specific MAC address; alarm semantics controlled by `always_up` flag — alarms on wrong MAC always, alarms on port-down/MAC-absent only when `always_up: true`
- `port` monitors collect per-interface RRD metrics using the same `create_snmp_rrd` / `update_snmp_rrd` machinery as `snmp` monitors (single-interface schema)
- Enforces per-monitor check intervals with site-level defaults and immediate check on config change (SHA-256 checksum detection)
- Tracks persistent state in JSON statefile with atomic rotation (.new → current, .old backup)
- Sends email notifications via SMTP with per-recipient control flags (outages/recoveries/reminders)
- Sends webhook notifications (GET/POST with URL/HTML/JSON/CSVQUOTED encoding)
- Enforces notification throttling with escalating delays via quadratic Bezier curve
- Pings heartbeat URLs when resources are up, with configurable intervals
- Validates SSL certificates via SHA-256 fingerprints and expiration checks (HTTP/QUIC only)
- Stores SNMP/port metrics in single RRD per device; availability monitors get separate RRD per resource; `ports` monitors produce no RRD
- Generates MRTG configs for `snmp` and `port` monitor types — `snmp` gets 6 targets (bandwidth/packets/packet-type-split/errors/retransmits/system), `port` gets 4 (bandwidth/packets/packet-type-split/errors); monitor names in MRTG output are prefixed with type (e.g. `snmp: core-switch`, `port: switch-uplink`)
- Generates unified index.html with L2/L3 Network Monitoring and L4 Availability Monitoring sections; monitors and graph cells shade red when down; display order follows config file order (insertion-ordered dict, not sorted)
- `display: false` on any monitor excludes it from MRTG index and config output while monitoring/alerting/RRD continue; hidden monitors appear in a small audit footer at the bottom of the index, rendered red when down
- Uses PID lockfiles per config file to prevent duplicate instances; supports concurrent monitoring of multiple sites
- Multithreaded with thread-local prefix storage for clean, filterable log output
- Explicit stdout flushing at synchronization points for correct pipe-captured output ordering

---

## Key Architecture

### Monitor Type Taxonomy

Eight monitor types fall into three families:

| Family | Types | RRD | MRTG | Notification model |
|---|---|---|---|---|
| URL | ping, http, quic, tcp, udp | availability.rrd | availability targets | up/down/recovery |
| SNMP metrics | snmp, port | snmp.rrd | snmp/port targets | up/down/recovery |
| SNMP state | ports | none | none | change events only |

`snmp` and `port` share `create_snmp_rrd` / `update_snmp_rrd` unchanged. `port` passes a single-entry `interfaces` dict. `ports` is entirely orthogonal — different return signature, different state model, no RRD, no MRTG.

### `port` Monitor (v1.2.12+)

Polls a single ifIndex via SNMPv2c. MAC resolved via Q-BRIDGE-MIB (same chain as `ports`). Alarm logic: `always_up=True` → alarm on oper≠up OR pinned MAC absent OR wrong MAC; `always_up=False` → alarm only on wrong MAC present. Recovery fires when all alarm conditions clear. RRD metrics collected via single-entry `interfaces` dict passed to shared `create/update_snmp_rrd`. State key: `port_state: {oper, mac}`.

### `ports` Monitor (v1.2.9+)

Distinct monitor type using SNMP transport with completely different semantics from `snmp`. Does not feed RRD/MRTG.

**State model:** Single `ports_state` key per monitor in statefile: `{if_index: {name, oper, admin, macs}}`. Advances to current state on every successful poll. No separate pending/silence dict — throttle uses existing `prev_last_notified` / `prev_notified_count` / `prev_last_alarm_started` machinery in `check_and_heartbeat_r()`.

**Change detection:** Two orthogonal checks per interface per poll:
1. Status diff: compare `(name, oper, admin)` tuple — `macs` deliberately excluded. Fires `##### PORT CHANGE: #####`.
2. MAC diff: set arithmetic on `curr_iface['macs']` vs `prev_iface['macs']`. Only when interface exists both sides. Fires `##### PORT MAC CHANGE: #####`.

**MAC resolution chain (Q-BRIDGE-MIB, RFC 2674):**
- Walk `dot1qTpFdbPort` (1.3.6.1.2.1.17.7.1.2.2.1.2) — OID tail is `<vlan_id>.<6 MAC octets>`, value is bridge port number (= ifIndex directly on this switch family)
- Walk `dot1qTpFdbStatus` (1.3.6.1.2.1.17.7.1.2.2.1.3) — filter to status=3 (learned) only
- MAC decoded from OID tail: 7-octet tail, strip first octet (vlan_id), convert remaining 6 decimal octets to `AA:BB:CC:DD:EE:FF`
- `dot1dTpFdbTable` (classic BRIDGE-MIB) returns 0 entries on VLAN-aware switches — Q-BRIDGE-MIB is correct
- `bridge_port_to_ifindex` join NOT needed — Q-BRIDGE-MIB value is already ifIndex on target hardware
- MAC walk failure is non-fatal: sets `macs: []` for all interfaces, monitoring continues

**Numeric interface sort:** `sorted(all_indices, key=lambda x: int(x))` — OID tail indices are strings; lexicographic sort is wrong.

### SNMP Vendor Detection & Metrics

Query sysObjectID first → match known enterprise OID prefixes (Cisco/HP/Juniper/Ubiquiti) → try vendor-specific CPU/memory OIDs → fall back to HOST-RESOURCES-MIB if any step fails. Linux hosts return net-snmp OID (1.3.6.1.4.1.8072.*) — no vendor match, falls through correctly to HOST-RESOURCES-MIB. CPU/memory failures store 'U' in RRD rather than failing the check. Aggregate bandwidth/packets computed in Python before RRD storage.

### SNMP RRD Schema

Single RRD per device. DS layout: `if{index}_in/out` (COUNTER) per interface (sorted numerically) + 11 fixed DS: `tcp_retrans`, `total_bits_in/out`, `total_pkts_in/out`, `total_errors_in/out`, `total_pkts_ucast`, `total_pkts_bmcast` (all COUNTER) + `cpu_load`, `memory_pct` (GAUGE). Expected DS count = `(2 × interface_count) + 11`. Auto-heal: if actual DS < expected, delete and recreate on next run. DS order must match exactly between create and update — template parameter always used in `rrdtool.update()`.

### MRTG Index Generation

`generate_mrtg_index()` parses MRTG config files to reconstruct monitor metadata. SNMP monitors identified by target name suffix (`-bandwidth`, `-packets`, `-packets-type`, `-retransmits`, `-system`, `-errors`). Display order follows insertion order of `snmp_monitors` dict (Python 3.7+ ordered) which mirrors config file order — do not re-introduce `sorted()`. Monitor names carry type prefix (e.g. `snmp: core-switch`) encoded in `PageTop`/`Title` at config-generation time — parsed back by regex `<h1>([^<]+)\s*\(([^)]+)\)</h1>` in index generation. Down state read from `state[monitor_name]['is_up']` — valid for all types. Hidden monitors (`display: false`) passed as `hidden_monitors` list from `main()` — rendered in audit footer, red when down.

### Notification Throttling (all monitor types)

Quadratic Bezier curve escalation: intervals start short, grow to `notify_every_n_secs` over `after_every_n_notifications` notifications, then plateau. `ports` monitors share this machinery. For `ports`, both `PORT CHANGE` and `PORT MAC CHANGE` events advance the same throttle counters — one notification window per monitor, not per interface.

### Unified URL Resource Architecture

HTTP/QUIC/TCP/UDP share `check_url_resource()` entry point returning `(error_msg, status_code, headers, response_text)`. TCP/UDP return 200 by convention for success. Expect checking lives once in `check_url_resource()`. SNMP/ports/port bypass this entirely.

### Thread Safety & Output Ordering

`STATE` dict protected by `STATE_LOCK`. `thread_local.prefix` stores `[T#XXXX Site/Resource]` per thread, set once at start of `check_and_heartbeat_r()`. Explicit `sys.stdout.flush()` inside `update_state()` ensures thread output visible atomically with state mutations — critical for pipe-captured output (systemd journal).

---

## Important Modules & Code Sections

### `check_port_resource(resource)`
Polls single ifIndex via SNMPv2c for oper/admin status and MAC (Q-BRIDGE-MIB). Returns `(error_msg, current_oper, current_mac)`. Alarm evaluation per `always_up` flag. If RRD enabled: builds single-entry `interfaces` dict, calls `create/update_snmp_rrd` unchanged. Non-fatal MAC walk — consistent with `check_ports_resource` pattern.

### `check_ports_resource(resource)`
Polls IF-MIB (ifDescr/ifOperStatus/ifAdminStatus) and Q-BRIDGE-MIB (dot1qTpFdbPort/dot1qTpFdbStatus). Returns `(error_msg, current_ports_state)` where `current_ports_state` is `{if_index: {name, oper, admin, macs}}`. MAC walk non-fatal. Interface state sorted by numeric ifIndex. No RRD involvement.

### `check_and_heartbeat_r(resource, site_config)`
Main per-resource orchestration. For `ports` type with `is_up=True`: diffs current vs prev `ports_state`, fires `PORT CHANGE` on status tuple mismatch and `PORT MAC CHANGE` on MAC set difference. For `port` and all other types: standard up/down/recovery logic. Both branches write full `new_state` dict. `display` field has no effect here — purely a presentation concern handled upstream in MRTG generation.

### `check_snmp_resource(resource)`
Vendor detection → per-interface byte/packet polls → aggregate calculation → TCP retransmits → CPU/memory → RRD update. Returns `Optional[str]` (None = success). All metric failures graceful — store 'U' not error. hrStorage memory description matching covers: `'physical memory'` (Debian/Ubuntu), `'real memory'` (some BSD/Linux), `'ram'` (generic), exact `'memory'`.

### `create_snmp_rrd(path, interval, interfaces)` / `update_snmp_rrd(...)`
Shared by `snmp` and `port` monitor types. Single RRD per device/port. See SNMP RRD Schema above. Stable numeric sort on `interfaces.keys()` in both create and update — DS order must match exactly.

### `get_rrd_path(monitor_name, metric_type='availability')`
Resolves to `{statefile_dir}/{statefile_stem}.rrd/{safe_name}-{metric_type}.rrd`. Types: `'availability'` (ping/http/quic/tcp/udp) or `'snmp'` (snmp/port). `ports` monitors: not called.

### `generate_mrtg_config(config, work_dir, mrtg_config_path)`
Iterates monitors, skips `display: false` and `ports` type. For `snmp`/`port`: builds `display_name = f"{monitor_type}: {resource['name']}"`, emits 4 targets (`port`) or 6 targets (`snmp`) using `display_name` in all `Title` and `PageTop` fields. Percentile applied to `snmp` only (nulled for `port`). Atomic `.new`/`.old` file rotation.

### `generate_mrtg_index(all_config_files, index_path, site_name, state, hidden_monitors)`
Parses MRTG config files to reconstruct target metadata. SNMP section iterates `snmp_monitors.items()` (insertion order = config order). Down state per monitor via `state[monitor['title']]['is_up']`. `cell_class` and `label_class` conditioned on `is_down`. Hidden monitors rendered in audit footer — red when down. Atomic `.new`/`.old` rotation.

### `check_url_resource(resource)` / Protocol checkers
Unified tuple contract: `(error_msg, status_code, headers, response_text)`. TCP/UDP return 200 for success. Expect checking once in `check_url_resource()`. SNMP/ports/port not routed here.

### `print_and_exit_on_bad_config(config)`
Comprehensive validation before any monitoring. `display` accepted on all monitor types (natural language boolean). `port` type: requires `port` (ifIndex int ≥ 0) and `mac` (XX:XX:XX:XX:XX:XX); `always_up` optional boolean; forbidden fields: `expect`, `ssl_fingerprint`, `ignore_ssl_expiry`, `send`, `content_type`, `percentile`. `ports` type: `percentile` forbidden. `snmp` type: `percentile` permitted (1–99).

### `update_state(updates)` / `load_state()` / `save_state()`
Thread-safe: `STATE_LOCK` → in-memory update → write `.new` → `flush()`. Atomic rotation on exit. `ports_state` persisted per `ports` monitor. `port_state` persisted per `port` monitor. No `ports_pending` key — throttling uses existing `last_notified`/`notified_count` fields.

### `main()`
PID lock → load config/state → thread pool → `future.result()` barrier → flush → save state → release lock. MRTG path: `generate_mrtg_config()` → `update_mrtg_rrd_cgi_config()` → build `hidden_monitors` list → `generate_mrtg_index()`. `site_name` extracted once from config, never parsed from MRTG file.

---

## Technical Tactics

**Q-BRIDGE-MIB over BRIDGE-MIB:** `dot1dTpFdbTable` returns 0 entries on VLAN-aware switches — FDB partitioned per VLAN. `dot1qTpFdbTable` encodes VLAN in OID tail, returns all learned MACs. Target hardware maps bridge port directly to ifIndex, eliminating `dot1dBasePortIfIndex` join.

**7-octet OID tail for MAC decoding:** Q-BRIDGE-MIB OID tail is `<vlan_id>.<6 MAC octets>`. Split last 7 elements, discard element 0 (vlan_id), convert elements 1–6 from decimal to hex: `':'.join(f'{int(o):02X}' for o in mac_octets)`.

**Status tuple excludes macs:** `(name, oper, admin)` comparison for `PORT CHANGE` — prevents MAC change spuriously triggering status alert with misleading "was oper=up admin=up" messaging.

**Non-fatal MAC walk:** Wrap Q-BRIDGE-MIB walks in try/except. On any failure: log if VERBOSE, set `macs_by_ifindex = {}`, proceed. Interface status monitoring unaffected.

**Linux SNMP compatibility:** Linux `snmpd` returns net-snmp sysObjectID — no vendor match, falls through to HOST-RESOURCES-MIB correctly. hrStorage memory description matching covers `'physical memory'` (Debian default) and `'real memory'` (some BSD/Linux variants) — both lowercased before comparison.

**Vendor detection via sysObjectID prefix match:** `startswith()` on known enterprise OID prefixes. Detection failure acceptable — fall back to HOST-RESOURCES-MIB. Never skip vendor detection for potential match.

**Aggregate metrics in Python:** Total bits/packets computed before RRD storage. Enables per-interface error handling, flexible combinations, validation before storage. RRD COUNTER auto-calculates rates.

**display flag is presentation-only:** `display: false` skips MRTG config and index output only. `check_and_heartbeat_r()` is unaware of it — monitoring, alerting, heartbeats, RRD all continue. Detective control via audit footer in index.

**MRTG index display order:** `snmp_monitors` dict preserves insertion order (Python 3.7+). Insertion order mirrors MRTG config file order which mirrors APMonitor config file order. Never re-introduce `sorted()` on this dict — it breaks user-controlled ordering.

**Type prefix in MRTG names:** `display_name = f"{monitor_type}: {resource['name']}"` encoded into `Title` and `PageTop` at config-generation time. `generate_mrtg_index()` parses it back via regex — no extra data passing needed.

**Explicit flush at synchronization points:** `sys.stdout.flush()` inside `update_state()`. Systemd captures via pipes (fully buffered). Without flush, thread output accumulates and appears out-of-order in journal.

**Stable sort on interface indices everywhere:** `sorted(interfaces.keys(), key=lambda x: int(x))` — SNMP OID tail indices are strings, lexicographic sort is wrong. RRD DS order must match between create and update.

**SHA-256 config checksums:** JSON-serialize with `sort_keys=True`, compute SHA-256, store as `last_config_checksum`. Mismatch forces immediate check bypassing `check_every_n_secs`.

**Bezier escalation for notifications:** `t = index / N`, delay = `(1-t)² × 0 + 2(1-t)t × base + t² × base`. After N notifications, plateau at `notify_every_n_secs`. Applies to all monitor types.

**Thread-local prefix:** `threading.local()` eliminates prefix parameter threading. Set once in `check_and_heartbeat_r()`, retrieved via `getattr(thread_local, 'prefix', '')`. Main thread stays unprefixed.

**COUNTER vs GAUGE selection:** COUNTER for cumulative metrics (bytes, packets, retransmits) — RRD calculates rate, handles 32/64-bit wraparound. GAUGE for instantaneous values (CPU %, memory %). Never mix.

---

## Engineering Principles for This Code

**Never delete code or diagnostic comments without explicit notification.** Comments carry operational knowledge and hard-learned lessons (e.g., why Q-BRIDGE-MIB and not BRIDGE-MIB).

**Status comparison must exclude `macs`.** Always use explicit `(name, oper, admin)` tuple for `PORT CHANGE` detection. Full dict equality conflates status and MAC changes.

**MAC walk is non-fatal, always.** Interface status monitoring is the primary function of `ports` and `port`. MAC changes are valuable but secondary. Never let Q-BRIDGE-MIB failure degrade port status monitoring.

**Q-BRIDGE-MIB is the correct MAC table for VLAN-aware switches.** `dot1dTpFdbTable` will return zero entries. Debug MAC detection with `snmpwalk -v2c -c <community> <host> 1.3.6.1.2.1.17.7.1.2.2` first.

**Numeric sort on interface indices everywhere.** String sort on SNMP OID tail indices is wrong. Applies in `check_ports_resource()`, `check_port_resource()`, `check_snmp_resource()`, and RRD create/update.

**Ports throttle is per-monitor, not per-interface.** MAC change and status change on different interfaces both advance the same `prev_last_notified` / `prev_notified_count` counters. Intentional — one notification window per monitor resource.

**`ports_state` is the only ports-related statefile key.** No `ports_pending`. Throttling uses existing `last_notified`/`notified_count` machinery shared with all monitor types.

**`port` and `snmp` share RRD machinery.** `create_snmp_rrd` / `update_snmp_rrd` are called unchanged for `port` monitors with a single-entry `interfaces` dict. Do not create separate RRD functions for `port`.

**Partial data over complete failure.** SNMP metric failures store 'U'. MAC walk failure → `macs: []`. Better to collect 9/10 metrics than nothing.

**Vendor detection first, HOST-RESOURCES-MIB fallback second.** Never assume HOST-RESOURCES-MIB on network hardware. Linux hosts fall through correctly — do not special-case them.

**SNMP monitors and `ports` monitors are orthogonal.** Shared `snmp://` transport scheme but completely different check logic, return signatures, state models, and RRD involvement. Do not conflate them. `port` is closer to `snmp` than to `ports`.

**All interfaces in a single RRD per SNMP device.** Atomic updates prevent timestamp skew. Stale DS on interface list change stays unused but harmless. Never recreate RRD on interface list change alone — only recreate if DS count < expected.

**Validate before execute, always.** Config validation in `print_and_exit_on_bad_config()` is comprehensive and fail-fast. Any new monitor type or field requires corresponding validation rules.

**`display` is a presentation concern only.** Never check it in monitoring, alerting, or RRD code paths. It belongs exclusively in `generate_mrtg_config()` and is resolved before `generate_mrtg_index()` via what was or wasn't written to the MRTG config file.

**Leave code cleaner than you found it.** Preserving comments is part of this. Comments represent operational knowledge. Deleting them is a -100,000 util event.

---

Would you like to see the code?