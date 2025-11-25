# APMONITOR.PY - ON-PREMISES AVAILABILITY MONITORING WITH ALERT GUARANTEES

Hello! I need your help working on APMonitor.py, an on-premises monitoring tool I've built. Let me bring you up to speed on the latest version.

## Purpose

APMonitor monitors network resources (ping/HTTP/HTTPS/QUIC) on your LAN and integrates with external heartbeat services like Site24x7. When resources are down, APMonitor stops pinging heartbeats, triggering external alerts—guaranteeing notifications even if the monitoring host fails completely.

## What APMonitor Does

- Loads YAML/JSON configuration defining site name, monitors, email/webhook notifications, and timing parameters
- Validates configuration structure, types, URL formats, SSL fingerprints, email addresses, and monitor name uniqueness
- Checks each monitor's availability (ICMP ping, HTTP/HTTPS, or QUIC/HTTP3 with optional content matching)
- Enforces per-monitor check intervals (`check_every_n_secs`) with site-level defaults to prevent unnecessary checks
- Detects configuration changes via SHA-256 checksum and immediately checks modified monitors regardless of timing
- Tracks resource state (up/down status, outage duration, notification history, config checksum) in persistent JSON statefile
- Sends email notifications via SMTP with per-recipient control flags (outages/recoveries/reminders)
- Sends webhook notifications (GET/POST with URL/HTML/JSON/CSVQUOTED encoding) when resources go down or recover
- Enforces notification throttling with escalating delays via quadratic Bezier curve (`after_every_n_notifications`)
- Notification intervals start short, gradually increase over first N notifications, then plateau at `notify_every_n_secs`
- Pings heartbeat URLs when resources are up, with configurable heartbeat intervals (`heartbeat_every_n_secs`)
- Supports SSL certificate pinning via SHA-256 fingerprints for self-signed certificates
- Validates SSL certificate expiration unless `ignore_ssl_expiry=True` (for HTTP and QUIC)
- Uses natural language boolean parsing for config flags (true/yes/on/1 vs false/no/off/0)
- Uses PID lockfiles (per-config) to prevent duplicate instances when invoked via cron
- Runs multi-threaded for concurrent monitoring of many resources
- Uses atomic file rotation (.new → .old) to prevent state corruption on crashes
- Designed for repeated invocation (via cron or systemd loop) rather than long-running daemon mode

## Key Architecture

**Stateless Execution Model**: Each invocation loads state, performs checks, saves state, and exits. No persistent daemon process—safer for crashes and easier to manage.

**Per-Config PID Locking**: Creates `/tmp/apmonitor-{hash}.lock` where hash = SHA256(config_path)[:16]. Prevents duplicate processes per config file, allows concurrent monitoring of different sites. Stale lockfile detection via `os.kill(pid, 0)`. Unix-only feature (Linux/Darwin/BSD).

**Thread-Safe State Management**: Global `STATE` dict protected by `STATE_LOCK`. Updates written immediately to `.new` file, rotated atomically on exit.

**Configuration Change Detection**: SHA-256 checksum of entire monitor config (JSON serialized with sorted keys) stored as `last_config_checksum`. On mismatch, monitor checked immediately bypassing `check_every_n_secs`. Enables rapid response to config changes without restart.

**Interval-Based Scheduling**: Each monitor tracks `last_checked`, `last_notified`, `last_successful_heartbeat` timestamps. Decisions made by comparing elapsed time against configured intervals—enables sub-minute execution without redundant work.

**Site-Level Defaults with Monitor Overrides**: Site config provides `check_every_n_secs`, `notify_every_n_secs`, `after_every_n_notifications` as global defaults. Individual monitors override via same-named fields. Enables consistent policy with per-resource exceptions.

**Bezier Curve Notification Escalation**: Notification timing follows quadratic Bezier curve over first `after_every_n_notifications` alerts. Formula: `t = (1/N) * index`, `delay = (1-t)² * 0 + 2(1-t)t * notify_every_n_secs + t² * notify_every_n_secs`. After N notifications, delay plateaus at `notify_every_n_secs`.

**Separation of Concerns**: Configuration validation happens once at startup. Check logic is type-specific (ping vs HTTP/S vs QUIC). Notification logic is protocol-specific (webhook vs email). State management is centralized. PID locking is isolated in dedicated function.

**Natural Language Boolean Handling**: Unified `to_natural_language_boolean()` accepts bool/int/str, normalizes to lowercase, maps common boolean representations. Used for `email`, `ignore_ssl_expiry`, `email_outages`, `email_recoveries`, `email_reminders`, `use_tls`.

## Important Modules & Communication

**PID Lock Management** (`create_pid_file_or_exit_on_unix`):
- Platform detection—only runs on Unix-like systems (Linux/Darwin/BSD)
- Generates deterministic hash from config path: `SHA256(config_path)[:16]`
- Lockfile path: `/tmp/apmonitor-{hash}.lock`
- Reads existing lockfile, checks if PID alive via `os.kill(pid, 0)`
- Exits with error if another instance running same config
- Removes stale lockfiles from dead processes
- Returns lockfile path for cleanup in `main()`'s finally block
- Critical for cron use case—prevents job pileup

**Boolean Parsing** (`to_natural_language_boolean`):
- Accepts bool, int, str, or None
- False: false/no/fail/0/bad/negative/off/n/f (case-insensitive)
- True: true/yes/ok/1/good/positive/on/y/t (case-insensitive)
- Raises ValueError on unrecognized strings
- Used throughout validation and runtime for consistent boolean handling
- Replaces scattered boolean checking logic

**Configuration Loading & Validation** (`load_config`, `print_and_exit_on_bad_config`):
- Loads YAML/JSON into dict
- Validates all fields, types, formats, constraints including site-level `check_every_n_secs`, `notify_every_n_secs`, `after_every_n_notifications`
- Validates email_server settings (smtp_host, smtp_port, from_address, optional auth)
- Validates outage_emails with per-recipient flags (email_outages, email_recoveries, email_reminders)
- Validates monitor-level `email` flag and `after_every_n_notifications`
- Exits with clear error messages on invalid config
- No config state passed between invocations—reloaded fresh each run

**State Management** (`load_state`, `save_state`, `update_state`):
- `load_state`: Reads JSON from disk at startup
- `update_state`: Thread-safe in-memory update + immediate write to `.new` file
- `save_state`: Atomic rotation (current → `.old`, `.new` → current) on exit
- Per-monitor state: `is_up`, `last_checked`, `last_response_time_ms`, `down_count`, `last_alarm_started`, `last_notified`, `last_successful_heartbeat`, `notified_count`, `error_reason`, `last_config_checksum`
- Global state: `execution_time`, `execution_ms`

**Resource Checking** (`check_resource`, `check_ping_resource`, `check_url_resource`, `check_http_url`, `check_quic_url`):
- Returns tuple: `(error_msg, response_time_ms)` where error_msg is None if up
- Retries `MAX_RETRIES` times with `MAX_TRY_SECS` timeout per attempt
- HTTP/S: Validates SSL fingerprint before request, checks certificate expiry unless `ignore_ssl_expiry=True`, validates expected content substring, returns status/headers/text for expect checking
- QUIC: Async implementation using aioquic, validates SSL fingerprint and expiry, parses HTTP/3 headers/data, validates expected content substring
- Ping: Platform-specific command construction (Linux/Darwin/Windows)
- `check_url_resource`: Common wrapper for HTTP/QUIC that handles expect logic

**Configuration Checksum & Change Detection** (`check_and_heartbeat`):
- Calculates SHA-256 of JSON-serialized monitor config (sorted keys)
- Loads `prev_config_checksum` from state
- If mismatch: sets `config_changed=True`, bypasses timing logic, checks immediately
- If match: follows normal `check_every_n_secs` interval logic
- Updates `last_config_checksum` in state after every check
- Verbose output announces config changes

**Heartbeat Management** (`ping_heartbeat_url`):
- Called only when resource is up and heartbeat URL configured
- Respects `heartbeat_every_n_secs` interval to prevent excessive pings
- Returns boolean success, updates `last_successful_heartbeat` timestamp

**Email Notifications** (`notify_resource_outage_with_email`):
- Accepts notification_type: 'outage', 'recovery', or 'reminder'
- Checks per-recipient flags (email_outages, email_recoveries, email_reminders) via `to_natural_language_boolean()`
- Skips notification if recipient disabled that type
- Connects to SMTP server, uses STARTTLS if `use_tls=True`
- Authenticates if smtp_username/smtp_password provided
- Sends email with appropriate subject prefix ([OUTAGE]/[RECOVERY]/[REMINDER])
- Returns boolean success

**Webhook Notifications** (`notify_resource_outage_with_webhook`):
- Encodes message per `request_encoding` (URL/HTML/JSON/CSVQUOTED)
- Adds `request_prefix` and `request_suffix` to final payload
- Webhooks: GET appends to URL, POST uses appropriate Content-Type header
- Returns boolean success

**Notification Timing** (`calc_next_notification_delay_secs`):
- Computes next notification delay using quadratic Bezier curve
- Parameters: `notify_every_n_secs`, `after_every_n_notifications`, `secs_since_first_notification`, `current_notification_index`
- Returns escalating delay for first N notifications, then constant `notify_every_n_secs`
- Debug output gated by `VERBOSE > 1`

**Main Orchestration** (`check_and_heartbeat`, `main`):
- `main`: Acquires PID lock first (exits if duplicate detected), loads config/state, applies site-level defaults (including `DEFAULT_CHECK_EVERY_N_SECS`), spawns thread pool, records execution time, saves state, releases PID lock in finally block
- `check_and_heartbeat`: Per-monitor logic—calculate config checksum, load prev state, decide if config changed or check/notify/heartbeat due, execute actions, update state with new checksum
- State transitions: down→up triggers recovery notification (respects `email_recoveries` flag), up→down starts new outage (sets `last_alarm_started`), ongoing down increments `down_count` and `notified_count`

**Time Formatting** (`format_time_ago`):
- Accepts ISO timestamps or raw seconds (int/float)
- Returns human-readable duration strings
- Used for verbose output showing time until next check/notification and time since last action

## Technical Tactics

**Configuration Change Detection**: JSON-serialize monitor config with `sort_keys=True` for determinism. Compute SHA-256 hash. Store as `last_config_checksum`. On load, compare checksums—mismatch forces immediate check. Detects any field change (address, expect, intervals, etc.). Bypasses `check_every_n_secs` only when checksum differs.

**PID Lockfile Strategy**: Hash config path to enable per-site locking. Use `/tmp` for tempfs performance. Check process liveness before claiming lock. Clean stale locks automatically. Remove lock in outermost finally block to handle all exit paths (normal, exception, sys.exit). Deterministic hash ensures same config always gets same lockfile.

**Atomic State File Rotation**: Write to `.new`, then atomically rename to prevent corruption if killed mid-write. Keep `.old` as backup. This ensures state consistency even with kill -9.

**Timestamp Comparison for Scheduling**: Store ISO 8601 timestamps, convert to datetime, calculate `total_seconds()` delta. Compare against interval thresholds. Allows flexible intervals without complex scheduling logic.

**SSL Certificate Pinning**: Fetch cert with `ssl.get_server_certificate()`, convert PEM→DER, compute SHA-256 hash, compare to configured fingerprint. Enables trust of self-signed certs without CA validation. Works for both HTTP and QUIC.

**SSL Certificate Expiry Validation**: Use OpenSSL.crypto to parse cert, extract `notAfter` ASN.1 timestamp, parse to datetime, compare to now. Skip if `ignore_ssl_expiry=True` (via `to_natural_language_boolean()`). Works for both HTTP and QUIC.

**QUIC/HTTP3 Implementation**: Async function using aioquic library. Custom protocol class extends QuicConnectionProtocol, handles HTTP/3 events (HeadersReceived, DataReceived). Wraps in `asyncio.run()` for sync interface. Timeout via `asyncio.timeout()`. Peer certificate extracted from TLS layer for fingerprint/expiry validation.

**Simplified Expect Logic**: String-only content matching. If `expect` present, checks if substring appears in response text. If absent, any 200 OK passes. Separate handling in `check_url_resource()` after protocol-specific code returns status/headers/text.

**Email Control Flags**: Per-recipient dict with optional `email_outages`, `email_recoveries`, `email_reminders` flags. Each flag parsed via `to_natural_language_boolean()` with default=True. Notification type determined by state transition and `notified_count`. Email function checks appropriate flag before sending.

**Variable Retry Logic**: `MAX_RETRIES` and `MAX_TRY_SECS` configurable per-site. Sleep `MAX_TRY_SECS` between retries. All check functions follow same pattern for consistency.

**Lazy Checking**: Skip checks when `check_every_n_secs` hasn't elapsed UNLESS config changed. Skip heartbeats when `heartbeat_every_n_secs` hasn't elapsed. Skip notifications when calculated Bezier delay hasn't elapsed. Minimizes work and external API calls.

**Platform-Appropriate Defaults**: State file location varies by OS—`/var/tmp` (persistent across reboots) on Unix-like, `%TEMP%` on Windows, `./` as fallback. PID locking only on Unix-like systems where `/tmp` exists.

**Global Configuration Override**: Site-level settings (`max_retries`, `max_try_secs`, `check_every_n_secs`, `notify_every_n_secs`, `after_every_n_notifications`) override module-level constants using `global` declaration in `main()`.

## Engineering Principles for This Code

**Config Checksums Enable Immediate Response**: Store SHA-256 of entire monitor dict. Compare on load. Mismatch bypasses timing—check immediately. Critical for rapid config deployment without waiting for scheduled intervals.

**PID Lock Cleanup is Critical**: Lockfile must be removed in outermost finally block to handle all exit paths. Never use multiple cleanup locations (once and only once). Hash-based naming prevents collisions between different configs while enabling duplicate detection for same config.

**State Transitions Are Critical**: `last_alarm_started` must only be set on first down detection (transition from up→down), never on subsequent down states. `notified_count` increments only when notifications actually sent. Recovery notifications require previous `last_alarm_started` to exist. Get these wrong and alert timing breaks.

**Boolean Handling Must Be Consistent**: Use `to_natural_language_boolean()` everywhere. Never scatter boolean checks. Handles bool/int/str uniformly. Provides clear error messages on invalid values. Maps common human-friendly terms (yes/no, on/off, good/bad).

**Email Flags Control Notification Types**: Three independent flags per recipient: outages, recoveries, reminders. Check appropriate flag based on `notification_type` parameter. Default all to True for backward compatibility. Enables fine-grained control per recipient.

**Expect Field Is String-Only**: Removed complex bool/int/dict handling. Simple substring search. If present, must find in response text. If absent, 200 OK sufficient. Protocol-specific code returns text, common wrapper does expect check.

**QUIC Requires Async Wrapper**: aioquic is async-only. Wrap in sync function using `asyncio.run()`. Custom protocol class to handle HTTP/3 events. Timeout via `asyncio.timeout()` context manager. Extract cert from TLS layer, not HTTP layer.

**Site Defaults Cascade to Monitors**: Global `DEFAULT_*` constants set from site config in `main()`. Monitors use `.get(field, DEFAULT_*)` pattern. Enables consistent policy with per-monitor overrides. Check interval defaults particularly important for new monitors.

**Interval Comparisons Need Null Handling**: Always check if timestamp exists before parsing. Use try/except around `datetime.fromisoformat()`. Default to "should perform action" on parse failures to ensure monitoring continues.

**Thread Safety on State**: All reads/writes to global `STATE` dict must hold `STATE_LOCK`. Write to `.new` file inside lock to ensure consistency between memory and disk.

**Verbosity Levels Matter**: `-v` shows check results, `-vv` shows skip decisions, heartbeat activity, config changes, and Bezier curve calculations. Design output for progressive detail, not noise.

**Error Messages Include Context**: Always include monitor name, address, and specific error reason in messages. Site name in notifications helps when monitoring multiple sites. Timestamp format includes AM/PM for human readability. PID lock errors show config path and conflicting PID.

**Validation Before Execution**: Config validation must be comprehensive and fail-fast. Better to exit with clear error than silently ignore invalid config. Validate types, formats, constraints, and cross-field dependencies (e.g., `heartbeat_every_n_secs` requires `heartbeat_url`, `after_every_n_notifications` requires `notify_every_n_secs`, `outage_emails` requires `email_server`).

**Retry Logic Consistency**: All external operations (HTTP requests, pings, heartbeats, webhooks, emails) follow same retry pattern—loop `MAX_RETRIES`, sleep between attempts, return success/failure. Never retry infinitely.

**Preserve Historical State**: After recovery, keep `last_alarm_started` and `notified_count` from previous outage. Provides useful forensic data without affecting current monitoring state. Config checksum updates every check regardless of up/down status.

**Notification Index is Zero-Based**: `current_notification_index` passed to Bezier calculation represents notification about to be sent. First notification has index 0. `prev_notified_count` increments after sending, making it correct as current index before increment.

Would you like to see the code?