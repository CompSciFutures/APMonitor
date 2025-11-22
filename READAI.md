# APMONITOR.PY - ON-PREMISES AVAILABILITY MONITORING WITH ALERT GUARANTEES

Hello! I need your help working on APMonitor.py, an on-premises monitoring tool I've built. Let me bring you up to speed.

## Purpose

APMonitor monitors network resources (ping/HTTP/HTTPS) on your LAN and integrates with external heartbeat services like Site24x7. When resources are down, APMonitor stops pinging heartbeats, triggering external alerts—guaranteeing notifications even if the monitoring host fails completely.

## What APMonitor Does

- Loads YAML/JSON configuration defining site name, monitors, webhooks, and notification settings
- Validates configuration structure, types, URL formats, SSL fingerprints, and monitor name uniqueness
- Checks each monitor's availability (ICMP ping, HTTP/HTTPS with optional content matching)
- Enforces per-monitor check intervals (`check_every_n_secs`) to prevent unnecessary checks
- Tracks resource state (up/down status, outage duration, notification history) in persistent JSON statefile
- Sends notifications via webhooks (GET/POST with URL/HTML/JSON/CSVQUOTED encoding) when resources go down or recover
- Enforces notification throttling with escalating delays via quadratic Bezier curve (`after_every_n_notifications`)
- Notification intervals start short, gradually increase over first N notifications, then plateau at `notify_every_n_secs`
- Pings heartbeat URLs when resources are up, with configurable heartbeat intervals (`heartbeat_every_n_secs`)
- Supports SSL certificate pinning via SHA-256 fingerprints for self-signed certificates
- Optionally ignores SSL certificate expiration for development environments
- Uses PID lockfiles (per-config) to prevent duplicate instances when invoked via cron
- Runs multi-threaded for concurrent monitoring of many resources
- Uses atomic file rotation (.new → .old) to prevent state corruption on crashes
- Designed for repeated invocation (via cron or systemd loop) rather than long-running daemon mode

## Key Architecture

**Stateless Execution Model**: Each invocation loads state, performs checks, saves state, and exits. No persistent daemon process—safer for crashes and easier to manage.

**Per-Config PID Locking**: Creates `/tmp/apmonitor-{hash}.lock` where hash = SHA256(config_path)[:16]. Prevents duplicate processes per config file, allows concurrent monitoring of different sites. Stale lockfile detection via `os.kill(pid, 0)`. Unix-only feature (Linux/Darwin/BSD).

**Thread-Safe State Management**: Global `STATE` dict protected by `STATE_LOCK`. Updates written immediately to `.new` file, rotated atomically on exit.

**Interval-Based Scheduling**: Each monitor tracks `last_checked`, `last_notified`, `last_successful_heartbeat` timestamps. Decisions made by comparing elapsed time against configured intervals—enables sub-minute execution without redundant work.

**Bezier Curve Notification Escalation**: Notification timing follows quadratic Bezier curve over first `after_every_n_notifications` alerts. Formula: `t = (1/N) * index`, `delay = (1-t)² * 0 + 2(1-t)t * notify_every_n_secs + t² * notify_every_n_secs`. After N notifications, delay plateaus at `notify_every_n_secs`.

**Separation of Concerns**: Configuration validation happens once at startup. Check logic is type-specific (ping vs HTTP/S). Notification logic is protocol-specific (webhook vs email). State management is centralized. PID locking is isolated in dedicated function.

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

**Configuration Loading & Validation** (`load_config`, `print_and_exit_on_bad_config`):
- Loads YAML/JSON into dict
- Validates all fields, types, formats, constraints including `default_after_every_n_notifications` site setting and per-monitor `after_every_n_notifications`
- Exits with clear error messages on invalid config
- No config state passed between invocations—reloaded fresh each run

**State Management** (`load_state`, `save_state`, `update_state`):
- `load_state`: Reads JSON from disk at startup
- `update_state`: Thread-safe in-memory update + immediate write to `.new` file
- `save_state`: Atomic rotation (current → `.old`, `.new` → current) on exit
- Per-monitor state: `is_up`, `last_checked`, `down_count`, `last_alarm_started`, `last_notified`, `last_successful_heartbeat`, `notified_count`, `error_reason`
- Global state: `execution_time`, `execution_ms`

**Resource Checking** (`check_resource`, `check_ping_resource`, `check_url_resource`):
- Returns `None` if up, error message string if down
- Retries `MAX_RETRIES` times with `MAX_TRY_SECS` timeout per attempt
- HTTP/S: Validates SSL fingerprint before request, checks certificate expiry unless `ignore_ssl_expiry=True`, validates expected content substring
- Ping: Platform-specific command construction (Linux/Darwin/Windows)

**Heartbeat Management** (`ping_heartbeat_url`):
- Called only when resource is up and heartbeat URL configured
- Respects `heartbeat_every_n_secs` interval to prevent excessive pings
- Returns boolean success, updates `last_successful_heartbeat` timestamp

**Notification Dispatch** (`notify_resource_outage_with_webhook`, `notify_resource_outage_with_email`):
- Encodes message per `request_encoding` (URL/HTML/JSON/CSVQUOTED)
- Adds `request_prefix` and `request_suffix` to final payload
- Webhooks: GET appends to URL, POST uses appropriate Content-Type header
- Email: Currently stub implementation (prints debug info)

**Notification Timing** (`calc_next_notification_delay_secs`):
- Computes next notification delay using quadratic Bezier curve
- Parameters: `notify_every_n_secs`, `after_every_n_notifications`, `secs_since_first_notification`, `current_notification_index`
- Returns escalating delay for first N notifications, then constant `notify_every_n_secs`
- Debug output gated by `VERBOSE > 1`

**Main Orchestration** (`check_and_heartbeat`, `main`):
- `main`: Acquires PID lock first (exits if duplicate detected), loads config/state, applies site-level defaults, spawns thread pool, records execution time, saves state, releases PID lock in finally block
- `check_and_heartbeat`: Per-monitor logic—load prev state, decide if check/notify/heartbeat due, execute actions, update state
- State transitions: down→up triggers recovery notification, up→down starts new outage (sets `last_alarm_started`), ongoing down increments `down_count` and `notified_count`

**Time Formatting** (`format_time_ago`):
- Accepts ISO timestamps or raw seconds (int/float)
- Returns human-readable duration strings
- Used for verbose output showing time until next check/notification and time since last action

## Technical Tactics

**PID Lockfile Strategy**: Hash config path to enable per-site locking. Use `/tmp` for tempfs performance. Check process liveness before claiming lock. Clean stale locks automatically. Remove lock in outermost finally block to handle all exit paths (normal, exception, sys.exit). Deterministic hash ensures same config always gets same lockfile.

**Atomic State File Rotation**: Write to `.new`, then atomically rename to prevent corruption if killed mid-write. Keep `.old` as backup. This ensures state consistency even with kill -9.

**Timestamp Comparison for Scheduling**: Store ISO 8601 timestamps, convert to datetime, calculate `total_seconds()` delta. Compare against interval thresholds. Allows flexible intervals without complex scheduling logic.

**SSL Certificate Pinning**: Fetch cert with `ssl.get_server_certificate()`, convert PEM→DER, compute SHA-256 hash, compare to configured fingerprint. Enables trust of self-signed certs without CA validation.

**Variable Retry Logic**: `MAX_RETRIES` and `MAX_TRY_SECS` configurable per-site. Sleep `MAX_TRY_SECS` between retries. All check functions follow same pattern for consistency.

**Lazy Checking**: Skip checks when `check_every_n_secs` hasn't elapsed. Skip heartbeats when `heartbeat_every_n_secs` hasn't elapsed. Skip notifications when calculated Bezier delay hasn't elapsed. Minimizes work and external API calls.

**Platform-Appropriate Defaults**: State file location varies by OS—`/var/tmp` (persistent across reboots) on Unix-like, `%TEMP%` on Windows, `./` as fallback. PID locking only on Unix-like systems where `/tmp` exists.

**Global Configuration Override**: Site-level settings (`max_retries`, `max_try_secs`, `default_after_every_n_notifications`) override module-level constants using `global` declaration in `main()`.

## Engineering Principles for This Code

**PID Lock Cleanup is Critical**: Lockfile must be removed in outermost finally block to handle all exit paths. Never use multiple cleanup locations (once and only once). Hash-based naming prevents collisions between different configs while enabling duplicate detection for same config.

**State Transitions Are Critical**: `last_alarm_started` must only be set on first down detection (transition from up→down), never on subsequent down states. `notified_count` increments only when notifications actually sent. Recovery notifications require previous `last_alarm_started` to exist. Get these wrong and alert timing breaks.

**Interval Comparisons Need Null Handling**: Always check if timestamp exists before parsing. Use try/except around `datetime.fromisoformat()`. Default to "should perform action" on parse failures to ensure monitoring continues.

**Thread Safety on State**: All reads/writes to global `STATE` dict must hold `STATE_LOCK`. Write to `.new` file inside lock to ensure consistency between memory and disk.

**Verbosity Levels Matter**: `-v` shows check results, `-vv` shows skip decisions, heartbeat activity, and Bezier curve calculations. Design output for progressive detail, not noise.

**Error Messages Include Context**: Always include monitor name, address, and specific error reason in messages. Site name in notifications helps when monitoring multiple sites. Timestamp format includes AM/PM for human readability. PID lock errors show config path and conflicting PID.

**Validation Before Execution**: Config validation must be comprehensive and fail-fast. Better to exit with clear error than silently ignore invalid config. Validate types, formats, constraints, and cross-field dependencies (e.g., `heartbeat_every_n_secs` requires `heartbeat_url`, `after_every_n_notifications` requires `notify_every_n_secs`).

**Retry Logic Consistency**: All external operations (HTTP requests, pings, heartbeats, webhooks) follow same retry pattern—loop `MAX_RETRIES`, sleep between attempts, return success/failure. Never retry infinitely.

**Preserve Historical State**: After recovery, keep `last_alarm_started` and `notified_count` from previous outage. Provides useful forensic data without affecting current monitoring state.

**Notification Index is Zero-Based**: `current_notification_index` passed to Bezier calculation represents notification about to be sent. First notification has index 0. `prev_notified_count` increments after sending, making it correct as current index before increment.

Would you like to see the code?