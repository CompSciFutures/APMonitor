# APMONITOR.PY - THREADED OUTPUT BUFFERING FIX & LOG LINE PREFIXING

Hey! Welcome back to APMonitor.py. We just completed a critical debugging session fixing output buffering issues in multi-threaded execution, and now we're adding thread-aware log prefixing. Let me get you oriented on the latest state.

## Purpose

APMonitor monitors network resources (ping/HTTP/HTTPS/QUIC) on-premises, integrates with external heartbeat services, and guarantees alert delivery even if the monitoring host fails. Designed for repeated cron/systemd invocation rather than daemon mode.

## What APMonitor Does

- Loads YAML/JSON configuration defining site name, monitors, email/webhook notifications, timing parameters
- Validates configuration structure, types, URL formats, SSL fingerprints, email addresses, monitor name uniqueness
- Checks resource availability via ICMP ping, HTTP/HTTPS, or QUIC/HTTP3 with optional content matching
- Enforces per-monitor check intervals with site-level defaults and configuration change detection via SHA-256 checksums
- Tracks persistent state in JSON statefile with atomic rotation to prevent corruption
- Sends email notifications via SMTP with per-recipient control flags (outages/recoveries/reminders)
- Sends webhook notifications (GET/POST with URL/HTML/JSON/CSVQUOTED encoding)
- Enforces notification throttling with escalating delays via quadratic Bezier curve
- Pings heartbeat URLs when resources are up with configurable intervals
- Validates SSL certificates via SHA-256 fingerprints and expiration checks
- Uses PID lockfiles to prevent duplicate instances per config file
- Runs multi-threaded with explicit stdout flushing for proper log ordering under systemd
- Prefixes all thread output with thread ID and context for debugging and audit trails

## Key Architecture

**Output Buffering Solution**: Python stdout is line-buffered for terminals but fully buffered for pipes. Systemd captures output via pipes, causing interleaved thread output to appear out-of-order or delayed. Solution: explicit `sys.stdout.flush()` after welcome banner, startup messages, and critically inside `update_state()` after every state write. The `update_state()` flush is the key insight—it's called by every thread after completing work, ensuring thread output becomes visible atomically after state updates.

**Thread-Aware Log Prefixing**: New `prefix_logline(site_name, resource_name)` function generates `[T#XXXX Site/Resource]` prefix where XXXX is `threading.get_ident()`. Applied to all output from worker threads. Main thread output (banner, startup messages, execution time) remains unprefixed. Enables tracing which thread generated which log line, critical for debugging race conditions or understanding concurrent execution patterns.

**Stateless Execution with Flush Discipline**: Each invocation loads state, performs checks, flushes output explicitly at synchronization points, saves state atomically, and exits. No persistent daemon—output ordering guaranteed by strategic flush placement rather than hoping for line-buffering behavior.

**Per-Config PID Locking**: Creates `/tmp/apmonitor-{hash}.lock` where hash = SHA256(config_path)[:16]. Prevents duplicate processes per config, allows concurrent monitoring of different sites. Stale lockfile detection via `os.kill(pid, 0)`. Unix-only.

**Thread-Safe State Management**: Global `STATE` dict protected by `STATE_LOCK`. Updates written immediately to `.new` file inside lock, flushed immediately after lock release. Atomic rotation on exit prevents corruption.

**Configuration Change Detection**: SHA-256 checksum of JSON-serialized monitor config triggers immediate checks when configuration changes, bypassing normal timing intervals.

**Interval-Based Scheduling**: Each monitor tracks last_checked, last_notified, last_successful_heartbeat timestamps. Decisions made by comparing elapsed time against configured intervals.

**Bezier Curve Notification Escalation**: Notification delays follow quadratic Bezier curve over first N notifications, then plateau. Formula: `t = (1/N) * index`, `delay = (1-t)² * 0 + 2(1-t)t * base + t² * base`.

## Important Modules & Communication

**Output Flushing Strategy** (multiple locations):
- After welcome banner in `main()`: Ensures version info visible immediately
- After startup messages in `main()`: Ensures config summary visible before threads start
- Inside `update_state()`: **Critical location**—ensures thread output visible after state mutation
- In `main()` finally block: Ensures all buffered output written before exit
- Why `update_state()` matters: Every thread calls it after doing work, making it the natural synchronization point for output visibility

**Log Line Prefixing** (`prefix_logline`):
- Generates `[T#XXXX Site/Resource]` prefix using `threading.get_ident()`
- Handles None values gracefully for site_name or resource_name
- Thread ID formatted as 4-digit zero-padded decimal
- Context built from available names: "Site/Resource", "Site", "Resource", or "unknown"
- Applied to ALL output from `check_and_heartbeat()` and functions it calls
- Main thread output (banner, startup, execution time) intentionally unprefixed for clarity

**Thread Output Functions** (require prefix parameter):
- `check_and_heartbeat()`: Creates prefix once, passes to all subfunctions
- `check_resource()`: Accepts prefix, passes to protocol-specific checkers
- `check_ping_resource()`, `check_http_url()`, `check_quic_url()`: Accept and use prefix
- `ping_heartbeat_url()`: Accepts prefix for heartbeat success/failure messages
- `notify_resource_outage_with_email()`: Accepts prefix for email notification status
- `notify_resource_outage_with_webhook()`: Accepts prefix for webhook notification status
- All VERBOSE output and stderr output from threads includes prefix

**PID Lock Management** (`create_pid_file_or_exit_on_unix`):
- Platform detection—only runs on Unix-like systems
- Generates deterministic hash: `SHA256(config_path)[:16]`
- Lockfile path: `/tmp/apmonitor-{hash}.lock`
- Checks process liveness via `os.kill(pid, 0)`
- Returns lockfile path for cleanup in `main()`'s finally block
- Critical for cron—prevents job pileup

**Boolean Parsing** (`to_natural_language_boolean`):
- Unified handler for bool/int/str/None
- False: false/no/fail/0/bad/negative/off/n/f/none/null/never/nein
- True: true/yes/ok/1/good/positive/on/y/t
- Case-insensitive matching
- Raises ValueError on unrecognized strings
- Used throughout for consistent boolean handling

**Configuration Loading & Validation** (`load_config`, `print_and_exit_on_bad_config`):
- Loads YAML/JSON into dict
- Comprehensive validation of all fields, types, formats, constraints
- Exits with clear error messages on invalid config
- No config state passed between invocations—reloaded fresh each run

**State Management** (`load_state`, `save_state`, `update_state`):
- `load_state`: Reads JSON at startup
- `update_state`: Thread-safe in-memory update + immediate write to `.new` + **immediate flush**
- `save_state`: Atomic rotation (current → `.old`, `.new` → current)
- Per-monitor state includes: is_up, last_checked, last_response_time_ms, down_count, last_alarm_started, last_notified, last_successful_heartbeat, notified_count, error_reason, last_config_checksum

**Resource Checking** (`check_resource`, protocol-specific functions):
- Returns tuple: `(error_msg, response_time_ms)`
- Retries with configurable attempts and timeouts
- HTTP/S: Validates SSL fingerprint, checks certificate expiry, validates content
- QUIC: Async implementation using aioquic, validates SSL fingerprint/expiry
- Ping: Platform-specific command construction
- All accept and use prefix parameter for output

**Main Orchestration** (`check_and_heartbeat`, `main`):
- `main`: Acquires PID lock, loads config/state, spawns thread pool, waits for completion with explicit result retrieval, flushes output, records execution time, saves state, releases lock
- `check_and_heartbeat`: Creates prefix once at start, passes to all operations, handles state transitions with proper notification types
- Thread pool uses `executor.submit()` to launch threads, then `future.result()` in sequential loop to wait for ALL threads and propagate exceptions

## Technical Tactics

**Explicit Flush for Pipe-Captured Output**: Systemd captures stdout/stderr via pipes, which are fully buffered (not line-buffered). Without explicit flush, thread output accumulates in buffer and appears out-of-order or delayed. Strategic flush after state updates ensures output visibility aligns with state mutations. The `update_state()` flush is the critical discovery—it's called by every thread, making it the natural synchronization point.

**Thread ID in Log Prefixes**: Using `threading.get_ident()` instead of `threading.current_thread().name` because thread names in ThreadPoolExecutor are generic. Thread ID is guaranteed unique per thread and provides sufficient differentiation for debugging. Four-digit zero-padding ensures visual alignment in logs.

**Prefix Parameter Threading**: Rather than calling `prefix_logline()` repeatedly, create prefix once in `check_and_heartbeat()` and pass as parameter to all subfunctions. Reduces redundant `threading.get_ident()` calls and ensures consistent prefix format throughout execution chain. All thread-originated output functions accept prefix parameter.

**Future Result Retrieval Pattern**: After submitting all jobs to thread pool, loop through futures calling `future.result()`. This blocks until each future completes AND re-raises any exceptions from worker threads. Without explicit result retrieval, thread exceptions are silently swallowed. Sequential result retrieval ensures proper exception propagation while maintaining concurrency during execution.

**Flush After State Lock Release**: `update_state()` acquires STATE_LOCK, mutates STATE dict, writes `.new` file, releases lock, then immediately flushes stdout. This ensures output from thread appears in logs after state is safely persisted but while still holding logical "atomicity" of the operation.

**Subprocess Timeout Coordination**: `subprocess.run()` timeout set to `MAX_TRY_SECS + 2` to allow subprocess termination before thread timeout. Prevents orphaned processes outliving parent thread. Ensures cleanup even in worst-case scenarios.

**Configuration Change Detection**: JSON-serialize monitor config with `sort_keys=True`, compute SHA-256, store as `last_config_checksum`. Compare on load—mismatch forces immediate check bypassing timing intervals. Detects any field change.

**Atomic State File Rotation**: Write to `.new`, atomically rename to current. Keep `.old` as backup. Ensures state consistency even with kill -9.

**SSL Certificate Pinning**: Fetch cert, convert PEM→DER, compute SHA-256, compare to configured fingerprint. Works for both HTTP and QUIC. Enables trust of self-signed certs.

**QUIC/HTTP3 Implementation**: Async function using aioquic. Custom protocol class handles HTTP/3 events. Wraps in `asyncio.run()` for sync interface. Timeout via `asyncio.timeout()`. Peer certificate from TLS layer.

## Engineering Principles for This Code

**Flush at Synchronization Points**: Don't rely on line-buffering when output is pipe-captured. Flush after banner (startup visibility), after config messages (pre-thread visibility), inside `update_state()` (post-thread-work visibility), and in finally block (exit visibility). The `update_state()` flush is the key insight—it's where threads naturally synchronize.

**Prefix Consistency in Threads**: ALL output from worker threads must include prefix. Main thread output (banner, startup, execution time) stays unprefixed for clarity. Pass prefix as parameter rather than regenerating—once and only once principle applies to prefix creation per execution chain.

**Thread Pool Exception Handling**: Always call `future.result()` on all futures to propagate exceptions. Without explicit result retrieval, thread exceptions are silently lost. Wrap each result retrieval in try/except to handle exceptions gracefully rather than crashing main thread.

**State Transitions Require Prefix**: Outage and recovery messages include prefix for audit trails. Makes it clear which thread detected which state transition. Critical for debugging timing issues or understanding concurrent execution.

**Output Before State vs After State**: Thread prints diagnostic output (SSL checks, HTTP success) BEFORE calling `update_state()`. State update happens last, with flush immediately after. This ordering ensures output appears chronologically correct relative to state mutations.

**Verbose Output Levels**: `-v` shows thread prefixes, check results, skip decisions. `-vv` adds Bezier curve calculations, DEBUG lines. Design for progressive detail—prefix format aids in filtering by thread when debugging specific resources.

**PID Lock Cleanup in Finally**: Lockfile removal must be in outermost finally block to handle all exit paths. Never use multiple cleanup locations. Hash-based naming prevents collisions while enabling duplicate detection.

**Boolean Handling Uniformity**: Use `to_natural_language_boolean()` everywhere. Never scatter boolean checks. Provides consistent behavior and clear error messages.

**State Must Survive Flush**: `update_state()` writes state to disk BEFORE flushing. Ensures state persistence happens before output visibility. Critical ordering for crash recovery—state must be durable before announcing completion.

**Subprocess vs Thread Timeout**: Subprocess timeout must be ≤ thread operation timeout. Set subprocess timeout to `MAX_TRY_SECS` (not `+2`), ensure subprocess killed before thread completes. Prevents orphaned processes.

**Email Flags Control Types**: Three independent flags per recipient: email_outages, email_recoveries, email_reminders. Check appropriate flag based on notification_type. Default all to True. Enables fine-grained control.

**Validation Before Execution**: Config validation must be comprehensive and fail-fast. Better to exit with clear error than silently ignore invalid config. Validate types, formats, constraints, cross-field dependencies.

**Thread ID Formatting**: Zero-pad to 4 digits for visual alignment. Use decimal, not hex. Thread IDs are process-local and reset on restart, so no need for global uniqueness—just local differentiation.

Would you like to see the code?