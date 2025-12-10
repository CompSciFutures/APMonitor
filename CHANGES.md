# Changelog & Release Notes for `APMonitor.py`

## About `APMonitor.py` (APMonitor)

Synopsis:

On-prem/LAN availability monitoring with realtime guarantees & decaying alert pacing. 
Multithreaded high speed availability checking for PING, QUIC & HTTP/S resources incl. SSL/TLS cert. pinning.
Integrates with Site24x7 heartbeat monitoring for failover alerting + Slack & Pushover webhooks.
Thread safe, reentrant, easily modifiable.

# Release ??? (???): ???
- Updated telemetry to show we know how long ago and for how long the last run was
- Cleaned up 'Expect:' that tpython #SWE picked up


# Release 1.1.7 (9-Dec-25): Heartbeat Timing Discretisation Error Fix
- Updated docs to match default +/- 10 secs near-realtime tolerance when using `make install`.
- Updated docs to explain how to monitor for near-realtime performance.
- Added VERBOSE status msg around hearbeat timing due-ness.
- Refactored `check_and_heartbeat` so due-ness logic is in separate `is_heartbeat_due`, `is_check_due`, `calc_config_checksum` functions.
- fixed problem where discretisation error was causing heartbeats to be missed until the next check.

# Release 1.1.6 (8-Dec-25): Order of operations fix
- Trying a different setting of time.now after check_resource() is called

# Release 1.1.5 (06-Dec-2025): Fixed notification edge cases
- Added telemetry around logic associated with heartbeat timing to systemd journal instrumentation
- Fixed problem with incorrect alarm duration being reported in recovery messages.
- Fixed problem with RECOVERY messages deferring subsequent new alarms die to last_notified not being Falsey
- Tuned notifications so IS DOWN is different to NEW OUTAGE.

# Release 1.1.4 (05-Dec-2025): Tuned defaults for heartbeat monitoring tolerances 
- Changed default Makefile install to be within the +/- 10 secs of Site24x7 & PagerDuty 

# Release 1.1.3 (28-Nov-2025): Fixed repeating recovery alarms
- simplified logic for testing recovery of an outage to avoid some weird edge cases 

# Release 1.1.2 (27-Nov-2025): Better Threaded Instrumentation & Telemetry
- Added atomic flushing of threaded console logs so things appear in the right order.
- Added thread local telemetry & improved systemd journal output. 

## Release 1.1.1 (27-Nov-2025): Concurrency & Statefulness Fixes
- Fixed concurrency issue with exiting before all state data was written (needed a proper barrier before the final save).
- Added some basic instrumentation so the logs show when a critical section is entered and left.

## Release 1.0.1 (25-Nov-2025): Implemented QUIC

- Removed deprecated `https` monitor type and replaced with (prototyped) `quic` monitor type
- Added support for `type: quic` (HTTP/3 over UDP).
- Refactored repetitive boolean checking logic into `to_natural_language_boolean`
- Add option to set the default `check_every_n_secs` to global `site` config to maintain consistency with monitored resources
- Add `last_config_checksum` to statefile so when a monitored resource changes it's checked immediately

## Release 1.0.0 (24-Nov-2025): Email now works

- Implemented per site server email_server configuration
- Added per-email and per-monitored resource `email_outages`, `email_recoveries` & `email_reminders`
- Implemented delivery of email with internal email client (ignoring system settings)

## Release 0.1.4 (24-Nov-2025): Made outage messages more user friendly 

- Cleaned up SSL certificate checking control flow for `http` monitored resources so it always runs for SSL resources
- Cleaned up `http` errors so "Name or service not known", "Connection timeout" and "Connection refused" are clearer
- Refactor retry logic out of checking resources into an enclosing function
- add `last_response_time_ms` to statefile for successful requests

## Release 0.1.3 (23-Nov-2025)

- Tweaked parallel PID locking to use absolute paths to fix problems with concurrently checking multiple site configs & crontab use-case.
- Allowed setting of default MAX_THREADS in config file (still can be overridden on command line).
- Made config file parsing more robust and added support for missing `notify_every_n_sec` to global site config.

## Release 0.1.2 (22-Nov-2025)

This release supports multi-site crontab use cases by way of slightly fancy PID file locking that supports one process per site config file. 

- Add a PID lockfile to tempfs to correctly enable support for crontab use case.
- Add a hash of the config file to the PID lockfile name to enable monitoring of multiple site configs in parallel.

## Release 0.1.0 (22-Nov-2025)

This is a notification/heartbeat webhooks only version that doesn't support email yet.

- Documentation updates + added CHANGES.md file + added a logo to docs.
- Corrected printing of 12-hour time without leading 0 (was visually confusing).
- Added site name to recovery/error messages sent to endpoints.
- Added/cleaned up last_execution_ms & last_execution_time in statefile.
- Added a timing curve controllable with `notify_every_n_secs` & `after_every_n_notifications` that delivers alert notifications quickly at the start, then slows down notifications over time, i.e., pace server monitoring alarms using a decaying curve.
- Updated systemctl config to run APMonitor every 15 seconds in batch-based-realtime mode by default.

## Release 0.0.2 (22-Nov-2025)
- Lots of bugfixes to `make install` so it doesn't fail, lose state or clobber the configuration. 

## Release 0.0.1
- Initial release.