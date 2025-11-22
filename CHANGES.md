# Changelog & Release Notes for `APMonitor.py`

## About `APMonitor.py` (APMonitor)

On-premises/LAN availability monitoring tool with guaranteed alerts & decaying alert pacing.
Multithreaded high speed availability checking for PING & HTTP(S) resources.
Integrates with Site24x7 heartbeat monitoring for failover alerting + Slack & Pushover webhooks.
Runs on Raspberry Pi to enterprise systems.
Python-only, easily modifiable.
GPL 3.0 licensed.

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