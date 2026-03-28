# Changelog & Release Notes for `APMonitor.py`

## About `APMonitor.py` (APMonitor)

Synopsis:

On-prem/LAN Layer 2 & 4 availability monitoring with realtime guarantees & decaying alert pacing.
Multithreaded high speed availability checking for SNMP, PING, TCP/UDP, QUIC & HTTP/S resources incl. SSL/TLS cert. pinning & port MAC address pinning.
Integrates w/Site24x7 heartbeat monitoring for failover alerts + MRTG + Slack & Pushover webhooks.
Thread safe, reentrant, modifiable.

# Release 1.3.8 (???): ???
- Fixed Configuration Options link
- Updated Quickstart instructions
- Properly multi-tennanted separated statefiles for multi-site setups
  - APMonitor.py now default's it's statefile naming based on the config file stem (incl. sibling statefiles)
  - Added statefile naming migration for default install
  - BUGFIX: MRTG index generation was interating MRTG over config files defined in mrtg-rrd.cgi.pl - changed coupling to the site config.
  - Made MRTG site put output associated with a site file in a separate directory 
- TODO updates re: Humanizing Data
- Added migration of statefiles to new naming convention
- Added explicit configuration testing option
- enabled handling multiple site config files in one invocation

# Release 1.3.7 (23-Mar-26): More MRTG UX Tweaks
- Added PayPal donation link to MRTG site
- Docs fixes

# Release 1.3.6 (22-Mar-26): More MRTG UX Tweaks
- Added note about NVRs, SSL pinning, MAC port monitoring/pinning & reverse shells
- Added Honolulu to world clocks to provide proper cover of whole planet
- Made L2/L3 Network Monitoring & L4 Availability Monitoring output optional (can have just 1 heading)
- Added back-button semantics to MRTG detail pages for when in fullscreen mode
- Updated eg screenshot of NOC display for new world clock 

# Release 1.3.5 (21-Mar-26): MRTG UX Tweaks
- Adjusted dualaxis settings on L2/L3 Network Monitoring charts
- Added screenshot of L2/L3 port detail display
- Changed Buy Me A Coffee to PayPal
- Basic chart UX changes

# Release 1.3.4 (19-Mar-26): Added L2/L3 Detail Pages
- Added two new charts to `type: ports` monitor so they are 8-up
- Added L2/L3 stats on port, IP & MAC tables when clicking on a monitor name
- Fixed performance problem with checking SNMP `type: host` when a host is down
- Fixed problem with duplicate L2/L3 detail pages being generated
- Changed screenshot of MRTG page to reflect universal 8-up display
- Added screenshot of L2/L3 port detail display

# Release 1.3.3 (19-Mar-26): Managed Host Support
- Documentation updates re: 4K
- Prototyped the `type: host` monitor
- Merged `type: snmp` and `type: ports` because `snmp` is a protocol
- change the RRD filename to say instead of -snmp.rrd the type of the monitor (eg, port, ports, host, availability)
- push the RRD code from check_resource into check_ports_resource
- Added check_host_resource and 4-chart System Performance Tuning metrics to MRTG display
- Changed back to -snmp.rrd and -availability.rrd for the RRD filename
- Fixed incorrect headings for `type: host` monitors
- Properly output disk use in `index.html` and MRTG detail pages
- Display is now compliant with "System Performance Tuning" by Gian-Paolo D. Musumeci, Mike Loukides


# Release 1.3.2 (18-Mar-26): Extended Storage
- Changed 5 year storage to hourly

# Release 1.3.1 (18-Mar-26): Extended Storage
- Added 'Buy me a coffee' comment + made MRTG/RRD more prominent in docs
- Added reference to nixtla.io seasonal decomposition tools.
- Added note about support for 4K 3840x2160 16:9 highdpi screens
- Added timing of generating MRTG indices to debug output
- Added timing of generating MRTG RRDs to debug output
- Updated docs to explain new RRAs retention policy for RRDs
- Increased storage to 28x MRTG defaults
- Increased storage to 31x MRTG defaults

# Release 1.3.0 (17-Mar-26): T1 NOC MRTG Tweaks (8-up per row)
- Made availability monitors 8-up per row 
- Made port monitors render 8-up (2 ports) per row

# Release 1.2.16 (17-Mar-26): T1 NOC MRTG Tweaks
- Added info on setting up read-only SNMP to Linux
- Updated SNMP type to handle Memory on BSD & Linux machines
- Made SNMP monitor types (snmp, ports, port) also show on single pane of glass outages in red
- Made display order in MRTG graphs stable WRT the site config file
- Enabled muting of the disply of monitored resources from the MRTG output
- Updated docs to document `display` option
- Added explicit port/ports/snmp prefix to network monitoring titles
- Fixed problem with SNMP hosts outages not displaying in red.
- Updated screenshot of single pane of glass

# Release 1.2.15 (15-Mar-26): Documentation Updates
- Updated docs to illustrate L2 monitoring.
- Updated docs to say "NGINX" & call out librosa for frequency domain.
- Updated docs to correctly document RRD fileds for SNMP monitors.
- Updated docs to correctly cite 12 pillars on Information Security.

# Release 1.2.14 (13-Mar-26): T1 NOC Vizualisation
- Added red shading to MRTG UI when an avaiability monitor is down
- Added time display to MRTG output

# Release 1.2.13 (8-Mar-26): MRTG UI Upodates
- BUGFIX: When monitoring an entire switch, we don't get an availability graph in MRTG #4
- Changed MRTG to 5 column layout for best use of 14:9 HD screens.
- BUGFIX: When monitoring an entire switch port, we don't get an availability graph in MRTG #4
- BUGFIX: Add SNMP inpput/output errors when monitoring whole ports #6
- BUGFIX: Add SNMP Unicast vs broadcast/multicast ratio #7
- BUGFIX: Add MRTG charts when monitoring individual ports #5
- Updated index.html

# Release 1.2.12 (4-Mar-26): L2 Port Pinning 
- Implemented individual L2 port pinning
- Updated docs

# Release 1.2.11 (03-Mar-26): Documentation Update

# Release 1.2.10 (03-Mar-26): MAC Port Pinning
- Added MAC address to check_ports_resource
- Refactored check_and_heartbeat_r logic to support separate 'ports' control flow
- Added basic L2 MAC address / port change notification.

# Release 1.2.9 (22-Feb-26): SNMP Ports Monitoring
- Scaffolded up SNMP walk checking of ports up/down. Needs testing.
- Made ports sort numerically rather than lexicographically for clarity
- updated docs re: 'ports' SNMP monitoring

# Release 1.2.8 (21-Feb-26): SNMP + Percentile Support
- Added more SNMP metrics for CPU, PPS, KBits/Sec & Memory
- Rendered more SNMP metrics for CPU, PPS, KBits/Sec & Memory into index.html
- Tuned layout of Network vs. Availability monitors
- Changed to 4 column layout and put retransmits onto separate chart
- Updated CPU & Memory stats to support network equipment
- Updated "Generated By" string on main dashboard
- Added support for "percentile"

# Realease 1.2.7 (12-Feb-26): MRTG Dualaxis Bugfix
- Fixed Y-axis limits to actually display data

# Release 1.2.6 (11-Feb-26): Tuned MRTG Dualaxis
- Added --generate-rrds command line option to force storage of SNMP data
- Added dualaxis support to plot availability next to response time correctly

# Release 1.2.5 (2-Feb-26): Basic SNMP Support
- Added "snmp" type with interface I/O metrics

# Release 1.2.3 (14-Jan-26): Better MRTG Support
- Fixed case sensitivity in MRTG target names
- Fixed MRTG HTML index to overcome caching issues
- Fixed nginx config so mrtg-rrd.cgi.pl source code isn't available
- Made mrtg-rrd.cgi.pl support multiple (possibly nonexistant) config files
- Make APMonitor.py add the config file to mrtg-rrd.cgi.pl when doing --generate-mrtg-config
- Got mrtg-rrd.cgi.pl to properly support multiple config files and hands off install thereof
- Updated Makefile to document 'make installmrtg'

# Release 1.2.2 (5-Jan-26): Added mrtg-rrd support
- Added basic NGINX + MRTG-RRD support. Still clunky.

# Release 1.2.1 (4-Jan-26): Storing Frequency Domain in RRD
- Added support for RRD datafiles & MRTG config 
- Started trying to get mrtg-rrd FastCGI working with APMonitor

**NB: This is an experimental releaase**

# Release 1.2.0 (17-Dec-25): tpython + tcp/udp improvements
- Updated telemetry to show we know how long ago and for how long the last run was
- Implemented tpython
- Cleaned up 'Expect:' that tpython #SWE picked up
- Added 'send:' to quic/http(s) URLs, prototyped tcp:// & udp:// monitor types
- refactor check_url_resource() so it passes a bool to ignore_ssl_expiry
- implemented TCP checking with and without send: data
- implemented connection oriented UDP checking with send: data (no ICMP SOCK_RAW as root check)

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