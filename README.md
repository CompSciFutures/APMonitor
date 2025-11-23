<img src="images/APMonitor-logo.png" alt="APMonitor logo" width="128" height="128" style="vertical-align: text-bottom;">

# `APMonitor.py` - An On-Premises Monitoring Tool with Alert Delivery Guarantees

This is an on-prem monitoring tool written completely in very clear Python-only code (so you can modify it) and is designed to work on a LAN for on-prem availability monitoring of resources that aren't necesarilly connected to The Internet, and/or where the on-prem monitoring itself is also required to have availability guarantees.

It supports multi-threading of the availability checking of monitored resources for high speed near-realtime performance, if that is what you need (see the `-t` command line option). The default operation mode is single-threaded for log clarity that runs on small systems like a Raspberry Pi.

`APMonitor.py` (APMonitor) is primarily designed to work in tandem with [Site24x7](https://site24x7.com) and integrates very well with their "[Heartbeat Monitoring](https://www.site24x7.com/help/heartbeat/)".

To achieve **guaranteed always-on monitoring service levels**, simply setup local availability monitors in your config, [sign-up for a Pro Plan at Site24x7](https://www.site24x7.com/site24x7-pricing.html) then use `heartbeat_url` and `heartbeat_every_n_secs` configuration options to `APMonitor.py` to ping a [Heartbeat Monitoring](https://www.site24x7.com/help/heartbeat/) URL endpoint at [Site24x7](https://site24x7.com) when the monitored resource is up. This then ensures that when a heartbeat doesn't arrive from APMonitor, monitoring alerts fall back to Site24x7, and when both are working you have second-opinion availability monitoring reporting.

**The service level guarantee works as follows:** If the resource is down, `APMonitor.py` won't hit the [Heartbeat Monitoring](https://www.site24x7.com/help/heartbeat/) endpoint URL, and Site24x7 will then send an alert about the missed heartbeat without the need for any additional dependencies on-prem/on-site. So the entire machine `APMonitor.py` is running on can fall over, and you still get availability monitoring alerts sent, with all the benefits of having on-prem monitoring on your local network behind your firewall.  

You can quickly signup for a [Site24x7.com Lite or Pro Plan](https://www.site24x7.com/site24x7-pricing.html) for \$10-\$50 USD per month, then setup a bunch of [Heartbeat Monitoring](https://www.site24x7.com/help/heartbeat/) URL endpoints that works with `APMonitor.py` rather easily.

**Note: Heartbeat Monitoring is not available on their Website Monitoring plans. You need an 'Infrastructure Monitoring' or 'All-In-One' plan for it to work correctly.**

APMonitor also integrates well with [Slack](https://slack.com/) and [Pushover](https://pushover.net/) via webhook URL endpoints. Email is not yet supported, because my focus was primarily realtime environments for this initial release.

APMonitor is a neat way to guarantee your on-prem availability monitoring will always let you know about an outage and to avoid putting resources onto the net that don't need to be.

ap

# Recommended configuration for real-time environments

To put APMonitor into near-realtime mode so that it check resources multiple times per second, use these global settings:

- Dial up threads with `-t 15`,
- set `max_retries` to 1 and
- dial down `max_try_secs` to 10 or 15 seconds

for real-time environments.

# Recommended configuration of Site24x7 Heartbeat Monitor Thresholds for HA Availability Monitoring

You do need to configure Site24x7's Hearbeat Monitoring to achieve high-availability second opinion availability monitoring.

As an exemplar, for the following monitored resource:
```text
monitors:
- type: http
    name: home-nas
    address: https://192.168.1.12/api/bump
    expect: "(C) COPYRIGHT 2005, Super NAS Storage Inc."
    ssl_fingerprint: a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890
    heartbeat_url: https://plus.site24x7.com/hb/your-unique-heartbeat-id/homenas
    heartbeat_every_n_secs: 300
```

Setup Site24x7 as follows:

![site24x7-heartbeat-settings.png](images%2Fsite24x7-heartbeat-settings.png)

This will send a heartbeat to [Site24x7](https://site24x7.com) every 5 minutes, and Site24x7 will drop an alarm whenever a heartbeat doesn't arrive or arrives out of sequence +/- 1 minute.
This ensures availability monitoring will always function, even when one of APMonitor or Site24x7 is down. 

This also means you don't need to expose internal LAN network resources to The Internets.

See Site24x7 docs for more info:
- [Heartbeat Monitoring](https://www.site24x7.com/help/heartbeat/)
- [Thresholds configuration](https://www.site24x7.com/help/admin/configuration-profiles/threshold-and-availability/server-monitor.html)

# `APMonitor.py` YAML/JSON Site Configuration Options

APMonitor uses a YAML or JSON configuration file to define the site being monitored and the resources to check. The configuration consists of two main sections: site-level settings that apply globally, and per-monitor settings that define individual resources to check.

## site: configuration options

The `site` section defines global settings for the monitoring site.

### Required Fields

- **`name`** (string): The name of the site being monitored. Used in notification messages to identify which site is reporting issues.
```yaml
  site:
    name: "HomeLab"
```

### Optional Fields

- **`outage_emails`** (list of objects): Email addresses to notify when resources go down or recover. Each entry is an object with an `email` field.
```yaml
  outage_emails:
    - email: "admin@example.com"
    - email: "alerts@example.com"
```
  - **`email`** (string, required): Valid email address matching standard email format

- **`outage_webhooks`** (list of objects): Webhook endpoints to call when resources go down or recover. Each webhook requires several configuration fields.
```yaml
  outage_webhooks:
    - endpoint_url: "https://api.example.com/alerts"
      request_method: POST
      request_encoding: JSON
      request_prefix: ""
      request_suffix: ""
```
  - **`endpoint_url`** (string, required): Valid URL with scheme and host for the webhook
  - **`request_method`** (string, required): HTTP method, must be `GET` or `POST`
  - **`request_encoding`** (string, required): Message encoding format:
    - `URL`: URL-encode the message (for query parameters or form data)
    - `HTML`: HTML-escape the message
    - `JSON`: Send as JSON object with `message` field (POST only)
    - `CSVQUOTED`: CSV-quote the message for comma-separated values
  - **`request_prefix`** (string, optional): String to prepend to encoded message (e.g., API tokens, field names)
  - **`request_suffix`** (string, optional): String to append to encoded message

- **`max_threads`** (integer, optional): Number of concurrent threads for checking resources in parallel. Must be ≥ 1. Default: 1 (single-threaded). Can be overridden by command line `-t` option.
```yaml
  max_threads: 1
```

**Note**: For near-realtime monitoring environments, set `max_threads` to 5-15 to enable parallel checking of multiple resources. Single-threaded mode (1) is recommended for small systems like Raspberry Pi or when log clarity is important. This setting is overridden by the `-t` command line argument if specified.

- **`max_retries`** (integer, optional): Number of times to retry failed checks before marking resource as down. Must be ≥ 1. Default: 3
```yaml
  max_retries: 3
```

**Note**: For near-realtime monitoring, set `max_retries: 1` to reduce detection latency. Higher values (3-5) are better for unstable networks where transient failures are common.

- **`max_try_secs`** (integer, optional): Timeout in seconds for each individual check attempt. Must be ≥ 1. Default: 20
```yaml
  max_try_secs: 20
```

- **`notify_every_n_secs`** (integer, optional): Default minimum seconds between outage notifications for all monitors. Individual monitors can override this with their own `notify_every_n_secs` setting. Must be ≥ 1. Default: 600
```yaml
  notify_every_n_secs: 1800
```

**Note**: This sets the baseline notification throttling interval. Combined with `default_after_every_n_notifications`, controls the notification escalation curve for all monitors unless overridden per-monitor.

- **`after_every_n_notifications`** (integer, optional): Default number of notifications after which the notification interval reaches `notify_every_n_secs` for all monitors. Individual monitors can override this with their own `after_every_n_notifications` setting. Must be ≥ 1. Default: 1 (constant notification intervals)
```yaml
  after_every_n_notifications: 1
```

**Note**: When set to a value > 1, notification intervals start shorter and gradually increase following a quadratic Bezier curve until reaching `notify_every_n_secs` after the specified number of notifications. This provides more frequent alerts at the start of an outage when immediate attention is needed, then reduces notification frequency as the outage continues. A value of 1 maintains constant notification intervals (original behavior).

## monitors: configuration options

The `monitors` section is a list of resources to monitor. Each monitor defines what to check and how often.

### Required Fields (All Monitor Types)

- **`type`** (string): Type of check to perform. Must be one of:
  - `ping`: ICMP ping check
  - `http`: HTTP endpoint check
  - `https`: HTTPS endpoint check

- **`name`** (string): Unique identifier for this monitor. Must be unique across all monitors in the configuration. Used in notifications and state tracking.

- **`address`** (string): Resource to check. Format depends on monitor type:
  - For `ping`: Valid hostname, IPv4, or IPv6 address
  - For `http`/`https`: Full URL with scheme and host

### Optional Fields (All Monitor Types)

- **`check_every_n_secs`** (integer, optional): Seconds between checks for this resource. Must be ≥ 1. Default: 60
```yaml
  check_every_n_secs: 300
```

- **`notify_every_n_secs`** (integer, optional): Minimum seconds between outage notifications while resource remains down. Must be ≥ 1 and ≥ `check_every_n_secs`. Default: 600
```yaml
  notify_every_n_secs: 1800
```

- **`after_every_n_notifications`** (integer, optional): Number of notifications after which the notification interval reaches `notify_every_n_secs` for this specific monitor. Overrides site-level `default_after_every_n_notifications`. Can only be specified if `notify_every_n_secs` is present. Must be ≥ 1.
```yaml
  notify_every_n_secs: 3600
  after_every_n_notifications: 5
```

**Behavior**: Notification timing follows a quadratic Bezier curve—intervals start shorter and gradually increase over the first N notifications until reaching the full `notify_every_n_secs` interval. After N notifications, the interval remains constant at `notify_every_n_secs`. This provides aggressive early alerting that tapers off as outages persist.

- **`heartbeat_url`** (string, optional): URL to ping (HTTP GET) when resource check succeeds. Useful for external monitoring services like Site24x7 or Healthchecks.io. Must be valid URL with scheme and host.
```yaml
  heartbeat_url: "https://hc-ping.com/your-uuid-here"
```

- **`heartbeat_every_n_secs`** (integer, optional): Seconds between heartbeat pings. Must be ≥ 1. Can only be specified if `heartbeat_url` is present. If not specified, heartbeat is sent on every successful check.
```yaml
  heartbeat_every_n_secs: 300
```

### HTTP/HTTPS Monitor Specific Fields

These fields are only valid for monitors with `type: http` or `type: https`:

- **`expect`** (string, optional): Substring that must appear in the HTTP response body for the check to succeed. If not present, any 200 OK response is considered successful.
```yaml
  expect: "System Name: <b>HomeLab</b>"
```

- **`ssl_fingerprint`** (string, optional): SHA-256 fingerprint of the expected SSL certificate (with or without colons). Enables certificate pinning for self-signed certificates. When specified, the certificate is verified before making the HTTP request.
```yaml
  ssl_fingerprint: "e85260e8f8e85629cfa4d023ea0ae8dd3ce8ccc0040b054a4753c2a5ab269296"
```

- **`ignore_ssl_expiry`** (boolean/integer/string, optional): Skip SSL certificate expiration checking. Accepts: `true`/`1`/`"yes"`/`"ok"` (case-insensitive) for true, or `false`/`0`/`"no"` for false. Useful for development environments or when certificate renewal is managed separately.
```yaml
  ignore_ssl_expiry: true
```

### Example Configurations

**Ping Monitor:**
```yaml
- type: ping
  name: home-gateway
  address: "192.168.1.1"
  check_every_n_secs: 60
  heartbeat_url: "https://hc-ping.com/uuid-here"
```

**HTTP Monitor with Content Check:**
```yaml
- type: http
  name: web-server
  address: "http://192.168.1.100/health"
  expect: "status: ok"
  check_every_n_secs: 120
  notify_every_n_secs: 3600
```

**HTTPS Monitor with Certificate Pinning:**
```yaml
- type: https
  name: nvr0
  address: "https://192.168.1.12/api/system"
  expect: "nvr0"
  ssl_fingerprint: "e85260e8f8e85629cfa4d023ea0ae8dd3ce8ccc0040b054a4753c2a5ab269296"
  ignore_ssl_expiry: true
  heartbeat_url: "https://plus.site24x7.com/hb/uuid/nvr0"
  heartbeat_every_n_secs: 60
```

### Validation Rules

The configuration validator enforces these rules:

1. Monitor names must be unique across all monitors
2. `notify_every_n_secs` must be ≥ `check_every_n_secs` if both specified
3. `heartbeat_every_n_secs` can only be specified if `heartbeat_url` exists
4. `expect`, `ssl_fingerprint`, and `ignore_ssl_expiry` are only valid for HTTP/HTTPS monitors
5. All URLs must include both scheme (http/https) and hostname
6. Email addresses must match standard email format (RFC 5322 simplified)
7. SSL fingerprints must be valid hexadecimal strings with length that's a power of two
8. `after_every_n_notifications` can only be specified if `notify_every_n_secs` is present

# Dependencies

Install system-wide for production use:
```
sudo pip3 install PyYAML requests pyOpenSSL urllib3
```

Or on Debian 12+ systems:
```
sudo pip3 install --break-system-packages PyYAML requests pyOpenSSL urllib3
```

# Example invocation:
```
./APMonitor.py -s /tmp/statefile.json homelab-monitorhosts.yaml 
```
```
./APMonitor.py --test-webhooks -v homelab-monitorhosts.yaml 
```

# Command Line Usage

APMonitor is invoked from the command line with various options to control verbosity, threading, state file location, and testing modes.

## Synopsis
```
./APMonitor.py [OPTIONS] <config_file>
```

## Command Line Options

- **`config_file`** (required): Path to YAML or JSON configuration file

- **`-v, --verbose`**: Increase verbosity level (can be repeated: `-v`, `-vv`, `-vvv`). Shows check progress, skip reasons, and diagnostic information. Useful for troubleshooting configuration or understanding monitoring behavior.

- **`-t, --threads <N>`**: Number of concurrent threads for checking resources (default: 1). Higher values enable parallel checking of multiple resources but increase lock contention. Use values > 1 for systems with many independent monitors. Will override the configuration file settings if `max_threads` is specified in the site config.

- **`-s, --statefile <path>`**: Path to state file for persistence (default: platform-dependent). **Recommended: use `/tmp/statefile.json`** to store state in tmpfs for better performance and reduced disk wear.

- **`--test-webhooks`**: Test webhook notifications by sending a dummy alert to all configured webhooks, then exit. Does not check resources or modify state file. Useful for verifying webhook configuration and credentials.

- **`--test-emails`**: Test email notifications by sending a dummy alert to all configured email addresses, then exit. Does not check resources or modify state file.

## Common Usage Examples

### Basic Monitoring (Single-Threaded)

Run with default settings, state stored in tmpfs:
```
./APMonitor.py -s /tmp/statefile.json monitoring-config.yaml
```

### Verbose Monitoring for Debugging

Show detailed progress and decision-making:
```
./APMonitor.py -v -s /tmp/statefile.json monitoring-config.yaml
```

### High-Frequency Monitoring (Multiple Threads)

Check many resources concurrently for near-realtime behavior:
```
./APMonitor.py -t 10 -s /tmp/statefile.json monitoring-config.yaml
```

Use higher thread counts (`-t 5` to `-t 20`) when:
- Monitoring many independent resources (50+)
- Resources have long check timeouts
- Near-realtime alerting is required
- System has sufficient CPU cores

**Warning**: High thread counts increase lock contention. Test with `-v` to ensure checks aren't blocking each other.

### Test Webhook Configuration

Verify webhooks are configured correctly before production use:
```
./APMonitor.py --test-webhooks -v monitoring-config.yaml
```

This sends test messages to all configured webhooks with verbose output showing request/response details.

### Test Email Configuration

Verify email settings work correctly:
```
./APMonitor.py --test-emails -v monitoring-config.yaml
```

## Running `APMonitor.py` Continuously

APMonitor is designed to be run repeatedly rather than as a long-running daemon. There are two common approaches:

### Option 1: Cron (Recommended for Most Cases)

Run every minute via cron for standard monitoring:
```
* * * * * /path/to/APMonitor.py -s /tmp/statefile.json /path/to/monitoring-config.yaml 2>&1 | logger -t apmonitor
```

NB: PID file locking should keep this under control, in case you get a long-running process.

**Advantages**:
- Automatic restart if process crashes
- Built-in scheduling
- System handles process lifecycle
- Easy to enable/disable (comment out cron entry)

**Best for**: Production systems, servers with standard monitoring requirements (check intervals ≥ 60 seconds)

### Option 2: While Loop (For Sub-Minute Monitoring)

Run continuously with short sleep intervals for near-realtime monitoring:
```
#!/bin/bash
while true; do
    ./APMonitor.py -t 5 -s /tmp/statefile.json monitoring-config.yaml
    sleep 10
done
```

Or as a one-liner:
```
while true; do ./APMonitor.py -s /tmp/statefile.json monitoring-config.yaml; sleep 30; done
```

**Advantages**:
- Sub-minute check intervals
- Near-realtime alerting
- Fine control over execution frequency

**Best for**: Development, testing, systems requiring rapid failure detection (check intervals < 60 seconds)

**Note**: Use short sleep intervals (5-30 seconds) combined with per-resource `check_every_n_secs` settings to balance responsiveness and system load. APMonitor's internal scheduling prevents redundant checks even with frequent invocations.

### Systemd Service (Alternative)

For production deployments requiring process supervision:
```
[Unit]
Description=APMonitor Network Resource Monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do /usr/local/bin/APMonitor.py -vv -s /var/tmp/apmonitor-statefile.json /usr/local/etc/apmonitor-config.yaml; sleep 15; done'
Restart=always
RestartSec=10
User=monitoring
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

## Default State File Location

APMonitor automatically selects a platform-appropriate default location for the state file if the `-s/--statefile` option is not specified:

### Linux, macOS, FreeBSD, OpenBSD, NetBSD
**Default**: `/var/tmp/apmonitor-statefile.json`

- Located in `/var/tmp` which persists across system reboots
- Preserves monitoring history and outage timestamps through restarts
- Enables accurate outage duration reporting even after system reboot
- No special permissions required (unlike `/var/run`)

### Windows
**Default**: `%TEMP%\apmonitor-statefile.json`

- Uses the system temporary directory defined by `TEMP` or `TMP` environment variables
- Typically resolves to `C:\Users\<username>\AppData\Local\Temp\apmonitor-statefile.json`
- Falls back to `C:\Temp\apmonitor-statefile.json` if environment variables are not set

### Unknown/Other Platforms
**Default**: `./apmonitor-statefile.json`

- Creates state file in current working directory
- Safe fallback for uncommon or embedded systems
- Avoids permission issues on unfamiliar filesystem layouts

### Concurrency and Multiple Instances

APMonitor's state file locking &amp; PID locking is designed for **single-process concurrency only**—multiple threads within one process safely share state through internal locks. However, **no file-level locking** is implemented to coordinate between multiple APMonitor processes.

Having said that, APMonitor is very much re-entrant and thread safe for the most part, thus, if you specify different config files, it will happily allow a single process per config file to co-exist in parallel. 
The config filename is used as the hash when forming a PID lockfile in tempfs (`/tmp/apmonitor-##########.lock`), so that multiple lockfiles can coexist.

**Thus, running multiple concurrent instances requires separate state files**:
```
# Instance 1: Production monitoring
./APMonitor.py -s /var/tmp/apmonitor-prod.json prod-apmonitor-config.yaml

# Instance 2: Development monitoring
./APMonitor.py -s /var/tmp/apmonitor-dev.json dev-apmonitor-config.yaml

# Instance 3: Critical services (high-frequency)
./APMonitor.py -t 5 -s /tmp/apmonitor-critical.json critical-apmonitor-config.yaml
```

Which should mean sensible cardinality rules are enforced: one config per site, one process per config, one and IFF only one; good for running out of crontab. 

**Why separate state files are required**:
- No inter-process file locking mechanism exists
- Concurrent writes from multiple processes will corrupt state files
- Each process maintains independent monitoring schedules and notification state
- Atomic file rotation (`.new` → `.old`) only protects single-process integrity

**Use cases for multiple instances**:
- Different monitoring priorities (high-frequency critical vs. low-frequency non-critical)
- Separate environments (production, staging, development)
- Independent notification channels (ops team vs. dev team)
- Isolated failure domains (prevent one misconfigured monitor from blocking others)

### Override Behavior

Always specify `-s/--statefile` when:
- Running from cron (working directory may vary)
- Requiring tmpfs storage for performance (`-s /tmp/apmonitor-statefile.json`)
- Managing multiple independent monitoring instances
- Deploying in containers or restricted environments

**Example**: Force tmpfs storage (cleared on reboot, faster I/O):
```
./APMonitor.py -s /tmp/apmonitor-statefile.json apmonitor-config.yaml
```

**Note**: The `apmonitor-` prefix prevents naming collisions with other applications using generic `statefile.json` names.



# Developer Notes for modifying `APMonitor.py`

## State File

APMonitor uses a JSON state file to persist monitoring data across runs:

- **Location**: Recommended path is `/tmp/statefile.json` for tmpfs storage (faster, no disk wear)
- **Format**: JSON with per-resource nested objects containing timestamps, status, and counters
- **Atomic Updates**: Uses `.new` and `.old` rotation to prevent corruption on crashes
- **Thread Safety**: Protected by internal lock during concurrent access

The state file tracks:
- `is_up`: Current resource status
- `last_checked`: When resource was last checked
- `last_notified`: When last notification was sent
- `last_alarm_started`: When current/last outage began
- `last_successful_heartbeat`: When heartbeat URL last succeeded
- `down_count`: Consecutive failed checks
- `error_reason`: Last error message

**Note**: If using `/tmp/statefile.json`, the state file is cleared on system reboot. This resets all monitoring history but doesn't affect functionality—monitoring resumes normally on first run.


## Execution Flow

Here are some basic devnotes on how APMonitor is built, in case you want to modify it.

Each invocation of APMonitor:

1. Acquires a PID lockfile via tempfs, using the config path as the hash to support multiple site configs in parallel. 
2. Loads and validates configuration file
3Loads previous state from state file (if exists)
4For each monitor:
   - Checks if `check_every_n_secs` has elapsed since `last_checked`
   - If due: performs resource check
   - If down and `notify_every_n_secs` elapsed: sends notifications
   - If up and heartbeat configured: pings heartbeat URL if due
   - Updates state atomically
5. Saves state file with execution timing
6. Cleans up the PID file if possible.
7. Exits

This stateless design allows APMonitor to be killed/restarted safely at any time without losing monitoring history or creating duplicate notifications.

## Modifying with AI

APMonitor was designed with an engineering based approach to Vibe Coding in mind, should you wish to change it. 

Steps:

1. Paste in `READAI.md` (containing an Entrance Prompt) into your favourite AI coding tool (e.g., Grok 4.1 or Claude Sonnet)
2. Paste in `APMonitor.py` (tell your AI this is the source code)
3. Paste in `README.md` (tell your AI this is the documentation)
4. Vibe your changes as you see fit.

Enjoy!


# Installation Instructions - Debian Linux

This guide covers installing APMonitor as a systemd service on Debian-based systems (Debian 10+, Ubuntu 20.04+).

## Prerequisites

Fresh Debian/Ubuntu system with sudo access.


## Automated Install - Quickstart

If you want to do an automated install, just follow these instructions, otherwise start with **Step 1** below:
```
# Install (requires root)
sudo make install

# Edit configuration
sudo nano /usr/local/etc/apmonitor-config.yaml

# Test configuration
make test-config

# Enable and start service
sudo make enable

# Check status
make status

# View logs
make logs

# Restart after config changes
sudo make restart

# Uninstall completely
sudo make uninstall
```

## Step 1: Install System Dependencies
```
sudo apt update
sudo apt install python3 python3-pip -y
```

## Step 2: Install Python Dependencies

Install dependencies globally (required for systemd service):
```
sudo pip3 install --break-system-packages PyYAML requests pyOpenSSL urllib3
```

**Note**: On Debian 12+, the `--break-system-packages` flag is required. On older systems, omit this flag:
```
sudo pip3 install PyYAML requests pyOpenSSL urllib3
```

**Dependencies installed**:
- `PyYAML` - YAML configuration file parsing
- `requests` - HTTP/HTTPS resource checking and webhook notifications
- `pyOpenSSL` - SSL certificate verification and fingerprint checking
- `urllib3` - HTTP connection pooling (dependency of requests)

## Step 3: Create Monitoring User

Create a dedicated system user for running APMonitor:
```
sudo useradd -r -s /bin/bash -d /var/lib/apmonitor -m monitoring
```

## Step 4: Install APMonitor

Copy the APMonitor script and example configuration to system locations:
```
# Install APMonitor script
sudo cp APMonitor.py /usr/local/bin/
sudo chmod +x /usr/local/bin/APMonitor.py

# Install example configuration
sudo cp example-apmonitor-config.yaml /usr/local/etc/apmonitor-config.yaml
sudo chown monitoring:monitoring /usr/local/etc/apmonitor-config.yaml
sudo chmod 640 /usr/local/etc/apmonitor-config.yaml
```

**Important**: Edit `/usr/local/etc/apmonitor-config.yaml` to configure your monitoring targets, notification endpoints, and site name before proceeding.

## Step 5: Create systemd Service

Create the systemd service definition:
```
sudo nano /etc/systemd/system/apmonitor.service
```

Paste the following content:
```
[Unit]
Description=APMonitor Network Resource Monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do /usr/local/bin/APMonitor.py -vv -s /var/tmp/apmonitor-statefile.json /usr/local/etc/apmonitor-config.yaml; sleep 15; done'
Restart=always
RestartSec=10
User=monitoring
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Save and exit (Ctrl+X, then Y, then Enter in nano).

## Step 6: Enable and Start Service

Reload systemd, enable the service to start on boot, and start it:
```
sudo systemctl daemon-reload
sudo systemctl enable apmonitor.service
sudo systemctl start apmonitor.service
```

## Step 7: Verify Operation

Check service status:
```
sudo systemctl status apmonitor.service
```

View live logs:
```
sudo journalctl -u apmonitor.service -f
```

View recent logs:
```
sudo journalctl -u apmonitor.service -n 100
```

## Troubleshooting

### Test APMonitor Manually

Run APMonitor manually as the monitoring user to verify configuration:
```
sudo -u monitoring /usr/local/bin/APMonitor.py -vv -s /var/tmp/apmonitor-statefile.json /usr/local/etc/apmonitor-config.yaml
```

### Test Webhook Notifications

Test webhook configuration without checking resources:
```
sudo -u monitoring /usr/local/bin/APMonitor.py --test-webhooks -v /usr/local/etc/apmonitor-config.yaml
```

### Check State File Permissions

Verify the monitoring user can write to the state file location:
```
sudo ls -la /var/tmp/apmonitor-statefile.json
```

The `/var/tmp` directory should have permissions `1777` (drwxrwxrwt) allowing any user to create files.

### View Configuration

Display the active configuration:
```
sudo cat /usr/local/etc/apmonitor-config.yaml
```

### Service Management Commands
```
# Stop service
sudo systemctl stop apmonitor.service

# Restart service (after config changes)
sudo systemctl restart apmonitor.service

# Disable service from starting on boot
sudo systemctl disable apmonitor.service

# Check if service is enabled
sudo systemctl is-enabled apmonitor.service
```

## Updating Configuration

After modifying `/usr/local/etc/apmonitor-config.yaml`, restart the service:
```
sudo systemctl restart apmonitor.service
```

Configuration changes take effect on the next monitoring cycle (within 30 seconds).

## Uninstallation

To completely remove APMonitor:
```
# Stop and disable service
sudo systemctl stop apmonitor.service
sudo systemctl disable apmonitor.service

# Remove service file
sudo rm /etc/systemd/system/apmonitor.service
sudo systemctl daemon-reload

# Remove files
sudo rm /usr/local/bin/APMonitor.py
sudo rm /usr/local/etc/apmonitor-config.yaml
sudo rm /var/tmp/apmonitor-statefile.json*

# Remove monitoring user
sudo userdel -r monitoring

# Optionally remove Python dependencies
sudo pip3 uninstall -y PyYAML requests pyOpenSSL urllib3
```

# TODO

- Add additional monitors:
  - TCP &amp; UDP
  - Add `quic` UDP monitoring resource type to replace `https`
  - Make `https` do certificate checking AFTER failed SSL hit & see if we can do in one request (hit an invalid SSL url host to isolate current problem)

- Make email work (right now we're only using webhooks and heartbeats for alerts):
  - With system mailer
  - With specified SMTP server details

- Aggregated root cause alerting:
  - Specify parent dependencies using config option `parent_name` so we have a network topology graph
  - Add loop detection to ensure the topology graph is a DAG
  - Use the topology to only notify outages for the root cause and list the affected services in the same alert
  - When a monitored resource has multiple parent dependencies, specify if it's down when all are down (AND relation) or down when one is down (OR relation)
  - Consider correct use of pre/in/post-order traversal when deciding which alerts to drop

- Convert finished version to pure C `APMonitor.c` 
  - Strictly only with `libc`/SVR4 C Systems Programming dependencies for really tiny cross-platform embedded systems application environments 
  - Add a Mercator + `APTree.c` `#InfoRec` inspired/styled priority queue for handling large numbers of monitored resources with proper realtime programming guarantees
  - Test if we are `root` when doing a `ping` syscall and fallback to direct `SOCK_RAW` if we are for high performance

- Update docs to provide examples for Pushover &amp; Slack

- Refactor retry logic out of checking resources into an enclosing function such that we can add `last_response_time_ms` to statefile for successful requests 

# Licensing & Versioning

APMonitor.py is licensed under the [GNU General Public License version 3](LICENSE.txt).
```
Software: APMonitor 0.1.3
License: GNU General Public License version 3
Licensor: Andrew (AP) Prendergast, ap@andrewprendergast.com -- FSF Member
```

We use [SemVer](http://semver.org/) for version numbering.

[![Free Software Foundation](https://apwww-static-assets.s3.us-west-1.amazonaws.com/images/FSF-Badge-6055467.png)](https://www.fsf.org/)
