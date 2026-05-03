#!/usr/bin/env python3
"""
APMonitor - On-Premises Network Resource Availability Monitor
https://github.com/CompSciFutures/APMonitor

“Commons Clause” License Condition v1.0
=======================================

The Software is provided to you by the Licensor under the License,
as defined below, subject to the following condition.

Without limiting other conditions in the License, the grant of rights
under the License will not include, and the License does not grant to
you, the right to Sell the Software.

For purposes of the foregoing, “Sell” means practicing any or all of
the rights granted to you under the License to provide to third
parties, for a fee or other consideration (including without
limitation fees for hosting or consulting/ support services related
to the Software), a product or service whose value derives, entirely
or substantially, from the functionality of the Software. Any license
notice or attribution required by the License must also include this
Commons Clause License Condition notice.

Software: APMonitor
License: GNU General Public License version 3
Licensor: Andrew (AP) Prendergast, ap@andrewprendergast.com -- FSF Member

GNU General Public License version 3
------------------------------------

(C) COPYRIGHT 2000-2025 Andrew Prendergast

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

__version__ = "1.3.15"
__app_name__ = "APMonitor"

import argparse
import json
import re
from urllib.parse import urlparse
import OpenSSL.crypto
from pathlib import Path
import yaml  # can push into load_config() if this is a dependency problem for you
import requests
import time
import platform
import subprocess
import concurrent.futures
import sys
import threading
import os
from datetime import datetime
import ssl
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import traceback
from typing import Any, Dict, List, Optional, Tuple, Union
import rrdtool
import tempfile
import difflib

# NB: check_quic_url() already has aioquic defined as a function local import so you don't have to lug it around if you don't need it

# Hush insecure SSL warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration constants
MAX_RETRIES: int = 3
MAX_TRY_SECS: int = 20
VERBOSE: int = 0
IGNORE_SSL_ERRORS: bool = True
MAX_THREADS: int = 1
STATEFILE: str = "statefile.json"
STATE: Dict[str, Any] = {}
STATE_LOCK: threading.Lock = threading.Lock()
DEFAULT_CHECK_EVERY_N_SECS: int = 60
DEFAULT_NOTIFY_EVERY_N_SECS: int = 600
DEFAULT_AFTER_EVERY_N_NOTIFICATIONS: int = 1
RRD_ENABLED: bool = False
RRD_ELAPSED_MS: int = 0
RRD_ELAPSED_LOCK: threading.Lock = threading.Lock()

# Global thread-local storage
thread_local: threading.local = threading.local()
thread_local.prefix = None


def to_natural_language_boolean(value: Any) -> bool:
    """Convert various representations to boolean.

    False values: false, no, fail, 0, bad, negative, off, n, f (case-insensitive)
    True values: true, yes, ok, 1, good, positive, on, y, t (case-insensitive)

    Args:
        value: Can be bool, int, str, or None

    Returns:
        bool: The boolean interpretation

    Raises:
        ValueError: If string value is not a recognized boolean representation
    """
    if value is None:
        return False

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return bool(value)

    if isinstance(value, str):
        normalized = value.lower().strip()

        # False values
        if normalized in ['false', 'no', 'fail', '0', 'bad', 'negative', 'off', 'n', 'f']:
            return False

        # True values
        if normalized in ['true', 'yes', 'ok', '1', 'good', 'positive', 'on', 'y', 't']:
            return True

        raise ValueError(f"Unrecognized boolean value: '{value}'")

    # For any other type, use Python's truthiness
    return bool(value)


# Loads YAML or JSON config file
#
# Example Config
# --------------
#
# site: "HomeLab"
# emails:
#   - "ap@andrewprendergast.com"
#   - sfgdfgdfg@sendmonitoringalert.com
#
# monitors:
#
#   - type: ping
#     name: home-fw
#     address: "192.168.1.1"
#     heartbeat_url: "http://google.com/"
#
#   - type: ping
#     name: "Inception t4000"
#     address: "192.168.1.22"
#     heartbeat_url: "http://excite.com/"
#
#   - type: http
#     name: in3245622
#     address: "http://192.168.1.21/Login?oldUrl=Index"
#     expect: "System Name: <b>HomeLab</b>"
#     heartbeat_url: "http://google.com/"
#
def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from JSON or YAML file."""
    path = Path(config_path)

    if not path.exists():
        print(f"Error: Config file '{config_path}' not found", file=sys.stderr)
        sys.exit(1)

    with open(path, 'r') as f:
        if path.suffix in ['.json']:
            return json.load(f)
        elif path.suffix in ['.yaml', '.yml']:
            return yaml.safe_load(f)
        else:
            print(f"Error: Unsupported file format '{path.suffix}'", file=sys.stderr)
            sys.exit(1)


def load_state(statefile_path: str) -> Dict[str, Any]:
    """Load state from JSON file."""
    path = Path(statefile_path)
    if not path.exists():
        return {}

    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        if VERBOSE:
            print(f"Warning: Could not load state from '{statefile_path}': {e}")
        return {}


def update_state(updates: Dict[str, Any]) -> None:
    """Thread-safely update state and write to .new file."""
    global STATE

    with STATE_LOCK:
        STATE.update(updates)

        new_path = Path(STATEFILE + '.new')
        try:
            with open(new_path, 'w') as f:
                json.dump(STATE, f, indent=2)
        except Exception as e:
            print(f"Error: Could not write state to '{new_path}': {e}", file=sys.stderr)

    # keep console logging atomic as well
    sys.stdout.flush()


def save_state(state: Dict[str, Any]) -> None:
    """Rotate state files: current -> .old, .new -> current."""

    global STATE
    STATE = state
    update_state(state)

    path = Path(STATEFILE)
    new_path = Path(STATEFILE + '.new')
    old_path = Path(STATEFILE + '.old')

    try:
        # Rotate files: current -> .old, .new -> current
        if path.exists():
            os.replace(path, old_path)
        if new_path.exists():
            os.replace(new_path, path)
    except Exception as e:
        print(f"Error: Could not rotate state files: {e}", file=sys.stderr)


def format_time_ago(timestamp_or_secs: Union[str, int, float, None]) -> str:
    """Format time difference in human-readable form."""
    if not timestamp_or_secs:
        return "never"

    try:
        # If it's an integer, treat as seconds directly
        if isinstance(timestamp_or_secs, int) or isinstance(timestamp_or_secs, float):
            total_seconds = int(timestamp_or_secs)
        else:
            # Otherwise parse as ISO timestamp
            last_time = datetime.fromisoformat(timestamp_or_secs)
            delta = datetime.now() - last_time
            total_seconds = int(delta.total_seconds())

        if total_seconds < 60:
            return f"{total_seconds} secs"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f"{minutes} mins {seconds} secs"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours} hrs {minutes} mins"
        else:
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            return f"{days} days {hours} hrs"
    except:
        return "unknown"


class ConfigError(Exception):
    """Configuration validation error."""
    pass


def print_and_exit_on_bad_config(config: Dict[str, Any]) -> None:
    """Validate configuration structure and required fields."""
    try:
        # Check site is present and is a dict
        if 'site' not in config:
            raise ConfigError("Missing required field: 'site'")
        if not isinstance(config['site'], dict):
            raise ConfigError("Field 'site' must be a dictionary")

        site = config['site']

        # Check site name is present and is a string
        if 'name' not in site:
            raise ConfigError("Missing required field: 'site.name'")
        if not isinstance(site['name'], str):
            raise ConfigError("Field 'site.name' must be a string")

        # Validate optional site.email_server
        if 'email_server' in site:
            if not isinstance(site['email_server'], dict):
                raise ConfigError("Field 'site.email_server' must be a dictionary")

            email_server = site['email_server']

            if 'smtp_host' not in email_server:
                raise ConfigError("Field 'site.email_server': missing required field 'smtp_host'")
            if not isinstance(email_server['smtp_host'], str):
                raise ConfigError("Field 'site.email_server.smtp_host' must be a string")

            if 'smtp_port' not in email_server:
                raise ConfigError("Field 'site.email_server': missing required field 'smtp_port'")
            if not isinstance(email_server['smtp_port'], int) or email_server['smtp_port'] < 1 or email_server['smtp_port'] > 65535:
                raise ConfigError("Field 'site.email_server.smtp_port' must be an integer between 1 and 65535")

            if 'smtp_username' in email_server:
                if not isinstance(email_server['smtp_username'], str):
                    raise ConfigError("Field 'site.email_server.smtp_username' must be a string")

            if 'smtp_password' in email_server:
                if not isinstance(email_server['smtp_password'], str):
                    raise ConfigError("Field 'site.email_server.smtp_password' must be a string")

            if 'from_address' not in email_server:
                raise ConfigError("Field 'site.email_server': missing required field 'from_address'")
            if not isinstance(email_server['from_address'], str):
                raise ConfigError("Field 'site.email_server.from_address' must be a string")

            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email_server['from_address']):
                raise ConfigError(f"Field 'site.email_server.from_address': '{email_server['from_address']}' is not a valid email address")

            if 'use_tls' in email_server:
                if not isinstance(email_server['use_tls'], bool):
                    raise ConfigError("Field 'site.email_server.use_tls' must be a boolean")

        # Validate optional site.outage_emails
        if 'outage_emails' in site:
            if 'email_server' not in site:
                raise ConfigError("Field 'site.outage_emails' can only be specified if 'site.email_server' is configured")

            if not isinstance(site['outage_emails'], list):
                raise ConfigError("Field 'site.outage_emails' must be a list")

            for i, email_entry in enumerate(site['outage_emails']):
                if not isinstance(email_entry, dict):
                    raise ConfigError(f"Field 'site.outage_emails[{i}]' must be a dictionary")
                if 'email' not in email_entry:
                    raise ConfigError(f"Field 'site.outage_emails[{i}]': missing required field 'email'")
                if not isinstance(email_entry['email'], str):
                    raise ConfigError(f"Field 'site.outage_emails[{i}].email' must be a string")

                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if not re.match(email_pattern, email_entry['email']):
                    raise ConfigError(f"Field 'site.outage_emails[{i}].email': '{email_entry['email']}' is not a valid email address")

                if 'email_outages' in email_entry:
                    try:
                        to_natural_language_boolean(email_entry['email_outages'])
                    except ValueError as e:
                        raise ConfigError(f"Field 'site.outage_emails[{i}].email_outages': {e}")

                if 'email_recoveries' in email_entry:
                    try:
                        to_natural_language_boolean(email_entry['email_recoveries'])
                    except ValueError as e:
                        raise ConfigError(f"Field 'site.outage_emails[{i}].email_recoveries': {e}")

                if 'email_reminders' in email_entry:
                    try:
                        to_natural_language_boolean(email_entry['email_reminders'])
                    except ValueError as e:
                        raise ConfigError(f"Field 'site.outage_emails[{i}].email_reminders': {e}")

        # Validate optional site.outage_webhooks
        if 'outage_webhooks' in site:
            if not isinstance(site['outage_webhooks'], list):
                raise ConfigError("Field 'site.outage_webhooks' must be a list")

            for i, webhook in enumerate(site['outage_webhooks']):
                if not isinstance(webhook, dict):
                    raise ConfigError(f"Field 'site.outage_webhooks[{i}]' must be a dictionary")

                if 'endpoint_url' not in webhook:
                    raise ConfigError(f"Missing required field: 'site.outage_webhooks[{i}].endpoint_url'")
                if not isinstance(webhook['endpoint_url'], str):
                    raise ConfigError(f"Field 'site.outage_webhooks[{i}].endpoint_url' must be a string")

                parsed_webhook = urlparse(webhook['endpoint_url'])
                if not parsed_webhook.scheme or not parsed_webhook.netloc:
                    raise ConfigError(f"Field 'site.outage_webhooks[{i}].endpoint_url' must be a valid URL with scheme and host, got '{webhook['endpoint_url']}'")

                if 'request_method' not in webhook:
                    raise ConfigError(f"Missing required field: 'site.outage_webhooks[{i}].request_method'")
                if webhook['request_method'] not in ['GET', 'POST']:
                    raise ConfigError(f"Field 'site.outage_webhooks[{i}].request_method' must be 'GET' or 'POST', got '{webhook['request_method']}'")

                if 'request_encoding' not in webhook:
                    raise ConfigError(f"Missing required field: 'site.outage_webhooks[{i}].request_encoding'")
                if webhook['request_encoding'] not in ['URL', 'HTML', 'JSON', 'CSVQUOTED']:
                    raise ConfigError(f"Field 'site.outage_webhooks[{i}].request_encoding' must be one of 'URL', 'HTML', 'JSON', 'CSVQUOTED', got '{webhook['request_encoding']}'")

                if 'request_prefix' in webhook:
                    if not isinstance(webhook['request_prefix'], str):
                        raise ConfigError(f"Field 'site.outage_webhooks[{i}].request_prefix' must be a string")

                if 'request_suffix' in webhook:
                    if not isinstance(webhook['request_suffix'], str):
                        raise ConfigError(f"Field 'site.outage_webhooks[{i}].request_suffix' must be a string")

        # Validate optional site.max_threads
        if 'max_threads' in site:
            if not isinstance(site['max_threads'], int) or site['max_threads'] < 1:
                raise ConfigError("Field 'site.max_threads' must be a positive integer")

        if 'max_retries' in site:
            if not isinstance(site['max_retries'], int) or site['max_retries'] < 1:
                raise ConfigError("Field 'site.max_retries' must be a positive integer")

        if 'max_try_secs' in site:
            if not isinstance(site['max_try_secs'], int) or site['max_try_secs'] < 1:
                raise ConfigError("Field 'site.max_try_secs' must be a positive integer")

        if 'check_every_n_secs' in site:
            if not isinstance(site['check_every_n_secs'], int) or site['check_every_n_secs'] < 1:
                raise ConfigError("Field 'site.check_every_n_secs' must be a positive integer")

        if 'notify_every_n_secs' in site:
            if not isinstance(site['notify_every_n_secs'], int) or site['notify_every_n_secs'] < 1:
                raise ConfigError("Field 'site.notify_every_n_secs' must be a positive integer")

        if 'after_every_n_notifications' in site:
            if not isinstance(site['after_every_n_notifications'], int) or site['after_every_n_notifications'] < 1:
                raise ConfigError("Field 'site.after_every_n_notifications' must be a positive integer")

        if 'alarms' in site:
            try:
                to_natural_language_boolean(site['alarms'])
            except ValueError as e:
                raise ConfigError(f"Field 'site.alarms': {e}")

        valid_site_params = {
            'name', 'email_server', 'outage_emails', 'outage_webhooks', 'max_threads', 'max_retries',
            'max_try_secs', 'check_every_n_secs', 'notify_every_n_secs', 'after_every_n_notifications',
            'alarms'
        }
        unrecognized_site = set(site.keys()) - valid_site_params
        if unrecognized_site:
            raise ConfigError(f"Unrecognized site-level parameters: {', '.join(sorted(unrecognized_site))}")

        if 'monitors' not in config:
            raise ConfigError("Missing required field: 'monitors'")
        if not isinstance(config['monitors'], list):
            raise ConfigError("Field 'monitors' must be a list")
        if len(config['monitors']) == 0:
            raise ConfigError("Field 'monitors' must contain at least one monitor")

        monitor_names = set()

        for i, monitor in enumerate(config['monitors']):
            if not isinstance(monitor, dict):
                raise ConfigError(f"Monitor {i}: must be a dictionary")

            required_fields = ['type', 'name', 'address']
            for field in required_fields:
                if field not in monitor:
                    raise ConfigError(
                        f"Monitor {i} (name: {monitor.get('name', 'unknown')}): missing required field '{field}'")

            valid_monitor_params = {
                'type', 'name', 'address', 'check_every_n_secs', 'notify_every_n_secs',
                'notify_on_down_every_n_secs', 'after_every_n_notifications', 'heartbeat_url',
                'heartbeat_every_n_secs', 'expect', 'ssl_fingerprint', 'ignore_ssl_expiry', 'email',
                'send', 'content_type', 'community', 'percentile', 'port', 'mac', 'always_up',
                'display', 'alarms'
            }
            unrecognized_monitor = set(monitor.keys()) - valid_monitor_params
            if unrecognized_monitor:
                raise ConfigError(f"Monitor {i} (name: {monitor.get('name', 'unknown')}): unrecognized parameters: {', '.join(sorted(unrecognized_monitor))}")

            if not isinstance(monitor['name'], str):
                raise ConfigError(f"Monitor {i} (name: {monitor.get('name', 'unknown')}): 'name' must be a string")

            name = monitor['name']
            if name in monitor_names:
                raise ConfigError(f"Monitor {i} (name: {name}): duplicate monitor name '{name}'")
            monitor_names.add(name)

            # 'snmp' removed — direct users to 'ports'
            valid_types = ['ping', 'http', 'quic', 'tcp', 'udp', 'ports', 'port', 'host']
            if monitor['type'] == 'snmp':
                raise ConfigError(f"Monitor {i} (name: {name}): type 'snmp' is not valid. Did you mean type: ports?")
            if monitor['type'] not in valid_types:
                raise ConfigError(f"Monitor {i} (name: {monitor.get('name', 'unknown')}): invalid type '{monitor['type']}', must be one of {valid_types}")

            if not isinstance(monitor['address'], str):
                raise ConfigError(f"Monitor {i} (name: {monitor.get('name', 'unknown')}): 'address' must be a string")

            if 'check_every_n_secs' in monitor:
                if not isinstance(monitor['check_every_n_secs'], int) or monitor['check_every_n_secs'] < 1:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'check_every_n_secs' must be a positive integer")

            if 'notify_on_down_every_n_secs' in monitor:
                if not isinstance(monitor['notify_on_down_every_n_secs'], int) or monitor['notify_on_down_every_n_secs'] < 1:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'notify_on_down_every_n_secs' must be a positive integer")
                if 'check_every_n_secs' in monitor:
                    if monitor['notify_on_down_every_n_secs'] < monitor['check_every_n_secs']:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'notify_on_down_every_n_secs' must be >= 'check_every_n_secs'")

            if 'after_every_n_notifications' in monitor:
                if 'notify_every_n_secs' not in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'after_every_n_notifications' can only be specified if 'notify_every_n_secs' is present")
                if not isinstance(monitor['after_every_n_notifications'], int) or monitor['after_every_n_notifications'] < 1:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'after_every_n_notifications' must be a positive integer")

            if 'email' in monitor:
                try:
                    to_natural_language_boolean(monitor['email'])
                except ValueError as e:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'email' field: {e}")

            if 'display' in monitor:
                try:
                    to_natural_language_boolean(monitor['display'])
                except ValueError as e:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'display' field: {e}")

            if 'alarms' in monitor:
                try:
                    to_natural_language_boolean(monitor['alarms'])
                except ValueError as e:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'alarms' field: {e}")

            monitor_type = monitor['type']
            address = monitor['address']

            if monitor_type == 'ping':
                ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
                hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
                if not (re.match(ipv4_pattern, address) or re.match(ipv6_pattern, address) or re.match(hostname_pattern, address)):
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must be a valid hostname, IPv4 or IPv6 address, got '{address}'")
                for forbidden in ('expect', 'ssl_fingerprint', 'percentile'):
                    if forbidden in monitor:
                        raise ConfigError(f"Monitor {i} (name: {name}): '{forbidden}' field is not valid for ping monitors")

            elif monitor_type in ['http', 'quic']:
                parsed = urlparse(address)
                if not parsed.scheme or not parsed.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must be a valid URL with scheme and host, got '{address}'")
                if 'expect' in monitor:
                    if not isinstance(monitor['expect'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'expect' must be a string")
                    if len(monitor['expect']) == 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'expect' must not be empty")
                if 'ssl_fingerprint' in monitor:
                    if not isinstance(monitor['ssl_fingerprint'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'ssl_fingerprint' must be a string")
                    fingerprint_clean = monitor['ssl_fingerprint'].replace(':', '')
                    if not re.match(r'^[0-9a-fA-F]+$', fingerprint_clean):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'ssl_fingerprint' must be a valid hex string")
                    fp_len = len(fingerprint_clean)
                    if fp_len == 0 or (fp_len & (fp_len - 1)) != 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'ssl_fingerprint' length must be a power of two (got {fp_len} hex characters)")
                if 'percentile' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'percentile' field is only valid for 'ports' monitors")

            elif monitor_type in ['tcp', 'udp']:
                parsed = urlparse(address)
                if monitor_type == 'tcp' and parsed.scheme != 'tcp':
                    raise ConfigError(f"Monitor {i} (name: {name}): TCP monitor must use 'tcp://' scheme, got '{address}'")
                if monitor_type == 'udp' and parsed.scheme != 'udp':
                    raise ConfigError(f"Monitor {i} (name: {name}): UDP monitor must use 'udp://' scheme, got '{address}'")
                if not parsed.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must include hostname/IP and port, got '{address}'")
                if 'send' in monitor:
                    if not isinstance(monitor['send'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'send' must be a string")
                if 'content_type' in monitor:
                    if 'send' not in monitor:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'content_type' can only be specified if 'send' is present")
                    valid_content_types = ['text', 'hex', 'base64']
                    if monitor['content_type'] not in valid_content_types:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'content_type' must be one of {valid_content_types}, got '{monitor['content_type']}'")
                if 'expect' in monitor:
                    if not isinstance(monitor['expect'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'expect' must be a string")
                    if len(monitor['expect']) == 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'expect' must not be empty")
                for forbidden in ('ssl_fingerprint', 'percentile'):
                    if forbidden in monitor:
                        raise ConfigError(f"Monitor {i} (name: {name}): '{forbidden}' field is not valid for {monitor_type} monitors")

            elif monitor_type == 'ports':
                # ports: merged snmp metrics + port state/MAC monitoring
                parsed = urlparse(address)
                if parsed.scheme != 'snmp':
                    raise ConfigError(f"Monitor {i} (name: {name}): ports monitor must use 'snmp://' scheme, got '{address}'")
                if not parsed.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must include hostname/IP, got '{address}'")

                hostname = parsed.hostname
                if hostname:
                    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
                    hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
                    if not (re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname) or re.match(hostname_pattern, hostname)):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'address' hostname must be valid hostname, IPv4 or IPv6 address, got '{hostname}'")

                if 'community' in monitor:
                    if not isinstance(monitor['community'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must be a string")
                    if len(monitor['community']) == 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must not be empty")

                if 'percentile' in monitor:
                    if not isinstance(monitor['percentile'], int) or not (1 <= monitor['percentile'] <= 99):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'percentile' must be an integer between 1 and 99")

                for forbidden in ('expect', 'ssl_fingerprint', 'ignore_ssl_expiry', 'send', 'content_type'):
                    if forbidden in monitor:
                        raise ConfigError(f"Monitor {i} (name: {name}): '{forbidden}' field not valid for ports monitors")

            elif monitor_type == 'host':
                parsed = urlparse(address)
                if parsed.scheme != 'snmp':
                    raise ConfigError(f"Monitor {i} (name: {name}): host monitor must use 'snmp://' scheme, got '{address}'")
                if not parsed.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must include hostname/IP, got '{address}'")

                hostname = parsed.hostname
                if hostname:
                    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
                    hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
                    if not (re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname) or re.match(hostname_pattern, hostname)):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'address' hostname must be valid hostname, IPv4 or IPv6 address, got '{hostname}'")

                if 'community' in monitor:
                    if not isinstance(monitor['community'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must be a string")
                    if len(monitor['community']) == 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must not be empty")

                for forbidden in ('expect', 'ssl_fingerprint', 'ignore_ssl_expiry', 'send', 'content_type', 'percentile'):
                    if forbidden in monitor:
                        raise ConfigError(f"Monitor {i} (name: {name}): '{forbidden}' field not valid for host monitors")

            elif monitor_type == 'port':
                parsed = urlparse(address)
                if parsed.scheme != 'snmp':
                    raise ConfigError(f"Monitor {i} (name: {name}): port monitor must use 'snmp://' scheme, got '{address}'")
                if not parsed.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must include hostname/IP, got '{address}'")

                hostname = parsed.hostname
                if hostname:
                    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
                    hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
                    if not (re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname) or re.match(hostname_pattern, hostname)):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'address' hostname must be valid hostname, IPv4 or IPv6 address, got '{hostname}'")

                if 'port' not in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'port' (ifIndex) is required for port monitors")
                if not isinstance(monitor['port'], int) or monitor['port'] < 0:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'port' must be a non-negative integer (ifIndex)")

                if 'mac' not in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'mac' (pinned MAC address) is required for port monitors")
                if not isinstance(monitor['mac'], str):
                    raise ConfigError(f"Monitor {i} (name: {name}): 'mac' must be a string")
                if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', monitor['mac']):
                    raise ConfigError(f"Monitor {i} (name: {name}): 'mac' must be a valid MAC address (XX:XX:XX:XX:XX:XX), got '{monitor['mac']}'")

                if 'always_up' in monitor:
                    try:
                        to_natural_language_boolean(monitor['always_up'])
                    except ValueError as e:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'always_up' field: {e}")

                if 'community' in monitor:
                    if not isinstance(monitor['community'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must be a string")
                    if len(monitor['community']) == 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must not be empty")

                for forbidden in ('expect', 'ssl_fingerprint', 'ignore_ssl_expiry', 'send', 'content_type', 'percentile'):
                    if forbidden in monitor:
                        raise ConfigError(f"Monitor {i} (name: {name}): '{forbidden}' field not valid for port monitors")

            if 'heartbeat_url' in monitor:
                if not isinstance(monitor['heartbeat_url'], str):
                    raise ConfigError(f"Monitor {i} (name: {name}): 'heartbeat_url' must be a string")
                parsed_heartbeat = urlparse(monitor['heartbeat_url'])
                if not parsed_heartbeat.scheme or not parsed_heartbeat.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'heartbeat_url' must be a valid URL with scheme and host, got '{monitor['heartbeat_url']}'")

            if 'heartbeat_every_n_secs' in monitor:
                if 'heartbeat_url' not in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'heartbeat_every_n_secs' can only be specified if 'heartbeat_url' is present")
                if not isinstance(monitor['heartbeat_every_n_secs'], int) or monitor['heartbeat_every_n_secs'] < 1:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'heartbeat_every_n_secs' must be a positive integer")

            if 'ignore_ssl_expiry' in monitor:
                if monitor_type not in ['http', 'quic']:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'ignore_ssl_expiry' field is only valid for 'http' and 'quic' monitors")
                try:
                    to_natural_language_boolean(monitor['ignore_ssl_expiry'])
                except ValueError as e:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'ignore_ssl_expiry' field: {e}")

    except ConfigError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


def check_http_url_resource(
        url: str,
        name: str,
        ssl_fingerprint: Optional[str],
        ignore_ssl_expiry: bool,
        send_data: Optional[str] = None,
        content_type: Optional[str] = None) \
        -> Tuple[Optional[str], Optional[int], Any, Optional[str]]:
    """Perform HTTP/S request and return None if OK, error message if failed."""
    prefix = getattr(thread_local, 'prefix', '')
    error_msg = None

    # parse the url and don't proceed if it's not pure HTTP/S
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        error_msg = f"{parsed.scheme.upper()} protocol not supported for HTTP, use http or https"
        print(f"{prefix}HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
        return error_msg, None, None, None

    # calculate is_ssl
    is_ssl = parsed.scheme == 'https'

    # Determine if we need to verify SSL
    if is_ssl and (ssl_fingerprint or not ignore_ssl_expiry):
        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            # Get server certificate
            cert_pem = ssl.get_server_certificate((hostname, port))
            cert_der = ssl.PEM_cert_to_DER_cert(cert_pem)

            # Check fingerprint if provided
            if ssl_fingerprint:
                server_fingerprint = hashlib.sha256(cert_der).hexdigest()
                expected_fingerprint = ssl_fingerprint.replace(':', '').lower()

                if server_fingerprint != expected_fingerprint:
                    error_msg = f"SSL fingerprint mismatch"
                    if VERBOSE:
                        print(f"{prefix}SSL fingerprint check FAILED for '{name}': expected {expected_fingerprint}, got {server_fingerprint}")
                    print(f"{prefix}HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                    return error_msg, None, None, None

                if VERBOSE:
                    print(f"{prefix}SSL fingerprint check PASSED for '{name}'")

            # Check certificate expiry unless ignored
            if not ignore_ssl_expiry:
                try:
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
                    not_after_asn1 = x509.get_notAfter()

                    if VERBOSE > 1:
                        print(f"{prefix}DEBUG: notAfter raw (ASN1) = {not_after_asn1}")

                    if not not_after_asn1:
                        error_msg = "Certificate has no expiry date"
                        print(f"{prefix}HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                        return error_msg, None, None, None

                    not_after_str = not_after_asn1.decode('ascii')
                    not_after = datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ')

                    if datetime.now() > not_after:
                        error_msg = f"SSL certificate expired on {not_after}"
                        if VERBOSE:
                            print(f"{prefix}SSL certificate expiry check FAILED for '{name}': expired on {not_after}")
                        print(f"{prefix}HTTP/S check FAILED for '{name}' at '{url}': SSL certificate expired", file=sys.stderr)
                        return error_msg, None, None, None

                    if VERBOSE:
                        print(f"{prefix}SSL certificate expiry check PASSED for '{name}': valid until {not_after}")

                except Exception as e:
                    error_msg = f"Certificate parsing error: {e}"
                    print(f"{prefix}HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                    return error_msg, None, None, None
            elif VERBOSE:
                print(f"{prefix}SSL certificate expiry check SKIPPED for '{name}' (ignore_ssl_expiry=True)")

        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            print(f"{prefix}HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
            return error_msg, None, None, None

        # Certificate checks passed, proceed with verification disabled (we already validated)
        verify_ssl = False
    elif is_ssl:
        # HTTPS but no certificate checks requested, use standard verification
        verify_ssl = not IGNORE_SSL_ERRORS
    else:
        # HTTP - no SSL verification
        verify_ssl = False

    try:
        # Determine request method and prepare data
        if send_data:
            # POST request with data
            # Send data as UTF-8 encoded bytes
            data_to_send = send_data.encode('utf-8')

            # Use provided content_type or default to text/plain
            headers = {'Content-Type': content_type if content_type else 'text/plain; charset=utf-8'}

            if VERBOSE:
                print(f"{prefix}HTTP/S POST sending {len(data_to_send)} bytes to '{name}' at '{url}' (Content-Type: {headers['Content-Type']})")

            response = requests.post(url, data=data_to_send, headers=headers, timeout=MAX_TRY_SECS, verify=verify_ssl)
        else:
            # GET request (original behavior)
            response = requests.get(url, timeout=MAX_TRY_SECS, verify=verify_ssl)

        # Return response details for expect checking
        return None, response.status_code, response.headers, response.text

    except requests.exceptions.RequestException as e:
        # Extract the root cause from nested exceptions (check both __cause__ and __context__)
        root_cause = e
        while True:
            next_cause = getattr(root_cause, '__cause__', None) or getattr(root_cause, '__context__', None)
            if next_cause is None or next_cause == root_cause:
                break
            root_cause = next_cause

        error_msg = f"{type(root_cause).__name__}: {root_cause}"
        print(f"{prefix}HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
        return error_msg, None, None, None


def check_quic_url_resource(
        url: str,
        name: str,
        ssl_fingerprint: Optional[str],
        ignore_ssl_expiry: bool,
        send_data: Optional[str] = None,
        content_type: Optional[str] = None) \
        -> Tuple[Optional[str], Optional[int], Any, Optional[str]]:
    """Perform QUIC/HTTP3 request and return None if OK, error message if failed."""
    import asyncio
    prefix = getattr(thread_local, 'prefix', '')

    async def _check_quic_url_async():
        """Async implementation of QUIC/HTTP3 check."""
        from aioquic.asyncio.client import connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3_ALPN
        from aioquic.h3.events import HeadersReceived, DataReceived, H3Event
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import QuicEvent
        import OpenSSL.crypto

        error_msg = None

        # Parse the URL and check scheme
        parsed = urlparse(url)
        if parsed.scheme not in ('https', 'quic'):
            error_msg = f"{parsed.scheme.upper()} protocol not supported for QUIC, use https or quic"
            print(f"{prefix}QUIC check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
            return error_msg, None, None, None

        hostname = parsed.hostname
        port = parsed.port or 443
        path = parsed.path or '/'
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # Configure QUIC connection with timeout
        configuration = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=True,
            verify_mode=ssl.CERT_NONE if (ssl_fingerprint or ignore_ssl_expiry) else ssl.CERT_REQUIRED,
            idle_timeout=MAX_TRY_SECS
        )

        # Storage for response
        response_headers = None
        response_data = b""
        response_complete = asyncio.Event()

        # Custom protocol to handle HTTP/3 events
        class HttpClientProtocol(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                from aioquic.h3.connection import H3Connection
                self._http = H3Connection(self._quic)

            def quic_event_received(self, event: QuicEvent):
                nonlocal response_headers, response_data

                # Pass QUIC event to HTTP/3 layer
                for h3_event in self._http.handle_event(event):
                    if isinstance(h3_event, HeadersReceived):
                        response_headers = h3_event.headers
                        if VERBOSE > 2:
                            print(f"{prefix}DEBUG: Received headers: {response_headers}")

                    elif isinstance(h3_event, DataReceived):
                        response_data += h3_event.data
                        if VERBOSE > 2:
                            print(f"{prefix}DEBUG: Received {len(h3_event.data)} bytes, stream_ended={h3_event.stream_ended}, total={len(response_data)}")
                        if h3_event.stream_ended:
                            response_complete.set()

        try:
            # Establish QUIC connection with custom protocol and timeout
            async with asyncio.timeout(MAX_TRY_SECS):
                async with connect(
                        hostname,
                        port,
                        configuration=configuration,
                        create_protocol=HttpClientProtocol,
                ) as protocol:

                    # Get the peer certificate
                    quic = protocol._quic
                    tls = quic.tls

                    # Extract certificate from TLS connection
                    if tls and hasattr(tls, 'peer_certificate'):
                        peer_cert_der = tls.peer_certificate

                        if peer_cert_der:
                            # Check fingerprint if provided
                            if ssl_fingerprint:
                                server_fingerprint = hashlib.sha256(peer_cert_der).hexdigest()
                                expected_fingerprint = ssl_fingerprint.replace(':', '').lower()

                                if server_fingerprint != expected_fingerprint:
                                    error_msg = f"SSL fingerprint mismatch"
                                    if VERBOSE:
                                        print(f"{prefix}SSL fingerprint check FAILED for '{name}': expected {expected_fingerprint}, got {server_fingerprint}")
                                    print(f"{prefix}QUIC check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                                    return error_msg, None, None, None

                                if VERBOSE:
                                    print(f"{prefix}SSL fingerprint check PASSED for '{name}'")

                            # Check certificate expiry unless ignored
                            if not ignore_ssl_expiry:
                                try:
                                    # Convert DER to PEM for OpenSSL
                                    cert_pem = ssl.DER_cert_to_PEM_cert(peer_cert_der)
                                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
                                    not_after_asn1 = x509.get_notAfter()

                                    if VERBOSE > 1:
                                        print(f"{prefix}DEBUG: notAfter raw (ASN1) = {not_after_asn1}")

                                    if not not_after_asn1:
                                        error_msg = "Certificate has no expiry date"
                                        print(f"{prefix}QUIC check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                                        return error_msg, None, None, None

                                    not_after_str = not_after_asn1.decode('ascii')
                                    not_after = datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ')

                                    if datetime.now() > not_after:
                                        error_msg = f"SSL certificate expired on {not_after}"
                                        if VERBOSE:
                                            print(f"{prefix}SSL certificate expiry check FAILED for '{name}': expired on {not_after}")
                                        print(f"{prefix}QUIC check FAILED for '{name}' at '{url}': SSL certificate expired", file=sys.stderr)
                                        return error_msg, None, None, None

                                    if VERBOSE:
                                        print(f"{prefix}SSL certificate expiry check PASSED for '{name}': valid until {not_after}")

                                except Exception as e:
                                    error_msg = f"Certificate parsing error: {e}"
                                    print(f"{prefix}QUIC check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                                    return error_msg, None, None, None
                            elif VERBOSE:
                                print(f"{prefix}SSL certificate expiry check SKIPPED for '{name}' (ignore_ssl_expiry=True)")

                    # Access HTTP/3 connection from protocol
                    http = protocol._http

                    # Get next available stream ID
                    stream_id = quic.get_next_available_stream_id()

                    # Determine method and prepare data
                    if send_data:
                        # POST request
                        method = b"POST"

                        # Send data as UTF-8 encoded bytes
                        data_bytes = send_data.encode('utf-8')

                        # Use provided content_type or default to text/plain
                        content_type_header = (content_type if content_type else 'text/plain; charset=utf-8').encode()

                        if VERBOSE:
                            print(f"{prefix}QUIC POST sending {len(data_bytes)} bytes to '{name}' at '{url}' (Content-Type: {content_type_header.decode()})")

                        # Send HTTP POST request with body
                        headers = [
                            (b":method", method),
                            (b":scheme", b"https"),
                            (b":authority", hostname.encode()),
                            (b":path", path.encode()),
                            (b"content-type", content_type_header),
                            (b"content-length", str(len(data_bytes)).encode()),
                            (b"user-agent", b"APMonitor/1.0"),
                        ]

                        http.send_headers(stream_id=stream_id, headers=headers, end_stream=False)
                        http.send_data(stream_id=stream_id, data=data_bytes, end_stream=True)
                    else:
                        # GET request (original behavior)
                        headers = [
                            (b":method", b"GET"),
                            (b":scheme", b"https"),
                            (b":authority", hostname.encode()),
                            (b":path", path.encode()),
                            (b"user-agent", b"APMonitor/1.0"),
                        ]

                        http.send_headers(stream_id=stream_id, headers=headers, end_stream=True)

                    # Transmit the request
                    protocol.transmit()

                    # Wait for response with timeout
                    await response_complete.wait()

                    # Parse response status
                    status_code = None
                    if response_headers:
                        for name_bytes, value_bytes in response_headers:
                            if name_bytes == b":status":
                                status_code = int(value_bytes.decode())
                                break

                    if status_code is None:
                        error_msg = "no status code in response"
                        print(f"{prefix}QUIC check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                        return error_msg, None, None, None

                    # Convert headers to dict for easier checking
                    headers_dict = {}
                    if response_headers:
                        for name_bytes, value_bytes in response_headers:
                            headers_dict[name_bytes.decode('utf-8', errors='ignore')] = value_bytes.decode('utf-8', errors='ignore')

                    # Decode response text
                    response_text = response_data.decode('utf-8', errors='ignore')

                    # Return response details for expect checking
                    return None, status_code, headers_dict, response_text

        except asyncio.TimeoutError:
            error_msg = "timeout"
            print(f"{prefix}QUIC check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
            return error_msg, None, None, None

        except Exception as e:
            # Extract the root cause from nested exceptions
            root_cause = e
            while True:
                next_cause = getattr(root_cause, '__cause__', None) or getattr(root_cause, '__context__', None)
                if next_cause is None or next_cause == root_cause:
                    break
                root_cause = next_cause

            error_msg = f"{type(root_cause).__name__}: {root_cause}"

            # Add traceback in verbose mode
            if VERBOSE > 1:
                print(f"{prefix}DEBUG: Full traceback:", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)

            print(f"{prefix}QUIC check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
            return error_msg, None, None, None

    # Outer function execution
    try:
        # Run with timeout
        result = asyncio.run(_check_quic_url_async())
        return result
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"

        # Add traceback in verbose mode
        if VERBOSE > 1:
            import traceback
            print(f"{prefix}DEBUG: Full outer traceback:", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

        print(f"{prefix}QUIC check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
        return error_msg, None, None, None


def check_tcp_url_resource(
        url: str,
        name: str,
        ssl_fingerprint: Optional[str],
        ignore_ssl_expiry: bool,
        send_data: Optional[str] = None,
        content_type: Optional[str] = None) \
        -> Tuple[Optional[str], Optional[int], Any, Optional[str]]:
    """Perform TCP connection check and return None if OK, error message if failed."""
    import socket

    prefix = getattr(thread_local, 'prefix', '')
    error_msg = None

    # Parse the URL
    parsed = urlparse(url)
    if parsed.scheme != 'tcp':
        error_msg = f"{parsed.scheme.upper()} protocol not supported for TCP, use tcp"
        print(f"{prefix}TCP check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
        return error_msg, None, None, None

    hostname = parsed.hostname
    port = parsed.port

    if not port:
        error_msg = "TCP address must include port"
        print(f"{prefix}TCP check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
        return error_msg, None, None, None

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(MAX_TRY_SECS)

    try:
        # Connect
        sock.connect((hostname, port))

        if VERBOSE:
            print(f"{prefix}TCP connection SUCCESS for '{name}' at '{hostname}:{port}'")

        response_text = ""

        # Send data if specified
        if send_data:
            # Encode based on content_type
            if content_type == 'hex':
                hex_clean = send_data.replace(' ', '').replace(':', '')
                data_to_send = bytes.fromhex(hex_clean)
            elif content_type == 'base64':
                import base64
                data_to_send = base64.b64decode(send_data)
            else:  # text or raw content-type header
                data_to_send = send_data.encode('utf-8')

            sock.sendall(data_to_send)

            if VERBOSE:
                print(f"{prefix}TCP sent {len(data_to_send)} bytes to '{name}'")

        # Always attempt to receive (for server banners like SSH, SMTP, etc.)
        try:
            response_data = sock.recv(4096)
            response_text = response_data.decode('utf-8', errors='ignore')

            if VERBOSE:
                print(f"{prefix}TCP received {len(response_data)} bytes from '{name}': {response_text[:100]}{'...' if len(response_text) > 100 else ''}")
        except socket.timeout:
            # Timeout receiving is only an error if expect is specified
            if VERBOSE and send_data:
                print(f"{prefix}TCP receive timeout for '{name}' (no response after sending data)")

        # Return success with response details
        # status_code=200 for success (HTTP-like convention), headers={} (no headers in TCP)
        return None, 200, {}, response_text

    except socket.timeout:
        error_msg = "connection timeout"
        print(f"{prefix}TCP check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
        return error_msg, None, None, None
    except socket.error as e:
        error_msg = f"socket error: {e}"
        print(f"{prefix}TCP check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
        return error_msg, None, None, None
    finally:
        sock.close()


def check_udp_url_resource(
        url: str,
        name: str,
        ssl_fingerprint: Optional[str],
        ignore_ssl_expiry: bool,
        send_data: Optional[str] = None,
        content_type: Optional[str] = None) \
        -> Tuple[Optional[str], Optional[int], Any, Optional[str]]:
    """Perform UDP send/receive check and return None if OK, error message if failed.

    Note: UDP is connectionless, so "success" means:
    - If expect specified: received matching response
    - If no expect: sendto() succeeded (packet may still be dropped)
    """
    import socket

    prefix = getattr(thread_local, 'prefix', '')
    error_msg = None

    # Parse the URL
    parsed = urlparse(url)
    if parsed.scheme != 'udp':
        error_msg = f"{parsed.scheme.upper()} protocol not supported for UDP, use udp"
        print(f"{prefix}UDP check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
        return error_msg, None, None, None

    hostname = parsed.hostname
    port = parsed.port

    if not port:
        error_msg = "UDP address must include port"
        print(f"{prefix}UDP check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
        return error_msg, None, None, None

    # UDP requires sending data to check connectivity
    if not send_data:
        error_msg = "UDP monitor requires 'send' parameter"
        print(f"{prefix}UDP check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, None, None, None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(MAX_TRY_SECS)

    try:
        # Encode based on content_type
        if content_type == 'hex':
            hex_clean = send_data.replace(' ', '').replace(':', '')
            data_to_send = bytes.fromhex(hex_clean)
        elif content_type == 'base64':
            import base64
            data_to_send = base64.b64decode(send_data)
        else:  # text or raw content-type header
            data_to_send = send_data.encode('utf-8')

        # Send data
        sock.sendto(data_to_send, (hostname, port))

        if VERBOSE:
            print(f"{prefix}UDP sent {len(data_to_send)} bytes to '{name}' at '{hostname}:{port}'")

        response_text = ""

        # Always try to receive response
        try:
            response_data, addr = sock.recvfrom(4096)
            response_text = response_data.decode('utf-8', errors='ignore')

            if VERBOSE:
                print(f"{prefix}UDP received {len(response_data)} bytes from '{name}': {response_text[:100]}{'...' if len(response_text) > 100 else ''}")
        except socket.timeout:
            # Timeout is not an error if no expect specified
            if VERBOSE:
                print(f"{prefix}UDP receive timeout for '{name}' (no response)")

        # Return success with response details
        # status_code=200 for success (HTTP-like convention), headers={} (no headers in UDP)
        return None, 200, {}, response_text

    except socket.error as e:
        error_msg = f"socket error: {e}"
        print(f"{prefix}UDP check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
        return error_msg, None, None, None
    finally:
        sock.close()


def check_url_resource(resource: Dict[str, Any]) -> Optional[str]:
    """Check URL resource (HTTP/QUIC/TCP/UDP) and return None if OK, error message if failed."""
    prefix = getattr(thread_local, 'prefix', '')
    resource_type = resource['type']
    url = resource['address']
    name = resource['name']
    expect = resource.get('expect')
    ssl_fingerprint = resource.get('ssl_fingerprint')
    ignore_ssl_expiry = resource.get('ignore_ssl_expiry', False)
    send_data = resource.get('send')
    content_type = resource.get('content_type')

    # Call the appropriate check function
    ignore_ssl_expiry = to_natural_language_boolean(ignore_ssl_expiry)

    error_msg, status_code, headers, response_text = (
        check_http_url_resource(url, name, ssl_fingerprint, ignore_ssl_expiry, send_data, content_type)
        if resource_type == 'http'
        else check_quic_url_resource(url, name, ssl_fingerprint, ignore_ssl_expiry, send_data, content_type)
        if resource_type == 'quic'
        else check_tcp_url_resource(url, name, ssl_fingerprint, ignore_ssl_expiry, send_data, content_type)
        if resource_type == 'tcp'
        else check_udp_url_resource(url, name, ssl_fingerprint, ignore_ssl_expiry, send_data, content_type)
        if resource_type == 'udp'
        else (f"Unknown URL resource type: {resource_type}", None, None, None)
    )

    # Handle unknown resource type error
    if resource_type not in ('http', 'quic', 'tcp', 'udp'):
        print(f"{prefix}URL check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg

    # If there was a connection/SSL error, return it immediately
    if error_msg is not None:
        return error_msg

    # Handle expect checking - simple string-only approach
    if expect:
        # Check if expected content is in response
        if expect in response_text:
            if VERBOSE:
                print(f"{prefix}{resource_type.upper()} check SUCCESS for '{name}' at '{url}' (expected content found)")
            return None
        else:
            error_msg = f"expected content not found: '{expect}'"
            if VERBOSE:
                print(f"{prefix}{resource_type.upper()} check FAILED for '{name}': expected '{expect}' not found in response")
            print(f"{prefix}{resource_type.upper()} check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
            return error_msg
    else:
        # No expect specified - just check for 200 OK
        if status_code == 200:
            if VERBOSE:
                print(f"{prefix}{resource_type.upper()} check SUCCESS {status_code} for '{name}' at '{url}'")
            return None
        else:
            error_msg = f"error response code {status_code}"
            print(f"{prefix}{resource_type.upper()} check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
            return error_msg


def check_ping_resource(resource: Dict[str, Any]) -> Optional[str]:
    """Ping host and return None if up, error message if down."""
    prefix = getattr(thread_local, 'prefix', '')
    address = resource['address']
    name = resource['name']

    system = platform.system().lower()

    if system == 'linux':
        cmd = ['ping', '-c', '1', '-W', str(MAX_TRY_SECS), address]
    elif system == 'darwin':
        cmd = ['ping', '-c', '1', '-W', str(MAX_TRY_SECS * 1000), address]
    elif system == 'windows':
        cmd = ['ping', '-n', '1', '-w', str(MAX_TRY_SECS * 1000), address]
    else:
        cmd = ['ping', '-c', '1', '-W', str(MAX_TRY_SECS), address]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=MAX_TRY_SECS + 2)
        if result.returncode == 0:
            if VERBOSE:
                print(f"{prefix}PING check SUCCESS for '{name}' at '{address}'")
            return None
        else:
            error_msg = "host unreachable"
            print(f"{prefix}PING check FAILED for '{name}' at '{address}': {error_msg}", file=sys.stderr)
            return error_msg
    except subprocess.TimeoutExpired:
        error_msg = "timeout"
        print(f"{prefix}PING check FAILED for '{name}' at '{address}': {error_msg}", file=sys.stderr)
        return error_msg


def collect_snmp_detail(
        session: Any,
        vendor: Optional[str],
        interfaces: Dict[str, Dict[str, Any]],
        macs_by_ifindex: Dict[str, list],
        arp_by_mac: Dict[str, str]) -> Dict[str, Any]:
    """Collect detail data for monitor detail page from an already-open SNMP session.

    Gathers sysName/Location/Contact, ifAlias, ifSpeed, slot (ENTITY-MIB + ifDescr fallback),
    LLDP/CDP neighbours, and ARP→IP→PTR hostname mapping.

    DNS PTR lookups are capped at 50 per poll — warning logged if capped.

    Args:
        session:         Open easysnmp Session
        vendor:          Detected vendor string ('cisco', 'hp', 'juniper', 'ubiquiti', None)
        interfaces:      Dict {if_index: {'name': ifDescr, ...}} — already collected by caller
        macs_by_ifindex: Dict {if_index: [mac, ...]} — already collected by caller
        arp_by_mac:      Dict {mac: ip} — already collected by caller

    Returns:
        detail dict suitable for storage under state[name]['detail']
    """
    import socket

    prefix = getattr(thread_local, 'prefix', '')

    # Standard MIB-II OIDs
    OID_SYS_NAME = '1.3.6.1.2.1.1.5.0'
    OID_SYS_LOCATION = '1.3.6.1.2.1.1.6.0'
    OID_SYS_CONTACT = '1.3.6.1.2.1.1.4.0'
    OID_IF_ALIAS = '1.3.6.1.2.1.31.1.1.1.18'
    OID_IF_HIGH_SPEED = '1.3.6.1.2.1.31.1.1.1.15'  # ifHighSpeed (Mbps)
    OID_IF_SPEED = '1.3.6.1.2.1.2.2.1.5'  # ifSpeed (bps)

    # ENTITY-MIB OIDs
    OID_ENTITY_ALIAS_MAP = '1.3.6.1.2.1.47.2.1.1.1.2'  # entAliasMappingIdentifier
    OID_ENTITY_CONTAINED = '1.3.6.1.2.1.47.1.1.1.1.4'  # entPhysicalContainedIn
    OID_ENTITY_CLASS = '1.3.6.1.2.1.47.1.1.1.1.5'  # entPhysicalClass
    OID_ENTITY_DESCR = '1.3.6.1.2.1.47.1.1.1.1.2'  # entPhysicalDescr

    # LLDP OIDs
    OID_LLDP_REM_SYS_NAME = '1.0.8802.1.1.2.1.4.1.1.9'  # lldpRemSysName
    OID_LLDP_REM_PORT_DESC = '1.0.8802.1.1.2.1.4.1.1.8'  # lldpRemPortDesc

    # CDP OIDs (Cisco only)
    OID_CDP_CACHE_DEVICE_ID = '1.3.6.1.4.1.9.9.23.1.2.1.1.6'  # cdpCacheDeviceId
    OID_CDP_CACHE_DEVICE_PORT = '1.3.6.1.4.1.9.9.23.1.2.1.1.7'  # cdpCacheDevicePort

    # ifDescr slot parsing patterns — tried in order, first match wins
    # Group 1 captures the slot number
    SLOT_PATTERNS = [
        (r'[A-Za-z\-]+(\d+)/\d+/\d+', 1),  # Cisco 3-part (Gi1/0/24), Juniper (ge-0/0/1)
        (r'[A-Za-z\-]*(\d+)/\d+', 1),  # Cisco 2-part (Gi0/24), HP (1/0/24)
    ]

    # ENTITY-MIB physical class values
    ENTITY_CLASS_SLOT = '5'
    ENTITY_CLASS_MODULE = '6'

    detail: Dict[str, Any] = {
        'sys_name': None,
        'sys_location': None,
        'sys_contact': None,
        'interfaces': {},
    }

    # --- sysName / sysLocation / sysContact ---
    for key, oid in [('sys_name', OID_SYS_NAME), ('sys_location', OID_SYS_LOCATION), ('sys_contact', OID_SYS_CONTACT)]:
        try:
            detail[key] = session.get(oid).value
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}DETAIL {key} FAILED: {e}")

    # --- ifAlias walk ---
    alias_by_index: Dict[str, str] = {}
    try:
        for item in session.walk(OID_IF_ALIAS):
            alias_by_index[item.oid.split('.')[-1]] = item.value
    except Exception as e:
        if VERBOSE:
            print(f"{prefix}DETAIL ifAlias walk FAILED: {e}")

    # --- ifHighSpeed / ifSpeed walk ---
    speed_by_index: Dict[str, int] = {}  # Mbps
    try:
        for item in session.walk(OID_IF_HIGH_SPEED):
            idx = item.oid.split('.')[-1]
            try:
                speed_by_index[idx] = int(item.value)
            except Exception:
                pass
    except Exception as e:
        if VERBOSE:
            print(f"{prefix}DETAIL ifHighSpeed walk FAILED: {e}")

    # ifSpeed fallback for interfaces where ifHighSpeed == 0
    try:
        for item in session.walk(OID_IF_SPEED):
            idx = item.oid.split('.')[-1]
            if speed_by_index.get(idx, 0) == 0:
                try:
                    speed_by_index[idx] = int(item.value) // 1_000_000  # bps → Mbps
                except Exception:
                    pass
    except Exception as e:
        if VERBOSE:
            print(f"{prefix}DETAIL ifSpeed walk FAILED: {e}")

    # --- ENTITY-MIB slot resolution ---
    # Build: ifIndex → entPhysicalIndex (port entity) via entAliasMappingTable
    # Then walk up entPhysicalContainedIn tree to first class-5 or class-6 ancestor.
    slot_by_ifindex: Dict[str, str] = {}
    try:
        # entAliasMappingIdentifier value is an OID ending in ifIndex.N — extract N
        alias_map: Dict[str, str] = {}  # entPhysicalIndex → ifIndex
        for item in session.walk(OID_ENTITY_ALIAS_MAP):
            # OID tail: entPhysicalIndex.logicalIndex
            ent_phys_index = item.oid.split('.')[-2]
            # value is OID like 1.3.6.1.2.1.2.2.1.1.N — last element is ifIndex
            try:
                if_index = item.value.split('.')[-1]
                alias_map[ent_phys_index] = if_index
            except Exception:
                pass

        if alias_map:
            # Walk ENTITY-MIB trees once
            contained_in: Dict[str, str] = {}
            entity_class: Dict[str, str] = {}
            entity_descr: Dict[str, str] = {}

            for item in session.walk(OID_ENTITY_CONTAINED):
                contained_in[item.oid.split('.')[-1]] = item.value
            for item in session.walk(OID_ENTITY_CLASS):
                entity_class[item.oid.split('.')[-1]] = item.value
            for item in session.walk(OID_ENTITY_DESCR):
                entity_descr[item.oid.split('.')[-1]] = item.value

            for ent_phys_index, if_index in alias_map.items():
                # Walk up containment tree to first slot or module ancestor
                current = contained_in.get(ent_phys_index)
                slot_label = None
                seen = set()
                while current and current != '0' and current not in seen:
                    seen.add(current)
                    cls = entity_class.get(current)
                    if cls in (ENTITY_CLASS_SLOT, ENTITY_CLASS_MODULE):
                        slot_label = entity_descr.get(current)
                        break
                    current = contained_in.get(current)

                if slot_label:
                    slot_by_ifindex[if_index] = slot_label
                    if VERBOSE > 1:
                        print(f"{prefix}DETAIL slot ifIndex={if_index}: {slot_label}")

        if VERBOSE and alias_map:
            print(f"{prefix}DETAIL ENTITY-MIB slot resolution: {len(slot_by_ifindex)}/{len(alias_map)} interfaces resolved")

    except Exception as e:
        if VERBOSE:
            print(f"{prefix}DETAIL ENTITY-MIB slot walk FAILED (will use ifDescr fallback): {e}")

    # ifDescr fallback for interfaces without ENTITY-MIB slot
    def _parse_slot_from_descr(descr: str) -> Optional[str]:
        import re as _re
        for pattern, group in SLOT_PATTERNS:
            m = _re.match(pattern, descr)
            if m:
                return m.group(group)
        return None

    # --- LLDP neighbour walk ---
    # OID tail: timeMark.localPortNum.remoteIndex — localPortNum maps to ifIndex on most gear
    lldp_sys_by_ifindex: Dict[str, str] = {}
    lldp_port_by_ifindex: Dict[str, str] = {}
    try:
        for item in session.walk(OID_LLDP_REM_SYS_NAME):
            local_port = item.oid.split('.')[-2]
            lldp_sys_by_ifindex[local_port] = item.value
        for item in session.walk(OID_LLDP_REM_PORT_DESC):
            local_port = item.oid.split('.')[-2]
            lldp_port_by_ifindex[local_port] = item.value
        if VERBOSE and lldp_sys_by_ifindex:
            print(f"{prefix}DETAIL LLDP: {len(lldp_sys_by_ifindex)} neighbours")
    except Exception as e:
        if VERBOSE:
            print(f"{prefix}DETAIL LLDP walk FAILED: {e}")

    # --- CDP neighbour walk (Cisco only) ---
    cdp_device_by_ifindex: Dict[str, str] = {}
    cdp_port_by_ifindex: Dict[str, str] = {}
    if vendor == 'cisco':
        try:
            for item in session.walk(OID_CDP_CACHE_DEVICE_ID):
                if_index = item.oid.split('.')[-2]
                cdp_device_by_ifindex[if_index] = item.value
            for item in session.walk(OID_CDP_CACHE_DEVICE_PORT):
                if_index = item.oid.split('.')[-2]
                cdp_port_by_ifindex[if_index] = item.value
            if VERBOSE and cdp_device_by_ifindex:
                print(f"{prefix}DETAIL CDP: {len(cdp_device_by_ifindex)} neighbours")
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}DETAIL CDP walk FAILED: {e}")

    # --- DNS PTR lookups (capped at 50) ---
    # Build ip→hostname map across all IPs in arp_by_mac
    PTR_LOOKUP_CAP = 50
    all_ips = list(set(arp_by_mac.values()))
    if len(all_ips) > PTR_LOOKUP_CAP:
        print(f"{prefix}DETAIL PTR lookup capped at {PTR_LOOKUP_CAP} (total IPs: {len(all_ips)})", file=sys.stderr)
        all_ips = all_ips[:PTR_LOOKUP_CAP]

    hostname_by_ip: Dict[str, str] = {}
    for ip in all_ips:
        try:
            hostname_by_ip[ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname_by_ip[ip] = ''

    if VERBOSE:
        resolved = sum(1 for h in hostname_by_ip.values() if h)
        print(f"{prefix}DETAIL PTR: {resolved}/{len(hostname_by_ip)} IPs resolved")

    # --- Build per-interface detail dict ---
    # mac → ip reverse map for ARP join
    ip_by_mac = arp_by_mac  # mac → ip (already built by caller)

    for if_index in sorted(interfaces.keys(), key=lambda x: int(x)):
        descr = interfaces[if_index]['name']

        # Slot: ENTITY-MIB first, ifDescr parse fallback
        slot = slot_by_ifindex.get(if_index) or _parse_slot_from_descr(descr)

        # Neighbour: LLDP preferred, CDP fallback
        neighbour_host = lldp_sys_by_ifindex.get(if_index) or cdp_device_by_ifindex.get(if_index)
        neighbour_port = lldp_port_by_ifindex.get(if_index) or cdp_port_by_ifindex.get(if_index)
        neighbour_proto = None
        if lldp_sys_by_ifindex.get(if_index):
            neighbour_proto = 'LLDP'
        elif cdp_device_by_ifindex.get(if_index):
            neighbour_proto = 'CDP'

        # MACs on this port
        macs = sorted(macs_by_ifindex.get(if_index, []))

        # ARP entries for MACs on this port
        arp_entries = []
        for mac in macs:
            ip = ip_by_mac.get(mac, '')
            hostname = hostname_by_ip.get(ip, '') if ip else ''
            arp_entries.append({'mac': mac, 'ip': ip, 'hostname': hostname})

        detail['interfaces'][if_index] = {
            'descr': descr,
            'alias': alias_by_index.get(if_index, ''),
            'slot': slot,
            'speed_mbps': speed_by_index.get(if_index, 0),
            'oper': interfaces[if_index].get('oper', ''),
            'admin': interfaces[if_index].get('admin', ''),
            'neighbour_host': neighbour_host,
            'neighbour_port': neighbour_port,
            'neighbour_proto': neighbour_proto,
            'arp': arp_entries,
        }

    return detail


def check_host_resource(resource: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
    """Poll SNMP device for host performance metrics and write RRD if enabled.

    Collects UCD-SNMP-MIB system performance metrics:
      - Chart 1 (-system1): CPU utilisation % + context switches/sec
      - Chart 2 (-system2): Memory utilisation % + swap I/O rate
      - Chart 3 (-system3): Disk read/write bytes summed across all devices
      - Chart 4 (-system4): Swap used bytes + hardware interrupts/sec (System Thrashing)

    Network DS (total_bits_*, total_pkts_*, total_errors_*, tcp_retrans) stored as U.
    Tamper/network DS (ports_up_count, nvram_flash_bytes, mac_count, arp_count) stored as U.
    disk_space_pct is persisted to state for use by generate_mrtg_config() / generate_mrtg_index().
    Detail data (sysName/Location/Contact, interfaces, ARP) persisted for detail page.

    Returns (error_msg, {}) — empty ports_state, consistent with check_resource() interface.
    """
    try:
        from easysnmp import Session
    except ImportError as e:
        error_msg = f"easysnmp library import failed: {e} (try: pip install easysnmp)"
        prefix = getattr(thread_local, 'prefix', '')
        print(f"{prefix}HOST check FAILED: {error_msg}", file=sys.stderr)
        return error_msg, {}

    prefix = getattr(thread_local, 'prefix', '')
    address = resource['address']
    name    = resource['name']

    parsed = urlparse(address)
    if parsed.scheme != 'snmp':
        error_msg = f"{parsed.scheme.upper()} protocol not supported for host monitor, use snmp"
        print(f"{prefix}HOST check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, {}

    community = resource.get('community') or parsed.username or 'public'
    hostname  = parsed.hostname
    port      = parsed.port or 161

    if not hostname:
        error_msg = "host monitor address must include hostname"
        print(f"{prefix}HOST check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, {}

    # HOST-RESOURCES-MIB
    OID_HR_PROCESSOR_LOAD = '1.3.6.1.2.1.25.3.3.1.2'  # hrProcessorLoad
    OID_HR_STORAGE_DESCR  = '1.3.6.1.2.1.25.2.3.1.3'  # hrStorageDescr
    OID_HR_STORAGE_UNITS  = '1.3.6.1.2.1.25.2.3.1.4'  # hrStorageAllocationUnits
    OID_HR_STORAGE_SIZE   = '1.3.6.1.2.1.25.2.3.1.5'  # hrStorageSize
    OID_HR_STORAGE_USED   = '1.3.6.1.2.1.25.2.3.1.6'  # hrStorageUsed

    # UCD-SNMP-MIB system stats
    OID_SS_RAW_CONTEXT_SWITCHES = '1.3.6.1.4.1.2021.11.60.0'  # ssRawContexts
    OID_SS_RAW_SWAP_IN          = '1.3.6.1.4.1.2021.11.62.0'  # ssRawSwapIn
    OID_SS_RAW_SWAP_OUT         = '1.3.6.1.4.1.2021.11.63.0'  # ssRawSwapOut
    OID_SS_RAW_INTERRUPTS       = '1.3.6.1.4.1.2021.11.59.0'  # ssRawInterrupts

    # UCD-SNMP-MIB memory (fallback if hrStorage gives nothing)
    OID_MEM_TOTAL_REAL = '1.3.6.1.4.1.2021.4.5.0'  # memTotalReal (kB)
    OID_MEM_AVAIL_REAL = '1.3.6.1.4.1.2021.4.6.0'  # memAvailReal (kB)
    OID_MEM_TOTAL_SWAP = '1.3.6.1.4.1.2021.4.3.0'  # memTotalSwap (kB)
    OID_MEM_AVAIL_SWAP = '1.3.6.1.4.1.2021.4.4.0'  # memAvailSwap (kB)

    # UCD-DISKIO-MIB — walk all block devices and sum
    OID_DISK_IO_READ  = '1.3.6.1.4.1.2021.13.15.1.1.5'  # diskIOReadX (64-bit bytes)
    OID_DISK_IO_WRITE = '1.3.6.1.4.1.2021.13.15.1.1.6'  # diskIOWriteX (64-bit bytes)

    # IF-MIB for host network interfaces (detail page)
    OID_IF_DESCR        = '1.3.6.1.2.1.2.2.1.2'
    OID_IF_OPER_STATUS  = '1.3.6.1.2.1.2.2.1.8'
    OID_IF_ADMIN_STATUS = '1.3.6.1.2.1.2.2.1.7'

    # ARP tables (RFC 4293 preferred, RFC 2011 fallback)
    OID_IP_NET_TO_PHYSICAL = '1.3.6.1.2.1.4.35.1.4'
    OID_IP_NET_TO_MEDIA    = '1.3.6.1.2.1.4.22.1.2'

    OPER_STATUS  = {
        '1': 'up', '2': 'down', '3': 'testing',
        '4': 'unknown', '5': 'dormant', '6': 'notPresent', '7': 'lowerLayerDown'
    }
    ADMIN_STATUS = {'1': 'up', '2': 'down', '3': 'testing'}

    try:
        session = Session(
            hostname=hostname,
            community=community,
            version=2,
            remote_port=port,
            timeout=MAX_TRY_SECS,
            retries=MAX_RETRIES - 1
        )

        # --- CPU utilisation (hrProcessorLoad averaged across cores) ---
        # First mandatory SNMP operation — fail fast on timeout/error rather than
        # attempting all subsequent walks against an unreachable host.
        cpu_load = None
        try:
            cpu_items = session.walk(OID_HR_PROCESSOR_LOAD)
            if cpu_items:
                cpu_values = [int(item.value) for item in cpu_items]
                cpu_load   = sum(cpu_values) / len(cpu_values)
                if VERBOSE:
                    print(f"{prefix}HOST CPU: {len(cpu_values)} cores, avg={cpu_load:.1f}%")
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            print(f"{prefix}HOST check FAILED for '{name}' at '{address}': {error_msg}", file=sys.stderr)
            return error_msg, {}

        # --- Memory utilisation + swap used + disk space (hrStorage walk) ---
        memory_pct     = None
        swap_used      = None
        disk_space_pct = None

        try:
            storage_descr_items = session.walk(OID_HR_STORAGE_DESCR)
            for item in storage_descr_items:
                descr    = item.value.lower()
                st_index = item.oid.split('.')[-1]

                # Physical memory
                if memory_pct is None and (
                    'physical memory' in descr or 'real memory' in descr
                    or 'ram' in descr or descr == 'memory'
                ):
                    try:
                        units = int(session.get(f"{OID_HR_STORAGE_UNITS}.{st_index}").value)
                        size  = int(session.get(f"{OID_HR_STORAGE_SIZE}.{st_index}").value)
                        used  = int(session.get(f"{OID_HR_STORAGE_USED}.{st_index}").value)
                        if size > 0:
                            memory_pct = (used / size) * 100.0
                            if VERBOSE:
                                print(f"{prefix}HOST memory: used={used * units:,} total={size * units:,} ({memory_pct:.1f}%)")
                    except Exception as e:
                        if VERBOSE:
                            print(f"{prefix}HOST hrStorage memory FAILED: {e}")

                # Virtual memory / swap
                elif swap_used is None and (
                    'virtual memory' in descr or 'swap' in descr or 'swap space' in descr
                ):
                    try:
                        units     = int(session.get(f"{OID_HR_STORAGE_UNITS}.{st_index}").value)
                        used      = int(session.get(f"{OID_HR_STORAGE_USED}.{st_index}").value)
                        swap_used = used * units  # bytes
                        if VERBOSE:
                            size = int(session.get(f"{OID_HR_STORAGE_SIZE}.{st_index}").value)
                            print(f"{prefix}HOST swap: used={swap_used:,} total={size * units:,}")
                    except Exception as e:
                        if VERBOSE:
                            print(f"{prefix}HOST hrStorage swap FAILED: {e}")

                # Root filesystem disk space
                elif disk_space_pct is None and descr in ('/', 'root', 'c:\\', 'c:'):
                    try:
                        size = int(session.get(f"{OID_HR_STORAGE_SIZE}.{st_index}").value)
                        used = int(session.get(f"{OID_HR_STORAGE_USED}.{st_index}").value)
                        if size > 0:
                            disk_space_pct = (used / size) * 100.0
                            if VERBOSE:
                                print(f"{prefix}HOST disk space ({item.value}): {disk_space_pct:.1f}%")
                    except Exception as e:
                        if VERBOSE:
                            print(f"{prefix}HOST hrStorage disk space FAILED: {e}")

        except Exception as e:
            if VERBOSE:
                print(f"{prefix}HOST hrStorage walk FAILED: {e}")

        # UCD memAvailReal fallback for memory_pct
        if memory_pct is None:
            try:
                total_kb = int(session.get(OID_MEM_TOTAL_REAL).value)
                avail_kb = int(session.get(OID_MEM_AVAIL_REAL).value)
                if total_kb > 0:
                    memory_pct = ((total_kb - avail_kb) / total_kb) * 100.0
                    if VERBOSE:
                        print(f"{prefix}HOST memory (UCD fallback): {memory_pct:.1f}%")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}HOST UCD memory fallback FAILED: {e}")

        # UCD memAvailSwap fallback for swap_used
        if swap_used is None:
            try:
                total_swap_kb = int(session.get(OID_MEM_TOTAL_SWAP).value)
                avail_swap_kb = int(session.get(OID_MEM_AVAIL_SWAP).value)
                swap_used     = (total_swap_kb - avail_swap_kb) * 1024  # bytes
                if VERBOSE:
                    print(f"{prefix}HOST swap used (UCD fallback): {swap_used:,} bytes")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}HOST UCD swap fallback FAILED: {e}")

        # --- Context switches ---
        context_switches = None
        try:
            context_switches = int(session.get(OID_SS_RAW_CONTEXT_SWITCHES).value)
            if VERBOSE:
                print(f"{prefix}HOST context switches: {context_switches:,}")
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}HOST ssRawContexts FAILED: {e}")

        # --- Swap I/O (ssRawSwapIn + ssRawSwapOut combined COUNTER) ---
        swap_io = None
        try:
            swap_in  = int(session.get(OID_SS_RAW_SWAP_IN).value)
            swap_out = int(session.get(OID_SS_RAW_SWAP_OUT).value)
            swap_io  = swap_in + swap_out
            if VERBOSE:
                print(f"{prefix}HOST swap I/O: in={swap_in:,} out={swap_out:,} total={swap_io:,}")
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}HOST ssRawSwapIn/Out FAILED: {e}")

        # --- Disk I/O (diskIOReadX / diskIOWriteX summed across all devices) ---
        disk_read = disk_write = None
        try:
            read_items  = session.walk(OID_DISK_IO_READ)
            write_items = session.walk(OID_DISK_IO_WRITE)
            if read_items:
                disk_read  = sum(int(item.value) for item in read_items)
            if write_items:
                disk_write = sum(int(item.value) for item in write_items)
            if VERBOSE:
                print(f"{prefix}HOST disk I/O: read={disk_read:,} write={disk_write:,}")
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}HOST diskIO walk FAILED: {e}")

        # --- Hardware interrupts ---
        interrupts = None
        try:
            interrupts = int(session.get(OID_SS_RAW_INTERRUPTS).value)
            if VERBOSE:
                print(f"{prefix}HOST interrupts: {interrupts:,}")
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}HOST ssRawInterrupts FAILED: {e}")

        if VERBOSE:
            print(f"{prefix}HOST poll SUCCESS for '{name}': "
                  f"cpu={f'{cpu_load:.1f}%' if cpu_load is not None else 'U'} "
                  f"mem={f'{memory_pct:.1f}%' if memory_pct is not None else 'U'} "
                  f"ctx={context_switches} swap_io={swap_io} "
                  f"disk_r={disk_read} disk_w={disk_write} "
                  f"disk_space={f'{disk_space_pct:.1f}%' if disk_space_pct is not None else 'U'} "
                  f"swap_used={swap_used} interrupts={interrupts}")

        # Persist disk_space_pct to state so generate_mrtg_config() / generate_mrtg_index()
        # can embed the live value in PageTop and index cell headings without a live SNMP poll.
        update_state({name: {**STATE.get(name, {}), 'disk_space_pct': disk_space_pct}})

        # --- Detail page: collect host interfaces and ARP ---
        interfaces: Dict[str, Dict[str, Any]] = {}
        try:
            for item in session.walk(OID_IF_DESCR):
                interfaces[item.oid.split('.')[-1]] = {'name': item.value}
            oper_items  = session.walk(OID_IF_OPER_STATUS)
            admin_items = session.walk(OID_IF_ADMIN_STATUS)
            for item in oper_items:
                idx = item.oid.split('.')[-1]
                if idx in interfaces:
                    interfaces[idx]['oper'] = OPER_STATUS.get(item.value, item.value)
            for item in admin_items:
                idx = item.oid.split('.')[-1]
                if idx in interfaces:
                    interfaces[idx]['admin'] = ADMIN_STATUS.get(item.value, item.value)
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}HOST interface walk FAILED for detail page: {e}")

        arp_by_mac: Dict[str, str] = {}
        try:
            arp_items = session.walk(OID_IP_NET_TO_PHYSICAL)
            for item in arp_items:
                try:
                    parts = item.oid.split('.')
                    ip    = '.'.join(parts[-4:])
                    raw   = item.value
                    if raw:
                        mac_str = ':'.join(f'{int(b):02X}' for b in raw.split() if b) if ' ' in raw \
                                  else ':'.join(f'{ord(c):02X}' for c in raw)
                        arp_by_mac[mac_str] = ip
                except Exception:
                    pass
            if not arp_by_mac:
                arp_items = session.walk(OID_IP_NET_TO_MEDIA)
                for item in arp_items:
                    try:
                        parts = item.oid.split('.')
                        ip    = '.'.join(parts[-4:])
                        raw   = item.value
                        if raw:
                            mac_str = ':'.join(f'{int(b):02X}' for b in raw.split() if b) if ' ' in raw \
                                      else ':'.join(f'{ord(c):02X}' for c in raw)
                            arp_by_mac[mac_str] = ip
                    except Exception:
                        pass
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}HOST ARP walk FAILED for detail page: {e}")

        # host has no FDB — empty macs_by_ifindex
        detail = collect_snmp_detail(session, None, interfaces, {}, arp_by_mac)
        update_state({name: {**STATE.get(name, {}), 'detail': detail}})

        # --- RRD update ---
        if RRD_ENABLED:
            check_every_n_secs = resource.get('check_every_n_secs', DEFAULT_CHECK_EVERY_N_SECS)
            rrd_path           = get_rrd_path(name, 'snmp')
            rras               = create_rrd_rras(check_every_n_secs)

            # host uses empty interfaces dict — no per-interface DS
            # fixed DS count = 0 per-interface + 22 fixed DS total
            interfaces_rrd    = {}
            expected_ds_count = 22

            if os.path.exists(rrd_path):
                needs_recreation = False
                try:
                    info            = rrdtool.info(rrd_path)
                    actual_ds_count = len([k for k in info if k.startswith('ds[') and k.endswith('].type')])
                    if actual_ds_count < expected_ds_count:
                        print(f"{prefix}HOST RRD deleted for recreation: {rrd_path} "
                              f"(ds_count={actual_ds_count} < expected={expected_ds_count})")
                        needs_recreation = True
                except Exception as e:
                    print(f"{prefix}HOST RRD introspection failed for '{rrd_path}': {e}, will recreate",
                          file=sys.stderr)
                    needs_recreation = True

                if not needs_recreation and _check_rrd_needs_recreation(rrd_path, rras):
                    print(f"{prefix}HOST RRD deleted for recreation: {rrd_path} (RRA rows under-provisioned)")
                    needs_recreation = True

                if needs_recreation:
                    os.remove(rrd_path)

            if not os.path.exists(rrd_path):
                create_snmp_rrd(rrd_path, check_every_n_secs, interfaces_rrd)
                if VERBOSE:
                    print(f"{prefix}Created HOST RRD: {rrd_path}")

            if os.path.exists(rrd_path):
                rrd_err = update_snmp_rrd(
                    rrd_path, datetime.now(), interfaces_rrd,
                    None,        # tcp_retrans
                    None, None,  # total_bits_in/out
                    None, None,  # total_pkts_in/out
                    None, None,  # total_errors_in/out
                    cpu_load, memory_pct,
                    None, None,  # total_pkts_ucast/bmcast
                    context_switches=context_switches,
                    swap_io=swap_io,
                    disk_read=disk_read,
                    disk_write=disk_write,
                    disk_space_pct=disk_space_pct,
                    swap_used=swap_used,
                    interrupts=interrupts,
                    # tamper/network DS — U for host
                )
                if rrd_err:
                    return rrd_err, {}
            else:
                error_msg = f"RRD creation failed: {rrd_path} does not exist after create"
                print(f"{prefix}HOST RRD FAILED for '{name}': {error_msg}", file=sys.stderr)
                return error_msg, {}

        return None, {}

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        print(f"{prefix}HOST check FAILED for '{name}' at '{address}': {error_msg}", file=sys.stderr)
        if VERBOSE > 1:
            traceback.print_exc(file=sys.stderr)
        return error_msg, {}


def check_ports_resource(resource: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
    """Poll SNMP device for interface metrics (bandwidth/packets/errors/CPU/memory),
    port state (oper/admin status + MAC forwarding table), tamper/network capacity
    metrics (active port count, NVRAM/flash bytes, MAC count, ARP count), and
    full detail data for the monitor detail page. Writes SNMP RRD if enabled.

    Combines former check_snmp_resource() and check_ports_resource() into a single
    SNMP session with one ifDescr walk shared across both metric and state collection.

    Returns (error_msg, current_ports_state) where:
    - error_msg:           None on success, string on any SNMP or RRD failure
    - current_ports_state: dict of {if_index: {name, oper, admin, macs}} for all interfaces
    """
    try:
        from easysnmp import Session
    except ImportError as e:
        error_msg = f"easysnmp library import failed: {e} (try: pip install easysnmp)"
        prefix = getattr(thread_local, 'prefix', '')
        print(f"{prefix}PORTS check FAILED: {error_msg}", file=sys.stderr)
        return error_msg, {}

    prefix = getattr(thread_local, 'prefix', '')
    address = resource['address']
    name    = resource['name']

    parsed = urlparse(address)
    if parsed.scheme != 'snmp':
        error_msg = f"{parsed.scheme.upper()} protocol not supported for ports monitor, use snmp"
        print(f"{prefix}PORTS check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, {}

    community = resource.get('community') or parsed.username or 'public'
    hostname  = parsed.hostname
    port      = parsed.port or 161

    if not hostname:
        error_msg = "ports monitor address must include hostname"
        print(f"{prefix}PORTS check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, {}

    # Standard SNMP OIDs
    OID_SYS_OBJECT_ID        = '1.3.6.1.2.1.1.2.0'
    OID_IF_DESCR              = '1.3.6.1.2.1.2.2.1.2'
    OID_IF_OPER_STATUS        = '1.3.6.1.2.1.2.2.1.8'
    OID_IF_ADMIN_STATUS       = '1.3.6.1.2.1.2.2.1.7'
    OID_IF_IN_OCTETS          = '1.3.6.1.2.1.2.2.1.10'
    OID_IF_OUT_OCTETS         = '1.3.6.1.2.1.2.2.1.16'
    OID_IF_IN_ERRORS          = '1.3.6.1.2.1.2.2.1.14'
    OID_IF_OUT_ERRORS         = '1.3.6.1.2.1.2.2.1.20'
    OID_TCP_RETRANS_SEGS      = '1.3.6.1.2.1.6.12.0'

    # IF-MIB high-capacity 64-bit packet counters
    OID_IF_HC_IN_UCAST_PKTS  = '1.3.6.1.2.1.31.1.1.1.7'
    OID_IF_HC_IN_MCAST_PKTS  = '1.3.6.1.2.1.31.1.1.1.8'
    OID_IF_HC_IN_BCAST_PKTS  = '1.3.6.1.2.1.31.1.1.1.9'
    OID_IF_HC_OUT_UCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.11'
    OID_IF_HC_OUT_MCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.12'
    OID_IF_HC_OUT_BCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.13'

    # HOST-RESOURCES-MIB
    OID_HR_PROCESSOR_LOAD    = '1.3.6.1.2.1.25.3.3.1.2'
    OID_HR_STORAGE_DESCR     = '1.3.6.1.2.1.25.2.3.1.3'
    OID_HR_STORAGE_UNITS     = '1.3.6.1.2.1.25.2.3.1.4'
    OID_HR_STORAGE_SIZE      = '1.3.6.1.2.1.25.2.3.1.5'
    OID_HR_STORAGE_USED      = '1.3.6.1.2.1.25.2.3.1.6'

    # Vendor-specific CPU OIDs
    OID_CISCO_CPU_5SEC       = '1.3.6.1.4.1.9.9.109.1.1.1.1.7.1'
    OID_CISCO_CPU_1MIN       = '1.3.6.1.4.1.9.9.109.1.1.1.1.5.1'
    OID_HP_CPU_LOAD          = '1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0'
    OID_JUNIPER_CPU          = '1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0'
    OID_UBNT_SYS_CPU         = '1.3.6.1.4.1.41112.1.4.1.2.1.0'

    # Vendor-specific memory OIDs
    OID_CISCO_MEM_POOL_USED  = '1.3.6.1.4.1.9.9.48.1.1.1.5.1'
    OID_CISCO_MEM_POOL_FREE  = '1.3.6.1.4.1.9.9.48.1.1.1.6.1'
    OID_HP_MEM_TOTAL         = '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5.1'
    OID_HP_MEM_FREE          = '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6.1'
    OID_JUNIPER_MEM_UTIL     = '1.3.6.1.4.1.2636.3.1.13.1.11.9.1.0.0'
    OID_UBNT_SYS_MEM_TOTAL   = '1.3.6.1.4.1.41112.1.4.1.2.2.0'
    OID_UBNT_SYS_MEM_FREE    = '1.3.6.1.4.1.41112.1.4.1.2.3.0'

    # Q-BRIDGE-MIB (RFC 2674)
    OID_DOT1Q_TP_FDB_PORT    = '1.3.6.1.2.1.17.7.1.2.2.1.2'
    OID_DOT1Q_TP_FDB_STATUS  = '1.3.6.1.2.1.17.7.1.2.2.1.3'

    # ARP tables (RFC 4293 preferred, RFC 2011 fallback)
    OID_IP_NET_TO_PHYSICAL   = '1.3.6.1.2.1.4.35.1.4'  # ipNetToPhysicalPhysAddress
    OID_IP_NET_TO_MEDIA      = '1.3.6.1.2.1.4.22.1.2'   # ipNetToMediaPhysAddress

    # ARP IP address columns (parallel to the physical address OIDs above)
    OID_IP_NET_TO_PHYSICAL_ADDR = '1.3.6.1.2.1.4.35.1.4'  # value IS the MAC; IP is in OID tail
    OID_IP_NET_TO_MEDIA_ADDR    = '1.3.6.1.2.1.4.22.1.2'   # value IS the MAC; IP is in OID tail

    OPER_STATUS = {
        '1': 'up', '2': 'down', '3': 'testing',
        '4': 'unknown', '5': 'dormant', '6': 'notPresent', '7': 'lowerLayerDown'
    }
    ADMIN_STATUS       = {'1': 'up', '2': 'down', '3': 'testing'}
    FDB_STATUS_LEARNED = '3'

    # hrStorage description keywords for NVRAM/flash detection (case-insensitive match)
    NVRAM_FLASH_KEYWORDS = {'nvram', 'flash', 'bootflash', 'nvmram'}

    try:
        session = Session(
            hostname=hostname,
            community=community,
            version=2,
            remote_port=port,
            timeout=MAX_TRY_SECS,
            retries=MAX_RETRIES - 1
        )

        # --- Vendor detection ---
        vendor = None
        try:
            sys_obj_id = session.get(OID_SYS_OBJECT_ID).value
            if VERBOSE > 1:
                print(f"{prefix}SNMP sysObjectID: {sys_obj_id}")
            if sys_obj_id.startswith('1.3.6.1.4.1.9.'):
                vendor = 'cisco'
            elif sys_obj_id.startswith('1.3.6.1.4.1.11.'):
                vendor = 'hp'
            elif sys_obj_id.startswith('1.3.6.1.4.1.2636.'):
                vendor = 'juniper'
            elif sys_obj_id.startswith('1.3.6.1.4.1.41112.'):
                vendor = 'ubiquiti'
            if VERBOSE and vendor:
                print(f"{prefix}Detected vendor: {vendor}")
        except Exception as e:
            if VERBOSE > 1:
                print(f"{prefix}SNMP sysObjectID query failed: {e}, will use HOST-RESOURCES-MIB")

        # --- Single ifDescr walk shared by metrics and state collection ---
        try:
            if_descr_items = session.walk(OID_IF_DESCR)
        except Exception as e:
            error_msg = f"SNMP walk failed: {e}"
            print(f"{prefix}PORTS check FAILED for '{name}': {error_msg}", file=sys.stderr)
            return error_msg, {}

        if not if_descr_items:
            error_msg = "no interfaces found"
            print(f"{prefix}PORTS check FAILED for '{name}': {error_msg}", file=sys.stderr)
            return error_msg, {}

        interfaces = {
            item.oid.split('.')[-1]: {'name': item.value}
            for item in if_descr_items
        }

        # --- IF-MIB oper/admin status ---
        try:
            oper_items  = session.walk(OID_IF_OPER_STATUS)
            admin_items = session.walk(OID_IF_ADMIN_STATUS)
        except Exception as e:
            error_msg = f"SNMP walk failed: {e}"
            print(f"{prefix}PORTS check FAILED for '{name}': {error_msg}", file=sys.stderr)
            return error_msg, {}

        oper_by_index  = {item.oid.split('.')[-1]: item.value for item in oper_items}
        admin_by_index = {item.oid.split('.')[-1]: item.value for item in admin_items}

        # --- Byte and error counters ---
        total_octets_in = total_octets_out = 0
        total_errors_in = total_errors_out = 0

        for if_index in interfaces:
            try:
                v = int(session.get(f"{OID_IF_IN_OCTETS}.{if_index}").value)
                interfaces[if_index]['in_octets'] = v
                total_octets_in += v
            except Exception:
                interfaces[if_index]['in_octets'] = None

            try:
                v = int(session.get(f"{OID_IF_OUT_OCTETS}.{if_index}").value)
                interfaces[if_index]['out_octets'] = v
                total_octets_out += v
            except Exception:
                interfaces[if_index]['out_octets'] = None

            try:
                v = int(session.get(f"{OID_IF_IN_ERRORS}.{if_index}").value)
                interfaces[if_index]['in_errors'] = v
                total_errors_in += v
            except Exception:
                interfaces[if_index]['in_errors'] = None

            try:
                v = int(session.get(f"{OID_IF_OUT_ERRORS}.{if_index}").value)
                interfaces[if_index]['out_errors'] = v
                total_errors_out += v
            except Exception:
                interfaces[if_index]['out_errors'] = None

        # --- Packet counters ---
        total_pkts_ucast_in = total_pkts_ucast_out = 0
        total_pkts_bmcast_in = total_pkts_bmcast_out = 0
        total_pkts_in = total_pkts_out = 0

        for if_index in interfaces:
            if_pkts_in = if_pkts_out = 0

            for oid, is_in, is_ucast in [
                (OID_IF_HC_IN_UCAST_PKTS,   True,  True),
                (OID_IF_HC_IN_MCAST_PKTS,   True,  False),
                (OID_IF_HC_IN_BCAST_PKTS,   True,  False),
                (OID_IF_HC_OUT_UCAST_PKTS,  False, True),
                (OID_IF_HC_OUT_MCAST_PKTS,  False, False),
                (OID_IF_HC_OUT_BCAST_PKTS,  False, False),
            ]:
                try:
                    v = int(session.get(f"{oid}.{if_index}").value)
                    if is_in:
                        if_pkts_in += v
                        if is_ucast: total_pkts_ucast_in  += v
                        else:        total_pkts_bmcast_in += v
                    else:
                        if_pkts_out += v
                        if is_ucast: total_pkts_ucast_out  += v
                        else:        total_pkts_bmcast_out += v
                except Exception:
                    pass

            total_pkts_in  += if_pkts_in
            total_pkts_out += if_pkts_out

            if VERBOSE:
                print(f"{prefix}Interface {if_index} packets: in={if_pkts_in:,} out={if_pkts_out:,}")

        total_bits_in  = total_octets_in  * 8
        total_bits_out = total_octets_out * 8
        total_pkts_ucast  = total_pkts_ucast_in  + total_pkts_ucast_out
        total_pkts_bmcast = total_pkts_bmcast_in + total_pkts_bmcast_out

        if VERBOSE:
            print(f"{prefix}Aggregate totals: bits_in={total_bits_in:,} bits_out={total_bits_out:,} "
                  f"pkts_in={total_pkts_in:,} pkts_out={total_pkts_out:,} "
                  f"errors_in={total_errors_in:,} errors_out={total_errors_out:,}")
            print(f"{prefix}Packet type totals: ucast={total_pkts_ucast:,} bmcast={total_pkts_bmcast:,}")

        # --- TCP retransmits ---
        tcp_retrans = None
        try:
            tcp_retrans = int(session.get(OID_TCP_RETRANS_SEGS).value)
            if VERBOSE:
                print(f"{prefix}SNMP tcpRetransSegs = {tcp_retrans}")
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}SNMP tcpRetransSegs FAILED: {e}")

        # --- CPU (vendor-specific → HOST-RESOURCES-MIB fallback) ---
        cpu_load = None
        if vendor == 'cisco':
            try:
                cpu_load = float(session.get(OID_CISCO_CPU_5SEC).value)
            except Exception:
                try:
                    cpu_load = float(session.get(OID_CISCO_CPU_1MIN).value)
                except Exception:
                    pass
        elif vendor == 'hp':
            try:
                cpu_load = float(session.get(OID_HP_CPU_LOAD).value)
            except Exception:
                pass
        elif vendor == 'juniper':
            try:
                cpu_load = float(session.get(OID_JUNIPER_CPU).value)
            except Exception:
                pass
        elif vendor == 'ubiquiti':
            try:
                cpu_load = float(session.get(OID_UBNT_SYS_CPU).value)
            except Exception:
                pass

        if cpu_load is None:
            try:
                cpu_items = session.walk(OID_HR_PROCESSOR_LOAD)
                if cpu_items:
                    cpu_values = [int(item.value) for item in cpu_items]
                    cpu_load   = sum(cpu_values) / len(cpu_values)
                    if VERBOSE:
                        print(f"{prefix}SNMP CPU (HOST-RESOURCES-MIB): {len(cpu_values)} cores, avg={cpu_load:.1f}%")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP hrProcessorLoad FAILED: {e}")

        # --- Memory (vendor-specific → HOST-RESOURCES-MIB fallback) ---
        memory_pct = None
        if vendor == 'cisco':
            try:
                mem_used  = int(session.get(OID_CISCO_MEM_POOL_USED).value)
                mem_free  = int(session.get(OID_CISCO_MEM_POOL_FREE).value)
                mem_total = mem_used + mem_free
                if mem_total > 0:
                    memory_pct = (mem_used / mem_total) * 100.0
            except Exception:
                pass
        elif vendor == 'hp':
            try:
                mem_total = int(session.get(OID_HP_MEM_TOTAL).value)
                mem_free  = int(session.get(OID_HP_MEM_FREE).value)
                if mem_total > 0:
                    memory_pct = ((mem_total - mem_free) / mem_total) * 100.0
            except Exception:
                pass
        elif vendor == 'juniper':
            try:
                memory_pct = float(session.get(OID_JUNIPER_MEM_UTIL).value)
            except Exception:
                pass
        elif vendor == 'ubiquiti':
            try:
                mem_total = int(session.get(OID_UBNT_SYS_MEM_TOTAL).value)
                mem_free  = int(session.get(OID_UBNT_SYS_MEM_FREE).value)
                if mem_total > 0:
                    memory_pct = ((mem_total - mem_free) / mem_total) * 100.0
            except Exception:
                pass

        if memory_pct is None:
            try:
                storage_items = session.walk(OID_HR_STORAGE_DESCR)
                memory_index  = None
                for item in storage_items:
                    descr = item.value.lower()
                    if 'physical memory' in descr or 'real memory' in descr or 'ram' in descr or descr == 'memory':
                        memory_index = item.oid.split('.')[-1]
                        if VERBOSE:
                            print(f"{prefix}Found memory storage entry: index={memory_index} descr='{item.value}'")
                        break
                if memory_index:
                    units = int(session.get(f"{OID_HR_STORAGE_UNITS}.{memory_index}").value)
                    size  = int(session.get(f"{OID_HR_STORAGE_SIZE}.{memory_index}").value)
                    used  = int(session.get(f"{OID_HR_STORAGE_USED}.{memory_index}").value)
                    if size > 0:
                        memory_pct = (used / size) * 100.0
                        if VERBOSE:
                            print(f"{prefix}SNMP memory (HOST-RESOURCES-MIB): "
                                  f"used={used * units:,} total={size * units:,} ({memory_pct:.1f}%)")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP hrStorage FAILED: {e}")

        # --- Q-BRIDGE-MIB MAC table ---
        macs_by_ifindex: Dict[str, list] = {}
        try:
            fdb_port_items   = session.walk(OID_DOT1Q_TP_FDB_PORT)
            fdb_status_items = session.walk(OID_DOT1Q_TP_FDB_STATUS)

            fdb_status_by_oid = {
                '.'.join(item.oid.split('.')[-7:]): item.value
                for item in fdb_status_items
            }

            for item in fdb_port_items:
                oid_tail   = '.'.join(item.oid.split('.')[-7:])
                mac_octets = oid_tail.split('.')[1:]
                if_index   = item.value

                if fdb_status_by_oid.get(oid_tail) != FDB_STATUS_LEARNED:
                    continue
                if len(mac_octets) != 6:
                    continue

                mac_str = ':'.join(f'{int(o):02X}' for o in mac_octets)
                macs_by_ifindex.setdefault(if_index, []).append(mac_str)

            if VERBOSE:
                total_macs = sum(len(v) for v in macs_by_ifindex.values())
                print(f"{prefix}PORTS MAC table: {total_macs} learned MACs across {len(macs_by_ifindex)} interfaces")

        except Exception as e:
            if VERBOSE:
                print(f"{prefix}PORTS Q-BRIDGE FDB walk failed for '{name}' (MACs unavailable): {e}")

        # --- Build current_ports_state (numeric sort on if_index) ---
        current_ports_state = {}
        for if_index in sorted(interfaces.keys(), key=lambda x: int(x)):
            oper_raw  = oper_by_index.get(if_index, '4')
            admin_raw = admin_by_index.get(if_index, '2')
            current_ports_state[if_index] = {
                'name':  interfaces[if_index]['name'],
                'oper':  OPER_STATUS.get(oper_raw, oper_raw),
                'admin': ADMIN_STATUS.get(admin_raw, admin_raw),
                'macs':  sorted(macs_by_ifindex.get(if_index, [])),
            }

        # --- Tamper detection: active port count (free — derived from current_ports_state) ---
        ports_up_count = sum(1 for s in current_ports_state.values() if s['oper'] == 'up')
        if VERBOSE:
            print(f"{prefix}PORTS up count: {ports_up_count}/{len(current_ports_state)}")

        # --- Tamper detection: NVRAM + flash used bytes (vendor-neutral hrStorage walk) ---
        # Keywords matched case-insensitively; sum used×units across all matching entries.
        # Silent U if no matching entries — consistent with partial-data philosophy.
        nvram_flash_bytes = None
        try:
            storage_descr_items = session.walk(OID_HR_STORAGE_DESCR)
            for item in storage_descr_items:
                if any(kw in item.value.lower() for kw in NVRAM_FLASH_KEYWORDS):
                    st_index = item.oid.split('.')[-1]
                    try:
                        units = int(session.get(f"{OID_HR_STORAGE_UNITS}.{st_index}").value)
                        used  = int(session.get(f"{OID_HR_STORAGE_USED}.{st_index}").value)
                        nvram_flash_bytes = (nvram_flash_bytes or 0) + used * units
                        if VERBOSE:
                            print(f"{prefix}PORTS NVRAM/flash '{item.value}': {used * units:,} bytes used")
                    except Exception as e:
                        if VERBOSE:
                            print(f"{prefix}PORTS NVRAM/flash entry '{item.value}' FAILED: {e}")
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}PORTS hrStorage NVRAM/flash walk FAILED: {e}")

        # --- Network capacity: MAC count (free — already have macs_by_ifindex from FDB walk) ---
        mac_count = sum(len(v) for v in macs_by_ifindex.values())
        if VERBOSE:
            print(f"{prefix}PORTS MAC count: {mac_count}")

        # --- Network capacity: ARP entry count + build mac→ip map for detail page ---
        # ipNetToPhysicalTable (RFC 4293) preferred; ipNetToMediaTable (RFC 2011) fallback.
        # OID tail for ipNetToPhysicalTable: ifIndex.ipVersion.ip1.ip2.ip3.ip4
        # OID tail for ipNetToMediaTable:    ifIndex.ip1.ip2.ip3.ip4
        arp_count  = None
        arp_by_mac: Dict[str, str] = {}  # mac → ip

        def _parse_arp_physical(items: list) -> Dict[str, str]:
            """Parse ipNetToPhysicalTable items → {mac: ip}."""
            result = {}
            for item in items:
                try:
                    # OID tail: ifIndex.addrType.ip1.ip2.ip3.ip4
                    parts = item.oid.split('.')
                    ip = '.'.join(parts[-4:])
                    # value is MAC as hex octets separated by spaces or as raw bytes
                    raw = item.value
                    if raw:
                        mac_str = ':'.join(f'{int(b):02X}' for b in raw.split() if b) if ' ' in raw \
                                  else ':'.join(f'{ord(c):02X}' for c in raw)
                        result[mac_str] = ip
                except Exception:
                    pass
            return result

        def _parse_arp_media(items: list) -> Dict[str, str]:
            """Parse ipNetToMediaTable items → {mac: ip}."""
            result = {}
            for item in items:
                try:
                    parts = item.oid.split('.')
                    ip = '.'.join(parts[-4:])
                    raw = item.value
                    if raw:
                        mac_str = ':'.join(f'{int(b):02X}' for b in raw.split() if b) if ' ' in raw \
                                  else ':'.join(f'{ord(c):02X}' for c in raw)
                        result[mac_str] = ip
                except Exception:
                    pass
            return result

        try:
            arp_items = session.walk(OID_IP_NET_TO_PHYSICAL)
            arp_count = len(arp_items)
            arp_by_mac = _parse_arp_physical(arp_items)
            if VERBOSE:
                print(f"{prefix}PORTS ARP count (ipNetToPhysicalTable): {arp_count}")
            if arp_count == 0:
                # Fallback — some devices only populate the older table
                arp_items = session.walk(OID_IP_NET_TO_MEDIA)
                arp_count = len(arp_items)
                arp_by_mac = _parse_arp_media(arp_items)
                if VERBOSE:
                    print(f"{prefix}PORTS ARP count (ipNetToMediaTable fallback): {arp_count}")
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}PORTS ARP walk FAILED: {e}")

        if VERBOSE:
            print(f"{prefix}PORTS poll SUCCESS for '{name}': {len(current_ports_state)} interfaces")
            for if_index, iface in current_ports_state.items():
                mac_str = ', '.join(iface['macs']) if iface['macs'] else 'none'
                in_val  = interfaces[if_index].get('in_octets')
                out_val = interfaces[if_index].get('out_octets')
                print(f"{prefix}  Interface {if_index} ({iface['name']}): "
                      f"oper={iface['oper']} admin={iface['admin']} "
                      f"in={f'{in_val:,}' if in_val is not None else 'N/A'} "
                      f"out={f'{out_val:,}' if out_val is not None else 'N/A'} "
                      f"macs=[{mac_str}]")

        # --- Detail page data collection ---
        # Enrich interfaces dict with oper/admin strings for collect_snmp_detail
        for if_index in interfaces:
            oper_raw  = oper_by_index.get(if_index, '4')
            admin_raw = admin_by_index.get(if_index, '2')
            interfaces[if_index]['oper']  = OPER_STATUS.get(oper_raw, oper_raw)
            interfaces[if_index]['admin'] = ADMIN_STATUS.get(admin_raw, admin_raw)

        detail = collect_snmp_detail(session, vendor, interfaces, macs_by_ifindex, arp_by_mac)
        update_state({name: {**STATE.get(name, {}), 'detail': detail}})

        # --- RRD update ---
        if RRD_ENABLED:
            check_every_n_secs = resource.get('check_every_n_secs', DEFAULT_CHECK_EVERY_N_SECS)
            rrd_path           = get_rrd_path(name, 'snmp')
            rras               = create_rrd_rras(check_every_n_secs)

            if os.path.exists(rrd_path):
                expected_ds_count = 2 * len(interfaces) + 22  # per-interface pairs + 22 fixed DS
                needs_recreation  = False
                try:
                    info            = rrdtool.info(rrd_path)
                    actual_ds_count = len([k for k in info if k.startswith('ds[') and k.endswith('].type')])
                    if actual_ds_count < expected_ds_count:
                        print(f"{prefix}SNMP RRD deleted for recreation: {rrd_path} "
                              f"(ds_count={actual_ds_count} < expected={expected_ds_count})")
                        needs_recreation = True
                except Exception as e:
                    print(f"{prefix}SNMP RRD introspection failed for '{rrd_path}': {e}, will recreate",
                          file=sys.stderr)
                    needs_recreation = True

                if not needs_recreation and _check_rrd_needs_recreation(rrd_path, rras):
                    print(f"{prefix}SNMP RRD deleted for recreation: {rrd_path} (RRA rows under-provisioned)")
                    needs_recreation = True

                if needs_recreation:
                    os.remove(rrd_path)

            if not os.path.exists(rrd_path):
                create_snmp_rrd(rrd_path, check_every_n_secs, interfaces)
                if VERBOSE:
                    print(f"{prefix}Created SNMP RRD: {rrd_path}")

            if os.path.exists(rrd_path):
                rrd_err = update_snmp_rrd(
                    rrd_path, datetime.now(), interfaces,
                    tcp_retrans,
                    total_bits_in, total_bits_out,
                    total_pkts_in, total_pkts_out,
                    total_errors_in, total_errors_out,
                    cpu_load, memory_pct,
                    total_pkts_ucast, total_pkts_bmcast,
                    # host DS — U for ports
                    ports_up_count=ports_up_count,
                    nvram_flash_bytes=nvram_flash_bytes,
                    mac_count=mac_count,
                    arp_count=arp_count,
                )
                if rrd_err:
                    return rrd_err, {}
            else:
                error_msg = f"RRD creation failed: {rrd_path} does not exist after create"
                print(f"{prefix}SNMP RRD FAILED for '{name}': {error_msg}", file=sys.stderr)
                return error_msg, {}

        return None, current_ports_state

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        print(f"{prefix}PORTS check FAILED for '{name}' at '{address}': {error_msg}", file=sys.stderr)
        if VERBOSE > 1:
            traceback.print_exc(file=sys.stderr)
        return error_msg, {}


def check_port_resource(resource: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Poll a single switch port by ifIndex for oper status and MAC address.

    Uses IF-MIB for oper/admin status and Q-BRIDGE-MIB (RFC 2674) dot1qTpFdbTable for learned MACs.
    Q-BRIDGE-MIB OID tail encodes <vlan_id>.<6 MAC octets>, value is bridge port number (= ifIndex).

    Alarm logic:
      always_up=True:  alarm if oper!=up OR pinned MAC absent OR wrong MAC on port
      always_up=False: alarm only if a non-pinned MAC is present on the port

    Returns (error_msg, current_oper, current_mac) where:
    - error_msg:    None if no alarm condition, string describing the fault
    - current_oper: IF-MIB oper status string (or None on SNMP failure)
    - current_mac:  MAC found on port (or None if absent / SNMP failure)
    """
    try:
        from easysnmp import Session
    except ImportError as e:
        error_msg = f"easysnmp library import failed: {e} (try: pip install easysnmp)"
        prefix = getattr(thread_local, 'prefix', '')
        print(f"{prefix}PORT check FAILED: {error_msg}", file=sys.stderr)
        return error_msg, None, None

    prefix     = getattr(thread_local, 'prefix', '')
    address    = resource['address']
    name       = resource['name']
    if_index   = str(resource['port'])
    pinned_mac = resource['mac'].upper()
    always_up  = to_natural_language_boolean(resource.get('always_up', False))

    parsed    = urlparse(address)
    community = resource.get('community') or parsed.username or 'public'
    hostname  = parsed.hostname
    port      = parsed.port or 161

    if not hostname:
        error_msg = "port monitor address must include hostname"
        print(f"{prefix}PORT check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, None, None

    # IF-MIB OIDs
    OID_IF_DESCR         = '1.3.6.1.2.1.2.2.1.2'
    OID_IF_OPER_STATUS   = '1.3.6.1.2.1.2.2.1.8'
    OID_IF_ADMIN_STATUS  = '1.3.6.1.2.1.2.2.1.7'
    OID_IF_IN_OCTETS     = '1.3.6.1.2.1.2.2.1.10'
    OID_IF_OUT_OCTETS    = '1.3.6.1.2.1.2.2.1.16'
    OID_IF_IN_ERRORS     = '1.3.6.1.2.1.2.2.1.14'
    OID_IF_OUT_ERRORS    = '1.3.6.1.2.1.2.2.1.20'

    # IF-MIB high-capacity 64-bit packet counters
    OID_IF_HC_IN_UCAST_PKTS  = '1.3.6.1.2.1.31.1.1.1.7'
    OID_IF_HC_IN_MCAST_PKTS  = '1.3.6.1.2.1.31.1.1.1.8'
    OID_IF_HC_IN_BCAST_PKTS  = '1.3.6.1.2.1.31.1.1.1.9'
    OID_IF_HC_OUT_UCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.11'
    OID_IF_HC_OUT_MCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.12'
    OID_IF_HC_OUT_BCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.13'

    # Q-BRIDGE-MIB OIDs (RFC 2674)
    OID_DOT1Q_TP_FDB_PORT   = '1.3.6.1.2.1.17.7.1.2.2.1.2'
    OID_DOT1Q_TP_FDB_STATUS = '1.3.6.1.2.1.17.7.1.2.2.1.3'

    # ARP tables (RFC 4293 preferred, RFC 2011 fallback)
    OID_IP_NET_TO_PHYSICAL  = '1.3.6.1.2.1.4.35.1.4'
    OID_IP_NET_TO_MEDIA     = '1.3.6.1.2.1.4.22.1.2'

    OPER_STATUS = {
        '1': 'up', '2': 'down', '3': 'testing',
        '4': 'unknown', '5': 'dormant', '6': 'notPresent', '7': 'lowerLayerDown'
    }
    ADMIN_STATUS       = {'1': 'up', '2': 'down', '3': 'testing'}
    FDB_STATUS_LEARNED = '3'

    try:
        session = Session(
            hostname=hostname,
            community=community,
            version=2,
            remote_port=port,
            timeout=MAX_TRY_SECS,
            retries=MAX_RETRIES - 1
        )

        oper_raw  = session.get(f"{OID_IF_OPER_STATUS}.{if_index}").value
        admin_raw = session.get(f"{OID_IF_ADMIN_STATUS}.{if_index}").value
        oper      = OPER_STATUS.get(oper_raw, oper_raw)
        admin     = ADMIN_STATUS.get(admin_raw, admin_raw)

        if VERBOSE:
            print(f"{prefix}PORT poll ifIndex={if_index}: oper={oper} admin={admin}")

    except Exception as e:
        error_msg = f"SNMP failed: {e}"
        print(f"{prefix}PORT check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, None, None

    # MAC walk — non-fatal
    current_mac = None
    macs_by_ifindex: Dict[str, list] = {}
    try:
        fdb_port_items   = session.walk(OID_DOT1Q_TP_FDB_PORT)
        fdb_status_items = session.walk(OID_DOT1Q_TP_FDB_STATUS)

        fdb_status_by_oid = {
            '.'.join(item.oid.split('.')[-7:]): item.value
            for item in fdb_status_items
        }

        for item in fdb_port_items:
            oid_tail     = '.'.join(item.oid.split('.')[-7:])
            mac_octets   = oid_tail.split('.')[1:]
            port_ifindex = item.value

            if fdb_status_by_oid.get(oid_tail) != FDB_STATUS_LEARNED:
                continue
            if len(mac_octets) != 6:
                continue

            mac_str = ':'.join(f'{int(o):02X}' for o in mac_octets)
            macs_by_ifindex.setdefault(port_ifindex, []).append(mac_str)

            if port_ifindex == if_index and current_mac is None:
                current_mac = mac_str

        if VERBOSE:
            print(f"{prefix}PORT mac on ifIndex={if_index}: {current_mac or 'none'} (pinned={pinned_mac})")

    except Exception as e:
        if VERBOSE:
            print(f"{prefix}PORT Q-BRIDGE FDB walk failed for '{name}' (MAC unavailable): {e}")

    # --- Alarm evaluation ---
    if always_up:
        if oper != 'up':
            return f"port ifIndex={if_index} {pinned_mac} is {oper} (admin={admin})", oper, current_mac
        if current_mac is None:
            return f"port ifIndex={if_index} is up but pinned MAC {pinned_mac} absent", oper, current_mac
        if current_mac != pinned_mac:
            return f"port ifIndex={if_index} wrong MAC: expected {pinned_mac}, got {current_mac}", oper, current_mac
    else:
        if current_mac is not None and current_mac != pinned_mac:
            return f"port ifIndex={if_index} wrong MAC: expected {pinned_mac}, got {current_mac}", oper, current_mac

    # --- ARP collection for detail page ---
    arp_by_mac: Dict[str, str] = {}
    try:
        arp_items = session.walk(OID_IP_NET_TO_PHYSICAL)
        for item in arp_items:
            try:
                parts = item.oid.split('.')
                ip    = '.'.join(parts[-4:])
                raw   = item.value
                if raw:
                    mac_str = ':'.join(f'{int(b):02X}' for b in raw.split() if b) if ' ' in raw \
                              else ':'.join(f'{ord(c):02X}' for c in raw)
                    arp_by_mac[mac_str] = ip
            except Exception:
                pass
        if not arp_by_mac:
            arp_items = session.walk(OID_IP_NET_TO_MEDIA)
            for item in arp_items:
                try:
                    parts = item.oid.split('.')
                    ip    = '.'.join(parts[-4:])
                    raw   = item.value
                    if raw:
                        mac_str = ':'.join(f'{int(b):02X}' for b in raw.split() if b) if ' ' in raw \
                                  else ':'.join(f'{ord(c):02X}' for c in raw)
                        arp_by_mac[mac_str] = ip
                except Exception:
                    pass
    except Exception as e:
        if VERBOSE:
            print(f"{prefix}PORT ARP walk FAILED for detail page: {e}")

    # --- Detail page data collection ---
    try:
        if_name = session.get(f"{OID_IF_DESCR}.{if_index}").value
    except Exception:
        if_name = f"if{if_index}"

    interfaces = {if_index: {'name': if_name, 'oper': oper, 'admin': admin}}
    detail = collect_snmp_detail(session, None, interfaces, macs_by_ifindex, arp_by_mac)
    update_state({name: {**STATE.get(name, {}), 'detail': detail}})

    # --- RRD update (single-interface schema) ---
    if RRD_ENABLED:
        check_every_n_secs = resource.get('check_every_n_secs', DEFAULT_CHECK_EVERY_N_SECS)
        rrd_path           = get_rrd_path(name, 'snmp')

        interfaces_rrd = {if_index: {'name': if_name}}

        try:
            octets_in = int(session.get(f"{OID_IF_IN_OCTETS}.{if_index}").value)
            interfaces_rrd[if_index]['in_octets'] = octets_in
        except Exception:
            interfaces_rrd[if_index]['in_octets'] = None
            octets_in = 0

        try:
            octets_out = int(session.get(f"{OID_IF_OUT_OCTETS}.{if_index}").value)
            interfaces_rrd[if_index]['out_octets'] = octets_out
        except Exception:
            interfaces_rrd[if_index]['out_octets'] = None
            octets_out = 0

        try:
            interfaces_rrd[if_index]['in_errors'] = int(session.get(f"{OID_IF_IN_ERRORS}.{if_index}").value)
        except Exception:
            interfaces_rrd[if_index]['in_errors'] = None

        try:
            interfaces_rrd[if_index]['out_errors'] = int(session.get(f"{OID_IF_OUT_ERRORS}.{if_index}").value)
        except Exception:
            interfaces_rrd[if_index]['out_errors'] = None

        ucast_in = bmcast_in = ucast_out = bmcast_out = 0
        for oid, bucket in [
            (OID_IF_HC_IN_UCAST_PKTS,  'ucast_in'),
            (OID_IF_HC_IN_MCAST_PKTS,  'bmcast_in'),
            (OID_IF_HC_IN_BCAST_PKTS,  'bmcast_in'),
            (OID_IF_HC_OUT_UCAST_PKTS, 'ucast_out'),
            (OID_IF_HC_OUT_MCAST_PKTS, 'bmcast_out'),
            (OID_IF_HC_OUT_BCAST_PKTS, 'bmcast_out'),
        ]:
            try:
                v = int(session.get(f"{oid}.{if_index}").value)
                if   bucket == 'ucast_in':   ucast_in   += v
                elif bucket == 'bmcast_in':  bmcast_in  += v
                elif bucket == 'ucast_out':  ucast_out  += v
                else:                        bmcast_out += v
            except Exception:
                pass

        total_bits_in  = octets_in  * 8
        total_bits_out = octets_out * 8
        total_pkts_in  = ucast_in  + bmcast_in
        total_pkts_out = ucast_out + bmcast_out
        total_pkts_ucast  = ucast_in  + ucast_out
        total_pkts_bmcast = bmcast_in + bmcast_out

        if VERBOSE:
            print(f"{prefix}PORT metrics ifIndex={if_index}: bits_in={total_bits_in:,} bits_out={total_bits_out:,} "
                  f"pkts_in={total_pkts_in:,} pkts_out={total_pkts_out:,} "
                  f"ucast={total_pkts_ucast:,} bmcast={total_pkts_bmcast:,}")

        rras = create_rrd_rras(check_every_n_secs)
        if os.path.exists(rrd_path):
            expected_ds_count = 2 * len(interfaces_rrd) + 22  # per-interface pairs + 22 fixed DS
            needs_recreation  = False
            try:
                info            = rrdtool.info(rrd_path)
                actual_ds_count = len([k for k in info if k.startswith('ds[') and k.endswith('].type')])
                if actual_ds_count < expected_ds_count:
                    print(f"{prefix}PORT RRD deleted for recreation: {rrd_path} "
                          f"(ds_count={actual_ds_count} < expected={expected_ds_count})")
                    needs_recreation = True
            except Exception as e:
                print(f"{prefix}PORT RRD introspection failed for '{rrd_path}': {e}, will recreate",
                      file=sys.stderr)
                needs_recreation = True

            if not needs_recreation and _check_rrd_needs_recreation(rrd_path, rras):
                print(f"{prefix}PORT RRD deleted for recreation: {rrd_path} (RRA rows under-provisioned)")
                needs_recreation = True

            if needs_recreation:
                os.remove(rrd_path)

        if not os.path.exists(rrd_path):
            create_snmp_rrd(rrd_path, check_every_n_secs, interfaces_rrd)
            if VERBOSE:
                print(f"{prefix}Created PORT RRD: {rrd_path}")

        rrd_err = update_snmp_rrd(
            rrd_path, datetime.now(), interfaces_rrd,
            None,               # tcp_retrans — not polled for single port
            total_bits_in, total_bits_out,
            total_pkts_in, total_pkts_out,
            None, None,         # errors — not aggregated for single port
            None, None,         # cpu_load / memory_pct — not polled for single port
            total_pkts_ucast, total_pkts_bmcast,
            # host DS — all None for port
            # tamper/network DS — all None for port
        )
        if rrd_err and VERBOSE:
            print(f"{prefix}PORT RRD update failed: {rrd_err}", file=sys.stderr)

    return None, oper, current_mac


def check_resource(resource: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], Optional[Dict]]:
    """Check resource with retry logic and response time tracking.

    Returns (error_msg, response_time_ms, ports_state) where ports_state is only
    populated for 'ports' and 'port' monitors, None for all other types.
    For 'port' monitors, ports_state carries {'oper': oper, 'mac': mac}.
    """
    error_msg = None

    for attempt in range(1, MAX_RETRIES + 1):
        start_time_ms = int(time.time() * 1000)

        if resource['type'] == 'ping':
            error_msg   = check_ping_resource(resource)
            ports_state = None

        elif resource['type'] == 'ports':
            error_msg, ports_state = check_ports_resource(resource)

        elif resource['type'] == 'host':
            error_msg, ports_state = check_host_resource(resource)

        elif resource['type'] == 'port':
            error_msg, oper, mac = check_port_resource(resource)
            ports_state = {'oper': oper, 'mac': mac}

        elif resource['type'] in ('http', 'quic', 'tcp', 'udp'):
            error_msg   = check_url_resource(resource)
            ports_state = None

        else:
            raise ConfigError(f"Unknown resource type: {resource['type']} for monitor {resource['name']}")

        end_time_ms      = int(time.time() * 1000)
        response_time_ms = end_time_ms - start_time_ms

        if error_msg is None:
            return None, response_time_ms, ports_state

        if attempt < MAX_RETRIES:
            time.sleep(MAX_TRY_SECS)

    return error_msg, None, None


def ping_heartbeat_url(
        heartbeat_url: str,
        monitor_name: str,
        site_name: str) \
        -> bool:
    """Fetch a heartbeat URL - tries MAX_RETRIES times and returns True if 200 OK."""
    prefix = getattr(thread_local, 'prefix', '')
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(heartbeat_url, timeout=MAX_TRY_SECS)
            if response.status_code == 200:
                if VERBOSE:
                    print(f"{prefix}Heartbeat ping SUCCESS to '{heartbeat_url}'")
                return True
            else:
                print(f"{prefix}Heartbeat ping FAILED to '{heartbeat_url}': status {response.status_code}", file=sys.stderr)
                if attempt < MAX_RETRIES:
                    time.sleep(MAX_TRY_SECS)
        except requests.exceptions.RequestException as e:
            print(f"{prefix}Heartbeat ping FAILED to '{heartbeat_url}': {e}", file=sys.stderr)
            if attempt < MAX_RETRIES:
                time.sleep(MAX_TRY_SECS)

    return False


def notify_resource_outage_with_webhook(
        outage_notifier: Dict[str, Any],
        site_name: str,
        error_reason: str) \
        -> bool:
    """Send outage notification via webhook."""
    prefix = getattr(thread_local, 'prefix', '')
    endpoint_url = outage_notifier['endpoint_url']
    request_method = outage_notifier['request_method']
    request_encoding = outage_notifier['request_encoding']
    request_prefix = outage_notifier.get('request_prefix', '')
    request_suffix = outage_notifier.get('request_suffix', '')

    # Encode message based on request_encoding (before prefix/suffix)
    if request_encoding == 'URL':
        from urllib.parse import quote
        encoded_message = quote(error_reason)
    elif request_encoding == 'HTML':
        import html
        encoded_message = html.escape(error_reason)
    elif request_encoding == 'CSVQUOTED':
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([error_reason])
        encoded_message = output.getvalue().strip()
    elif request_encoding == 'JSON':
        # For JSON, don't encode yet - will be handled during POST
        encoded_message = error_reason
    else:
        encoded_message = error_reason

    # Build final message with prefix and suffix
    message = f"{request_prefix}{encoded_message}{request_suffix}"

    try:
        if request_method == 'GET':
            full_url = f"{endpoint_url}{message}"

            if VERBOSE:
                print(f"{prefix}Webhook GET: {full_url}")

            response = requests.get(full_url, timeout=MAX_TRY_SECS)

            if response.status_code == 200:
                if VERBOSE:
                    print(f"{prefix}Webhook notification SUCCESS to '{endpoint_url}'")
                return True
            else:
                print(f"{prefix}Webhook notification FAILED to '{endpoint_url}': status {response.status_code}", file=sys.stderr)
                return False

        elif request_method == 'POST':
            if request_encoding == 'JSON':
                headers = {'Content-Type': 'application/json'}
                body = json.dumps({'message': message})
            elif request_encoding == 'URL':
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                body = message
            elif request_encoding == 'HTML':
                headers = {'Content-Type': 'text/html'}
                body = message
            else:  # CSVQUOTED, or any other encoding
                headers = {'Content-Type': 'text/plain'}
                body = message

            if VERBOSE:
                print(f"{prefix}Webhook POST: {endpoint_url}")
                print(f"{prefix}  Headers: {headers}")
                print(f"{prefix}  Body: {body[:200]}...")

            response = requests.post(endpoint_url, data=body, headers=headers, timeout=MAX_TRY_SECS)

            if response.status_code in [200, 201]:
                if VERBOSE:
                    print(f"{prefix}Webhook notification SUCCESS to '{endpoint_url}'")
                return True
            else:
                print(f"{prefix}Webhook notification FAILED to '{endpoint_url}': status {response.status_code}", file=sys.stderr)
                return False

    except requests.exceptions.RequestException as e:
        print(f"{prefix}Webhook notification FAILED to '{endpoint_url}': {e}", file=sys.stderr)
        return False


def notify_resource_outage_with_email(
        email_entry: Dict[str, Any],
        site_name: str,
        error_reason: str,
        site_config: Dict[str, Any],
        notification_type: str = 'outage') \
        -> bool:
    """Send outage notification via email.

    Args:
        email_entry: Email configuration dict with 'email' and optional control flags
        site_name: Name of the site
        error_reason: The error/recovery message to send
        site_config: Full site configuration dict (needed for email_server)
        notification_type: One of 'outage', 'recovery', or 'reminder'
    """
    prefix = getattr(thread_local, 'prefix', '')

    # Check if email_server is configured
    if 'email_server' not in site_config:
        if VERBOSE:
            print(f"{prefix}Email notification skipped: no email_server configured")
        return False

    email_server = site_config['email_server']

    # Check notification type control flags (default: true for all)
    email_outages = to_natural_language_boolean(email_entry.get('email_outages', True))
    email_recoveries = to_natural_language_boolean(email_entry.get('email_recoveries', True))
    email_reminders = to_natural_language_boolean(email_entry.get('email_reminders', True))

    # Check if this notification type should be sent
    if notification_type == 'outage' and not email_outages:
        if VERBOSE:
            print(f"{prefix}Email notification skipped for {email_entry['email']}: email_outages=false")
        return False
    elif notification_type == 'recovery' and not email_recoveries:
        if VERBOSE:
            print(f"{prefix}Email notification skipped for {email_entry['email']}: email_recoveries=false")
        return False
    elif notification_type == 'reminder' and not email_reminders:
        if VERBOSE:
            print(f"{prefix}Email notification skipped for {email_entry['email']}: email_reminders=false")
        return False

    # Extract SMTP configuration
    smtp_host = email_server['smtp_host']
    smtp_port = email_server['smtp_port']
    smtp_username = email_server.get('smtp_username')
    smtp_password = email_server.get('smtp_password')
    from_address = email_server['from_address']
    use_tls = email_server.get('use_tls', True)
    to_address = email_entry['email']

    # Determine subject based on notification type
    if notification_type == 'recovery':
        subject = f"[RECOVERY] {site_name} - Service Restored"
    elif notification_type == 'reminder':
        subject = f"[REMINDER] {site_name} - Ongoing Outage"
    else:  # outage
        subject = f"[OUTAGE] {site_name} - Service Down"

    # Create message
    msg = MIMEMultipart()
    msg['From'] = from_address
    msg['To'] = to_address
    msg['Subject'] = subject

    # Email body
    body = f"{error_reason}\n\n---\nAPMonitor Notification\nSite: {site_name}\n"
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to SMTP server
        if use_tls:
            # Use STARTTLS
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=MAX_TRY_SECS)
            server.starttls()
        else:
            # Plain connection
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=MAX_TRY_SECS)

        # Authenticate if credentials provided
        if smtp_username and smtp_password:
            server.login(smtp_username, smtp_password)

        # Send email
        server.send_message(msg)
        server.quit()

        if VERBOSE:
            print(f"{prefix}Email notification SUCCESS to '{to_address}' via {smtp_host}:{smtp_port}")

        return True

    except smtplib.SMTPAuthenticationError as e:
        print(f"{prefix}Email notification FAILED to '{to_address}': SMTP authentication error: {e}", file=sys.stderr)
        return False
    except smtplib.SMTPException as e:
        print(f"{prefix}Email notification FAILED to '{to_address}': SMTP error: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"{prefix}Email notification FAILED to '{to_address}': {type(e).__name__}: {e}", file=sys.stderr)
        return False


def calc_next_notification_delay_secs(
        notify_every_n_secs: int,
        after_every_n_notifications: int,
        secs_since_first_notification: float,
        current_notification_index: int) \
        -> float:
    """Increases the delay between notification messages according to a quadratic bezier curve.

    See devnotes/20151122 Reminder Timing with Quadratic Bezier Curve.xlsx for calculation
    """
    t = (1 / after_every_n_notifications) * current_notification_index  # See D12:D31 in devnote spreadsheet (this is a closed form solution)
    By_t = (1 - t) * (1 - t) * 0 + 2 * (1 - t) * t * notify_every_n_secs + t * t * notify_every_n_secs  # See F13 = (1-$D13)*(1-$D13)*E$39+2*(1-$D13)*$D13*E$40+$D13*$D13*E$41L13 in devnote spreadsheet
    # By_t = notify_every_n_secs # This is default behaviour with fixed intervals
    secs_between_alarms = By_t if t <= 1 else notify_every_n_secs
    if VERBOSE > 1:
        prefix = getattr(thread_local, 'prefix', '')
        print(f"{prefix}##### DEBUG: calc_next_notification_delay_secs(" +
              f"notify_every_n_secs={notify_every_n_secs}, " +
              f"after_every_n_notifications={after_every_n_notifications}, " +
              f"secs_since_first_notification={secs_since_first_notification}, " +
              f"current_notification_index={current_notification_index}) = {secs_between_alarms}"
              )
    return secs_between_alarms


def prefix_logline(site_name: Optional[str], resource_name: Optional[str]) -> str:
    """Generate log line prefix with thread ID and context.

    Args:
        site_name: Name of the site (or None)
        resource_name: Name of the resource (or None)

    Returns:
        String prefix in format "[T#XXXX Site/Resource]" where XXXX is thread ID
    """
    # thread_id = threading.get_ident()
    thread_id = threading.get_native_id()

    # Build context string
    context_parts = []
    if site_name:
        context_parts.append(site_name)
    if resource_name:
        context_parts.append(resource_name)

    context = "/".join(context_parts) if context_parts else "unknown"

    return f"[T#{thread_id:04d} {context}] "


def calc_config_checksum(resource: Dict[str, Any]) -> str:
    """Calculate SHA256 checksum of resource configuration.

    Args:
        resource: Resource configuration dict

    Returns:
        str: SHA256 hex digest of resource JSON
    """
    resource_json = json.dumps(resource, sort_keys=True)
    return hashlib.sha256(resource_json.encode()).hexdigest()


def is_check_due(
        resource: Dict[str, Any],
        prev_last_checked: Optional[str],
        check_every_n_secs: int,
    ) -> Tuple[bool, Union[float, bool]]:
    """Determine if a resource check is due.

    Args:
        resource: Resource configuration dict
        prev_last_checked: ISO timestamp string of last check (or None)

    Returns:
        tuple: (should_check: bool, seconds_since_check: float or False)
    """
    prefix = getattr(thread_local, 'prefix', '')

    # No previous check - first check
    if not prev_last_checked:
        return True, False

    # Calculate time since last check
    try:
        last_checked_time = datetime.fromisoformat(prev_last_checked)
        seconds_since_check = (datetime.now() - last_checked_time).total_seconds()
        should_check = seconds_since_check >= check_every_n_secs
    except:
        should_check = True
        seconds_since_check = False

    # Check is due if timing says yes
    if should_check:
        if VERBOSE:
            print(f"{prefix}checking: {resource}")
        return True, seconds_since_check

    # Check not due
    if VERBOSE:
        if not seconds_since_check:
            print(f"{prefix}skipping {resource['name']} (checked {format_time_ago(prev_last_checked)} ago)")
        else:
            time_until_next_check = check_every_n_secs - seconds_since_check
            print(f"{prefix}skipping {resource['name']} for {format_time_ago(time_until_next_check)} (checked {format_time_ago(prev_last_checked)} ago)")

    return False, seconds_since_check


def is_heartbeat_due(
        resource: Dict[str, Any],
        prev_last_successful_heartbeat: Optional[str],
        now: datetime) \
        -> Tuple[bool, Optional[float]]:
    """Determine if a heartbeat ping is due.

    Args:
        resource: Resource configuration dict
        prev_last_successful_heartbeat: ISO timestamp string of last heartbeat (or None)
        now: datetime object representing current time

    Returns:
        tuple: (should_heartbeat: bool, seconds_since_heartbeat: float or None)
    """
    prefix = getattr(thread_local, 'prefix', '')

    # No heartbeat configured
    if 'heartbeat_url' not in resource:
        return False, None

    heartbeat_every_n_secs = resource.get('heartbeat_every_n_secs')

    # No interval configured - heartbeat every check
    if heartbeat_every_n_secs is None:
        if VERBOSE:
            print(f"{prefix}Heartbeat SEND for {resource['name']}: "
                  f"heartbeat_every_n_secs not configured (sending every check)")
        return True, None

    # No previous heartbeat - first heartbeat
    if not prev_last_successful_heartbeat:
        if VERBOSE:
            print(f"{prefix}Heartbeat SEND for {resource['name']}: "
                  f"no previous heartbeat timestamp (first heartbeat)")
        return True, None

    # Calculate time since last heartbeat
    try:
        last_heartbeat_time = datetime.fromisoformat(prev_last_successful_heartbeat)
        seconds_since_heartbeat = (now - last_heartbeat_time).total_seconds()
        should_heartbeat = seconds_since_heartbeat >= heartbeat_every_n_secs

        # DIAGNOSTIC: One-line heartbeat timing
        if VERBOSE:
            time_till_due = heartbeat_every_n_secs - seconds_since_heartbeat
            status = "IS DUE" if should_heartbeat else "IS NOT DUE"
            last_str = format_time_ago(seconds_since_heartbeat)

            if should_heartbeat:
                overdue_str = format_time_ago(abs(time_till_due))
                print(f"{prefix}Heartbeat: {status} - last {last_str} ({int(seconds_since_heartbeat * 1000):,} ms) ago, overdue by: {overdue_str} ({int(time_till_due * 1000):,} ms)")
            else:
                next_str = format_time_ago(time_till_due)
                print(f"{prefix}Heartbeat: {status} - last {last_str} ({int(seconds_since_heartbeat * 1000):,} ms) ago, next due in: {next_str} ({int(time_till_due * 1000):,} ms)")

        # HIGH-SIGNAL INSTRUMENTATION: Show heartbeat timing decision
        if VERBOSE:
            if should_heartbeat:
                print(f"{prefix}Heartbeat DUE for {resource['name']}: "
                      f"{seconds_since_heartbeat:.1f}s elapsed >= {heartbeat_every_n_secs}s interval "
                      f"(last: {format_time_ago(prev_last_successful_heartbeat)} ago)")
            else:
                time_until_next = heartbeat_every_n_secs - seconds_since_heartbeat
                print(f"{prefix}Heartbeat SKIP for {resource['name']}: "
                      f"{seconds_since_heartbeat:.1f}s elapsed < {heartbeat_every_n_secs}s interval "
                      f"(wait {format_time_ago(time_until_next)}, last: {format_time_ago(prev_last_successful_heartbeat)} ago)")

        return should_heartbeat, seconds_since_heartbeat

    except Exception as e:
        # HIGH-SIGNAL INSTRUMENTATION: Show timestamp parse failure
        print(f"{prefix}Heartbeat timestamp parse FAILED for {resource['name']}: {e} "
              f"(prev_last_successful_heartbeat='{prev_last_successful_heartbeat}'), "
              f"defaulting to should_heartbeat=True", file=sys.stderr)
        return True, None


def get_rrd_path(monitor_name: str, rrd_type: str) -> str:
    """Generate filesystem-safe RRD file path for a monitor.

    Args:
        monitor_name: Name of the monitor
        rrd_type: Type of RRD file ('availability', 'ports', 'port', 'host')

    Returns:
        str: Full path to RRD file
    """
    safe_name = re.sub(r'[^\w\-.]', '_', monitor_name)

    base_path = Path(STATEFILE)
    rrd_dir = base_path.parent / (base_path.stem + '.rrd')

    return str(rrd_dir / f"{safe_name}-{rrd_type}.rrd")


def _check_rrd_needs_recreation(rrd_path: str, expected_rras: List[str]) -> bool:
    """Return True if any RRA in the existing RRD has fewer rows than configured.

    Args:
        rrd_path: Full path to existing RRD file
        expected_rras: RRA definition strings from create_rrd_rras() — row count
                       parsed from the 4th colon-separated field (e.g. 'RRA:AVERAGE:0.5:1:8640')

    Returns:
        bool: True if RRD should be deleted and recreated, False if compatible
    """
    prefix = getattr(thread_local, 'prefix', '')
    try:
        info = rrdtool.info(rrd_path)
        for i, rra_def in enumerate(expected_rras):
            # RRA def format: RRA:CF:xff:steps:rows
            expected_rows = int(rra_def.split(':')[4])
            actual_rows = info.get(f'rra[{i}].rows')
            if actual_rows is None or actual_rows < expected_rows:
                if VERBOSE:
                    print(f"{prefix}RRD recreation needed: {rrd_path} "
                          f"rra[{i}] actual_rows={actual_rows} < expected={expected_rows}")
                return True
        return False
    except Exception as e:
        print(f"{prefix}RRD introspection failed for '{rrd_path}': {e}, will recreate", file=sys.stderr)
        return True


def create_rrd(rrd_path: str, step_secs: int) -> None:
    """Create RRD file with MRTG-compatible retention policy.

    Args:
        rrd_path: Full path to RRD file to create
        step_secs: Update interval in seconds (from check_every_n_secs)
    """
    global RRD_ELAPSED_MS
    prefix = getattr(thread_local, 'prefix', '')

    # Ensure RRD directory exists
    os.makedirs(os.path.dirname(rrd_path), exist_ok=True)

    # Calculate heartbeat (2x step allows one missed update)
    heartbeat = step_secs * 2

    # Data sources
    # Store availability as 0-100 for natural percentage display
    data_sources = [
        f'DS:response_time:GAUGE:{heartbeat}:0:U',  # Response time in ms (0 to unlimited)
        f'DS:is_up:GAUGE:{heartbeat}:0:100',  # Availability percentage (0 to 100)
    ]

    # Generate RRAs for this step interval
    rras = create_rrd_rras(step_secs)

    # Create RRD
    try:
        _t = int(time.time() * 1000)
        rrdtool.create(
            rrd_path,
            '--step', str(step_secs),
            '--start', str(int(time.time()) - step_secs),
            *data_sources,
            *rras
        )
        with RRD_ELAPSED_LOCK:
            RRD_ELAPSED_MS += int(time.time() * 1000) - _t
        if VERBOSE:
            print(f"{prefix}Created RRD file: {rrd_path} (step={step_secs}s)")
    except rrdtool.OperationalError as e:
        print(f"{prefix}Failed to create RRD file '{rrd_path}': {e}", file=sys.stderr)


def update_rrd(rrd_path: str, timestamp: datetime, response_time_ms: Optional[int], is_up: bool) -> str:
    """Update RRD file with latest metrics.

    Args:
        rrd_path: Full path to RRD file
        timestamp: Timestamp of the measurement
        response_time_ms: Response time in milliseconds (or None if check failed)
        is_up: Whether resource is up (True) or down (False)
    """
    global RRD_ELAPSED_MS
    prefix = getattr(thread_local, 'prefix', '')

    # Convert to epoch timestamp
    epoch = int(timestamp.timestamp())

    # Format values (use 'U' for unknown if response_time is None)
    # Store availability as 0-100 for percentage display
    response_val = str(response_time_ms) if response_time_ms is not None else 'U'
    is_up_val = '100' if is_up else '0'

    try:
        _t = int(time.time() * 1000)
        rrdtool.update(
            rrd_path,
            f'{epoch}:{response_val}:{is_up_val}'
        )
        with RRD_ELAPSED_LOCK:
            RRD_ELAPSED_MS += int(time.time() * 1000) - _t
        if VERBOSE > 1:
            print(f"{prefix}Updated RRD: {rrd_path} @ {epoch} response={response_val}ms is_up={is_up_val}%")
    except rrdtool.OperationalError as e:
        error_msg = f"Failed to update RRD file '{rrd_path}': {e}"
        print(f"{prefix}{error_msg}", file=sys.stderr)
        return error_msg

    return None


def create_snmp_rrd(rrd_path: str, step_secs: int, interfaces: Dict[str, Dict[str, Any]]) -> None:
    """Create RRD file for SNMP interface metrics, system resources, and host performance metrics.

    Unified schema for port, ports, and host monitor types:
    - Per-interface DS pairs (ports/port only, empty for host)
    - 11 fixed aggregate network DS (ports/port populated, host stores U)
    - 7 fixed host performance DS (host populated, ports/port store U)
    - 4 fixed tamper/network DS (ports only — port/host store U)

    Args:
        rrd_path: Full path to RRD file to create
        step_secs: Update interval in seconds
        interfaces: Dict mapping interface index to interface data (with 'name' key)

    NB: DS count is now 22 fixed. Existing RRDs with <22 fixed DS will be auto-healed (deleted and recreated).
    """
    global RRD_ELAPSED_MS
    prefix = getattr(thread_local, 'prefix', '')

    os.makedirs(os.path.dirname(rrd_path), exist_ok=True)

    heartbeat = step_secs * 2

    data_sources = []

    # Per-interface byte counters (ports/port only — empty for host)
    for if_index in interfaces:
        safe_if_name = f"if{if_index}"
        data_sources.append(f'DS:{safe_if_name}_in:COUNTER:{heartbeat}:0:U')
        data_sources.append(f'DS:{safe_if_name}_out:COUNTER:{heartbeat}:0:U')

    # Fixed aggregate network DS (ports/port populated, host stores U)
    data_sources.append(f'DS:tcp_retrans:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_bits_in:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_bits_out:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_pkts_in:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_pkts_out:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_errors_in:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_errors_out:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_pkts_ucast:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_pkts_bmcast:COUNTER:{heartbeat}:0:U')

    # System resource DS (all types)
    data_sources.append(f'DS:cpu_load:GAUGE:{heartbeat}:0:100')
    data_sources.append(f'DS:memory_pct:GAUGE:{heartbeat}:0:100')

    # Fixed host performance DS (host populated, ports/port store U)
    data_sources.append(f'DS:context_switches:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:swap_io:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:disk_read:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:disk_write:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:disk_space_pct:GAUGE:{heartbeat}:0:100')
    data_sources.append(f'DS:swap_used:GAUGE:{heartbeat}:0:U')
    data_sources.append(f'DS:interrupts:COUNTER:{heartbeat}:0:U')

    # Fixed tamper/network capacity DS (ports only — port/host store U)
    data_sources.append(f'DS:ports_up_count:GAUGE:{heartbeat}:0:U')
    data_sources.append(f'DS:nvram_flash_bytes:GAUGE:{heartbeat}:0:U')
    data_sources.append(f'DS:mac_count:GAUGE:{heartbeat}:0:U')
    data_sources.append(f'DS:arp_count:GAUGE:{heartbeat}:0:U')

    rras = create_rrd_rras(step_secs)

    try:
        _t = int(time.time() * 1000)
        rrdtool.create(
            rrd_path,
            '--step', str(step_secs),
            '--start', str(int(time.time()) - step_secs),
            *data_sources,
            *rras
        )
        with RRD_ELAPSED_LOCK:
            RRD_ELAPSED_MS += int(time.time() * 1000) - _t
        if VERBOSE:
            print(f"{prefix}Created SNMP RRD file: {rrd_path} (step={step_secs}s, {len(interfaces)} interfaces, {len(data_sources)} data sources)")
    except rrdtool.OperationalError as e:
        print(f"{prefix}Failed to create SNMP RRD file '{rrd_path}': {e}", file=sys.stderr)


def update_snmp_rrd(rrd_path: str, timestamp: datetime, interfaces: Dict[str, Dict[str, Any]],
                    tcp_retrans: Optional[int],
                    total_bits_in: Optional[int], total_bits_out: Optional[int],
                    total_pkts_in: Optional[int], total_pkts_out: Optional[int],
                    total_errors_in: Optional[int], total_errors_out: Optional[int],
                    cpu_load: Optional[float], memory_pct: Optional[float],
                    total_pkts_ucast: Optional[int] = None, total_pkts_bmcast: Optional[int] = None,
                    context_switches: Optional[int] = None, swap_io: Optional[int] = None,
                    disk_read: Optional[int] = None, disk_write: Optional[int] = None,
                    disk_space_pct: Optional[float] = None, swap_used: Optional[int] = None,
                    interrupts: Optional[int] = None,
                    ports_up_count: Optional[int] = None, nvram_flash_bytes: Optional[int] = None,
                    mac_count: Optional[int] = None, arp_count: Optional[int] = None) -> Optional[str]:
    """Update SNMP RRD file with latest interface metrics, system resources, and host performance.

    All numeric parameters accept None → stored as 'U' (unknown) in RRD.
    Network DS (total_bits_*, total_pkts_*, total_errors_*, tcp_retrans) should be
    passed as None for host monitors. Host DS (context_switches etc.) should be
    passed as None for ports/port monitors.
    Tamper/network DS (ports_up_count, nvram_flash_bytes, mac_count, arp_count) should be
    passed as None for port and host monitors — these are ports-only metrics.

    Args:
        rrd_path: Full path to RRD file
        timestamp: Timestamp of the measurement
        interfaces: Dict mapping interface index to metrics (with 'in_octets', 'out_octets')
        tcp_retrans: TCP retransmit segments counter (ports only)
        total_bits_in: Aggregate inbound bits across all interfaces (ports/port only)
        total_bits_out: Aggregate outbound bits across all interfaces (ports/port only)
        total_pkts_in: Aggregate inbound packets across all interfaces (ports/port only)
        total_pkts_out: Aggregate outbound packets across all interfaces (ports/port only)
        total_errors_in: Aggregate inbound errors across all interfaces (ports/port only)
        total_errors_out: Aggregate outbound errors across all interfaces (ports/port only)
        cpu_load: Average CPU utilization percentage (0-100)
        memory_pct: Memory utilization percentage (0-100)
        total_pkts_ucast: Total unicast packets in+out combined (ports/port only)
        total_pkts_bmcast: Total broadcast+multicast packets in+out combined (ports/port only)
        context_switches: Raw context switch counter (host only)
        swap_io: Raw swap in+out counter (host only)
        disk_read: Summed disk read bytes counter (host only)
        disk_write: Summed disk write bytes counter (host only)
        disk_space_pct: Root filesystem utilization percentage (host only)
        swap_used: Swap used bytes (host only)
        interrupts: Raw hardware interrupt counter (host only)
        ports_up_count: Count of oper=up interfaces (ports only)
        nvram_flash_bytes: Sum of used bytes across NVRAM/flash hrStorage entries (ports only)
        mac_count: Count of learned FDB entries via Q-BRIDGE-MIB (ports only)
        arp_count: Count of ARP entries via ipNetToPhysicalTable / ipNetToMediaTable (ports only)
    """
    global RRD_ELAPSED_MS
    prefix = getattr(thread_local, 'prefix', '')

    epoch = int(timestamp.timestamp())

    def _v(val: Any) -> str:
        """Format value for RRD update — None becomes 'U'."""
        if val is None:
            return 'U'
        if isinstance(val, float):
            return f'{val:.2f}'
        return str(val)

    ds_names = []
    values   = []

    # Per-interface byte counters
    for if_index in sorted(interfaces.keys()):
        if_data      = interfaces[if_index]
        safe_if_name = f"if{if_index}"
        ds_names.append(f'{safe_if_name}_in')
        ds_names.append(f'{safe_if_name}_out')
        values.append(_v(if_data.get('in_octets')))
        values.append(_v(if_data.get('out_octets')))

    # Fixed aggregate network DS
    ds_names.append('tcp_retrans');       values.append(_v(tcp_retrans))
    ds_names.append('total_bits_in');     values.append(_v(total_bits_in))
    ds_names.append('total_bits_out');    values.append(_v(total_bits_out))
    ds_names.append('total_pkts_in');     values.append(_v(total_pkts_in))
    ds_names.append('total_pkts_out');    values.append(_v(total_pkts_out))
    ds_names.append('total_errors_in');   values.append(_v(total_errors_in))
    ds_names.append('total_errors_out');  values.append(_v(total_errors_out))
    ds_names.append('total_pkts_ucast');  values.append(_v(total_pkts_ucast))
    ds_names.append('total_pkts_bmcast'); values.append(_v(total_pkts_bmcast))

    # System resource DS
    ds_names.append('cpu_load');   values.append(_v(cpu_load))
    ds_names.append('memory_pct'); values.append(_v(memory_pct))

    # Fixed host performance DS
    ds_names.append('context_switches'); values.append(_v(context_switches))
    ds_names.append('swap_io');          values.append(_v(swap_io))
    ds_names.append('disk_read');        values.append(_v(disk_read))
    ds_names.append('disk_write');       values.append(_v(disk_write))
    ds_names.append('disk_space_pct');   values.append(_v(disk_space_pct))
    ds_names.append('swap_used');        values.append(_v(swap_used))
    ds_names.append('interrupts');       values.append(_v(interrupts))

    # Fixed tamper/network capacity DS (ports only — port/host pass None → U)
    ds_names.append('ports_up_count');    values.append(_v(ports_up_count))
    ds_names.append('nvram_flash_bytes'); values.append(_v(nvram_flash_bytes))
    ds_names.append('mac_count');         values.append(_v(mac_count))
    ds_names.append('arp_count');         values.append(_v(arp_count))

    template  = ':'.join(ds_names)
    value_str = ':'.join(values)

    try:
        _t = int(time.time() * 1000)
        rrdtool.update(
            rrd_path,
            '--template', template,
            f'{epoch}:{value_str}'
        )
        with RRD_ELAPSED_LOCK:
            RRD_ELAPSED_MS += int(time.time() * 1000) - _t
        if VERBOSE > 1:
            print(f"{prefix}Updated SNMP RRD: {rrd_path} @ {epoch} ({len(interfaces)} interfaces, aggregates, system, host)")
    except rrdtool.OperationalError as e:
        error_msg = f"Failed to update SNMP RRD file '{rrd_path}': {e}"
        print(f"{prefix}{error_msg}", file=sys.stderr)
        return error_msg
    return None


def create_rrd_rras(step_secs: int) -> List[str]:
    """Generate RRAs that maintain MRTG-compatible time ranges.

    Time ranges maintained:
    - High-resolution recent: 31 days at native resolution
    - Short-term: ~64 days at 5-minute intervals
    - Medium-term: ~387 days at 30-minute intervals
    - Long-term (hourly): ~5 years at 1-hour intervals
    - Historical: ~62 years at 1-day intervals

    Args:
        step_secs: RRD step interval in seconds

    Returns:
        List of RRA definition strings
    """
    # Calculate consolidation factors to achieve target intervals
    steps_per_5min  = max(1, 300   // step_secs)
    steps_per_30min = max(1, 1800  // step_secs)
    steps_per_1hour = max(1, 3600  // step_secs)
    steps_per_day   = max(1, 86400 // step_secs)

    # Calculate rows to maintain time ranges
    rows_1day_native  = 86400 // step_secs * 31  # 31 days at native resolution
    rows_2days_5min   = 18600                     # ~64 days at 5-min
    rows_12days_30min = 18600                     # ~387 days at 30-min
    rows_5years_1hour = 43830                     # ~5 years at 1-hour
    rows_2years_daily = 22692                     # ~62 years at 1-day

    return [
        # High-resolution recent data
        f'RRA:AVERAGE:0.5:1:{rows_1day_native}',
        f'RRA:MIN:0.5:1:{rows_1day_native}',
        f'RRA:MAX:0.5:1:{rows_1day_native}',

        # MRTG-compatible intervals
        f'RRA:AVERAGE:0.5:{steps_per_5min}:{rows_2days_5min}',
        f'RRA:AVERAGE:0.5:{steps_per_30min}:{rows_12days_30min}',
        f'RRA:AVERAGE:0.5:{steps_per_1hour}:{rows_5years_1hour}',
        f'RRA:AVERAGE:0.5:{steps_per_day}:{rows_2years_daily}',

        # Min/Max for MRTG intervals
        f'RRA:MIN:0.5:{steps_per_5min}:{rows_2days_5min}',
        f'RRA:MAX:0.5:{steps_per_5min}:{rows_2days_5min}',
    ]


def check_and_heartbeat_r(resource: Dict[str, Any], site_config: Dict[str, Any]) -> None:
    """Check resource and ping heartbeat if up."""

    # Store prefix in thread-local storage at start of thread execution
    thread_local.prefix = prefix_logline(site_config['name'], resource['name'])
    prefix = thread_local.prefix

    # Calculate current config checksum
    resource_checksum = calc_config_checksum(resource)

    # Get previous state for this resource
    with STATE_LOCK:
        prev_state = STATE.get(resource['name'], {}) or {}
        prev_last_checked = prev_state.get('last_checked')
        prev_config_checksum = prev_state.get('last_config_checksum')
        prev_last_successful_heartbeat = prev_state.get('last_successful_heartbeat')
        prev_last_response_time_ms = prev_state.get('last_response_time_ms') or 0

    # Check if config changed
    config_changed = prev_config_checksum and prev_config_checksum != resource_checksum

    # Determine if we should check this resource
    check_every_n_secs = resource.get('check_every_n_secs', DEFAULT_CHECK_EVERY_N_SECS)
    should_check, seconds_since_check = is_check_due(resource, prev_last_checked, check_every_n_secs)

    # Determine if heartbeat is due (adjust time by last response time to account for check duration)
    from datetime import timedelta
    now_adjusted = datetime.now() + timedelta(milliseconds=prev_last_response_time_ms)
    should_heartbeat_early, _ = is_heartbeat_due(resource, prev_last_successful_heartbeat, now_adjusted)

    # Override if config changed or heartbeat due
    if not should_check and config_changed:
        should_check = True
        if VERBOSE:
            print(f"{prefix}configuration changed for {resource['name']}, checking immediately: {resource}")
    elif not should_check and should_heartbeat_early:
        should_check = True
        if VERBOSE:
            print(f"{prefix}heartbeat due for {resource['name']}, checking immediately")

    if not should_check:
        return

    # Get previous state for this resource
    with STATE_LOCK:
        prev_state = STATE.get(resource['name'], {})
        prev_is_up = prev_state.get('is_up', True)
        prev_down_count = prev_state.get('down_count', 0)
        prev_last_alarm_started = prev_state.get('last_alarm_started')
        prev_last_notified = prev_state.get('last_notified')
        prev_last_successful_heartbeat = prev_state.get('last_successful_heartbeat')
        prev_notified_count = prev_state.get('notified_count', 0)
        prev_ports_state = prev_state.get('ports_state')  # None on first poll

    # Check resource
    error_reason, last_response_time_ms, current_ports_state = check_resource(resource)
    is_up = error_reason is None
    last_successful_heartbeat = prev_last_successful_heartbeat

    # Get current time with timezone
    now = datetime.now()
    timestamp_str = now.strftime('%I:%M %p %Z').lstrip('0').strip()

    # Get pacing & notification config for this resource
    notify_every_n_secs = resource.get('notify_every_n_secs', DEFAULT_NOTIFY_EVERY_N_SECS)
    after_every_n_notifications = resource.get('after_every_n_notifications', DEFAULT_AFTER_EVERY_N_NOTIFICATIONS)
    monitor_email_enabled = to_natural_language_boolean(resource.get('email', True))
    alarms_enabled = to_natural_language_boolean(
        resource.get('alarms', site_config.get('alarms', True))
    )

    # Ping heartbeat URL if required
    if is_up and 'heartbeat_url' in resource:
        should_heartbeat, seconds_since_heartbeat = is_heartbeat_due(resource, prev_last_successful_heartbeat, now)

        if should_heartbeat:
            if ping_heartbeat_url(resource['heartbeat_url'], resource['name'], site_config['name']):
                last_successful_heartbeat = datetime.now().isoformat()
        elif VERBOSE:
            print(f"{prefix}skipping heartbeat for {resource['name']} (heartbeat sent {format_time_ago(prev_last_successful_heartbeat)} ago)")

    # Handle ports monitor diff/notify logic
    # 'host' skips this block — it has no port state to diff
    if resource['type'] == 'ports' and is_up and current_ports_state:
        if prev_ports_state is None:
            if VERBOSE:
                print(f"{prefix}PORTS baseline established for '{resource['name']}': {len(current_ports_state)} interfaces")
        else:
            all_indices = set(prev_ports_state.keys()) | set(current_ports_state.keys())

            for if_index in sorted(all_indices, key=lambda x: int(x)):
                prev_iface = prev_ports_state.get(if_index)
                curr_iface = current_ports_state.get(if_index)

                def _notify(msg: str) -> None:
                    """Fire notification and advance throttle state."""
                    if alarms_enabled:
                        if monitor_email_enabled and 'outage_emails' in site_config:
                            for email_entry in site_config['outage_emails']:
                                notify_resource_outage_with_email(
                                    email_entry, site_config['name'], msg, site_config, 'outage')
                        if 'outage_webhooks' in site_config:
                            for webhook in site_config['outage_webhooks']:
                                notify_resource_outage_with_webhook(webhook, site_config['name'], msg)

                def _status_tuple(iface):
                    if iface is None:
                        return None
                    return (iface['name'], iface['oper'], iface['admin'])

                if _status_tuple(curr_iface) != _status_tuple(prev_iface):
                    if prev_iface is None:
                        change_msg = (
                            f"{resource['name']} in {site_config['name']}: "
                            f"{curr_iface['name']} appeared "
                            f"oper={curr_iface['oper']} admin={curr_iface['admin']} at {timestamp_str}"
                        )
                    elif curr_iface is None:
                        change_msg = (
                            f"{resource['name']} in {site_config['name']}: "
                            f"{prev_iface['name']} disappeared "
                            f"(was oper={prev_iface['oper']} admin={prev_iface['admin']}) at {timestamp_str}"
                        )
                    else:
                        change_msg = (
                            f"{resource['name']} in {site_config['name']}: "
                            f"{curr_iface['name']} oper={curr_iface['oper']} admin={curr_iface['admin']} "
                            f"(was oper={prev_iface['oper']} admin={prev_iface['admin']}) at {timestamp_str}"
                        )
                    print(f"{prefix}##### PORT CHANGE: {change_msg} #####", file=sys.stderr)
                    _notify(change_msg)

                if curr_iface is not None and prev_iface is not None:
                    appeared    = sorted(set(curr_iface['macs']) - set(prev_iface['macs']))
                    disappeared = sorted(set(prev_iface['macs']) - set(curr_iface['macs']))

                    if appeared or disappeared:
                        parts = []
                        if appeared:
                            parts.append(f"appeared=[{', '.join(appeared)}]")
                        if disappeared:
                            parts.append(f"disappeared=[{', '.join(disappeared)}]")
                        mac_change_msg = (
                            f"{resource['name']} in {site_config['name']}: "
                            f"{curr_iface['name']} MAC change {' '.join(parts)} at {timestamp_str}"
                        )
                        print(f"{prefix}##### PORT MAC CHANGE: {mac_change_msg} #####", file=sys.stderr)
                        _notify(mac_change_msg)

    # Normal up/down/recovery logic (all types except 'ports' diff path)
    else:
        if is_up:
            if not prev_is_up:
                outage_duration = format_time_ago(prev_last_alarm_started)
                recovery_message = f"{resource['name']} in {site_config['name']} is UP ({resource['address']}) at {timestamp_str}, outage lasted {outage_duration}"
                print(f"{prefix}##### RECOVERY: {recovery_message} #####", file=sys.stderr)

                if alarms_enabled:
                    if monitor_email_enabled and 'outage_emails' in site_config:
                        for email_entry in site_config['outage_emails']:
                            notify_resource_outage_with_email(email_entry, site_config['name'], recovery_message, site_config, 'recovery')

                    if 'outage_webhooks' in site_config:
                        for webhook in site_config['outage_webhooks']:
                            notify_resource_outage_with_webhook(webhook, site_config['name'], recovery_message)

                last_notified = now.isoformat()
                notified_count = prev_notified_count
            else:
                last_notified = prev_last_notified
                notified_count = prev_notified_count

            down_count = 0
            last_alarm_started = prev_last_alarm_started
        else:
            down_count = prev_down_count + 1
            if prev_is_up:
                last_alarm_started = now.isoformat()
                prev_last_notified = None
                prev_notified_count = 0
            else:
                last_alarm_started = prev_last_alarm_started

            if prev_is_up:
                error_message = f"{resource['name']} in {site_config['name']} new outage: {error_reason} ({resource['address']}) at {timestamp_str}, down for {format_time_ago(last_alarm_started)}"
                print(f"{prefix}##### NEW OUTAGE: {error_message} #####", file=sys.stderr)
            else:
                error_message = f"{resource['name']} in {site_config['name']} is down: {error_reason} ({resource['address']}) at {timestamp_str}, down for {format_time_ago(last_alarm_started)}"
                print(f"{prefix}##### DOWN: {error_message} #####", file=sys.stderr)

            should_notify = True

            secs_since_first_notification = 0
            if last_alarm_started:
                try:
                    alarm_started_time = datetime.fromisoformat(last_alarm_started)
                    secs_since_first_notification = (now - alarm_started_time).total_seconds()
                except:
                    secs_since_first_notification = 0

            next_notification_delay_secs = calc_next_notification_delay_secs(
                notify_every_n_secs, after_every_n_notifications,
                secs_since_first_notification, prev_notified_count)
            seconds_since_notify = False
            if prev_last_notified:
                try:
                    last_notified_time = datetime.fromisoformat(prev_last_notified)
                    seconds_since_notify = (now - last_notified_time).total_seconds()
                    should_notify = seconds_since_notify >= next_notification_delay_secs
                except:
                    should_notify = True

            if should_notify:
                notification_type = 'outage' if prev_notified_count == 0 else 'reminder'

                if alarms_enabled:
                    if monitor_email_enabled and 'outage_emails' in site_config:
                        for email_entry in site_config['outage_emails']:
                            notify_resource_outage_with_email(email_entry, site_config['name'], error_message, site_config, notification_type)

                    if 'outage_webhooks' in site_config:
                        for webhook in site_config['outage_webhooks']:
                            notify_resource_outage_with_webhook(webhook, site_config['name'], error_message)

                last_notified = now.isoformat()
                notified_count = prev_notified_count + 1
            else:
                if VERBOSE:
                    if not seconds_since_notify:
                        print(f"{prefix}skipping {resource['name']} notification (notified {format_time_ago(prev_last_notified)} ago)")
                    else:
                        time_until_next_secs = next_notification_delay_secs - seconds_since_notify
                        print(f"{prefix}skipping {resource['name']} notification for {format_time_ago(time_until_next_secs)} (notified {format_time_ago(prev_last_notified)} ago)")

                last_notified = prev_last_notified
                notified_count = prev_notified_count

    # Update RRD database for availability monitors (ping, http, quic, tcp, udp)
    # SNMP-family RRDs (ports, host, port) are handled in check_resource() / check_port_resource()
    if RRD_ENABLED and resource['type'] not in ('ports', 'host', 'port'):
        rrd_path = get_rrd_path(resource['name'], 'availability')
        rras = create_rrd_rras(check_every_n_secs)

        if os.path.exists(rrd_path) and _check_rrd_needs_recreation(rrd_path, rras):
            print(f"{prefix}Availability RRD deleted for recreation: {rrd_path} (RRA rows under-provisioned)")
            os.remove(rrd_path)

        if VERBOSE > 1:
            print(f"{prefix}updating RRD database for {rrd_path} w/ {now}, {last_response_time_ms}, {is_up}")
        if not os.path.exists(rrd_path):
            create_rrd(rrd_path, check_every_n_secs)
        update_rrd(rrd_path, now, last_response_time_ms, is_up)

    # Update state for this resource.
    # Preserve 'detail' and 'disk_space_pct' written by check functions during this poll —
    # both are stored via update_state() inside check_ports_resource / check_host_resource
    # before this point, and must not be clobbered by the broader state update below.
    with STATE_LOCK:
        prev_detail       = STATE.get(resource['name'], {}).get('detail')
        prev_disk_space   = STATE.get(resource['name'], {}).get('disk_space_pct')

    new_state = {
        'is_up':                    is_up,
        'detail':                   prev_detail,       # preserve detail written by check functions
        'disk_space_pct':           prev_disk_space,   # preserve disk_space_pct written by check_host_resource
        'last_checked':             now.isoformat(),
        'last_response_time_ms':    last_response_time_ms,
        'last_successful_heartbeat': last_successful_heartbeat,
        'error_reason':             error_reason,
        'last_config_checksum':     resource_checksum,
    }

    if resource['type'] == 'ports' and current_ports_state:
        new_state['ports_state'] = current_ports_state
    else:
        new_state['down_count']        = down_count
        new_state['last_alarm_started'] = prev_last_alarm_started if is_up else last_alarm_started
        new_state['last_notified']      = last_notified if is_up else (last_notified if should_notify else prev_last_notified)
        new_state['notified_count']     = notified_count

    update_state({resource['name']: new_state})


def get_default_statefile(config_path: str) -> str:
    """Get platform-appropriate default statefile location derived from config filename.

    On Unix-like systems: /var/tmp/APMonitor/<config-stem>.statefile.json
    On Windows:          %TEMP%\\APMonitor\\<config-stem>.statefile.json
    Fallback:            ./<config-stem>.statefile.json

    Directory is created with 755 permissions (no group write — www-data excluded).
    """
    config_stem = Path(config_path).stem  # e.g. "apmonitor-config"
    filename    = f"{config_stem}.statefile.json"
    system      = platform.system().lower()

    if system in ['linux', 'darwin', 'freebsd', 'openbsd', 'netbsd']:
        state_dir = '/var/tmp/APMonitor'
        os.makedirs(state_dir, mode=0o755, exist_ok=True)
        return f'{state_dir}/{filename}'
    elif system == 'windows':
        temp_dir  = os.environ.get('TEMP', os.environ.get('TMP', 'C:\\Temp'))
        state_dir = os.path.join(temp_dir, 'APMonitor')
        os.makedirs(state_dir, exist_ok=True)
        return os.path.join(state_dir, filename)
    else:
        return f'./{filename}'


def check_and_heartbeat(resource: Dict[str, Any], site_config: Dict[str, Any]) -> None:

    return check_and_heartbeat_r(resource, site_config)


def create_pid_file_or_exit_on_unix(config_path: str) -> Optional[str]:
    """Create PID lockfile on Unix-like systems. Returns lockfile path or None."""
    system = platform.system().lower()

    print(f"create_pid_file_or_exit_on_unix({config_path}) called")
    if system not in ['linux', 'darwin', 'freebsd', 'openbsd', 'netbsd']:
        return None

    # Generate hash from config file path (use absolute path for consistency)
    config_hash = hashlib.sha256(os.path.abspath(config_path).encode()).hexdigest()[:16]
    lockfile_path = f'/tmp/apmonitor-{config_hash}.lock'

    if os.path.exists(lockfile_path):
        try:
            with open(lockfile_path, 'r') as f:
                old_pid = int(f.read().strip())

            # Check if process exists
            try:
                os.kill(old_pid, 0)
                # Process exists, exit
                print(f"Error: Another APMonitor instance is already running with config '{config_path}' (PID {old_pid})", file=sys.stderr)
                sys.exit(1)
            except OSError:
                # Process doesn't exist, stale lockfile
                if VERBOSE:
                    print(f"Removing stale lockfile for PID {old_pid}")
        except (ValueError, IOError) as e:
            if VERBOSE:
                print(f"Warning: Could not read lockfile: {e}")

    # Create lockfile with current PID
    try:
        with open(lockfile_path, 'w') as f:
            f.write(str(os.getpid()))
    except IOError as e:
        print(f"Error: Could not create lockfile '{lockfile_path}': {e}", file=sys.stderr)
        sys.exit(1)

    return lockfile_path


def generate_monitor_detail_page(resource: Dict[str, Any], detail: Dict[str, Any],
                                  work_dir: str) -> None:
    """Generate a per-monitor detail HTML page with system info, interface table, and MAC/IP/hostname table.

    Written to {work_dir}/{monitor_type}-{safe_name}-detail.html alongside index.html,
    with atomic .new/.old rotation. Auto-refreshes every 95 seconds matching index.html.

    Args:
        resource: Monitor config dict (needs 'name', 'type', 'address')
        detail:   Detail dict from state[name]['detail'] — populated by collect_snmp_detail()
        work_dir: MRTG working directory — detail page written here alongside index.html
    """
    prefix = getattr(thread_local, 'prefix', '')

    if not detail:
        if VERBOSE:
            print(f"{prefix}DETAIL page skipped for '{resource['name']}': no detail data in state yet")
        return

    safe_name    = re.sub(r'[^\w\-.]', '_', resource['name'])
    monitor_type = resource['type']
    display_name = f"{monitor_type}: {resource['name']}"
    output_path  = str(Path(work_dir) / f"{monitor_type}-{safe_name}-detail.html")

    sys_name     = detail.get('sys_name')     or '—'
    sys_location = detail.get('sys_location') or '—'
    sys_contact  = detail.get('sys_contact')  or '—'
    interfaces   = detail.get('interfaces', {})

    generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _fmt_speed(mbps: int) -> str:
        if not mbps:
            return '—'
        if mbps >= 1000:
            return f"{mbps // 1000} Gbps"
        return f"{mbps} Mbps"

    # -------------------------------------------------------------------------
    # Interface table rows
    # -------------------------------------------------------------------------
    iface_rows = []
    for if_index in sorted(interfaces.keys(), key=lambda x: int(x)):
        iface = interfaces[if_index]
        oper  = iface.get('oper', '—')
        oper_class = 'oper-up' if oper == 'up' else ('oper-down' if oper == 'down' else 'oper-other')

        neighbour = '—'
        if iface.get('neighbour_host'):
            proto = iface.get('neighbour_proto', '')
            port  = iface.get('neighbour_port', '')
            neighbour = f"{iface['neighbour_host']}"
            if port:
                neighbour += f" &nbsp;<span class='sub'>{port}</span>"
            if proto:
                neighbour += f" &nbsp;<span class='proto'>{proto}</span>"

        iface_rows.append(
            f"<tr>"
            f"<td class='mono'>{if_index}</td>"
            f"<td class='mono'>{iface.get('slot') or '—'}</td>"
            f"<td class='mono'>{iface.get('descr', '—')}</td>"
            f"<td>{iface.get('alias', '') or '—'}</td>"
            f"<td>{_fmt_speed(iface.get('speed_mbps', 0))}</td>"
            f"<td class='{oper_class}'>{oper}</td>"
            f"<td>{iface.get('admin', '—')}</td>"
            f"<td>{neighbour}</td>"
            f"</tr>"
        )

    iface_table = "\n".join(iface_rows) if iface_rows else \
        "<tr><td colspan='8' class='empty'>No interface data available</td></tr>"

    # -------------------------------------------------------------------------
    # MAC / IP / Hostname table rows
    # -------------------------------------------------------------------------
    seen_macs: set = set()
    arp_rows  = []
    for if_index in sorted(interfaces.keys(), key=lambda x: int(x)):
        iface = interfaces[if_index]
        for entry in iface.get('arp', []):
            mac = entry.get('mac', '')
            if mac in seen_macs:
                continue
            seen_macs.add(mac)
            ip         = entry.get('ip', '')       or '—'
            hostname   = entry.get('hostname', '') or '—'
            port_label = f"{iface.get('descr', '')} <span class='sub'>if{if_index}</span>"
            arp_rows.append(
                f"<tr>"
                f"<td>{port_label}</td>"
                f"<td class='mono'>{mac or '—'}</td>"
                f"<td class='mono'>{ip}</td>"
                f"<td>{hostname}</td>"
                f"</tr>"
            )

    arp_table = "\n".join(arp_rows) if arp_rows else \
        "<tr><td colspan='4' class='empty'>No MAC/ARP data available</td></tr>"

    # -------------------------------------------------------------------------
    # HTML assembly
    # -------------------------------------------------------------------------
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <meta http-equiv='refresh' content='95'>
    <title>{display_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5;
                max-width: 600px; min-width: min-content; }}
        h1 {{ color: #333; margin-bottom: 4px; }}
        h2 {{ color: #555; margin-top: 32px; margin-bottom: 12px; border-bottom: 2px solid #ddd; padding-bottom: 6px; }}
        .sysinfo {{ display: flex; gap: 40px; margin-bottom: 8px; flex-wrap: wrap; }}
        .sysinfo-item {{ font-size: 14px; color: #555; }}
        .sysinfo-item span {{ font-weight: bold; color: #333; }}
        table {{ border-collapse: collapse; min-width: 100%; background: white;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 5px; overflow: hidden; }}
        th {{ background: #4a4a4a; color: white; padding: 10px 12px; text-align: left;
              font-size: 13px; font-weight: bold; white-space: nowrap; }}
        td {{ padding: 8px 12px; font-size: 13px; border-bottom: 1px solid #eee; vertical-align: top;
              white-space: nowrap; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: #f9f9f9; }}
        .mono {{ font-family: monospace; font-size: 12px; }}
        .oper-up {{ color: #2a7a2a; font-weight: bold; }}
        .oper-down {{ color: #cc0000; font-weight: bold; }}
        .oper-other {{ color: #888; }}
        .sub {{ font-size: 11px; color: #888; }}
        .proto {{ font-size: 11px; color: #fff; background: #5a7ab8; padding: 1px 5px;
                  border-radius: 3px; }}
        .empty {{ color: #aaa; font-style: italic; text-align: center; padding: 20px; }}
        .back {{ margin-bottom: 20px; font-size: 14px; }}
        .back a {{ color: #5a7ab8; text-decoration: none; }}
        .back a:hover {{ text-decoration: underline; }}
        .footer {{ margin-top: 20px; text-align: center; color: #888; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='back'><a href='index.html'>&larr; Back to monitoring index</a></div>
    <h1>{display_name}</h1>
    <div class='sysinfo'>
        <div class='sysinfo-item'>Name: <span>{sys_name}</span></div>
        <div class='sysinfo-item'>Location: <span>{sys_location}</span></div>
        <div class='sysinfo-item'>Contact: <span>{sys_contact}</span></div>
        <div class='sysinfo-item'>Address: <span>{resource['address']}</span></div>
    </div>

    <h2>Interfaces</h2>
    <table>
        <thead>
            <tr>
                <th>ifIndex</th>
                <th>Slot</th>
                <th>Name</th>
                <th>Alias / Description</th>
                <th>Speed</th>
                <th>Oper</th>
                <th>Admin</th>
                <th>Neighbour (LLDP/CDP)</th>
            </tr>
        </thead>
        <tbody>
{iface_table}
        </tbody>
    </table>

    <h2>MAC / IP / Hostname</h2>
    <table>
        <thead>
            <tr>
                <th>Port</th>
                <th>MAC Address</th>
                <th>IP Address</th>
                <th>Hostname (PTR)</th>
            </tr>
        </thead>
        <tbody>
{arp_table}
        </tbody>
    </table>

    <p class='footer'>Generated by <a href='https://github.com/CompSciFutures/APMonitor/'>APMonitor v{__version__}</a> at {generated_at} - <a href=\"https://www.paypal.com/donate/?hosted_button_id=WN472NX5XC5CJ\">Donate: Buy me a coffee with PayPal</a></p>
</body>
</html>"""

    new_path     = Path(output_path + '.new')
    old_path     = Path(output_path + '.old')
    current_path = Path(output_path)

    try:
        with open(new_path, 'w') as f:
            f.write(html)
        if current_path.exists():
            os.replace(current_path, old_path)
        os.replace(new_path, current_path)
        _set_www_data_group(str(current_path))
        if VERBOSE:
            print(f"{prefix}Generated detail page: {output_path}")
    except Exception as e:
        print(f"{prefix}Failed to generate detail page '{output_path}': {e}", file=sys.stderr)


def _set_www_data_group(path: str) -> None:
    """Set group ownership to www-data and ensure group-writable permissions.

    Non-fatal — logs warning on failure (e.g. running as non-root without www-data membership).
    Directories get 775, files get 664.
    """
    import grp
    try:
        gid = grp.getgrnam('www-data').gr_gid
        os.chown(path, -1, gid)  # -1 = leave user owner unchanged
        current_mode = os.stat(path).st_mode
        if os.path.isdir(path):
            os.chmod(path, current_mode | 0o775)
        else:
            os.chmod(path, current_mode | 0o664)
    except Exception as e:
        if VERBOSE:
            print(f"Warning: could not set www-data group on '{path}': {e}")


def generate_mrtg_config(config: Dict[str, Any], work_dir: str, mrtg_config_path: str,
                          state: Dict[str, Any]) -> None:
    """Generate MRTG configuration from APMonitor config with atomic file rotation.

    Args:
        config: APMonitor configuration dict
        work_dir: MRTG working directory (where graphs will be generated)
        mrtg_config_path: Path to MRTG config file (will use .new/.old rotation)
        state: APMonitor state dict — used to embed live disk_space_pct in host PageTop
    """
    prefix = getattr(thread_local, 'prefix', '')

    mrtg_lines = [
        "# MRTG Configuration - Generated by APMonitor",
        f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"WorkDir: {work_dir}",
        "LogFormat: rrdtool",
        "Options[_]: growright",
        "YLegend[_]: ",
        "Y2Legend[_]: ",
        "ShortLegend[_]: ",
        "WriteExpires: Yes",
        "",
    ]

    for resource in config['monitors']:
        safe_name    = re.sub(r'[^\w\-.]', '_', resource['name'])
        monitor_type = resource['type']

        if not to_natural_language_boolean(resource.get('display', True)):
            continue

        if monitor_type in ('ports', 'port', 'host'):
            rrd_path     = get_rrd_path(resource['name'], 'snmp')
            percentile   = resource.get('percentile') if monitor_type in ('ports', 'port') else None
            display_name = f"{monitor_type}: {resource['name']}"

            if monitor_type == 'host':
                disk_space_pct = state.get(resource['name'], {}).get('disk_space_pct')
                disk_space_str = f"{disk_space_pct:.1f}%" if disk_space_pct is not None else "N/A"

                # Chart 1: CPU % (left) & Context Switches/sec (right)
                mrtg_lines.extend([
                    f"######################################################################",
                    f"# {display_name} - CPU & Load",
                    f"",
                    f"Target[{safe_name}-system1]: cpu_load&context_switches:{rrd_path}",
                    f"MaxBytes1[{safe_name}-system1]: 100",
                    f"MaxBytes2[{safe_name}-system1]: 100000",
                    f"Title[{safe_name}-system1]: {display_name} - CPU & Load",
                    f"PageTop[{safe_name}-system1]: <h1>{display_name} ({resource['address']})</h1><h2>CPU Utilization & Context Switches/sec</h2>",
                    f"Options[{safe_name}-system1]: gauge,nopercent,growright,dualaxis",
                    f"YLegend[{safe_name}-system1]: CPU %",
                    f"Y2Legend[{safe_name}-system1]: ctx/s",
                    f"ShortLegend[{safe_name}-system1]: ",
                    f"Legend1[{safe_name}-system1]: CPU Utilization %",
                    f"Legend2[{safe_name}-system1]: Context Switches/sec",
                    f"LegendI[{safe_name}-system1]: CPU:",
                    f"LegendO[{safe_name}-system1]: Ctx/s:",
                    f"WithPeak[{safe_name}-system1]: dwmy",
                    f"",
                ])

                # Chart 2: Memory % (left) & Swap I/O rate (right)
                mrtg_lines.extend([
                    f"######################################################################",
                    f"# {display_name} - Memory & Paging",
                    f"",
                    f"Target[{safe_name}-system2]: memory_pct&swap_io:{rrd_path}",
                    f"MaxBytes1[{safe_name}-system2]: 100",
                    f"MaxBytes2[{safe_name}-system2]: 100000",
                    f"Title[{safe_name}-system2]: {display_name} - Memory & Paging",
                    f"PageTop[{safe_name}-system2]: <h1>{display_name} ({resource['address']})</h1><h2>Memory Utilization % & Swap I/O Rate</h2>",
                    f"Options[{safe_name}-system2]: gauge,nopercent,growright,dualaxis",
                    f"YLegend[{safe_name}-system2]: Mem %",
                    f"Y2Legend[{safe_name}-system2]: swap/s",
                    f"ShortLegend[{safe_name}-system2]: ",
                    f"Legend1[{safe_name}-system2]: Memory Utilization %",
                    f"Legend2[{safe_name}-system2]: Swap I/O Rate",
                    f"LegendI[{safe_name}-system2]: Mem:",
                    f"LegendO[{safe_name}-system2]: Swap I/O:",
                    f"WithPeak[{safe_name}-system2]: dwmy",
                    f"",
                ])

                # Chart 3: Disk read bytes/sec (left) & Disk write bytes/sec (right)
                mrtg_lines.extend([
                    f"######################################################################",
                    f"# {display_name} - Disk I/O",
                    f"",
                    f"Target[{safe_name}-system3]: disk_read&disk_write:{rrd_path}",
                    f"MaxBytes1[{safe_name}-system3]: 1000000000",
                    f"MaxBytes2[{safe_name}-system3]: 1000000000",
                    f"Title[{safe_name}-system3]: {display_name} - Disk I/O",
                    f"PageTop[{safe_name}-system3]: <h1>{display_name} ({resource['address']})</h1><h2>Disk Read/Write Throughput &mdash; Disk Use: {disk_space_str}</h2>",
                    f"Options[{safe_name}-system3]: gauge,nopercent,growright,dualaxis",
                    f"YLegend[{safe_name}-system3]: Read B/s",
                    f"Y2Legend[{safe_name}-system3]: Write B/s",
                    f"ShortLegend[{safe_name}-system3]: B/s",
                    f"Legend1[{safe_name}-system3]: Disk Read Bytes/sec",
                    f"Legend2[{safe_name}-system3]: Disk Write Bytes/sec",
                    f"LegendI[{safe_name}-system3]: Read:",
                    f"LegendO[{safe_name}-system3]: Write:",
                    f"WithPeak[{safe_name}-system3]: dwmy",
                    f"",
                ])

                # Chart 4: Swap used bytes (left) & Hardware interrupts/sec (right)
                mrtg_lines.extend([
                    f"######################################################################",
                    f"# {display_name} - System Thrashing",
                    f"",
                    f"Target[{safe_name}-system4]: swap_used&interrupts:{rrd_path}",
                    f"MaxBytes1[{safe_name}-system4]: 1000000000",
                    f"MaxBytes2[{safe_name}-system4]: 100000",
                    f"Title[{safe_name}-system4]: {display_name} - System Thrashing",
                    f"PageTop[{safe_name}-system4]: <h1>{display_name} ({resource['address']})</h1><h2>Swap Used (bytes) & Hardware Interrupts/sec</h2>",
                    f"Options[{safe_name}-system4]: gauge,nopercent,growright,dualaxis",
                    f"YLegend[{safe_name}-system4]: Swap bytes",
                    f"Y2Legend[{safe_name}-system4]: IRQ/s",
                    f"ShortLegend[{safe_name}-system4]: ",
                    f"Legend1[{safe_name}-system4]: Swap Used (bytes)",
                    f"Legend2[{safe_name}-system4]: Hardware Interrupts/sec",
                    f"LegendI[{safe_name}-system4]: Swap:",
                    f"LegendO[{safe_name}-system4]: IRQ/s:",
                    f"WithPeak[{safe_name}-system4]: dwmy",
                    f"",
                ])

            else:
                # ports and port: full bandwidth/packets/errors target set

                # Bandwidth: bits in (left) & bits out (right)
                mrtg_lines.extend([
                    f"######################################################################",
                    f"# {display_name} - Total Bandwidth",
                    f"",
                    f"Target[{safe_name}-bandwidth]: total_bits_in&total_bits_out:{rrd_path}",
                    f"MaxBytes1[{safe_name}-bandwidth]: 10000000000",
                    f"MaxBytes2[{safe_name}-bandwidth]: 10000000000",
                    f"Title[{safe_name}-bandwidth]: {display_name} - Total Bandwidth",
                    f"PageTop[{safe_name}-bandwidth]: <h1>{display_name} ({resource['address']})</h1><h2>Total Bandwidth In/Out</h2>",
                    f"Options[{safe_name}-bandwidth]: gauge,nopercent,growright,bits",
                    f"YLegend[{safe_name}-bandwidth]: Bits/s",
                    f"Y2Legend[{safe_name}-bandwidth]: Bits/s out",
                    f"ShortLegend[{safe_name}-bandwidth]: b/s",
                    f"Legend1[{safe_name}-bandwidth]: Total Inbound Traffic",
                    f"Legend2[{safe_name}-bandwidth]: Total Outbound Traffic",
                    f"LegendI[{safe_name}-bandwidth]: In:",
                    f"LegendO[{safe_name}-bandwidth]: Out:",
                    f"WithPeak[{safe_name}-bandwidth]: dwmy",
                    *([f"Percentile[{safe_name}-bandwidth]: {percentile}"] if percentile else []),
                    f"",
                ])

                # Packets: pkts in (left) & pkts out (right)
                mrtg_lines.extend([
                    f"######################################################################",
                    f"# {display_name} - Total Packets",
                    f"",
                    f"Target[{safe_name}-packets]: total_pkts_in&total_pkts_out:{rrd_path}",
                    f"MaxBytes1[{safe_name}-packets]: 10000000",
                    f"MaxBytes2[{safe_name}-packets]: 10000000",
                    f"Title[{safe_name}-packets]: {display_name} - Total Packets",
                    f"PageTop[{safe_name}-packets]: <h1>{display_name} ({resource['address']})</h1><h2>Total Packets In/Out</h2>",
                    f"Options[{safe_name}-packets]: gauge,nopercent,growright",
                    f"YLegend[{safe_name}-packets]: pps",
                    f"Y2Legend[{safe_name}-packets]: pps out",
                    f"ShortLegend[{safe_name}-packets]: pps",
                    f"Legend1[{safe_name}-packets]: Total Inbound Packets",
                    f"Legend2[{safe_name}-packets]: Total Outbound Packets",
                    f"LegendI[{safe_name}-packets]: In:",
                    f"LegendO[{safe_name}-packets]: Out:",
                    f"WithPeak[{safe_name}-packets]: dwmy",
                    *([f"Percentile[{safe_name}-packets]: {percentile}"] if percentile else []),
                    f"",
                ])

                # Packet type: unicast (left) & broadcast+multicast (right)
                mrtg_lines.extend([
                    f"######################################################################",
                    f"# {display_name} - Packet Type Split (Unicast vs Broadcast+Multicast)",
                    f"",
                    f"Target[{safe_name}-packets-type]: total_pkts_ucast&total_pkts_bmcast:{rrd_path}",
                    f"MaxBytes1[{safe_name}-packets-type]: 10000000",
                    f"MaxBytes2[{safe_name}-packets-type]: 10000000",
                    f"Title[{safe_name}-packets-type]: {display_name} - Packet Type Split",
                    f"PageTop[{safe_name}-packets-type]: <h1>{display_name} ({resource['address']})</h1><h2>Unicast vs Broadcast+Multicast Packets</h2>",
                    f"Options[{safe_name}-packets-type]: gauge,nopercent,growright",
                    f"YLegend[{safe_name}-packets-type]: pps",
                    f"Y2Legend[{safe_name}-packets-type]: B+Mcast pps",
                    f"ShortLegend[{safe_name}-packets-type]: pps",
                    f"Legend1[{safe_name}-packets-type]: Unicast Packets (in+out)",
                    f"Legend2[{safe_name}-packets-type]: Broadcast+Multicast Packets (in+out)",
                    f"LegendI[{safe_name}-packets-type]: Ucast:",
                    f"LegendO[{safe_name}-packets-type]: B+Mcast:",
                    f"WithPeak[{safe_name}-packets-type]: dwmy",
                    *([f"Percentile[{safe_name}-packets-type]: {percentile}"] if percentile else []),
                    f"",
                ])

                # Errors: errors in (left) & errors out (right)
                mrtg_lines.extend([
                    f"######################################################################",
                    f"# {display_name} - Interface Errors",
                    f"",
                    f"Target[{safe_name}-errors]: total_errors_in&total_errors_out:{rrd_path}",
                    f"MaxBytes1[{safe_name}-errors]: 1000000",
                    f"MaxBytes2[{safe_name}-errors]: 1000000",
                    f"Title[{safe_name}-errors]: {display_name} - Interface Errors",
                    f"PageTop[{safe_name}-errors]: <h1>{display_name} ({resource['address']})</h1><h2>Interface Errors In/Out</h2>",
                    f"Options[{safe_name}-errors]: gauge,nopercent,growright",
                    f"YLegend[{safe_name}-errors]: Err/s",
                    f"Y2Legend[{safe_name}-errors]: Err/s out",
                    f"ShortLegend[{safe_name}-errors]: err/s",
                    f"Legend1[{safe_name}-errors]: Inbound Interface Errors",
                    f"Legend2[{safe_name}-errors]: Outbound Interface Errors",
                    f"LegendI[{safe_name}-errors]: In Err:",
                    f"LegendO[{safe_name}-errors]: Out Err:",
                    f"WithPeak[{safe_name}-errors]: dwmy",
                    *([f"Percentile[{safe_name}-errors]: {percentile}"] if percentile else []),
                    f"",
                ])

                if monitor_type == 'ports':
                    # TCP retransmits: same DS both sides (single metric, symmetric display)
                    mrtg_lines.extend([
                        f"######################################################################",
                        f"# {display_name} - TCP Retransmits",
                        f"",
                        f"Target[{safe_name}-retransmits]: tcp_retrans&tcp_retrans:{rrd_path}",
                        f"MaxBytes1[{safe_name}-retransmits]: 100000",
                        f"MaxBytes2[{safe_name}-retransmits]: 100000",
                        f"Title[{safe_name}-retransmits]: {display_name} - TCP Retransmits",
                        f"PageTop[{safe_name}-retransmits]: <h1>{display_name} ({resource['address']})</h1><h2>TCP Retransmits</h2>",
                        f"Options[{safe_name}-retransmits]: gauge,nopercent,growright",
                        f"YLegend[{safe_name}-retransmits]: retrans/s",
                        f"Y2Legend[{safe_name}-retransmits]: retrans/s",
                        f"ShortLegend[{safe_name}-retransmits]: retrans/s",
                        f"Legend1[{safe_name}-retransmits]: TCP Retransmit Segments",
                        f"Legend2[{safe_name}-retransmits]: TCP Retransmit Segments",
                        f"LegendI[{safe_name}-retransmits]: Retrans:",
                        f"LegendO[{safe_name}-retransmits]: Retrans:",
                        f"WithPeak[{safe_name}-retransmits]: dwmy",
                        *([f"Percentile[{safe_name}-retransmits]: {percentile}"] if percentile else []),
                        f"",
                    ])

                    # System: CPU % (left) & memory % (right)
                    mrtg_lines.extend([
                        f"######################################################################",
                        f"# {display_name} - CPU & Memory Utilization",
                        f"",
                        f"Target[{safe_name}-system]: cpu_load&memory_pct:{rrd_path}",
                        f"MaxBytes1[{safe_name}-system]: 100",
                        f"MaxBytes2[{safe_name}-system]: 100",
                        f"Title[{safe_name}-system]: {display_name} - System Resources",
                        f"PageTop[{safe_name}-system]: <h1>{display_name} ({resource['address']})</h1><h2>CPU & Memory Utilization</h2>",
                        f"Options[{safe_name}-system]: gauge,nopercent,growright,dualaxis",
                        f"YLegend[{safe_name}-system]: CPU %",
                        f"Y2Legend[{safe_name}-system]: Mem %",
                        f"ShortLegend[{safe_name}-system]: %",
                        f"Legend1[{safe_name}-system]: CPU Load Average",
                        f"Legend2[{safe_name}-system]: Memory Utilization",
                        f"LegendI[{safe_name}-system]: CPU:",
                        f"LegendO[{safe_name}-system]: Memory:",
                        f"WithPeak[{safe_name}-system]: dwmy",
                        *([f"Percentile[{safe_name}-system]: {percentile}"] if percentile else []),
                        f"",
                    ])

                    # Tamper: active port count (left) & NVRAM/flash bytes (right)
                    mrtg_lines.extend([
                        f"######################################################################",
                        f"# {display_name} - Tamper Detection",
                        f"",
                        f"Target[{safe_name}-tamper]: ports_up_count&nvram_flash_bytes:{rrd_path}",
                        f"MaxBytes1[{safe_name}-tamper]: 1000",
                        f"MaxBytes2[{safe_name}-tamper]: 1000000000",
                        f"Title[{safe_name}-tamper]: {display_name} - Tamper Detection",
                        f"PageTop[{safe_name}-tamper]: <h1>{display_name} ({resource['address']})</h1><h2>Active Ports & NVRAM/Flash Used Bytes</h2>",
                        f"Options[{safe_name}-tamper]: gauge,nopercent,growright,dualaxis",
                        f"YLegend[{safe_name}-tamper]: Ports up",
                        f"Y2Legend[{safe_name}-tamper]: NVRAM/Flash B",
                        f"ShortLegend[{safe_name}-tamper]: ",
                        f"Legend1[{safe_name}-tamper]: Active (oper=up) Port Count",
                        f"Legend2[{safe_name}-tamper]: NVRAM + Flash Used Bytes",
                        f"LegendI[{safe_name}-tamper]: Ports Up:",
                        f"LegendO[{safe_name}-tamper]: NVRAM/Flash:",
                        f"WithPeak[{safe_name}-tamper]: dwmy",
                        *([f"Percentile[{safe_name}-tamper]: {percentile}"] if percentile else []),
                        f"",
                    ])

                    # Network: MAC count (left) & ARP count (right)
                    mrtg_lines.extend([
                        f"######################################################################",
                        f"# {display_name} - Network Provisioning",
                        f"",
                        f"Target[{safe_name}-network]: mac_count&arp_count:{rrd_path}",
                        f"MaxBytes1[{safe_name}-network]: 100000",
                        f"MaxBytes2[{safe_name}-network]: 100000",
                        f"Title[{safe_name}-network]: {display_name} - Network Provisioning",
                        f"PageTop[{safe_name}-network]: <h1>{display_name} ({resource['address']})</h1><h2>Learned MAC Count &amp; ARP Table Entries</h2>",
                        f"Options[{safe_name}-network]: gauge,nopercent,growright,dualaxis",
                        f"YLegend[{safe_name}-network]: MACs",
                        f"Y2Legend[{safe_name}-network]: ARP entries",
                        f"ShortLegend[{safe_name}-network]: entries",
                        f"Legend1[{safe_name}-network]: Learned MAC Table Entries",
                        f"Legend2[{safe_name}-network]: ARP Table Entries",
                        f"LegendI[{safe_name}-network]: MACs:",
                        f"LegendO[{safe_name}-network]: ARP:",
                        f"WithPeak[{safe_name}-network]: dwmy",
                        *([f"Percentile[{safe_name}-network]: {percentile}"] if percentile else []),
                        f"",
                    ])

        else:
            # Non-SNMP monitors (ping, http, quic, tcp, udp) — availability tracking
            rrd_path = get_rrd_path(resource['name'], 'availability')

            mrtg_lines.extend([
                f"######################################################################",
                f"# {resource['name']} ({resource['type']})",
                f"",
                f"Target[{safe_name}]: response_time&is_up:{rrd_path}",
                f"MaxBytes1[{safe_name}]: 100000",
                f"MaxBytes2[{safe_name}]: 100",
                f"Title[{safe_name}]: {resource['name']} - Availability",
                f"PageTop[{safe_name}]: <h1>{resource['name']} ({resource['address']})</h1>",
                f"Options[{safe_name}]: gauge,nopercent,growright,dualaxis",
                f"YLegend[{safe_name}]: Response Time (ms)",
                f"Y2Legend[{safe_name}]: Availability (%)",
                f"ShortLegend[{safe_name}]:",
                f"Legend1[{safe_name}]: Response Time (ms)",
                f"Legend2[{safe_name}]: Availability (%)",
                f"LegendI[{safe_name}]: Response:",
                f"LegendO[{safe_name}]: Avail:",
                f"WithPeak[{safe_name}]: dwmy",
                f"",
            ])

    config_content = "\n".join(mrtg_lines)

    new_path    = Path(mrtg_config_path + '.new')
    old_path    = Path(mrtg_config_path + '.old')
    config_path = Path(mrtg_config_path)

    try:
        with open(new_path, 'w') as f:
            f.write(config_content)
        if config_path.exists():
            os.replace(config_path, old_path)
        os.replace(new_path, config_path)
        _set_www_data_group(str(config_path))
        if VERBOSE:
            print(f"{prefix}Generated MRTG config: {mrtg_config_path}")
    except Exception as e:
        print(f"{prefix}Failed to generate MRTG config '{mrtg_config_path}': {e}", file=sys.stderr)


def generate_mrtg_index(config: Dict[str, Any], index_path: str, state: Dict[str, Any] = None) -> None:
    """Generate index.html driven directly from APMonitor config and STATE.

    L2/L3 Network Monitoring section: ports, port, host monitors.
    L4 Availability Monitoring section: ping, http, quic, tcp, udp monitors.
    Hidden monitors (display=false) appear in audit footer only.

    Args:
        config:     APMonitor configuration dict
        index_path: Full path to index.html (atomic .new/.old rotation)
        state:      APMonitor state dict for outage highlighting
    """
    prefix    = getattr(thread_local, 'prefix', '')
    site_name = config['site']['name']
    monitors  = config['monitors']

    world_clocks = [
        ('Honolulu',    'Pacific/Honolulu'),
        ('Anchorage',   'America/Anchorage'),
        ('California',  'America/Los_Angeles'),
        ('New York',    'America/New_York'),
        ('London',      'Europe/London'),
        ('Amsterdam',   'Europe/Amsterdam'),
        ('Mumbai',      'Asia/Kolkata'),
        ('Tokyo',       'Asia/Tokyo'),
        ('Melbourne',   'Australia/Melbourne'),
    ]

    try:
        from zoneinfo import ZoneInfo
        def _fmt_tz(tz_name: str, fmt: str) -> str:
            return datetime.now(ZoneInfo(tz_name)).strftime(fmt).lstrip('0') or '12'
    except ImportError:
        def _fmt_tz(tz_name: str, fmt: str) -> str:
            return datetime.utcnow().strftime(fmt).lstrip('0') or '12'

    local_time_str    = _fmt_tz('Australia/Melbourne', '%a %I:%M %p')
    world_clock_parts = ' &nbsp;&nbsp; '.join(
        f"{city}: <b>{_fmt_tz(tz, '%I:%M %p')}</b>"
        for city, tz in world_clocks
    )

    html_lines = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "    <meta charset='UTF-8'>",
        "    <meta http-equiv='refresh' content='95'>",
        f"    <title>{site_name}</title>",
        "    <style>",
        "        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; position: relative; }",
        "        h1 { color: #333; margin-bottom: 10px; }",
        "        h2 { color: #555; margin-top: 40px; margin-bottom: 20px; border-bottom: 2px solid #ddd; padding-bottom: 10px; }",
        "        .grid { display: grid; grid-template-columns: repeat(8, 1fr); gap: 20px; }",
        "        .monitor { background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }",
        "        .monitor.down { background: #ffe8e8; }",
        "        .monitor h3 { margin-top: 0; font-size: 18px; color: #555; }",
        "        .monitor a { text-decoration: none; color: inherit; }",
        "        .monitor a:hover { text-decoration: underline; }",
        "        .monitor img { max-width: 100%; height: auto; }",
        "        .network-host-label { font-size: 16px; font-weight: bold; color: #333; margin-bottom: 10px; padding: 6px 10px; border-radius: 4px; display: inline-block; }",
        "        .network-host-label.down { background: #ffe8e8; color: #cc0000; }",
        "        .network-host-label a { text-decoration: none; color: inherit; }",
        "        .network-host-label a:hover { text-decoration: underline; }",
        "        .network-row { display: grid; gap: 20px; margin-bottom: 20px; }",
        "        .network-cell { background: white; padding: 8px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }",
        "        .network-cell.down { background: #ffe8e8; }",
        "        .network-cell h4 { margin-top: 0; margin-bottom: 4px; font-size: 11px; color: #666; text-align: center; }",
        "        .network-cell a { display: block; text-align: center; }",
        "        .network-cell img { max-width: 100%; height: auto; max-height: 80px; }",
        "        .port-label-row { display: grid; gap: 20px; margin-bottom: 4px; }",
        "        .port-label-cell { display: flex; align-items: flex-end; }",
        "        .port-label-spacer { visibility: hidden; }",
        "        .header-clock { position: absolute; top: 0; right: 0; text-align: right; padding: 6px 12px; }",
        "        .header-clock-main { font-size: 36px; font-weight: bold; color: #333; }",
        "        .header-clock-world { font-size: 20px; color: #999; margin-top: 4px; }",
        "        .nothing-configured { color: #aaa; font-style: italic; margin: 10px 0 30px 0; }",
        "        @media (max-width: 1400px) { ",
        "            .grid { grid-template-columns: repeat(4, 1fr); }",
        "            .network-row { grid-template-columns: repeat(var(--cols-narrow, 2), 1fr); }",
        "            .port-label-row { grid-template-columns: repeat(var(--cols-narrow, 2), 1fr) !important; }",
        "        }",
        "        @media (max-width: 768px) { ",
        "            .grid { grid-template-columns: 1fr; }",
        "            .network-row { grid-template-columns: 1fr; }",
        "            .port-label-row { grid-template-columns: 1fr !important; }",
        "        }",
        "    </style>",
        "</head>",
        "<body>",
        "    <div class='header-clock'>",
        f"        <div class='header-clock-main'>{local_time_str}</div>",
        f"        <div class='header-clock-world'>{world_clock_parts}</div>",
        "    </div>",
        f"    <h1>{site_name}</h1>",
    ]

    def _detail_href(monitor_type: str, safe_name: str) -> str:
        return f"{monitor_type}-{safe_name}-detail.html"

    def _emit_snmp_row(resource: Dict[str, Any]) -> None:
        """Emit one ports monitor row (label + full-width network-row grid)."""
        safe_name    = re.sub(r'[^\w\-.]', '_', resource['name'])
        display_name = f"ports: {resource['name']}"
        monitor_state = state.get(resource['name'], {}) if state else {}
        is_down      = not monitor_state.get('is_up', True)
        label_class  = "network-host-label down" if is_down else "network-host-label"
        cell_class   = "network-cell down" if is_down else "network-cell"
        outage_str   = f" &nbsp;<span style='font-weight: normal; font-size: 13px;'>Down {format_time_ago(monitor_state.get('last_alarm_started'))}</span>" if is_down else ""
        detail_href  = _detail_href('ports', safe_name)

        col_style = "repeat(8, 1fr); --cols-narrow: 3"

        html_lines.extend([
            f"    <div class='{label_class}'><a href='{detail_href}'>{display_name}</a>{outage_str}</div>",
            f"    <div class='network-row' style='grid-template-columns: {col_style};'>",
            f"        <div class='{cell_class}'>",
            "            <h4>Total Bandwidth In/Out</h4>",
            f"            <a href='/mrtg-rrd/{safe_name}-bandwidth.html'>",
            f"                <img src='/mrtg-rrd/{safe_name}-bandwidth-day.png' alt='{display_name} Bandwidth'>",
            "            </a>",
            "        </div>",
            f"        <div class='{cell_class}'>",
            "            <h4>Total Packets In/Out</h4>",
            f"            <a href='/mrtg-rrd/{safe_name}-packets.html'>",
            f"                <img src='/mrtg-rrd/{safe_name}-packets-day.png' alt='{display_name} Packets'>",
            "            </a>",
            "        </div>",
            f"        <div class='{cell_class}'>",
            "            <h4>Unicast vs B+Mcast Packets</h4>",
            f"            <a href='/mrtg-rrd/{safe_name}-packets-type.html'>",
            f"                <img src='/mrtg-rrd/{safe_name}-packets-type-day.png' alt='{display_name} Packet Types'>",
            "            </a>",
            "        </div>",
            f"        <div class='{cell_class}'>",
            "            <h4>Interface Errors In/Out</h4>",
            f"            <a href='/mrtg-rrd/{safe_name}-errors.html'>",
            f"                <img src='/mrtg-rrd/{safe_name}-errors-day.png' alt='{display_name} Errors'>",
            "            </a>",
            "        </div>",
            f"        <div class='{cell_class}'>",
            "            <h4>TCP Retransmits</h4>",
            f"            <a href='/mrtg-rrd/{safe_name}-retransmits.html'>",
            f"                <img src='/mrtg-rrd/{safe_name}-retransmits-day.png' alt='{display_name} TCP Retransmits'>",
            "            </a>",
            "        </div>",
            f"        <div class='{cell_class}'>",
            "            <h4>CPU & Memory</h4>",
            f"            <a href='/mrtg-rrd/{safe_name}-system.html'>",
            f"                <img src='/mrtg-rrd/{safe_name}-system-day.png' alt='{display_name} System'>",
            "            </a>",
            "        </div>",
            f"        <div class='{cell_class}'>",
            "            <h4>Active Ports & NVRAM/Flash</h4>",
            f"            <a href='/mrtg-rrd/{safe_name}-tamper.html'>",
            f"                <img src='/mrtg-rrd/{safe_name}-tamper-day.png' alt='{display_name} Tamper'>",
            "            </a>",
            "        </div>",
            f"        <div class='{cell_class}'>",
            "            <h4>MACs & ARP Entries</h4>",
            f"            <a href='/mrtg-rrd/{safe_name}-network.html'>",
            f"                <img src='/mrtg-rrd/{safe_name}-network-day.png' alt='{display_name} Network'>",
            "            </a>",
            "        </div>",
            "    </div>",
        ])

    def _emit_port_host_group(run: List[Tuple[str, str, Dict[str, Any]]]) -> None:
        """Emit a contiguous run of port/host monitors as a single grid (8-up or 4-up).

        run: list of (safe_name, monitor_type, resource) tuples
        """
        col_count  = 8 if len(run) >= 2 else 4
        col_narrow = min(col_count, 4)
        col_style  = f"repeat({col_count}, 1fr); --cols-narrow: {col_narrow}"

        port_targets = [
            ('-bandwidth',    'Bandwidth In/Out'),
            ('-packets',      'Packets In/Out'),
            ('-packets-type', 'Unicast vs B+Mcast'),
            ('-errors',       'Errors In/Out'),
        ]

        # --- label row ---
        html_lines.append(f"    <div class='port-label-row' style='grid-template-columns: {col_style};'>")
        for safe_name, monitor_type, resource in run:
            display_name  = f"{monitor_type}: {resource['name']}"
            monitor_state = state.get(resource['name'], {}) if state else {}
            is_down       = not monitor_state.get('is_up', True)
            label_class   = "network-host-label down" if is_down else "network-host-label"
            outage_str    = f" &nbsp;<span style='font-weight: normal; font-size: 13px;'>Down {format_time_ago(monitor_state.get('last_alarm_started'))}</span>" if is_down else ""
            detail_href   = _detail_href(monitor_type, safe_name)
            html_lines.append(
                f"        <div class='port-label-cell'>"
                f"<span class='{label_class}'>"
                f"<a href='{detail_href}'>{display_name}</a>"
                f"{outage_str}</span></div>"
            )
            for _ in range(3):
                html_lines.append("        <div class='port-label-cell port-label-spacer'></div>")
        html_lines.append("    </div>")

        # --- chart row ---
        html_lines.append(f"    <div class='network-row' style='grid-template-columns: {col_style};'>")
        for safe_name, monitor_type, resource in run:
            display_name  = f"{monitor_type}: {resource['name']}"
            monitor_state = state.get(resource['name'], {}) if state else {}
            is_down       = not monitor_state.get('is_up', True)
            cell_class    = "network-cell down" if is_down else "network-cell"

            if monitor_type == 'host':
                disk_space_pct = monitor_state.get('disk_space_pct')
                disk_space_str = f"{disk_space_pct:.1f}%" if disk_space_pct is not None else "N/A"
                targets = [
                    ('-system1', 'CPU & Load'),
                    ('-system2', 'Memory & Paging'),
                    ('-system3', f'Disk I/O &mdash; Disk Use: {disk_space_str}'),
                    ('-system4', 'System Thrashing'),
                ]
            else:
                targets = port_targets

            for suffix, heading in targets:
                html_lines.extend([
                    f"        <div class='{cell_class}'>",
                    f"            <h4>{heading}</h4>",
                    f"            <a href='/mrtg-rrd/{safe_name}{suffix}.html'>",
                    f"                <img src='/mrtg-rrd/{safe_name}{suffix}-day.png' alt='{display_name} {heading}'>",
                    "            </a>",
                    "        </div>",
                ])
        html_lines.append("    </div>")

    # Partition monitors into displayed/hidden, preserving config file order
    displayed  = [r for r in monitors if     to_natural_language_boolean(r.get('display', True))]
    hidden     = [r for r in monitors if not to_natural_language_boolean(r.get('display', True))]

    snmp_types  = ('ports', 'port', 'host')
    avail_types = ('ping', 'http', 'quic', 'tcp', 'udp')

    has_snmp  = any(r['type'] in snmp_types  for r in displayed)
    has_avail = any(r['type'] in avail_types for r in displayed)

    # --- L2/L3 Network Monitoring section ---
    if has_snmp:
        html_lines.append("    <h2>L2/L3 Network Monitoring</h2>")
        port_host_run: List[Tuple[str, str, Dict[str, Any]]] = []

        for resource in displayed:
            if resource['type'] not in snmp_types:
                continue
            safe_name = re.sub(r'[^\w\-.]', '_', resource['name'])
            monitor_type = resource['type']

            if monitor_type == 'ports':
                if port_host_run:
                    _emit_port_host_group(port_host_run)
                    port_host_run = []
                _emit_snmp_row(resource)
            else:
                port_host_run.append((safe_name, monitor_type, resource))

        if port_host_run:
            _emit_port_host_group(port_host_run)

    # --- Nothing configured at all ---
    if not has_snmp and not has_avail:
        html_lines.append("    <p class='nothing-configured'>No monitors configured.</p>")

    # --- L4 Availability Monitoring section ---
    if has_avail:
        html_lines.append("    <h2>L4 Availability Monitoring</h2>")
        html_lines.append("    <div class='grid'>")
        for resource in displayed:
            if resource['type'] not in avail_types:
                continue
            safe_name = re.sub(r'[^\w\-.]', '_', resource['name'])
            monitor_state = state.get(resource['name'], {}) if state else {}
            is_down = not monitor_state.get('is_up', True)
            div_class = "monitor down" if is_down else "monitor"
            outage_str = f"<span style='color: #cc0000; font-weight: bold;'>Down {format_time_ago(monitor_state.get('last_alarm_started'))}</span>" if is_down else ""

            html_lines.extend([
                f"        <div class='{div_class}'>",
                f"            <h3><a href='/mrtg-rrd/{safe_name}.html'>{resource['name']}</a></h3>",
                f"            <a href='/mrtg-rrd/{safe_name}.html'>",
                f"                <img src='/mrtg-rrd/{safe_name}-day.png' alt='{resource['name']} Daily Graph'>",
                "            </a>",
                f"            <p style='font-size: 12px; color: #666;'>{resource['address']}{(' &nbsp;' + outage_str) if is_down else ''}</p>",
                "        </div>",
            ])
        html_lines.append("    </div>")

    # --- Hidden monitors audit footer ---
    if hidden:
        hidden_parts = []
        for r in hidden:
            monitor_state = state.get(r['name'], {}) if state else {}
            is_down       = not monitor_state.get('is_up', True)
            if is_down:
                outage_str = f" (down {format_time_ago(monitor_state.get('last_alarm_started'))})"
                hidden_parts.append(f"<span style='color: #cc0000;'>{r['name']}{outage_str}</span>")
            else:
                hidden_parts.append(f"<span style='color: #aaa;'>{r['name']}</span>")
        html_lines.append(
            f"    <p style='margin-top: 20px; text-align: center; color: #333; font-size: 14px; font-weight: bold;'>"
            f"Not displayed: {', '.join(hidden_parts)}</p>"
        )

    html_lines.extend([
        f"    <p style='margin-top: 10px; text-align: center; color: #888; font-size: 12px;'>Generated by <a href='https://github.com/CompSciFutures/APMonitor/'>APMonitor v{__version__}</a> at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - <a href=\"https://www.paypal.com/donate/?hosted_button_id=WN472NX5XC5CJ\">Donate: Buy me a coffee with PayPal</a></p>",
        "</body>",
        "</html>",
    ])

    html_content = '\n'.join(html_lines)

    new_path     = Path(index_path + '.new')
    old_path     = Path(index_path + '.old')
    current_path = Path(index_path)

    try:
        with open(new_path, 'w') as f:
            f.write(html_content)
        if current_path.exists():
            os.replace(current_path, old_path)
        os.replace(new_path, current_path)
        _set_www_data_group(str(current_path))

        if VERBOSE:
            snmp_count   = sum(1 for r in displayed if r['type'] == 'ports')
            port_count   = sum(1 for r in displayed if r['type'] == 'port')
            host_count   = sum(1 for r in displayed if r['type'] == 'host')
            avail_count  = sum(1 for r in displayed if r['type'] in avail_types)
            hidden_count = len(hidden)
            print(f"{prefix}Generated MRTG master index: {index_path} ({snmp_count} SNMP hosts, {port_count} port monitors, {host_count} host monitors, {avail_count} availability monitors, {hidden_count} hidden)")

    except Exception as e:
        print(f"{prefix}Failed to generate MRTG master index '{index_path}': {e}", file=sys.stderr)


def update_mrtg_rrd_cgi_config(work_dir: str, mrtg_config_path: str, site_name: str) -> None:
    """Update mrtg-rrd.cgi.pl %site_config hash with site_name -> mrtg_config_path mapping.

    Uses a PID lockfile in tempdir to serialise concurrent subprocess access.
    Spinlocks until the incumbent process releases the lock (PID gone), then proceeds.

    Args:
        work_dir:         Base MRTG working directory — mrtg-rrd.cgi.pl is one level up
        mrtg_config_path: Full path to the MRTG config file to add
        site_name:        Sanitised site name to use as hash key
    """
    prefix   = getattr(thread_local, 'prefix', '')
    cgi_path = Path(work_dir).parent / 'mrtg-rrd.cgi.pl'
    new_path = Path(str(cgi_path) + '.new')
    old_path = Path(str(cgi_path) + '.old')
    lck_path = Path(tempfile.gettempdir()) / 'apmonitor-cgi-update.lock'

    if not cgi_path.exists():
        if VERBOSE:
            print(f"{prefix}Warning: mrtg-rrd.cgi.pl not found at {cgi_path}, skipping config update")
        return

    # --- PID spinlock ---
    my_pid = os.getpid()
    while True:
        try:
            with open(lck_path, 'r') as f:
                incumbent_pid = int(f.read().strip())
            if incumbent_pid == my_pid:
                break  # We already hold the lock
            try:
                os.kill(incumbent_pid, 0)
                # Still alive — wait and retry
                time.sleep(0.1)
                continue
            except OSError:
                pass  # Incumbent gone — stale lock, take it
        except (FileNotFoundError, ValueError):
            pass  # No lock file or unreadable — proceed to acquire

        # Acquire the lock
        try:
            with open(lck_path, 'w') as f:
                f.write(str(my_pid))
            # Verify we won the race
            with open(lck_path, 'r') as f:
                if int(f.read().strip()) == my_pid:
                    break  # Lock acquired
        except Exception:
            time.sleep(0.1)
            continue

    try:
        with open(cgi_path, 'r') as f:
            content = f.read()

        pattern = r'(BEGIN\s*\{\s*%site_config\s*=\s*\()([^)]*)\)'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            print(f"{prefix}Warning: Could not find %site_config declaration in {cgi_path}", file=sys.stderr)
            return

        entries: Dict[str, str] = {}
        for line in match.group(2).splitlines():
            line = line.strip().rstrip(',')
            m = re.match(r"'([^']+)'\s*=>\s*'([^']+)'", line)
            if m:
                entries[m.group(1)] = m.group(2)

        entries[site_name] = mrtg_config_path

        new_body = '\n' + ''.join(
            f"        '{k}' => '{v}',\n"
            for k, v in sorted(entries.items())
        ) + '    '

        new_content = re.sub(
            pattern,
            lambda m: m.group(1) + new_body + ')',
            content,
            flags=re.DOTALL
        )

        with open(new_path, 'w') as f:
            f.write(new_content)

        if cgi_path.exists():
            os.replace(cgi_path, old_path)
        os.replace(new_path, cgi_path)

        os.chmod(cgi_path, 0o755)

        if VERBOSE:
            print(f"{prefix}Updated mrtg-rrd.cgi.pl site_config: {site_name} -> {mrtg_config_path}")

    except Exception as e:
        print(f"{prefix}Failed to update mrtg-rrd.cgi.pl config: {e}", file=sys.stderr)

    finally:
        # Release lock
        try:
            with open(lck_path, 'r') as f:
                if int(f.read().strip()) == my_pid:
                    os.remove(lck_path)
        except Exception:
            pass


def get_config_previous_path(config_path: str) -> str:
    """Return path to cached previous config file for change detection.

    Args:
        config_path: Path to the config file being monitored

    Returns:
        str: Full path to .previous file under /var/tmp/APMonitor/
    """
    config_filename = Path(config_path).name  # preserve full filename, not just stem
    state_dir       = Path(get_default_statefile(config_path)).parent
    return str(state_dir / f"{config_filename}.previous")


def check_config_changed_and_notify(config_path: str, config: Dict[str, Any]) -> None:
    """Compare current config file bytes against cached previous copy.

    On first run or any change: saves current bytes to .previous and fires
    a one-shot notification via outage_emails/outage_webhooks.
    No throttling, no recovery, no state tracking — pure one-shot.
    Respects site-level alarms flag.

    Args:
        config_path: Path to the config file that was loaded
        config:      Parsed config dict (used for site name and notification targets)
    """
    prefix         = getattr(thread_local, 'prefix', '')
    site_name      = config['site']['name']
    alarms_enabled = to_natural_language_boolean(config['site'].get('alarms', True))
    previous_path  = get_config_previous_path(config_path)

    # Read current raw bytes
    try:
        with open(config_path, 'rb') as f:
            current_bytes = f.read()
    except Exception as e:
        print(f"{prefix}Config change check FAILED: could not read '{config_path}': {e}", file=sys.stderr)
        return

    # Read previous bytes if exists
    previous_bytes = None
    if os.path.exists(previous_path):
        try:
            with open(previous_path, 'rb') as f:
                previous_bytes = f.read()
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}Config change check: could not read previous '{previous_path}': {e}")

    # No change
    if previous_bytes is not None and current_bytes == previous_bytes:
        if VERBOSE:
            print(f"{prefix}Config unchanged: {config_path}")
        return

    # Save current as new previous (before notifying — idempotent on repeated runs)
    try:
        with open(previous_path, 'wb') as f:
            f.write(current_bytes)
    except Exception as e:
        print(f"{prefix}Config change check: could not write '{previous_path}': {e}", file=sys.stderr)

    # First run — no previous to diff against, silent save
    if previous_bytes is None:
        if VERBOSE:
            print(f"{prefix}Config baseline saved: {config_path}")
        return

    # Build unified diff
    previous_lines = previous_bytes.decode('utf-8', errors='replace').splitlines(keepends=True)
    current_lines  = current_bytes.decode('utf-8', errors='replace').splitlines(keepends=True)
    diff_lines     = list(difflib.unified_diff(
        previous_lines, current_lines,
        fromfile=f"{config_path} (previous)",
        tofile=f"{config_path} (current)",
        lineterm='',
    ))
    diff_text = ''.join(diff_lines) if diff_lines else "(no textual diff — binary change?)"

    timestamp_str = datetime.now().strftime('%I:%M %p %Z').lstrip('0').strip()
    message = (
        f"Config file changed: {config_path} in {site_name} at {timestamp_str}\n\n"
        f"{diff_text}"
    )

    print(f"{prefix}##### CONFIG CHANGE: {config_path} #####", file=sys.stderr)
    if VERBOSE:
        print(f"{prefix}{diff_text}")

    if not alarms_enabled:
        return

    if 'outage_emails' in config['site']:
        for email_entry in config['site']['outage_emails']:
            notify_resource_outage_with_email(
                email_entry, site_name, message, config['site'], 'outage')

    if 'outage_webhooks' in config['site']:
        for webhook in config['site']['outage_webhooks']:
            notify_resource_outage_with_webhook(webhook, site_name, message)

def main() -> None:
    global VERBOSE, MAX_THREADS, STATEFILE, STATE, MAX_RETRIES, MAX_TRY_SECS, DEFAULT_CHECK_EVERY_N_SECS, DEFAULT_NOTIFY_EVERY_N_SECS, DEFAULT_AFTER_EVERY_N_NOTIFICATIONS, RRD_ENABLED

    parser = argparse.ArgumentParser(description='Network resource availability monitor')
    parser.add_argument('config', nargs='+', metavar='config',
                        help='Path to one or more configuration files (JSON or YAML)')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity (can be repeated: -v, -vv, -vvv)')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of concurrent threads (default: 1)')
    parser.add_argument('-s', '--statefile', default=None, help='Path to state file (only valid with a single config file)')
    parser.add_argument('--test-webhooks', action='store_true', help='Test webhook notifications and exit')
    parser.add_argument('--test-emails', action='store_true', help='Test email notifications and exit')
    parser.add_argument('--test-config', action='store_true', help='Validate configuration and print summary, then exit')
    parser.add_argument('--generate-rrds', action='store_true', help='Enable RRD database creation and updates')
    parser.add_argument('--generate-mrtg-config', metavar='WORKDIR', nargs='?', const='/var/www/html/mrtg', help='Generate MRTG config file and exit (default workdir: /var/www/html/mrtg)')
    args = parser.parse_args()

    configs = args.config

    print(f"-    - --=[ {__app_name__} v{__version__} ]=--- -     -")

    # -s is only valid with a single config
    if args.statefile and len(configs) > 1:
        parser.error("-s/--statefile is not valid when multiple config files are specified")

    # Multi-config: spawn one subprocess per config, join all, exit with worst exit code
    if len(configs) > 1:
        passthrough = []
        if args.verbose:
            passthrough.append('-' + 'v' * args.verbose)
        if args.threads != 1:
            passthrough.extend(['-t', str(args.threads)])
        if args.test_webhooks:
            passthrough.append('--test-webhooks')
        if args.test_emails:
            passthrough.append('--test-emails')
        if args.test_config:
            passthrough.append('--test-config')
        if args.generate_rrds:
            passthrough.append('--generate-rrds')
        if args.generate_mrtg_config is not None:
            if args.generate_mrtg_config == '/var/www/html/mrtg':
                passthrough.append('--generate-mrtg-config')
            else:
                passthrough.extend(['--generate-mrtg-config', args.generate_mrtg_config])

        processes = []
        for config_path in configs:
            cmd = [sys.executable, os.path.abspath(__file__), config_path] + passthrough
            if args.verbose:
                print(f"Spawning: {' '.join(cmd)}")
            processes.append(subprocess.Popen(cmd))

        exit_code = 0
        for i, p in enumerate(processes):
            remaining = len(processes) - i
            print(f"Waiting on {remaining} process{'es' if remaining != 1 else ''} (PID {p.pid})")
            p.wait()
            print(f"PID {p.pid} exited (rc={p.returncode}), {remaining - 1} remaining")
            if p.returncode != 0:
                exit_code = p.returncode

        sys.exit(exit_code)

    print(f"Spawned: {' '.join(sys.argv)}")

    # Single config — proceed as before
    args.config = configs[0]

    if args.statefile is None:
        args.statefile = get_default_statefile(args.config)

    VERBOSE = args.verbose
    MAX_THREADS = args.threads
    STATEFILE = args.statefile

    if MAX_THREADS < 1:
        print("Error: threads must be a positive integer greater than 0", file=sys.stderr)
        sys.exit(1)

    # Acquire PID lock (Unix-like systems only)
    lockfile_path = create_pid_file_or_exit_on_unix(args.config)
    thread_local.prefix = prefix_logline(args.config, "ALL")

    try:
        # load & parse YAML/JSON config
        config = load_config(args.config)
        if VERBOSE > 2:
            print(json.dumps(config, indent=2))

        print_and_exit_on_bad_config(config)
        if not args.test_config:
            check_config_changed_and_notify(args.config, config)

        # Test mode for config validation
        if args.test_config:
            print(f"Configuration OK: {args.config}")
            print(f"Site: {config['site']['name']}")
            print(f"Monitors ({len(config['monitors'])}):")
            for r in config['monitors']:
                display = '' if to_natural_language_boolean(r.get('display', True)) else ' [hidden]'
                print(f"  {r['type']:8s}  {r['name']:40s}  {r['address']}{display}")
            sys.exit(0)

        # Test mode for webhooks
        if args.test_webhooks:
            if 'outage_webhooks' not in config['site']:
                print("Error: No outage_webhooks configured in site config", file=sys.stderr)
                sys.exit(1)

            test_error = "TEST: test_monitor is down: connection timeout (192.168.1.999)"
            print("Testing webhook notifications...")
            for webhook in config['site']['outage_webhooks']:
                notify_resource_outage_with_webhook(webhook, config['site']['name'], test_error)
            print("Webhook test complete")
            sys.exit(0)

        # Test mode for emails
        if args.test_emails:
            if 'outage_emails' not in config['site']:
                print("Error: No outage_emails configured in site config", file=sys.stderr)
                sys.exit(1)
            if 'email_server' not in config['site']:
                print("Error: No email_server configured in site config", file=sys.stderr)
                sys.exit(1)

            test_error = "TEST: test_monitor is down: connection timeout (192.168.1.999)"
            print("Testing email notifications...")
            for email_entry in config['site']['outage_emails']:
                notify_resource_outage_with_email(email_entry, config['site']['name'], test_error, config['site'], 'outage')
            print("Email test complete")
            sys.exit(0)

        # Load previous state
        STATE = load_state(STATEFILE)

        # Hoisted so the finally block can always reference them regardless of code path
        mrtg_index_elapsed_ms: int = 0
        detail_elapsed_ms: int     = 0
        work_dir: str              = ''

        # Generate MRTG config mode
        if args.generate_mrtg_config is not None:
            base_work_dir    = args.generate_mrtg_config
            site_name        = config['site']['name']
            safe_site_name   = re.sub(r'[^\w\-.]', '_', site_name)
            work_dir         = str(Path(base_work_dir) / safe_site_name)
            mrtg_config_path = str(Path(STATEFILE).with_suffix('.mrtg.cfg'))
            os.makedirs(work_dir, exist_ok=True)
            _set_www_data_group(work_dir)

            mrtg_start_ms = int(datetime.now().timestamp() * 1000)

            generate_mrtg_config(config, work_dir, mrtg_config_path, STATE)
            print(f"DEBUG: calling update_mrtg_rrd_cgi_config({base_work_dir!r}, {mrtg_config_path!r}, {safe_site_name!r})", file=sys.stderr)
            update_mrtg_rrd_cgi_config(base_work_dir, mrtg_config_path, safe_site_name)

            # Generate master index into site subdirectory
            master_index_path = str(Path(work_dir) / 'index.html')
            generate_mrtg_index(config, master_index_path, STATE)

            mrtg_index_elapsed_ms = int(datetime.now().timestamp() * 1000) - mrtg_start_ms

            print(f"MRTG config generated at: {mrtg_config_path}")
            print(f"MRTG master index generated at: {master_index_path}")
            print(f"MRTG working directory: {work_dir}")
            RRD_ENABLED = True

        # Enable RRD if requested
        if args.generate_rrds:
            RRD_ENABLED = True

        if args.threads == 1 and 'max_threads' in config['site']:  # only if not overridden by command line
            MAX_THREADS = config['site']['max_threads']
        if 'max_retries' in config['site']:
            MAX_RETRIES = config['site']['max_retries']
        if 'max_try_secs' in config['site']:
            MAX_TRY_SECS = config['site']['max_try_secs']
        if 'check_every_n_secs' in config['site']:
            DEFAULT_CHECK_EVERY_N_SECS = config['site']['check_every_n_secs']
        if 'notify_every_n_secs' in config['site']:
            DEFAULT_NOTIFY_EVERY_N_SECS = config['site']['notify_every_n_secs']
        if 'after_every_n_notifications' in config['site']:
            DEFAULT_AFTER_EVERY_N_NOTIFICATIONS = config['site']['after_every_n_notifications']

        if VERBOSE and STATE:
            last_execution_time = STATE.get('execution_time')
            last_execution_ms   = STATE.get('execution_ms')
            if last_execution_ms and last_execution_time:
                last_execution_time_dt = datetime.fromisoformat(last_execution_time)
                time_since_last_run    = format_time_ago(last_execution_time)
                print(f"Last execution time: {last_execution_ms}ms, ending at {last_execution_time_dt.strftime('%Y-%m-%d %H:%M:%S')} ({time_since_last_run} ago)")
            elif last_execution_ms:
                print(f"Last execution time: {last_execution_ms}ms")

        # Record start time
        start_time = datetime.now()
        start_ms   = int(start_time.timestamp() * 1000)

        if VERBOSE:
            print(f"Starting monitoring run at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"max_threads={MAX_THREADS}, max_retries={MAX_RETRIES}, max_try_secs={MAX_TRY_SECS}, default_check_every_n_secs={DEFAULT_CHECK_EVERY_N_SECS}, " +
                  f"default_notify_every_n_secs={DEFAULT_NOTIFY_EVERY_N_SECS}, default_after_every_n_notifications={DEFAULT_AFTER_EVERY_N_NOTIFICATIONS}")
            print(f"Loaded {len(config['monitors'])} resources to monitor for " + config['site']['name'])

        sys.stdout.flush()

        # Check availability of each resource in config using thread pool
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                futures = [executor.submit(check_and_heartbeat, resource, config['site']) for resource in config['monitors']]

                # Wait for ALL futures to complete AND retrieve results to ensure exceptions propagate
                for future in futures:
                    try:
                        future.result()  # Blocks until this specific future completes, re-raises exceptions
                    except Exception as e:
                        print(f"Thread exception in barrier: {e}", file=sys.stderr)
                        if VERBOSE > 1:
                            print(f"DEBUG: Full traceback:", file=sys.stderr)
                            traceback.print_exc(file=sys.stderr)

        finally:
            # All threads guaranteed complete at this point
            # Flush all output buffers to ensure thread output is written
            sys.stdout.flush()
            sys.stderr.flush()

            # Calculate execution time
            end_time     = datetime.now()
            end_ms       = int(end_time.timestamp() * 1000)
            execution_ms = end_ms - start_ms

            # Update state
            STATE.update({
                'execution_time': end_time.isoformat(),
                'execution_ms':   execution_ms,
            })

            # --- Detail page generation pass (post-poll, uses freshly updated STATE) ---
            # Placed before the timing separator so only elapsed time appears after it.
            # Runs after every monitoring poll when MRTG generation is enabled,
            # ensuring detail pages always reflect data collected in this run.
            if args.generate_mrtg_config is not None:
                thread_local.prefix = ''  # clear any stale thread prefix for clean log lines
                detail_start_ms = int(datetime.now().timestamp() * 1000)
                for resource in config['monitors']:
                    if resource['type'] in ('ports', 'port', 'host'):
                        detail = STATE.get(resource['name'], {}).get('detail', {})
                        generate_monitor_detail_page(resource, detail, work_dir)
                detail_elapsed_ms = int(datetime.now().timestamp() * 1000) - detail_start_ms

            if VERBOSE:
                print(f"_ ___ _____________  {'.' * len(str(execution_ms))} .. .")
                print(f"               Site: {config['site']['name']}")
                print(f"     Execution time: {execution_ms} ms")

            if RRD_ENABLED:
                print(f"  MRTG indices time: {mrtg_index_elapsed_ms} ms")
                print(f"RRD generation time: {RRD_ELAPSED_MS} ms")
                print(f"  L2/L3 Detail time: {detail_elapsed_ms} ms")

            # Save state atomically
            save_state(STATE)
    finally:
        # Remove lockfile on exit
        if lockfile_path and os.path.exists(lockfile_path):
            os.remove(lockfile_path)


if __name__ == '__main__':
    main()
