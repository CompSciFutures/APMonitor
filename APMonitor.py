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

__version__ = "1.3.1"
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

            # Required fields
            if 'smtp_host' not in email_server:
                raise ConfigError("Field 'site.email_server': missing required field 'smtp_host'")
            if not isinstance(email_server['smtp_host'], str):
                raise ConfigError("Field 'site.email_server.smtp_host' must be a string")

            if 'smtp_port' not in email_server:
                raise ConfigError("Field 'site.email_server': missing required field 'smtp_port'")
            if not isinstance(email_server['smtp_port'], int) or email_server['smtp_port'] < 1 or email_server['smtp_port'] > 65535:
                raise ConfigError("Field 'site.email_server.smtp_port' must be an integer between 1 and 65535")

            # Optional fields
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

            # Validate from_address email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email_server['from_address']):
                raise ConfigError(f"Field 'site.email_server.from_address': '{email_server['from_address']}' is not a valid email address")

            # Optional use_tls field
            if 'use_tls' in email_server:
                if not isinstance(email_server['use_tls'], bool):
                    raise ConfigError("Field 'site.email_server.use_tls' must be a boolean")

        # Validate optional site.outage_emails
        if 'outage_emails' in site:
            # Require email_server if outage_emails is specified
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

                # Validate email format
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if not re.match(email_pattern, email_entry['email']):
                    raise ConfigError(f"Field 'site.outage_emails[{i}].email': '{email_entry['email']}' is not a valid email address")

                # Validate optional email_outages
                if 'email_outages' in email_entry:
                    try:
                        to_natural_language_boolean(email_entry['email_outages'])
                    except ValueError as e:
                        raise ConfigError(f"Field 'site.outage_emails[{i}].email_outages': {e}")

                # Validate optional email_recoveries
                if 'email_recoveries' in email_entry:
                    try:
                        to_natural_language_boolean(email_entry['email_recoveries'])
                    except ValueError as e:
                        raise ConfigError(f"Field 'site.outage_emails[{i}].email_recoveries': {e}")

                # Validate optional email_reminders
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

                # Validate required endpoint_url
                if 'endpoint_url' not in webhook:
                    raise ConfigError(f"Missing required field: 'site.outage_webhooks[{i}].endpoint_url'")
                if not isinstance(webhook['endpoint_url'], str):
                    raise ConfigError(f"Field 'site.outage_webhooks[{i}].endpoint_url' must be a string")

                # Validate URL format
                parsed_webhook = urlparse(webhook['endpoint_url'])
                if not parsed_webhook.scheme or not parsed_webhook.netloc:
                    raise ConfigError(f"Field 'site.outage_webhooks[{i}].endpoint_url' must be a valid URL with scheme and host, got '{webhook['endpoint_url']}'")

                # Validate required request_method
                if 'request_method' not in webhook:
                    raise ConfigError(f"Missing required field: 'site.outage_webhooks[{i}].request_method'")
                if webhook['request_method'] not in ['GET', 'POST']:
                    raise ConfigError(f"Field 'site.outage_webhooks[{i}].request_method' must be 'GET' or 'POST', got '{webhook['request_method']}'")

                # Validate required request_encoding
                if 'request_encoding' not in webhook:
                    raise ConfigError(f"Missing required field: 'site.outage_webhooks[{i}].request_encoding'")
                if webhook['request_encoding'] not in ['URL', 'HTML', 'JSON', 'CSVQUOTED']:
                    raise ConfigError(f"Field 'site.outage_webhooks[{i}].request_encoding' must be one of 'URL', 'HTML', 'JSON', 'CSVQUOTED', got '{webhook['request_encoding']}'")

                # Validate optional request_prefix
                if 'request_prefix' in webhook:
                    if not isinstance(webhook['request_prefix'], str):
                        raise ConfigError(f"Field 'site.outage_webhooks[{i}].request_prefix' must be a string")

                # Validate optional request_suffix
                if 'request_suffix' in webhook:
                    if not isinstance(webhook['request_suffix'], str):
                        raise ConfigError(f"Field 'site.outage_webhooks[{i}].request_suffix' must be a string")

        # Validate optional site.max_threads
        if 'max_threads' in site:
            if not isinstance(site['max_threads'], int) or site['max_threads'] < 1:
                raise ConfigError("Field 'site.max_threads' must be a positive integer")

        # Validate optional site.max_retries
        if 'max_retries' in site:
            if not isinstance(site['max_retries'], int) or site['max_retries'] < 1:
                raise ConfigError("Field 'site.max_retries' must be a positive integer")

        # Validate optional site.max_try_secs
        if 'max_try_secs' in site:
            if not isinstance(site['max_try_secs'], int) or site['max_try_secs'] < 1:
                raise ConfigError("Field 'site.max_try_secs' must be a positive integer")

        # Validate optional site.check_every_n_secs
        if 'check_every_n_secs' in site:
            if not isinstance(site['check_every_n_secs'], int) or site['check_every_n_secs'] < 1:
                raise ConfigError("Field 'site.check_every_n_secs' must be a positive integer")

        # Validate optional site.notify_every_n_secs
        if 'notify_every_n_secs' in site:
            if not isinstance(site['notify_every_n_secs'], int) or site['notify_every_n_secs'] < 1:
                raise ConfigError("Field 'site.notify_every_n_secs' must be a positive integer")

        # Validate optional site.after_every_n_notifications
        if 'after_every_n_notifications' in site:
            if not isinstance(site['after_every_n_notifications'], int) or site['after_every_n_notifications'] < 1:
                raise ConfigError("Field 'site.after_every_n_notifications' must be a positive integer")

        # Check for unrecognized site-level parameters
        valid_site_params = {
            'name', 'email_server', 'outage_emails', 'outage_webhooks', 'max_threads', 'max_retries',
            'max_try_secs', 'check_every_n_secs', 'notify_every_n_secs', 'after_every_n_notifications'
        }
        unrecognized_site = set(site.keys()) - valid_site_params
        if unrecognized_site:
            raise ConfigError(f"Unrecognized site-level parameters: {', '.join(sorted(unrecognized_site))}")

        # Check monitors list exists
        if 'monitors' not in config:
            raise ConfigError("Missing required field: 'monitors'")

        if not isinstance(config['monitors'], list):
            raise ConfigError("Field 'monitors' must be a list")

        if len(config['monitors']) == 0:
            raise ConfigError("Field 'monitors' must contain at least one monitor")

        # Track monitor names for uniqueness check
        monitor_names = set()

        # Validate each monitor entry
        for i, monitor in enumerate(config['monitors']):
            if not isinstance(monitor, dict):
                raise ConfigError(f"Monitor {i}: must be a dictionary")

            # Check required fields
            required_fields = ['type', 'name', 'address']
            for field in required_fields:
                if field not in monitor:
                    raise ConfigError(
                        f"Monitor {i} (name: {monitor.get('name', 'unknown')}): missing required field '{field}'")

            # Check for unrecognized monitor-level parameters
            valid_monitor_params = {
                'type', 'name', 'address', 'check_every_n_secs', 'notify_every_n_secs',
                'notify_on_down_every_n_secs', 'after_every_n_notifications', 'heartbeat_url',
                'heartbeat_every_n_secs', 'expect', 'ssl_fingerprint', 'ignore_ssl_expiry', 'email',
                'send', 'content_type', 'community', 'percentile', 'port', 'mac', 'always_up',
                'display'
            }
            unrecognized_monitor = set(monitor.keys()) - valid_monitor_params
            if unrecognized_monitor:
                raise ConfigError(f"Monitor {i} (name: {monitor.get('name', 'unknown')}): unrecognized parameters: {', '.join(sorted(unrecognized_monitor))}")

            # Validate name is non-empty string
            if not isinstance(monitor['name'], str):
                raise ConfigError(f"Monitor {i} (name: {monitor.get('name', 'unknown')}): 'name' must be a string")

            # Check for duplicate names
            name = monitor['name']
            if name in monitor_names:
                raise ConfigError(f"Monitor {i} (name: {name}): duplicate monitor name '{name}'")
            monitor_names.add(name)

            # Validate type field
            valid_types = ['ping', 'http', 'quic', 'tcp', 'udp', 'snmp', 'ports', 'port']
            if monitor['type'] not in valid_types:
                raise ConfigError(f"Monitor {i} (name: {monitor.get('name', 'unknown')}): invalid type '{monitor['type']}', must be one of {valid_types}")

            # Validate address is non-empty string
            if not isinstance(monitor['address'], str):
                raise ConfigError(f"Monitor {i} (name: {monitor.get('name', 'unknown')}): 'address' must be a string")

            # Validate optional check_every_n_secs
            if 'check_every_n_secs' in monitor:
                if not isinstance(monitor['check_every_n_secs'], int) or monitor['check_every_n_secs'] < 1:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'check_every_n_secs' must be a positive integer")

            # Validate optional notify_on_down_every_n_secs
            if 'notify_on_down_every_n_secs' in monitor:
                if not isinstance(monitor['notify_on_down_every_n_secs'], int) or monitor[
                    'notify_on_down_every_n_secs'] < 1:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'notify_on_down_every_n_secs' must be a positive integer")

                # Check that notify_on_down_every_n_secs >= check_every_n_secs
                if 'check_every_n_secs' in monitor:
                    if monitor['notify_on_down_every_n_secs'] < monitor['check_every_n_secs']:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'notify_on_down_every_n_secs' must be >= 'check_every_n_secs'")

            # Validate optional after_every_n_notifications
            if 'after_every_n_notifications' in monitor:
                if 'notify_every_n_secs' not in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'after_every_n_notifications' can only be specified if 'notify_every_n_secs' is present")
                if not isinstance(monitor['after_every_n_notifications'], int) or monitor['after_every_n_notifications'] < 1:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'after_every_n_notifications' must be a positive integer")

            # Validate optional email flag
            if 'email' in monitor:
                try:
                    to_natural_language_boolean(monitor['email'])
                except ValueError as e:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'email' field: {e}")

            # Validate optional display flag
            if 'display' in monitor:
                try:
                    to_natural_language_boolean(monitor['display'])
                except ValueError as e:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'display' field: {e}")

            monitor_type = monitor['type']
            address = monitor['address']

            if monitor_type == 'ping':
                # Validate hostname or IP address (IPv4 or IPv6)
                ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
                hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'

                if not (re.match(ipv4_pattern, address) or re.match(ipv6_pattern, address) or re.match(hostname_pattern, address)):
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must be a valid hostname, IPv4 or IPv6 address, got '{address}'")

                # 'expect' not allowed for ping
                if 'expect' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'expect' field is only valid for 'http' and 'quic' monitors")

                # 'ssl_fingerprint' not allowed for ping
                if 'ssl_fingerprint' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'ssl_fingerprint' field is only valid for 'http' and 'quic' monitors")

                # 'percentile' not allowed for ping
                if 'percentile' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'percentile' field is only valid for 'snmp' monitors")

            elif monitor_type in ['http', 'quic']:
                # Validate URL/URI
                parsed = urlparse(address)
                if not parsed.scheme or not parsed.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must be a valid URL with scheme and host, got '{address}'")

                # Validate 'expect' if present - must be a string
                if 'expect' in monitor:
                    if not isinstance(monitor['expect'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'expect' must be a string")
                    if len(monitor['expect']) == 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'expect' must not be empty")

                # Validate 'ssl_fingerprint' if present
                if 'ssl_fingerprint' in monitor:
                    if not isinstance(monitor['ssl_fingerprint'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'ssl_fingerprint' must be a string")

                    # Remove colons and validate hex string
                    fingerprint_clean = monitor['ssl_fingerprint'].replace(':', '')

                    if not re.match(r'^[0-9a-fA-F]+$', fingerprint_clean):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'ssl_fingerprint' must be a valid hex string")

                    # Check length is power of two
                    fp_len = len(fingerprint_clean)
                    if fp_len == 0 or (fp_len & (fp_len - 1)) != 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'ssl_fingerprint' length must be a power of two (got {fp_len} hex characters)")

                # 'percentile' not allowed for http/quic
                if 'percentile' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'percentile' field is only valid for 'snmp' monitors")

            elif monitor_type in ['tcp', 'udp']:
                # Validate URL/URI with tcp:// or udp:// scheme
                parsed = urlparse(address)
                if monitor_type == 'tcp' and parsed.scheme != 'tcp':
                    raise ConfigError(f"Monitor {i} (name: {name}): TCP monitor must use 'tcp://' scheme, got '{address}'")
                if monitor_type == 'udp' and parsed.scheme != 'udp':
                    raise ConfigError(f"Monitor {i} (name: {name}): UDP monitor must use 'udp://' scheme, got '{address}'")
                if not parsed.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must include hostname/IP and port, got '{address}'")

                # Validate optional 'send'
                if 'send' in monitor:
                    if not isinstance(monitor['send'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'send' must be a string")

                # Validate optional 'content_type'
                if 'content_type' in monitor:
                    if 'send' not in monitor:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'content_type' can only be specified if 'send' is present")
                    valid_content_types = ['text', 'hex', 'base64']
                    if monitor['content_type'] not in valid_content_types:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'content_type' must be one of {valid_content_types}, got '{monitor['content_type']}'")

                # 'expect' is optional for TCP/UDP
                if 'expect' in monitor:
                    if not isinstance(monitor['expect'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'expect' must be a string")
                    if len(monitor['expect']) == 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'expect' must not be empty")

                # 'ssl_fingerprint' not allowed for TCP/UDP
                if 'ssl_fingerprint' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'ssl_fingerprint' field is only valid for 'http' and 'quic' monitors")

                # 'percentile' not allowed for tcp/udp
                if 'percentile' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'percentile' field is only valid for 'snmp' monitors")

            elif monitor_type == 'snmp':
                # Validate URL/URI with snmp:// scheme
                parsed = urlparse(address)
                if parsed.scheme != 'snmp':
                    raise ConfigError(f"Monitor {i} (name: {name}): SNMP monitor must use 'snmp://' scheme, got '{address}'")
                if not parsed.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must include hostname/IP, got '{address}'")

                # Validate hostname or IP address (IPv4 or IPv6)
                hostname = parsed.hostname
                if hostname:
                    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
                    hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'

                    if not (re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname) or re.match(hostname_pattern, hostname)):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'address' hostname must be valid hostname, IPv4 or IPv6 address, got '{hostname}'")

                # Validate optional 'community' string
                if 'community' in monitor:
                    if not isinstance(monitor['community'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must be a string")
                    if len(monitor['community']) == 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must not be empty")

                # Validate optional 'percentile'
                if 'percentile' in monitor:
                    if not isinstance(monitor['percentile'], int) or not (1 <= monitor['percentile'] <= 99):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'percentile' must be an integer between 1 and 99")

                # 'expect' not allowed for SNMP
                if 'expect' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'expect' field not valid for SNMP monitors")

                # 'ssl_fingerprint' not allowed for SNMP
                if 'ssl_fingerprint' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'ssl_fingerprint' field not valid for SNMP monitors")

                # 'ignore_ssl_expiry' not allowed for SNMP
                if 'ignore_ssl_expiry' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'ignore_ssl_expiry' field not valid for SNMP monitors")

                # 'send' not allowed for SNMP
                if 'send' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'send' field not valid for SNMP monitors")

                # 'content_type' not allowed for SNMP
                if 'content_type' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'content_type' field not valid for SNMP monitors")

            elif monitor_type == 'ports':
                # Validate URL/URI with snmp:// scheme (ports uses SNMP transport)
                parsed = urlparse(address)
                if parsed.scheme != 'snmp':
                    raise ConfigError(f"Monitor {i} (name: {name}): ports monitor must use 'snmp://' scheme, got '{address}'")
                if not parsed.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must include hostname/IP, got '{address}'")

                # Validate hostname or IP address (IPv4 or IPv6)
                hostname = parsed.hostname
                if hostname:
                    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
                    hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'

                    if not (re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname) or re.match(hostname_pattern, hostname)):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'address' hostname must be valid hostname, IPv4 or IPv6 address, got '{hostname}'")

                # Validate optional 'community' string
                if 'community' in monitor:
                    if not isinstance(monitor['community'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must be a string")
                    if len(monitor['community']) == 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must not be empty")

                # 'expect' not allowed for ports
                if 'expect' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'expect' field not valid for ports monitors")

                # 'ssl_fingerprint' not allowed for ports
                if 'ssl_fingerprint' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'ssl_fingerprint' field not valid for ports monitors")

                # 'ignore_ssl_expiry' not allowed for ports
                if 'ignore_ssl_expiry' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'ignore_ssl_expiry' field not valid for ports monitors")

                # 'send' not allowed for ports
                if 'send' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'send' field not valid for ports monitors")

                # 'content_type' not allowed for ports
                if 'content_type' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'content_type' field not valid for ports monitors")

                # 'percentile' not allowed for ports
                if 'percentile' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'percentile' field not valid for ports monitors")

            elif monitor_type == 'port':
                # Validate URL/URI with snmp:// scheme (port uses SNMP transport)
                parsed = urlparse(address)
                if parsed.scheme != 'snmp':
                    raise ConfigError(f"Monitor {i} (name: {name}): port monitor must use 'snmp://' scheme, got '{address}'")
                if not parsed.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must include hostname/IP, got '{address}'")

                # Validate hostname or IP address (IPv4 or IPv6)
                hostname = parsed.hostname
                if hostname:
                    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
                    hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'

                    if not (re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname) or re.match(hostname_pattern, hostname)):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'address' hostname must be valid hostname, IPv4 or IPv6 address, got '{hostname}'")

                # 'port' (ifIndex) is required
                if 'port' not in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'port' (ifIndex) is required for port monitors")
                if not isinstance(monitor['port'], int) or monitor['port'] < 0:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'port' must be a non-negative integer (ifIndex)")

                # 'mac' is required
                if 'mac' not in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'mac' (pinned MAC address) is required for port monitors")
                if not isinstance(monitor['mac'], str):
                    raise ConfigError(f"Monitor {i} (name: {name}): 'mac' must be a string")
                if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', monitor['mac']):
                    raise ConfigError(f"Monitor {i} (name: {name}): 'mac' must be a valid MAC address (XX:XX:XX:XX:XX:XX), got '{monitor['mac']}'")

                # 'always_up' is optional boolean
                if 'always_up' in monitor:
                    try:
                        to_natural_language_boolean(monitor['always_up'])
                    except ValueError as e:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'always_up' field: {e}")

                # Validate optional 'community' string
                if 'community' in monitor:
                    if not isinstance(monitor['community'], str):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must be a string")
                    if len(monitor['community']) == 0:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'community' must not be empty")

                # Fields not valid for port
                for forbidden in ('expect', 'ssl_fingerprint', 'ignore_ssl_expiry', 'send', 'content_type', 'percentile'):
                    if forbidden in monitor:
                        raise ConfigError(f"Monitor {i} (name: {name}): '{forbidden}' field not valid for port monitors")

            # Validate heartbeat_url if present (valid for all monitor types)
            if 'heartbeat_url' in monitor:
                if not isinstance(monitor['heartbeat_url'], str):
                    raise ConfigError(f"Monitor {i} (name: {name}): 'heartbeat_url' must be a string")

                parsed_heartbeat = urlparse(monitor['heartbeat_url'])
                if not parsed_heartbeat.scheme or not parsed_heartbeat.netloc:
                    raise ConfigError(
                        f"Monitor {i} (name: {name}): 'heartbeat_url' must be a valid URL with scheme and host, got '{monitor['heartbeat_url']}'")

            # Validate optional heartbeat_every_n_secs
            if 'heartbeat_every_n_secs' in monitor:
                if 'heartbeat_url' not in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'heartbeat_every_n_secs' can only be specified if 'heartbeat_url' is present")
                if not isinstance(monitor['heartbeat_every_n_secs'], int) or monitor['heartbeat_every_n_secs'] < 1:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'heartbeat_every_n_secs' must be a positive integer")

            # Validate optional ignore_ssl_expiry
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


def check_snmp_resource(resource: Dict[str, Any]) -> Optional[str]:
    """Poll SNMP device for interface bandwidth/retransmit metrics and system resources, update RRD."""
    try:
        from easysnmp import Session
    except ImportError as e:
        error_msg = f"easysnmp library import failed: {e} (try: pip install easysnmp)"
        prefix = getattr(thread_local, 'prefix', '')
        print(f"{prefix}SNMP check FAILED: {error_msg}", file=sys.stderr)
        return error_msg

    prefix = getattr(thread_local, 'prefix', '')
    address = resource['address']
    name = resource['name']

    # Parse SNMP configuration from address (format: snmp://community@host:port)
    parsed = urlparse(address)
    if parsed.scheme != 'snmp':
        error_msg = f"{parsed.scheme.upper()} protocol not supported for SNMP, use snmp"
        print(f"{prefix}SNMP check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg

    # Extract community string - priority: monitor config > URL userinfo > default 'public'
    community = resource.get('community') or parsed.username or 'public'
    hostname = parsed.hostname
    port = parsed.port or 161

    if not hostname:
        error_msg = "SNMP address must include hostname"
        print(f"{prefix}SNMP check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg

    # Standard SNMP OIDs
    OID_SYS_OBJECT_ID = '1.3.6.1.2.1.1.2.0'  # SNMPv2-MIB::sysObjectID
    OID_IF_DESCR = '1.3.6.1.2.1.2.2.1.2'  # IF-MIB::ifDescr
    OID_IF_IN_OCTETS = '1.3.6.1.2.1.2.2.1.10'  # IF-MIB::ifInOctets
    OID_IF_OUT_OCTETS = '1.3.6.1.2.1.2.2.1.16'  # IF-MIB::ifOutOctets
    OID_IF_IN_ERRORS = '1.3.6.1.2.1.2.2.1.14'   # IF-MIB::ifInErrors
    OID_IF_OUT_ERRORS = '1.3.6.1.2.1.2.2.1.20'  # IF-MIB::ifOutErrors
    OID_TCP_RETRANS_SEGS = '1.3.6.1.2.1.6.12.0'  # TCP-MIB::tcpRetransSegs

    # Interface packet counters (high-capacity 64-bit)
    OID_IF_HC_IN_UCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.7'  # IF-MIB::ifHCInUcastPkts
    OID_IF_HC_IN_MCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.8'  # IF-MIB::ifHCInMulticastPkts
    OID_IF_HC_IN_BCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.9'  # IF-MIB::ifHCInBroadcastPkts
    OID_IF_HC_OUT_UCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.11'  # IF-MIB::ifHCOutUcastPkts
    OID_IF_HC_OUT_MCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.12'  # IF-MIB::ifHCOutMulticastPkts
    OID_IF_HC_OUT_BCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.13'  # IF-MIB::ifHCOutBroadcastPkts

    # HOST-RESOURCES-MIB for CPU and memory (fallback)
    OID_HR_PROCESSOR_LOAD = '1.3.6.1.2.1.25.3.3.1.2'  # HOST-RESOURCES-MIB::hrProcessorLoad
    OID_HR_STORAGE_INDEX = '1.3.6.1.2.1.25.2.3.1.1'  # HOST-RESOURCES-MIB::hrStorageIndex
    OID_HR_STORAGE_DESCR = '1.3.6.1.2.1.25.2.3.1.3'  # HOST-RESOURCES-MIB::hrStorageDescr
    OID_HR_STORAGE_UNITS = '1.3.6.1.2.1.25.2.3.1.4'  # HOST-RESOURCES-MIB::hrStorageAllocationUnits
    OID_HR_STORAGE_SIZE = '1.3.6.1.2.1.25.2.3.1.5'  # HOST-RESOURCES-MIB::hrStorageSize
    OID_HR_STORAGE_USED = '1.3.6.1.2.1.25.2.3.1.6'  # HOST-RESOURCES-MIB::hrStorageUsed

    # Vendor-specific OIDs for CPU
    OID_CISCO_CPU_5SEC = '1.3.6.1.4.1.9.9.109.1.1.1.1.7.1'  # CISCO-PROCESS-MIB::cpmCPUTotal5secRev
    OID_CISCO_CPU_1MIN = '1.3.6.1.4.1.9.9.109.1.1.1.1.5.1'  # CISCO-PROCESS-MIB::cpmCPUTotal1minRev
    OID_HP_CPU_LOAD = '1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0'  # HP-ICF-CHASSIS::hpSwitchCpuStat
    OID_JUNIPER_CPU = '1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0'  # JUNIPER-MIB::jnxOperatingCPU (RE0)
    OID_UBNT_SYS_CPU = '1.3.6.1.4.1.41112.1.4.1.2.1.0'  # UBNT-MIB::ubntSystemCpuLoad

    # Vendor-specific OIDs for memory
    OID_CISCO_MEM_POOL_USED = '1.3.6.1.4.1.9.9.48.1.1.1.5.1'  # CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolUsed
    OID_CISCO_MEM_POOL_FREE = '1.3.6.1.4.1.9.9.48.1.1.1.6.1'  # CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolFree
    OID_HP_MEM_TOTAL = '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5.1'  # HP-ICF-CHASSIS::hpLocalMemTotalBytes
    OID_HP_MEM_FREE = '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6.1'  # HP-ICF-CHASSIS::hpLocalMemFreeBytes
    OID_JUNIPER_MEM_UTIL = '1.3.6.1.4.1.2636.3.1.13.1.11.9.1.0.0'  # JUNIPER-MIB::jnxOperatingBuffer (RE0)
    OID_UBNT_SYS_MEM_TOTAL = '1.3.6.1.4.1.41112.1.4.1.2.2.0'  # UBNT-MIB::ubntSystemMemTotal
    OID_UBNT_SYS_MEM_FREE = '1.3.6.1.4.1.41112.1.4.1.2.3.0'  # UBNT-MIB::ubntSystemMemFree

    try:
        # Create SNMP session
        session = Session(
            hostname=hostname,
            community=community,
            version=2,
            remote_port=port,
            timeout=MAX_TRY_SECS,
            retries=MAX_RETRIES - 1
        )

        # Detect vendor via sysObjectID
        vendor = None
        try:
            sys_obj_id_item = session.get(OID_SYS_OBJECT_ID)
            sys_obj_id = sys_obj_id_item.value

            if VERBOSE > 1:
                print(f"{prefix}SNMP sysObjectID: {sys_obj_id}")

            # Vendor detection based on enterprise OID prefix
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

        # Walk interface table to discover all interfaces
        interfaces = {}

        try:
            if_descr_items = session.walk(OID_IF_DESCR)

            for item in if_descr_items:
                if_index = item.oid.split('.')[-1]
                if_name = item.value
                interfaces[if_index] = {'name': if_name}
        except Exception as e:
            error_msg = f"SNMP walk failed: {e}"
            print(f"{prefix}SNMP check FAILED for '{name}': {error_msg}", file=sys.stderr)
            return error_msg

        if not interfaces:
            error_msg = "no interfaces found"
            print(f"{prefix}SNMP check FAILED for '{name}': {error_msg}", file=sys.stderr)
            return error_msg

        # Initialize aggregate counters
        total_octets_in = 0
        total_octets_out = 0
        total_pkts_ucast_in = 0
        total_pkts_ucast_out = 0
        total_pkts_bmcast_in = 0   # broadcast + multicast combined
        total_pkts_bmcast_out = 0
        total_pkts_in = 0
        total_pkts_out = 0
        total_errors_in = 0
        total_errors_out = 0

        # Poll byte counters and error counters for each interface
        for if_index in interfaces:
            # Get input octets
            try:
                item = session.get(f"{OID_IF_IN_OCTETS}.{if_index}")
                octets_in = int(item.value)
                interfaces[if_index]['in_octets'] = octets_in
                total_octets_in += octets_in
                if VERBOSE:
                    print(f"{prefix}SNMP GET {OID_IF_IN_OCTETS}.{if_index} (ifInOctets) = {octets_in}")
            except Exception as e:
                interfaces[if_index]['in_octets'] = None
                if VERBOSE:
                    print(f"{prefix}SNMP GET {OID_IF_IN_OCTETS}.{if_index} (ifInOctets) FAILED: {e}")

            # Get output octets
            try:
                item = session.get(f"{OID_IF_OUT_OCTETS}.{if_index}")
                octets_out = int(item.value)
                interfaces[if_index]['out_octets'] = octets_out
                total_octets_out += octets_out
                if VERBOSE:
                    print(f"{prefix}SNMP GET {OID_IF_OUT_OCTETS}.{if_index} (ifOutOctets) = {octets_out}")
            except Exception as e:
                interfaces[if_index]['out_octets'] = None
                if VERBOSE:
                    print(f"{prefix}SNMP GET {OID_IF_OUT_OCTETS}.{if_index} (ifOutOctets) FAILED: {e}")

            # Get input errors
            try:
                item = session.get(f"{OID_IF_IN_ERRORS}.{if_index}")
                errors_in = int(item.value)
                interfaces[if_index]['in_errors'] = errors_in
                total_errors_in += errors_in
                if VERBOSE:
                    print(f"{prefix}SNMP GET {OID_IF_IN_ERRORS}.{if_index} (ifInErrors) = {errors_in}")
            except Exception as e:
                interfaces[if_index]['in_errors'] = None
                if VERBOSE:
                    print(f"{prefix}SNMP GET {OID_IF_IN_ERRORS}.{if_index} (ifInErrors) FAILED: {e}")

            # Get output errors
            try:
                item = session.get(f"{OID_IF_OUT_ERRORS}.{if_index}")
                errors_out = int(item.value)
                interfaces[if_index]['out_errors'] = errors_out
                total_errors_out += errors_out
                if VERBOSE:
                    print(f"{prefix}SNMP GET {OID_IF_OUT_ERRORS}.{if_index} (ifOutErrors) = {errors_out}")
            except Exception as e:
                interfaces[if_index]['out_errors'] = None
                if VERBOSE:
                    print(f"{prefix}SNMP GET {OID_IF_OUT_ERRORS}.{if_index} (ifOutErrors) FAILED: {e}")

        # Poll packet counters for each interface (IF-MIB high-capacity 64-bit counters)
        for if_index in interfaces:
            if_pkts_in = 0
            if_pkts_out = 0

            # Input packets (unicast + multicast + broadcast)
            try:
                item = session.get(f"{OID_IF_HC_IN_UCAST_PKTS}.{if_index}")
                v = int(item.value)
                if_pkts_in += v
                total_pkts_ucast_in += v
            except Exception as e:
                if VERBOSE > 1:
                    print(f"{prefix}SNMP GET {OID_IF_HC_IN_UCAST_PKTS}.{if_index} (ifHCInUcastPkts) FAILED: {e}")

            try:
                item = session.get(f"{OID_IF_HC_IN_MCAST_PKTS}.{if_index}")
                v = int(item.value)
                if_pkts_in += v
                total_pkts_bmcast_in += v
            except Exception as e:
                if VERBOSE > 1:
                    print(f"{prefix}SNMP GET {OID_IF_HC_IN_MCAST_PKTS}.{if_index} (ifHCInMulticastPkts) FAILED: {e}")

            try:
                item = session.get(f"{OID_IF_HC_IN_BCAST_PKTS}.{if_index}")
                v = int(item.value)
                if_pkts_in += v
                total_pkts_bmcast_in += v
            except Exception as e:
                if VERBOSE > 1:
                    print(f"{prefix}SNMP GET {OID_IF_HC_IN_BCAST_PKTS}.{if_index} (ifHCInBroadcastPkts) FAILED: {e}")

            # Output packets (unicast + multicast + broadcast)
            try:
                item = session.get(f"{OID_IF_HC_OUT_UCAST_PKTS}.{if_index}")
                v = int(item.value)
                if_pkts_out += v
                total_pkts_ucast_out += v
            except Exception as e:
                if VERBOSE > 1:
                    print(f"{prefix}SNMP GET {OID_IF_HC_OUT_UCAST_PKTS}.{if_index} (ifHCOutUcastPkts) FAILED: {e}")

            try:
                item = session.get(f"{OID_IF_HC_OUT_MCAST_PKTS}.{if_index}")
                v = int(item.value)
                if_pkts_out += v
                total_pkts_bmcast_out += v
            except Exception as e:
                if VERBOSE > 1:
                    print(f"{prefix}SNMP GET {OID_IF_HC_OUT_MCAST_PKTS}.{if_index} (ifHCOutMulticastPkts) FAILED: {e}")

            try:
                item = session.get(f"{OID_IF_HC_OUT_BCAST_PKTS}.{if_index}")
                v = int(item.value)
                if_pkts_out += v
                total_pkts_bmcast_out += v
            except Exception as e:
                if VERBOSE > 1:
                    print(f"{prefix}SNMP GET {OID_IF_HC_OUT_BCAST_PKTS}.{if_index} (ifHCOutBroadcastPkts) FAILED: {e}")

            # Aggregate totals
            total_pkts_in += if_pkts_in
            total_pkts_out += if_pkts_out

            if VERBOSE:
                print(f"{prefix}Interface {if_index} packets: in={if_pkts_in:,} out={if_pkts_out:,}")

        # Convert octets to bits for total_bits metrics (1 byte = 8 bits)
        total_bits_in = total_octets_in * 8
        total_bits_out = total_octets_out * 8

        # Unicast vs broadcast+multicast aggregates (in+out combined)
        total_pkts_ucast  = total_pkts_ucast_in  + total_pkts_ucast_out
        total_pkts_bmcast = total_pkts_bmcast_in  + total_pkts_bmcast_out

        if VERBOSE:
            print(f"{prefix}Aggregate totals: bits_in={total_bits_in:,} bits_out={total_bits_out:,} pkts_in={total_pkts_in:,} pkts_out={total_pkts_out:,} errors_in={total_errors_in:,} errors_out={total_errors_out:,}")
            print(f"{prefix}Packet type totals: ucast={total_pkts_ucast:,} bmcast={total_pkts_bmcast:,}")

        # Get TCP retransmit segments (global counter)
        tcp_retrans = None
        try:
            item = session.get(OID_TCP_RETRANS_SEGS)
            tcp_retrans = int(item.value)
            if VERBOSE:
                print(f"{prefix}SNMP GET {OID_TCP_RETRANS_SEGS} (tcpRetransSegs) = {tcp_retrans}")
        except Exception as e:
            if VERBOSE:
                print(f"{prefix}SNMP GET {OID_TCP_RETRANS_SEGS} (tcpRetransSegs) FAILED: {e}")

        # Poll CPU utilization (vendor-specific with HOST-RESOURCES-MIB fallback)
        cpu_load = None

        # Try vendor-specific OIDs first
        if vendor == 'cisco':
            try:
                item = session.get(OID_CISCO_CPU_5SEC)
                cpu_load = float(item.value)
                if VERBOSE:
                    print(f"{prefix}SNMP CPU (Cisco 5-sec): {cpu_load:.1f}%")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP GET Cisco CPU 5-sec FAILED: {e}, trying 1-min average")
                try:
                    item = session.get(OID_CISCO_CPU_1MIN)
                    cpu_load = float(item.value)
                    if VERBOSE:
                        print(f"{prefix}SNMP CPU (Cisco 1-min): {cpu_load:.1f}%")
                except Exception as e2:
                    if VERBOSE:
                        print(f"{prefix}SNMP GET Cisco CPU 1-min FAILED: {e2}")

        elif vendor == 'hp':
            try:
                item = session.get(OID_HP_CPU_LOAD)
                cpu_load = float(item.value)
                if VERBOSE:
                    print(f"{prefix}SNMP CPU (HP): {cpu_load:.1f}%")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP GET HP CPU FAILED: {e}")

        elif vendor == 'juniper':
            try:
                item = session.get(OID_JUNIPER_CPU)
                cpu_load = float(item.value)
                if VERBOSE:
                    print(f"{prefix}SNMP CPU (Juniper): {cpu_load:.1f}%")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP GET Juniper CPU FAILED: {e}")

        elif vendor == 'ubiquiti':
            try:
                item = session.get(OID_UBNT_SYS_CPU)
                cpu_load = float(item.value)
                if VERBOSE:
                    print(f"{prefix}SNMP CPU (Ubiquiti): {cpu_load:.1f}%")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP GET Ubiquiti CPU FAILED: {e}")

        # Fallback to HOST-RESOURCES-MIB if vendor-specific failed or no vendor detected
        if cpu_load is None:
            try:
                cpu_items = session.walk(OID_HR_PROCESSOR_LOAD)
                if cpu_items:
                    # Average all CPU cores
                    cpu_values = [int(item.value) for item in cpu_items]
                    cpu_load = sum(cpu_values) / len(cpu_values)
                    if VERBOSE:
                        print(f"{prefix}SNMP CPU (HOST-RESOURCES-MIB): {len(cpu_values)} cores, average={cpu_load:.1f}%")
                else:
                    if VERBOSE:
                        print(f"{prefix}SNMP CPU: no processors found (HOST-RESOURCES-MIB not supported)")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP GET hrProcessorLoad FAILED: {e}")

        # Poll memory utilization (vendor-specific with HOST-RESOURCES-MIB fallback)
        memory_pct = None

        # Try vendor-specific OIDs first
        if vendor == 'cisco':
            try:
                used_item = session.get(OID_CISCO_MEM_POOL_USED)
                free_item = session.get(OID_CISCO_MEM_POOL_FREE)
                mem_used = int(used_item.value)
                mem_free = int(free_item.value)
                mem_total = mem_used + mem_free

                if mem_total > 0:
                    memory_pct = (mem_used / mem_total) * 100.0
                    if VERBOSE:
                        print(f"{prefix}SNMP memory (Cisco): used={mem_used:,} total={mem_total:,} ({memory_pct:.1f}%)")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP GET Cisco memory FAILED: {e}")

        elif vendor == 'hp':
            try:
                total_item = session.get(OID_HP_MEM_TOTAL)
                free_item = session.get(OID_HP_MEM_FREE)
                mem_total = int(total_item.value)
                mem_free = int(free_item.value)
                mem_used = mem_total - mem_free

                if mem_total > 0:
                    memory_pct = (mem_used / mem_total) * 100.0
                    if VERBOSE:
                        print(f"{prefix}SNMP memory (HP): used={mem_used:,} total={mem_total:,} ({memory_pct:.1f}%)")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP GET HP memory FAILED: {e}")

        elif vendor == 'juniper':
            try:
                item = session.get(OID_JUNIPER_MEM_UTIL)
                memory_pct = float(item.value)
                if VERBOSE:
                    print(f"{prefix}SNMP memory (Juniper): {memory_pct:.1f}%")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP GET Juniper memory FAILED: {e}")

        elif vendor == 'ubiquiti':
            try:
                total_item = session.get(OID_UBNT_SYS_MEM_TOTAL)
                free_item = session.get(OID_UBNT_SYS_MEM_FREE)
                mem_total = int(total_item.value)
                mem_free = int(free_item.value)
                mem_used = mem_total - mem_free

                if mem_total > 0:
                    memory_pct = (mem_used / mem_total) * 100.0
                    if VERBOSE:
                        print(f"{prefix}SNMP memory (Ubiquiti): used={mem_used:,} total={mem_total:,} ({memory_pct:.1f}%)")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP GET Ubiquiti memory FAILED: {e}")

        # Fallback to HOST-RESOURCES-MIB if vendor-specific failed or no vendor detected
        if memory_pct is None:
            try:
                storage_items = session.walk(OID_HR_STORAGE_DESCR)

                # Find physical memory entry (description contains "memory" or "RAM")
                # Known descriptions by platform:
                #   Debian/Ubuntu net-snmp:  "Physical memory"
                #   Some BSD/Linux net-snmp: "Real Memory"
                #   Generic fallback:        "Memory" or contains "RAM"
                memory_index = None
                for item in storage_items:
                    descr = item.value.lower()
                    if 'physical memory' in descr or 'real memory' in descr or 'ram' in descr or descr == 'memory':
                        memory_index = item.oid.split('.')[-1]
                        if VERBOSE:
                            print(f"{prefix}Found memory storage entry: index={memory_index} descr='{item.value}'")
                        break

                if memory_index:
                    # Get allocation units (bytes per unit)
                    units_item = session.get(f"{OID_HR_STORAGE_UNITS}.{memory_index}")
                    units = int(units_item.value)

                    # Get total size (in allocation units)
                    size_item = session.get(f"{OID_HR_STORAGE_SIZE}.{memory_index}")
                    size = int(size_item.value)

                    # Get used size (in allocation units)
                    used_item = session.get(f"{OID_HR_STORAGE_USED}.{memory_index}")
                    used = int(used_item.value)

                    # Calculate percentage
                    if size > 0:
                        memory_pct = (used / size) * 100.0

                        if VERBOSE:
                            memory_total_bytes = size * units
                            memory_used_bytes = used * units
                            print(f"{prefix}SNMP memory (HOST-RESOURCES-MIB): used={memory_used_bytes:,} total={memory_total_bytes:,} ({memory_pct:.1f}%)")
                    else:
                        if VERBOSE:
                            print(f"{prefix}SNMP memory: size=0, cannot calculate percentage")
                else:
                    if VERBOSE:
                        print(f"{prefix}SNMP memory: no physical memory entry found in hrStorage table")
            except Exception as e:
                if VERBOSE:
                    print(f"{prefix}SNMP GET hrStorage FAILED: {e}")

        # Update RRD database if enabled
        if RRD_ENABLED:
            check_every_n_secs = resource.get('check_every_n_secs', DEFAULT_CHECK_EVERY_N_SECS)
            rrd_path = get_rrd_path(name, 'snmp')
            rras = create_rrd_rras(check_every_n_secs)

            # Auto-heal: recreate if DS count is less than expected OR any RRA has fewer rows
            # than configured. Expected DS count = 2 per interface + 11 fixed DS.
            if os.path.exists(rrd_path):
                expected_ds_count = 2 * len(interfaces) + 11
                needs_recreation = False
                try:
                    info = rrdtool.info(rrd_path)
                    actual_ds_count = len([k for k in info if k.startswith('ds[') and k.endswith('].type')])
                    if actual_ds_count < expected_ds_count:
                        print(f"{prefix}SNMP RRD deleted for recreation: {rrd_path} "
                              f"(ds_count={actual_ds_count} < expected={expected_ds_count})")
                        needs_recreation = True
                except Exception as e:
                    print(f"{prefix}SNMP RRD introspection failed for '{rrd_path}': {e}, will recreate", file=sys.stderr)
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

            if not os.path.exists(rrd_path):
                error_msg = f"RRD creation failed: {rrd_path} does not exist after create"
                print(f"{prefix}SNMP check FAILED for '{name}': {error_msg}", file=sys.stderr)
                return error_msg

            error_msg = update_snmp_rrd(rrd_path, datetime.now(), interfaces, tcp_retrans,
                                        total_bits_in, total_bits_out, total_pkts_in, total_pkts_out,
                                        total_errors_in, total_errors_out, cpu_load, memory_pct,
                                        total_pkts_ucast, total_pkts_bmcast)
            if error_msg != None:
                return error_msg

            if not os.path.exists(rrd_path):
                error_msg = f"RRD file disappeared after update: {rrd_path}"
                print(f"{prefix}SNMP check FAILED for '{name}': {error_msg}", file=sys.stderr)
                return error_msg

            if VERBOSE:
                print(f"{prefix}RRD updated: {rrd_path}")

        elif VERBOSE:
            print(f"{prefix}RRD disabled (would use: {get_rrd_path(name, 'snmp')})")

        # Verbose output
        if VERBOSE:
            summary_parts = [f"{len(interfaces)} interfaces"]
            if tcp_retrans is not None:
                summary_parts.append(f"tcp_retrans={tcp_retrans}")
            if cpu_load is not None:
                summary_parts.append(f"cpu={cpu_load:.1f}%")
            else:
                summary_parts.append("cpu=unavailable")
            if memory_pct is not None:
                summary_parts.append(f"memory={memory_pct:.1f}%")
            else:
                summary_parts.append("memory=unavailable")
            summary_parts.append(f"errors_in={total_errors_in:,} errors_out={total_errors_out:,}")

            print(f"{prefix}SNMP poll SUCCESS for '{name}': {', '.join(summary_parts)}")
            for if_index in sorted(interfaces.keys()):
                if_data = interfaces[if_index]
                in_octets = if_data.get('in_octets', 'N/A')
                out_octets = if_data.get('out_octets', 'N/A')
                in_errors = if_data.get('in_errors', 'N/A')
                out_errors = if_data.get('out_errors', 'N/A')
                in_str = f"{in_octets:,}" if in_octets != 'N/A' else 'N/A'
                out_str = f"{out_octets:,}" if out_octets != 'N/A' else 'N/A'
                err_in_str = f"{in_errors:,}" if in_errors != 'N/A' else 'N/A'
                err_out_str = f"{out_errors:,}" if out_errors != 'N/A' else 'N/A'
                print(f"{prefix}  Interface {if_index} ({if_data['name']}): in={in_str} out={out_str} err_in={err_in_str} err_out={err_out_str}")

        return None  # Success

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        print(f"{prefix}SNMP check FAILED for '{name}' at '{address}': {error_msg}", file=sys.stderr)
        if VERBOSE > 1:
            traceback.print_exc(file=sys.stderr)
        return error_msg


def check_ports_resource(resource: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
    """Poll SNMP device for switch port (interface) oper/admin status and MAC forwarding table.

    Uses IF-MIB for port status and Q-BRIDGE-MIB (RFC 2674) dot1qTpFdbTable for MAC addresses.
    Q-BRIDGE-MIB OID tail encodes <vlan_id>.<6 MAC octets>, value is bridge port number (= ifIndex).

    Returns (error_msg, current_ports_state) where:
    - error_msg: None on success, string on SNMP failure
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
    name = resource['name']

    # Parse SNMP configuration from address (format: snmp://community@host:port)
    parsed = urlparse(address)
    if parsed.scheme != 'snmp':
        error_msg = f"{parsed.scheme.upper()} protocol not supported for ports monitor, use snmp"
        print(f"{prefix}PORTS check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, {}

    # Extract community string - priority: monitor config > URL userinfo > default 'public'
    community = resource.get('community') or parsed.username or 'public'
    hostname = parsed.hostname
    port = parsed.port or 161

    if not hostname:
        error_msg = "ports monitor address must include hostname"
        print(f"{prefix}PORTS check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, {}

    # IF-MIB OIDs
    OID_IF_DESCR        = '1.3.6.1.2.1.2.2.1.2'    # IF-MIB::ifDescr
    OID_IF_OPER_STATUS  = '1.3.6.1.2.1.2.2.1.8'    # IF-MIB::ifOperStatus
    OID_IF_ADMIN_STATUS = '1.3.6.1.2.1.2.2.1.7'    # IF-MIB::ifAdminStatus

    # Q-BRIDGE-MIB OIDs (RFC 2674)
    # OID tail: <vlan_id>.<6 MAC octets>, value = bridge port number (= ifIndex on most switches)
    OID_DOT1Q_TP_FDB_PORT   = '1.3.6.1.2.1.17.7.1.2.2.1.2'  # dot1qTpFdbPort
    OID_DOT1Q_TP_FDB_STATUS = '1.3.6.1.2.1.17.7.1.2.2.1.3'  # dot1qTpFdbStatus - 3=learned

    # IF-MIB integer -> human-readable status
    OPER_STATUS = {
        '1': 'up', '2': 'down', '3': 'testing',
        '4': 'unknown', '5': 'dormant', '6': 'notPresent', '7': 'lowerLayerDown'
    }
    ADMIN_STATUS = {
        '1': 'up', '2': 'down', '3': 'testing'
    }

    # dot1qTpFdbStatus - only learned MACs are dynamically associated with a port
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

        # Walk all three IF-MIB tables
        descr_items  = session.walk(OID_IF_DESCR)
        oper_items   = session.walk(OID_IF_OPER_STATUS)
        admin_items  = session.walk(OID_IF_ADMIN_STATUS)

    except Exception as e:
        error_msg = f"SNMP walk failed: {e}"
        print(f"{prefix}PORTS check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, {}

    # Index by interface index
    descr_by_index = {item.oid.split('.')[-1]: item.value for item in descr_items}
    oper_by_index  = {item.oid.split('.')[-1]: item.value for item in oper_items}
    admin_by_index = {item.oid.split('.')[-1]: item.value for item in admin_items}

    if not descr_by_index:
        error_msg = "no interfaces found"
        print(f"{prefix}PORTS check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, {}

    # Build ifIndex -> sorted list of learned MAC addresses from dot1qTpFdbTable
    # OID tail is 7 octets: <vlan_id>.<6 MAC octets>
    # Value is bridge port number, which equals ifIndex directly on most switches
    macs_by_ifindex: Dict[str, list] = {}
    try:
        fdb_port_items   = session.walk(OID_DOT1Q_TP_FDB_PORT)
        fdb_status_items = session.walk(OID_DOT1Q_TP_FDB_STATUS)

        # Index status by 7-octet OID tail for O(1) lookup
        fdb_status_by_oid = {
            '.'.join(item.oid.split('.')[-7:]): item.value
            for item in fdb_status_items
        }

        for item in fdb_port_items:
            oid_tail    = '.'.join(item.oid.split('.')[-7:])  # e.g. "1.36.90.76.31.80.156"
            mac_octets  = oid_tail.split('.')[1:]             # strip vlan_id, keep 6 MAC octets
            if_index    = item.value                          # = ifIndex directly on this switch

            # Only include learned MACs (status=3); skip self, mgmt, invalid, other
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
        # Non-fatal: proceed without MAC data
        if VERBOSE:
            print(f"{prefix}PORTS Q-BRIDGE FDB walk failed for '{name}' (MACs unavailable): {e}")

    # Build current state - numeric sort on interface index
    current_ports_state = {}
    for if_index in sorted(descr_by_index.keys(), key=lambda x: int(x)):
        oper_raw  = oper_by_index.get(if_index, '4')   # default: unknown
        admin_raw = admin_by_index.get(if_index, '2')  # default: down
        macs      = sorted(macs_by_ifindex.get(if_index, []))  # sorted for stable set comparison
        current_ports_state[if_index] = {
            'name':  descr_by_index[if_index],
            'oper':  OPER_STATUS.get(oper_raw, oper_raw),
            'admin': ADMIN_STATUS.get(admin_raw, admin_raw),
            'macs':  macs,
        }

    if VERBOSE:
        print(f"{prefix}PORTS poll SUCCESS for '{name}': {len(current_ports_state)} interfaces found")
        for if_index, iface in current_ports_state.items():
            mac_str = ', '.join(iface['macs']) if iface['macs'] else 'none'
            print(f"{prefix}  Interface {if_index} ({iface['name']}): oper={iface['oper']} admin={iface['admin']} macs=[{mac_str}]")

    return None, current_ports_state


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

    prefix = getattr(thread_local, 'prefix', '')
    address = resource['address']
    name = resource['name']
    if_index = str(resource['port'])  # ifIndex as string for OID suffix
    pinned_mac = resource['mac'].upper()
    always_up = to_natural_language_boolean(resource.get('always_up', False))

    # Parse SNMP transport config
    parsed = urlparse(address)
    community = resource.get('community') or parsed.username or 'public'
    hostname = parsed.hostname
    port = parsed.port or 161

    if not hostname:
        error_msg = "port monitor address must include hostname"
        print(f"{prefix}PORT check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, None, None

    # IF-MIB OIDs
    OID_IF_DESCR        = '1.3.6.1.2.1.2.2.1.2'   # IF-MIB::ifDescr
    OID_IF_OPER_STATUS  = '1.3.6.1.2.1.2.2.1.8'   # IF-MIB::ifOperStatus
    OID_IF_ADMIN_STATUS = '1.3.6.1.2.1.2.2.1.7'   # IF-MIB::ifAdminStatus
    OID_IF_IN_OCTETS    = '1.3.6.1.2.1.2.2.1.10'  # IF-MIB::ifInOctets
    OID_IF_OUT_OCTETS   = '1.3.6.1.2.1.2.2.1.16'  # IF-MIB::ifOutOctets
    OID_IF_IN_ERRORS    = '1.3.6.1.2.1.2.2.1.14'  # IF-MIB::ifInErrors
    OID_IF_OUT_ERRORS   = '1.3.6.1.2.1.2.2.1.20'  # IF-MIB::ifOutErrors

    # Interface packet counters (high-capacity 64-bit) — same OIDs as check_snmp_resource
    OID_IF_HC_IN_UCAST_PKTS  = '1.3.6.1.2.1.31.1.1.1.7'   # IF-MIB::ifHCInUcastPkts
    OID_IF_HC_IN_MCAST_PKTS  = '1.3.6.1.2.1.31.1.1.1.8'   # IF-MIB::ifHCInMulticastPkts
    OID_IF_HC_IN_BCAST_PKTS  = '1.3.6.1.2.1.31.1.1.1.9'   # IF-MIB::ifHCInBroadcastPkts
    OID_IF_HC_OUT_UCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.11'  # IF-MIB::ifHCOutUcastPkts
    OID_IF_HC_OUT_MCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.12'  # IF-MIB::ifHCOutMulticastPkts
    OID_IF_HC_OUT_BCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.13'  # IF-MIB::ifHCOutBroadcastPkts

    # Q-BRIDGE-MIB OIDs (RFC 2674) — same semantics as check_ports_resource
    # OID tail: <vlan_id>.<6 MAC octets>, value = bridge port number (= ifIndex on this switch family)
    OID_DOT1Q_TP_FDB_PORT   = '1.3.6.1.2.1.17.7.1.2.2.1.2'  # dot1qTpFdbPort
    OID_DOT1Q_TP_FDB_STATUS = '1.3.6.1.2.1.17.7.1.2.2.1.3'  # dot1qTpFdbStatus - 3=learned

    OPER_STATUS = {
        '1': 'up', '2': 'down', '3': 'testing',
        '4': 'unknown', '5': 'dormant', '6': 'notPresent', '7': 'lowerLayerDown'
    }
    ADMIN_STATUS = {'1': 'up', '2': 'down', '3': 'testing'}
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
        oper  = OPER_STATUS.get(oper_raw, oper_raw)
        admin = ADMIN_STATUS.get(admin_raw, admin_raw)

        if VERBOSE:
            print(f"{prefix}PORT poll ifIndex={if_index}: oper={oper} admin={admin}")

    except Exception as e:
        error_msg = f"SNMP failed: {e}"
        print(f"{prefix}PORT check FAILED for '{name}': {error_msg}", file=sys.stderr)
        return error_msg, None, None

    # MAC walk — non-fatal, mirrors check_ports_resource pattern
    # dot1dTpFdbTable returns 0 entries on VLAN-aware switches; Q-BRIDGE-MIB is correct
    current_mac = None
    try:
        fdb_port_items   = session.walk(OID_DOT1Q_TP_FDB_PORT)
        fdb_status_items = session.walk(OID_DOT1Q_TP_FDB_STATUS)

        # Index status by 7-octet OID tail for O(1) lookup
        fdb_status_by_oid = {
            '.'.join(item.oid.split('.')[-7:]): item.value
            for item in fdb_status_items
        }

        for item in fdb_port_items:
            oid_tail     = '.'.join(item.oid.split('.')[-7:])  # e.g. "1.36.90.76.31.80.156"
            mac_octets   = oid_tail.split('.')[1:]             # strip vlan_id, keep 6 MAC octets
            port_ifindex = item.value                          # = ifIndex directly on this switch family

            if port_ifindex != if_index:
                continue
            if fdb_status_by_oid.get(oid_tail) != FDB_STATUS_LEARNED:
                continue
            if len(mac_octets) != 6:
                continue

            current_mac = ':'.join(f'{int(o):02X}' for o in mac_octets)
            break  # one MAC per pinned port; take first learned

        if VERBOSE:
            print(f"{prefix}PORT mac on ifIndex={if_index}: {current_mac or 'none'} (pinned={pinned_mac})")

    except Exception as e:
        # Non-fatal: proceed with current_mac=None, consistent with check_ports_resource MAC walk failure
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
        # always_up=False: alarm only when a non-pinned MAC is present on the port
        if current_mac is not None and current_mac != pinned_mac:
            return f"port ifIndex={if_index} wrong MAC: expected {pinned_mac}, got {current_mac}", oper, current_mac

    # Collect SNMP metrics for this single interface and update RRD (identical schema to snmp monitor)
    if RRD_ENABLED:
        check_every_n_secs = resource.get('check_every_n_secs', DEFAULT_CHECK_EVERY_N_SECS)
        rrd_path = get_rrd_path(name, 'snmp')

        # Single-entry interfaces dict — reuses create/update_snmp_rrd unchanged
        try:
            if_name = session.get(f"{OID_IF_DESCR}.{if_index}").value
        except Exception:
            if_name = f"if{if_index}"
        interfaces = {if_index: {'name': if_name}}

        # Poll byte counters
        try:
            octets_in = int(session.get(f"{OID_IF_IN_OCTETS}.{if_index}").value)
            interfaces[if_index]['in_octets'] = octets_in
        except Exception:
            interfaces[if_index]['in_octets'] = None
            octets_in = 0

        try:
            octets_out = int(session.get(f"{OID_IF_OUT_OCTETS}.{if_index}").value)
            interfaces[if_index]['out_octets'] = octets_out
        except Exception:
            interfaces[if_index]['out_octets'] = None
            octets_out = 0

        try:
            interfaces[if_index]['in_errors'] = int(session.get(f"{OID_IF_IN_ERRORS}.{if_index}").value)
        except Exception:
            interfaces[if_index]['in_errors'] = None

        try:
            interfaces[if_index]['out_errors'] = int(session.get(f"{OID_IF_OUT_ERRORS}.{if_index}").value)
        except Exception:
            interfaces[if_index]['out_errors'] = None

        # Packet counters — accumulate ucast/bmcast in/out separately for aggregate DS
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

        # Auto-heal: recreate if DS count < expected OR any RRA has fewer rows than configured.
        # 1 interface → expected DS = 2*1 + 11 = 13
        rras = create_rrd_rras(check_every_n_secs)
        if os.path.exists(rrd_path):
            expected_ds_count = 2 * len(interfaces) + 11
            needs_recreation = False
            try:
                info = rrdtool.info(rrd_path)
                actual_ds_count = len([k for k in info if k.startswith('ds[') and k.endswith('].type')])
                if actual_ds_count < expected_ds_count:
                    print(f"{prefix}PORT RRD deleted for recreation: {rrd_path} "
                          f"(ds_count={actual_ds_count} < expected={expected_ds_count})")
                    needs_recreation = True
            except Exception as e:
                print(f"{prefix}PORT RRD introspection failed for '{rrd_path}': {e}, will recreate", file=sys.stderr)
                needs_recreation = True

            if not needs_recreation and _check_rrd_needs_recreation(rrd_path, rras):
                print(f"{prefix}PORT RRD deleted for recreation: {rrd_path} (RRA rows under-provisioned)")
                needs_recreation = True

            if needs_recreation:
                os.remove(rrd_path)

        if not os.path.exists(rrd_path):
            create_snmp_rrd(rrd_path, check_every_n_secs, interfaces)
            if VERBOSE:
                print(f"{prefix}Created PORT RRD: {rrd_path}")

        rrd_err = update_snmp_rrd(
            rrd_path, datetime.now(), interfaces, None,
            total_bits_in, total_bits_out, total_pkts_in, total_pkts_out,
            0, 0, None, None,
            total_pkts_ucast, total_pkts_bmcast,
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
            error_msg = check_ping_resource(resource)
            ports_state = None
        elif resource['type'] == 'snmp':
            error_msg = check_snmp_resource(resource)
            ports_state = None
        elif resource['type'] == 'ports':
            error_msg, ports_state = check_ports_resource(resource)
        elif resource['type'] == 'port':
            error_msg, oper, mac = check_port_resource(resource)
            ports_state = {'oper': oper, 'mac': mac}
        elif resource['type'] in ('http', 'quic', 'tcp', 'udp'):
            error_msg = check_url_resource(resource)
            ports_state = None
        else:
            raise ConfigError(f"Unknown resource type: {resource['type']} for monitor {resource['name']}")

        end_time_ms = int(time.time() * 1000)
        response_time_ms = end_time_ms - start_time_ms

        if error_msg is None:
            last_response_time_ms = response_time_ms
            return None, last_response_time_ms, ports_state

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


def get_rrd_path(monitor_name: str, metric_type: str = 'availability') -> str:
    """Generate filesystem-safe RRD file path for a monitor.

    Args:
        monitor_name: Name of the monitor
        metric_type: Type of metrics ('availability' or 'snmp')

    Returns:
        str: Full path to RRD file
    """
    safe_name = re.sub(r'[^\w\-.]', '_', monitor_name)

    base_path = Path(STATEFILE)
    rrd_dir = base_path.parent / (base_path.stem + '.rrd')

    return str(rrd_dir / f"{safe_name}-{metric_type}.rrd")


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
    """Create RRD file for SNMP interface metrics and system resources.

    Args:
        rrd_path: Full path to RRD file to create
        step_secs: Update interval in seconds
        interfaces: Dict mapping interface index to interface data (with 'name' key)

    NB: existing SNMP RRDs must be deleted before next run whenever DS layout changes.
    """
    global RRD_ELAPSED_MS
    prefix = getattr(thread_local, 'prefix', '')

    # Ensure RRD directory exists
    os.makedirs(os.path.dirname(rrd_path), exist_ok=True)

    # Calculate heartbeat (2x step allows one missed update)
    heartbeat = step_secs * 2

    # Build data sources dynamically for each interface
    data_sources = []

    for if_index, if_data in interfaces.items():
        # Use interface index as DS name base (guarantees uniqueness)
        safe_if_name = f"if{if_index}"

        # COUNTER type for cumulative byte counters (handles wraps at 32/64-bit boundaries)
        data_sources.append(f'DS:{safe_if_name}_in:COUNTER:{heartbeat}:0:U')
        data_sources.append(f'DS:{safe_if_name}_out:COUNTER:{heartbeat}:0:U')

    # Add TCP retransmit counter
    data_sources.append(f'DS:tcp_retrans:COUNTER:{heartbeat}:0:U')

    # Add aggregate interface metrics (COUNTER for cumulative values)
    data_sources.append(f'DS:total_bits_in:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_bits_out:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_pkts_in:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_pkts_out:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_errors_in:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_errors_out:COUNTER:{heartbeat}:0:U')

    # Unicast vs broadcast+multicast packet type split (in+out combined)
    data_sources.append(f'DS:total_pkts_ucast:COUNTER:{heartbeat}:0:U')
    data_sources.append(f'DS:total_pkts_bmcast:COUNTER:{heartbeat}:0:U')

    # Add system resource metrics (GAUGE for instantaneous values)
    data_sources.append(f'DS:cpu_load:GAUGE:{heartbeat}:0:100')  # Percentage 0-100
    data_sources.append(f'DS:memory_pct:GAUGE:{heartbeat}:0:100')  # Percentage 0-100

    # Generate RRAs
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
            print(f"{prefix}Created SNMP RRD file: {rrd_path} (step={step_secs}s, {len(interfaces)} interfaces, {len(data_sources)} data sources)")
    except rrdtool.OperationalError as e:
        print(f"{prefix}Failed to create SNMP RRD file '{rrd_path}': {e}", file=sys.stderr)


def update_snmp_rrd(rrd_path: str, timestamp: datetime, interfaces: Dict[str, Dict[str, Any]],
                    tcp_retrans: Optional[int], total_bits_in: int, total_bits_out: int,
                    total_pkts_in: int, total_pkts_out: int,
                    total_errors_in: int, total_errors_out: int,
                    cpu_load: Optional[float], memory_pct: Optional[float],
                    total_pkts_ucast: int = 0, total_pkts_bmcast: int = 0) -> Optional[str]:
    """Update SNMP RRD file with latest interface metrics and system resources.

    Args:
        rrd_path: Full path to RRD file
        timestamp: Timestamp of the measurement
        interfaces: Dict mapping interface index to metrics (with 'in_octets', 'out_octets')
        tcp_retrans: TCP retransmit segments counter
        total_bits_in: Aggregate inbound bits across all interfaces
        total_bits_out: Aggregate outbound bits across all interfaces
        total_pkts_in: Aggregate inbound packets across all interfaces
        total_pkts_out: Aggregate outbound packets across all interfaces
        total_errors_in: Aggregate inbound errors across all interfaces
        total_errors_out: Aggregate outbound errors across all interfaces
        cpu_load: Average CPU utilization percentage (0-100)
        memory_pct: Memory utilization percentage (0-100)
        total_pkts_ucast: Total unicast packets (in+out combined)
        total_pkts_bmcast: Total broadcast+multicast packets (in+out combined)
    """
    global RRD_ELAPSED_MS
    prefix = getattr(thread_local, 'prefix', '')

    # Convert to epoch timestamp
    epoch = int(timestamp.timestamp())

    # Build template string (DS names in order)
    ds_names = []
    values = []

    for if_index in sorted(interfaces.keys()):  # Stable sort for deterministic DS order
        if_data = interfaces[if_index]
        safe_if_name = f"if{if_index}"

        ds_names.append(f'{safe_if_name}_in')
        ds_names.append(f'{safe_if_name}_out')

        in_octets = if_data.get('in_octets')
        out_octets = if_data.get('out_octets')

        values.append(str(in_octets) if in_octets is not None else 'U')
        values.append(str(out_octets) if out_octets is not None else 'U')

    # Add TCP retransmit
    ds_names.append('tcp_retrans')
    values.append(str(tcp_retrans) if tcp_retrans is not None else 'U')

    # Add aggregate metrics
    ds_names.append('total_bits_in')
    values.append(str(total_bits_in))

    ds_names.append('total_bits_out')
    values.append(str(total_bits_out))

    ds_names.append('total_pkts_in')
    values.append(str(total_pkts_in))

    ds_names.append('total_pkts_out')
    values.append(str(total_pkts_out))

    ds_names.append('total_errors_in')
    values.append(str(total_errors_in))

    ds_names.append('total_errors_out')
    values.append(str(total_errors_out))

    # Add packet type split
    ds_names.append('total_pkts_ucast')
    values.append(str(total_pkts_ucast))

    ds_names.append('total_pkts_bmcast')
    values.append(str(total_pkts_bmcast))

    # Add system resources
    ds_names.append('cpu_load')
    values.append(f'{cpu_load:.2f}' if cpu_load is not None else 'U')

    ds_names.append('memory_pct')
    values.append(f'{memory_pct:.2f}' if memory_pct is not None else 'U')

    template = ':'.join(ds_names)
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
            print(f"{prefix}Updated SNMP RRD: {rrd_path} @ {epoch} ({len(interfaces)} interfaces, aggregates, system)")
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

    # Skip if check not due
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

    # Check resource and ping heartbeat URL
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

    # Ping heartbeat URL if required
    if is_up and 'heartbeat_url' in resource:
        should_heartbeat, seconds_since_heartbeat = is_heartbeat_due(resource, prev_last_successful_heartbeat, now)

        if should_heartbeat:
            if ping_heartbeat_url(resource['heartbeat_url'], resource['name'], site_config['name']):
                last_successful_heartbeat = datetime.now().isoformat()
        elif VERBOSE:
            print(f"{prefix}skipping heartbeat for {resource['name']} (heartbeat sent {format_time_ago(prev_last_successful_heartbeat)} ago)")

    # Handle ports monitor diff/notify logic
    if resource['type'] == 'ports' and is_up and current_ports_state:
        if prev_ports_state is None:
            # First poll - establish baseline, no alerts
            if VERBOSE:
                print(f"{prefix}PORTS baseline established for '{resource['name']}': {len(current_ports_state)} interfaces")
        else:
            # Collect all interface indices across both states - numeric sort
            all_indices = set(prev_ports_state.keys()) | set(current_ports_state.keys())

            for if_index in sorted(all_indices, key=lambda x: int(x)):
                prev_iface = prev_ports_state.get(if_index)
                curr_iface = current_ports_state.get(if_index)

                def _notify(msg: str) -> None:
                    """Fire notification and advance throttle state."""
                    if monitor_email_enabled and 'outage_emails' in site_config:
                        for email_entry in site_config['outage_emails']:
                            notify_resource_outage_with_email(
                                email_entry, site_config['name'], msg, site_config, 'outage')
                    if 'outage_webhooks' in site_config:
                        for webhook in site_config['outage_webhooks']:
                            notify_resource_outage_with_webhook(webhook, site_config['name'], msg)

                # --- Status change detection ---
                def _status_tuple(iface):
                    """Comparable status fields, excluding macs."""
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

                # --- MAC change detection (only when interface exists both sides) ---
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

    # Normal up/down/recovery logic (all types except 'ports')
    else:
        # Calculate new down_count, last_alarm_started, and last_notified
        if is_up:
            # Check if this is a transition from down to up
            if not prev_is_up:
                # Calculate outage duration
                outage_duration = format_time_ago(prev_last_alarm_started)

                # Send recovery notification
                recovery_message = f"{resource['name']} in {site_config['name']} is UP ({resource['address']}) at {timestamp_str}, outage lasted {outage_duration}"
                print(f"{prefix}##### RECOVERY: {recovery_message} #####", file=sys.stderr)

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
            # Set last_alarm_started on fresh DOWN transition, preserve on continued DOWN
            if prev_is_up:  # Fresh transition from UP to DOWN
                last_alarm_started = now.isoformat()
                prev_last_notified = None
                prev_notified_count = 0
            else:  # Resource was already down, preserve existing alarm start time
                last_alarm_started = prev_last_alarm_started

            if prev_is_up:
                error_message = f"{resource['name']} in {site_config['name']} new outage: {error_reason} ({resource['address']}) at {timestamp_str}, down for {format_time_ago(last_alarm_started)}"
                print(f"{prefix}##### NEW OUTAGE: {error_message} #####", file=sys.stderr)
            else:
                error_message = f"{resource['name']} in {site_config['name']} is down: {error_reason} ({resource['address']}) at {timestamp_str}, down for {format_time_ago(last_alarm_started)}"
                print(f"{prefix}##### DOWN: {error_message} #####", file=sys.stderr)

            should_notify = True

            # Calculate seconds since first notification of current outage
            secs_since_first_notification = 0
            if last_alarm_started:
                try:
                    alarm_started_time = datetime.fromisoformat(last_alarm_started)
                    secs_since_first_notification = (now - alarm_started_time).total_seconds()
                except:
                    secs_since_first_notification = 0

            # Calculate should_notify & next_notification_delay_secs
            next_notification_delay_secs = calc_next_notification_delay_secs(notify_every_n_secs, after_every_n_notifications, secs_since_first_notification, prev_notified_count)
            seconds_since_notify = False
            if prev_last_notified:
                try:
                    last_notified_time = datetime.fromisoformat(prev_last_notified)
                    seconds_since_notify = (now - last_notified_time).total_seconds()
                    should_notify = seconds_since_notify >= next_notification_delay_secs
                except:
                    should_notify = True

            if should_notify:
                # Determine notification type (first notification is 'outage', subsequent are 'reminder')
                notification_type = 'outage' if prev_notified_count == 0 else 'reminder'

                # Send outage notifications
                if monitor_email_enabled and 'outage_emails' in site_config:
                    for email_entry in site_config['outage_emails']:
                        notify_resource_outage_with_email(email_entry, site_config['name'], error_message, site_config, notification_type)

                if 'outage_webhooks' in site_config:
                    for webhook in site_config['outage_webhooks']:
                        notify_resource_outage_with_webhook(webhook, site_config['name'], error_message)

                # Record notification time and increment count
                last_notified = now.isoformat()
                notified_count = prev_notified_count + 1
            else:
                if VERBOSE:
                    if not seconds_since_notify:
                        print(f"{prefix}skipping {resource['name']} notification (notified {format_time_ago(prev_last_notified)} ago)")
                    else:
                        time_until_next_secs = next_notification_delay_secs - seconds_since_notify
                        print(f"{prefix}skipping {resource['name']} notification for {format_time_ago(time_until_next_secs)} (notified {format_time_ago(prev_last_notified)} ago)")

                # Keep previous notification time and count
                last_notified = prev_last_notified
                notified_count = prev_notified_count

    # Update RRD database for MRTG (availability monitors only)
    if RRD_ENABLED and resource['type'] not in ('snmp'):
        rrd_path = get_rrd_path(resource['name'])
        rras = create_rrd_rras(check_every_n_secs)

        # Auto-heal: recreate if any RRA has fewer rows than configured
        if os.path.exists(rrd_path) and _check_rrd_needs_recreation(rrd_path, rras):
            print(f"{prefix}Availability RRD deleted for recreation: {rrd_path} (RRA rows under-provisioned)")
            os.remove(rrd_path)

        if VERBOSE > 1:
            print(f"{prefix}updating RRD database for {rrd_path} w/ {now}, {last_response_time_ms}, {is_up}")
        if not os.path.exists(rrd_path):
            create_rrd(rrd_path, check_every_n_secs)
        update_rrd(rrd_path, now, last_response_time_ms, is_up)

    # Update state for this resource
    new_state = {
        'is_up': is_up,
        'last_checked': now.isoformat(),
        'last_response_time_ms': last_response_time_ms,
        'last_successful_heartbeat': last_successful_heartbeat,
        'error_reason': error_reason,
        'last_config_checksum': resource_checksum,
    }

    # Persist ports baseline for next poll
    if resource['type'] == 'ports' and current_ports_state:
        new_state['ports_state'] = current_ports_state
    else:
        new_state['down_count'] = down_count
        new_state['last_alarm_started'] = prev_last_alarm_started if is_up else last_alarm_started
        new_state['last_notified'] = last_notified if is_up else (last_notified if should_notify else prev_last_notified)
        new_state['notified_count'] = notified_count

    update_state({resource['name']: new_state})


def get_default_statefile() -> str:
    """Get platform-appropriate default statefile location."""
    system = platform.system().lower()

    if system in ['linux', 'darwin', 'freebsd', 'openbsd', 'netbsd']:
        # Unix-like: /var/tmp persists across reboots
        return '/var/tmp/apmonitor-statefile.json'
    elif system == 'windows':
        # Windows: Use TEMP directory
        temp_dir = os.environ.get('TEMP', os.environ.get('TMP', 'C:\\Temp'))
        return os.path.join(temp_dir, 'apmonitor-statefile.json')
    else:
        # Unknown platform: Use current directory as safe fallback
        return './apmonitor-statefile.json'


def check_and_heartbeat(resource: Dict[str, Any], site_config: Dict[str, Any]) -> None:

    return check_and_heartbeat_r(resource, site_config)


def create_pid_file_or_exit_on_unix(config_path: str) -> Optional[str]:
    """Create PID lockfile on Unix-like systems. Returns lockfile path or None."""
    system = platform.system().lower()

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


def generate_mrtg_config(config: Dict[str, Any], work_dir: str, mrtg_config_path: str) -> None:
    """Generate MRTG configuration from APMonitor config with atomic file rotation.

    Args:
        config: APMonitor configuration dict
        work_dir: MRTG working directory (where graphs will be generated)
        mrtg_config_path: Path to MRTG config file (will use .new/.old rotation)
    """
    prefix = getattr(thread_local, 'prefix', '')

    # Build MRTG config content
    mrtg_lines = [
        "# MRTG Configuration - Generated by APMonitor",
        f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"WorkDir: {work_dir}",
        "LogFormat: rrdtool",
        "Options[_]: growright,bits",
        "WriteExpires: Yes",
        "",
    ]

    for resource in config['monitors']:
        safe_name = re.sub(r'[^\w\-.]', '_', resource['name'])
        monitor_type = resource['type']

        # Skip monitors explicitly excluded from MRTG display (monitoring continues unaffected)
        if not to_natural_language_boolean(resource.get('display', True)):
            continue

        if monitor_type in ('snmp', 'port'):
            rrd_path = get_rrd_path(resource['name'], 'snmp')
            percentile = resource.get('percentile') if monitor_type == 'snmp' else None

            # Prefix monitor name with type for index and graph page identification
            display_name = f"{monitor_type}: {resource['name']}"

            # Target 1: Bandwidth (total_bits_in / total_bits_out)
            mrtg_lines.extend([
                f"######################################################################",
                f"# {display_name} - Total Bandwidth",
                f"",
                f"Target[{safe_name}-bandwidth]: total_bits_in&total_bits_out:{rrd_path}",
                f"MaxBytes[{safe_name}-bandwidth]: 10000000000",  # 10 Gbps max
                f"Title[{safe_name}-bandwidth]: {display_name} - Total Bandwidth",
                f"PageTop[{safe_name}-bandwidth]: <h1>{display_name} ({resource['address']})</h1><h2>Total Bandwidth In/Out</h2>",
                f"Options[{safe_name}-bandwidth]: gauge,nopercent,growright,bits",
                f"YLegend[{safe_name}-bandwidth]: Bits per second",
                f"ShortLegend[{safe_name}-bandwidth]: b/s",
                f"Legend1[{safe_name}-bandwidth]: Total Inbound Traffic",
                f"Legend2[{safe_name}-bandwidth]: Total Outbound Traffic",
                f"LegendI[{safe_name}-bandwidth]: In:",
                f"LegendO[{safe_name}-bandwidth]: Out:",
                f"WithPeak[{safe_name}-bandwidth]: dwmy",
                *([f"Percentile[{safe_name}-bandwidth]: {percentile}"] if percentile else []),
                f"",
            ])

            # Target 2: Packets (total_pkts_in / total_pkts_out)
            mrtg_lines.extend([
                f"######################################################################",
                f"# {display_name} - Total Packets",
                f"",
                f"Target[{safe_name}-packets]: total_pkts_in&total_pkts_out:{rrd_path}",
                f"MaxBytes[{safe_name}-packets]: 10000000",  # 10M pps max
                f"Title[{safe_name}-packets]: {display_name} - Total Packets",
                f"PageTop[{safe_name}-packets]: <h1>{display_name} ({resource['address']})</h1><h2>Total Packets In/Out</h2>",
                f"Options[{safe_name}-packets]: gauge,nopercent,growright",
                f"YLegend[{safe_name}-packets]: Packets per second",
                f"ShortLegend[{safe_name}-packets]: pps",
                f"Legend1[{safe_name}-packets]: Total Inbound Packets",
                f"Legend2[{safe_name}-packets]: Total Outbound Packets",
                f"LegendI[{safe_name}-packets]: In:",
                f"LegendO[{safe_name}-packets]: Out:",
                f"WithPeak[{safe_name}-packets]: dwmy",
                *([f"Percentile[{safe_name}-packets]: {percentile}"] if percentile else []),
                f"",
            ])

            # Target 3: Packet type split (unicast vs broadcast+multicast, in+out combined)
            mrtg_lines.extend([
                f"######################################################################",
                f"# {display_name} - Packet Type Split (Unicast vs Broadcast+Multicast)",
                f"",
                f"Target[{safe_name}-packets-type]: total_pkts_ucast&total_pkts_bmcast:{rrd_path}",
                f"MaxBytes[{safe_name}-packets-type]: 10000000",  # 10M pps max
                f"Title[{safe_name}-packets-type]: {display_name} - Packet Type Split",
                f"PageTop[{safe_name}-packets-type]: <h1>{display_name} ({resource['address']})</h1><h2>Unicast vs Broadcast+Multicast Packets</h2>",
                f"Options[{safe_name}-packets-type]: gauge,nopercent,growright",
                f"YLegend[{safe_name}-packets-type]: Packets per second",
                f"ShortLegend[{safe_name}-packets-type]: pps",
                f"Legend1[{safe_name}-packets-type]: Unicast Packets (in+out)",
                f"Legend2[{safe_name}-packets-type]: Broadcast+Multicast Packets (in+out)",
                f"LegendI[{safe_name}-packets-type]: Ucast:",
                f"LegendO[{safe_name}-packets-type]: B+Mcast:",
                f"WithPeak[{safe_name}-packets-type]: dwmy",
                *([f"Percentile[{safe_name}-packets-type]: {percentile}"] if percentile else []),
                f"",
            ])

            # Target 4: Interface Errors (total_errors_in / total_errors_out)
            mrtg_lines.extend([
                f"######################################################################",
                f"# {display_name} - Interface Errors",
                f"",
                f"Target[{safe_name}-errors]: total_errors_in&total_errors_out:{rrd_path}",
                f"MaxBytes[{safe_name}-errors]: 1000000",
                f"Title[{safe_name}-errors]: {display_name} - Interface Errors",
                f"PageTop[{safe_name}-errors]: <h1>{display_name} ({resource['address']})</h1><h2>Interface Errors In/Out</h2>",
                f"Options[{safe_name}-errors]: gauge,nopercent,growright",
                f"YLegend[{safe_name}-errors]: Errors per second",
                f"ShortLegend[{safe_name}-errors]: err/s",
                f"Legend1[{safe_name}-errors]: Inbound Interface Errors",
                f"Legend2[{safe_name}-errors]: Outbound Interface Errors",
                f"LegendI[{safe_name}-errors]: In Err:",
                f"LegendO[{safe_name}-errors]: Out Err:",
                f"WithPeak[{safe_name}-errors]: dwmy",
                *([f"Percentile[{safe_name}-errors]: {percentile}"] if percentile else []),
                f"",
            ])

            if monitor_type == 'snmp':
                # Target 5: TCP Retransmits (tcp_retrans / tcp_retrans - same DS for both to show single line)
                mrtg_lines.extend([
                    f"######################################################################",
                    f"# {display_name} - TCP Retransmits",
                    f"",
                    f"Target[{safe_name}-retransmits]: tcp_retrans&tcp_retrans:{rrd_path}",
                    f"MaxBytes[{safe_name}-retransmits]: 100000",  # 100k retrans/sec max
                    f"Title[{safe_name}-retransmits]: {display_name} - TCP Retransmits",
                    f"PageTop[{safe_name}-retransmits]: <h1>{display_name} ({resource['address']})</h1><h2>TCP Retransmits</h2>",
                    f"Options[{safe_name}-retransmits]: gauge,nopercent,growright",
                    f"YLegend[{safe_name}-retransmits]: Retransmits per second",
                    f"ShortLegend[{safe_name}-retransmits]: retrans/s",
                    f"Legend1[{safe_name}-retransmits]: TCP Retransmit Segments",
                    f"Legend2[{safe_name}-retransmits]: TCP Retransmit Segments",
                    f"LegendI[{safe_name}-retransmits]: Retrans:",
                    f"LegendO[{safe_name}-retransmits]: Retrans:",
                    f"WithPeak[{safe_name}-retransmits]: dwmy",
                    *([f"Percentile[{safe_name}-retransmits]: {percentile}"] if percentile else []),
                    f"",
                ])

                # Target 6: System (cpu_load / memory_pct)
                mrtg_lines.extend([
                    f"######################################################################",
                    f"# {display_name} - CPU & Memory Utilization",
                    f"",
                    f"Target[{safe_name}-system]: cpu_load&memory_pct:{rrd_path}",
                    f"MaxBytes[{safe_name}-system]: 100",  # Percentage 0-100
                    f"Title[{safe_name}-system]: {display_name} - System Resources",
                    f"PageTop[{safe_name}-system]: <h1>{display_name} ({resource['address']})</h1><h2>CPU & Memory Utilization</h2>",
                    f"Options[{safe_name}-system]: gauge,nopercent,growright",
                    f"YLegend[{safe_name}-system]: Utilization %",
                    f"ShortLegend[{safe_name}-system]: %",
                    f"Legend1[{safe_name}-system]: CPU Load Average",
                    f"Legend2[{safe_name}-system]: Memory Utilization",
                    f"LegendI[{safe_name}-system]: CPU:",
                    f"LegendO[{safe_name}-system]: Memory:",
                    f"WithPeak[{safe_name}-system]: dwmy",
                    *([f"Percentile[{safe_name}-system]: {percentile}"] if percentile else []),
                    f"",
                ])

        else:
            # Non-SNMP monitors (ping, http, quic, tcp, udp) - availability tracking
            rrd_path = get_rrd_path(resource['name'])

            mrtg_lines.extend([
                f"######################################################################",
                f"# {resource['name']} ({resource['type']})",
                f"",
                f"Target[{safe_name}]: response_time&is_up:{rrd_path}",
                f"MaxBytes[{safe_name}]: 100000",
                f"MaxBytes1[{safe_name}]: 100000",  # Response time max (ms)
                f"MaxBytes2[{safe_name}]: 100",  # Availability max (percentage)
                f"Title[{safe_name}]: {resource['name']} - Availability",
                f"PageTop[{safe_name}]: <h1>{resource['name']} ({resource['address']})</h1>",
                f"Options[{safe_name}]: gauge,nopercent,growright,dualaxis",
                f"YLegend[{safe_name}]: Response Time (ms)",
                f"ShortLegend[{safe_name}]:",
                f"Legend1[{safe_name}]: Response Time (ms)",
                f"Legend2[{safe_name}]: Availability (%)",
                f"LegendI[{safe_name}]: Response:",
                f"LegendO[{safe_name}]: Avail:",
                f"WithPeak[{safe_name}]: dwmy",
                f"",
            ])

    config_content = "\n".join(mrtg_lines)

    # Write to .new file
    new_path = Path(mrtg_config_path + '.new')
    old_path = Path(mrtg_config_path + '.old')
    config_path = Path(mrtg_config_path)

    try:
        with open(new_path, 'w') as f:
            f.write(config_content)

        # Atomic rotation: current -> .old, .new -> current
        if config_path.exists():
            os.replace(config_path, old_path)
        os.replace(new_path, config_path)

        if VERBOSE:
            print(f"{prefix}Generated MRTG config: {mrtg_config_path}")

    except Exception as e:
        print(f"{prefix}Failed to generate MRTG config '{mrtg_config_path}': {e}", file=sys.stderr)


def generate_mrtg_index(all_config_files: List[str], index_path: str, site_name: str = "Availability Monitoring", state: Dict[str, Any] = None, hidden_monitors: Optional[List[Dict[str, Any]]] = None) -> None:
    """Generate index.html with Network Monitoring (SNMP) and Availability Monitoring sections using atomic file rotation.

    Args:
        all_config_files: List of paths to MRTG config files
        index_path: Full path to index.html file to create (will use .new/.old rotation)
        site_name: Site name for page heading (from APMonitor config)
        state: APMonitor state dict for outage highlighting (optional)
        hidden_monitors: List of monitor dicts with display=false — shown in audit footer only (optional)
    """
    prefix = getattr(thread_local, 'prefix', '')

    # Collect all monitors from all config files
    all_monitors = []
    snmp_monitors = {}  # Dict to deduplicate SNMP monitors by base name

    for config_file in all_config_files:
        if not os.path.exists(config_file):
            if VERBOSE:
                print(f"{prefix}Warning: Config file not found: {config_file}, skipping")
            continue

        try:
            # Parse MRTG config to extract targets
            with open(config_file, 'r') as f:
                content = f.read()

            # Find all Target[name]: entries
            target_pattern = r'Target\[([^\]]+)\]:'
            targets = re.findall(target_pattern, content)

            for target_name in targets:
                # Extract metadata for this target
                title_match = re.search(rf'Title\[{re.escape(target_name)}\]:\s*(.+)', content)
                pagetop_match = re.search(rf'PageTop\[{re.escape(target_name)}\]:\s*<h1>([^<]+)\s*\(([^)]+)\)</h1>', content)

                monitor_info = {
                    'name': target_name,
                    'title': title_match.group(1).strip() if title_match else target_name,
                    'type': 'monitor',
                    'address': ''
                }

                if pagetop_match:
                    monitor_info['title'] = pagetop_match.group(1).strip()
                    monitor_info['address'] = pagetop_match.group(2).strip()

                # Check if this is an SNMP target by known suffixes
                snmp_suffixes = (
                    '-bandwidth', '-packets', '-packets-type',
                    '-retransmits', '-system', '-errors',
                )
                if any(target_name.endswith(s) for s in snmp_suffixes):
                    # Strip the matching suffix to get the base name
                    base_name = target_name
                    for s in snmp_suffixes:
                        if target_name.endswith(s):
                            base_name = target_name[:-len(s)]
                            break

                    # Store metadata once per base name; accumulate target set for cell gating.
                    # Insertion order is preserved (Python 3.7+ dict) — display order follows
                    # config file order, which is controlled by the user via the monitors: list.
                    if base_name not in snmp_monitors:
                        monitor_info['targets'] = set()
                        snmp_monitors[base_name] = monitor_info
                    snmp_monitors[base_name]['targets'].add(target_name)
                else:
                    # Regular availability monitor
                    all_monitors.append(monitor_info)

        except Exception as e:
            print(f"{prefix}Warning: Failed to parse config file '{config_file}': {e}", file=sys.stderr)
            continue

    if not all_monitors and not snmp_monitors:
        print(f"{prefix}Warning: No monitors found in any config files", file=sys.stderr)
        return

    # Build world clock display for header
    world_clocks = [
        ('California',  'America/Los_Angeles'),
        ('New York',    'America/New_York'),
        ('London',      'Europe/London'),
        ('Amsterdam',   'Europe/Amsterdam'),
        ('Mumbai',      'Asia/Kolkata'),
        ('Tokyo',       'Asia/Tokyo'),
        ('Melbourne',   'Australia/Melbourne'),
    ]

    # zoneinfo available Python 3.9+; fallback to UTC if unavailable
    try:
        from zoneinfo import ZoneInfo
        def _fmt_tz(tz_name: str, fmt: str) -> str:
            return datetime.now(ZoneInfo(tz_name)).strftime(fmt).lstrip('0') or '12'
    except ImportError:
        def _fmt_tz(tz_name: str, fmt: str) -> str:
            return datetime.utcnow().strftime(fmt).lstrip('0') or '12'

    local_time_str = _fmt_tz('Australia/Melbourne', '%a %I:%M %p')
    world_clock_parts = ' &nbsp;&nbsp; '.join(
        f"{city}: <b>{_fmt_tz(tz, '%I:%M %p')}</b>"
        for city, tz in world_clocks
    )

    # Build HTML content
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
        "        .network-row { display: grid; gap: 20px; margin-bottom: 20px; }",
        "        .network-cell { background: white; padding: 8px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }",
        "        .network-cell.down { background: #ffe8e8; }",
        "        .network-cell h4 { margin-top: 0; margin-bottom: 4px; font-size: 11px; color: #666; text-align: center; }",
        "        .network-cell a { display: block; text-align: center; }",
        "        .network-cell img { max-width: 100%; height: auto; max-height: 80px; }",
        # port-label-row: same grid as the chart row below it, labels sit in col 1 and col 5
        "        .port-label-row { display: grid; gap: 20px; margin-bottom: 4px; }",
        "        .port-label-cell { display: flex; align-items: flex-end; }",
        "        .port-label-spacer { visibility: hidden; }",
        "        .header-clock { position: absolute; top: 0; right: 0; text-align: right; padding: 6px 12px; }",
        "        .header-clock-main { font-size: 36px; font-weight: bold; color: #333; }",
        "        .header-clock-world { font-size: 20px; color: #999; margin-top: 4px; }",
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

    def _emit_snmp_row(base_name: str, monitor: Dict[str, Any]) -> None:
        """Emit one snmp monitor row (label + network-row grid)."""
        targets = monitor.get('targets', set())
        has_retransmits = f"{base_name}-retransmits" in targets
        has_system      = f"{base_name}-system"      in targets

        col_count = 4 + int(has_retransmits) + int(has_system)
        col_narrow = min(col_count, 3)
        col_style = f"repeat({col_count}, 1fr); --cols-narrow: {col_narrow}"

        plain_name = re.sub(r'^[^:]+:\s*', '', monitor['title'])
        monitor_state = state.get(plain_name, {}) if state else {}
        is_down = not monitor_state.get('is_up', True)
        label_class = "network-host-label down" if is_down else "network-host-label"
        cell_class  = "network-cell down" if is_down else "network-cell"
        outage_str = f" &nbsp;<span style='font-weight: normal; font-size: 13px;'>Down {format_time_ago(monitor_state.get('last_alarm_started'))}</span>" if is_down else ""

        html_lines.extend([
            f"    <div class='{label_class}'>{monitor['title']}{outage_str}</div>",
            f"    <div class='network-row' style='grid-template-columns: {col_style};'>",
            f"        <div class='{cell_class}'>",
            "            <h4>Total Bandwidth In/Out</h4>",
            f"            <a href='/mrtg-rrd/{base_name}-bandwidth.html'>",
            f"                <img src='/mrtg-rrd/{base_name}-bandwidth-day.png' alt='{monitor['title']} Bandwidth'>",
            "            </a>",
            "        </div>",
            f"        <div class='{cell_class}'>",
            "            <h4>Total Packets In/Out</h4>",
            f"            <a href='/mrtg-rrd/{base_name}-packets.html'>",
            f"                <img src='/mrtg-rrd/{base_name}-packets-day.png' alt='{monitor['title']} Packets'>",
            "            </a>",
            "        </div>",
            f"        <div class='{cell_class}'>",
            "            <h4>Unicast vs B+Mcast Packets</h4>",
            f"            <a href='/mrtg-rrd/{base_name}-packets-type.html'>",
            f"                <img src='/mrtg-rrd/{base_name}-packets-type-day.png' alt='{monitor['title']} Packet Types'>",
            "            </a>",
            "        </div>",
            f"        <div class='{cell_class}'>",
            "            <h4>Interface Errors In/Out</h4>",
            f"            <a href='/mrtg-rrd/{base_name}-errors.html'>",
            f"                <img src='/mrtg-rrd/{base_name}-errors-day.png' alt='{monitor['title']} Errors'>",
            "            </a>",
            "        </div>",
            *([
                f"        <div class='{cell_class}'>",
                "            <h4>TCP Retransmits</h4>",
                f"            <a href='/mrtg-rrd/{base_name}-retransmits.html'>",
                f"                <img src='/mrtg-rrd/{base_name}-retransmits-day.png' alt='{monitor['title']} TCP Retransmits'>",
                "            </a>",
                "        </div>",
            ] if has_retransmits else []),
            *([
                f"        <div class='{cell_class}'>",
                "            <h4>CPU & Memory</h4>",
                f"            <a href='/mrtg-rrd/{base_name}-system.html'>",
                f"                <img src='/mrtg-rrd/{base_name}-system-day.png' alt='{monitor['title']} System'>",
                "            </a>",
                "        </div>",
            ] if has_system else []),
            "    </div>",
        ])

    def _emit_port_group(run: List[Tuple[str, Dict[str, Any]]]) -> None:
        """Emit a contiguous run of port monitors as a single grid (8-up or 4-up).

        Layout: label row + chart row share the same column grid so labels sit
        directly above their respective 4-cell blocks on the grey background.

        Label row columns:
          - col 1: monitor name label
          - cols 2-4: invisible spacers (maintain grid alignment)
          - col 5 (if 2nd monitor): monitor name label
          - cols 6-8: invisible spacers
        """
        col_count = 8 if len(run) >= 2 else 4
        col_narrow = min(col_count, 4)
        col_style = f"repeat({col_count}, 1fr); --cols-narrow: {col_narrow}"

        port_targets = [
            ('-bandwidth',    'Bandwidth In/Out'),
            ('-packets',      'Packets In/Out'),
            ('-packets-type', 'Unicast vs B+Mcast'),
            ('-errors',       'Errors In/Out'),
        ]

        # --- label row: one cell per column, labels at col 1 and col 5 ---
        html_lines.append(f"    <div class='port-label-row' style='grid-template-columns: {col_style};'>")
        for base_name, monitor in run:
            plain_name = re.sub(r'^[^:]+:\s*', '', monitor['title'])
            monitor_state = state.get(plain_name, {}) if state else {}
            is_down = not monitor_state.get('is_up', True)
            label_class = "network-host-label down" if is_down else "network-host-label"
            outage_str = f" &nbsp;<span style='font-weight: normal; font-size: 13px;'>Down {format_time_ago(monitor_state.get('last_alarm_started'))}</span>" if is_down else ""
            # Label cell at position 1 (or 5 for second monitor)
            html_lines.append(f"        <div class='port-label-cell'><span class='{label_class}'>{monitor['title']}{outage_str}</span></div>")
            # Three invisible spacer cells to fill cols 2-4 (or 6-8)
            for _ in range(3):
                html_lines.append("        <div class='port-label-cell port-label-spacer'></div>")
        html_lines.append("    </div>")

        # --- chart row ---
        html_lines.append(f"    <div class='network-row' style='grid-template-columns: {col_style};'>")
        for base_name, monitor in run:
            plain_name = re.sub(r'^[^:]+:\s*', '', monitor['title'])
            monitor_state = state.get(plain_name, {}) if state else {}
            is_down = not monitor_state.get('is_up', True)
            cell_class = "network-cell down" if is_down else "network-cell"

            for suffix, heading in port_targets:
                html_lines.extend([
                    f"        <div class='{cell_class}'>",
                    f"            <h4>{heading}</h4>",
                    f"            <a href='/mrtg-rrd/{base_name}{suffix}.html'>",
                    f"                <img src='/mrtg-rrd/{base_name}{suffix}-day.png' alt='{monitor['title']} {heading}'>",
                    "            </a>",
                    "        </div>",
                ])
        html_lines.append("    </div>")

    # Add Network Monitoring section — iterate snmp_monitors in insertion order,
    # flushing contiguous runs of port monitors as grouped grids.
    if snmp_monitors:
        html_lines.append("    <h2>L2/L3 Network Monitoring</h2>")

        port_run: List[Tuple[str, Dict[str, Any]]] = []
        port_count_total = 0

        for base_name, monitor in snmp_monitors.items():
            is_port = monitor['title'].startswith('port: ')
            if is_port:
                port_run.append((base_name, monitor))
                port_count_total += 1
            else:
                # Flush any buffered port run before this snmp row
                if port_run:
                    _emit_port_group(port_run)
                    port_run = []
                _emit_snmp_row(base_name, monitor)

        # Flush any trailing port run
        if port_run:
            _emit_port_group(port_run)

    # Add Availability Monitoring section (non-SNMP monitors)
    if all_monitors:
        html_lines.extend([
            "    <h2>L4 Availability Monitoring</h2>",
            "    <div class='grid'>",
        ])

        for monitor in all_monitors:
            safe_name = monitor['name']
            monitor_state = state.get(monitor['title'], {}) if state else {}
            is_down = not monitor_state.get('is_up', True)
            div_class = "monitor down" if is_down else "monitor"
            outage_str = f"<span style='color: #cc0000; font-weight: bold;'>Down {format_time_ago(monitor_state.get('last_alarm_started'))}</span>" if is_down else ""

            html_lines.extend([
                f"        <div class='{div_class}'>",
                f"            <h3><a href='/mrtg-rrd/{safe_name}.html'>{monitor['title']}</a></h3>",
                f"            <a href='/mrtg-rrd/{safe_name}.html'>",
                f"                <img src='/mrtg-rrd/{safe_name}-day.png' alt='{monitor['title']} Daily Graph'>",
                "            </a>",
                f"            <p style='font-size: 12px; color: #666;'>{monitor['address']}{(' &nbsp;' + outage_str) if is_down else ''}</p>",
                "        </div>",
            ])

        html_lines.append("    </div>")

    # Build hidden monitors audit footer — omitted entirely if no monitors are hidden
    if hidden_monitors:
        hidden_parts = []
        for m in hidden_monitors:
            monitor_state = state.get(m['name'], {}) if state else {}
            is_down = not monitor_state.get('is_up', True)
            if is_down:
                outage_str = f" (down {format_time_ago(monitor_state.get('last_alarm_started'))})"
                hidden_parts.append(f"<span style='color: #cc0000;'>{m['name']}{outage_str}</span>")
            else:
                hidden_parts.append(f"<span style='color: #aaa;'>{m['name']}</span>")
        hidden_line = ", ".join(hidden_parts)
        html_lines.append(
            f"    <p style='margin-top: 20px; text-align: center; color: #333; font-size: 14px; font-weight: bold;'>"
            f"Not displayed: {hidden_line}</p>"
        )

    html_lines.extend([
        f"    <p style='margin-top: 10px; text-align: center; color: #888; font-size: 12px;'>Generated by <a href='https://github.com/CompSciFutures/APMonitor/'>APMonitor v{__version__}</a> at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "</body>",
        "</html>",
    ])

    html_content = '\n'.join(html_lines)

    # Write to .new file
    new_path = Path(index_path + '.new')
    old_path = Path(index_path + '.old')
    current_path = Path(index_path)

    try:
        with open(new_path, 'w') as f:
            f.write(html_content)

        # Atomic rotation: current -> .old, .new -> current
        if current_path.exists():
            os.replace(current_path, old_path)
        os.replace(new_path, current_path)

        if VERBOSE:
            snmp_count = sum(1 for m in snmp_monitors.values() if not m['title'].startswith('port: '))
            avail_count = len(all_monitors)
            hidden_count = len(hidden_monitors) if hidden_monitors else 0
            print(f"{prefix}Generated MRTG master index: {index_path} ({snmp_count} SNMP hosts, {port_count_total} port monitors, {avail_count} availability monitors, {hidden_count} hidden)")

    except Exception as e:
        print(f"{prefix}Failed to generate MRTG master index '{index_path}': {e}", file=sys.stderr)


def update_mrtg_rrd_cgi_config(work_dir: str, mrtg_config_path: str) -> List[str]:
    """Update mrtg-rrd.cgi.pl to include the new MRTG config path.

    Args:
        work_dir: MRTG working directory where mrtg-rrd.cgi.pl is located
        mrtg_config_path: Full path to the MRTG config file to add

    Returns:
        List of all MRTG config file paths (empty list if file not found or error)
    """
    prefix = getattr(thread_local, 'prefix', '')

    cgi_path = Path(work_dir) / 'mrtg-rrd.cgi.pl'

    if not cgi_path.exists():
        if VERBOSE:
            print(f"{prefix}Warning: mrtg-rrd.cgi.pl not found at {cgi_path}, skipping config update")
        return []

    try:
        # Read the current CGI file
        with open(cgi_path, 'r') as f:
            content = f.read()

        # Find the BEGIN block with @config_files
        pattern = r'(BEGIN\s*\{\s*@config_files\s*=\s*qw\()([^)]*)\)'
        match = re.search(pattern, content)

        if not match:
            print(f"{prefix}Warning: Could not find @config_files declaration in {cgi_path}", file=sys.stderr)
            return []

        # Extract existing config files
        existing_configs_str = match.group(2).strip()
        existing_configs = existing_configs_str.split() if existing_configs_str else []

        # Add new config if not already present
        if mrtg_config_path not in existing_configs:
            existing_configs.append(mrtg_config_path)

            # Build new config list
            new_config_list = ' '.join(existing_configs)

            # Replace the old list with the new one
            new_content = re.sub(
                pattern,
                r'\g<1>' + new_config_list + ')',
                content
            )

            # Write back atomically using .new/.old pattern
            new_path = Path(str(cgi_path) + '.new')
            old_path = Path(str(cgi_path) + '.old')

            with open(new_path, 'w') as f:
                f.write(new_content)

            # Atomic rotation
            if cgi_path.exists():
                os.replace(cgi_path, old_path)
            os.replace(new_path, cgi_path)

            if VERBOSE:
                print(f"{prefix}Updated mrtg-rrd.cgi.pl config list: {existing_configs}")
        else:
            if VERBOSE:
                print(f"{prefix}Config path already present in mrtg-rrd.cgi.pl: {mrtg_config_path}")

        # Set executable permissions (755)
        os.chmod(cgi_path, 0o755)
        if VERBOSE:
            print(f"{prefix}Set permissions 755 on {cgi_path}")

        return existing_configs

    except Exception as e:
        print(f"{prefix}Failed to update mrtg-rrd.cgi.pl config: {e}", file=sys.stderr)
        return []


def main() -> None:
    global VERBOSE, MAX_THREADS, STATEFILE, STATE, MAX_RETRIES, MAX_TRY_SECS, DEFAULT_CHECK_EVERY_N_SECS, DEFAULT_NOTIFY_EVERY_N_SECS, DEFAULT_AFTER_EVERY_N_NOTIFICATIONS, RRD_ENABLED

    parser = argparse.ArgumentParser(description='Network resource availability monitor')
    parser.add_argument('config', help='Path to configuration file (JSON or YAML)')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity (can be repeated: -v, -vv, -vvv)')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of concurrent threads (default: 1)')
    parser.add_argument('-s', '--statefile', default=get_default_statefile(), help=f'Path to state file (default: platform-dependent, see docs)')
    parser.add_argument('--test-webhooks', action='store_true', help='Test webhook notifications and exit')
    parser.add_argument('--test-emails', action='store_true', help='Test email notifications and exit')
    parser.add_argument('--generate-rrds', action='store_true', help='Enable RRD database creation and updates')
    parser.add_argument('--generate-mrtg-config', metavar='WORKDIR', nargs='?', const='/var/www/html/mrtg', help='Generate MRTG config file and exit (default workdir: /var/www/html/mrtg)')
    args = parser.parse_args()

    VERBOSE = args.verbose
    MAX_THREADS = args.threads
    STATEFILE = args.statefile

    if VERBOSE:
        print(f"-    - --=[ {__app_name__} v{__version__} ]=--- -     -")

    if MAX_THREADS < 1:
        print("Error: threads must be a positive integer greater than 0", file=sys.stderr)
        sys.exit(1)

    # Acquire PID lock (Unix-like systems only)
    lockfile_path = create_pid_file_or_exit_on_unix(args.config)

    try:
        # load & parse YAML/JSON config
        config = load_config(args.config)
        if VERBOSE > 2:
            print(json.dumps(config, indent=2))

        print_and_exit_on_bad_config(config)

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

        # Hoisted so the finally block can always reference it regardless of code path
        mrtg_index_elapsed_ms: int = 0

        # Generate MRTG config mode
        if args.generate_mrtg_config is not None:
            work_dir = args.generate_mrtg_config
            mrtg_config_path = str(Path(STATEFILE).with_suffix('.mrtg.cfg'))

            # Extract site name from config
            site_name = config['site']['name']

            mrtg_start_ms = int(datetime.now().timestamp() * 1000)

            generate_mrtg_config(config, work_dir, mrtg_config_path)
            all_config_files = update_mrtg_rrd_cgi_config(work_dir, mrtg_config_path)

            # Monitors with display=false are excluded from MRTG config but shown in audit footer
            hidden_monitors = [r for r in config['monitors'] if not to_natural_language_boolean(r.get('display', True))]

            # Generate master index from all config files, passing site name and hidden monitors
            master_index_path = str(Path(work_dir) / 'index.html')
            generate_mrtg_index(all_config_files, master_index_path, site_name, STATE, hidden_monitors)

            mrtg_index_elapsed_ms = int(datetime.now().timestamp() * 1000) - mrtg_start_ms

            print(f"MRTG config generated at: {mrtg_config_path}")
            print(f"MRTG master index generated at: {master_index_path}")
            print(f"MRTG working directory: {work_dir}")
            if all_config_files:
                print(f"All MRTG config files in mrtg-rrd.cgi.pl: {', '.join(all_config_files)}")
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
            last_execution_ms = STATE.get('execution_ms')
            if last_execution_ms and last_execution_time:
                last_execution_time_dt = datetime.fromisoformat(last_execution_time)
                time_since_last_run = format_time_ago(last_execution_time)
                print(f"Last execution time: {last_execution_ms}ms, ending at {last_execution_time_dt.strftime('%Y-%m-%d %H:%M:%S')} ({time_since_last_run} ago)")
            elif last_execution_ms:
                print(f"Last execution time: {last_execution_ms}ms")

        # Record start time
        start_time = datetime.now()
        start_ms = int(start_time.timestamp() * 1000)

        if VERBOSE:
            print(f"Starting monitoring run at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"max_threads={MAX_THREADS}, max_retries={MAX_RETRIES}, max_try_secs={MAX_TRY_SECS}, default_check_every_n_secs={DEFAULT_CHECK_EVERY_N_SECS}, " +
                  f"default_notify_every_n_secs={DEFAULT_NOTIFY_EVERY_N_SECS}, default_after_every_n_notifications={DEFAULT_AFTER_EVERY_N_NOTIFICATIONS}")
            print(f"Loaded {len(config['monitors'])} resources to monitor for " + config['site']['name'])

        sys.stdout.flush()

        # check availability of each resource in config using thread pool
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
            end_time = datetime.now()
            end_ms = int(end_time.timestamp() * 1000)
            execution_ms = end_ms - start_ms

            # Update state
            STATE.update({
                'execution_time': end_time.isoformat(),
                'execution_ms': execution_ms,
            })

            if VERBOSE:
                print(f"_ ___ _____________  {'.' * len(str(execution_ms))} .. .")
                print(f"     Execution time: {execution_ms} ms")

            if RRD_ENABLED:
                print(f"  MRTG indices time: {mrtg_index_elapsed_ms} ms")
                print(f"RRD generation time: {RRD_ELAPSED_MS} ms")

            # Save state atomically
            save_state(STATE)
    finally:
        # Remove lockfile on exit
        if lockfile_path and os.path.exists(lockfile_path):
            os.remove(lockfile_path)


if __name__ == '__main__':
    main()