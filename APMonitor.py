#!/usr/bin/env python3
"""
APMonitor - On-Premises Network Resource Availability Monitor
"""

__version__ = "1.1.3"
__app_name__ = "APMonitor"

import argparse
import json
import re
from urllib.parse import urlparse
import OpenSSL.crypto
from pathlib import Path
import yaml
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

# Hush insecure SSL warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration constants
MAX_RETRIES = 3
MAX_TRY_SECS = 20
VERBOSE = 0
IGNORE_SSL_ERRORS = True
MAX_THREADS = 1
STATEFILE = "statefile.json"
STATE = {}
STATE_LOCK = threading.Lock()
DEFAULT_CHECK_EVERY_N_SECS = 60
DEFAULT_NOTIFY_EVERY_N_SECS = 600
DEFAULT_AFTER_EVERY_N_NOTIFICATIONS = 1

# Global thread-local storage
thread_local = threading.local()
thread_local.prefix = None

def to_natural_language_boolean(value):
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
def load_config(config_path):
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


def load_state(statefile_path):
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


def update_state(updates):
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


def save_state(state):
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


def format_time_ago(timestamp_or_secs):
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


def print_and_exit_on_bad_config(config):
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
                'heartbeat_every_n_secs', 'expect', 'ssl_fingerprint', 'ignore_ssl_expiry', 'email'
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
            valid_types = ['ping', 'http', 'quic']
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


def check_http_url(url, name, expect, ssl_fingerprint, ignore_ssl_expiry):
    """Perform HTTP/S request and return None if OK, error message if failed."""
    prefix = getattr(thread_local, 'prefix', '')
    error_msg = None

    # Normalize ignore_ssl_expiry to boolean
    ignore_ssl_expiry = to_natural_language_boolean(ignore_ssl_expiry)

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


def check_quic_url(url, name, expect, ssl_fingerprint, ignore_ssl_expiry):
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

        # Normalize ignore_ssl_expiry to boolean
        nonlocal_ignore_ssl_expiry = to_natural_language_boolean(ignore_ssl_expiry)

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
            verify_mode=ssl.CERT_NONE if (ssl_fingerprint or nonlocal_ignore_ssl_expiry) else ssl.CERT_REQUIRED,
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
                            if not nonlocal_ignore_ssl_expiry:
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

                    # Send HTTP request
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


def check_url_resource(resource):
    """Check URL resource (HTTP or QUIC) and return None if OK, error message if failed."""
    prefix = getattr(thread_local, 'prefix', '')
    resource_type = resource['type']
    url = resource['address']
    name = resource['name']
    expect = resource.get('expect')
    ssl_fingerprint = resource.get('ssl_fingerprint')
    ignore_ssl_expiry = resource.get('ignore_ssl_expiry', False)

    # Call the appropriate check function
    if resource_type == 'http':
        error_msg, status_code, headers, response_text = check_http_url(url, name, expect, ssl_fingerprint, ignore_ssl_expiry)
    elif resource_type == 'quic':
        error_msg, status_code, headers, response_text = check_quic_url(url, name, expect, ssl_fingerprint, ignore_ssl_expiry)
    else:
        error_msg = f"Unknown URL resource type: {resource_type}"
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


def check_ping_resource(resource):
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


def check_resource(resource):
    """Check resource with retry logic and response time tracking."""
    last_response_time_ms = None

    for attempt in range(1, MAX_RETRIES + 1):
        start_time_ms = int(time.time() * 1000)

        if resource['type'] == 'ping':
            error_msg = check_ping_resource(resource)
        elif resource['type'] in ('http', 'quic'):
            error_msg = check_url_resource(resource)
        else:
            raise ConfigError(f"Unknown resource type: {resource['type']} for monitor {resource['name']}")

        end_time_ms = int(time.time() * 1000)
        response_time_ms = end_time_ms - start_time_ms

        # If check succeeded, record response time and return
        if error_msg is None:
            last_response_time_ms = response_time_ms
            return None, last_response_time_ms

        # If check failed and we have retries left, sleep before next attempt
        if attempt < MAX_RETRIES:
            time.sleep(MAX_TRY_SECS)

    # All retries exhausted, return the last error (no response time on failure)
    return error_msg, None


# fetch a heartbeat URL - tries 5 times and returns True if 200 OK
def ping_heartbeat_url(heartbeat_url, monitor_name, site_name):
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


def notify_resource_outage_with_webhook(outage_notifier, site_name, error_reason):
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


def notify_resource_outage_with_email(email_entry, site_name, error_reason, site_config, notification_type='outage'):
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


# Increases the delay between notification messages according to a quadratic bezier curve
# See devnotes/20151122 Reminder Timing with Quadratic Bezier Curve.xlsx for calculation
def calc_next_notification_delay_secs(notify_every_n_secs, after_every_n_notifications, secs_since_first_notification, current_notification_index):
    t = (1 / after_every_n_notifications) * current_notification_index # See D12:D31 in devnote spreadsheet (this is a closed form solution)
    By_t = (1 - t) * (1 - t) * 0 + 2 * (1 - t) * t * notify_every_n_secs + t * t * notify_every_n_secs # See F13 = (1-$D13)*(1-$D13)*E$39+2*(1-$D13)*$D13*E$40+$D13*$D13*E$41L13 in devnote spreadsheet
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


def prefix_logline(site_name, resource_name):
    """Generate log line prefix with thread ID and context.

    Args:
        site_name: Name of the site (or None)
        resource_name: Name of the resource (or None)

    Returns:
        String prefix in format "[T#XXXX Site/Resource]" where XXXX is thread ID
    """
    #thread_id = threading.get_ident()
    thread_id = threading.get_native_id()

    # Build context string
    context_parts = []
    if site_name:
        context_parts.append(site_name)
    if resource_name:
        context_parts.append(resource_name)

    context = "/".join(context_parts) if context_parts else "unknown"

    return f"[T#{thread_id:04d} {context}] "


def check_and_heartbeat(resource, site_config):
    """Check resource and ping heartbeat if up."""

    # Store prefix in thread-local storage at start of thread execution
    thread_local.prefix = prefix_logline(site_config['name'], resource['name'])
    prefix = thread_local.prefix

    # Calculate checksum of resource configuration
    import hashlib
    resource_json = json.dumps(resource, sort_keys=True)
    resource_checksum = hashlib.sha256(resource_json.encode()).hexdigest()

    # Get previous state for this resource
    with STATE_LOCK:
        prev_state = STATE.get(resource['name'], {})
        prev_last_checked = prev_state.get('last_checked')
        prev_config_checksum = prev_state.get('last_config_checksum')

    # Determine if we should check this resource
    config_changed = prev_config_checksum and prev_config_checksum != resource_checksum
    check_every_n_secs = resource.get('check_every_n_secs', DEFAULT_CHECK_EVERY_N_SECS)
    should_check = True

    seconds_since_check = False
    if prev_last_checked:
        try:
            last_checked_time = datetime.fromisoformat(prev_last_checked)
            seconds_since_check = (datetime.now() - last_checked_time).total_seconds()
            should_check = seconds_since_check >= check_every_n_secs
        except:
            should_check = True

    # Skip only if timing says no AND config hasn't changed
    if not should_check and not config_changed:
        if VERBOSE:
            if not seconds_since_check:
                print(f"{prefix}skipping {resource['name']} (checked {format_time_ago(prev_last_checked)} ago)")
            else:
                time_until_next_check = check_every_n_secs - seconds_since_check
                print(f"{prefix}skipping {resource['name']} for {format_time_ago(time_until_next_check)} (checked {format_time_ago(prev_last_checked)} ago)")
        return

    if VERBOSE and config_changed:
        print(f"{prefix}configuration changed for {resource['name']}, checking immediately: {resource}")
    elif VERBOSE:
        print(f"{prefix}checking: {resource}")

    # Get previous state for this resource
    with STATE_LOCK:
        prev_state = STATE.get(resource['name'], {})
        prev_is_up = prev_state.get('is_up', True)
        prev_down_count = prev_state.get('down_count', 0)
        prev_last_alarm_started = prev_state.get('last_alarm_started')
        prev_last_notified = prev_state.get('last_notified')
        prev_last_successful_heartbeat = prev_state.get('last_successful_heartbeat')
        prev_notified_count = prev_state.get('notified_count', 0)

    # Get current time with timezone
    now = datetime.now()
    timestamp_str = now.strftime('%I:%M %p %Z').lstrip('0').strip()

    # Check resource and ping heartbeat URL
    error_reason, last_response_time_ms = check_resource(resource)
    is_up = error_reason is None
    last_successful_heartbeat = prev_last_successful_heartbeat
    if is_up and 'heartbeat_url' in resource:

        # Determine if we should ping heartbeat
        heartbeat_every_n_secs = resource.get('heartbeat_every_n_secs')
        should_heartbeat = True

        if heartbeat_every_n_secs is not None and prev_last_successful_heartbeat:
            try:
                last_heartbeat_time = datetime.fromisoformat(prev_last_successful_heartbeat)
                seconds_since_heartbeat = (now - last_heartbeat_time).total_seconds()
                should_heartbeat = seconds_since_heartbeat >= heartbeat_every_n_secs
            except:
                should_heartbeat = True

        if should_heartbeat:
            if ping_heartbeat_url(resource['heartbeat_url'], resource['name'], site_config['name']):
                last_successful_heartbeat = datetime.now().isoformat()
        elif VERBOSE:
            print(f"{prefix}skipping heartbeat for {resource['name']} (heartbeat sent {format_time_ago(prev_last_successful_heartbeat)} ago)")

    # Calculate new down_count, last_alarm_started, and last_notified
    if is_up:
        # Check if this is a transition from down to up
        if not prev_is_up:
            # Calculate outage duration
            outage_duration = format_time_ago(prev_last_alarm_started)

            # Send recovery notification
            recovery_message = f"{resource['name']} in {site_config['name']} is UP ({resource['address']}) at {timestamp_str}, outage lasted {outage_duration}"
            print(f"{prefix}##### RECOVERY: {recovery_message} #####", file=sys.stderr)

            # Check monitor-level email override
            monitor_email_enabled = to_natural_language_boolean(resource.get('email', True))

            if monitor_email_enabled and 'outage_emails' in site_config:
                for email_entry in site_config['outage_emails']:
                    notify_resource_outage_with_email(email_entry, site_config['name'], recovery_message, site_config, 'recovery')

            if 'outage_webhooks' in site_config:
                for webhook in site_config['outage_webhooks']:
                    notify_resource_outage_with_webhook(webhook, site_config['name'], recovery_message)

            last_notified = now.isoformat()

            # Keep notified_count from previous outage
            notified_count = prev_notified_count
        else:
            last_notified = prev_last_notified
            notified_count = prev_notified_count

        down_count = 0
        last_alarm_started = prev_last_alarm_started
    else:
        down_count = prev_down_count + 1
        # Set last_alarm_started if not already set
        if not prev_last_alarm_started:
            last_alarm_started = now.isoformat()
        else:
            last_alarm_started = prev_last_alarm_started

        error_message = f"{resource['name']} in {site_config['name']} is down: {error_reason} ({resource['address']}) at {timestamp_str}, down for {format_time_ago(last_alarm_started)}"

        print(f"{prefix}##### OUTAGE: {error_message} #####", file=sys.stderr)

        # Determine if we should send notifications
        notify_every_n_secs = resource.get('notify_every_n_secs', DEFAULT_NOTIFY_EVERY_N_SECS)
        after_every_n_notifications = resource.get('after_every_n_notifications', DEFAULT_AFTER_EVERY_N_NOTIFICATIONS)
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
            # Check monitor-level email override
            monitor_email_enabled = to_natural_language_boolean(resource.get('email', True))

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

    # Update state for this resource
    update_state({
        resource['name']: {
            'is_up': is_up,
            'last_checked': now.isoformat(),
            'last_response_time_ms': last_response_time_ms,
            'down_count': down_count,
            'last_alarm_started': last_alarm_started,
            'last_notified': last_notified,
            'last_successful_heartbeat': last_successful_heartbeat,
            'notified_count': notified_count,
            'error_reason': error_reason,
            'last_config_checksum': resource_checksum
        }
    })


def get_default_statefile():
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


def create_pid_file_or_exit_on_unix(config_path):
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


def main():
    global VERBOSE, MAX_THREADS, STATEFILE, STATE, MAX_RETRIES, MAX_TRY_SECS, DEFAULT_CHECK_EVERY_N_SECS, DEFAULT_NOTIFY_EVERY_N_SECS, DEFAULT_AFTER_EVERY_N_NOTIFICATIONS

    parser = argparse.ArgumentParser(description='Network resource availability monitor')
    parser.add_argument('config', help='Path to configuration file (JSON or YAML)')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity (can be repeated: -v, -vv, -vvv)')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of concurrent threads (default: 1)')
    parser.add_argument('-s', '--statefile', default=get_default_statefile(), help=f'Path to state file (default: platform-dependent, see docs)')
    parser.add_argument('--test-webhooks', action='store_true', help='Test webhook notifications and exit')
    parser.add_argument('--test-emails', action='store_true', help='Test email notifications and exit')
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

        if args.threads == 1 and 'max_threads' in config['site']: # only if not overridden by command line
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

        # Load previous state
        STATE = load_state(STATEFILE)

        if VERBOSE and STATE:
            last_execution_time = STATE.get('execution_time')
            last_execution_ms = STATE.get('execution_ms')
            if last_execution_ms and last_execution_time:
                last_execution_time = datetime.fromisoformat(last_execution_time)
                print(f"Last execution time: {last_execution_ms}ms, ending at {last_execution_time.strftime('%Y-%m-%d %H:%M:%S')}")
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
                print(f"_ ___ ________  {'.' * len(str(execution_ms))} .. .")
                print(f"Execution time: {execution_ms} ms")

            # Save state atomically
            save_state(STATE)
    finally:
        # Remove lockfile on exit
        if lockfile_path and os.path.exists(lockfile_path):
            os.remove(lockfile_path)


if __name__ == '__main__':
    main()