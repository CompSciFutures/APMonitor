#!/usr/bin/env python3
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

        # Check for unrecognized site-level parameters
        valid_site_params = {
            'name', 'outage_emails', 'outage_webhooks', 'max_threads', 'max_retries',
            'max_try_secs', 'notify_every_n_secs', 'after_every_n_notifications'
        }
        unrecognized_site = set(site.keys()) - valid_site_params
        if unrecognized_site:
            raise ConfigError(f"Unrecognized site-level parameters: {', '.join(sorted(unrecognized_site))}")

        # Check site name is present and is a string
        if 'name' not in site:
            raise ConfigError("Missing required field: 'site.name'")
        if not isinstance(site['name'], str):
            raise ConfigError("Field 'site.name' must be a string")

        # Validate optional site.outage_emails
        if 'outage_emails' in site:
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

        # Validate optional site.notify_every_n_secs
        if 'notify_every_n_secs' in site:
            if not isinstance(site['notify_every_n_secs'], int) or site['notify_every_n_secs'] < 1:
                raise ConfigError("Field 'site.notify_every_n_secs' must be a positive integer")

        # Validate optional site.after_every_n_notifications
        if 'after_every_n_notifications' in site:
            if not isinstance(site['after_every_n_notifications'], int) or site['after_every_n_notifications'] < 1:
                raise ConfigError("Field 'site.after_every_n_notifications' must be a positive integer")

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
                'heartbeat_every_n_secs', 'expect', 'ssl_fingerprint', 'ignore_ssl_expiry'
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
            valid_types = ['ping', 'http', 'https']
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
                    raise ConfigError(f"Monitor {i} (name: {name}): 'expect' field is only valid for 'http' and 'https' monitors")

                # 'ssl_fingerprint' not allowed for ping
                if 'ssl_fingerprint' in monitor:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'ssl_fingerprint' field is only valid for 'http' and 'https' monitors")

            elif monitor_type in ['http', 'https']:
                # Validate URL/URI
                parsed = urlparse(address)
                if not parsed.scheme or not parsed.netloc:
                    raise ConfigError(f"Monitor {i} (name: {name}): 'address' must be a valid URL with scheme and host, got '{address}'")

                # Validate 'expect' if present
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
                    if monitor_type not in ['http', 'https']:
                        raise ConfigError(f"Monitor {i} (name: {name}): 'ignore_ssl_expiry' field is only valid for 'http' and 'https' monitors")
                    # Accept various truthy values (case-insensitive)
                    if not isinstance(monitor['ignore_ssl_expiry'], (bool, int, str)):
                        raise ConfigError(f"Monitor {i} (name: {name}): 'ignore_ssl_expiry' must be a boolean, integer, or string")

    except ConfigError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


def check_url_resource(resource):
    """Perform HTTP/S request and return None if OK, error message if failed."""
    url = resource['address']
    name = resource['name']
    expect = resource.get('expect')
    ssl_fingerprint = resource.get('ssl_fingerprint')
    ignore_ssl_expiry = resource.get('ignore_ssl_expiry', False)

    # Normalize ignore_ssl_expiry to boolean
    if isinstance(ignore_ssl_expiry, str):
        ignore_ssl_expiry = ignore_ssl_expiry.lower() in ['true', 'yes', 'ok', '1']
    elif isinstance(ignore_ssl_expiry, int):
        ignore_ssl_expiry = bool(ignore_ssl_expiry)

    # If ssl_fingerprint provided, verify it before making request
    if ssl_fingerprint:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            # Get server certificate
            cert_pem = ssl.get_server_certificate((hostname, port))
            cert_der = ssl.PEM_cert_to_DER_cert(cert_pem)

            # Calculate fingerprint
            server_fingerprint = hashlib.sha256(cert_der).hexdigest()
            expected_fingerprint = ssl_fingerprint.replace(':', '').lower()

            if server_fingerprint != expected_fingerprint:
                error_msg = f"SSL fingerprint mismatch"
                if VERBOSE:
                    print(f"SSL fingerprint check FAILED for '{name}': expected {expected_fingerprint}, got {server_fingerprint}")
                print(f"HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                return error_msg

            if VERBOSE:
                print(f"SSL fingerprint check PASSED for '{name}'")

            # Check certificate expiry unless ignored
            if not ignore_ssl_expiry:
                try:
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
                    not_after_asn1 = x509.get_notAfter()

                    if VERBOSE > 1:
                        print(f"DEBUG: notAfter raw (ASN1) = {not_after_asn1}")

                    if not not_after_asn1:
                        error_msg = "Certificate has no expiry date"
                        print(f"HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                        return error_msg

                    not_after_str = not_after_asn1.decode('ascii')
                    not_after = datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ')

                    if datetime.now() > not_after:
                        error_msg = f"SSL certificate expired on {not_after}"
                        if VERBOSE:
                            print(f"SSL certificate expiry check FAILED for '{name}': expired on {not_after}")
                        print(f"HTTP/S check FAILED for '{name}' at '{url}': SSL certificate expired", file=sys.stderr)
                        return error_msg

                    if VERBOSE:
                        print(f"SSL certificate expiry check PASSED for '{name}': valid until {not_after}")

                except Exception as e:
                    error_msg = f"Certificate parsing error: {e}"
                    print(f"HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                    return error_msg
            elif VERBOSE:
                print(f"SSL certificate expiry check SKIPPED for '{name}' (ignore_ssl_expiry=True)")

        except Exception as e:
            error_msg = f"SSL verification error: {e}"
            print(f"HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
            return error_msg

        # Fingerprint matched and cert valid, proceed with pinned cert
        verify_ssl = False
    else:
        verify_ssl = not IGNORE_SSL_ERRORS

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(url, timeout=MAX_TRY_SECS, verify=verify_ssl)

            if response.status_code == 200:
                # If 'expect' is specified, check content
                if expect:
                    if expect in response.text:
                        if VERBOSE:
                            print(f"HTTP/S check SUCCESS for '{name}' at '{url}' (expected content found)")
                        return None
                    else:
                        error_msg = "expected content not found"
                        print(f"HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                        if attempt < MAX_RETRIES:
                            time.sleep(MAX_TRY_SECS)
                        continue
                else:
                    if VERBOSE:
                        print(f"HTTP/S check SUCCESS for '{name}' at '{url}'")
                    return None
            else:
                error_msg = f"status {response.status_code}"
                print(f"HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
                if attempt < MAX_RETRIES:
                    time.sleep(MAX_TRY_SECS)

        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            print(f"HTTP/S check FAILED for '{name}' at '{url}': {error_msg}", file=sys.stderr)
            if attempt < MAX_RETRIES:
                time.sleep(MAX_TRY_SECS)

    return error_msg if 'error_msg' in locals() else "unknown error"


# ping host & return None if up, error message if down
def check_ping_resource(resource):
    """Ping host and return None if up, error message if down."""
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

    error_msg = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=MAX_TRY_SECS + 2)
            if result.returncode == 0:
                if VERBOSE:
                    print(f"PING check SUCCESS for '{name}' at '{address}'")
                return None
            else:
                error_msg = "host unreachable"
                print(f"PING check FAILED for '{name}' at '{address}': {error_msg}", file=sys.stderr)
                if attempt < MAX_RETRIES:
                    time.sleep(MAX_TRY_SECS)
        except subprocess.TimeoutExpired:
            error_msg = "timeout"
            print(f"PING check FAILED for '{name}' at '{address}': {error_msg}", file=sys.stderr)
            if attempt < MAX_RETRIES:
                time.sleep(MAX_TRY_SECS)

    return error_msg if error_msg else "unknown error"


def check_resource(resource):
    if resource['type'] == 'ping':
        return check_ping_resource(resource)
    elif resource['type'] == 'http' or resource['type'] == 'https':
        return check_url_resource(resource)
    else:
        raise ConfigError(f"Unknown resource type: {resource['type']} for monitor {resource['name']}")


# fetch a heartbeat URL - tries 5 times and returns True if 200 OK
def ping_heartbeat_url(heartbeat_url, monitor_name, site_name):
    """Fetch a heartbeat URL - tries MAX_RETRIES times and returns True if 200 OK."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(heartbeat_url, timeout=MAX_TRY_SECS)
            if response.status_code == 200:
                if VERBOSE:
                    print(f"[{site_name}/{monitor_name}] Heartbeat ping SUCCESS to '{heartbeat_url}'")
                return True
            else:
                print(f"[{site_name}/{monitor_name}] Heartbeat ping FAILED to '{heartbeat_url}': status {response.status_code}", file=sys.stderr)
                if attempt < MAX_RETRIES:
                    time.sleep(MAX_TRY_SECS)
        except requests.exceptions.RequestException as e:
            print(f"[{site_name}/{monitor_name}] Heartbeat ping FAILED to '{heartbeat_url}': {e}", file=sys.stderr)
            if attempt < MAX_RETRIES:
                time.sleep(MAX_TRY_SECS)

    return False


def notify_resource_outage_with_webhook(outage_notifier, site_name, error_reason):
    """Send outage notification via webhook."""
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
                print(f"Webhook GET: {full_url}")

            response = requests.get(full_url, timeout=MAX_TRY_SECS)

            if response.status_code == 200:
                if VERBOSE:
                    print(f"Webhook notification SUCCESS to '{endpoint_url}'")
                return True
            else:
                print(f"Webhook notification FAILED to '{endpoint_url}': status {response.status_code}", file=sys.stderr)
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
                print(f"Webhook POST: {endpoint_url}")
                print(f"  Headers: {headers}")
                print(f"  Body: {body[:200]}...")

            response = requests.post(endpoint_url, data=body, headers=headers, timeout=MAX_TRY_SECS)

            if response.status_code in [200, 201]:
                if VERBOSE:
                    print(f"Webhook notification SUCCESS to '{endpoint_url}'")
                return True
            else:
                print(f"Webhook notification FAILED to '{endpoint_url}': status {response.status_code}", file=sys.stderr)
                return False

    except requests.exceptions.RequestException as e:
        print(f"Webhook notification FAILED to '{endpoint_url}': {e}", file=sys.stderr)
        return False


def notify_resource_outage_with_email(outage_notifier, site_name, error_reason):
    print(f"DEBUG: notify_resource_outage_with_email called", file=sys.stderr)
    print(f"  outage_notifier: {outage_notifier}", file=sys.stderr)
    print(f"  site_name: {site_name}", file=sys.stderr)
    print(f"  error_reason: {error_reason}", file=sys.stderr)


# Increases the delay between notification messages according to a quadratic bezier curve
# See devnotes/20151122 Reminder Timing with Quadratic Bezier Curve.xlsx for calculation
def calc_next_notification_delay_secs(notify_every_n_secs, after_every_n_notifications, secs_since_first_notification, current_notification_index):
    t = (1 / after_every_n_notifications) * current_notification_index # See D12:D31 in devnote spreadsheet (this is a closed form solution)
    By_t = (1 - t) * (1 - t) * 0 + 2 * (1 - t) * t * notify_every_n_secs + t * t * notify_every_n_secs # See F13 = (1-$D13)*(1-$D13)*E$39+2*(1-$D13)*$D13*E$40+$D13*$D13*E$41L13 in devnote spreadsheet
    # By_t = notify_every_n_secs # This is default behaviour with fixed intervals
    secs_between_alarms = By_t if t <= 1 else notify_every_n_secs
    if VERBOSE > 1:
        print(f"##### DEBUG: calc_next_notification_delay_secs(" +
              f"notify_every_n_secs={notify_every_n_secs}, " +
              f"after_every_n_notifications={after_every_n_notifications}, " +
              f"secs_since_first_notification={secs_since_first_notification}, " +
              f"current_notification_index={current_notification_index}) = {secs_between_alarms}"
              )
    return secs_between_alarms

def check_and_heartbeat(resource, site_config):
    """Check resource and ping heartbeat if up."""

    # Get previous state for this resource
    with STATE_LOCK:
        prev_state = STATE.get(resource['name'], {})
        prev_last_checked = prev_state.get('last_checked')

    # Determine if we should check this resource
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

    if not should_check:
        if VERBOSE:
            if not seconds_since_check:
                print(f"  - skipping {resource['name']} (checked {format_time_ago(prev_last_checked)} ago)")
            else:
                time_until_next_check = check_every_n_secs - seconds_since_check
                print(f"  - skipping {resource['name']} for {format_time_ago(time_until_next_check)} (checked {format_time_ago(prev_last_checked)} ago)")
        return

    if VERBOSE:
        print(f"  - checking {resource}")

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
    error_reason = check_resource(resource)
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
            print(f"  - skipping heartbeat for {resource['name']} (heartbeat sent {format_time_ago(prev_last_successful_heartbeat)} ago)")

    # Calculate new down_count, last_alarm_started, and last_notified
    if is_up:
        # Check if this is a transition from down to up
        if not prev_is_up and prev_last_alarm_started:
            # Calculate outage duration
            outage_duration = format_time_ago(prev_last_alarm_started)

            # Send recovery notification
            recovery_message = f"{resource['name']} in {site_config['name']} is UP ({resource['address']}) at {timestamp_str}, outage lasted {outage_duration}"
            print(f"##### RECOVERY: {recovery_message} #####", file=sys.stderr)

            if 'outage_emails' in site_config:
                for email_entry in site_config['outage_emails']:
                    notify_resource_outage_with_email(email_entry, site_config['name'], recovery_message)
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

        print(f"##### OUTAGE: {error_message} #####", file=sys.stderr)

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
            # Send outage notifications
            if 'outage_emails' in site_config:
                for email_entry in site_config['outage_emails']:
                    notify_resource_outage_with_email(email_entry, site_config['name'], error_message)
            if 'outage_webhooks' in site_config:
                for webhook in site_config['outage_webhooks']:
                    notify_resource_outage_with_webhook(webhook, site_config['name'], error_message)

            # Record notification time and increment count
            last_notified = now.isoformat()
            notified_count = prev_notified_count + 1
        else:
            if VERBOSE:
                if not seconds_since_notify:
                    print(f"  - skipping {resource['name']} notification (notified {format_time_ago(prev_last_notified)} ago)")
                else:
                    time_until_next_secs = next_notification_delay_secs - seconds_since_notify
                    print(f"  - skipping {resource['name']} notification for {format_time_ago(time_until_next_secs)} (notified {format_time_ago(prev_last_notified)} ago)")

            # Keep previous notification time and count
            last_notified = prev_last_notified
            notified_count = prev_notified_count

    # Update state for this resource
    update_state({
        resource['name']: {
            'is_up': is_up,
            'last_checked': now.isoformat(),
            'down_count': down_count,
            'last_alarm_started': last_alarm_started,
            'last_notified': last_notified,
            'last_successful_heartbeat': last_successful_heartbeat,
            'notified_count': notified_count,
            'error_reason': error_reason
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
    global VERBOSE, MAX_THREADS, STATEFILE, STATE, MAX_RETRIES, MAX_TRY_SECS, DEFAULT_NOTIFY_EVERY_N_SECS, DEFAULT_AFTER_EVERY_N_NOTIFICATIONS

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

            test_error = "TEST: test_monitor is down: connection timeout (192.168.1.999)"
            print("Testing email notifications...")
            for email_entry in config['site']['outage_emails']:
                notify_resource_outage_with_email(email_entry, config['site']['name'], test_error)
            print("Email test complete")
            sys.exit(0)

        if args.threads == 1 and 'max_threads' in config['site']: # only if not overridden by command line
            MAX_THREADS = config['site']['max_threads']
        if 'max_retries' in config['site']:
            MAX_RETRIES = config['site']['max_retries']
        if 'max_try_secs' in config['site']:
            MAX_TRY_SECS = config['site']['max_try_secs']
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

        # check availability of each resource in config using thread pool
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                futures = [executor.submit(check_and_heartbeat, resource, config['site']) for resource in config['monitors']]
                concurrent.futures.wait(futures)
        finally:
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
                print(f"Execution time: {execution_ms}ms")

            # Save state atomically
            save_state(STATE)
    finally:
        # Remove lockfile on exit
        if lockfile_path and os.path.exists(lockfile_path):
            os.remove(lockfile_path)


if __name__ == '__main__':
    main()