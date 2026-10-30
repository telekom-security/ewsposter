# honeypots/redishoneypot

import time
from modules.ealert import EAlert
from datetime import datetime


EWS_CORE_FIELDS = {
    'timestamp', 'network', 'src_ip', 'src_port', 'dest_ip', 'dest_port',
}

LOG_ENVELOPE_FIELDS = {
    'level', 'message', 'event',
}

REDIS_METADATA_FIELDS = (
    'protocol', 'profile',
    'session_id', 'client_id', 'session_start', 'session_end',
    'session_duration', 'session_duration_ms',
    'client_name', 'client_library_name', 'client_library_version',
    'user_agent',
    'redis_db', 'command', 'command_category', 'arg_count',
    'response_class', 'response_bytes', 'outcome', 'close_after_command',
    'args_text', 'args_truncated', 'args_sha256',
    'analysis_hint',
    'key', 'key_count', 'key_pattern', 'value_size', 'value_sha256',
    'config_subcommand', 'config_key', 'config_value',
    'config_value_truncated', 'config_value_sha256',
    'replica_host', 'replica_port',
    'replconf_key', 'replconf_value',
    'module_subcommand', 'module_path',
    'auth_username', 'auth_password_length', 'auth_password_sha256',
    'client_subcommand',
    'value_text', 'value_truncated',
    'script_sha1', 'script_sha256', 'script_size', 'script_text',
    'script_truncated', 'script_numkeys',
    'target_dir', 'target_dbfilename',
    'ioc_urls', 'ioc_ips', 'ioc_domains', 'ioc_count',
    'error', 'max_bulk_bytes', 'max_inline_bytes', 'max_array_elems',
    'session_command_count', 'session_hints',
    'reason', 'refused_count', 'reply_limited',
    'log_truncated', 'ioc_truncated',
    'client_name_truncated', 'client_library_name_truncated',
    'client_library_version_truncated', 'user_agent_truncated',
    'command_truncated', 'key_truncated', 'key_pattern_truncated',
    'config_subcommand_truncated', 'config_key_truncated',
    'auth_username_truncated', 'replica_host_truncated',
    'replica_port_truncated', 'replconf_key_truncated',
    'replconf_value_truncated', 'module_subcommand_truncated',
    'module_path_truncated', 'client_subcommand_truncated',
    'script_sha1_truncated', 'target_dir_truncated',
    'target_dbfilename_truncated',
)


def _is_metadata_value(value):
    return value is not None and isinstance(value, (str, int, float, bool))


def _format_timestamp(value):
    if not value:
        return None

    if isinstance(value, str) and value.endswith('Z'):
        value = value[:-1] + '+00:00'

    try:
        return datetime.fromisoformat(str(value)).strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None


def _is_alert_event(line):
    """ every command, every refused connection (RedisHoneyPot logs at most one
    per source address and minute) and the close of a session without any
    command (port scans, protocol errors) """
    if line.get('event') in ('command', 'refused'):
        return True
    count = line.get('session_command_count')
    return line.get('event') == 'close' and not isinstance(count, bool) and count == 0


def _request_text(line):
    if line.get('event') == 'close':
        return 'connection without command'
    if line.get('event') == 'refused':
        reason = line.get('reason')
        return f"connection refused ({reason})" if reason else 'connection refused'

    command = line.get('command')

    if command and line.get('args_text'):
        return f"{command} {line['args_text']}"
    if command:
        return str(command)

    return 'Redis command'


def _add_redis_metadata(alert, line):
    added = set()

    for key in REDIS_METADATA_FIELDS:
        value = line.get(key)
        if _is_metadata_value(value):
            alert.adata(key, value)
            added.add(key)

    for key, value in line.items():
        if key in added or key in EWS_CORE_FIELDS or key in LOG_ENVELOPE_FIELDS:
            continue
        if _is_metadata_value(value):
            alert.adata(key, value)


def redishoneypot(ECFG):
    redishoneypot = EAlert('redishoneypot', ECFG)

    ITEMS = ['redishoneypot', 'nodeid', 'logfile']
    HONEYPOT = (redishoneypot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('redishoneypot').lower() == "false":
        print(f"    -> Honeypot Redishoneypot set to false. Skip Honeypot.")
        return()

    while True:
        line = redishoneypot.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if not isinstance(line, dict):
            continue
        if not _is_alert_event(line):
            continue

        timestamp = _format_timestamp(line.get('timestamp'))
        source_address = line.get('src_ip')
        source_port = line.get('src_port')

        if not timestamp or not source_address or source_port is None:
            continue

        redishoneypot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        redishoneypot.data('timestamp', timestamp)
        redishoneypot.data('timezone', time.strftime('%z'))

        # dest_ip is the container address on the Docker bridge, so the
        # sensor's external IP is reported like for the other T-Pot honeypots.
        target_address = ECFG['ip_ext']
        target_port = line.get('dest_port') or '6379'
        network = line.get('network') or 'tcp'

        redishoneypot.data('source_address', source_address)
        redishoneypot.data('target_address', target_address)
        redishoneypot.data('source_port', str(source_port))
        redishoneypot.data('target_port', str(target_port))
        redishoneypot.data('source_protocol', network)
        redishoneypot.data('target_protocol', network)

        redishoneypot.request('description', 'Redis Honeypot')
        redishoneypot.request('request', _request_text(line))

        _add_redis_metadata(redishoneypot, line)
        redishoneypot.adata('hostname', ECFG['hostname'])
        redishoneypot.adata('externalIP', ECFG['ip_ext'])
        redishoneypot.adata('internalIP', ECFG['ip_int'])
        redishoneypot.adata('uuid', ECFG['uuid'])

        if redishoneypot.buildAlert() == "sendlimit":
            break

    redishoneypot.finAlert()
    return()
