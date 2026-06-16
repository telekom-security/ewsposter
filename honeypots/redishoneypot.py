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
    'error', 'max_bulk_bytes', 'max_inline_bytes', 'max_array_elems',
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


def _request_text(line):
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
        if line.get('event') != 'command':
            continue

        timestamp = _format_timestamp(line.get('timestamp'))
        source_address = line.get('src_ip')
        source_port = line.get('src_port')

        if not timestamp or not source_address or source_port is None:
            continue

        redishoneypot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        redishoneypot.data('timestamp', timestamp)
        redishoneypot.data('timezone', time.strftime('%z'))

        target_address = line.get('dest_ip') or ECFG['ip_ext']
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
