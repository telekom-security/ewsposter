# honeypots/mailoney.py

import base64
import hashlib
import ipaddress
import json
import time
from datetime import datetime
from pathlib import Path


EVENT_TYPES = ("mail", "auth", "session")
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024
SMALL_PAYLOAD_SIZE = 5 * 1024

""" Mailoney JSONL fields forwarded as AdditionalData, per event type """
COMMON_FIELDS = (
    'session_id',
    'session_duration',
    'session_outcome',
    'session_last_response_code',
    'smtp_input',
    'smtp_input_count',
    'smtp_input_truncated',
    'listener.name',
    'listener.tls_mode',
    'tls.used',
    'tls.version',
    'tls.cipher',
    'errors',
)

EVENT_FIELDS = {
    'auth': (
        'auth.sequence',
        'auth.method',
        'auth.raw',
        'auth.username',
        'auth.password',
        'auth.decode_error',
    ),
    'session': (
        'auth.count',
    ),
    'mail': (
        'mail.message_id',
        'mail.sequence',
        'mail.envelope_from',
        'mail.envelope_to',
        'mail.header_from',
        'mail.header_to',
        'mail.subject',
        'mail.sending_mailserver',
        'mail.eml_size',
        'mail.truncated',
        'attachment.count',
        'attachment.filenames',
        'attachment.sha256',
    ),
}

""" Event specific time first, session end (timestamp) last """
TIMESTAMP_FIELDS = ('mail.timestamp', 'auth.timestamp', 'session_start', 'timestamp')


def _parse_timestamp(value):
    if not value:
        return(None, None)

    timestamp = str(value)
    try:
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return(f"{str(value)[0:10]} {str(value)[11:19]}", time.strftime('%z'))

    timezone = parsed.strftime('%z') or time.strftime('%z')
    return(parsed.strftime('%Y-%m-%d %H:%M:%S'), timezone)


def _event_timestamp(line):
    for field in TIMESTAMP_FIELDS:
        if line.get(field):
            return(_parse_timestamp(line[field]))
    return(None, None)


def _normalize_ip(value):
    """ IPv4-mapped IPv6 (::ffff:a.b.c.d) from dual-stack listeners -> IPv4 """
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return(value)

    if address.version == 6 and address.ipv4_mapped is not None:
        return(str(address.ipv4_mapped))
    return(str(address))


def _compact_value(value):
    if isinstance(value, bool):
        return("true" if value else "false")
    if isinstance(value, (dict, list)):
        return(json.dumps(value, ensure_ascii=False, separators=(',', ':')))
    return(value)


def _is_empty(value):
    return(value is None or value == "" or value == [] or value == {})


def _event_additional_data(line):
    adata = {}
    fields = COMMON_FIELDS + EVENT_FIELDS.get(line.get('event.type'), ())

    for key in fields:
        value = line.get(key)
        if _is_empty(value):
            continue
        adata[key] = _compact_value(value)

    return(adata)


def _as_list(value):
    if isinstance(value, str):
        return([value])
    if isinstance(value, list):
        return(value)
    return([])


def _attachment_refs(line):
    """ (relative file, sha256) pairs; attachments without a hash are skipped """
    files = _as_list(line.get('attachment.files'))
    hashes = _as_list(line.get('attachment.sha256'))

    return([(filename, checksum) for filename, checksum in zip(files, hashes) if filename and checksum])


def _resolve_malware_path(malwaredir, filename):
    if not malwaredir or not filename:
        return(None)

    base = Path(malwaredir).resolve()
    candidate = Path(str(filename))

    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (base / candidate).resolve()

    try:
        resolved.relative_to(base)
    except ValueError:
        return(None)

    return(resolved)


def _payload_file(alert, malwaredir, filename):
    payload_file = _resolve_malware_path(malwaredir, filename)

    if payload_file is None:
        alert.logger.warning(f"Mailoney storage path {filename} is outside malwaredir {malwaredir}. Not send.", '2')
        return(None)

    if not payload_file.is_file():
        alert.logger.warning(f"Mailoney storage file {payload_file} does not exist. Not send.", '2')
        return(None)

    if payload_file.stat().st_size > MAX_PAYLOAD_SIZE:
        alert.logger.warning(f"Mailoney storage file {payload_file} is bigger than 10 MB. Not send.", '2')
        return(None)

    return(payload_file)


def _attach_payload(alert, payload_file, checksum, remove_after_send=False, content=None):
    if alert.md5malware(checksum) is False:
        alert.logger.warning(f"Mailoney storage file {checksum} already submitted.", '2')
        return(False)

    if content is None:
        content = payload_file.read_bytes()

    payload = base64.b64encode(content)
    if remove_after_send is True:
        payload_file.unlink()

    if len(payload) <= SMALL_PAYLOAD_SIZE and len(payload) > 0:
        alert.request('binary', payload.decode('utf-8'))
    elif len(payload) > 0:
        alert.request('largepayload', payload.decode('utf-8'))
    else:
        return(False)

    return(True)


def _attach_event_payloads(alert, line, HONEYPOT, ECFG):
    """ One payload per alert: first new attachment, else the .eml of a mail without attachments """
    if ECFG.get('send_malware') is not True or line.get('event.type') != 'mail':
        return(False)

    malwaredir = HONEYPOT.get('malwaredir')
    remove = ECFG.get('del_malware_after_send', False)

    for filename, checksum in _attachment_refs(line):
        payload_file = _payload_file(alert, malwaredir, filename)
        if payload_file is not None and _attach_payload(alert, payload_file, checksum, remove) is True:
            return(True)

    if _as_list(line.get('attachment.files')) or not line.get('mail.eml_file'):
        return(False)

    payload_file = _payload_file(alert, malwaredir, line['mail.eml_file'])
    if payload_file is None:
        return(False)

    content = payload_file.read_bytes()
    return(_attach_payload(alert, payload_file, hashlib.sha256(content).hexdigest(), remove, content))


def _build_event(line, HONEYPOT, ECFG):
    if line.get('event.type') not in EVENT_TYPES:
        return(None)
    if not line.get('src_ip'):
        return(None)

    timestamp, timezone = _event_timestamp(line)
    if timestamp is None:
        return(None)

    target_port = line.get('dest_port') or line.get('listener.port') or 25
    event_type = line['event.type']

    event = {
        'data': {
            'timestamp': timestamp,
            'timezone': timezone,
            'source_address': _normalize_ip(line['src_ip']),
            'target_address': _normalize_ip(line['dest_ip']) if line.get('dest_ip') else ECFG['ip_ext'],
            'source_port': str(line.get('src_port', 0)),
            'target_port': str(target_port),
            'source_protocol': 'tcp',
            'target_protocol': 'tcp',
        },
        'request': {
            'description': f"Mail Honeypot mailoney ({event_type})",
        },
        'adata': _event_additional_data(line),
    }

    if HONEYPOT.get('nodeid'):
        event['data']['analyzer_id'] = HONEYPOT['nodeid']

    event['adata']['hostname'] = ECFG['hostname']
    event['adata']['externalIP'] = ECFG['ip_ext']
    event['adata']['internalIP'] = ECFG['ip_int']
    event['adata']['uuid'] = ECFG['uuid']

    return(event)


def mailoney(ECFG):
    from modules.ealert import EAlert

    mailoney = EAlert('mailoney', ECFG)

    ITEMS = ['mailoney', 'nodeid', 'logfile', 'malwaredir']
    HONEYPOT = (mailoney.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('mailoney').lower() == "false":
        print(f"    -> Honeypot Mailoney set to false. Skip Honeypot.")
        return()

    while True:
        line = mailoney.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        event = _build_event(line, HONEYPOT, ECFG)
        if event is None:
            continue

        for key, value in event['data'].items():
            mailoney.data(key, value)
        for key, value in event['request'].items():
            mailoney.request(key, value)
        for key, value in event['adata'].items():
            mailoney.adata(key, value)

        _attach_event_payloads(mailoney, line, HONEYPOT, ECFG)

        if mailoney.buildAlert() == "sendlimit":
            break

    mailoney.finAlert()
    return()
