# honeypots/mailoney.py

import base64
import json
import time
from datetime import datetime
from pathlib import Path


SKIP_EVENT_TYPES = ("rate_limit_block",)
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024
SMALL_PAYLOAD_SIZE = 5 * 1024


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


def _compact_value(value):
    if isinstance(value, (dict, list)):
        return(json.dumps(value, ensure_ascii=False, separators=(',', ':')))
    return(value)


def _is_empty(value):
    return(value is None or value == "" or value == [] or value == {})


def _event_additional_data(line):
    adata = {}

    for key, value in line.items():
        if _is_empty(value):
            continue
        adata[key] = _compact_value(value)

    return(adata)


def _event_file_refs(line):
    refs = []

    if line.get('mail.eml_file'):
        refs.append((line['mail.eml_file'], f"mailoney:eml:{line['mail.eml_file']}"))

    attachment_files = line.get('attachment.files', [])
    attachment_hashes = line.get('attachment.sha256', [])

    if isinstance(attachment_files, str):
        attachment_files = [attachment_files]
    if isinstance(attachment_hashes, str):
        attachment_hashes = [attachment_hashes]
    if not isinstance(attachment_files, list):
        return(refs)

    for index, attachment in enumerate(attachment_files):
        if not attachment:
            continue

        if isinstance(attachment_hashes, list) and index < len(attachment_hashes) and attachment_hashes[index]:
            checksum = attachment_hashes[index]
        else:
            checksum = attachment

        refs.append((attachment, f"mailoney:attachment:{checksum}"))

    return(refs)


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


def _attach_payload(alert, malwaredir, filename, checksum, remove_after_send=False):
    payload_file = _resolve_malware_path(malwaredir, filename)

    if payload_file is None:
        alert.logger.warning(f"Mailoney storage path {filename} is outside malwaredir {malwaredir}. Not send.", '2')
        return(False)

    if not payload_file.is_file():
        alert.logger.warning(f"Mailoney storage file {payload_file} does not exist. Not send.", '2')
        return(False)

    if payload_file.stat().st_size > MAX_PAYLOAD_SIZE:
        alert.logger.warning(f"Mailoney storage file {payload_file} is bigger than 10 MB. Not send.", '2')
        return(False)

    if alert.md5malware(checksum) is False:
        alert.logger.warning(f"Mailoney storage file {checksum} already submitted.", '2')
        return(False)

    payload = base64.b64encode(payload_file.read_bytes())
    if remove_after_send is True:
        payload_file.unlink()

    if len(payload) <= SMALL_PAYLOAD_SIZE and len(payload) > 0:
        alert.request('binary', payload.decode('utf-8'))
    elif len(payload) > 0:
        alert.request('largepayload', payload.decode('utf-8'))

    return(True)


def _attach_event_payloads(alert, line, HONEYPOT, ECFG):
    if ECFG.get('send_malware') is not True:
        return(False)

    for filename, checksum in _event_file_refs(line):
        _attach_payload(alert, HONEYPOT.get('malwaredir'), filename, checksum, ECFG.get('del_malware_after_send', False))

    return(True)


def _build_event(line, HONEYPOT, ECFG):
    if line.get('event.type') in SKIP_EVENT_TYPES:
        return(None)
    if not line.get('timestamp') or not line.get('src_ip'):
        return(None)

    timestamp, timezone = _parse_timestamp(line.get('timestamp'))
    if timestamp is None:
        return(None)

    target_port = line.get('dest_port') or line.get('listener.port') or 25
    event_type = line.get('event.type', 'unknown')

    event = {
        'data': {
            'timestamp': timestamp,
            'timezone': timezone,
            'source_address': line.get('src_ip'),
            'target_address': line.get('dest_ip') or ECFG['ip_ext'],
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
