# honeypots/wordpot.py

import base64
import ipaddress
import json
import time
from datetime import datetime
from pathlib import Path
from urllib import parse


MAX_PAYLOAD_SIZE = 10 * 1024 * 1024
SMALL_PAYLOAD_SIZE = 5 * 1024
DEFAULT_TARGET_PORT = '80'
URL_SAFE_CHARS = "/?&=%:@+;,"

""" Wordpot JSONL fields forwarded as AdditionalData (plugin only exists in legacy lines) """
ADATA_FIELDS = (
    'browser_family',
    'browser_version',
    'os_family',
    'os_version',
    'device_family',
    'user_agent',
    'method',
    'technique',
    'component_type',
    'component_slug',
    'profile_id',
    'request_id',
    'response_status',
    'username',
    'password',
    'payload_sha256',
    'payload_size',
    'details',
    'plugin',
)

""" Techniques whose stored request body is an exploit payload worth submitting """
EXPLOIT_TECHNIQUES = (
    'upload_followup',
    'webshell_command',
    'xmlrpc_multicall',
    'xmlrpc_pingback',
    'rest_user_write_attempt',
    'rest_post_write_attempt',
    'admin_ajax_action',
)

""" Login bodies carry credentials only and are never submitted as payload """
LOGIN_TECHNIQUES = ('credential_attempt', 'xmlrpc_login', 'webshell_login')


def _parse_timestamp(value):
    if not value:
        return(None, None)

    timestamp = str(value)
    try:
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return(None, None)

    timezone = parsed.strftime('%z') or time.strftime('%z')
    return(parsed.strftime('%Y-%m-%d %H:%M:%S'), timezone)


def _normalize_ip(value):
    """ IPv4-mapped IPv6 (::ffff:a.b.c.d) from dual-stack listeners -> IPv4, invalid -> None """
    if not value:
        return(None)

    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return(None)

    if address.version == 6 and address.ipv4_mapped is not None:
        return(str(address.ipv4_mapped))
    return(str(address))


def _normalize_port(value, default):
    if isinstance(value, bool):
        return(default)

    try:
        port = int(str(value))
    except (TypeError, ValueError):
        return(default)

    if 1 <= port <= 65535:
        return(str(port))
    return(default)


def _compact_value(value):
    if isinstance(value, bool):
        return("true" if value else "false")
    if isinstance(value, (dict, list)):
        return(json.dumps(value, ensure_ascii=False, separators=(',', ':')))
    return(value)


def _is_empty(value):
    return(value is None or value == "" or value == [] or value == {})


def _event_url(line):
    """ Request target as path?query; legacy lines carry an absolute url instead """
    if line.get('path'):
        url = str(line['path'])
        if line.get('query'):
            url = f"{url}?{line['query']}"
    elif line.get('url'):
        parts = parse.urlsplit(str(line['url']))
        url = parts.path or "/"
        if parts.query:
            url = f"{url}?{parts.query}"
    else:
        return(None)

    return(parse.quote(url.encode('ascii', 'ignore'), safe=URL_SAFE_CHARS))


def _event_additional_data(line):
    adata = {}

    for key in ADATA_FIELDS:
        value = line.get(key)
        if _is_empty(value):
            continue
        adata[key] = _compact_value(value)

    return(adata)


def _is_exploit_payload(line):
    technique = str(line.get('technique') or "")

    if technique in LOGIN_TECHNIQUES:
        return(False)

    return(line.get('component_type') == 'upload'
           or technique in EXPLOIT_TECHNIQUES
           or technique.endswith('_lure_payload'))


def _resolve_malware_path(malwaredir, filename):
    """ Only relative refs that resolve (incl. symlinks) inside malwaredir """
    if not malwaredir or not filename:
        return(None)

    candidate = Path(str(filename))
    if candidate.is_absolute():
        return(None)

    base = Path(malwaredir).resolve()
    resolved = (base / candidate).resolve()

    try:
        resolved.relative_to(base)
    except ValueError:
        return(None)

    return(resolved)


def _payload_file(alert, malwaredir, filename):
    payload_file = _resolve_malware_path(malwaredir, filename)

    if payload_file is None:
        alert.logger.warning(f"Wordpot payload_ref {filename} is outside malwaredir {malwaredir}. Not send.", '2')
        return(None)

    if not payload_file.is_file():
        alert.logger.warning(f"Wordpot payload file {payload_file} does not exist. Not send.", '2')
        return(None)

    if payload_file.stat().st_size > MAX_PAYLOAD_SIZE:
        alert.logger.warning(f"Wordpot payload file {payload_file} is bigger than 10 MB. Not send.", '2')
        return(None)

    return(payload_file)


def _attach_payload(alert, payload_file, checksum, remove_after_send=False):
    if alert.md5malware(checksum) is False:
        alert.logger.warning(f"Wordpot payload {checksum} already submitted.", '2')
        return(False)

    payload = base64.b64encode(payload_file.read_bytes())
    if remove_after_send is True:
        payload_file.unlink()

    if len(payload) <= SMALL_PAYLOAD_SIZE and len(payload) > 0:
        alert.request('binary', payload.decode('utf-8'))
    elif len(payload) > 0:
        alert.request('largepayload', payload.decode('utf-8'))
    else:
        return(False)

    return(True)


def _attach_event_payload(alert, line, HONEYPOT, ECFG):
    """ One payload per alert: the stored exploit body referenced by payload_ref """
    if ECFG.get('send_malware') is not True or line.get('payload_stored') is not True:
        return(False)
    if not _is_exploit_payload(line):
        return(False)

    checksum = line.get('payload_sha256')
    if not checksum or not line.get('payload_ref'):
        return(False)

    payload_file = _payload_file(alert, HONEYPOT.get('malwaredir'), line['payload_ref'])
    if payload_file is None:
        return(False)

    return(_attach_payload(alert, payload_file, str(checksum), ECFG.get('del_malware_after_send', False)))


def _build_event(line, HONEYPOT, ECFG):
    if not isinstance(line, dict):
        return(None)

    source_address = _normalize_ip(line.get('src_ip'))
    if source_address is None:
        return(None)

    timestamp, timezone = _parse_timestamp(line.get('timestamp'))
    if timestamp is None:
        return(None)

    """ dest_ip may be derived from the attacker controlled Host header, always report ip_ext """
    event = {
        'data': {
            'timestamp': timestamp,
            'timezone': timezone,
            'source_address': source_address,
            'target_address': ECFG['ip_ext'],
            'source_port': _normalize_port(line.get('src_port'), '0'),
            'target_port': _normalize_port(line.get('dest_port'), DEFAULT_TARGET_PORT),
            'source_protocol': 'tcp',
            'target_protocol': 'tcp',
        },
        'request': {
            'description': "Wordpot Honeypot",
        },
        'adata': _event_additional_data(line),
    }

    url = _event_url(line)
    if url:
        event['request']['url'] = url

    if HONEYPOT.get('nodeid'):
        event['data']['analyzer_id'] = HONEYPOT['nodeid']

    event['adata']['hostname'] = ECFG['hostname']
    event['adata']['externalIP'] = ECFG['ip_ext']
    event['adata']['internalIP'] = ECFG['ip_int']
    event['adata']['uuid'] = ECFG['uuid']

    return(event)


def wordpot(ECFG):
    from modules.ealert import EAlert

    wordpot = EAlert('wordpot', ECFG)

    ITEMS = ['wordpot', 'nodeid', 'logfile', 'malwaredir']
    HONEYPOT = (wordpot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('wordpot').lower() == "false":
        print(f"    -> Honeypot Wordpot set to false. Skip Honeypot.")
        return()

    while True:
        line = wordpot.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        event = _build_event(line, HONEYPOT, ECFG)
        if event is None:
            continue

        for key, value in event['data'].items():
            wordpot.data(key, value)
        for key, value in event['request'].items():
            wordpot.request(key, value)
        for key, value in event['adata'].items():
            wordpot.adata(key, value)

        _attach_event_payload(wordpot, line, HONEYPOT, ECFG)

        if wordpot.buildAlert() == "sendlimit":
            break

    wordpot.finAlert()
    return()
