from datetime import datetime
import ipaddress
import json
import os
import time
from urllib import parse

from modules.ealert import EAlert


SMALL_PAYLOAD_LIMIT = 5 * 1024


def _compact(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(',', ':'))
    if isinstance(value, bool):
        return str(value).lower()
    return value


def _adata(alert, key, value):
    if value is None or value == "":
        return
    alert.adata(key, _compact(value))


def _event_ip(value, default):
    try:
        ipaddress.ip_address(str(value))
        return str(value)
    except (ipaddress.AddressValueError, ValueError):
        return default


def _event_timestamp(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).strftime('%Y-%m-%d %H:%M:%S')


def _event_port(value, default):
    if value is None or value == "":
        return str(default)
    return str(value)


def _safe_payload_ref(payload_ref):
    if not payload_ref:
        return None

    payload_ref = os.path.normpath(str(payload_ref).replace("/", os.sep))
    if os.path.isabs(payload_ref) or payload_ref == "." or payload_ref.startswith(".." + os.sep) or payload_ref == "..":
        return None
    return payload_ref


def _payload_ref_from_event(line, payloaddir):
    payload_ref = _safe_payload_ref(line.get('payload_ref'))
    if payload_ref:
        return payload_ref

    payload_path = line.get('payload_path')
    if not payload_path:
        return None

    payload_dir = os.path.realpath(payloaddir)
    payload_path = os.path.realpath(str(payload_path))
    try:
        if os.path.commonpath([payload_dir, payload_path]) == payload_dir:
            return _safe_payload_ref(os.path.relpath(payload_path, payload_dir))
    except ValueError:
        return None
    return None


def _send_payload(alert, honeypot, ecfg, line):
    if ecfg.get('send_malware') is not True or line.get('payload_stored') is not True:
        return

    payload_ref = _payload_ref_from_event(line, honeypot['payloaddir'])
    if not payload_ref:
        return

    checksum = line.get('payload_sha256') or payload_ref
    error, payload = alert.malwarecheck(honeypot['payloaddir'], payload_ref, False, checksum)
    if error is not True or not payload:
        return

    if len(payload) <= SMALL_PAYLOAD_LIMIT:
        alert.request('binary', payload.decode('utf-8'))
    else:
        alert.request('largepayload', payload.decode('utf-8'))


def wordpot(ECFG):
    wordpot = EAlert('wordpot', ECFG)

    ITEMS = ['wordpot', 'nodeid', 'logfile', 'payloaddir']
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
        
        if HONEYPOT.get('nodeid'): wordpot.data('analyzer_id', HONEYPOT['nodeid'])

        if line.get('timestamp'):
            wordpot.data('timestamp', _event_timestamp(line['timestamp']))
            wordpot.data('timezone', time.strftime('%z'))
        
        if line.get('src_ip'): wordpot.data('source_address', line['src_ip']) 
        wordpot.data('target_address', _event_ip(line.get('dest_ip'), ECFG['ip_ext']))
        wordpot.data('source_port', _event_port(line.get('src_port'), 0))
        wordpot.data('target_port', _event_port(line.get('dest_port'), 80))
        wordpot.data('source_protocol', "tcp")
        wordpot.data('target_protocol', "tcp")

        wordpot.request("description", "Wordpot Honeypot")
        if line.get('url'): wordpot.request("url", parse.quote(str(line['url']).encode('ascii', 'ignore')))
        _send_payload(wordpot, HONEYPOT, ECFG, line)

        for element in [
            'browser_family', 'browser_version', 'os_family', 'os_version', 'device_family',
            'user_agent', 'url', 'method', 'path', 'query', 'profile_id', 'request_id',
            'component_type', 'component_slug', 'technique', 'response_status',
            'payload_sha256', 'payload_excerpt', 'payload_size', 'payload_stored',
            'payload_ref', 'payload_path', 'username', 'password', 'plugin',
            'dest_ip', 'headers_subset', 'details', 'credentials_observed',
        ]:
            _adata(wordpot, element, line.get(element))

        wordpot.adata('hostname', ECFG['hostname'])
        wordpot.adata('externalIP', ECFG['ip_ext'])
        wordpot.adata('internalIP', ECFG['ip_int'])
        wordpot.adata('uuid', ECFG['uuid'])

        if wordpot.buildAlert() == "sendlimit":
            break

    wordpot.finAlert()
    return()            
