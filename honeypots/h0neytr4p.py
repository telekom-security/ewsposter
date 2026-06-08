from datetime import datetime
from urllib import parse
import os
import time
from modules.ealert import EAlert


def _format_timezone(offset):
    seconds = int(offset.total_seconds())
    sign = '+' if seconds >= 0 else '-'
    seconds = abs(seconds)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    return f"{sign}{hours:02d}{minutes:02d}"


def _parse_timestamp(timestamp):
    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))

    if dt.tzinfo is not None and dt.utcoffset() is not None:
        timezone = _format_timezone(dt.utcoffset())
    else:
        timezone = time.strftime('%z')

    return dt.strftime('%Y-%m-%d %H:%M:%S'), timezone


def _payload_path(line, payloaddir):
    payload_filename = line.get('payload_filename')
    payload_hash = line.get('payload_hash_md5')
    candidates = []

    if payload_filename:
        if os.path.isabs(payload_filename):
            candidates.append(payload_filename)
        elif payloaddir:
            candidates.append(os.path.join(payloaddir, payload_filename))

    if payloaddir and payload_filename:
        candidates.append(os.path.join(payloaddir, os.path.basename(payload_filename)))

    if payloaddir and payload_hash:
        candidates.append(os.path.join(payloaddir, payload_hash))

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    return candidates[0] if candidates else None


def _add_metadata(alert, line, keys):
    for key in keys:
        if key in line:
            alert.adata(key, line[key])


def _add_prefixed_metadata(alert, line, prefixes):
    for key, value in line.items():
        if key.startswith(prefixes):
            alert.adata(key, value)


def h0neytr4p(ECFG):
    h0neytr4p = EAlert('h0neytr4p', ECFG)

    ITEMS = ['h0neytr4p', 'nodeid', 'logfile', 'payloaddir']
    HONEYPOT = (h0neytr4p.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('h0neytr4p').lower() == "false":
        print(f"    -> Honeypot h0neytr4p set to false. Skip Honeypot.")
        return()

    while True:
        line = h0neytr4p.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        h0neytr4p.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            timestamp, timezone = _parse_timestamp(line['timestamp'])
            h0neytr4p.data('timestamp', timestamp)
            h0neytr4p.data("timezone", timezone)

        h0neytr4p.data('source_address', line['src_ip'] ) if 'src_ip' in line else None
        h0neytr4p.data('target_address', ECFG['ip_ext'])
        h0neytr4p.data('source_port', '0') # No source_port in logs :-(
        h0neytr4p.data('target_port', line['dest_port'] ) if 'dest_port' in line else None
        h0neytr4p.data('source_protocol', "tcp")
        h0neytr4p.data('target_protocol', "tcp")

        h0neytr4p.request("description", "H0neytr4p Honeypot")
        h0neytr4p.request("url", parse.quote(str(line['request_uri']).encode('ascii', 'ignore'))) if 'request_uri' in line else None

        if 'request_method' in line:
            h0neytr4p.adata('httpmethod', line['request_method'])

        _add_metadata(h0neytr4p, line, [
            'protocol',
            'hostname',
            'request_proto',
            'request_uri',
            'user-agent',
            'user-agent_browser',
            'user-agent_browser_version',
            'user-agent_os',
            'trapped',
            'trapped_for',
            'trapped_references',
            'trapped_risk_rating',
        ])
        _add_prefixed_metadata(h0neytr4p, line, ('header_', 'cookie_', 'payload_'))

        if ECFG['send_malware'] is True and ('payload_filename' in line or 'payload_hash_md5' in line):
            payload_path = _payload_path(line, HONEYPOT.get('payloaddir'))
            if payload_path:
                payload_md5 = line.get('payload_hash_md5') or os.path.basename(payload_path)
                error, payload = h0neytr4p.malwarecheck(
                    os.path.dirname(payload_path),
                    os.path.basename(payload_path),
                    ECFG['del_malware_after_send'],
                    payload_md5
                )
                if (error is True) and (len(payload) <= 5 * 1024) and (len(payload) > 0):
                    h0neytr4p.request('binary', payload.decode('utf-8'))
                elif (error is True) and (len(payload) > 0):
                    h0neytr4p.request('largepayload', payload.decode('utf-8'))

        h0neytr4p.adata('externalIP', ECFG['ip_ext'])
        h0neytr4p.adata('internalIP', ECFG['ip_int'])
        h0neytr4p.adata('uuid', ECFG['uuid'])

        if h0neytr4p.buildAlert() == "sendlimit":
            break

    h0neytr4p.finAlert()
    return()
