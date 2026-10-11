# honeypots/ciscoasa.py

import time
from modules.ealert import EAlert
from datetime import datetime

def _port(value, default):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return str(port) if 0 <= port <= 65535 else default


def ciscoasa(ECFG):
    ciscoasa = EAlert('ciscoasa', ECFG)

    ITEMS = ['ciscoasa', 'nodeid', 'logfile']
    HONEYPOT = (ciscoasa.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('ciscoasa').lower() == "false":
        print(f"    -> Honeypot Ciscosas set to false. Skip Honeypot.")
        return()

    while True:
        line = ciscoasa.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if 'Status' in line or 'Version' in line:
            continue

        ciscoasa.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            ciscoasa.data('timestamp', datetime.fromisoformat(line['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S'))
            ciscoasa.data("timezone", time.strftime('%z'))

        ciscoasa.data('source_address', line['src_ip']) if 'src_ip' in line else None
        ciscoasa.data('target_address', ECFG['ip_ext'])
        ciscoasa.data('source_port', _port(line.get('src_port'), '0'))
        ciscoasa.data('target_port', _port(line.get('dest_port'), '8443'))
        protocol = line.get('protocol', 'tcp')
        protocol = protocol if protocol in ('tcp', 'udp') else 'tcp'
        ciscoasa.data('source_protocol', protocol)
        ciscoasa.data('target_protocol', protocol)

        ciscoasa.request("description", "Cisco-ASA Honeypot")
        payload = line.get('payload', line.get('payload_printable'))
        if payload is not None:
            ciscoasa.request('payload', str(payload))

        ciscoasa.adata('hostname', ECFG['hostname'])
        ciscoasa.adata('externalIP', ECFG['ip_ext'])
        ciscoasa.adata('internalIP', ECFG['ip_int'])
        ciscoasa.adata('uuid', ECFG['uuid'])

        if ciscoasa.buildAlert() == "sendlimit":
            break

    ciscoasa.finAlert()
    return()
