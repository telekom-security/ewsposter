# honeypots/ciscoasa.py

import time
from modules.ealert import EAlert
from datetime import datetime

def ciscoasa(ECFG):
    ciscoasa = EAlert('ciscoasa', ECFG)

    ITEMS = ['ciscoasa', 'nodeid', 'logfile']
    HONEYPOT = (ciscoasa.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
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
            ciscoasa.data('timestamp', datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
            ciscoasa.data("timezone", time.strftime('%z'))

        ciscoasa.data('source_address', line['src_ip']) if 'src_ip' in line else None
        ciscoasa.data('target_address', ECFG['ip_ext'])
        ciscoasa.data('source_port', "0")
        ciscoasa.data('target_port', "8443")
        ciscoasa.data('source_protocol', "tcp")
        ciscoasa.data('target_protocol', "tcp")

        ciscoasa.request("description", "Cisco-ASA Honeypot")
        ciscoasa.request("payload", str(line['payload_printable'])) if 'payload' in line else None

        ciscoasa.adata('hostname', ECFG['hostname'])
        ciscoasa.adata('externalIP', ECFG['ip_ext'])
        ciscoasa.adata('internalIP', ECFG['ip_int'])
        ciscoasa.adata('uuid', ECFG['uuid'])

        if ciscoasa.buildAlert() == "sendlimit":
            break

    ciscoasa.finAlert()
    return()
