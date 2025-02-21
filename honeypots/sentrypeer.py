# honeypots/sentrypeer.py

import time
from modules.ealert import EAlert
from datetime import datetime


def sentrypeer(ECFG):
    sentrypeer = EAlert('sentrypeer', ECFG)

    ITEMS = ['sentrypeer', 'nodeid', 'logfile']
    HONEYPOT = (sentrypeer.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = sentrypeer.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        sentrypeer.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'event_timestamp' in line:
            sentrypeer.data('timestamp', datetime.fromisoformat(line['event_timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
            sentrypeer.data("timezone", time.strftime('%z'))

        sentrypeer.data('source_address', line['source_ip']) if 'source_ip' in line else None
        sentrypeer.data('target_address', line['destination_ip']) if 'destination_ip' in line else None
        sentrypeer.data('source_port', '5060')
        sentrypeer.data('target_port', '5060')
        sentrypeer.data('source_protocol', line['transport_type'].lower()) if 'transport_type' in line else None
        sentrypeer.data('target_protocol', line['transport_type'].lower()) if 'transport_type' in line else None

        sentrypeer.request('description', 'Sentrypeer Honeypot')

        sentrypeer.adata('hostname', ECFG['hostname'])
        sentrypeer.adata('externalIP', ECFG['ip_ext'])
        sentrypeer.adata('internalIP', ECFG['ip_int'])
        sentrypeer.adata('uuid', ECFG['uuid'])

        if sentrypeer.buildAlert() == "sendlimit":
            break

    sentrypeer.finAlert()
    return()
