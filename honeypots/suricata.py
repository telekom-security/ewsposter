# honeypots/suricata.py

import time
from modules.ealert import EAlert
from datetime import datetime


def suricata(ECFG):
    suricata = EAlert('suricata', ECFG)

    ITEMS = ['suricata', 'nodeid', 'logfile']
    HONEYPOT = (suricata.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('suricata').lower() == "false":
        print(f"    -> Honeypot Suricata set to false. Skip Honeypot.")
        return()

    while True:
        line = suricata.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        suricata.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            suricata.data('timestamp', datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
            suricata.data("timezone", time.strftime('%z'))

        suricata.data('source_address', line['src_ip']) if 'src_ip' in line else None
        suricata.data('target_address', line['dest_ip']) if 'dest_ip' in line else None
        suricata.data('source_port', line['src_port']) if 'src_port' in line else None
        suricata.data('target_port', line['dest_port']) if 'dest_port' in line else None
        suricata.data('source_protocol', line['proto'].lower()) if 'proto' in line else None
        suricata.data('target_protocol', line['proto'].lower()) if 'proto' in line else None

        suricata.request('description', 'Suricata Attack')

        suricata.adata('hostname', ECFG['hostname'])
        suricata.adata('externalIP', ECFG['ip_ext'])
        suricata.adata('internalIP', ECFG['ip_int'])
        suricata.adata('uuid', ECFG['uuid'])

        if suricata.buildAlert() == "sendlimit":
            break

    suricata.finAlert()
    return()
