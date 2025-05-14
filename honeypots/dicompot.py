# honeypots/dicompot.py

import time
from modules.ealert import EAlert
from datetime import datetime

def dicompot(ECFG):
    dicompot = EAlert('dicompot', ECFG)

    ITEMS = ['dicompot', 'nodeid', 'logfile']
    HONEYPOT = (dicompot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('dicompot').lower() == "false":
        print(f"    -> Honeypot Dicompot set to false. Skip Honeypot.")
        return()

    while True:
        line = dicompot.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if 'Status' in line or 'Version' in line:
            continue

        dicompot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'time' in line:
            dicompot.data('timestamp', datetime.fromisoformat(line['time']).strftime('%Y-%m-%d %H:%M:%S'))
            dicompot.data("timezone", time.strftime('%z'))

        dicompot.data('source_address', line['IP']) if 'IP' in line else None
        dicompot.data('target_address', ECFG['ip_ext'])
        dicompot.data('source_port', str(line['Port'])) if 'Port' in line else None
        dicompot.data('target_port', "11112")
        dicompot.data('source_protocol', "tcp")
        dicompot.data('target_protocol', "tcp")

        dicompot.request("description", "Dicompot Honeypot")

        dicompot.adata('hostname', ECFG['hostname'])
        dicompot.adata('externalIP', ECFG['ip_ext'])
        dicompot.adata('internalIP', ECFG['ip_int'])
        dicompot.adata('uuid', ECFG['uuid'])

        if dicompot.buildAlert() == "sendlimit":
            break

    dicompot.finAlert()
    return()
