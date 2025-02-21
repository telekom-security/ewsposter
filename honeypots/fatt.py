# honeypots/fatt.py

import time
from modules.ealert import EAlert


def fatt(ECFG):
    fatt = EAlert('fatt', ECFG)

    ITEMS = ['fatt', 'nodeid', 'logfile']
    HONEYPOT = (fatt.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = fatt.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        fatt.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            fatt.data('timestamp', line['timestamp'][0:10] + " " + line['timestamp'][11:19])
            fatt.data("timezone", time.strftime('%z'))

        fatt.data('source_address', line['sourceIp']) if 'sourceIp' in line else None
        fatt.data('target_address', ECFG['ip_ext'])
        fatt.data('source_port', str(line['sourcePort'])) if 'sourcePort' in line else None
        fatt.data('target_port', str(line['destinationPort'])) if 'destinationPort' in line else None
        fatt.data('source_protocol', "tcp")
        fatt.data('target_protocol', "tcp")

        fatt.request("description", "FATT Honeypot")

        fatt.adata('hostname', ECFG['hostname'])
        fatt.adata('externalIP', ECFG['ip_ext'])
        fatt.adata('internalIP', ECFG['ip_int'])
        fatt.adata('uuid', ECFG['uuid'])

        if fatt.buildAlert() == "sendlimit":
            break

    fatt.finAlert()
    return()

