# honeypots/honeysap.py

import time
from modules.ealert import EAlert
from datetime import datetime


def honeysap(ECFG):
    honeysap = EAlert('honeysap', ECFG)

    ITEMS = ['honeysap', 'nodeid', 'logfile']
    HONEYPOT = (honeysap.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = honeysap.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        honeysap.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            honeysap.data('timestamp', datetime.fromisoformat(line['timestamp'][0:19]).strftime('%Y-%m-%d %H:%M:%S'))
            honeysap.data("timezone", time.strftime('%z'))

        honeysap.data('source_address', line['source_ip']) if 'source_ip' in line else None
        honeysap.data('target_address', ECFG['ip_ext'])
        honeysap.data('source_port', str(line['source_port'])) if 'source_port' in line else None
        honeysap.data('target_port', str(line['target_port'])) if 'target_port' in line else None
        honeysap.data('source_protocol', "tcp")
        honeysap.data('target_protocol', "tcp")

        honeysap.request("description", "Honeysap Honeypot")
        honeysap.request("request", line['request']) if line['request'] != "" else None

        honeysap.adata('hostname', ECFG['hostname'])
        honeysap.adata('externalIP', ECFG['ip_ext'])
        honeysap.adata('internalIP', ECFG['ip_int'])
        honeysap.adata('uuid', ECFG['uuid'])

        if honeysap.buildAlert() == "sendlimit":
            break

    honeysap.finAlert()
    return()
