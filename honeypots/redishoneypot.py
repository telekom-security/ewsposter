# honeypots/redishoneypot

import time
from modules.ealert import EAlert
from datetime import datetime

def redishoneypot(ECFG):
    redishoneypot = EAlert('redishoneypot', ECFG)

    ITEMS = ['redishoneypot', 'nodeid', 'logfile']
    HONEYPOT = (redishoneypot.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = redishoneypot.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if line['action'] != "NewConnect":
            continue

        redishoneypot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'time' in line:
            redishoneypot.data('timestamp', datetime.fromisoformat(line['time']).strftime('%Y-%m-%d %H:%M:%S'))
            redishoneypot.data("timezone", time.strftime('%z'))

        redishoneypot.data('source_address', line['addr'].split(':')[0]) if 'addr' in line else None
        redishoneypot.data('target_address', ECFG['ip_ext'])
        redishoneypot.data('source_port', line['addr'].split(':')[1]) if 'addr' in line else None
        redishoneypot.data('target_port', '6379')
        redishoneypot.data('source_protocol', 'tcp')
        redishoneypot.data('target_protocol', 'tcp')

        redishoneypot.request('description', 'Redis Honeypot')

        redishoneypot.adata('hostname', ECFG['hostname'])
        redishoneypot.adata('externalIP', ECFG['ip_ext'])
        redishoneypot.adata('internalIP', ECFG['ip_int'])
        redishoneypot.adata('uuid', ECFG['uuid'])

        if redishoneypot.buildAlert() == "sendlimit":
            break

    redishoneypot.finAlert()
    return()