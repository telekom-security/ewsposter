# honeypots/medpot.py 

import time
from modules.ealert import EAlert
from datetime import datetime

def medpot(ECFG):
    medpot = EAlert('medpot', ECFG)

    ITEMS = ['medpot', 'nodeid', 'logfile']
    HONEYPOT = (medpot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('medpot').lower() == "false":
        print(f"    -> Honeypot Medpot set to false. Skip Honeypot.")
        return()

    while True:
        line = medpot.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        medpot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            medpot.data('timestamp', datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
            medpot.data("timezone", time.strftime('%z'))

        medpot.data('source_address', line['src_ip']) if 'src_ip' in line else None
        medpot.data('target_address', ECFG['ip_ext'])
        medpot.data('source_port', line['src_port']) if 'src_port' in line else None
        medpot.data('target_port', '2575')
        medpot.data('source_protocol', 'tcp')
        medpot.data('target_protocol', 'tcp')

        medpot.request('description', 'Medpot Honeypot')

        medpot.adata('hostname', ECFG['hostname'])
        medpot.adata('externalIP', ECFG['ip_ext'])
        medpot.adata('internalIP', ECFG['ip_int'])
        medpot.adata('uuid', ECFG['uuid'])

        if medpot.buildAlert() == "sendlimit":
            break

    medpot.finAlert()
    return()
