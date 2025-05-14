# honeypots/vnclowpot.py

import time
from modules.ealert import EAlert


def vnclowpot(ECFG):
    vnclowpot = EAlert('vnclowpot', ECFG)

    ITEMS = ['vnclowpot', 'nodeid', 'logfile']
    HONEYPOT = (vnclowpot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('vnclowpot').lower() == "false":
        print(f"    -> Honeypot VNClowPot set to false. Skip Honeypot.")
        return()

    while True:
        line = vnclowpot.lineREAD(HONEYPOT['logfile'], 'simple')

        if len(line) == 0:
            break

        vnclowpot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        vnclowpot.data('timestamp', f"{line[0:10].replace('/', '-')} {line[11:19]}")
        vnclowpot.data("timezone", time.strftime('%z'))

        vnclowpot.data('source_address', str(line.split(' ')[2].split(':')[0]))
        vnclowpot.data('target_address', ECFG['ip_ext'])
        vnclowpot.data('source_port', str(line.split(' ')[2].split(':')[1]))
        vnclowpot.data('target_port', "5900")
        vnclowpot.data('source_protocol', "tcp")
        vnclowpot.data('target_protocol', "tcp")

        vnclowpot.request("description", "vnc Honeypot vnclowpot")

        vnclowpot.adata('hostname', ECFG['hostname'])
        vnclowpot.adata('externalIP', ECFG['ip_ext'])
        vnclowpot.adata('internalIP', ECFG['ip_int'])
        vnclowpot.adata('uuid', ECFG['uuid'])

        if vnclowpot.buildAlert() == "sendlimit":
            break

    vnclowpot.finAlert()
    return()
