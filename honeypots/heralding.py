# honeypots/heralding.py

import time
from modules.ealert import EAlert


def heralding(ECFG):

    heralding = EAlert('heralding', ECFG)

    ITEMS = ['heralding', 'nodeid', 'logfile']
    HONEYPOT = (heralding.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = heralding.lineREAD(HONEYPOT['logfile'], 'simple')

        if len(line) == 0:
            break
        if "timestamp" in line:
            continue

        heralding.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        heralding.data('timestamp', str(line[0:19]))
        heralding.data("timezone", time.strftime('%z'))

        heralding.data('source_address', str(line.split(',')[3]))
        heralding.data('target_address', str(line.split(',')[5]))
        heralding.data('source_port', str(line.split(',')[4]))
        heralding.data('target_port', str(line.split(',')[6]))
        heralding.data('source_protocol', "tcp")
        heralding.data('target_protocol', "tcp")

        heralding.request("description", "Heralding Honeypot")

        heralding.adata('hostname', ECFG['hostname'])
        heralding.adata('externalIP', ECFG['ip_ext'])
        heralding.adata('internalIP', ECFG['ip_int'])
        heralding.adata('uuid', ECFG['uuid'])
        heralding.adata('protocol', str(line.split(',')[7])) if str(line.split(',')[7]) != "" else None
        heralding.adata('username', str(line.split(',')[8])) if str(line.split(',')[8]) != "" else None
        heralding.adata('password', str(line.split(',')[9])) if str(line.split(',')[9]) != "" else None

        if heralding.buildAlert() == "sendlimit":
            break

    heralding.finAlert()
    return()
