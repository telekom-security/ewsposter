# honeypots/endlessh.py

import time
from modules.ealert import EAlert


def endlessh(ECFG):
    endlessh = EAlert('endlessh', ECFG)

    ITEMS = ['endlessh', 'nodeid', 'logfile']
    HONEYPOT = (endlessh.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = endlessh.lineREAD(HONEYPOT['logfile'], 'simple')

        if len(line) == 0:
            break
        if line.split(' ')[1] != "ACCEPT":
            continue

        endlessh.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None
        endlessh.data('timestamp', f"{line.split(' ')[0][0:10]} {line.split(' ')[0][11:19]}")
        endlessh.data("timezone", time.strftime('%z'))

        endlessh.data('source_address', line.split(' ')[2].replace('host=', ''))
        endlessh.data('target_address', ECFG['ip_ext'])
        endlessh.data('source_port', line.split(' ')[3].replace('port=', ''))
        endlessh.data('target_port', '22')
        endlessh.data('source_protocol', 'tcp')
        endlessh.data('target_protocol', 'tcp')

        endlessh.request('description', 'Endlessh Honeypot')

        endlessh.adata('hostname', ECFG['hostname'])
        endlessh.adata('externalIP', ECFG['ip_ext'])
        endlessh.adata('internalIP', ECFG['ip_int'])
        endlessh.adata('uuid', ECFG['uuid'])

        if endlessh.buildAlert() == "sendlimit":
            break

    endlessh.finAlert()
    return()