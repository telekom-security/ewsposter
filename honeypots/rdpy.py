# honeypots/rdpy.py

import time
from modules.ealert import EAlert


def rdpy(ECFG):
    rdpy = EAlert('rdpy', ECFG)

    ITEMS = ['rdpy', 'nodeid', 'logfile']
    HONEYPOT = (rdpy.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = rdpy.lineREAD(HONEYPOT['logfile'], 'simple')

        if line[0:3] == '[*]':
            continue
        if len(line) == 0:
            break

        rdpy.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        rdpy.data('timestamp', f"{line[0:10]} {line[11:19]}")
        rdpy.data("timezone", time.strftime('%z'))

        rdpy.data('source_address', str(line.split("Connection from ")[1].split(":")[0])) if 'Connection from ' in line else None
        rdpy.data('target_address', ECFG['ip_ext'])
        rdpy.data('source_port', str(line.split("Connection from ")[1].split(":")[1])) if 'Connection from ' in line else None
        rdpy.data('target_port', "3389")
        rdpy.data('source_protocol', "tcp")
        rdpy.data('target_protocol', "tcp")

        rdpy.request("description", "RDP Honeypot RDPY")

        rdpy.adata('hostname', ECFG['hostname'])
        rdpy.adata('externalIP', ECFG['ip_ext'])
        rdpy.adata('internalIP', ECFG['ip_int'])
        rdpy.adata('uuid', ECFG['uuid'])

        if rdpy.buildAlert() == "sendlimit":
            break

    rdpy.finAlert()
    return()
