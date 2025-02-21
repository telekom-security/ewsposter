# honeypots/ipphoney.py

import time
from modules.ealert import EAlert


def ipphoney(ECFG):
    ipphoney = EAlert('ipphoney', ECFG)

    ITEMS = ['ipphoney', 'nodeid', 'logfile']
    HONEYPOT = (ipphoney.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = ipphoney.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        ipphoney.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            ipphoney.data('timestamp', line['timestamp'][0:10] + " " + line['timestamp'][11:19])
            ipphoney.data("timezone", time.strftime('%z'))

        ipphoney.data('source_address', line['src_ip']) if 'src_ip' in line else None
        ipphoney.data('target_address', line['dst_ip']) if 'dst_ip' in line else None
        ipphoney.data('source_port', line['src_port']) if 'src_port' in line else None
        ipphoney.data('target_port', line['dst_port']) if 'dst_port' in line else None
        ipphoney.data('source_protocol', "tcp")
        ipphoney.data('target_protocol', "tcp")

        ipphoney.request("description", "IPP Honeypot")

        ipphoney.adata('hostname', ECFG['hostname'])
        ipphoney.adata('externalIP', ECFG['ip_ext'])
        ipphoney.adata('internalIP', ECFG['ip_int'])
        ipphoney.adata('uuid', ECFG['uuid'])

        if ipphoney.buildAlert() == "sendlimit":
            break

    ipphoney.finAlert()
    return()
