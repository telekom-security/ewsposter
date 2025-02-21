# honeypots/honeypy.py 

import time
from modules.ealert import EAlert


def honeypy(ECFG):
    honeypy = EAlert('honeypy', ECFG)

    ITEMS = ['honeypy', 'nodeid', 'logfile']
    HONEYPOT = (honeypy.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = honeypy.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if line['event_type'] != "CONNECT":
            continue

        honeypy.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            honeypy.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
            honeypy.data("timezone", time.strftime('%z'))

        honeypy.data('source_address', line['src_ip']) if 'src_ip' in line else None
        honeypy.data('target_address', line['dest_ip']) if 'dest_ip' in line else None
        honeypy.data('source_port', line['src_port']) if 'src_port' in line else None
        honeypy.data('target_port', line['dest_port']) if 'dest_port' in line else None
        honeypy.data('source_protocol', line['protocol'].lower()) if 'protocol' in line else None
        honeypy.data('target_protocol', line['protocol'].lower()) if 'protocol' in line else None

        honeypy.request('description', 'Honeypy Honeypot')

        honeypy.adata('hostname', ECFG['hostname'])
        honeypy.adata('externalIP', ECFG['ip_ext'])
        honeypy.adata('internalIP', ECFG['ip_int'])
        honeypy.adata('uuid', ECFG['uuid'])

        if honeypy.buildAlert() == "sendlimit":
            break

    honeypy.finAlert()
    return()
