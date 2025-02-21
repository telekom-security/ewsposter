# honeypots/miniprint.py

import time
from modules.ealert import EAlert
from datetime import datetime

def miniprint(ECFG):
    miniprint = EAlert('miniprint', ECFG)

    ITEMS = ['miniprint', 'nodeid', 'logfile']
    HONEYPOT = (miniprint.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()
    
    while True:
        line = miniprint.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        # No SessionID in Logs so only Meta Event 'Connection opened'
        if line['info'] == 'Connection opened':
            miniprint.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None
            
            if 'timestamp' in line:
                miniprint.data('timestamp', datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
                miniprint.data('timezone', time.strftime('%z'))
            
            miniprint.data('source_address', line['src_ip']) if 'src_ip' in line else None
            miniprint.data('target_address', ECFG['ip_ext'])
            miniprint.data('source_port', '0') # No source_port in logs :-( """
            miniprint.data('target_port', str(line['dest_port'])) if 'dest_port' in line else None
            miniprint.data('source_protocol', "tcp")
            miniprint.data('target_protocol', "tcp")

            miniprint.request("description", "Miniprint Honeypot")

            miniprint.adata('hostname', ECFG['hostname'])
            miniprint.adata('externalIP', ECFG['ip_ext'])
            miniprint.adata('internalIP', ECFG['ip_int'])
            miniprint.adata('uuid', ECFG['uuid'])

            if miniprint.buildAlert() == "sendlimit":
                 break

    miniprint.finAlert()
    return()            
