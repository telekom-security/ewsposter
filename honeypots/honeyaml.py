# honeypots/honeyaml.py

import time
from modules.ealert import EAlert
from datetime import datetime

def honeyaml(ECFG):
    honeyaml = EAlert('honeyaml', ECFG)

    ITEMS = ['honeyaml', 'nodeid', 'logfile']
    HONEYPOT = (honeyaml.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('honeyaml').lower() == "false":
        print(f"    -> Honeypot Honeyaml set to false. Skip Honeypot.")
        return()

    while True:
        line = honeyaml.lineREAD(HONEYPOT['logfile'], 'json')
        
        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        honeyaml.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'src_ip' in line:
            if 'timestamp' in line:
                honeyaml.data('timestamp', datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
                honeyaml.data('timezone', time.strftime('%z'))

            honeyaml.data('source_address', line['src_ip']) if 'src_ip' in line else None
            honeyaml.data('target_address', ECFG['ip_ext'])
            honeyaml.data('source_port', '0')
            honeyaml.data('target_port', str(line['dest_port'])) if 'dest_port' in line else None
            honeyaml.data('source_protocol', 'tcp')
            honeyaml.data('target_protocol', 'tcp')

            honeyaml.request('description', 'Honeyaml Honeypot')

            honeyaml.adata('method', line['method']) if 'method' in line else None
            honeyaml.adata('path', line['path']) if 'path' in line else None
            honeyaml.adata('status_code', line['status_code']) if 'status_code' in line else None
            honeyaml.adata('user_agent', line['user_agent']) if 'user_agent' in line else None
            honeyaml.adata('user_agent_browser', line['user_agent_browser']) if 'user_agent_browser' in line else None
            
            honeyaml.adata('hostname', ECFG['hostname'])
            honeyaml.adata('externalIP', ECFG['ip_ext'])
            honeyaml.adata('internalIP', ECFG['ip_int'])
            honeyaml.adata('uuid', ECFG['uuid'])

            if honeyaml.buildAlert() == "sendlimit":
                break
            
    honeyaml.finAlert()
    return()            
