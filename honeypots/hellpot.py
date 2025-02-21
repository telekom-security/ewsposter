# honeypots/hellpot.py

import time
from modules.ealert import EAlert
from datetime import datetime

def hellpot(ECFG):
    hellpot = EAlert('hellpot', ECFG)
    
    ITEMS = ['hellpot', 'nodeid', 'logfile']
    HONEYPOT = (hellpot.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return

    while True:
        line = hellpot.lineREAD(HONEYPOT['logfile'], 'json')
  
        if len(line) == 0:
            break
        if line == 'jsonfail' or line.get('message') != 'NEW':
            continue

        hellpot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None
        
        if line.get('time'):
            hellpot.data('timestamp', datetime.fromisoformat(line['time']).strftime('%Y-%m-%d %H:%M:%S'))
            hellpot.data('timezone', time.strftime('%z'))
        
        if line.get('REMOTE_ADDR'): hellpot.data('source_address', line['REMOTE_ADDR'])
        hellpot.data('target_address', ECFG['ip_ext'])
        hellpot.data('source_port', '0') 
        hellpot.data('target_port', '80') 
        hellpot.data('source_protocol', "tcp")
        hellpot.data('target_protocol', "tcp")

        hellpot.request("description", "Hellpot Honeypot")

        if line.get('URL'): hellpot.adata('url', line['URL'])
        hellpot.adata('hostname', ECFG['hostname'])
        hellpot.adata('externalIP', ECFG['ip_ext'])
        hellpot.adata('internalIP', ECFG['ip_int'])
        hellpot.adata('uuid', ECFG['uuid'])

        if hellpot.buildAlert() == "sendlimit":
            break
    
    hellpot.finAlert()
    return
