# honeypots/h0neytr4p.py

import time
from modules.ealert import EAlert
from datetime import datetime

def h0neytr4p(ECFG):
    h0neytr4p = EAlert('h0neytr4p', ECFG)

    ITEMS = ['h0neytr4p', 'nodeid', 'logfile', 'payloaddir']
    HONEYPOT = (h0neytr4p.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('h0neytr4p').lower() == "false":
        print(f"    -> Honeypot h0neytr4p set to false. Skip Honeypot.")
        return()

    while True:
        line = h0neytr4p.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        
        h0neytr4p.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        h0neytr4p.data('timestamp', datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
        h0neytr4p.data("timezone", time.strftime('%z'))

        h0neytr4p.data('source_address', line['src_ip'] ) if 'src_ip' in line else None
        h0neytr4p.data('target_address', ECFG['ip_ext'])
        h0neytr4p.data('source_port', '0') # No source_port in logs :-( 
        h0neytr4p.data('target_port', line['dest_port'] ) if 'dest_port' in line else None
        h0neytr4p.data('source_protocol', "tcp")
        h0neytr4p.data('target_protocol', "tcp")

        h0neytr4p.request("description", "H0neytr4p Honeypot")

        h0neytr4p.adata('user-agent', line['user-agent']) if 'user-agent' in line else None
        h0neytr4p.adata('user-agent_browser', line['user-agent_browser']) if 'user-agent_browser' in line else None
        h0neytr4p.adata('user-agent_browser_version', line['user-agent_browser_version']) if 'user-agent_browser_version' in line else None
        h0neytr4p.adata('user-agent_os', line['user-agent_os']) if 'user-agent_os' in line else None
        
        h0neytr4p.adata('trapped', line['trapped']) if 'trapped' in line else None
        h0neytr4p.adata('trapped_for', line['trapped_for']) if 'trapped_for' in line else None
        h0neytr4p.adata('request_uri', line['request_uri']) if 'request_uri' in line else None
        
        h0neytr4p.adata('externalIP', ECFG['ip_ext'])
        h0neytr4p.adata('internalIP', ECFG['ip_int'])
        h0neytr4p.adata('uuid', ECFG['uuid'])

        if h0neytr4p.buildAlert() == "sendlimit":
            break

    h0neytr4p.finAlert()
    return()            
