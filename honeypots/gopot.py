# honeypots/gopot.py

import time
from modules.ealert import EAlert
from datetime import datetime


def gopot(ECFG):
    gopot = EAlert('gopot', ECFG)

    ITEMS = ['gopot', 'nodeid', 'logfile']
    HONEYPOT = (gopot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('gopot').lower() == "false":
        print(f"    -> Honeypot GOPot set to false. Skip Honeypot.")
        return()

    gopotSessionIDs = gopot.fileIndex('gopot.session', 'read')
    gopotSessions = {}

    gopot.alertCount('GOPOT', 'reset_counter')

    while (line := gopot.lineREAD(HONEYPOT['logfile'], 'json')):
   
        if line == 'jsonfail' or not line.get('id') or line.get('id') in gopotSessionIDs:
            continue
        
        sid = line['id']

        if line.get('phase') in ["start"] and line.get('id') not in gopotSessions:
            gopotSessions[sid] = {}
            gopotSessions[sid]['timestamp_start'] = datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            gopotSessions[sid]['source_ip'] = line.get('src_ip')
            gopotSessions[sid]['source_port'] = '0'
            gopotSessions[sid]['target_ip'] =  ECFG.get('ip_ext')
            gopotSessions[sid]['target_port'] =  line.get('dest_port')
        
            for key in [ 'status', 'method', 'path', 'user_agent', 'browser', 'browser_version', 'os', 'os_version', 'device', 'device_brand']:
                if line.get(key):
                    gopotSessions[sid][key] = line[key]

        if line.get('phase') == 'end' and line['id'] in gopotSessions:
           if line.get('timestamp'): gopotSessions[sid]['timestamp_stop'] = datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S')

    """ second loop """   

    for session in gopotSessions:
        if HONEYPOT.get('nodeid'): gopot.data('analyzer_id', HONEYPOT.get('nodeid'))

        if  gopotSessions[session].get('timestamp_start'):
            gopot.data('timestamp',gopotSessions[session]['timestamp_start'])
            gopot.data("timezone", time.strftime('%z'))

        if gopotSessions[session].get('source_ip'): gopot.data('source_address', gopotSessions[session]['source_ip'])
        if gopotSessions[session].get('target_ip'): gopot.data('target_address', gopotSessions[session]['target_ip'])
        if gopotSessions[session].get('source_port'): gopot.data('source_port', gopotSessions[session]['source_port'])
        if gopotSessions[session].get('target_port'): gopot.data('target_port', gopotSessions[session]['target_port'])
        gopot.data('source_protocol', 'tcp')
        gopot.data('target_protocol', 'tcp')

        gopot.request("description", "Go-Pot Honeypot")

        if gopotSessions[session].get('status'): gopot.adata('htmlerrocode', gopotSessions[session]['status'])
        if gopotSessions[session].get('method'): gopot.adata('htmlmethod', gopotSessions[session]['method'])
        if gopotSessions[session].get('path'): gopot.adata('url', gopotSessions[session]['path'])
        if gopotSessions[session].get('user_agent'): gopot.adata('user_agent', gopotSessions[session]['user_agent'])
        if gopotSessions[session].get('browser'): gopot.adata('browser', gopotSessions[session]['browser'])
        if gopotSessions[session].get('browser_version'): gopot.adata('browser_version', gopotSessions[session]['browser_version'])
        if gopotSessions[session].get('os'): gopot.adata('os', gopotSessions[session]['os'])
        if gopotSessions[session].get('os_version'): gopot.adata('os_version', gopotSessions[session]['os_version'])
        if gopotSessions[session].get('device'): gopot.adata('device', gopotSessions[session]['device'])
        if gopotSessions[session].get('device_brand'): gopot.adata('device_brand', gopotSessions[session]['device_brand'])

        gopot.adata('hostname', ECFG['hostname'])
        gopot.adata('externalIP', ECFG['ip_ext'])
        gopot.adata('internalIP', ECFG['ip_int'])
        gopot.adata('uuid', ECFG['uuid'])

        gopot.fileIndex('gopot.session', 'write', session)

        if gopot.buildAlert() == "sendlimit":
            break

    gopot.finAlert()
    return
