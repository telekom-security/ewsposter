# honeypots/beelzebub.py

import time
from modules.ealert import EAlert
from datetime import datetime


def beelzebub(ECFG):
    beelzebub = EAlert('beelzebub', ECFG)

    ITEMS = ['beelzebub', 'nodeid', 'logfile']
    HONEYPOT = (beelzebub.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return

    beelzebubSessionIDs = beelzebub.fileIndex('beelzebub.session', 'read')
    beelzebubSessions = {}

    beelzebub.alertCount('BEELZEBUB', 'reset_counter')

    while (line := beelzebub.lineREAD(HONEYPOT['logfile'], 'json')):

        if line == 'jsonfail' or not line.get('session') or line.get('session') in beelzebubSessionIDs:
            continue
        
        sid = line['session']
        
        if line.get('message') in ["New SSH Inline Session", "New SSH Session", "New SSH attempt"] and line.get('session') not in beelzebubSessions:
        
            beelzebubSessions[sid] = {}
            beelzebubSessions[sid]['timestamp_start'] = datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            beelzebubSessions[sid]['source_ip'] = line.get('src_ip')
            beelzebubSessions[sid]['source_port'] = line.get('src_port')
            beelzebubSessions[sid]['target_ip'] =  ECFG.get('ip_ext')
            beelzebubSessions[sid]['target_port'] =  line.get('dest_port')
            beelzebubSessions[sid]['type'] =  line.get('message')
            
            for key in ['protocol', 'username', 'password', 'input', 'environ', 'client', 'client_version']:
                if line.get(key):
                    beelzebubSessions[sid][key] = line[key]
            
        if line.get('message') in ["End SSH Inline Session", "End SSH Session"] and line['session'] in beelzebubSessions:
            beelzebubSessions[sid]['timestamp_stop'] = datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            beelzebubSessions[sid]['type'] =  line.get('message')
      
        if line['message'] == "New SSH Terminal Session" and line['session'] in beelzebubSessions:
            if 'input' in beelzebubSessions[sid]:
                beelzebubSessions[sid]['input'] += f";{line.get('input')}"
            else:
                beelzebubSessions[sid]['input'] = line.get('input')
            beelzebubSessions[sid]['type'] =  line.get('message')
      
    """ second loop """

    for session in beelzebubSessions:
        if HONEYPOT.get('nodeid'): beelzebub.data('analyzer_id', HONEYPOT.get('nodeid'))

        if  beelzebubSessions[session]['timestamp_start']:
            beelzebub.data('timestamp',beelzebubSessions[session].get('timestamp_start'))
            beelzebub.data("timezone", time.strftime('%z'))

        if beelzebubSessions[session].get('source_ip'): beelzebub.data('source_address', beelzebubSessions[session].get('source_ip'))
        if beelzebubSessions[session].get('target_ip'): beelzebub.data('target_address', beelzebubSessions[session].get('target_ip'))
        if beelzebubSessions[session].get('source_port'): beelzebub.data('source_port', beelzebubSessions[session].get('source_port'))
        if beelzebubSessions[session].get('target_port'): beelzebub.data('target_port', beelzebubSessions[session].get('target_port'))
        beelzebub.data('source_protocol', 'tcp')
        beelzebub.data('target_protocol', 'tcp')

        beelzebub.request("description", "Beelzebub Honeypot")

        if beelzebubSessions[session].get('protocol'): beelzebub.adata('protocol', beelzebubSessions[session].get('protocol'))
        if beelzebubSessions[session].get('timestamp_start'): beelzebub.adata('logintime', beelzebubSessions[session].get('timestamp_start'))
        if beelzebubSessions[session].get('timestamp_stop'): beelzebub.adata('logouttime', beelzebubSessions[session].get('timestamp_stop'))            
        if beelzebubSessions[session].get('type'): beelzebub.adata('type', beelzebubSessions[session].get('type'))
        if beelzebubSessions[session].get('username'): beelzebub.adata('username', beelzebubSessions[session].get('username'))
        if beelzebubSessions[session].get('password'): beelzebub.adata('password', beelzebubSessions[session].get('password'))
        if beelzebubSessions[session].get('input'): beelzebub.adata('input', beelzebubSessions[session].get('input'))
        if beelzebubSessions[session].get('environ'): beelzebub.adata('environ', beelzebubSessions[session].get('environ'))
        if beelzebubSessions[session].get('client'): beelzebub.adata('client', beelzebubSessions[session].get('client'))
        if beelzebubSessions[session].get('client_version'): beelzebub.adata('client_version', beelzebubSessions[session].get('client_version'))

        beelzebub.adata('hostname', ECFG['hostname'])
        beelzebub.adata('externalIP', ECFG['ip_ext'])
        beelzebub.adata('internalIP', ECFG['ip_int'])
        beelzebub.adata('uuid', ECFG['uuid'])

        beelzebub.fileIndex('beelzebub.session', 'write', session)

        if beelzebub.buildAlert() == "sendlimit":
            break

    beelzebub.finAlert()
    return
