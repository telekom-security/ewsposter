# honeypots/galah.py

import time
from modules.ealert import EAlert
from datetime import datetime


def galah(ECFG):
    galah = EAlert('galah', ECFG)

    ITEMS = ['galah', 'nodeid', 'logfile']
    HONEYPOT = (galah.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return

    galahSessionIDs = galah.fileIndex('galah.session', 'read')
    galahSessions = {}

    galah.alertCount('GALAH', 'reset_counter')

    while (line := galah.lineREAD(HONEYPOT['logfile'], 'json')):
        
        if line == 'jsonfail' or not line.get('session') or line.get('session') in galahSessionIDs:
            continue
        
        sid = line['session']

        if line.get('msg') in ["successfulResponse"] and line.get('session') not in galahSessions:
            galahSessions[sid] = {}
            galahSessions[sid]['timestamp_start'] = datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            galahSessions[sid]['source_ip'] = line.get('src_ip')
            galahSessions[sid]['source_port'] = line.get('src_port')
            galahSessions[sid]['target_ip'] =  ECFG.get('ip_ext')
            galahSessions[sid]['target_port'] =  line.get('dest_port')
        
            for key in ['request.requestURI', 'request.userAgent', 'response.metadata.model', 'response.metadata.provider']:
                if line.get(key):
                    galahSessions[sid][key] = line[key]

        if line.get('msg') in ["failedResponse: returned 500 internal server error"] and line['session'] in galahSessions:
           if line.get('fields.msg'):
               galahSessions[sid]['fields.msg'] = line['fields.msg']

    """ second loop """

    for session in galahSessions:
        if HONEYPOT.get('nodeid'): galah.data('analyzer_id', HONEYPOT.get('nodeid'))

        if  galahSessions[session].get('timestamp_start'):
            galah.data('timestamp',galahSessions[session]['timestamp_start'])
            galah.data("timezone", time.strftime('%z'))

        if galahSessions[session].get('source_ip'): galah.data('source_address', galahSessions[session]['source_ip'])
        if galahSessions[session].get('target_ip'): galah.data('target_address', galahSessions[session]['target_ip'])
        if galahSessions[session].get('source_port'): galah.data('source_port', galahSessions[session]['source_port'])
        if galahSessions[session].get('target_port'): galah.data('target_port', galahSessions[session]['target_port'])
        galah.data('source_protocol', 'tcp')
        galah.data('target_protocol', 'tcp')

        galah.request("description", "Galah Honeypot")

        if galahSessions[session].get('request.requestURI'): galah.adata('url', galahSessions[session]['request.requestURI'])
        if galahSessions[session].get('request.userAgent'): galah.adata('useragent', galahSessions[session]['request.userAgent'])
        if galahSessions[session].get('response.metadata.model'): galah.adata('llmmodel', galahSessions[session]['response.metadata.model'])            
        if galahSessions[session].get('response.metadata.provider'): galah.adata('llmprovider', galahSessions[session]['response.metadata.provider'])            

        galah.adata('hostname', ECFG['hostname'])
        galah.adata('externalIP', ECFG['ip_ext'])
        galah.adata('internalIP', ECFG['ip_int'])
        galah.adata('uuid', ECFG['uuid'])

        galah.fileIndex('galah.session', 'write', session)

        if galah.buildAlert() == "sendlimit":
            break

    galah.finAlert()
    return
