# honeypots/rdphoneypot.py

import time
from datetime import datetime
from modules.ealert import EAlert


def _timestamp(timestamp):
    if not timestamp:
        return(None)

    clean_timestamp = timestamp
    if clean_timestamp.endswith('Z'):
        clean_timestamp = clean_timestamp[:-1]
        if '+' not in clean_timestamp[10:] and '-' not in clean_timestamp[10:]:
            clean_timestamp = clean_timestamp + '+00:00'

    try:
        return(datetime.fromisoformat(clean_timestamp).strftime('%Y-%m-%d %H:%M:%S'))
    except ValueError:
        if len(timestamp) >= 19:
            return(f"{timestamp[0:10]} {timestamp[11:19]}")
        return(None)


def rdphoneypot(ECFG):
    rdphoneypot = EAlert('rdphoneypot', ECFG)

    ITEMS = ['rdphoneypot', 'nodeid', 'logfile']
    HONEYPOT = (rdphoneypot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('rdphoneypot').lower() == "false":
        print(f"    -> Honeypot rdphoneypot set to false. Skip Honeypot.")
        return()

    rdphoneypotSessionIDs = rdphoneypot.fileIndex('rdphoneypot.session', 'read')
    rdphoneypotSessions = {}

    rdphoneypot.alertCount('RDPHONEYPOT', 'reset_counter')

    while (line := rdphoneypot.lineREAD(HONEYPOT['logfile'], 'json')):

        if line == 'jsonfail' or not line.get('session') or line.get('session') in rdphoneypotSessionIDs:
            continue

        sid = line['session']
        if sid not in rdphoneypotSessions:
            rdphoneypotSessions[sid] = {}

        session = rdphoneypotSessions[sid]

        if line.get('src_ip'): session['source_ip'] = line.get('src_ip')
        if line.get('src_port'): session['source_port'] = line.get('src_port')
        if line.get('dst_ip'): session['target_ip'] = line.get('dst_ip')
        if line.get('dst_port'): session['target_port'] = line.get('dst_port')
        if line.get('sensor'): session['sensor'] = line.get('sensor')

        if line.get('eventid') == 'rdphoneypot.session.connect':
            session['timestamp_start'] = _timestamp(line.get('timestamp'))
            session['message_connect'] = line.get('message')

        if line.get('eventid') == 'rdphoneypot.login':
            session['timestamp_login'] = _timestamp(line.get('timestamp'))
            session['message_login'] = line.get('message')

            for key in [
                'auth_method', 'derived_domain', 'domain', 'hashcat_line', 'hostname',
                'nt_challenge', 'nt_proof', 'nt_response', 'password', 'username'
            ]:
                if line.get(key) is not None:
                    session[key] = line.get(key)

        if line.get('eventid') == 'rdphoneypot.session.closed':
            session['timestamp_stop'] = _timestamp(line.get('timestamp'))
            session['message_closed'] = line.get('message')
            if line.get('duration') is not None:
                session['duration'] = line.get('duration')

    """ second loop """

    for session in rdphoneypotSessions:
        if not rdphoneypotSessions[session].get('timestamp_stop'):
            continue

        if HONEYPOT.get('nodeid'): rdphoneypot.data('analyzer_id', HONEYPOT.get('nodeid'))

        if rdphoneypotSessions[session].get('timestamp_start'):
            rdphoneypot.data('timestamp', rdphoneypotSessions[session].get('timestamp_start'))
        else:
            rdphoneypot.data('timestamp', rdphoneypotSessions[session].get('timestamp_stop'))
        rdphoneypot.data("timezone", time.strftime('%z'))

        if rdphoneypotSessions[session].get('source_ip'): rdphoneypot.data('source_address', rdphoneypotSessions[session].get('source_ip'))
        if rdphoneypotSessions[session].get('target_ip'): rdphoneypot.data('target_address', rdphoneypotSessions[session].get('target_ip'))
        else: rdphoneypot.data('target_address', ECFG['ip_ext'])
        if rdphoneypotSessions[session].get('source_port'): rdphoneypot.data('source_port', rdphoneypotSessions[session].get('source_port'))
        if rdphoneypotSessions[session].get('target_port'): rdphoneypot.data('target_port', rdphoneypotSessions[session].get('target_port'))
        rdphoneypot.data('source_protocol', 'tcp')
        rdphoneypot.data('target_protocol', 'tcp')

        rdphoneypot.request("description", "RDP Honeypot rdphoneypot")

        rdphoneypot.adata('sessionid', session) if session else None
        if rdphoneypotSessions[session].get('sensor'): rdphoneypot.adata('sensor', rdphoneypotSessions[session].get('sensor'))
        if rdphoneypotSessions[session].get('timestamp_login'): rdphoneypot.adata('logintime', rdphoneypotSessions[session].get('timestamp_login'))
        if rdphoneypotSessions[session].get('timestamp_stop'): rdphoneypot.adata('logouttime', rdphoneypotSessions[session].get('timestamp_stop'))
        if rdphoneypotSessions[session].get('duration') is not None: rdphoneypot.adata('duration', rdphoneypotSessions[session].get('duration'))
        if rdphoneypotSessions[session].get('auth_method'): rdphoneypot.adata('auth_method', rdphoneypotSessions[session].get('auth_method'))
        if rdphoneypotSessions[session].get('derived_domain') is not None: rdphoneypot.adata('derived_domain', rdphoneypotSessions[session].get('derived_domain'))
        if rdphoneypotSessions[session].get('domain') is not None: rdphoneypot.adata('domain', rdphoneypotSessions[session].get('domain'))
        if rdphoneypotSessions[session].get('hostname') is not None: rdphoneypot.adata('client_hostname', rdphoneypotSessions[session].get('hostname'))
        if rdphoneypotSessions[session].get('username') is not None: rdphoneypot.adata('username', rdphoneypotSessions[session].get('username'))
        if rdphoneypotSessions[session].get('password') is not None: rdphoneypot.adata('password', rdphoneypotSessions[session].get('password'))
        if rdphoneypotSessions[session].get('hashcat_line') is not None: rdphoneypot.adata('hashcat_line', rdphoneypotSessions[session].get('hashcat_line'))
        if rdphoneypotSessions[session].get('nt_challenge') is not None: rdphoneypot.adata('nt_challenge', rdphoneypotSessions[session].get('nt_challenge'))
        if rdphoneypotSessions[session].get('nt_proof') is not None: rdphoneypot.adata('nt_proof', rdphoneypotSessions[session].get('nt_proof'))
        if rdphoneypotSessions[session].get('nt_response') is not None: rdphoneypot.adata('nt_response', rdphoneypotSessions[session].get('nt_response'))
        if rdphoneypotSessions[session].get('message_connect'): rdphoneypot.adata('message_connect', rdphoneypotSessions[session].get('message_connect'))
        if rdphoneypotSessions[session].get('message_login'): rdphoneypot.adata('message_login', rdphoneypotSessions[session].get('message_login'))
        if rdphoneypotSessions[session].get('message_closed'): rdphoneypot.adata('message_closed', rdphoneypotSessions[session].get('message_closed'))

        rdphoneypot.adata('hostname', ECFG['hostname'])
        rdphoneypot.adata('externalIP', ECFG['ip_ext'])
        rdphoneypot.adata('internalIP', ECFG['ip_int'])
        rdphoneypot.adata('uuid', ECFG['uuid'])

        rdphoneypot.fileIndex('rdphoneypot.session', 'write', session)

        if rdphoneypot.buildAlert() == "sendlimit":
            break

    rdphoneypot.finAlert()
    return()
