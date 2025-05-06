# honeypots/cowrie.py

import time
import re
from modules.ealert import EAlert
from datetime import datetime

def cowrie(ECFG):
    cowrie = EAlert('cowrie', ECFG)

    ITEMS = ['cowrie', 'nodeid', 'logfile']
    HONEYPOT = (cowrie.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    cowrieSessionIDs = cowrie.fileIndex('cowrie.session', 'read')
    cowrieSessions = {}

    cowrie.alertCount('COWRIE', 'reset_counter')

    while True:
        line = cowrie.lineREAD(HONEYPOT['logfile'], 'json')

        if isinstance(line, int):
            break
        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if not line['session'] or line['session'] in cowrieSessionIDs:
            continue

        sid = line['session']

        if line['eventid'] == 'cowrie.session.connect' and line['session'] not in cowrieSessions:
            cowrieSessions[sid] = {}
            cowrieSessions[sid]['timestamp_start'] = line.get('timestamp')
            cowrieSessions[sid]['source_ip'] = line.get('src_ip')
            cowrieSessions[sid]['source_port'] = line.get('src_port')
            cowrieSessions[sid]['target_ip'] = line.get('dst_ip')
            cowrieSessions[sid]['target_port'] = line.get('dst_port')
            cowrieSessions[sid]['session_id'] = line.get('session')
            cowrieSessions[sid]['protocol'] = line.get('protocol')

        if line['eventid'] == 'cowrie.login.success' and line['session'] in cowrieSessions:
            cowrieSessions[sid]['login'] = "Success"
            cowrieSessions[sid]['username'] = line.get('username')
            cowrieSessions[sid]['password'] = line.get('password')
            cowrieSessions[sid]['timestamp_login'] = line.get('timestamp')

        if line['eventid'] == 'cowrie.login.failed' and line['session'] in cowrieSessions:
            cowrieSessions[sid]['login'] = "Fail"
            cowrieSessions[sid]['username'] = line.get('username')
            cowrieSessions[sid]['password'] = line.get('password')
            cowrieSessions[sid]['timestamp_login'] = line.get('timestamp')

        if line['eventid'] == 'cowrie.session.closed' and line['session'] in cowrieSessions:
            cowrieSessions[sid]['timestamp_close'] = line.get('timestamp')

        if line['eventid'] == 'cowrie.command.input' and line['session'] in cowrieSessions:
            try:
                cowrieSessions[sid]['input'].append(line['input'])
            except:
                cowrieSessions[sid]['input'] = [line.get('input')]

        if line['eventid'] == 'cowrie.client.version' and line['session'] in cowrieSessions:
            if "b'" in line["version"]:
                cowrieSessions[sid]['version'] = re.search(r"b'(.*)'", line.get("version"), re.M).group(1)
            else:
                cowrieSessions[sid]['version'] = line.get("version")

    """ second loop """

    for session in cowrieSessions:
        cowrie.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if cowrieSessions[session]['timestamp_start']:
            cowrie.data('timestamp', datetime.fromisoformat(cowrieSessions[session]['timestamp_start']).strftime('%Y-%m-%d %H:%M:%S'))
            cowrie.data("timezone", time.strftime('%z'))

        cowrie.data('source_address', cowrieSessions[session]['source_ip']) if cowrieSessions[session]['source_ip'] else None
        cowrie.data('target_address', cowrieSessions[session]['target_ip']) if cowrieSessions[session]['target_ip'] else None
        cowrie.data('source_port', cowrieSessions[session]['source_port']) if cowrieSessions[session]['source_port'] else None
        cowrie.data('target_port', cowrieSessions[session]['target_port']) if cowrieSessions[session]['target_port'] else None
        cowrie.data('source_protocol', 'tcp')
        cowrie.data('target_protocol', 'tcp')

        if cowrieSessions[session]['target_port'] == "23" or cowrieSessions[session]['target_port'] == "2323":
            cowrie.request("description", "Telnet Honeypot Cowrie")
        else:
            cowrie.request("description", "SSH Honeypot Cowrie")

        cowrie.adata('sessionid', session) if session else None
        cowrie.adata('logintime', f"{cowrieSessions[session]['timestamp_login'][0:10]} {cowrieSessions[session]['timestamp_login'][11:19]}") if 'timestamp_login' in cowrieSessions[session] else None
        cowrie.adata('endtimetime', f"{cowrieSessions[session]['timestamp_close'][0:10]} {cowrieSessions[session]['timestamp_close'][11:19]}") if 'timestamp_close' in cowrieSessions[session] else None
        cowrie.adata('version', str(cowrieSessions[session]['version'])) if 'version' in cowrieSessions[session] else None
        cowrie.adata('login', cowrieSessions[session]['login']) if 'login' in cowrieSessions[session] else None
        cowrie.adata('username', cowrieSessions[session]['username']) if 'username' in cowrieSessions[session]else None
        cowrie.adata('password', cowrieSessions[session]['password']) if 'password' in cowrieSessions[session] else None
        cowrie.adata('input', cowrieSessions[session]['input']) if 'input' in cowrieSessions[session] else None
        cowrie.adata('hostname', ECFG['hostname'])
        cowrie.adata('externalIP', ECFG['ip_ext'])
        cowrie.adata('internalIP', ECFG['ip_int'])
        cowrie.adata('uuid', ECFG['uuid'])

        cowrie.fileIndex('cowrie.session', 'write', session)

        if cowrie.buildAlert() == "sendlimit":
            break

    cowrie.finAlert()
    return()
