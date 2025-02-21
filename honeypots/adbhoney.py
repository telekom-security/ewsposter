# honeypots/adbhoney.py

import time
from modules.ealert import EAlert
from datetime import datetime

def adbhoney(ECFG):
    adbhoney = EAlert('adbhoney', ECFG)

    ITEMS = ['adbhoney', 'nodeid', 'logfile', 'malwaredir']
    HONEYPOT = (adbhoney.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    adbhoneySessionIDs = adbhoney.fileIndex('adbhoney.session', 'read')
    adbhoneySessions = {}

    adbhoney.alertCount('ADBHONEY', 'reset_counter')

    while True:
        line = adbhoney.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if not line['session'] or line['session'] in adbhoneySessionIDs:
            continue

        sid = line['session']

        if line['eventid'] == 'adbhoney.session.connect' and line['session'] not in adbhoneySessions:
            adbhoneySessions[sid] = {}
            adbhoneySessions[sid]['timestamp'] = line['timestamp']
            adbhoneySessions[sid]['source_ip'] = line['src_ip']
            adbhoneySessions[sid]['source_port'] = line['src_port']
            adbhoneySessions[sid]['target_ip'] = line['dest_ip']
            adbhoneySessions[sid]['target_port'] = line['dest_port']
            adbhoneySessions[sid]['session'] = line['session']

        if line['eventid'] == 'adbhoney.session.closed' and line['session'] in adbhoneySessions:
            adbhoneySessions[sid]['duration'] = line['duration']

        if line['eventid'] == 'adbhoney.command.input' and line['session'] in adbhoneySessions:
            try:
                adbhoneySessions[sid]['input'].append(line['input'] + "\n")
            except:
                adbhoneySessions[sid]['input'] = line['input'] + "\n"

        if line['eventid'] == 'adbhoney.session.file_upload' and line['session'] in adbhoneySessions:
            for index in ['shasum', 'outfile', 'filename']:
                if index not in adbhoneySessions[sid]:
                    adbhoneySessions[sid][index] = {}
                if index == 'shasum':
                    adbhoneySessions[sid][index][len(adbhoneySessions[sid][index])] = line['shasum']
                if index == 'outfile':
                    adbhoneySessions[sid][index][len(adbhoneySessions[sid][index])] = line['outfile'][3:]  # remove "dl/"
                if index == 'filename':
                    adbhoneySessions[sid][index][len(adbhoneySessions[sid][index])] = line['filename']

    """ second loop """

    for session in adbhoneySessions:
        adbhoney.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if adbhoneySessions[session]['timestamp']:
            adbhoney.data('timestamp', datetime.fromisoformat(adbhoneySessions[session]['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
            adbhoney.data("timezone", time.strftime('%z'))

        adbhoney.data('source_address', adbhoneySessions[session]['source_ip']) if adbhoneySessions[session]['source_ip'] else None
        adbhoney.data('target_address', ECFG['ip_ext'])
        adbhoney.data('source_port', str(adbhoneySessions[session]['source_port'])) if adbhoneySessions[session]['source_port'] else None
        adbhoney.data('target_port', str(adbhoneySessions[session]['target_port'])) if adbhoneySessions[session]['target_port'] else None
        adbhoney.data('source_protocol', "tcp")
        adbhoney.data('target_protocol', "tcp")

        adbhoney.request("description", "ADBHoney Honeypot")

        if 'outfile' in adbhoneySessions[session]:
            for index in range(len(adbhoneySessions[session]['outfile'])):
                error, payload = adbhoney.malwarecheck(HONEYPOT['malwaredir'], adbhoneySessions[session]['outfile'][index], ECFG['del_malware_after_send'], str(adbhoneySessions[session]['shasum'][index]))
                if (error is False):
                    continue
                elif (error is True) and (len(payload) <= 5 * 1024) and (len(payload) > 0):
                    adbhoney.request('binary', payload.decode('utf-8'))
                    break
                elif (error is True) and (ECFG["send_malware"] is True) and (len(payload) > 0):
                    adbhoney.request('largepayload', payload.decode('utf-8'))
                    break

        adbhoney.adata('duration', adbhoneySessions[session]['duration']) if 'duration' in adbhoneySessions[session] else None
        adbhoney.adata('input', adbhoneySessions[session]['input']) if 'input' in adbhoneySessions[session] else None
        adbhoney.adata('hostname', ECFG['hostname'])
        adbhoney.adata('externalIP', ECFG['ip_ext'])
        adbhoney.adata('internalIP', ECFG['ip_int'])
        adbhoney.adata('uuid', ECFG['uuid'])

        adbhoney.fileIndex('adbhoney.session', 'write', session)

        if adbhoney.buildAlert() == "sendlimit":
            break

    adbhoney.finAlert()
    return()

