# honeypots/conpot.py

import time
import glob
from modules.ealert import EAlert
from datetime import datetime


def conpot(ECFG):
    conpot = EAlert('conpot', ECFG)

    ITEMS = ['conpot', 'nodeid', 'logfile']
    HONEYPOT = (conpot.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    logfiles = glob.glob(HONEYPOT['logfile'])
    if len(logfiles) < 1:
        print("[ERROR] Missing of correct LogFile for conpot. Skip!")
        return()

    for logfile in logfiles:
        index = ''
        for indexsearch in ['IEC104', 'guardian_ast', 'ipmi', 'kamstrup_382']:
            if indexsearch in logfile:
                index = indexsearch
              
        while True:
            line = conpot.lineREAD(logfile, 'json', None, index)

            if len(line) == 0:
                break
            if line == 'jsonfail':
                continue
            if line['event_type'] != 'NEW_CONNECTION':
                continue

            conpot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

            conpot.data('timestamp', datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
            conpot.data("timezone", time.strftime('%z'))

            conpot.data('source_address', line['src_ip']) if 'src_ip' in line else None
            conpot.data('target_address', line['dst_ip']) if 'dst_ip' in line else None
            conpot.data('source_port', str(line['src_port'])) if 'src_port' in line else None
            conpot.data('target_port', str(line['dst_port'])) if 'dst_ip' in line else None
            conpot.data('source_protocol', "tcp")
            conpot.data('target_protocol', "tcp")

            conpot.request('description', 'Conpot Honeypot')
            conpot.request('request', line['request']) if 'request' in line and line['request'] != "" else None

            conpot.adata('hostname', ECFG['hostname'])
            conpot.adata('externalIP', ECFG['ip_ext'])
            conpot.adata('internalIP', ECFG['ip_int'])
            conpot.adata('uuid', ECFG['uuid'])
            conpot.adata('conpot_data_type', line['data_type'])
            conpot.adata('conpot_response', line['conpot_response']) if 'conpot_response' in line and line['conpot_response'] != "" else None

            if conpot.buildAlert() == "sendlimit":
                break

        conpot.finAlert()

    return()
