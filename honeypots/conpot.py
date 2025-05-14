# honeypots/conpot.py

import time
from modules.ealert import EAlert
from datetime import datetime
from pathlib import Path


def conpot(ECFG):
    conpot = EAlert('conpot', ECFG)

    ITEMS = ['conpot', 'nodeid', 'logdir']
    HONEYPOT = (conpot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('conpot').lower() == "false":
        print(f"    -> Honeypot Conpot set to false. Skip Honeypot.")
        return()

    logfiles = [f for f in Path(HONEYPOT['logdir']).glob('*.json') if f.stat().st_size > 0]
    filetypes = ['conpot_IEC104', 'conpot_guardian_ast', 'conpot_ipmi', 'conpot_kamstrup_382']

    for logfile in logfiles:
        index = Path(logfile).stem

        if  index not in filetypes:
            print(f'    -> Filetype {index} in {logfile} not in list. Continue.')
            continue
        
        while (line := conpot.lineREAD(str(logfile), 'json', None, index)):
            
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
