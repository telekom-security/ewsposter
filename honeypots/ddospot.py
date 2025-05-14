# honeypots/ddospot.py

import time
from modules.ealert import EAlert
from pathlib import Path
from datetime import datetime


def ddospot(ECFG):
    ddospot = EAlert('ddospot', ECFG)

    ITEMS = ['ddospot', 'nodeid', 'logdir']
    HONEYPOT = (ddospot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('ddospot').lower() == "false":
        print(f"    -> Honeypot Ddospot set to false. Skip Honeypot.")
        return()
    
    logfiles = [f for f in Path(HONEYPOT['logdir']).glob('*.log') if f.stat().st_size > 0]
    filetypes = ['chargenpot', 'dnspot', 'genericpot', 'ntpot', 'ssdpot']

    for logfile in logfiles:
        index = Path(logfile).stem

        if index not in filetypes:
            print(f'    -> Filetype {index} in {logfile} not in list. Continue.')
            continue

        while (line := ddospot.lineREAD(str(logfile), 'json', None, index)):
            
            if len(line) == 0:
                break
            if line == 'jsonfail':
                continue


            if HONEYPOT.get('nodeid'): ddospot.data('analyzer_id', HONEYPOT['nodeid'])
            if line.get('time'):
                ddospot.data('timestamp', datetime.fromisoformat(line['time']).strftime('%Y-%m-%d %H:%M:%S'))
                ddospot.data('timezone', time.strftime('%z'))
            
            if line.get('src_ip'): ddospot.data('source_address', line['src_ip'])             
            ddospot.data('target_address', ECFG['ip_ext'])
            if line.get('src_port'): ddospot.data('source_port', str(line['src_port'])) 
            ddospot.data('target_port', "0")
            ddospot.data('source_protocol', "tcp")
            ddospot.data('target_protocol', "tcp")

            ddospot.request("description", "Ddospot Honeypot") 
 
            ddospot.adata('hostname', ECFG['hostname'])
            ddospot.adata('externalIP', ECFG['ip_ext'])
            ddospot.adata('internalIP', ECFG['ip_int'])
            ddospot.adata('uuid', ECFG['uuid'])

            if ddospot.buildAlert() == "sendlimit":
                break

        ddospot.finAlert()
    return
