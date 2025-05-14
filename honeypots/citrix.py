# honeypots/citrix.py

import time
import re
from modules.ealert import EAlert
from datetime import datetime


def citrix(ECFG):
    citrix = EAlert('citrix', ECFG)

    ITEMS = ['citrix', 'nodeid', 'logfile']
    HONEYPOT = (citrix.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('citrix').lower() == "false":
        print(f"    -> Honeypot Citrix set to false. Skip Honeypot.")
        return()

    while True:
        line = citrix.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        citrix.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'asctime' in line:
            citrix.data('timestamp', datetime.fromisoformat(line['asctime']).strftime('%Y-%m-%d %H:%M:%S'))
            citrix.data("timezone", time.strftime('%z'))

        try:
            citrix.data('source_address', re.search(r"\((.*)\).*", line['message'], re.M).group(1).split(":")[0]) if 'message' in line else None
            citrix.data('source_port', re.search(r"\((.*)\).*", line['message'], re.M).group(1).split(":")[1]) if 'message' in line else None
        except AttributeError:
            continue

        citrix.data('target_address', ECFG['ip_ext'])
        citrix.data('target_port', '80')
        citrix.data('source_protocol', 'tcp')
        citrix.data('target_protocol', 'tcp')

        citrix.request('description', 'Citrix Honeypot')

        citrix.adata('hostname', ECFG['hostname'])
        citrix.adata('externalIP', ECFG['ip_ext'])
        citrix.adata('internalIP', ECFG['ip_int'])
        citrix.adata('uuid', ECFG['uuid'])

        if citrix.buildAlert() == "sendlimit":
            break

    citrix.finAlert()
    return()
