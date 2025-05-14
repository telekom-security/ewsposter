# honeypots/glutton.py

import time
import codecs
import base64
from datetime import datetime
from modules.ealert import EAlert

def glutton(ECFG):
    glutton = EAlert('glutton', ECFG)

    ITEMS = ['glutton', 'nodeid', 'logfile']
    HONEYPOT = (glutton.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('glutton').lower() == "false":
        print(f"    -> Honeypot Glutton set to false. Skip Honeypot.")
        return()

    while True:
        line = glutton.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if "src_ip" not in line:
            continue
        if "error" in line["level"]:
            continue

        glutton.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'ts' in line:
            glutton.data('timestamp', datetime.fromtimestamp(float(line['ts'])).strftime('%Y-%m-%d %H:%M:%S'))
            glutton.data("timezone", time.strftime('%z'))

        glutton.data('source_address', line['src_ip']) if 'src_ip' in line else None
        glutton.data('target_address', ECFG['ip_ext'])
        glutton.data('source_port', str(line['src_port'])) if 'src_port' in line else None
        glutton.data('target_port', str(line['dest_port'])) if 'dest_port' in line else None
        glutton.data('source_protocol', "tcp")
        glutton.data('target_protocol', "tcp")

        glutton.request("description", "Glutton Honeypot")
        glutton.request("binary", base64.b64encode(codecs.decode(line['payload_hex'], 'hex')).decode()) if "payload_hex" in line else None

        glutton.adata('hostname', ECFG['hostname'])
        glutton.adata('externalIP', ECFG['ip_ext'])
        glutton.adata('internalIP', ECFG['ip_int'])
        glutton.adata('uuid', ECFG['uuid'])

        if glutton.buildAlert() == "sendlimit":
            break

    glutton.finAlert()
    return()
