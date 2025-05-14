# honeypots/log4pot

import time
import base64
from modules.ealert import EAlert


def log4pot(ECFG):
    log4pot = EAlert('log4pot', ECFG)

    ITEMS = ['log4pot', 'nodeid', 'logfile']
    HONEYPOT = (log4pot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('log4pot').lower() == "false":
        print(f"    -> Honeypot Log4pot set to false. Skip Honeypot.")
        return()

    while True:
        line = log4pot.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if line['reason'] != "request":
            continue

        log4pot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            log4pot.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
            log4pot.data("timezone", time.strftime('%z'))

        log4pot.data('source_address', str(line['client'])) if 'client' in line else None
        log4pot.data('target_address', ECFG['ip_ext'])
        log4pot.data('source_port', '5060')
        log4pot.data('target_port', '5060')
        log4pot.data('source_protocol', str(line['port'])) if 'port' in line else None
        log4pot.data('target_protocol', str(line['server_port'])) if 'server_port' in line else None

        if len(line['headers']) > 0:
            generateRequest = ""
            generateRequest += f"{line['request']}\r\n"

            for index in line['headers']:
                generateRequest += f"{index}: {line['headers'][index]}\r\n"

            log4pot.request("raw", base64.encodebytes(generateRequest.encode('ascii', 'ignore')).decode())

        log4pot.request('description', 'Log4pot Honeypot')

        log4pot.request("request", line['request']) if line['request'] != "" else None

        log4pot.adata('hostname', ECFG['hostname'])
        log4pot.adata('externalIP', ECFG['ip_ext'])
        log4pot.adata('internalIP', ECFG['ip_int'])
        log4pot.adata('uuid', ECFG['uuid'])

        if log4pot.buildAlert() == "sendlimit":
            break

    log4pot.finAlert()
    return()
