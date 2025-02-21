# honeypots/emobility.py

import time
from urllib import parse
from modules.ealert import EAlert


def emobility(ECFG):
    emobility = EAlert('emobility', ECFG)

    ITEMS = ['emobility', 'nodeid', 'logfile']
    HONEYPOT = (emobility.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = emobility.lineREAD(HONEYPOT['logfile'], 'simple')

        if len(line) == 0:
            break

        srcipandport, dstipandport, url, dateandtime = line.split("|", 3)

        emobility.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None
        emobility.data('timestamp', f"{dateandtime[0:10]} {dateandtime[11:19]}")
        emobility.data("timezone", time.strftime('%z'))

        emobility.data('source_address', f"{srcipandport.split('.')[0]}.{srcipandport.split('.')[1]}.{srcipandport.split('.')[2]}.{srcipandport.split('.')[3]}")
        emobility.data('target_address', f"{dstipandport.split('.')[0]}.{dstipandport.split('.')[1]}.{dstipandport.split('.')[2]}.{dstipandport.split('.')[3]}")
        emobility.data('source_port', f"{srcipandport.split('.')[4]}")
        emobility.data('target_port', f"{dstipandport.split('.')[4]}")
        emobility.data('source_protocol', "tcp")
        emobility.data('target_protocol', "tcp")

        emobility.request('description', 'Emobility Honeypot')
        emobility.request('url', parse.quote(url.encode('ascii', 'ignore')))

        emobility.adata('hostname', ECFG['hostname'])
        emobility.adata('externalIP', ECFG['ip_ext'])
        emobility.adata('internalIP', ECFG['ip_int'])
        emobility.adata('uuid', ECFG['uuid'])

        if emobility.buildAlert() == "sendlimit":
            break

    emobility.finAlert()
    return()
