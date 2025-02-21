# honeypots/mailoney.py

import time
from modules.ealert import EAlert


def mailoney(ECFG):
    mailoney = EAlert('mailoney', ECFG)

    ITEMS = ['mailoney', 'nodeid', 'logfile']
    HONEYPOT = (mailoney.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = mailoney.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if 'EHLO User' not in line['data']:
            continue

        mailoney.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        mailoney.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
        mailoney.data("timezone", time.strftime('%z'))

        mailoney.data('source_address', line['src_ip']) if 'src_ip' in line else None
        mailoney.data('target_address', ECFG['ip_ext'])
        mailoney.data('source_port', str(line['src_port'])) if 'src_port' in line else None
        mailoney.data('target_port', "25")
        mailoney.data('source_protocol', "tcp")
        mailoney.data('target_protocol', "tcp")

        mailoney.request("description", "Mail Honeypot mailoney")

        mailoney.adata('hostname', ECFG['hostname'])
        mailoney.adata('externalIP', ECFG['ip_ext'])
        mailoney.adata('internalIP', ECFG['ip_int'])
        mailoney.adata('uuid', ECFG['uuid'])

        if mailoney.buildAlert() == "sendlimit":
            break

    mailoney.finAlert()
    return()