# honeypots/honeytrap.py

import time
import re
import os
import hashlib
from modules.ealert import EAlert


def honeytrap(ECFG):
    honeytrap = EAlert('honeytrap', ECFG)

    ITEMS = ['honeytrap', 'nodeid', 'attackerfile', 'payloaddir', 'newversion']
    HONEYPOT = (honeytrap.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('honeytrap').lower() == "false":
        print(f"    -> Honeypot Honeytrap set to false. Skip Honeypot.")
        return()

    if HONEYPOT["newversion"].lower() == "true":
        print("    -> Calculate MD5Sum for payload files and rename files.")
        for index in os.listdir(HONEYPOT["payloaddir"]):
            if '_md5_' not in index:
                filein = HONEYPOT["payloaddir"] + os.sep + index
                os.rename(filein, filein + "_md5_" + hashlib.md5(open(filein, 'rb').read()).hexdigest())

    payloadfilelist = os.listdir(HONEYPOT["payloaddir"])

    while True:
        line = honeytrap.lineREAD(HONEYPOT['attackerfile'], 'simple')

        if len(line) == 0:
            break

        line = re.sub(r'  ', r' ', re.sub(r'[\[\]\-\>]', r'', line))

        if HONEYPOT["newversion"].lower() == "false":
            dates, times, _, source, dest, _ = line.split(" ", 5)
            protocol = ""
            md5 = ""
        else:
            dates, times, _, protocol, source, dest, md5, _ = line.split(" ", 7)

        honeytrap.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        honeytrap.data('timestamp', f"{dates[0:4]}-{dates[4:6]}-{dates[6:8]} {times[0:8]}")
        honeytrap.data("timezone", time.strftime('%z'))

        honeytrap.data('source_address', re.sub(":.*$", "", source)) if source else None
        honeytrap.data('target_address', re.sub(":.*$", "", dest)) if dest else None
        honeytrap.data('source_port', re.sub("^.*:", "", source)) if source else None
        honeytrap.data('target_port', re.sub("^.*:", "", dest)) if dest else None
        honeytrap.data('source_protocol', protocol) if protocol else None
        honeytrap.data('target_protocol', protocol) if protocol else None

        honeytrap.request('description', 'NetworkHoneypot Honeytrap v1.1')

        if (HONEYPOT["newversion"].lower() == "true"):
            for md5_file in payloadfilelist:
                if (re.search(md5, md5_file)):
                    error, payload = honeytrap.malwarecheck(HONEYPOT['payloaddir'], md5_file , False, md5)
                    if (error is True) and (len(payload) <= 5 * 1024) and (len(payload) > 0):
                        honeytrap.request('binary', payload.decode('utf-8'))
                    elif (error is True) and (ECFG["send_malware"] is True) and (len(payload) > 0):
                        honeytrap.request('largepayload', payload.decode('utf-8'))
                    break

        honeytrap.adata('hostname', ECFG['hostname'])
        honeytrap.adata('externalIP', ECFG['ip_ext'])
        honeytrap.adata('internalIP', ECFG['ip_int'])
        honeytrap.adata('uuid', ECFG['uuid'])
        honeytrap.adata('payload_md5', md5) if md5 else None

        if honeytrap.buildAlert() == "sendlimit":
            break

    honeytrap.finAlert()
    return()
