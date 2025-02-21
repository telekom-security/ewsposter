# honeypots/tanner.py

import time
import base64
from urllib import parse
from modules.ealert import EAlert
from datetime import datetime

def tanner(ECFG):
    tanner = EAlert('tanner', ECFG)

    ITEMS = ['tanner', 'nodeid', 'logfile']
    HONEYPOT = (tanner.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = tanner.lineREAD(HONEYPOT['logfile'], 'json')

        if line == 'jsonfail':
            continue
        if len(line) == 0:
            break

        tanner.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            tanner.data('timestamp', datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
            tanner.data("timezone", time.strftime('%z'))

        tanner.data('source_address', line['peer']['ip']) if 'ip' in line['peer'] else None
        tanner.data('target_address', ECFG['ip_ext'])
        tanner.data('source_port', str(line['peer']['port'])) if 'port' in line['peer'] else None
        tanner.data('target_port', "80")
        tanner.data('source_protocol', "tcp")
        tanner.data('target_protocol', "tcp")

        tanner.request("description", "Tanner Honeypot")
        tanner.request("url", parse.quote(line["path"].encode('ascii', 'ignore'))) if line['path'] != "" else None

        if len(line['headers']) > 0:
            generateRequest = ""
            httpversion = "HTTP/1.1" if 'host' in line['headers'] else "HTTP/1.0"
            generateRequest = f"{line['method']} {line['path']} {httpversion}\n"

            for index in line['headers']:
                generateRequest += f"{index}: {line['headers'][index]}\r\n"

            if 'post_data' in line and len(line['post_data']) > 0:
                postdatacontent = ""
                counter = 0

                for key, value in line['post_data'].items():
                    if len(value) > 0:
                        counter += 1
                        postdatacontent += f"{key}={value}"
                        postdatacontent += "&" if counter < len(line['post_data']) else ""

                generateRequest += f"\r\n{postdatacontent}"

            tanner.request("raw", base64.encodebytes(generateRequest.encode('ascii', 'ignore')).decode())

        tanner.adata('hostname', ECFG['hostname'])
        tanner.adata('externalIP', ECFG['ip_ext'])
        tanner.adata('internalIP', ECFG['ip_int'])
        tanner.adata('uuid', ECFG['uuid'])

        if tanner.buildAlert() == "sendlimit":
            break

    tanner.finAlert()
    return()