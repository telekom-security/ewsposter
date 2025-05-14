# honeypots/glastopfv3.py

import time
import re
import base64
from urllib import parse
from modules.ealert import EAlert


def glastopfv3(ECFG):
    glastopfv3 = EAlert('glastopfv3', ECFG)

    ITEMS = ['glastopfv3', 'nodeid', 'sqlitedb', 'malwaredir']
    HONEYPOT = (glastopfv3.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('glastopfv3').lower() == "false":
        print(f"    -> Honeypot Glastop V3 set to false. Skip Honeypot.")
        return()

    while True:
        line = glastopfv3.lineSQLITE(HONEYPOT['sqlitedb'])

        if len(line) == 0 or line == 'false':
            break
        if line["request_url"] == "/" or line["request_url"] == "/index.do?hash=DEADBEEF&activate=1":
            continue

        glastopfv3.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'time' in line:
            glastopfv3.data('timestamp', line['time'])
            glastopfv3.data("timezone", time.strftime('%z'))

        glastopfv3.data('source_address', re.sub(":.*$", "", line["source"])) if 'source' in line else None
        glastopfv3.data('target_address', ECFG['ip_ext'])
        glastopfv3.data('source_port', re.sub("^.*:", "", line["source"]))
        glastopfv3.data('target_port', '80')
        glastopfv3.data('source_protocol', "tcp")
        glastopfv3.data('target_protocol', "tcp")

        glastopfv3.request("description", "WebHoneypot : Glastopf v3.1")
        glastopfv3.request("url", parse.quote(line['request_url'].encode('ascii', 'ignore'))) if "request_url" in line else None

        if 'request_raw' in line and len(line['request_raw']) > 0:
            glastopfv3.request('raw', base64.encodebytes(line['request_raw'].encode('ascii', 'ignore')).decode())

        if 'filename' in line and line['filename'] is not None and ECFG['send_malware'] is True:
            error, payload = glastopfv3.malwarecheck(HONEYPOT["malwaredir"], str(line["filename"]), ECFG["del_malware_after_send"], str(line["filename"]))
            glastopfv3.request("binary", payload.decode('utf-8')) if error is True and len(payload) > 0 else None

        glastopfv3.adata('hostname', ECFG['hostname'])
        glastopfv3.adata('externalIP', ECFG['ip_ext'])
        glastopfv3.adata('internalIP', ECFG['ip_int'])
        glastopfv3.adata('uuid', ECFG['uuid'])

        glastopfv3.adata('httpmethod', line['request_method']) if 'request_method' in line else None
        glastopfv3.adata('request_body', line['request_body']) if 'request_body' in line and len(line['request_body']) > 0 else None
        glastopfv3.adata('host', str(re.search(r'Host: (\b.+\b)', line["request_raw"], re.M).group(1))) if 'request_raw' in line and re.match(".*host:.*", line["request_raw"], re.I) else None

        if glastopfv3.buildAlert() == "sendlimit":
            break

    glastopfv3.finAlert()
    return()
