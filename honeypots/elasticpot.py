# honeypots/elasticpot.py

import time
from urllib import parse
from modules.ealert import EAlert
from datetime import datetime


def elasticpot(ECFG):
    elasticpot = EAlert('elasticpot', ECFG)

    ITEMS = ['elasticpot', 'nodeid', 'logfile']
    HONEYPOT = (elasticpot.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = elasticpot.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        elasticpot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            elasticpot.data('timestamp',datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
            elasticpot.data("timezone", time.strftime('%z'))

        elasticpot.data('source_address', line['src_ip']) if 'src_ip' in line else None
        elasticpot.data('target_address', line['dst_ip']) if 'dst_ip' in line else None
        elasticpot.data('source_port', str(line['src_port'])) if 'src_port' in line else None
        elasticpot.data('target_port', str(line['dst_port'])) if 'dst_port' in line else None
        elasticpot.data('source_protocol', "tcp")
        elasticpot.data('target_protocol', "tcp")

        elasticpot.request("description", "ElasticSearch Honeypot : Elasticpot")
        elasticpot.request("url", parse.quote(line["url"].encode('ascii', 'ignore'))) if 'url' in line else None

        for element in ['user_agent', 'request', 'payload', 'content_type', 'accept_language']:
            if element in line:
                elasticpot.adata(element, str(line[element]))

        elasticpot.adata('hostname', ECFG['hostname'])
        elasticpot.adata('externalIP', ECFG['ip_ext'])
        elasticpot.adata('internalIP', ECFG['ip_int'])
        elasticpot.adata('uuid', ECFG['uuid'])
        elasticpot.adata('message', line['message']) if 'message' in line else None

        if elasticpot.buildAlert() == "sendlimit":
            break

    elasticpot.finAlert()
    return()