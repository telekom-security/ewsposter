# honeypots/sentrypeer.py

import time
from modules.ealert import EAlert
from datetime import datetime


def sentrypeer(ECFG):
    sentrypeer = EAlert('sentrypeer', ECFG)

    ITEMS = ['sentrypeer', 'nodeid', 'logfile']
    HONEYPOT = (sentrypeer.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('sentrypeer').lower() == "false":
        print(f"    -> Honeypot Sentrypeer set to false. Skip Honeypot.")
        return()

    while True:
        line = sentrypeer.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        if HONEYPOT.get('nodeid'): sentrypeer.data('analyzer_id', HONEYPOT['nodeid'])

        if line.get('event_timestamp'):
            sentrypeer.data('timestamp', datetime.fromisoformat(line['event_timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
            sentrypeer.data("timezone", time.strftime('%z'))

        if line.get('source_ip'):
            if ':' in line['source_ip']:
                ip, port = line['source_ip'].split(':', 1)
                sentrypeer.data('source_address', str(ip))
                sentrypeer.data('source_port', str(port))
            else:
                sentrypeer.data('source_address', line['source_ip'])
                sentrypeer.data('source_port', '5060')

        if line.get('destination_ip'):
            if ':' in line['destination_ip']:
                ip, port = line['destination_ip'].split(':', 1)
                sentrypeer.data('target_address', str(ip))
                sentrypeer.data('target_port', str(port))
            else:
                sentrypeer.data('target_address', line['destination_ip'])
                sentrypeer.data('target_port', '5060')

        if line.get('transport_type'):
            sentrypeer.data('source_protocol', line['transport_type'].lower())
            sentrypeer.data('target_protocol', line['transport_type'].lower())
        else:
            sentrypeer.data('source_protocol', 'udp')
            sentrypeer.data('target_protocol', 'udp')


        sentrypeer.request('description', 'Sentrypeer Honeypot')

        sentrypeer.adata('hostname', ECFG['hostname'])
        sentrypeer.adata('externalIP', ECFG['ip_ext'])
        sentrypeer.adata('internalIP', ECFG['ip_int'])
        sentrypeer.adata('uuid', ECFG['uuid'])

        if sentrypeer.buildAlert() == "sendlimit":
            break

    sentrypeer.finAlert()
    return()
