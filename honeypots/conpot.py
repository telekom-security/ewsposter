# honeypots/conpot.py

import time
from modules.ealert import EAlert
from datetime import datetime
from pathlib import Path

# Conpot >= 1.0 logs the event schema v1 (protocol, session_id, session_time,
# event_time, ...), older versions data_type, id and timestamp. Both are read,
# so logs written before an update are still processed.
UDP_PROTOCOLS = {'bacnet', 'goose', 'ipmi', 'knxnetip', 'snmp', 'tftp'}
ADS_DISCOVERY_PORT = 48899


def conpot(ECFG):
    conpot = EAlert('conpot', ECFG)

    ITEMS = ['conpot', 'nodeid', 'logdir']
    HONEYPOT = (conpot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('conpot').lower() == "false":
        print(f"    -> Honeypot Conpot set to false. Skip Honeypot.")
        return()

    # one log file per Conpot template, e.g. conpot_IEC104.json
    logfiles = [f for f in Path(HONEYPOT['logdir']).glob('conpot_*.json') if f.stat().st_size > 0]

    for logfile in logfiles:
        index = Path(logfile).stem

        while (line := conpot.lineREAD(str(logfile), 'json', None, index)):

            if len(line) == 0:
                break
            if line == 'jsonfail':
                continue
            if line.get('event_type') != 'NEW_CONNECTION':
                continue

            timestamp = line.get('event_time') or line.get('session_time') or line.get('timestamp')
            protocol = line.get('protocol') or line.get('data_type')
            if timestamp is None or protocol is None:
                continue

            if protocol in UDP_PROTOCOLS or (protocol == 'ads' and str(line.get('dst_port')) == str(ADS_DISCOVERY_PORT)):
                transport = "udp"
            else:
                transport = "tcp"

            conpot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

            conpot.data('timestamp', datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S'))
            conpot.data("timezone", time.strftime('%z'))

            conpot.data('source_address', line['src_ip']) if 'src_ip' in line else None
            conpot.data('target_address', line['dst_ip']) if 'dst_ip' in line else None
            conpot.data('source_port', str(line['src_port'])) if 'src_port' in line else None
            conpot.data('target_port', str(line['dst_port'])) if 'dst_port' in line else None
            conpot.data('source_protocol', transport)
            conpot.data('target_protocol', transport)

            conpot.request('description', 'Conpot Honeypot')
            conpot.request('request', line['request']) if line.get('request') else None

            conpot.adata('hostname', ECFG['hostname'])
            conpot.adata('externalIP', ECFG['ip_ext'])
            conpot.adata('internalIP', ECFG['ip_int'])
            conpot.adata('uuid', ECFG['uuid'])
            conpot.adata('conpot_data_type', protocol)
            conpot.adata('conpot_response', line['response']) if line.get('response') else None

            if conpot.buildAlert() == "sendlimit":
                break

        conpot.finAlert()

    return()
