# honeypots/ciscoasa.py

import time
from urllib import parse
from modules.ealert import EAlert
from datetime import datetime

def _port(value, default):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return str(port) if 0 <= port <= 65535 else default


def _joined(value):
    if isinstance(value, list):
        return ','.join(str(item) for item in value if item not in (None, ''))
    return value


def _v2_metadata(line):
    """ (url, additional data) of a Ciscoasa v2 event: HTTP request, IKE exchange, client, upload """
    adata = {}
    for key in ('event_type', 'username', 'password'):
        if line.get(key):
            adata[key] = line[key]
    if _joined(line.get('cve')):
        adata['cve'] = _joined(line['cve'])

    asa = line.get('asa') if isinstance(line.get('asa'), dict) else {}
    http = asa.get('http') if isinstance(asa.get('http'), dict) else {}
    ike = asa.get('ike') if isinstance(asa.get('ike'), dict) else {}
    client = asa.get('client') if isinstance(asa.get('client'), dict) else {}
    upload = asa.get('upload') if isinstance(asa.get('upload'), dict) else {}

    url = http.get('uri') or None
    for target, value in (
        ('httpmethod', http.get('method')),
        ('user_agent', http.get('user_agent')),
        ('ike_version', ike.get('version')),
        ('ike_exchange', ike.get('exchange')),
        ('ike_group_name', ike.get('group_name')),
        ('ike_vendor_ids', _joined(ike.get('vendor_ids'))),
        ('ike_proposals', _joined(ike.get('proposals'))),
        ('group', asa.get('group')),
        ('client_version', client.get('version')),
        ('client_platform', client.get('platform')),
        ('upload_sha256', upload.get('sha256')),
        ('upload_size', upload.get('size')),
        ('chain_stage', asa.get('chain_stage')),
        ('anomaly', asa.get('anomaly')),
        ('count', asa.get('count')),
    ):
        if value not in (None, '', 0):
            adata[target] = value

    return url, adata


def ciscoasa(ECFG):
    ciscoasa = EAlert('ciscoasa', ECFG)

    ITEMS = ['ciscoasa', 'nodeid', 'logfile']
    HONEYPOT = (ciscoasa.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('ciscoasa').lower() == "false":
        print(f"    -> Honeypot Ciscosas set to false. Skip Honeypot.")
        return()

    while True:
        line = ciscoasa.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if 'Status' in line or 'Version' in line:
            continue

        ciscoasa.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            ciscoasa.data('timestamp', datetime.fromisoformat(line['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S'))
            ciscoasa.data("timezone", time.strftime('%z'))

        ciscoasa.data('source_address', line['src_ip']) if 'src_ip' in line else None
        ciscoasa.data('target_address', ECFG['ip_ext'])
        ciscoasa.data('source_port', _port(line.get('src_port'), '0'))
        ciscoasa.data('target_port', _port(line.get('dest_port'), '8443'))
        protocol = line.get('protocol', 'tcp')
        protocol = protocol if protocol in ('tcp', 'udp') else 'tcp'
        ciscoasa.data('source_protocol', protocol)
        ciscoasa.data('target_protocol', protocol)

        ciscoasa.request("description", "Cisco-ASA Honeypot")
        payload = line.get('payload', line.get('payload_printable'))
        if payload is not None:
            ciscoasa.request('payload', str(payload))

        url, metadata = _v2_metadata(line)
        if url:
            ciscoasa.request('url', parse.quote(str(url).encode('ascii', 'ignore'), safe="/?&=%:@+;,"))
        for key, value in metadata.items():
            ciscoasa.adata(key, value)

        ciscoasa.adata('hostname', ECFG['hostname'])
        ciscoasa.adata('externalIP', ECFG['ip_ext'])
        ciscoasa.adata('internalIP', ECFG['ip_int'])
        ciscoasa.adata('uuid', ECFG['uuid'])

        if ciscoasa.buildAlert() == "sendlimit":
            break

    ciscoasa.finAlert()
    return()
