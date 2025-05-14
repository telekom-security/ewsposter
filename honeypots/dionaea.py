# honeypots/dionaea.py

import time
from datetime import datetime
from modules.ealert import EAlert


def dionaea(ECFG):
    dionaea = EAlert('dionaea', ECFG)

    ITEMS = ['dionaea', 'nodeid', 'sqlitedb', 'malwaredir']
    HONEYPOT = (dionaea.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('dionaea').lower() == "false":
        print(f"    -> Honeypot Dionaea set to false. Skip Honeypot.")
        return()

    while True:
        line, download = dionaea.lineSQLITE(HONEYPOT['sqlitedb'])

        if len(line) == 0 or (line == 'false' and download == 'false'):
            break
        if line['remote_host'] == "":
            continue

        for dockerIp in ['remote_host', 'local_host']:
            if '..ffff:' in line[dockerIp]:
                line[dockerIp] = line[dockerIp].split('::ffff:')[1]

        dionaea.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'connection_timestamp' in line:
            dionaea.data('timestamp', datetime.utcfromtimestamp(int(line["connection_timestamp"])).strftime('%Y-%m-%d %H:%M:%S'))
            dionaea.data("timezone", time.strftime('%z'))

        dionaea.data('source_address', line['remote_host']) if 'remote_host' in line else None
        dionaea.data('target_address', line['local_host']) if 'local_host' in line else None
        dionaea.data('source_port', line['remote_port']) if 'remote_port' in line else None
        dionaea.data('target_port', line['local_port']) if 'local_port' in line else None
        dionaea.data('source_protocol', line['connection_transport']) if 'connection_transport' in line else None
        dionaea.data('target_protocol', line['connection_transport']) if 'connection_transport' in line else None

        dionaea.request('description', 'Network Honeyport Dionaea v0.1.0')

        if 'download_md5_hash' in download and ECFG['send_malware'] is True:
            error, payload = dionaea.malwarecheck(HONEYPOT['malwaredir'], str(download['download_md5_hash']), ECFG['del_malware_after_send'], str(download['download_md5_hash']))
            if (error is True) and (len(payload) <= 5 * 1024) and (len(payload) > 0):
                dionaea.request('binary', payload.decode('utf-8'))
            elif (error is True) and (ECFG["send_malware"] is True) and (len(payload) > 0):
                dionaea.request('largepayload', payload.decode('utf-8'))

        dionaea.adata('hostname', ECFG['hostname'])
        dionaea.adata('externalIP', ECFG['ip_ext'])
        dionaea.adata('internalIP', ECFG['ip_int'])
        dionaea.adata('uuid', ECFG['uuid'])
        dionaea.adata('payload_md5', download['download_md5_hash']) if 'download_md5_hash' in download else None

        if dionaea.buildAlert() == "sendlimit":
            break

    dionaea.finAlert()
    return()
