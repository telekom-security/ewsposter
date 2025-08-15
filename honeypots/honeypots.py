# honeypots/honeypots.py

import time
from modules.ealert import EAlert
from pathlib import Path
from datetime import datetime


def honeypots(ECFG):
    honeypots = EAlert('honeypots', ECFG)

    ITEMS = ['honeypots', 'nodeid', 'logdir']
    HONEYPOT = (honeypots.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('honeypots').lower() == "false":
        print(f"    -> Honeypot Honeypots set to false. Skip Honeypot.")
        return()

    logfiles = [f for f in Path(HONEYPOT['logdir']).glob('*.log') if f.stat().st_size > 0]
    filetypes = ['dhcp', 'dns', 'elastic', 'ftp', 'http', 'httpproxy', 'https', 'imap',
                 'ipp', 'irc', 'ldap', 'memcache', 'mssql', 'mysql', 'ntp', 'oracle',
                 'pjl', 'pop3', 'postgres', 'rdp', 'redis', 'sip', 'smb', 'smtp', 'snmp',
                 'socks5', 'ssh', 'telnet', 'vnc'
    ]

    for logfile in logfiles:
        index = Path(logfile).stem

        if index not in filetypes:
            print(f'    -> Filetype {index} in {logfile} not in list. Continue.')
            continue

        while (line := honeypots.lineREAD(str(logfile), 'json', None, index)):

            if len(line) == 0:
                break
            if line == 'jsonfail':
                continue

            if HONEYPOT.get('nodeid'): honeypots.data('analyzer_id', HONEYPOT['nodeid'])

            if line.get('action') == "connection":

                if line.get('timestamp'):
                    honeypots.data('timestamp', datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
                    honeypots.data('timezone', time.strftime('%z'))

                if line.get('src_ip'): honeypots.data('source_address', line['src_ip'])
                if line.get('dst_ip') == '0.0.0.0':
                    honeypots.data('target_address', ECFG['ip_ext'])
                else:
                    honeypots.data('target_address', line['dest_ip'])

                if line.get('src_port'): honeypots.data('source_port', str(line['src_port']))
                if line.get('dest_port'): honeypots.data('target_port', str(line['dest_port']))
                honeypots.data('source_protocol', "tcp")
                honeypots.data('target_protocol', "tcp")

                honeypots.request("description", "Honeypots Honeypot")

                honeypots.adata('modul', index)
                honeypots.adata('hostname', ECFG['hostname'])
                honeypots.adata('externalIP', ECFG['ip_ext'])
                honeypots.adata('internalIP', ECFG['ip_int'])
                honeypots.adata('uuid', ECFG['uuid'])

                if honeypots.buildAlert() == "sendlimit":
                    break

        honeypots.finAlert()
    return
