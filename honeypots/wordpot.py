# honeypots/wordpot.py

import time
from modules.ealert import EAlert
from datetime import datetime


def wordpot(ECFG):
    wordpot = EAlert('wordpot', ECFG)

    ITEMS = ['wordpot', 'nodeid', 'logfile']
    HONEYPOT = (wordpot.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('wordpot').lower() == "false":
        print(f"    -> Honeypot Wordpot set to false. Skip Honeypot.")
        return()

    while True:
        line = wordpot.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        
        if HONEYPOT.get('nodeid'): wordpot.data('analyzer_id', HONEYPOT['nodeid'])

        if line.get('timestamp'):
            wordpot.data('timestamp', datetime.fromisoformat(line['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
            wordpot.data('timezone', time.strftime('%z'))
        
        if line.get('src_ip'): wordpot.data('source_address', line['src_ip']) 
        wordpot.data('target_address', ECFG['ip_ext'])
        if line.get('src_port'): wordpot.data('source_port', str(line['src_port'])) 
        if line.get('dest_port'): wordpot.data('target_port', str(line['dest_port'])) 
        wordpot.data('source_protocol', "tcp")
        wordpot.data('target_protocol', "tcp")

        wordpot.request("description", "Wordpot Honeypot")

        if line.get('browser_family'): wordpot.adata('browser_family', line['browser_family'])
        if line.get('browser_version'): wordpot.adata('browser_version', line['browser_version'])
        if line.get('os_family'): wordpot.adata('os_family', line['os_family'])
        if line.get('os_version'): wordpot.adata('os_version', line['os_version'])
        if line.get('device_family'): wordpot.adata('device_family', line['device_family']) 
        if line.get('user_agent'): wordpot.adata('user_agent', line['user_agent']) 
        if line.get('url'): wordpot.adata('url', line['url'])
        if line.get('username'): wordpot.adata('username', line['username'])
        if line.get('password'): wordpot.adata('password', line['password']) 
        if line.get('plugin'): wordpot.adata('plugin', line['plugin']) 

        wordpot.adata('hostname', ECFG['hostname'])
        wordpot.adata('externalIP', ECFG['ip_ext'])
        wordpot.adata('internalIP', ECFG['ip_int'])
        wordpot.adata('uuid', ECFG['uuid'])

        if wordpot.buildAlert() == "sendlimit":
            break

    wordpot.finAlert()
    return()            
