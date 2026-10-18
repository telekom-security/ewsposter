# honeypots/heralding.py

import csv
import ipaddress
import time
from modules.ealert import EAlert


""" auth.csv: timestamp,auth_id,session_id,source_ip,source_port,destination_ip,destination_port,protocol,username,password[,password_hash] """
MIN_FIELDS = 10
""" a quoted value may span lines (a newline in a username or password), at most this many """
MAX_RECORD_LINES = 50


def _complete(text):
    """ True when every quote of the record is closed (RFC 4180 doubles quotes inside a value) """
    return text.count('"') % 2 == 0


def _fields(text):
    try:
        return next(csv.reader([text]), [])
    except csv.Error:
        return []


def _valid_record(fields):
    if len(fields) < MIN_FIELDS:
        return False
    if fields[0] == "timestamp":
        return False
    try:
        ipaddress.ip_address(fields[3])
        ipaddress.ip_address(fields[5])
    except ValueError:
        return False
    return fields[4].isdigit() and fields[6].isdigit()


def heralding(ECFG):

    heralding = EAlert('heralding', ECFG)

    ITEMS = ['heralding', 'nodeid', 'logfile']
    HONEYPOT = (heralding.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('heralding').lower() == "false":
        print(f"    -> Honeypot Heralding set to false. Skip Honeypot.")
        return()

    while True:
        start = int(heralding.alertCount(heralding.MODUL, 'get_counter'))
        line = heralding.lineREAD(HONEYPOT['logfile'], 'simple')

        if len(line) == 0:
            break

        record = line
        lines = 1
        while not _complete(record) and lines < MAX_RECORD_LINES:
            more = heralding.lineREAD(HONEYPOT['logfile'], 'simple')
            if len(more) == 0:
                break
            record += more
            lines += 1

        if not _complete(record):
            if lines < MAX_RECORD_LINES:
                """ the rest of the record is not written yet: read it again on the next run """
                heralding.alertCount(heralding.MODUL, 'set_counter', setto=start)
                break
            heralding.logger.warning(f"Heralding record at line {start} has an open quote after {lines} lines. Skipped.", '2')
            continue

        fields = _fields(record.rstrip("\r\n"))
        if not _valid_record(fields):
            if fields and fields[0] != "timestamp":
                heralding.logger.warning(f"Heralding record at line {start} has an unexpected format. Skipped.", '2')
            continue

        heralding.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        heralding.data('timestamp', fields[0][0:19])
        heralding.data("timezone", time.strftime('%z'))

        heralding.data('source_address', fields[3])
        heralding.data('target_address', fields[5])
        heralding.data('source_port', fields[4])
        heralding.data('target_port', fields[6])
        heralding.data('source_protocol', "tcp")
        heralding.data('target_protocol', "tcp")

        heralding.request("description", "Heralding Honeypot")

        heralding.adata('hostname', ECFG['hostname'])
        heralding.adata('externalIP', ECFG['ip_ext'])
        heralding.adata('internalIP', ECFG['ip_int'])
        heralding.adata('uuid', ECFG['uuid'])
        heralding.adata('protocol', fields[7]) if fields[7] != "" else None
        heralding.adata('username', fields[8]) if fields[8] != "" else None
        heralding.adata('password', fields[9]) if fields[9] != "" else None
        heralding.adata('password_hash', fields[10]) if len(fields) > 10 and fields[10] != "" else None

        if heralding.buildAlert() == "sendlimit":
            break

    heralding.finAlert()
    return()
