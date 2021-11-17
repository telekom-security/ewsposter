#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import time
import codecs
import hashlib
from datetime import datetime
import glob
from moduls.einit import locksocket, ecfg
from moduls.elog import ELog
from moduls.etoolbox import readonecfg
from moduls.ealert import EAlert
from moduls.esend import ESend
import base64
from urllib import parse

name = "EWS Poster"
version = "v1.21"

def ipphoney():

    ipphoney = EAlert('ipphoney', ECFG)

    ITEMS = ['ipphoney', 'nodeid', 'logfile']
    HONEYPOT = (ipphoney.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = ipphoney.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        ipphoney.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            ipphoney.data('timestamp', line['timestamp'][0:10] + " " + line['timestamp'][11:19])
            ipphoney.data("timezone", time.strftime('%z'))

        ipphoney.data('source_address', line['src_ip']) if 'src_ip' in line else None
        ipphoney.data('target_address', line['dst_ip']) if 'dst_ip' in line else None
        ipphoney.data('source_port', line['src_port']) if 'src_port' in line else None
        ipphoney.data('target_port', line['dst_port']) if 'dst_port' in line else None
        ipphoney.data('source_protokoll', "tcp")
        ipphoney.data('target_protokoll', "tcp")

        ipphoney.request("description", "IPP Honeypot")

        ipphoney.adata('hostname', ECFG['hostname'])
        ipphoney.adata('externalIP', ECFG['ip_ext'])
        ipphoney.adata('internalIP', ECFG['ip_int'])
        ipphoney.adata('uuid', ECFG['uuid'])

        if ipphoney.buildAlert() == "sendlimit":
            break

    ipphoney.finAlert()
    return()


def fatt():

    fatt = EAlert('fatt', ECFG)

    ITEMS = ['fatt', 'nodeid', 'logfile']
    HONEYPOT = (fatt.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = fatt.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        fatt.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            fatt.data('timestamp', line['timestamp'][0:10] + " " + line['timestamp'][11:19])
            fatt.data("timezone", time.strftime('%z'))

        fatt.data('source_address', line['sourceIp']) if 'sourceIp' in line else None
        fatt.data('target_address', ECFG['ip_ext'])
        fatt.data('source_port', str(line['sourcePort'])) if 'sourcePort' in line else None
        fatt.data('target_port', str(line['destinationPort'])) if 'destinationPort' in line else None
        fatt.data('source_protokoll', "tcp")
        fatt.data('target_protokoll', "tcp")

        fatt.request("description", "FATT Honeypot")

        fatt.adata('hostname', ECFG['hostname'])
        fatt.adata('externalIP', ECFG['ip_ext'])
        fatt.adata('internalIP', ECFG['ip_int'])
        fatt.adata('uuid', ECFG['uuid'])

        if fatt.buildAlert() == "sendlimit":
            break

    fatt.finAlert()
    return()


def adbhoney():

    adbhoney = EAlert('adbhoney', ECFG)

    ITEMS = ['adbhoney', 'nodeid', 'logfile']
    HONEYPOT = (adbhoney.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = adbhoney.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if line['eventid'] != "adbhoney.session.connect":
            continue

        adbhoney.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            adbhoney.data('timestamp', line['timestamp'][0:10] + " " + line['timestamp'][11:19])
            adbhoney.data("timezone", time.strftime('%z'))

        adbhoney.data('source_address', line['src_ip']) if 'src_ip' in line else None
        adbhoney.data('target_address', ECFG['ip_ext'])
        adbhoney.data('source_port', str(line['src_port'])) if 'src_port' in line else None
        adbhoney.data('target_port', str(line['dest_port'])) if 'dest_port' in line else None
        adbhoney.data('source_protokoll', "tcp")
        adbhoney.data('target_protokoll', "tcp")

        adbhoney.request("description", "ADBHoney Honeypot")

        adbhoney.adata('hostname', ECFG['hostname'])
        adbhoney.adata('externalIP', ECFG['ip_ext'])
        adbhoney.adata('internalIP', ECFG['ip_int'])
        adbhoney.adata('uuid', ECFG['uuid'])

        if adbhoney.buildAlert() == "sendlimit":
            break

    adbhoney.finAlert()
    return()


def honeysap():

    honeysap = EAlert('honeysap', ECFG)

    ITEMS = ['honeysap', 'nodeid', 'logfile']
    HONEYPOT = (honeysap.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = honeysap.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        honeysap.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            honeysap.data('timestamp', line['timestamp'][0:19])
            honeysap.data("timezone", time.strftime('%z'))

        honeysap.data('source_address', line['source_ip']) if 'source_ip' in line else None
        honeysap.data('target_address', ECFG['ip_ext'])
        honeysap.data('source_port', str(line['source_port'])) if 'source_port' in line else None
        honeysap.data('target_port', str(line['target_port'])) if 'target_port' in line else None
        honeysap.data('source_protokoll', "tcp")
        honeysap.data('target_protokoll', "tcp")

        honeysap.request("description", "Honeysap Honeypot")
        honeysap.request("request", line['request']) if line['request'] != "" else None

        honeysap.adata('hostname', ECFG['hostname'])
        honeysap.adata('externalIP', ECFG['ip_ext'])
        honeysap.adata('internalIP', ECFG['ip_int'])
        honeysap.adata('uuid', ECFG['uuid'])

        if honeysap.buildAlert() == "sendlimit":
            break

    honeysap.finAlert()
    return()


def dicompot():

    dicompot = EAlert('dicompot', ECFG)

    ITEMS = ['dicompot', 'nodeid', 'logfile']
    HONEYPOT = (dicompot.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = dicompot.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if 'Status' in line or 'Version' in line:
            continue

        dicompot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'time' in line:
            dicompot.data('timestamp', line['time'])
            dicompot.data("timezone", time.strftime('%z'))

        dicompot.data('source_address', line['IP']) if 'IP' in line else None
        dicompot.data('target_address', ECFG['ip_ext'])
        dicompot.data('source_port', str(line['Port'])) if 'Port' in line else None
        dicompot.data('target_port', "11112")
        dicompot.data('source_protokoll', "tcp")
        dicompot.data('target_protokoll', "tcp")

        dicompot.request("description", "Dicompot Honeypot")

        dicompot.adata('hostname', ECFG['hostname'])
        dicompot.adata('externalIP', ECFG['ip_ext'])
        dicompot.adata('internalIP', ECFG['ip_int'])
        dicompot.adata('uuid', ECFG['uuid'])

        if dicompot.buildAlert() == "sendlimit":
            break

    dicompot.finAlert()
    return()


def elasticpot():

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
            elasticpot.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
            elasticpot.data("timezone", time.strftime('%z'))

        elasticpot.data('source_address', line['src_ip']) if 'src_ip' in line else None
        elasticpot.data('target_address', line['dst_ip']) if 'dst_ip' in line else None
        elasticpot.data('source_port', str(line['src_port'])) if 'src_port' in line else None
        elasticpot.data('target_port', str(line['dst_port'])) if 'dst_port' in line else None
        elasticpot.data('source_protokoll', "tcp")
        elasticpot.data('target_protokoll', "tcp")

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


def glutton():

    glutton = EAlert('glutton', ECFG)

    ITEMS = ['glutton', 'nodeid', 'logfile']
    HONEYPOT = (glutton.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = glutton.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if "src_ip" not in line:
            continue
        if "error" in line["level"]:
            continue

        glutton.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'ts' in line:
            glutton.data('timestamp', datetime.fromtimestamp(float(line['ts'])).strftime('%Y-%m-%d %H:%M:%S'))
            glutton.data("timezone", time.strftime('%z'))

        glutton.data('source_address', line['src_ip']) if 'src_ip' in line else None
        glutton.data('target_address', ECFG['ip_ext'])
        glutton.data('source_port', str(line['src_port'])) if 'src_port' in line else None
        glutton.data('target_port', str(line['dest_port'])) if 'dest_port' in line else None
        glutton.data('source_protokoll', "tcp")
        glutton.data('target_protokoll', "tcp")

        glutton.request("description", "Glutton Honeypot")
        glutton.request("binary", base64.b64encode(codecs.decode(line['payload_hex'], 'hex')).decode()) if "payload_hex" in line else None

        glutton.adata('hostname', ECFG['hostname'])
        glutton.adata('externalIP', ECFG['ip_ext'])
        glutton.adata('internalIP', ECFG['ip_int'])
        glutton.adata('uuid', ECFG['uuid'])

        if glutton.buildAlert() == "sendlimit":
            break

    glutton.finAlert()
    return()


def ciscoasa():

    ciscoasa = EAlert('ciscoasa', ECFG)

    ITEMS = ['ciscoasa', 'nodeid', 'logfile']
    HONEYPOT = (ciscoasa.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
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
            ciscoasa.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
            ciscoasa.data("timezone", time.strftime('%z'))

        ciscoasa.data('source_address', line['src_ip']) if 'src_ip' in line else None
        ciscoasa.data('target_address', ECFG['ip_ext'])
        ciscoasa.data('source_port', "0")
        ciscoasa.data('target_port', "8443")
        ciscoasa.data('source_protokoll', "tcp")
        ciscoasa.data('target_protokoll', "tcp")

        ciscoasa.request("description", "Cisco-ASA Honeypot")
        ciscoasa.request("payload", str(line['payload_printable'])) if 'payload' in line else None

        ciscoasa.adata('hostname', ECFG['hostname'])
        ciscoasa.adata('externalIP', ECFG['ip_ext'])
        ciscoasa.adata('internalIP', ECFG['ip_int'])
        ciscoasa.adata('uuid', ECFG['uuid'])

        if ciscoasa.buildAlert() == "sendlimit":
            break

    ciscoasa.finAlert()
    return()


def tanner():

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
            tanner.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
            tanner.data("timezone", time.strftime('%z'))

        tanner.data('source_address', line['peer']['ip']) if 'ip' in line['peer'] else None
        tanner.data('target_address', ECFG['ip_ext'])
        tanner.data('source_port', str(line['peer']['port'])) if 'port' in line['peer'] else None
        tanner.data('target_port', "80")
        tanner.data('source_protokoll', "tcp")
        tanner.data('target_protokoll', "tcp")

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


def rdpy():

    rdpy = EAlert('rdpy', ECFG)

    ITEMS = ['rdpy', 'nodeid', 'logfile']
    HONEYPOT = (rdpy.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = rdpy.lineREAD(HONEYPOT['logfile'], 'simple')

        if line[0:3] == '[*]':
            continue
        if len(line) == 0:
            break

        rdpy.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        rdpy.data('timestamp', f"{line[0:10]} {line[11:19]}")
        rdpy.data("timezone", time.strftime('%z'))

        rdpy.data('source_address', str(line.split("Connection from ")[1].split(":")[0])) if 'Connection from ' in line else None
        rdpy.data('target_address', ECFG['ip_ext'])
        rdpy.data('source_port', str(line.split("Connection from ")[1].split(":")[1])) if 'Connection from ' in line else None
        rdpy.data('target_port', "3389")
        rdpy.data('source_protokoll', "tcp")
        rdpy.data('target_protokoll', "tcp")

        rdpy.request("description", "RDP Honeypot RDPY")

        rdpy.adata('hostname', ECFG['hostname'])
        rdpy.adata('externalIP', ECFG['ip_ext'])
        rdpy.adata('internalIP', ECFG['ip_int'])
        rdpy.adata('uuid', ECFG['uuid'])

        if rdpy.buildAlert() == "sendlimit":
            break

    rdpy.finAlert()
    return()


def vnclowpot():

    vnclowpot = EAlert('vnclowpot', ECFG)

    ITEMS = ['vnclowpot', 'nodeid', 'logfile']
    HONEYPOT = (vnclowpot.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = vnclowpot.lineREAD(HONEYPOT['logfile'], 'simple')

        if len(line) == 0:
            break

        vnclowpot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        vnclowpot.data('timestamp', f"{line[0:10].replace('/', '-')} {line[11:19]}")
        vnclowpot.data("timezone", time.strftime('%z'))

        vnclowpot.data('source_address', str(line.split(' ')[2].split(':')[0]))
        vnclowpot.data('target_address', ECFG['ip_ext'])
        vnclowpot.data('source_port', str(line.split(' ')[2].split(':')[1]))
        vnclowpot.data('target_port', "5900")
        vnclowpot.data('source_protokoll', "tcp")
        vnclowpot.data('target_protokoll', "tcp")

        vnclowpot.request("description", "vnc Honeypot vnclowpot")

        vnclowpot.adata('hostname', ECFG['hostname'])
        vnclowpot.adata('externalIP', ECFG['ip_ext'])
        vnclowpot.adata('internalIP', ECFG['ip_int'])
        vnclowpot.adata('uuid', ECFG['uuid'])

        if vnclowpot.buildAlert() == "sendlimit":
            break

    vnclowpot.finAlert()
    return()


def heralding():

    heralding = EAlert('heralding', ECFG)

    ITEMS = ['heralding', 'nodeid', 'logfile']
    HONEYPOT = (heralding.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = heralding.lineREAD(HONEYPOT['logfile'], 'simple')

        if len(line) == 0:
            break
        if "timestamp" in line:
            continue

        heralding.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        heralding.data('timestamp', str(line[0:19]))
        heralding.data("timezone", time.strftime('%z'))

        heralding.data('source_address', str(line.split(',')[3]))
        heralding.data('target_address', str(line.split(',')[5]))
        heralding.data('source_port', str(line.split(',')[4]))
        heralding.data('target_port', str(line.split(',')[6]))
        heralding.data('source_protokoll', "tcp")
        heralding.data('target_protokoll', "tcp")

        heralding.request("description", "Heralding Honeypot")

        heralding.adata('hostname', ECFG['hostname'])
        heralding.adata('externalIP', ECFG['ip_ext'])
        heralding.adata('internalIP', ECFG['ip_int'])
        heralding.adata('uuid', ECFG['uuid'])
        heralding.adata('protocol', str(line.split(',')[7])) if str(line.split(',')[7]) != "" else None
        heralding.adata('username', str(line.split(',')[8])) if str(line.split(',')[8]) != "" else None
        heralding.adata('password', str(line.split(',')[9])) if str(line.split(',')[9]) != "" else None

        if heralding.buildAlert() == "sendlimit":
            break

    heralding.finAlert()
    return()


def mailoney():

    mailoney = EAlert('mailoney', ECFG)

    ITEMS = ['mailoney', 'nodeid', 'logfile']
    HONEYPOT = (mailoney.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = mailoney.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if 'EHLO User' not in line['data']:
            continue

        mailoney.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        mailoney.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
        mailoney.data("timezone", time.strftime('%z'))

        mailoney.data('source_address', line['src_ip']) if 'src_ip' in line else None
        mailoney.data('target_address', ECFG['ip_ext'])
        mailoney.data('source_port', str(line['src_port'])) if 'src_port' in line else None
        mailoney.data('target_port', "25")
        mailoney.data('source_protokoll', "tcp")
        mailoney.data('target_protokoll', "tcp")

        mailoney.request("description", "Mail Honeypot mailoney")

        mailoney.adata('hostname', ECFG['hostname'])
        mailoney.adata('externalIP', ECFG['ip_ext'])
        mailoney.adata('internalIP', ECFG['ip_int'])
        mailoney.adata('uuid', ECFG['uuid'])

        if mailoney.buildAlert() == "sendlimit":
            break

    mailoney.finAlert()
    return()


def conpot():

    conpot = EAlert('conpot', ECFG)

    ITEMS = ['conpot', 'nodeid', 'logfile']
    HONEYPOT = (conpot.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    logfiles = glob.glob(HONEYPOT['logfile'])
    if len(logfiles) < 1:
        print("[ERROR] Missing of correct LogFile for conpot. Skip!")
        return()

    for logfile in logfiles:
        index = ''
        for indexsearch in ['IEC104', 'guardian_ast', 'ipmi', 'kamstrup_382']:
            if indexsearch in logfile:
                index = indexsearch
        while True:
            line = conpot.lineREAD(logfile, 'json', None, index)

            if len(line) == 0:
                break
            if line == 'jsonfail':
                continue
            if line['event_type'] != 'NEW_CONNECTION':
                continue

            conpot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

            conpot.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
            conpot.data("timezone", time.strftime('%z'))

            conpot.data('source_address', line['src_ip']) if 'src_ip' in line else None
            conpot.data('target_address', line['dst_ip']) if 'dst_ip' in line else None
            conpot.data('source_port', str(line['src_port'])) if 'src_port' in line else None
            conpot.data('target_port', str(line['dst_port'])) if 'dst_ip' in line else None
            conpot.data('source_protokoll', "tcp")
            conpot.data('target_protokoll', "tcp")

            conpot.request('description', 'Conpot Honeypot')
            conpot.request('request', line['request']) if 'request' in line and line['request'] != "" else None

            conpot.adata('hostname', ECFG['hostname'])
            conpot.adata('externalIP', ECFG['ip_ext'])
            conpot.adata('internalIP', ECFG['ip_int'])
            conpot.adata('uuid', ECFG['uuid'])
            conpot.adata('conpot_data_type', line['data_type'])
            conpot.adata('conpot_response', line['conpot_response']) if 'conpot_response' in line and line['conpot_response'] != "" else None

            if conpot.buildAlert() == "sendlimit":
                break

        conpot.finAlert()

    return()


def glastopfv3():

    glastopfv3 = EAlert('glastopfv3', ECFG)

    ITEMS = ['glastopfv3', 'nodeid', 'sqlitedb', 'malwaredir']
    HONEYPOT = (glastopfv3.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
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
        glastopfv3.data('source_protokoll', "tcp")
        glastopfv3.data('target_protokoll', "tcp")

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


def emobility():

    emobility = EAlert('emobility', ECFG)

    ITEMS = ['emobility', 'nodeid', 'logfile']
    HONEYPOT = (emobility.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = emobility.lineREAD(HONEYPOT['logfile'], 'simple')

        if len(line) == 0:
            break

        srcipandport, dstipandport, url, dateandtime = line.split("|", 3)

        emobility.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None
        emobility.data('timestamp', f"{dateandtime[0:10]} {dateandtime[11:19]}")
        emobility.data("timezone", time.strftime('%z'))

        emobility.data('source_address', f"{srcipandport.split('.')[0]}.{srcipandport.split('.')[1]}.{srcipandport.split('.')[2]}.{srcipandport.split('.')[3]}")
        emobility.data('target_address', f"{dstipandport.split('.')[0]}.{dstipandport.split('.')[1]}.{dstipandport.split('.')[2]}.{dstipandport.split('.')[3]}")
        emobility.data('source_port', f"{srcipandport.split('.')[4]}")
        emobility.data('target_port', f"{dstipandport.split('.')[4]}")
        emobility.data('source_protokoll', "tcp")
        emobility.data('target_protokoll', "tcp")

        emobility.request('description', 'Emobility Honeypot')
        emobility.request('url', parse.quote(url.encode('ascii', 'ignore')))

        emobility.adata('hostname', ECFG['hostname'])
        emobility.adata('externalIP', ECFG['ip_ext'])
        emobility.adata('internalIP', ECFG['ip_int'])
        emobility.adata('uuid', ECFG['uuid'])

        if emobility.buildAlert() == "sendlimit":
            break

    emobility.finAlert()
    return()


def dionaea():

    dionaea = EAlert('dionaea', ECFG)

    ITEMS = ['dionaea', 'nodeid', 'sqlitedb', 'malwaredir']
    HONEYPOT = (dionaea.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
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
        dionaea.data('source_protokoll', line['connection_transport']) if 'connection_transport' in line else None
        dionaea.data('target_protokoll', line['connection_transport']) if 'connection_transport' in line else None

        dionaea.request('description', 'Network Honeyport Dionaea v0.1.0')

        if 'download_md5_hash' in download and ECFG['send_malware'] is True:
            error, payload = dionaea.malwarecheck(HONEYPOT['malwaredir'], str(download['download_md5_hash']), ECFG['del_malware_after_send'], str(download['download_md5_hash']))
            dionaea.request('binary', payload.decode('utf-8')) if error is True and len(payload) > 0 else None

        dionaea.adata('hostname', ECFG['hostname'])
        dionaea.adata('externalIP', ECFG['ip_ext'])
        dionaea.adata('internalIP', ECFG['ip_int'])
        dionaea.adata('uuid', ECFG['uuid'])
        dionaea.adata('payload_md5', download['download_md5_hash']) if 'download_md5_hash' in download else None

        if dionaea.buildAlert() == "sendlimit":
            break

    dionaea.finAlert()
    return()


def honeytrap():

    honeytrap = EAlert('honeytrap', ECFG)

    ITEMS = ['honeytrap', 'nodeid', 'attackerfile', 'payloaddir', 'newversion']
    HONEYPOT = (honeytrap.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    if HONEYPOT["newversion"].lower() == "true":
        print("    -> Calculate MD5Sum for payload files and rename files.")
        for index in os.listdir(HONEYPOT["payloaddir"]):
            if '_md5_' not in index:
                filein = HONEYPOT["payloaddir"] + os.sep + index
                os.rename(filein, filein + "_md5_" + hashlib.md5(open(filein, 'rb').read()).hexdigest())

    payloadfilelist = os.listdir(HONEYPOT["payloaddir"])

    while True:
        line = honeytrap.lineREAD(HONEYPOT['attackerfile'], 'simple')

        if len(line) == 0:
            break

        line = re.sub(r'  ', r' ', re.sub(r'[\[\]\-\>]', r'', line))

        if HONEYPOT["newversion"].lower() == "false":
            dates, times, _, source, dest, _ = line.split(" ", 5)
            protocol = ""
            md5 = ""
        else:
            dates, times, _, protocol, source, dest, md5, _ = line.split(" ", 7)

        honeytrap.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        honeytrap.data('timestamp', f"{dates[0:4]}-{dates[4:6]}-{dates[6:8]} {times[0:8]}")
        honeytrap.data("timezone", time.strftime('%z'))

        honeytrap.data('source_address', re.sub(":.*$", "", source)) if source else None
        honeytrap.data('target_address', re.sub(":.*$", "", dest)) if dest else None
        honeytrap.data('source_port', re.sub("^.*:", "", source)) if source else None
        honeytrap.data('target_port', re.sub("^.*:", "", dest)) if dest else None
        honeytrap.data('source_protokoll', protocol) if protocol else None
        honeytrap.data('target_protokoll', protocol) if protocol else None

        honeytrap.request('description', 'NetworkHoneypot Honeytrap v1.1')

        if HONEYPOT["newversion"].lower() == "true" and ECFG["send_malware"] is True:
            if md5 in payloadfilelist:
                error, payload = honeytrap.malwarecheck(HONEYPOT['payloaddir'], re.findall(f'.*{md5}*', payloadfilelist), False, md5)
                honeytrap.request('binary', payload.decode('utf-8')) if error is True and len(payload) > 0 else None

        honeytrap.adata('hostname', ECFG['hostname'])
        honeytrap.adata('externalIP', ECFG['ip_ext'])
        honeytrap.adata('internalIP', ECFG['ip_int'])
        honeytrap.adata('uuid', ECFG['uuid'])
        honeytrap.adata('payload_md5', md5) if md5 else None

        if honeytrap.buildAlert() == "sendlimit":
            break

    honeytrap.finAlert()
    return()


def cowrie():

    cowrie = EAlert('cowrie', ECFG)

    ITEMS = ['cowrie', 'nodeid', 'logfile']
    HONEYPOT = (cowrie.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    cowrieSessionIDs = cowrie.fileIndex('cowrie.session', 'read')
    cowrieSessions = {}

    cowrie.alertCount('COWRIE', 'reset_counter')

    while True:
        line = cowrie.lineREAD(HONEYPOT['logfile'], 'json')

        if isinstance(line, int):
            break
        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if not line['session'] or line['session'] in cowrieSessionIDs:
            continue

        sid = line['session']

        if line['eventid'] == 'cowrie.session.connect' and line['session'] not in cowrieSessions:
            cowrieSessions[sid] = {}
            cowrieSessions[sid]['timestamp_start'] = line['timestamp']
            cowrieSessions[sid]['source_ip'] = line['src_ip']
            cowrieSessions[sid]['source_port'] = line['src_port']
            cowrieSessions[sid]['target_ip'] = line['dst_ip']
            cowrieSessions[sid]['target_port'] = line['dst_port']
            cowrieSessions[sid]['session_id'] = line['session']
            cowrieSessions[sid]['protocol'] = line['protocol']

        if line['eventid'] == 'cowrie.login.success' and line['session'] in cowrieSessions:
            cowrieSessions[sid]['login'] = "Success"
            cowrieSessions[sid]['username'] = line['username']
            cowrieSessions[sid]['password'] = line['password']
            cowrieSessions[sid]['timestamp_login'] = line['timestamp']

        if line['eventid'] == 'cowrie.login.failed' and line['session'] in cowrieSessions:
            cowrieSessions[sid]['login'] = "Fail"
            cowrieSessions[sid]['username'] = line['username']
            cowrieSessions[sid]['password'] = line['password']
            cowrieSessions[sid]['timestamp_login'] = line['timestamp']

        if line['eventid'] == 'cowrie.session.closed' and line['session'] in cowrieSessions:
            cowrieSessions[sid]['timestamp_close'] = line['timestamp']

        if line['eventid'] == 'cowrieSession.command.input' and line['session'] in cowrieSessions:
            cowrieSessions[sid]['input'] = line['input']

        if line['eventid'] == 'cowrie.client.version' and line['session'] in cowrieSessions:
            if "b'" in line["version"]:
                cowrieSessions[sid]['version'] = re.search(r"b'(.*)'", line["version"], re.M).group(1)
            else:
                cowrieSessions[sid]['version'] = line["version"]

    """ second loop """

    for session in cowrieSessions:
        cowrie.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if cowrieSessions[session]['timestamp_start']:
            cowrie.data('timestamp', f"{cowrieSessions[session]['timestamp_start'][0:10]} {cowrieSessions[session]['timestamp_start'][11:19]}")
            cowrie.data("timezone", time.strftime('%z'))

        cowrie.data('source_address', cowrieSessions[session]['source_ip']) if cowrieSessions[session]['source_ip'] else None
        cowrie.data('target_address', cowrieSessions[session]['target_ip']) if cowrieSessions[session]['target_ip'] else None
        cowrie.data('source_port', cowrieSessions[session]['source_port']) if cowrieSessions[session]['source_port'] else None
        cowrie.data('target_port', cowrieSessions[session]['target_port']) if cowrieSessions[session]['target_port'] else None
        cowrie.data('source_protokoll', 'tcp')
        cowrie.data('target_protokoll', 'tcp')

        if cowrieSessions[session]['target_port'] == "23" or cowrieSessions[session]['target_port'] == "2323":
            cowrie.request("description", "Telnet Honeypot Cowrie")
        else:
            cowrie.request("description", "SSH Honeypot Cowrie")

        cowrie.adata('sessionid', session) if session else None
        cowrie.adata('logintime', f"{cowrieSessions[session]['timestamp_login'][0:10]} {cowrieSessions[session]['timestamp_login'][11:19]}") if 'timestamp_login' in cowrieSessions[session] else None
        cowrie.adata('endtimetime', f"{cowrieSessions[session]['timestamp_close'][0:10]} {cowrieSessions[session]['timestamp_close'][11:19]}") if 'timestamp_close' in cowrieSessions[session] else None
        cowrie.adata('version', str(cowrieSessions[session]['version'])) if 'version' in cowrieSessions[session] else None
        cowrie.adata('login', cowrieSessions[session]['login']) if 'login' in cowrieSessions[session] else None
        cowrie.adata('username', cowrieSessions[session]['username']) if 'username' in cowrieSessions[session]else None
        cowrie.adata('password', cowrieSessions[session]['password']) if 'password' in cowrieSessions[session] else None
        cowrie.adata('input', cowrieSessions[session]['input']) if 'input' in cowrieSessions[session] else None
        cowrie.adata('hostname', ECFG['hostname'])
        cowrie.adata('externalIP', ECFG['ip_ext'])
        cowrie.adata('internalIP', ECFG['ip_int'])
        cowrie.adata('uuid', ECFG['uuid'])

        cowrie.fileIndex('cowrie.session', 'write', session)

        if cowrie.buildAlert() == "sendlimit":
            break

    cowrie.finAlert()
    return()


def suricata():

    # MS 2021-11-17 temporarily disabled 
    return()

    suricata = EAlert('suricata', ECFG)

    ITEMS = ['suricata', 'nodeid', 'logfile']
    HONEYPOT = (suricata.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = suricata.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        suricata.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            suricata.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
            suricata.data("timezone", time.strftime('%z'))

        suricata.data('source_address', line['src_ip']) if 'src_ip' in line else None
        suricata.data('target_address', line['dest_ip']) if 'dest_ip' in line else None
        suricata.data('source_port', line['src_port']) if 'src_port' in line else None
        suricata.data('target_port', line['dest_port']) if 'dest_port' in line else None
        suricata.data('source_protokoll', line['proto'].lower()) if 'proto' in line else None
        suricata.data('target_protokoll', line['proto'].lower()) if 'proto' in line else None

        suricata.request('description', 'Suricata Attack')

        suricata.adata('hostname', ECFG['hostname'])
        suricata.adata('externalIP', ECFG['ip_ext'])
        suricata.adata('internalIP', ECFG['ip_int'])
        suricata.adata('uuid', ECFG['uuid'])

        if suricata.buildAlert() == "sendlimit":
            break

    suricata.finAlert()
    return()


def medpot():

    medpot = EAlert('medpot', ECFG)

    ITEMS = ['medpot', 'nodeid', 'logfile']
    HONEYPOT = (medpot.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = medpot.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        medpot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            medpot.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
            medpot.data("timezone", time.strftime('%z'))

        medpot.data('source_address', line['src_ip']) if 'src_ip' in line else None
        medpot.data('target_address', ECFG['ip_ext'])
        medpot.data('source_port', line['src_port']) if 'src_port' in line else None
        medpot.data('target_port', '2575')
        medpot.data('source_protokoll', 'tcp')
        medpot.data('target_protokoll', 'tcp')

        medpot.request('description', 'Medpot Honeypot')

        medpot.adata('hostname', ECFG['hostname'])
        medpot.adata('externalIP', ECFG['ip_ext'])
        medpot.adata('internalIP', ECFG['ip_int'])
        medpot.adata('uuid', ECFG['uuid'])

        if medpot.buildAlert() == "sendlimit":
            break

    medpot.finAlert()
    return()


def honeypy():

    honeypy = EAlert('honeypy', ECFG)

    ITEMS = ['honeypy', 'nodeid', 'logfile']
    HONEYPOT = (honeypy.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = honeypy.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue
        if line['event_type'] != "CONNECT":
            continue

        honeypy.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'timestamp' in line:
            honeypy.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
            honeypy.data("timezone", time.strftime('%z'))

        honeypy.data('source_address', line['src_ip']) if 'src_ip' in line else None
        honeypy.data('target_address', line['dest_ip']) if 'dest_ip' in line else None
        honeypy.data('source_port', line['src_port']) if 'src_port' in line else None
        honeypy.data('target_port', line['dest_port']) if 'dest_port' in line else None
        honeypy.data('source_protokoll', line['protocol'].lower()) if 'protocol' in line else None
        honeypy.data('target_protokoll', line['protocol'].lower()) if 'protocol' in line else None

        honeypy.request('description', 'Honeypy Honeypot')

        honeypy.adata('hostname', ECFG['hostname'])
        honeypy.adata('externalIP', ECFG['ip_ext'])
        honeypy.adata('internalIP', ECFG['ip_int'])
        honeypy.adata('uuid', ECFG['uuid'])

        if honeypy.buildAlert() == "sendlimit":
            break

    honeypy.finAlert()
    return()


def citrix():

    citrix = EAlert('citrix', ECFG)

    ITEMS = ['citrix', 'nodeid', 'logfile']
    HONEYPOT = (citrix.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line = citrix.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break
        if line == 'jsonfail':
            continue

        citrix.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'asctime' in line:
            citrix.data('timestamp', f"{line['asctime'][0:10]} {line['asctime'][11:19]}")
            citrix.data("timezone", time.strftime('%z'))

        try:
            citrix.data('source_address', re.search(r"\((.*)\).*", line['message'], re.M).group(1).split(":")[0]) if 'message' in line else None
            citrix.data('source_port', re.search(r"\((.*)\).*", line['message'], re.M).group(1).split(":")[1]) if 'message' in line else None
        except AttributeError:
            continue

        citrix.data('target_address', ECFG['ip_ext'])
        citrix.data('target_port', '80')
        citrix.data('source_protokoll', 'tcp')
        citrix.data('target_protokoll', 'tcp')

        citrix.request('description', 'Citrix Honeypot')

        citrix.adata('hostname', ECFG['hostname'])
        citrix.adata('externalIP', ECFG['ip_ext'])
        citrix.adata('internalIP', ECFG['ip_int'])
        citrix.adata('uuid', ECFG['uuid'])

        if citrix.buildAlert() == "sendlimit":
            break

    citrix.finAlert()
    return()


""" --- [ MAIN ] ------------------------------------------------------------------ """

if __name__ == "__main__":

    ECFG = ecfg(name, version)
    locksocket(name, ECFG['logdir'])
    logger = ELog('EMain')

    while True:
        if ECFG["a.ewsonly"] is False:
            ESend(ECFG)

        for honeypot in ECFG["HONEYLIST"]:

            if ECFG["a.modul"]:
                if ECFG["a.modul"] == honeypot:
                    if readonecfg(honeypot.upper(), honeypot, ECFG["cfgfile"]).lower() == "true":
                        eval(honeypot + '()')
                        break
                else:
                    continue

            if readonecfg(honeypot.upper(), honeypot, ECFG["cfgfile"]).lower() == "true":
                eval(honeypot + '()')

        if int(ECFG["a.loop"]) == 0:
            print(" => EWSrun finish.")
            break
        else:
            print(f" => Sleeping for {ECFG['a.loop']} seconds ...")
            time.sleep(int(ECFG["a.loop"]))
