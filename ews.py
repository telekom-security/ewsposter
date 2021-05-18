#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import time
import codecs
import hashlib
from linecache import getline, clearcache
from datetime import datetime
from lxml import etree
from copy import deepcopy
import glob
from moduls.exml import ewsauth, ewsalert
from moduls.einit import locksocket, ecfg
from moduls.elog import logme
from moduls.etoolbox import ip4or6, readcfg, readonecfg, calcminmax, countme
from moduls.ealert import EAlert
from moduls.esend import ESend
import sqlite3
import requests
import random
import base64
from urllib import parse
import hpfeeds
import fnmatch
import json
import OpenSSL.SSL
import ipaddress
from collections import OrderedDict
import socket
from xmljson import BadgerFish
import sys
import pprint

name = "EWS Poster"
version = "v1.15"


def ewswebservice(ems):

    MODUL = "ewswebservice"

    headers = {'User-Agent': name + " " + version,
               'Content-type': 'text/xml',
               'SOAPAction': '',
               'charset': 'UTF-8',
               'Connection': 'close'}

    host = random.choice([ECFG["rhost_first"], ECFG["rhost_second"]])

    if ECFG["proxy"] != "NULL" and ECFG["proxy"] != "FALSE":
        proxydic = {"https": ECFG["proxy"]}
    else:
        proxydic = {}

    try:
        if "https" not in proxydic:
            webservice = requests.post(host,
                                       data=ems,
                                       headers=headers,
                                       allow_redirects=True,
                                       timeout=60,
                                       verify=not ECFG["a.ignorecert"])
        else:
            webservice = requests.post(host,
                                       data=ems,
                                       headers=headers,
                                       allow_redirects=True,
                                       proxies=proxydic,
                                       timeout=60,
                                       verify=not ECFG["a.ignorecert"])

        webservice.raise_for_status()

        xmlresult = re.search('<StatusCode>(.*)</StatusCode>', webservice.text).groups()[0]

        if xmlresult != "OK":
            logme(MODUL, "XML Result != ok ( %s) (%s)" % (xmlresult, webservice.text), ("LOG", "VERBOSE"), ECFG)
            return False

        if ECFG["a.verbose"] is True:
            logme(MODUL, "---- Webservice Report ----", ("VERBOSE"), ECFG)
            logme(MODUL, "HOST          : %s" % (host), ("VERBOSE"), ECFG)
            logme(MODUL, "XML Result    : %s" % (xmlresult), ("VERBOSE"), ECFG)
            logme(MODUL, "Statuscode    : %s" % (webservice.status_code), ("VERBOSE"), ECFG)
            logme(MODUL, "Header        : %s" % (webservice.headers), ("VERBOSE"), ECFG)
            logme(MODUL, "Body          : %s" % (webservice.text), ("VERBOSE"), ECFG)
            logme(MODUL, "", ("VERBOSE"), ECFG)

        return True

    except requests.exceptions.Timeout as e:
        logme(MODUL, "Timeout to remote host %s (%s)" % (host, str(e)), ("LOG", "VERBOSE"), ECFG)
        return False

    except requests.exceptions.ConnectionError as e:
        logme(MODUL, "Remote host %s didn't answer! (%s)" % (host, str(e)), ("LOG", "VERBOSE"), ECFG)
        return False

    except requests.exceptions.HTTPError as e:
        logme(MODUL, "HTTP Errorcode != 200 (%s)" % (str(e)), ("LOG", "VERBOSE"), ECFG)
        return False

    except OpenSSL.SSL.WantWriteError as e:
        logme(MODUL, "OpenSSL Write Buffer too small (%s)" % (str(e)), ("LOG", "VERBOSE"), ECFG)
        return False


def viewcounter(MODUL, x, y):

    if y == 100:
        x += 100
        """ Inform every 100 send records """
        logme(MODUL, str(x) + " log entries processed ...", ("P2"), ECFG)
        y = 1
    else:
        y += 1

    return x, y


def buildews(esm, DATA, REQUEST, ADATA):

    ewsalert(esm, DATA, REQUEST, ADATA)

    if int(esm.xpath('count(//Alert)')) >= 100:
        sendews(esm)
        esm = ewsauth(ECFG["username"], ECFG["token"])

    return esm


def sendews(esm):

    if ECFG["a.ewsonly"] is True:
        writeews(etree.tostring(esm, pretty_print=True))
        return

    if ECFG["a.debug"] is True:
        writeews(etree.tostring(esm, pretty_print=True))

    if ECFG["ews"] is True and ewswebservice(etree.tostring(esm)) is not True:
        writeews(etree.tostring(esm, pretty_print=True))

    if ECFG["hpfeed"] is True:
        if ECFG["hpfformat"].lower() == "json":
            hpfeedsend(esm, "json")
        else:
            hpfeedsend(esm, "xml")

    return


def writeews(EWSALERT):
    with open(ECFG["spooldir"] + os.sep + datetime.now().strftime('%Y%m%dT%H%M%S.%f')[:-3] + ".ews", 'wb') as f:
        f.write(EWSALERT)
        f.close()

    return True


def md5malware(malware_md5):
    """ create file if its not present """
    with open(ECFG["homedir"] + os.sep + "malware.md5", "a+") as malwarefile:

        """ empty file """
        if os.stat(ECFG["homedir"] + os.sep + "malware.md5").st_size == 0:
            malwarefile.write(malware_md5 + "\n")
            malwarefile.close()
            return True

        if malware_md5 in open(ECFG["homedir"] + os.sep + "malware.md5", "r").read():
            malwarefile.close()
            return(False)
        else:
            malwarefile.write(malware_md5 + "\n")
            malwarefile.close()
            return(True)


def malware(DIR, FILE, KILL, md5):
    if not os.path.isdir(DIR):
        return 1, DIR + " DOES NOT EXIST!"

    if md5 and not md5malware(md5):
        return 1, "Malware MD5 %s already submitted." % md5

    if os.path.isfile(DIR + os.sep + FILE) is True:
        if os.path.getsize(DIR + os.sep + FILE) <= 5 * 1024 * 1024:
            payload = open(DIR + os.sep + FILE, "rb").read()
            malwarefile = base64.b64encode(payload)
            if KILL is True:
                os.remove(DIR + os.sep + FILE)
            return 0, malwarefile
        else:
            return 1, "FILE " + DIR + os.sep + FILE + " is bigger than 5 MB!"
    else:
        return 1, "FILE " + DIR + os.sep + FILE + " DOES NOT EXIST!"


def hpfeedsend(esm, eformat):
    if not hpc:
        return False

    """ remove auth header """
    etree.strip_elements(esm, "Authentication")

    for i in range(0, len(esm)):
        if eformat == "xml":
            hpc.publish(ECFG["channels"], etree.tostring(esm[i], pretty_print=False))

        if eformat == "json":
            bf = BadgerFish(dict_type=OrderedDict)
            hpc.publish(ECFG["channels"], json.dumps(bf.data(esm[i])))

    return True


def testhpfeedsbroker():
    if ECFG["hpfeed"] is True:
        """ workaround if hpfeeds broker is offline as otherwise hpfeeds lib will loop connection attempt """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ECFG["host"], int(ECFG["port"])))
        sock.close()

        if result != 0:
            """ broker unavailable """
            logme(MODUL, "HPFEEDS broker is configured to {0}:{1} but is currently unavailable. Disabling hpfeeds submission for this round!".format(ECFG["host"], ECFG["port"]), ("P1"), ECFG)
            return False

        try:
            if ECFG["tlscert"].lower() != "none":
                hpc = hpfeeds.new(ECFG["host"], int(ECFG["port"]), ECFG["ident"], ECFG["secret"], certfile=ECFG["tlscert"], reconnect=False)
                logme("hpfeedsend", "Connecting to %s via TLS" % format(hpc.brokername + "/" + ECFG["host"] + ":" + str(ECFG["port"])), ("P3", "VERBOSE"), ECFG)
            else:
                hpc = hpfeeds.new(ECFG["host"], int(ECFG["port"]), ECFG["ident"], ECFG["secret"], reconnect=False)
                logme("hpfeedsend", "Connecting to %s" % format(hpc.brokername + "/" + ECFG["host"] + ":" + str(ECFG["port"])), ("P3", "VERBOSE"), ECFG)

            return hpc

        except hpfeeds.FeedException as e:
            logme("hpfeedsend", "HPFeeds Error (%s)" % format(e), ("P1", "VERBOSE"), ECFG)
            return False
    return False


def buildjson(jesm, DATA, REQUEST, ADATA):

    if DATA["sport"] == "":
        DATA["sport"] = "0"

    if 'raw' in REQUEST and REQUEST['raw'] != "":
        REQUEST['raw'] = REQUEST['raw']

    myjson = {}
    myjson['timestamp'] = ("%sT%s.000000" % (DATA["timestamp"][0:10], DATA["timestamp"][11:19]))
    myjson['event_type'] = "alert"
    myjson['src_ip'] = DATA["sadr"]
    myjson['src_port'] = DATA['sport']
    myjson['dest_ip'] = DATA['tadr']
    myjson['dest_port'] = DATA['tport']

    if REQUEST:
        myjson["request"] = REQUEST

    if ADATA:
        myjson["additionaldata"] = ADATA

    return jesm + json.dumps(myjson) + "\n"


def writejson(jesm):
    if len(jesm) > 0 and ECFG["json"] is True:
        with open(ECFG["jsondir"], 'a+') as f:
            f.write(jesm)
            f.close()


def verbosemode(MODUL, DATA, REQUEST, ADATA):
    logme(MODUL, "---- " + MODUL + " ----", ("VERBOSE"), ECFG)
    logme(MODUL, "Nodeid          : %s" % DATA["aid"], ("VERBOSE"), ECFG)
    logme(MODUL, "Timestamp       : %s" % DATA["timestamp"], ("VERBOSE"), ECFG)
    logme(MODUL, "", ("VERBOSE"), ECFG)
    logme(MODUL, "Source IP       : %s" % DATA["sadr"], ("VERBOSE"), ECFG)
    logme(MODUL, "Source IPv      : %s" % DATA["sipv"], ("VERBOSE"), ECFG)
    logme(MODUL, "Source Port     : %s" % DATA["sport"], ("VERBOSE"), ECFG)
    logme(MODUL, "Source Protocol : %s" % DATA["sprot"], ("VERBOSE"), ECFG)
    logme(MODUL, "Target IP       : %s" % DATA["tadr"], ("VERBOSE"), ECFG)
    logme(MODUL, "Target IPv      : %s" % DATA["tipv"], ("VERBOSE"), ECFG)
    logme(MODUL, "Target Port     : %s" % DATA["tport"], ("VERBOSE"), ECFG)
    logme(MODUL, "Target Protocol : %s" % DATA["tprot"], ("VERBOSE"), ECFG)

    for key, value in list(ADATA.items()):
        logme(MODUL, "%s       : %s" % (key, value), ("VERBOSE"), ECFG)

    logme(MODUL, "", ("VERBOSE"), ECFG)

    return()


def cowrie():

    MODUL = "COWRIE"
    logme(MODUL, "Starting Cowrie Modul.", ("P1"), ECFG)

    """ session related variables """
    lastSubmittedLine, firstOpenedWithoutClose = 0, 0

    """ collect honeypot config dic """

    ITEMS = ("cowrie", "nodeid", "logfile")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    HONEYPOT["ip"] = readonecfg(MODUL, "ip_ext", ECFG["cfgfile"])

    if HONEYPOT["ip"].lower() == "false" or HONEYPOT["ip"].lower() == "null":
        HONEYPOT["ip"] = ECFG["ip_ext"]

    """ logfile file exists ? """

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL, "[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !", ("P3", "LOG"), ECFG)

    """ count limit """

    imin = int(countme(MODUL, 'firstopenedwithoutclose', -1, ECFG))

    if imin > 0:
        imin = imin - 1
    firstOpenedWithoutClose = imin
    lastSubmittedLine = int(countme(MODUL, 'lastsubmittedline', -1, ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL, "Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!", ("P1"), ECFG)

    I = 0
    x = 0
    y = 1
    J = 0

    esm = ewsauth(ECFG["username"], ECFG["token"])
    jesm = ""

    """ dict to gather session information """
    cowriesessions = OrderedDict()
    sessionstosend = []

    while True:
        if int(ECFG["sendlimit"]) > 0 and J >= int(ECFG["sendlimit"]):
            break
        I += 1

        line = getline(HONEYPOT["logfile"], (imin + I)).rstrip()
        currentline = imin + I

        if len(line) == 0:
            break
        else:
            """ parse json """
            try:
                content = json.loads(line)
            except ValueError:
                logme(MODUL, "Invalid json entry found in line " + str(currentline) + ", skipping entry.", ("P3"), ECFG)
            else:
                """ if new session is started, store session-related info """
                if (content['eventid'] == "cowrie.session.connect"):
                    """
                         create empty session content: structure will be the same as kippo, add dst port and commands
                         | id  | username | password | success | logintimestamp | session | sessionstarttime| sessionendtime | ip | cowrieip | version| src_port|dst_port|dst_ip|commands | successful login
                    """
                    cowriesessions[content["session"]] = [currentline, '', '', '', '', content["session"], content["timestamp"], '', content["src_ip"], content["sensor"], '', content["src_port"], content["dst_port"], content["dst_ip"], "", False]
                    firstOpenedWithoutClose = list(cowriesessions.values())[0][0]

                """ store correponding ssh client version """
                if (content['eventid'] == "cowrie.client.version"):
                    if content["session"] in cowriesessions:
                        cowriesessions[content["session"]][10] = content["version"]

                """ create successful login """
                if (content['eventid'] == "cowrie.login.success"):
                    if content["session"] in cowriesessions:
                        cowriesessions[content["session"]][3] = "Success"
                        cowriesessions[content["session"]][1] = content["username"]
                        cowriesessions[content["session"]][2] = content["password"]
                        cowriesessions[content["session"]][4] = content["timestamp"]
                        cowriesessions[content["session"]][15] = True

                """ create failed login """
                if (content['eventid'] == "cowrie.login.failed"):
                    if content["session"] in cowriesessions:
                        cowriesessions[content["session"]][3] = "Fail"
                        cowriesessions[content["session"]][1] = content["username"]
                        cowriesessions[content["session"]][2] = content["password"]
                        cowriesessions[content["session"]][4] = content["timestamp"]
                        if currentline > lastSubmittedLine:
                            sessionstosend.append(deepcopy(cowriesessions[content["session"]]))
                            lastSubmittedLine = currentline
                            J += 1

                """ store terminal input / commands """
                if (content['eventid'] == "cowrie.command.input"):
                    if content["session"] in cowriesessions:
                        cowriesessions[content["session"]][14] = cowriesessions[content["session"]][14] + "\n" + content["input"]
                        cowriesessions[content["session"]][15] = True

                """ store session close """
                if (content['eventid'] == "cowrie.session.closed"):
                    if content["session"] in cowriesessions:
                        if (cowriesessions[content["session"]][5] == content["session"]):
                            cowriesessions[content["session"]][7] == content["timestamp"]
                            if currentline > lastSubmittedLine:
                                if cowriesessions[content["session"]][15] is True:
                                    sessionstosend.append(deepcopy(cowriesessions[content["session"]]))
                                    lastSubmittedLine = currentline
                                    J += 1
                                cowriesessions.pop(content["session"])
                                if len(cowriesessions) == 0:
                                    firstOpenedWithoutClose = currentline

    """ loop through list of sessions to send """
    for key in sessionstosend:

        x, y = viewcounter(MODUL, x, y)

        """ map ssh ports for t-pot """
        if key[12] == 2223:
            service = "Telnet"
            serviceport = "23"
        elif key[12] == 2222:
            service = "SSH"
            serviceport = "22"
        elif key[12] == 23:
            service = "Telnet"
            serviceport = "23"
        else:
            service = "SSH"
            serviceport = "22"

        DATA = {"aid": HONEYPOT["nodeid"],
                "timestamp": "%s-%s-%s %s" % (key[4][0:4], key[4][5:7], key[4][8:10], key[4][11:19]),
                "sadr": str(key[8]),
                "sipv": "ipv" + ip4or6(str(key[8])),
                "sprot": "tcp",
                "sport": str(key[11]),
                "tipv": "ipv" + ip4or6(HONEYPOT["ip"]),
                "tadr": str(key[13]),
                "tprot": "tcp",
                "tport": serviceport}

        REQUEST = {"description": service + " Honeypot Cowrie"}

        """ Collect additional Data """
        login = str(key[3])
        if (key[7] != ""):
            endtime = "%s-%s-%s %s" % (key[7][0:4], key[7][5:7], key[7][8:10], key[7][11:19])
        else:
            endtime = ""

        """ fix unicode in json log """
        cusername, cpassword, cinput = "", "", ""
        try:
            cusername = str(key[1])
        except UnicodeEncodeError:
            logme(MODUL, "Unicode in username  " + key[1] + " - removing unicode.", ("P3"), ECFG)
            cusername = key[1].encode('ascii', 'ignore')

        try:
            cpassword = str(key[2])
        except UnicodeEncodeError:
            logme(MODUL, "Unicode in password " + key[2] + " - removing unicode.", ("P3"), ECFG)
            cpassword = key[2].encode('ascii', 'ignore')

        try:
            cinput = str(key[14])
        except UnicodeEncodeError:
            logme(MODUL, "Unicode in input " + key[14] + " - removing unicode.", ("P3"), ECFG)
            cinput = str(key[14]).encode('ascii', 'ignore')

        ADATA = {"sessionid": str(key[5]),
                 "starttime": "%s-%s-%s %s" % (key[6][0:4], key[6][5:7], key[6][8:10], key[6][11:19]),
                 "endtime": endtime,
                 "version": str(key[10]),
                 "login": login,
                 "username": cusername,
                 "password": cpassword,
                 "input": cinput,
                 "hostname": ECFG["hostname"],
                 "externalIP": ECFG['ip_ext'],
                 "internalIP": ECFG['ip_int'],
                 "uuid": ECFG['uuid']}

        """ generate template and send """

        esm = buildews(esm, DATA, REQUEST, ADATA)
        jesm = buildjson(jesm, DATA, REQUEST, ADATA)

        countme(MODUL, 'firstopenedwithoutclose', firstOpenedWithoutClose, ECFG)
        countme(MODUL, 'lastsubmittedline', lastSubmittedLine, ECFG)

        if ECFG["a.verbose"] is True:
            verbosemode(MODUL, DATA, REQUEST, ADATA)

    """ Cleaning linecache """
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 1), ("P2"), ECFG)
    return


def dionaea():
    MODUL = "DIONAEA"
    logme(MODUL, "Starting Dionaea Modul.", ("P1"), ECFG)

    """ collect honeypot config dic """

    ITEMS = ("dionaea", "nodeid", "sqlitedb", "malwaredir")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    """ Malwaredir exist """

    if os.path.isdir(HONEYPOT["malwaredir"]) is False:
        logme(MODUL, "[ERROR] Missing Malware Dir " + HONEYPOT["malwaredir"] + ". Abort !", ("P3", "LOG"), ECFG)

    """ is sqlitedb exist ? """

    if os.path.isfile(HONEYPOT["sqlitedb"]) is False:
        logme(MODUL, "[ERROR] Missing sqlitedb file " + HONEYPOT["sqlitedb"] + ". Abort !", ("P3", "LOG"), ECFG)
        return

    """ open database """

    con = sqlite3.connect(HONEYPOT["sqlitedb"], 30)
    con.row_factory = sqlite3.Row
    c = con.cursor()

    """ calculate send limit """

    try:
        c.execute("SELECT max(connection) from connections;")
    except sqlite3.DatabaseError:
        logme(MODUL, "[INFO] Sqlitedb %s is corrupt or does not contain events. Skipping ! " % HONEYPOT["sqlitedb"],
              ("P3", "LOG"), ECFG)
        return

    maxid = c.fetchone()["max(connection)"]

    if maxid is None:
        logme(MODUL, "[INFO] No entry's in Dionaea Database. Skip !", ("P2", "LOG"), ECFG)
        return

    imin, imax = calcminmax(MODUL, int(countme(MODUL, 'sqliteid', -1, ECFG)), int(maxid), ECFG)

    """ read alerts from database """

    c.execute("SELECT * from connections where connection > ? and connection <= ?;", (imin, imax,))
    rows = c.fetchall()

    """ counter inits """

    x = 0
    y = 1

    esm = ewsauth(ECFG["username"], ECFG["token"])
    jesm = ""

    for row in rows:

        x, y = viewcounter(MODUL, x, y)

        """ filter empty remote_host """

        if row["remote_host"] == "":
            countme(MODUL, 'sqliteid', row["connection"], ECFG)
            continue

        """ fix docker problems with dionaea IPs """
        if '::ffff:' in row["remote_host"]:
            remoteHost = row["remote_host"].split('::ffff:')[1]
        else:
            remoteHost = row["remote_host"]

        if '::ffff:' in row["local_host"]:
            localHost = row["local_host"].split('::ffff:')[1]
        else:
            localHost = row["local_host"]

        """ prepare and collect Alert Data """

        DATA = {"aid": HONEYPOT["nodeid"],
                "timestamp": datetime.utcfromtimestamp(int(row["connection_timestamp"])).strftime('%Y-%m-%d %H:%M:%S'),
                "sadr": str(remoteHost),
                "sipv": "ipv" + ip4or6(str(remoteHost)),
                "sprot": str(row["connection_transport"]),
                "sport": str(row["remote_port"]),
                "tipv": "ipv" + ip4or6(str(localHost)),
                "tadr": str(localHost),
                "tprot": str(row["connection_transport"]),
                "tport": str(row["local_port"])}

        REQUEST = {"description": "Network Honeyport Dionaea v0.1.0"}

        """ Collect additional Data """

        ADATA = {"sqliteid": str(row["connection"]),
                 "hostname": ECFG["hostname"],
                 "externalIP": ECFG['ip_ext'],
                 "internalIP": ECFG['ip_int'],
                 "uuid": ECFG['uuid']}

        """ Check for malware bin's """

        c.execute("SELECT download_md5_hash from downloads where connection = ?;", (str(row["connection"]),))
        check = c.fetchone()
        if check is not None and ECFG["send_malware"] is True:
            error, malwarefile = malware(HONEYPOT["malwaredir"], check[0], ECFG["del_malware_after_send"], check[0])
            if error == 0:
                REQUEST["binary"] = malwarefile.decode('utf-8')
            else:
                logme(MODUL, "Malwarefile: %s" % malwarefile, ("P1", "LOG"), ECFG)
            if check[0]:
                ADATA["payload_md5"] = check[0]

        """ generate template and send """

        esm = buildews(esm, DATA, REQUEST, ADATA)
        jesm = buildjson(jesm, DATA, REQUEST, ADATA)

        countme(MODUL, 'sqliteid', row["connection"], ECFG)

        if ECFG["a.verbose"] is True:
            verbosemode(MODUL, DATA, REQUEST, ADATA)

    con.close()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 1), ("P2"), ECFG)
    return


def honeytrap():

    MODUL = "HONEYTRAP"
    logme(MODUL, "Starting Honeytrap Modul.", ("P1"), ECFG)

    """ collect honeypot config dic """

    ITEMS = ("honeytrap", "nodeid", "attackerfile", "payloaddir", "newversion")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    """ Attacking file exists """

    if os.path.isfile(HONEYPOT["attackerfile"]) is False:
        logme(MODUL, "[ERROR] Missing Attacker File " + HONEYPOT["attackerfile"] + ". Abort !", ("P3", "LOG"), ECFG)

    """ Payloaddir exist """

    if os.path.isdir(HONEYPOT["payloaddir"]) is False:
        logme(MODUL, "[ERROR] Missing Payload Dir " + HONEYPOT["payloaddir"] + ". Abort !", ("P3", "LOG"), ECFG)

    """ New Version are use """

    if HONEYPOT["newversion"].lower() == "true" and not os.path.isdir(HONEYPOT["payloaddir"]):
        logme(MODUL, "[ERROR] Missing Payload Directory " + HONEYPOT["payloaddir"] + ". Abort !", ("P3", "LOG"), ECFG)

    """ Calc MD5sum for Payloadfiles """

    if HONEYPOT["newversion"].lower() == "true":
        logme(MODUL, "Calculate MD5sum for Payload Files", ("P2"), ECFG)

        for i in os.listdir(HONEYPOT["payloaddir"]):
            if "_md5_" not in i:
                filein = HONEYPOT["payloaddir"] + os.sep + i
                os.rename(filein, filein + "_md5_" + hashlib.md5(open(filein, 'rb').read()).hexdigest())

    """ count limit """
    imin = int(countme(MODUL, 'fileline', -1, ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL, "Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!", ("P1"), ECFG)

    I = 0
    x = 0
    y = 1

    esm = ewsauth(ECFG["username"], ECFG["token"])
    jesm = ""

    while True:

        x, y = viewcounter(MODUL, x, y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["attackerfile"], (imin + I)).rstrip()

        if len(line) == 0:
            break
        else:
            line = re.sub(r'  ', r' ', re.sub(r'[\[\]\-\>]', r'', line))

            if HONEYPOT["newversion"].lower() == "false":
                date, time, _, source, dest, _ = line.split(" ", 5)
                protocol = ""
                md5 = ""
            else:
                date, time, _, protocol, source, dest, md5, _ = line.split(" ", 7)

            """  Prepair and collect Alert Data """

            DATA = {"aid": HONEYPOT["nodeid"],
                    "timestamp": "%s-%s-%s %s" % (date[0:4], date[4:6], date[6:8], time[0:8]),
                    "sadr": re.sub(":.*$", "", source),
                    "sipv": "ipv" + ip4or6(re.sub(":.*$", "", source)),
                    "sprot": protocol,
                    "sport": re.sub("^.*:", "", source),
                    "tipv": "ipv" + ip4or6(re.sub(":.*$", "", dest)),
                    "tadr": re.sub(":.*$", "", dest),
                    "tprot": protocol,
                    "tport": re.sub("^.*:", "", dest)}

            REQUEST = {"description": "NetworkHoneypot Honeytrap v1.1"}

            """ Collect additional Data """

            ADATA = {"hostname": ECFG["hostname"],
                     "externalIP": ECFG['ip_ext'],
                     "internalIP": ECFG['ip_int'],
                     "uuid": ECFG['uuid']}

            """ Search for Payload """
            if HONEYPOT["newversion"].lower() == "true" and ECFG["send_malware"] is True:
                sfile = "from_port_%s-%s_*_%s-%s-%s_md5_%s" % (re.sub("^.*:", "", dest), protocol, date[0:4], date[4:6], date[6:8], md5)
                for mfile in os.listdir(HONEYPOT["payloaddir"]):
                    if fnmatch.fnmatch(mfile, sfile):
                        error, payloadfile = malware(HONEYPOT["payloaddir"], mfile, False, md5)
                        if error == 0:
                            REQUEST["binary"] = payloadfile.decode('utf-8')
                        else:
                            logme(MODUL, "Malwarefile : %s" % payloadfile, ("P1", "LOG"), ECFG)
                        if md5:
                            ADATA["payload_md5"] = md5

            """ generate template and send """

            esm = buildews(esm, DATA, REQUEST, ADATA)
            jesm = buildjson(jesm, DATA, REQUEST, ADATA)

            countme(MODUL, 'fileline', -2, ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL, DATA, REQUEST, ADATA)

    """ Cleaning linecache """
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 2), ("P2"), ECFG)
    return


def emobility():

    MODUL = "EMOBILITY"
    logme(MODUL, "Starting eMobility Modul.", ("P1"), ECFG)

    """ collect honeypot config dic """

    ITEMS = ("eMobility", "nodeid", "logfile")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    """ logfile file exists ? """

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL, "[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !", ("P3", "LOG"), ECFG)

    """ count limit """

    imin = int(countme(MODUL, 'fileline', -1, ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL, "Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!", ("P1"), ECFG)

    I = 0
    x = 0
    y = 1

    esm = ewsauth(ECFG["username"], ECFG["token"])
    jesm = ""

    while True:

        x, y = viewcounter(MODUL, x, y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["logfile"], (imin + I)).rstrip()

        if len(line) == 0:
            break
        else:
            """ Prepair and collect Alert Data """

            line = re.sub(r'  ', r' ', re.sub(r'[\[\]\-\>]', r'', line))

            srcipandport, dstipandport, url, dateandtime = line.split("|", 3)

            DATA = {"aid": HONEYPOT["nodeid"],
                    "timestamp": "%s-%s-%s %s" % (dateandtime[0:4], dateandtime[4:6], dateandtime[6:8], dateandtime[9:17]),
                    "sadr": "%s.%s.%s.%s" % (srcipandport.split(".")[0], srcipandport.split(".")[1], srcipandport.split(".")[2], srcipandport.split(".")[3]),
                    "sipv": "ipv4",
                    "sprot": "tcp",
                    "sport": srcipandport.split(".")[4],
                    "tipv": "ipv4",
                    "tadr": "%s.%s.%s.%s" % (dstipandport.split(".")[0], dstipandport.split(".")[1], dstipandport.split(".")[2], dstipandport.split(".")[3]),
                    "tprot": "tcp",
                    "tport": dstipandport.split(".")[4]}

            REQUEST = {"description": "eMobility Honeypot",
                       "url": parse.quote(url.encode('ascii', 'ignore'))}

            """ collect additional Data """

            ADATA = {"hostname": ECFG["hostname"],
                     "externalIP": ECFG['ip_ext'],
                     "internalIP": ECFG['ip_int'],
                     "uuid": ECFG['uuid']}

            """ generate template and send """

            esm = buildews(esm, DATA, REQUEST, ADATA)
            jesm = buildjson(jesm, DATA, REQUEST, ADATA)

            countme(MODUL, 'fileline', -2, ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL, DATA, REQUEST, ADATA)

    """ Cleaning linecache """
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 2), ("P2"), ECFG)
    return


def suricata():
    MODUL = "SURICATA"
    logme(MODUL, "Starting Suricata Modul.", ("P1"), ECFG)

    """ collect honeypot config dic """

    ITEMS = ("suricata", "nodeid", "logfile")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    """ logfile file exists ? """

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL, "[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !", ("P3", "LOG"), ECFG)

    """ count limit """

    imin = int(countme(MODUL, 'fileline', -1, ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL, "Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!", ("P1"), ECFG)

    I = 0
    x = 0
    y = 1
    J = 0

    esm = ewsauth(ECFG["username"], ECFG["token"])
    jesm = ""

    while True:

        x, y = viewcounter(MODUL, x, y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["logfile"], (imin + I)).rstrip()
        currentline = imin + I

        if len(line) == 0:
            break
        else:
            """ parse json """
            try:
                content = json.loads(line)
            except ValueError:
                logme(MODUL, "Invalid json entry found in line " + str(currentline) + ", skipping entry.", ("P3"), ECFG)
                countme(MODUL, 'fileline', -2, ECFG)
                J += 1
            else:
                if 'alert' in content and "src_port" in content:
                    if 'cve_id' in content['alert']:
                        """ use t-pots external address if src_ip is rfc1819 / private """
                        if (ipaddress.ip_address(content["dest_ip"]).is_private):
                            externalip = content["t-pot_ip_ext"]
                        else:
                            externalip = content["dest_ip"]

                        """ Prepare and collect Alert Data """

                        DATA = {"aid": HONEYPOT["nodeid"],
                                "timestamp": "%s" % re.sub("T", " ", content["timestamp"][:-12]),
                                "sadr": "%s" % content["src_ip"],
                                "sipv": "ipv" + ip4or6(content["src_ip"]),
                                "sprot": content["proto"].lower(),
                                "sport": "%d" % content["src_port"],
                                "tipv": "ipv" + ip4or6(externalip),
                                "tadr": "%s" % externalip,
                                "tprot": content["proto"].lower(),
                                "tport": "%d" % content["dest_port"]}

                        if "http" in content:
                            httpextras = parse.quote(str(content["http"]).encode('ascii', 'ignore'))
                        else:
                            httpextras = ""

                        REQUEST = {"description": "Suricata CVE Attack",
                                   "request": httpextras}

                        """ Collect additional Data """

                        ADATA = {"cve_id": "%s" % content["alert"]["cve_id"],
                                 "hostname": ECFG["hostname"],
                                 "externalIP": ECFG['ip_ext'],
                                 "internalIP": ECFG['ip_int'],
                                 "uuid": ECFG['uuid']}

                        """ generate template and send """
                        esm = buildews(esm, DATA, REQUEST, ADATA)
                        jesm = buildjson(jesm, DATA, REQUEST, ADATA)

                        countme(MODUL, 'fileline', -2, ECFG)

                        if ECFG["a.verbose"] is True:
                            verbosemode(MODUL, DATA, REQUEST, ADATA)

                    else:
                        countme(MODUL, 'fileline', -2, ECFG)
                        J += 1
                else:
                    countme(MODUL, 'fileline', -2, ECFG)
                    J += 1

    """ Cleaning linecache """
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 2 - J), ("P2"), ECFG)
    return


def ipphoney():

    ipphoney = EAlert('ipphoney', ECFG)

    ITEMS = ['ipphoney', 'nodeid', 'logfile']
    HONEYPOT = (ipphoney.readCFG(ITEMS, ECFG['cfgfile']))

    while True:
        line = ipphoney.lineREAD(HONEYPOT['logfile'], 'json')

        if line == 'jsonfail':
            continue
        if len(line) == 0:
            break

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

    while True:
        line = fatt.lineREAD(HONEYPOT['logfile'], 'json')

        if line == 'jsonfail':
            continue
        if len(line) == 0:
            break

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

    while True:
        line = adbhoney.lineREAD(HONEYPOT['logfile'], 'json')

        if line == 'jsonfail':
            continue
        if len(line) == 0:
            break
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

    while True:
        line = honeysap.lineREAD(HONEYPOT['logfile'], 'json')

        if line == 'jsonfail':
            continue
        if len(line) == 0:
            break

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

    while True:
        line = dicompot.lineREAD(HONEYPOT['logfile'], 'json')

        if line == 'jsonfail':
            continue
        if len(line) == 0:
            break
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

    ITEMS = ['elasticport', 'nodeid', 'logfile']
    HONEYPOT = (elasticpot.readCFG(ITEMS, ECFG['cfgfile']))

    while True:
        line = elasticpot.lineREAD(HONEYPOT['logfile'], 'json')

        if line == 'jsonfail':
            continue
        if len(line) == 0:
            break

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
                elasticpot.request(element, str(line[element]))

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

    while True:
        line = glutton.lineREAD(HONEYPOT['logfile'], 'json')

        if line == 'jsonfail':
            continue
        if len(line) == 0:
            break
        if "src_ip" not in line:
            continue
        if "error" in line["level"]:
            continue

        glutton.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'ts' in line:
            glutton.data('timestamp', datetime.fromtimestamp(float(line['ts']))).strftime('%Y-%m-%d %H:%M:%S')
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

    while True:
        line = ciscoasa.lineREAD(HONEYPOT['logfile'], 'json')

        if line == 'jsonfail':
            continue
        if len(line) == 0:
            break
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

        heralding.data('hostname', ECFG['hostname'])
        heralding.data('externalIP', ECFG['ip_ext'])
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

    while True:
        line = mailoney.lineREAD(HONEYPOT['logfile'], 'json')

        if len(line) == 0:
            break

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

        mailoney.data('hostname', ECFG['hostname'])
        mailoney.data('externalIP', ECFG['ip_ext'])
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

    logfiles = glob.glob(HONEYPOT['logfile'])
    if len(logfiles) < 1:
        print("[ERROR] Missing of correct LogFile for conpot. Skip!")
        return()

    for logfile in logfiles:
        while True:
            index = ''
            for indexsearch in ['IEC104', 'guardian_ast', 'ipmi', 'kampstrup_382']:
                if 'indexsearch' in logfile:
                    index = indexsearch

            line = conpot.lineREAD(logfile, 'json', None, index)

            if len(line) == 0:
                break
            if 'NEW_CONNECTION' not in line['event_type']:
                continue

            conpot.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

            conpot.data('timestamp', f"{line['timestamp'][0:10]} {line['timestamp'][11:19]}")
            conpot.data("timezone", time.strftime('%z'))

            conpot.data('source_address', line['src_ip']) if 'src_ip' in line else None
            conpot.data('target_address', line['dst_ip']) if 'dst_ip' in line else None
            conpot.data('source_port', str(line['src_port'])) if 'src_port' in line else None
            conpot.data('target_port', str(line['dst_ip'])) if 'dst_ip' in line else None
            conpot.data('source_protokoll', "tcp")
            conpot.data('target_protokoll', "tcp")

            conpot.request('description', 'Conpot Honeypot')
            conpot.request('request', line['request']) if 'request' in line and line['request'] != "" else None

            conpot.data('hostname', ECFG['hostname'])
            conpot.data('externalIP', ECFG['ip_ext'])
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

    while True:
        line = glastopfv3.lineSQLITE(HONEYPOT['sqlitedb'])

        if len(line) == 0:
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
            error, message, payload = glastopfv3.malwarecheck(HONEYPOT["malwaredir"], str(line["filename"]), ECFG["del_malware_after_send"], str(line["filename"]))
            glastopfv3.request("binary", payload.decode('utf-8')) if error is True and len(payload) > 0 else None

        glastopfv3.adata('hostname', ECFG['hostname'])
        glastopfv3.adata('externalIP', ECFG['ip_ext'])
        glastopfv3.adata('internalIP', ECFG['ip_int'])
        glastopfv3.adata('uuid', ECFG['uuid'])

        glastopfv3.adata('httpmethod', line['request_method']) if 'request_method' in line else None
        glastopfv3.adata('request_body', line['request_body']) if 'request_body' in line and len(line['request_body']) > 0 else None
        glastopfv3.adata('host', str(re.search(r'Host: (\b.+\b)', line["request_raw"], re.M).group(1))) if 'request_raw' in line and len(line['request_raw']) > 0 else None

        if glastopfv3.buildAlert() == "sendlimit":
            break

    glastopfv3.finAlert()
    return()


def medpot():
    pass


def honeypy():
    pass


""" --- [ MAIN ] ------------------------------------------------------------------ """

if __name__ == "__main__":

    MODUL = "MAIN"

    global ECFG
    ECFG = ecfg(name, version)

    global hpc
    hpc = testhpfeedsbroker()

    lock = locksocket(name)

    if lock is True:
        logme(MODUL, "Create lock socket successfull.", ("P1"), ECFG)
    else:
        logme(MODUL, "Another Instance is running ! EWSrun finish.", ("P1", "EXIT"), ECFG)

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
            logme(MODUL, "EWSrun finish.", ("P1"), ECFG)
            break
        else:
            logme(MODUL, "Sleeping for %s seconds ...." % ECFG["a.loop"], ("P1"), ECFG)
            time.sleep(int(ECFG["a.loop"]))
