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
import ast

from moduls.exml import ewsauth, ewsalert
from moduls.einit import locksocket, ecfg, daycounterreset
from moduls.elog import logme
from moduls.etoolbox import ip4or6, readcfg, readonecfg, timestamp, calcminmax, countme, checkForPublicIP, getOwnExternalIP, getOwnInternalIP, resolveHost

import sqlite3
import MySQLdb.cursors
import requests
import random
import base64
import urllib.request, urllib.parse, urllib.error
import hpfeeds
import fnmatch
import json
import OpenSSL.SSL
import ipaddress
from collections import OrderedDict
import logging
import socket
from xmljson import BadgerFish

name = "EWS Poster"
version = "v1.9.7a"


def init():
    global externalIP
    global internalIP
    global hpc
    externalIP=ECFG["ip"]
    internalIP=getOwnInternalIP()
    logging.basicConfig()
    hpc = False

def ewswebservice(ems):

    MODUL = "ewswebservice"

    headers = { 'User-Agent'     : name + " " + version,
                'Content-type'   : 'text/xml',
                'SOAPAction'     : '',
                'charset'        : 'UTF-8',
                'Connection'     : 'close'
              }

    host = random.choice([ ECFG["rhost_first"] , ECFG["rhost_second"] ])

    if ECFG["proxy"] != "NULL" and ECFG["proxy"] != "FALSE":
        proxydic = { "https" : ECFG["proxy"] }
    else:
        proxydic = {}

    try:
        if not "https" in proxydic:
            webservice = requests.post(host,
                                       data=ems,
                                       headers=headers,
                                       allow_redirects=True,
                                       timeout=60,
                                       verify= not ECFG["a.ignorecert"]
                                      )
        else:
            webservice = requests.post(host,
                                       data=ems,
                                       headers=headers,
                                       allow_redirects=True,
                                       proxies=proxydic,
                                       timeout=60,
                                       verify= not ECFG["a.ignorecert"]
                                      )


        webservice.raise_for_status()

        xmlresult = re.search('<StatusCode>(.*)</StatusCode>', webservice.text).groups()[0]

        if xmlresult != "OK":
            logme(MODUL,"XML Result != ok ( %s) (%s)" % (xmlresult,webservice.text) ,("LOG","VERBOSE"),ECFG)
            return False

        if ECFG["a.verbose"] is True:
            logme(MODUL,"---- Webservice Report ----" ,("VERBOSE"),ECFG)
            logme(MODUL,"HOST          : %s" % (host) ,("VERBOSE"),ECFG)
            logme(MODUL,"XML Result    : %s" % (xmlresult) ,("VERBOSE"),ECFG)
            logme(MODUL,"Statuscode    : %s" % (webservice.status_code) ,("VERBOSE"),ECFG)
            logme(MODUL,"Header        : %s" % (webservice.headers) ,("VERBOSE"),ECFG)
            logme(MODUL,"Body          : %s" % (webservice.text) ,("VERBOSE"),ECFG)
            logme(MODUL,"",("VERBOSE"),ECFG)

        return True

    except requests.exceptions.Timeout as e:
        logme(MODUL,"Timeout to remote host %s (%s)" % (host , str(e)) ,("LOG","VERBOSE"),ECFG)
        return False

    except requests.exceptions.ConnectionError as e:
        logme(MODUL,"Remote host %s didn't answer! (%s)" % (host , str(e)) ,("LOG","VERBOSE"),ECFG)
        return False

    except requests.exceptions.HTTPError as e:
        logme(MODUL,"HTTP Errorcode != 200 (%s)" % (str(e)) ,("LOG","VERBOSE"),ECFG)
        return False

    except OpenSSL.SSL.WantWriteError as e:
        logme(MODUL,"OpenSSL Write Buffer too small",("LOG","VERBOSE"),ECFG)
        return False


def viewcounter(MODUL,x,y):

    if y  == 100:
        x += 100
        # Inform every 100 send records
        logme(MODUL,str(x) +" log entries processed ...",("P2"),ECFG)
        y = 1
    else:
        y += 1

    return x,y


def sender():

    MODUL = "sender"

    def clean_dir(DIR,MODUL):
        FILEIN = filelist(DIR)

        for files in FILEIN:
            if not ".ews" in files:
                os.remove(DIR + os.sep + files)
                logme(MODUL, "Cleaning spooler dir: %s delete file: %s" % (DIR, files),("LOG"),ECFG)
        return()

    def check_job(DIR,MODUL):
        FILEIN = filelist(DIR)

        if len(FILEIN) < 1:
            logme(MODUL, "Sender : No Jobs to send in %s" % (DIR),("P1"),ECFG)
            return False
        else:
            logme(MODUL, "Sender : There are %s jobs to send in %s" %(str(len(FILEIN)),DIR),("P1"),ECFG)
            return True

    def send_job(DIR):
        FILEIN = filelist(DIR)

        for files in FILEIN:
            with open(DIR +  os.sep + files,'r') as alert:
                EWSALERT = alert.read()
                alert.close()

            if ewswebservice(EWSALERT) is True:
                os.remove(DIR + os.sep + files)
            else:
                fpart = files.split('.')

                if len(fpart) == 2:
                    newname = fpart[0] + ".1." + fpart[1]
                else:
                    newname = fpart[0] + "." + str(int(fpart[1]) + 1) + "." + fpart[2]

                os.rename(DIR + os.sep + files, DIR + os.sep + newname)
        return

    def del_job(DIR,MODUL):
        FILEIN = filelist(DIR)

        for files in FILEIN:
            fpart = files.split('.')
            if len(fpart) == 3 and int(fpart[1]) > 4:
                logme(MODUL, "Cleaning spooler dir: %s delete file: %s reached max transmit counter !" % (DIR, files),("LOG"),ECFG)
                os.remove(DIR + os.sep + files)

    def filelist(DIR):

        if os.path.isdir(DIR) is not True:
            logme(MODUL,"Error missing dir " + DIR + " Abort !",("P1","EXIT"),ECFG)
        else:
            return os.listdir(DIR)

    clean_dir(ECFG["spooldir"],MODUL)
    del_job(ECFG["spooldir"],MODUL)

    if check_job(ECFG["spooldir"],MODUL) is False:
        return

    send_job(ECFG["spooldir"])

    return


def buildews(esm,DATA,REQUEST,ADATA):

    ewsalert(esm,DATA,REQUEST,ADATA)

    if int(esm.xpath('count(//Alert)')) >= 100:
        sendews(esm)
        esm = ewsauth(ECFG["username"],ECFG["token"])

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
    with open(ECFG["spooldir"] + os.sep + timestamp() + ".ews",'wb') as f:
        f.write(EWSALERT)
        f.close()

    return True

def md5malware(malware_md5):
    #create file if its not present
    with open(ECFG["homedir"] + os.sep + "malware.md5", "a+") as malwarefile:
        # empty file
        if os.stat(ECFG["homedir"] + os.sep + "malware.md5").st_size == 0:
            malwarefile.write(malware_md5+"\n")
            malwarefile.close()
            return True

        if malware_md5 in open(ECFG["homedir"] + os.sep + "malware.md5", "r").read():
            malwarefile.close()
            return False
        else:
            malwarefile.write(malware_md5+"\n")
            malwarefile.close()
            return True


def malware(DIR,FILE,KILL, md5):
    if not os.path.isdir(DIR):
        return 1,DIR + " DOES NOT EXIST!"

    if md5 and not md5malware(md5):
        return 1, "Malware MD5 %s already submitted." % md5

    if os.path.isfile(DIR + os.sep + FILE) is True:
        if os.path.getsize(DIR + os.sep + FILE) <= 5 * 1024 * 1024:
            payload=open(DIR + os.sep + FILE, "rb").read()
            malwarefile = base64.b64encode(payload)
            if KILL is True:
                os.remove(DIR + os.sep + FILE)
            return 0, malwarefile
        else:
            return 1,"FILE " + DIR + os.sep + FILE + " is bigger than 5 MB!"
    else:
        return 1, "FILE " + DIR + os.sep + FILE + " DOES NOT EXIST!"


def hpfeedsend(esm, eformat):
    global hpc
    if not hpc:
        return False

    # remove auth header
    etree.strip_elements(esm, "Authentication")

    for i in range(0, len(esm)):
        if eformat == "xml":
            hpc.publish(ECFG["channels"], etree.tostring(esm[i], pretty_print=False))

        if eformat == "json":
            bf = BadgerFish(dict_type=OrderedDict)
            hpc.publish(ECFG["channels"], json.dumps(bf.data(esm[i])))

    # should be removed if no issues can be found. 03-13-19 av
    # emsg = hpc.wait()
    # if emsg:
    #     logme("hpfeedsend","HPFeeds Error (%s)" % format(emsg) ,("P1","VERBOSE"),ECFG)
    #     hpc=False
    #     return False

    return True

def testhpfeedsbroker():
    if ECFG["hpfeed"] is True:
        # workaround if hpfeeds broker is offline as otherwise hpfeeds lib will loop connection attempt
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ECFG["host"], int(ECFG["port"])))
        sock.close()

        if result != 0:
            # broker unavailable
            logme(MODUL, "HPFEEDS broker is configured to {0}:{1} but is currently unavailable. Disabling hpfeeds submission for this round!".format(ECFG["host"], ECFG["port"]), ("P1"), ECFG)
            return False

        try:
            if ECFG["tlscert"].lower() != "false":
                hpc = hpfeeds.new(ECFG["host"], int(ECFG["port"]), ECFG["ident"], ECFG["secret"], certfile=ECFG["tlscert"], reconnect=False)
                logme("hpfeedsend", "Connecting to %s via TLS" % format(hpc.brokername+"/"+ECFG["host"]+":"+str(ECFG["port"])), ("P3", "VERBOSE"), ECFG)
            else:
                hpc = hpfeeds.new(ECFG["host"], int(ECFG["port"]), ECFG["ident"], ECFG["secret"], reconnect=False)
                logme("hpfeedsend", "Connecting to %s" % format(hpc.brokername+"/"+ECFG["host"]+":"+str(ECFG["port"])), ("P3", "VERBOSE"), ECFG)

            return hpc
        except hpfeeds.FeedException as e:
            logme("hpfeedsend", "HPFeeds Error (%s)" % format(e), ("P1", "VERBOSE"), ECFG)
            return False
    return False


def buildjson(jesm,DATA,REQUEST,ADATA):

    if DATA["sport"] == "":
        DATA["sport"] = "0"

    if 'raw' in REQUEST and REQUEST['raw'] != "":
        REQUEST['raw'] = REQUEST['raw']

    myjson = {}
    myjson['timestamp'] = ("%sT%s.000000" % (DATA["timestamp"][0:10],DATA["timestamp"][11:19]))
    myjson['event_type'] = "alert"
    myjson['src_ip'] = DATA["sadr"]
    myjson['src_port'] = DATA['sport']
    myjson['dest_ip'] = DATA['tadr']
    myjson['dest_port'] = DATA['tport']

    if REQUEST:
        myjson["request"] = REQUEST

    if ADATA:
        myjson["additionaldata"] = ADATA

    return jesm + json.dumps(myjson)+"\n"

def writejson(jesm):
    if len(jesm) > 0 and ECFG["json"] is True:
        with open(ECFG["jsondir"],'a+') as f:
            f.write(jesm)
            f.close()


def verbosemode(MODUL,DATA,REQUEST,ADATA):
    logme(MODUL,"---- " + MODUL + " ----" ,("VERBOSE"),ECFG)
    logme(MODUL,"Nodeid          : %s" % DATA["aid"],("VERBOSE"),ECFG)
    logme(MODUL,"Timestamp       : %s" % DATA["timestamp"],("VERBOSE"),ECFG)
    logme(MODUL,"" ,("VERBOSE"),ECFG)
    logme(MODUL,"Source IP       : %s" % DATA["sadr"],("VERBOSE"),ECFG)
    logme(MODUL,"Source IPv      : %s" % DATA["sipv"],("VERBOSE"),ECFG)
    logme(MODUL,"Source Port     : %s" % DATA["sport"],("VERBOSE"),ECFG)
    logme(MODUL,"Source Protocol : %s" % DATA["sprot"],("VERBOSE"),ECFG)
    logme(MODUL,"Target IP       : %s" % DATA["tadr"],("VERBOSE"),ECFG)
    logme(MODUL,"Target IPv      : %s" % DATA["tipv"],("VERBOSE"),ECFG)
    logme(MODUL,"Target Port     : %s" % DATA["tport"],("VERBOSE"),ECFG)
    logme(MODUL,"Target Protocol : %s" % DATA["tprot"],("VERBOSE"),ECFG)

    for key,value in list(ADATA.items()):
        logme(MODUL,"%s       : %s" %(key,value) ,("VERBOSE"),ECFG)

    logme(MODUL,"" ,("VERBOSE"),ECFG)

    return

def glastopfv3():

    MODUL  = "GLASTOPFV3"
    logme(MODUL,"Starting Glastopf V3.x Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("glastopfv3","nodeid","sqlitedb","malwaredir")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    HONEYPOT["ip"] = externalIP

    # Malwaredir exist ? Issue in Glastopf ! RFI Directory first create when the first RFI was downloaded

    #if os.path.isdir(HONEYPOT["malwaredir"]) == False:
    #    logme(MODUL,"[ERROR] Missing Malware Dir " + HONEYPOT["malwaredir"] + ". Abort !",("P3","LOG"),ECFG)
    #    return

    # is sqlitedb exist ?

    if os.path.isfile(HONEYPOT["sqlitedb"]) is False:
        logme(MODUL,"[INFO] Missing sqlitedb file " + HONEYPOT["sqlitedb"] + ". Skipping !",("P3","LOG"),ECFG)
        return

    # open database

    con = sqlite3.connect(HONEYPOT["sqlitedb"],30)
    con.row_factory = sqlite3.Row
    c = con.cursor()

    # calculate send limit

    try:
        c.execute("SELECT max(id) from events")
    except:
        logme(MODUL,"[INFO] Sqlitedb %s is corrupt or does not contain events. Skipping ! " % HONEYPOT["sqlitedb"] ,("P3","LOG"),ECFG)
        return

    maxid = c.fetchone()["max(id)"]

    if maxid is None:
        logme(MODUL,"[INFO] No entry's in Glastopf Database. Skip !",("P2","LOG"),ECFG)
        return

    imin, imax = calcminmax(MODUL,int(countme(MODUL,'sqliteid',-1,ECFG)),int(maxid),ECFG)

    # read alerts from database

    c.execute("SELECT * from events where id > ? and id <= ?;",(imin,imax))
    rows = c.fetchall()

    # counter inits

    x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    for row in rows:

        x,y = viewcounter(MODUL,x,y)

        # filter empty requests and nagios checks

        if  row["request_url"] == os.sep or row["request_url"] == "/index.do?hash=DEADBEEF&activate=1":
            countme(MODUL,'sqliteid',row["id"],ECFG)
            continue

        # Prepair and collect Alert Data

        DATA = {
                    "aid"       : HONEYPOT["nodeid"],
                    "timestamp" : row["time"],
                    "sadr"      : re.sub(":.*$","",row["source"]),
                    "sipv"      : "ipv" + ip4or6(re.sub(":.*$","",row["source"])),
                    "sprot"     : "tcp",
                    "sport"     : "",
                    "tipv"      : "ipv" + ip4or6(HONEYPOT["ip"]),
                    "tadr"      : HONEYPOT["ip"],
                    "tprot"     : "tcp",
                    "tport"     : "80",
                  }

        REQUEST = {
                    "description" : "WebHoneypot : Glastopf v3.1",
                    "url"         : urllib.parse.quote(row["request_url"].encode('ascii', 'ignore'))
                  }

        ADATA = {
                    "sqliteid"    : row ["id"],
                    "hostname": ECFG["hostname"],
                    "externalIP": externalIP,
                    "internalIP": internalIP

                }

        if "request_raw" in  list(row.keys()) and len(row["request_raw"]) > 0:
            #REQUEST["raw"] = base64.b64encode(row["request_raw"].encode('ascii')).decode()
             REQUEST["raw"] = base64.encodebytes(row["request_raw"].encode('ascii', 'ignore')).decode()

        if "filename" in  list(row.keys()) and row["filename"] != None and ECFG["send_malware"] == True:
            error,malwarefile = malware(HONEYPOT["malwaredir"],row["filename"],ECFG["del_malware_after_send"], False)
            if error == 0:
                REQUEST["binary"] = malwarefile.decode('utf-8')
            else:
                logme(MODUL,"Mission Malwarefile %s" % row["filename"] ,("P1","LOG"),ECFG)

        # Collect additional Data



        if "request_method" in  list(row.keys()):
            ADATA["httpmethod"] = row["request_method"]

        if "request_raw" in  list(row.keys()):
            m = re.search( r'Host: (\b.+\b)', row["request_raw"] , re.M)
            if m:
                ADATA["host"] = str(m.group(1))

        if "request_header" in  list(row.keys()):
            if 'Host' in json.loads(row["request_header"]):
                ADATA["host"] = str(json.loads(row["request_header"])["Host"])

        if "request_body" in  list(row.keys()):
            if len(row["request_body"]) > 0:
                ADATA["requestbody"] = row["request_body"]

        esm = buildews(esm,DATA,REQUEST,ADATA)
        if "request_body" in  list(row.keys()):
            if len(row["request_body"]) > 0:
                ADATA["requestbody"] = row["request_body"]

        esm = buildews(esm,DATA,REQUEST,ADATA)
        jesm = buildjson(jesm,DATA,REQUEST,ADATA)

        countme(MODUL,'sqliteid',row["id"],ECFG)
        countme(MODUL,'daycounter', -2,ECFG)

        if ECFG["a.verbose"] is True:
            verbosemode(MODUL,DATA,REQUEST,ADATA)

    con.close()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-1),("P2"),ECFG)
    return

def glastopfv2():

    MODUL  = "GLASTOPFV2"
    logme(MODUL,"Starting Glastopf V2 Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("glastopfv2","nodeid","mysqlhost","mysqldb","mysqluser","mysqlpw","malwaredir")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    HONEYPOT["ip"] = readonecfg(MODUL,"ip", ECFG["cfgfile"])

    if HONEYPOT["ip"].lower() == "false" or HONEYPOT["ip"].lower() == "null":
        HONEYPOT["ip"] = ECFG["ip"]

    # open database

    try:
        con = MySQLdb.connect(host=HONEYPOT["mysqlhost"], user=HONEYPOT["mysqluser"], passwd=HONEYPOT["mysqlpw"],
                              db=HONEYPOT["mysqldb"], cursorclass=MySQLdb.cursors.DictCursor)
    except MySQLdb.Error as e:
        logme(MODUL,"[ERROR] %s" %(str(e)),("P3","LOG"),ECFG)
        return 

    c = con.cursor()

    # calculate send limit

    c.execute("SELECT max(id) from log")

    maxid = c.fetchone()["max(id)"]

    if maxid is None:
        logme(MODUL,"[INFO] No entry's in Glastopf Database. Skip!",("P2","LOG"),ECFG)
        return

    imin, imax = calcminmax(MODUL,int(countme(MODUL,'sqliteid',-1,ECFG)),int(maxid),ECFG)

    # read alerts from database

    c.execute("SELECT * from log where id > %s and id <= %s;",(imin,imax))
    rows = c.fetchall()

    # counter inits

    x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    for row in rows:

        x,y = viewcounter(MODUL,x,y)

        # filter nagios checks

        if row["req"] == "/index.do?hash=DEADBEEF&activate=1":
            countme(MODUL,'mysqlid',row["id"],ECFG)
            continue

        # Prepair and collect Alert Data

        DATA = {
                 "aid"       : HONEYPOT["nodeid"],
                 "timestamp" : str(row["attime"]),
                 "sadr"      : row["ip"],
                 "sipv"      : "ipv" + ip4or6(row["ip"]),
                 "sprot"     : "tcp",
                 "sport"     : "",
                 "tipv"      : "ipv" + ip4or6(HONEYPOT["ip"]),
                 "tadr"      : HONEYPOT["ip"],
                 "tprot"     : "tcp",
                 "tport"     : "80",
                }

        REQUEST = {
                    "description"  : "Webhoneypot : Glastopf v2.x",
                    "url"          : urllib.parse.quote(row["req"])
                  }
        # Collect additional Data

        ADATA = {
            "mysqlid": str(row["id"]),
            "host": row["host"],
            "hostname": ECFG["hostname"],
            "externalIP": externalIP,
            "internalIP": internalIP
        }

        if row["victim"] != "None":
            ADATA["victim"] = row["victim"]

        if row["filename"] != None and ECFG["send_malware"] == True:
            error,malwarefile = malware(HONEYPOT["malwaredir"],row["filename"],ECFG["del_malware_after_send"], False)
            if error == 0:
                REQUEST["binary"] = malwarefile.decode('utf-8')
            else:
                logme(MODUL,"Mission Malwarefile %s" % row["filename"] ,("P1","LOG"),ECFG)

        # Collect additional Data

        ADATA = {
                 "mysqlid"   : str(row ["id"]),
                 "host"      : row["host"],
                 "hostname": ECFG["hostname"],
                 "externalIP": externalIP,
                 "internalIP": internalIP
        }

        if row["victim"] != "None":
            ADATA["victim"] = row["victim"]

        # Rest

        esm = buildews(esm,DATA,REQUEST, ADATA)
        jesm = buildjson(jesm,DATA,REQUEST,ADATA)

        countme(MODUL,'mysqlid',row["id"],ECFG)
        countme(MODUL,'daycounter', -2,ECFG)

        if ECFG["a.verbose"] is True:
            verbosemode(MODUL,DATA,REQUEST,ADATA)


    con.close()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-1),("P2"),ECFG)
    return

def kippo():

    MODUL  = "KIPPO"
    logme(MODUL,"Starting Kippo Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("kippo","nodeid","mysqlhost","mysqldb","mysqluser","mysqlpw")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    HONEYPOT["ip"] = readonecfg(MODUL,"ip", ECFG["cfgfile"])

    if HONEYPOT["ip"].lower() == "false" or HONEYPOT["ip"].lower() == "null":
        HONEYPOT["ip"] = ECFG["ip"]

    # open database

    try:
        con = MySQLdb.connect(host=HONEYPOT["mysqlhost"], user=HONEYPOT["mysqluser"], passwd=HONEYPOT["mysqlpw"],
                              db=HONEYPOT["mysqldb"], cursorclass=MySQLdb.cursors.DictCursor)

    except MySQLdb.Error as e:
        logme(MODUL,"[ERROR] %s" %(str(e)),("P3","LOG"),ECFG)

    c = con.cursor()

    # calculate send limit

    c.execute("SELECT max(id) from auth")

    maxid = c.fetchone()["max(id)"]

    if maxid is None:
        logme(MODUL,"[INFO] No entry's in Kippo Database. Skip!",("P2","LOG"),ECFG)
        return

    imin, imax = calcminmax(MODUL,int(countme(MODUL,'sqliteid',-1,ECFG)),int(maxid),ECFG)

    # read alerts from database

    c.execute("SELECT auth.id, auth.username, auth.password, auth.success, auth.timestamp, auth.session, sessions.starttime, sessions.endtime, sessions.ip, sensors.ip as kippoip, clients.version from auth, sessions, sensors, clients WHERE (sessions.id=auth.session) AND (sessions.sensor = sensors.id) AND (sessions.client = clients.id) AND auth.id > %s and auth.id <= %s ORDER BY auth.id;" % (imin,imax))

    rows = c.fetchall()

    # counter inits

    x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    for row in rows:

        x,y = viewcounter(MODUL,x,y)

        # Prepair and collect Alert Data

        DATA =    {
                    "aid"       : HONEYPOT["nodeid"],
                    "timestamp" : str(row["timestamp"]),
                    "sadr"      : str(row["ip"]),
                    "sipv"      : "ipv" + ip4or6(str(row["ip"])),
                    "sprot"     : "tcp",
                    "sport"     : "",
                    "tipv"      : "ipv" + ip4or6(HONEYPOT["ip"]),
                    "tadr"      : HONEYPOT["ip"],
                    "tprot"     : "tcp",
                    "tport"     : "22",
                  }

        REQUEST = {
                    "description" : "SSH Honeypot Kippo",
                  }

        # Collect additional Data

        if str(row["success"]) == "0":
            login = "Fail"
        else:
            login = "Success"

        ADATA = {
                    "sqliteid"    : str(row["id"]),
                    "starttime"   : str(row["starttime"]),
                    "endtime"     : str(row["endtime"]),
                    "version"     : str(row["version"]),
                    "login"       : login,
                    "username"    : str(row["username"]),
                    "password"    : str(row["password"]),
                    "hostname": ECFG["hostname"],
                    "externalIP": externalIP,
                    "internalIP": internalIP
                }

        esm = buildews(esm,DATA,REQUEST,ADATA)
        jesm = buildjson(jesm,DATA,REQUEST,ADATA)

        countme(MODUL,'mysqlid',row["id"],ECFG)
        countme(MODUL,'daycounter', -2,ECFG)

        if ECFG["a.verbose"] is True:
            verbosemode(MODUL,DATA,REQUEST,ADATA)

    con.close()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-1),("P2"),ECFG)
    return

def cowrie():

    MODUL  = "COWRIE"
    logme(MODUL,"Starting Cowrie Modul.",("P1"),ECFG)

    # session related variables
    lastSubmittedLine, firstOpenedWithoutClose = 0, 0

    # collect honeypot config dic

    ITEMS  = ("cowrie","nodeid","logfile")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    HONEYPOT["ip"] = readonecfg(MODUL,"ip", ECFG["cfgfile"])

    if HONEYPOT["ip"].lower() == "false" or HONEYPOT["ip"].lower() == "null":
        HONEYPOT["ip"] = ECFG["ip"]

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL,"[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !",("P3","LOG"),ECFG)

    # count limit

    imin = int(countme(MODUL,'firstopenedwithoutclose',-1,ECFG))
    if imin>0:
        imin=imin-1
    firstOpenedWithoutClose = imin
    lastSubmittedLine=int(countme(MODUL,'lastsubmittedline',-1,ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL,"Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)

    I = 0 ; x = 0 ; y = 1; J = 0

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    # dict to gather session information
    cowriesessions=OrderedDict()
    sessionstosend=[]
    while True:
        if int(ECFG["sendlimit"]) > 0 and J >= int(ECFG["sendlimit"]):
            break
        I += 1

        line = getline(HONEYPOT["logfile"],(imin +I)).rstrip()
        currentline=imin + I

        if len(line) == 0:
            break
        else:
            # parse json
            try:
                content = json.loads(line)
            except ValueError:
                logme(MODUL,"Invalid json entry found in line "+str(currentline)+", skipping entry.",("P3"),ECFG)
                pass # invalid json
            else:
                # if new session is started, store session-related info
                if (content['eventid'] == "cowrie.session.connect"):
                    # create empty session content: structure will be the same as kippo, add dst port and commands
                    # | id  | username | password | success | logintimestamp | session | sessionstarttime| sessionendtime | ip | cowrieip | version| src_port|dst_port|dst_ip|commands | successful login
                    cowriesessions[content["session"]]=[currentline,'','','','',content["session"],content["timestamp"],'',content["src_ip"],content["sensor"],'',content["src_port"],content["dst_port"],content["dst_ip"],"", False]
                    firstOpenedWithoutClose = list(cowriesessions.values())[0][0]

                # store correponding ssh client version
                if (content['eventid'] == "cowrie.client.version"):
                    if content["session"] in cowriesessions:
                        cowriesessions[content["session"]][10]=content["version"]
                
                # create successful login 
                if (content['eventid'] == "cowrie.login.success"):
                    if content["session"] in cowriesessions:
                        cowriesessions[content["session"]][3]="Success"
                        cowriesessions[content["session"]][1]=content["username"]
                        cowriesessions[content["session"]][2]=content["password"]
                        cowriesessions[content["session"]][4]=content["timestamp"]
                        cowriesessions[content["session"]][15]=True

                # create failed login
                if (content['eventid'] == "cowrie.login.failed"):
                    if content["session"] in cowriesessions:
                        cowriesessions[content["session"]][3]="Fail"
                        cowriesessions[content["session"]][1]=content["username"]
                        cowriesessions[content["session"]][2]=content["password"]
                        cowriesessions[content["session"]][4]=content["timestamp"]
                        if currentline > lastSubmittedLine:
                            sessionstosend.append(deepcopy(cowriesessions[content["session"]]))
                            lastSubmittedLine = currentline
                            J+=1

                # store terminal input / commands
                if (content['eventid'] == "cowrie.command.input"):
                    if content["session"] in cowriesessions:
                        cowriesessions[content["session"]][14]=cowriesessions[content["session"]][14] + "\n" +content["input"]
                        cowriesessions[content["session"]][15]=True

                # store session close
                if (content['eventid'] == "cowrie.session.closed"):
                    if content["session"] in cowriesessions:
                        if (cowriesessions[content["session"]][5]==content["session"]):
                            cowriesessions[content["session"]][7]=content["timestamp"]
                            if currentline > lastSubmittedLine:
                                if cowriesessions[content["session"]][15]==True:
                                    sessionstosend.append(deepcopy(cowriesessions[content["session"]]))
                                    lastSubmittedLine = currentline
                                    J+= 1
                                cowriesessions.pop(content["session"])
                                if len(cowriesessions) == 0:
                                    firstOpenedWithoutClose = currentline

    # loop through list of sessions to send
    for key in sessionstosend:

        x,y = viewcounter(MODUL,x,y)

        # map ssh ports for t-pot
        if key[12]==2223:
            service="Telnet"
            serviceport="23"
        elif key[12]==2222:
            service="SSH"
            serviceport="22"
        elif key[12]==23:
            service="Telnet"
            serviceport="23"
        else:
            service="SSH"
            serviceport="22"

        DATA =    {
            "aid"       : HONEYPOT["nodeid"],
            "timestamp" : "%s-%s-%s %s" % (key[4][0:4], key[4][5:7], key[4][8:10], key[4][11:19]),
            "sadr"      : str(key[8]),
            "sipv"      : "ipv" + ip4or6(str(key[8])),
            "sprot"     : "tcp",
            "sport"     : str(key[11]),
            "tipv"      : "ipv" + ip4or6(HONEYPOT["ip"]),
            "tadr"      : str(key[13]),
            "tprot"     : "tcp",
            "tport"     : serviceport
            }

        REQUEST = {
                    "description" : service + " Honeypot Cowrie",
                  }

        # Collect additional Data
        login = str(key[3])
        if (key[7] !=""):
            endtime = "%s-%s-%s %s" % (key[7][0:4], key[7][5:7], key[7][8:10], key[7][11:19])
        else: 
            endtime = ""

        # fix unicode in json log
        cusername, cpassword, cinput="","",""
        try:
            cusername=str(key[1])
        except UnicodeEncodeError:
            logme(MODUL, "Unicode in username  "+ key[1]+ " - removing unicode.", ("P3"), ECFG)
            cusername=key[1].encode('ascii', 'ignore')

        try:
            cpassword = str(key[2])
        except UnicodeEncodeError:
            logme(MODUL, "Unicode in password " + key[2] + " - removing unicode.", ("P3"), ECFG)
            cpassword = key[2].encode('ascii', 'ignore')

        try:
            cinput = str(key[14])
        except UnicodeEncodeError:
            logme(MODUL, "Unicode in input " + key[14] + " - removing unicode.", ("P3"), ECFG)
            cinput=str(key[14]).encode('ascii', 'ignore')


        ADATA = {
                 "sessionid"   : str(key[5]),
                 "starttime"   : "%s-%s-%s %s" % (key[6][0:4], key[6][5:7], key[6][8:10], key[6][11:19]),
                 "endtime"     : endtime,
                 "version"     : str(key[10]),
                 "login"       : login,
                 "username"    : cusername,
                 "password"    : cpassword,
                 "input"       : cinput,
                 "hostname": ECFG["hostname"],
                 "externalIP": externalIP,
                 "internalIP": internalIP
                }

        # generate template and send

        esm = buildews(esm,DATA,REQUEST,ADATA)
        jesm = buildjson(jesm,DATA,REQUEST,ADATA)

        countme(MODUL,'daycounter', -2,ECFG)

        countme(MODUL,'firstopenedwithoutclose', firstOpenedWithoutClose,ECFG)
        countme(MODUL,'lastsubmittedline', lastSubmittedLine,ECFG)

        if ECFG["a.verbose"] is True:
            verbosemode(MODUL,DATA,REQUEST,ADATA)


    # Cleaning linecache
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-1),("P2"),ECFG)
    return

def dionaea():
    MODUL  = "DIONAEA"
    logme(MODUL,"Starting Dionaea Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("dionaea","nodeid","sqlitedb","malwaredir")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # Malwaredir exist ?

    if os.path.isdir(HONEYPOT["malwaredir"]) is False:
        logme(MODUL,"[ERROR] Missing Malware Dir " + HONEYPOT["malwaredir"] + ". Abort !",("P3","LOG"),ECFG)

     # is sqlitedb exist ?

    if os.path.isfile(HONEYPOT["sqlitedb"]) is False:
        logme(MODUL,"[ERROR] Missing sqlitedb file " + HONEYPOT["sqlitedb"] + ". Abort !",("P3","LOG"),ECFG)
        return

    # open database

    con = sqlite3.connect(HONEYPOT["sqlitedb"],30)
    con.row_factory = sqlite3.Row
    c = con.cursor()

    # calculate send limit

    try:
        c.execute("SELECT max(connection) from connections;")
    except:
        logme(MODUL, "[INFO] Sqlitedb %s is corrupt or does not contain events. Skipping ! " % HONEYPOT["sqlitedb"],
              ("P3", "LOG"), ECFG)
        return

    maxid = c.fetchone()["max(connection)"]

    if maxid is None:
        logme(MODUL,"[INFO] No entry's in Dionaea Database. Skip !",("P2","LOG"),ECFG)
        return

    imin, imax = calcminmax(MODUL,int(countme(MODUL,'sqliteid',-1,ECFG)),int(maxid),ECFG)

    # read alerts from database

    c.execute("SELECT * from connections where connection > ? and connection <= ?;",(imin,imax,))
    rows = c.fetchall()

    # counter inits

    x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    for row in rows:

        x,y = viewcounter(MODUL,x,y)

        # filter empty remote_host

        if row["remote_host"] == "":
            countme(MODUL,'sqliteid',row["connection"],ECFG)
            continue

        # fix docker problems with dionaea IPs
        if '::ffff:' in row["remote_host"]:
            remoteHost= row["remote_host"].split('::ffff:')[1]
        else:
            remoteHost = row["remote_host"]

        if '::ffff:' in row["local_host"]:
            localHost = row["local_host"].split('::ffff:')[1]
        else:
            localHost = row["local_host"]

        # prepare and collect Alert Data

        DATA =   {
                    "aid"       : HONEYPOT["nodeid"],
                    "timestamp" : datetime.utcfromtimestamp(int(row["connection_timestamp"])).strftime('%Y-%m-%d %H:%M:%S'),
                    "sadr"      : str(remoteHost),
                    "sipv"      : "ipv" + ip4or6(str(remoteHost)),
                    "sprot"     : str(row["connection_transport"]),
                    "sport"     : str(row["remote_port"]),
                    "tipv"      : "ipv" + ip4or6(str(localHost)),
                    "tadr"      : str(localHost),
                    "tprot"     : str(row["connection_transport"]),
                    "tport"     : str(row["local_port"]),
                  }

        REQUEST = {
                    "description" : "Network Honeyport Dionaea v0.1.0",
                  }

        # Collect additional Data

        ADATA = {
                 "sqliteid"    : str(row["connection"]),
                 "hostname": ECFG["hostname"],
                 "externalIP": externalIP,
                 "internalIP": internalIP

        }

        # Check for malware bin's

        c.execute("SELECT download_md5_hash from downloads where connection = ?;",(str(row["connection"]),))
        check = c.fetchone()
        if check is not None and ECFG["send_malware"] == True:
            error,malwarefile = malware(HONEYPOT["malwaredir"],check[0],ECFG["del_malware_after_send"],check[0])
            if error == 0:
                REQUEST["binary"] = malwarefile.decode('utf-8')
            else:
                logme(MODUL, "Malwarefile: %s" % malwarefile, ("P1", "LOG"), ECFG)
            if check[0]:
                ADATA["payload_md5"] = check[0]



        # generate template and send

        esm = buildews(esm,DATA,REQUEST,ADATA)
        jesm = buildjson(jesm,DATA,REQUEST,ADATA)

        countme(MODUL,'sqliteid',row["connection"],ECFG)
        countme(MODUL,'daycounter', -2,ECFG)

        if ECFG["a.verbose"] is True:
            verbosemode(MODUL,DATA,REQUEST,ADATA)

    con.close()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-1),("P2"),ECFG)
    return

def honeytrap():

    MODUL  = "HONEYTRAP"
    logme(MODUL,"Starting Honeytrap Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("honeytrap","nodeid","attackerfile","payloaddir","newversion")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # Attacking file exists ?

    if os.path.isfile(HONEYPOT["attackerfile"]) is False:
        logme(MODUL,"[ERROR] Missing Attacker File " + HONEYPOT["attackerfile"] + ". Abort !",("P3","LOG"),ECFG)

    # Payloaddir exist ?

    if os.path.isdir(HONEYPOT["payloaddir"]) is False:
        logme(MODUL,"[ERROR] Missing Payload Dir " + HONEYPOT["payloaddir"] + ". Abort !",("P3","LOG"),ECFG)

    # New Version are use ?

    if HONEYPOT["newversion"].lower() == "true" and not os.path.isdir(HONEYPOT["payloaddir"]):
        logme(MODUL,"[ERROR] Missing Payload Directory " + HONEYPOT["payloaddir"] + ". Abort !",("P3","LOG"),ECFG)

    # Calc MD5sum for Payloadfiles

    if HONEYPOT["newversion"].lower() == "true":
        logme(MODUL,"Calculate MD5sum for Payload Files",("P2"),ECFG)

        for i in os.listdir(HONEYPOT["payloaddir"]):
            if not "_md5_" in i:
                filein = HONEYPOT["payloaddir"] + os.sep + i
                os.rename(filein,filein + "_md5_" +  hashlib.md5(open(filein, 'rb').read()).hexdigest())

    # count limit
    imin = int(countme(MODUL,'fileline',-1,ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL,"Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)

    I = 0 ; x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    while True:

        x,y = viewcounter(MODUL,x,y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["attackerfile"],(imin + I)).rstrip()

        if len(line) == 0:
            break
        else:
            line = re.sub(r'  ',r' ',re.sub(r'[\[\]\-\>]',r'',line))

            if HONEYPOT["newversion"].lower() == "false":
                date , time , _ , source, dest, _ = line.split(" ",5)
                protocol = "" ; md5 = ""
            else:
                date , time , _ , protocol, source, dest, md5, _ = line.split(" ",7)

            #  Prepair and collect Alert Data

            DATA =    {
                        "aid"       : HONEYPOT["nodeid"],
                        "timestamp" : "%s-%s-%s %s" % (date[0:4], date[4:6], date[6:8], time[0:8]),
                        "sadr"      : re.sub(":.*$","",source),
                        "sipv"      : "ipv" + ip4or6(re.sub(":.*$","",source)),
                        "sprot"     : protocol,
                        "sport"     : re.sub("^.*:","",source),
                        "tipv"      : "ipv" + ip4or6(re.sub(":.*$","",dest)),
                        "tadr"      : re.sub(":.*$","",dest),
                        "tprot"     : protocol,
                        "tport"     : re.sub("^.*:","",dest),
                      }


            REQUEST = {
                        "description" : "NetworkHoneypot Honeytrap v1.1"
                      }

            # Collect additional Data

            ADATA = {
                "hostname": ECFG["hostname"],
                "externalIP": externalIP,
                "internalIP": internalIP
            }

            # Search for Payload
            if HONEYPOT["newversion"].lower() == "true" and ECFG["send_malware"] == True:
                sfile = "from_port_%s-%s_*_%s-%s-%s_md5_%s" % (re.sub("^.*:","",dest),protocol,date[0:4], date[4:6], date[6:8],md5)
                for mfile in os.listdir(HONEYPOT["payloaddir"]):
                    if fnmatch.fnmatch(mfile, sfile):
                        error , payloadfile = malware(HONEYPOT["payloaddir"],mfile,False, md5)
                        if error == 0:
                            REQUEST["binary"] = payloadfile.decode('utf-8')
                        else:
                            logme(MODUL,"Malwarefile : %s" % payloadfile ,("P1","LOG"),ECFG)
                        if md5:
                            ADATA["payload_md5"] = md5

            # generate template and send

            esm = buildews(esm,DATA,REQUEST,ADATA)
            jesm = buildjson(jesm,DATA,REQUEST,ADATA)

            countme(MODUL,'fileline',-2,ECFG)
            countme(MODUL,'daycounter', -2,ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL,DATA,REQUEST,ADATA)

    # Cleaning linecache
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-2),("P2"),ECFG)
    return

def rdpdetect():

    MODUL  = "RDPDETECT"
    logme(MODUL,"Starting RDPDetect Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("rdpdetect","nodeid","iptableslog","targetip")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # iptables file exists ?

    if os.path.isfile(HONEYPOT["iptableslog"]) is False:
        logme(MODUL,"[ERROR] Missing Iptables LogFile " + HONEYPOT["iptableslog"] + ". Abort !",("P3","LOG"),ECFG)

    # count limit

    imin = int(countme(MODUL,'fileline',-1,ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL,"Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)

    I = 0 ; x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    while True:

        x,y = viewcounter(MODUL,x,y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["iptableslog"],(imin + I)).rstrip()

        if len(line) == 0:
            break
        else:
            line = re.sub(r'  ',r' ',re.sub(r'[\[\]\-\>]',r'',line))

            if HONEYPOT["targetip"] == re.search('SRC=(.*?) ', line).groups()[0]:
                continue

            # Prepair and collect Alert Data

            DATA =    {
                        "aid"       : HONEYPOT["nodeid"],
                        "timestamp" : "%s-%s-%s %s:%s:%s" % (line[0:4], line[4:6], line[6:8], line[9:11], line[12:14], line[15:17]),
                        "sadr"      : re.search('SRC=(.*?) ', line).groups()[0],
                        "sipv"      : "ipv" + ip4or6(re.search('SRC=(.*?) ', line).groups()[0]),
                        "sprot"     : re.search('PROTO=(.*?) ', line).groups()[0].lower(),
                        "sport"     : re.search('SPT=(.*?) ', line).groups()[0],
                        "tipv"      : "ipv" + ip4or6(ECFG["ip"]),
                        "tadr"      : ECFG["ip"],
                        "tprot"     : re.search('PROTO=(.*?) ', line).groups()[0].lower(),
                        "tport"     : re.search('DPT=(.*?) ', line).groups()[0],
                      }

            REQUEST = {
                        "description" : "RDPDetect"
                      }


            # Collect additional Data

            ADATA =   {
                "hostname": ECFG["hostname"],
                "externalIP": externalIP,
                "internalIP": internalIP
            }

            # generate template and send

            esm = buildews(esm,DATA,REQUEST,ADATA)
            jesm = buildjson(jesm,DATA,REQUEST,ADATA)

            countme(MODUL,'fileline',-2,ECFG)
            countme(MODUL,'daycounter', -2,ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL,DATA,REQUEST,ADATA)

    # Cleaning linecache
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-2),("P2"),ECFG)
    return

def emobility():

    MODUL  = "EMOBILITY"
    logme(MODUL,"Starting eMobility Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("eMobility","nodeid","logfile")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL,"[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !",("P3","LOG"),ECFG)

    # count limit

    imin = int(countme(MODUL,'fileline',-1,ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL,"Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)

    I = 0 ; x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    while True:

        x,y = viewcounter(MODUL,x,y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["logfile"],(imin + I)).rstrip()

        if len(line) == 0:
            break
        else:
            # Prepair and collect Alert Data

            line = re.sub(r'  ',r' ',re.sub(r'[\[\]\-\>]',r'',line))

            srcipandport, dstipandport, url, dateandtime =  line.split("|",3)

            DATA =    {
                        "aid"       : HONEYPOT["nodeid"],
                        "timestamp" : "%s-%s-%s %s" % (dateandtime[0:4], dateandtime[4:6], dateandtime[6:8], dateandtime[9:17]),
                        "sadr"      : "%s.%s.%s.%s" % (srcipandport.split(".")[0], srcipandport.split(".")[1], srcipandport.split(".")[2], srcipandport.split(".")[3]),
                        "sipv"      : "ipv4",
                        "sprot"     : "tcp",
                        "sport"     : srcipandport.split(".")[4],
                        "tipv"      : "ipv4",
                        "tadr"      : "%s.%s.%s.%s" % (dstipandport.split(".")[0], dstipandport.split(".")[1], dstipandport.split(".")[2], dstipandport.split(".")[3]),
                        "tprot"     : "tcp",
                        "tport"     : dstipandport.split(".")[4],
                      }

            REQUEST = {
                        "description" : "eMobility Honeypot",
                        "url"         : urllib.parse.quote(url.encode('ascii', 'ignore'))
                      }


            # Collect additional Data

            ADATA =   {
                "hostname": ECFG["hostname"],
                "externalIP": externalIP,
                "internalIP": internalIP
                      }

            # generate template and send

            esm = buildews(esm,DATA,REQUEST,ADATA)
            jesm = buildjson(jesm,DATA,REQUEST,ADATA)

            countme(MODUL,'fileline',-2,ECFG)
            countme(MODUL,'daycounter', -2,ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL,DATA,REQUEST,ADATA)

    # Cleaning linecache
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-2),("P2"),ECFG)
    return

def conpot():
    MODUL  = "CONPOT"
    logme(MODUL,"Starting Conpot Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("conpot","nodeid","logfile")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # if multiple logfiles:
    conpotlog=glob.glob(HONEYPOT["logfile"])
    if len(conpotlog) < 1:
        logme(MODUL, "[ERROR] Missing of incorrect LogFile for conpot. Skip !", ("P3", "LOG"), ECFG)

    index=0
    orgModul = MODUL

    for logfile in conpotlog:
        index+=1
        if len(conpotlog) > 1:
            MODUL=orgModul + "-" + str(index)

        # logfile file exists ? should not be triggered when using glob.glob.
        if os.path.isfile(logfile) is False:
            logme(MODUL,"[ERROR] Missing LogFile " + logfile + ". Skip !",("P3","LOG"),ECFG)

        # count limit
        imin = int(countme(MODUL,'fileline',-1,ECFG))

        if int(ECFG["sendlimit"]) > 0:
            logme(MODUL,"Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)

        I = 0 ; x = 0 ; y = 1 ; J = 0

        esm = ewsauth(ECFG["username"],ECFG["token"])
        jesm = ""

        while True:

            x,y = viewcounter(MODUL,x,y)

            I += 1

            if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
                break

            line = getline(logfile,(imin + I)).rstrip()
            currentline=imin+I

            if len(line) == 0:
                break
            else:
                # parse json
                try:
                    content = json.loads(line)
                except ValueError as e:
                    logme(MODUL,"Invalid json entry found in line "+str(currentline)+", skipping entry.",("P3"),ECFG)
                    countme(MODUL,'fileline',-2,ECFG)
                    J+=1
                    pass # invalid json
                else:
                    DATA =    {
                                "aid"       : HONEYPOT["nodeid"],
                                "timestamp" : "%s-%s-%s %s" % (content['timestamp'][0:4], content['timestamp'][5:7], content['timestamp'][8:10], content['timestamp'][11:19]),
                                "sadr"      : "%s" % content['src_ip'],
                                "sipv"      : "ipv4",
                                "sprot"     : "tcp",
                                "sport"     : "%d" % content['src_port'],
                                "tipv"      : "ipv4",
                                "tadr"      : "%s" % content['dst_ip'],
                                "tprot"     : "tcp",
                                "tport"     : "-1",
                            }

                    REQUEST = {
                                "description" : "Conpot Honeypot",
                            }


                    # Collect additional Data

                    ADATA =   {
                                "conpot_event_type"    :   "%s" % content['event_type'],
                                "conpot_data_type"     :   "%s" % content['data_type'],
                                "conpot_sensor_id"     :   "%s" % content['sensorid'],
                                "conpot_request"       :   "%s" % content['request'],
                                "conpot_id"            :   "%s" % content['id'],
                                "conpot_response"      :   "%s" % content['response'],
                                "hostname": ECFG["hostname"],
                                "externalIP": externalIP,
                                "internalIP": internalIP

                            }

                    # generate template and send

                    esm = buildews(esm,DATA,REQUEST,ADATA)
                    jesm = buildjson(jesm,DATA,REQUEST,ADATA)

                    countme(MODUL,'fileline',-2,ECFG)
                    countme(MODUL,'daycounter', -2,ECFG)

                    if ECFG["a.verbose"] is True:
                        verbosemode(MODUL,DATA,REQUEST,ADATA)

        # Cleaning linecache
        clearcache()

        if int(esm.xpath('count(//Alert)')) > 0:
            sendews(esm)

        writejson(jesm)

        if y  > 1:
            logme(MODUL,"%s EWS alert records send ..." % (x+y-2-J),("P2"),ECFG)
    return

def elasticpot():
    MODUL  = "ELASTICPOT"
    logme(MODUL,"Starting Elasticpot Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("elasticpot","nodeid","logfile")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL,"[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !",("P3","LOG"),ECFG)

    # count limit

    imin = int(countme(MODUL,'fileline',-1,ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL,"Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)

    I = 0 ; x = 0 ; y = 1 ; J = 0

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    while True:
    
        x,y = viewcounter(MODUL,x,y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["logfile"],(imin + I)).rstrip()
        currentline=imin+I 

        if len(line) == 0:
            break
        else:
            # parse json
            try:
                content = json.loads(line)
            except ValueError as e:
                logme(MODUL,"Invalid json entry found in line "+str(currentline)+", skipping entry.",("P3"),ECFG)
                countme(MODUL,'fileline',-2,ECFG)
                J+=1
                pass # invalid json
            else:

                # filter empty requests and nagios checks

                if  content["honeypot"]["query"] == os.sep or content["honeypot"]["query"] == "/index.do?hash=DEADBEEF&activate=1":
                    countme(MODUL,'fileline',-2,ECFG)
                    continue
                try:
                    if checkForPublicIP(content["dest_ip"]):
                        pubIP=content["dest_ip"]
                except:
                    pubIP=externalIP

                # Prepair and collect Alert Data
                DATA = {
                            "aid"       : HONEYPOT["nodeid"],
                            "timestamp" : "%s" % re.sub("T"," ",content["timestamp"]),
                            "sadr"      : "%s" % content["src_ip"],
                            "sipv"      : "ipv" + ip4or6(content["src_ip"]),
                            "sprot"     : "tcp",
                            "sport"     : "%s" % content["src_port"],
                            "tipv"      : "ipv" + ip4or6(ECFG["ip"]),
                            "tadr"      : "%s" % pubIP,
                            "tprot"     : "tcp",
                            "tport"     : "%s" % content["dest_port"],
                        }

                REQUEST = {
                            "description" : "ElasticSearch Honeypot : Elasticpot",
                            "url"         : urllib.parse.quote(content["honeypot"]["query"].encode('ascii', 'ignore')),
                            "raw"         : content["honeypot"]["raw"]

                        }

                # Collect additional Data

                ADATA = {
                        "postdata"       : "%s" % content["honeypot"]["postdata"],
                        "hostname": ECFG["hostname"],
                        "externalIP": externalIP,
                        "internalIP": internalIP

                }

                # generate template and send
                esm = buildews(esm,DATA,REQUEST,ADATA)
                jesm = buildjson(jesm,DATA,REQUEST,ADATA)

                countme(MODUL,'fileline',-2,ECFG)
                countme(MODUL,'daycounter', -2,ECFG)

                if ECFG["a.verbose"] is True:
                    verbosemode(MODUL,DATA,REQUEST,ADATA)

    # Cleaning linecache
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-2-J),("P2"),ECFG)
    return

def suricata():
    MODUL  = "SURICATA"
    logme(MODUL,"Starting Suricata Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("suricata","nodeid","logfile")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL,"[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !",("P3","LOG"),ECFG)

    # count limit

    imin = int(countme(MODUL,'fileline',-1,ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL,"Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)

    I = 0 ; x = 0 ; y = 1 ; J = 0

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    while True:

        x,y = viewcounter(MODUL,x,y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["logfile"],(imin + I)).rstrip()
        currentline=imin+I 

        if len(line) == 0:
            break
        else:
            # parse json
            try:
                content = json.loads(line)
            except ValueError as e:
                logme(MODUL,"Invalid json entry found in line "+str(currentline)+", skipping entry.",("P3"),ECFG)
                countme(MODUL,'fileline',-2,ECFG)
                J+=1
                pass # invalid json
            else:
                if 'alert' in content and "src_port" in content:
                    if 'cve_id' in content['alert']:
                        # use t-pots external address if src_ip is rfc1819 / private
                        if (ipaddress.ip_address(content["dest_ip"]).is_private):
                            externalip=content["t-pot_ip_ext"]
                        else:
                            externalip=content["dest_ip"]

                        # Prepare and collect Alert Data

                        DATA = {
                                    "aid"       : HONEYPOT["nodeid"],
                                    "timestamp" : "%s" % re.sub("T"," ",content["timestamp"][:-12]),
                                    "sadr"      : "%s" % content["src_ip"],
                                    "sipv"      : "ipv" + ip4or6(content["src_ip"]),
                                    "sprot"     : content["proto"].lower(),
                                    "sport"     : "%d" % content["src_port"],
                                    "tipv"      : "ipv" + ip4or6(externalip),
                                    "tadr"      : "%s" % externalip,
                                    "tprot"     : content["proto"].lower(),
                                    "tport"     : "%d" % content["dest_port"],
                                }
                        httpextras = ""
                        if "http" in content:
                            httpextras = urllib.parse.quote(str(content["http"]).encode('ascii', 'ignore'))


                        REQUEST = {
                                    "description" : "Suricata CVE Attack",
                                    "request" : httpextras
                                }

                        # Collect additional Data

                        ADATA = {
                                "cve_id": "%s" % content["alert"]["cve_id"],
                                "hostname": ECFG["hostname"],
                                "externalIP": externalIP,
                                "internalIP": internalIP
                                }


                        # generate template and send
                        esm = buildews(esm,DATA,REQUEST,ADATA)
                        jesm = buildjson(jesm,DATA,REQUEST,ADATA)

                        countme(MODUL,'fileline',-2,ECFG)
                        countme(MODUL,'daycounter', -2,ECFG)

                        if ECFG["a.verbose"] is True:
                            verbosemode(MODUL,DATA,REQUEST,ADATA)

                    else:
                        countme(MODUL, 'fileline', -2, ECFG)
                        J += 1
                        pass  # no cve-data
                else:
                    countme(MODUL, 'fileline', -2, ECFG)
                    J += 1
                    pass # no cve-data

    # Cleaning linecache
    clearcache()
    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-2-J),("P2"),ECFG)
    return

def rdpy():
    MODUL = "RDPY"
    logme(MODUL, "Starting RDPY Modul.", ("P1"), ECFG)

    # collect honeypot config dic

    ITEMS = ("rdpy", "nodeid", "logfile")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL, "[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !", ("P3", "LOG"), ECFG)

    # count limit

    imin = int(countme(MODUL, 'fileline', -1, ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL, "Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!", ("P1"), ECFG)

    I = 0;
    x = 0;
    y = 1;
    J = 0

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
            if line[0:3]=="[*]":
                countme(MODUL,'fileline',-2,ECFG)
                J+=1
                continue

            date=line[0:10]
            time=line[11:19]
            if "Connection from " in line:
                sourceip=line.split("Connection from ")[1].split(":")[0]
                sport=line.split("Connection from ")[1].split(":")[1]
            else:
                J+=1
                countme(MODUL,'fileline',-2,ECFG)
                continue

            # Prepare and collect Alert Data

            DATA = {
                "aid": HONEYPOT["nodeid"],
                "timestamp": "%s %s" % (date,time),
                "sadr": sourceip,
                "sipv": "ipv" + ip4or6(sourceip),
                "sprot": "tcp",
                "sport": sport,
                "tipv": "ipv" + ip4or6(externalIP),
                "tadr": externalIP,
                "tprot": "tcp",
                "tport": "3389",
            }

            REQUEST = {
                "description": "RDP Honeypot RDPY"
            }

            # Collect additional Data

            ADATA = {
                "hostname": ECFG["hostname"],
                "externalIP": externalIP,
                "internalIP": internalIP
            }

            # generate template and send

            esm = buildews(esm, DATA, REQUEST, ADATA)
            jesm = buildjson(jesm, DATA, REQUEST, ADATA)

            countme(MODUL, 'fileline', -2, ECFG)
            countme(MODUL, 'daycounter', -2, ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL, DATA, REQUEST, ADATA)

    # Cleaning linecache
    clearcache()
    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 2 - J), ("P2"), ECFG)
    return

def vnclowpot():
    MODUL = "VNCLOWPOT"
    logme(MODUL, "Starting VNCLOWPOT Modul.", ("P1"), ECFG)

    # collect honeypot config dic

    ITEMS = ("vnclowpot", "nodeid", "logfile")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL, "[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !", ("P3", "LOG"), ECFG)

    # count limit

    imin = int(countme(MODUL, 'fileline', -1, ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL, "Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!", ("P1"), ECFG)

    I = 0;
    x = 0;
    y = 1;
    J = 0

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
            date=line[0:10].replace("/","-")
            time=line[11:19]
            sourceip = line.split(" ")[2].split(":")[0]
            sport = line.split(" ")[2].split(":")[1]

            # Prepare and collect Alert Data

            DATA = {
                "aid": HONEYPOT["nodeid"],
                "timestamp": "%s %s" % (date,time),
                "sadr": sourceip,
                "sipv": "ipv" + ip4or6(sourceip),
                "sprot": "tcp",
                "sport": sport,
                "tipv": "ipv" + ip4or6(externalIP),
                "tadr": externalIP,
                "tprot": "tcp",
                "tport": "5900",
            }

            REQUEST = {
                "description": "vnc Honeypot vnclowpot"
            }

            # Collect additional Data

            ADATA = {
                "hostname": ECFG["hostname"],
                "externalIP": externalIP,
                "internalIP": internalIP
            }

            # generate template and send

            esm = buildews(esm, DATA, REQUEST, ADATA)
            jesm = buildjson(jesm, DATA, REQUEST, ADATA)

            countme(MODUL, 'fileline', -2, ECFG)
            countme(MODUL, 'daycounter', -2, ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL, DATA, REQUEST, ADATA)

    # Cleaning linecache
    clearcache()
    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 2 - J), ("P2"), ECFG)
    return

def mailoney():
    MODUL = "MAILONEY"
    logme(MODUL, "Starting MAILONEY Modul.", ("P1"), ECFG)

    # collect honeypot config dic

    ITEMS = ("mailoney", "nodeid", "logfile")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL, "[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !", ("P3", "LOG"), ECFG)

    # count limit

    imin = int(countme(MODUL, 'fileline', -1, ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL, "Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!", ("P1"), ECFG)

    I = 0;
    x = 0;
    y = 1;
    J = 0

    esm = ewsauth(ECFG["username"], ECFG["token"])
    jesm = ""
    trigger=['HELO', 'EHLO']

    while True:

        x, y = viewcounter(MODUL, x, y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["logfile"], (imin + I)).rstrip()

        if len(line) == 0:
            break
        else:
            try:
                if not any(s in line.split(" ")[1] for s in trigger):
                    countme(MODUL,'fileline',-2,ECFG)
                    J+=1
                    continue
            except:
                countme(MODUL, 'fileline', -2, ECFG)
                J += 1
                continue

            time = datetime.utcfromtimestamp(float(line.split("][")[0].split(".")[0][1:]))
            sourceip = line.split("][")[1].split(":")[0]
            sport= line.split("][")[1].split(":")[1].split("]")[0]

            # Prepare and collect Alert Data

            DATA = {
                "aid": HONEYPOT["nodeid"],
                "timestamp": "%s" % (time),
                "sadr": sourceip,
                "sipv": "ipv" + ip4or6(sourceip),
                "sprot": "tcp",
                "sport": sport,
                "tipv": "ipv" + ip4or6(externalIP),
                "tadr": externalIP,
                "tprot": "tcp",
                "tport": "25",
            }

            REQUEST = {
                "description": "Mail Honeypot mailoney"
            }

            # Collect additional Data

            ADATA = {
                "hostname": ECFG["hostname"],
                "externalIP": externalIP,
                "internalIP": internalIP
            }

            # generate template and send

            esm = buildews(esm, DATA, REQUEST, ADATA)
            jesm = buildjson(jesm, DATA, REQUEST, ADATA)

            countme(MODUL, 'fileline', -2, ECFG)
            countme(MODUL, 'daycounter', -2, ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL, DATA, REQUEST, ADATA)

    # Cleaning linecache
    clearcache()
    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 2 - J), ("P2"), ECFG)
    return

def heralding():
    MODUL = "HERALDING"
    logme(MODUL, "Starting HERALDING Modul.", ("P1"), ECFG)

    # collect honeypot config dic

    ITEMS = ("heralding", "nodeid", "logfile")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL, "[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !", ("P3", "LOG"), ECFG)

    # count limit

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

        if len(line) == 0:
            break
        else:
            if "timestamp" in line:
                countme(MODUL,'fileline',-2,ECFG)
                J+=1
                continue
            linecontent=line.split(",")

            time = linecontent[0].split(".")[0]

            # Prepare and collect Alert Data

            DATA = {
                "aid": HONEYPOT["nodeid"],
                "timestamp": "%s" % (time),
                "sadr": linecontent[3],
                "sipv": "ipv" + ip4or6(linecontent[3]),
                "sprot": "tcp",
                "sport": linecontent[4],
                "tipv": "ipv" + ip4or6(linecontent[5]),
                "tadr": linecontent[5],
                "tprot": "tcp",
                "tport": linecontent[6],
            }

            REQUEST = {
                "description": "Heralding Honeypot"
            }

            # Collect additional Data

            ADATA = {
                "protocol": linecontent[7],
                "username": linecontent[8],
                "password": linecontent[9],
                "hostname": ECFG["hostname"],
                "externalIP": externalIP,
                "internalIP": internalIP
            }

            # generate template and send

            esm = buildews(esm, DATA, REQUEST, ADATA)
            jesm = buildjson(jesm, DATA, REQUEST, ADATA)

            countme(MODUL, 'fileline', -2, ECFG)
            countme(MODUL, 'daycounter', -2, ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL, DATA, REQUEST, ADATA)

    # Cleaning linecache
    clearcache()
    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 2 - J), ("P2"), ECFG)
    return

def ciscoasa():
    MODUL = "CISCOASA"
    logme(MODUL, "Starting CISCO-ASA Modul.", ("P1"), ECFG)

    # collect honeypot config dic

    ITEMS = ("ciscoasa", "nodeid", "logfile")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL, "[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !", ("P3", "LOG"), ECFG)

    # count limit

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

        if len(line) == 0:
            break
        else:
            
            if not line[0] =="{" or not line[-1]=="}":
                countme(MODUL,'fileline',-2,ECFG)
                J+=1
                continue

            try:
                linecontent=ast.literal_eval(line)
            except:
                countme(MODUL, 'fileline', -2, ECFG)
                J += 1
                continue

            time = linecontent['timestamp'].split("T")[0]+" "+linecontent['timestamp'].split("T")[1].split(".")[0]

            """ Prepare and collect Alert Data """

            DATA = {
                "aid": HONEYPOT["nodeid"],
                "timestamp": "%s" % (time),
                "sadr": linecontent['src_ip'],
                "sipv": "ipv" + ip4or6(linecontent['src_ip']),
                "sprot": "tcp",
                "sport": "0",
                "tipv": "ipv" + ip4or6(externalIP),
                "tadr": externalIP,
                "tprot": "tcp",
                "tport": "8443",
            }
            REQUEST = {
                "description": "Cisco-ASA Honeypot"
            }

            # Collect additional Data

            ADATA = {
                "payload": str(linecontent['payload_printable']),
                "hostname": ECFG["hostname"],
                "externalIP": externalIP,
                "internalIP": internalIP
            }

            # generate template and send

            esm = buildews(esm, DATA, REQUEST, ADATA)
            jesm = buildjson(jesm, DATA, REQUEST, ADATA)

            countme(MODUL, 'fileline', -2, ECFG)
            countme(MODUL, 'daycounter', -2, ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL, DATA, REQUEST, ADATA)

    # Cleaning linecache
    clearcache()
    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 2 - J), ("P2"), ECFG)
    return

def tanner():
    MODUL = "TANNER"
    logme(MODUL, "Starting Tanner Modul.", ("P1"), ECFG)

    # collect honeypot config dic

    ITEMS = ("tanner", "nodeid", "logfile")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL, "[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !", ("P3", "LOG"), ECFG)

    # count limit

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

        if len(line) == 0:
            break
        else:
            linecontent=json.loads(line, object_pairs_hook=OrderedDict)
            time = linecontent['timestamp'].split("T")[0]+" "+linecontent['timestamp'].split("T")[1].split(".")[0]
            # Prepare and collect Alert Data

            DATA = {
                "aid": HONEYPOT["nodeid"],
                "timestamp": "%s" % (time),
                "sadr": linecontent['peer']['ip'],
                "sipv": "ipv" + ip4or6(str(linecontent['peer']['port'])),
                "sprot": "tcp",
                "sport": str(linecontent['peer']['port']),
                "tipv": "ipv" + ip4or6(externalIP),
                "tadr": externalIP,
                "tprot": "tcp",
                "tport": "80",
            }

            REQUEST = {
                "description": "Tanner Honeypot",
                "url": urllib.parse.quote(linecontent["path"].encode('ascii', 'ignore'))
            }

            # Collect additional Data

            ADATA = {
                "hostname": ECFG["hostname"],
                "externalIP": externalIP,
                "internalIP": internalIP
            }

            reassembledReq = ""
            if 'host' in linecontent['headers']:
                httpversion="HTTP/1.1"
            else:
                httpversion="HTTP/1.0"
            if len(linecontent['headers']) > 0:
                reassembledReq="{} {} {}\n".format(linecontent['method'], linecontent['path'], httpversion)
                for i in linecontent['headers']:
                    headercontent = ""
                    if linecontent['headers'][i]:
                        headercontent=linecontent['headers'][i]
                    reassembledReq = "{}{}: {}\r\n".format(reassembledReq, i.title(), headercontent)

            #REQUEST["raw"] = base64.b64encode(reassembledReq.encode('ascii')).decode()
            REQUEST["raw"] = base64.encodebytes(reassembledReq.encode('ascii', 'ignore')).decode()

            esm = buildews(esm, DATA, REQUEST, ADATA)
            jesm = buildjson(jesm, DATA, REQUEST, ADATA)

            countme(MODUL, 'fileline', -2, ECFG)
            countme(MODUL, 'daycounter', -2, ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL, DATA, REQUEST, ADATA)

    # Cleaning linecache
    clearcache()
    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 2 - J), ("P2"), ECFG)
    return

def glutton():
    MODUL = "GLUTTON"
    logme(MODUL, "Starting Glutton Modul.", ("P1"), ECFG)

    """ collect honeypot config dic """

    ITEMS = ("glutton", "nodeid", "logfile")
    HONEYPOT = readcfg(MODUL, ITEMS, ECFG["cfgfile"])

    """ logfile file exists ? """

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL, "[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !", ("P3", "LOG"), ECFG)

    """ count limit """

    imin = int(countme(MODUL, 'fileline', -1, ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL, "Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!", ("P1"), ECFG)

    I = 0 ; x = 0 ; y = 1 ; J = 0

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
            linecontent=json.loads(line, object_pairs_hook=OrderedDict)
            dtime = (datetime.fromtimestamp(float(linecontent['ts']))).strftime('%Y-%m-%d %H:%M:%S')

            """ skip non attack info """
            if "src_ip" not in linecontent:
                countme(MODUL,'fileline',-2,ECFG)
                J += 1
                continue
            if "error" in linecontent["level"]:
                countme(MODUL,'fileline',-2,ECFG)
                J += 1
                continue

            """ Prepare and collect Alert Data """
            DATA = {
                "aid": HONEYPOT["nodeid"],
                "timestamp": "%s" % (dtime),
                "sadr": linecontent['src_ip'],
                "sipv": "ipv" + ip4or6(str(linecontent['src_ip'])),
                "sprot": "tcp",
                "sport": str(linecontent['src_port']),
                "tipv": "ipv" + ip4or6(externalIP),
                "tadr": externalIP,
                "tprot": "tcp",
                "tport": str(linecontent['dest_port']),
            }

            REQUEST = {
                "description": "Glutton Honeypot",
            }

            """ Collect additional Data """

            ADATA = {
                "hostname": ECFG["hostname"],
                "externalIP": externalIP,
                "internalIP": internalIP
            }

            if "payload_hex" in linecontent:
                ADATA["binary"] = base64.b64encode(codecs.decode(linecontent['payload_hex'], 'hex')).decode()

            """
            if re.search("[+]", linecontent['msg']):
                print "found [] in " + str(linecontent)


            #REQUEST["raw"] = base64.encodestring(reassembledReq.encode('ascii', 'ignore'))
            REQUEST["raw"] = base64.encodebytes(reassembledReq.encode('ascii', 'ignore')).decode()

            """

            # generate template and send

            esm = buildews(esm, DATA, REQUEST, ADATA)
            jesm = buildjson(jesm, DATA, REQUEST, ADATA)

            countme(MODUL, 'fileline', -2, ECFG)
            countme(MODUL, 'daycounter', -2, ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL, DATA, REQUEST, ADATA)

    # Cleaning linecache
    clearcache()
    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y > 1:
        logme(MODUL, "%s EWS alert records send ..." % (x + y - 2 - J), ("P2"), ECFG)
    return

###############################################################################
 
if __name__ == "__main__":

    MODUL = "MAIN"

    global ECFG
    ECFG = ecfg(name,version)
    init()

    lock = locksocket(name)

    if lock is True:
        logme(MODUL,"Create lock socket successfull.",("P1"),ECFG)
    else:
        logme(MODUL,"Another Instance is running !",("P1"),ECFG)
        logme(MODUL,"EWSrun finish.",("P1","EXIT"),ECFG)

    while True:

        global hpc
        hpc=testhpfeedsbroker()

        if ECFG["a.daycounter"] is True:
            daycounterreset(lock,ECFG)

        if ECFG["a.ewsonly"] is False:
            sender()

        for i in ("glastopfv3", "glastopfv2", "kippo", "dionaea", "honeytrap", "rdpdetect", "emobility", "conpot", "cowrie","elasticpot",
                  "suricata", "rdpy", "mailoney", "vnclowpot", "heralding", "ciscoasa", "tanner", "glutton"):

            if ECFG["a.modul"]:
                if ECFG["a.modul"] == i:
                    if readonecfg(i.upper(),i,ECFG["cfgfile"]).lower() == "true":
                        eval(i+'()')
                        break
                else:
                    continue

            if readonecfg(i.upper(),i,ECFG["cfgfile"]).lower() == "true":
                eval(i+'()')

        if int(ECFG["a.loop"]) == 0:
            logme(MODUL,"EWSrun finish.",("P1"),ECFG)
            break
        else:
            logme(MODUL,"Sleeping for %s seconds ...." % ECFG["a.loop"] ,("P1"),ECFG)
            time.sleep(int(ECFG["a.loop"]))

