#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from influxdb_client import InfluxDBClient
#from influxdb import InfluxDBClient
from collections import OrderedDict
from datetime import datetime
from lxml import etree
from modules.elog import ELog
import xmltodict
import base64
import configparser
import hpfeeds
import ipaddress
import json
import linecache
import os
import random
import re
import requests
import socket
import sqlite3
import ssl


class EAlert:
    def __init__(self, MODUL, ECFG):
        self.MODUL = MODUL.upper()
        self.DATA = {}
        self.REQUEST = {}
        self.ADATA = {}
        self.ECFG = ECFG
        self.esm = ""
        self.jesm = ""
        self.iesm = []
        self.counter = 0
        self.hcounter = 0
        self.jsonfailcounter = 0
        self.sqlite3connect = False
        self.maxid = 0
        self.malwareindex = []
        self.ewsAuth(self.ECFG["username"], self.ECFG["token"])
        print(f' => Starting {self.MODUL.title()} Honeypot Modul.')
        self.logger = ELog('EAlert')

    def lineREAD(self, filename, format='json', linenumber=None, item='index', debugoutput=False):
        if linenumber is None:
            linecounter = int(self.alertCount(self.MODUL, 'get_counter', item))
        else:
            linecounter = linenumber

        lcache = linecache.getline(filename, linecounter)

        if linenumber is None and lcache != '':
            self.alertCount(self.MODUL, "add_counter", item)

        if lcache != '' and format == "json":
            try:
                jsonline = json.loads(lcache)
            except ValueError:
                self.jsonfailcounter += 1
                if debugoutput:
                    self.logger.warning(f"lineREAD invalid json entry found '{lcache.rstrip()}' in {filename} line {linecounter}. Skipping line.", '2')
                return("jsonfail")
            else:
                return(jsonline)
        elif lcache != '' and format == "simple":
            return(lcache)
        else:
            linecache.clearcache()
            return()

    def lineSQLITE(self, filename, linenumber=None, item='index'):
        if linenumber is None:
            linecounter = int(self.alertCount(self.MODUL, 'get_counter', item))
        else:
            linecounter = linenumber

        if self.sqlite3connect is False:
            self.con = sqlite3.connect(filename, 30)
            self.con.row_factory = sqlite3.Row
            self.c = self.con.cursor()
            self.sqlite3connect = True

        if self.MODUL == 'GLASTOPFV3' and self.sqlite3connect is True:
            if self.maxid == 0:
                try:
                    self.c.execute("SELECT max(id) from events;")
                    self.maxid = self.c.fetchone()["max(id)"]
                    if self.maxid is None:
                        self.maxid = 0
                        return('false')
                except sqlite3.OperationalError as e:
                    self.logger.warning(f'SQLite3 Error on Glastopf Database {e}', '2')
                    return('false')

            if self.maxid >= linecounter:
                self.c.execute("SELECT * from events where id = ?", (str(linecounter),))
                self.alertCount(self.MODUL, "add_counter", item)
                return(dict(self.c.fetchone()))
            else:
                return('')

        if self.MODUL == 'DIONAEA' and self.sqlite3connect is True:
            if self.maxid == 0:
                try:
                    self.c.execute("SELECT max(connection) from connections;")
                    self.maxid = self.c.fetchone()["max(connection)"]
                    if self.maxid is None:
                        self.maxid = 0
                        return('false', 'false')
                except sqlite3.OperationalError as e:
                    self.logger.warning(f'SQLite3 Error on Dionaea Database {e}', '2')
                    return('false', 'false')

            if self.maxid >= linecounter:
                data = self.c.execute("SELECT * from connections where connection = ?;", (str(linecounter),)).fetchone()
                download = self.c.execute("SELECT download_md5_hash from downloads where connection = ?;", (str(linecounter),)).fetchone()
                if download is None:
                    download = ''
                self.alertCount(self.MODUL, "add_counter", item)
                return(dict(data), dict(download))
            else:
                return('false', 'false')

        self.con.close()
        return()

    def readCFG(self, items, file):
        files = ["logfile", "attackerfile", "sqlitedb"]
        dirs = ["payloaddir", "malwaredir", "jsondir", "homedir", "spooldir", "logdir"]

        config = configparser.ConfigParser()
        config.read(file)

        returndic = {}

        for item in items:
            if config.has_option(self.MODUL, item) is True:
                if len(config.get(self.MODUL, item)) > 0:
                    returndic[item] = config.get(self.MODUL, item)
                elif len(config.get(self.MODUL, item)) == 0:
                    returndic[item] = None

                if item in files and os.path.isfile(returndic[item]) is False:
                    returndic['error_files'] = False
                    returndic['error_files_msg'] = f"Missing File! {item} = {returndic[item]}"
                    # self.logger.error(f"checkCFG mission File! {item} = {returndic[item]}. Abort!", '1E')

                if item in dirs and os.path.isdir(returndic[item]) is False:
                    returndic['error_dirs'] = False
                    returndic['error_dirs_msg'] = f"checkCFG mission Directory! {item} = {returndic[item]}. Abort!"
                    # self.logger.error(f"checkCFG mission Directory! {item} = {returndic[item]}. Abort!", '1E')

            else:
                self.logger.error(f"[readCFG] Config parameter '{item}=' didn't find or empty in config file '{file}'. Abort!", '1E')

        return(returndic)

    def alertCount(self, section, counting, item='index', setto=1):
        count = configparser.ConfigParser()
        count.read(self.ECFG["homedir"] + os.sep + "ews.idx")

        if count.has_section(section) is False:
            count.add_section(section)

        if count.has_option(section, item) is False:
            count.set(section, item, str(1))

        if isinstance(counting, int) and counting >= 0:
            count.set(section, item, str(counting))

        elif isinstance(counting, str) and counting == "get_counter":
            return count.get(section, item)

        elif isinstance(counting, str) and counting == "add_counter":
            count.set(section, item, str(int(count.get(section, item)) + 1))

        elif isinstance(counting, str) and counting == "set_counter":
            count.set(section, item, str(setto))

        elif isinstance(counting, str) and counting == "reset_counter":
            count.set(section, item, str(setto))

        with open(self.ECFG["homedir"] + os.sep + "ews.idx", 'w') as countfile:
            count.write(countfile)
            countfile.close

        return()

    def fileIndex(self, filename, action, content=None):
        filename = self.ECFG['homedir'] + os.sep + filename

        """ check if file exist, else create file """
        if not os.path.isfile(filename):
            with open(filename, "w+") as reader:
                reader.close()

        """ get a list of content stript newline """
        with open(filename, "r", newline=None) as reader:
            filelist = list(filter(None, [line.rstrip("\n") for line in reader]))
            reader.close()

        if action == "read":
            return(filelist)

        if action == "write" and content is not None:
            with open(filename, "a+") as reader:
                if isinstance(content, list):
                    for line in content:
                        if line not in filelist and line != "":
                            reader.write(line + "\n")

                if isinstance(content, str):
                    if content not in filelist and content != "":
                        reader.write(content + "\n")

                if isinstance(content, int):
                    if str(content) not in filelist and content != "":
                        reader.write(str(content) + "\n")

                reader.close()

        return()

    def data(self, key, value):
        keywords = ("source_address", "target_address", "source_port", "target_port", "source_protocol",
                    "target_protocol", "timestamp", "timezone", "analyzer_id", "cident", "corigin", "ctext")

        if key in keywords:
            self.DATA[key] = value
            if key == "source_address":
                self.DATA["source_ip_version"] = "ipv" + str(ipaddress.ip_address(value).version)

            if key == "target_address":
                self.DATA["target_ip_version"] = "ipv" + str(ipaddress.ip_address(value).version)
                if ipaddress.ip_address(self.DATA['target_address']).is_private is True:
                    self.DATA['target_address'] = self.ECFG['ip_ext']
        else:
            self.logger.error(f"Unknow keyword in data {key} = {value}.", '1E')
            return(False)

        return(True)

    def dataCheck(self):
        keywords = ("source_address", "target_address", "source_port", "target_port", "source_protocol",
                    "target_protocol", "source_ip_version", "target_ip_version", "timestamp", "timezone",
                    "analyzer_id")

        for keyword in keywords:
            if keyword not in self.DATA:
                self.logger.error(f"Missing keyword  in dataCheck '{keyword}'. Alert skipt!", '2')
                return(False)

        if "cident" in self.DATA or "corigin" in self.DATA or "ctext" in self.DATA:
            if "cident" in self.DATA and "corigin" in self.DATA and "ctext" in self.DATA:
                return(True)
            else:
                self.logger.error(f"Unknow cident/corgin/ctext in dataCheck combination. Alert skipt!", '2')
                return(False)

        return(True)

    def request(self, key, value):
        keywords = ("description", 'url', 'binary', 'request', 'raw', 'payload', 'largepayload')

        if key in keywords:
            self.REQUEST[key] = value
        else:
            self.logger.error(f"Unknow keyword in request {key} = {value}.", '1E')
            return(False)

        return(True)

    def adata(self, key, value):
        self.ADATA[key] = value
        return(True)

    def ewsAuth(self, username, token):
        self.esm = etree.Element("EWS-SimpleMessage", version="3.0")
        Auth = etree.SubElement(self.esm, "Authentication")
        etree.SubElement(Auth, "username").text = username
        etree.SubElement(Auth, "token").text = token
        return()

    def ewsAlert(self):
        Alert = etree.SubElement(self.esm, "Alert")
        etree.SubElement(Alert, "Analyzer", id=self.DATA["analyzer_id"])
        etree.SubElement(Alert, "CreateTime", tz=self.DATA["timezone"]).text = self.DATA["timestamp"]
        etree.SubElement(Alert, "Source", category=self.DATA["source_ip_version"], port=str(self.DATA["source_port"]), protocol=self.DATA["source_protocol"]).text = self.DATA["source_address"]
        etree.SubElement(Alert, "Target", category=self.DATA["target_ip_version"], port=str(self.DATA["target_port"]), protocol=self.DATA["target_protocol"]).text = self.DATA["target_address"]

        if "corigin" and "cident" and "ctext" in self.DATA:
            etree.SubElement(Alert, "Classification", origin=self.DATA["corigin"], ident=self.DATA["cident"], text=self.DATA["ctext"])

        for key, value in list(self.REQUEST.items()):
            etree.SubElement(Alert, "Request", type=key).text = value

        for key, value in list(self.ADATA.items()):
            if isinstance(value, int):
                mytype = "integer"
            elif isinstance(value, str):
                mytype = "string"
            else:
                mytype = "string"

            etree.SubElement(Alert, "AdditionalData", type=mytype, meaning=key).text = re.sub(u'[^\u0020-\uD7FF\u0009\u000A\u000D\uE000-\uFFFD\U00010000-\U0010FFFF]+', '', str(value))
        return()

    def ewsWrite(self):
        with open(self.ECFG['spooldir'] + os.sep + datetime.now().strftime('%Y%m%dT%H%M%S.%f')[:-3] + ".ews", "wb") as file:
            file.write(etree.tostring(self.esm, pretty_print=True))
            file.close
            return()

    def influxAlert(self):
        iAlert = {}
        iAlert["measurement"] = "honeypots"
        iAlert["tags"] = dict(honeypot=self.MODUL.lower()
                              )
        iAlert["time"] = f"{self.DATA['timestamp'][0:10]}T{self.DATA['timestamp'][11:19]}{self.DATA['timezone']}"
        iAlert["fields"] = dict(analyzer_id=self.DATA['analyzer_id'],
                                source_address=self.DATA['source_address'],
                                source_port=int(self.DATA['source_port']),
                                source_protocol=self.DATA['source_protocol'],
                                target_address=self.DATA['target_address'],
                                target_port=int(self.DATA['target_port']),
                                target_protocol=self.DATA['target_protocol']
                                )
        """ append cident, corigin, ctext """
        for index in ['cident', 'corigin', 'ctext']:
            if index in self.DATA:
                iAlert['fields'][index] = self.DATA[index]

        """ append additional data """
        for key, value in self.ADATA.items():
            if key in ['host', 'externalIP', 'internalIP', 'uuid']:
                continue
            else:
                iAlert['fields'][key] = value

        self.iesm.append(iAlert)

        return()

    def influxWrite(self):
        client = InfluxDBClient(self.ECFG['influx_host'], self.ECFG['influx_port'], self.ECFG['influx_username'], self.ECFG['influx_password'], self.ECFG['influx_bucket'])
        client.write_points(self.iesm)
        self.iesm.clear()

    def ewsVerbose(self):
        print(f'--------------- {self.MODUL} ---------------')
        print(f'NodeID          : {self.DATA["analyzer_id"]}')
        print(f'Timestamp       : {self.DATA["timestamp"]}')
        print(f'            ')
        print(f'Source IP       : {self.DATA["source_address"]}')
        print(f'Source IPv      : {self.DATA["source_ip_version"]}')
        print(f'Source Port     : {self.DATA["source_port"]}')
        print(f'Source Protocol : {self.DATA["source_protocol"]}')
        print(f'            ')
        print(f'Target IP       : {self.DATA["target_address"]}')
        print(f'Target IPv      : {self.DATA["target_ip_version"]}')
        print(f'Target Port     : {self.DATA["target_port"]}')
        print(f'Target Protocol : {self.DATA["target_protocol"]}')
        print(f'-- REQUEST ----------------------------------')

        for key, value in list(self.REQUEST.items()):
            print(f'{key} : {value}')

        print(f'-- ADATA ------------------------------------')

        for key, value in list(self.ADATA.items()):
            print(f'{key} : {value}')
        return()

    def jsonAlert(self):
        myjson = {}
        myjson['timestamp'] = ("%sT%s.000000" % (self.DATA["timestamp"][0:10], self.DATA["timestamp"][11:19]))
        myjson['event_type'] = "alert"
        myjson['src_ip'] = self.DATA["source_address"]
        myjson['src_port'] = self.DATA['source_port']
        myjson['dest_ip'] = self.DATA['target_address']
        myjson['dest_port'] = self.DATA['target_port']

        if self.REQUEST:
            myjson["request"] = self.REQUEST
        if self.ADATA:
            myjson["additionaldata"] = self.ADATA

        self.jesm = self.jesm + json.dumps(myjson) + "\n"
        return()

    def jsonWrite(self):
        if len(self.jesm) > 0:
            if len(self.ECFG['a.jsondir']) > 0:
                jsondir = self.ECFG['a.jsondir']
            else:
                jsondir = self.ECFG['jsondir']

            with open(jsondir, 'a+') as file:
                file.write(self.jesm)
                file.close
            return()

    def clearandcount(self):
        """ Count up and delete data variables """
        self.counter += 1
        self.DATA.clear()
        self.REQUEST.clear()
        self.ADATA.clear()
        return()

    def buildAlert(self):
        """ Check if all required data exists. """
        if self.dataCheck() is False:
            self.clearandcount()
            return(False)

        """ Create ews and json and influx alert """
        self.ewsAlert() if self.ECFG['ews'] is True or self.ECFG["hpfeed"] is True else None
        self.jsonAlert() if self.ECFG['json'] is True else None
        self.influxAlert() if self.ECFG['influxdb'] is True else None

        """ View Alert details if ARG Verbose is on """
        if self.ECFG['a.verbose'] is True:
            self.ewsVerbose()

        """ check if alerts must be send """
        if int(self.esm.xpath('count(//Alert)')) >= 100:
            self.counter = 0
            self.hcounter += 1
            self.sendAlert()

        """ clear, count, check if sendlimit ist reach ! """
        self.clearandcount()
        if (self.counter + (self.hcounter * 100)) >= int(self.ECFG["sendlimit"]):
            print(f'    -> Sendlimit ({self.ECFG["sendlimit"]}) for Honeypot {self.MODUL} reached. Skip.')
            return('sendlimit')

        return(True)

    def finAlert(self):
        """ check for unsend EWS alerts """
        if int(self.esm.xpath('count(//Alert)')) > 0:
            self.sendAlert()

    def clearAlert(self):
        """ Clean ews & json """
        self.ewsAuth(self.ECFG["username"], self.ECFG["token"])
        self.jesm = ''

    def sendAlert(self):
        """ Print Counter """
        if self.hcounter >= 1 and self.counter == 0:
            print(f'    -> Send {100*self.hcounter:3d} {self.MODUL} alert(s) to EWS Backend.')
        if self.counter > 0:
            print(f"    -> Send {100 * self.hcounter + self.counter:3d} {self.MODUL} alert(s) to EWS Backend.")

        """ When ARG 'EWS Only' write to file and return """
        if self.ECFG["a.ewsonly"] is True:
            self.ewsWrite()
            self.clearAlert()
            return(True)

        """ Debug Mode """
        if self.ECFG['a.debug'] is True:
            print(etree.tostring(self.esm, pretty_print=True))

        """ Check Json write """
        if self.ECFG["json"] is True:
            self.jsonWrite()

        """ Check HpFeed write """
        if self.ECFG["hpfeed"] is True:
            if self.ECFG["hpfformat"].lower() == "json":
                self.hpfeedsend('json')
            else:
                self.hpfeedsend('xml')

        """ Check InfluxDB write """
        if self.ECFG['influxdb'] is True:
            self.influxWrite()

        """ Check Ews and send via webservice or drop to spool """
        if self.ECFG["ews"] is True:
            if self.ewsWebservice() is False:
                self.ewsWrite()
                self.clearAlert()
                return(False)

        self.clearAlert()
        return(True)

    def ewsWebservice(self):
        headers = {'User-Agent': f"{self.ECFG['name']} {self.ECFG['version']}",
                   'Content-type': 'text/xml',
                   'SOAPAction': '',
                   'Charset': 'UTF-8',
                   'Connection': 'close'}

        host = random.choice([self.ECFG["rhost_first"], self.ECFG["rhost_second"]])

        proxies = {}

        if self.ECFG['proxy'] is not False:
            if "https:" in self.ECFG["proxy"]:
                proxies = {"https": self.ECFG["proxy"]}
            elif "http:" in self.ECFG["proxy"]:
                proxies = {"http": self.ECFG["proxy"]}

        verify = (False if self.ECFG["a.ignorecert"] is True else True)

        try:
            webservice = requests.post(host,
                                       data=etree.tostring(self.esm),
                                       headers=headers,
                                       allow_redirects=True,
                                       timeout=60,
                                       proxies=proxies,
                                       verify=verify)

            webservice.raise_for_status()
            xmlresult = re.search('<StatusCode>(.*)</StatusCode>', webservice.text).groups()[0]

            if xmlresult != "OK":
                self.logger.warning(f'ewsWebservice XML Result != ok ({xmlresult}) ({webservice.text})', '2')
                return(False)

            return(True)

        except requests.exceptions.Timeout:
            self.logger.warning(f'ewsWebservice Timeout to remote Host {host}', '2')
            return(False)

        except requests.exceptions.ConnectionError:
            self.logger.warning(f"ewsWebservice Remote Host {host} didn't answer!", '2')
            return(False)

        except requests.exceptions.HTTPError:
            self.logger.warning(f'ewsWebservice HTTP(S) Errorcode != 200', '2')
            return(False)

        except ssl.WantWriteError:
            self.logger.warning(f'ewsWebservice SSL Write Buffer too small', '2')
            return(False)

    def ewsprint(self):
        print(etree.tostring(self.esm, pretty_print=True))
        return

    def printdata(self):
        print(f"MODUL: {self.MODUL}\n")
        print(f"DATA:  {self.DATA}\n")
        print(f"REQUEST: {self.REQUEST}\n")
        print(f"ADATA: {self.ADATA}\n")
        return()

    def hpfeedsend(self, eformat):
        """ workaround if hpfeeds broker is offline as otherwise hpfeeds lib will loop connection attempt """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((self.ECFG["host"], int(self.ECFG["port"])))
        sock.close()

        if result != 0:
            """ broker unavailable """
            self.logger.warning(f"HPFEEDS broker is configured to {self.ECFG['host']}:{self.ECFG['port']} but is currently unavailable. Disabling hpfeeds submission for this round!", '2')
            return(False)

        try:
            hpc = ''
            if self.ECFG["tlscert"].lower() != "none":
                hpc = hpfeeds.new(self.ECFG["host"],
                                  int(self.ECFG["port"]),
                                  self.ECFG["ident"],
                                  self.ECFG["secret"],
                                  certfile=self.ECFG["tlscert"],
                                  reconnect=False)
                print(f'    -> Connecting to {hpc.brokername}/{self.ECFG["host"]}:{self.ECFG["port"]} via TLS')
            else:
                hpc = hpfeeds.new(self.ECFG["host"],
                                  int(self.ECFG["port"]),
                                  self.ECFG["ident"],
                                  self.ECFG["secret"],
                                  reconnect=False)
                print(f'    -> Connecting to {hpc.brokername}/{self.ECFG["host"]}:{self.ECFG["port"]} via none TLS')

            """ remove auth header """
            etree.strip_elements(self.esm, "Authentication")

            for i in range(0, len(self.esm)):
                if eformat == "xml":
                    hpc.publish(self.ECFG["channels"], etree.tostring(self.esm[i], pretty_print=False))

                if eformat == "json":
                    parsed_data = xmltodict.parse(etree.tostring(self.esm[i]), dict_constructor=OrderedDict)
                    hpc.publish(self.ECFG["channels"], json.dumps(parsed_data))

            return(True)

        except hpfeeds.FeedException as e:
            self.logger.error(f"HPFeeds Error ({e})", '2')
            return(False)

    def malwarecheck(self, malwaredir, malwarefile, localremove, md5filechecksum=None):
        if not os.path.isdir(malwaredir):
            self.logger.warning(f"Malwaredir {malwaredir} does not exist!", '2')
            return(False, None)

        if self.md5malware(md5filechecksum) is False:
            self.logger.warning(f"MD5File {md5filechecksum} already submitted.", '2')
            return(False, None)

        if os.path.isfile(malwaredir + os.sep + malwarefile) is True:
            if os.path.getsize(malwaredir + os.sep + malwarefile) <= 10 * 1024 * 1024:
                payload = open(malwaredir + os.sep + malwarefile, "rb").read()
                if localremove is True:
                    os.remove(malwaredir + os.sep + malwarefile)
                return(True, base64.b64encode(payload))
            else:
                self.logger.warning(f"FILE {malwaredir}{os.sep}{malwarefile} is bigger than 10 MB! Not send.", '2')
                return(False, None)
        else:
            self.logger.warning(f"FILE {malwaredir}{os.sep}{malwarefile} does not exist!", '2')
            return(False, None)

    def md5malware(self, md5filechecksum):
        if os.path.isfile(self.ECFG["homedir"] + os.sep + "malware.md5") is False:
            with open(self.ECFG["homedir"] + os.sep + "malware.md5", "a+") as malwarefile:
                malwarefile.close()

        if len(self.malwareindex) == 0:
            with open(self.ECFG["homedir"] + os.sep + "malware.md5", "r", newline=None) as malwarefile:
                self.malwareindex = list(filter(None, [line.rstrip("\n") for line in malwarefile]))
                malwarefile.close()

        if md5filechecksum in self.malwareindex:
            return(False)
        else:
            with open(self.ECFG["homedir"] + os.sep + "malware.md5", "a+") as malwarefile:
                malwarefile.write(f'{md5filechecksum}\n')
                malwarefile.close()
            self.malwareindex.append(md5filechecksum)
            return(True)
