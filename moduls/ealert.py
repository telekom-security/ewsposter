#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from lxml import etree
import ipaddress
from urllib import parse
import json
import os
import random
import requests
import re
import configparser
import linecache
import OpenSSL.SSL
import hpfeeds
import socket
from xmljson import BadgerFish
from collections import OrderedDict

class EAlert:

    def __init__(self, MODUL, ECFG):

        self.MODUL = MODUL.upper()
        self.DATA = {}
        self.REQUEST = {}
        self.ADATA = {}
        self.ECFG = ECFG
        self.esm = ""
        self.jesm = ""
        self.counter = 0
        self.hcounter = 0
        self.jsonfailcounter = 0
        self.ewsAuth(self.ECFG["username"], self.ECFG["token"])
        print(f' => Starting {self.MODUL} Honeypot Modul.')

    def lineREAD(self, filename, format='json', linenumber=None):

        if linenumber is None:
            linecounter = int(self.alertCount(self.MODUL, 'get_counter'))
        else:
            linecounter = linenumber

        lcache = linecache.getline(filename, linecounter)

        if linenumber is None and lcache != '':
            self.alertCount(self.MODUL, "add_counter")

        if lcache != '' and format == "json":
            try:
                jsonline = json.loads(lcache)
            except ValueError:
                self.jsonfailcounter += 1
                print(f" => [WARNING] Invalid json entry found '{lcache.rstrip()}' in {filename} line {linecounter}. Skipping line.")
                return('jsonfail')
            else:
                return(jsonline)
        elif lcache != '' and format == "simple":
            return(lcache)
        else:
            linecache.clearcache()
            return()

    def readCFG(self, items, file):

        config = configparser.ConfigParser()
        config.read(file)

        returndic = {}

        for item in items:
            if config.has_option(self.MODUL, item) is True:
                if len(config.get(self.MODUL, item)) > 0:
                    returndic[item] = config.get(self.MODUL, item)
                elif len(config.get(self.MODUL, item)) == 0:
                    returndic[item] = None
                self.checkCFG(item, returndic[item])
            else:
                errormsg = "[ERROR] Config parameter [{}] '{}=' didn't find or empty in {} config file. Abort!".format(self.MODUL, item, file)
                print(errormsg)

        return(returndic)

    def checkCFG(self, key, value):
        files = ["logfile", "attackerfile", "sqlitedb"]
        dirs = ["payloaddir", "malwaredir", "jsondir", "homedir", "spooldir", "logdir"]

        if key in files and os.path.isfile(value) is False:
            print(f'=> [ERROR] Mission File! {key} = {value} in Modul [{self.MODUL}]. Abort !')
            sys.exit()

        if key in dirs and os.path.isdir(value) is False:
            print(f'=> [ERROR] Mission Directory! {key} = {value} in Modul [{self.MODUL}]. Abort !')
            sys.exit()

        return()

    def alertCount(self, section, counting, item='index'):

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

        elif isinstance(counting, str) and counting == "reset_counter":
            count.set(section, item, str(1))

        with open(self.ECFG["homedir"] + os.sep + "ews.idx", 'w') as countfile:
            count.write(countfile)
            countfile.close

        return()

    def fileIndex(self, filename, action, content=None):
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

        keywords = ("source_address", "target_address", "source_port", "target_port", "source_protokoll",
                    "target_protokoll", "timestamp", "timezone", "analyzer_id", "cident", "corigin", "ctext")

        if key in keywords:
            self.DATA[key] = value
            if key == "source_address":
                self.DATA["source_ip_version"] = "ipv" + str(ipaddress.ip_address(value).version)
            if key == "target_address":
                self.DATA["target_ip_version"] = "ipv" + str(ipaddress.ip_address(value).version)
        else:
            return(False)

        return(True)

    def dataCheck(self):

        keywords = ("source_address", "target_address", "source_port", "target_port", "source_protokoll",
                    "target_protokoll", "source_ip_version", "target_ip_version", "timestamp", "timezone",
                    "analyzer_id")

        for keyword in keywords:
            if keyword not in self.DATA:
                return(False)

        if "cident" in self.DATA or "corigin" in self.DATA or "ctext" in self.DATA:
            if "cident" in self.DATA and "corigin" in self.DATA and "ctext" in self.DATA:
                return(True)
            else:
                return(False)
        return(True)

    def request(self, key, value):
        self.REQUEST[key] = value
        return(True)

    def adata(self, key, value):
        self.ADATA[key] = value
        return (True)

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
        etree.SubElement(Alert, "Source", category=self.DATA["source_ip_version"], port=str(self.DATA["source_port"]), protocol=self.DATA["source_protokoll"]).text = self.DATA["source_address"]
        etree.SubElement(Alert, "Target", category=self.DATA["target_ip_version"], port=str(self.DATA["target_port"]), protocol=self.DATA["target_protokoll"]).text = self.DATA["target_address"]

        if "corigin" and "cident" and "ctext" in self.DATA:
            etree.SubElement(Alert, "Classification", origin=self.DATA["corigin"], ident=self.DATA["cident"], text=self.DATA["ctext"])

        for key, value in list(self.REQUEST.items()):
            etree.SubElement(Alert, "Request", type=key).text = value

        for key, value in list(self.ADATA.items()):
            if type(value) is int:
                mytype = "integer"
            elif type(value) is str:
                mytype = "string"
            else:
                mytype = "string"

            etree.SubElement(Alert, "AdditionalData", type=mytype, meaning=key).text = parse.quote(str(value).encode('ascii', 'ignore'))
        return()

    def ewsWrite(self):
        with open(self.ECFG['spooldir'] + os.sep + time.strftime('%Y%m%dT%H%M%S') + ".ews", "wb") as file:
            file.write(etree.tostring(self.esm, pretty_print=True))
            file.close
        return()

    def ewsVerbose(self):
        print(f'--------------- {self.MODUL} ---------------')
        print(f'NodeID          : {self.DATA["analyzer_id"]}')
        print(f'Timestamp       : {self.DATA["timestamp"]}')
        print(f'            ')
        print(f'Source IP       : {self.DATA["source_address"]}')
        print(f'Source IPv      : {self.DATA["source_ip_version"]}')
        print(f'Source Port     : {self.DATA["source_port"]}')
        print(f'Source Protocol : {self.DATA["source_protokoll"]}')
        print(f'            ')
        print(f'Target IP       : {self.DATA["target_address"]}')
        print(f'Target IPv      : {self.DATA["target_ip_version"]}')
        print(f'Target Port     : {self.DATA["target_port"]}')
        print(f'Target Protocol : {self.DATA["target_protokoll"]}')
        print(f'-- REQUEST ----------------------------------')

        for key, value in list(self.REQUEST.items()):
            print(f'{key} : {value}')

        print(f'-- ADATA ------------------------------------')

        for key, value in list(self.ADATA.items()):
            print(f'{key} : {value}')
        return()

    def jsonAlert(self):
        if self.DATA["source_port"] == "":
            self.DATA["source_port"] = "0"

        if self.DATA["target_port"] == "":
            self.DATA["target_port"] = "0"

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
        if len(self.jesm) > 0 and self.ECFG["json"] is True:
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
            print(f'{self.MODUL} there my an problem white collectet Datas. dataCheck skip!')
            self.clearandcount()
            return(False)

        """ Create XML Alert """
        self.ewsAlert()

        if self.ECFG['json'] is True:
            self.jsonAlert()

        if self.ECFG['a.verbose'] is True:
            self.ewsVerbose()

        """ clear, count, check if Sendlimit ist reach ! """
        self.clearandcount()
        if (self.counter + (self.hcounter * 100)) >= int(self.ECFG["sendlimit"]):
            print(f'    -> Sendlimit ({self.ECFG["sendlimit"]}) for Honeypot {self.MODUL} reached. Skip.')
            return('sendlimit')

        """ check if alerts must be send """
        if int(self.esm.xpath('count(//Alert)')) >= 100:
            self.counter = 0
            self.hcounter += 1
            self.sendAlert()
            self.ewsAuth(self.ECFG["username"], self.ECFG["token"])

        return(True)

    def finAlert(self):
        """ check for unsend EWS alerts """
        if int(self.esm.xpath('count(//Alert)')) > 0:
            self.sendAlert()

        """ finish json alerts  """
        self.jsonWrite()

    def sendAlert(self):
        """ Check if ECFG["a.ewsonly"] """
        if self.ECFG["a.ewsonly"] is True:
            self.ewsWrite()
            return(True)

        """ Check if ECFG["a.debug"] """

        """ Print Counter """
        if self.counter == 0 and self.hcounter > 1:
            print(f"    -> Send {100 * self.hcounter:3d} {self.MODUL} alerts to EWS Backend.")
        if self.counter > 0 and self.hcounter == 0:
            print(f"    -> Send {self.counter:3d} {self.MODUL} alert(s) to EWS Backend.")

        """ Send via Webservice or drop to Spool """
        if self.ECFG["ews"] is True and self.ewsWebservice() is not True:
            self.ewsWrite()
            return(False)
        else:
            return(True)

        """ Check if ECFG["hpfeed"] """

    def ewsWebservice(self):
        headers = {'User-Agent': self.ECFG['name'] + " " + self.ECFG['version'],
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
                print("XML Result != ok ( %s) (%s)" % (xmlresult, webservice.text))
                return(False)

            return(True)

        except requests.exceptions.Timeout:
            print("Timeout to remote host")
            return(False)

        except requests.exceptions.ConnectionError:
            print("Remote host didn't answer!")
            return(False)

        except requests.exceptions.HTTPError:
            print("HTTP Errorcode != 200")
            return(False)

        except OpenSSL.SSL.WantWriteError:
            print("OpenSSL Write Buffer too small")
            return(False)

    def ewsprint(self):
        print(etree.tostring(self.esm, pretty_print=True))
        return

    def printdata(self):
        print(self.MODUL)
        print(self.DATA)
        print(self.REQUEST)
        print(self.ADATA)
        return()

    def hpfeedsend(self, esm, eformat):
        if self.ECFG["hpfeed"] is True:
            """ workaround if hpfeeds broker is offline as otherwise hpfeeds lib will loop connection attempt """
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.ECFG["host"], int(self.ECFG["port"])))
            sock.close()

            if result != 0:
                """ broker unavailable """
                print(f'HPFEEDS broker is configured to {self.ECFG["host"]}:{self.ECFG["port"]} but is currently unavailable. Disabling hpfeeds submission for this round!')
                return(False)
            else:
                try:
                    hpc = ''
                    if self.ECFG["tlscert"].lower() != "none":
                        hpc = hpfeeds.new(self.ECFG["host"],
                                          int(self.ECFG["port"]),
                                          self.ECFG["ident"],
                                          self.ECFG["secret"],
                                          certfile=self.ECFG["tlscert"],
                                          reconnect=False)
                        print(f'Connecting to {hpc.brokername}/{self.ECFG["host"]}:{self.ECFG["port"]} via TLS')
                    else:
                        hpc = hpfeeds.new(self.ECFG["host"],
                                          int(self.ECFG["port"]),
                                          self.ECFG["ident"],
                                          self.ECFG["secret"],
                                          reconnect=False)
                        print(f'Connecting to {hpc.brokername}/{self.ECFG["host"]}:{self.ECFG["port"]} via none TLS')

                    """ remove auth header """
                    etree.strip_elements(self.esm, "Authentication")

                    for i in range(0, len(self.esm)):
                        if eformat == "xml":
                            hpc.publish(self.ECFG["channels"], etree.tostring(esm[i], pretty_print=False))

                        if eformat == "json":
                            bf = BadgerFish(dict_type=OrderedDict)
                            hpc.publish(self.ECFG["channels"], json.dumps(bf.data(esm[i])))

                    return(True)

                except hpfeeds.FeedException as e:
                    print(f'HPFeeds Error ({e}%)')
                    return(False)
