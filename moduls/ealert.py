#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class EAlert:

    def __init__(self, MODUL):

        self.MODUL = MODUL.upper()
        self.DATA = {}
        self.REQUEST = {}
        self.ADATA = {}
        self.esm = ""
        self.jesm = ""
        self.counter = 0
        self.hcounter = 0
        self.ewsAuth(ECFG["username"], ECFG["token"])
        print(f' => Starting {self.MODUL} Honeypot Modul.')

    def lineREAD(self, filename, format='json'):
        lcache = linecache.getline(filename, self.alertCount(self.MODUL, 'get_counter')).lstrip()

        if lcache != '' and format == "json":
            return(json.loads(lcache))
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
                errormsg = "[ERROR] Config parameter [{}] '{}=' didn't find or empty in {} config file. Abort !".format(self.MODUL, item, file)
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
        count.read(ECFG["homedir"] + os.sep + "ews.idx")

        if count.has_section(section) is False:
            count.add_section(section)

        if count.has_option(section, item) is False:
            count.set(section, item, str(0))

        if isinstance(counting, int) and counting >= 0:
            count.set(section, item, str(counting))

        elif isinstance(counting, str) and counting == "get_counter":
            return count.get(section, item)

        elif isinstance(counting, str) and counting == "add_counter":
            count.set(section, item, str(int(count.get(section, item)) + 1))

        elif isinstance(counting, str) and counting == "reset_counter":
            count.set(section, item, str(0))

        with open(ECFG["homedir"] + os.sep + "ews.idx", 'w') as countfile:
            count.write(countfile)
            countfile.close

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
        Auth = etree.SubElement(self.esm, "Authenticatio")
        etree.SubElement(Auth, "username").text = username
        etree.SubElement(Auth, "token").text = token
        return()

    def ewsAlert(self):
        Alert = etree.SubElement(self.esm, "Alert")
        etree.SubElement(Alert, "Analyzer", id=self.DATA["analyzer_id"])
        etree.SubElement(Alert, "CreateTime", tz=self.DATA["timezone"]).text = self.DATA["timestamp"]
        etree.SubElement(Alert, "Source", category=self.DATA["source_ip_version"], port=self.DATA["source_port"], protocol=self.DATA["source_protokoll"]).text = self.DATA["source_address"]
        etree.SubElement(Alert, "Target", category=self.DATA["target_ip_version"], port=self.DATA["target_port"], protocol=self.DATA["target_protokoll"]).text = self.DATA["target_address"]

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
        with open(ECFG['spooldir'] + os.sep + time.strftime('%Y%m%dT%H%M%S') + ".ews", "wb") as file:
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
        if len(self.jesm) > 0 and ECFG["json"] is True:
            with open(ECFG["a.jsondir"], 'a+') as file:
                file.write(self.jesm)
                file.close
        return()

    def buildAlert(self):
        if self.dataCheck() is False:
            return(False)

        self.ewsAlert()

        if ECFG['json'] is True:
            self.jsonAlert()

        if ECFG['a.verbose'] is True:
            self.ewsVerbose()

        """ After alert was created """
        self.counter += 1
        self.alertCount(self.MODUL, "add_counter")
        self.DATA.clear()
        self.REQUEST.clear()
        self.ADATA.clear()

        """ check if alerts must be send """
        if int(self.esm.xpath('count(//Alert)')) >= 100:
            self.counter = 0
            self.hcounter += 1
            self.sendAlert()
            self.ewsAuth(ECFG["username"], ECFG["token"])

        return(True)

    def finAlert(self):
        """ check for unsend EWS alerts """
        if int(self.esm.xpath('count(//Alert)')) >= 0:
            self.sendAlert()

        """ finish json alerts  """
        self.jsonWrite()

    def sendAlert(self):
        """ Check if ECFG["a.ewsonly"] """
        if ECFG["a.ewsonly"] is True:
            self.ewsWrite()
            return(True)

        """ Check if ECFG["a.debug"] """

        """ Check if ECFG["ews"] """
        if ECFG["ews"] is True and self.ewsWebservice() is not True:
            self.ewsWrite()
            return(False)
        else:
            return(True)

        """ Check if ECFG["hpfeed"] """


    def ewsWebservice(self):
        headers = {'User-Agent': name + " " + version,
                   'Content-type': 'text/xml',
                   'SOAPAction': '',
                   'Charset': 'UTF-8',
                   'Connection': 'close'}

        host = random.choice([ECFG["rhost_first"], ECFG["rhost_second"]])

        if ECFG["proxy"] != "" and "https:" in ECFG["proxy"]:
            proxy = {"https": ECFG["proxy"]}
        elif ECFG["proxy"] != "" and "http:" in ECFG["proxy"]:
            proxy = {"http": ECFG["proxy"]}
        else:
            proxy = {}

        verify = (False if ECFG["a.ignorecert"] is True else True)

        try:
            webservice = requests.post(host,
                                       data=self.esm,
                                       headers=headers,
                                       allow_redirects=True,
                                       timeout=60,
                                       proxy=proxy,
                                       verify=verify)

            webservice.raise_for_status()
            xmlresult = re.search('<StatusCode>(.*)</StatusCode>', webservice.text).groups()[0]

            if xmlresult != "OK":
                print("XML Result != ok ( %s) (%s)" % (xmlresult, webservice.text))
                return(False)

        except request.excepions.Timeout as e:
            print(f'Timeout. Error: {e}')
            return(False)

        except request.excepions.ConnectionError as e:
            print(f'Connection Error. Error: {e}')
            return(False)

        except request.excepions.HTTPError as e:
            print(f'HTTP Error." Error: {e}')
            return(False)

        except request.excepions.ConnectTimeout as e:
            print(f'Connection Timeout. Error: {e}')
            return(False)

        except OpenSSL.SSL.WantWriteError as e:
            print(f'OpenSSL Write Buffer too small. Error: {e}')
            return(False)

        return(True)

    def ewsprint(self):
        print(etree.tostring(self.esm, pretty_print=True))
        return

    def printdata(self):
        print(self.MODUL)
        print(self.DATA)
        print(self.REQUEST)
        print(self.ADATA)
        return()

