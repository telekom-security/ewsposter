#!/usr/bin/env python3

from moduls.elog import logme
import configparser
import re
import time
import os
import ipaddress
from requests import get
import socket
import random
import string
import sys


def countme(Section, Item, Count, ECFG):

    z = configparser.RawConfigParser()
    z.read(ECFG["homedir"] + os.sep + "ews.idx")

    if z.has_section(Section) is not True:
        z.add_section(Section)

    if z.has_option(Section, Item) is not True:
        z.set(Section, Item, 0)

    if Count >= 0:
        z.set(Section, Item, Count)
    elif Count == -2:
        z.set(Section, Item, str(int(z.get(Section, Item)) + 1))
    elif Count == -3:
        z.set(Section, Item, 0)

    with open(ECFG["homedir"] + os.sep + "ews.idx", 'w') as countfile:
        z.write(countfile)
        countfile.close

    if Count == -1:
        return(z.get(Section, Item))

    return


def calcminmax(MODUL, imin, imax, ECFG):

    if (imax - imin) > int(ECFG["sendlimit"]):
        logme(MODUL, "Need to send : " + str(imax - imin) + " limit is : " + str(ECFG["sendlimit"]) + ". Adapting to limit!", ("P1"), ECFG)
        imax = imin + int(ECFG["sendlimit"])

    return(imin, imax)


def timestamp():
    now = time.time()
    localtime = time.localtime(now)
    milliseconds = '%03d' % int((now - int(now)) * 1000)
    return time.strftime('%Y%m%dT%H%M%ST', localtime) + milliseconds


def ip4or6(ip):

    if re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip):
        return("4")
    else:
        return("6")


def readcfg(MODUL, ITEMS, FILE):

    result = {}

    config = configparser.SafeConfigParser(os.environ)
    config.read(FILE)

    for item in ITEMS:
        if config.has_option(MODUL, item) is True and len(config.get(MODUL, item)) > 0:
            result[item] = config.get(MODUL, item)
        else:       
            print(f'[ERROR] in Config MODUL [{MODUL}] parameter \'{item}\' didn\'t find or empty or not \'none\' in {FILE} config file. Abort !')
            sys.exit()

    if "ip" in result:
        result["ipv"] = ip4or6(result["ip"])

    return(result)


def readonecfg(MODUL, item, FILE):

    config = configparser.SafeConfigParser(os.environ)
    config.read(FILE)

    if config.has_option(MODUL, item) is True and len(config.get(MODUL, item)) > 0:
        return config.get(MODUL, item)
    elif config.has_option(MODUL, item) is True and len(config.get(MODUL, item)) == 0:
        return "NULL"
    elif config.has_option(MODUL, item) is False:
        return "FALSE"
    else:
        return "UNKNOW"


def getIP(MODUL, ECFG):
    myIP = {}

    """ Read ip from ews.ip file if exist """
    if os.path.isfile(ECFG["path"] + os.sep + "ews.ip"):
        ipfile = dict(readcfg('EWSIP', ('ip_int', 'ip_ext'), 'ews.ip'))

        for dic in ipfile:
            if ipfile[dic] != "" and ipfile[dic] is not None:
                myIP['file_' + dic] = ipfile[dic]
            else:
                myIP['file_' + dic] = ""

    """ Read Enviroment Variables """
    for item in ['env_ip_int', 'env_ip_ext']:

        if item == 'env_ip_int' and os.environ.get('MY_INTIP') is not None:
            myIP[item] = os.environ.get('MY_INTIP')

        if item == 'env_ip_ext' and os.environ.get('MY_EXTIP') is not None:
            myIP[item] = os.environ.get('MY_EXTIP')

        try:
            ipaddress.ip_address(myIP[item])
        except (ipaddress.AddressValueError, ValueError) as e:
            logme(MODUL, "Error IP Adress " + str(e) + " in Environment Variable is not an IPv4/IPv6 address " + " Abort !", ("P1"), ECFG)

    """ Get local IP via connection """
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connection.connect(("8.8.8.8", 53))
        myIP["connect_ip_int"] = connection.getsockname()[0]
    except:
        logme(MODUL, "[ERROR] Could not determine a valid intern IP by Environment variable", ("P1", "LOG"), ECFG)
        myIP["connect_ip_int"] = ""
    finally:
        connection.close()

    """ get external IP via connection """
    try:
        myIP["connect_ip_ext"] = get('https://api.ipify.org', timeout=5).text
    except:
        logme(MODUL, "[ERROR] Could not determine a valid public IP using external service", ("P1", "LOG"), ECFG)
        myIP["connect_ip_ext"] = ""
    finally:
        connection.close()

    return(myIP)


def getHostname(MODUL, ECFG):
    """ get Hostname from ENV/SOCKET/RANDOM """
    if os.environ.get('MY_HOSTNAME') is not None:
        return(os.environ.get('MY_HOSTNAME'))
    elif socket.gethostname() is not None:
        return(socket.gethostname())
    else:
        return("host-".join(random.choice(string.ascii_lowercase) for i in range(16)))


def resolveHost(host):
    """ resolve an IP, either from IP or hostname """
    try:
        return(ipaddress.IPv4Address(host))
    except Exception:
        if ipaddress.IPv4Address(socket.gethostbyname(host)):
            return(socket.gethostbyname(host))
        else:
            return(False)


def checkForPublicIP(ip):
    return ipaddress.ip_address(ip).is_global


if __name__ == "__main__":
    pass
