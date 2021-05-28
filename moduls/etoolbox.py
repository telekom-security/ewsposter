#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import os
import ipaddress
from requests import get
import socket
import random
import string
import sys
from moduls.elog import ELog

logger = ELog('Etoolbox', "/work2/ewsposter/log")

def readcfg(MODUL, ITEMS, FILE):

    result = {}

    config = configparser.SafeConfigParser(os.environ)
    config.read(FILE)

    for item in ITEMS:
        if config.has_option(MODUL, item) is True and len(config.get(MODUL, item)) > 0:
            result[item] = config.get(MODUL, item)
        else:
            msg = f'[ERROR] in Config MODUL [{MODUL}] parameter \'{item}\' didn\'t find or empty or not \'none\' in {FILE} config file. Abort!'
            print(f' => {msg}')
            logger.error(msg)
            sys.exit()

    return(result)

def checkSECTIONcfg(MODUL, FILE):

    config = configparser.SafeConfigParser(os.environ)
    config.read(FILE)

    if config.has_section(MODUL):
        return(True)
    else:
        return(False)

def checkITEMcfg(MODUL, ITEM, FILE):

    config = configparser.SafeConfigParser(os.environ)
    config.read(FILE)

    if config.has_section(MODUL) and config.has_section(ITEM):
        return(True)
    else:
        return(False)


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
        if checkSECTIONcfg("EWSIP", ECFG['path'] + os.sep + "ews.ip"):
            ipfile = dict(readcfg('EWSIP', ('ip_int', 'ip_ext'), ECFG["path"] + os.sep + "ews.ip"))
            for dic in ipfile:
                if ipfile[dic] != "" and ipfile[dic] is not None:
                    myIP['file_' + dic] = ipfile[dic]
                else:
                    myIP['file_' + dic] = ""

        elif checkSECTIONcfg("MAIN", "ews.ip"):
            ipfile = dict(readcfg('MAIN', ('ip',), ECFG['path'] + os.sep + "ews.ip"))
            myIP['file_ip_int'] = ""
            myIP['file_ip_ext'] = ipfile['ip']

        else:
            myIP['file_ip_int'] = ""
            myIP['file_ip_ext'] = ""
            msg = f'[ERROR] File ews.ip exist but not in an right format. Set to zero!'
            print(f' => {msg}')
            logger.error(msg)

    """ Read Enviroment Variables """
    for item, envvar in [['env_ip_int', 'MY_INTIP'], ['env_ip_ext', 'MY_EXTIP']]:
        if len(os.environ.get(envvar)) > 0:
            myIP[item] = os.environ.get(envvar)
            try:
                ipaddress.ip_address(myIP[item])
            except (ipaddress.AddressValueError, ValueError) as e:
                myIP[item] = ""
                msg = f"Error IP Adress {e} in Environment Variable is not an IPv4/IPv6 address Abort!"
                print(f' => {msg}')
                logger.error(msg)
        else:
            myIP[item] = ""

    """ Get local IP via connection """
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connection.connect(("9.9.9.9", 53))
        myIP["connect_ip_int"] = connection.getsockname()[0]
    except:
        msg = f'Could not determine a valid intern IP by Environment variable'
        print(f' => [ERROR] {msg}')
        logger.error(msg)
        myIP["connect_ip_int"] = ""
    finally:
        connection.close()

    """ get external IP via connection """
    try:
        myIP["connect_ip_ext"] = get('https://api.ipify.org', timeout=5).text
    except:
        msg = f'Could not determine a valid public IP using external service'
        print(f' => [ERROR] {msg}')
        logger.error(msg)
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
