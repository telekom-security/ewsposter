#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from moduls.elog import ELog
import requests
import configparser
import ipaddress
import os
import random
import socket
import string

logger = ELog('Etoolbox')


def readcfg(MODUL, ITEMS, FILE):
    result = {}

    config = configparser.SafeConfigParser(os.environ)
    config.read(FILE)

    for item in ITEMS:
        if config.has_option(MODUL, item) is True and len(config.get(MODUL, item)) > 0:
            result[item] = config.get(MODUL, item)
        else:
            logger.error(f"Config MODUL [{MODUL}] parameter '{item}' didn't find or empty or not 'none' in {FILE} config file. Abort!", '1E')

    return(result)


def readcfg2(MODUL, ITEMS, FILE):
    result = {}

    config = configparser.SafeConfigParser(os.environ)
    config.read(FILE)

    for item in ITEMS:
        if config.has_option(MODUL, item) is True and len(config.get(MODUL, item)) > 0:
            result[item] = config.get(MODUL, item)
    return(result)


def checkSECTIONcfg(MODUL, FILE):
    config = configparser.SafeConfigParser(os.environ)
    config.read(FILE)

    if config.has_section(MODUL):
        return(True)
    else:
        return(False)


def readonecfg(MODUL, item, FILE):
    config = configparser.SafeConfigParser(os.environ)
    config.read(FILE)

    if config.has_option(MODUL, item) is True and len(config.get(MODUL, item)) > 0:
        return config.get(MODUL, item)
    elif config.has_option(MODUL, item) is True and len(config.get(MODUL, item)) == 0:
        return('NULL')
    elif config.has_option(MODUL, item) is False:
        return('FALSE')
    else:
        return ('UNKNOW')


def getIP(MODUL, ECFG):
    myIP = {}

    """ Read ip from ews.ip file if exist """
    myIP['file_ip_int'] = ""
    myIP['file_ip_ext'] = ""
    if os.path.isfile(ECFG["path"] + os.sep + "ews.ip"):
        if checkSECTIONcfg("EWSIP", ECFG['path'] + os.sep + "ews.ip"):
            ipfile = dict(readcfg('EWSIP', ('ip_int', 'ip_ext'), ECFG["path"] + os.sep + "ews.ip"))
            for dic in ipfile:
                if ipfile[dic] != "" and ipfile[dic] is not None:
                    myIP['file_' + dic] = ipfile[dic]

        elif checkSECTIONcfg("MAIN", "ews.ip"):
            ipfile = dict(readcfg('MAIN', ('ip',), ECFG['path'] + os.sep + "ews.ip"))
            myIP['file_ip_ext'] = ipfile['ip']

        else:
            logger.info(f"File ews.ip exist but not in an right format. Set to zero!", '1')

    """ Read Enviroment Variables """
    for item, envvar in [['env_ip_int', 'MY_INTIP'], ['env_ip_ext', 'MY_EXTIP']]:
        if os.environ.get(envvar) is not None:
            myIP[item] = os.environ.get(envvar)
            try:
                ipaddress.ip_address(myIP[item])
            except (ipaddress.AddressValueError, ValueError) as e:
                myIP[item] = ""
                logger.error(f"Error IP Adress {e} in Environment Variable is not an IPv4/IPv6 address Abort!", '1')
        else:
            myIP[item] = ""

    """ Get local IP via connection """
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connection.connect(("9.9.9.9", 53))
        myIP["connect_ip_int"] = connection.getsockname()[0]
    except socket.error as e:
        logger.error(f'Could not determine a valid intern IP by socket connection {e}', '1')
        myIP["connect_ip_int"] = ""
    finally:
        connection.close()

    """ get external IP via connection """
    try:
        myIP["connect_ip_ext"] = requests.get('https://api.ipify.org', timeout=10).text
    except requests.exceptions.Timeout:
        logger.error(f'Timeout to get extern IP via https://api.ipify.org!', '1')
        myIP["connect_ip_ext"] = ""
    except requests.exceptions.TooManyRedirects:
        logger.error(f'TooManyRedirects to get extern IP via https://api.ipify.org!', '1')
        myIP["connect_ip_ext"] = ""
    except requests.exceptions.HTTPError:
        logger.error(f'Could not determine a valid public IP using external service', '1')
        myIP["connect_ip_ext"] = ""
    except requests.exceptions.RequestException as e:
        logger.error(f'RequestException to get extern IP via https://api.ipify.org!', '1')
        myIP["connect_ip_ext"] = ""
        raise SystemExit(e)
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


if __name__ == "__main__":
    pass
