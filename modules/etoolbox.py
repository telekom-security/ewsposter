#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.elog import ELog
import requests
import configparser
import ipaddress
import os
import random
import socket
import string

logger = ELog('Etoolbox')

def readMYcfg(MODUL, ITEMS, FILE, loghandler='1E'):
    result = {}

    config = configparser.ConfigParser(os.environ)
    config.read(FILE)
 
    if isinstance(ITEMS, str):
        if config.has_option(MODUL, ITEMS) and len(config.get(MODUL, ITEMS)) > 0:
            return(True)
        elif config.has_option(MODUL, ITEMS) and len(config.get(MODUL, ITEMS)) == 0:
            return(None)
        else:
            return(False)
        
    if isinstance(ITEMS, tuple):    
        for item in ITEMS:
            if config.has_option(MODUL, item) and len(config.get(MODUL, item)) > 0:
                result[item] = config.get(MODUL, item)
            elif loghandler == '1E':
                logger.error(f"Config MODUL [{MODUL}] parameter '{item}' didn't find or empty or not 'none' in {FILE} config file. Abort!", '1E')
        return(result)

def checkSECTIONcfg(MODUL, FILE):
    config = configparser.ConfigParser(os.environ)
    config.read(FILE)

    if config.has_section(MODUL):
        return(True)
    else:
        return(False)

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
    # get Hostname from ENV/SOCKET/RANDOM
    hostname = os.environ.get('MY_HOSTNAME')
    if hostname:
        return hostname
    return socket.gethostname() or f"host-{''.join(random.choices(string.ascii_lowercase, k=16))}"

if __name__ == "__main__":
    pass
