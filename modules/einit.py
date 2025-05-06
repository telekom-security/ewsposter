#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import argparse
import os
import ipaddress
import uuid
from modules.elog import ELog
from modules.etoolbox import getHostname, getIP, readMYcfg

logger = ELog('EInit')


def ecfg(name, version, functions):

    MODUL = "EINIT"
    ECFG = {
       'HONEYLIST': [func.__name__ for func in functions],
       'name': name,
       'version': version
    }
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--configpath", help="load configuration file from Path")
    parser.add_argument("-v", "--verbose", help="set output verbosity", action="store_true")
    parser.add_argument("-d", "--debug", help="set output debug", action="store_true")
    parser.add_argument("-l", "--loop", help="endless loop. Set {xx} for seconds to wait for next loop", type=int, default=0, action="store")
    parser.add_argument("-m", "--modul", help="only send alerts for this modul", choices=ECFG['HONEYLIST'], action="store")
    parser.add_argument("-s", "--silent", help="silent mode without output", action="store_true")
    parser.add_argument("-i", "--ignorecert", help="ignore certificate warnings", action="store_true")
    parser.add_argument("-S", "--sendonly", help="only send unsend alerts", action="store_true")
    parser.add_argument("-E", "--ewsonly", help="only generate ews alerts files", action="store_true")
    parser.add_argument("-j", "--jsonpath", help="write JSON output file to path")
    parser.add_argument("-L", "--sendlimit", help="set {xxx} for max alerts will send in one session", type=int, action="store")
    parser.add_argument("-V", "--version", help="show the EWS Poster Version", action="version", version=f"{name} {version}")

    args = parser.parse_args()

    ECFG["a.sendlimit"] = (args.sendlimit if args.sendlimit else 0)
    ECFG["a.loop"] = (args.loop if args.loop else 0)
    ECFG["a.verbose"] = (True if args.verbose else False)
    ECFG["a.debug"] = (True if args.debug else False)
    ECFG["a.ignorecert"] = (True if args.ignorecert else False)
    ECFG["a.silent"] = (True if args.silent else False)
    ECFG["a.sendonly"] = (True if args.sendonly else False)
    ECFG["a.ewsonly"] = (True if args.ewsonly else False)
    ECFG["a.modul"] = (args.modul if args.modul and args.modul in ECFG['HONEYLIST'] else "")
    ECFG["a.path"] = (args.configpath if args.configpath else "")
    ECFG["a.jsondir"] = (args.jsonpath if args.jsonpath else "")

    if ECFG["a.path"] != "" and not os.path.isdir(ECFG["a.path"]):
        logger.error(f"ConfigDir {ECFG['a.path']} from commandline argument -c/--configpath did not exist. Abort!", '1E')

    if ECFG["a.jsondir"] != "" and not os.path.isdir(ECFG["a.jsondir"]):
        logger.error(f"JsonDir {ECFG['a.jsondir']} from commandline argument -j/--jsonpath did not exist. Abort!", '1E')

    # say hello

    print(f"{name} {version} (c) by Markus Schroer <markus.schroer@telekom.de>")
    
    # read EWSPoster Main Path

    ECFG["path"] = os.path.dirname(os.path.abspath(__file__)).replace("/modules", "")

    if ECFG.get('a.path'):
        ECFG["path"] = ECFG["a.path"]

    if not os.path.isfile(ECFG["path"] + os.sep + "ews.cfg"):
        logger.error(f"Missing EWS Config {ECFG['path']}{os.sep}ews.cfg. Abort!", '1E')
    else:
        ECFG["cfgfile"] = ECFG["path"] + os.sep + "ews.cfg"

    # Create IDX File if not exist

    if not os.path.isfile(ECFG["path"] + os.sep + "ews.idx"):
        os.open(ECFG["path"] + os.sep + "ews.idx", os.O_RDWR | os.O_CREAT)
        logger.info(f"Create ews.idx counterfile.", '1')

    # Read Main Config Parameter

    ITEMS = ("homedir", "spooldir", "logdir", "del_malware_after_send", "send_malware",
             "sendlimit", "contact", "proxy", "ip_int", "ip_ext")

    MCFG = readMYcfg('MAIN', ITEMS, ECFG['cfgfile'])
   
    # home dir available?
    if not os.path.isdir(MCFG["homedir"]):
        logger.error(f"Missing homedir {MCFG['homedir']}. Abort!", '1E')
    else:
        os.chdir(MCFG["homedir"])

    # spool dir available?
    if not os.path.isdir(MCFG["spooldir"]):
        logger.error(f"Missing spooldir {MCFG['spooldir']}. Abort!", '1E')

    # log dir available?
    if not os.path.isdir(MCFG["logdir"]):
        logger.error(f"Missing logdir {MCFG['logdir']}. Abort!", '1E')
    else:
        MCFG["logfile"] = MCFG["logdir"] + os.sep + "ews.log"

    # del_malware_after_send?
    if MCFG["del_malware_after_send"].lower() == "true":
        MCFG["del_malware_after_send"] = True
    else:
        MCFG["del_malware_after_send"] = False

    # send_malware?
    if MCFG["send_malware"].lower() == "true":
        MCFG["send_malware"] = True
    else:
        MCFG["send_malware"] = False

    # sendlimit expect
    if int(ECFG["a.sendlimit"]) > 0:
        MCFG["sendlimit"] = ECFG["a.sendlimit"]
    if int(MCFG["sendlimit"]) > 5000:
        logger.error(f"Sendlimit {str(MCFG['sendlimit'])} to high. Max 5000!", '1E')
    elif int(MCFG["sendlimit"]) < 1:
        logger.error(f"Sendlimit {str(MCFG['sendlimit'])} to low. Min 1!", '1E')
    elif MCFG["sendlimit"] is None:
        logger.error(f"Sendlimit {str(MCFG['sendlimit'])}. Must set between 1 and 5000.", '1E')

    # Proxy Settings
    if MCFG["proxy"] == "" or MCFG["proxy"].lower() == "false" or MCFG["proxy"].lower() == "none":
        MCFG["proxy"] = False

    # ip_int and ip_ext
    if MCFG["ip_int"] != "" and MCFG["ip_int"].lower() != "none":
        try:
            ipaddress.ip_address(MCFG["ip_int"])
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.error(f"ip_int Address {str(e)} in [EWS] is not an IPv4/IPv6 address. Abort!", '1E')

    if MCFG["ip_ext"] != "" and MCFG["ip_ext"].lower() != "none":
        try:
            ipaddress.ip_address(MCFG["ip_ext"])
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.error(f"ip_ext Address {str(e)} in [EWS] config section is not an IPv4/IPv6 address. Abort!", '1E')

    # Read EWS Config Parameter

    ITEMS = ("ews", "username", "token", "rhost_first", "rhost_second", "ignorecert")
    EWSCFG = readMYcfg("EWS", ITEMS, ECFG["cfgfile"])

    if EWSCFG["ews"].lower() == "true":
        EWSCFG["ews"] = True
    else:
        EWSCFG["ews"] = False

    for index in ["username", "token", "rhost_first", "rhost_second"]:
        if EWSCFG[index] == "" and EWSCFG["ews"] is True:
            logger.error(f"Missing {index} in [EWS] config section. Abort!", '1E')

    if ECFG["a.ignorecert"] is True:
        EWSCFG["ignorecert"] = True
    elif EWSCFG["ignorecert"].lower() == "true":
        EWSCFG["ignorecert"] = True
    else:
        EWSCFG["ignorecert"] = False

    # Read HPFEED Config Parameter

    ITEMS = ("hpfeed", "host", "port", "channels", "ident", "secret", "hpfformat",
             "tlscert")

    HCFG = readMYcfg("HPFEED", ITEMS, ECFG["cfgfile"])

    if HCFG["hpfeed"].lower() == "true":
        HCFG["hpfeed"] = True

        for index in ["host", "port", "channels", "ident", "secret"]:
            if HCFG[index] == "" and HCFG["hpfeed"] is True:
                logger.error(f"Missing {index} in [HPFEED] config section. Abort!", '1E')

        if HCFG["hpfformat"].lower() not in ("ews", "json"):
            HCFG["hpfformat"] = "ews"

        if HCFG["tlscert"].lower() == "none" or HCFG["tlscert"] == "false":
            HCFG["tlscert"] = "none"
        elif os.path.isfile(HCFG["tlscert"]) is False:
            logger.error(f"Missing TLS cert {HCFG['tlscert']}. Use tlscert = none", '1')
            HCFG["tlscert"] = "none"
        else:
            logger.info(f"Use TLS cert {HCFG['tlscert']} for HPFeed transfer.", '1')

    else:
        HCFG["hpfeed"] = False

    # Read EWSJSON Config Parameter

    ITEMS = ("json", "jsondir")
    EWSJSON = readMYcfg("EWSJSON", ITEMS, ECFG["cfgfile"])

    if ECFG["a.jsondir"] != "":
        EWSJSON["json"] = True
        EWSJSON["jsondir"] = ECFG["a.jsondir"] + os.sep + "ews.json"

    elif EWSJSON["json"].lower() == "true":
        EWSJSON["json"] = True

        if os.path.isdir(EWSJSON["jsondir"]):
            EWSJSON["jsondir"] = EWSJSON["jsondir"] + os.sep + "ews.json"
        else:
            logger.error(f"Missing jsondir {EWSJSON['jsondir']} in [EWSJSON]. Abort!", '1E')

    else:
        EWSJSON["json"] = False

    # Read INFLUX Config Parameter

    ITEMS = ('influxdb', 'host', 'port', 'username', 'password', 'token', 'bucket', 'org')
    ICFG = readMYcfg("INFLUXDB", ITEMS, ECFG["cfgfile"], loghandler='')

    if 'influxdb' not in ICFG:
        ICFG['influxdb'] = False
    elif ICFG['influxdb'].lower() == "true":
        ICFG['influxdb'] = True
    else:
        ICFG['influxdb'] = False

    if ICFG.get('influxdb'):
        for index in ['host', 'port', 'username', 'password', 'token', 'bucket', 'org']:

            if ICFG[index] == '' and ICFG["influxdb"] is True:
                logger.error(f"Missing {index} in [INFLUXDB] config section. Abort!", '1E')
            else:
                ICFG['influx_' + index] = ICFG[index]
                ICFG[index] = ''

    ECFG.update(ICFG)
    ECFG.update(MCFG)
    ECFG.update(EWSCFG)
    ECFG.update(HCFG)
    ECFG.update(EWSJSON)

    # Setup UUID
    if os.environ.get('HONEY_UUID'):
        ECFG['uuid'] = os.environ.get('HONEY_UUID')
    else:
        if os.path.isfile(ECFG["path"] + os.sep + "ews.uuid"):
            with open(ECFG["path"] + os.sep + "ews.uuid", 'r') as filein:
                ECFG['uuid'] = str(filein.read())
        else:
            with open(ECFG["path"] + os.sep + "ews.uuid", 'w') as fileout:
                ECFG['uuid'] = str(uuid.uuid4())
                fileout.write(ECFG['uuid'])

    # Setup Hostname

    ECFG['hostname'] = getHostname(MODUL, ECFG)

    # Collection IP Config, Enviroment, lookup
    IPCFG = getIP(MODUL, ECFG)

    for place in ['ip_int', 'ip_ext']:
        for source in [f'env_{place}', f'file_{place}', f'connect_{place}']:
            if not ECFG[place] or ECFG[place].lower() == "none":
                ECFG[place] = IPCFG[source]
    
        if not ECFG[place] or ECFG[place].lower() == "none":
            logger.error(f"{place} is 'none' or empty. Abort!", '1E')

    return(ECFG)


def locksocket(name, logdir):
    # create lock socket

    global lock_socket
    lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        lock_socket.bind('\0' + name)
        print(f" => Create lock socket successfull.")
        return(True)
    except socket.error:
        logger.error(f"Another Instance is running! EWSrun finish.", '1E')
        return(False)


if __name__ == "__main__":
    pass
