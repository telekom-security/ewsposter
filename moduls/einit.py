#!/usr/bin/env python3

import configparser
import socket
import argparse
import os
import ipaddress

import sys

from moduls.elog import logme
from moduls.etoolbox import readcfg, readonecfg, getOwnExternalIP, getHostname, getOwnInternalIP


def ecfg(name, version):

    MODUL = "EINIT"
    ECFG = {}
    ECFG["HONEYLIST"] = ['glastopfv3', 'dionaea', 'honeytrap', 'emobility', 'conpot', 'cowrie',
                         'elasticpot', 'suricata', 'rdpy', 'mailoney', 'vnclowpot', 'heralding',
                         'ciscoasa', 'tanner', 'glutton', 'honeysap', 'adbhoney', 'fatt']

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--configpath", help="Load configuration file from Path")
    parser.add_argument("-v", "--verbose", help="set output verbosity", action="store_true")
    parser.add_argument("-d", "--debug", help="set output debug", action="store_true")
    parser.add_argument("-l", "--loop", help="Go in endless loop. Set {xx} for seconds to wait for next loop", type=int, default=0, action="store")
    parser.add_argument("-m", "--modul", help="only send alerts for this modul", choices=ECFG["HONEYLIST"], action="store")
    parser.add_argument("-s", "--silent", help="silent mode without output", action="store_true")
    parser.add_argument("-i", "--ignorecert", help="ignore certificate warnings", action="store_true")
    parser.add_argument("-S", "--sendonly", help="only send unsend alerts", action="store_true")
    parser.add_argument("-E", "--ewsonly", help="only generate ews alerts files", action="store_true")
    parser.add_argument("-j", "--jsonpath", help="Write JSON output file to path")
    parser.add_argument("-L", "--sendlimit", help="Set {xxx} for max alerts will send in one session", type=int, action="store")
    parser.add_argument("-V", "--version", help="show the EWS Poster Version", action="version", version=name + " " + version)

    args = parser.parse_args()

    ECFG["a.path"] = (args.configpath if args.configpath else "")
    ECFG["a.verbose"] = (True if args.verbose else False)
    ECFG["a.debug"] = (True if args.debug else False)
    ECFG["a.loop"] = (args.loop if args.loop else 0)
    ECFG["a.modul"] = (args.modul if args.modul and args.modul in ECFG["HONEYLIST"] else "")
    ECFG["a.silent"] = (True if args.silent else False)
    ECFG["a.ignorecert"] = (True if args.ignorecert else False)
    ECFG["a.silent"] = (True if args.silent else False)
    ECFG["a.sendonly"] = (True if args.sendonly else False)
    ECFG["a.ewsonly"] = (True if args.ewsonly else False)
    ECFG["a.modul"] = (args.modul if args.modul and args.modul in HONEYLIST else "")
    ECFG["a.path"] = (args.configpath if args.configpath else "")
    ECFG["a.jsondir"] = (args.jsonpath if args.jsonpath else "")
    ECFG["a.sendlimit"] = (args.sendlimit if args.sendlimit else "")

    if ECFG["a.path"] != "" and os.path.isdir(ECFG["a.path"]) is False:
        logme(MODUL, "ConfigDir %s did not exist. Abort !" % (ECFG["a.path"]), ("P1", "EXIT"), ECFG)

    if ECFG["a.jsondir"] != "" and os.path.isdir(ECFG["a.jsondir"]) is False:
        logme(MODUL, "JsonDir %s did not exist. Abort !" % (ECFG["a.jsondir"]), ("P1", "EXIT"), ECFG)

    """ say hello """

    logme(MODUL, name + " " + version + " (c) by Markus Schroer <markus.schroer@telekom.de>\n", ("P0"), ECFG)

    """ read EWSPoster Main Path """

    ECFG["path"] = os.path.dirname(os.path.abspath(__file__)).replace("/moduls", "")

    if ECFG["a.path"] != "":
        ECFG["path"] = ECFG["a.path"]

    if os.path.isfile(ECFG["path"] + os.sep + "ews.cfg") is False:
        logme(MODUL, "Missing EWS Config %s. Abort !" % (ECFG["path"] + os.sep + "ews.cfg"), ("P1", "EXIT"), ECFG)
    else:
        ECFG["cfgfile"] = ECFG["path"] + os.sep + "ews.cfg"

    """ Create IDX File if not exist """

    if os.path.isfile(ECFG["path"] + os.sep + "ews.idx") is False:
        os.open(ECFG["path"] + os.sep + "ews.idx", os.O_RDWR | os.O_CREAT)
        logme(MODUL, "Create ews.idx counterfile", ("P1"), ECFG)

    """ Read Main Config Parameter """

    ITEMS = ("homedir", "spooldir", "logdir", "del_malware_after_send", "send_malware",
             "sendlimit", "contact", "proxy", "ip")

    MCFG = readcfg("MAIN", ITEMS, ECFG["cfgfile"])

    """ home dir available ? """
    if os.path.isdir(MCFG["homedir"]) is False:
        logme(MODUL, "Error missing homedir " + MCFG["homedir"] + " Abort !", ("P1", "EXIT"), ECFG)
    else:
        os.chdir(MCFG["homedir"])

    """ spool dir available ? """
    if os.path.isdir(MCFG["spooldir"]) is False:
        logme(MODUL, "Error missing spooldir " + MCFG["spooldir"] + " Abort !", ("P1", "EXIT"), ECFG)

    """ log dir available ? """
    if os.path.isdir(MCFG["logdir"]) is False:
        logme(MODUL, "Error missing logdir " + MCFG["logdir"] + " Abort !", ("P1", "EXIT"), ECFG)
    else:
        MCFG["logfile"] = MCFG["logdir"] + os.sep + "ews.log"

    """ del_malware_after_send ? """
    if MCFG["del_malware_after_send"].lower() == "true":
        MCFG["del_malware_after_send"] = True
    else:
        MCFG["del_malware_after_send"] = False

    """ send_malware ? """
    if MCFG["send_malware"].lower() == "true":
        MCFG["send_malware"] = True
    else:
        MCFG["send_malware"] = False

    """ sendlimit expect """
    if int(ECFG["a.sendlimit"]) != 0:
        MCFG["sendlimit"] = ECFG["a.sendlimit"]

    if int(MCFG["sendlimit"]) > 500:
        logme(MODUL, "Error Sendlimit " + str(MCFG["sendlimit"]) + " to high. Max 500 ! ", ("P1", "EXIT"), ECFG)
    elif int(MCFG["sendlimit"]) < 1:
        logme(MODUL, "Error Sendlimit " + str(MCFG["sendlimit"]) + " to low. Min 1 ! ", ("P1", "EXIT"), ECFG)
    elif MCFG["sendlimit"] is None:
        logme(MODUL, "Error Sendlimit " + str(MCFG["sendlimit"]) + " Must set between 1 and 500. ", ("P1", "EXIT"), ECFG)

    """ contact """

    """ Proxy Settings """
    if MCFG["proxy"] == "" or MCFG["proxy"].lower() == "false" or MCFG["proxy"].lower() == "none":
        MCFG["proxy"] = False

    """ ip """
    if MCFG["ip"] != "" and MCFG["ip"].lower() != "none":
        try:
            ipaddress.ip_address(MCFG["ip"])        
        except (ipaddress.AddressValueError, ValueError) as e:
            logme(MODUL, "Error IP Adress " + str(e) + " in [EWS] is not an IPv4/IPv6 address " + " Abort !", ("P1", "EXIT"), ECFG)

    """ Read EWS Config Parameter """

    ITEMS = ("ews", "username", "token", "rhost_first", "rhost_second", "ignorecert")
    EWSCFG = readcfg("EWS", ITEMS, ECFG["cfgfile"])

    """ Set ews real true or false """

    if EWSCFG["ews"].lower() == "true":
        EWSCFG["ews"] = True
    else:
        EWSCFG["ews"] = False

    for index in ["username", "token", "rhost_first", "rhost_second"]:
        if EWSCFG[index] == "" and EWSCFG["ews"] is True:
            logme(MODUL, "Error missing " + index + " in [EWS] Config Section " + " Abort !", ("P1", "EXIT"), ECFG)

    if ECFG["a.ignorecert"] is True:
        EWSCFG["ignorecert"] = True
    elif EWSCFG["ignorecert"].lower() == "true":
        EWSCFG["ignorecert"] = True
    else:
        EWSCFG["ignorecert"] = False

    """ Read HPFEED Config Parameter """

    ITEMS = ("hpfeed", "host", "port", "channels", "ident", "secret", "hpfformat",
             "tlscert")

    HCFG = readcfg("HPFEED", ITEMS, ECFG["cfgfile"])

    if HCFG["hpfeed"].lower() == "true":
        HCFG["hpfeed"] = True
    else:
        HCFG["hpfeed"] = False

    for index in ["host", "port", "channels", "ident", "secret"]:
        if HCFG[index] == "" and HCFG["hpfeed"] is True:
            logme(MODUL, "Error missing " + index + " in [HPFEED] Config Section " + " Abort !", ("P1", "EXIT"), ECFG)

    if HCFG["hpfformat"].lower() not in ("ews", "json"):
        HCFG["hpfformat"] = "ews"

    if HCFG["tlscert"].lower() == "false":
        HCFG["tlscert"] = False
    elif os.path.isfile(HCFG["tlscert"]) is False:
        logme(MODUL, "Error missing TLS cert " + HCFG["tlscert"] + " Abort !", ("P1", "EXIT"), ECFG)

    """ Read EWSJSON Config Parameter """

    ITEMS = ("json", "jsondir")
    EWSJSON = readcfg("EWSJSON", ITEMS, ECFG["cfgfile"])

    if ECFG["a.jsondir"] != "":
        EWSJSON["json"] = True
        EWSJSON["jsondir"] = ECFG["a.jsondir"] + os.sep + "ews.json"

    elif EWSJSON["json"].lower() == "true":
        EWSJSON["json"] = True

        if os.path.isdir(EWSJSON["jsondir"]) is True:
            EWSJSON["jsondir"] = EWSJSON["jsondir"] + os.sep + "ews.json"
        else:
            logme(MODUL, "Error missing jsondir " + EWSJSON["jsondir"] + " Abort !", ("P1", "EXIT"), ECFG)

    else:
        EWSJSON["json"] = False

    if ECFG["a.jsondir"] != "" and os.path.isdir(ECFG["a.jsondir"]) is True:
        EWSJSON["json"] = True
        EWSJSON["jsondir"] = ECFG["a.jsondir"] + os.sep + "ews.json"

    ECFG.update(MCFG)
    ECFG.update(EWSCFG)
    ECFG.update(HCFG)
    ECFG.update(EWSJSON)

    """ Collection Hostname, intern and extern IP """

    IPCFG = {}

    """ Setup Hostname """
    IPCFG["hostname"] = getHostname(MODUL, ECFG)
    print("Hostname",IPCFG["hostname"])
    print("InternalIP",getOwnInternalIP(MODUL, ECFG))
    print("ExternalIP",getOwnExternalIP(MODUL, ECFG))

    sys.exit("AUS")


    return(ECFG)


def locksocket(name):

    """ create lock socket """

    global lock_socket

    lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        lock_socket.bind('\0' + name)
        return(True)
    except socket.error:
        print("could not bind socket")
        return(False)


if __name__ == "__main__":
    pass
