#!/usr/bin/env python3

import configparser
import socket
import argparse
import os
import sys
import time
from moduls.elog import logme
from moduls.etoolbox import readcfg, readonecfg, getOwnExternalIP, getHostname


def ecfg(name, version):

    MODUL = "EINIT"
    ECFG = {}
    HONEYLIST = ['glastopfv3', 'dionaea', 'honeytrap', 'emobility', 'conpot', 'cowrie',
                 'elasticpot', 'suricata', 'rdpy', 'mailoney', 'vnclowpot', 'heralding',
                 'ciscoasa', 'tanner', 'glutton', 'honeysap', 'adbhoney', 'fatt']

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--configpath", help="Load configuration file from Path")
    parser.add_argument("-v", "--verbose", help="set output verbosity", action="store_true")
    parser.add_argument("-d", "--debug", help="set output debug", action="store_true")
    parser.add_argument("-l", "--loop", help="Go in endless loop. Set {xx} for seconds to wait for next loop", type=int, default=0, action="store")
    parser.add_argument("-m", "--modul", help="only send alerts for this modul", choices=HONEYLIST, action="store")
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
    ECFG["a.modul"] = (args.modul if args.modul and args.modul in HONEYLIST else "")
    ECFG["a.silent"] = (True if args.silent else False)
    ECFG["a.ignorecert"] = (True if args.ignorecert else False)
    ECFG["a.sendonly"] = (True if args.sendonly else False)
    ECFG["a.ewsonly"] = (True if args.ewsonly else False)
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

    if ECFG["a.path"] == "":
        ECFG["a.path"] = ECFG["path"]

    if os.path.isfile(ECFG["a.path"] + os.sep + "ews.cfg") is False:
        logme(MODUL, "Missing EWS Config %s. Abort !" % (ECFG["a.path"] + os.sep + "ews.cfg"), ("P1", "EXIT"), ECFG)
    else:
        ECFG["cfgfile"] = ECFG["a.path"] + os.sep + "ews.cfg"

    """ Create IDX File if not exist """

    if os.path.isfile(ECFG["a.path"] + os.sep + "ews.idx") is False:
        os.open(ECFG["a.path"] + os.sep + "ews.idx", os.O_RDWR | os.O_CREAT)
        logme(MODUL, "Create ews.idx counterfile", ("P1"), ECFG)

    """ Read Main Config Parameter """

    ITEMS = ("homedir", "spooldir", "logdir", "contact",
             "del_malware_after_send", "send_malware", "sendlimit")
    MCFG = readcfg("MAIN", ITEMS, ECFG["cfgfile"])

    """ Setup Hostname """
    MCFG["hostname"] = getHostname()

    """ IP Handling """

    """ try to determine the external IP """
    MCFG["ip"] = getOwnExternalIP(ECFG)

    if not MCFG["ip"]:
        logme(MODUL, "External IP address cannot be determined. Set external IP in ews.cfg, ews.ip or env variable MY_EXTIP or allow external api request.. Abort !", ("P1", "EXIT"), ECFG)

    logme(MODUL, "Using external IP address " + str(MCFG["ip"]), ("P1", "Log"), ECFG)

    """ sendlimit expect """

    if ECFG["a.sendlimit"] != "":
        MCFG["sendlimit"] = ECFG["a.sendlimit"]

    if int(MCFG["sendlimit"]) > 500:
        logme(MODUL, "Error Sendlimit " + str(MCFG["sendlimit"]) + " to high. Max 500 ! ", ("P1", "EXIT"), ECFG)
    elif int(MCFG["sendlimit"]) < 1:
        logme(MODUL, "Error Sendlimit " + str(MCFG["sendlimit"]) + " to low. Min 1 ! ", ("P1", "EXIT"), ECFG)
    elif MCFG["sendlimit"] == "NULL" or str(MCFG["sendlimit"]) == "UNKNOW":
        logme(MODUL, "Error Sendlimit " + str(MCFG["sendlimit"]) + " Must set between 1 and 500. ", ("P1", "EXIT"), ECFG)

    """ send_malware ? """

    if MCFG["send_malware"].lower() == "true":
        MCFG["send_malware"] = True
    else:
        MCFG["send_malware"] = False

    """ del_malware_after_send ? """

    if MCFG["del_malware_after_send"].lower() == "true":
        MCFG["del_malware_after_send"] = True
    else:
        MCFG["del_malware_after_send"] = False

    """ home dir available ? """

    if os.path.isdir(MCFG["homedir"]) is not True:
        logme(MODUL, "Error missing homedir " + MCFG["homedir"] + " Abort !", ("P1", "EXIT"), ECFG)
    else:
        os.chdir(MCFG["homedir"])

    """ spool dir available ? """

    if os.path.isdir(MCFG["spooldir"]) is not True:
        logme(MODUL, "Error missing spooldir " + MCFG["spooldir"] + " Abort !", ("P1", "EXIT"), ECFG)

    # log dir available ?

    MCFG["logdir"] = readonecfg("MAIN", "logdir", ECFG["cfgfile"])

    if MCFG["logdir"] != "NULL" and MCFG["logdir"] != "FALSE" and os.path.isdir(MCFG["logdir"]) is True:
        MCFG["logfile"] = MCFG["logdir"] + os.sep + "ews.log"
    elif MCFG["logdir"] != "NULL" and MCFG["logdir"] != "FALSE" and os.path.isdir(MCFG["logdir"]) is True:
        logme(MODUL, "Error missing logdir " + MCFG["logdir"] + " Abort !", ("P1", "EXIT"), ECFG)
    else:
        MCFG["logfile"] = "/var/log" + os.sep + "ews.log"

    """ Proxy Settings ? """

    MCFG["proxy"] = readonecfg(MODUL, "proxy", ECFG["cfgfile"])

    """ Read EWS Config Parameter """

    ITEMS = ("ews", "username", "token", "rhost_first", "rhost_second")
    EWSCFG = readcfg("EWS", ITEMS, ECFG["cfgfile"])

    """ Set ews real true or false """

    if EWSCFG["ews"].lower() == "true":
        EWSCFG["ews"] = True
    else:
        EWSCFG["ews"] = False

    """ ignore cert validation if ignorecert-parameter is set """

    EWSCFGCERT = readonecfg("EWS", "ignorecert", ECFG["cfgfile"])

    if EWSCFGCERT.lower() == "true":
        ECFG["a.ignorecert"] = True

    """ Read HPFEED Config Parameter """

    ITEMS = ("hpfeed", "host", "port", "channels", "ident", "secret")
    HCFG = readcfg("HPFEED", ITEMS, ECFG["cfgfile"])

    if HCFG["hpfeed"].lower() == "true":
        HCFG["hpfeed"] = True
    else:
        HCFG["hpfeed"] = False

    """ hpfeeds format """

    EWSHPFFORMAT = readonecfg("HPFEED", "hpfformat", ECFG["cfgfile"])

    if EWSHPFFORMAT.lower() in ("ews", "json"):
        ECFG["hpfformat"] = EWSHPFFORMAT.lower()
    else:
        ECFG["hpfformat"] = "ews"

    """ hpfeeds tls cert """

    EWSHPFCERT = readonecfg("HPFEED", "tlscert", ECFG["cfgfile"])

    if EWSHPFCERT and EWSHPFCERT.lower() != "":
        ECFG["tlscert"] = EWSHPFCERT.lower()

    """ Read EWSJSON Config Parameter """

    ITEMS = ("json", "jsondir")
    EWSJSON = readcfg("EWSJSON", ITEMS, ECFG["cfgfile"])

    if EWSJSON["json"].lower() == "true":
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

    return ECFG


def locksocket(name):

    """ create lock socket """

    global lock_socket

    lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        lock_socket.bind('\0' + name)
        return True
    except socket.error:
        print("could not bind socket")
        return False


if __name__ == "__main__":
    pass
