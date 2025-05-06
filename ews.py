#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import sys

from modules.einit import locksocket, ecfg
from modules.elog import ELog
from modules.etoolbox import readMYcfg
from modules.ealert import EAlert
from modules.esend import ESend

from honeypots import (
    adbhoney, beelzebub, ciscoasa, citrix, conpot, cowrie, ddospot, dicompot, dionaea,
    elasticpot, emobility, endlessh, fatt, galah, glastopfv3, glutton, gopot, h0neytr4p,
    hellpot, heralding, honeyaml, honeypots, honeypy, honeysap, honeytrap, ipphoney,
    log4pot, mailoney, medpot, miniprint, rdpy, redishoneypot, sentrypeer, suricata,
    tanner, vnclowpot, wordpot
)

if __name__ == "__main__":

    name = "EWS Poster"
    version = "v1.32"

    functions = [adbhoney, beelzebub, ciscoasa, citrix, conpot, cowrie, ddospot, dicompot, dionaea,
                 elasticpot, emobility, endlessh, fatt, galah, glastopfv3, glutton, gopot, h0neytr4p,
                 hellpot, heralding, honeyaml, honeypots, honeypy, honeysap, honeytrap, ipphoney,
                 log4pot, mailoney, medpot, miniprint, rdpy, redishoneypot, sentrypeer, suricata,
                 tanner, vnclowpot, wordpot]

    ECFG = ecfg(name, version, functions)
    locksocket(name, ECFG['logdir'])
    logger = ELog('EMain')


    while True:
        if ECFG["a.ewsonly"] is False:
            ESend(ECFG)

        for honeypot in functions:
            honeypotname = honeypot.__name__

            if ECFG["a.modul"] and ECFG["a.modul"] == honeypotname:
               if readMYcfg(honeypotname.upper(), honeypotname, ECFG["cfgfile"]):
                   honeypot(ECFG)
                   break
            elif ECFG["a.modul"]:
                continue

            if readMYcfg(honeypotname.upper(), honeypotname, ECFG["cfgfile"]):
                honeypot(ECFG)

        if int(ECFG["a.loop"]) == 0:
            print(f" => EWSrun finish.")
            sys.exit(0)
        else:
            print(f" => Sleeping for {ECFG['a.loop']} seconds ...")
            time.sleep(int(ECFG["a.loop"]))
