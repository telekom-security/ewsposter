#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import requests
import sys
import ssl
import re
import logging
import moduls.elog

def ESend(ECFG):

    def clean_dir(spooldir):
        FILES = filelist(spooldir)

        for file in FILES:
            if ".ews" not in file:
                os.remove(spooldir + os.sep + file)
                print(f'    -> Cleaning spooler dir: {spooldir} delete file: {file}')
        return()

    def check_job(spooldir):
        FILES = filelist(spooldir)

        if len(FILES) < 1:
            print(f'    -> No jobs to send in spooldir: {spooldir}.')
            return(False)
        else:
            print(f'    -> There {str(len(FILES))} jobs to send in spooldir: {spooldir}')
            return(True)

    def send_job(spooldir):
        FILES = filelist(spooldir)

        for file in FILES:
            with open(spooldir + os.sep + file, 'r') as alert:
                EWSALERT = alert.read()
                alert.close()

            if ewsWebservice(EWSALERT) is True:
                os.remove(spooldir + os.sep + file)
            else:
                fileparts = file.split('.')

                if len(fileparts) == 3:
                    newname = f'{fileparts[0]}.{fileparts[1]}.1.{fileparts[2]}'
                else:
                    newname = f'{fileparts[0]}.{fileparts[1]}.{str(int(fileparts[2])+1)}.{fileparts[3]}'

                os.rename(spooldir + os.sep + file, spooldir + os.sep + newname)
        return()

    def del_job(spooldir):
        FILES = filelist(spooldir)

        for file in FILES:
            fileparts = file.split('.')
            if len(fileparts) == 4 and int(fileparts[2]) >= 10:
                msg = f'Cleaning spooler dir: {spooldir} delete file: {file}. Reached max transmit counter !'
                print(f'    -> {msg}')
                logger.info(msg)
                os.remove(spooldir + os.sep + file)

    def filelist(spooldir):
        if os.path.isdir(spooldir) is not True:
            msg = f'Error missing spooldir {spooldir}. Abort!'
            print(f'    -> {msg}')
            logger.error(msg)
            sys.exit()
        else:
            return(os.listdir(spooldir))

    def ewsWebservice(EWSALERT):
        headers = {'User-Agent': ECFG['name'] + " " + ECFG['version'],
                   'Content-type': 'text/xml',
                   'SOAPAction': '',
                   'Charset': 'UTF-8',
                   'Connection': 'close'}

        host = random.choice([ECFG["rhost_first"], ECFG["rhost_second"]])

        proxies = {}

        if ECFG['proxy'] is not False:
            if "https:" in ECFG["proxy"]:
                proxies = {"https": ECFG["proxy"]}
            elif "http:" in ECFG["proxy"]:
                proxies = {"http": ECFG["proxy"]}

        verify = (False if ECFG["a.ignorecert"] is True else True)

        try:
            webservice = requests.post(host,
                                       data=EWSALERT,
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
            logger.warning(f'ewsWebservice Timeout to remote Host {host}')
            return(False)

        except requests.exceptions.ConnectionError:
            logger.warning(f"ewsWebservice Remote Host {host} didn't answer!")
            return(False)

        except requests.exceptions.HTTPError:
            logger.warning(f'ewsWebservice HTTP(S) Errorcode != 200')
            return(False)

        except ssl.WantWriteError:
            logger.warning(f'ewsWebservice OpenSSL Write Buffer too small')
            return(False)

    """ Main instance for this Modul """
    logger = logging.getLogger('esend')

    print(f' => ESend: checking spooldir and resend alert')
    clean_dir(ECFG["spooldir"])
    del_job(ECFG["spooldir"])

    if check_job(ECFG["spooldir"]) is False:
        return()

    send_job(ECFG["spooldir"])
