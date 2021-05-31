#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import requests
import ssl
import re
from moduls.elog import ELog

def ESend(ECFG):

    def clean_dir(spooldir):
        FILES = filelist(spooldir)

        for file in FILES:
            if ".ews" not in file:
                os.remove(spooldir + os.sep + file)
                logger.info(f"Cleaning spooler dir: {spooldir} delete file: {file}", '2')
        return()

    def check_job(spooldir):
        FILES = filelist(spooldir)

        if len(FILES) < 1:
            logger.info(f"No jobs to send in spooldir: {spooldir}.", '2')
            return(False)
        else:
            logger.info(f"There {str(len(FILES))} jobs to send in spooldir: {spooldir}", '2')
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
                logger.info(f'Cleaning spooler dir: {spooldir} delete file: {file}. Reached max transmit counter !', '2')
                os.remove(spooldir + os.sep + file)

    def filelist(spooldir):
        if os.path.isdir(spooldir) is not True:
            logger.error(f'Error missing spooldir {spooldir}. Abort!', '2E')
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
                logger.info('XML Result != ok ({xmlresult}) ({webservice.text})', '2')
                return(False)

            return(True)

        except requests.exceptions.Timeout:
            logger.warning(f'ewsWebservice Timeout to remote Host {host}', '2')
            return(False)

        except requests.exceptions.ConnectionError:
            logger.warning(f"ewsWebservice Remote Host {host} didn't answer!", '2')
            return(False)

        except requests.exceptions.HTTPError:
            logger.warning(f'ewsWebservice HTTP(S) Errorcode != 200', '2')
            return(False)

        except ssl.WantWriteError:
            logger.warning(f'ewsWebservice SSL Write Buffer too small', '2')
            return(False)

    """ Main instance for this Modul """
    logger = ELog('ESend')

    print(f' => ESend: checking spooldir and resend alert')
    clean_dir(ECFG["spooldir"])
    del_job(ECFG["spooldir"])

    if check_job(ECFG["spooldir"]) is False:
        return()

    send_job(ECFG["spooldir"])
