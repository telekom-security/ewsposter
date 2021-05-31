#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import configparser
import pprint
import sys
import argparse


class ELog:
    def __init__(self, modul):
        self.modul = modul
        self.init()
        self.logger = logging.getLogger(self.modul)
        logging.basicConfig(filename=f"{self.logdir}/ews.log",
                            filemode="a",
                            format='%(asctime)s - [%(levelname)s] [%(name)s] - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S',
                            level=logging.DEBUG)

    def init(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-c", "--configpath")
        args, _ = parser.parse_known_args()

        if args.configpath:
            ewsconfig = f'{args.configpath}/ews.cfg'
        else:
            ewsconfig = f"{os.path.dirname(os.path.abspath(__file__)).replace('/moduls', '')}/ews.cfg"

        if os.path.isfile(ewsconfig) is False:
            print(f" => [ERROR] Configfile {ewsconfig} didn't exist. Abort!")
            sys.exit(1)

        config = configparser.SafeConfigParser(os.environ)
        config.read(ewsconfig)

        if config.has_option('MAIN', 'logdir') is True:
            self.logdir = config.get('MAIN', 'logdir')
        else:
            print(f" => [ERROR] Logdir Parameter didn't exist in [MAIN] section. Abort!")
            sys.exit(1)

        if os.path.isdir(self.logdir) is False:
            print(f" => [ERROR] Logdir Path {self.logdir} didn't exist. Abort!")
            sys.exit(1)

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)
