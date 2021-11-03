#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import configparser
import sys

class ELog:
    def __init__(self, modul):
        self.modul = modul
        self.init()
        logging.basicConfig(filename=f"{self.logdir}/ews.log",
                            filemode="a",
                            format='%(asctime)s - [%(levelname)s] [%(name)s] - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S',
                            level=logging.DEBUG)
        self.logger = logging.getLogger(self.modul)

    def init(self):

        if '-c' in sys.argv:
            configpath = sys.argv[sys.argv.index('-c') + 1]
        elif'--configpath' in sys.argv:
            configpath = sys.argv[sys.argv.index('--configpath') + 1]
        else:
            configpath = ''

        if configpath:
            ewsconfig = f'{configpath}/ews.cfg'
        else:
            ewsconfig = f"{os.path.dirname(os.path.abspath(__file__)).replace('/moduls', '')}/ews.cfg"

        if os.path.isfile(ewsconfig) is False:
            print(f" => [ERROR] Configfile {ewsconfig} didn't exist. Abort!")
            sys.exit(1)

        config = configparser.ConfigParser(os.environ)
        config.read(ewsconfig)

        if config.has_option('MAIN', 'logdir') is True:
            self.logdir = config.get('MAIN', 'logdir')
        else:
            print(f" => [ERROR] Logdir Parameter didn't exist in [MAIN] section. Abort!")
            sys.exit(1)

        if os.path.isdir(self.logdir) is False:
            print(f" => [ERROR] Logdir Path {self.logdir} didn't exist. Abort!")
            sys.exit(1)

    def debug(self, msg, handles=''):
        self.handle('debug', msg, handles)

    def info(self, msg, handles=''):
        self.handle('info', msg, handles)

    def warning(self, msg, handles=''):
        self.handle('warning', msg, handles)

    def error(self, msg, handles=''):
        self.handle('error', msg, handles)

    def handle(self, level, msg, handles):
        myerror = ''
        for index in ['debug', 'info', 'warning', 'error']:
            if level == index:
                myerror = f"[{level.upper()}]"
        print(f' => {myerror} {msg}') if '1' in handles else None
        print(f'    -> {myerror} {msg}') if '2' in handles else None
        self.logger.debug(msg) if level == 'debug' else None
        self.logger.info(msg) if level == 'info' else None
        self.logger.warning(msg) if level == 'warning' else None
        self.logger.error(msg) if level == 'error' else None
        sys.exit(1) if 'E' in handles else None
