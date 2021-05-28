#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging


class ELog:
    def __init__(self, modul, logpath):
        self.modul = modul
        self.logpath = logpath
        self.logger = logging.getLogger(self.modul)
        logging.basicConfig(filename=f"{self.logpath}/ews.log",
                            filemode="a",
                            format='%(asctime)s - [%(levelname)s] [%(name)s] - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S',
                            level=logging.DEBUG)

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)
