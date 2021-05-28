#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from moduls.etoolbox import readonecfg
import os
import sys

ecfgfile = os.path.dirname(os.path.abspath(__file__)).replace("/moduls", "") + os.sep + "ews.cfg"
logdir = readonecfg('MAIN', 'logdir', ecfgfile)

if logdir == "FALSE":
    print(f" => [ERROR] Logdir not exists or not configured in ews.cfg")
    sys.exit(1)

logging.basicConfig(filename=f"{logdir}/ews.log",
                    filemode="a",
                    format='%(asctime)s - [%(levelname)s] [%(name)s] - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG)

logger = logging.getLogger('elog')


if __name__ == "__main__":
    pass
