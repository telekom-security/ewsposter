#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from moduls.etoolbox import readonecfg
import os

ecfgfile = os.path.dirname(os.path.abspath(__file__)).replace("/moduls", "") + os.sep + "ews.cfg"
logdir = readonecfg('MAIN', 'logdir', ecfgfile)

logging.basicConfig(filename=f"{logdir}/ews.log",
                    filemode="a",
                    format='%(asctime)s - [%(levelname)s] [%(name)s] - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG)

logger = logging.getLogger('elog')


if __name__ == "__main__":
    pass
