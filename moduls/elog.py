#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

logging.basicConfig(filename=f"/work2/ewsposter/log/ews.log",
                    filemode="a",
                    format='%(asctime)s - [%(levelname)s] [%(name)s] - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG)

logger = logging.getLogger('elog')


if __name__ == "__main__":
    pass
