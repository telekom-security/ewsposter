#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser

class EAlert:

    def __init__(self,MODUL):
        self.MODUL = MODUL
        self.cfg = {}
        self.counter = 0
        self.counter_hundert = 0

