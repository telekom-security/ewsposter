#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import MySQLdb.cursors
import os
import sys

from moduls.elog import logme
from moduls.etoolbox import readcfg, readonecfg, calcminmax, countme

def sqlitedb(MODUL,DBPATH,ECFG):

    rows = []

    # is sqlitedb exist ?

    if os.path.isfile(DBPATH) == False:
        logme(MODUL,"[ERROR] Missing sqlitedb file " + DBPATH + ". Abort !",("P3","LOG"),ECFG)
        return 1, rows

    # open database

    try:
        con = sqlite3.connect(DBPATH,30)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

    except sqlite.Error as e:
        logme(MODUL,"[ERROR] Sqlite Error : %s . Abort !" % e.args[0],("P3","LOG"),ECFG)
        return 1, rows

    # calculate max alerts

    if MODUL == "GLASTOPFV3":
        cur.execute("SELECT max(id) from events")
        maxid = cur.fetchone()["max(id)"]
    elif MODUL == "DIONAEA":
        cur.execute("SELECT max(connection) from connections;")
        maxid = cur.fetchone()["max(connection)"]
    else:
        logme(MODUL,"[ERROR] Unknow Modul for Sqlite Database Access. Abort!",("P2","LOG"),ECFG)
        return 1, rows

    if maxid is None:
        logme(MODUL,"[ERROR] No entry's in Database %s. Abort!" % DBPATH,("P2","LOG"),ECFG)
        return 1, rows

    imin, imax = calcminmax(MODUL,int(countme(MODUL,'sqliteid',-1,ECFG)),int(maxid),ECFG)

    # read alerts from database

    if MODUL == "GLASTOPFV3":
        cur.execute("SELECT * from events where id > ? and id <= ?;",(imin,imax,))
    elif MODUL == "DIONAEA":
        cur.execute("SELECT * from connections where connection > ? and connection <= ?;",(imin,imax,))
    else:
        logme(MODUL,"[ERROR] Unknow Modul for Sqlite Database Access. Abort!",("P2","LOG"),ECFG)
        return 1, rows

    rows = cur.fetchall()
    con.close()

    return 0, rows


def mysqldb():

    try:
        con = MySQLdb.connect(host=HONEYPOT["mysqlhost"], user=HONEYPOT["mysqluser"], passwd=HONEYPOT["mysqlpw"],
                              db=HONEYPOT["mysqldb"], cursorclass=MySQLdb.cursors.DictCursor)
    except MySQLdb.Error as e:
        logme(MODUL,"[ERROR] %s" %(str(e)),("P3","LOG"),ECFG)
        return 

    c = con.cursor()

    # calculate send limit

    c.execute("SELECT max(id) from log")

    maxid = c.fetchone()["max(id)"]

    if maxid is None:
        logme(MODUL,"[ERROR] No entry's in Glastopf Database. Abort!",("P2","LOG"),ECFG)
        return

    imin, imax = calcminmax(MODUL,int(countme(MODUL,'sqliteid',-1)),int(maxid),ECFG)

    # read alerts from database

    c.execute("SELECT * from log where id > %s and id <= %s;",(imin,imax))
    rows = c.fetchall()

if __name__ == "__main__":
    pass