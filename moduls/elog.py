#!/usr/bin/env python3

import sys
import time

def logme(MODUL,MESSAGE,HANDLE,ECFG):

    if ECFG["a.silent"] is False:

        if "P0" in HANDLE:
            print(MESSAGE)

        if "P1" in HANDLE:
            print((" => " + MESSAGE))

        if "P2" in HANDLE:
            print(("    -> " + MESSAGE))

        if "P3" in HANDLE:
            print(("    => [" + MODUL + "] " + MESSAGE))

        if "VERBOSE" in HANDLE and ECFG["a.verbose"] is True:
            print(MESSAGE)
 
    if ECFG["a.debug"] is True and "DEBUG" in HANDLE:
        print(MESSAGE)

    if "LOG" in HANDLE:
        with open(ECFG["logfile"] ,"a") as logfile:
            logfile.write(time.strftime("%Y-%m-%d %H:%M:%S") + " [" + MODUL + "] " + MESSAGE + "\n")
            logfile.close()

    if "EXIT" in HANDLE:
        sys.exit()

    return


if __name__ == "__main__":
    pass
