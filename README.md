# EWSPOSTER

ews.py is a tool, written in Python, to **collect** log and alerts from
different honeypots (eg Glastopf, Honeytrap, Dionaea, Cowrie, Kippo, eMobility,
Conpot, Elasticpot, Mailoney, RDPY, VNClowPot, Heralding, Ciscoasa, Tanner and
Clutton ) and transmit them to Peba.


# Requirements
You need to install the libarys list in requirements.txt

    pip3 install -r requirements.txt

# Usage
Take a look at the usage text.

    ./ews.py -h
    usage: ews.py [-h] [-c CONFIGPATH] [-v] [-d] [-l LOOP]
              [-m {glastopfv3,dionaea,honeytrap,emobility,conpot,cowrie,elasticpot,suricata,rdpy,mailoney,
                   vnclowpot,heralding,ciscoasa,tanner,glutton,honeysap,adbhoney,fatt,ipphoney,dicompot,
                   medpot,honeypy}]
              [-s] [-i] [-S] [-E] [-j JSONPATH] [-L SENDLIMIT] [-V]

    optional arguments:
       -h, --help                                  show this help message and exit
       -c CONFIGPATH, --configpath CONFIGPATH      Load configuration file from Path
       -v, --verbose                               set output verbosity
       -d, --debug                                 set output debug
       -l LOOP, --loop LOOP                        endless loop. Set {xx} for seconds to wait for next loop
       -m, --modul {glastopfv3, dionaea,           only send alerts for this modul
                   honeytrap, emobility,
                   conpot, cowrie, elasticpot,
                   suricata, rdpy, mailoney,
                   vnclowpot, heralding,
                   ciscoasa, tanner, glutton,
                   honeysap, adbhoney, fatt,
                   ipphoney, dicompot, medpot,
                   honeypy}
       -s, --silent                                silent mode without output
       -i, --ignorecert                            ignore certificate warnings
       -S, --sendonly                              only send unsend alerts
       -E, --ewsonly                               only generate ews alerts files
       -j JSONPATH, --jsonpath JSONPATH            write JSON output file to path
       -L SENDLIMIT, --sendlimit SENDLIMIT         set {xxx} for max alerts will send in one session
       -V, --version                               show the EWS Poster Version

# Configuration
Take a look at the example **ews.cfg.default** and copy it via

    cp ews.cfg.default ews.cfg

# TODO's

# Usefull Links

