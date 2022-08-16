# EWSPOSTER

**EWSPoster** is a tool, written in Python to, to **collect logs** and **alers** from differents honeypots (eq [Glastopf v3](https://github.com/mushorg/glastopf), [Dionaea](https://github.com/DinoTools/dionaea), [Honeytrap](https://github.com/tillmannw/honeytrap), [eMobility](https://github.com/telekom-security/emobility), [Conpot](https://github.com/mushorg/conpot), [Cowrie](https://github.com/cowrie/cowrie), [Elasticpot](https://gitlab.com/bontchev/elasticpot), [Rdpy](https://github.com/citronneur/rdpy), [Mailoney](https://github.com/awhitehatter/mailoney), [Vnclowpot](https://github.com/magisterquis/vnclowpot), [Heralding](https://github.com/johnnykv/heralding), [Ciscoasa](https://github.com/Cymmetria/ciscoasa_honeypot), [Tanner](https://github.com/mushorg/tanner), [Snare](https://github.com/mushorg/snare), [Glutton](https://github.com/mushorg/glutton), [Honeysap](https://github.com/SecureAuthCorp/HoneySAP), [Adbhoney](https://github.com/huuck/ADBHoney), [Ipphoney](https://gitlab.com/bontchev/ipphoney), [Dicompot](https://github.com/nsmfoo/dicompot), [Medpot](https://github.com/schmalle/medpot), [Honeypy](https://github.com/foospidy/HoneyPy), [Citrixhoneypot](https://github.com/MalwareTech/CitrixHoneypot), [redishoneypot](https://github.com/cypwnpwnsocute/RedisHoneyPot), [endlessh](https://github.com/skeeto/endlessh)), [sentrypeer](https://github.com/SentryPeer/SentryPeer), [log4pot](https://github.com/thomaspatzke/Log4Pot) also network IDS (eg [Suricata](https://github.com/OISF/suricata), [Fatt](https://github.com/0x4D31/fatt)) and transmit them to InfluxDb, JSON, Hpfeed or an Honeypot backend (eg [Peba](https://github.com/telekom-security/PEBA) or Geba).

# Requirements
You need to install the libarys list in requirements.txt

    pip3 install -r requirements.txt

# Usage
Take a look at the usage text.

    ./ews.py -h
    usage: ews.py [-h] [-c CONFIGPATH] [-v] [-d] [-l LOOP]
              [-m {glastopfv3,dionaea,honeytrap,emobility,conpot,cowrie,elasticpot,suricata,rdpy,mailoney,
                   vnclowpot,heralding,ciscoasa,tanner,glutton,honeysap,adbhoney,fatt,ipphoney,dicompot,
                   medpot,honeypy,citrix,redishoneypot,endlessh,sentrypeer,log4pot}]
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
                   honeypy, citrix, redishoneypot,
                   endlessh, sentrypeer, log4pot}
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


