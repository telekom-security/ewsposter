#!/usr/bin/env python3

from lxml import etree
import sys
import time
import urllib.request, urllib.parse, urllib.error

def ewsauth(username,token):

    esm = etree.Element("EWS-SimpleMessage", version="3.0")

    Auth = etree.SubElement(esm,"Authentication")
    etree.SubElement(Auth,"username").text = username
    etree.SubElement(Auth,"token").text = token

    return esm

def ewsalert(esm,DATA,REQUEST,ADATA):

    if "honeytrap" in REQUEST['description'].lower():
        timezone="+0000"
    else:
        timezone = time.strftime('%z')

    Alert = etree.SubElement(esm,"Alert")
    etree.SubElement(Alert,"Analyzer",id=DATA["aid"])
    etree.SubElement(Alert,"CreateTime",tz=timezone).text= DATA["timestamp"]
    etree.SubElement(Alert,"Source",category=DATA["sipv"],port=DATA["sport"],protocol=DATA["sprot"]).text = DATA["sadr"]
    etree.SubElement(Alert,"Target",category=DATA["tipv"],port=DATA["tport"],protocol=DATA["tprot"]).text = DATA["tadr"]
    #etree.SubElement(Alert,"Request",type=urllib.quote(DATA["rtype"]),text=urllib.quote(DATA["rtext"])).text = urllib.quote(DATA["request"])
    #etree.SubElement(Alert,"Request",type=urllib.quote(DATA["rtype"])).text = DATA["request"]
    #
    #if "rtype2" and "request2" in DATA:
    #    etree.SubElement(Alert,"Request",type=urllib.quote(DATA["rtype2"])).text = DATA["request2"]

    for key, value in list(REQUEST.items()):
        etree.SubElement(Alert,"Request",type=key).text = value

    if "corigin" and "cident" and "ctext" in DATA:
        etree.SubElement(Alert,"Classification",origin=DATA["corigin"],ident=DATA["cident"],text=DATA["ctext"])

    for key, value in list(ADATA.items()):

        if type(value) is int:
            mytype = "integer"
        elif type(value) is str:
            mytype = "string"
        else:
            mytype = "string"

        etree.SubElement(Alert,"AdditionalData",type=mytype,meaning=key).text = urllib.parse.quote(str(value).encode('ascii', 'ignore'))

    return esm

if __name__ == "__main__":

    DATA = {
                 "aid"       : "4711",
                 "aname"     : "testid",
                 "timestamp" : "2013-06-01 13:59:59",
                 "sadr"      : "1.2.3.4",
                 "sipv"      : "ipv4-addr",
                 "sprot"     : "tcp",
                 "sport"     : "129843",
                 "tident"    : "Dionaea",
                 "tipv"      : "ipv4-addr",
                 "tadr"      : "6.7.8.9",
                 "sident"    : "multi",
                 "tprot"     : "tcp",
                 "tport"     : "80",
                }

    REQUEST = { "describtion" : "Network Honeypot Dionaea",
                "binary"      : "W01BSU5dCmhvbWVkaXIgPSAvb3B0L2V3c3Bvc3RlcgpzcG9vbGRpciA9IC9vcHQvZXdzcG9zdGVyL3Nwb29sCmxvZ2RpciA9IC9vcHQvZXdzcG9zdGVyCmRlbF9tYWx3YXJlX2FmdGVyX3NlbmQgPSBmYWxzZQpzZW5kX21hbHdhcmUgPSB0cnVlCnNlbmRsaW1pdCA9IDQwMApjb250YWN0ID0gc2VuZGVyQGV4YW1wbGUuY29tCnByb3h5ID0gCmlwID0gMS4yLjMuNAoKW0VXU10KZXdzID0gdHJ1ZQp1c2VybmFtZSA9IDx5b3VyIGV3cyBwb3J0YWwgdXNlcm5hbWU+CnRva2VuID0gPHlvdXIgZXdzIHBvcnRhbCB0b2tlbj4Kcmhvc3RfZmlyc3QgPSBodHRwczovLzx5b3VyIGV3cyBwb3J0YWwgMT4Kcmhvc3Rfc2Vjb25kID0gaHR0cHM6Ly88eW91ciBld3MgcG9ydGFsIDI+CgpbSFBGRUVEXQpocGZlZWQgPSBmYWxzZQpob3N0ID0gbG9jYWxob3N0CnBvcnQgPSAxMzM3CmNoYW5uZWxzID0gdGVzdAppZGVudCA9IHVzZXJuYW1lCnNlY3JldD0gcGFzc3dvcnQKCltFV1NKU09OXQpqc29uID0gdHJ1ZQpqc29uZGlyID0gL29wdC9ld3Nwb3N0ZXIvanNvbgoKW0dMQVNUT1BGVjNdCmdsYXN0b3BmdjMgPSB0cnVlCm5vZGVpZCA9IDx5b3VyIHVuaXF1ZSBhbmFseXplciBpZD4Kc3FsaXRlZGIgPSAvb3B0L2hvbmV5cG90L2dsYXN0b3BmL2RhdGEvZGIvZ2xhc3RvcGYuZGIKbWFsd2FyZWRpciA9IC9vcHQvaG9uZXlwb3QvZ2xhc3RvcGYvZGF0YS9maWxlcwoKW0dMQVNUT1BGVjJdCmdsYXN0b3BmdjIgPSBmYWxzZQpub2RlaWQgPSAgPHlvdXIgdW5pcXVlIGFuYWx5emVyIGlkPgpteXNxbGhvc3QgPSBsb2NhbGhvc3QKbXlzcWxkYiA9IDx5b3VyIG15c3FsIGRiIGZvciBraXBwbz4KbXlzcWx1c2VyID0gPHlvdXIgdXNlciBmb3IgdGhpcyBkYj4KbXlzcWxwdyA9IDx5b3VyIHBhc3N3b3JkPgptYWx3YXJlZGlyID0gL29wdC9ld3Nwb3N0ZXIvbWFsd2FyZQoKW0tJUFBPXQpraXBwbyA9IGZhbHNlCm5vZGVpZCA9ICA8eW91ciB1bmlxdWUgYW5hbHl6ZXIgaWQ+Cm15c3FsaG9zdCA9IGxvY2FsaG9zdApteXNxbGRiID0gPHlvdXIgbXlzcWwgZGIgZm9yIGdsYXN0b3BmPgpteXNxbHVzZXIgPSA8eW91ciB1c2VyIGZvciB0aGlzIGRiPgpteXNxbHB3ID0gPHlvdXIgcGFzc3dvcmQ+Cm1hbHdhcmVkaXIgPSAvb3B0L2hvbmV5cG90L2tpcHBvL2Rvd25sb2FkcwoKW0RJT05BRUFdCmRpb25hZWEgPSBmYWxzZQpub2RlaWQgPSAgPHlvdXIgdW5pcXVlIGFuYWx5emVyIGlkPgptYWx3YXJlZGlyID0gL29wdC9ob25leXBvdC9kaW9uYWVhL3Zhci9kb3dubG9hZApzcWxpdGVkYiA9IC9vcHQvaG9uZXlwb3QvZGlvbmFlYS92YXIvbG9nc3FsLnNxbGl0ZQoKW0hPTkVZVFJBUF0KaG9uZXl0cmFwID0gZmFsc2UKbm9kZWlkID0gIDx5b3VyIHVuaXF1ZSBhbmFseXplciBpZD4KbmV3dmVyc2lvbiA9IHRydWUKcGF5bG9hZGRpciA9IC9vcHQvaG9uZXlwb3QvaG9uZXl0cmFwL2F0dGFja3MKYXR0YWNrZXJmaWxlID0gL29wdC9ob25leXBvdC9ob25leXRyYXAvbG9nL2F0dGFja2VyLmxvZwo="
                }

    ADATA = { "SqliteID"   : 3,
              "Request"    : "/index.html?<>"
            }

    esm = ewsauth("example","elpmaxe")
    ewsalert(esm,DATA,REQUEST,ADATA)
    print(etree.tostring(esm, pretty_print=True))
    print("----------------------------------------------------")
    print(etree.tostring(esm))
    print("----------------------------------------------------")

    sys.exit()
