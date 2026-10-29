# honeypots/glutton.py

import base64
import binascii
from datetime import datetime, timezone
import ipaddress
import json
import re
from modules.ealert import EAlert

UDP_ONLY = {"udp", "mdns", "openvpn", "coap", "rtps", "raknet", "l2tp", "dht",
            "a2s", "slp", "radius", "steam", "wsdiscovery", "tftp", "knx", "rip",
            "hiflying", "ddp", "itp", "ike", "dtls"}


def _timestamp(line, session):
    value = line.get("timestamp" if session else "time")
    if value is not None:
        if not isinstance(value, str):
            raise ValueError("invalid ISO timestamp")
        # Python 3.9 accepts at most microseconds; Go emits RFC3339 nanoseconds.
        value = re.sub(r"(\.\d{6})\d+(?=Z|[+-]\d{2}:?\d{2}$)", r"\1", value)
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError("timestamp has no timezone")
    else:
        value = line.get("ts")
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise ValueError("missing timestamp")
        stamp = datetime.fromtimestamp(float(value), timezone.utc)
    return stamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _port(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("invalid port")
    text = str(value)
    if not text.isascii() or not text.isdecimal() or not 0 <= int(text) <= 65535:
        raise ValueError("invalid port")
    return str(int(text))


def _event(line):
    if not isinstance(line, dict):
        return None
    session = line.get("event_kind") == "session" or "srcHost" in line
    if "event_kind" in line and line["event_kind"] != "session":
        return None
    if str(line.get("level", "info")).lower() != "info":
        return None
    source = line.get("srcHost" if session else "src_ip")
    if source is None:
        return None
    if not isinstance(source, str):
        raise ValueError("invalid source address")
    source = str(ipaddress.ip_address(source))
    transport = line.get("transport")
    if session and transport is None:
        raise ValueError("session has no transport")
    if transport is None:
        protocol = str(line.get("protocol", "")).lower()
        if protocol in ("tcp", "udp"):
            transport = protocol
        elif re.search(r"\bUDP\b", str(line.get("msg", "")), re.IGNORECASE) or line.get("handler") in UDP_ONLY:
            transport = "udp"
        else:
            # Old Glutton logs were TCP-only and have no transport field.
            transport = "tcp"
    if not isinstance(transport, str) or transport.lower() not in ("tcp", "udp"):
        raise ValueError("invalid transport")
    event = {"timestamp": _timestamp(line, session), "timezone": "+0000",
             "source_address": source,
             "source_port": _port(line.get("srcPort" if session else "src_port")),
             "target_port": _port(line.get("dstPort" if session else "dest_port")),
             "source_protocol": transport.lower(), "target_protocol": transport.lower()}
    if session and "payload" in line:
        value = line["payload"]
        if not isinstance(value, str):
            raise ValueError("invalid base64 payload")
        event["binary"] = base64.b64encode(base64.b64decode(value, validate=True)).decode("ascii")
    elif "payload_hex" in line:
        value = line["payload_hex"]
        if not isinstance(value, str):
            raise ValueError("invalid hex payload")
        event["binary"] = base64.b64encode(bytes.fromhex(value)).decode("ascii")
    metadata = {key: line[key] for key in (
        "handler", "handlers", "scanner", "tls", "durationMs", "frameCount", "endReason",
        "payloadHash", "rule", "ruleName", "sensorVersion", "decoded",
    ) if key in line}
    event["metadata"] = json.dumps(metadata, ensure_ascii=True, separators=(",", ":"))
    return event


def glutton(ECFG):
    alert = EAlert('glutton', ECFG)
    honeypot = alert.readCFG(['glutton', 'nodeid', 'logfile'], ECFG['cfgfile'])
    if honeypot.get('glutton').lower() == "false":
        print("    -> Honeypot Glutton set to false. Skip Honeypot.")
        return
    while True:
        line = alert.lineREAD(honeypot['logfile'], 'json')
        if line == '' or line == {}:
            break
        if line == 'jsonfail':
            continue
        try:
            event = _event(line)
        except (ValueError, TypeError, OverflowError, OSError, binascii.Error):
            alert.logger.warning("Skipping invalid Glutton timestamp, address, port, transport or payload.", '2')
            continue
        if event is None:
            continue
        if 'nodeid' in honeypot:
            alert.data('analyzer_id', honeypot['nodeid'])
        for key in ('timestamp', 'timezone', 'source_address', 'source_port', 'target_port',
                    'source_protocol', 'target_protocol'):
            alert.data(key, event[key])
        alert.data('target_address', ECFG['ip_ext'])
        alert.request('description', 'Glutton Honeypot')
        if 'binary' in event:
            alert.request('binary', event['binary'])
        alert.adata('glutton', event['metadata'])
        for field, config in (('hostname', 'hostname'), ('externalIP', 'ip_ext'),
                              ('internalIP', 'ip_int'), ('uuid', 'uuid')):
            alert.adata(field, ECFG[config])
        if alert.buildAlert() == 'sendlimit':
            break
    alert.finAlert()
