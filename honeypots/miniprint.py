# honeypots/miniprint.py

import configparser
import time
from datetime import datetime

from modules.ealert import EAlert


LIST_FIELDS = (
    "action",
    "command",
    "cve_hint",
    "event",
    "file_name",
    "info",
    "payload_preview",
    "payload_sha256",
    "request",
    "request_line",
    "url",
    "user_agent",
    "username",
)


def _append_unique(session, key, value):
    if value is None or value == "":
        return
    value = str(value)
    if key not in session:
        session[key] = []
    if value not in session[key]:
        session[key].append(value)


def _first(session, key):
    value = session.get(key)
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _joined(session, key, separator=","):
    value = session.get(key)
    if isinstance(value, list):
        return separator.join(value)
    return value


def _format_timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _safe_file_name(value):
    if not value:
        return None
    file_name = str(value)
    if "/" in file_name or "\\" in file_name or file_name in (".", ".."):
        return None
    return file_name


def _optional_miniprint_dir(ECFG, option):
    config = configparser.ConfigParser()
    config.read(ECFG["cfgfile"])
    if config.has_option("MINIPRINT", option) and config.get("MINIPRINT", option):
        return config.get("MINIPRINT", option)
    return None


def _artifact_dir(ECFG):
    return _optional_miniprint_dir(ECFG, "malwaredir") or _optional_miniprint_dir(ECFG, "uploaddir")


def _session_id(line, counter):
    if line.get("session_id"):
        return line["session_id"]
    timestamp = line.get("session_start") or line.get("timestamp") or counter
    return "{}:{}->{}:{}:{}".format(
        line.get("src_ip", ""),
        line.get("src_port", ""),
        line.get("dest_ip", ""),
        line.get("dest_port", ""),
        timestamp,
    )


def _update_session(session, line):
    for target, source in (
        ("timestamp", "session_start"),
        ("timestamp", "timestamp"),
        ("source_ip", "src_ip"),
        ("source_port", "src_port"),
        ("target_ip", "dest_ip"),
        ("target_port", "dest_port"),
        ("protocol", "protocol"),
        ("secret_supplied", "secret_supplied"),
    ):
        if source in line and line[source] not in (None, "") and target not in session:
            session[target] = line[source]

    for target, source in (
        ("session_end", "session_end"),
        ("session_duration", "session_duration"),
        ("size", "size"),
        ("limit", "limit"),
    ):
        if source in line and line[source] not in (None, ""):
            session[target] = line[source]

    for key in LIST_FIELDS:
        _append_unique(session, key, line.get(key))

    if line.get("file_name"):
        session.setdefault("artifacts", []).append((line.get("file_name"), line.get("payload_sha256")))

    if line.get("event") == "append_raw_print_job":
        session["append_raw_print_job_count"] = session.get("append_raw_print_job_count", 0) + 1
        session["append_raw_print_job_bytes"] = session.get("append_raw_print_job_bytes", 0) + int(line.get("size", 0))


def _add_artifact(miniprint, session, HONEYPOT, ECFG):
    artifact_dir = HONEYPOT.get("malwaredir")
    if not artifact_dir:
        return

    artifacts = session.get("artifacts") or [(value, None) for value in session.get("file_name", [])]
    for value, payload_sha256 in artifacts:
        file_name = _safe_file_name(value)
        if not file_name:
            continue
        checksum = payload_sha256 or file_name
        error, payload = miniprint.malwarecheck(
            artifact_dir,
            file_name,
            ECFG["del_malware_after_send"],
            checksum,
        )
        if error is False or not payload:
            continue
        if len(payload) <= 5 * 1024:
            miniprint.request("binary", payload.decode("utf-8"))
            break
        if ECFG["send_malware"] is True:
            miniprint.request("largepayload", payload.decode("utf-8"))
            break


def _add_common_adata(miniprint, session, ECFG):
    for key in (
        "session_id",
        "protocol",
        "session_end",
        "session_duration",
        "size",
        "limit",
        "append_raw_print_job_count",
        "append_raw_print_job_bytes",
        "secret_supplied",
    ):
        if key in session:
            miniprint.adata(key, session[key])

    for key in LIST_FIELDS:
        value = _joined(session, key, "\n" if key in ("payload_preview", "request_line", "url") else ",")
        if value:
            miniprint.adata(key, value)

    miniprint.adata("hostname", ECFG["hostname"])
    miniprint.adata("externalIP", ECFG["ip_ext"])
    miniprint.adata("internalIP", ECFG["ip_int"])
    miniprint.adata("uuid", ECFG["uuid"])


def _build_session_alert(miniprint, session, HONEYPOT, ECFG):
    miniprint.data("analyzer_id", HONEYPOT["nodeid"]) if "nodeid" in HONEYPOT else None

    timestamp = _format_timestamp(session.get("timestamp"))
    if timestamp:
        miniprint.data("timestamp", timestamp)
        miniprint.data("timezone", time.strftime("%z"))

    miniprint.data("source_address", session["source_ip"]) if session.get("source_ip") else None
    miniprint.data("target_address", session.get("target_ip") or ECFG["ip_ext"])
    miniprint.data("source_port", str(session.get("source_port") or "0"))
    miniprint.data("target_port", str(session.get("target_port") or "0"))
    miniprint.data("source_protocol", "tcp")
    miniprint.data("target_protocol", "tcp")

    miniprint.request("description", "Miniprint Honeypot")
    if _first(session, "url"):
        miniprint.request("url", _first(session, "url"))
    if _first(session, "request"):
        miniprint.request("request", _first(session, "request"))
    elif _first(session, "command"):
        miniprint.request("request", _joined(session, "command"))
    elif _first(session, "request_line"):
        miniprint.request("request", _first(session, "request_line"))
    if _first(session, "payload_preview"):
        miniprint.request("payload", _first(session, "payload_preview"))

    _add_artifact(miniprint, session, HONEYPOT, ECFG)
    _add_common_adata(miniprint, session, ECFG)

    return miniprint.buildAlert()


def miniprint(ECFG):
    miniprint = EAlert("miniprint", ECFG)

    ITEMS = ["miniprint", "nodeid", "logfile"]
    HONEYPOT = miniprint.readCFG(ITEMS, ECFG["cfgfile"])
    HONEYPOT["malwaredir"] = _artifact_dir(ECFG)

    if HONEYPOT.get("miniprint").lower() == "false":
        print("    -> Honeypot Miniprint set to false. Skip Honeypot.")
        return()

    sessions = {}
    counter = 0

    while True:
        line = miniprint.lineREAD(HONEYPOT["logfile"], "json")

        if not line:
            break
        if line == "jsonfail":
            continue
        if not isinstance(line, dict):
            continue

        counter += 1
        sid = _session_id(line, counter)
        if sid not in sessions:
            sessions[sid] = {"session_id": sid}
        _update_session(sessions[sid], line)

    for session in sessions.values():
        if _build_session_alert(miniprint, session, HONEYPOT, ECFG) == "sendlimit":
            break

    miniprint.finAlert()
    return()
