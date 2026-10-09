# honeypots/miniprint.py

import configparser
import re
import time
from datetime import UTC, datetime

from modules.ealert import EAlert


LIST_FIELDS = (
    "action",
    "command",
    "cve_hint",
    "event",
    "file_name",
    "virtual_path",
    "persona",
    "language",
    "artifact_type",
    "limit_event",
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
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        return timestamp.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")
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
    ):
        if source in line and line[source] not in (None, "") and target not in session:
            session[target] = line[source]

    for target, source in (
        ("session_end", "session_end"),
        ("session_duration", "session_duration"),
    ):
        if source in line and line[source] not in (None, ""):
            session[target] = line[source]

    if "secret_supplied" in line:
        session["secret_supplied"] = session.get("secret_supplied", False) or line["secret_supplied"] is True
    event = line.get("event", "")
    for key in LIST_FIELDS:
        if key == "file_name" and not event.startswith("save_"):
            continue
        if key == "request":
            if line.get("request"):
                _append_unique(session, key, "{} {}".format(line["request"], line.get("url", "")).rstrip())
        elif key == "cve_hint":
            for hint in str(line.get(key) or "").split(","):
                _append_unique(session, key, hint.strip())
        else:
            _append_unique(session, key, line.get(key))
    if event.startswith("save_") and line.get("size") is not None:
        session["artifact_size"] = max(session.get("artifact_size", 0), int(line["size"]))
    if "limit" in line:
        _append_unique(session, "limit_event", event)
        session[event + "_limit"] = line["limit"]
        if "size" in line:
            session[event + "_size"] = line["size"]

    if event.startswith("save_") and line.get("file_name"):
        artifact = {
            "file_name": line["file_name"],
            "sha256": line.get("payload_sha256"),
            "artifact_type": line.get("artifact_type") or ("ps" if line["file_name"].endswith(".ps") else "raw"),
            "size": int(line.get("size", 0)),
        }
        if artifact not in session.setdefault("artifacts", []):
            session["artifacts"].append(artifact)

    if line.get("event") == "append_raw_print_job":
        session["append_raw_print_job_count"] = session.get("append_raw_print_job_count", 0) + 1
        session["append_raw_print_job_bytes"] = session.get("append_raw_print_job_bytes", 0) + int(line.get("size", 0))


def _add_artifact(miniprint, session, HONEYPOT, ECFG):
    artifact_dir = HONEYPOT.get("malwaredir")
    if not artifact_dir:
        return

    priorities = {"firmware": 3, "ps": 2, "pcl": 2, "pdf": 2, "raw": 1}
    artifacts = sorted(
        session.get("artifacts", []),
        key=lambda item: (priorities.get(item["artifact_type"], 0), item["size"]),
        reverse=True,
    )
    for artifact in artifacts:
        file_name = _safe_file_name(artifact["file_name"])
        if not file_name:
            continue
        error, payload = miniprint.malwarecheck(
            artifact_dir, file_name, ECFG["del_malware_after_send"], artifact["sha256"] or file_name
        )
        if error is False or not payload:
            continue
        if len(payload) <= 5 * 1024:
            miniprint.request("binary", payload.decode("utf-8"))
            session["artifact_size"] = artifact["size"]
            break
        if ECFG["send_malware"] is True:
            miniprint.request("largepayload", payload.decode("utf-8"))
            session["artifact_size"] = artifact["size"]
            break


def _add_common_adata(miniprint, session, ECFG):
    for key in (
        "session_id",
        "protocol",
        "session_end",
        "session_duration",
        "artifact_size",
        "append_raw_print_job_count",
        "append_raw_print_job_bytes",
        "secret_supplied",
    ):
        if key in session:
            miniprint.adata(key, session[key])

    for key, value in session.items():
        if key.endswith(("_size", "_limit")) and key != "artifact_size":
            miniprint.adata(key, value)
    artifacts = session.get("artifacts", [])
    if artifacts:
        miniprint.adata(
            "artifacts", "\n".join("{}:{}".format(item["file_name"], item["sha256"] or "") for item in artifacts)
        )
    for key in LIST_FIELDS:
        value = _joined(session, key, "\n" if key in ("payload_preview", "request_line", "url", "request") else ",")
        if value:
            miniprint.adata(key, value)

    miniprint.adata("hostname", ECFG["hostname"])
    miniprint.adata("externalIP", ECFG["ip_ext"])
    miniprint.adata("internalIP", ECFG["ip_int"])
    miniprint.adata("uuid", ECFG["uuid"])


def _xml_text(value):
    # EAlert sanitizes AdditionalData, but writes Request text directly to lxml.
    return re.sub(r"[^\u0020-\uD7FF\u0009\u000A\u000D\uE000-\uFFFD\U00010000-\U0010FFFF]+", "", str(value))


def _build_session_alert(miniprint, session, HONEYPOT, ECFG):
    miniprint.data("analyzer_id", HONEYPOT["nodeid"]) if "nodeid" in HONEYPOT else None

    timestamp = _format_timestamp(session.get("timestamp"))
    if timestamp:
        miniprint.data("timestamp", timestamp)
        miniprint.data("timezone", "+0000")

    miniprint.data("source_address", session["source_ip"]) if session.get("source_ip") else None
    miniprint.data("target_address", session.get("target_ip") or ECFG["ip_ext"])
    miniprint.data("source_port", str(session.get("source_port") or "0"))
    miniprint.data("target_port", str(session.get("target_port") or "0"))
    miniprint.data("source_protocol", "tcp")
    miniprint.data("target_protocol", "tcp")

    miniprint.request("description", "Miniprint Honeypot")
    if _first(session, "url"):
        miniprint.request("url", _xml_text(_first(session, "url")))
    if _first(session, "request"):
        miniprint.request("request", _xml_text(_joined(session, "request", "\n")))
    elif _first(session, "command"):
        miniprint.request("request", _xml_text(_joined(session, "command")))
    elif _first(session, "request_line"):
        miniprint.request("request", _xml_text(_first(session, "request_line")))
    if _first(session, "payload_preview"):
        miniprint.request("payload", _xml_text(_first(session, "payload_preview")))

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
        return ()

    config = configparser.ConfigParser()
    config.read(ECFG["cfgfile"])
    send_empty = config.getboolean("MINIPRINT", "send_empty_connections", fallback=False)
    sent = set(miniprint.fileIndex("miniprint.session", "read"))
    sessions = {}
    rewind = []
    while True:
        line_number = int(miniprint.alertCount(miniprint.MODUL, "get_counter"))
        line = miniprint.lineREAD(HONEYPOT["logfile"], "json")
        if not line:
            break
        if not isinstance(line, dict):
            continue
        sid = _session_id(line, line_number)
        if sid in sent:
            continue
        if sid not in sessions:
            sessions[sid] = {"session_id": sid, "first_line": line_number}
        _update_session(sessions[sid], line)

    ordered = list(sessions.values())
    for index, session in enumerate(ordered):
        try:
            timestamp = datetime.fromisoformat(str(session.get("timestamp", "")).replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=UTC)
            expired = time.time() - timestamp.timestamp() >= 600
        except ValueError:
            expired = False
        if not session.get("session_end") and not expired:
            rewind.append(session["first_line"])
            continue
        events = session.get("event", [])
        if (
            not send_empty
            and events
            and all(event in ("empty_connection", "http_connection_closed") for event in events)
        ):
            miniprint.fileIndex("miniprint.session", "write", session["session_id"])
            continue
        result = _build_session_alert(miniprint, session, HONEYPOT, ECFG)
        miniprint.fileIndex("miniprint.session", "write", session["session_id"])
        if result == "sendlimit":
            # EAlert has already built the current alert when it reports its limit.
            rewind.extend(item["first_line"] for item in ordered[index + 1 :])
            break
    if rewind:
        miniprint.alertCount(miniprint.MODUL, "set_counter", setto=min(rewind))
    miniprint.finAlert()
    return ()
