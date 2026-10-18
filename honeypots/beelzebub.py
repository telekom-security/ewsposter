# honeypots/beelzebub.py

import time
from datetime import datetime, timezone
from urllib import parse
from modules.ealert import EAlert


""" A session without an end line is reported once its last line is this old (the T-Pot log forgets it then) """
SESSION_TTL = 2 * 60 * 60
""" The most characters of a request body sent as additional data """
BODY_LIMIT = 1024
URL_SAFE_CHARS = "/?&=%:@+;,"
""" Status of the T-Pot log line: Start / Interaction / End belong to a session, Stateless is one request """
DONE_STATUS = ('End', 'Stateless')
""" Messages of the former T-Pot fork that end a session without an End status """
END_MESSAGES = ('End SSH Inline Session', 'End SSH Session', 'End TCP Session', 'End TELNET Session')
FIRST_FIELDS = (
    ('src_ip', 'source_ip'), ('src_port', 'source_port'), ('dest_port', 'target_port'),
    ('protocol', 'protocol'), ('service', 'service'), ('username', 'username'), ('password', 'password'),
    ('environ', 'environ'), ('client', 'client'), ('client_version', 'client_version'),
    ('request_method', 'httpmethod'), ('request_uri', 'url'), ('userAgent', 'user_agent'),
    ('hostname', 'http_host'), ('tls_server_name', 'tls_server_name'), ('body', 'body'),
)


def _parse_time(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return(None)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return(parsed)


def _format_time(value):
    parsed = _parse_time(value)
    return(parsed.strftime('%Y-%m-%d %H:%M:%S') if parsed else None)


def _update_session(session, line):
    for source, target in FIRST_FIELDS:
        value = line.get(source)
        if value not in (None, '') and target not in session:
            session[target] = value

    if not session.get('timestamp_start'):
        session['timestamp_start'] = _format_time(line.get('timestamp'))
    session['last_seen'] = _parse_time(line.get('timestamp')) or session.get('last_seen')
    if line.get('message'):
        session['type'] = line['message']

    command = line.get('input') or line.get('command')
    if command:
        session.setdefault('input', []).append(str(command))

    if line.get('status') in DONE_STATUS or line.get('message') in END_MESSAGES:
        session['done'] = True
        if line.get('status') == 'End' or line.get('message') in END_MESSAGES:
            session['timestamp_stop'] = _format_time(line.get('timestamp'))


def _ready(session, now):
    if session.get('done'):
        return(True)
    last_seen = session.get('last_seen')
    return(last_seen is not None and (now - last_seen).total_seconds() >= SESSION_TTL)


def beelzebub(ECFG):
    beelzebub = EAlert('beelzebub', ECFG)

    ITEMS = ['beelzebub', 'nodeid', 'logfile']
    HONEYPOT = (beelzebub.readCFG(ITEMS, ECFG['cfgfile']))

    if HONEYPOT.get('beelzebub').lower() == "false":
        print(f"    -> Honeypot Beelzebub set to false. Skip Honeypot.")
        return()

    beelzebubSessionIDs = beelzebub.fileIndex('beelzebub.session', 'read')
    beelzebubSessions = {}

    beelzebub.alertCount('BEELZEBUB', 'reset_counter')

    while (line := beelzebub.lineREAD(HONEYPOT['logfile'], 'json')):

        if line == 'jsonfail' or not isinstance(line, dict) or not line.get('session') or line.get('session') in beelzebubSessionIDs:
            continue

        _update_session(beelzebubSessions.setdefault(line['session'], {}), line)

    """ second loop: every session that ended (or one request), and sessions without an end after SESSION_TTL """

    now = datetime.now(timezone.utc)
    for session, values in beelzebubSessions.items():
        if not _ready(values, now):
            continue

        if HONEYPOT.get('nodeid'): beelzebub.data('analyzer_id', HONEYPOT.get('nodeid'))

        if values.get('timestamp_start'):
            beelzebub.data('timestamp', values['timestamp_start'])
            beelzebub.data("timezone", "+0000")

        if values.get('source_ip'): beelzebub.data('source_address', values['source_ip'])
        beelzebub.data('target_address', ECFG['ip_ext'])
        if values.get('source_port'): beelzebub.data('source_port', str(values['source_port']))
        if values.get('target_port'): beelzebub.data('target_port', str(values['target_port']))
        beelzebub.data('source_protocol', 'tcp')
        beelzebub.data('target_protocol', 'tcp')

        beelzebub.request("description", "Beelzebub Honeypot")
        if values.get('url'):
            beelzebub.request("url", parse.quote(str(values['url']).encode('ascii', 'ignore'), safe=URL_SAFE_CHARS))

        beelzebub.adata('sessionid', session)
        for key in ('protocol', 'service', 'type', 'username', 'password', 'environ', 'client', 'client_version',
                    'httpmethod', 'user_agent', 'http_host', 'tls_server_name'):
            if values.get(key): beelzebub.adata(key, values[key])
        if values.get('timestamp_start'): beelzebub.adata('logintime', values['timestamp_start'])
        if values.get('timestamp_stop'): beelzebub.adata('logouttime', values['timestamp_stop'])
        if values.get('input'): beelzebub.adata('input', ';'.join(values['input']))
        if values.get('body'): beelzebub.adata('body', str(values['body'])[:BODY_LIMIT])

        beelzebub.adata('hostname', ECFG['hostname'])
        beelzebub.adata('externalIP', ECFG['ip_ext'])
        beelzebub.adata('internalIP', ECFG['ip_int'])
        beelzebub.adata('uuid', ECFG['uuid'])

        beelzebub.fileIndex('beelzebub.session', 'write', session)

        if beelzebub.buildAlert() == "sendlimit":
            break

    beelzebub.finAlert()
    return
