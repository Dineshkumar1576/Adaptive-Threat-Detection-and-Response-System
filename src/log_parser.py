# src/log_parser.py
import re, platform, time
from datetime import datetime
USE_WIN = platform.system().lower().startswith('win')
try:
    if USE_WIN:
        import win32evtlog
    else:
        win32evtlog = None
except Exception:
    win32evtlog = None

IP_RE = re.compile(r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)')

def make_event(ts, src_ip, event_type, details, event_id=None):
    return {"timestamp": ts, "src_ip": src_ip, "event_type": event_type, "details": details, "event_id": event_id}

def parse_line(line):
    m = IP_RE.search(line)
    ip = m.group(0) if m else 'unknown'
    low = line.lower()
    if any(x in low for x in ('failed','failure','invalid','unauth','authentication')):
        return make_event(datetime.utcnow().isoformat(), ip, "auth_failure", line.strip())
    if 'connection' in low and 'closed' not in low:
        return make_event(datetime.utcnow().isoformat(), ip, "connection", line.strip())
    return None

def read_windows_security_log(callback, server='localhost'):
    if not win32evtlog:
        print("[!] pywin32 not available; Windows Event Log reading disabled.")
        return
    log_type = 'Security'
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    seen = set()
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            time.sleep(2)
            continue
        for ev in events:
            if ev.RecordNumber in seen:
                continue
            seen.add(ev.RecordNumber)
            ev_id = ev.EventID & 0xFFFF
            ts = ev.TimeGenerated.Format() if hasattr(ev, 'TimeGenerated') else datetime.utcnow().isoformat()
            inserts = ev.StringInserts or []
            msg = ' '.join(str(x) for x in inserts)
            m = IP_RE.search(msg)
            ip = m.group(0) if m else 'unknown'
            if ev_id == 4625:
                callback(make_event(ts, ip, 'auth_failure', msg, event_id=ev_id))
            elif ev_id in (5156, 5158):
                callback(make_event(ts, ip, 'connection', msg, event_id=ev_id))
            else:
                low = msg.lower()
                if 'failed' in low or 'failure' in low:
                    callback(make_event(ts, ip, 'auth_failure', msg, event_id=ev_id))
        time.sleep(2)
