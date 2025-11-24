# src/detector.py
import time, os, re, requests
from collections import defaultdict, deque
DASHBOARD_POST = os.environ.get('DASHBOARD_POST', 'http://127.0.0.1:5000/alert')

class Detector:
    def __init__(self):
        self.failed_auth = defaultdict(deque)
        self.scan_attempts = defaultdict(deque)
        self.brute_force_threshold = 10
        self.brute_force_window = 60
        self.port_scan_threshold = 30
        self.port_scan_window = 10

    def handle_event(self, event):
        now = time.time()
        ip = event.get('src_ip') or 'unknown'
        etype = event.get('event_type')
        if not ip or ip=='unknown':
            return None
        if etype == 'auth_failure':
            dq = self.failed_auth[ip]
            dq.append(now)
            while dq and dq[0] < now - self.brute_force_window:
                dq.popleft()
            if len(dq) >= self.brute_force_threshold:
                alert = {'alert':'brute_force','ip':ip,'count':len(dq),'timestamp':time.strftime('%Y-%m-%d %H:%M:%S')}
                self._post(alert)
                return alert
        if etype == 'connection':
            details = event.get('details','')
            m = re.search(r':(\d{1,5})', details)
            port = int(m.group(1)) if m else None
            dq2 = self.scan_attempts[ip]
            dq2.append((now, port))
            while dq2 and dq2[0][0] < now - self.port_scan_window:
                dq2.popleft()
            distinct_ports = len({p for t,p in dq2 if p})
            if distinct_ports >= self.port_scan_threshold:
                alert = {'alert':'port_scan','ip':ip,'ports':distinct_ports,'timestamp':time.strftime('%Y-%m-%d %H:%M:%S')}
                self._post(alert)
                return alert
        return None

    def _post(self, alert):
        try:
            requests.post(DASHBOARD_POST, json=alert, timeout=2)
        except Exception:
            pass
