# run_monitor.py
from src.log_parser import parse_line, read_windows_security_log
from src.detector import Detector
from src.response_engine import block_ip, generate_report
import threading, platform, os, time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

d = Detector()

def callback(event):
    print('[MONITOR EVENT]', event)
    a = d.handle_event(event)
    if a:
        print('[ALERT]', a)
        block_ip(a['ip'])
        generate_report(a)

def start_dashboard():
    try:
        from src.dashboard import run as run_dashboard
        t = threading.Thread(target=run_dashboard, daemon=True)
        t.start()
        print('[*] Dashboard started at http://127.0.0.1:5000')
    except Exception as e:
        print('[!] Dashboard failed to start:', e)

class TailHandler(FileSystemEventHandler):
    def __init__(self, path, cb):
        self.path = path; self.cb = cb; self._f = open(path,'r',errors='ignore'); self._f.seek(0,2)
    def on_modified(self, event):
        if event.src_path != self.path: return
        for line in self._f:
            ev = parse_line(line)
            if ev: self.cb(ev)

if __name__=='__main__':
    start_dashboard()
    if platform.system().lower().startswith('win'):
        try:
            read_windows_security_log(callback)
        except Exception as e:
            print('Windows event read failed or pywin32 missing. Falling back to sample_auth.log.', e)
            p = 'sample_auth.log'
    else:
        p = '/var/log/auth.log'
    if not os.path.exists(p):
        open(p,'a').close()
    obs = Observer()
    obs.schedule(TailHandler(p, callback), path='.', recursive=False)
    obs.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()
