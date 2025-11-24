# src/response_engine.py
import platform, subprocess, os, time
IS_WIN = platform.system().lower().startswith('win')
AUTO_BLOCK = os.environ.get('AUTO_BLOCK','0') == '1'

def _log(msg):
    os.makedirs('logs', exist_ok=True)
    with open(os.path.join('logs','actions.log'),'a') as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")

def block_ip(ip):
    _log(f"BLOCK intent for {ip} - AUTO_BLOCK={'1' if AUTO_BLOCK else '0'}")
    if not AUTO_BLOCK:
        return False
    if IS_WIN:
        try:
            cmd = ['netsh','advfirewall','firewall','add','rule','name=BlockFromDetected','dir=in',f'remoteip={ip}','action=block']
            subprocess.check_call(cmd)
            _log(f"Blocked {ip} via netsh")
            return True
        except Exception as e:
            _log(f"Block failed: {e}")
            return False
    else:
        try:
            subprocess.check_call(['ufw','deny','from',ip])
            _log(f"Blocked {ip} via ufw")
            return True
        except Exception:
            try:
                subprocess.check_call(['iptables','-I','INPUT','-s',ip,'-j','DROP'])
                _log(f"Blocked {ip} via iptables")
                return True
            except Exception as e:
                _log(f"Block failed: {e}")
                return False

def generate_report(alert, outdir='reports'):
    os.makedirs(outdir, exist_ok=True)
    fname = os.path.join(outdir, f"incident_{alert.get('ip','unknown')}_{int(time.time())}.txt")
    with open(fname,'w') as f:
        f.write(str(alert))
    _log(f"Report {fname}")
    return fname
