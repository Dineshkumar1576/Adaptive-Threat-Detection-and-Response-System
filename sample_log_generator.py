# sample_log_generator.py
import threading, time, socket

def simulate_port_scan(target='127.0.0.1', ports=range(8000,8050), delay=0.02):
    for p in ports:
        try:
            s=socket.socket(); s.settimeout(0.1); s.connect((target,p)); s.close()
        except Exception: pass
        print(f'Conn attempt {target}:{p}')
        time.sleep(delay)

def simulate_bruteforce(logfile='sample_auth.log', ip='203.0.113.55', attempts=20, delay=0.5):
    for i in range(attempts):
        with open(logfile,'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - FAILED LOGIN from {ip} - user: admin\n")
        time.sleep(delay)
    print('Bruteforce simulated.')

if __name__=='__main__':
    t1=threading.Thread(target=simulate_port_scan); t2=threading.Thread(target=simulate_bruteforce)
    t1.start(); t2.start(); t1.join(); t2.join()
