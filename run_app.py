#!/usr/bin/env python3
import venv, subprocess, pathlib, os, sys
ROOT = pathlib.Path(__file__).resolve().parent
VENV = ROOT / 'venv'
PY = VENV / 'Scripts' / 'python.exe' if os.name=='nt' else VENV / 'bin' / 'python'

def ensure_venv():
    if VENV.exists() and PY.exists():
        return True
    print('Creating virtual environment...')
    venv.EnvBuilder(with_pip=True).create(VENV)
    return PY.exists()

def pip_install():
    req = ROOT / 'requirements.txt'
    if not req.exists():
        return True
    print('Installing requirements inside venv... (this may take a few minutes)')
    subprocess.check_call([str(PY), '-m', 'pip', 'install', '--upgrade', 'pip'])
    subprocess.check_call([str(PY), '-m', 'pip', 'install', '-r', str(req)])
    if os.name=='nt':
        subprocess.check_call([str(PY), '-m', 'pip', 'install', 'pywin32'])
    return True

def launch():
    env = os.environ.copy()
    env.setdefault('AUTO_BLOCK','0')
    env.setdefault('DASHBOARD_POST','http://127.0.0.1:5000/alert')
    print('Launching monitor...')
    subprocess.run([str(PY), str(ROOT/'run_monitor.py')], env=env)

if __name__=='__main__':
    ok = ensure_venv()
    if not ok:
        print('Failed to create venv. Ensure Python is installed.'); sys.exit(1)
    pip_install()
    launch()

