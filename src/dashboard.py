# src/dashboard.py
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, abort
from collections import deque
import time, json, os, functools, secrets

app = Flask(__name__, template_folder='../templates')
# Load secret key from auth_config or generate one
_cfg = os.path.join(os.path.dirname(__file__), 'auth_config.json')
def _load_cfg():
    try:
        with open(_cfg, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}
_cfg_data = _load_cfg()
app.secret_key = _cfg_data.get('flask_secret_key') or secrets.token_hex(16)

ALERTS = deque(maxlen=2000)

def check_credentials(username, password):
    cfg = _cfg_data
    return username == cfg.get('username') and password == cfg.get('password')

def login_required(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if session.get('logged_in'):
            return f(*args, **kwargs)
        return redirect(url_for('login', next=request.path))
    return wrapped

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')
        if check_credentials(username, password):
            session['logged_in'] = True
            session['username'] = username
            nxt = request.args.get('next') or url_for('index')
            return redirect(nxt)
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/alert', methods=['POST'])
def post_alert():
    # Public endpoint used by detector to post alerts
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
    data.setdefault('timestamp', time.strftime('%Y-%m-%d %H:%M:%S'))
    ALERTS.appendleft(data)
    return jsonify({'status':'ok'}), 201

@app.route('/api/alerts')
@login_required
def api_alerts():
    args = request.args; t = args.get('type'); ip = args.get('ip')
    out = []
    for a in list(ALERTS):
        if t and a.get('alert') != t: continue
        if ip and ip not in str(a.get('ip','')): continue
        out.append(a)
    return jsonify({'alerts': out})

@app.route('/health')
def health():
    return {'status':'ok'}

def run(host='127.0.0.1', port=5000):
    app.run(host=host, port=port, debug=False, threaded=True)

if __name__ == '__main__':
    run()
