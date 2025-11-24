# Adaptive Threat Detection & Response System

A powerful cybersecurity project that detects, analyses, and visualizes suspicious activity in real time.  
Built using **Python**, **Flask**, and a modular detection engine, this system includes:

- A neon hacker-style login page  
- Secure session-based authentication  
- Real-time dashboard with charts & tables  
- Threat detection (brute force, scanning, anomalies)  
- Optional response actions (safe mode enabled by default)  
- Windows and cross-platform support  

Perfect for portfolios, GitHub, and master’s program applications.

---

Features
Secure Login System  
- Neon hacker-styled login UI  
- Flask session-based authentication  
- Logout + username display  
- Prevents unauthorized dashboard access  

Threat Detection Engine  
- Brute-force pattern detection  
- Port-scan behaviour detection  
- Repeated suspicious IP activity  
- Custom test alerts  
- Windows Event Log ingestion (optional admin mode)

Response Engine  
- Sends alerts to the dashboard  
- Optional automated firewall blocking  
- Safe mode ON by default  

Real-Time Dashboard  
- Light, modern UI  
- Live alerts table  
- Chart.js trend visualization  
- IP filter & alert filter  
- Quick action test panel  
- Logout button & username display  

---

Project Structure

project/
```
run_app.py
run_monitor.py
requirements.txt
sample_log_generator.py
```

src/
```
dashboard.py
detector.py
log_parser.py
response_engine.py
auth_config.json
```

templates/
```
login.html
index.html
```

docs/
```
architecture.png
project_report.pdf
```


---

Installation

1. Install Python (3.10 or newer)

2. Extract the project, then run:
```
py run_app.py
```

3. Open in browser:
```
http://127.0.0.1:5000/
```

4. Login credentials  
Stored in:
```
src/auth_config.json
```

---

Send a Test Alert
PowerShell:
```
Invoke-RestMethod -Uri http://127.0.0.1:5000/alert -Method Post 
-Body (@{alert="test"; ip="203.0.113.55"; timestamp=(Get-Date).ToString()} | ConvertTo-Json) 
-ContentType "application/json"
```

---

Firewall Blocking (Optional)
Safe mode (default):
```
AUTO_BLOCK = 0
```

Enable blocking (admin required):
```
AUTO_BLOCK = 1
```

---

Documentation  
Full project report inside:
```
docs/project_report.pdf
```
---
This is the full project: cross-platform threat detection with a polished Flask dashboard.
**Optional SAFE MODE:** firewall blocking exists but is disabled by default (AUTO_BLOCK=0).

Run (NO-BAT, Smart App Control friendly):
1. Ensure Python 3.9+ is installed.
2. Extract this repo to a folder.
3. Open PowerShell in that folder and run:
4. py run_app.py
5. Open http://127.0.0.1:5000 and log in with credentials from src/auth_config.json

If this project helped you, star it on GitHub!
