"""
UI Backend - Flask API that serves log data to the web dashboard.
"""

from flask import Flask, jsonify
from flask_cors import CORS
import json, os, psutil
from ml_predictor import run_ml_prediction

app = Flask(__name__)
CORS(app)

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history.log")


def read_logs():
    logs = []
    if not os.path.exists(LOG_FILE):
        return logs
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return logs


@app.route("/api/status")
def get_status():
    honeypot_running = False
    try:
        for proc in psutil.process_iter(['cmdline']):
            try:
                if any('honeypot.py' in c for c in proc.info['cmdline'] or []):
                    honeypot_running = True
                    break
            except Exception:
                pass
    except Exception:
        pass
    logs = read_logs()
    last_event = logs[-1].get("timestamp", "Never") if logs else "Never"
    return jsonify({
        "honeypot_live": honeypot_running,
        "mode": "LIVE" if honeypot_running else "OFFLINE",
        "total_events": len(logs),
        "last_event": last_event
    })


@app.route("/api/logs")
def get_logs():
    return jsonify(read_logs())


@app.route("/api/stats")
def get_stats():
    logs = read_logs()
    total_connections = 0
    total_commands = 0
    total_logins = 0
    unique_ips = set()
    top_commands = {}
    attacker_sessions = {}

    for entry in logs:
        t = entry.get("type")
        ip = entry.get("ip", "unknown")
        if t == "CONNECTION":
            total_connections += 1
            unique_ips.add(ip)
            if ip not in attacker_sessions:
                attacker_sessions[ip] = {"commands": 0, "first_seen": entry.get("timestamp")}
        elif t == "LOGIN":
            total_logins += 1
        elif t == "COMMAND":
            total_commands += 1
            if ip in attacker_sessions:
                attacker_sessions[ip]["commands"] += 1
            cmd = entry.get("command", "").split()[0] if entry.get("command") else ""
            if cmd:
                top_commands[cmd] = top_commands.get(cmd, 0) + 1

    sorted_cmds = sorted(top_commands.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify({
        "total_connections": total_connections,
        "total_commands": total_commands,
        "total_logins": total_logins,
        "unique_ips": len(unique_ips),
        "top_commands": sorted_cmds,
        "attacker_sessions": [{"ip": ip, **data} for ip, data in attacker_sessions.items()]
    })


@app.route("/api/recent")
def get_recent():
    return jsonify(read_logs()[-50:])


@app.route("/api/geo")
def get_geo():
    logs = read_logs()
    attackers = {}
    for entry in logs:
        if entry.get("type") == "LOGIN" and entry.get("country"):
            ip = entry.get("ip")
            if ip not in attackers:
                attackers[ip] = {
                    "ip": ip,
                    "country": entry.get("country", "Unknown"),
                    "city": entry.get("city", "Unknown"),
                    "isp": entry.get("isp", "Unknown"),
                    "lat": entry.get("lat", 0),
                    "lon": entry.get("lon", 0),
                    "countryCode": entry.get("countryCode", ""),
                    "attempts": 0
                }
            attackers[ip]["attempts"] += 1
    return jsonify(list(attackers.values()))


@app.route("/api/predictions")
def get_predictions():
    result = run_ml_prediction(LOG_FILE)
    return jsonify(result)


if __name__ == "__main__":
    print(f"[UI] Reading logs from: {LOG_FILE}")
    print(f"[UI] Log file exists: {os.path.exists(LOG_FILE)}")
    print("[UI] Dashboard API running on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)