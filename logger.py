"""
Honeypot Logger - Records all attacker activity to history.log
"""

import os
import json
import threading
import requests
from datetime import datetime
GEO_CACHE = {}
def geolocate(ip: str) -> dict:
    """Looks up country, city, ISP for an IP. Returns empty dict on failure."""
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    if ip in ("127.0.0.1", "localhost", "::1"):
        return {"country": "Local", "city": "Local", "isp": "Local"}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,lat,lon,countryCode", timeout=5)
        data = r.json() if r.status_code == 200 else {}
        GEO_CACHE[ip] = data
        return data
    except Exception:
        return {}
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history.log")

class HoneypotLogger:
    """
    Thread-safe logger that writes all honeypot events to history.log.
    Each entry is a JSON line for easy parsing by the UI.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._write({
            "type": "STARTUP",
            "timestamp": self._now(),
            "message": "Chameleon Honeypot started"
        })

    def _now(self):
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    def _write(self, entry: dict):
        """Writes a JSON entry to the log file in a thread-safe way."""
        with self._lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    def log_login_attempt(self, ip: str, username: str, password: str):
        """Logs an SSH login attempt with geolocation data."""
        geo = geolocate(ip)
        entry = {
            "type": "LOGIN",
            "timestamp": self._now(),
            "ip": ip,
            "username": username,
            "password": password,
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", "Unknown"),
            "isp": geo.get("isp", "Unknown"),
            "lat": geo.get("lat", 0),
            "lon": geo.get("lon", 0),
            "countryCode": geo.get("countryCode", ""),
        }
        self._write(entry)
        print(f"  [LOGIN] {ip} → {username}:{password}")

    def log_command(self, ip: str, command: str):
        """Logs a command typed by the attacker."""
        entry = {
            "type": "COMMAND",
            "timestamp": self._now(),
            "ip": ip,
            "command": command,
        }
        self._write(entry)
        print(f"  [CMD]   {ip} → {command}")

    def log_event(self, ip: str, event_type: str, message: str):
        """Logs a general event (connection, disconnect, error)."""
        entry = {
            "type": event_type,
            "timestamp": self._now(),
            "ip": ip,
            "message": message,
        }
        self._write(entry)

    def get_all_logs(self):
        """Returns all log entries as a list of dicts (for the UI)."""
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

    def get_stats(self):
        """Returns summary statistics for the UI dashboard."""
        logs = self.get_all_logs()
        stats = {
            "total_connections": 0,
            "total_commands": 0,
            "total_logins": 0,
            "unique_ips": set(),
            "top_commands": {},
            "top_ips": {},
        }

        for entry in logs:
            t = entry.get("type")
            ip = entry.get("ip", "unknown")

            if t == "CONNECTION":
                stats["total_connections"] += 1
                stats["unique_ips"].add(ip)
                stats["top_ips"][ip] = stats["top_ips"].get(ip, 0) + 1

            elif t == "LOGIN":
                stats["total_logins"] += 1

            elif t == "COMMAND":
                stats["total_commands"] += 1
                cmd = entry.get("command", "").split()[0] if entry.get("command") else ""
                if cmd:
                    stats["top_commands"][cmd] = stats["top_commands"].get(cmd, 0) + 1

        stats["unique_ips"] = list(stats["unique_ips"])
        return stats
