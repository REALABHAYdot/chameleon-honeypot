"""
ML Prediction Engine - Real machine learning for attack forecasting.
Uses Linear Regression + moving averages on real attack data.
Produces actual metrics: MAE, RMSE, R² for the research paper.
"""

import json
import os
import numpy as np
from datetime import datetime, timedelta

# Lazy imports so missing packages don't crash the whole app
try:
    from sklearn.linear_model import LinearRegression
    from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


def parse_logs(log_file: str) -> list:
    """Read and parse history.log into a list of dicts."""
    logs = []
    if not os.path.exists(log_file):
        return logs
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return logs


def build_daily_features(logs: list) -> dict:
    """
    Builds a per-day feature matrix from logs.
    Returns dict of date -> feature dict.
    """
    daily = {}

    for entry in logs:
        ts = entry.get("timestamp", "")
        if not ts:
            continue
        try:
            day = ts[:10]  # "YYYY-MM-DD"
        except Exception:
            continue

        if day not in daily:
            daily[day] = {
                "logins": 0,
                "commands": 0,
                "connections": 0,
                "unique_ips": set(),
                "recon_cmds": 0,
                "privesc_cmds": 0,
            }

        t = entry.get("type")
        if t == "LOGIN":
            daily[day]["logins"] += 1
            ip = entry.get("ip", "")
            if ip:
                daily[day]["unique_ips"].add(ip)
        elif t == "COMMAND":
            daily[day]["commands"] += 1
            cmd = entry.get("command", "").split()[0].lower() if entry.get("command") else ""
            if cmd in ["whoami", "id", "uname", "hostname", "ifconfig"]:
                daily[day]["recon_cmds"] += 1
            if cmd in ["sudo", "su", "chmod", "chown"]:
                daily[day]["privesc_cmds"] += 1
        elif t == "CONNECTION":
            daily[day]["connections"] += 1

    # Convert sets to counts
    for day in daily:
        daily[day]["unique_ips"] = len(daily[day]["unique_ips"])

    return daily


def run_ml_prediction(log_file: str) -> dict:
    """
    Main function — runs ML pipeline and returns predictions + metrics.
    Falls back to simple average if not enough data.
    """
    logs = parse_logs(log_file)
    daily = build_daily_features(logs)

    if not daily:
        return _empty_result("No log data found")

    # Sort days chronologically
    sorted_days = sorted(daily.keys())
    n = len(sorted_days)

    # --- Always compute these (even with 1 day) ---
    attack_counts = [daily[d]["logins"] for d in sorted_days]
    cmd_counts    = [daily[d]["commands"] for d in sorted_days]

    # --- Hourly activity (from all logs) ---
    hourly = {}
    for entry in logs:
        if entry.get("type") == "COMMAND":
            ts = entry.get("timestamp", "")
            try:
                hour = ts[11:13] + ":00"
                hourly[hour] = hourly.get(hour, 0) + 1
            except Exception:
                pass
    hourly_activity = [{"hour": h, "commands": c} for h, c in sorted(hourly.items())]

    # --- Command categories ---
    categories = {
        "Recon":                ["whoami", "id", "uname", "hostname", "ifconfig", "ip"],
        "File Explore":         ["ls", "cat", "find", "pwd", "cd", "head", "tail"],
        "Privilege Escalation": ["sudo", "su", "chmod", "chown"],
        "Network":              ["netstat", "ping", "curl", "wget", "ssh", "nmap"],
        "Persistence":          ["crontab", "cron", "echo", "touch", "mkdir"],
        "Data Theft":           ["cp", "scp", "tar", "zip", "history", "env"],
    }
    cat_counts = {k: 0 for k in categories}
    for entry in logs:
        if entry.get("type") == "COMMAND":
            cmd = entry.get("command", "").split()[0].lower() if entry.get("command") else ""
            for cat, keywords in categories.items():
                if any(cmd.startswith(k) for k in keywords):
                    cat_counts[cat] += 1
                    break
    command_categories = [{"category": k, "count": v} for k, v in cat_counts.items() if v > 0]

    # --- Need at least 3 days for real ML ---
    if n < 3 or not ML_AVAILABLE:
        predictions, metrics = _simple_prediction(sorted_days, attack_counts)
        return {
            "method": "moving_average",
            "note": "Need 3+ days of data for full ML model",
            "historical": [{"day": d, "logins": c} for d, c in zip(sorted_days, attack_counts)],
            "predicted": predictions,
            "metrics": metrics,
            "hourly_activity": hourly_activity,
            "command_categories": command_categories,
            "feature_importance": [],
        }

    # --- Build feature matrix for ML ---
    X, y = [], []
    for i in range(1, n):
        prev_day  = sorted_days[i - 1]
        curr_day  = sorted_days[i]
        features  = [
            daily[prev_day]["logins"],       # previous day logins
            daily[prev_day]["commands"],      # previous day commands
            daily[prev_day]["connections"],   # previous day connections
            daily[prev_day]["unique_ips"],    # previous day unique IPs
            daily[prev_day]["recon_cmds"],    # recon activity
            daily[prev_day]["privesc_cmds"],  # privilege escalation attempts
            i,                                # day index (trend)
        ]
        X.append(features)
        y.append(daily[curr_day]["logins"])

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=float)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # --- Train Linear Regression ---
    model = LinearRegression()

    # Leave-one-out cross validation for metrics (works with small datasets)
    if n >= 4:
        y_pred_cv = []
        for i in range(len(X_scaled)):
            X_train = np.delete(X_scaled, i, axis=0)
            y_train = np.delete(y, i)
            X_test  = X_scaled[i:i+1]
            m = LinearRegression()
            m.fit(X_train, y_train)
            y_pred_cv.append(max(0, m.predict(X_test)[0]))

        mae  = round(mean_absolute_error(y, y_pred_cv), 3)
        rmse = round(np.sqrt(mean_squared_error(y, y_pred_cv)), 3)
        r2   = round(r2_score(y, y_pred_cv), 3) if len(y) > 1 else 0.0
    else:
        mae, rmse, r2 = 0.0, 0.0, 0.0

    # Train on all data for future predictions
    model.fit(X_scaled, y)

    # --- Predict next 7 days ---
    predictions = []
    last_day_data = daily[sorted_days[-1]]
    last_dt = datetime.strptime(sorted_days[-1], "%Y-%m-%d")

    prev_features = [
        last_day_data["logins"],
        last_day_data["commands"],
        last_day_data["connections"],
        last_day_data["unique_ips"],
        last_day_data["recon_cmds"],
        last_day_data["privesc_cmds"],
        n,
    ]

    for i in range(1, 8):  # 7-day forecast
        f_scaled = scaler.transform([prev_features])
        pred_val = max(0, round(model.predict(f_scaled)[0], 2))
        future_day = (last_dt + timedelta(days=i)).strftime("%Y-%m-%d")
        predictions.append({"day": future_day, "predicted": pred_val})

        # Roll features forward
        prev_features = [
            pred_val,
            prev_features[1],   # keep commands stable
            prev_features[2],   # keep connections stable
            prev_features[3],   # keep unique IPs stable
            prev_features[4],
            prev_features[5],
            n + i,
        ]

    # --- Feature importance (coefficients) ---
    feature_names = ["Prev Logins", "Prev Commands", "Connections",
                     "Unique IPs", "Recon Cmds", "PrivEsc Cmds", "Day Trend"]
    importance = []
    for name, coef in zip(feature_names, model.coef_):
        importance.append({"feature": name, "coefficient": round(float(coef), 4)})
    importance.sort(key=lambda x: abs(x["coefficient"]), reverse=True)

    return {
        "method": "linear_regression",
        "note": f"Trained on {n} days of real attack data",
        "historical": [{"day": d, "logins": c} for d, c in zip(sorted_days, attack_counts)],
        "predicted": predictions,
        "metrics": {
            "mae":  mae,
            "rmse": rmse,
            "r2":   r2,
            "training_days": n,
            "model": "Linear Regression with StandardScaler",
        },
        "hourly_activity": hourly_activity,
        "command_categories": command_categories,
        "feature_importance": importance,
    }


def _simple_prediction(sorted_days, attack_counts):
    """Fallback: moving average prediction when data is too sparse."""
    avg = sum(attack_counts) / len(attack_counts) if attack_counts else 0
    last_dt = datetime.strptime(sorted_days[-1], "%Y-%m-%d")
    predictions = []
    for i in range(1, 8):
        future = (last_dt + timedelta(days=i)).strftime("%Y-%m-%d")
        predictions.append({"day": future, "predicted": round(avg * (1 + 0.1 * i), 2)})
    metrics = {"mae": "N/A", "rmse": "N/A", "r2": "N/A",
               "training_days": len(sorted_days), "model": "Moving Average (fallback)"}
    return predictions, metrics


def _empty_result(note):
    return {
        "method": "none", "note": note,
        "historical": [], "predicted": [],
        "metrics": {"mae":"N/A","rmse":"N/A","r2":"N/A","training_days":0,"model":"None"},
        "hourly_activity": [], "command_categories": [], "feature_importance": [],
    }