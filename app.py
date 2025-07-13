# app.py
import streamlit as st
from streamlit_autorefresh import st_autorefresh
import requests
import json
import os
import pandas as pd
from datetime import datetime, timedelta, timezone
import time

# === Config ===
USER_TOKEN = "QyXSX360esEHoVmge2VTwstx6oIE6xdXe7aKwWUXfkz18wlhe01byby4rfRnJFne"
ACCOUNT_ID = "962759605811675136"
VEHICLE_ID = "1150813660168323072"
HEADERS = {
    "intangles-user-token": USER_TOKEN,
    "intangles-session-type": "web",
    "accept": "application/json"
}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERIAL_TRACK_FILE = os.path.join(BASE_DIR, "serial_tracker.json")

# === Streamlit Config ===
st.set_page_config(page_title="Unified Alert Dashboard", layout="wide")
st.title("🚨 Unified Alert & DTC History Dashboard")

REFRESH_INTERVAL = 10  # seconds
st_autorefresh(interval=REFRESH_INTERVAL * 1000, key="refresh")

# === Utility ===
def format_ist(ts_ms):
    dt_utc = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    dt_ist = dt_utc + timedelta(hours=5, minutes=30)
    return dt_ist.strftime("%Y-%m-%d %H:%M:%S")

def normalize_key(timestamp, vehicle_tag, code):
    return f"{int(timestamp)}_{vehicle_tag.strip().upper()}_{code.strip().upper()}"

def load_serial_map():
    if os.path.exists(SERIAL_TRACK_FILE):
        with open(SERIAL_TRACK_FILE, "r") as f:
            return json.load(f)
    return {}

def save_serial_map(map_data):
    with open(SERIAL_TRACK_FILE, "w") as f:
        json.dump(map_data, f, indent=2)

serial_map = load_serial_map()

# === Alert Fetching ===
def get_alert_logs():
    end_ts = int(time.time() * 1000)
    start_ts = end_ts - 30 * 60 * 1000  # last 30 minutes
    url = f"https://apis.intangles.com/alertlog/logsV2/{start_ts}/{end_ts}"
    params = {
        "pnum": "1",
        "psize": "50",
        "show_group": "true",
        "types": "dtc",
        "sort": "timestamp desc",
        "no_total": "true",
        "show_resolved_status": "true",
        "show_driver_name": "true",
        "accounts_with_access": ACCOUNT_ID,
        "lang": "en"
    }
    response = requests.get(url, headers=HEADERS, params=params)
    return response.json().get("logs", [])

def calculate_active_time(status_history, fallback_ts=None):
    now_ms = int(time.time() * 1000)
    if not status_history:
        if fallback_ts:
            duration = now_ms - fallback_ts
            return format_ist(fallback_ts), "-", str(timedelta(milliseconds=duration)).split('.')[0]
        return "-", "-", "-"

    status_history.sort(key=lambda x: x['timestamp'])
    total_active = timedelta(0)
    active_start = None
    last_active = last_removed = None

    for entry in status_history:
        ts, status = entry.get("timestamp"), entry.get("status", "").lower()
        if status == "active":
            active_start = ts
            last_active = ts
        elif status == "removed":
            last_removed = ts
            if active_start:
                total_active += timedelta(milliseconds=ts - active_start)
                active_start = None

    if active_start:
        total_active += timedelta(milliseconds=now_ms - active_start)

    return format_ist(last_active) if last_active else "-", format_ist(last_removed) if last_removed else "-", str(total_active).split('.')[0]

# === Process Alerts and Track DTCs ===
def process_alerts(alerts):
    output = []

    # Filter only numeric serial values
    current_serials = {v for v in serial_map.values() if isinstance(v, int)}
    new_serial = max(current_serials, default=0) + 1

    active_dtc_codes = set()

    for log in alerts:
        timestamp = log.get("timestamp", 0)
        log_id = log.get("id", "")
        code = log.get("dtcs", {}).get("code", "")
        vehicle_tag = log.get("vehicle_tag", log.get("vehicle_plate", ""))
        unique_key = normalize_key(timestamp, vehicle_tag, code)

        severity_value = log.get("dtcs", {}).get("severity_level", 1)
        severity = {1: "LOW", 2: "HIGH", 3: "CRITICAL"}.get(severity_value, "LOW")

        if severity not in ["HIGH", "CRITICAL"]:
            continue  # Skip non-important alerts

        # 🛠️ Validate serial_no mapping
        serial_no = serial_map.get(unique_key)
        if not isinstance(serial_no, int):
            serial_no = new_serial
            serial_map[unique_key] = serial_no
            new_serial += 1

        dtc_info = log.get("dtc_info", [{}])[0]
        status_list = log.get("status", [])
        last_active, last_removed, active_duration = calculate_active_time(status_list, timestamp)

        row = {
            "S.No.": serial_no,
            "Log ID": log_id,
            "Timestamp": format_ist(timestamp),
            "Vehicle Tag": vehicle_tag,
            "DTC Code": code,
            "Severity": severity,
            "Description": dtc_info.get("description", ""),
            "Last Active": last_active,
            "Last Removed": last_removed,
            "Active Duration": active_duration
        }

        output.append(row)
        active_dtc_codes.add(code)

    save_serial_map(serial_map)
    return output, active_dtc_codes


# === DTC History ===
def fetch_dtc_logs(dtc_code):
    logs = []
    page, PAGE_SIZE = 1, 20
    MAX_PAGES = 5
    while page <= MAX_PAGES:
        url = f"https://apis.intangles.com/dtc/{dtc_code}/vehicle/{VEHICLE_ID}/historyV2"
        params = {
            "psize": PAGE_SIZE,
            "pnum": page,
            "acc_id": ACCOUNT_ID,
            "lang": "en"
        }
        response = requests.get(url, headers=HEADERS, params=params)
        if response.status_code != 200:
            break
        page_logs = response.json().get("dtc_log", [])
        if not page_logs:
            break
        logs.extend(page_logs)
        if len(page_logs) < PAGE_SIZE:
            break
        page += 1
    return logs

def analyze_logs(logs):
    logs.sort(key=lambda x: x["timestamp"])
    history, current = [], None
    for log in logs:
        ts, status = log["timestamp"], log.get("status")
        odo = log.get("vehicle_odo_info", "N/A")
        if status == "active" and not current:
            current = {"start": ts, "odo": odo}
        elif status == "removed" and current:
            current["end"] = ts
            history.append(current)
            current = None
    if current:
        current["end"] = None
        history.append(current)
    return history

# === Main Display Logic ===
alerts = get_alert_logs()
data, active_dtc_codes = process_alerts(alerts)

# === Display Alerts ===
if not data:
    st.info("No HIGH or CRITICAL alerts in the past 30 minutes.")
else:
    for alert in sorted(data, key=lambda x: x["Timestamp"], reverse=True):
        color = "#ffcccc" if alert["Severity"] == "CRITICAL" else "#ffe5b4"
        st.markdown(
            f"""
            <div style="background-color:{color}; padding:10px; border-radius:8px; margin-bottom:10px;">
                <strong>[{alert['Severity']}]</strong><br>
                <strong>Timestamp:</strong> {alert['Timestamp']}<br>
                <strong>Vehicle:</strong> {alert['Vehicle Tag']}<br>
                <strong>DTC Code:</strong> {alert['DTC Code']}<br>
                <strong>Description:</strong> {alert['Description']}<br>
                <strong>Last Active:</strong> {alert['Last Active']}<br>
                <strong>Last Removed:</strong> {alert['Last Removed']}<br>
                <strong>Active Duration:</strong> {alert['Active Duration']}<br>
            </div>
            """,
            unsafe_allow_html=True
        )

# === Display DTC History ===
st.subheader("🧾 Activation/Removal History (Last 30 mins DTCs)")
for code in sorted(active_dtc_codes):
    logs = fetch_dtc_logs(code)
    history = analyze_logs(logs)
    st.markdown(f"**DTC Code: {code}**")
    if not history:
        st.markdown("*No activation/removal history found.*")
    else:
        for i, entry in enumerate(history, 1):
            start = format_ist(entry["start"])
            end = format_ist(entry["end"]) if entry["end"] else "❌ Still Active"
            odo = entry["odo"]
            st.markdown(f"{i}. **Activated:** {start} | **Odo:** {odo} km | **Cleared:** {end}")

# === Footer ===
ist_now = datetime.utcnow() + timedelta(hours=5, minutes=30)
st.markdown(f"Last Updated: `{ist_now.strftime('%Y-%m-%d %H:%M:%S')} IST`")
