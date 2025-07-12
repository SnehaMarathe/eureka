# app.py
import streamlit as st
from streamlit_autorefresh import st_autorefresh
import requests
import json
import os
import csv
import pandas as pd
from datetime import datetime, timedelta, timezone
import time

# === File Paths ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_CSV = os.path.join(BASE_DIR, "alert_history.csv")
SERIAL_TRACK_FILE = os.path.join(BASE_DIR, "serial_tracker.json")

# === Config ===
USER_TOKEN = "QyXSX360esEHoVmge2VTwstx6oIE6xdXe7aKwWUXfkz18wlhe01byby4rfRnJFne"
ACCOUNT_ID = "962759605811675136"
HEADERS = {
    "intangles-user-token": USER_TOKEN,
    "intangles-session-type": "web",
    "Accept": "application/json"
}
ALERT_TEMPLATE = "https://apis.intangles.com/alertlog/logsV2/{start_ts}/{end_ts}"

# === Streamlit Setup ===
st.set_page_config(page_title="Alerts", layout="wide")
st.title("🔔 Alert Dashboard - Only Critical and High")

REFRESH_INTERVAL = 10  # seconds
# Automatically refresh and track the refresh trigger
autorefresh_triggered = st_autorefresh(interval=REFRESH_INTERVAL * 1000, key="datarefresh")
if autorefresh_triggered and time.time() - st.session_state.last_refresh >= REFRESH_INTERVAL:
    st.session_state.last_refresh = time.time()

# === State ===
if "seen_alerts" not in st.session_state:
    st.session_state.seen_alerts = set()
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()

# === Serial Mapping ===
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

# === Utils ===
def format_ist(ts_ms):
    dt_utc = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    dt_ist = dt_utc + timedelta(hours=5, minutes=30)
    return dt_ist.strftime("%Y-%m-%d %H:%M:%S")

def get_alert_logs():
    end_ts = int(time.time() * 1000)
    start_ts = end_ts - 2 * 60 * 60 * 1000
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
    url = ALERT_TEMPLATE.format(start_ts=start_ts, end_ts=end_ts)
    response = requests.get(url, headers=HEADERS, params=params)
    return response.json().get("logs", [])

def process_alerts(alerts):
    output = []
    current_serials = set(serial_map.values())
    new_serial = max(current_serials, default=0) + 1

    for log in alerts:
        timestamp = log.get("timestamp", 0)
        log_id = log.get("id", "")
        code = log.get("dtcs", {}).get("code", "")
        vehicle_tag = log.get("vehicle_tag", log.get("vehicle_plate", ""))
        unique_key = normalize_key(timestamp, vehicle_tag, code)

        severity_value = log.get("dtcs", {}).get("severity_level", 1)
        severity = {1: "LOW", 2: "HIGH", 3: "CRITICAL"}.get(severity_value, "LOW")

        if severity not in ["HIGH", "CRITICAL"]:
            continue

        serial_no = serial_map.get(unique_key)
        if serial_no is None:
            serial_no = new_serial
            serial_map[unique_key] = serial_no
            new_serial += 1

        dtc_info = log.get("dtc_info", [{}])[0]

        row = {
            "S.No.": serial_no,
            "Log ID": log_id,
            "Timestamp": format_ist(timestamp),
            "Vehicle Tag": vehicle_tag,
            "DTC Code": code,
            "Severity": severity,
            "Description": dtc_info.get("description", ""),
            "Seen": "✅" if log_id in st.session_state.seen_alerts else "❌"
        }
        output.append(row)

    save_serial_map(serial_map)
    return output

# === Fetch Data ===
alerts = get_alert_logs()
data = process_alerts(alerts)

# === Countdown Timer ===
elapsed = int(time.time() - st.session_state.last_refresh)
countdown = max(0, REFRESH_INTERVAL - elapsed)
st.sidebar.markdown(f"⏳ Refreshing in **{countdown}s**")

if st.sidebar.button("🔁 Manual Refresh"):
    st.session_state.last_refresh = time.time()
    st.experimental_rerun()

# === Display Data as Alert Cards ===
if not data:
    st.info("No HIGH or CRITICAL alerts found.")
else:
    for row in sorted(data, key=lambda x: x["S.No."], reverse=True):
        bg_color = "#ffe5b4" if row["Severity"] == "HIGH" else "#ffcccc"  # orange / red
        with st.container():
            st.markdown(
                f"""
                <div style="background-color:{bg_color}; padding:15px; border-radius:10px; margin-bottom:10px;">
                    <strong>🚨 Alert #{row['S.No.']} [{row['Severity']}]</strong><br>
                    <b>Vehicle:</b> {row['Vehicle Tag']}<br>
                    <b>Timestamp:</b> {row['Timestamp']}<br>
                    <b>DTC Code:</b> {row['DTC Code']}<br>
                    <b>Description:</b> {row['Description']}<br>
                    <b>Seen:</b> {row['Seen']}
                </div>
                """,
                unsafe_allow_html=True
            )

# === IST Timestamp ===
ist_now = datetime.utcnow() + timedelta(hours=5, minutes=30)
st.markdown(f"✅ Last Updated: `{ist_now.strftime('%Y-%m-%d %H:%M:%S')} IST`")
