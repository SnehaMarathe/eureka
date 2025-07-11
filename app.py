# app.py
import streamlit as st
import requests
import json
import time
import csv
import os
import pandas as pd
from datetime import datetime, timedelta, timezone

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
REFRESH_INTERVAL = 10

# === Page Setup ===
st.set_page_config(page_title="Blue Energy Alerts", layout="wide")
st.title("🔔 Blue Energy Motors Alert Dashboard")

if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()
if "seen_alerts" not in st.session_state:
    st.session_state.seen_alerts = {}

# === Serial Tracking ===
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

# === API Functions ===
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

# === Process Alerts ===
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

        serial_no = serial_map.get(unique_key)
        if serial_no is None:
            serial_no = new_serial
            serial_map[unique_key] = serial_no
            new_serial += 1

        dtc_info = log.get("dtc_info", [{}])[0]
        severity = {1: "LOW", 2: "HIGH", 3: "CRITICAL"}.get(log.get("dtcs", {}).get("severity_level", 1), "LOW")

        row = {
            "S.No.": serial_no,
            "Log ID": log_id,
            "Timestamp": format_ist(timestamp),
            "Vehicle Tag": vehicle_tag,
            "DTC Code": code,
            "Severity": severity,
            "Description": dtc_info.get("description", ""),
            "Seen": st.session_state.seen_alerts.get(log_id, False)
        }
        output.append(row)

    save_serial_map(serial_map)
    return output

# === Refresh Control UI ===
auto = st.sidebar.toggle("🔄 Auto-Refresh", value=True)
countdown = st.sidebar.empty()

placeholder = st.empty()

# Manual Refresh
if st.sidebar.button("🔁 Manual Refresh"):
    st.session_state.last_refresh = time.time()
    st.rerun()

# Auto-refresh logic
while auto:
    elapsed = time.time() - st.session_state.last_refresh
    remaining = REFRESH_INTERVAL - int(elapsed)

    if remaining <= 0:
        st.session_state.last_refresh = time.time()
        st.rerun()
    else:
        countdown.info(f"Refreshing in {remaining}s")
        time.sleep(1)  # Delay for countdown
        st.experimental_rerun()  # Rerun only to update countdown

    alerts = get_alert_logs()
    data = process_alerts(alerts)

    if not data:
        st.info("No alerts found.")
    else:
        df = pd.DataFrame(data).sort_values("S.No.", ascending=False)
        edited_df = st.data_editor(df, use_container_width=True, num_rows="dynamic", key="editor")

        # Update session state for Seen
        for _, row in edited_df.iterrows():
            st.session_state.seen_alerts[row["Log ID"]] = row["Seen"]

        # Save to CSV
        if not os.path.exists(HISTORY_CSV):
            with open(HISTORY_CSV, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=df.columns)
                writer.writeheader()
                writer.writerows(df.to_dict(orient="records"))
        else:
            with open(HISTORY_CSV, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=df.columns)
                writer.writerows(df.to_dict(orient="records"))

        st.success("✅ Data saved to alert_history.csv")

    # IST time
    ist_now = datetime.utcnow() + timedelta(hours=5, minutes=30)
    st.markdown(f"✅ Last Updated: `{ist_now.strftime('%Y-%m-%d %H:%M:%S')} IST`")
