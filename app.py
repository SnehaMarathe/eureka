# app.py
import streamlit as st
import requests
import json
import csv
import os
import pandas as pd
from datetime import datetime, timedelta, timezone
from streamlit_autorefresh import st_autorefresh

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

# === Streamlit Config ===
st.set_page_config(page_title="Blue Energy Alerts", layout="wide")
st.title("🔔 Blue Energy Motors Alert Dashboard")

# === Refresh Control ===
refresh_interval = 10  # in seconds
auto = st.sidebar.toggle("🔄 Auto-Refresh", value=True)

if auto:
    st_autorefresh(interval=refresh_interval * 1000, key="auto_refresh")

if "seen_alerts" not in st.session_state:
    st.session_state.seen_alerts = set()

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

# === Utility ===
def format_ist(ts_ms):
    dt_utc = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    dt_ist = dt_utc + timedelta(hours=5, minutes=30)
    return dt_ist.strftime("%Y-%m-%d %H:%M:%S")

def get_alert_logs():
    end_ts = int(datetime.utcnow().timestamp() * 1000)
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

        serial_no = serial_map.get(unique_key)
        if serial_no is None:
            serial_no = new_serial
            serial_map[unique_key] = serial_no
            new_serial += 1

        dtc_info = log.get("dtc_info", [{}])[0]
        severity = {1: "LOW", 2: "HIGH", 3: "CRITICAL"}.get(log.get("dtcs", {}).get("severity_level", 1), "LOW")

        seen = "✅" if log_id in st.session_state.seen_alerts else "❌"

        row = {
            "S.No.": serial_no,
            "Log ID": log_id,
            "Timestamp": format_ist(timestamp),
            "Vehicle Tag": vehicle_tag,
            "DTC Code": code,
            "Severity": severity,
            "Description": dtc_info.get("description", ""),
            "Seen": seen
        }
        output.append(row)

    save_serial_map(serial_map)
    return output

# === Fetch and Display ===
alerts = get_alert_logs()
data = process_alerts(alerts)

if not data:
    st.info("No alerts found.")
else:
    df = pd.DataFrame(data).sort_values("S.No.", ascending=False)

    # Seen Toggle
    for i, row in df.iterrows():
        log_id = row["Log ID"]
        col1, col2 = st.columns([8, 1])
        with col1:
            st.markdown(
                f"""
                **#{row['S.No.']}** | `{row['Timestamp']}` | 🚛 **{row['Vehicle Tag']}**  
                **Code**: `{row['DTC Code']}` | **Severity**: `{row['Severity']}`  
                _{row['Description']}_
                """
            )
        with col2:
            if st.button("✅" if log_id in st.session_state.seen_alerts else "❌", key=log_id):
                if log_id in st.session_state.seen_alerts:
                    st.session_state.seen_alerts.remove(log_id)
                else:
                    st.session_state.seen_alerts.add(log_id)
                st.rerun()

    # CSV Storage
    clean_data = df.drop(columns=["Seen"])
    if not os.path.exists(HISTORY_CSV):
        with open(HISTORY_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=clean_data.columns)
            writer.writeheader()
            writer.writerows(clean_data.to_dict(orient="records"))
    else:
        with open(HISTORY_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=clean_data.columns)
            writer.writerows(clean_data.to_dict(orient="records"))

# === Footer ===
ist_now = datetime.utcnow() + timedelta(hours=5, minutes=30)
st.markdown(f"✅ Last Updated: `{ist_now.strftime('%Y-%m-%d %H:%M:%S')} IST`")
