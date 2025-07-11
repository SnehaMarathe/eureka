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
OBD_TEMPLATE = "https://apis.intangles.com/vehicle/{}/getLastFewObdData"
ALERT_TEMPLATE = "https://apis.intangles.com/alertlog/logsV2/{start_ts}/{end_ts}"

# === State Setup ===
st.set_page_config(page_title="Blue Energy Alerts", layout="wide")
st.title("🔔 Blue Energy Motors Alert Dashboard")

refresh_interval = 10
MAX_OBD_LOOKUPS = 10  # Limit OBD lookups per refresh to speed things up

if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()
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

# === API Functions ===
def format_ist(ts_ms):
    dt_utc = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    dt_ist = dt_utc + timedelta(hours=5, 30)
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

def get_obd_data(vehicle_id):
    url = OBD_TEMPLATE.format(vehicle_id)
    params = {"packet_count": 3, "acc_id": ACCOUNT_ID, "lang": "en"}
    summary = {
        "Battery Voltage (V)": "N/A",
        "Engine Speed (RPM)": "N/A",
        "Coolant Temp (°C)": "N/A",
        "Wheel Speed (kmph)": "N/A"
    }
    try:
        r = requests.get(url, headers=HEADERS, params=params)
        packets = r.json().get("results") or []
        for pkt in packets:
            battery = pkt.get("battery")
            if battery and "voltage" in battery:
                summary["Battery Voltage (V)"] = round(float(battery["voltage"]), 1)
            for p in pkt.get("pids", []):
                for pid, d in p.items():
                    val = d.get("value")
                    if isinstance(val, list):
                        val = val[0] if val else None
                    if val is not None:
                        try:
                            val = round(float(val), 1)
                        except:
                            pass
                        if pid == "84": summary["Wheel Speed (kmph)"] = val
                        elif pid == "110": summary["Coolant Temp (°C)"] = val
                        elif pid == "158": summary["Battery Voltage (V)"] = val
                        elif pid == "190": summary["Engine Speed (RPM)"] = val
    except:
        pass
    return summary

# === Process Alerts ===
def process_alerts(alerts):
    output = []
    current_serials = set(serial_map.values())
    new_serial = max(current_serials, default=0) + 1

    for i, log in enumerate(alerts):
        vehicle_id = log.get("vehicle_id", "")
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

        obd = get_obd_data(vehicle_id) if i < MAX_OBD_LOOKUPS else {
            "Battery Voltage (V)": "-",
            "Engine Speed (RPM)": "-",
            "Coolant Temp (°C)": "-",
            "Wheel Speed (kmph)": "-"
        }

        row = {
            "S.No.": serial_no,
            "Log ID": log_id,
            "Timestamp": format_ist(timestamp),
            "Vehicle Tag": vehicle_tag,
            "DTC Code": code,
            "Severity": severity,
            "Description": dtc_info.get("description", ""),
            **obd
        }
        output.append(row)

    save_serial_map(serial_map)
    return output

# === Auto-Refresh and UI ===
auto = st.sidebar.toggle("🔄 Auto-Refresh", value=True)
countdown = st.sidebar.empty()

elapsed = time.time() - st.session_state.last_refresh
remaining = refresh_interval - int(elapsed)
if auto:
    if remaining <= 0:
        st.session_state.last_refresh = time.time()
        st.experimental_rerun()
    else:
        countdown.info(f"Refreshing in {remaining}s")

if st.button("🔁 Manual Refresh"):
    st.session_state.last_refresh = time.time()
    st.experimental_rerun()

# === Fetch and Display ===
alerts = get_alert_logs()
data = process_alerts(alerts)

if not data:
    st.info("No alerts found.")
else:
    df = pd.DataFrame(data).sort_values("S.No.", ascending=False)
    st.dataframe(df, use_container_width=True, height=600)

    if not os.path.exists(HISTORY_CSV):
        with open(HISTORY_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
    else:
        with open(HISTORY_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writerows(data)

    st.success("✅ Data saved to alert_history.csv")

# Show IST Timestamp
ist_now = datetime.utcnow() + timedelta(hours=5, minutes=30)
st.markdown(f"✅ Last Updated: `{ist_now.strftime('%Y-%m-%d %H:%M:%S')} IST`")

# Inject auto-refresh meta tag if enabled
if auto:
    st.markdown("""
        <meta http-equiv="refresh" content="10">
    """, unsafe_allow_html=True)
