import streamlit as st
from streamlit_autorefresh import st_autorefresh
import requests
import os
import json
import pandas as pd
from datetime import datetime, timedelta, timezone
import time
import random

# === Config ===
USER_TOKEN = "QyXSX360esEHoVmge2VTwstx6oIE6xdXe7aKwWUXfkz18wlhe01byby4rfRnJFne"
ACCOUNT_ID = "962759605811675136"
VEHICLE_ID = "1150813660168323072"
DTC_CODES = ["789-10", "790-10", "790-5"]
PAGE_SIZE = 20
MAX_PAGES = 5
HEADERS = {
    "accept": "application/json",
    "intangles-user-token": USER_TOKEN,
    "intangles-session-type": "web"
}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERIAL_TRACK_FILE = os.path.join(BASE_DIR, "serial_tracker.json")

# === Streamlit UI ===
st.set_page_config(page_title="DTC Dashboard", layout="wide")
st.title("🚛 Vehicle Alerts & DTC Summary")

REFRESH_INTERVAL = 10
st_autorefresh(interval=REFRESH_INTERVAL * 1000, key="refresh")
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()

# === Utility ===
def format_ist(ts_ms):
    dt_utc = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    return (dt_utc + timedelta(hours=5, minutes=30)).strftime('%Y-%m-%d %H:%M:%S')

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

# === Alerts API ===
def get_alert_logs():
    end_ts = int(time.time() * 1000)
    start_ts = end_ts - 2 * 60 * 60 * 1000
    url = f"https://apis.intangles.com/alertlog/logsV2/{start_ts}/{end_ts}"
    params = {
        "pnum": "1", "psize": "50", "types": "dtc", "sort": "timestamp desc",
        "no_total": "true", "show_resolved_status": "true", "show_driver_name": "true",
        "accounts_with_access": ACCOUNT_ID, "lang": "en"
    }
    response = requests.get(url, headers=HEADERS, params=params)
    return response.json().get("logs", [])

def calculate_active_time(status_history, fallback_ts=None):
    now_ms = int(time.time() * 1000)
    if not status_history and fallback_ts:
        duration = now_ms - fallback_ts
        return format_ist(fallback_ts), "-", str(timedelta(milliseconds=duration)).split('.')[0]
    total_active = timedelta(0)
    active_start = None
    last_active, last_removed = None, None
    for entry in sorted(status_history, key=lambda x: x["timestamp"]):
        ts = entry["timestamp"]
        status = entry["status"].lower()
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
    return (
        format_ist(last_active) if last_active else "-",
        format_ist(last_removed) if last_removed else "-",
        str(total_active).split('.')[0]
    )

def process_alerts(alerts):
    output = []
    current_serials = set(serial_map.values())
    new_serial = max(current_serials, default=0) + 1
    for log in alerts:
        timestamp = log.get("timestamp", 0)
        code = log.get("dtcs", {}).get("code", "")
        vehicle_tag = log.get("vehicle_tag", log.get("vehicle_plate", ""))
        severity = {1: "LOW", 2: "HIGH", 3: "CRITICAL"}.get(log.get("dtcs", {}).get("severity_level", 1), "LOW")
        if severity not in ["HIGH", "CRITICAL"]:
            continue
        unique_key = normalize_key(timestamp, vehicle_tag, code)
        serial_no = serial_map.get(unique_key, new_serial)
        if unique_key not in serial_map:
            serial_map[unique_key] = new_serial
            new_serial += 1
        dtc_info = log.get("dtc_info", [{}])[0]
        last_active, last_removed, active_duration = calculate_active_time(log.get("status", []), timestamp)
        output.append({
            "S.No.": serial_no,
            "Vehicle Tag": vehicle_tag,
            "DTC Code": code,
            "Severity": severity,
            "Description": dtc_info.get("description", ""),
            "Timestamp": format_ist(timestamp),
            "Last Active": last_active,
            "Last Removed": last_removed,
            "Active Duration": active_duration
        })
    save_serial_map(serial_map)
    return output

alerts = process_alerts(get_alert_logs())

# === Display Alerts ===
st.subheader("🔴 Live Alerts (High & Critical)")
if not alerts:
    st.info("No HIGH or CRITICAL alerts found.")
else:
    for alert in sorted(alerts, key=lambda x: x["Timestamp"], reverse=True):
        color = "#ffcccc" if alert["Severity"] == "CRITICAL" else "#ffe5b4"
        st.markdown(
            f"""<div style="background-color:{color};padding:10px;border-radius:10px">
            <b>[{alert['Severity']}]</b> {alert['DTC Code']} - {alert['Description']}<br>
            Vehicle: {alert['Vehicle Tag']}<br>
            Last Active: {alert['Last Active']} | Removed: {alert['Last Removed']}<br>
            Duration: {alert['Active Duration']}
            </div>""", unsafe_allow_html=True
        )

# === Historical DTC Summary ===
st.subheader("📊 DTC Code Summary Report")

def fetch_dtc_logs(dtc_code):
    logs = []
    page = 1
    while page <= MAX_PAGES:
        url = f"https://apis.intangles.com/dtc/{dtc_code}/vehicle/{VEHICLE_ID}/historyV2"
        params = {
            "psize": PAGE_SIZE, "pnum": page,
            "acc_id": ACCOUNT_ID, "lang": "en"
        }
        r = requests.get(url, headers=HEADERS, params=params)
        if r.status_code != 200:
            break
        entries = r.json().get("dtc_log", [])
        if not entries: break
        logs.extend(entries)
        if len(entries) < PAGE_SIZE: break
        page += 1
    return logs

def summarize_dtc(dtc_code, logs):
    history = []
    current = None
    for log in sorted(logs, key=lambda x: x["timestamp"]):
        ts = log["timestamp"]
        odo = log.get("vehicle_odo_info", 0)
        status = log.get("status", "").lower()
        if status == "active" and not current:
            current = {"start": ts, "odo_start": odo}
        elif status == "removed" and current:
            current["end"] = ts
            current["odo_end"] = odo
            history.append(current)
            current = None
    if current:
        current["end"] = int(time.time() * 1000)
        current["odo_end"] = current.get("odo_start", 0)
        history.append(current)

    # Simulated parameter values (replace with actual if available)
    param_vals = [random.uniform(70, 100) for _ in history]
    total_duration = sum([(entry["end"] - entry["start"]) for entry in history])
    total_distance = sum([entry["odo_end"] - entry["odo_start"] for entry in history])
    if not history:
        return None
    return {
        "Vehicle Number": VEHICLE_ID,
        "Model": "[N/A]",
        "Incident": dtc_code,
        "Min Param": round(min(param_vals), 2),
        "Max Param": round(max(param_vals), 2),
        "Avg Param": round(sum(param_vals)/len(param_vals), 2),
        "Start - End": f"{format_ist(min(h['start'] for h in history))} → {format_ist(max(h['end'] for h in history))}",
        "Total Duration": str(timedelta(milliseconds=total_duration)).split('.')[0],
        "Total Distance": f"{total_distance} km",
        "Count": len(history)
    }

summary_rows = []
for code in DTC_CODES:
    raw_logs = fetch_dtc_logs(code)
    summary = summarize_dtc(code, raw_logs)
    if summary:
        summary_rows.append(summary)

if summary_rows:
    df = pd.DataFrame(summary_rows)
    st.dataframe(df)
else:
    st.info("No DTC history found for selected codes.")

# === Footer ===
ist_now = datetime.utcnow() + timedelta(hours=5, minutes=30)
st.markdown(f"\n---\n🕒 Last updated: `{ist_now.strftime('%Y-%m-%d %H:%M:%S')} IST`")

