# app.py
import streamlit as st
from streamlit_autorefresh import st_autorefresh
import requests
import json
import os
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
st.title("🔔 Alert Dashboard - Only Critical and High - Try1")

REFRESH_INTERVAL = 10  # seconds
st_autorefresh(interval=REFRESH_INTERVAL * 1000, key="datarefresh")

if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()

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

# === Helper Functions ===
def format_ist(ts_ms):
    dt_utc = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    dt_ist = dt_utc + timedelta(hours=5, minutes=30)
    return dt_ist.strftime("%Y-%m-%d %H:%M:%S")

def calculate_active_time(status_history, fallback_timestamp=None, is_removed=False, removed_ts=None):
    now_ms = int(time.time() * 1000)

    if not status_history:
        if fallback_timestamp:
            end_ts = removed_ts if is_removed and removed_ts else now_ms
            active_duration = end_ts - fallback_timestamp
            return format_ist(fallback_timestamp), format_ist(removed_ts) if removed_ts else "-", str(timedelta(milliseconds=active_duration)).split('.')[0]
        else:
            return "-", "-", "-"

    status_history.sort(key=lambda x: x['timestamp'])
    total_active = timedelta(0)
    active_start = None
    last_active = None
    last_removed = None

    for entry in status_history:
        status = entry.get("status", "").lower()
        ts = entry.get("timestamp")
        if status == "active":
            active_start = ts
            last_active = ts
        elif status == "removed":
            last_removed = ts
            if active_start:
                total_active += timedelta(milliseconds=ts - active_start)
                active_start = None

    if active_start:
        if is_removed and removed_ts:
            total_active += timedelta(milliseconds=removed_ts - active_start)
        else:
            total_active += timedelta(milliseconds=now_ms - active_start)

    def ts_to_str(ts):
        return format_ist(ts) if ts else "-"

    return ts_to_str(last_active), ts_to_str(last_removed), str(total_active).split('.')[0]

# === Alert Fetching ===
def get_alert_logs():
    end_ts = int(time.time() * 1000)
    start_ts = end_ts - 2 * 60 * 60 * 1000  # past 2 hours
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
    current_keys = set()
    current_serials = [v["serial"] if isinstance(v, dict) else v for v in serial_map.values()]
    new_serial = max(current_serials, default=0) + 1

    for log in alerts:
        timestamp = log.get("timestamp", 0)
        log_id = log.get("id", "")
        code = log.get("dtcs", {}).get("code", "")
        vehicle_tag = log.get("vehicle_tag", log.get("vehicle_plate", ""))
        unique_key = normalize_key(timestamp, vehicle_tag, code)
        current_keys.add(unique_key)

        severity_value = log.get("dtcs", {}).get("severity_level", 1)
        severity = {1: "LOW", 2: "HIGH", 3: "CRITICAL"}.get(severity_value, "LOW")
        if severity not in ["HIGH", "CRITICAL"]:
            continue

        dtc_info = log.get("dtc_info", [{}])[0]
        status_list = log.get("status", [])
        removal_status = any(s.get("status", "").lower() == "removed" for s in status_list)
        last_active, last_removed, active_duration = calculate_active_time(status_list, timestamp, removal_status, next((s.get("timestamp") for s in status_list if s.get("status", "").lower() == "removed"), None))

        entry = serial_map.get(unique_key)
        if entry:
            serial_no = entry["serial"]
            removed = entry.get("removed", removal_status)
            removal_ts = entry.get("removal_ts", last_removed)
        else:
            serial_no = new_serial
            removed = removal_status
            removal_ts = last_removed if removed else None
            serial_map[unique_key] = {
                "serial": serial_no,
                "removed": removed,
                "removal_ts": removal_ts
            }
            new_serial += 1

        # update removal state if changed
        if unique_key in serial_map:
            if removal_status:
                serial_map[unique_key]["removed"] = True
                serial_map[unique_key]["removal_ts"] = last_removed

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
            "Active Duration": active_duration,
            "Removed": removal_status
        }
        output.append(row)

    # Add past removed DTCs that are not in current alerts
    now = int(time.time() * 1000)
    for key, info in serial_map.items():
        if key in current_keys:
            continue
        if not isinstance(info, dict) or not info.get("removed"):
            continue
        removal_ts = info.get("removal_ts")
        if removal_ts and now - datetime.strptime(removal_ts, "%Y-%m-%d %H:%M:%S").timestamp() * 1000 > 2 * 60 * 60 * 1000:
            continue  # skip very old removed ones

        parts = key.split("_")
        if len(parts) >= 3:
            timestamp = int(parts[0])
            vehicle_tag = parts[1]
            code = parts[2]
            row = {
                "S.No.": info["serial"],
                "Log ID": "-",
                "Timestamp": format_ist(timestamp),
                "Vehicle Tag": vehicle_tag,
                "DTC Code": code,
                "Severity": "UNKNOWN",
                "Description": "Previously Removed DTC",
                "Last Active": format_ist(timestamp),
                "Last Removed": info.get("removal_ts", "-"),
                "Active Duration": "-",
                "Removed": True
            }
            output.append(row)

    save_serial_map(serial_map)
    return output

# === Fetch & Display Alerts ===
alerts = get_alert_logs()
data = process_alerts(alerts)

# === Countdown Timer ===
elapsed = int(time.time() - st.session_state.last_refresh)
countdown = max(0, REFRESH_INTERVAL - elapsed)
st.sidebar.markdown(f"\u23F3 Refreshing in **{countdown}s**")

if st.sidebar.button("\U0001F501 Manual Refresh"):
    st.session_state.last_refresh = time.time()
    st.experimental_rerun()

# === Display Cards ===
if not data:
    st.info("No HIGH or CRITICAL alerts found.")
else:
    for alert in sorted(data, key=lambda x: x["Timestamp"], reverse=True):
        if alert["Removed"]:
            color = "#ccffcc"  # green
        elif alert["Severity"] == "CRITICAL":
            color = "#ffcccc"  # red
        else:
            color = "#ffe5b4"  # orange

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

# === Show Last Updated ===
ist_now = datetime.utcnow() + timedelta(hours=5, minutes=30)
st.markdown(f"\u2705 Last Updated: `{ist_now.strftime('%Y-%m-%d %H:%M:%S')} IST`")
