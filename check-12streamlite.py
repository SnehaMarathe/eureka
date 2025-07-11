import streamlit as st
import requests
import json
import time
from datetime import datetime, timedelta, timezone

# === CONFIGURATION ===
USER_TOKEN = "QyXSX360esEHoVmge2VTwstx6oIE6xdXe7aKwWUXfkz18wlhe01byby4rfRnJFne"
ACCOUNT_ID = "962759605811675136"
HEADERS = {
    "intangles-user-token": USER_TOKEN,
    "intangles-session-type": "web",
    "Accept": "application/json"
}
OBD_TEMPLATE = "https://apis.intangles.com/vehicle/{}/getLastFewObdData"
ALERT_TEMPLATE = "https://apis.intangles.com/alertlog/logsV2/{start_ts}/{end_ts}"

# === FUNCTIONS ===
@st.cache_data(ttl=60)
def get_alert_logs():
    end_ts = int(time.time() * 1000)
    start_ts = end_ts - 2 * 60 * 60 * 1000  # last 2 hours
    params = {
        "pnum": "1",
        "psize": "20",
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

@st.cache_data(ttl=60)
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
                    value = d.get("value")
                    if isinstance(value, list):
                        value = value[0] if value else None
                    if value is not None:
                        try:
                            value = round(float(value), 1)
                        except:
                            pass
                        if pid == "84": summary["Wheel Speed (kmph)"] = value
                        elif pid == "110": summary["Coolant Temp (°C)"] = value
                        elif pid == "158": summary["Battery Voltage (V)"] = value
                        elif pid == "190": summary["Engine Speed (RPM)"] = value
    except:
        pass
    return summary

def format_ist(ts_ms):
    dt_utc = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    dt_ist = dt_utc + timedelta(hours=5, minutes=30)
    return dt_ist.strftime("%Y-%m-%d %H:%M:%S")

def process_alerts(alerts):
    rows = []
    for alert in alerts:
        ts = alert.get("timestamp", 0)
        vehicle_id = alert.get("vehicle_id", "")
        vehicle_tag = alert.get("vehicle_tag", alert.get("vehicle_plate", ""))
        code = alert.get("dtcs", {}).get("code", "")
        severity = {1: "LOW", 2: "HIGH", 3: "CRITICAL"}.get(alert.get("dtcs", {}).get("severity_level", 1), "LOW")
        dtc_info = alert.get("dtc_info", [{}])[0]
        obd = get_obd_data(vehicle_id)

        rows.append({
            "Timestamp (IST)": format_ist(ts),
            "Vehicle Tag": vehicle_tag,
            "DTC Code": code,
            "Severity": severity,
            "Location": alert.get("address", ""),
            "Description": dtc_info.get("description", ""),
            **obd
        })
    return rows

# === STREAMLIT UI ===
st.set_page_config(page_title="Blue Energy Alerts", layout="wide")
st.title("🔔 Blue Energy Motors Alert Dashboard")

# === Auto-refresh Settings ===
refresh_interval_sec = 10

# Toggle to enable/disable auto-refresh
auto_refresh = st.sidebar.toggle("🔄 Enable Auto-Refresh", value=True)
countdown_placeholder = st.sidebar.empty()

# Timer logic
if auto_refresh:
    if "last_refresh" not in st.session_state:
        st.session_state.last_refresh = time.time()

    elapsed = time.time() - st.session_state.last_refresh
    remaining = refresh_interval_sec - int(elapsed)
    if remaining <= 0:
        st.session_state.last_refresh = time.time()
        st.experimental_rerun()
    else:
        countdown_placeholder.info(f"Auto-refresh in {remaining} seconds...")

# Manual refresh button
if st.button("🔁 Refresh Now"):
    st.session_state.last_refresh = time.time()
    st.experimental_rerun()

# === Fetch and Display Data ===
with st.spinner("Fetching latest alerts..."):
    alerts = get_alert_logs()
    data = process_alerts(alerts)

# === Display Table ===
st.markdown(f"✅ Last Updated: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`")

if not data:
    st.info("No alerts found in the past 2 hours.")
else:
    st.dataframe(data, use_container_width=True)
