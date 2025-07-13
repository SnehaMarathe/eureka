import streamlit as st
import pandas as pd
import requests
from datetime import datetime, timedelta

# === Configuration ===
ACCOUNT_ID = "962759605811675136"
USER_TOKEN = "QyXSX360esEHoVmge2VTwstx6oIE6xdXe7aKwWUXfkz18wlhe01byby4rfRnJFne"
PAGE_SIZE = 20
MAX_PAGES = 5

# === Utility Functions ===
def format_timestamp(ts):
    return datetime.fromtimestamp(ts / 1000).strftime('%Y-%m-%d %H:%M:%S')

def fetch_dtc_activation_removal_time(dtc_code, vehicle_id):
    end_ts = int(datetime.utcnow().timestamp() * 1000)
    start_ts = int((datetime.utcnow() - timedelta(minutes=15)).timestamp() * 1000)

    headers = {
        "accept": "application/json",
        "intangles-user-token": USER_TOKEN
    }

    logs = []
    page = 1

    while page <= MAX_PAGES:
        url = (
            f"https://apis.intangles.com/dtc/{dtc_code}/vehicle/{vehicle_id}"
            f"/historyV2?psize={PAGE_SIZE}&pnum={page}&acc_id={ACCOUNT_ID}&lang=en"
        )
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            break

        entries = response.json().get("dtc_log", [])
        if not entries:
            break

        logs.extend(entries)
        if len(entries) < PAGE_SIZE:
            break

        page += 1

    # Filter logs in time range
    logs = [log for log in logs if start_ts <= log["timestamp"] <= end_ts]
    logs.sort(key=lambda x: x["timestamp"])

    history = []
    current = None

    for log in logs:
        ts = log["timestamp"]
        status = log.get("status")

        if status == "active" and not current:
            current = {"start": ts}
        elif status == "removed" and current:
            current["end"] = ts
            history.append(current)
            current = None

    if current:
        current["end"] = None
        history.append(current)

    if history:
        latest = history[-1]
        start = format_timestamp(latest["start"])
        end = (
            format_timestamp(latest["end"]) if latest["end"] else "❌ Still Active"
        )
        return start, end
    return "-", "-"

# === Mock Data Fetch ===
def get_alert_logs():
    return [
        {
            "vehicle_number": "MH12AB1234",
            "spec_model": "Model X",
            "dtc_code": "789-10",
            "vehicle_id": "1150813660168323072",
            "incident": "Engine Overheat",
            "min_value": 80,
            "max_value": 105,
            "avg_value": 92,
            "total_duration": "00:05:00",
            "total_distance": 3.2,
            "count": 2
        },
        {
            "vehicle_number": "MH14CD5678",
            "spec_model": "Model Y",
            "dtc_code": "790-10",
            "vehicle_id": "1150813660168323072",
            "incident": "Fuel Pressure Low",
            "min_value": 40,
            "max_value": 55,
            "avg_value": 48,
            "total_duration": "00:03:00",
            "total_distance": 1.5,
            "count": 1
        },
    ]

# === Streamlit App ===
st.title("🚛 Vehicle Alerts & DTC Summary")

dtc_alerts = get_alert_logs()

rows = []

for dtc in dtc_alerts:
    start_time, removal_time = fetch_dtc_activation_removal_time(
        dtc["dtc_code"], dtc["vehicle_id"]
    )

    rows.append({
        "Vehicle Number": dtc["vehicle_number"],
        "{ Spec Model }": dtc["spec_model"],
        "Incident": dtc["incident"],
        "Min Param Value": dtc["min_value"],
        "Max Param Value": dtc["max_value"],
        "Avg Param Value": dtc["avg_value"],
        "Min Start and Max End Time": f"{start_time} → {removal_time}",
        "Total Duration": dtc["total_duration"],
        "Total Distance": dtc["total_distance"],
        "Count": dtc["count"]
    })

st.dataframe(pd.DataFrame(rows))
