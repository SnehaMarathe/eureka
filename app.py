import streamlit as st
from datetime import datetime, timedelta
from collections import defaultdict

# Sample alert data (replace with actual input source or API)
alerts = [
    {
        "timestamp": "2025-07-13 13:38:30",
        "vehicle": "MH 14 LB 3735",
        "dtc_code": "7581",
        "description": "Rail fuel pressure too low (below first threshold) [ Medium issue not affecting engine / ATS integrity. Continue the mission and go to Service Station to control/fix root cause ]",
        "last_active": "2025-07-13 13:38:30",
        "last_removed": "-",
        "active_duration": "0:01:40",
        "severity": "HIGH"
    },
    {
        "timestamp": "2025-07-13 13:31:24",
        "vehicle": "MH 14 LL 3864",
        "dtc_code": "1328",
        "description": "Misfire With Spark Ignition In Cylinder 6 For Potential Catalyst Damage [ STOP immediately... ]",
        "last_active": "2025-07-13 13:31:24",
        "last_removed": "-",
        "active_duration": "0:08:46",
        "severity": "CRITICAL"
    }
]

# Sample log history (event_type can be Activated or Removed)
all_logs = [
    {
        "timestamp": "2025-07-13 13:30:00",
        "dtc_code": "7581",
        "event_type": "Activated",
        "status": "Active"
    },
    {
        "timestamp": "2025-07-13 13:35:00",
        "dtc_code": "7581",
        "event_type": "Removed",
        "status": "Cleared"
    },
    {
        "timestamp": "2025-07-13 13:25:00",
        "dtc_code": "1328",
        "event_type": "Activated",
        "status": "Active"
    }
]


def process_alerts(alerts):
    processed = []
    active_dtc_codes = set()

    for alert in alerts:
        severity = alert.get("severity", "UNKNOWN").upper()
        dtc_code = alert.get("dtc_code", "")
        active_dtc_codes.add(dtc_code)

        processed.append({
            "Timestamp": alert.get("timestamp", "-"),
            "Vehicle": alert.get("vehicle", "N/A"),
            "DTC Code": dtc_code,
            "Severity": severity,
            "Description": alert.get("description", ""),
            "Last Active": alert.get("last_active", "-"),
            "Last Removed": alert.get("last_removed", "-"),
            "Active Duration": alert.get("active_duration", "-"),
        })

    return processed, active_dtc_codes


def build_dtc_history(logs, dtc_codes):
    dtc_history = defaultdict(list)
    now = datetime.strptime("2025-07-13 13:40:00", "%Y-%m-%d %H:%M:%S")
    window_start = now - timedelta(minutes=30)

    for log in logs:
        try:
            log_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
            if log["dtc_code"] in dtc_codes and window_start <= log_time <= now:
                dtc_history[log["dtc_code"]].append({
                    "Time": log["timestamp"],
                    "Event": log["event_type"],
                    "Status": log["status"]
                })
        except Exception:
            continue

    return dtc_history


# === Streamlit UI ===
st.set_page_config(page_title="Unified Alert & DTC History Dashboard", layout="wide")
st.title("🚨 Unified Alert & DTC History Dashboard")

# Process alerts
alert_data, active_dtc_codes = process_alerts(alerts)

# Display each alert
for alert in alert_data:
    st.markdown(f"### [{alert['Severity']}]")
    st.write(f"**Timestamp:** {alert['Timestamp']}")
    st.write(f"**Vehicle:** {alert['Vehicle']}")
    st.write(f"**DTC Code:** {alert['DTC Code']}")
    st.write(f"**Description:** {alert['Description']}")
    st.write(f"**Last Active:** {alert['Last Active']}")
    st.write(f"**Last Removed:** {alert['Last Removed']}")
    st.write(f"**Active Duration:** {alert['Active Duration']}")
    st.markdown("---")

# History section
st.subheader("🧾 Activation/Removal History (Last 30 mins DTCs)")
dtc_history = build_dtc_history(all_logs, active_dtc_codes)

for code in sorted(active_dtc_codes):
    st.markdown(f"#### DTC Code: {code}")
    history = dtc_history.get(code)
    if not history:
        st.write("No activation/removal history found.")
    else:
        for event in history:
            st.write(f"- **{event['Time']}** → *{event['Event']}* ({event['Status']})")

st.caption(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} IST")
