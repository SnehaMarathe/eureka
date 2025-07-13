import streamlit as st
import pandas as pd

# Assume alerts, all_logs are loaded JSON/dict data
alert_data, active_dtc_codes = process_alerts(alerts)
dtc_history = build_dtc_history(all_logs, active_dtc_codes)

# ---------- UI Starts ----------
st.title("🚨 Unified Alert & DTC History Dashboard")

# 🔥 Active Alerts Table
st.subheader("🚨 Active Alerts")
if alert_data:
    df_alerts = pd.DataFrame(alert_data)
    df_alerts = df_alerts.sort_values(by=["Severity", "Timestamp"], ascending=[True, False])
    st.dataframe(df_alerts)
else:
    st.info("No active alerts in the last 30 minutes.")

# 📜 DTC History
st.subheader("🧾 Activation/Removal History (Last 30 mins DTCs)")

if dtc_history:
    for dtc_code in sorted(dtc_history.keys()):
        st.markdown(f"**DTC Code: {dtc_code}**")
        if dtc_history[dtc_code]:
            df_history = pd.DataFrame(dtc_history[dtc_code])
            st.table(df_history)
        else:
            st.write("No activation/removal history found.")
else:
    st.write("No DTC activity in the last 30 minutes.")

# ⏰ Timestamp
from datetime import datetime
st.markdown(f"**Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} IST")
