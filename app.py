import streamlit as st
import re
import os
import pandas as pd
from datetime import datetime
from collections import defaultdict

# --- Page Config ---
st.set_page_config(page_title="EurekaCheck - CAN Diagnostic", layout="wide")

# --- Header with Logo beside Title ---
col1, col2 = st.columns([1, 6])
with col1:
    st.image("BEM-Logo.png", width=150)  # Make sure this file is in your app folder
with col2:
    st.markdown("## 🔧 EurekaCheck - CAN Bus Diagnostic Tool")
    st.write("Upload a `.trc` file from PCAN-View to get a full diagnosis of ECU connectivity and harness health.")

# --- ECU & Harness Mapping (from Diagnostic PDF) ---
ecu_map = {
    0x17: ("Instrument Cluster", "Cabin Harness", "N/A"),
    0x0B: ("ABS ECU", "Cabin Harness Pig Tail", "PEE0000025"),
    0xEE: ("Telematics", "Cabin Harness Pig Tail", "PEE0000025"),
    0x00: ("Engine ECU", "Front Chassis Wiring Harness", "PEE0000013"),
    0x4E: ("LNG Sensor 1", "Rear Chassis / Pig Tail (double tank)", "PEE0000014 / PEE0000081"),
    0x4F: ("LNG Sensor 2", "Pig Tail for Double Tank", "PEE0000081"),
    0x05: ("Gear Shift Lever", "AMT to Vehicle Wiring Harness", "PEE0000099"),
    0x03: ("TCU", "AMT to Vehicle Wiring Harness", "PEE0000099"),
    0x10: ("Retarder Controller", "Retarder Wiring (Inferred)", "N/A"),
}

def extract_source_address(can_id):
    return can_id & 0xFF

# --- Vehicle Metadata Input ---
st.markdown("### 🚛 Vehicle Info")
vehicle_name = st.text_input("Enter Vehicle Name or ID", max_chars=30)

# --- File Upload ---
uploaded_file = st.file_uploader("📁 Upload your `.trc` file", type=["trc"])

# --- Process File ---
if uploaded_file and vehicle_name.strip():
    content = uploaded_file.read().decode("latin1")
    lines = content.splitlines()

    # Extract seen source addresses
    found_sources = set()
    for line in lines:
        match = re.match(r'\s*\d+\)\s+([\d.]+)\s+Rx\s+([0-9A-Fa-f]{6,8})', line)
        if match:
            can_id = int(match.group(2), 16)
            src_addr = extract_source_address(can_id)
            found_sources.add(src_addr)

    # Build diagnosis report
    report = []
    for addr, (ecu, harness_desc, part_no) in ecu_map.items():
        status = "✅ OK" if addr in found_sources else "❌ MISSING"
        report.append({
            "ECU": ecu,
            "Source Address": f"0x{addr:02X}",
            "Status": status,
            "Harness Description": harness_desc,
            "Harness Part No.": part_no
        })

    df = pd.DataFrame(report)

    # Show diagnosis results
    st.success("Diagnostics completed successfully!")
    st.subheader("📋 ECU Diagnosis Report")
    st.dataframe(df, use_container_width=True)

    # Show missing ECUs
    with st.expander("🔍 Show only MISSING ECUs"):
        missing_df = df[df["Status"].str.contains("MISSING")]
        st.table(missing_df)

    # Save report
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    filename = f"reports/{timestamp}_{vehicle_name.replace(' ', '_')}.csv"
    df.to_csv(filename, index=False)
    st.success(f"📁 Report saved to `{filename}`")

    # Download button (optional)
    st.download_button(
        label="⬇️ Download CSV Report",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name=os.path.basename(filename),
        mime="text/csv"
    )

elif uploaded_file:
    st.warning("Please enter a vehicle name to generate and save the report.")

elif vehicle_name:
    st.info("Please upload a valid `.trc` file to begin diagnosis.")
