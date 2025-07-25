import streamlit as st
import re

# Page configuration
st.set_page_config(page_title="EurekaCheck - CAN Diagnostic", layout="centered")

# ---- Logo & Header Section ----
col1, col2, col3 = st.columns([1, 4, 1])
with col2:
    st.image("BEM-Logo.png", width=160)

st.markdown(
    "<h2 style='text-align: center; color: #003366;'>EurekaCheck</h2>"
    "<h4 style='text-align: center; color: #444;'>CAN Bus Diagnostic Tool</h4>",
    unsafe_allow_html=True
)

st.markdown("---")

# ---- Instructions ----
st.markdown(
    "<p style='text-align: center; font-size: 16px;'>"
    "Upload a <code>.trc</code> file from PCAN-View to receive a complete ECU diagnosis, including harness health and missing communication sources."
    "</p>",
    unsafe_allow_html=True
)

# ---- File Uploader ----
uploaded_file = st.file_uploader(
    "📁 Upload your `.trc` file below:",
    type=["trc"],
    help="You can drag & drop your file or browse. Max file size: 200MB.",
    label_visibility="visible"
)

# ---- ECU Mapping ----
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

# ---- File Processing & Diagnosis ----
if uploaded_file:
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

    # Generate diagnosis report
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

    st.markdown("### 📋 ECU Diagnosis Report")
    st.dataframe(report, use_container_width=True)

    # Optional filter
    with st.expander("🔍 Show only missing ECUs"):
        missing_only = [row for row in report if "MISSING" in row["Status"]]
        if missing_only:
            st.table(missing_only)
        else:
            st.success("All ECUs are communicating. No issues found.")

else:
    st.info("Please upload a valid `.trc` file to begin diagnosis.")
