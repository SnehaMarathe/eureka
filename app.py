import streamlit as st
import re

st.set_page_config(page_title="EurekaCheck - Diagnostic", layout="centered")

# === Header with Logo and Title ===
col1, col2 = st.columns([1, 4])
with col1:
    st.image("BEM-Logo.png", width=100)
with col2:
    st.markdown("<h1 style='margin-bottom:0;'>EurekaCheck</h1>", unsafe_allow_html=True)
    st.caption("Advanced CAN Bus Diagnostic Tool for Blue Energy Motors")

st.markdown("---")

# === Description Box ===
st.markdown("### 🚛 Upload your PCAN `.trc` file")
st.markdown(
    """
    Upload a diagnostic `.trc` file captured using **PCAN-View** to automatically analyze CAN traffic 
    and detect **ECU communication issues** and **wiring harness problems**.

    """
)

# === File Upload ===
uploaded_file = st.file_uploader("📁 Upload .trc file", type=["trc"], label_visibility="collapsed")

if uploaded_file:
    content = uploaded_file.read().decode("latin1")
    lines = content.splitlines()

    st.success("✅ File uploaded successfully!")

    # === Diagnostic Logic ===
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

    found_sources = set()
    for line in lines:
        match = re.match(r'\s*\d+\)\s+([\d.]+)\s+Rx\s+([0-9A-Fa-f]{6,8})', line)
        if match:
            can_id = int(match.group(2), 16)
            src_addr = extract_source_address(can_id)
            found_sources.add(src_addr)

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

    with st.expander("🔍 Show Only MISSING ECUs"):
        st.table([r for r in report if "MISSING" in r["Status"]])
else:
    st.info("👈 Please upload a `.trc` file to begin.")
