import streamlit as st
import re
import io
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors

# --- Streamlit Config ---
st.set_page_config(page_title="EurekaCheck - CAN Diagnostic", layout="wide")

# --- Header with Logo ---
col1, col2 = st.columns([1, 6])
with col1:
    st.image("BEM-Logo.png", width=150)
with col2:
    st.markdown("## 🔧 EurekaCheck - CAN Bus Diagnostic Tool")
    st.write("Upload a `.trc` file from PCAN-View to get a full diagnosis of ECU connectivity, harness status, and power supply integrity.")

# --- ECU → Fuse & Harness Map ---
ecu_fuse_harness_map = {
    "Engine ECU": {
        "fuse": "F42 (30A)",
        "harness": "Front Chassis Wiring Harness",
        "part_no": "PEE0000013",
        "circuit": "Engine Power Supply"
    },
    "ABS ECU": {
        "fuse": "F47 (5A)",
        "harness": "Cabin Harness Pig Tail",
        "part_no": "PEE0000025",
        "circuit": "Brake Circuit"
    },
    "Telematics": {
        "fuse": "F47 (5A)",
        "harness": "Cabin Harness Pig Tail",
        "part_no": "PEE0000025",
        "circuit": "Telematics Supply"
    },
    "Instrument Cluster": {
        "fuse": "F46 (10A)",
        "harness": "Cabin Harness",
        "part_no": "N/A",
        "circuit": "Indicator Circuit"
    },
    "TCU": {
        "fuse": "F43 (15A)",
        "harness": "AMT to Vehicle Wiring Harness",
        "part_no": "PEE0000099",
        "circuit": "Transmission System"
    },
    "Gear Shift Lever": {
        "fuse": "F43 (15A)",
        "harness": "AMT to Vehicle Wiring Harness",
        "part_no": "PEE0000099",
        "circuit": "Gear Control"
    },
    "LNG Sensor 1": {
        "fuse": "F52 (5A)",
        "harness": "Rear Chassis / Pig Tail (Double Tank)",
        "part_no": "PEE0000014 / PEE0000081",
        "circuit": "LNG Level Sensor"
    },
    "LNG Sensor 2": {
        "fuse": "F52 (5A)",
        "harness": "Pig Tail for Double Tank",
        "part_no": "PEE0000081",
        "circuit": "LNG Level Sensor"
    },
    "Retarder Controller": {
        "fuse": "F49 (10A)",
        "harness": "Retarder Wiring (Inferred)",
        "part_no": "N/A",
        "circuit": "Retarder Braking System"
    }
}

# --- Extract CAN Source Address ---
def extract_source_address(can_id):
    return can_id & 0xFF

# --- Generate PDF Buffer ---
def generate_pdf_buffer(report_data, vehicle_name):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 50, f"Diagnostic Report - {vehicle_name}")
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 70, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    y = height - 100
    headers = ["ECU", "Source Addr", "Status", "Harness", "Part No.", "Fuse"]
    col_widths = [100, 70, 60, 150, 90, 60]
    for i, header in enumerate(headers):
        c.setFillColor(colors.grey)
        c.rect(50 + sum(col_widths[:i]), y, col_widths[i], 20, fill=1)
        c.setFillColor(colors.white)
        c.drawString(55 + sum(col_widths[:i]), y + 5, header)

    y -= 20
    c.setFillColor(colors.black)
    for row in report_data:
        if y < 50:
            c.showPage()
            y = height - 50
        for i, key in ["ECU", "Source Address", "Status", "Harness Description", "Harness Part No.", "Fuse"]:
            c.drawString(55 + sum(col_widths[:i]), y, str(row.get(key, "-")))
        y -= 18

    c.save()
    buffer.seek(0)
    return buffer

# --- Rule-Based Reasoning ---
def run_diagnostic_rules(report):
    suggestions = []
    missing_ecus = [r for r in report if "MISSING" in r["Status"]]
    
    # Check for grouped fuse failures
    fuse_counter = {}
    for ecu in missing_ecus:
        fuse = ecu_fuse_harness_map.get(ecu["ECU"], {}).get("fuse")
        if fuse:
            fuse_counter[fuse] = fuse_counter.get(fuse, 0) + 1

    for fuse, count in fuse_counter.items():
        if count >= 2:
            suggestions.append(f"❌ Multiple ECUs missing that share {fuse} — possible blown fuse or power loss.")

    # ECU-specific suggestions
    for ecu in missing_ecus:
        m = ecu_fuse_harness_map.get(ecu["ECU"])
        if m:
            suggestions.append(
                f"❌ {ecu['ECU']} missing — check {m['harness']} (Part No: {m['part_no']}), and Fuse {m['fuse']} on {m['circuit']} circuit."
            )
    if not suggestions:
        suggestions.append("✅ All ECUs are responding — no electrical or harness faults detected.")
    return suggestions

# --- Vehicle Info Input ---
st.markdown("### 🚛 Vehicle Info")
vehicle_name = st.text_input("Enter Vehicle Name or ID", max_chars=30)

# --- File Upload ---
uploaded_file = st.file_uploader("📁 Upload your `.trc` file", type=["trc"])

# --- Main Diagnosis ---
if uploaded_file and vehicle_name.strip():
    content = uploaded_file.read().decode("latin1")
    lines = content.splitlines()

    found_sources = set()
    for line in lines:
        match = re.match(r'\s*\d+\)\s+([\d.]+)\s+Rx\s+([0-9A-Fa-f]{6,8})', line)
        if match:
            can_id = int(match.group(2), 16)
            src_addr = extract_source_address(can_id)
            found_sources.add(src_addr)

    # Build diagnosis report
    report = []
    for addr, (ecu, harness_desc, part_no) in {
        0x17: ("Instrument Cluster", "Cabin Harness", "N/A"),
        0x0B: ("ABS ECU", "Cabin Harness Pig Tail", "PEE0000025"),
        0xEE: ("Telematics", "Cabin Harness Pig Tail", "PEE0000025"),
        0x00: ("Engine ECU", "Front Chassis Wiring Harness", "PEE0000013"),
        0x4E: ("LNG Sensor 1", "Rear Chassis / Pig Tail (double tank)", "PEE0000014 / PEE0000081"),
        0x4F: ("LNG Sensor 2", "Pig Tail for Double Tank", "PEE0000081"),
        0x05: ("Gear Shift Lever", "AMT to Vehicle Wiring Harness", "PEE0000099"),
        0x03: ("TCU", "AMT to Vehicle Wiring Harness", "PEE0000099"),
        0x10: ("Retarder Controller", "Retarder Wiring (Inferred)", "N/A"),
    }.items():
        status = "✅ OK" if addr in found_sources else "❌ MISSING"
        fuse = ecu_fuse_harness_map.get(ecu, {}).get("fuse", "-")
        report.append({
            "ECU": ecu,
            "Source Address": f"0x{addr:02X}",
            "Status": status,
            "Harness Description": harness_desc,
            "Harness Part No.": part_no,
            "Fuse": fuse
        })

    df = pd.DataFrame(report)
    st.success("✅ Diagnostics completed successfully!")

    st.subheader("📋 ECU Status Report")
    st.dataframe(df, use_container_width=True)

    with st.expander("🔍 Show only MISSING ECUs"):
        st.table(df[df["Status"].str.contains("MISSING")])

    # 🧠 Smart Diagnostics
    st.subheader("🧠 Diagnostic Insights")
    for msg in run_diagnostic_rules(report):
        if "❌" in msg:
            st.error(msg)
        else:
            st.success(msg)

    # PDF Report
    pdf_buffer = generate_pdf_buffer(report, vehicle_name)
    st.download_button(
        label="⬇️ Download PDF Report",
        data=pdf_buffer,
        file_name=f"{datetime.now().strftime('%Y-%m-%d_%H%M')}_{vehicle_name.replace(' ', '_')}.pdf",
        mime="application/pdf"
    )

elif uploaded_file:
    st.warning("⚠️ Please enter a vehicle name to generate and download the report.")
elif vehicle_name:
    st.info("📂 Please upload a valid `.trc` file to begin diagnosis.")
