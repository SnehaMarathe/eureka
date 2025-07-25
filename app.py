import streamlit as st
import re
import os
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch

# --- Page Config ---
st.set_page_config(page_title="EurekaCheck - CAN Diagnostic", layout="wide")

# --- Header with Logo beside Title ---
col1, col2 = st.columns([1, 6])
with col1:
    st.image("BEM-Logo.png", width=150)  # Make sure this file is in your app folder
with col2:
    st.markdown("## 🔧 EurekaCheck - CAN Bus Diagnostic Tool")
    st.write("Upload a `.trc` file from PCAN-View to get a full diagnosis of ECU connectivity and harness health.")

# --- ECU & Harness Mapping ---
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

def generate_pdf(report_data, vehicle_name, filename):
    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 50, f"Diagnostic Report - {vehicle_name}")
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 70, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Table headers
    y = height - 100
    headers = ["ECU", "Source Addr", "Status", "Harness", "Part No."]
    col_widths = [120, 80, 60, 170, 80]
    for i, header in enumerate(headers):
        c.setFillColor(colors.grey)
        c.rect(50 + sum(col_widths[:i]), y, col_widths[i], 20, fill=1)
        c.setFillColor(colors.white)
        c.drawString(55 + sum(col_widths[:i]), y + 5, header)

    # Table rows
    c.setFillColor(colors.black)
    y -= 20
    for row in report_data:
        if y < 50:  # new page if space is low
            c.showPage()
            y = height - 50
        for i, key in enumerate(["ECU", "Source Address", "Status", "Harness Description", "Harness Part No."]):
            c.setFillColor(colors.black)
            c.drawString(55 + sum(col_widths[:i]), y, str(row[key]))
        y -= 18

    c.save()

# --- Input Vehicle Info ---
st.markdown("### 🚛 Vehicle Info")
vehicle_name = st.text_input("Enter Vehicle Name or ID", max_chars=30)

# --- Upload File ---
uploaded_file = st.file_uploader("📁 Upload your `.trc` file", type=["trc"])

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

    st.success("Diagnostics completed successfully!")
    st.subheader("📋 ECU Diagnosis Report")
    st.dataframe(df, use_container_width=True)

    with st.expander("🔍 Show only MISSING ECUs"):
        st.table(df[df["Status"].str.contains("MISSING")])

    # Save PDF
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    pdf_filename = f"reports/{timestamp}_{vehicle_name.replace(' ', '_')}.pdf"
    generate_pdf(report, vehicle_name, pdf_filename)
    st.success(f"📁 PDF Report saved to `{pdf_filename}`")

    # Show download button
    with open(pdf_filename, "rb") as f:
        st.download_button(
            label="⬇️ Download PDF Report",
            data=f,
            file_name=os.path.basename(pdf_filename),
            mime="application/pdf"
        )

elif uploaded_file:
    st.warning("Please enter a vehicle name to generate and save the report.")

elif vehicle_name:
    st.info("Please upload a valid `.trc` file to begin diagnosis.")
