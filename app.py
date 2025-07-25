# Phase 2 - 1
import streamlit as st
import re
import io
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from collections import defaultdict
import os

# --- Streamlit Config ---
st.set_page_config(page_title="EurekaCheck - CAN Diagnostic", layout="wide")

# --- Visitor Counter ---
def update_visitor_count():
    counter_file = "counter.txt"
    if not os.path.exists(counter_file):
        with open(counter_file, "w") as f:
            f.write("0")
    if "visitor_counted" not in st.session_state:
        with open(counter_file, "r+") as f:
            count = int(f.read().strip())
            count += 1
            f.seek(0)
            f.write(str(count))
            f.truncate()
        st.session_state["visitor_counted"] = True
        st.session_state["visitor_count"] = count
    else:
        with open(counter_file, "r") as f:
            st.session_state["visitor_count"] = int(f.read().strip())

update_visitor_count()

# --- User Credentials ---
USER_CREDENTIALS = {
    "admin": "admin123",
    "user": "check2025"
}

def login():
    st.markdown("## 🔐 User Login")
    with st.form("login_form"):
        username = st.text_input("Username", key="username_input")
        password = st.text_input("Password", type="password", key="password_input")
        submitted = st.form_submit_button("🔓 Login")
        if submitted:
            if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
                st.session_state["authenticated"] = True
                st.session_state["username"] = username
                st.success(f"Welcome, {username}!")
                st.rerun()
            else:
                st.error("❌ Invalid username or password.")

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    login()
    st.stop()

# --- Header ---
col1, col2, col3 = st.columns([1, 6, 1])
with col1:
    st.image("BEM-Logo.png", width=150)
with col2:
    st.markdown(
        """
        <div style='text-align: center;'>
            <h2 style='margin-bottom: 0;'>🔧 EurekaCheck - CAN Bus Diagnostic Tool</h2>
            <p style='margin-top: 0;'>Upload a <code>.trc</code> file to analyze ECU health.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
with col3:
    st.markdown(
        f"<p style='text-align: right; color: gray;'>👥 Visitors: {st.session_state['visitor_count']}</p>",
        unsafe_allow_html=True
    )
st.markdown("<hr style='margin-top: 0.5rem;'>", unsafe_allow_html=True)

# --- ECU & Drawing Maps ---
ecu_connector_map = {
    "Engine ECU": {"connector": "Connector 4", "location": "Front left engine bay near pre-fuse box", "harness": "Front Chassis Wiring Harness", "fuse": "F42"},
    "ABS ECU": {"connector": "Connector 3", "location": "Cabin firewall, near brake switch", "harness": "Cabin Harness Pig Tail", "fuse": "F47"},
    "Telematics": {"connector": "Cabin Interface Connector (Brown)", "location": "Behind dashboard, cabin side", "harness": "Cabin Harness Pig Tail", "fuse": "F47"},
    "Instrument Cluster": {"connector": "89E", "location": "Dashboard behind cluster unit", "harness": "Cabin Harness", "fuse": "F46"},
    "TCU": {"connector": "AMT Gearbox Inline Connector", "location": "Under chassis near gearbox", "harness": "AMT to Vehicle Wiring Harness", "fuse": "F43"},
    "Gear Shift Lever": {"connector": "AMT Gear Shifter Inline Connector", "location": "Cabin floor, gear lever base", "harness": "AMT to Vehicle Wiring Harness", "fuse": "F43"},
    "LNG Sensor 1": {"connector": "Rear Harness Inline", "location": "Left rear chassis, tank area", "harness": "Rear Chassis / Pig Tail", "fuse": "F52"},
    "LNG Sensor 2": {"connector": "Pig Tail Tank Sensor", "location": "Right rear tank (if double tank)", "harness": "Pig Tail for Double Tank", "fuse": "F52"},
    "Retarder Controller": {"connector": "Retarder Module Connector", "location": "Chassis, near prop shaft", "harness": "Retarder Wiring", "fuse": "F49"},
}

drawing_map = {
    "Connector 3": "PEE0000014_K.pdf",
    "Connector 4": "PEE0000014_K.pdf",
    "F46": "PEE0000014_K.pdf",
    "F47": "PEE0000014_K.pdf",
    "F42": "PEE0000014_K.pdf",
    "Cabin Harness": "PEE0000014_K.pdf",
    "Rear Harness": "PEE0000083_A_01072024.pdf",
    "Retarder Wiring": "PEE0000013_J_01072024.pdf",
    "Pig Tail for Double Tank": "PEE0000083_A_01072024.pdf",
    "Trailer Interface": "PEE0000084.pdf"
}

# --- Utility Functions ---
def extract_source_address(can_id):
    return can_id & 0xFF

def generate_pdf_buffer(report_data, vehicle_name):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 50, f"Diagnostic Report - {vehicle_name}")
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 70, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y = height - 100
    headers = ["ECU", "Source Addr", "Status", "Connector", "Location", "Fuse"]
    col_widths = [100, 70, 60, 120, 120, 50]
    for i, header in enumerate(headers):
        c.setFillColor(colors.grey)
        c.rect(50 + sum(col_widths[:i]), y, col_widths[i], 20, fill=1)
        c.setFillColor(colors.white)
        c.drawString(55 + sum(col_widths[:i]), y + 5, header)
    y -= 20
    for row in report_data:
        if y < 50:
            c.showPage()
            y = height - 50
        for i, key in enumerate(["ECU", "Source Address", "Status", "Connector", "Location", "Fuse"]):
            c.setFillColor(colors.black)
            c.drawString(55 + sum(col_widths[:i]), y, str(row.get(key, "-")))
        y -= 18
    c.save()
    buffer.seek(0)
    return buffer

def infer_root_causes(df):
    causes = {"Fuse": defaultdict(list), "Connector": defaultdict(list), "Harness": defaultdict(list)}
    for _, row in df[df["Status"] == "❌ MISSING"].iterrows():
        causes["Fuse"][row["Fuse"]].append(row["ECU"])
        causes["Connector"][row["Connector"].strip()].append(row["ECU"])
        harness = ecu_connector_map.get(row["ECU"], {}).get("harness", "-")
        causes["Harness"][harness].append(row["ECU"])
    ranked = []
    for cause_type, items in causes.items():
        for item, affected in items.items():
            total = sum(
                1 for row in df.itertuples()
                if (row.Fuse == item if cause_type == "Fuse"
                    else row.Connector.strip() == item if cause_type == "Connector"
                    else ecu_connector_map.get(row.ECU, {}).get("harness") == item)
            )
            confidence = round(len(affected) / total * 100) if total > 0 else 0
            ranked.append({
                "Type": cause_type,
                "Component": item,
                "Affected ECUs": affected,
                "Missing": len(affected),
                "Total": total,
                "Confidence": confidence
            })
    ranked.sort(key=lambda x: (-x["Confidence"], -x["Missing"]))
    return ranked

def generate_detailed_diagnosis(ecu_name):
    entry = ecu_connector_map.get(ecu_name, {})
    if not entry:
        return "No diagnostic mapping available."
    connector = entry.get("connector", "-")
    fuse = entry.get("fuse", "-")
    harness = entry.get("harness", "-")
    drawing = drawing_map.get(connector) or drawing_map.get(fuse) or drawing_map.get(harness)
    wire_examples = {
        "Instrument Cluster": ["14A", "14C", "14K", "53K"],
        "ABS ECU": ["16A", "16B", "53E", "53F", "53M"],
        "Telematics": ["13B", "13C", "53E", "53F"],
        "Engine ECU": ["11A", "11B", "11C", "11G"],
        "TCU": ["12G", "12F", "51J", "12C"],
        "Gear Shift Lever": ["12H", "12K", "12L", "12A"],
        "Retarder Controller": ["51A", "51B", "51C"],
        "LNG Sensor 1": ["53A", "53B"],
        "LNG Sensor 2": ["53C", "53D"]
    }
    wires = wire_examples.get(ecu_name, ["(refer drawing)"])
    return f"""
### 🔍 Diagnosis: {ecu_name} Missing

- ✅ **From diagnostic logic:**
  - Connector: `{connector}`
  - Fuse: `{fuse}`
  - Harness: `{harness}`

- 🔎 **From Drawing**: `{drawing}`
  - Trace wires: {', '.join(wires)}

### 🛠️ Suggested Checks:
1. Verify voltage from **{fuse}** to **{connector}**.
2. Inspect CAN lines: CAN_H (`R/G`), CAN_L (`Br/W`).
3. Check connector `{connector}` for corrosion or damage.
4. Inspect harness `{harness}` bends and joints for breaks.
"""

# --- User Inputs ---
st.markdown("### 🚛 Vehicle Info")
vehicle_name = st.text_input("Enter Vehicle Name or ID", max_chars=30)

st.markdown("### ⚙️ Configuration")
has_double_tank = st.checkbox("Has Double Tank?", value=True)
has_amt = st.checkbox("Has AMT?", value=True)
has_retarder = st.checkbox("Has Retarder?", value=True)

uploaded_file = st.file_uploader("📁 Upload `.trc` File", type=["trc"])

# --- Process File ---
if uploaded_file and vehicle_name.strip():
    lines = uploaded_file.read().decode("latin1").splitlines()
    found_sources = {
        extract_source_address(int(re.match(r'\s*\d+\)\s+[\d.]+\s+Rx\s+([0-9A-Fa-f]{6,8})', line).group(1), 16))
        for line in lines if re.match(r'\s*\d+\)\s+[\d.]+\s+Rx\s+([0-9A-Fa-f]{6,8})', line)
    }

    ecu_map = {
        0x17: "Instrument Cluster",
        0x0B: "ABS ECU",
        0xEE: "Telematics",
        0x00: "Engine ECU",
        0x4E: "LNG Sensor 1",
        0x4F: "LNG Sensor 2",
        0x05: "Gear Shift Lever",
        0x03: "TCU",
        0x10: "Retarder Controller",
    }

    report = []
    for addr, ecu in ecu_map.items():
        if ecu == "LNG Sensor 2" and not has_double_tank: continue
        if ecu in ["TCU", "Gear Shift Lever"] and not has_amt: continue
        if ecu == "Retarder Controller" and not has_retarder: continue
        status = "✅ OK" if addr in found_sources else "❌ MISSING"
        conn = ecu_connector_map.get(ecu, {})
        report.append({
            "ECU": ecu,
            "Source Address": f"0x{addr:02X}",
            "Status": status,
            "Connector": conn.get("connector", "-"),
            "Location": conn.get("location", "-"),
            "Fuse": conn.get("fuse", "-")
        })

    df = pd.DataFrame(report)

    st.success("✅ Diagnostics completed!")
    st.subheader("📋 ECU Status")
    st.dataframe(df, use_container_width=True)

    st.subheader("🧠 Root Cause Analysis")
    for cause in infer_root_causes(df):
        st.markdown(
            f"""<div style='background:#fffbe6; border-left:5px solid #faad14; padding:10px; margin-bottom:10px;'>
            <b>{cause['Type']}</b>: <code>{cause['Component']}</code><br>
            Missing: {cause['Missing']} / {cause['Total']} — Confidence: {cause['Confidence']}%
            <br>ECUs: {', '.join(cause['Affected ECUs'])}</div>""", unsafe_allow_html=True)

    show_pdf = generate_pdf_buffer(report, vehicle_name)
    st.download_button("⬇️ Download PDF Report", show_pdf, f"{vehicle_name}_diagnostics.pdf", "application/pdf")

    st.subheader("🔧 Detailed ECU Diagnostics")
    for _, row in df[df["Status"] == "❌ MISSING"].iterrows():
        st.markdown(generate_detailed_diagnosis(row["ECU"]), unsafe_allow_html=True)

elif uploaded_file:
    st.warning("⚠️ Please enter a vehicle name.")
elif vehicle_name:
    st.info("📂 Please upload a `.trc` file.")

# --- Show Relevant Diagnostic Slides ---
st.markdown("---")
st.markdown("### 🖼️ Diagnostic Visual Reference")

# Map ECUs, connectors, and fuses to slide numbers
slide_map = {
    "Connector 3": [12],
    "Connector 4": [3],
    "89E": [5, 6, 7, 8, 9],
    "Cabin Interface Connector (Brown)": [4],
    "F47": [6],
    "F46": [6],
    "F42": [3],
    "F43": [3],
    "F52": [3],
    "ABS ECU": [12],
    "Telematics": [4],
    "Instrument Cluster": [5, 6, 7],
    "Engine ECU": [3],
    "Gear Shift Lever": [3],
    "TCU": [3],
    "LNG Sensor 1": [3],
    "LNG Sensor 2": [3],
    "Retarder Controller": [3]
}

# Collect unique relevant slides based on missing ECUs
missing_slides = set()
for row in report:
    if row["Status"] == "❌ MISSING":
        for key in [row["ECU"], row["Connector"], row["Fuse"]]:
            missing_slides.update(slide_map.get(key, []))

# Display slides
if missing_slides:
    st.success(f"📌 Relevant slides for missing ECUs: {', '.join(f'Slide {s}' for s in sorted(missing_slides))}")
    for slide_num in sorted(missing_slides):
        st.image(f"static_images/Slide{slide_num}.PNG", caption=f"Slide {slide_num}", use_container_width=True)
else:
    st.info("✅ No ECUs are missing — all components appear functional.")


# --- Footer ---
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; font-size: 0.85em; color: gray;'>
        © 2025 Blue Energy Motors. All rights reserved.<br>
        For authorized diagnostic use only.
    </div>
    """,
    unsafe_allow_html=True
)
