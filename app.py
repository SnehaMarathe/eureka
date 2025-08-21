import streamlit as st
from streamlit_javascript import st_javascript
import re
import io
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from collections import defaultdict
import os
import threading
# ---2/8/2025---Adding Firebase 

import firebase_admin
from firebase_admin import credentials, firestore
import requests

# =============================
# 🌍 Get Browser-based Location
# =============================
def capture_browser_location():
    ip = st_javascript("await fetch('https://api64.ipify.org?format=json').then(r => r.json()).then(data => data.ip)")
    if ip:
        st.session_state["ip"] = ip

        try:
            location_response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            location_data = location_response.json()
            st.session_state["city"] = location_data.get("city", "Unknown")
            st.session_state["region"] = location_data.get("region", "Unknown")
            st.session_state["country"] = location_data.get("country_name", "Unknown")
            st.session_state["latitude"] = location_data.get("latitude")
            st.session_state["longitude"] = location_data.get("longitude")
        except Exception as e:
            st.session_state["city"] = "Error"
            st.session_state["country"] = "Error"
            st.session_state["error"] = str(e)

# =============================
# 🔑 Initialize Firebase
# =============================
@st.cache_resource
def init_firebase():
    firebase_config = st.secrets["FIREBASE"]
    
    cred = credentials.Certificate({
        "type": firebase_config["type"],
        "project_id": firebase_config["project_id"],
        "private_key_id": firebase_config["private_key_id"],
        "private_key": firebase_config["private_key"].replace("\\n", "\n"),
        "client_email": firebase_config["client_email"],
        "client_id": firebase_config["client_id"],
        "auth_uri": firebase_config["auth_uri"],
        "token_uri": firebase_config["token_uri"],
        "auth_provider_x509_cert_url": firebase_config["auth_provider_x509_cert_url"],
        "client_x509_cert_url": firebase_config["client_x509_cert_url"],
        "universe_domain": firebase_config.get("universe_domain", "")
    })

    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)

    return firestore.client()

db = init_firebase()

# =============================
# 🛠️ Utility: Log Data
# =============================
def log_to_firebase(vehicle_name, df):
    user_info = {
        "ip": st.session_state.get("ip", "Unknown"),
        "city": st.session_state.get("city", "Unknown"),
        "region": st.session_state.get("region", "Unknown"),
        "country": st.session_state.get("country", "Unknown"),
        "latitude": st.session_state.get("latitude"),
        "longitude": st.session_state.get("longitude")
    }
    data = {
        "vehicle": vehicle_name,
        "records": df.to_dict(orient="records"),
        "user_info": user_info,
        "timestamp": datetime.now().isoformat()
    }
    db.collection("diagnostics_logs").add(data)

# =============================
# ✅ # Increment counter in Firestore
# =============================
def update_visitor_count_firestore():
    counter_ref = db.collection("visitors").document("counter")
    counter_doc = counter_ref.get()

    if not counter_doc.exists:
        counter_ref.set({"count": 1})
        count = 1
    else:
        count = counter_doc.to_dict().get("count", 0) + 1
        counter_ref.update({"count": count})

    st.session_state["visitor_count"] = count

def visitor_listener():
    counter_ref = db.collection("visitors").document("counter")
    def on_snapshot(doc_snapshot, changes, read_time):
        for doc in doc_snapshot:
            count = doc.to_dict().get("count", 0)
            st.session_state["visitor_count"] = count
    counter_ref.on_snapshot(on_snapshot)

if "listener_started" not in st.session_state:
    threading.Thread(target=visitor_listener, daemon=True).start()
    st.session_state["listener_started"] = True

if "visitor_counted" not in st.session_state:
    update_visitor_count_firestore()
    st.session_state["visitor_counted"] = True

if "ip" not in st.session_state:
    capture_browser_location()

# =============================
# Try importing python-can
# =============================
try:
    import can
    PCAN_AVAILABLE = True
except ImportError:
    PCAN_AVAILABLE = False

st.set_page_config(page_title="EurekaCheck - CAN Diagnostic", layout="wide")

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

col1, col2, col3 = st.columns([1, 6, 1])
with col1:
    st.image("BEM-Logo.png", width=150)
with col2:
    st.markdown(
        """
        <div style='text-align: center;'>
            <h2 style='margin-bottom: 0;'>🔧 EurekaCheck - CAN Bus Diagnostic Tool</h2>
            <p style='margin-top: 0;'>Connect PCAN or Upload a <code>.trc</code> file or read live PCAN to analyze ECU health.</p>
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

# ECU mapping
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

# Utility Functions
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

input_mode = st.radio("Select Input Mode", (
    "Upload File",
    "Live PCAN" if PCAN_AVAILABLE else "Upload File Only"
))

# --- Live PCAN Mode ---
live_messages = []
if input_mode == "Live PCAN" and PCAN_AVAILABLE:
    with st.form("live_pcan_form"):
        st.write("### 🔌 Connect to PCAN")
        channel = st.text_input("PCAN Channel (e.g., PCAN_USBBUS1)", "PCAN_USBBUS1")
        bitrate = st.selectbox("Bitrate", ["500000", "250000", "125000"], index=0)
        duration = st.slider("Capture Duration (seconds)", 1, 30, 5)
        submitted = st.form_submit_button("▶️ Start Live Diagnostics")

        if submitted:
            st.info(f"Connecting to {channel} @ {bitrate} bps...")
            try:
                bus = can.interface.Bus(channel=channel, bustype='pcan', bitrate=int(bitrate))
                st.success("Connected. Reading messages...")
                start_time = datetime.now()
                with st.spinner("Capturing messages..."):
                    while (datetime.now() - start_time).seconds < duration:
                        msg = bus.recv(timeout=0.2)
                        if msg:
                            live_messages.append(msg)
                bus.shutdown()
                st.success(f"✅ Captured {len(live_messages)} messages.")
            except Exception as e:
                st.error(f"❌ PCAN connection failed: {e})

