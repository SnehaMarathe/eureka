# app.py
# EurekaCheck - CAN Diagnostic Tool (Full app)
# - Preserves your full layout & features
# - DM1 decoding with TP/BAM reassembly
# - Corrected lamp strategy (MIL/RSL/AWL/PL + flash bits)
# - DTC cross-reference from dtc_lookup_merged.json (and optional Excel merge)
# - ECU presence, harness root-cause, PDF export, wiring slides
# - Firebase login + logging + live visitor counter
# - Optional PCAN live capture (if python-can is available)

import streamlit as st
from streamlit_javascript import st_javascript
import re
import io
import json
import math
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from collections import defaultdict, deque
import os
import threading
import tempfile
import time
from typing import Dict, List, Tuple, Optional

# --- Firebase ---
import firebase_admin
from firebase_admin import credentials, firestore
import requests

# =============================
# Try importing python-can (Live PCAN support)
# =============================
try:
    import can
    PCAN_AVAILABLE = True
except Exception:
    PCAN_AVAILABLE = False

# =============================
# Streamlit Config
# =============================
st.set_page_config(page_title="EurekaCheck - CAN Diagnostic", layout="wide")

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
def log_to_firebase(vehicle_name: str, df: pd.DataFrame, kind: str = "diagnostics"):
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
    try:
        db.collection(f"{kind}_logs").add(data)
    except Exception as e:
        st.warning(f"⚠️ Firestore log failed: {e}")

# =============================
# ✅ Visitors counter in Firestore (with listener)
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
# Auth
# =============================
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

# =============================
# Header
# =============================
col1, col2, col3 = st.columns([1, 6, 1])
with col1:
    st.image("BEM-Logo.png", width=150)
with col2:
    st.markdown(
        """
        <div style='text-align: center;'>
            <h2 style='margin-bottom: 0;'>🔧 EurekaCheck - CAN Bus Diagnostic Tool</h2>
            <p style='margin-top: 0;'>Connect PCAN or Upload a <code>.trc</code> file to analyze ECU health & DTCs.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
with col3:
    st.markdown(
        f"<p style='text-align: right; color: gray;'>👥 Visitors: {st.session_state.get('visitor_count', 0)}</p>",
        unsafe_allow_html=True
    )
st.markdown("<hr style='margin-top: 0.5rem;'>", unsafe_allow_html=True)

# =============================
# ECU & Drawing Maps
# =============================
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

# =============================
# Utility & Diagnostic Helpers
# =============================
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
    col_widths = [130, 80, 80, 150, 150, 60]
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


def infer_root_causes(df: pd.DataFrame):
    causes = {"Fuse": defaultdict(list), "Connector": defaultdict(list), "Harness": defaultdict(list)}
    if df.empty:
        return []
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


def generate_detailed_diagnosis(ecu_name: str):
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

# =============================
# Vehicle Inputs / Config
# =============================
st.markdown("### 🚛 Vehicle Info")
vehicle_name = st.text_input("Enter Vehicle Name or ID", max_chars=30)

st.markdown("### ⚙️ Configuration")
has_double_tank = st.checkbox("Has Double Tank?", value=True)
has_amt = st.checkbox("Has AMT?", value=True)
has_retarder = st.checkbox("Has Retarder?", value=True)

# =============================
# DTC LOOKUP (JSON + optional Excel merge)
# =============================
def load_dtc_lookup() -> Dict[Tuple[int, int], dict]:
    lookup = {}
    # JSON first
    if os.path.exists("dtc_lookup_merged.json"):
        try:
            with open("dtc_lookup_merged.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            for row in data:
                try:
                    spn = int(row.get("SPN", 0))
                    fmi = int(row.get("FMI", 0))
                    lookup[(spn, fmi)] = row
                except Exception:
                    continue
        except Exception as e:
            st.warning(f"⚠️ Failed to load dtc_lookup_merged.json: {e}")

    # Optional: merge in from any Excel references if they exist in app folder
    excel_candidates = [
        "CAN_Interface_Matrix_BEMC_NG_EVI_StepE_1box_rev1.0.xlsx",
        "F300G810_FnR_T222BECDG8100033206_Trimmed_Signed.xlsx"
    ]
    for x in excel_candidates:
        if os.path.exists(x):
            try:
                # Try read all sheets and look for SPN/FMI columns
                xls = pd.ExcelFile(x)
                for sheet in xls.sheet_names:
                    try:
                        df = pd.read_excel(x, sheet_name=sheet)
                        cols = [c.strip().upper() for c in df.columns.astype(str)]
                        # Heuristic column detection
                        col_map = {}
                        for i, c in enumerate(cols):
                            if c in ("SPN", "SPN NO", "SPN#"):
                                col_map["SPN"] = df.columns[i]
                            if c in ("FMI", "FMI NO", "FMI#"):
                                col_map["FMI"] = df.columns[i]
                            if c in ("DESCRIPTION", "DESC", "FAULT DESCRIPTION", "DTC DESCRIPTION"):
                                col_map["Description"] = df.columns[i]
                            if c in ("TITLE", "DTC TITLE", "NAME"):
                                col_map["Title"] = df.columns[i]
                            if c in ("DTC", "CODE"):
                                col_map["DTC"] = df.columns[i]
                            if c in ("ERROR CLASS", "SEVERITY", "CLASS"):
                                col_map["Error Class"] = df.columns[i]
                        if "SPN" in col_map and "FMI" in col_map:
                            for _, r in df.iterrows():
                                try:
                                    spn = int(str(r[col_map["SPN"]]).strip().split(".")[0])
                                    fmi = int(str(r[col_map["FMI"]]).strip().split(".")[0])
                                    entry = lookup.get((spn, fmi), {})
                                    entry.setdefault("SPN", spn)
                                    entry.setdefault("FMI", fmi)
                                    if "Description" in col_map:
                                        entry["Description"] = r.get(col_map["Description"], entry.get("Description", ""))
                                    if "Title" in col_map:
                                        entry["Title"] = r.get(col_map["Title"], entry.get("Title", ""))
                                    if "DTC" in col_map:
                                        entry["DTC"] = r.get(col_map["DTC"], entry.get("DTC", ""))
                                    if "Error Class" in col_map:
                                        entry["Error Class"] = r.get(col_map["Error Class"], entry.get("Error Class", ""))
                                    lookup[(spn, fmi)] = entry
                                except Exception:
                                    continue
                    except Exception:
                        continue
            except Exception as e:
                st.warning(f"⚠️ Could not merge Excel DTCs from {x}: {e}")
    return lookup

DTC_LOOKUP = load_dtc_lookup()

# =============================
# J1939 helpers
# =============================
def extract_sa(can_id: int) -> int:
    return can_id & 0xFF

def extract_pgn(can_id: int) -> int:
    # 29-bit ID: [Priority(3)] [PGN(18)] [SA(8)]
    return (can_id >> 8) & 0xFFFF

def is_dm1_pgn(pgn: int) -> bool:
    return pgn == 0xFECA  # 65226

# =============================
# DM1 parsing (CORRECTED LAMP STRATEGY)
# =============================
def parse_dm1_frame_with_lamp(timestamp: float, can_id: int, data_bytes: List[int], dtc_lookup: Dict[Tuple[int, int], dict]) -> List[dict]:
    """
    Correct lamp strategy:
      - Byte 0: 2-bit status for MIL, RSL, AWL, PL (00 Off, 01 On, 10 On, 11 Flash)
      - Byte 1: 2-bit flash request per lamp (some ECUs OR this; treat non-zero as flashing request)
      - Byte 2: Number of DTCs (per J1939-73, use this instead of guessing)
      - Bytes 3..: DTCs (4 bytes each) → SPN/FMI/OC
    """
    results = []
    if len(data_bytes) < 8:
        return results

    lb = data_bytes[0]  # lamp byte (steady state)
    fb = data_bytes[1] if len(data_bytes) >= 2 else 0  # flash byte (flash request)
    num_dtcs = data_bytes[2] if len(data_bytes) >= 3 else 0

    def lamp_on(bits2):
        # 00=Off, 01=On, 10=On, 11=Flash (treat as On/True for user display)
        return bits2 in (0b01, 0b10, 0b11)

    def lamp_flash(bits2, flash_req):
        # If steady state 11 OR flash byte says non-zero → flashing
        return (bits2 == 0b11) or (flash_req != 0)

    mil_bits = (lb & 0b00000011)
    rsl_bits = (lb & 0b00001100) >> 2
    awl_bits = (lb & 0b00110000) >> 4
    pl_bits  = (lb & 0b11000000) >> 6

    mil_flash_req = (fb & 0b00000011)
    rsl_flash_req = (fb & 0b00001100) >> 2
    awl_flash_req = (fb & 0b00110000) >> 4
    pl_flash_req  = (fb & 0b11000000) >> 6

    lamp_state = {
        "MIL": lamp_on(mil_bits),
        "RSL": lamp_on(rsl_bits),
        "AWL": lamp_on(awl_bits),
        "PL":  lamp_on(pl_bits),
        "FlashMIL": lamp_flash(mil_bits, mil_flash_req),
        "FlashRSL": lamp_flash(rsl_bits, rsl_flash_req),
        "FlashAWL": lamp_flash(awl_bits, awl_flash_req),
        "FlashPL":  lamp_flash(pl_bits, pl_flash_req),
    }

    offset = 3
    for _ in range(num_dtcs):
        if offset + 4 > len(data_bytes):
            break
        b1, b2, b3, b4 = data_bytes[offset:offset+4]
        spn = b1 | (b2 << 8) | ((b3 & 0xE0) << 11)  # 19 bits
        fmi = b3 & 0x1F
        oc = b4 & 0x7F

        desc = "Unknown (not in lookup)"
        title = ""
        dtc_code = ""
        error_class = ""

        entry = dtc_lookup.get((spn, fmi))
        if entry:
            desc = entry.get("Description", desc)
            title = entry.get("Title", "")
            dtc_code = entry.get("DTC", "")
            error_class = entry.get("Error Class", "")

        results.append({
            "Time": timestamp,
            "Source Address": f"0x{extract_sa(can_id):02X}",
            "Assembled": False,
            "SPN": spn,
            "FMI": fmi,
            "OC": oc,
            "DTC": dtc_code,
            "Title": title,
            "Description": desc,
            "Error Class": error_class,
            "MIL": lamp_state["MIL"],
            "RSL": lamp_state["RSL"],
            "AWL": lamp_state["AWL"],
            "PL": lamp_state["PL"],
            "FlashMIL": lamp_state["FlashMIL"],
            "FlashRSL": lamp_state["FlashRSL"],
            "FlashAWL": lamp_state["FlashAWL"],
            "FlashPL": lamp_state["FlashPL"],
        })
        offset += 4

    # If ECU sends 0 DTCs but lamps indicate fault, still show a marker row
    if num_dtcs == 0:
        results.append({
            "Time": timestamp,
            "Source Address": f"0x{extract_sa(can_id):02X}",
            "Assembled": False,
            "SPN": None,
            "FMI": None,
            "OC": None,
            "DTC": "",
            "Title": "",
            "Description": "No DTCs reported in DM1 but lamp indicates status.",
            "Error Class": "",
            "MIL": lamp_state["MIL"],
            "RSL": lamp_state["RSL"],
            "AWL": lamp_state["AWL"],
            "PL": lamp_state["PL"],
            "FlashMIL": lamp_state["FlashMIL"],
            "FlashRSL": lamp_state["FlashRSL"],
            "FlashAWL": lamp_state["FlashAWL"],
            "FlashPL": lamp_state["FlashPL"],
        })
    return results

# =============================
# TP/BAM reassembly (J1939-21)
# =============================
TP_CM_PGN = 0xEC00  # Connection Management
TP_DT_PGN = 0xEB00  # Data Transfer
TP_CM_BAM  = 0x20   # Broadcast Announce Message
TP_CM_RTS  = 0x10   # Request To Send (not used for BAM)
TP_CM_CTS  = 0x11
TP_CM_EOM  = 0x13

class TPSession:
    def __init__(self, total_size, pgn, sa, ts_start):
        self.total_size = total_size
        self.pgn = pgn
        self.sa = sa
        self.ts_start = ts_start
        self.buffer = bytearray()
        self.expected_packets = math.ceil(total_size / 7)
        self.received = 0
        self.done = False

    def add_dt(self, seq_num, payload7):
        # Append payload7 (up to 7 bytes) in order; seq_num starts at 1
        if self.done:
            return
        self.buffer.extend(payload7)
        self.received += 1
        if self.received >= self.expected_packets or len(self.buffer) >= self.total_size:
            self.done = True
            self.buffer = self.buffer[:self.total_size]

def reassemble_tp_stream(rows: List[Tuple[float, int, List[int]]]) -> List[Tuple[float, int, int, bytes, bool]]:
    """
    Input rows: list of (timestamp, can_id, payload[0..7])
    Output list of tuples: (timestamp, pgn, sa, data, assembled)
      - For single-frame DM1: assembled=False
      - For TP/BAM DM1: assembled=True with full reassembled payload
    """
    sessions: Dict[Tuple[int, int], TPSession] = {}  # key=(sa,pgn)
    out = []

    for ts, can_id, data in rows:
        pgn = extract_pgn(can_id)
        sa = extract_sa(can_id)

        # Single frame DM1
        if is_dm1_pgn(pgn) and len(data) >= 8:
            out.append((ts, pgn, sa, bytes(data[:8]), False))
            continue

        # TP.CM (control)
        if pgn == TP_CM_PGN and len(data) >= 8:
            control = data[0]
            total_size = data[1] | (data[2] << 8)
            total_packets = data[3]
            tp_pgn = data[5] | (data[6] << 8) | (data[7] << 16)  # 24-bit PGN (ignore PDU specifics)
            if control == TP_CM_BAM:
                sessions[(sa, tp_pgn)] = TPSession(total_size, tp_pgn, sa, ts)
            # (RTS/CTS/EOM ignored for BAM mode; for peer-to-peer you could extend here)
            continue

        # TP.DT (data packets)
        if pgn == TP_DT_PGN and len(data) >= 8:
            seq = data[0]
            payload7 = bytes(data[1:])  # 7 bytes
            # Find any open session for this SA (we don't know PGN here in DT; map by last BAM)
            # Use most recent session per SA (if multiple PGNs per SA arrive interleaved, you'd disambiguate on DA)
            # Here we keep a single session per (sa, pgn)
            # Find active sessions for SA
            active = [(k, s) for k, s in sessions.items() if k[0] == sa and not s.done]
            if active:
                # Assume the most recent (deterministic: max by ts_start)
                (key, sess) = max(active, key=lambda kv: kv[1].ts_start)
                sess.add_dt(seq, payload7)
                if sess.done and sess.pgn:
                    out.append((sess.ts_start, sess.pgn, sa, bytes(sess.buffer), True))
                    # Cleanup the finished session
                    del sessions[key]
            continue

        # Other PGNs ignored

    return out

# =============================
# .TRC Parser (robust ID + payload extraction)
# =============================
def parse_trc_lines(file_path: str) -> List[Tuple[float, int, List[int]]]:
    """
    Returns: list of (timestamp, can_id_int, data_bytes[0..7])
    Supports common PEAK .trc formats.
    """
    rows = []
    # Patterns:
    #  1) "  1)   0.123  Rx 18FECA00  8  FF 00 01 00 00 00 00 00"
    #  2) "  2) 123.456  Rx   18FECA00  DLC = 8  Data = FF 00 01 00 00 00 00 00"
    pat_basic = re.compile(r"\s*\d+\)\s+([\d.]+)\s+R[xt]\s+([0-9A-Fa-f]{8})\s+(\d+)\s+([0-9A-Fa-f ]+)")
    pat_alt = re.compile(r"\s*\d+\)\s+([\d.]+)\s+R[xt]\s+([0-9A-Fa-f]{8}).*?(?:DLC\s*=\s*(\d+)).*?([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}){0,7})")
    pat_min = re.compile(r"\s*\d+\)\s+([\d.]+)\s+R[xt]\s+([0-9A-Fa-f]{8})")

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            m = pat_basic.match(line)
            if not m:
                m = pat_alt.match(line)
            if m:
                ts = float(m.group(1))
                can_id = int(m.group(2), 16)
                dlc = int(m.group(3)) if m.group(3) else 8
                payload_str = m.group(4)
                bytes_list = [int(x, 16) for x in payload_str.strip().split() if re.fullmatch(r"[0-9A-Fa-f]{2}", x)]
                # pad/truncate to 8
                if len(bytes_list) < dlc:
                    bytes_list += [0x00] * (dlc - len(bytes_list))
                bytes_list = bytes_list[:dlc]
                rows.append((ts, can_id, bytes_list))
            else:
                # At least capture ts + id to mark SA presence if payload missing
                m2 = pat_min.match(line)
                if m2:
                    ts = float(m2.group(1))
                    can_id = int(m2.group(2), 16)
                    rows.append((ts, can_id, []))
    return rows

# =============================
# DM1 end-to-end decoding from .trc rows (single + TP/BAM)
# =============================
def decode_dm1_from_rows(rows: List[Tuple[float, int, List[int]]], dtc_lookup: Dict[Tuple[int, int], dict]) -> pd.DataFrame:
    # First: emit single frame DM1 and prepare TP input
    tp_input = []
    decoded = []

    for ts, can_id, data in rows:
        pgn = extract_pgn(can_id)
        if is_dm1_pgn(pgn) and len(data) >= 8:
            decoded.extend(parse_dm1_frame_with_lamp(ts, can_id, data, dtc_lookup))
        # keep all rows for TP reassembly too
        if data and len(data) > 0:
            # TP needs fixed 8-byte chunks; pad where needed
            d = list(data)
            if len(d) < 8:
                d += [0xFF] * (8 - len(d))
            tp_input.append((ts, can_id, d[:8]))

    # Reassemble TP/BAM
    assembled = reassemble_tp_stream(tp_input)
    for ts, pgn, sa, payload, assembled_flag in assembled:
        if is_dm1_pgn(pgn) and payload and len(payload) >= 3:
            # payload for DM1 can be > 8 in BAM
            data_list = list(payload)
            decoded.extend(parse_dm1_frame_with_lamp(ts, (pgn << 8) | sa, data_list, dtc_lookup))
            # Overwrite Assembled=True for these
            for d in decoded[-10:]:
                # Tag last bunch we just added
                d["Assembled"] = True

    return pd.DataFrame(decoded)

# =============================
# Live PCAN (optional) capture for a short window
# =============================
def capture_pcan_seconds(seconds: int = 5, bitrate: int = 500000) -> List[Tuple[float, int, List[int]]]:
    rows = []
    if not PCAN_AVAILABLE:
        return rows
    try:
        bus = can.interface.Bus(bustype="pcan", channel="PCAN_USBBUS1", bitrate=bitrate)
    except Exception:
        return rows
    start = time.time()
    while time.time() - start < seconds:
        msg = bus.recv(1)
        if msg:
            ts = time.time() - start
            can_id = msg.arbitration_id
            data = list(bytearray(msg.data))
            rows.append((ts, can_id, data))
    try:
        bus.shutdown()
    except Exception:
        pass
    return rows

# =============================
# ECU Address Map for Detection
# =============================
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

# =============================
# --- CAN Data Input Section ---
# =============================
st.markdown("### 📡 CAN Data Input")
left, right = st.columns(2)
with left:
    uploaded_file = st.file_uploader("Upload CAN Trace (.trc)", type=["trc"])
with right:
    live_capture = st.checkbox("Try 5s Live PCAN capture (if available)")

all_rows = []
if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".trc") as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        tmp_path = tmp_file.name
    all_rows = parse_trc_lines(tmp_path)
    st.success("✅ Trace file processed successfully.")
elif live_capture:
    st.info("Reading live messages from PCAN for ~5s…")
    all_rows = capture_pcan_seconds(5)
    if all_rows:
        st.success(f"✅ Captured {len(all_rows)} messages from PCAN.")
    else:
        st.warning("No messages captured.")

# =============================
# Decode DM1
# =============================
df_dtc = pd.DataFrame()
if all_rows:
    df_dtc = decode_dm1_from_rows(all_rows, DTC_LOOKUP)

# =============================
# ECU Presence Report
# =============================
report = []
found_sources = set()
if all_rows:
    for _, can_id, _ in all_rows:
        found_sources.add(extract_sa(can_id))

if not vehicle_name.strip():
    st.info("📂 Please enter a vehicle name.")
else:
    for addr, ecu in ecu_map.items():
        if ecu == "LNG Sensor 2" and not has_double_tank:
            continue
        if ecu in ["TCU", "Gear Shift Lever"] and not has_amt:
            continue
        if ecu == "Retarder Controller" and not has_retarder:
            continue
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

    df_report = pd.DataFrame(report)

    if not df_report.empty:
        # Log to Firebase
        log_to_firebase(vehicle_name, df_report, kind="presence")

        st.success("✅ Diagnostics completed!")
        st.subheader("📋 ECU Status")
        st.dataframe(df_report, use_container_width=True)

        st.subheader("🧠 Root Cause Analysis")
        for cause in infer_root_causes(df_report):
            st.markdown(
                f"""<div style='background:#fffbe6; border-left:5px solid #faad14; padding:10px; margin-bottom:10px;'>
                <b>{cause['Type']}</b>: <code>{cause['Component']}</code><br>
                Missing: {cause['Missing']} / {cause['Total']} — Confidence: {cause['Confidence']}%
                <br>ECUs: {', '.join(cause['Affected ECUs'])}</div>""",
                unsafe_allow_html=True
            )

        show_pdf = generate_pdf_buffer(report, vehicle_name)
        st.download_button("⬇️ Download PDF Report", show_pdf, f"{vehicle_name}_diagnostics.pdf", "application/pdf")

        st.subheader("🔧 Detailed ECU Diagnostics")
        for _, row in df_report[df_report["Status"] == "❌ MISSING"].iterrows():
            st.markdown(generate_detailed_diagnosis(row["ECU"]), unsafe_allow_html=True)

        # --- Diagnostic Visual Reference ---
        st.markdown("---")
        st.markdown("### 🖼️ Diagnostic Visual Reference")

        # Static mapping preserved (functionality unchanged)
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

        # Dynamically resolve slide image paths
        def get_slide_path(slide_num: int):
            candidates = [
                os.path.join("Electrical Wiring", f"Slide{slide_num}.PNG"),
                os.path.join("Electrical Wiring", f"Slide{slide_num}.png"),
                os.path.join("static_images", f"Slide{slide_num}.PNG"),
                os.path.join("static_images", f"Slide{slide_num}.png"),
            ]
            for p in candidates:
                if os.path.exists(p):
                    return p
            return None

        missing_slides = set()
        for row in report:
            if row["Status"] == "❌ MISSING":
                for key in [row["ECU"], row["Connector"], row["Fuse"]]:
                    missing_slides.update(slide_map.get(key, []))

        if missing_slides:
            st.success("📌 Relevant slides for missing ECUs: " + ", ".join(f"Slide {s}" for s in sorted(missing_slides)))
            for slide_num in sorted(missing_slides):
                slide_path = get_slide_path(slide_num)
                if slide_path:
                    st.image(slide_path, caption=f"Slide {slide_num}", use_container_width=True)
                else:
                    st.warning(f"⚠️ Slide {slide_num} image not found in 'Electrical Wiring' or 'static_images'.")
        else:
            st.info("✅ No ECUs are missing — all components appear functional.")

# =============================
# Active DTCs section
# =============================
st.markdown("---")
st.markdown("### 🚨 Active DTCs (DM1)")

if df_dtc is not None and not df_dtc.empty:
    # Reorder/rename for nicer display
    cols = ["Time", "Source Address", "Assembled", "SPN", "FMI", "OC", "DTC", "Title", "Description", "Error Class",
            "MIL", "RSL", "AWL", "PL", "FlashMIL", "FlashRSL", "FlashAWL", "FlashPL"]
    display_cols = [c for c in cols if c in df_dtc.columns]
    st.dataframe(df_dtc[display_cols], use_container_width=True)
    # Log DTCs
    try:
        log_to_firebase(vehicle_name or "Unknown", df_dtc[display_cols], kind="dtc")
    except Exception:
        pass
else:
    st.info("No active DM1 entries decoded yet.")

# --- Footer ---
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; font-size: 0.85em; color: gray;'>
        © 2025 Blue Energy Motors.<br>
        All rights reserved.<br>
        This diagnostic tool and its associated materials are proprietary and intended for authorized diagnostic and engineering use only.
    </div>
    """,
    unsafe_allow_html=True
)
