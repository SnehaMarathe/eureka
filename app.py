# app.py — EurekaCheck Unified Diagnostic Tool
# TP/BAM reassembly + DM1 with corrected lamp parsing + Clean DM1 table
# Firebase upload (ECU presence, DTCs) + Wiring/Ground Heuristics
# + Wiring PDF parsing to extract ground labels and connector-pin→ground mappings

import streamlit as st
from streamlit_javascript import st_javascript
import re
import io
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib import colors
from collections import defaultdict, Counter
import os
import threading
import tempfile
import time
import json
import requests

# Optional: PDF parsers for wiring drawings
PDF_BACKEND = None
try:
    import pdfplumber  # best for coordinates
    PDF_BACKEND = "pdfplumber"
except Exception:
    try:
        from PyPDF2 import PdfReader  # text-only fallback
        PDF_BACKEND = "pypdf2"
    except Exception:
        PDF_BACKEND = None

# --- OCR / PDF fallbacks (optional but recommended) ---
try:
    from pdf2image import convert_from_path
    import pytesseract
    OCR_AVAILABLE = True
except Exception:
    OCR_AVAILABLE = False

# Firebase
import firebase_admin
from firebase_admin import credentials, firestore

# Optional PCAN/live CAN support
try:
    import can
    PCAN_AVAILABLE = True
except Exception:
    PCAN_AVAILABLE = False

# -------------------------
# Streamlit config
# -------------------------
st.set_page_config(page_title="EurekaCheck - CAN Diagnostic", layout="wide")

# -------------------------
# Config (JSON-only lookup)
# -------------------------
JSON_LOOKUP_PATH = "dtc_lookup_engine_abs_full.json"  # unified Engine+ABS with WorkshopActions

# -------------------------
# Helper: Browser-based location (via JS)
# -------------------------
def capture_browser_location():
    try:
        ip = st_javascript(
            "await fetch('https://api64.ipify.org?format=json')"
            ".then(r => r.json()).then(data => data.ip)"
        )
    except Exception:
        ip = None
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

# -------------------------
# Initialize Firebase
# -------------------------
@st.cache_resource
def init_firebase():
    try:
        firebase_config = st.secrets["FIREBASE"]
    except Exception:
        st.warning("⚠️ Firebase secrets not found in Streamlit secrets. Firebase features will be disabled.")
        return None

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

db = None
try:
    db = init_firebase()
except Exception:
    db = None

# -------------------------
# Firebase logging helpers
# -------------------------
def _current_user_info():
    return {
        "ip": st.session_state.get("ip", "Unknown"),
        "city": st.session_state.get("city", "Unknown"),
        "region": st.session_state.get("region", "Unknown"),
        "country": st.session_state.get("country", "Unknown"),
        "latitude": st.session_state.get("latitude"),
        "longitude": st.session_state.get("longitude")
    }

def log_to_firebase(vehicle_name: str, df: pd.DataFrame):
    """ECU presence/status log."""
    if db is None:
        return
    data = {
        "vehicle": vehicle_name,
        "records": df.to_dict(orient="records"),
        "user_info": _current_user_info(),
        "timestamp": datetime.now().isoformat()
    }
    try:
        db.collection("diagnostics_logs").add(data)
    except Exception as e:
        st.warning(f"⚠️ Firestore log failed: {e}")

def log_dtcs_to_firebase(vehicle_name: str, raw_dtcs: pd.DataFrame = None, cleaned_dtcs: pd.DataFrame = None):
    """Upload DTCs to Firestore (raw + cleaned)."""
    if db is None:
        return
    payload = {
        "vehicle": vehicle_name,
        "user_info": _current_user_info(),
        "timestamp": datetime.now().isoformat()
    }
    if raw_dtcs is not None and not raw_dtcs.empty:
        payload["raw_dtcs"] = raw_dtcs.to_dict(orient="records")
    if cleaned_dtcs is not None and not cleaned_dtcs.empty:
        payload["cleaned_dtcs"] = cleaned_dtcs.to_dict(orient="records")

    try:
        db.collection("diagnostics_dtcs").add(payload)
    except Exception as e:
        st.warning(f"⚠️ Firestore DTC upload failed: {e}")

def log_wiring_findings(vehicle_name: str, findings: list, faults: list, extracted: dict = None):
    if db is None:
        return
    payload = {
        "vehicle": vehicle_name,
        "user_info": _current_user_info(),
        "timestamp": datetime.now().isoformat(),
        "findings": findings or [],
        "fault_hypotheses": faults or [],
        "extracted": extracted or {}
    }
    try:
        db.collection("diagnostics_wiring_health").add(payload)
        db.collection("diagnostics_wiring_faults").add(payload)
    except Exception as e:
        st.warning(f"⚠️ Firestore wiring upload failed: {e}")

def log_wiring_extraction(vehicle_name: str, extraction: dict):
    if db is None:
        return
    payload = {
        "vehicle": vehicle_name,
        "user_info": _current_user_info(),
        "timestamp": datetime.now().isoformat(),
        "extraction": extraction
    }
    try:
        db.collection("wiring_extractions").add(payload)
    except Exception as e:
        st.warning(f"⚠️ Firestore extraction upload failed: {e}")

def update_visitor_count_firestore():
    if db is None:
        st.session_state["visitor_count"] = st.session_state.get("visitor_count", 0)
        return
    try:
        counter_ref = db.collection("visitors").document("counter")
        counter_doc = counter_ref.get()
        if not counter_doc.exists:
            counter_ref.set({"count": 1})
            count = 1
        else:
            count = counter_doc.to_dict().get("count", 0) + 1
            counter_ref.update({"count": count})
        st.session_state["visitor_count"] = count
    except Exception:
        st.session_state["visitor_count"] = st.session_state.get("visitor_count", 0)

def visitor_listener():
    if db is None:
        return
    counter_ref = db.collection("visitors").document("counter")
    def on_snapshot(doc_snapshot, changes, read_time):
        for doc in doc_snapshot:
            count = doc.to_dict().get("count", 0)
            st.session_state["visitor_count"] = count
    try:
        counter_ref.on_snapshot(on_snapshot)
    except Exception:
        pass

# start listener thread once
if "listener_started" not in st.session_state:
    try:
        threading.Thread(target=visitor_listener, daemon=True).start()
    except Exception:
        pass
    st.session_state["listener_started"] = True

if "visitor_counted" not in st.session_state:
    update_visitor_count_firestore()
    st.session_state["visitor_counted"] = True

if "ip" not in st.session_state:
    try:
        capture_browser_location()
    except Exception:
        pass

# -------------------------
# Authentication
# -------------------------
USER_CREDENTIALS = {"admin": "admin123", "user": "check2025"}
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

# -------------------------
# Header + layout
# -------------------------
col1, col2, col3 = st.columns([1, 6, 1])
with col1:
    try:
        st.image("BEM-Logo.png", width=150)
    except Exception:
        pass
with col2:
    st.markdown(
        """
        <div style='text-align: center;'>
            <h2 style='margin-bottom: 0;'>🔧 EurekaCheck - CAN Bus Diagnostic Tool</h2>
            <p style='margin-top: 0;'>Connect PCAN or Upload a <code>.trc</code> file to analyze ECU health & DTCs.</p>
        </div>
        """, unsafe_allow_html=True
    )
with col3:
    st.markdown(
        f"<p style='text-align: right; color: gray;'>👥 Visitors: {st.session_state.get('visitor_count', 0)}</p>",
        unsafe_allow_html=True
    )
st.markdown("<hr style='margin-top: 0.5rem;'>", unsafe_allow_html=True)

# -------------------------
# ECU connector map & drawing map
# -------------------------
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
    "Front Chassis Wiring Harness": "PEE0000082 FRONT CHASSIS WIRING HARNESS FOR LOCALIZED CABIN.pdf",
    "Rear Harness": "PEE0000083_A_01072024.pdf",
    "Retarder Wiring": "PEE0000013_J.pdf",
    "Pig Tail for Double Tank": "PEE0000083_A_01072024.pdf",
    "Trailer Interface": "PEE0000084.pdf"
}

# Power/Ground topology (static defaults; can be overridden by PDF parsing)
ground_map_default = {
    "Engine ECU": "G101",
    "ABS ECU": "G201",
    "Telematics": "G202",
    "Instrument Cluster": "G203",
    "TCU": "G301",
    "Gear Shift Lever": "G301",
    "LNG Sensor 1": "G401",
    "LNG Sensor 2": "G401",
    "Retarder Controller": "G302",
}

# -------------------------
# Utility: PDF report generation
# -------------------------
def generate_pdf_buffer(report_data, vehicle_name):
    buffer = io.BytesIO()
    c = rl_canvas.Canvas(buffer, pagesize=A4)
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

# -------------------------
# Utility: .trc parser (extract IDs + payloads)
# -------------------------
def parse_trc_file(file_path: str) -> pd.DataFrame:
    """
    Parse .trc log into DataFrame with columns:
    Timestamp, CAN ID (int), DLC, Data (bytes), Source Address (int)
    """
    records = []
    try:
        with open(file_path, "r", errors="ignore") as f:
            for line in f:
                # Pattern: "1)   0.000 Rx   18FECA17   8  00 FF FF 00 00 00 00 00"
                m = re.match(r"\s*\d+\)\s+([\d.]+)\s+Rx\s+([0-9A-Fa-f]{6,8})\s+(\d+)\s+((?:[0-9A-Fa-f]{2}\s+)+)", line)
                if m:
                    ts = float(m.group(1))
                    can_id = int(m.group(2), 16)
                    dlc = int(m.group(3))
                    data_str = m.group(4).strip()
                    data_bytes = bytes(int(b, 16) for b in data_str.split()[:dlc])
                    sa = can_id & 0xFF
                    records.append({"Timestamp": ts, "CAN ID": can_id, "DLC": dlc, "Data": data_bytes, "Source Address": sa})
                    continue
                # Fallback pattern: "ID = 18FECA17 Len = 8 Data = 00 FF ..."
                m2 = re.search(r"ID\s*=\s*([0-9A-Fa-f]{6,8}).*?Len\s*=\s*(\d+).*?Data\s*=\s*((?:[0-9A-Fa-f]{2}\s+)+)", line)
                if m2:
                    can_id = int(m2.group(1), 16)
                    dlc = int(m2.group(2))
                    data_str = m2.group(3).strip()
                    data_bytes = bytes(int(b, 16) for b in data_str.split()[:dlc])
                    sa = can_id & 0xFF
                    records.append({"Timestamp": None, "CAN ID": can_id, "DLC": dlc, "Data": data_bytes, "Source Address": sa})
    except Exception as e:
        st.error(f"❌ Failed to parse .trc file: {e}")
        return pd.DataFrame()
    return pd.DataFrame(records)

# -------------------------
# J1939 / DM1 parsing (SPN/FMI + corrected lamp strategy)
# -------------------------
DM1_PGN = 0xFECA  # 65226
TP_CM_PGN = 0xEC00  # 60416 (TP.CM)
TP_DT_PGN = 0xEB00  # 60160 (TP.DT)

# 2-bit decode maps per J1939-73
_LAMP_CMD = {0b00: "OFF", 0b01: "ON", 0b10: "FLASH", 0b11: "N/A"}
_FLASH_CODE = {0b00: "NONE", 0b01: "SLOW", 0b10: "FAST", 0b11: "N/A"}

def _lamp_bits(v: int, shift: int) -> int:
    return (v >> shift) & 0x03

def parse_dm1_frame_with_lamp(data_bytes: bytes):
    """
    DM1 Byte 1 (lamp status): bits 7..6=MIL, 5..4=RSL, 3..2=AWL, 1..0=PL
    DM1 Byte 2 (flash status): same ordering (NONE/SLOW/FAST/N/A)
    Subsequent bytes: DTCs (4-byte blocks)
    Returns: lamp (dict), dtcs (list)
    """
    lamp = {
        "MIL": None, "RSL": None, "AWL": None, "PL": None,
        "FlashMIL": None, "FlashRSL": None, "FlashAWL": None, "FlashPL": None,
        "MIL State": None, "RSL State": None, "AWL State": None, "PL State": None,
        "MIL Flash Rate": None, "RSL Flash Rate": None, "AWL Flash Rate": None, "PL Flash Rate": None,
    }
    dtcs = []

    if not data_bytes:
        return lamp, dtcs

    b1 = data_bytes[0] if len(data_bytes) >= 1 else 0xFF
    b2 = data_bytes[1] if len(data_bytes) >= 2 else 0xFF

    # Correct MSB->LSB ordering
    mil_cmd = _lamp_bits(b1, 6)
    rsl_cmd = _lamp_bits(b1, 4)
    awl_cmd = _lamp_bits(b1, 2)
    pl_cmd  = _lamp_bits(b1, 0)

    mil_fr = _lamp_bits(b2, 6)
    rsl_fr = _lamp_bits(b2, 4)
    awl_fr = _lamp_bits(b2, 2)
    pl_fr  = _lamp_bits(b2, 0)

    def lit(cmd, fr):
        return (cmd in (0b01, 0b10)) or (fr in (0b01, 0b10))

    def flashing(fr, cmd):
        return fr in (0b01, 0b10) or (cmd == 0b10)

    lamp["MIL State"] = _LAMP_CMD.get(mil_cmd)
    lamp["RSL State"] = _LAMP_CMD.get(rsl_cmd)
    lamp["AWL State"] = _LAMP_CMD.get(awl_cmd)
    lamp["PL State"]  = _LAMP_CMD.get(pl_cmd)

    lamp["MIL"] = lit(mil_cmd, mil_fr)
    lamp["RSL"] = lit(rsl_cmd, rsl_fr)
    lamp["AWL"] = lit(awl_cmd, awl_fr)
    lamp["PL"]  = lit(pl_cmd, pl_fr)

    lamp["FlashMIL"] = flashing(mil_fr, mil_cmd)
    lamp["FlashRSL"] = flashing(rsl_fr, rsl_cmd)
    lamp["FlashAWL"] = flashing(awl_fr, awl_cmd)
    lamp["FlashPL"]  = flashing(pl_fr, pl_cmd)

    lamp["MIL Flash Rate"] = _FLASH_CODE.get(mil_fr)
    lamp["RSL Flash Rate"] = _FLASH_CODE.get(rsl_fr)
    lamp["AWL Flash Rate"]  = _FLASH_CODE.get(awl_fr)
    lamp["PL Flash Rate"]   = _FLASH_CODE.get(pl_fr)

    if len(data_bytes) <= 2:
        return lamp, dtcs

    available = len(data_bytes) - 2
    dtc_count = available // 4
    for i in range(dtc_count):
        offset = 2 + i * 4
        if offset + 3 >= len(data_bytes):
            break
        b1d = data_bytes[offset]
        b2d = data_bytes[offset + 1]
        b3d = data_bytes[offset + 2]
        b4d = data_bytes[offset + 3]

        spn = int(b1d) | (int(b2d) << 8) | ((int(b3d) & 0xE0) << 11)
        fmi = int(b3d) & 0x1F
        cm  = (int(b4d) & 0x80) >> 7
        oc  = int(b4d) & 0x7F

        if spn == 0 and fmi == 0 and oc == 0:
            continue

        dtcs.append({"SPN": spn, "FMI": fmi, "OC": oc, "CM": cm, "offset": offset})

    return lamp, dtcs

# -------------------------
# TP/BAM assembler
# -------------------------
def assemble_tp_bam(df: pd.DataFrame):
    assembled = []
    if df is None or df.empty:
        return assembled

    rows = df.reset_index().to_dict(orient="records")
    open_bams = {}

    for row in rows:
        can_id = row.get("CAN ID")
        data = row.get("Data")
        ts = row.get("Timestamp", None)
        if can_id is None or not isinstance(data, (bytes, bytearray)):
            continue
        pgn = (can_id >> 8) & 0xFFFF
        sa = int(can_id & 0xFF)
        if pgn == 0xEC00:  # TP.CM
            if len(data) < 8: continue
            control = data[0]
            if control == 0x20:  # BAM
                total_size = data[1] | (data[2] << 8)
                total_packets = data[3]
                transported_pgn = data[5] | (data[6] << 8) | (data[7] << 16)
                open_bams[sa] = {
                    "PGN": transported_pgn & 0xFFFFFF,
                    "total_size": total_size,
                    "total_packets": total_packets,
                    "received": {},
                    "start_ts": ts
                }
        elif pgn == 0xEB00:  # TP.DT
            if len(data) < 1: continue
            seq = data[0]
            payload = bytes(data[1:])
            if sa in open_bams and open_bams[sa]["total_packets"] >= seq >= 1:
                open_bams[sa]["received"][seq] = payload
                if len(open_bams[sa]["received"]) >= open_bams[sa]["total_packets"]:
                    parts = []
                    for s in range(1, open_bams[sa]["total_packets"] + 1):
                        parts.append(open_bams[sa]["received"].get(s, b""))
                    data_full = b"".join(parts)[:open_bams[sa]["total_size"]]
                    assembled.append({
                        "PGN": open_bams[sa]["PGN"] & 0xFFFFFF,
                        "Source": sa,
                        "Data": data_full,
                        "Timestamp": open_bams[sa]["start_ts"]
                    })
                    del open_bams[sa]
        else:
            continue

    return assembled

def merge_assembled_into_df(df_can: pd.DataFrame, assembled_msgs: list):
    synthetic_rows = []
    for m in assembled_msgs:
        can_id = (m["PGN"] << 8) | (m["Source"] & 0xFF)
        data = m["Data"]
        dlc = len(data)
        synthetic_rows.append({
            "Timestamp": m.get("Timestamp"),
            "CAN ID": int(can_id),
            "DLC": dlc,
            "Data": data,
            "Source Address": int(m["Source"]),
            "Assembled": True
        })
    base = df_can.copy()
    if not base.empty:
        base = base.assign(Assembled=False)
    if synthetic_rows:
        df_synth = pd.DataFrame(synthetic_rows)
        combined = pd.concat([base, df_synth], ignore_index=True, sort=False)
    else:
        combined = base
    if "Timestamp" in combined.columns and combined["Timestamp"].notna().any():
        combined = combined.sort_values(by=["Timestamp"], na_position="last").reset_index(drop=True)
    return combined

# -------------------------
# Lookup loader (JSON-only), preserving WorkshopActions
# -------------------------
@st.cache_resource
def load_dtc_lookup(json_cache: str = JSON_LOOKUP_PATH):
    def _safe_int(x):
        try:
            if x is None or (isinstance(x, float) and pd.isna(x)):
                return None
            return int(str(x).strip())
        except Exception:
            return None

    if not json_cache or not os.path.exists(json_cache):
        st.warning(f"⚠️ DTC JSON not found at '{json_cache}'. Lookup disabled.")
        return {}

    try:
        with open(json_cache, "r", encoding="utf-8") as f:
            items = json.load(f)
        if not isinstance(items, list):
            st.error("❌ DTC JSON must be a list of entries.")
            return {}
    except Exception as e:
        st.error(f"❌ Failed to read DTC JSON: {e}")
        return {}

    lookup = {}
    skipped = 0
    for x in items:
        spn = _safe_int(x.get("SPN"))
        fmi = _safe_int(x.get("FMI"))
        if spn is None or fmi is None:
            skipped += 1
            continue

        name = x.get("Name") or ""
        title = x.get("Title") or ""
        component = x.get("Component") or ""
        dtc = x.get("DTC") or ""

        desc = x.get("Description")
        if not desc:
            parts = [p for p in [title, name, component] if p]
            desc = " | ".join(parts)

        entry = {
            "SPN": spn,
            "FMI": fmi,
            "DTC": dtc,
            "Name": name,
            "Title": title,
            "Component": component,
            "Description": desc,
            "Error Class": x.get("Error Class", ""),
            "Source": x.get("Source", ""),
            "Extra": x.get("Extra", {}),
            "WorkshopActions": x.get("WorkshopActions", None),
        }
        if not entry["WorkshopActions"]:
            extra = entry.get("Extra") or {}
            wa = extra.get("WorkshopAction")
            if wa:
                entry["WorkshopActions"] = [wa] if isinstance(wa, str) else wa

        lookup[(spn, fmi)] = entry

    st.info(f"📚 Loaded {len(lookup)} DTC entries from JSON (skipped {skipped} without SPN/FMI).")
    return lookup

DTC_LOOKUP = load_dtc_lookup()

# -------------------------
# Helper: format WorkshopActions for the table
# -------------------------
def _format_workshop_actions(entry: dict) -> str:
    if not entry:
        return ""
    wa = entry.get("WorkshopActions")
    if isinstance(wa, list):
        wa = [s for s in wa if s and str(s).strip()]
        return "\n• " + "\n• ".join(wa) if wa else ""
    if isinstance(wa, str):
        s = wa.strip()
        return s if s else ""
    extra = entry.get("Extra") or {}
    wa2 = extra.get("WorkshopAction")
    if isinstance(wa2, str) and wa2.strip():
        return wa2.strip()
    return ""

# -------------------------
# DTC decode routine (applies lookup + corrected lamp fields)
# -------------------------
def decode_dtcs_from_df(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame()

    assembled = assemble_tp_bam(df)
    merged_df = merge_assembled_into_df(df, assembled)

    rows = []
    for _, r in merged_df.iterrows():
        can_id = r.get("CAN ID")
        data = r.get("Data")
        if can_id is None or not isinstance(data, (bytes, bytearray)):
            continue
        pgn = (can_id >> 8) & 0xFFFF
        if pgn != DM1_PGN:
            continue
        lamp, dtcs = parse_dm1_frame_with_lamp(data)

        for d in dtcs:
            key = (d["SPN"], d["FMI"])
            entry = DTC_LOOKUP.get(key, {})
            rows.append({
                "Time": r.get("Timestamp"),
                "Source Address": f"0x{(can_id & 0xFF):02X}",
                "Assembled": bool(r.get("Assembled", False)),
                "SPN": d["SPN"],
                "FMI": d["FMI"],
                "OC": d["OC"],
                "CM": d.get("CM"),
                "DTC": entry.get("DTC", ""),
                "Title": entry.get("Title", "") or entry.get("Name", ""),
                "Description": entry.get("Description", "Unknown (not in lookup)"),
                "Error Class": entry.get("Error Class", ""),
                "Workshop Actions": _format_workshop_actions(entry),
                "MIL": lamp.get("MIL"), "MIL Flash": lamp.get("FlashMIL"), "MIL Flash Rate": lamp.get("MIL Flash Rate"),
                "RSL": lamp.get("RSL"), "RSL Flash": lamp.get("FlashRSL"), "RSL Flash Rate": lamp.get("RSL Flash Rate"),
                "AWL": lamp.get("AWL"), "AWL Flash": lamp.get("FlashAWL"), "AWL Flash Rate": lamp.get("AWL Flash Rate"),
                "PL": lamp.get("PL"), "PL Flash": lamp.get("FlashPL"), "PL Flash Rate": lamp.get("PL Flash Rate"),
            })

        if not dtcs and any(lamp.get(k) is True for k in ("MIL", "RSL", "AWL", "PL")):
            rows.append({
                "Time": r.get("Timestamp"),
                "Source Address": f"0x{(can_id & 0xFF):02X}",
                "Assembled": bool(r.get("Assembled", False)),
                "SPN": None, "FMI": None, "OC": None, "CM": None,
                "DTC": "", "Title": "", "Description": "Lamp active but no SPN/FMI blocks present",
                "Error Class": "", "Workshop Actions": "",
                "MIL": lamp.get("MIL"), "MIL Flash": lamp.get("FlashMIL"), "MIL Flash Rate": lamp.get("MIL Flash Rate"),
                "RSL": lamp.get("RSL"), "RSL Flash": lamp.get("FlashRSL"), "RSL Flash Rate": lamp.get("RSL Flash Rate"),
                "AWL": lamp.get("AWL"), "AWL Flash": lamp.get("FlashAWL"), "AWL Flash Rate": lamp.get("AWL Flash Rate"),
                "PL": lamp.get("PL"), "PL Flash": lamp.get("FlashPL"), "PL Flash Rate": lamp.get("PL Flash Rate"),
            })

    out = pd.DataFrame(rows)
    if not out.empty:
        out = (out.sort_values(["Source Address", "SPN", "FMI", "OC"], ascending=[True, True, True, False])
               .drop_duplicates(subset=["Source Address", "SPN", "FMI"], keep="first")
               .reset_index(drop=True))
    return out

# -------------------------
# ECU mapping for presence detection
# -------------------------
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

# -------------------------
# Root cause inference & detailed diagnosis (presence-based)
# -------------------------
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

# -------------------------
# Wiring PDF parsing (grounds & connector-pin→ground)
# -------------------------
# Ground label: allow 3–4 digits (e.g., G101, G4379), avoid title-block false positives
GROUND_REGEX = re.compile(r"(?<![A-Z0-9-])G([1-9]\d{2,4})(?!\d)", re.IGNORECASE)
GROUND_ALT_REGEXES = [
    re.compile(r"(?<![A-Z0-9-])G-?\s*([1-9]\d{2,4})(?!\d)", re.IGNORECASE),
    re.compile(r"(?<![A-Z0-9-])GND[\s\-]*([1-9]\d{2,4})(?!\d)", re.IGNORECASE),
]

# Connector/pin → ground patterns (relaxed + variants)
CONN_PIN_GROUND_REGEX = re.compile(
    r"(?:(?:Conn(?:ector)?)[\s:]*|(?:\bC\b)?)([A-Za-z0-9\-_/ ]{1,20})\s*(?:pin|p|PIN|Pin)\s*([0-9]{1,3})[^A-Za-z0-9]+(G-?\s*[1-9]\d{2,4})\b",
    re.IGNORECASE
)
CONN_PIN_GROUND_REGEX_2 = re.compile(
    r"\b([A-Za-z0-9\-_/]{2,20})\b.*?\b(?:pin|p)\s*([0-9]{1,3})\b.*?\b(G-?\s*[1-9]\d{2,4})\b",
    re.IGNORECASE
)
CONN_PIN_GROUND_REGEX_3 = re.compile(
    r"\b(?:pin|p)\s*([0-9]{1,3})\b.*?(?:->|→|to|-|—|–)\s*\b(G-?\s*[1-9]\d{2,4})\b.*?\b([A-Za-z0-9\-_/]{2,20})\b",
    re.IGNORECASE
)

def list_available_drawings():
    candidates = [
        "PEE0000013_J.pdf",
        "PEE0000014_K.pdf",
        "PEE0000082 FRONT CHASSIS WIRING HARNESS FOR LOCALIZED CABIN.pdf",
        "PEE0000083_A_01072024.pdf",
        "PEE0000084.pdf",
    ]
    found = []
    for c in candidates:
        if os.path.exists(c):
            found.append(c)
        elif os.path.exists(os.path.join("/mnt/data", c)):
            found.append(os.path.join("/mnt/data", c))
    return found

def parse_pdfs_for_grounds_and_mappings(paths):
    """
    Returns:
      {
        "grounds": { "G201": [ {file, page, coords: (x0,y0,x1,y1) or None, text_snippet } ...], ... },
        "conn_pin_ground": [ {file, page, connector, pin, ground, context, coords}, ... ]
      }
    """
    results = {"grounds": defaultdict(list), "conn_pin_ground": []}
    if not paths:
        return results

    def _emit_ground(num_str, text, words, file_path, page_idx, idx_start=None, idx_end=None):
        g = f"G{num_str}"
        if text:
            s = max(0, (idx_start or 0) - 30)
            e = min(len(text), (idx_end or 0) + 30)
            snippet = text[s:e].replace("\n", " ")
        else:
            snippet = ""
        bbox = None
        if words:
            token = g.upper()
            for w in words:
                if (w.get("text", "").strip().upper() == token):
                    bbox = (w.get("x0"), w.get("top"), w.get("x1"), w.get("bottom"))
                    break
        results["grounds"][g].append({
            "file": file_path, "page": page_idx, "coords": bbox, "text_snippet": snippet
        })

    for p in paths:
        try:
            file_path = p
            if PDF_BACKEND == "pdfplumber":
                import pdfplumber
                with pdfplumber.open(file_path) as pdf:
                    for page_idx, page in enumerate(pdf.pages, start=1):
                        try:
                            words = page.extract_words(use_text_flow=True, keep_blank_chars=False)
                            text = page.extract_text() or ""
                        except Exception:
                            words, text = [], ""
                        # Normalize punctuation/spaces so regexes match more often
                        text = (text or "").replace("\u2013","-").replace("\u2014","-").replace("\xa0"," ")

                        # Ground labels (primary + alternates)
                        for m in GROUND_REGEX.finditer(text):
                            _emit_ground(m.group(1), text, words, file_path, page_idx, m.start(), m.end())
                        for alt in GROUND_ALT_REGEXES:
                            for m in alt.finditer(text):
                                _emit_ground(m.group(1), text, words, file_path, page_idx, m.start(), m.end())

                        # Connector/pin -> ground (exact + relaxed)
                        for m in CONN_PIN_GROUND_REGEX.finditer(text):
                            connector = (m.group(1) or "").strip()
                            pin = m.group(2)
                            ground = (m.group(3) or "").upper().replace(" ", "")
                            ctx_start = max(0, m.start() - 40)
                            ctx_end = min(len(text), m.end() + 40)
                            context = text[ctx_start:ctx_end].replace("\n", " ")
                            results["conn_pin_ground"].append({
                                "file": file_path, "page": page_idx, "connector": connector, "pin": pin,
                                "ground": ground, "context": context, "coords": None
                            })
                        for m in CONN_PIN_GROUND_REGEX_2.finditer(text):
                            results["conn_pin_ground"].append({
                                "file": file_path, "page": page_idx,
                                "connector": (m.group(1) or "").strip(),
                                "pin": m.group(2),
                                "ground": (m.group(3) or "").upper().replace(" ", ""),
                                "context": m.group(0).replace("\n"," "),
                                "coords": None
                            })
                        for m in CONN_PIN_GROUND_REGEX_3.finditer(text):
                            results["conn_pin_ground"].append({
                                "file": file_path, "page": page_idx,
                                "connector": (m.group(3) or "").strip(),
                                "pin": m.group(1),
                                "ground": (m.group(2) or "").upper().replace(" ", ""),
                                "context": m.group(0).replace("\n"," "),
                                "coords": None
                            })

                        # Row-based mining from word rows
                        try:
                            rows_by_y = defaultdict(list)
                            for w in words or []:
                                y = round(w.get("top", 0), 1)
                                rows_by_y[y].append(w)
                            for y, ws in rows_by_y.items():
                                line = " ".join(
                                    (w.get("text","") or "")
                                    for w in sorted(ws, key=lambda z: z.get("x0", 0))
                                )
                                line = line.replace("\u2013","-").replace("\u2014","-").replace("\xa0"," ")
                                for rx in (CONN_PIN_GROUND_REGEX, CONN_PIN_GROUND_REGEX_2, CONN_PIN_GROUND_REGEX_3):
                                    m = rx.search(line)
                                    if not m:
                                        continue
                                    if rx is CONN_PIN_GROUND_REGEX_3:
                                        pin, ground, connector = m.group(1), m.group(2), m.group(3)
                                    else:
                                        connector, pin, ground = m.group(1), m.group(2), m.group(3)
                                    results["conn_pin_ground"].append({
                                        "file": file_path, "page": page_idx,
                                        "connector": (connector or "").strip(),
                                        "pin": pin,
                                        "ground": (ground or "").upper().replace(" ", ""),
                                        "context": line.strip(),
                                        "coords": None
                                    })
                        except Exception:
                            pass

            elif PDF_BACKEND == "pypdf2":
                from PyPDF2 import PdfReader
                reader = PdfReader(file_path)
                for page_idx, page in enumerate(reader.pages, start=1):
                    try:
                        text = page.extract_text() or ""
                    except Exception:
                        text = ""
                    text = text.replace("\u2013","-").replace("\u2014","-").replace("\xa0"," ")

                    for m in GROUND_REGEX.finditer(text):
                        _emit_ground(m.group(1), text, None, file_path, page_idx, m.start(), m.end())
                    for alt in GROUND_ALT_REGEXES:
                        for m in alt.finditer(text):
                            _emit_ground(m.group(1), text, None, file_path, page_idx, m.start(), m.end())

                    for m in CONN_PIN_GROUND_REGEX.finditer(text):
                        connector = (m.group(1) or "").strip()
                        pin = m.group(2)
                        ground = (m.group(3) or "").upper().replace(" ", "")
                        ctx_start = max(0, m.start() - 40)
                        ctx_end = min(len(text), m.end() + 40)
                        context = text[ctx_start:ctx_end].replace("\n", " ")
                        results["conn_pin_ground"].append({
                            "file": file_path, "page": page_idx, "connector": connector, "pin": pin,
                            "ground": ground, "context": context, "coords": None
                        })
                    for m in CONN_PIN_GROUND_REGEX_2.finditer(text):
                        results["conn_pin_ground"].append({
                            "file": file_path, "page": page_idx,
                            "connector": (m.group(1) or "").strip(),
                            "pin": m.group(2),
                            "ground": (m.group(3) or "").upper().replace(" ", ""),
                            "context": m.group(0).replace("\n"," "),
                            "coords": None
                        })
                    for m in CONN_PIN_GROUND_REGEX_3.finditer(text):
                        results["conn_pin_ground"].append({
                            "file": file_path, "page": page_idx,
                            "connector": (m.group(3) or "").strip(),
                            "pin": m.group(1),
                            "ground": (m.group(2) or "").upper().replace(" ", ""),
                            "context": m.group(0).replace("\n"," "),
                            "coords": None
                        })

            else:
                st.warning("⚠️ No PDF backend available. Install `pdfplumber` or `PyPDF2` to enable parsing.")

            # OCR fallback (only if needed / available)
            if OCR_AVAILABLE:
                low_hits = (sum(len(v) for v in results["grounds"].values()) < 3) and (len(results["conn_pin_ground"]) == 0)
                if low_hits:
                    try:
                        images = convert_from_path(file_path, dpi=300)
                        for page_idx, img in enumerate(images, start=1):
                            ocr_text = pytesseract.image_to_string(img)
                            ocr_text = ocr_text.replace("\u2013","-").replace("\u2014","-").replace("\xa0"," ")

                            for m in GROUND_REGEX.finditer(ocr_text):
                                _emit_ground(m.group(1), ocr_text, None, file_path, page_idx, m.start(), m.end())
                            for alt in GROUND_ALT_REGEXES:
                                for m in alt.finditer(ocr_text):
                                    _emit_ground(m.group(1), ocr_text, None, file_path, page_idx, m.start(), m.end())

                            for rx in (CONN_PIN_GROUND_REGEX, CONN_PIN_GROUND_REGEX_2, CONN_PIN_GROUND_REGEX_3):
                                for m in rx.finditer(ocr_text):
                                    if rx is CONN_PIN_GROUND_REGEX_3:
                                        pin, ground, connector = m.group(1), m.group(2), m.group(3)
                                    else:
                                        connector, pin, ground = m.group(1), m.group(2), m.group(3)
                                    results["conn_pin_ground"].append({
                                        "file": file_path, "page": page_idx,
                                        "connector": (connector or "").strip(),
                                        "pin": re.sub(r"\D","", str(pin)),
                                        "ground": ("G" + re.sub(r"\D","", str(ground))).upper(),
                                        "context": m.group(0).replace("\n"," "),
                                        "coords": None
                                    })
                    except Exception as e:
                        st.warning(f"⚠️ OCR fallback failed for '{os.path.basename(file_path)}': {e}")

        except Exception as e:
            st.warning(f"⚠️ Failed parsing '{os.path.basename(p)}': {e}")
            continue

    return results

def build_dynamic_ground_map(ecu_connector_map, extraction):
    """
    Use connector-pin→ground hits to assign grounds per ECU based on its main connector.
    Returns: dict ecu_name -> ground_label (best guess)
    """
    dynamic_map = {}
    if not extraction or "conn_pin_ground" not in extraction:
        return dynamic_map

    hits_by_connector = defaultdict(list)
    for hit in extraction["conn_pin_ground"]:
        conn = (hit.get("connector") or "").strip().lower()
        if conn:
            hits_by_connector[conn].append(hit)

    for ecu, meta in ecu_connector_map.items():
        conn_name = (meta.get("connector") or "").strip()
        if not conn_name:
            continue
        key_variants = {
            conn_name.lower(),
            conn_name.replace("connector", "").strip().lower(),
            conn_name.replace(" ", "").lower()
        }
        best = None
        for k in list(key_variants):
            if k in hits_by_connector:
                best = hits_by_connector[k]
                break
        if best is None:
            for k, v in hits_by_connector.items():
                if conn_name.lower() in k or k in conn_name.lower():
                    best = v
                    break
        if best:
            counter = Counter([h["ground"] for h in best if h.get("ground")])
            if counter:
                ground, _ = counter.most_common(1)[0]
                dynamic_map[ecu] = ground

    return dynamic_map

# -------------------------
# UI: Vehicle info & config
# -------------------------
st.markdown("### 🚛 Vehicle Info")
vehicle_name = st.text_input("Enter Vehicle Name or ID", max_chars=30)

st.markdown("### ⚙️ Configuration")
has_double_tank = st.checkbox("Has Double Tank?", value=True)
has_amt = st.checkbox("Has AMT?", value=True)
has_retarder = st.checkbox("Has Retarder?", value=True)

# Convenience: reload lookup after swapping JSON file
if st.button("🔄 Reload DTC Lookup (clear cache)"):
    load_dtc_lookup.clear()
    DTC_LOOKUP = load_dtc_lookup()
    st.success("Lookup cache cleared and reloaded.")

# -------------------------
# CAN Data Input
# -------------------------
st.markdown("### 📡 CAN Data Input")
st.subheader("Upload Trace File")
uploaded_file = st.file_uploader("Upload CAN Trace (.trc)", type=["trc"])

df_can = pd.DataFrame()  # parsed CAN frames

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".trc") as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        tmp_path = tmp_file.name
    df_can = parse_trc_file(tmp_path)
    if not df_can.empty:
        st.success("✅ Trace file processed successfully.")
    else:
        st.error("❌ No frames parsed from the trace file. Check format.")

# Optional live PCAN
st.subheader("Live PCAN (Optional)")
bus = None
if PCAN_AVAILABLE:
    try:
        bus = can.interface.Bus(bustype="pcan", channel="PCAN_USBBUS1", bitrate=500000)
        st.success("✅ Connected to PCAN successfully.")
    except Exception as e:
        st.error(f"❌ PCAN connection failed: {e}")
        bus = None
else:
    st.info("ℹ️ python-can not installed or PCAN not available on this machine.")

if bus:
    st.info("Reading live messages from PCAN… (5s)")
    live_data = []
    start_time = time.time()
    while time.time() - start_time < 5:
        msg = bus.recv(1)
        if msg:
            data_bytes = msg.data if hasattr(msg, "data") else b""
            live_data.append({
                "Timestamp": None,
                "CAN ID": msg.arbitration_id,
                "DLC": msg.dlc if hasattr(msg, "dlc") else len(data_bytes),
                "Data": data_bytes,
                "Source Address": msg.arbitration_id & 0xFF
            })
    if live_data:
        df_can = pd.DataFrame(live_data)
        st.success(f"✅ Captured {len(live_data)} messages from PCAN.")

# -------------------------
# GATE: Require CAN data before any analysis
# -------------------------
has_data = not df_can.empty
if not has_data:
    st.info("📂 Upload a .trc file or connect to live PCAN to start analysis.")
    st.stop()

# -------------------------
# Build ECU presence report
# -------------------------
if not vehicle_name.strip():
    st.info("📝 Please enter a vehicle name to run diagnostics.")
    st.stop()

report = []
found_sources = set()
if not df_can.empty and "Source Address" in df_can.columns:
    try:
        found_sources = {int(x) for x in df_can["Source Address"].astype(int).tolist()}
    except Exception:
        try:
            found_sources = {
                int(str(x), 16) if isinstance(x, str) and re.fullmatch(r"[0-9A-Fa-f]+", str(x))
                else int(x)
                for x in df_can["Source Address"].tolist() if str(x) != "nan"
            }
        except Exception:
            found_sources = set()

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

df_report = pd.DataFrame(report)

# Log ECU status to Firebase
if not df_report.empty:
    try:
        log_to_firebase(vehicle_name, df_report)
    except Exception:
        pass

st.success("✅ Diagnostics completed!")
st.subheader("📋 ECU Status")
st.dataframe(df_report, use_container_width=True)

# Root Cause Analysis (presence)
st.subheader("🧠 Root Cause Analysis")
root_causes = infer_root_causes(df_report)
if root_causes:
    for cause in root_causes:
        st.markdown(
            f"""<div style='background:#fffbe6; border-left:5px solid #faad14; padding:10px; margin-bottom:10px;'>
            <b>{cause['Type']}</b>: <code>{cause['Component']}</code><br>
            Missing: {cause['Missing']} / {cause['Total']} — Confidence: {cause['Confidence']}%
            <br>ECUs: {', '.join(cause['Affected ECUs'])}</div>""",
            unsafe_allow_html=True
        )
else:
    st.info("No root-cause candidates found (no missing ECUs).")

# PDF report
pdf_buf = generate_pdf_buffer(report, vehicle_name)
st.download_button("⬇️ Download PDF Report", pdf_buf, f"{vehicle_name}_diagnostics.pdf", "application/pdf")

# Detailed ECU diagnostics for missing ECUs
st.subheader("🔧 Detailed ECU Diagnostics")
for _, row in df_report[df_report["Status"] == "❌ MISSING"].iterrows():
    st.markdown(generate_detailed_diagnosis(row["ECU"]), unsafe_allow_html=True)

# -------------------------
# CLEAN DM1 TABLE HELPERS
# -------------------------
def _sa_to_int(sa):
    if sa is None:
        return None
    if isinstance(sa, str) and sa.lower().startswith("0x"):
        try:
            return int(sa, 16)
        except Exception:
            return None
    try:
        return int(sa)
    except Exception:
        return None

def _lamp_summary(row):
    pieces = []
    def add(label, on, flash, rate):
        if on is True:
            if flash:
                pieces.append(f"{label} ({(rate or 'FLASH').title()})")
            else:
                if not rate or str(rate).upper() in ("NONE", "STEADY"):
                    pieces.append(f"{label} (steady)")
                else:
                    pieces.append(f"{label} ({str(rate).title()})")
    add("MIL", row.get("MIL"), row.get("MIL Flash"), row.get("MIL Flash Rate"))
    add("RSL", row.get("RSL"), row.get("RSL Flash"), row.get("RSL Flash Rate"))
    add("AWL", row.get("AWL"), row.get("AWL Flash"), row.get("AWL Flash Rate"))
    add("PL",  row.get("PL"),  row.get("PL Flash"),  row.get("PL Flash Rate"))
    return ", ".join(pieces) if pieces else "—"

def _severity_rank(row):
    if row.get("MIL") is True: return 0
    if row.get("RSL") is True: return 1
    if row.get("AWL") is True: return 2
    if row.get("PL")  is True: return 3
    return 4

def clean_dm1_table(raw: pd.DataFrame) -> pd.DataFrame:
    """
    - Adds ECU column from Source Address
    - Collapses lamp columns into a single 'Lamp' summary
    - Creates 'SPN/FMI' view column
    - Ranks & de-duplicates: keep worst-severity + highest OC per (SA, SPN, FMI)
    - Orders columns for readability
    """
    if raw is None or raw.empty:
        return raw

    df = raw.copy()
    df["SA_int"] = df["Source Address"].apply(_sa_to_int)
    df["ECU"] = df["SA_int"].apply(lambda x: ecu_map.get(x, f"SA 0x{x:02X}" if x is not None else "Unknown"))
    df["Lamp"] = df.apply(_lamp_summary, axis=1)
    df["Severity"] = df.apply(_severity_rank, axis=1)

    for c in ("SPN", "FMI", "OC"):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    df["SPN/FMI"] = df.apply(
        lambda r: f"{int(r['SPN'])}/{int(r['FMI'])}" if pd.notna(r["SPN"]) and pd.notna(r["FMI"]) else "—",
        axis=1
    )

    sort_cols = ["Severity", "OC"]
    ascending = [True, False]
    if "Time" in df.columns:
        sort_cols.append("Time")
        ascending.append(False)
    df = df.sort_values(sort_cols, ascending=ascending)
    df = df.drop_duplicates(subset=["SA_int", "SPN", "FMI"], keep="first").reset_index(drop=True)

    preferred = [
        "Time", "ECU", "Source Address",
        "SPN", "FMI", "OC", "SPN/FMI",
        "DTC", "Title", "Description", "Error Class",
        "Lamp", "Assembled", "Workshop Actions"
    ]
    existing = [c for c in preferred if c in df.columns]
    df_view = df[existing].copy()

    if "Assembled" in df_view.columns:
        df_view["Assembled"] = df_view["Assembled"].map({True: "TP/BAM", False: "—"}).fillna("—")
    for col in ("Title", "Description", "Error Class", "DTC"):
        if col in df_view.columns:
            df_view[col] = df_view[col].fillna("—").replace("", "—")

    df_view = df_view.rename(columns={
        "OC": "Occurrences",
        "DTC": "DTC Code",
        "Error Class": "Severity Class",
    })
    return df_view

# -------------------------
# DTC decoding + UI + Firebase upload
# -------------------------
st.markdown("---")
st.subheader("🚨 Active Diagnostic Trouble Codes (DM1)")
raw_dtcs = decode_dtcs_from_df(df_can)
if raw_dtcs.empty:
    st.info("No active DM1 DTCs detected.")
else:
    cleaned = clean_dm1_table(raw_dtcs)
    try:
        st.dataframe(cleaned, use_container_width=True, hide_index=True)
    except Exception:
        st.dataframe(cleaned, use_container_width=True)

    st.download_button(
        "⬇️ Download DTC Report (CSV)",
        cleaned.to_csv(index=False),
        f"{vehicle_name}_dtc_report.csv",
        "text/csv"
    )

    try:
        log_dtcs_to_firebase(vehicle_name, raw_dtcs=raw_dtcs, cleaned_dtcs=cleaned)
        st.success("☁️ DTCs uploaded to Firebase.")
    except Exception as e:
        st.warning(f"⚠️ Unable to upload DTCs to Firebase: {e}")

# -------------------------
# Wiring PDF parsing UI (service-centric)
# -------------------------
st.markdown("---")
st.subheader("📑 Auto-parse Wiring PDFs (Grounds & Connector Pins)")
st.caption(f"📄 Using PDF backend: {PDF_BACKEND or '— none —'}")

available = list_available_drawings()
selected = st.multiselect("Select drawings to parse", options=available, default=available)
parse_now = st.button("🔎 Parse selected PDFs")
if parse_now and selected:
    extraction = parse_pdfs_for_grounds_and_mappings(selected)
    # Store raw extraction
    st.session_state["wiring_extraction"] = extraction
    try:
        log_wiring_extraction(vehicle_name, extraction)
    except Exception:
        pass
    total_g = sum(len(v) for v in (extraction.get("grounds") or {}).values())
    total_m = len(extraction.get("conn_pin_ground") or [])
    st.success(f"Parsed {len(selected)} file(s). Found {total_g} ground labels and {total_m} conn-pin mappings.")

extraction = st.session_state.get("wiring_extraction") or {}

def _normalize_ground(g: str) -> str:
    if not g: return ""
    m = re.search(r"\bG([1-9]\d{2})\b", str(g), flags=re.IGNORECASE)
    return f"G{m.group(1)}" if m else ""

def _clean_conn_name(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"\s", " ", s)
    return s

def _dedupe_hits(hits: list) -> pd.DataFrame:
    if not hits: return pd.DataFrame(columns=["Connector","Pin","Ground","File","Page","Context"])
    rows = []
    for h in hits:
        rows.append({
            "Connector": _clean_conn_name(h.get("connector")),
            "Pin": str(h.get("pin") or "").strip(),
            "Ground": _normalize_ground(h.get("ground")),
            "File": os.path.basename(h.get("file","")),
            "Page": h.get("page"),
            "Context": (h.get("context") or "").strip()
        })
    df = pd.DataFrame(rows)
    # keep only sane grounds and non-empty connector/pin
    df = df[(df["Ground"] != "") & (df["Connector"] != "") & (df["Pin"] != "")]
    # de-duplicate
    if not df.empty:
        df = (df.sort_values(["Connector","Ground","Pin","File","Page"])
                .drop_duplicates(subset=["Connector","Pin","Ground"], keep="first")
                .reset_index(drop=True))
    return df

def _match_to_ecu(connector_label: str) -> str:
    c = (connector_label or "").lower().replace("connector", "").strip()
    for ecu, meta in ecu_connector_map.items():
        ec = (meta.get("connector") or "").lower()
        if not ec: continue
        # exact or relaxed contains match
        if ec == connector_label.lower() or c and (c in ec or ec.replace("connector","").strip() in connector_label.lower()):
            return ecu
    return ""

def _build_ecu_effective_ground(df_hits: pd.DataFrame) -> tuple[dict, pd.DataFrame]:
    # count grounds per ECU inferred from connector matches
    votes = defaultdict(Counter)
    for row in df_hits.itertuples(index=False):
        ecu = _match_to_ecu(row.Connector)
        if not ecu: continue
        votes[ecu][row.Ground] = 1
    dyn = {}
    rows = []
    for ecu in ecu_connector_map.keys():
        default_g = ground_map_default.get(ecu, "—")
        best = votes.get(ecu, Counter())
        parsed = best.most_common(1)[0][0] if best else "—"
        eff = parsed if parsed != "—" else default_g
        total_votes = sum(best.values()) or 0
        conf = 0
        if total_votes:
            top_votes = best[parsed]
            conf = int(round(100 * top_votes / total_votes))
        dyn[ecu] = parsed if parsed != "—" else None
        rows.append({
            "ECU": ecu,
            "Connector": ecu_connector_map.get(ecu,{}).get("connector","-"),
            "Default Ground": default_g,
            "Parsed Ground": parsed,
            "Effective Ground": eff,
            "Confidence (%)": conf,
            "Votes": total_votes
        })
    return dyn, pd.DataFrame(rows).sort_values(["Confidence (%)","Votes","ECU"], ascending=[False,False,True]).reset_index(drop=True)

# 1) Clean connector→pin→ground hits (service-facing)
df_hits_clean = _dedupe_hits((extraction.get("conn_pin_ground") or []))
st.markdown("#### 🔌 Connector → Pin → Ground (clean)")
if df_hits_clean.empty:
    st.info("No connector/pin/ground mappings parsed.")
else:
    st.dataframe(df_hits_clean, use_container_width=True, hide_index=True)
    st.download_button(
        "⬇️ Download Connector–Pin–Ground (CSV)",
        df_hits_clean.to_csv(index=False),
        file_name=f"{vehicle_name}_connector_pin_ground.csv",
        mime="text/csv"
    )

# 2) ECU Effective Ground table (with confidence)
dyn_map, df_ecu_eff = _build_ecu_effective_ground(df_hits_clean)
st.session_state["dynamic_ground_map"] = {k:v for k,v in dyn_map.items() if v}
st.markdown("#### 🧭 ECU Ground Map (effective, confidence)")
if df_ecu_eff.empty:
    st.info("No ECU ground inferences available yet.")
else:
    st.dataframe(df_ecu_eff, use_container_width=True, hide_index=True)
    st.download_button(
        "⬇️ Download ECU Ground Map (CSV)",
        df_ecu_eff.to_csv(index=False),
        file_name=f"{vehicle_name}_ecu_effective_ground.csv",
        mime="text/csv"
    )

# 3) Top ground check targets (groups ECUs by Effective Ground)
st.markdown("#### 🎯 Top Ground Check Targets")
if df_ecu_eff.empty:
    st.write("—")
else:
    # use Effective Ground and keep rows where Effective Ground is a real Gxxx
    df_targets = df_ecu_eff[df_ecu_eff["Effective Ground"].str.match(r"^G\d{3}$", na=False)].copy()
    if df_targets.empty:
        st.write("—")
    else:
        summary = (df_targets.groupby("Effective Ground")
                   .agg(ECUs=("ECU", lambda s: ", ".join(sorted(set(s)))),
                        Count=("ECU","nunique"),
                        AvgConfidence=("Confidence (%)","mean"))
                   .reset_index()
                   .sort_values(["Count","AvgConfidence"], ascending=[False,False]))
        st.dataframe(summary, use_container_width=True, hide_index=True)
        st.download_button(
            "⬇️ Download Ground Targets (CSV)",
            summary.to_csv(index=False),
            file_name=f"{vehicle_name}_ground_targets.csv",
            mime="text/csv"
        )

def get_ground_for_ecu(ecu_name: str):
    # prefer parsed ground mapping; fallback to default
    dgm = st.session_state.get("dynamic_ground_map") or {}
    return dgm.get(ecu_name, ground_map_default.get(ecu_name, "-"))

# -------------------------
# Wiring & Ground Health Heuristics
# -------------------------
st.markdown("---")
st.subheader("⚡ Wiring & Ground Health Heuristics")

# FMI groups (wiring-related)
FMI_SHORT_TO_BATT = {3}
FMI_SHORT_TO_GND  = {4}
FMI_OPEN_CIRCUIT  = {5}
FMI_OVER_CURRENT  = {6}

def extract_battery_voltage_stats(df_can: pd.DataFrame):
    """Lightweight sampler for SPN 168 in PGN 0xFEF7 (if present)."""
    if df_can.empty:
        return None
    volt_samples = []
    for _, r in df_can.iterrows():
        can_id = r.get("CAN ID")
        data = r.get("Data")
        if not isinstance(data, (bytes, bytearray)) or can_id is None:
            continue
        pgn = (int(can_id) >> 8) & 0xFFFF
        if pgn == 0xFEF7 and len(data) >= 2:
            raw = data[0] | (data[1] << 8)
            if raw not in (0xFF, 0xFE, 0xFFFF):
                volt_samples.append(raw * 0.05)  # 0.05 V/bit
    if not volt_samples:
        return None
    return {"min_v": round(min(volt_samples), 2), "max_v": round(max(volt_samples), 2),
            "avg_v": round(sum(volt_samples)/len(volt_samples), 2), "n": len(volt_samples)}

def detect_addr_flapping(df_can: pd.DataFrame, gap_seconds: float = 3.0, min_msgs: int = 100, min_long_gaps: int = 5):
    """
    Robust flapping detector:
    - Ignore sparse sources (< min_msgs frames)
    - Count only gaps > gap_seconds
    - Require long gaps to occupy >15% of capture duration
    - Returns {sa_int: {gaps, first, last, median_gap}}
    """
    if df_can.empty or "Timestamp" not in df_can.columns:
        return {}
    flaps = {}
    df_ts = df_can.dropna(subset=["Timestamp"]).copy()
    if df_ts.empty:
        return flaps

    for sa, g in df_ts.groupby("Source Address"):
        ts = sorted([t for t in g["Timestamp"].tolist() if isinstance(t, (int, float))])
        if len(ts) < min_msgs:
            continue
        gaps = [ts[i]-ts[i-1] for i in range(1, len(ts))]
        long_gaps = [d for d in gaps if d > gap_seconds]
        if not long_gaps:
            continue
        duration = max(1e-6, ts[-1] - ts[0])
        if (sum(long_gaps) / duration) > 0.15 and len(long_gaps) >= min_long_gaps:
            flaps[int(sa)] = {
                "gaps": len(long_gaps),
                "first": ts[0],
                "last": ts[-1],
                "median_gap": float(pd.Series(gaps).median())
            }
    return flaps


def analyze_wiring_health(df_presence: pd.DataFrame, raw_dtcs_df: pd.DataFrame, df_can: pd.DataFrame):
    findings = []
    if df_presence is None or df_presence.empty:
        return findings, {}

    # Build presence + harness + dynamic ground
    presence = df_presence.copy()
    presence["Harness"] = presence["ECU"].map(lambda e: ecu_connector_map.get(e, {}).get("harness", "-"))
    presence["Ground"] = presence["ECU"].map(lambda e: get_ground_for_ecu(e))

    missing = presence[presence["Status"] == "❌ MISSING"].copy()

    def cluster_findings(by_col: str, label: str, base_weight: int = 50):
        grp = missing.groupby(by_col)
        for key, g in grp:
            if key in (None, "-", "", "—"): continue
            affected = g["ECU"].tolist()
            total_in_zone = sum(1 for row in presence.itertuples() if getattr(row, by_col, None) == key)
            conf = int(round((len(affected) / (total_in_zone or 1)) * base_weight + 25))
            findings.append({
                "type": f"Power/CAN path issue around {label}",
                "component": key,
                "confidence": min(conf, 95),
                "evidence": {"affected_ecus": affected, "missing_count": len(affected), "zone_total": total_in_zone}
            })

    if not missing.empty:
        cluster_findings("Fuse", "Fuse", 60)
        cluster_findings("Connector", "Connector", 55)
        cluster_findings("Harness", "Harness", 50)
        cluster_findings("Ground", "Ground", 70)

    # DTC patterns
    def _sa_name(sa_str):
        try:
            if isinstance(sa_str, str) and sa_str.startswith("0x"):
                sa_int = int(sa_str, 16)
            else:
                sa_int = int(sa_str)
            return ecu_map.get(sa_int, f"SA 0x{sa_int:02X}")
        except Exception:
            return str(sa_str)

    if raw_dtcs_df is not None and not raw_dtcs_df.empty:
        by_fmi = defaultdict(list)
        for _, r in raw_dtcs_df.iterrows():
            fmi = r.get("FMI")
            if pd.notna(fmi):
                by_fmi[int(fmi)].append(_sa_name(r.get("Source Address")))
        if any(f in by_fmi for f in FMI_SHORT_TO_BATT):
            findings.append({"type":"DTC pattern: Short to Battery (FMI 3)","component":"Multiple","confidence":65,"evidence":{"ecus":sorted(set(sum((by_fmi[f] for f in FMI_SHORT_TO_BATT if f in by_fmi), [])))}})
        if any(f in by_fmi for f in FMI_SHORT_TO_GND):
            findings.append({"type":"DTC pattern: Short to Ground/Low V (FMI 4)","component":"Multiple","confidence":65,"evidence":{"ecus":sorted(set(sum((by_fmi[f] for f in FMI_SHORT_TO_GND if f in by_fmi), [])))}})
        if any(f in by_fmi for f in FMI_OPEN_CIRCUIT):
            findings.append({"type":"DTC pattern: Open Circuit (FMI 5)","component":"Multiple","confidence":60,"evidence":{"ecus":sorted(set(sum((by_fmi[f] for f in FMI_OPEN_CIRCUIT if f in by_fmi), [])))}})
        if any(f in by_fmi for f in FMI_OVER_CURRENT):
            findings.append({"type":"DTC pattern: Over Current/Grounded (FMI 6)","component":"Multiple","confidence":60,"evidence":{"ecus":sorted(set(sum((by_fmi[f] for f in FMI_OVER_CURRENT if f in by_fmi), [])))}})

    # Behavior: flapping + low voltage
    flap = detect_addr_flapping(df_can)
    if flap:
        affected = []
        for sa_int, meta in flap.items():
            ecu = ecu_map.get(sa_int, f"SA 0x{sa_int:02X}")
            affected.append(f"{ecu} (gaps={meta['gaps']})")
        findings.append({"type":"Intermittent connectivity (possible loose power/ground)","component":"Multiple ECUs","confidence":70,"evidence":{"flapping": affected}})

    vstats = extract_battery_voltage_stats(df_can)
    if vstats and vstats["min_v"] <= 10.5:
        findings.append({"type":"System Voltage Low","component":"Vehicle Power Supply","confidence":65 if vstats['min_v']>9.5 else 80,"evidence":vstats})

    findings.sort(key=lambda x: (-x["confidence"], x["type"]))
    return findings, {"flap": flap, "voltage": vstats}

def _zone_for_ecu(ecu_name: str):
    m = ecu_connector_map.get(ecu_name, {}) or {}
    return {
        "Connector": m.get("connector", "-"),
        "Fuse": m.get("fuse", "-"),
        "Harness": m.get("harness", "-"),
        "Ground": get_ground_for_ecu(ecu_name),
        "Drawing": (
            drawing_map.get(m.get("connector","")) or
            drawing_map.get(m.get("fuse","")) or
            drawing_map.get(m.get("harness","")) or
            None
        )
    }

def infer_wiring_faults(raw_dtcs_df: pd.DataFrame) -> list:
    if raw_dtcs_df is None or raw_dtcs_df.empty:
        return []
    FMI_SHORT_TO_BATT = {3}
    FMI_SHORT_TO_GND  = {4}
    FMI_OPEN_CIRCUIT  = {5}
    FMI_OVER_CURRENT  = {6}

    faults = []
    seen = set()
    for _, r in raw_dtcs_df.iterrows():
        spn = r.get("SPN"); fmi = r.get("FMI"); sa = r.get("Source Address")
        if pd.isna(spn) or pd.isna(fmi): continue
        key = (sa, int(spn), int(fmi))
        if key in seen: continue
        seen.add(key)

        try:
            sa_int = int(sa, 16) if isinstance(sa, str) and sa.startswith("0x") else int(sa)
        except Exception:
            sa_int = None
        ecu_name = ecu_map.get(sa_int, f"SA {sa}")
        zone = _zone_for_ecu(ecu_name)

        checks = []
        cause = "Electrical Fault"; confidence = 60

        if int(fmi) in FMI_SHORT_TO_BATT:
            cause = "Short to Battery / High Voltage"; confidence = 70
            checks += [
                f"Inspect signal wire chafing to +B on {zone['Harness']} (near bends/clips).",
                f"Backprobe at {zone['Connector']} for unexpected >VBAT on signal pin.",
                f"Check moisture/corrosion in {zone['Connector']} causing bridge to supply."
            ]
        elif int(fmi) in FMI_SHORT_TO_GND:
            cause = "Short to Ground / Low Voltage"; confidence = 70
            checks += [
                f"Check continuity to chassis from signal pin at {zone['Connector']} (should be open).",
                f"Inspect rubbed-through insulation on {zone['Harness']} where it contacts metal.",
                f"Verify sensor supply present at {zone['Connector']} (key ON).",
                f"Torque & clean ground {zone['Ground']}."
            ]
        elif int(fmi) in FMI_OPEN_CIRCUIT:
            cause = "Open Circuit / Loose Contact"; confidence = 65
            checks += [
                f"Pin-tension & latch check at {zone['Connector']} (pull test, pin fit).",
                f"Continuity test sensor↔ECU over {zone['Harness']} (wiggle while measuring).",
                f"Inspect fuse {zone['Fuse']} seating and oxidation.",
                f"Clean and retorque ground {zone['Ground']}."
            ]
        elif int(fmi) in FMI_OVER_CURRENT:
            cause = "Overcurrent / Grounded Circuit"; confidence = 65
            checks += [
                f"Check for pin deformation/short in {zone['Connector']}.",
                f"Inspect branch splices on {zone['Harness']} for melted tape/shorts.",
                f"Unplug suspect sensor/actuator; recheck if DTC state changes."
            ]
        else:
            cause = "General Circuit Fault"; confidence = 55
            checks += [
                f"Verify supply and ground at {zone['Connector']} (key ON).",
                f"Inspect {zone['Harness']} for crush, pinch, or water ingress.",
            ]

        # Enrich with parsed connector-pin→ground info (exact pins)
        extraction = st.session_state.get("wiring_extraction") or {}
        pin_hints = []
        if extraction and "conn_pin_ground" in extraction:
            conn_lower = (zone['Connector'] or "").strip().lower()
            for hit in extraction["conn_pin_ground"]:
                hconn = (hit.get("connector") or "").strip().lower()
                if not hconn: continue
                if conn_lower and (conn_lower in hconn or hconn in conn_lower):
                    if not zone["Ground"] or (hit.get("ground") == zone["Ground"]):
                        pin_hints.append(f"Pin {hit.get('pin')} → {hit.get('ground')} ({os.path.basename(hit.get('file',''))} p.{hit.get('page')})")
        if pin_hints:
            checks.append("Pin references: " + "; ".join(sorted(set(pin_hints))[:6]))

        if zone["Drawing"]:
            checks.append(f"Refer drawing: {zone['Drawing']} for pinout/route.")

        faults.append({
            "ECU": ecu_name,
            "Source Address": sa,
            "SPN": int(spn),
            "FMI": int(fmi),
            "Cause": cause,
            "Confidence": confidence,
            "Connector": zone["Connector"],
            "Fuse": zone["Fuse"],
            "Harness": zone["Harness"],
            "Ground": zone["Ground"],
            "Drawing": zone["Drawing"],
            "Checks": checks
        })
    faults.sort(key=lambda x: (-x["Confidence"], x["ECU"], x["SPN"], x["FMI"]))
    return faults

# -------------------------
# Analyze & display wiring health + per-DTC faults
# -------------------------
findings, extras = analyze_wiring_health(df_report, raw_dtcs if 'raw_dtcs' in globals() else pd.DataFrame(), df_can)

if not findings:
    st.info("No wiring/ground risk patterns detected from current trace and DTC set.")
else:
    for f in findings:
        ev = f.get("evidence", {})
        st.markdown(
            f"""<div style='background:#f6ffed; border-left:5px solid #52c41a; padding:10px; margin-bottom:10px;'>
            <b>{f['type']}</b><br>
            Component/Zone: <code>{f['component']}</code><br>
            Confidence: <b>{f['confidence']}%</b><br>
            <i>Evidence:</i> {ev}
            </div>""",
            unsafe_allow_html=True
        )

st.subheader("🧰 Wiring Fault Analyzer (Per-DTC suggestions)")
faults = infer_wiring_faults(raw_dtcs if 'raw_dtcs' in globals() else pd.DataFrame())
if not faults:
    st.info("No wiring-related DTC patterns found.")
else:
    for f in faults:
        checks_html = "<br>".join([f"• {c}" for c in f["Checks"]])
        st.markdown(
            f"""<div style='background:#e6f4ff; border-left:5px solid #1677ff; padding:10px; margin-bottom:10px;'>
            <b>{f['ECU']}</b> — SPN {f['SPN']}/FMI {f['FMI']}<br>
            Cause: <b>{f['Cause']}</b> (Confidence {f['Confidence']}%)<br>
            Connector: <code>{f['Connector']}</code> | Fuse: <code>{f['Fuse']}</code> |
            Harness: <code>{f['Harness']}</code> | Ground: <code>{f['Ground']}</code><br>
            Drawing: <code>{f['Drawing'] or '—'}</code><br>
            <i>Suggested checks:</i><br>{checks_html}
            </div>""",
            unsafe_allow_html=True
        )

# Upload wiring results to Firebase
try:
    log_wiring_findings(vehicle_name, findings=findings, faults=faults, extracted=extraction if 'extraction' in globals() else st.session_state.get("wiring_extraction"))
    st.success("☁️ Wiring/ground findings uploaded to Firebase.")
except Exception as e:
    st.warning(f"⚠️ Could not upload wiring/ground findings: {e}")

# -------------------------
# Ground map viewer (dynamic vs default)
# -------------------------
st.markdown("---")
st.subheader("📍 Ground Map (Parsed vs Default)")
g_rows = []
for ecu in ecu_connector_map.keys():
    d = ecu_connector_map.get(ecu, {})
    g_rows.append({
        "ECU": ecu,
        "Connector": d.get("connector", "-"),
        "Fuse": d.get("fuse", "-"),
        "Harness": d.get("harness", "-"),
        "Default Ground": ground_map_default.get(ecu, "—"),
        "Parsed Ground": (st.session_state.get("dynamic_ground_map") or {}).get(ecu, "—"),
        "Effective Ground": (st.session_state.get("dynamic_ground_map") or {}).get(ecu, ground_map_default.get(ecu, "—"))
    })
df_gmap = pd.DataFrame(g_rows)
st.dataframe(df_gmap, use_container_width=True)

# Export options
col_a, col_b = st.columns(2)
with col_a:
    st.download_button(
        "⬇️ Download Ground Map (CSV)",
        df_gmap.to_csv(index=False),
        file_name=f"{vehicle_name}_ground_map.csv",
        mime="text/csv"
    )
with col_b:
    _extraction_json = json.dumps(st.session_state.get("wiring_extraction", {}), indent=2, default=str)
    st.download_button(
        "⬇️ Download Parsed Wiring Extraction (JSON)",
        _extraction_json,
        file_name=f"{vehicle_name}_wiring_extraction.json",
        mime="application/json"
    )

+# (Optional) keep a compact raw view for engineers (collapsed by default)
+with st.expander("🔬 Raw ground label occurrences (engineering reference)", expanded=False):
+    if not extraction or not extraction.get("grounds"):
+        st.write("—")
+    else:
+        rows = []
+        for g_label, hits in sorted(extraction["grounds"].items()):
+            for h in hits:
+                rows.append({
+                    "Ground": g_label,
+                    "File": os.path.basename(h.get("file","")),
+                    "Page": h.get("page"),
+                    "Coords (approx)": h.get("coords"),
+                    "Context": h.get("text_snippet","")
+                })
+        if rows:
+            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
+        else:
+            st.write("—")

# -------------------------
# Wrap-up & tech tips
# -------------------------
st.markdown("---")
st.markdown(
    """
**Tech tips for field checks**
- If several ECUs share the same **Effective Ground** and are **❌ MISSING** or show FMI 4/5/6, prioritize that ground stud.
- Use a voltage drop test across the ground strap while loads are active; >0.2V indicates excessive resistance.
- For connectors mapped to a ground in the parsed PDFs, do a **pin-tension** check and inspect for moisture/corrosion.
"""
)

# -------------------------
# Footer
# -------------------------
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



