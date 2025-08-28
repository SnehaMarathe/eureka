# app.py — EurekaCheck Unified Diagnostic Tool
# TP/BAM reassembly + DM1 with corrected lamp parsing + Clean DM1 table
# Firebase upload (ECU presence, DTCs)
# NEW: Trace-only Loose-Ground Detection (no PDF parsing)

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

def log_ground_health(vehicle_name: str, ground_report: pd.DataFrame, ecu_events: dict):
    if db is None:
        return
    payload = {
        "vehicle": vehicle_name,
        "user_info": _current_user_info(),
        "timestamp": datetime.now().isoformat(),
        "ground_report": ground_report.to_dict(orient="records") if ground_report is not None else [],
        "ecu_events": ecu_events
    }
    try:
        db.collection("diagnostics_ground_health").add(payload)
    except Exception as e:
        st.warning(f"⚠️ Firestore ground health upload failed: {e}")

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
# ECU connector map & ground map (static)
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
# Utility: PDF report generation (for presence report)
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
VOLT_PGN = 0xFEF7   # 65271 (Battery Potential / System Voltage)

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
        if pgn == TP_CM_PGN:  # TP.CM
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
        elif pgn == TP_DT_PGN:  # TP.DT
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
# Workshop actions formatting
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
# DTC decode routine
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
    return f"""
### 🔍 Diagnosis: {ecu_name} Missing

- ✅ **From diagnostic logic:**
  - Connector: `{connector}`
  - Fuse: `{fuse}`
  - Harness: `{harness}`

### 🛠️ Suggested Checks:
1. Verify voltage from **{fuse}** to **{connector}**.
2. Inspect CAN lines: CAN_H (`R/G`), CAN_L (`Br/W`).
3. Check connector `{connector}` for corrosion or damage.
4. Inspect harness `{harness}` bends and joints for breaks.
"""

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
# Trace-only Loose-Ground Detection
# -------------------------
# FMI groups (wiring-related)
FMI_SHORT_TO_BATT = {3}
FMI_SHORT_TO_GND  = {4}
FMI_OPEN_CIRCUIT  = {5}
FMI_OVER_CURRENT  = {6}

POWER_SUPPLY_SPNS = {158, 168, 627}  # Battery/System Voltage related (varies by vendor)

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

def collect_voltage_series(df_can: pd.DataFrame):
    """
    Extract battery/system voltage from FEF7 frames.
    Returns list of dicts: {t, v, sa}
    """
    series = []
    if df_can.empty:
        return series
    for _, r in df_can.iterrows():
        can_id = r.get("CAN ID")
        data = r.get("Data")
        t = r.get("Timestamp")
        if can_id is None or not isinstance(data, (bytes, bytearray)):
            continue
        pgn = (int(can_id) >> 8) & 0xFFFF
        if pgn == VOLT_PGN and len(data) >= 2:
            raw = data[0] | (data[1] << 8)
            if raw not in (0xFF, 0xFE, 0xFFFF):
                v = raw * 0.05  # 0.05 V/bit
                series.append({"t": t, "v": v, "sa": int(can_id & 0xFF)})
    return series

def detect_coordinated_voltage_dips(series, drop_v: float = 2.0, window_s: float = 0.5, min_ecus: int = 2):
    """
    Detect events where >= min_ecus show a voltage drop >= drop_v within window_s.
    Returns list of events: {t_window, ecus, v_before_avg, v_after_avg, drop_avg}
    """
    if not series:
        return []
    df = pd.DataFrame(series).dropna(subset=["t"])
    if df.empty:
        return []
    df = df.sort_values("t")
    events = []

    # Compute per-SA rolling min/max to find drops
    # Simple heuristic: compare current reading to the max in previous 3s
    for sa, g in df.groupby("sa"):
        g = g.sort_values("t")
        g["prev_max"] = g["v"].rolling(window=50, min_periods=5).max()  # arbitrary rolling count
        g["drop"] = g["prev_max"] - g["v"]
        df.loc[g.index, "drop"] = g["drop"]

    candidates = df[df["drop"] >= drop_v]
    if candidates.empty:
        return []

    # Cluster by time window
    times = candidates["t"].tolist()
    used = set()
    for i, t0 in enumerate(times):
        if i in used:
            continue
        group_idx = [i]
        for j in range(i+1, len(times)):
            if abs(times[j] - t0) <= window_s:
                group_idx.append(j)
        used.update(group_idx)
        idxs = candidates.iloc[group_idx].index
        ecus = sorted(set(int(x) for x in df.loc[idxs, "sa"].tolist()))
        if len(ecus) >= min_ecus:
            before = df[df["t"].between(t0-1.0, t0-0.2)]
            after  = df[df["t"].between(t0, t0+0.5)]
            v_before = before["v"].mean() if not before.empty else None
            v_after  = after["v"].mean()  if not after.empty  else None
            if v_before and v_after:
                events.append({
                    "t_window": (round(t0-0.2,2), round(t0+0.5,2)),
                    "ecus": ecus,
                    "v_before_avg": round(v_before,2),
                    "v_after_avg": round(v_after,2),
                    "drop_avg": round(v_before - v_after, 2)
                })
    return events

def dtc_ground_signatures(raw_dtcs_df: pd.DataFrame):
    """
    Look for FMIs 4/5/6 and power-supply SPNs indicating ground/power issues.
    Returns dicts:
      fmi_map: {fmi: [ecu_names]}
      psupply_sa: set(sa_int) where power SPNs seen
    """
    fmi_map = defaultdict(list)
    psupply_sa = set()
    if raw_dtcs_df is None or raw_dtcs_df.empty:
        return fmi_map, psupply_sa

    def _sa_name(sa_str):
        try:
            if isinstance(sa_str, str) and sa_str.startswith("0x"):
                sa_int = int(sa_str, 16)
            else:
                sa_int = int(sa_str)
            return ecu_map.get(sa_int, f"SA 0x{sa_int:02X}"), sa_int
        except Exception:
            return str(sa_str), None

    for _, r in raw_dtcs_df.iterrows():
        fmi = r.get("FMI")
        spn = r.get("SPN")
        ecu_n, sa_int = _sa_name(r.get("Source Address"))
        if pd.notna(fmi) and int(fmi) in FMI_SHORT_TO_BATT | FMI_SHORT_TO_GND | FMI_OPEN_CIRCUIT | FMI_OVER_CURRENT:
            fmi_map[int(fmi)].append(ecu_n)
        if pd.notna(spn) and int(spn) in POWER_SUPPLY_SPNS and sa_int is not None:
            psupply_sa.add(sa_int)
    return fmi_map, psupply_sa

def ground_health_from_trace(df_can: pd.DataFrame, raw_dtcs_df: pd.DataFrame):
    """
    Combine: flapping + coordinated voltage dips + DTC patterns.
    Score per *ground* using ground_map_default.
    Returns:
      ground_df (pd.DataFrame) and ecu_events (dict for details)
    """
    # Per-ECU events
    flap = detect_addr_flapping(df_can)
    volt_series = collect_voltage_series(df_can)
    dip_events = detect_coordinated_voltage_dips(volt_series)
    fmi_map, psupply_sa = dtc_ground_signatures(raw_dtcs_df)

    # Build ECU-level flags
    ecu_flags = {}
    for sa, name in ecu_map.items():
        ecu_flags[name] = {
            "flapping": sa in flap,
            "psupply_spn": sa in psupply_sa,
            "fmi4": name in (fmi_map.get(4, [])),
            "fmi5": name in (fmi_map.get(5, [])),
            "fmi6": name in (fmi_map.get(6, [])),
        }

    # Map dip events ECUs into names
    dip_ecus_flat = set()
    for ev in dip_events:
        for sa in ev["ecus"]:
            dip_ecus_flat.add(ecu_map.get(sa, f"SA 0x{sa:02X}"))

    # Score per ground
    rows = []
    for ecu, g in ground_map_default.items():
        flags = ecu_flags.get(ecu, {})
        score = 0
        notes = []

        if flags.get("flapping"):
            score += 35; notes.append("ECU flapping")
        if ecu in dip_ecus_flat:
            score += 35; notes.append("Voltage dip correlated")
        if flags.get("fmi4"):
            score += 15; notes.append("FMI4 (Low/Short to GND)")
        if flags.get("fmi5"):
            score += 15; notes.append("FMI5 (Open circuit)")
        if flags.get("fmi6"):
            score += 10; notes.append("FMI6 (Overcurrent/Grounded)")
        if flags.get("psupply_spn"):
            score += 10; notes.append("Power SPN active")

        rows.append({
            "Ground": g,
            "ECU": ecu,
            "Connector": ecu_connector_map.get(ecu, {}).get("connector", "-"),
            "Fuse": ecu_connector_map.get(ecu, {}).get("fuse", "-"),
            "Harness": ecu_connector_map.get(ecu, {}).get("harness", "-"),
            "Confidence": min(score, 95),
            "Evidence": ", ".join(notes) if notes else "—"
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        # Aggregate to ground stud for a service-friendly report
        agg = (df.groupby("Ground")
                 .agg(Confidence=("Confidence", "max"),
                      ECUs=("ECU", lambda s: ", ".join(sorted(set(s)))),
                      Worst_Evidence=("Evidence", lambda s: "; ".join(sorted(set([x for x in s if x != "—"]))[:4])))
                 .reset_index()
              )
        agg = agg.sort_values(by="Confidence", ascending=False)
    else:
        agg = pd.DataFrame(columns=["Ground", "Confidence", "ECUs", "Worst_Evidence"])

    ecu_events = {
        "flapping": {ecu_map.get(sa, f"SA 0x{sa:02X}"): meta for sa, meta in flap.items()},
        "voltage_dip_events": dip_events,
        "dtc_fmi_buckets": {str(k): sorted(set(v)) for k, v in fmi_map.items()},
        "power_spn_ecus": [ecu_map.get(sa, f"SA 0x{sa:02X}") for sa in sorted(psupply_sa)],
    }
    return agg, df, ecu_events

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
# Ground Health from Trace Only
# -------------------------
st.markdown("---")
st.subheader("⚡ Ground Health (from trace only)")

ground_summary, ecu_ground_rows, ecu_events = ground_health_from_trace(df_can, raw_dtcs)

if ground_summary is None or ground_summary.empty:
    st.info("No ground risk patterns detected from trace.")
else:
    st.markdown("**Ranked Grounds (higher = more likely issue):**")
    st.dataframe(ground_summary.rename(columns={
        "Worst_Evidence": "Evidence (top)"
    }), use_container_width=True)

    with st.expander("Per-ECU scoring & evidence"):
        st.dataframe(ecu_ground_rows, use_container_width=True)

    with st.expander("Detection details"):
        st.write("• Intermittent flapping ECUs:")
        if ecu_events.get("flapping"):
            for ecu, meta in ecu_events["flapping"].items():
                st.write(f"- {ecu}: gaps={meta['gaps']}, median_gap={round(meta['median_gap'],2)}s")
        else:
            st.write("—")

        st.write("• Coordinated voltage dip events (PGN FEF7):")
        if ecu_events.get("voltage_dip_events"):
            st.dataframe(pd.DataFrame(ecu_events["voltage_dip_events"]), use_container_width=True)
        else:
            st.write("—")

        st.write("• DTC buckets (FMI 3/4/5/6):")
        st.json(ecu_events.get("dtc_fmi_buckets", {}))

        st.write("• Power supply SPN ECUs:")
        st.write(", ".join(ecu_events.get("power_spn_ecus", [])) or "—")

# Export ground health as CSV
if ground_summary is not None and not ground_summary.empty:
    st.download_button(
        "⬇️ Download Ground Health (CSV)",
        ground_summary.to_csv(index=False),
        file_name=f"{vehicle_name}_ground_health.csv",
        mime="text/csv"
    )

# Upload to Firebase
try:
    log_ground_health(vehicle_name, ground_summary if ground_summary is not None else pd.DataFrame(), ecu_events)
    st.success("☁️ Ground health (trace-only) uploaded to Firebase.")
except Exception as e:
    st.warning(f"⚠️ Could not upload ground health: {e}")

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
