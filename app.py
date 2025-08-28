# app.py — EurekaCheck Unified Diagnostic Tool (TP/BAM reassembly + DM1 with DTC count parsing)
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
# Firebase logging & visitor counter helpers
# -------------------------
def log_to_firebase(vehicle_name: str, df: pd.DataFrame):
    if db is None:
        return
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
        db.collection("diagnostics_logs").add(data)
    except Exception as e:
        st.warning(f"⚠️ Firestore log failed: {e}")

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
# ECU connector map & drawing map (preserve your original mappings)
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
    "Rear Harness": "PEE0000083_A_01072024.pdf",
    "Retarder Wiring": "PEE0000013_J_01072024.pdf",
    "Pig Tail for Double Tank": "PEE0000083_A_01072024.pdf",
    "Trailer Interface": "PEE0000084.pdf"
}

# -------------------------
# Utility: PDF report generation
# -------------------------
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
                # Primary pattern: "1)   0.000 Rx   18FECA17   8  00 FF FF 00 00 00 00 00"
                m = re.match(r"\s*\d+\)\s+([\d.]+)\s+Rx\s+([0-9A-Fa-f]{6,8})\s+(\d+)\s+((?:[0-9A-Fa-f]{2}\s+)+)", line)
                if m:
                    ts = float(m.group(1))
                    can_id = int(m.group(2), 16)
                    dlc = int(m.group(3))
                    data_str = m.group(4).strip()
                    data_bytes = bytes(int(b, 16) for b in data_str.split()[:dlc])
                    sa = can_id & 0xFF
                    records.append({
                        "Timestamp": ts,
                        "CAN ID": can_id,
                        "DLC": dlc,
                        "Data": data_bytes,
                        "Source Address": sa
                    })
                    continue
                # Fallback pattern: "ID = 18FECA17 Len = 8 Data = 00 FF ..."
                m2 = re.search(r"ID\s*=\s*([0-9A-Fa-f]{6,8}).*?Len\s*=\s*(\d+).*?Data\s*=\s*((?:[0-9A-Fa-f]{2}\s+)+)", line)
                if m2:
                    can_id = int(m2.group(1), 16)
                    dlc = int(m2.group(2))
                    data_str = m2.group(3).strip()
                    data_bytes = bytes(int(b, 16) for b in data_str.split()[:dlc])
                    sa = can_id & 0xFF
                    records.append({
                        "Timestamp": None,
                        "CAN ID": can_id,
                        "DLC": dlc,
                        "Data": data_bytes,
                        "Source Address": sa
                    })
    except Exception as e:
        st.error(f"❌ Failed to parse .trc file: {e}")
        return pd.DataFrame()
    return pd.DataFrame(records)

# -------------------------
# J1939 / DM1 parsing (SPN/FMI extraction)
# -------------------------
DM1_PGN = 0xFECA  # 65226
TP_CM_PGN = 0xEC00  # 60416 (TP.CM)
TP_DT_PGN = 0xEB00  # 60160 (TP.DT)

def parse_dm1_frame_with_lamp(data_bytes: bytes):
    """
    Parse DM1 payload strictly according to SAE J1939-73 (Version 4 layout).
    """
    lamp = {"MIL": None, "RSL": None, "AWL": None, "PL": None, "FlashMIL": None, "FlashRSL": None, "FlashAWL": None, "FlashPL": None}
    dtcs = []

    if not data_bytes or len(data_bytes) < 1:
        return lamp, dtcs

    # Lamp byte (Byte1)
    lb = data_bytes[0]
    def twobit(val, shift):
        return (val >> shift) & 0x03
    try:
        mil_state = twobit(lb, 0)
        rsl_state = twobit(lb, 2)
        awl_state = twobit(lb, 4)
        pl_state = twobit(lb, 6)
        lamp["MIL"] = (mil_state == 1)
        lamp["RSL"] = (rsl_state == 1)
        lamp["AWL"] = (awl_state == 1)
        lamp["PL"] = (pl_state == 1)
    except Exception:
        lamp["MIL"] = lamp["RSL"] = lamp["AWL"] = lamp["PL"] = None

    # Flash byte (Byte2)
    if len(data_bytes) >= 2:
        fb = data_bytes[1]
        lamp["FlashMIL"] = ((fb >> 0) & 0x03) == 1
        lamp["FlashRSL"] = ((fb >> 2) & 0x03) == 1
        lamp["FlashAWL"] = ((fb >> 4) & 0x03) == 1
        lamp["FlashPL"]  = ((fb >> 6) & 0x03) == 1

    # Determine count of 4-byte DTC blocks after first two bytes
    if len(data_bytes) <= 2:
        return lamp, dtcs

    available = len(data_bytes) - 2
    dtc_count = available // 4

    for i in range(dtc_count):
        offset = 2 + i * 4
        if offset + 3 >= len(data_bytes):
            break
        b1 = data_bytes[offset]       # SPN low 8
        b2 = data_bytes[offset + 1]   # SPN next 8
        b3 = data_bytes[offset + 2]   # SPN high 3 bits + FMI (low 5 bits)
        b4 = data_bytes[offset + 3]   # CM (bit7) + OC (bits6..0)

        spn = int(b1) | (int(b2) << 8) | ((int(b3) & 0xE0) << 11)  # SPN
        fmi = int(b3) & 0x1F                                        # FMI
        cm = (int(b4) & 0x80) >> 7                                  # Conversion Method
        oc = int(b4) & 0x7F                                         # Occurrence Count

        # Skip empty slots
        if spn == 0 and fmi == 0 and oc == 0:
            continue

        dtcs.append({
            "SPN": spn,
            "FMI": fmi,
            "OC": oc,
            "CM": cm,
            "offset": offset
        })

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
        if pgn == TP_CM_PGN:
            if len(data) < 8:
                continue
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
        elif pgn == TP_DT_PGN:
            if len(data) < 1:
                continue
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
        # Fallback for ABS-only JSONs if WorkshopActions missing but Extra.WorkshopAction present
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
# DTC decode routine (applies lookup)
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
        # DTC list (zero or more)
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
                "MIL": lamp.get("MIL"),
                "RSL": lamp.get("RSL"),
                "AWL": lamp.get("AWL"),
                "PL": lamp.get("PL")
            })
        # If no dtcs but lamp indicates MIL ON, still report lamp status row
        if not dtcs and lamp.get("MIL"):
            rows.append({
                "Time": r.get("Timestamp"),
                "Source Address": f"0x{(can_id & 0xFF):02X}",
                "Assembled": bool(r.get("Assembled", False)),
                "SPN": None,
                "FMI": None,
                "OC": None,
                "CM": None,
                "DTC": "",
                "Title": "",
                "Description": "No SPN/FMI present in payload — MIL ON",
                "Error Class": "",
                "Workshop Actions": "",
                "MIL": lamp.get("MIL"),
                "RSL": lamp.get("RSL"),
                "AWL": lamp.get("AWL"),
                "PL": lamp.get("PL")
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
# Root cause inference & detailed diagnosis
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
# Build ECU presence report & harness analysis & DTCs
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
    try:
        log_to_firebase(vehicle_name, df_report)
    except Exception:
        pass

    st.success("✅ Diagnostics completed!")
    st.subheader("📋 ECU Status")
    st.dataframe(df_report, use_container_width=True)

    # Root Cause Analysis
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

    # Detailed ECU diagnostics
    st.subheader("🔧 Detailed ECU Diagnostics")
    for _, row in df_report[df_report["Status"] == "❌ MISSING"].iterrows():
        st.markdown(generate_detailed_diagnosis(row["ECU"]), unsafe_allow_html=True)

    # Visual Reference slides
    st.markdown("---")
    st.markdown("### 🖼️ Diagnostic Visual Reference")
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

    # -------------------------
    # DTC decoding section (uses latest JSON + WorkshopActions)
    # -------------------------
    st.markdown("---")
    st.subheader("🚨 Active Diagnostic Trouble Codes (DM1)")
    df_dtcs = decode_dtcs_from_df(df_can)
    if df_dtcs.empty:
        st.info("No active DM1 DTCs detected.")
    else:
        st.dataframe(df_dtcs, use_container_width=True)
        st.download_button("⬇️ Download DTC Report (CSV)", df_dtcs.to_csv(index=False), f"{vehicle_name}_dtc_report.csv", "text/csv")

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; font-size: 0.85em; color: gray;'>
        © 2025 Blue Energy Motors.<br>
        All rights reserved.<br>
        This diagnostic tool and its associated materials are proprietary and intended for authorized diagnostic and engineering use only.
    </div>
    """, unsafe_allow_html=True
)
