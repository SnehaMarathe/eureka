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

# --- 2/8/2025 --- Adding Firebase
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
# Utility: Log Data
# =============================
def log_to_firebase(vehicle_name: str, df: pd.DataFrame):
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
USER_CREDENTIALS = {"admin": "admin123","user": "check2025"}

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
# ECU & Diagnostic Helpers
# =============================

def parse_dm1_frame_with_lamp(timestamp, can_id, data_bytes, dtc_lookup):
    """Parse a DM1 frame, including lamp status and DTCs."""
    results = []
    if len(data_bytes) < 8:
        return results

    # Lamp Status Byte (Byte0) + Flash Status Byte (Byte1)
    lamp = {}
    def lamp_state(bits):
        if bits == 0b00: return False
        elif bits in (0b01,0b10): return True
        elif bits == 0b11: return True
        return False
    lb = data_bytes[0]
    lamp["MIL"] = lamp_state(lb & 0b11)
    lamp["RSL"] = lamp_state((lb >> 2) & 0b11)
    lamp["AWL"] = lamp_state((lb >> 4) & 0b11)
    lamp["PL"]  = lamp_state((lb >> 6) & 0b11)

    if len(data_bytes) >= 2:
        fb = data_bytes[1]
        lamp["FlashMIL"] = ((fb & 0b11) != 0)
        lamp["FlashRSL"] = (((fb >> 2) & 0b11) != 0)
        lamp["FlashAWL"] = (((fb >> 4) & 0b11) != 0)
        lamp["FlashPL"]  = (((fb >> 6) & 0b11) != 0)

    num_dtcs = data_bytes[2]
    offset = 3
    for i in range(num_dtcs):
        if offset + 4 > len(data_bytes): break
        b1,b2,b3,b4 = data_bytes[offset:offset+4]
        spn = b1 | (b2<<8) | ((b3 & 0xE0)<<11)
        fmi = b3 & 0x1F
        oc = b4 & 0x7F
        desc = "Unknown (not in lookup)"
        title,dtc_code,error_class = "","",""
        if (spn,fmi) in dtc_lookup:
            entry = dtc_lookup[(spn,fmi)]
            desc = entry.get("Description",desc)
            title = entry.get("Title","")
            dtc_code = entry.get("DTC","")
            error_class = entry.get("Error Class","")
        results.append({
            "Time": timestamp,
            "Source Address": f"0x{can_id & 0xFF:02X}",
            "Assembled": True,
            "SPN": spn,
            "FMI": fmi,
            "OC": oc,
            "DTC": dtc_code,
            "Title": title,
            "Description": desc,
            "Error Class": error_class,
            "MIL": lamp.get("MIL",False),
            "RSL": lamp.get("RSL",False),
            "AWL": lamp.get("AWL",False),
            "PL": lamp.get("PL",False),
            "FlashMIL": lamp.get("FlashMIL",False),
            "FlashRSL": lamp.get("FlashRSL",False),
            "FlashAWL": lamp.get("FlashAWL",False),
            "FlashPL": lamp.get("FlashPL",False)
        })
        offset += 4
    return results



# -------------------------
# TP/BAM assembler (unchanged)
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
            else:
                continue
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
# DTC lookup loader (merged JSON preferred, fallback to Excel)
# -------------------------
@st.cache_resource
def load_dtc_lookup(excel_path: str = EXCEL_DTC_PATH,
                    sheet: str = EXCEL_SHEET,
                    header_row: int = EXCEL_HEADER_ROW,
                    json_cache: str = JSON_LOOKUP_PATH):
    if json_cache and os.path.exists(json_cache):
        try:
            with open(json_cache, "r", encoding="utf-8") as f:
                cached = json.load(f)
            return {(int(x["SPN"]), int(x["FMI"])): x for x in cached}
        except Exception:
            pass

    try:
        df = pd.read_excel(excel_path, sheet_name=sheet, header=header_row)
    except Exception as e:
        st.warning(f"⚠️ Could not open Excel '{excel_path}': {e}")
        return {}

    col_spn_fmi = next((c for c in df.columns if str(c).strip().upper() == 'DTC SAE (SPN-FMI)'), None)
    if not col_spn_fmi:
        for c in df.columns:
            if "SPN" in str(c).upper() and "FMI" in str(c).upper():
                col_spn_fmi = c
                break
    if not col_spn_fmi:
        st.warning("⚠️ Could not find 'DTC SAE (SPN-FMI)' column in Excel. DTC lookup disabled.")
        return {}

    lookup = {}
    for _, row in df.iterrows():
        sf = row.get(col_spn_fmi)
        if pd.isna(sf):
            continue
        m = re.search(r'(\d+)\s*[-/,\s]\s*(\d+)', str(sf))
        if not m:
            continue
        spn, fmi = int(m.group(1)), int(m.group(2))
        entry = {
            "SPN": spn,
            "FMI": fmi,
            "DTC": row.get("DTC", ""),
            "Name": row.get("Name", ""),
            "Title": row.get("Title", ""),
            "Component": row.get("Component", ""),
            "Fid Name": row.get("Fid Name", ""),
            "Fid Description": row.get("Fid Description", ""),
            "System Reaction": row.get("System Reaction", ""),
            "Error Class": row.get("Error Class", "")
        }
        bits = []
        for k in ("Title", "Name", "Component", "Fid Description", "System Reaction"):
            v = entry.get(k)
            if v and str(v) != "nan":
                bits.append(str(v))
        entry["Description"] = " | ".join(bits) if bits else ""
        lookup[(spn, fmi)] = entry

    try:
        with open(json_cache, "w", encoding="utf-8") as f:
            json.dump(list(lookup.values()), f, indent=2, ensure_ascii=False)
    except Exception:
        pass

    return lookup

DTC_LOOKUP = load_dtc_lookup()

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
            live_data.append({"Timestamp": None, "CAN ID": msg.arbitration_id, "DLC": msg.dlc if hasattr(msg, "dlc") else len(data_bytes), "Data": data_bytes, "Source Address": msg.arbitration_id & 0xFF})
    if live_data:
        df_can = pd.DataFrame(live_data)
        st.success(f"✅ Captured {len(live_data)} messages from PCAN.")

# -------------------------
# Build ECU presence report & harness analysis & DTCs
# -------------------------
if not vehicle_name.strip():
    st.info("📂 Please enter a vehicle name to run diagnostics.")
else:
    report = []
    found_sources = set()
    if not df_can.empty and "Source Address" in df_can.columns:
        try:
            found_sources = {int(x) for x in df_can["Source Address"].astype(int).tolist()}
        except Exception:
            try:
                found_sources = {int(str(x), 16) if isinstance(x, str) and re.fullmatch(r"[0-9A-Fa-f]+", str(x)) else int(x) for x in df_can["Source Address"].tolist() if str(x) != "nan"}
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
        # DTC decoding section
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


