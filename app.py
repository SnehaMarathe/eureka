# app.py — EurekaCheck Unified Diagnostic Tool
import streamlit as st
from streamlit_javascript import st_javascript
import re, io, os, threading, tempfile, time, json
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from collections import defaultdict
import requests

# --- Firebase
import firebase_admin
from firebase_admin import credentials, firestore

# --- Optional live CAN
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
# 🌍 Browser-based Location
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
# 🔑 Firebase Init
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
# Firebase Helpers
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

# =============================
# Header
# =============================
col1, col2, col3 = st.columns([1, 6, 1])
with col1: st.image("BEM-Logo.png", width=150)
with col2:
    st.markdown("""
    <div style='text-align: center;'>
        <h2 style='margin-bottom: 0;'>🔧 EurekaCheck - CAN Bus Diagnostic Tool</h2>
        <p style='margin-top: 0;'>Connect PCAN or Upload a <code>.trc</code> file to analyze ECU health & DTCs.</p>
    </div>""", unsafe_allow_html=True)
with col3:
    st.markdown(f"<p style='text-align: right; color: gray;'>👥 Visitors: {st.session_state.get('visitor_count', 0)}</p>", unsafe_allow_html=True)
st.markdown("<hr style='margin-top: 0.5rem;'>", unsafe_allow_html=True)

# =============================
# ECU + Drawing Maps (unchanged)
# =============================
ecu_connector_map = {...}   # [keep your full map here]
drawing_map = {...}

# =============================
# --- New Section: .trc Parser + DM1 Decoding
# =============================
DM1_PGN = 0xFECA
EXCEL_DTC_PATH = "F300G810_FnR_T222BECDG8100033206_Trimmed_Signed.xlsx"
EXCEL_SHEET = "Sheet1"
EXCEL_HEADER_ROW = 3
JSON_LOOKUP_PATH = "dtc_lookup_from_excel.json"

def parse_trc_file(file_path: str) -> pd.DataFrame:
    records = []
    try:
        with open(file_path, "r", errors="ignore") as f:
            for line in f:
                m = re.match(r"\s*\d+\)\s+([\d.]+)\s+Rx\s+([0-9A-Fa-f]{6,8})\s+(\d+)\s+((?:[0-9A-Fa-f]{2}\s+)+)", line)
                if m:
                    ts = float(m.group(1))
                    can_id = int(m.group(2), 16)
                    dlc = int(m.group(3))
                    data_bytes = bytes(int(b,16) for b in m.group(4).strip().split()[:dlc])
                    sa = can_id & 0xFF
                    records.append({"Timestamp": ts, "CAN ID": can_id, "DLC": dlc, "Data": data_bytes, "Source Address": sa})
    except Exception as e:
        st.error(f"❌ Failed to parse .trc: {e}")
    return pd.DataFrame(records)

def parse_dm1_frame(data_bytes: bytes):
    out = []
    if not data_bytes or len(data_bytes) < 8: return out
    i = 8
    while i+3 < len(data_bytes):
        b1,b2,b3,b4 = data_bytes[i:i+4]
        spn = b1 | ((b2 & 0xE0)<<3) | (b3<<11)
        fmi = b2 & 0x1F
        oc = b4
        if spn==0 and fmi==0 and oc==0: break
        out.append({"SPN": spn, "FMI": fmi, "OC": oc})
        i += 4
    return out

@st.cache_resource
def load_dtc_lookup():
    if os.path.exists(JSON_LOOKUP_PATH):
        try:
            with open(JSON_LOOKUP_PATH,"r",encoding="utf-8") as f:
                data=json.load(f)
            return {(int(x["SPN"]),int(x["FMI"])):x for x in data}
        except: pass
    df = pd.read_excel(EXCEL_DTC_PATH, sheet_name=EXCEL_SHEET, header=EXCEL_HEADER_ROW)
    lookup={}
    col_spn_fmi = next((c for c in df.columns if str(c).strip().upper()=="DTC SAE (SPN-FMI)"), None)
    for _,row in df.iterrows():
        sf=row.get(col_spn_fmi)
        if pd.isna(sf): continue
        m=re.search(r'(\d+)\s*[-/,\s]\s*(\d+)', str(sf))
        if not m: continue
        spn,fmi=int(m.group(1)),int(m.group(2))
        entry={ "SPN":spn, "FMI":fmi,
            "DTC":row.get("DTC",""),
            "Title":row.get("Title",""),
            "Description":row.get("Fid Description",""),
            "Error Class":row.get("Error Class","") }
        lookup[(spn,fmi)] = entry
    try:
        with open(JSON_LOOKUP_PATH,"w",encoding="utf-8") as f:
            json.dump(list(lookup.values()),f,indent=2,ensure_ascii=False)
    except: pass
    return lookup

DTC_LOOKUP = load_dtc_lookup()

def decode_dtcs_from_df(df: pd.DataFrame):
    rows=[]
    for _,r in df.iterrows():
        can_id=r["CAN ID"]; data=r["Data"]
        pgn=(can_id>>8)&0xFFFF
        if pgn!=DM1_PGN: continue
        for d in parse_dm1_frame(data):
            key=(d["SPN"],d["FMI"])
            entry=DTC_LOOKUP.get(key,{})
            rows.append({
                "Time":r["Timestamp"], "SA":f"0x{(can_id&0xFF):02X}",
                "SPN":d["SPN"], "FMI":d["FMI"], "OC":d["OC"],
                "DTC":entry.get("DTC",""), "Title":entry.get("Title",""),
                "Description":entry.get("Description","Unknown"), "Error Class":entry.get("Error Class","")
            })
    return pd.DataFrame(rows)

# =============================
# Main Workflow (Vehicle input, ECU report, DTC report)
# =============================
st.markdown("### 🚛 Vehicle Info")
vehicle_name = st.text_input("Enter Vehicle Name or ID", max_chars=30)

uploaded_file = st.file_uploader("📂 Upload CAN Trace (.trc)", type=["trc"])
df_can = pd.DataFrame()
if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".trc") as tmp:
        tmp.write(uploaded_file.getvalue())
        df_can=parse_trc_file(tmp.name)
    if df_can.empty:
        st.error("No frames parsed.")
    else:
        st.success(f"Parsed {len(df_can)} CAN frames.")
        # ECU presence report (reuse your existing report code) ...
        # --- [KEEP YOUR ECU PRESENCE + PDF REPORT CODE HERE] ---
        # DTC decoding
        st.subheader("🚨 Active DTCs from DM1")
        df_dtc=decode_dtcs_from_df(df_can)
        if df_dtc.empty: st.info("No active DM1 DTCs found.")
        else:
            st.dataframe(df_dtc,use_container_width=True)
            st.download_button("⬇️ Download DTC CSV", df_dtc.to_csv(index=False),"dtc_report.csv","text/csv")

# --- Footer ---
st.markdown("---")
st.markdown("<div style='text-align:center;font-size:0.85em;color:gray;'>© 2025 Blue Energy Motors.</div>", unsafe_allow_html=True)
