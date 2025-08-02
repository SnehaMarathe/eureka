import streamlit as st
import pandas as pd
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, firestore
import io

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
# Admin Credentials
# =============================
ADMIN_CREDENTIALS = {
    "admin": "admin123"
}

def login():
    st.title("🔐 Admin Dashboard Login")
    with st.form("admin_login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            if username in ADMIN_CREDENTIALS and ADMIN_CREDENTIALS[username] == password:
                st.session_state["admin_authenticated"] = True
                st.success("✅ Login successful!")
                st.rerun()
            else:
                st.error("❌ Invalid credentials")

if "admin_authenticated" not in st.session_state:
    st.session_state["admin_authenticated"] = False

if not st.session_state["admin_authenticated"]:
    login()
    st.stop()

# =============================
# Fetch Logs
# =============================
st.title("📜 Diagnostics Logs Viewer")

@st.cache_data(ttl=60)
def fetch_logs():
    docs = db.collection("diagnostics_logs").stream()
    data = []
    for doc in docs:
        item = doc.to_dict()
        item["log_id"] = doc.id
        data.append(item)
    return data

logs = fetch_logs()

if not logs:
    st.info("No logs found yet.")
    st.stop()

# =============================
# Display Logs
# =============================
df_list = []
for log in logs:
    records_df = pd.DataFrame(log["records"])
    records_df["vehicle"] = log["vehicle"]
    records_df["timestamp"] = log["timestamp"]
    user_info = log.get("user_info", {})
    records_df["ip"] = user_info.get("ip", "")
    records_df["city"] = user_info.get("city", "")
    records_df["region"] = user_info.get("region", "")
    records_df["country"] = user_info.get("country", "")
    df_list.append(records_df)

full_df = pd.concat(df_list, ignore_index=True)
full_df["timestamp"] = pd.to_datetime(full_df["timestamp"])

# Search & Filters
st.sidebar.header("🔎 Filters")
vehicle_filter = st.sidebar.text_input("Filter by Vehicle Name")
country_filter = st.sidebar.text_input("Filter by Country")
status_filter = st.sidebar.selectbox("Status", ["All", "✅ OK", "❌ MISSING"])

filtered_df = full_df.copy()
if vehicle_filter:
    filtered_df = filtered_df[filtered_df["vehicle"].str.contains(vehicle_filter, case=False)]
if country_filter:
    filtered_df = filtered_df[filtered_df["country"].str.contains(country_filter, case=False)]
if status_filter != "All":
    filtered_df = filtered_df[filtered_df["Status"] == status_filter]

st.dataframe(filtered_df, use_container_width=True)

# =============================
# Download Logs
# =============================
csv = filtered_df.to_csv(index=False).encode("utf-8")
st.download_button("⬇️ Download Logs as CSV", csv, "diagnostics_logs.csv", "text/csv")

# =============================
# PDF Export (Optional)
# =============================
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors

def generate_pdf(df):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 50, "Diagnostics Logs Report")
    c.setFont("Helvetica", 10)
    y = height - 80
    headers = ["Vehicle", "ECU", "Status", "Timestamp", "City", "Country"]
    col_widths = [80, 80, 50, 100, 80, 80]
    # Header
    for i, header in enumerate(headers):
        c.setFillColor(colors.grey)
        c.rect(50 + sum(col_widths[:i]), y, col_widths[i], 20, fill=1)
        c.setFillColor(colors.white)
        c.drawString(55 + sum(col_widths[:i]), y + 5, header)
    y -= 20
    # Rows
    for _, row in df.iterrows():
        if y < 50:
            c.showPage()
            y = height - 50
        row_data = [
            row["vehicle"], row["ECU"], row["Status"],
            row["timestamp"].strftime("%Y-%m-%d %H:%M"),
            row.get("city", ""), row.get("country", "")
        ]
        for i, value in enumerate(row_data):
            c.setFillColor(colors.black)
            c.drawString(55 + sum(col_widths[:i]), y, str(value))
        y -= 18
    c.save()
    buffer.seek(0)
    return buffer

pdf = generate_pdf(filtered_df)
st.download_button("⬇️ Download Logs as PDF", pdf, "diagnostics_logs.pdf")

st.success("✅ Admin dashboard ready. You can filter and download logs.")

