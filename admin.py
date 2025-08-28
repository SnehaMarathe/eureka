# admin.py — EurekaCheck Admin Dashboard
# - Mirrors Firebase init from app.py (Storage optional)
# - Admin-only login
# - Metrics: visitors, counts of logs/archives
# - Browse & download: trace_archives (Storage or Firestore preview)
# - Inspect: diagnostics_logs (presence) and diagnostics_dtcs (raw+cleaned)
# - Reset visitor counter

import streamlit as st
import pandas as pd
import json
from datetime import datetime, timedelta
import threading
import base64
import re

# Firebase
import firebase_admin
from firebase_admin import credentials, firestore
try:
    from firebase_admin import storage as fb_storage
    STORAGE_AVAILABLE = True
except Exception:
    STORAGE_AVAILABLE = False

# -------------------------
# Streamlit config
# -------------------------
st.set_page_config(page_title="EurekaCheck — Admin", layout="wide")

# -------------------------
# Authentication (admin only)
# -------------------------
USER_CREDENTIALS = {"admin": "admin123"}  # Only admin here

def login():
    st.markdown("## 🔐 Admin Login")
    with st.form("login_form"):
        username = st.text_input("Username", key="username_input_admin")
        password = st.text_input("Password", type="password", key="password_input_admin")
        submitted = st.form_submit_button("🔓 Login")
        if submitted:
            if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
                st.session_state["authenticated_admin"] = True
                st.session_state["username_admin"] = username
                st.success(f"Welcome, {username}!")
                st.rerun()
            else:
                st.error("❌ Invalid username or password.")

if "authenticated_admin" not in st.session_state:
    st.session_state["authenticated_admin"] = False
if not st.session_state["authenticated_admin"]:
    login()
    st.stop()

# -------------------------
# Firebase init (same style as app.py)
# -------------------------
@st.cache_resource
def init_firebase():
    try:
        firebase_config = st.secrets["FIREBASE"]
    except Exception:
        st.error("❌ Firebase secrets missing. Add FIREBASE block to Streamlit secrets.")
        return None, None

    cred_dict = {
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
    }

    bucket_name = firebase_config.get("storage_bucket")
    if not firebase_admin._apps:
        if bucket_name and STORAGE_AVAILABLE:
            firebase_admin.initialize_app(
                credentials.Certificate(cred_dict),
                {"storageBucket": bucket_name}
            )
        else:
            firebase_admin.initialize_app(credentials.Certificate(cred_dict))
    db = firestore.client()
    bucket = None
    if bucket_name and STORAGE_AVAILABLE:
        try:
            bucket = fb_storage.bucket()
        except Exception:
            bucket = None
    return db, bucket

db, bucket = init_firebase()
if db is None:
    st.stop()

# -------------------------
# Helpers
# -------------------------
def _count_collection(col_name: str, days: int | None = None) -> int:
    try:
        col_ref = db.collection(col_name)
        if days:
            since = datetime.utcnow() - timedelta(days=days)
            return len([d for d in col_ref.where("timestamp", ">=", since.isoformat()).stream()])
        return len([d for d in col_ref.stream()])
    except Exception:
        return 0

def _docs_to_df(docs):
    rows = []
    for d in docs:
        rec = d.to_dict() or {}
        rec["_id"] = d.id
        rows.append(rec)
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)

def _get_visitor_count():
    try:
        doc = db.collection("visitors").document("counter").get()
        if doc.exists:
            return int(doc.to_dict().get("count", 0))
    except Exception:
        pass
    return 0

def _reset_visitor_count():
    try:
        db.collection("visitors").document("counter").set({"count": 0})
        return True
    except Exception:
        return False

def _signed_url_if_possible(storage_path: str, minutes: int = 20) -> str | None:
    if not (bucket and STORAGE_AVAILABLE and storage_path):
        return None
    try:
        blob = bucket.blob(storage_path)
        # This requires service account creds with signing ability
        return blob.generate_signed_url(expiration=timedelta(minutes=minutes), method="GET")
    except Exception:
        return None

# -------------------------
# Header
# -------------------------
st.markdown(
    """
    <div style='text-align: center;'>
        <h2 style='margin-bottom: 0;'>🛠️ EurekaCheck — Admin Dashboard</h2>
        <p style='margin-top: 0;'>Monitor archives, logs, DTCs, and visitor stats</p>
    </div>
    """,
    unsafe_allow_html=True
)
st.markdown("<hr style='margin-top: 0.5rem;'>", unsafe_allow_html=True)

# -------------------------
# Top KPIs
# -------------------------
colA, colB, colC, colD = st.columns(4)
with colA:
    st.metric("👥 Visitors", _get_visitor_count())
with colB:
    st.metric("🧾 Presence Logs", _count_collection("diagnostics_logs"))
with colC:
    st.metric("⚠️ DTC Uploads", _count_collection("diagnostics_dtcs"))
with colD:
    st.metric("📦 Trace Archives", _count_collection("trace_archives"))

with st.expander("Visitor Counter Controls"):
    if st.button("🔁 Reset counter to 0"):
        ok = _reset_visitor_count()
        if ok:
            st.success("Visitor counter reset.")
            st.rerun()
        else:
            st.error("Failed to reset counter.")

# -------------------------
# Trace Archives
# -------------------------
st.markdown("## 📦 Trace Archives")
st.caption("Shows either Cloud Storage path or Firestore preview (when Storage unavailable).")

time_filter = st.selectbox(
    "Filter by timeframe",
    ["All", "Last 24h", "Last 7d", "Last 30d"],
    index=2
)
limit = st.slider("Max rows to fetch", min_value=50, max_value=2000, value=500, step=50)

def _time_cutoff():
    now = datetime.utcnow()
    if time_filter == "Last 24h":
        return now - timedelta(days=1)
    if time_filter == "Last 7d":
        return now - timedelta(days=7)
    if time_filter == "Last 30d":
        return now - timedelta(days=30)
    return None

cutoff = _time_cutoff()
try:
    q = db.collection("trace_archives")
    if cutoff:
        q = q.where("timestamp", ">=", cutoff.isoformat())
    q = q.order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit)
    docs = list(q.stream())
    df_arch = _docs_to_df(docs)
except Exception as e:
    st.warning(f"Failed to query trace_archives: {e}")
    df_arch = pd.DataFrame()

if df_arch.empty:
    st.info("No archived traces found for the selected filter.")
else:
    # Derive handy columns
    if "timestamp" in df_arch.columns:
        df_arch["timestamp"] = pd.to_datetime(df_arch["timestamp"], errors="coerce")
    if "size_bytes" in df_arch.columns:
        df_arch["size_kb"] = (pd.to_numeric(df_arch["size_bytes"], errors="coerce") / 1024).round(1)
    cols_show = [c for c in [
        "timestamp", "vehicle", "file", "storage_path", "size_kb", "size_bytes", "preview_b64_len", "_id"
    ] if c in df_arch.columns]
    st.dataframe(df_arch[cols_show], use_container_width=True)

    # Download helper for a selected row
    st.markdown("#### Download selection")
    selected_id = st.selectbox("Pick an archive by document ID", options=df_arch["_id"].tolist())
    if selected_id:
        row = df_arch[df_arch["_id"] == selected_id].iloc[0].to_dict()
        storage_path = row.get("storage_path")
        preview_b64 = row.get("preview_b64")
        filename = row.get("file") or "trace.trc"

        # Try signed URL if we have Storage path
        url = _signed_url_if_possible(storage_path)
        if url:
            st.success("Signed URL generated (valid for a short time):")
            st.write(url)
        elif preview_b64:
            try:
                raw = base64.b64decode(preview_b64.encode("ascii"))
                st.download_button("⬇️ Download preview chunk (.trc)", raw, filename=f"preview_{filename}")
            except Exception as e:
                st.warning(f"Unable to present preview: {e}")
        else:
            st.info("No Storage URL and no preview chunk available.")

# -------------------------
# Presence Logs (diagnostics_logs)
# -------------------------
st.markdown("## 📋 ECU Presence Logs")
limit_logs = st.slider("Max presence logs to fetch", min_value=50, max_value=2000, value=300, step=50)
try:
    ql = db.collection("diagnostics_logs").order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit_logs)
    docs_logs = list(ql.stream())
    df_logs = _docs_to_df(docs_logs)
except Exception as e:
    st.warning(f"Failed to query diagnostics_logs: {e}")
    df_logs = pd.DataFrame()

if df_logs.empty:
    st.info("No presence logs found.")
else:
    if "timestamp" in df_logs.columns:
        df_logs["timestamp"] = pd.to_datetime(df_logs["timestamp"], errors="coerce")
    cols_basic = [c for c in ["timestamp", "vehicle", "user_info", "_id"] if c in df_logs.columns]
    st.dataframe(df_logs[cols_basic], use_container_width=True)

    with st.expander("View a log's ECU table"):
        sel = st.selectbox("Pick presence log by ID", options=df_logs["_id"].tolist())
        if sel:
            rec = next(d for d in docs_logs if d.id == sel).to_dict()
            rows = rec.get("records", [])
            df_rec = pd.DataFrame(rows)
            if not df_rec.empty:
                st.dataframe(df_rec, use_container_width=True)
                st.download_button("⬇️ Download this ECU table (CSV)", df_rec.to_csv(index=False), file_name=f"{sel}_presence.csv")
            else:
                st.write("— No records in this log —")

# -------------------------
# DTC Uploads (diagnostics_dtcs)
# -------------------------
st.markdown("## ⚠️ DTC Uploads")
limit_dtcs = st.slider("Max DTC uploads to fetch", min_value=50, max_value=2000, value=300, step=50, key="dtc_slider")
try:
    qd = db.collection("diagnostics_dtcs").order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit_dtcs)
    docs_dtcs = list(qd.stream())
    df_dtcs = _docs_to_df(docs_dtcs)
except Exception as e:
    st.warning(f"Failed to query diagnostics_dtcs: {e}")
    df_dtcs = pd.DataFrame()

if df_dtcs.empty:
    st.info("No DTC uploads found.")
else:
    if "timestamp" in df_dtcs.columns:
        df_dtcs["timestamp"] = pd.to_datetime(df_dtcs["timestamp"], errors="coerce")
    cols_basic = [c for c in ["timestamp", "vehicle", "user_info", "_id"] if c in df_dtcs.columns]
    st.dataframe(df_dtcs[cols_basic], use_container_width=True)

    with st.expander("View a DTC upload"):
        sel_d = st.selectbox("Pick DTC upload by ID", options=df_dtcs["_id"].tolist())
        if sel_d:
            rec = next(d for d in docs_dtcs if d.id == sel_d).to_dict()
            raw_dtcs = pd.DataFrame(rec.get("raw_dtcs", []))
            cleaned_dtcs = pd.DataFrame(rec.get("cleaned_dtcs", []))
            st.markdown("**Raw DM1 rows**")
            if raw_dtcs.empty:
                st.write("—")
            else:
                st.dataframe(raw_dtcs, use_container_width=True)
                st.download_button("⬇️ Download raw DM1 (CSV)", raw_dtcs.to_csv(index=False), file_name=f"{sel_d}_raw_dm1.csv")
            st.markdown("**Cleaned report**")
            if cleaned_dtcs.empty:
                st.write("—")
            else:
                st.dataframe(cleaned_dtcs, use_container_width=True)
                st.download_button("⬇️ Download cleaned DTCs (CSV)", cleaned_dtcs.to_csv(index=False), file_name=f"{sel_d}_cleaned_dtcs.csv")

# -------------------------
# Danger Zone (optional deletes)
# -------------------------
st.markdown("---")
with st.expander("🧨 Danger Zone — Delete a document (advanced)"):
    st.caption("Use with care. Deleting is permanent.")
    target_col = st.selectbox("Collection", ["trace_archives", "diagnostics_logs", "diagnostics_dtcs", "visitors"])
    target_id = st.text_input("Document ID (exact)")
    if st.button("Delete document"):
        if not target_id.strip():
            st.error("Provide a document ID.")
        else:
            try:
                db.collection(target_col).document(target_id).delete()
                st.success(f"Deleted {target_col}/{target_id}")
            except Exception as e:
                st.error(f"Failed to delete: {e}")

st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; font-size: 0.85em; color: gray;'>
        © 2025 Blue Energy Motors. Admin dashboard for EurekaCheck.
    </div>
    """,
    unsafe_allow_html=True
)
