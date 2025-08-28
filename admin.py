# admin.py — EurekaCheck Admin Console
# - Uses same Firebase creds as app.py
# - Read-only dashboards: Visitors, Trace Archives, Presence Logs, DTC Uploads
# - Safe to run on Streamlit Cloud

import streamlit as st
from datetime import datetime, timedelta
import pandas as pd
import base64

# =========================
# Firebase bootstrap
# =========================
import firebase_admin
from firebase_admin import credentials, firestore

try:
    from firebase_admin import storage as fb_storage
    _STORAGE_OK = True
except Exception:
    _STORAGE_OK = False

@st.cache_resource
def init_firebase_admin():
    try:
        firebase_config = st.secrets["FIREBASE"]
    except Exception:
        st.error("❌ Firebase secrets missing in Streamlit secrets.")
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
        if bucket_name and _STORAGE_OK:
            firebase_admin.initialize_app(
                credentials.Certificate(cred_dict),
                {"storageBucket": bucket_name}
            )
        else:
            firebase_admin.initialize_app(credentials.Certificate(cred_dict))

    db = firestore.client()
    bucket = None
    if bucket_name and _STORAGE_OK:
        try:
            bucket = fb_storage.bucket()
        except Exception:
            bucket = None
    return db, bucket

db, bucket = init_firebase_admin()

# =========================
# Helpers (no layout coupling)
# =========================
def docs_to_df(docs):
    rows = []
    for d in docs:
        rec = d.to_dict() or {}
        rec["_id"] = d.id
        rows.append(rec)
    return pd.DataFrame(rows)

def collection_count(col_name: str, days: int | None = None) -> int:
    try:
        ref = db.collection(col_name)
        if days:
            since = datetime.utcnow() - timedelta(days=days)
            return len(list(ref.where("timestamp", ">=", since.isoformat()).stream()))
        return len(list(ref.stream()))
    except Exception:
        return 0

def get_visitor_count() -> int:
    try:
        doc = db.collection("visitors").document("counter").get()
        return int(doc.to_dict().get("count", 0)) if doc.exists else 0
    except Exception:
        return 0

def reset_visitor_count() -> bool:
    try:
        db.collection("visitors").document("counter").set({"count": 0})
        return True
    except Exception:
        return False

def query_trace_archives(time_cutoff_iso: str | None, limit: int = 500) -> pd.DataFrame:
    try:
        q = db.collection("trace_archives")
        if time_cutoff_iso:
            q = q.where("timestamp", ">=", time_cutoff_iso)
        q = q.order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit)
        return docs_to_df(list(q.stream()))
    except Exception as e:
        st.warning(f"trace_archives query failed: {e}")
        return pd.DataFrame()

def signed_url(storage_path: str, minutes: int = 20) -> str | None:
    if not (bucket and _STORAGE_OK and storage_path):
        return None
    try:
        blob = bucket.blob(storage_path)
        return blob.generate_signed_url(expiration=timedelta(minutes=minutes), method="GET")
    except Exception:
        return None

def decode_preview_b64(preview_b64: str) -> bytes | None:
    if not preview_b64:
        return None
    try:
        return base64.b64decode(preview_b64.encode("ascii"))
    except Exception:
        return None

def query_presence_logs(limit: int = 300) -> pd.DataFrame:
    try:
        q = db.collection("diagnostics_logs").order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit)
        return docs_to_df(list(q.stream()))
    except Exception as e:
        st.warning(f"diagnostics_logs query failed: {e}")
        return pd.DataFrame()

def get_presence_log_records(doc_id: str) -> pd.DataFrame:
    try:
        d = db.collection("diagnostics_logs").document(doc_id).get()
        if not d.exists:
            return pd.DataFrame()
        rec = d.to_dict() or {}
        return pd.DataFrame(rec.get("records", []))
    except Exception:
        return pd.DataFrame()

def query_dtc_uploads(limit: int = 300) -> pd.DataFrame:
    try:
        q = db.collection("diagnostics_dtcs").order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit)
        return docs_to_df(list(q.stream()))
    except Exception as e:
        st.warning(f"diagnostics_dtcs query failed: {e}")
        return pd.DataFrame()

def get_dtc_payloads(doc_id: str):
    try:
        d = db.collection("diagnostics_dtcs").document(doc_id).get()
        if not d.exists:
            return pd.DataFrame(), pd.DataFrame()
        rec = d.to_dict() or {}
        return pd.DataFrame(rec.get("raw_dtcs", [])), pd.DataFrame(rec.get("cleaned_dtcs", []))
    except Exception:
        return pd.DataFrame(), pd.DataFrame()

def delete_doc(collection: str, doc_id: str) -> bool:
    try:
        db.collection(collection).document(doc_id).delete()
        return True
    except Exception:
        return False

# =========================
# Admin UI (minimal, safe defaults)
# =========================
st.set_page_config(page_title="EurekaCheck — Admin", layout="wide")
st.title("🛠️ EurekaCheck — Admin")

if db is None:
    st.stop()

# --- Metrics row
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("👥 Visitors (all-time)", get_visitor_count())
with m2:
    st.metric("📄 Presence Logs", collection_count("diagnostics_logs"))
with m3:
    st.metric("🚨 DTC Uploads", collection_count("diagnostics_dtcs"))
with m4:
    st.metric("🗂️ Trace Archives", collection_count("trace_archives"))

st.divider()

# --- Visitors controls
with st.expander("Visitors"):
    c1, c2 = st.columns([1,3])
    with c1:
        if st.button("Reset visitor counter"):
            if reset_visitor_count():
                st.success("Visitor counter reset.")
            else:
                st.error("Failed to reset.")
    with c2:
        st.write("Simple global counter stored in Firestore at `visitors/counter`.")

st.divider()

# --- Trace archives
st.subheader("🗂️ Trace Archives")
a1, a2, a3 = st.columns([1,1,2])
with a1:
    timeframe = st.selectbox("Timeframe", ["All", "Last 24h", "Last 7d", "Last 30d"], index=2)
with a2:
    limit_val = st.number_input("Limit", 50, 2000, 500, step=50)
with a3:
    st.caption("If Storage is configured, you’ll get a signed URL. Else, a base64 preview (first 64KB) is available.")

cutoff = None
if timeframe == "Last 24h":
    cutoff = (datetime.utcnow() - timedelta(days=1)).isoformat()
elif timeframe == "Last 7d":
    cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
elif timeframe == "Last 30d":
    cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()

df_arch = query_trace_archives(cutoff, limit=limit_val)

if df_arch.empty:
    st.info("No archives found for the selected filter.")
else:
    show_cols = ["timestamp", "vehicle", "file", "size_bytes", "storage_path", "_id"]
    for c in show_cols:
        if c not in df_arch.columns:
            df_arch[c] = ""
    st.dataframe(df_arch[show_cols], use_container_width=True, hide_index=True)

    st.markdown("**Download / Preview**")
    sel = st.selectbox(
        "Select archive row (by _id)",
        options=[""] + df_arch["_id"].tolist(),
        index=0
    )
    if sel:
        row = df_arch[df_arch["_id"] == sel].iloc[0].to_dict()
        url = signed_url(row.get("storage_path"))
        if url:
            st.write(f"[🔗 Signed download link (20 min)]({url})")
        else:
            # Try preview
            preview_b64 = row.get("preview_b64", "")
            chunk = decode_preview_b64(preview_b64)
            if chunk:
                fname = f"preview_{row.get('file','trace.trc')}"
                st.download_button("⬇️ Download preview (first 64KB)", chunk, file_name=fname, mime="text/plain")
            else:
                st.warning("No Storage link and no preview available for this item.")

st.divider()

# --- Presence logs
st.subheader("📄 Presence Logs (diagnostics_logs)")
p1, p2 = st.columns([1,1])
with p1:
    limit_logs = st.number_input("Limit logs", 50, 1000, 300, step=50)
with p2:
    st.caption("Each log contains a `records` array of ECU presence rows.")

df_logs = query_presence_logs(limit=limit_logs)
if df_logs.empty:
    st.info("No presence logs found.")
else:
    keep = ["timestamp", "vehicle", "user_info", "_id"]
    for c in keep:
        if c not in df_logs.columns:
            df_logs[c] = ""
    st.dataframe(df_logs[keep], use_container_width=True, hide_index=True)

    sel_log = st.selectbox(
        "Expand log (by _id)",
        options=[""] + df_logs["_id"].tolist(),
        index=0
    )
    if sel_log:
        df_rec = get_presence_log_records(sel_log)
        if df_rec.empty:
            st.info("No records in this log.")
        else:
            st.dataframe(df_rec, use_container_width=True, hide_index=True)

st.divider()

# --- DTC uploads
st.subheader("🚨 DTC Uploads (diagnostics_dtcs)")
d1, d2 = st.columns([1,1])
with d1:
    limit_dtcs = st.number_input("Limit DTC uploads", 50, 1000, 300, step=50)
with d2:
    st.caption("Inspect raw + cleaned DM1 payloads uploaded by clients.")

df_dtcs = query_dtc_uploads(limit=limit_dtcs)
if df_dtcs.empty:
    st.info("No DTC uploads found.")
else:
    keep = ["timestamp", "vehicle", "user_info", "_id"]
    for c in keep:
        if c not in df_dtcs.columns:
            df_dtcs[c] = ""
    st.dataframe(df_dtcs[keep], use_container_width=True, hide_index=True)

    sel_dtc = st.selectbox(
        "Expand DTC upload (by _id)",
        options=[""] + df_dtcs["_id"].tolist(),
        index=0
    )
    if sel_dtc:
        raw_df, cleaned_df = get_dtc_payloads(sel_dtc)
        st.markdown("**Raw DM1 rows**")
        if raw_df.empty:
            st.write("—")
        else:
            st.dataframe(raw_df, use_container_width=True, hide_index=True)
        st.markdown("**Cleaned DM1 table**")
        if cleaned_df.empty:
            st.write("—")
        else:
            st.dataframe(cleaned_df, use_container_width=True, hide_index=True)

st.divider()

# --- Danger zone (optional)
with st.expander("🧨 Danger zone (delete single doc)"):
    colz = st.columns(3)
    with colz[0]:
        coll = st.text_input("Collection", value="trace_archives")
    with colz[1]:
        docid = st.text_input("Doc _id to delete", value="")
    with colz[2]:
        if st.button("Delete"):
            if not coll or not docid:
                st.error("Collection and _id required.")
            else:
                if delete_doc(coll, docid):
                    st.success("Deleted.")
                else:
                    st.error("Delete failed.")
