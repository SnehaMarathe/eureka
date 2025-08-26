# app.py  — Unified CAN Diagnostic (ECU presence + DM1 decode from Excel DTCs)
import streamlit as st
import re, io, os, tempfile, time, json
import pandas as pd
from datetime import datetime

# ---------------------------------
# Config
# ---------------------------------
st.set_page_config(page_title="EurekaCheck – CAN + DTC", layout="wide")

# Paths (adjust if needed)
EXCEL_DTC_PATH = "F300G810_FnR_T222BECDG8100033206_Trimmed_Signed.xlsx"
EXCEL_SHEET = "Sheet1"
EXCEL_HEADER_ROW = 3  # zero-based header row where names appear
JSON_LOOKUP_PATH = "dtc_lookup_from_excel.json"  # optional prebuilt JSON cache

# ---------------------------------
# Parser: .trc (IDs + payload)
# ---------------------------------
def parse_trc_file(file_path: str) -> pd.DataFrame:
    """
    Parse a Vector/PCAN .trc log into:
      [Timestamp, CAN ID, DLC, Data (bytes), Source Address]
    """
    records = []
    try:
        with open(file_path, "r", errors="ignore") as f:
            for line in f:
                # Example: "1)  0.000 Rx  18FECA17   8  00 FF FF 00 00 00 00 00"
                m = re.match(
                    r"\s*\d+\)\s+([\d.]+)\s+Rx\s+([0-9A-Fa-f]{6,8})\s+(\d+)\s+((?:[0-9A-Fa-f]{2}\s+)+)",
                    line
                )
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
                else:
                    # Alternate pattern some tools use ("ID = ...")
                    m2 = re.search(r"ID\s*=\s*([0-9A-Fa-f]{6,8}).*?Len\s*=\s*(\d+).*?((?:[0-9A-Fa-f]{2}\s+)+)", line)
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

# ---------------------------------
# DM1 parsing helpers (SAE J1939)
# ---------------------------------
DM1_PGN = 0xFECA  # 65226

def parse_dm1_frame(data_bytes: bytes):
    """
    DM1 payload: 8 lamp bytes, followed by zero or more 4-byte DTCs:
      DTC: 19-bit SPN, 5-bit FMI, 8-bit OC
    Returns list of dicts: {SPN, FMI, OC}
    """
    out = []
    if not data_bytes or len(data_bytes) < 8:
        return out
    i = 8
    while i + 3 < len(data_bytes):
        b1, b2, b3, b4 = data_bytes[i:i+4]
        spn = b1 | ((b2 & 0xE0) << 3) | (b3 << 11)  # 19-bit SPN
        fmi = b2 & 0x1F                                  # 5-bit
        oc  = b4                                         # occurrence
        # Zero DTC terminator sometimes appears; ignore clearly empty entries
        if spn == 0 and fmi == 0 and oc == 0:
            break
        out.append({"SPN": spn, "FMI": fmi, "OC": oc})
        i += 4
    return out

# ---------------------------------
# DTC Lookup loading (Excel → dict) with JSON cache
# ---------------------------------
@st.cache_resource
def load_dtc_lookup(excel_path: str = EXCEL_DTC_PATH,
                    sheet: str = EXCEL_SHEET,
                    header_row: int = EXCEL_HEADER_ROW,
                    json_cache: str = JSON_LOOKUP_PATH):
    """
    Build {(SPN,FMI): {DTC, Title, Description, ...}} from Excel, with JSON cache if available.
    """
    # Prefer cache if present
    if json_cache and os.path.exists(json_cache):
        try:
            with open(json_cache, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {(int(x["SPN"]), int(x["FMI"])): x for x in data}
        except Exception as e:
            st.warning(f"⚠️ Failed to read JSON cache '{json_cache}': {e}. Rebuilding from Excel…")

    # Build from Excel
    try:
        df = pd.read_excel(excel_path, sheet_name=sheet, header=header_row)
    except Exception as e:
        st.warning(f"⚠️ Could not open Excel '{excel_path}': {e}")
        return {}

    # find the SPN-FMI column name robustly
    col_spn_fmi = next((c for c in df.columns if str(c).strip().upper() == 'DTC SAE (SPN-FMI)'), None)
    if not col_spn_fmi:
        st.warning("⚠️ Could not find 'DTC SAE (SPN-FMI)' column in Excel.")
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
        # concise long-text
        bits = [entry.get("Title") or entry.get("Name") or entry.get("Component")]
        if entry.get("Fid Description"): bits.append(str(entry["Fid Description"]))
        if entry.get("System Reaction"): bits.append("Reaction: " + str(entry["System Reaction"]))
        entry["Description"] = " | ".join([str(b) for b in bits if b and str(b) != "nan"])
        lookup[(spn, fmi)] = entry

    # write cache for next run (optional)
    try:
        with open(json_cache, "w", encoding="utf-8") as f:
            json.dump(list(lookup.values()), f, indent=2, ensure_ascii=False)
    except Exception as e:
        st.info(f"ℹ️ Could not persist JSON cache: {e}")

    return lookup

DTC_LOOKUP = load_dtc_lookup()

# ---------------------------------
# Decode DTCs from parsed df
# ---------------------------------
def decode_dtcs_from_df(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    if df is None or df.empty:
        return pd.DataFrame()
    for _, r in df.iterrows():
        can_id = r.get("CAN ID")
        data   = r.get("Data")
        if not isinstance(data, (bytes, bytearray)) or can_id is None:
            continue
        pgn = (can_id >> 8) & 0xFFFF
        if pgn != DM1_PGN:
            continue  # not DM1
        for d in parse_dm1_frame(data):
            key = (d["SPN"], d["FMI"])
            entry = DTC_LOOKUP.get(key, {})
            rows.append({
                "Time": r.get("Timestamp"),
                "SA": f"0x{(can_id & 0xFF):02X}",
                "SPN": d["SPN"],
                "FMI": d["FMI"],
                "OC": d["OC"],
                "DTC": entry.get("DTC", ""),
                "Title": entry.get("Title", entry.get("Name", "")),
                "Description": entry.get("Description", "Unknown (not in lookup)"),
                "Error Class": entry.get("Error Class", "")
            })
    out = pd.DataFrame(rows)
    if not out.empty:
        # Deduplicate identical DTCs by SA/SPN/FMI keeping max OC
        out = (out.sort_values(["SA","SPN","FMI","OC"], ascending=[True,True,True,False])
                  .drop_duplicates(subset=["SA","SPN","FMI"], keep="first")
                  .reset_index(drop=True))
    return out

# ---------------------------------
# ECU presence (simple)
# ---------------------------------
ECU_MAP = {
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

def build_ecu_report(df: pd.DataFrame) -> pd.DataFrame:
    present = set(df["Source Address"].astype(int)) if (df is not None and not df.empty) else set()
    rows = []
    for sa, name in ECU_MAP.items():
        rows.append({"ECU": name, "Source Address": f"0x{sa:02X}", "Status": "✅ OK" if sa in present else "❌ MISSING"})
    return pd.DataFrame(rows)

# ---------------------------------
# UI
# ---------------------------------
st.markdown("## 🔧 EurekaCheck — Unified CAN Diagnostic (ECU presence + DM1 DTCs)")

with st.sidebar:
    st.markdown("### DTC Lookup Source")
    st.write(f"Excel: `{EXCEL_DTC_PATH}` (sheet `{EXCEL_SHEET}`, header row {EXCEL_HEADER_ROW})")
    if os.path.exists(JSON_LOOKUP_PATH):
        st.success("Using JSON cache for DTC lookup.")
    else:
        st.info("No JSON cache yet; built from Excel at runtime.")

veh = st.text_input("Vehicle Name / ID", max_chars=40)

uploaded = st.file_uploader("Upload CAN Trace (.trc)", type=["trc"])
df_can = pd.DataFrame()

if uploaded:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".trc") as tmp:
        tmp.write(uploaded.getvalue())
        tmp_path = tmp.name
    df_can = parse_trc_file(tmp_path)

    if df_can.empty:
        st.error("❌ Could not parse any CAN frames from the .trc.")
    else:
        st.success(f"✅ Parsed {len(df_can)} CAN frames.")
        # ECU presence
        st.subheader("📋 ECU Presence")
        df_ecu = build_ecu_report(df_can)
        st.dataframe(df_ecu, use_container_width=True)

        # DM1 DTCs
        st.subheader("🚨 Active Diagnostic Trouble Codes (DM1)")
        df_dtc = decode_dtcs_from_df(df_can)
        if df_dtc.empty:
            st.info("No active DM1 DTCs detected in the trace.")
        else:
            st.dataframe(df_dtc, use_container_width=True)
            st.download_button("⬇️ Download DTC Report (CSV)", df_dtc.to_csv(index=False), "dtc_report.csv", "text/csv")
else:
    st.info("📂 Upload a .trc file to begin.")
