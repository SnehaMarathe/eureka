import requests
import time
import json
import csv
import sys
from datetime import datetime, timedelta, timezone
import os

# === SAFE PATH SETUP FOR NO-ADMIN EXECUTION ===
if getattr(sys, 'frozen', False):
    # Running as a bundled executable (PyInstaller)
    BASE_DIR = os.path.join(os.getenv("LOCALAPPDATA"), "BlueEnergyAlerts")
else:
    # Running as a regular .py script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

os.makedirs(BASE_DIR, exist_ok=True)

OUTPUT_HTML = os.path.join(BASE_DIR, "alert_report.html")
HISTORY_CSV = os.path.join(BASE_DIR, "alert_history.csv")
SERIAL_TRACK_FILE = os.path.join(BASE_DIR, "serial_tracker.json")

print("🔽 Output folder:", BASE_DIR)

# === CONFIGURATION ===
USER_TOKEN = "QyXSX360esEHoVmge2VTwstx6oIE6xdXe7aKwWUXfkz18wlhe01byby4rfRnJFne"
ACCOUNT_ID = "962759605811675136"
HEADERS = {
    "intangles-user-token": USER_TOKEN,
    "intangles-session-type": "web",
    "Accept": "application/json"
}
OBD_TEMPLATE = "https://apis.intangles.com/vehicle/{}/getLastFewObdData"
ALERT_TEMPLATE = "https://apis.intangles.com/alertlog/logsV2/{start_ts}/{end_ts}"
REFRESH_INTERVAL = 10

obd_cache = {}
serial_map = {}

def normalize_key(timestamp, vehicle_tag, code):
    return f"{int(timestamp)}_{vehicle_tag.strip().upper()}_{code.strip().upper()}"

def migrate_serial_map(old_map):
    new_map = {}
    for k, v in old_map.items():
        try:
            parts = k.split("_", 2)
            if len(parts) < 3:
                new_map[k] = v
                continue
            ts, tag, code = parts
            new_key = normalize_key(ts, tag, code)
            new_map[new_key] = v
        except:
            new_map[k] = v
    return new_map

if os.path.exists(SERIAL_TRACK_FILE):
    with open(SERIAL_TRACK_FILE, "r") as f:
        raw_map = json.load(f)
    serial_map = migrate_serial_map(raw_map)
    with open(SERIAL_TRACK_FILE, "w") as f:
        json.dump(serial_map, f, indent=2)

def save_serial_map():
    with open(SERIAL_TRACK_FILE, "w") as f:
        json.dump(serial_map, f, indent=2)

HTML_HEAD = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Blue Energy Motors Alert Report</title>
    <meta http-equiv="refresh" content="10">
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; font-size: 12px; padding: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ccc; padding: 6px; text-align: left; }}
        th {{ background: #f0f0f0; cursor: pointer; }}
        tr:hover {{ background-color: #f9f9f9; }}
        .high {{ background-color: #ffe6e6; }}
        .critical {{ background-color: #ffcccc; }}
    </style>
    <script>
        document.addEventListener("DOMContentLoaded", () => {{
            const getCellValue = (tr, idx) => tr.children[idx].innerText || tr.children[idx].textContent;
            const comparer = (idx, asc) => (a, b) => ((v1, v2) =>
                v1 !== "" && v2 !== "" && !isNaN(v1) && !isNaN(v2) ? v1 - v2 : v1.toString().localeCompare(v2)
            )(getCellValue(asc ? a : b, idx), getCellValue(asc ? b : a, idx));

            document.querySelectorAll("th").forEach(th => th.addEventListener("click", (() => {{
                const table = th.closest("table");
                Array.from(table.querySelectorAll("tr:nth-child(n+2)"))
                     .sort(comparer(Array.from(th.parentNode.children).indexOf(th), this.asc = !this.asc))
                     .forEach(tr => table.appendChild(tr));
            }})));

            document.querySelectorAll(".seen-toggle").forEach(btn => {{
                const id = btn.dataset.id;
                if (localStorage.getItem("seen_" + id) === "true") {{
                    btn.textContent = "✅";
                }}
                btn.addEventListener("click", () => {{
                    const current = localStorage.getItem("seen_" + id) === "true";
                    localStorage.setItem("seen_" + id, !current);
                    btn.textContent = !current ? "✅" : "❌";
                }});
            }});
        }});
    </script>
</head>
<body>
    <h1>🔔 Blue Energy Motors Alert Report</h1>
    <p>Last Updated: {update_time}</p>
    <table>
        <thead>
            <tr>{headers}</tr>
        </thead>
        <tbody>
"""
HTML_TAIL = """
        </tbody>
    </table>
</body>
</html>
"""

def format_ist(ts_ms):
    dt_utc = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    dt_ist = dt_utc + timedelta(hours=5, minutes=30)
    return dt_ist.strftime("%Y %b %d %H:%M:%S")

def get_alert_logs():
    end_ts = int(time.time() * 1000)
    start_ts = end_ts - 2 * 60 * 60 * 1000
    params = {
        "pnum": "1",
        "psize": "20",
        "show_group": "true",
        "types": "dtc",
        "sort": "timestamp desc",
        "no_total": "true",
        "show_resolved_status": "true",
        "show_driver_name": "true",
        "accounts_with_access": ACCOUNT_ID,
        "lang": "en"
    }
    url = ALERT_TEMPLATE.format(start_ts=start_ts, end_ts=end_ts)
    response = requests.get(url, headers=HEADERS, params=params)
    return response.json().get("logs", [])

def get_obd_data(vehicle_id):
    url = OBD_TEMPLATE.format(vehicle_id)
    params = {"packet_count": 3, "acc_id": ACCOUNT_ID, "lang": "en"}
    summary = obd_cache.get(vehicle_id, {
        "Battery Voltage (V)": "N/A",
        "Engine Speed (RPM)": "N/A",
        "Coolant Temp (°C)": "N/A",
        "Wheel Speed (kmph)": "N/A"
    })

    try:
        r = requests.get(url, headers=HEADERS, params=params)
        packets = r.json().get("results") or []
        for pkt in packets:
            battery = pkt.get("battery")
            if battery and "voltage" in battery:
                try:
                    summary["Battery Voltage (V)"] = round(float(battery.get("voltage")), 1)
                except:
                    summary["Battery Voltage (V)"] = battery.get("voltage")
            for p in pkt.get("pids", []):
                for pid, d in p.items():
                    value = d.get("value")
                    if isinstance(value, list):
                        value = value[0] if value else None
                    if value is not None:
                        try:
                            value = round(float(value), 1)
                        except:
                            pass
                        if pid == "84": summary["Wheel Speed (kmph)"] = value
                        elif pid == "110": summary["Coolant Temp (°C)"] = value
                        elif pid == "158": summary["Battery Voltage (V)"] = value
                        elif pid == "190": summary["Engine Speed (RPM)"] = value
        obd_cache[vehicle_id] = summary
    except:
        pass
    return summary

def format_alerts(logs):
    logs.sort(key=lambda log: log.get("timestamp", 0))
    output = []
    current_serials = set(serial_map.values())
    max_serial = max(current_serials) if current_serials else 0
    new_serial = max_serial + 1

    for log in logs:
        vehicle_id = log.get("vehicle_id", "")
        timestamp = log.get("timestamp", 0)
        log_id = log.get("id", "")
        code = log.get("dtcs", {}).get("code", "")
        vehicle_tag = log.get("vehicle_tag", log.get("vehicle_plate", ""))
        unique_key = f"{timestamp}_{vehicle_tag}_{code}"

        if unique_key in serial_map:
            serial_no = serial_map[unique_key]
        else:
            serial_no = new_serial
            serial_map[unique_key] = serial_no
            new_serial += 1
            save_serial_map()

        dtc_number = ""
        if log_id and "-dtc-" in log_id:
            try:
                dtc_number = log_id.split("-dtc-")[1].split("-")
                dtc_number = "-".join(dtc_number[:2])
            except:
                pass

        dtc_info = log.get("dtc_info", [{}])[0] if log.get("dtc_info") else {}
        severity_level = log.get("dtcs", {}).get("severity_level", 1)
        severity = {1: "LOW", 2: "HIGH", 3: "CRITICAL"}.get(severity_level, "LOW")
        active_seconds = int(time.time()) - int(timestamp / 1000)
        if active_seconds < 60:
            active_time_str = f"{active_seconds}s"
        elif active_seconds < 3600:
            minutes, seconds = divmod(active_seconds, 60)
            active_time_str = f"{minutes}m {seconds}s"
        else:
            hours, remainder = divmod(active_seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            active_time_str = f"{hours}h {minutes}m"

        row = {
            "S.No.": serial_no,
            "Log ID": log_id,
            "DTC Number": dtc_number,
            "Timestamp": format_ist(timestamp),
            "Active Time": active_time_str,
            "Location": log.get("address", ""),
            "Vehicle Tag": vehicle_tag,
            "Severity": severity,
            "Description": dtc_info.get("description", "")
        }

        obd = get_obd_data(vehicle_id)
        row.update(obd)
        output.append(row)

    output.sort(key=lambda row: row.get("S.No.", 0), reverse=True)
    return output

def generate_html(data):
    if not data:
        with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
            f.write("<html><body><h2>No alerts found</h2></body></html>")
        return

    columns = list(data[0].keys()) + ["Seen"]
    headers_html = "".join(f"<th>{col}</th>" for col in columns)
    rows_html = ""

    for row in data:
        severity = row.get("Severity")
        cls = "critical" if severity == "CRITICAL" else "high" if severity == "HIGH" else ""
        rows_html += f'<tr class="{cls}">'
        for col in columns:
            if col == "Seen":
                log_id = row.get("Log ID", "")
                rows_html += f'<td><button class="seen-toggle" data-id="{log_id}">❌</button></td>'
            else:
                rows_html += f"<td>{row.get(col, '')}</td>"
        rows_html += "</tr>"

    html = HTML_HEAD.format(update_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), headers=headers_html)
    html += rows_html + HTML_TAIL

    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)

    write_mode = "a" if os.path.exists(HISTORY_CSV) else "w"
    with open(HISTORY_CSV, write_mode, newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        if write_mode == "w":
            writer.writeheader()
        writer.writerows(data)

    print(f"✅ HTML report updated: {OUTPUT_HTML}")

# === MAIN LOOP ===
print("🔄 Starting alert monitoring (CTRL+C to stop)...")
while True:
    try:
        alerts = get_alert_logs()
        processed = format_alerts(alerts)
        generate_html(processed)
    except Exception as e:
        print("❌ Error:", e)
    time.sleep(REFRESH_INTERVAL)
