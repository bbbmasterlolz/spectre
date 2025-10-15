#!/usr/bin/env python3
"""
Spectre IDS Analyzer (config-driven, single log file)

- Loads settings from config.json
- Watches for latest .meta.json in pcaps/
- Sends corresponding .pcap to API for prediction
- Saves JSON responses and JSONL alerts (for Wazuh)
- Persists last processed capture in spectre.json
- Logs all activity to logs/analyzer.log (truncated on startup)
"""

import requests
import json
import time
from pathlib import Path
from datetime import datetime

# === LOAD CONFIG ===
CONFIG_PATH = Path("config.json")
if not CONFIG_PATH.exists():
    raise FileNotFoundError("Missing config.json. Please create it first.")

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    cfg = json.load(f)

analysis_cfg = cfg["analysis"]

API_URL = analysis_cfg["api_url"]
PCAPS_DIR = Path(analysis_cfg["pcaps_dir"])
LOG_DIR = Path(analysis_cfg["log_dir"])
CHECK_INTERVAL = analysis_cfg["check_interval"]
ABNORMAL_CLASSES = set(analysis_cfg["abnormal_classes"])

# === PATHS ===
RESP_LOG_DIR = LOG_DIR / "responses"
ALERT_JSON_PATH = LOG_DIR / "alerts.json"
SPECTRE_PATH = LOG_DIR / "spectre.json"
LOG_FILE = LOG_DIR / "analyzer.log"

RESP_LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Truncate log file at startup
with open(LOG_FILE, "w", encoding="utf-8") as f:
    f.write("=== New analyzer session started ===\n")

def log(msg: str):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} {msg}\n")


# === PERSISTENCE ===
def load_last_uploaded():
    if not SPECTRE_PATH.exists():
        return None
    try:
        data = json.loads(SPECTRE_PATH.read_text())
        return data.get("last_uploaded_time")
    except Exception:
        return None


def save_last_uploaded(timestamp: str):
    with open(SPECTRE_PATH, "w", encoding="utf-8") as f:
        json.dump(
            {"last_uploaded_time": timestamp, "updated_at": datetime.now().isoformat(timespec="seconds")},
            f,
            indent=2,
            ensure_ascii=False,
        )


# === HELPERS ===
def get_latest_meta():
    meta_files = list(PCAPS_DIR.glob("*.meta.json"))
    if not meta_files:
        return None
    return max(meta_files, key=lambda f: f.stat().st_mtime)


def read_capture_start(meta_path: Path):
    try:
        data = json.loads(meta_path.read_text())
        return data.get("start")
    except Exception as e:
        log(f"Failed to read {meta_path.name}: {e}")
        return None


def send_pcap(meta_path: Path):
    pcap_path = PCAPS_DIR / (meta_path.stem.replace(".meta", "") + ".pcap")
    if not pcap_path.exists():
        log(f"No matching .pcap for {meta_path.name}")
        return None

    log(f"Sending {pcap_path.name} to API")
    try:
        with open(pcap_path, "rb") as f:
            res = requests.post(API_URL, files={"file": f}, timeout=60)
        if res.ok:
            log(f"Received response for {pcap_path.name}")
            return res.json()
        else:
            log(f"API error {res.status_code}: {res.text}")
    except Exception as e:
        log(f"Request failed for {pcap_path.name}: {e}")
    return None


def save_response_log(response: dict, capture_start: str):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = RESP_LOG_DIR / f"response_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(
            {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "capture_start": capture_start,
                "response": response,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    log(f"Saved response to {filename.name}")


def append_alerts(response: dict):
    preview_rows = response.get("preview_rows", [])
    if not preview_rows:
        log("No preview_rows found in response")
        return

    new_alerts = []
    for row in preview_rows:
        label = row.get("predicted_label")
        if label in ABNORMAL_CLASSES:
            alert = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "source": "spectre-ids",
                "alert_type": f"Spectre-{label}",
                "src_ip": row.get("source_ip", "-"),
                "dst_ip": row.get("destination_ip", "-"),
                "confidence": row.get("confidence", 0)
            }
            new_alerts.append(alert)

    if new_alerts:
        with open(ALERT_JSON_PATH, "a", encoding="utf-8") as f:
            for alert in new_alerts:
                f.write(json.dumps(alert) + "\n")
        log(f"Recorded {len(new_alerts)} new alerts")
    else:
        log("No abnormal connections detected")


# === MAIN LOOP ===
def main():
    last_uploaded_time = load_last_uploaded()
    if last_uploaded_time:
        log(f"Loaded last processed capture: {last_uploaded_time}")
    else:
        log("No previous state found, starting fresh")

    log(f"Monitoring folder: {PCAPS_DIR.resolve()}")
    log(f"Check interval: {CHECK_INTERVAL}s")

    while True:
        latest_meta = get_latest_meta()
        if latest_meta:
            capture_start = read_capture_start(latest_meta)
            if not capture_start:
                log(f"Skipping {latest_meta.name} (no 'start' field)")
            elif capture_start != last_uploaded_time:
                log(f"New capture detected: {latest_meta.name}")
                response = send_pcap(latest_meta)
                if response:
                    save_response_log(response, capture_start)
                    append_alerts(response)
                    last_uploaded_time = capture_start
                    save_last_uploaded(capture_start)
            else:
                log("No new captures since last check")
        else:
            log("No .meta.json files found in directory")
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
