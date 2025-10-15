#!/usr/bin/env python3
"""
Timed rolling capture with Scapy (config-driven, single log file)

- Loads capture settings from config.json
- Rotates capture files every interval_sec seconds
- Uses fixed filenames: pcap_1.pcap ... pcap_N.pcap
- Overwrites instead of deleting
- Writes .meta.json metadata alongside each .pcap
- Logs all actions to logs/capture.log (truncated on startup)
"""

from scapy.all import sniff, wrpcap
from datetime import datetime
from pathlib import Path
import json
import signal
import sys
import threading

# === LOAD CONFIG ===
CONFIG_PATH = Path("config.json")
if not CONFIG_PATH.exists():
    raise FileNotFoundError("Missing config.json. Please create it first.")

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    cfg = json.load(f)

capture_cfg = cfg["capture"]

output_dir = Path(capture_cfg["output_dir"])
output_dir.mkdir(parents=True, exist_ok=True)

interval_sec = capture_cfg["interval_sec"]
max_files = capture_cfg["max_files"]
bpf_filter = capture_cfg["bpf_filter"]
iface = capture_cfg["iface"]

# === LOGGING ===
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "capture.log"

# Truncate log file at startup
with open(LOG_FILE, "w", encoding="utf-8") as f:
    f.write("=== New capture session started ===\n")

def log(msg: str):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} {msg}\n")

# === STATE ===
current_index = 0
buffer = []
capture_start_time = datetime.now()
stop_event = threading.Event()


# === HELPERS ===
def make_pcap_name(idx):
    return output_dir / f"pcap_{idx+1}.pcap"

def make_meta_name(idx):
    return output_dir / f"pcap_{idx+1}.meta.json"

def write_pcap_and_meta(packets, idx, start_ts, end_ts):
    if not packets:
        return
    pcap_path = make_pcap_name(idx)
    meta_path = make_meta_name(idx)
    try:
        wrpcap(str(pcap_path), packets)
        meta = {
            "file": pcap_path.name,
            "start": start_ts.isoformat(),
            "end": end_ts.isoformat(),
            "packet_count": len(packets)
        }
        meta_path.write_text(json.dumps(meta, indent=2))
        log(f"Saved {pcap_path.name} with {len(packets)} packets")
    except Exception as e:
        log(f"ERROR writing {pcap_path}: {e}")

def rotate_file():
    global buffer, current_index, capture_start_time
    while not stop_event.wait(interval_sec):
        end_time = datetime.now()
        write_pcap_and_meta(buffer, current_index, capture_start_time, end_time)
        buffer = []
        capture_start_time = datetime.now()
        current_index = (current_index + 1) % max_files
        log(f"Rotated to file index {current_index}")

def packet_handler(pkt):
    buffer.append(pkt)

def stop_and_flush(signum=None, frame=None):
    log("Stop signal received, flushing remaining packets.")
    stop_event.set()
    end_time = datetime.now()
    write_pcap_and_meta(buffer, current_index, capture_start_time, end_time)
    log("Capture stopped and all data saved.")
    sys.exit(0)


# === MAIN ===
def main():
    log("=== Starting timed rolling capture ===")
    log(f"Interval: {interval_sec}s, max_files: {max_files}")
    log(f"Filter: {bpf_filter}, iface: {iface}")
    log(f"Output directory: {output_dir.resolve()}")
    log(f"Log file: {LOG_FILE.resolve()}")

    signal.signal(signal.SIGINT, stop_and_flush)
    signal.signal(signal.SIGTERM, stop_and_flush)

    rotator = threading.Thread(target=rotate_file, daemon=True)
    rotator.start()

    sniff(iface=iface, filter=bpf_filter, prn=packet_handler, store=False)


if __name__ == "__main__":
    main()
