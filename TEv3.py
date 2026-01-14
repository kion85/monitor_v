
import time
import threading
import psutil
import socket
import requests
import subprocess
import re
import os
import glob
import json
import platform
from datetime import datetime
import paramiko
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from flask import Flask, render_template_string

# ===========================
# НАСТРОЙКИ
# ===========================

REFRESH_RATE = 2.0  # Чуть реже, так как данных стало больше
HISTORY_LIMIT = 60
SSH_HOST = "192.168.1.1"
SSH_PORT = 22
SSH_USER = "root"
SSH_PASSWORD = "root"
SSH_TIMEOUT = 3
WEB_PORT = 5000

# ===========================
# ГЛОБАЛЬНЫЕ БУФЕРЫ ДАННЫХ
# ===========================

# История скорости
down_history = [0] * HISTORY_LIMIT
up_history = [0] * HISTORY_LIMIT
current_download = 0.0
current_upload = 0.0

# Локальная система
public_info = {'query': 'Loading...', 'isp': 'Loading...', 'city': '...', 'countryCode': '..'}
gateway_ip = None
local_interfaces = [] # IPv4/IPv6 details
active_interface = "Unknown"

# Окружение (Wi-Fi)
scanned_networks = [] # SSID, BSSID, Channel, Signal
saved_passwords = []

# Роутер (SSH)
ssh_client = None
remote_stats = {
    "hostname": "Connecting...",
    "uptime": "-",
    "load": "-",
    "ram_total": "-",
    "ram_free": "-",
    "kernel": "-",
    "active_routes": []
}
remote_procs = []
wifi_clients = []

# ===========================
# ФУНКЦИИ: ЛОКАЛЬНАЯ СИСТЕМА
# ===========================

def get_public_data():
    try:
        response = requests.get('http://ip-api.com/json/?fields=status,query,isp,city,countryCode', timeout=3)
        data = response.json()
        if data.get('status') == 'success':
            return data
    except:
        pass
    return {'query': 'Offline', 'isp': '-', 'city': '-', 'countryCode': '-'}

def get_gateway_info():
    try:
        # Универсальный способ для Linux
        with os.popen("ip route show default") as f:
            line = f.read()
            match = re.search(r"default via (\d+.\d+.\d+.\d+)", line)
            if match:
                return match.group(1)
    except:
        pass
    return None

def get_detailed_interfaces():
    """Сбор информации об IPv4 и IPv6 на всех интерфейсах"""
    details = []
    active_iface = "None"
    
    try:
        # Определяем активный интерфейс через шлюз по умолчанию
        gateways = psutil.net_if_gateways()
        default_gw = gateways.get('default', {})
        active_iface_name = default_gw.get(socket.AF_INET, [None, ''])[1]

        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, snics in addrs.items():
            is_up = "UP" if stats[name].isup else "DOWN"
            if name == active_iface_name:
                active_iface = f"{name} ({is_up})"

            info = {"name": name, "status": is_up, "ipv4": "-", "ipv6": "-"}
            
            for snic in snics:
                if snic.family == socket.AF_INET:
                    info["ipv4"] = snic.address
                elif snic.family == socket.AF_INET6:
                    info["ipv6"] = snic.address.split('%')[0] # Убираем scope ID
            
            details.append(info)
    except Exception as e:
        details.append({"name": "Error", "status": str(e), "ipv4": "-", "ipv6": "-"})
    
    return details, active_iface

def scan_wifi_channels():
    """Сканирование Wi-Fi с определением канала (nmcli)"""
    networks = []
    try:
        # SSID, CHAN, SIGNAL, SECURITY
        cmd = ["nmcli", "-t", "-f", "SSID,CHAN,SIGNAL,SECURITY,BARS", "dev", "wifi"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode('utf-8')
        
        for line in output.splitlines():
            # nmcli экранирует двоеточия, это упрощенный парсинг
            parts = line.split(":")
            if len(parts) >= 3:
                # Из-за экранирования SSID может побить, берем с конца
                bars = parts[-1]
                sec = parts[-2]
                sig = parts[-3]
                chan = parts[-4]
                ssid = ":".join(parts[:-4])
                
                networks.append({
                    "ssid": ssid,
                    "chan": chan,
                    "signal": sig,
                    "sec": sec,
                    "bars": bars
                })
    except:
        networks.append({"ssid": "Scan Error (Need nmcli)", "chan": "-", "signal": "-", "sec": "-", "bars": ""})
    return networks

def get_saved_wifi_passwords():
    """Чтение паролей (требует ROOT)"""
    creds = []
    path = "/etc/NetworkManager/system-connections/"
    if os.geteuid() != 0:
        return [{"ssid": "NO ROOT", "psk": "Run as sudo required"}]
    
    try:
        files = glob.glob(os.path.join(path, "*.nmconnection"))
        for file in files:
            ssid = "Unknown"
            psk = "-"
            try:
                with open(file, 'r') as f:
                    content = f.read()
                    id_match = re.search(r'^id=(.*)$', content, re.MULTILINE)
                    if id_match: ssid = id_match.group(1)
                    psk_match = re.search(r'^psk=(.*)$', content, re.MULTILINE)
                    if psk_match: psk = psk_match.group(1)
                    
                    if psk != "-": # Показываем только если есть пароль
                        creds.append({"ssid": ssid, "psk": psk})
            except: continue
    except: pass
    return creds

# ===========================
# ФУНКЦИИ: SSH (РОУТЕР)
# ===========================

def ssh_connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD, timeout=SSH_TIMEOUT)
        return client
    except:
        return None

def ssh_exec(client, command):
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=SSH_TIMEOUT)
        return stdout.read().decode('utf-8').strip()
    except:
        return ""

def get_router_detailed_stats(client):
    stats = {}
    # Hostname
    stats['hostname'] = ssh_exec(client, "hostname")
    
    # Kernel
    stats['kernel'] = ssh_exec(client, "uname -r")
    
    # Uptime & Load
    up_raw = ssh_exec(client, "uptime")
    stats['uptime'] = up_raw.split("up")[1].split(",")[0].strip() if "up" in up_raw else up_raw
    stats['load'] = up_raw.split("load average:")[-1].strip() if "load average:" in up_raw else "?"

    # RAM (Memory) - Parsing /proc/meminfo or free
    mem_out = ssh_exec(client, "free -m")
    try:
        lines = mem_out.splitlines()
        # Обычно 2-я строка Mem:
        parts = lines[1].split()
        stats['ram_total'] = parts[1] + " MB"
        stats['ram_free'] = parts[3] + " MB"
    except:
        stats['ram_total'] = "?"
        stats['ram_free'] = "?"

    # Active Routes (Count)
    routes = ssh_exec(client, "ip route | wc -l")
    stats['active_routes'] = routes
    
    return stats

def get_router_processes(client):
    # Упрощенный netstat
    out = ssh_exec(client, "netstat -tulnp 2>/dev/null | grep LISTEN")
    procs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) > 6:
            procs.append(f"{parts[0]} {parts[3]} ({parts[-1]})")
    return procs

def get_router_wifi_clients(client):
    # Комбинируем ARP и iwinfo/iwconfig если возможно (упрощенно через ARP)
    clients = []
    arp = ssh_exec(client, "cat /proc/net/arp")
    for line in arp.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
            clients.append({"ip": parts[0], "mac": parts[3], "dev": parts[5]})
    return clients

# ===========================
# FLASK WEB SERVER
# ===========================

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetworkOS Manager</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #121212; color: #00FF00; padding: 20px; }
        .card { background: #1E1E1E; border: 1px solid #333; padding: 15px; margin-bottom: 20px; border-radius: 8px; }
        h2 { color: #FFF; border-bottom: 1px solid #444; padding-bottom: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #444; padding: 8px; text-align: left; }
        th { background: #2D2D2D; color: #FFF; }
        .red { color: #FF5555; }
        .blue { color: #55AAFF; }
    </style>
</head>
<body>
    <h1>networkOS // ADMIN PANEL</h1>
    
    <div class="card">
        <h2>Global Status</h2>
        <p>Public IP: <span class="blue">{{ public.query }}</span> ({{ public.isp }})</p>
        <p>Active Interface: {{ active_iface }}</p>
        <p>Download: {{ down }} Mbps | Upload: {{ up }} Mbps</p>
    </div>

    <div class="card">
        <h2>Router Health (SSH)</h2>
        <p>Hostname: {{ r_stats.hostname }} | Kernel: {{ r_stats.kernel }}</p>
        <p>Uptime: {{ r_stats.uptime }} | Load: {{ r_stats.load }}</p>
        <p>RAM: {{ r_stats.ram_free }} free / {{ r_stats.ram_total }} total</p>
    </div>

    <div class="card">
        <h2>Wi-Fi Spectrum (Scan)</h2>
        <table>
            <tr><th>SSID</th><th>Channel</th><th>Signal</th><th>Security</th></tr>
            {% for net in networks %}
            <tr>
                <td>{{ net.ssid }}</td>
                <td>{{ net.chan }}</td>
                <td>{{ net.signal }}% {{ net.bars }}</td>
                <td>{{ net.sec }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="card">
        <h2>Network Clients (Router ARP)</h2>
        <table>
            <tr><th>IP Address</th><th>MAC Address</th><th>Interface</th></tr>
            {% for client in r_clients %}
            <tr><td>{{ client.ip }}</td><td>{{ client.mac }}</td><td>{{ client.dev }}</td></tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="card">
        <h2>Interfaces IPv4/IPv6</h2>
        <table>
            <tr><th>Name</th><th>IPv4</th><th>IPv6</th></tr>
            {% for iface in local_ifaces %}
            <tr>
                <td>{{ iface.name }} ({{ iface.status }})</td>
                <td>{{ iface.ipv4 }}</td>
                <td style="font-size: 0.8em;">{{ iface.ipv6 }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE,
                                  public=public_info,
                                  active_iface=active_interface,
                                  down=f"{current_download:.2f}",
                                  up=f"{current_upload:.2f}",
                                  r_stats=remote_stats,
                                  networks=scanned_networks,
                                  r_clients=wifi_clients,
                                  local_ifaces=local_interfaces)

def run_flask():
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port=WEB_PORT, debug=False, use_reloader=False)

# ===========================
# ФОНОВЫЙ ПОТОК
# ===========================

last_io = psutil.net_io_counters()
last_time = time.time()

def data_worker():
    global current_download, current_upload, last_io, last_time
    global public_info, gateway_ip, scanned_networks, saved_passwords, local_interfaces, active_interface
    global ssh_client, remote_stats, remote_procs, wifi_clients

    # Initial Connect
    public_info = get_public_data()
    gateway_ip = get_gateway_info()
    ssh_client = ssh_connect()

    counter = 0
    while True:
        try:
            # 1. Traffic Speed
            now = time.time()
            io_now = psutil.net_io_counters()
            dt = now - last_time
            if dt <= 0: dt = 1
            
            rx = (io_now.bytes_recv - last_io.bytes_recv) * 8 / 1_000_000 / dt
            tx = (io_now.bytes_sent - last_io.bytes_sent) * 8 / 1_000_000 / dt
            
            current_download = rx
            current_upload = tx
            
            global down_history, up_history
            down_history.append(rx)
            up_history.append(tx)
            down_history = down_history[-HISTORY_LIMIT:]
            up_history = up_history[-HISTORY_LIMIT:]
            
            last_io = io_now
            last_time = now

            # 2. Heavy Tasks (every ~5-10 sec)
            if counter % 3 == 0:
                local_interfaces, active_interface = get_detailed_interfaces()
                scanned_networks = scan_wifi_channels()
            
            if counter % 5 == 0:
                saved_passwords = get_saved_wifi_passwords()
                
                if ssh_client:
                    # Проверка жив ли SSH, если нет - реконнект
                    if ssh_client.get_transport() is None or not ssh_client.get_transport().is_active():
                        ssh_client = ssh_connect()
                    
                    if ssh_client:
                        remote_stats = get_router_detailed_stats(ssh_client)
                        remote_procs = get_router_processes(ssh_client)
                        wifi_clients = get_router_wifi_clients(ssh_client)

            counter += 1
            time.sleep(REFRESH_RATE)

        except Exception as e:
            print(f"Loop Error: {e}")
            time.sleep(REFRESH_RATE)

# Start Threads
threading.Thread(target=data_worker, daemon=True).start()
threading.Thread(target=run_flask, daemon=True).start()

# ===========================
# GUI: CUSTOMTKINTER
# ===========================

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

class NetworkAdminApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NetworkOS // Ultimate Control Panel")
        self.geometry("1300x850")
        
        # Determine local IP for Web Link
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
        except: self.local_ip = "127.0.0.1"

        # --- TABS ---
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_dashboard = self.tabview.add("Dashboard")
        self.tab_details = self.tabview.add("IPv4/IPv6 & WiFi")
        self.tab_router = self.tabview.add("Router Control")
        self.tab_mgmt = self.tabview.add("Management")

        self.setup_dashboard()
        self.setup_details()
        self.setup_router()
        self.setup_mgmt()

        self.after(1000, self.update_ui)

    def setup_dashboard(self):
        frame = self.tab_dashboard
        
        # Info Header
        self.lbl_info = ctk.CTkLabel(frame, text="Initializing...", font=("Consolas", 16), justify="left")
        self.lbl_info.pack(pady=10, padx=10, anchor="w")

        # Graphs
        fig = Figure(figsize=(5, 4), dpi=100, facecolor='#2b2b2b')
        self.ax = fig.add_subplot(111)
        self.ax.set_facecolor('#2b2b2b')
        self.ax.tick_params(colors='white')
        
        self.canvas = FigureCanvasTkAgg(fig, master=frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

        self.lbl_web = ctk.CTkLabel(frame, text=f"Web Admin Panel: http://{self.local_ip}:{WEB_PORT}", text_color="#00FF00")
        self.lbl_web.pack(pady=5)

    def setup_details(self):
        # Two columns: Interfaces and Wifi
        frame = self.tab_details
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        # Left: Local Interfaces
        f_left = ctk.CTkFrame(frame)
        f_left.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        ctk.CTkLabel(f_left, text="Active Interfaces (v4/v6)", font=("Arial", 14, "bold")).pack(pady=5)
        self.txt_ifaces = ctk.CTkTextbox(f_left, font=("Consolas", 11))
        self.txt_ifaces.pack(fill="both", expand=True, padx=5, pady=5)

        # Right: Wifi Scan
        f_right = ctk.CTkFrame(frame)
        f_right.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        ctk.CTkLabel(f_right, text="Wi-Fi Channel Scanner", font=("Arial", 14, "bold")).pack(pady=5)
        
        # Treeview for Wifi
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#333", foreground="white", fieldbackground="#333", borderwidth=0)
        style.map('Treeview', background=[('selected', '#1f538d')])
        
        columns = ("SSID", "CH", "SIG", "SEC")
        self.tree_wifi = ttk.Treeview(f_right, columns=columns, show="headings", height=20)
        self.tree_wifi.heading("SSID", text="SSID")
        self.tree_wifi.heading("CH", text="CH")
        self.tree_wifi.heading("SIG", text="Signal")
        self.tree_wifi.heading("SEC", text="Security")
        
        self.tree_wifi.column("SSID", width=150)
        self.tree_wifi.column("CH", width=40)
        self.tree_wifi.column("SIG", width=80)
        self.tree_wifi.column("SEC", width=80)
        
        self.tree_wifi.pack(fill="both", expand=True, padx=5, pady=5)

    def setup_router(self):
        frame = self.tab_router
        
        self.lbl_router_stats = ctk.CTkLabel(frame, text="Waiting for SSH...", font=("Consolas", 14), justify="left")
        self.lbl_router_stats.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(frame, text="Active Network Processes (Ports)", font=("Arial", 12, "bold")).pack(anchor="w", padx=10)
        self.txt_r_procs = ctk.CTkTextbox(frame, height=150, font=("Consolas", 11))
        self.txt_r_procs.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(frame, text="Connected Clients (ARP)", font=("Arial", 12, "bold")).pack(anchor="w", padx=10)
        self.txt_r_clients = ctk.CTkTextbox(frame, height=150, font=("Consolas", 11))
        self.txt_r_clients.pack(fill="x", padx=10, pady=5)

    def setup_mgmt(self):
        frame = self.tab_mgmt
        
        ctk.CTkLabel(frame, text="Local Network Management", font=("Arial", 16, "bold")).pack(pady=10)
        
        btn_frame = ctk.CTkFrame(frame)
        btn_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkButton(btn_frame, text="Flush DNS (Linux)", command=self.flush_dns_linux, fg_color="#555").grid(row=0, column=0, padx=10, pady=10)
        ctk.CTkButton(btn_frame, text="Ping Google (Check)", command=self.ping_check).grid(row=0, column=1, padx=10, pady=10)
        ctk.CTkButton(btn_frame, text="Show Routing Table", command=self.show_routing).grid(row=0, column=2, padx=10, pady=10)
        
        ctk.CTkLabel(frame, text="Router Management (SSH)", font=("Arial", 16, "bold"), text_color="orange").pack(pady=20)
        
        ssh_frame = ctk.CTkFrame(frame, border_color="orange", border_width=1)
        ssh_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkButton(ssh_frame, text="REBOOT ROUTER", command=self.reboot_router, fg_color="#AA0000", hover_color="#FF0000").pack(pady=20)
        ctk.CTkLabel(ssh_frame, text="Warning: This will restart the remote device.").pack(pady=5)

    # --- ACTIONS ---
    def flush_dns_linux(self):
        try:
            os.system("resolvectl flush-caches") # systemd-resolved
            messagebox.showinfo("Info", "Attempted to flush DNS caches (resolvectl).")
        except:
            messagebox.showerror("Error", "Command failed.")

    def ping_check(self):
        try:
            res = subprocess.check_output(["ping", "-c", "3", "8.8.8.8"]).decode('utf-8')
            messagebox.showinfo("Ping Result", res)
        except Exception as e:
            messagebox.showerror("Ping Failed", str(e))

    def show_routing(self):
        try:
            res = subprocess.check_output(["ip", "route"]).decode('utf-8')
            messagebox.showinfo("Routing Table", res)
        except:
            pass

    def reboot_router(self):
        if messagebox.askyesno("CONFIRM", "Are you sure you want to reboot the remote router?"):
            if ssh_client:
                ssh_exec(ssh_client, "reboot")
                messagebox.showinfo("Sent", "Reboot command sent.")
            else:
                messagebox.showerror("Error", "No SSH connection.")

    # --- UPDATE UI LOOP ---
    def update_ui(self):
        # 1. Dashboard
        self.lbl_info.configure(text=(
            f"Public IP: {public_info['query']} ({public_info['isp']})\n"
            f"Gateway: {gateway_ip}\n"
            f"Active Interface: {active_interface}\n"
            f"⇩ Download: {current_download:.2f} Mbps\n"
            f"⇧ Upload:   {current_upload:.2f} Mbps"
        ))

        self.ax.clear()
        self.ax.plot(down_history, label="Download", color="#00ff00")
        self.ax.plot(up_history, label="Upload", color="#0000ff")
        self.ax.legend(facecolor='#2b2b2b', labelcolor='white')
        self.ax.set_facecolor('#2b2b2b')
        self.ax.grid(True, alpha=0.3)
        self.canvas.draw()

        # 2. Details (Interfaces)
        self.txt_ifaces.delete("0.0", "end")
        for iface in local_interfaces:
            self.txt_ifaces.insert("end", f"[{iface['name']}] Status: {iface['status']}\n")
            self.txt_ifaces.insert("end", f" IPv4: {iface['ipv4']}\n")
            self.txt_ifaces.insert("end", f" IPv6: {iface['ipv6']}\n")
            self.txt_ifaces.insert("end", "-"*30 + "\n")

        # 2. Details (Wifi Tree)
        for item in self.tree_wifi.get_children():
            self.tree_wifi.delete(item)
        for net in scanned_networks:
            self.tree_wifi.insert("", "end", values=(net['ssid'], net['chan'], f"{net['signal']}%", net['sec']))

        # 3. Router
        r_info = (
            f"HOSTNAME: {remote_stats['hostname']}\n"
            f"KERNEL:   {remote_stats['kernel']}\n"
            f"UPTIME:   {remote_stats['uptime']}\n"
            f"LOAD AVG: {remote_stats['load']}\n"
            f"MEMORY:   {remote_stats['ram_free']} Free / {remote_stats['ram_total']} Total\n"
            f"ROUTES:   {remote_stats['active_routes']}"
        )
        self.lbl_router_stats.configure(text=r_info)
        
        self.txt_r_procs.delete("0.0", "end")
        self.txt_r_procs.insert("end", "\n".join(remote_procs))
        
        self.txt_r_clients.delete("0.0", "end")
        for c in wifi_clients:
            self.txt_r_clients.insert("end", f"IP: {c['ip']} | MAC: {c['mac']} | {c['dev']}\n")

        self.after(int(REFRESH_RATE * 1000), self.update_ui)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("!!! WARNING: Run with sudo for password reading and full network control !!!")
    
    app = NetworkAdminApp()
    app.mainloop()

