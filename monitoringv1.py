
import time
import threading
import psutil
import socket
import requests
import subprocess
import os
import platform
import re
import paramiko

import tkinter as tk
from tkinter import ttk
import customtkinter as ctk

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from flask import Flask, render_template_string, request, redirect, url_for, session
from functools import wraps

# ===========================
# CONFIG
# ===========================
REFRESH_RATE = 1.5

SSH_HOST = "192.168.1.1"
SSH_PORT = 22
SSH_USER = "root"
SSH_PASSWORD = "root"

WEB_PORT = 5000
WEB_USER = "root"
WEB_PASS = "root"

SPLASH_MAX_SECONDS = 3.0  # splash screen max time

# ===========================
# GLOBAL DATA
# ===========================
data_lock = threading.Lock()

data = {
    "inet_status": "Checking...",
    "inet_ip": "...",
    "public_info": {"query": "...", "isp": "..."},
    "local_ifaces": [],
    "router_stats": {
        "hostname": "...",
        "kernel": "...",
        "uptime": "...",
        "load": "...",
        "ram_total": "...",
        "ram_free": "...",
        "model": "...",
        "cpu": "...",
        "os_ver": "...",
        "ssh_status": "Checking..."  # OK / not log in
    },
    "wifi_clients": [],          # from router ARP, if SSH OK
    "clients_details": [],       # enriched (mtu, os guess)
    "scanned_networks": [],
    "down_speed": 0.0,
    "up_speed": 0.0
}

ssh_client = None
last_io = psutil.net_io_counters()
last_time = time.time()

# ===========================
# SSH HELPERS
# ===========================
def ssh_connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            SSH_HOST,
            port=SSH_PORT,
            username=SSH_USER,
            password=SSH_PASSWORD,
            timeout=3,
            banner_timeout=3,
            auth_timeout=3,
        )
        return client
    except Exception:
        return None

def ssh_exec(client, cmd):
    if not client:
        return ""
    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=4)
        out = stdout.read().decode("utf-8", errors="ignore").strip()
        return out
    except Exception:
        return ""

def get_router_deep_info(client):
    info = {}
    if not client:
        info["ssh_status"] = "not log in"
        return info

    info["ssh_status"] = "OK"
    info["hostname"] = ssh_exec(client, "hostname")
    info["kernel"] = ssh_exec(client, "uname -r")
    info["os_ver"] = ssh_exec(client, "grep -E \"DISTRIB_DESCRIPTION\" /etc/openwrt_release 2>/dev/null | cut -d= -f2 | tr -d \"'\"")
    if not info["os_ver"]:
        info["os_ver"] = ssh_exec(client, "cat /etc/os-release 2>/dev/null | grep -E '^PRETTY_NAME=' | cut -d= -f2 | tr -d '\"'")
    info["model"] = ssh_exec(client, "cat /sys/firmware/devicetree/base/model 2>/dev/null || cat /proc/cpuinfo | grep -E 'Hardware|Model' | head -1")
    cpu_raw = ssh_exec(client, "cat /proc/cpuinfo | grep -m1 -E 'model name|Processor|cpu model|Hardware'")
    info["cpu"] = cpu_raw.strip() if cpu_raw else "Unknown CPU"

    mem = ssh_exec(client, "free -m | awk 'NR==2{print $2\" \"$4}'")
    if mem:
        p = mem.split()
        if len(p) >= 2:
            info["ram_total"] = p[0]
            info["ram_free"] = p[1]

    up = ssh_exec(client, "uptime")
    if up:
        info["uptime"] = up.split("up", 1)[1].split(",", 1)[0].strip() if "up" in up else up
        info["load"] = up.split("load average:")[-1].strip() if "load average:" in up else "..."

    return info

def router_get_arp_clients(client):
    """Return list: [{ip, mac, dev}] from /proc/net/arp"""
    res = []
    if not client:
        return res
    arp = ssh_exec(client, "cat /proc/net/arp 2>/dev/null")
    for l in arp.splitlines()[1:]:
        p = l.split()
        if len(p) >= 6:
            res.append({"ip": p[0], "mac": p[3].lower(), "dev": p[5]})
    return res

# ===========================
# LOCAL HELPERS
# ===========================
def get_public_data():
    try:
        r = requests.get(
            "http://ip-api.com/json/?fields=status,query,isp,city,countryCode",
            timeout=3,
        )
        return r.json() if r.status_code == 200 else {"query": "Offline", "isp": "-"}
    except Exception:
        return {"query": "Offline", "isp": "-"}

def get_interfaces():
    res = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, snics in addrs.items():
            st = stats.get(name)
            item = {"name": name, "ipv4": "-", "ipv6": "-", "status": "UP" if (st and st.isup) else "DOWN"}
            for s in snics:
                if s.family == socket.AF_INET:
                    item["ipv4"] = s.address
                elif s.family == socket.AF_INET6:
                    item["ipv6"] = s.address.split("%")[0]
            res.append(item)
    except Exception:
        pass
    return res

def check_inet():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        ip = socket.gethostbyname(socket.gethostname())
        return "Online", ip
    except Exception:
        return "Offline", "No Inet"

def scan_wifi():
    nets = []
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,CHAN,SIGNAL,SECURITY", "dev", "wifi"],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore")
        for line in out.splitlines():
            p = line.split(":")
            if len(p) >= 4:
                nets.append({"ssid": ":".join(p[:-3]), "chan": p[-3], "sig": p[-2], "sec": p[-1]})
    except Exception:
        pass
    return nets

def local_mtu_for_ip(ip):
    """Best-effort MTU detection by routing decision on THIS machine."""
    try:
        if platform.system().lower() == "windows":
            return None
        out = subprocess.check_output(["ip", "-o", "route", "get", ip], stderr=subprocess.DEVNULL).decode()
        m = re.search(r"\bmtu\s+(\d+)\b", out)
        return int(m.group(1)) if m else None
    except Exception:
        return None

def guess_os_from_ttl(ip):
    """
    Very rough OS guess using ICMP TTL from ping.
    Returns: 'Windows'/'Linux/Unix'/'Network device'/'n/a'
    """
    try:
        if platform.system().lower() == "windows":
            out = subprocess.check_output(["ping", "-n", "1", "-w", "800", ip], stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
            m = re.search(r"TTL[=\s](\d+)", out, re.IGNORECASE)
        else:
            out = subprocess.check_output(["ping", "-c", "1", "-W", "1", ip], stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
            m = re.search(r"ttl[=\s](\d+)", out, re.IGNORECASE)

        if not m:
            return "n/a"
        ttl = int(m.group(1))
        if ttl >= 120:
            return "Windows"
        if 60 <= ttl < 120:
            return "Linux/Unix"
        if ttl < 60:
            return "Network device"
        return "n/a"
    except Exception:
        return "n/a"

def enrich_clients(clients):
    """Add mtu and os guess for each client"""
    out = []
    for c in clients:
        ip = c.get("ip", "")
        mtu = local_mtu_for_ip(ip)
        os_guess = guess_os_from_ttl(ip) if ip else "n/a"
        out.append({
            "ip": ip,
            "mac": c.get("mac", ""),
            "dev": c.get("dev", ""),
            "mtu": str(mtu) if mtu else "n/a",
            "os": os_guess if os_guess else "n/a"
        })
    return out

# ===========================
# WEB SERVER (LOCKED)
# ===========================
app_flask = Flask(__name__)
app_flask.secret_key = "networkos_secret_key"

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app_flask.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == WEB_USER and request.form.get("password") == WEB_PASS:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
    return render_template_string("""
<html>
  <body style="background:#222;color:#fff;font-family:sans-serif;text-align:center;padding:50px;">
    <h2>NetworkOS Locked</h2>
    <form method="post">
      User: <input name="username" value="root"><br><br>
      Pass: <input type="password" name="password"><br><br>
      <input type="submit" value="Unlock">
    </form>
  </body>
</html>
""")

@app_flask.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

@app_flask.route("/reboot", methods=["POST"])
@login_required
def reboot_router():
    global ssh_client
    ok = False
    with data_lock:
        ssh_status = data["router_stats"].get("ssh_status", "not log in")
    if ssh_status == "OK" and ssh_client:
        ssh_exec(ssh_client, "reboot")
        ok = True
    return redirect(url_for("dashboard", reboot=("1" if ok else "0")))

@app_flask.route("/")
@login_required
def dashboard():
    with data_lock:
        d = dict(data)
        clients = list(data.get("clients_details", []))

    return render_template_string("""
<html>
<head>
  <style>
    body{background:#111;color:#0f0;font-family:monospace;padding:20px}
    h1{border-bottom:1px solid #333;padding-bottom:8px}
    .card{background:#222;padding:15px;margin:10px 0;border:1px solid #333}
    table{width:100%;border-collapse:collapse}
    td,th{border:1px solid #444;padding:6px}
    .bad{color:#ff5c5c}
    .ok{color:#6dff6d}
    .btn{background:#333;color:#fff;border:1px solid #555;padding:8px 12px;cursor:pointer}
    .btnred{background:#6b1111;border:1px solid #aa3333}
    .top-right{float:right}
  </style>
</head>
<body>
  <h1>
    NetworkOS // CONTROL CENTER
    <a class="top-right" href="/logout" style="color:#ff5c5c;text-decoration:none">[LOGOUT]</a>
  </h1>

  <div class="card">
    <h3>Global Status</h3>
    Public IP: {{ d.public_info.query }} ({{ d.public_info.isp }})<br>
    Internet: {{ d.inet_status }} (Local IP: {{ d.inet_ip }})<br>
    Speed: {{ "%.2f"|format(d.down_speed) }} / {{ "%.2f"|format(d.up_speed) }} Mbps
  </div>

  <div class="card">
    <h3>Router Hardware</h3>
    SSH: {% if d.router_stats.ssh_status == "OK" %}<span class="ok">OK</span>{% else %}<span class="bad">not log in</span>{% endif %}<br>
    Model: {{ d.router_stats.model }}<br>
    CPU: {{ d.router_stats.cpu }}<br>
    OS: {{ d.router_stats.os_ver }}<br>
    Kernel: {{ d.router_stats.kernel }}<br>
    Uptime: {{ d.router_stats.uptime }}<br>
    Load: {{ d.router_stats.load }}<br>
    RAM: {{ d.router_stats.ram_free }}/{{ d.router_stats.ram_total }} MB
    <div style="margin-top:12px;">
      <form method="post" action="/reboot" style="display:inline;">
        <button class="btn btnred" type="submit">Reboot Router</button>
      </form>
    </div>
  </div>

  <div class="card">
    <h3>Connected Clients (ARP) + MTU + OS Guess</h3>
    <table>
      <tr><th>IP</th><th>MAC</th><th>Interface</th><th>MTU</th><th>OS</th></tr>
      {% for c in clients %}
        <tr>
          <td>{{ c.ip }}</td>
          <td>{{ c.mac }}</td>
          <td>{{ c.dev }}</td>
          <td>{{ c.mtu }}</td>
          <td>{{ c.os }}</td>
        </tr>
      {% endfor %}
      {% if clients|length == 0 %}
        <tr><td colspan="5" style="color:#aaa;">No data (SSH required for ARP).</td></tr>
      {% endif %}
    </table>
  </div>
</body>
</html>
""", d=d, clients=clients)

# ===========================
# GUI APP
# ===========================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class NetworkOS(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NetworkOS Monitor")
        self.geometry("1200x800")

        self.splash = ctk.CTkToplevel(self)
        self.splash.geometry("420x240")
        self.splash.overrideredirect(True)
        self.splash.lift()

        ctk.CTkLabel(self.splash, text="NetworkOS", font=("Arial", 30, "bold")).pack(pady=(55, 8))
        self.pb = ctk.CTkProgressBar(self.splash, width=320, mode="indeterminate")
        self.pb.pack(pady=10)
        self.pb.start()
        self.splash_lbl = ctk.CTkLabel(self.splash, text="Initializing System...")
        self.splash_lbl.pack(pady=8)

        self.withdraw()

        self._ui_ready = False
        self._start_ts = time.time()

        threading.Thread(target=self.worker, daemon=True).start()
        threading.Thread(target=self.run_web, daemon=True).start()

        self.after(100, self.update_ui)

    def setup_ui(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True)

        t1 = self.tabs.add("Dashboard")
        t2 = self.tabs.add("Network Map")
        t3 = self.tabs.add("Router Control")

        self.lbl_inet = ctk.CTkLabel(t1, text="Loading...", font=("Arial", 16))
        self.lbl_inet.pack(pady=10)

        hw_frame = ctk.CTkFrame(t1)
        hw_frame.pack(fill="x", padx=20, pady=5)

        self.lbl_router_model = ctk.CTkLabel(hw_frame, text="Model: ...")
        self.lbl_router_model.pack(side="left", padx=10)

        self.lbl_router_cpu = ctk.CTkLabel(hw_frame, text="CPU: ...")
        self.lbl_router_cpu.pack(side="left", padx=10)

        self.lbl_router_os = ctk.CTkLabel(hw_frame, text="OS: ...")
        self.lbl_router_os.pack(side="left", padx=10)

        self.lbl_ssh = ctk.CTkLabel(hw_frame, text="SSH: Checking...")
        self.lbl_ssh.pack(side="right", padx=10)

        fig = Figure(figsize=(5, 3), dpi=100, facecolor="#2b2b2b")
        self.ax = fig.add_subplot(111)
        self.ax.set_facecolor("#1e1e1e")
        self.ax.tick_params(colors="white")
        self.canvas = FigureCanvasTkAgg(fig, master=t1)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)

        cols = ("SSID", "Channel", "Signal")
        self.tree_wifi = ttk.Treeview(t2, columns=cols, show="headings")
        for c in cols:
            self.tree_wifi.heading(c, text=c)
        self.tree_wifi.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(t2, text="Connected Devices (IP / MAC / IFACE / MTU / OS)").pack(pady=5)
        self.tree_clients = ttk.Treeview(t2, columns=("IP", "MAC", "IFACE", "MTU", "OS"), show="headings")
        for c, t in [("IP", "IP"), ("MAC", "MAC"), ("IFACE", "IFACE"), ("MTU", "MTU"), ("OS", "OS")]:
            self.tree_clients.heading(c, text=t)
        self.tree_clients.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(t3, text="Management & Settings", font=("Arial", 20)).pack(pady=20)
        info = f"Web Interface: http://{self.get_local_ip_for_web()}:{WEB_PORT}\nLogin: {WEB_USER}\nPassword: {WEB_PASS}"
        ctk.CTkLabel(t3, text=info, justify="left", fg_color="#333", corner_radius=10).pack(pady=10)

        ctk.CTkButton(
            t3,
            text="Open Web Panel",
            command=lambda: os.system(f"xdg-open http://{self.get_local_ip_for_web()}:{WEB_PORT}")
        ).pack(pady=5)

        ctk.CTkButton(
            t3,
            text="Reboot Router (SSH)",
            fg_color="red",
            command=self.reboot_router_gui
        ).pack(pady=20)

    def get_local_ip_for_web(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def reboot_router_gui(self):
        global ssh_client
        with data_lock:
            ssh_status = data["router_stats"].get("ssh_status", "not log in")
        if ssh_status != "OK" or not ssh_client:
            return
        ssh_exec(ssh_client, "reboot")

    def run_web(self):
        app_flask.run(host="0.0.0.0", port=WEB_PORT, use_reloader=False)

    def worker(self):
        global ssh_client, last_io, last_time

        # fast init (no blocking GUI)
        with data_lock:
            data["public_info"] = get_public_data()
            data["inet_status"], data["inet_ip"] = check_inet()
            data["local_ifaces"] = get_interfaces()

        # SSH init (can fail, should not block)
        ssh_client = ssh_connect()
        with data_lock:
            if ssh_client:
                data["router_stats"].update(get_router_deep_info(ssh_client))
            else:
                data["router_stats"]["ssh_status"] = "not log in"

        while True:
            try:
                io = psutil.net_io_counters()
                now = time.time()
                dt = now - last_time
                if dt > 0:
                    down = (io.bytes_recv - last_io.bytes_recv) * 8 / 1_000_000 / dt
                    up = (io.bytes_sent - last_io.bytes_sent) * 8 / 1_000_000 / dt
                    last_io = io
                    last_time = now
                    with data_lock:
                        data["down_speed"] = max(0.0, down)
                        data["up_speed"] = max(0.0, up)

                # periodic tasks
                if int(time.time()) % 3 == 0:
                    with data_lock:
                        data["local_ifaces"] = get_interfaces()
                        data["scanned_networks"] = scan_wifi()
                        data["inet_status"], data["inet_ip"] = check_inet()

                    # SSH refresh / reconnect
                    if not ssh_client:
                        ssh_client = ssh_connect()

                    if ssh_client:
                        rinfo = get_router_deep_info(ssh_client)
                        with data_lock:
                            data["router_stats"].update(rinfo)

                        clients = router_get_arp_clients(ssh_client)
                        details = enrich_clients(clients)

                        with data_lock:
                            data["wifi_clients"] = clients
                            data["clients_details"] = details
                    else:
                        with data_lock:
                            data["router_stats"]["ssh_status"] = "not log in"
                            data["wifi_clients"] = []
                            data["clients_details"] = []

            except Exception:
                pass

            time.sleep(REFRESH_RATE)

    def update_ui(self):
        # splash max 3 seconds, then show GUI anyway
        if not self._ui_ready:
            elapsed = time.time() - self._start_ts
            if elapsed >= SPLASH_MAX_SECONDS:
                try:
                    self.splash.destroy()
                except Exception:
                    pass
                self.splash = None
                self.deiconify()
                self.setup_ui()
                self._ui_ready = True

        if self._ui_ready:
            try:
                with data_lock:
                    d = dict(data)
                    clients = list(data.get("clients_details", []))
                    nets = list(data.get("scanned_networks", []))

                self.lbl_inet.configure(text=f"{d['inet_status']} | Public: {d['public_info'].get('query','...')}")
                self.lbl_router_model.configure(text=f"Model: {d['router_stats'].get('model','...')}")
                self.lbl_router_cpu.configure(text=f"CPU: {d['router_stats'].get('cpu','...')}")
                self.lbl_router_os.configure(text=f"OS: {d['router_stats'].get('os_ver','...')}")
                self.lbl_ssh.configure(text=f"SSH: {d['router_stats'].get('ssh_status','Checking...')}")

                self.ax.clear()
                self.ax.plot([0, 1], [d["down_speed"], d["up_speed"]], color="cyan", linewidth=2)
                self.ax.set_ylim(0, max(10, (max(d["down_speed"], d["up_speed"]) * 1.3)))
                self.ax.set_xticks([0, 1])
                self.ax.set_xticklabels(["Down", "Up"], color="white")
                self.ax.set_title(f"Speed: {d['down_speed']:.2f} / {d['up_speed']:.2f} Mbps", color="white")
                self.canvas.draw()

                for i in self.tree_wifi.get_children():
                    self.tree_wifi.delete(i)
                for n in nets[:200]:
                    self.tree_wifi.insert("", "end", values=(n.get("ssid", ""), n.get("chan", ""), n.get("sig", "")))

                for i in self.tree_clients.get_children():
                    self.tree_clients.delete(i)
                for c in clients[:500]:
                    self.tree_clients.insert("", "end", values=(c["ip"], c["mac"], c["dev"], c["mtu"], c["os"]))

            except Exception:
                pass

        self.after(500, self.update_ui)

if __name__ == "__main__":
    NetworkOS().mainloop()

