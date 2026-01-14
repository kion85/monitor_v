
import time
import threading
import psutil
import socket
import requests
import subprocess
import re
import os
import json
import platform
from datetime import datetime
import paramiko
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from flask import Flask, render_template_string, request, redirect, url_for, session
from functools import wraps

# ===========================
# КОНФИГУРАЦИЯ
# ===========================

REFRESH_RATE = 1.5  # Частота обновления данных (секунды)
SSH_HOST = "192.168.1.1" # IP-адрес вашего роутера
SSH_PORT = 22
SSH_USER = "root"
SSH_PASSWORD = "root"
WEB_PORT = 5000
WEB_USER = "admin" # Логин для веб-интерфейса
WEB_PASS = "admin" # Пароль для веб-интерфейса

# ===========================
# ГЛОБАЛЬНЫЕ ДАННЫЕ
# ===========================

data = {
    "inet_status": "Checking...",
    "inet_ip": "...",
    "public_info": {'query': '...', 'isp': '...', 'city': '...', 'countryCode': '...'},
    "local_ifaces": [],
    "router_ifaces": [],
    "router_stats": {
        "hostname": "Not logged in", "kernel": "Not logged in", "uptime": "Not logged in",
        "load": "Not logged in", "ram_total": "Not logged in", "ram_free": "Not logged in",
        "ram_used_percent": 0.0, # Добавлено для роутера
        "model": "Not logged in", "cpu": "Not logged in", "os_ver": "Not logged in",
        "cpu_usage": "Not logged in" # Добавлено для роутера
    },
    "local_stats": { # Добавлено для локальной машины
        "cpu_usage": 0.0,
        "ram_total": "N/A", "ram_used": "N/A", "ram_free": "N/A", "ram_percent": 0.0,
        "disk_total": "N/A", "disk_used": "N/A", "disk_free": "N/A", "disk_percent": 0.0
    },
    "wifi_clients": [],
    "scanned_networks": [],
    "down_speed": 0.0, "up_speed": 0.0
}

ssh_client = None
last_io = psutil.net_io_counters()
last_time = time.time()
last_heavy_update = 0 # Для нечастых обновлений (публичный IP, роутер, WiFi сканирование)

# ===========================
# SSH ФУНКЦИИ
# ===========================
def ssh_connect():
    global ssh_client  # <--- СТРОГО ПЕРВАЯ СТРОКА
    if ssh_client:
        try:
            transport = ssh_client.get_transport()
            if transport and transport.is_active():
                ssh_client.exec_command("echo ping", timeout=1) 
                return ssh_client
            else:
                print("SSH transport not active. Reconnecting...")
                ssh_client.close()
                ssh_client = None
        except Exception:
            print("SSH connection lost or invalid. Reconnecting...")
            if ssh_client:
                ssh_client.close()
            ssh_client = None

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD, timeout=3)
        print(f"SSH Connected to {SSH_HOST}")
        ssh_client = client  # Сохраняем в глобальную переменную
        return client
    except Exception as e:
        print(f"SSH Connection Failed: {e}")
        return None

def ssh_exec(client, cmd):
    global ssh_client  # <--- СТРОГО ПЕРВАЯ СТРОКА
    if not client:
        return ""
    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        if error and "No such file or directory" not in error and "not found" not in error:
            print(f"SSH command error '{cmd}': {error}")
        return output
    except paramiko.SSHException as e:
        print(f"SSH exec error for cmd '{cmd}': {e}")
        if ssh_client == client: 
            ssh_client = None 
        return ""
    except Exception as e:
        print(f"General error for cmd '{cmd}': {e}")
        return ""

def get_router_interfaces(client):
    """Получаем информацию о интерфейсах роутера и их MTU"""
    if not client:
        return []
    try:
        output = ssh_exec(client, "ip -br link show")
        interfaces = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                # В OpenWrt MTU обычно идет вторым полем после имени, но может быть и часть флагов
                # Пробуем извлечь MTU из output 'ip link show' для надежности
                mtu_match = re.search(r'mtu (\d+)', ssh_exec(client, f"ip link show {parts[0]}"))
                mtu_value = mtu_match.group(1) if mtu_match else "Unknown"

                interfaces.append({
                    "name": parts[0],
                    "status": parts[1], # 'UP' or 'DOWN'
                    "mtu": mtu_value
                })
        return interfaces
    except Exception as e:
        print(f"Error getting router interfaces: {e}")
        return []

def get_router_deep_info(client):
    """Собирает информацию о железе и ОС роутера, включая CPU/RAM usage"""
    # Создаем шаблон для "Not logged in", чтобы избежать множества if-else
    default_info = {
        "hostname": "Not logged in", "kernel": "Not logged in", "uptime": "Not logged in",
        "load": "Not logged in", "ram_total": "Not logged in", "ram_free": "Not logged in",
        "ram_used_percent": 0.0, "model": "Not logged in", "cpu": "Not logged in",
        "os_ver": "Not logged in", "cpu_usage": "Not logged in"
    }
    if not client:
        return default_info

    info = {}
    info['hostname'] = ssh_exec(client, "hostname") or default_info['hostname']
    info['kernel'] = ssh_exec(client, "uname -r") or default_info['kernel']
    info['os_ver'] = ssh_exec(client, "cat /etc/openwrt_release | grep 'DISTRIB_DESCRIPTION' | cut -d= -f2 | tr -d '\"'") or default_info['os_ver']
    # Для модели пробуем несколько путей, т.к. может отличаться в зависимости от устройства
    info['model'] = ssh_exec(client, "cat /sys/firmware/devicetree/base/model || cat /tmp/sysinfo/model || cat /proc/cpuinfo | grep 'Hardware' | head -1 | cut -d: -f2") or default_info['model']

    # Информация о CPU
    cpu_raw = ssh_exec(client, "cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2")
    info['cpu'] = cpu_raw.strip() if cpu_raw else default_info['cpu']

    # CPU Usage (calculate 100 - idle percentage)
    cpu_idle_raw = ssh_exec(client, "top -bn1 | grep 'Cpu(s):' | awk '{print $8}'") # Idle CPU percentage
    if cpu_idle_raw:
        try:
            idle = float(cpu_idle_raw)
            info['cpu_usage'] = f"{100 - idle:.1f}%"
        except ValueError:
            info['cpu_usage'] = "N/A"
    else:
        info['cpu_usage'] = "N/A"

    # Информация о ОЗУ
    mem = ssh_exec(client, "free -m")
    parts = mem.split()
    if len(parts) > 5: # free -m output has changed in some OpenWrt versions, adjusted indexing
        try:
            # Find the header row and then corresponding data
            # Example output:
            #               total        used        free      shared  buff/cache   available
            # Mem:         256         100         150           0           6           140
            # The indices for total, used, free, available can vary
            header_index_map = {}
            header_line = mem.splitlines()[0]
            headers = header_line.split()
            for i, h in enumerate(headers):
                header_index_map[h.lower()] = i

            data_line = mem.splitlines()[1] # The line with actual numbers
            data_parts = data_line.split()

            total_mb = int(data_parts[header_index_map.get('total', 1)])
            free_mb = int(data_parts[header_index_map.get('free', 3)])
            # Using 'available' if present, as it's a more accurate 'free' from user perspective
            available_mb = int(data_parts[header_index_map.get('available', 6)]) if 'available' in header_index_map else free_mb
            
            used_mb = total_mb - available_mb # Calculate used from total - available
            
            info['ram_total'] = f"{total_mb} MB"
            info['ram_free'] = f"{available_mb} MB" # Store available as free
            info['ram_used_percent'] = (used_mb / total_mb * 100) if total_mb > 0 else 0.0
        except (ValueError, IndexError) as e:
            print(f"Error parsing router RAM: {e}")
            info['ram_total'] = default_info['ram_total']
            info['ram_free'] = default_info['ram_free']
            info['ram_used_percent'] = default_info['ram_used_percent']
    else:
        info['ram_total'] = default_info['ram_total']
        info['ram_free'] = default_info['ram_free']
        info['ram_used_percent'] = default_info['ram_used_percent']

    # Uptime и нагрузка
    up = ssh_exec(client, "uptime")
    if "up" in up:
        # Пример: 12:34:56 up 1 day, 2:30, 2 users, load average: 0.00, 0.01, 0.05
        uptime_match = re.search(r'up (.+?), load average:', up)
        if uptime_match:
            info['uptime'] = uptime_match.group(1).strip()
        else:
            info['uptime'] = "Unknown"
        info['load'] = up.split("load average:")[-1].strip()
    else:
        info['uptime'] = default_info['uptime']
        info['load'] = default_info['load']

    return info

def get_client_os_info(ip, mac):
    """Определяем ОС клиента, возвращаем N/A если не получается"""
    os_info = "N/A"
    vendor = "Unknown"
    
    try:
        # Попытка определения по MAC вендору
        # Используем более надежный сервис, если api.macvendors.com перестанет работать
        # Или можно использовать локальную базу MAC-адресов
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=1)
        vendor = r.text if r.status_code == 200 else "Unknown"
    except requests.exceptions.RequestException:
        pass # Игнорируем ошибки сети для macvendors

    # Попытка более точного определения через nmap (если установлен)
    # Это может быть долго, поэтому даем короткий таймаут и ловим ошибки
    try:
        # -O: OS detection, -Pn: skip host discovery (assume host is up)
        # --osscan-limit: limit OS detection to promising targets (faster)
        result = subprocess.check_output(["nmap", "-O", "-Pn", "--osscan-limit", ip], 
                                         stderr=subprocess.DEVNULL, timeout=5).decode()
        os_match = re.search(r"Running: (.+)\n", result)
        if os_match:
            os_info = os_match.group(1)
        elif vendor != "Unknown":
            os_info = f"{vendor} (N/A)" # Если nmap не нашел ОС, но есть вендор
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        if vendor != "Unknown":
            os_info = f"{vendor} (N/A)"
    except Exception as e:
        print(f"Error in nmap for {ip}: {e}")
        if vendor != "Unknown":
            os_info = f"{vendor} (N/A)"
            
    return os_info

# ===========================
# ЛОКАЛЬНЫЕ ФУНКЦИИ
# ===========================

def get_public_data():
    try:
        r = requests.get('http://ip-api.com/json/?fields=status,query,isp,city,countryCode', timeout=3)
        return r.json() if r.status_code == 200 else {'query': 'Offline', 'isp': '-', 'city': '-', 'countryCode': '-'}
    except requests.exceptions.RequestException:
        return {'query': 'Offline', 'isp': '-', 'city': '-', 'countryCode': '-'}

def get_interfaces():
    res = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, snics in addrs.items():
            if name in stats: # Убедимся, что интерфейс имеет статистику
                item = {
                    "name": name,
                    "ipv4": "-",
                    "ipv6": "-",
                    "status": "UP" if stats[name].isup else "DOWN",
                    "mtu": str(stats[name].mtu) if hasattr(stats[name], 'mtu') else "Unknown"
                }
                for s in snics:
                    if s.family == socket.AF_INET:
                        item["ipv4"] = s.address
                    elif s.family == socket.AF_INET6:
                        item["ipv6"] = s.address.split('%')[0] # Удаляем scope_id
                res.append(item)
    except Exception as e:
        print(f"Interface scan error: {e}")
    return res

def check_inet():
    try:
        # Проверяем DNS-сервер Google
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        # Получаем локальный IP, который используется для выхода в интернет
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return "✅ Online", local_ip
    except (socket.timeout, OSError):
        return "❌ Offline", "No Inet"
    except Exception as e:
        print(f"Error checking internet: {e}")
        return "❌ Offline", "No Inet"

def scan_wifi():
    nets = []
    try:
        # nmcli доступен не на всех системах. Добавляем проверку FileNotFoundError
        out = subprocess.check_output(["nmcli", "-t", "-f", "SSID,CHAN,SIGNAL,SECURITY", "dev", "wifi"], 
                                      stderr=subprocess.DEVNULL, timeout=5).decode()
        for line in out.splitlines():
            p = line.split(":")
            if len(p) >= 4 and p[0] != '':
                nets.append({
                    "ssid": ":".join(p[:-3]), # SSID может содержать ':'
                    "chan": p[-3],
                    "sig": p[-2],
                    "sec": p[-1]
                })
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass # nmcli не найден или ошибка/таймаут
    except Exception as e:
        print(f"Error scanning wifi: {e}")
    return nets

# ===========================
# WEB SERVER
# ===========================

app_flask = Flask(__name__) # Исправлено на __name__
app_flask.secret_key = "networkos_monitor_secure_key"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app_flask.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        if request.form['username'] == WEB_USER and request.form['password'] == WEB_PASS:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        message = "Неверный логин или пароль"
    return render_template_string('''
    <html><body style="background:#222;color:#fff;font-family:sans-serif;text-align:center;padding:50px;">
    <h2>🔒 Network Monitor</h2>
    {% if message %}<p style="color:red;">{{ message }}</p>{% endif %}
    <form method="post">
    <div>Логин: <input name="username" value="{{ web_user }}" style="padding:5px;margin:5px;"></div>
    <div>Пароль: <input type="password" name="password" style="padding:5px;margin:5px;"></div>
    <br>
    <input type="submit" value="Войти" style="padding:8px 25px;">
    </form>
    </body></html>
    ''', web_user=WEB_USER, message=message)

@app_flask.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app_flask.route('/reboot_router')
@login_required
def reboot_router_web(): # Изменено имя для избежания конфликта с GUI функцией
    if not ssh_client:
        return "Не подключено к роутеру по SSH", 400
    try:
        ssh_exec(ssh_client, "reboot &") # Запускаем в фоне, чтобы SSH не завис
        # Сбрасываем ssh_client, чтобы worker_thread попытался переподключиться
        if ssh_client:
            ssh_client.close()
            ssh_client = None
        return "Роутер будет перезагружен через несколько секунд. SSH соединение будет потеряно.", 200
    except Exception as e:
        return f"Ошибка при перезагрузке роутера: {e}", 500

@app_flask.route('/')
@login_required
def dashboard():
    return render_template_string('''
<html>
<head>
    <title>Network Monitor</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {background:#111;color:#fff;font-family:system-ui,sans-serif;padding:20px;max-width:1400px;margin:0 auto}
        h1 {border-bottom:2px solid #333;padding-bottom:10px}
        .card {background:#222;padding:20px;margin:15px 0;border-radius:10px;border:1px solid #333}
        table {width:100%;border-collapse:collapse;margin-top:10px}
        td,th {border:1px solid #444;padding:8px;text-align:left}
        th {background:#333}
        .btn-reboot {background:#dc2626;color:white;border:none;padding:10px 20px;border-radius:5px;cursor:pointer;margin-top:10px;}
        .btn-reboot:hover {background:#b91c1c}
        .info-grid {display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px; margin-top: 10px;}
        .info-grid > div {background: #333; padding: 10px; border-radius: 5px; display: flex; flex-direction: column; justify-content: space-between;}
        .progress-bar-container { width: 100%; background: #444; border-radius: 3px; height: 10px; margin-top: 5px; overflow: hidden; }
        .progress-bar-fill { height: 100%; background: #10b981; width: 0%; border-radius: 3px; }
        .stat-line { display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px; }
        .stat-label { font-weight: bold; }
        .stat-value { font-size: 0.9em; color: #bbb; }
        @media (max-width: 768px) {
            .info-grid { grid-template-columns: 1fr; }
        }
    </style>
    <script>
        function rebootRouter() {
            if (confirm('Вы уверены, что хотите перезагрузить роутер? Это приведет к потере SSH соединения.')) {
                fetch('/reboot_router')
                    .then(response => response.text())
                    .then(data => {
                        alert(data);
                        // Опционально: перезагрузить страницу через несколько секунд или перенаправить
                        setTimeout(() => location.reload(), 5000); 
                    })
                    .catch(error => {
                        alert('Произошла ошибка при отправке команды перезагрузки: ' + error);
                    });
            }
        }
    </script>
</head>
<body>
    <h1>🖥️ Network Monitor <a href="/logout" style="float:right;color:#f87171;text-decoration:none">[ВЫЙТИ]</a></h1>
    
    <div class="card">
        <h3>🌐 Общий статус</h3>
        <div class="info-grid">
            <div>
                <div class="stat-line"><span class="stat-label">Интернет:</span> <span class="stat-value">{{ data.inet_status }}</span></div>
                <div class="stat-line"><span class="stat-label">Публичный IP:</span> <span class="stat-value">{{ data.public_info.query }}</span></div>
            </div>
            <div>
                <div class="stat-line"><span class="stat-label">Провайдер:</span> <span class="stat-value">{{ data.public_info.isp }}</span></div>
                <div class="stat-line"><span class="stat-label">Локация:</span> <span class="stat-value">{{ data.public_info.city }}, {{ data.public_info.countryCode }}</span></div>
            </div>
            <div>
                <div class="stat-line"><span class="stat-label">Скорость:</span> <span class="stat-value">↓{{ data.down_speed|round(1) }} / ↑{{ data.up_speed|round(1) }} Mbps</span></div>
            </div>
        </div>
    </div>

    <div class="card">
        <h3>💻 Локальная система</h3>
        <div class="info-grid">
            <div>
                <div class="stat-line"><span class="stat-label">CPU:</span> <span class="stat-value">{{ data.local_stats.cpu_usage|round(1) }}%</span></div>
                <div class="progress-bar-container"><div class="progress-bar-fill" style="width:{{ data.local_stats.cpu_usage|round(1) }}%;"></div></div>
            </div>
            <div>
                {% set local_ram_total_val = data.local_stats.ram_total.split(' ')[0]|float(default=1.0) %}
                {% set local_ram_used_val = data.local_stats.ram_used.split(' ')[0]|float(default=0.0) %}
                <div class="stat-line"><span class="stat-label">ОЗУ:</span> <span class="stat-value">{{ data.local_stats.ram_used }} / {{ data.local_stats.ram_total }} ({{ data.local_stats.ram_percent|round(1) }}%)</span></div>
                <div class="progress-bar-container"><div class="progress-bar-fill" style="width:{{ data.local_stats.ram_percent|round(1) }}%;"></div></div>
            </div>
            <div>
                {% set local_disk_total_val = data.local_stats.disk_total.split(' ')[0]|float(default=1.0) %}
                {% set local_disk_used_val = data.local_stats.disk_used.split(' ')[0]|float(default=0.0) %}
                <div class="stat-line"><span class="stat-label">Диск:</span> <span class="stat-value">{{ data.local_stats.disk_used }} / {{ data.local_stats.disk_total }} ({{ data.local_stats.disk_percent|round(1) }}%)</span></div>
                <div class="progress-bar-container"><div class="progress-bar-fill" style="width:{{ data.local_stats.disk_percent|round(1) }}%;"></div></div>
            </div>
        </div>
    </div>

    <div class="card">
        <h3>📱 Роутер</h3>
        <div class="info-grid">
            <div>
                <div class="stat-line"><span class="stat-label">Модель:</span> <span class="stat-value">{{ data.router_stats.model }}</span></div>
                <div class="stat-line"><span class="stat-label">ОС:</span> <span class="stat-value">{{ data.router_stats.os_ver }}</span></div>
            </div>
            <div>
                <div class="stat-line"><span class="stat-label">CPU:</span> <span class="stat-value">{{ data.router_stats.cpu }}</span></div>
                <div class="stat-line"><span class="stat-label">Использование CPU:</span> <span class="stat-value">{{ data.router_stats.cpu_usage }}</span></div>
                {% set router_cpu_val = data.router_stats.cpu_usage.replace('%', '')|float(default=0.0) %}
                <div class="progress-bar-container"><div class="progress-bar-fill" style="width:{{ router_cpu_val }}%;"></div></div>
            </div>
            <div>
                {% set router_ram_total_str = data.router_stats.ram_total %}
                {% set router_ram_free_str = data.router_stats.ram_free %}
                {% set router_ram_total_mb = router_ram_total_str.split(' ')[0]|float(default=1.0) %}
                {% set router_ram_used_mb = (router_ram_total_mb - router_ram_free_str.split(' ')[0]|float(default=0.0))|round(0) %}
                <div class="stat-line"><span class="stat-label">ОЗУ:</span> <span class="stat-value">{% if router_ram_total_mb > 0 %}{{ router_ram_used_mb }} MB / {{ router_ram_total_str }} ({{ data.router_stats.ram_used_percent|round(1) }}%){% else %}N/A{% endif %}</span></div>
                <div class="progress-bar-container"><div class="progress-bar-fill" style="width:{{ data.router_stats.ram_used_percent|round(1) }}%;"></div></div>
            </div>
            <div>
                <div class="stat-line"><span class="stat-label">Время работы:</span> <span class="stat-value">{{ data.router_stats.uptime }}</span></div>
                <div class="stat-line"><span class="stat-label">Нагрузка:</span> <span class="stat-value">{{ data.router_stats.load }}</span></div>
            </div>
        </div>
        <button class="btn-reboot" onclick="rebootRouter()">🔄 Перезагрузить роутер</button>
    </div>

    <div class="card">
        <h3>🔌 Подключенные устройства</h3>
        <table>
            <thead>
                <tr><th>IP Адрес</th><th>MAC Адрес</th><th>Интерфейс</th><th>ОС / Вендор</th></tr>
            </thead>
            <tbody>
                {% for c in data.wifi_clients %}
                <tr><td>{{ c.ip }}</td><td>{{ c.mac }}</td><td>{{ c.dev }}</td><td>{{ c.os }}</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h3>🔗 Интерфейсы (MTU)</h3>
        <h4>Локальные интерфейсы</h4>
        <table>
            <thead>
                <tr><th>Имя</th><th>IPv4</th><th>Статус</th><th>MTU</th></tr>
            </thead>
            <tbody>
                {% for iface in data.local_ifaces %}
                <tr><td>{{ iface.name }}</td><td>{{ iface.ipv4 }}</td><td>{{ iface.status }}</td><td>{{ iface.mtu }}</td></tr>
                {% endfor %}
            </tbody>
        </table>
        {% if data.router_ifaces %}
        <h4 style="margin-top:20px">Интерфейсы роутера</h4>
        <table>
            <thead>
                <tr><th>Имя</th><th>Статус</th><th>MTU</th></tr>
            </thead>
            <tbody>
                {% for iface in data.router_ifaces %}
                <tr><td>{{ iface.name }}</td><td>{{ iface.status }}</td><td>{{ iface.mtu }}</td></tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
    </div>
</body>
</html>
''', data=data)

# ===========================
# GUI ПРИЛОЖЕНИЕ
# ===========================

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class NetworkMonitor(ctk.CTk):
    def __init__(self): # Исправлено на __init__
        super().__init__()
        self.title("Network Monitor")
        self.geometry("1200x800")
        self.minsize(900, 600)

        # Экран загрузки
        self.create_splash()
        self.withdraw() # Скрываем основное окно пока грузится сплеш

        # Запускаем рабочие потоки
        threading.Thread(target=self.worker_thread, daemon=True).start()
        threading.Thread(target=self.run_web_server, daemon=True).start()

        # Запускаем обновление интерфейса после закрытия сплеша
        self.after(100, self.update_interface)

    def create_splash(self):
        self.splash = ctk.CTkToplevel(self)
        self.splash.geometry("450x280")
        self.splash.overrideredirect(True)
        
        # Выравниваем по центру экрана
        x = (self.splash.winfo_screenwidth() // 2) - 225
        y = (self.splash.winfo_screenheight() // 2) - 140
        self.splash.geometry(f"+{x}+{y}")
        
        ctk.CTkLabel(self.splash, text="🖥️ Network Monitor", font=("Arial", 32, "bold")).pack(pady=(60, 15))
        progress = ctk.CTkProgressBar(self.splash, width=350, mode="indeterminate")
        progress.pack()
        progress.start()
        ctk.CTkLabel(self.splash, text="Инициализация системы...", font=("Arial", 12)).pack(pady=15)

        # Ограничиваем время показа сплеша 3 секундами, затем запускаем основное окно
        self.splash.after(3000, self.close_splash)

    def close_splash(self):
        if hasattr(self, 'splash') and self.splash.winfo_exists():
            self.splash.destroy()
            self.deiconify() # Показываем основное окно
            self.setup_main_interface() # Настраиваем основной интерфейс после закрытия сплеша

    def _is_ssh_connected(self, client):
        """Проверяет активность SSH соединения"""
        if client is None:
            return False
        try:
            transport = client.get_transport()
            if transport and transport.is_active():
                # Отправляем легковесную команду, чтобы проверить соединение
                stdin, stdout, stderr = client.exec_command("echo test", timeout=1)
                stdout.read() # Читаем, чтобы очистить буфер
                return True
            return False
        except Exception:
            return False

    def worker_thread(self):
        global ssh_client, last_io, last_time, last_heavy_update, data
        
        # Инициализация базовых данных
        data["public_info"] = get_public_data()
        data["inet_status"], data["inet_ip"] = check_inet()
        data["local_ifaces"] = get_interfaces()
        
        # Первая попытка подключения к роутеру
        ssh_client = ssh_connect()
        if ssh_client:
            data["router_stats"] = get_router_deep_info(ssh_client)
            data["router_ifaces"] = get_router_interfaces(ssh_client)

        # Основной цикл сбора данных
        while True:
            current_time = time.time()

            # Расчет скорости интернета
            current_io = psutil.net_io_counters()
            time_delta = current_time - last_time
            
            if time_delta > 0.1: # Избегаем деления на ноль и слишком частых расчетов
                data["down_speed"] = (current_io.bytes_recv - last_io.bytes_recv) * 8 / 1_000_000 / time_delta
                data["up_speed"] = (current_io.bytes_sent - last_io.bytes_sent) * 8 / 1_000_000 / time_delta
                last_io = current_io
                last_time = current_time

            # Обновление локальных системных ресурсов (CPU, RAM, Disk) - часто
            data["local_stats"]["cpu_usage"] = psutil.cpu_percent(interval=None) # Неблокирующая
            mem = psutil.virtual_memory()
            data["local_stats"]["ram_total"] = f"{mem.total / (1024**3):.1f} GB"
            data["local_stats"]["ram_used"] = f"{mem.used / (1024**3):.1f} GB"
            data["local_stats"]["ram_free"] = f"{mem.available / (1024**3):.1f} GB" # Используем 'available' как практическое "свободно"
            data["local_stats"]["ram_percent"] = mem.percent

            try:
                disk = psutil.disk_usage('/')
                data["local_stats"]["disk_total"] = f"{disk.total / (1024**3):.1f} GB"
                data["local_stats"]["disk_used"] = f"{disk.used / (1024**3):.1f} GB"
                data["local_stats"]["disk_free"] = f"{disk.free / (1024**3):.1f} GB"
                data["local_stats"]["disk_percent"] = disk.percent
            except Exception as e:
                # print(f"Disk info error: {e}") # Отладочная информация
                data["local_stats"]["disk_total"] = "N/A"
                data["local_stats"]["disk_used"] = "N/A"
                data["local_stats"]["disk_free"] = "N/A"
                data["local_stats"]["disk_percent"] = 0.0

            # Тяжелые операции и обновление данных роутера - реже
            if current_time - last_heavy_update > 3: # Обновляем раз в 3 секунды
                last_heavy_update = current_time
                
                # Обновление локальных сетевых данных
                data["local_ifaces"] = get_interfaces()
                data["scanned_networks"] = scan_wifi()
                data["inet_status"], data["inet_ip"] = check_inet()
                data["public_info"] = get_public_data()

                # Проверка и обновление SSH соединения, а также данных роутера
                if not ssh_client or not self._is_ssh_connected(ssh_client):
                    print("Attempting to reconnect SSH...")
                    ssh_client = ssh_connect()

                if ssh_client:
                    data["router_stats"] = get_router_deep_info(ssh_client)
                    data["router_ifaces"] = get_router_interfaces(ssh_client)
                    
                    # Получаем список подключенных клиентов и их ОС
                    arp_data = ssh_exec(ssh_client, "cat /proc/net/arp")
                    clients = []
                    for line in arp_data.splitlines()[1:]: # Пропускаем заголовок
                        parts = line.split()
                        # Пример строки: 192.168.1.100 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
                        if len(parts) >= 6 and parts[3] == "lladdr": # Проверка формата ARP записи
                            ip = parts[0]
                            mac = parts[4]
                            dev = parts[1]
                            clients.append({
                                "ip": ip,
                                "mac": mac,
                                "dev": dev,
                                "os": get_client_os_info(ip, mac) # Эта функция может быть медленной
                            })
                    data["wifi_clients"] = clients
                else:
                    # Если SSH не подключен, сбрасываем данные роутера
                    default_router_stats = {
                        "hostname": "Not logged in", "kernel": "Not logged in", "uptime": "Not logged in",
                        "load": "Not logged in", "ram_total": "Not logged in", "ram_free": "Not logged in",
                        "ram_used_percent": 0.0, "model": "Not logged in", "cpu": "Not logged in",
                        "os_ver": "Not logged in", "cpu_usage": "Not logged in"
                    }
                    data["router_stats"] = default_router_stats
                    data["router_ifaces"] = []
                    data["wifi_clients"] = []
            
            time.sleep(REFRESH_RATE)

    def run_web_server(self):
        try:
            # use_reloader=False - иначе Flask перезапустит поток и создаст новые
            # debug=False - не выводить отладочную информацию Flask
            app_flask.run(host='0.0.0.0', port=WEB_PORT, use_reloader=False, debug=False)
        except Exception as e:
            print(f"Web server error: {e}")

    def setup_main_interface(self):
        # Создаем вкладки
        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.pack(fill="both", expand=True, padx=10, pady=10)

        tab_dashboard = self.tab_view.add("📊 Дашборд")
        tab_network = self.tab_view.add("📡 Сеть")
        tab_router = self.tab_view.add("🖧 Управление роутером")

        # ==================== Вкладка Дашборд ====================
        # Общий статус интернета
        self.lbl_inet_status = ctk.CTkLabel(tab_dashboard, text="Загрузка...", font=("Arial", 16))
        self.lbl_inet_status.pack(pady=10)

        # Фрейм для локальной системы
        local_sys_frame = ctk.CTkFrame(tab_dashboard)
        local_sys_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(local_sys_frame, text="💻 Локальная система:", font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 5))
        
        local_grid_frame = ctk.CTkFrame(local_sys_frame, fg_color="transparent")
        local_grid_frame.pack(fill="x", padx=10, pady=5)
        
        # Настройка колонок для сетки локальной системы
        local_grid_frame.grid_columnconfigure(0, weight=1) # Метки
        local_grid_frame.grid_columnconfigure(1, weight=0) # Прогресс-бары

        self.lbl_local_cpu = ctk.CTkLabel(local_grid_frame, text="CPU: ---", width=150, anchor="w")
        self.lbl_local_cpu.grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.prog_local_cpu = ctk.CTkProgressBar(local_grid_frame, width=100)
        self.prog_local_cpu.set(0)
        self.prog_local_cpu.grid(row=0, column=1, padx=5, pady=2, sticky="w")

        self.lbl_local_ram = ctk.CTkLabel(local_grid_frame, text="RAM: ---", width=250, anchor="w")
        self.lbl_local_ram.grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.prog_local_ram = ctk.CTkProgressBar(local_grid_frame, width=100)
        self.prog_local_ram.set(0)
        self.prog_local_ram.grid(row=1, column=1, padx=5, pady=2, sticky="w")

        self.lbl_local_disk = ctk.CTkLabel(local_grid_frame, text="DISK: ---", width=250, anchor="w")
        self.lbl_local_disk.grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.prog_local_disk = ctk.CTkProgressBar(local_grid_frame, width=100)
        self.prog_local_disk.set(0)
        self.prog_local_disk.grid(row=2, column=1, padx=5, pady=2, sticky="w")


        # Фрейм для информации о роутере
        router_sys_frame = ctk.CTkFrame(tab_dashboard)
        router_sys_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(router_sys_frame, text="📱 Роутер:", font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 5))

        router_grid_frame = ctk.CTkFrame(router_sys_frame, fg_color="transparent")
        router_grid_frame.pack(fill="x", padx=10, pady=5)
        
        # Настройка колонок для сетки роутера
        router_grid_frame.grid_columnconfigure(0, weight=1) # Метки
        router_grid_frame.grid_columnconfigure(1, weight=1) # Значения/доп метки
        router_grid_frame.grid_columnconfigure(2, weight=0) # Прогресс-бары

        self.lbl_router_model = ctk.CTkLabel(router_grid_frame, text="Модель: ---", anchor="w")
        self.lbl_router_model.grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.lbl_router_os_ver = ctk.CTkLabel(router_grid_frame, text="ОС: ---", anchor="w")
        self.lbl_router_os_ver.grid(row=0, column=1, padx=5, pady=2, sticky="w")

        self.lbl_router_cpu_info = ctk.CTkLabel(router_grid_frame, text="CPU: ---", anchor="w")
        self.lbl_router_cpu_info.grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.lbl_router_cpu_usage = ctk.CTkLabel(router_grid_frame, text="Нагрузка CPU: ---", anchor="w")
        self.lbl_router_cpu_usage.grid(row=1, column=1, padx=5, pady=2, sticky="w")
        self.prog_router_cpu = ctk.CTkProgressBar(router_grid_frame, width=100)
        self.prog_router_cpu.set(0)
        self.prog_router_cpu.grid(row=1, column=2, padx=5, pady=2, sticky="w")

        self.lbl_router_ram_info = ctk.CTkLabel(router_grid_frame, text="RAM: ---", anchor="w")
        self.lbl_router_ram_info.grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.prog_router_ram = ctk.CTkProgressBar(router_grid_frame, width=100)
        self.prog_router_ram.set(0)
        self.prog_router_ram.grid(row=2, column=2, padx=5, pady=2, sticky="w")

        self.lbl_router_uptime = ctk.CTkLabel(router_grid_frame, text="Время работы: ---", anchor="w")
        self.lbl_router_uptime.grid(row=3, column=0, padx=5, pady=2, sticky="w")
        self.lbl_router_load = ctk.CTkLabel(router_grid_frame, text="Нагрузка: ---", anchor="w")
        self.lbl_router_load.grid(row=3, column=1, padx=5, pady=2, sticky="w")

        # График скорости интернета
        self.fig = Figure(figsize=(6, 3), dpi=100, facecolor='#2b2b2b')
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor('#1e1e1e')
        self.ax.tick_params(colors='white')
        self.ax.spines['bottom'].set_color('white')
        self.ax.spines['left'].set_color('white')
        self.ax.set_title(f"Текущая скорость интернета", color='white')
        self.ax.set_xlabel("Скорость приема (Мбит/с)", color='white')
        self.ax.set_ylabel("Скорость передачи (Мбит/с)", color='white')
        self.ax.grid(color='#444', linestyle=':', linewidth=0.5)

        self.canvas = FigureCanvasTkAgg(self.fig, master=tab_dashboard)
        self.canvas.get_tk_widget().pack(fill="x", padx=20, pady=15)

        # ==================== Вкладка Сеть ====================
        # Сканованные WiFi сети
        ctk.CTkLabel(tab_network, text="📶 Доступные WiFi сети", font=("Arial", 14)).pack(pady=5)
        cols_wifi = ("SSID", "Канал", "Сигнал %", "Защита")
        self.tree_wifi = ttk.Treeview(tab_network, columns=cols_wifi, show="headings", height=8)
        for col in cols_wifi:
            self.tree_wifi.heading(col, text=col)
            self.tree_wifi.column(col, anchor="center") # Выравнивание по центру
        self.tree_wifi.pack(fill="x", padx=20, pady=5)
        # Стилизация ttk Treeview для темной темы
        style = ttk.Style()
        style.theme_use("clam") # 'clam' или 'alt' лучше поддаются стилизации
        style.configure("Treeview", 
                        background="#2b2b2b", 
                        foreground="white", 
                        fieldbackground="#2b2b2b",
                        bordercolor="#444",
                        lightcolor="#444",
                        darkcolor="#222")
        style.map('Treeview', background=[('selected', '#3a7ebf')]) # Цвет выделения
        style.configure("Treeview.Heading", 
                        background="#333", 
                        foreground="white", 
                        font=("Arial", 10, "bold"), 
                        relief="flat")
        style.map("Treeview.Heading", background=[('active', '#444')])


        # Подключенные устройства
        ctk.CTkLabel(tab_network, text="🔌 Подключенные устройства", font=("Arial", 14)).pack(pady=(15,5))
        cols_clients = ("IP", "MAC", "Интерфейс", "ОС")
        self.tree_clients = ttk.Treeview(tab_network, columns=cols_clients, show="headings")
        for col in cols_clients:
            self.tree_clients.heading(col, text=col)
            self.tree_clients.column(col, anchor="center")
        self.tree_clients.pack(fill="both", expand=True, padx=20, pady=5)

        # ==================== Вкладка Управление роутером ====================
        ctk.CTkLabel(tab_router, text="🖥️ Управление роутером", font=("Arial", 18)).pack(pady=15)
        
        # Информация о веб доступе
        web_info_frame = ctk.CTkFrame(tab_router)
        web_info_frame.pack(fill="x", padx=20, pady=10, ipady=10)
        ctk.CTkLabel(web_info_frame, text=f"Веб интерфейс монитора: http://127.0.0.1:{WEB_PORT}\n"
                                        f"Логин: {WEB_USER}\nПароль: {WEB_PASS}", 
                                        justify="left").pack(padx=15, anchor="w")

        # Универсальная команда для открытия браузера
        open_cmd = ""
        if platform.system() == "Windows":
            open_cmd = f"start http://127.0.0.1:{WEB_PORT}"
        elif platform.system() == "Darwin": # macOS
            open_cmd = f"open http://127.0.0.1:{WEB_PORT}"
        else: # Linux и другие Unix-подобные
            open_cmd = f"xdg-open http://127.0.0.1:{WEB_PORT}"

        ctk.CTkButton(tab_router, text="🌐 Открыть веб панель",
                    command=lambda: os.system(open_cmd)).pack(pady=10) 

        ctk.CTkButton(tab_router, text="🔄 Перезагрузить роутер",
                    fg_color="#dc2626", hover_color="#b91c1c",
                    command=self.reboot_router_gui).pack(pady=20) # Изменено имя функции

    def reboot_router_gui(self): # Изменено имя для избежания конфликта с Flask функцией
        global ssh_client
        if not ssh_client:
            messagebox.showerror("Ошибка", "Не установлено соединение с роутером по SSH")
            return
            return
        
        if messagebox.askyesno("Подтверждение", "Вы действительно хотите перезагрузить роутер? Это приведет к потере SSH соединения."):
            try:
                ssh_exec(ssh_client, "reboot &") # Запускаем в фоне
                messagebox.showinfo("Информация", "Роутер будет перезагружен через несколько секунд. SSH соединение будет потеряно.")
                # Сбрасываем ssh_client, чтобы worker_thread попытался переподключиться
                if ssh_client:
                    ssh_client.close()
                    ssh_client = None
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось отправить команду перезагрузки: {e}")

    def update_interface(self):
        try:
            if hasattr(self, 'lbl_inet_status'): # Убеждаемся, что интерфейс уже создан
                # Обновление статуса интернета
                self.lbl_inet_status.configure(
                    text=f"🌐 {data['inet_status']} | Публичный IP: {data['public_info']['query']} | "
                         f"Скорость: ↓{data['down_speed']:.1f} / ↑{data['up_speed']:.1f} Мбит/с"
                )

                # Обновление локальной системы
                self.lbl_local_cpu.configure(text=f"CPU: {data['local_stats']['cpu_usage']:.1f}%")
                self.prog_local_cpu.set(data['local_stats']['cpu_usage'] / 100.0)

                self.lbl_local_ram.configure(text=f"RAM: {data['local_stats']['ram_used']} / {data['local_stats']['ram_total']} ({data['local_stats']['ram_percent']:.1f}%)")
                self.prog_local_ram.set(data['local_stats']['ram_percent'] / 100.0)

                self.lbl_local_disk.configure(text=f"DISK: {data['local_stats']['disk_used']} / {data['local_stats']['disk_total']} ({data['local_stats']['disk_percent']:.1f}%)")
                self.prog_local_disk.set(data['local_stats']['disk_percent'] / 100.0)

                # Обновление информации о роутере
                self.lbl_router_model.configure(text=f"Модель: {data['router_stats']['model']}")
                self.lbl_router_os_ver.configure(text=f"ОС: {data['router_stats']['os_ver']}")
                self.lbl_router_cpu_info.configure(text=f"CPU: {data['router_stats']['cpu']}")
                self.lbl_router_cpu_usage.configure(text=f"Нагрузка CPU: {data['router_stats']['cpu_usage']}")
                try:
                    cpu_usage_val = float(data['router_stats']['cpu_usage'].replace('%', '')) / 100.0
                    self.prog_router_cpu.set(cpu_usage_val)
                except ValueError:
                    self.prog_router_cpu.set(0) # Устанавливаем в 0 или N/A при ошибке

                ram_total_router = data['router_stats']['ram_total']
                ram_free_router = data['router_stats']['ram_free']
                ram_used_router_display = "N/A"
                
                if "MB" in ram_total_router and "MB" in ram_free_router:
                    try:
                        total_mb = float(ram_total_router.replace(' MB', ''))
                        free_mb = float(ram_free_router.replace(' MB', ''))
                        used_mb = total_mb - free_mb
                        ram_used_router_display = f"{used_mb:.0f} MB"
                    except ValueError:
                        pass # Останется N/A

                self.lbl_router_ram_info.configure(text=f"RAM: {ram_used_router_display} / {ram_total_router} ({data['router_stats']['ram_used_percent']:.1f}%)")
                self.prog_router_ram.set(data['router_stats']['ram_used_percent'] / 100.0)

                self.lbl_router_uptime.configure(text=f"Время работы: {data['router_stats']['uptime']}")
                self.lbl_router_load.configure(text=f"Нагрузка: {data['router_stats']['load']}")

                # Обновление графика скорости
                self.ax.clear()
                self.ax.set_facecolor('#1e1e1e')
                self.ax.tick_params(colors='white')
                self.ax.spines['bottom'].set_color('white')
                self.ax.spines['left'].set_color('white')
                
                max_speed = max(data["down_speed"], data["up_speed"], 10) * 1.2 # Динамический лимит осей
                self.ax.set_xlim(0, max_speed)
                self.ax.set_ylim(0, max_speed)
                
                self.ax.scatter(data["down_speed"], data["up_speed"], c="#10b981", s=200, alpha=0.8, edgecolors="white")
                self.ax.set_title(f"Текущая скорость интернета", color='white')
                self.ax.set_xlabel("Скорость приема (Мбит/с)", color='white')
                self.ax.set_ylabel("Скорость передачи (Мбит/с)", color='white')
                self.ax.grid(color='#444', linestyle=':', linewidth=0.5)
                self.canvas.draw()

                # Обновление списка WiFi сетей
                for item in self.tree_wifi.get_children():
                    self.tree_wifi.delete(item)
                for net in data["scanned_networks"]:
                    self.tree_wifi.insert("", "end", values=(net['ssid'], net['chan'], net['sig'], net['sec']))

                # Обновление списка подключенных клиентов
                for item in self.tree_clients.get_children():
                    self.tree_clients.delete(item)
                for client in data["wifi_clients"]:
                    self.tree_clients.insert("", "end", values=(client['ip'], client['mac'], client['dev'], client['os']))

        except Exception as e:
            # print(f"Error in update_interface: {e}") # Отладочная информация, можно включить для дебага
            pass # Игнорируем ошибки отрисовки, чтобы приложение не падало

        # Повторное обновление через 500 мс для плавности
        self.after(500, self.update_interface)

# ===========================
# ЗАПУСК ПРИЛОЖЕНИЯ
# ===========================

if __name__ == "__main__": # Исправлено на __name__
    app = NetworkMonitor()
    app.mainloop()
    

