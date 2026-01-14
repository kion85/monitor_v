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
import logging
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from flask import Flask, render_template_string, request, redirect, url_for, session
from functools import wraps
import hashlib

# ==================================================
# 📝 ИНИЦИАЛИЗАЦИЯ СИСТЕМНОГО ЖУРНАЛА
# ==================================================
LOG_FILE = "networkos_system.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================================================
# ⚙️ НАСТРОЙКИ
# ==================================================
REFRESH_RATE = 2.0
HISTORY_LIMIT = 60
SSH_HOST = "192.168.1.1"
SSH_PORT = 22
SSH_USER = "root"
SSH_PASSWORD = "root"
SSH_TIMEOUT = 5
WEB_PORT = 5000
WEB_USER = "root"
WEB_PASS = "root"
LOADING_SCREEN_DELAY = 3.5  # Время показа экрана загрузки в секундах

# ==================================================
# 📦 ГЛОБАЛЬНЫЕ ДАННЫЕ
# ==================================================
down_history = [0] * HISTORY_LIMIT
up_history = [0] * HISTORY_LIMIT
current_download = 0.0
current_upload = 0.0

public_info = {'query': 'Загрузка...', 'isp': 'Загрузка...', 'city': '...', 'countryCode': '..'}
gateway_ip = None
local_interfaces = []
active_interface = "Неизвестно"

scanned_networks = []
saved_passwords = []

ssh_client = None
remote_stats = {
    "hostname": "Подключение...",
    "uptime": "-",
    "load": "-",
    "ram_total": "-",
    "ram_free": "-",
    "kernel": "-",
    "active_routes": "0",
    "cpu_cores": "-",
    "cpu_usage": "-",
    "os_info": "-",
    "mtu_info": "-",
    "wifi_info": "-"
}
remote_procs = []
wifi_clients = []

# ==================================================
# 🖥️ ФУНКЦИИ РАБОТЫ С ЛОКАЛЬНОЙ СИСТЕМОЙ
# ==================================================
def get_public_data():
    """Получение информации о публичном IP и провайдере"""
    try:
        logger.info("Запрос информации о публичном IP адресе")
        response = requests.get(
            'http://ip-api.com/json/?fields=status,query,isp,city,countryCode', 
            timeout=3
        )
        data = response.json()
        if data.get('status') == 'success':
            logger.info(f"Получена информация: IP={data['query']}, ISP={data['isp']}")
            return data
    except Exception as e:
        logger.error(f"Ошибка получения публичной информации: {str(e)}")
    return {'query': 'Оффлайн', 'isp': '-', 'city': '-', 'countryCode': '-'}

def get_gateway_info():
    """Определение IP адреса шлюза (без использования psutil.net_if_gateways)"""
    try:
        logger.info("Определение основного шлюза сети")
        if platform.system() == "Linux":
            with os.popen("ip route show default") as f:
                line = f.read()
                match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    gateway = match.group(1)
                    logger.info(f"Шлюз найден: {gateway}")
                    return gateway
        elif platform.system() == "Windows":
            with os.popen("route print 0.0.0.0") as f:
                for line in f.readlines():
                    if "0.0.0.0" in line and len(line.split()) > 2:
                        gateway = line.split()[2]
                        logger.info(f"Шлюз найден: {gateway}")
                        return gateway
    except Exception as e:
        logger.error(f"Ошибка определения шлюза: {str(e)}")
    return "Не найден"

def get_detailed_interfaces():
    """Полная информация о сетевых интерфейсах, включая MTU"""
    details = []
    active_iface = "Не активен"
    try:
        logger.info("Сканирование сетевых интерфейсов")
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, snics in addrs.items():
            is_up = "🟢 ВКЛ" if name in stats and stats[name].isup else "🔴 ВЫКЛ"
            
            info = {
                "name": name, 
                "status": is_up, 
                "ipv4": "-", 
                "ipv6": "-", 
                "netmask": "-", 
                "broadcast": "-", 
                "mtu": "-"
            }

            # Сбор IP адресов
            for snic in snics:
                if snic.family == socket.AF_INET:
                    info["ipv4"] = snic.address
                    info["netmask"] = snic.netmask
                    info["broadcast"] = snic.broadcast if snic.broadcast else "-"
                    if snic.address != '127.0.0.1' and is_up == "🟢 ВКЛ":
                        active_iface = f"{name} ({is_up})"
                elif snic.family == socket.AF_INET6:
                    info["ipv6"] = snic.address.split('%')[0]

            # Получение MTU
            if name in stats:
                info["mtu"] = str(stats[name].mtu)

            details.append(info)
        logger.info(f"Найдено {len(details)} сетевых интерфейсов")
    except Exception as e:
        logger.error(f"Ошибка сканирования интерфейсов: {str(e)}")
        details.append({
            "name": "Ошибка", 
            "status": str(e), 
            "ipv4": "-", 
            "ipv6": "-", 
            "netmask": "-", 
            "broadcast": "-", 
            "mtu": "-"
        })
    return details, active_iface

def scan_wifi_channels():
    """Сканирование доступных Wi-Fi сетей"""
    networks = []
    try:
        logger.info("Сканирование Wi-Fi сетей")
        if platform.system() == "Linux":
            cmd = ["nmcli", "-t", "-f", "SSID,CHAN,SIGNAL,SECURITY,BARS", "dev", "wifi"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode('utf-8')
            
            for line in output.splitlines():
                parts = line.split(":")
                if len(parts) >= 5:
                    networks.append({
                        "ssid": parts[0] if parts[0] else "Скрытая сеть",
                        "chan": parts[1],
                        "signal": parts[2],
                        "sec": parts[3],
                        "bars": parts[4]
                    })
        logger.info(f"Найдено {len(networks)} Wi-Fi сетей")
    except Exception as e:
        logger.error(f"Ошибка сканирования Wi-Fi: {str(e)}")
        networks.append({"ssid": "Ошибка сканирования", "chan": "-", "signal": "-", "sec": "-", "bars": ""})
    return networks

def get_saved_wifi_passwords():
    """Получение сохраненных паролей Wi-Fi"""
    creds = []
    try:
        if os.geteuid() != 0:
            return [{"ssid": "Требуются права root", "psk": "Запустите приложение через sudo"}]
            
        path = "/etc/NetworkManager/system-connections/"
        files = glob.glob(os.path.join(path, "*.nmconnection"))
        for file in files:
            try:
                with open(file, 'r') as f:
                    content = f.read()
                    id_match = re.search(r'^id=(.*)\(', content, re.MULTILINE)
                    psk_match = re.search(r'^psk=(.*)\)', content, re.MULTILINE)
                    
                    if id_match and psk_match:
                        creds.append({
                            "ssid": id_match.group(1),
                            "psk": psk_match.group(1)
                        })
            except Exception as e:
                logger.warning(f"Не удалось прочитать файл {file}: {str(e)}")
    except Exception as e:
        logger.error(f"Ошибка получения паролей Wi-Fi: {str(e)}")
    return creds

# ==================================================
# 🖧 ФУНКЦИИ РАБОТЫ С РОУТЕРОМ ЧЕРЕЗ SSH
# ==================================================
def ssh_connect():
    """Установление SSH соединения с роутером"""
    global ssh_client
    try:
        logger.info(f"Попытка подключения к роутеру {SSH_HOST}:{SSH_PORT}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT,
            username=SSH_USER,
            password=SSH_PASSWORD,
            timeout=SSH_TIMEOUT,
            banner_timeout=SSH_TIMEOUT
        )
        logger.info("SSH соединение с роутером установлено")
        return client
    except Exception as e:
        logger.error(f"Не удалось подключиться по SSH: {str(e)}")
        return None

def ssh_exec(client, command):
    """Выполнение команды на роутере по SSH"""
    if not client or not client.get_transport().is_active():
        return ""
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=SSH_TIMEOUT)
        error = stderr.read().decode('utf-8').strip()
        if error:
            logger.warning(f"Ошибка выполнения команды '{command}': {error}")
        return stdout.read().decode('utf-8').strip()
    except Exception as e:
        logger.error(f"Не удалось выполнить SSH команду: {str(e)}")
        return ""

def get_router_full_stats(client):
    """Полная диагностическая информация о роутере"""
    stats = remote_stats.copy()
    try:
        logger.info("Сбор информации о роутере")
        
        # Основная информация
        stats['hostname'] = ssh_exec(client, "hostname")
        stats['kernel'] = ssh_exec(client, "uname -r")
        stats['os_info'] = ssh_exec(client, "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"' || cat /etc/openwrt_release 2>/dev/null | grep DISTRIB_DESCRIPTION | cut -d'=' -f2 | tr -d '\"'")
        
        # Информация о процессоре
        stats['cpu_cores'] = ssh_exec(client, "nproc")
        cpu_usage = ssh_exec(client, "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'")
        stats['cpu_usage'] = f"{cpu_usage}%" if cpu_usage else "Неизвестно"
        
        # Время работы и нагрузка
        up_raw = ssh_exec(client, "uptime")
        if "up" in up_raw:
            stats['uptime'] = up_raw.split("up")[1].split(",")[0].strip()
            stats['load'] = up_raw.split("load average:")[-1].strip()
        
        # Информация об оперативной памяти
        mem_out = ssh_exec(client, "free -m")
        if mem_out:
            lines = mem_out.splitlines()
            if len(lines) > 1:
                parts = lines[1].split()
                stats['ram_total'] = f"{parts[1]} MB"
                stats['ram_free'] = f"{parts[3]} MB"
        
        # Сетевые параметры
        stats['active_routes'] = ssh_exec(client, "ip route | wc -l")
        stats['mtu_info'] = ssh_exec(client, "ip link show | grep mtu")
        stats['wifi_info'] = ssh_exec(client, "iw dev 2>/dev/null | grep -E 'Interface|addr' || iwconfig 2>/dev/null | head -10")
        
    except Exception as e:
        logger.error(f"Ошибка сбора информации о роутере: {str(e)}")
    return stats

def get_router_processes(client):
    """Получение самых нагружающих процессов"""
    try:
        out = ssh_exec(client, "ps aux --sort=-%cpu | head -15")
        return out.splitlines()
    except Exception as e:
        logger.error(f"Ошибка получения списка процессов: {str(e)}")
        return ["Не удалось получить данные"]

def get_router_clients(client):
    """Получение списка подключенных клиентов"""
    clients = []
    try:
        # ARP таблица
        arp = ssh_exec(client, "cat /proc/net/arp")
        for line in arp.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6 and parts[3] != "00:00:00:00:00:00":
                clients.append({
                    "ip": parts[0], 
                    "mac": parts[3], 
                    "dev": parts[5]
                })
        
        # Дополнительная информация по Wi-Fi клиентам
        wifi_clients = ssh_exec(client, "iw dev wlan0 station dump 2>/dev/null || iw dev wlan1 station dump 2>/dev/null")
        if wifi_clients:
            current_mac = None
            for line in wifi_clients.splitlines():
                if "Station" in line:
                    current_mac = line.split()[1]
                elif "signal:" in line and current_mac:
                    signal = line.split()[1]
                    clients.append({
                        "ip": "N/A", 
                        "mac": current_mac, 
                        "dev": f"Wi-Fi ({signal} dBm)"
                    })
                    
    except Exception as e:
        logger.error(f"Ошибка получения списка клиентов: {str(e)}")
    return clients

def send_router_reboot():
    """Отправка команды перезагрузки роутера"""
    global ssh_client
    logger.warning("Попытка перезагрузки роутера по запросу пользователя")
    if ssh_client and ssh_client.get_transport().is_active():
        try:
            ssh_exec(ssh_client, "reboot &")
            logger.critical("Команда перезагрузки роутера отправлена")
            return True
        except Exception as e:
            logger.error(f"Не удалось отправить команду перезагрузки: {str(e)}")
    return False

# ==================================================
# 🌐 ВЕБ ИНТЕРФЕЙС С АВТОРИЗАЦИЕЙ
# ==================================================
app = Flask(__name__)
app.secret_key = "NetworkOS_Super_Secret_Key_2024"

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == WEB_USER and password == WEB_PASS:
            session['authenticated'] = True
            logger.info(f"Успешная авторизация в веб-интерфейсе пользователем {username}")
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Неуспешная попытка авторизации: {username}")
            return render_template_string(LOGIN_PAGE, error="Неверное имя пользователя или пароль")
    return render_template_string(LOGIN_PAGE)

@app.route('/logout')
def logout():
    session.clear()
    logger.info("Пользователь вышел из веб-интерфейса")
    return redirect(url_for('login'))

@app.route('/reboot', methods=['POST'])
@auth_required
def reboot():
    if send_router_reboot():
        return "✅ Команда перезагрузки отправлена"
    return "❌ Не удалось отправить команду"

@app.route('/')
@auth_required
def dashboard():
    return render_template_string(WEB_DASHBOARD,
        public=public_info,
        active_iface=active_interface,
        download=f"{current_download:.2f}",
        upload=f"{current_upload:.2f}",
        router=remote_stats,
        wifi_networks=scanned_networks,
        clients=wifi_clients,
        processes=remote_procs,
        interfaces=local_interfaces,
        down_history=down_history,
        up_history=up_history,
        history_len=HISTORY_LIMIT
    )

# HTML Шаблоны веб интерфейса
LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>NetworkOS - Авторизация</title>
    <style>
        body { background: #121212; color: #00ff00; font-family: monospace; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin:0;}
        .login-box { background: #1e1e1e; padding: 40px; border-radius: 10px; border: 1px solid #333; width: 320px; }
        h2 { text-align:center; margin-bottom:30px; }
        .input-field { width: 100%; margin: 10px 0; padding: 12px; background: #2d2d2d; border:1px solid #444; border-radius:5px; color:white; box-sizing: border-box; }
        .login-btn { width:100%; padding:12px; background: #00aa00; color:white; border:none; border-radius:5px; cursor:pointer; font-weight:bold; margin-top:10px; }
        .login-btn:hover { background: #00cc00; }
        .error { color: #ff4444; text-align:center; margin-top:15px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔐 NetworkOS Admin</h2>
        <form method="POST">
            <input type="text" name="username" class="input-field" placeholder="Логин (root)" required>
            <input type="password" name="password" class="input-field" placeholder="Пароль (root)" required>
            <button type="submit" class="login-btn">Войти</button>
        </form>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
    </div>
</body>
</html>
"""

WEB_DASHBOARD = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>NetworkOS - Панель управления</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin:0; padding:0; box-sizing: border-box; }
        body { background: #121212; color: #00ff00; font-family: 'Courier New', monospace; padding:20px; }
        .header { display:flex; justify-content: space-between; align-items:center; margin-bottom:20px; padding-bottom:15px; border-bottom:1px solid #333; }
        .logout { background:#333; color:white; padding:8px 16px; border-radius:4px; text-decoration:none; }
        .card { background:#1e1e1e; border:1px solid #333; border-radius:8px; padding:20px; margin-bottom:20px; }
        h2 { color:white; border-bottom:1px solid #444; padding-bottom:8px; margin-bottom:15px; }
        .grid-2 { display:grid; grid-template-columns: 1fr 1fr; gap:20px; }
        .grid-3 { display:grid; grid-template-columns: repeat(3, 1fr); gap:15px; }
        .stat-item { background:#252525; padding:12px; border-radius:6px; border-left:3px solid #00aa00; }
        .red { color:#ff5555; } .blue { color:#55aaff; } .green { color:#55ff55; }
        table { width:100%; border-collapse:collapse; margin-top:10px; }
        th, td { border:1px solid #444; padding:8px; text-align:left; font-size:0.9em; }
        th { background:#2d2d2d; color:white; }
        .reboot-btn { background:#aa0000; color:white; border:none; padding:12px 24px; border-radius:6px; cursor:pointer; font-weight:bold; margin-top:15px; }
        .reboot-btn:hover { background:#cc0000; }
        .chart { height:250px; width:100%; margin-top:10px; }
        pre { background:#2d2d2d; padding:15px; border-radius:6px; overflow-x:auto; max-height:300px; }
        
        @media (max-width: 992px) {
            .grid-2, .grid-3 { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🖥️ NetworkOS // Панель управления</h1>
        <a href="/logout" class="logout">🚪 Выйти</a>
    </div>

    <div class="grid-3">
        <div class="stat-item"><strong>🌐 Публичный IP:</strong> <span class="blue">{{ public.query }}</span></div>
        <div class="stat-item"><strong>📡 Провайдер:</strong> {{ public.isp }}</div>
        <div class="stat-item"><strong>📍 Местоположение:</strong> {{ public.city }}, {{ public.countryCode }}</div>
        <div class="stat-item red"><strong>⬇️ Скачивание:</strong> {{ download }} Mbps</div>
        <div class="stat-item blue"><strong>⬆️ Загрузка:</strong> {{ upload }} Mbps</div>
        <div class="stat-item"><strong>🔌 Интерфейс:</strong> {{ active_iface }}</div>
    </div>

    <div class="grid-2">
        <div class="card">
            <h2>📊 Мониторинг трафика</h2>
            <canvas id="trafficChart" class="chart"></canvas>
        </div>

        <div class="card">
            <h2>🖧 Состояние роутера</h2>
            <p><strong>Имя хоста:</strong> {{ router.hostname }}</p>
            <p><strong>Операционная система:</strong> {{ router.os_info }}</p>
            <p><strong>Ядро:</strong> {{ router.kernel }}</p>
            <p><strong>Время работы:</strong> {{ router.uptime }}</p>
            <p><strong>Нагрузка CPU:</strong> {{ router.cpu_usage }} ({{ router.cpu_cores }} ядер)</p>
            <p><strong>Оперативная память:</strong> {{ router.ram_free }} свободно / {{ router.ram_total }} всего</p>
            <form action="/reboot" method="POST" onsubmit="return confirm('⚠️ Вы действительно хотите перезагрузить роутер?')">
                <button type="submit" class="reboot-btn">🔄 ПЕРЕЗАГРУЗИТЬ РОУТЕР</button>
            </form>
        </div>
    </div>

    <div class="card">
        <h2>🔗 Сетевые интерфейсы</h2>
        <table>
            <tr><th>Имя</th><th>Статус</th><th>IPv4</th><th>IPv6</th><th>MTU</th></tr>
            {% for iface in interfaces %}
            <tr>
                <td>{{ iface.name }}</td>
                <td {% if "🟢" in iface.status %}class="green"{% else %}class="red"{% endif %}>{{ iface.status }}</td>
                <td>{{ iface.ipv4 }}</td>
                <td style="font-size:0.8em;">{{ iface.ipv6 }}</td>
                <td>{{ iface.mtu }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="grid-2">
        <div class="card">
            <h2>📶 Доступные Wi-Fi сети</h2>
            <table>
                <tr><th>SSID</th><th>Канал</th><th>Сигнал</th><th>Защита</th></tr>
                {% for net in wifi_networks %}
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
            <h2>👥 Подключенные клиенты</h2>
            <table>
                <tr><th>IP адрес</th><th>MAC адрес</th><th>Интерфейс</th></tr>
                {% for client in clients %}
                <tr>
                    <td>{{ client.ip }}</td>
                    <td>{{ client.mac }}</td>
                    <td>{{ client.dev }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </div>

    <div class="card">
        <h2>⚙️ Процессы на роутере</h2>
        <pre>{% for proc in processes %}{{ proc }}
{% endfor %}</pre>
    </div>

    <script>
        // График трафика
        const ctx = document.getElementById('trafficChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array.from({length: {{ history_len }}}, (_, i) => i),
                datasets: [
                    {
                        label: 'Скачивание Mbps',
                        data: {{ down_history }},
                        borderColor: '#ff5555',
                        backgroundColor: 'rgba(255, 85, 85, 0.1)',
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'Загрузка Mbps',
                        data: {{ up_history }},
                        borderColor: '#55aaff',
                        backgroundColor: 'rgba(85, 170, 255, 0.1)',
                        tension: 0.4,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    x: { grid: { color: '#333' }, ticks: { color: '#888' } },
                    y: { grid: { color: '#333' }, ticks: { color: '#888' }, beginAtZero: true }
                },
                plugins: { legend: { labels: { color: '#fff' } } }
            }
        });

        // Автоматическое обновление страницы
        setTimeout(() => window.location.reload(), 5000);
    </script>
</body>
</html>
"""

def run_web_server():
    """Запуск веб-сервера в отдельном потоке"""
    try:
        logger.info(f"Запуск веб-сервера на порту {WEB_PORT}")
        import logging as flask_log
        flask_log.getLogger('werkzeug').setLevel(flask_log.ERROR)
        app.run(host='0.0.0.0', port=WEB_PORT, debug=False, use_reloader=False)
    except Exception as e:
        logger.critical(f"Не удалось запустить веб-сервер: {str(e)}")

# ==================================================
# 🔄 ФОНОВЫЙ ПОТОК СБОРА ДАННЫХ
# ==================================================
last_io = psutil.net_io_counters()
last_time = time.time()

def background_data_collector():
    """Постоянный сбор сетевой информации в фоне"""
    global current_download, current_upload, last_io, last_time
    global public_info, gateway_ip, scanned_networks, saved_passwords
    global local_interfaces, active_interface, ssh_client
    global remote_stats, remote_procs, wifi_clients

    # Инициализация при старте
    public_info = get_public_data()
    gateway_ip = get_gateway_info()
    ssh_client = ssh_connect()
    local_interfaces, active_interface = get_detailed_interfaces()

    counter = 0
    logger.info("Фоновый поток сбора данных запущен")
    
    while True:
        try:
            # 1. Мониторинг скорости интернета
            now = time.time()
            io_now = psutil.net_io_counters()
            dt = max(now - last_time, 0.1)
            
            # Расчет скорости в Mbps
            current_download = (io_now.bytes_recv - last_io.bytes_recv) * 8 / 1_000_000 / dt
            current_upload = (io_now.bytes_sent - last_io.bytes_sent) * 8 / 1_000_000 / dt
            
            # Обновление истории
            down_history.append(current_download)
            up_history.append(current_upload)
            down_history[:] = down_history[-HISTORY_LIMIT:]
            up_history[:] = up_history[-HISTORY_LIMIT:]
            
            last_io = io_now
            last_time = now

            # 2. Обновление тяжелых данных не так часто
            if counter % 3 == 0:
                local_interfaces, active_interface = get_detailed_interfaces()
                scanned_networks = scan_wifi_channels()
            
            if counter % 5 == 0:
                saved_passwords = get_saved_wifi_passwords()
                
                # Поддержание SSH соединения
                if ssh_client:
                    if not ssh_client.get_transport() or not ssh_client.get_transport().is_active():
                        logger.info("Переподключение по SSH")
                        ssh_client = ssh_connect()
                
                if ssh_client and ssh_client.get_transport().is_active():
                    remote_stats = get_router_full_stats(ssh_client)
                    remote_procs = get_router_processes(ssh_client)
                    wifi_clients = get_router_clients(ssh_client)

            counter += 1
            time.sleep(REFRESH_RATE)
            
        except Exception as e:
            logger.critical(f"Критическая ошибка в фоновом потоке: {str(e)}")
            time.sleep(REFRESH_RATE)

# ==================================================
# 🎨 ГРАФИЧЕСКИЙ ИНТЕРФЕЙС ПРИЛОЖЕНИЯ
# ==================================================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

class LoadingWindow(ctk.CTkToplevel):
    """Экран загрузки приложения"""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("NetworkOS • Загрузка")
        self.geometry("450x220")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        
        # Центрирование окна
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (self.winfo_width() // 2)
        y = (self.winfo_screenheight() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

        # Содержимое
        ctk.CTkLabel(self, text="🚀 NetworkOS", font=("Consolas", 28, "bold")).pack(pady=(30, 10))
        self.progress = ctk.CTkProgressBar(self, width=350)
        self.progress.pack(pady=10)
        self.status_label = ctk.CTkLabel(self, text="Инициализация системы...", font=("Consolas", 12))
        self.status_label.pack(pady=10)

        self.grab_set()
        self.steps = [
            "Инициализация сетевых модулей",
            "Подключение к роутеру",
            "Сканирование интерфейсов",
            "Запуск веб-сервера",
            "Готово!"
        ]
        self.current_step = 0

    def update_step(self):
        if self.current_step < len(self.steps):
            self.progress.set((self.current_step + 1) / len(self.steps))
            self.status_label.configure(text=self.steps[self.current_step])
            self.current_step += 1
            return True
        return False

class MainApplication(ctk.CTk):
    """Основное окно приложения"""
    def __init__(self):
        super().__init__()
        self.title("NetworkOS • Управление сетью")
        self.geometry("1300x850")
        self.minsize(1000, 700)

        # Определение локального IP для ссылки на веб интерфейс
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
        except:
            self.local_ip = "127.0.0.1"

        # Создание вкладок
        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.tab_dashboard = self.tab_view.add("📊 Дашборд")
        self.tab_interfaces = self.tab_view.add("🔗 Интерфейсы")
        self.tab_router = self.tab_view.add("🖧 Роутер")
        self.tab_wifi = self.tab_view.add("📶 Wi-Fi")
        self.tab_logs = self.tab_view.add("📋 Системный журнал")

        # Настройка вкладок
        self.setup_dashboard()
        self.setup_interfaces()
        self.setup_router()
        self.setup_wifi()
        self.setup_logs()

        # Запуск обновления интерфейса
        self.schedule_ui_update()

    def setup_dashboard(self):
        """Вкладка с основным дашбордом"""
        # Информационная панель
        self.info_frame = ctk.CTkFrame(self.tab_dashboard)
        self.info_frame.pack(fill="x", padx=10, pady=10)
        
        self.info_label = ctk.CTkLabel(
            self.info_frame, 
            text="Инициализация...", 
            font=("Consolas", 14),
            justify="left"
        )
        self.info_label.pack(padx=15, pady=15, fill="x")

        # График трафика
        self.fig = Figure(figsize=(12, 5), dpi=100, facecolor='#2b2b2b')
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor('#2b2b2b')
        self.ax.tick_params(colors='white')
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.tab_dashboard)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=5)

        # Ссылка на веб интерфейс
        self.web_label = ctk.CTkLabel(
            self.tab_dashboard,
            text=f"🌐 Веб панель: http://{self.local_ip}:{WEB_PORT}",
            text_color="#55aaff",
            font=("Consolas", 12)
        )
        self.web_label.pack(pady=10)

    def setup_interfaces(self):
        """Вкладка с информацией о сетевых интерфейсах"""
        self.iface_text = ctk.CTkTextbox(self.tab_interfaces, font=("Consolas", 11))
        self.iface_text.pack(fill="both", expand=True, padx=10, pady=10)

    def setup_router(self):
        """Вкладка управления роутером"""
        # Информация о роутере
        self.router_info = ctk.CTkLabel(
            self.tab_router,
            text="Ожидание подключения...",
            font=("Consolas", 13),
            justify="left"
        )
        self.router_info.pack(fill="x", padx=10, pady=10)

        # Кнопка перезагрузки
        self.reboot_btn = ctk.CTkButton(
            self.tab_router,
            text="🔄 Перезагрузить роутер",
            fg_color="#aa0000",
            hover_color="#cc0000",
            command=self.confirm_reboot
        )
        self.reboot_btn.pack(pady=10)

        # Список процессов
        ctk.CTkLabel(self.tab_router, text="⚙️ Активные процессы", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(15,5))
        self.proc_text = ctk.CTkTextbox(self.tab_router, height=150, font=("Consolas", 11))
        self.proc_text.pack(fill="x", padx=10, pady=5)

        # Список клиентов
        ctk.CTkLabel(self.tab_router, text="👥 Подключенные клиенты", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(15,5))
        self.clients_text = ctk.CTkTextbox(self.tab_router, height=150, font=("Consolas", 11))
        self.clients_text.pack(fill="x", padx=10, pady=5)

    def setup_wifi(self):
        """Вкладка с информацией о Wi-Fi"""
        # Две колонки
        self.wifi_grid = ctk.CTkFrame(self.tab_wifi)
        self.wifi_grid.pack(fill="both", expand=True, padx=10, pady=10)
        self.wifi_grid.grid_columnconfigure(0, weight=1)
        self.wifi_grid.grid_columnconfigure(1, weight=1)

        # Левая колонка: сканированные сети
        left_frame = ctk.CTkFrame(self.wifi_grid)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        ctk.CTkLabel(left_frame, text="📶 Доступные сети", font=("Arial", 12, "bold")).pack(pady=5)
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#333", foreground="white", fieldbackground="#333", borderwidth=0)
        style.map('Treeview', background=[('selected', '#1f538d')])

        self.wifi_tree = ttk.Treeview(left_frame, columns=("ssid", "chan", "sig", "sec"), show="headings", height=15)
        self.wifi_tree.heading("ssid", text="SSID")
        self.wifi_tree.heading("chan", text="Канал")
        self.wifi_tree.heading("sig", text="Сигнал")
        self.wifi_tree.heading("sec", text="Защита")
        
        self.wifi_tree.column("ssid", width=200)
        self.wifi_tree.column("chan", width=60)
        self.wifi_tree.column("sig", width=80)
        self.wifi_tree.column("sec", width=100)
        self.wifi_tree.pack(fill="both", expand=True, padx=5, pady=5)

        # Правая колонка: сохраненные пароли
        right_frame = ctk.CTkFrame(self.wifi_grid)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        ctk.CTkLabel(right_frame, text="🔑 Сохраненные пароли", font=("Arial", 12, "bold")).pack(pady=5)
        self.pass_text = ctk.CTkTextbox(right_frame, font=("Consolas", 11))
        self.pass_text.pack(fill="both", expand=True, padx=5, pady=5)

    def setup_logs(self):
        """Вкладка с системным журналом"""
        self.log_text = ctk.CTkTextbox(self.tab_logs, font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.refresh_logs()

    def confirm_reboot(self):
        """Подтверждение перезагрузки роутера"""
        if messagebox.askyesno("⚠️ Внимание", "Вы действительно хотите перезагрузить роутер?\nСетевое соединение будет временно прервано!"):
            if send_router_reboot():
                messagebox.showinfo("✅ Успех", "Команда перезагрузки отправлена!\nРоутер перезагрузится в течение нескольких секунд.")
            else:
                messagebox.showerror("❌ Ошибка", "Не удалось отправить команду перезагрузки.\nПроверьте соединение с роутером.")

    def refresh_logs(self):
        """Обновление системного журнала"""
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    last_lines = lines[-50:]
                    self.log_text.delete("0.0", "end")
                    self.log_text.insert("0.0", "".join(last_lines))
                    self.log_text.see("end")
        except Exception as e:
            logger.error(f"Не удалось обновить журнал: {str(e)}")
        self.after(5000, self.refresh_logs)

    def update_ui(self):
        """Обновление информации в интерфейсе"""
        try:
            # Обновление дашборда
            info_text = (
                f"🌐 Публичный IP: {public_info['query']}\n"
                f"📡 Провайдер: {public_info['isp']}\n"
                f"📍 Местоположение: {public_info['city']}, {public_info['countryCode']}\n"
                f"🖥️ Шлюз: {gateway_ip}\n"
                f"🔌 Активный интерфейс: {active_interface}\n"
                f"🔴 ⬇️ Скачивание: {current_download:.2f} Mbps\n"
                f"🔵 ⬆️ Загрузка: {current_upload:.2f} Mbps"
            )
            self.info_label.configure(text=info_text)

            # Обновление графика трафика
            self.ax.clear()
            self.ax.plot(down_history, label="⬇️ Скачивание", color="#ff5555", linewidth=2)
            self.ax.plot(up_history, label="⬆️ Загрузка", color="#55aaff", linewidth=2)
            self.ax.legend(facecolor='#2b2b2b', labelcolor='white')
            self.ax.set_facecolor('#2b2b2b')
            self.ax.grid(True, alpha=0.3)
            self.ax.set_ylabel("Скорость, Mbps", color='white')
            self.canvas.draw()

            # Обновление информации об интерфейсах
            self.iface_text.delete("0.0", "end")
            for iface in local_interfaces:
                self.iface_text.insert("end", f"📶 [{iface['name']}]\n")
                self.iface_text.insert("end", f"   Статус: {iface['status']}\n")
                self.iface_text.insert("end", f"   IPv4: {iface['ipv4']}\n")
                self.iface_text.insert("end", f"   IPv6: {iface['ipv6']}\n")
                self.iface_text.insert("end", f"   MTU: {iface['mtu']}\n")
                self.iface_text.insert("end", "-"*60 + "\n")

            # Обновление информации о роутере
            router_text = (
                f"🖧 Имя хоста: {remote_stats['hostname']}\n"
                f"💻 Операционная система: {remote_stats['os_info']}\n"
                f"⚙️ Ядро: {remote_stats['kernel']}\n"
                f"⏱️ Время работы: {remote_stats['uptime']}\n"
                f"💽 Нагрузка CPU: {remote_stats['cpu_usage']} ({remote_stats['cpu_cores']} ядер)\n"
                f"🧠 Оперативная память: {remote_stats['ram_free']} свободно / {remote_stats['ram_total']} всего\n"
                f"🔗 Активных маршрутов: {remote_stats['active_routes']}"
            )
            self.router_info.configure(text=router_text)

            # Обновление процессов и клиентов
            self.proc_text.delete("0.0", "end")
            self.proc_text.insert("0.0", "\n".join(remote_procs))
            
            self.clients_text.delete("0.0", "end")
            for client in wifi_clients:
                self.clients_text.insert("end", f"🖥️ {client['ip']:16} | 📱 {client['mac']} | {client['dev']}\n")

            # Обновление Wi-Fi информации
            for item in self.wifi_tree.get_children():
                self.wifi_tree.delete(item)
            for net in scanned_networks:
                self.wifi_tree.insert("", "end", values=(net['ssid'], net['chan'], f"{net['signal']}% {net['bars']}", net['sec']))

            # Обновление сохраненных паролей
            self.pass_text.delete("0.0", "end")
            for cred in saved_passwords:
                self.pass_text.insert("end", f"📶 {cred['ssid']}\n")
                self.pass_text.insert("end", f"   🔑 {cred['psk']}\n")
                self.pass_text.insert("end", "-"*40 + "\n")

        except Exception as e:
            logger.error(f"Ошибка обновления интерфейса: {str(e)}")

    def schedule_ui_update(self):
        """Планирование регулярного обновления интерфейса"""
        self.update_ui()
        self.after(int(REFRESH_RATE * 1000), self.schedule_ui_update)

# ==================================================
# 🚀 ЗАПУСК ПРИЛОЖЕНИЯ
# ==================================================
def main():
    logger.info("==================================")
    logger.info("🚀 Запуск NetworkOS Control Panel")
    logger.info(f"🖥️ Операционная система: {platform.system()} {platform.release()}")
    logger.info("==================================")

    # Запуск фоновых потоков
    threading.Thread(target=background_data_collector, daemon=True).start()
    threading.Thread(target=run_web_server, daemon=True).start()

    # Создание приложения и экрана загрузки
    app = MainApplication()
    app.withdraw()  # Скрываем основное окно на время загрузки
    
    loading = LoadingWindow(app)

    # Имитация процесса загрузки
    def load_sequence():
        for _ in range(5):
            loading.update_step()
            time.sleep(LOADING_SCREEN_DELAY / 5)
        
        loading.destroy()
        app.deiconify()  # Показываем основное окно
        logger.info("Приложение готово к работе")

    threading.Thread(target=load_sequence, daemon=True).start()

    # Запуск основного цикла приложения
    app.mainloop()
    logger.info("📌 Приложение закрыто")

if __name__ == "__main__":
    # Проверка прав root для некоторых функций
    if os.geteuid() != 0:
        print("⚠️ ВНИМАНИЕ: Для полной функциональности рекомендуется запустить приложение с правами root (sudo)")
        logger.warning("Приложение запущено без прав root, некоторые функции будут недоступны")
    
    try:
        main()
    except Exception as e:
        logger.critical(f"Критическая ошибка при запуске приложения: {str(e)}")
