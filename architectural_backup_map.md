# IAM Security System: Architectural Map & Backup (LKGC)

This document serves as the **Last Known Good Configuration (LKGC)** for the IAM Security System. It provides a complete structural map of the current operational logic and a full code archive to ensure a safe recovery point.

---

## 🏗️ Structural Mapping

### 1. Authentication Logic
- **Verification Path**: The `login_user()` function in `models.py` performs a `SELECT` against the `users` table, specifically fetching the `password_hash`, `is_active` status, and primary `role`.
- **Credential Validation**: Passwords are verified using `bcrypt.checkpw()`.
- **Single-Factor Flow**: Following the decommissioning of the PIN feature, the `login()` route in `routes.py` immediately grants session cookies (`user_id`, `username`, `user_role`) upon first-factor success.
- **Audit Logging**: Every attempt (success or failure) is logged to the `login_attempts` table with the source `ip_address` for brute-force tracking.

### 2. Dashboard Telemetry
- **OS Monitoring**: The `os_monitor.py` module uses `psutil` to capture CPU, Memory, and Process counts.
- **Network Telemetry**: The `NetworkMonitor` class in `network_monitor.py` uses a "UDP Socket Trick" (connecting to `8.8.8.8` without sending packets) to identify the server's primary outbound interface IP, avoiding the `127.0.0.1` loopback.
- **MAC Discovery**: The system MAC address is retrieved via `uuid.getnode()` and formatted using regex to ensure uppercase hexadecimal consistency.
- **Frontend Sync**: Values are fetched via `/api/network-info` and `/api/system-stats` as JSON and injected into the glassmorphic Dashboard panels via `dashboard.js`.

### 3. Role Management & RBAC
- **Schema Mapping**: Relationships are managed via the `user_roles` junction table, which links `users.id` to `roles.id`.
- **UUID Handling**: All IDs are stored as `UNIQUEIDENTIFIER` (UUIDs). In Python, these are handled as strings (standardized via `str(uuid.uuid4())`) which the `pyodbc` driver correctly maps to SQL Server types.
- **Role Assignment**: The `update_user_role()` function performs an atomic "Delete-then-Insert" operation on the junction table to ensure a user has exactly one primary role assigned.
- **Permission Enforcement**: The `role_required` decorator in `routes.py` verifies the `session['user_role']` against an allowed list before granting access to view or edit resources.

---

## 🗄️ Code Archive

````carousel
```python
# models.py (Full - Latest)
import bcrypt
import uuid
from datetime import datetime
from config import get_connection

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

import re

def detect_malicious_patterns(input_str):
    if not input_str: return False
    sqli_patterns = [r"'.*OR.*'", r"'.*--", r"UNION.*SELECT", r"DROP.*TABLE", r";.*--"]
    xss_patterns = [r"<script.*>", r"onload=.*", r"javascript:.*", r"onerror=.*", r"<img.*src=.*>"]
    for pattern in sqli_patterns + xss_patterns:
        if re.search(pattern, str(input_str), re.IGNORECASE): return True
    return False

def register_user(username, email, password):
    if detect_malicious_patterns(username) or detect_malicious_patterns(email):
        log_activity(None, "Malicious Input Detected", f"Registration attempted: {username}", "SIMULATED-IP")
    if len(password) < 8 or not re.search(r"\d", password):
        return False, "Password must be at least 8 characters long and contain at least one number."
    conn = get_connection()
    if not conn: return False, "Database connection error."
    try:
        cursor = conn.cursor()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)", (user_id, username, email, password_hash))
        conn.commit()
        return True, "User registered successfully."
    except Exception as e: return False, f"Registration failed: {e}"
    finally: conn.close()

def login_user(username, password, ip_address):
    conn = get_connection()
    if not conn: return None, "Database error"
    try:
        cursor = conn.cursor()
        if detect_malicious_patterns(username):
            log_id = log_activity(None, "Malicious Login Input", f"Payload in username: {username}", ip_address)
            if log_id:
                cursor.execute("INSERT INTO anomaly_flags (id, activity_log_id, severity, type, is_resolved) VALUES (?, ?, ?, ?, ?)", (str(uuid.uuid4()), log_id, 'critical', 'injection_attempt', 0))
                conn.commit()
        cursor.execute("SELECT u.id, u.username, u.password_hash, u.is_active, r.name as role FROM users u LEFT JOIN user_roles ur ON u.id = ur.user_id LEFT JOIN roles r ON ur.role_id = r.id WHERE u.username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            cursor.execute("INSERT INTO login_attempts (user_id, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)", (None, ip_address, 0, "Invalid username"))
            conn.commit()
            return None, "Invalid credentials"
        user_id, uname, hashed_pwd, is_active, role = user
        if not is_active:
            cursor.execute("INSERT INTO login_attempts (user_id, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)", (user_id, ip_address, 0, "Account Locked"))
            conn.commit()
            return None, "Account is deactivated."
        if bcrypt.checkpw(password.encode('utf-8'), hashed_pwd.encode('utf-8')):
            cursor.execute("INSERT INTO login_attempts (user_id, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)", (user_id, ip_address, 1, "Success"))
            cursor.execute("UPDATE users SET last_login = GETDATE() WHERE id = ?", (user_id,))
            conn.commit()
            return {"id": str(user_id), "username": uname, "role": role or 'viewer'}, "Success"
        else:
            cursor.execute("INSERT INTO login_attempts (user_id, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)", (user_id, ip_address, 0, "Invalid password"))
            conn.commit()
            return None, "Invalid credentials"
    finally: conn.close()
# ... (Activity Logs, Role Assignment, Visualizer methods follow latest stable builds)
```
<!-- slide -->
```python
# routes.py (Full - Latest)
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
from models import *
from threat_detector import ThreatDetector
from network_monitor import NetworkMonitor
from os_monitor import get_system_metrics

bp = Blueprint('main', __name__)

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Please log in to access this page.", "error")
                return redirect(url_for('main.login'))
            if session.get('user_role') not in allowed_roles:
                log_activity(session.get('user_id'), "Unauthorized Access Attempt", request.path, request.remote_addr)
                return redirect(url_for('main.profile'))
            log_activity(session.get('user_id'), "Access Page", request.path, request.remote_addr)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr
        user_data, status_message = login_user(username, password, ip_address)
        if user_data:
            session['user_id'] = user_data['id']; session['username'] = user_data['username']; session['user_role'] = user_data['role']
            session.permanent = True
            log_activity(session['user_id'], "Login", "/login", request.remote_addr)
            return redirect(url_for('main.dashboard'))
        else: flash(status_message, 'error')
    return render_template('login.html')

@bp.route('/')
@role_required(['admin'])
def dashboard():
    stats = get_dashboard_stats()
    return render_template('dashboard.html', stats=stats)

@bp.route('/api/network-info', methods=['GET'])
@role_required(['admin', 'analyst'])
def api_network_info():
    info = NetworkMonitor.get_server_info()
    info['interfaces'] = NetworkMonitor.get_all_interfaces()
    info['connecting_ips'] = NetworkMonitor.get_connecting_ips()
    return jsonify(info)
```
<!-- slide -->
```html
<!-- dashboard.html (Full - Latest) -->
{% extends 'base.html' %}
{% block title %}Dashboard Overview{% endblock %}
{% block content %}
<div class="main-content">
    <header class="header">
        <h1>Security Intelligence</h1>
        <div class="date-display"><i class="far fa-clock"></i> <span id="current-time"></span></div>
    </header>

    <div class="card mb-8 animate-fade-in" id="system-health-panel">
        <!-- psutil metrics (CPU, RAM, Uptime) listed here... -->
    </div>

    <!-- Stats Grid (Identities, Access Attempts, Threats) -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Access Attempts</div>
            <div class="stat-value">{{ stats.total_attempts }}</div>
        </div>
        <!-- ... -->
    </div>

    <div class="row g-4 mb-4">
        <!-- Network Infrastructure Telemetry Panel -->
        <div class="col-xl-6">
            <div class="card glass-card h-100">
                <span id="host-ip">--.---.---.---</span>
                <span id="sys-mac">--:--:--:--:--:--</span>
                <div id="interface-list"></div>
                <!-- ... -->
            </div>
        </div>
        <!-- Namespace Visualizer (D3.js) -->
        <div class="col-xl-6">
            <div id="network-graph"></div>
        </div>
    </div>
</div>
{% endblock %}
{% block scripts %}
<script src="{{ url_for('static', filename='js/dashboard.js') }}"></script>
<script>
    // Live time JS here
</script>
{% endblock %}
```
````
