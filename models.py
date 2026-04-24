import bcrypt
import uuid
from datetime import datetime
from config import get_connection

def hash_password(password):
    """Hashes a password with bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    """Verifies a password matching its hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

import re

def detect_malicious_patterns(input_str):
    """Detects common SQL Injection and XSS patterns in user input."""
    if not input_str: return False
    
    # SQL Injection Patterns
    sqli_patterns = [
        r"'.*OR.*'", r"'.*--", r"UNION.*SELECT", r"DROP.*TABLE", r";.*--"
    ]
    # XSS Patterns
    xss_patterns = [
        r"<script.*>", r"onload=.*", r"javascript:.*", r"onerror=.*", r"<img.*src=.*>"
    ]
    
    for pattern in sqli_patterns + xss_patterns:
        if re.search(pattern, str(input_str), re.IGNORECASE):
            return True
    return False

def register_user(username, email, password):
    """Registers a new user with password validation and bcrypt hashing."""
    # Malicious Input Audit
    if detect_malicious_patterns(username) or detect_malicious_patterns(email):
        # We allow registration to continue (it will stay blocked by type-safety), 
        # but we MUST flag this as a critical anomaly immediately.
        # This is for forensic correlation.
        ip = "SYSTEM-REG" # Will be passed if we refactor, for now use generic
        log_id = log_activity(None, "Malicious Input Detected", f"Registration attempted with: {username}", "SIMULATED-IP")
        if log_id:
            conn = get_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO anomaly_flags (id, activity_log_id, severity, type, is_resolved) VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), log_id, 'critical', 'injection_attempt', 0)
                )
                conn.commit()
                conn.close()

    # Validate password: min 8 chars, at least one number
    if len(password) < 8 or not re.search(r"\d", password):
        return False, "Password must be at least 8 characters long and contain at least one number."
    
    conn = get_connection()
    if not conn:
        return False, "Database connection error."
    
    try:
        cursor = conn.cursor()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user_id = str(uuid.uuid4())
        
        cursor.execute(
            "INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)",
            (user_id, username, email, password_hash)
        )
        conn.commit()
        return True, "User registered successfully."
    except Exception as e:
        return False, f"Registration failed: {e}"
    finally:
        conn.close()
def reset_password(username, new_password):
    """Validates and updates a user's password with bcrypt hashing."""
    if len(new_password) < 8 or not re.search(r"\d", new_password):
        return False, "Password must be at least 8 characters long and contain at least one number."
    
    conn = get_connection()
    if not conn: return False, "Database connection error."
    try:
        cursor = conn.cursor()
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
        conn.commit()
        return True, "Password reset successfully."
    except Exception as e:
        return False, f"Reset failed: {e}"
    finally:
        conn.close()

def parse_os_from_ua(ua_string):
    """Simple regex to detect OS from User-Agent string."""
    if not ua_string: return "Unknown"
    ua_string = str(ua_string)
    if "Windows" in ua_string: return "Windows"
    if "Macintosh" in ua_string or "Mac OS X" in ua_string: return "Macintosh"
    if "Linux" in ua_string: return "Linux"
    if "Android" in ua_string: return "Android"
    if "iPhone" in ua_string or "iPad" in ua_string: return "iOS"
    return "Unknown Device"

def login_user(username, password, ip_address, user_agent=None):
    """Authenticates a user, logs attempt with detailed status, and updates last login."""
    conn = get_connection()
    if not conn: return None, "Database error"
    
    try:
        cursor = conn.cursor()
        # Pre-auth Malicious Input Check
        if detect_malicious_patterns(username):
            log_id = log_activity(None, "Malicious Login Input", f"Injection payload attempted in username: {username}", ip_address, user_agent)
            if log_id:
                cursor.execute(
                    "INSERT INTO anomaly_flags (id, activity_log_id, severity, type, is_resolved) VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), log_id, 'critical', 'injection_attempt', 0)
                )
                conn.commit()

        # 0. Query simplified user profile
        cursor.execute(
            "SELECT u.id, u.username, u.password_hash, u.is_active, r.name as role "
            "FROM users u "
            "LEFT JOIN user_roles ur ON u.id = ur.user_id "
            "LEFT JOIN roles r ON ur.role_id = r.id "
            "WHERE u.username = ?",
            (username,)
        )
        user = cursor.fetchone()
        
        if not user:
            # 1. Log attempt for non-existent user
            # Match 4-column schema: user_id, ip_address, success, failure_reason
            cursor.execute(
                "INSERT INTO login_attempts (user_id, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)",
                (None, ip_address, 0, "Invalid username")
            )
            conn.commit()
            return None, "Invalid credentials"
            
        user_id, uname, hashed_pwd, is_active, role = user
        
        # 2. Check if account is deactivated/locked
        if not is_active:
            cursor.execute(
                "INSERT INTO login_attempts (user_id, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)",
                (user_id, ip_address, 0, "Account Locked")
            )
            conn.commit()
            return None, "Account is deactivated. Contact security."

        # 3. Verify password
        if bcrypt.checkpw(password.encode('utf-8'), hashed_pwd.encode('utf-8')):
            # Success
            cursor.execute(
                "INSERT INTO login_attempts (user_id, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)",
                (user_id, ip_address, 1, "Success")
            )
            cursor.execute("UPDATE users SET last_login = GETDATE() WHERE id = ?", (user_id,))
            conn.commit()
            
            # Check for time-based anomaly
            check_time_anomaly(user_id, uname, ip_address)
            
            return {
                "id": str(user_id), 
                "username": uname, 
                "role": role or 'viewer'
            }, "Success"
        else:
            # Failure
            cursor.execute(
                "INSERT INTO login_attempts (user_id, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)",
                (user_id, ip_address, 0, "Invalid password")
            )
            conn.commit()
            # Side-effect logic for lockout is triggered in the route calling check_brute_force
            return None, "Invalid credentials"
            
    except Exception as e:
        print(f"Login error: {e}")
        return None, "System error"
    finally:
        conn.close()

def log_activity(user_id, action, resource, ip_address, metadata=None):
    """Logs a user activity to the database with optional metadata (e.g. User-Agent)."""
    conn = get_connection()
    if not conn:
        return None
    try:
        cursor = conn.cursor()
        log_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO activity_logs (id, user_id, action, resource, ip_address, metadata) VALUES (?, ?, ?, ?, ?, ?)",
            (log_id, user_id, action, resource, ip_address, metadata)
        )
        conn.commit()
        return log_id
    except Exception as e:
        print(f"Activity logging error: {e}")
        return None
    finally:
        conn.close()

def get_user_network_info(user_id):
    """Fetches the most recent network stats and OS detection for a user."""
    conn = get_connection()
    if not conn: return None
    try:
        cursor = conn.cursor()
        # Get latest IP and metadata (UA)
        cursor.execute(
            "SELECT TOP 1 ip_address, metadata, created_at "
            "FROM activity_logs "
            "WHERE user_id = ? "
            "ORDER BY created_at DESC",
            (user_id,)
        )
        row = cursor.fetchone()
        if not row: return {"ip": "N/A", "os": "Unknown", "type": "N/A", "time": "Never"}
        
        ip, ua, time = row
        os_name = parse_os_from_ua(ua)
        is_local = "LOCAL" if ip and (ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1") else "EXTERNAL"
        
        return {
            "ip": ip,
            "os": os_name,
            "type": is_local,
            "time": time.strftime('%Y-%m-%d %H:%M') if time else "N/A"
        }
    except:
        return None
    finally:
        conn.close()

def check_brute_force(ip_address):
    """Checks for 5+ failed login attempts from the same IP. Potentially deactivates user."""
    conn = get_connection()
    if not conn: return
    try:
        cursor = conn.cursor()
        # Count failed attempts in last 15 mins for this IP
        cursor.execute(
            "SELECT COUNT(*) FROM login_attempts "
            "WHERE ip_address = ? AND success = 0 "
            "AND attempted_at >= DATEADD(minute, -15, GETDATE())",
            (ip_address,)
        )
        failed_count = cursor.fetchone()[0]
        
        if failed_count >= 5:
            # 1. Identify which user accounts are being targeted
            cursor.execute(
                "SELECT DISTINCT user_id FROM login_attempts "
                "WHERE ip_address = ? AND success = 0 AND user_id IS NOT NULL "
                "AND attempted_at >= DATEADD(minute, -15, GETDATE())",
                (ip_address,)
            )
            target_user_ids = [row[0] for row in cursor.fetchall()]

            # 2. Deactivate targeted users to prevent further spray/brute
            main_user_id = target_user_ids[0] if target_user_ids else None
            for u_id in target_user_ids:
                cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (u_id,))
            
            # 3. Log a high-severity Lockout anomaly associated with the target
            log_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO activity_logs (id, user_id, action, resource, ip_address) VALUES (?, ?, ?, ?, ?)",
                (log_id, main_user_id, "Security Lockout", f"Account lockout for {len(target_user_ids)} targets from {ip_address}", ip_address)
            )
            
            cursor.execute(
                "INSERT INTO anomaly_flags (id, activity_log_id, severity, type, is_resolved) VALUES (?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), log_id, 'critical', 'account_lockout', 0)
            )
            conn.commit()
    except Exception as e:
        print(f"Anomaly detection error: {e}")
    finally:
        conn.close()

def check_time_anomaly(user_id, username, ip_address):
    """Flags successful logins during unauthorized hours (11 PM - 5 AM)."""
    current_hour = datetime.now().hour
    if current_hour >= 23 or current_hour < 5:
        conn = get_connection()
        if not conn: return
        try:
            cursor = conn.cursor()
            log_id = log_activity(user_id, "Off-Hours Access", "System Login", ip_address)
            if log_id:
                cursor.execute(
                    "INSERT INTO anomaly_flags (id, activity_log_id, severity, type, is_resolved) VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), log_id, 'medium', 'off_hours_login', 0)
                )
                conn.commit()
        except: pass
        finally: conn.close()

def get_user_by_id(user_id):
    """Fetches a single user by id."""
    conn = get_connection()
    if not conn:
        return None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, is_active, last_login, created_at FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            columns = [column[0] for column in cursor.description]
            return dict(zip(columns, row))
        return None
    except Exception as e:
        print(f"Fetch error: {e}")
        return None
    finally:
        conn.close()

def get_all_users():
    """Fetches all users with their current role for the admin panel."""
    conn = get_connection()
    if not conn: return []
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT u.id, u.username, u.email, u.is_active, u.last_login, "
            "r.id AS role_id, r.name AS role "
            "FROM users u "
            "LEFT JOIN user_roles ur ON u.id = ur.user_id "
            "LEFT JOIN roles r ON ur.role_id = r.id"
        )
        columns = [column[0] for column in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        conn.close()

def toggle_user_active(user_id):
    """Flips is_active between 0 and 1."""
    conn = get_connection()
    if not conn: return False
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?", (user_id,))
        conn.commit()
        return True
    finally:
        conn.close()

def assign_role(username, role_name):
    """
    Replaces a user's existing role with a new one.
    Accepts role by name (for form POST) or delegates to update_user_role for UUID flow.
    """
    conn = get_connection()
    if not conn: return False, "Database connection error."
    try:
        cursor = conn.cursor()

        # 1. Resolve user_id from username
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        if not user_row: return False, "User not found."
        user_id = user_row[0]

        # 2. Resolve role_id from role_name
        cursor.execute("SELECT id FROM roles WHERE name = ?", (role_name,))
        role_row = cursor.fetchone()
        if not role_row: return False, f"Role '{role_name}' does not exist."
        role_id = role_row[0]

        # 3. REPLACE: delete existing role(s) then insert the new one
        cursor.execute("DELETE FROM user_roles WHERE user_id = ?", (str(user_id),))
        cursor.execute(
            "INSERT INTO user_roles (id, user_id, role_id) VALUES (?, ?, ?)",
            (str(uuid.uuid4()), str(user_id), str(role_id))
        )

        # 5. Flag privilege escalation if assigning admin
        if role_name == 'admin':
            log_id = log_activity(user_id, "Privilege Escalation", "Admin Role Assigned", "System")
            if log_id:
                cursor.execute(
                    "INSERT INTO anomaly_flags (id, activity_log_id, severity, type, is_resolved) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), log_id, 'high', 'privilege_escalation', 0)
                )

        conn.commit()
        return True, f"Role '{role_name}' assigned to '{username}' successfully."
    except Exception as e:
        return False, f"Assignment failed: {e}"
    finally:
        conn.close()


def get_all_roles():
    """Fetches all available roles (UUID and Name) for selection dropdowns."""
    conn = get_connection()
    if not conn: return []
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, description FROM roles")
        columns = [column[0] for column in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        conn.close()


def update_user_role(user_id, new_role_id):
    """
    Updates a user's role using UUIDs directly (called from /api/update-role JSON endpoint).
    Deletes all existing roles and inserts the new one.
    """
    conn = get_connection()
    if not conn: return False, "Database connection error."
    try:
        cursor = conn.cursor()

        # Validate user exists
        cursor.execute("SELECT username FROM users WHERE id = ?", (str(user_id),))
        user_row = cursor.fetchone()
        if not user_row: return False, "User not found."
        username = user_row[0]

        # Validate role exists
        cursor.execute("SELECT name FROM roles WHERE id = ?", (str(new_role_id),))
        role_row = cursor.fetchone()
        if not role_row: return False, "Role not found."
        role_name = role_row[0]

        # Replace role
        cursor.execute("DELETE FROM user_roles WHERE user_id = ?", (str(user_id),))
        cursor.execute(
            "INSERT INTO user_roles (id, user_id, role_id) VALUES (?, ?, ?)",
            (str(uuid.uuid4()), str(user_id), str(new_role_id))
        )

        # Flag privilege escalation
        if role_name == 'admin':
            log_id = log_activity(user_id, "Privilege Escalation", "Admin Role Assigned", "System")
            if log_id:
                cursor.execute(
                    "INSERT INTO anomaly_flags (id, activity_log_id, severity, type, is_resolved) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), log_id, 'high', 'privilege_escalation', 0)
                )

        conn.commit()
        return True, f"Role updated to '{role_name}' for user '{username}'."
    except Exception as e:
        return False, f"Update failed: {e}"
    finally:
        conn.close()

def get_user_roles(user_id):
    """Returns a list of role names for a user."""
    conn = get_connection()
    if not conn: return []
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT r.name FROM roles r "
            "JOIN user_roles ur ON r.id = ur.role_id "
            "WHERE ur.user_id = ?",
            (user_id,)
        )
        return [row[0] for row in cursor.fetchall()]
    finally:
        conn.close()

def get_anomalies():
    """Fetches TOP 100 unresolved anomaly flags with associated details."""
    conn = get_connection()
    if not conn: return []
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT TOP 100 af.id, af.type, af.severity, af.flagged_at, af.response_note, al.ip_address, al.action, al.resource, u.username "
            "FROM anomaly_flags af "
            "JOIN activity_logs al ON af.activity_log_id = al.id "
            "LEFT JOIN users u ON al.user_id = u.id "
            "WHERE af.is_resolved = 0 "
            "ORDER BY af.flagged_at DESC"
        )
        columns = [column[0] for column in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        conn.close()

def resolve_anomaly(anomaly_id):
    """Marks an anomaly as resolved."""
    conn = get_connection()
    if not conn: return False
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE anomaly_flags SET is_resolved = 1 WHERE id = ?", (anomaly_id,))
        conn.commit()
        return True
    finally:
        conn.close()

def get_activity_logs(username=None, start_date=None, end_date=None):
    """Fetches TOP 100 activity logs, filtered by username, start_date, and end_date."""
    conn = get_connection()
    if not conn: return []
    try:
        cursor = conn.cursor()
        query = (
            "SELECT TOP 100 al.id, u.username, al.action, al.resource, al.ip_address, al.created_at "
            "FROM activity_logs al "
            "LEFT JOIN users u ON al.user_id = u.id "
            "WHERE 1=1"
        )
        params = []
        if username:
            query += " AND u.username = ?"
            params.append(username)
        if start_date:
            query += " AND al.created_at >= ?"
            params.append(start_date)
        if end_date:
            query += " AND al.created_at <= ?"
            params.append(f"{end_date} 23:59:59")
        
        query += " ORDER BY al.created_at DESC"
        
        cursor.execute(query, params)
        columns = [column[0] for column in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        conn.close()

def get_dashboard_stats():
    """Calculates counts for users, login attempts, anomalies and active users."""
    conn = get_connection()
    if not conn: return {}
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM login_attempts")
        total_attempts = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM anomaly_flags WHERE is_resolved = 0")
        anomaly_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        active_users = cursor.fetchone()[0]
        
        return {
            'total_users': user_count,
            'total_attempts': total_attempts,
            'open_anomalies': anomaly_count,
            'active_users': active_users
        }
    finally:
        conn.close()

def get_login_attempts_by_day():
    """Returns login attempts grouped by day for the last 7 days."""
    conn = get_connection()
    if not conn: return []
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT FORMAT(attempted_at, 'yyyy-MM-dd') as day, COUNT(*) as count "
            "FROM login_attempts "
            "WHERE attempted_at >= DATEADD(day, -7, GETDATE()) "
            "GROUP BY FORMAT(attempted_at, 'yyyy-MM-dd') "
            "ORDER BY day ASC"
        )
        return [{'day': row[0], 'count': row[1]} for row in cursor.fetchall()]
    finally:
        conn.close()

def get_success_fail_count():
    """Returns the total count of successful vs failed logins."""
    conn = get_connection()
    if not conn: return {'success': 0, 'failed': 0}
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT success, COUNT(*) FROM login_attempts GROUP BY success")
        results = {row[0]: row[1] for row in cursor.fetchall()}
        return {
            'success': results.get(1, 0),
            'failed': results.get(0, 0)
        }
    finally:
        conn.close()

def get_top_active_users():
    """Fetches the top 5 most active users by activity count."""
    conn = get_connection()
    if not conn: return []
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT TOP 5 u.username, COUNT(al.id) as activity_count "
            "FROM users u "
            "JOIN activity_logs al ON u.id = al.user_id "
            "GROUP BY u.username "
            "ORDER BY activity_count DESC"
        )
        return [{'username': row[0], 'count': row[1]} for row in cursor.fetchall()]
    finally:
        conn.close()

def get_network_graph_data():
    """Generates node/edge data ensuring nodes are populated even without links."""
    conn = get_connection()
    if not conn: return {'nodes': [], 'links': []}
    try:
        cursor = conn.cursor()
        nodes = []
        links = []
        seen_nodes = set()

        # 1. Fetch all Roles first
        cursor.execute("SELECT name FROM roles")
        for (role_name,) in cursor.fetchall():
            nodes.append({'id': role_name, 'type': 'role', 'role': role_name})
            seen_nodes.add(role_name)

        # 2. Fetch all Users
        cursor.execute("SELECT username FROM users")
        for (username,) in cursor.fetchall():
            if username not in seen_nodes:
                nodes.append({'id': username, 'type': 'user', 'role': 'unknown'})
                seen_nodes.add(username)

        # 3. Fetch specific assignments for links
        cursor.execute(
            "SELECT u.username, r.name "
            "FROM users u "
            "JOIN user_roles ur ON u.id = ur.user_id "
            "JOIN roles r ON ur.role_id = r.id"
        )
        for username, role_name in cursor.fetchall():
            links.append({'source': username, 'target': role_name})

        return {'nodes': nodes, 'links': links}
    finally:
        conn.close()

def delete_user(user_id):
    """
    Permanently removes a user from the system.
    Relies on database ON DELETE CASCADE/SET NULL for associated records.
    """
    conn = get_connection()
    if not conn: return False
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (str(user_id),))
        conn.commit()
        return True
    except Exception as e:
        print(f"User deletion failed: {e}")
        return False
    finally:
        conn.close()
