import uuid
import re
from datetime import datetime
from config import get_connection
from models import detect_malicious_patterns

class ThreatDetector:
    def __init__(self):
        self.conn = get_connection()

    def run_all_scans(self):
        """Runs all detection modules and returns a summary of new anomalies found."""
        if not self.conn: return {"error": "DB Connection Fail"}
        
        results = {
            "brute_force": self.scan_brute_force(),
            "credential_stuffing": self.scan_credential_stuffing(),
            "account_takeover": self.scan_account_takeover(),
            "privilege_escalation": self.scan_privilege_escalation(),
            "off_hours_access": self.scan_off_hours(),
            "sql_injection": self.scan_sql_injection(),
            "suspicious_activity": self.scan_suspicious_activity()
        }
        return results

    def _create_anomaly(self, log_id, severity, type_name, response_note=None):
        """Helper to insert an anomaly flag if it doesn't already exist for that log."""
        cursor = self.conn.cursor()
        # Check if already flagged
        cursor.execute("SELECT id FROM anomaly_flags WHERE activity_log_id = ?", (log_id,))
        if cursor.fetchone(): return False

        cursor.execute(
            "INSERT INTO anomaly_flags (id, activity_log_id, severity, type, response_note, is_resolved) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), log_id, severity, type_name, response_note, 0)
        )
        self.conn.commit()
        return True

    def scan_brute_force(self):
        """Detects 5+ failed logins from same IP in 10 minutes."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT ip_address, COUNT(*) as fail_count
            FROM login_attempts
            WHERE success = 0 AND attempted_at >= DATEADD(minute, -10, GETDATE())
            GROUP BY ip_address
            HAVING COUNT(*) >= 5
        """)
        found = 0
        for ip, count in cursor.fetchall():
            log_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO activity_logs (id, action, resource, ip_address, metadata) VALUES (?, ?, ?, ?, ?)",
                (log_id, "Brute Force Detected", "Auth System", ip, f"Failed Attempts: {count}")
            )
            note = "High: Implement IP ban and verify account integrity."
            if self._create_anomaly(log_id, 'critical', 'brute_force', note):
                found += 1
        return found

    def scan_credential_stuffing(self):
        """Detects failed logins across multiple usernames from same IP."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT ip_address, COUNT(DISTINCT user_id) as user_count
            FROM login_attempts
            WHERE success = 0 AND attempted_at >= DATEADD(minute, -30, GETDATE())
            GROUP BY ip_address
            HAVING COUNT(DISTINCT user_id) >= 3
        """)
        found = 0
        for ip, count in cursor.fetchall():
            log_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO activity_logs (id, action, resource, ip_address, metadata) VALUES (?, ?, ?, ?, ?)",
                (log_id, "Credential Stuffing", "Auth System", ip, f"Unique Users Targeted: {count}")
            )
            note = "High: Account harvesting attempt. Enable account lockout and notify users."
            if self._create_anomaly(log_id, 'high', 'credential_stuffing', note):
                found += 1
        return found

    def scan_account_takeover(self):
        """Detects success from new IP after multiple failures on same account."""
        cursor = self.conn.cursor()
        cursor.execute("""
            WITH recent_fails AS (
                SELECT user_id, COUNT(*) as fails
                FROM login_attempts
                WHERE success = 0 AND attempted_at >= DATEADD(hour, -24, GETDATE())
                GROUP BY user_id
                HAVING COUNT(*) >= 3
            )
            SELECT la.user_id, la.ip_address, la.attempted_at 
            FROM login_attempts la
            JOIN recent_fails rf ON la.user_id = rf.user_id
            WHERE la.success = 1 AND la.attempted_at >= DATEADD(hour, -1, GETDATE())
        """)
        found = 0
        for u_id, ip, time in cursor.fetchall():
            log_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO activity_logs (id, user_id, action, resource, ip_address, metadata) VALUES (?, ?, ?, ?, ?, ?)",
                (log_id, u_id, "Potential ATO", "Account Identity", ip, f"Success after multiple failures")
            )
            note = "Critical: Unauthorized success after multiple failures. Review account immediately."
            if self._create_anomaly(log_id, 'critical', 'account_takeover', note):
                found += 1
        return found

    def scan_privilege_escalation(self):
        """Detects user accessing resources outside their role permissions."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT al.id, al.user_id, al.action, al.resource, al.ip_address
            FROM activity_logs al
            JOIN users u ON al.user_id = u.id
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN role_permissions rp ON ur.role_id = rp.role_id
            LEFT JOIN permissions p ON rp.permission_id = p.id AND p.resource = al.resource AND p.action = al.action
            WHERE p.id IS NULL AND al.action NOT IN ('Login', 'Logout', 'Access Page', 'System Check')
            AND al.created_at >= DATEADD(hour, -1, GETDATE())
        """)
        found = 0
        for log_id, u_id, action, resource, ip in cursor.fetchall():
            note = "High: Unauthorized resource access attempt. Review user permissions."
            if self._create_anomaly(log_id, 'high', 'privilege_escalation', note):
                found += 1
        return found

    def scan_off_hours(self):
        """Detects logins between 12AM and 5AM."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT al.id 
            FROM activity_logs al
            WHERE al.action = 'Login' 
            AND (DATEPART(hour, al.created_at) >= 0 AND DATEPART(hour, al.created_at) < 5)
            AND al.created_at >= DATEADD(day, -1, GETDATE())
        """)
        found = 0
        for log_id, in cursor.fetchall():
            note = "Medium: Verify if this late-night access is authorized by the student."
            if self._create_anomaly(log_id, 'medium', 'off_hours_access', note):
                found += 1
        return found

    def scan_sql_injection(self):
        """Detects SQLi patterns in log metadata."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, metadata, ip_address FROM activity_logs WHERE created_at >= DATEADD(hour, -2, GETDATE())")
        found = 0
        for log_id, metadata, ip in cursor.fetchall():
            if metadata and detect_malicious_patterns(metadata):
                note = "Critical: Block IP and update WAF rules."
                if self._create_anomaly(log_id, 'critical', 'sql_injection', note):
                    found += 1
        return found

    def scan_suspicious_activity(self):
        """Same user logging in from multiple different IPs within 1 hour."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT user_id, COUNT(DISTINCT ip_address) as ip_count
            FROM login_attempts
            WHERE success = 1 AND attempted_at >= DATEADD(hour, -1, GETDATE())
            GROUP BY user_id
            HAVING COUNT(DISTINCT ip_address) >= 2
        """)
        found = 0
        for u_id, count in cursor.fetchall():
            log_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO activity_logs (id, user_id, action, resource, ip_address, metadata) VALUES (?, ?, ?, ?, ?, ?)",
                (log_id, u_id, "Suspicious IP Oscillation", "Identity", "MULTIPLE", f"User accessed from {count} IPs in 1hr")
            )
            note = "Medium: Identity oscillation detected. Review session integrity."
            if self._create_anomaly(log_id, 'high', 'suspicious_activity', note):
                found += 1
        return found

    def __del__(self):
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
