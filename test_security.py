import uuid
from datetime import datetime, timedelta
from config import get_connection

def simulate_threats():
    conn = get_connection()
    if not conn:
        print("Failed to connect to database.")
        return
    
    try:
        cursor = conn.cursor()
        print("--- Simulation Started ---")

        # 1. Simulate SQL Injection Attempt
        sql_log_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO activity_logs (id, user_id, action, resource, ip_address, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sql_log_id, None, "Malicious Login Input", "Auth System", "192.168.1.100", "' OR 1=1 --", datetime.now())
        )
        print("[+] Injected SQL Injection attempt from 192.168.1.100")

        # 2. Simulate Brute Force Attempt
        cursor.execute("SELECT id FROM users WHERE username = 'kirollos'")
        user_row = cursor.fetchone()
        kirollos_id = user_row[0] if user_row else None
        
        for i in range(10):
            cursor.execute(
                "INSERT INTO login_attempts (id, user_id, ip_address, success, failure_reason, attempted_at) VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), kirollos_id, "10.0.0.50", 0, "Invalid password", datetime.now())
            )
        print("[+] Injected 10 failed login attempts from 10.0.0.50")

        # 3. Simulate Off-Hours Activity (2:00 AM)
        off_hours_time = datetime.now().replace(hour=2, minute=0, second=0)
        off_hours_log_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO activity_logs (id, user_id, action, resource, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (off_hours_log_id, kirollos_id, "Login", "System Dashboard", "172.16.0.5", off_hours_time)
        )
        print(f"[+] Injected Off-Hours Login at {off_hours_time} from 172.16.0.5")

        conn.commit()
        print("--- Simulation Data Persisted ---")

        # 4. Trigger the ThreatDetector
        from threat_detector import ThreatDetector
        print("\n--- Running AI Threat Scan ---")
        detector = ThreatDetector()
        results = detector.run_all_scans()
        print(f"Detections Triggered: {results}")

    except Exception as e:
        print(f"Simulation Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    simulate_threats()
