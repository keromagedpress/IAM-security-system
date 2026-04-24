import time
import psutil
import platform
from datetime import datetime
from models import log_activity

def get_system_metrics():
    """Captures real host system metrics: CPU, RAM, Uptime, Process Count."""
    try:
        # User requested specific platform/psutil logic
        data = {
            "os": platform.system() + " " + platform.release(),
            "cpu": psutil.cpu_percent(interval=1),
            "memory": psutil.virtual_memory().percent,
            "uptime": str(datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M")),
            "processes": len(psutil.pids()),
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        return data
    except Exception as e:
        print(f"Metrics collection error: {e}")
        return None

def monitor_loop():
    """Background loop that heartbeats system health into activity_logs every 5 mins."""
    print("=== IAM SECURITY - OS MONITORING HEARTBEAT STARTED ===")
    while True:
        try:
            metrics = get_system_metrics()
            if metrics:
                resource_str = f"CPU:{metrics['cpu']} | RAM:{metrics['memory']} | Procs:{metrics['processes']}"
                log_activity(None, "System Status", resource_str, "LOCAL")
            time.sleep(300)
        except Exception as e:
            print(f"Monitoring heartbeat error: {e}")
            time.sleep(60)
