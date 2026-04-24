import socket
import psutil
import uuid
import re
from config import get_connection

class NetworkMonitor:
    @staticmethod
    def get_server_info():
        """Returns the primary interface IP and the system MAC address using a socket connection trick."""
        hostname = socket.gethostname()
        ip_address = "--.---.---.---"
        
        # Robust IP discovery: connect to a non-existent external IP to determine local exit interface
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)) # Google DNS (doesn't actually send packet)
            ip_address = s.getsockname()[0]
            s.close()
        except Exception:
            # Fallback to hostname lookup
            try:
                ip_address = socket.gethostbyname(hostname)
            except: pass

        # Get MAC address from the default interface
        mac_int = uuid.getnode()
        mac = ':'.join(re.findall('..', '%012x' % mac_int))
        
        return {
            "hostname": hostname,
            "ip": ip_address,
            "mac": mac.upper()
        }

    @staticmethod
    def get_all_interfaces():
        """Lists all active network interfaces with their IP and MAC addresses."""
        interfaces = []
        for interface_name, snics in psutil.net_if_addrs().items():
            info = {"name": interface_name, "ip": None, "mac": None}
            for snic in snics:
                if snic.family == socket.AF_INET:
                    info["ip"] = snic.address
                elif snic.family == psutil.AF_LINK:
                    info["mac"] = snic.address.upper()
            if info["ip"]: # Only show interfaces with an IP
                interfaces.append(info)
        return interfaces

    @staticmethod
    def is_local_ip(ip):
        """Determines if a connecting IP is on a local (LAN) range."""
        if ip in ("127.0.0.1", "::1"): return True
        parts = ip.split('.')
        if len(parts) != 4: return False
        
        # Ranges: 10.x.x.x, 192.168.x.x, 172.16-31.x.x
        first = int(parts[0])
        second = int(parts[1])
        
        if first == 10: return True
        if first == 192 and second == 168: return True
        if first == 172 and (16 <= second <= 31): return True
        return False

    @staticmethod
    def get_connecting_ips():
        """Fetches unique IP addresses that have connected to the system from activity logs."""
        conn = get_connection()
        if not conn: return []
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT ip_address FROM activity_logs WHERE ip_address IS NOT NULL")
            ips = []
            for row in cursor.fetchall():
                ip = row[0]
                if ip == "SYSTEM" or ip == "MULTIPLE": continue
                ips.append({
                    "ip": ip,
                    "type": "Local" if NetworkMonitor.is_local_ip(ip) else "External"
                })
            return ips
        finally:
            conn.close()

import re # needed for MAC regex in get_server_info
