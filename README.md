# Monitor-Wi-Fi-Usage-with-Packet-Sniffing
packet sniffing to monitor network traffic in real time. This method uses the scapy library to capture and analyze packets, allowing you to monitor per-device usage and enforce limits.
from scapy.all import sniff
import psutil
import subprocess
from collections import defaultdict
import time
import threading

# Configuration
USAGE_LIMIT_MB = 500  # Example: Limit in MB
STUDENT_IPS = ["192.168.1.101", "192.168.1.102"]  # List of student IPs
CHECK_INTERVAL = 60  # Check interval in seconds

# Data usage tracker
usage_tracker = defaultdict(int)
blocked_ips = set()

# Function to block an IP
def block_ip(ip_address):
    if ip_address not in blocked_ips:
        try:
            subprocess.run(["iptables", "-A", "OUTPUT", "-s", ip_address, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            blocked_ips.add(ip_address)
            print(f"Blocked IP: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {ip_address}: {e}")

# Function to unblock an IP
def unblock_ip(ip_address):
    if ip_address in blocked_ips:
        try:
            subprocess.run(["iptables", "-D", "OUTPUT", "-s", ip_address, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            blocked_ips.remove(ip_address)
            usage_tracker[ip_address] = 0  # Reset usage
            print(f"Unblocked IP: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error unblocking IP {ip_address}: {e}")

# Packet handler
def packet_handler(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        packet_size = len(packet)

        # Check if the source IP is in our list of students
        if src_ip in STUDENT_IPS:
            usage_tracker[src_ip] += packet_size

# Monitoring function
def monitor_usage():
    print("Starting packet sniffing...")
    sniff(filter="ip", prn=packet_handler, store=0)  # Sniff IP packets only

# Limit enforcement function
def enforce_limits():
    while True:
        time.sleep(CHECK_INTERVAL)
        for ip, usage in usage_tracker.items():
            usage_mb = usage / (1024 * 1024)  # Convert bytes to MB
            print(f"IP: {ip}, Usage: {usage_mb:.2f} MB")
            if usage_mb > USAGE_LIMIT_MB and ip not in blocked_ips:
                block_ip(ip)

# Main function
if __name__ == "__main__":
    # Start sniffing in a separate thread
    sniffing_thread = threading.Thread(target=monitor_usage, daemon=True)
    sniffing_thread.start()

    # Start monitoring usage and enforcing limits
    enforce_limits()
