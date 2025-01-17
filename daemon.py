#!/usr/bin/env python3
import json
import time
import subprocess
import threading
import requests
import platform
import re
from collections import defaultdict

CONFIG_FILE = "config.json"
CURRENT_DNS_RATINGS = {}
def load_config():
    """Loads the configuration from config.json"""
    with open(CONFIG_FILE, "r") as file:
        return json.load(file)

def send_telegram_message(message):
    """Sends a notification to Telegram if enabled."""
    config = load_config()
    telegram = config.get("telegram", {})

    if not telegram.get("enabled", False):
        return

    bot_token = telegram["bot_token"]
    chat_id = telegram["chat_id"]
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    
    try:
        requests.post(url, json={"chat_id": chat_id, "text": message})
    except requests.RequestException as e:
        print(f"❌ Failed to send Telegram message: {e}", flush=True)

def is_dns_reachable(dns_ip):
    """Checks if the DNS server is reachable using a simple ping."""
    try:
        subprocess.run(["ping", "-c", "1", dns_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def set_dns(dns_ip):
    """Sets the system's DNS resolver."""
    try:
        subprocess.run(["sudo", "networksetup", "-setdnsservers", "Wi-Fi", dns_ip], check=True)
        print(f"✅ Switched DNS to: {dns_ip}", flush=True)
        send_telegram_message(f"🔄 Switched DNS to {dns_ip}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to switch DNS: {e}", flush=True)

def get_ping_time(dns_ip):
    """Returns the ping time to the DNS server in milliseconds."""
    try:
        output = subprocess.check_output(["ping", "-c", "1", dns_ip], stderr=subprocess.STDOUT, text=True)
        match = re.search(r"time=(\d+\.\d+) ms", output)
        return float(match.group(1)) if match else float("inf")
    except subprocess.CalledProcessError:
        return float("inf")

def calculate_dns_ratings(dns_servers):
    """Calculates ratings for DNS servers based on their ping times."""
    dns_ratings = {}
    threads = []
    results = {}

    def ping_dns(dns):
        results[dns["address"]] = get_ping_time(dns["address"])

    for dns in dns_servers:
        thread = threading.Thread(target=ping_dns, args=(dns,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    for dns in dns_servers:
        dns_ratings[dns["address"]] = (results[dns["address"]]) * (10 ** (2 * dns["priority"]))
    CURRENT_DNS_RATINGS = dns_ratings.copy()    
    return dns_ratings

def get_highest_priority_dns():
    """Returns the highest-priority reachable DNS server."""
    config = load_config()
    dns_servers = sorted(config["dns_servers"], key=lambda x: x["priority"])  # Sort by priority (ascending)
    dns_server_ratings = calculate_dns_ratings(dns_servers)
    return min(dns_server_ratings, key=dns_server_ratings.get, default=None)
def unblock_dns_traffic(dns_ip):
    """Unblocks the DNS server by removing its block rule."""
    system_type = platform.system().lower()

    if system_type == "linux":
        unblock_dns_linux(dns_ip)
    elif system_type == "darwin":  # macOS
        unblock_dns_macos(dns_ip)
    else:
        print(f"⚠️ Unsupported OS: {system_type}. Cannot unblock DNS.", flush=True)

def unblock_dns_linux(dns_ip):
    """Unblocks DNS using iptables on Linux."""
    try:
        subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-d", dns_ip, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-d", dns_ip, "-j", "DROP"], check=True)
        print(f"✅ Unblocked DNS (Linux): {dns_ip}", flush=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to unblock DNS on Linux: {e}", flush=True)

def unblock_dns_macos(dns_ip):
    """Unblocks DNS using PF on macOS."""
    pf_rule = f"pass out proto udp to {dns_ip} port 53\npass out proto tcp to {dns_ip} port 53\n"
    
    try:
        command = f"echo '{pf_rule}' | cat /etc/pf.conf - | sudo /sbin/pfctl -Ef -"
        subprocess.run(command, shell=True, check=True)
        print(f"✅ Unblocked DNS (macOS) via pf: {dns_ip}", flush=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to unblock DNS on macOS: {e}", flush=True)

def block_dns_traffic(dns_ip, duration):
    """Blocks unauthorized DNS traffic using the appropriate method for the OS."""
    system_type = platform.system().lower()

    if system_type == "linux":
        block_dns_linux(dns_ip, duration)
    elif system_type == "darwin":  # macOS
        block_dns_macos(dns_ip, duration)
    else:
        print(f"⚠️ Unsupported OS: {system_type}. Cannot block DNS.", flush=True)

def block_dns_linux(dns_ip, block_duration):
    """Blocks DNS using iptables on Linux."""
    try:
        subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-d", dns_ip, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-d", dns_ip, "-j", "DROP"], check=True)
        print(f"🚫 Blocked unauthorized DNS (Linux): {dns_ip}", flush=True)
        threading.Timer(block_duration, unblock_dns_traffic, args=[dns_ip]).start()

    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to block DNS on Linux: {e}", flush=True)

def block_dns_macos(dns_ip, block_duration):
    """Blocks DNS using PF anchors on macOS."""
    anchor_name = "com.example.dnsblocker"
    "echo 'block out all' | cat /etc/pf.conf - | sudo /sbin/pfctl -Ef -"
    pf_rule = f"block drop out proto udp to {dns_ip} port 53\nblock drop out proto tcp to {dns_ip} port 53\n"

    try:
        command = f"echo '{pf_rule}' | cat /etc/pf.conf - | sudo /sbin/pfctl -Ef -"
        subprocess.run(command, shell=True, check=True)
        threading.Timer(block_duration, unblock_dns_traffic, args=[dns_ip]).start()
        print(f"🚫 Blocked unauthorized DNS (macOS): {dns_ip}", flush=True)
    except Exception as e:
        print(f"❌ Failed to block DNS on macOS: {e}", flush=True)

def unblock_all_dns():
    """Removes all DNS blocking rules (useful for testing)."""
    system_type = platform.system().lower()

    if system_type == "linux":
        subprocess.run(["sudo", "iptables", "-F"], check=True)
        print("✅ Flushed iptables rules (Linux).", flush=True)
    elif system_type == "darwin":
        subprocess.run(["sudo", "/sbin/pfctl", "-F", "all"], check=True)
        subprocess.run(["sudo", "/sbin/pfctl", "-d"], check=True)
        print("✅ Flushed PF rules (macOS).", flush=True)
    else:
        print(f"⚠️ Unsupported OS: {system_type}. Cannot unblock DNS.", flush=True)


def monitor_dns_leaks():
    """Monitors DNS traffic and blocks unauthorized DNS requests."""
    config = load_config()
    leak_config = config.get("leak_prevention", {})
    if not leak_config.get("enabled", False):
        return

    interface = leak_config.get("interface", "en0")  # Default to macOS "en0"
    allowed_dns = {dns["address"] for dns in config["dns_servers"]}
    alert_threshold = leak_config.get("alert_threshold", 3)
    enable_blocking = leak_config.get("iptables_blocking", False)
    block_duration = leak_config.get("block_duration", 3600)
    suspicious_requests = defaultdict(int)

    print(f"👀 Monitoring DNS traffic on {interface}...", flush=True)

    try:
        process = subprocess.Popen(
            ["sudo", "/usr/sbin/tcpdump", "-l", "-n", "-i", interface, "udp port 53"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        for line in iter(process.stdout.readline, ""):
            match = re.search(r"IP .*? > (\d+\.\d+\.\d+\.\d+)\.53:", line)
            if match:
                dns_ip = match.group(1)

                if dns_ip not in allowed_dns:
                    suspicious_requests[dns_ip] += 1
                    print(f"⚠️ Potential DNS leak: {dns_ip} (count: {suspicious_requests[dns_ip]})", flush=True)

                    if suspicious_requests[dns_ip] >= alert_threshold:
                        send_telegram_message(f"🚨 DNS Leak Detected! Unauthorized request to {dns_ip}")
                        if enable_blocking:
                            block_dns_traffic(dns_ip, block_duration)
                            suspicious_requests[dns_ip] = 0  # Reset counter after blocking
    except Exception as e:
        print(f"❌ Error monitoring DNS traffic: {e}", flush=True)

def main():
    """Main daemon loop for DNS switching."""
    config = load_config()
    check_interval = config["check_interval"]
    last_dns = None

    # Start DNS leak monitoring in a separate thread
    threading.Thread(target=monitor_dns_leaks, daemon=True).start()
    while True:
        best_dns = get_highest_priority_dns()
        
        if best_dns and best_dns != last_dns:
            set_dns(best_dns)
            last_dns = best_dns

        if not best_dns:
            send_telegram_message("⚠️ No DNS server is reachable!")

        time.sleep(check_interval)

if __name__ == "__main__":
    main()
