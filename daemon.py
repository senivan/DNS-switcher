#!/usr/bin/env python3

import time
import json
import subprocess
import os
import platform
import requests
from datetime import datetime
import subprocess
import re
import threading
from collections import defaultdict

CONFIG_FILE = "config.json"

def block_dns_traffic(dns_ip):
    """Block unauthorized DNS traffic using iptables."""
    try:
        subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-d", dns_ip, "-j", "DROP"], check=True)
        print(f"🚫 Blocked unauthorized DNS server: {dns_ip}")
        send_telegram_message(f"🚨 DNS Leak Prevented: Blocked {dns_ip}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block DNS: {e}")


def monitor_dns_leaks():
    """Monitors DNS traffic and blocks unauthorized DNS requests."""
    config = load_config()
    leak_config = config.get("leak_prevention", {})

    if not leak_config.get("enabled", False):
        return

    interface = leak_config.get("interface", "eth0")
    allowed_dns = set(config["dns_servers"])
    alert_threshold = leak_config.get("alert_threshold", 3)
    enable_blocking = leak_config.get("iptables_blocking", False)

    suspicious_requests = defaultdict(int)

    print(f"Monitoring DNS traffic on {interface}...")

    try:
        process = subprocess.Popen(
            ["tcpdump", "-l", "-n", "-i", interface, "udp port 53"],
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
                    print(f"⚠️ Potential DNS leak: {dns_ip} (count: {suspicious_requests[dns_ip]})")

                    if suspicious_requests[dns_ip] >= alert_threshold:
                        send_telegram_message(f"🚨 DNS Leak Detected! Unauthorized request to {dns_ip}")
                        if enable_blocking:
                            block_dns_traffic(dns_ip)
    
    except Exception as e:
        print(f"Error monitoring DNS traffic: {e}")

def send_telegram_message(message):
    """Sends a notification to Telegram if enabled."""
    config = load_config()
    telegram_config = config.get("telegram", {})

    if not telegram_config.get("enabled", False):
        return

    bot_token = telegram_config.get("bot_token")
    chat_id = telegram_config.get("chat_id")

    if not bot_token or not chat_id:
        print("Telegram bot token or chat ID missing in config.")
        return

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = {"chat_id": chat_id, "text": message}

    try:
        response = requests.post(url, json=data)
        if response.status_code != 200:
            print(f"Failed to send Telegram message: {response.text}")
    except Exception as e:
        print(f"Error sending Telegram message: {e}")


def load_config():
    """Loads configuration from the JSON file."""
    default_config = {
        "dns_servers": [
            {"address": "1.1.1.1", "priority": 1},
            {"address": "8.8.8.8", "priority": 2},
            {"address": "127.0.0.1", "priority": 3}
        ],
        "check_interval": 15  # Time (seconds) between checks
    }

    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=4)
        return default_config

    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def get_os():
    """Returns the operating system."""
    return platform.system().lower()

def get_current_dns():
    """Gets the current DNS settings based on the OS."""
    os_type = get_os()

    try:
        if os_type == "darwin":  # macOS
            result = subprocess.run(["networksetup", "-getdnsservers", "Wi-Fi"], capture_output=True, text=True)
            return result.stdout.strip().split("\n")[0]

        elif os_type == "linux":
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        return line.split()[1]
        
        elif os_type == "windows":
            result = subprocess.run(["nslookup", "example.com"], capture_output=True, text=True, shell=True)
            lines = result.stdout.split("\n")
            for line in lines:
                if "Address" in line:
                    return line.split(":")[-1].strip()
    
    except Exception as e:
        print(f"Error getting DNS: {e}")
    
    return "Unknown"

def set_dns(dns):
    """Sets the DNS server based on the OS."""
    os_type = get_os()

    try:
        if os_type == "darwin":  # macOS
            subprocess.run(["sudo", "/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", dns], check=True)

        elif os_type == "linux":
            with open("/etc/resolv.conf", "w") as f:
                f.write(f"nameserver {dns}\n")

        elif os_type == "windows":
            subprocess.run(f'netsh interface ip set dns "Wi-Fi" static {dns}', shell=True)

        print(f"{datetime.now()} - Switched to DNS: {dns}", flush=True)

    except subprocess.CalledProcessError as e:
        print(f"{datetime.now()} - Failed to set DNS: {e}", flush=True)

def is_dns_reachable(dns):
    """Checks if a DNS server is reachable via ping."""
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", dns], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception as e:
        print(f"{datetime.now()} - Ping error: {e}", flush=True)
        return False

def main():
    """Main daemon loop."""
    config = load_config()
    dns_servers = sorted(config["dns_servers"], key=lambda x: x["priority"])
    check_interval = config["check_interval"]
    send_telegram_message("🚀 DNS Switcher Daemon Started!")
    threading.Thread(target=monitor_dns_leaks, daemon=True).start()
    while True:
        for dns_entry in dns_servers:
            dns = dns_entry["address"]
            if is_dns_reachable(dns):
                if get_current_dns() != dns:
                    send_telegram_message(f"🔔 DNS switched to {dns}")
                    print(f"{datetime.now()} - Switching to DNS: {dns}", flush=True)
                    set_dns(dns)
                break  # Stop checking once a valid DNS is found
        else:
            print("No DNS server is reachable, trying again...")
            send_telegram_message("⚠️ No DNS server is reachable!")
        time.sleep(check_interval)

if __name__ == "__main__":
    main()
