#!/usr/bin/env python3

import time
import json
import subprocess
import os
import platform
from datetime import datetime

CONFIG_FILE = "config.json"

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

    while True:
        for dns_entry in dns_servers:
            dns = dns_entry["address"]
            if is_dns_reachable(dns):
                if get_current_dns() != dns:
                    print(f"{datetime.now()} - Switching to DNS: {dns}", flush=True)
                    set_dns(dns)
                break  # Stop checking once a valid DNS is found

        time.sleep(check_interval)

if __name__ == "__main__":
    main()
