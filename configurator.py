#!/usr/bin/env python3

import json
import os

CONFIG_FILE = "config.json"

def load_config():
    """Loads configuration from the JSON file."""
    default_config = {
        "dns_servers": ["1.1.1.1", "127.0.0.1"],  
        "check_interval": 15  
    }

    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=4)
        return default_config

    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def save_config(config):
    """Saves the configuration to the JSON file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def update_config():
    """Interactive menu to update the configuration."""
    config = load_config()

    print("\nCurrent Configuration:")
    print(f"DNS Servers (Priority Order): {', '.join(config['dns_servers'])}")
    print(f"Check Interval (Seconds): {config['check_interval']}")

    print("\nEnter new values (leave blank to keep current setting):")
    dns_servers_input = input(f"DNS Servers (comma separated) [{', '.join(config['dns_servers'])}]: ")
    if dns_servers_input:
        dns_servers = [dns.strip() for dns in dns_servers_input.split(",")]
        config["dns_servers"] = dns_servers
    check_interval_input = input(f"Check Interval (in seconds) [{config['check_interval']}]: ")
    if check_interval_input:
        config["check_interval"] = int(check_interval_input)

    save_config(config)
    print("\nConfiguration updated successfully!")

if __name__ == "__main__":
    update_config()
