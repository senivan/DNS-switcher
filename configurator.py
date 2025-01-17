#!/usr/bin/env python3

import json
import os

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

def save_config(config):
    """Saves the configuration to the JSON file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def update_config():
    """Interactive menu to update the configuration."""
    config = load_config()

    print("\nCurrent Configuration:")
    print("DNS Servers (Priority Order):")
    for server in config['dns_servers']:
        print(f"  Address: {server['address']}, Priority: {server['priority']}")
    print(f"Check Interval (Seconds): {config['check_interval']}")

    print("\nEnter new values (leave blank to keep current setting):")
    
    # Change number of DNS servers
    num_servers_input = input(f"Number of DNS Servers [{len(config['dns_servers'])}]: ")
    if num_servers_input:
        num_servers = int(num_servers_input)
        if num_servers > len(config['dns_servers']):
            for i in range(len(config['dns_servers']), num_servers):
                config['dns_servers'].append({"address": "", "priority": i+1})
        elif num_servers < len(config['dns_servers']):
            config['dns_servers'] = config['dns_servers'][:num_servers]

    # Update DNS server addresses and priorities
    for i, server in enumerate(config['dns_servers']):
        address_input = input(f"DNS Server {i+1} Address [{server['address']}]: ")
        if address_input:
            config['dns_servers'][i]['address'] = address_input
        priority_input = input(f"DNS Server {i+1} Priority [{server['priority']}]: ")
        if priority_input:
            config['dns_servers'][i]['priority'] = int(priority_input)
    
    # Update check interval
    check_interval_input = input(f"Check Interval (in seconds) [{config['check_interval']}]: ")
    if check_interval_input:
        config['check_interval'] = int(check_interval_input)

    save_config(config)
    print("\nConfiguration updated successfully!")

if __name__ == "__main__":
    update_config()
