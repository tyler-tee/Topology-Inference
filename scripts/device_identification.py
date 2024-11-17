import os
import json
import csv
import requests
from collections import defaultdict

# Constants
OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_JSON_PATH = "oui.json"
DEFAULT_CONFIG_PATH = "config.json"


# Load Tines Webhook URL
def load_webhook_url(config_file):
    """
    Load the Tines webhook URL from a local JSON configuration file.
    """
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        return config.get("TINES_WEBHOOK_URL")
    except FileNotFoundError:
        print(f"Configuration file '{config_file}' not found.")
        return None
    except Exception as e:
        print(f"Error loading webhook URL: {e}")
        return None


# Download and Convert OUI Database
def download_oui_database(csv_path):
    """
    Download the OUI database from IEEE.
    """
    try:
        print(f"Downloading OUI database from {OUI_CSV_URL}...")
        response = requests.get(OUI_CSV_URL)
        response.raise_for_status()
        with open(csv_path, "wb") as f:
            f.write(response.content)
        print(f"OUI database downloaded and saved to {csv_path}.")
    except Exception as e:
        print(f"Error downloading OUI database: {e}")
        raise RuntimeError("Failed to download OUI database.")


def convert_csv_to_json(csv_path, json_path):
    """
    Convert the OUI CSV database to a JSON file.
    """
    oui_dict = {}
    try:
        with open(csv_path, "r") as csv_file:
            reader = csv.reader(csv_file)
            next(reader)  # Skip the header
            for row in reader:
                oui_prefix = row[1].strip().upper()  # OUI prefix
                vendor_name = row[2].strip()  # Vendor name
                oui_dict[oui_prefix] = vendor_name

        with open(json_path, "w") as json_file:
            json.dump(oui_dict, json_file)
        print(f"Converted OUI CSV to JSON and saved to {json_path}.")
    except Exception as e:
        print(f"Error converting CSV to JSON: {e}")
        raise RuntimeError("Failed to convert OUI CSV to JSON.")


def load_oui_database(json_path):
    """
    Load the OUI database from a JSON file.
    """
    if os.path.exists(json_path):
        try:
            with open(json_path, "r") as json_file:
                return json.load(json_file)
        except Exception as e:
            print(f"Error loading OUI JSON file: {e}")
            raise RuntimeError("Failed to load OUI database.")

    # If JSON is missing, fallback to downloading and converting the CSV
    csv_path = json_path.replace(".json", ".csv")
    download_oui_database(csv_path)
    convert_csv_to_json(csv_path, json_path)
    return load_oui_database(json_path)


# Enrichment and Data Handling
def lookup_mac_vendor(mac_address, oui_database):
    """
    Look up the MAC vendor using the OUI database.
    """
    mac_prefix = mac_address[:8].upper().replace(":", "-")  # Format as OUI style
    return oui_database.get(mac_prefix, "Unknown Vendor")


def extract_device_data(log_file, oui_database):
    """
    Extract devices and activity based on MAC and IP addresses from Suricata logs.
    """
    devices = defaultdict(lambda: {
        "ip": None,
        "mac": None,
        "vendor": "Unknown",
        "traffic": {"bytes_sent": 0, "bytes_received": 0},
        "activity": []
    })

    try:
        with open(log_file, "r") as f:
            for line in f:
                event = json.loads(line)

                # Only process flow events
                if event.get("event_type") == "flow":
                    src_ip = event.get("src_ip")
                    dest_ip = event.get("dest_ip")
                    flow = event.get("flow", {})
                    ether = event.get("ether", {})
                    src_macs = ether.get("src_macs", [])
                    dest_macs = ether.get("dest_macs", [])

                    bytes_toserver = flow.get("bytes_toserver", 0)
                    bytes_toclient = flow.get("bytes_toclient", 0)

                    # Process source MAC addresses
                    for src_mac in src_macs:
                        if src_mac not in devices:
                            devices[src_mac]["mac"] = src_mac
                            devices[src_mac]["vendor"] = lookup_mac_vendor(src_mac, oui_database)
                        devices[src_mac]["ip"] = src_ip
                        devices[src_mac]["traffic"]["bytes_sent"] += bytes_toserver
                        devices[src_mac]["activity"].append(f"Sent {bytes_toserver} bytes to {dest_ip}")

                    # Process destination MAC addresses
                    for dest_mac in dest_macs:
                        if dest_mac not in devices:
                            devices[dest_mac]["mac"] = dest_mac
                            devices[dest_mac]["vendor"] = lookup_mac_vendor(dest_mac, oui_database)
                        devices[dest_mac]["ip"] = dest_ip
                        devices[dest_mac]["traffic"]["bytes_received"] += bytes_toclient
                        devices[dest_mac]["activity"].append(f"Received {bytes_toclient} bytes from {src_ip}")

        return devices
    except Exception as e:
        print(f"Error processing log file: {e}")
        return None


def send_to_tines(device_data, webhook_url):
    """
    Send the structured device data to Tines for further processing.
    """
    # Prepare the payload
    payload = {
        "devices": [
            {
                "mac": mac,
                "ip": data["ip"],
                "vendor": data["vendor"],
                "traffic": data["traffic"],
                "activity": data["activity"]
            }
            for mac, data in device_data.items()
        ]
    }

    # Send data to Tines webhook
    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        print("Data successfully sent to Tines.")
    except Exception as e:
        print(f"Error sending data to Tines: {e}")


# Main Script Logic
def main():
    # Paths
    log_file = "/var/log/suricata/eve.json"  # Update with your actual path
    config_file = DEFAULT_CONFIG_PATH

    # Load the Tines webhook URL
    webhook_url = load_webhook_url(config_file)
    if not webhook_url:
        print("Webhook URL could not be loaded. Exiting.")
        return

    # Load the OUI database
    try:
        oui_data = load_oui_database(OUI_JSON_PATH)
    except RuntimeError as e:
        print(e)
        return

    # Extract and send device data
    device_data = extract_device_data(log_file, oui_data)
    if device_data:
        print("\nSending data to Tines for processing...")
        send_to_tines(device_data, webhook_url)


if __name__ == "__main__":
    main()
