import os
import json
import csv
import requests
from collections import defaultdict

OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
DEFAULT_OUI_CSV_PATH = "oui.csv"
DEFAULT_OUI_JSON_PATH = "oui.json"


def download_oui_database(file_path):
    """
    Download the OUI database from IEEE if it does not exist locally.
    """
    try:
        print(f"Downloading OUI database from {OUI_CSV_URL}...")
        response = requests.get(OUI_CSV_URL)
        response.raise_for_status()
        with open(file_path, "wb") as f:
            f.write(response.content)
        print(f"OUI database downloaded and saved to {file_path}.")
    except Exception as e:
        print(f"Failed to download OUI database: {e}")
        raise


def convert_csv_to_json(csv_path, json_path):
    """
    Convert the OUI CSV database to a JSON file for faster lookups.
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
        raise


def load_oui_database(json_path, csv_path):
    """
    Load the OUI database from a JSON file, or convert CSV to JSON if needed.
    """
    # Check for JSON file
    if os.path.exists(json_path):
        try:
            with open(json_path, "r") as json_file:
                return json.load(json_file)
        except Exception as e:
            print(f"Error loading OUI JSON file: {e}")

    # Fallback to CSV file and convert to JSON
    if not os.path.exists(csv_path):
        print(f"OUI database CSV not found. Downloading...")
        download_oui_database(csv_path)

    # Convert CSV to JSON
    convert_csv_to_json(csv_path, json_path)

    # Load the newly created JSON file
    return load_oui_database(json_path, csv_path)


def lookup_mac_vendor(mac_address, oui_database):
    """
    Look up the MAC vendor locally, with a fallback to the macvendors.com API.
    """
    mac_prefix = mac_address[:8].upper().replace(":", "-")  # Format as OUI style
    # Check local database
    vendor = oui_database.get(mac_prefix)
    if vendor:
        return vendor

    # Fallback to macvendors.com API
    try:
        print(f"MAC not found locally. Querying API for: {mac_address}")
        response = requests.get(f"https://api.macvendors.com/v1/{mac_address}")
        if response.status_code == 200:
            vendor = response.text
            return vendor.strip()
        else:
            print(f"API Error: Status {response.status_code}")
            return "Unknown Vendor"
    except Exception as e:
        print(f"API Lookup Error: {e}")
        return "Unknown Vendor"


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


def main():
    # Path to the Suricata eve.json log file
    log_file = "/var/log/suricata/eve.json"  # Update with your actual path
    # Paths to the OUI database files
    oui_csv_path = DEFAULT_OUI_CSV_PATH
    oui_json_path = DEFAULT_OUI_JSON_PATH

    # Load the OUI database
    oui_data = load_oui_database(oui_json_path, oui_csv_path)

    # Extract and print enriched device data
    device_data = extract_device_data(log_file, oui_data)
    if device_data:
        for mac, data in device_data.items():
            print(f"MAC: {mac}, Vendor: {data['vendor']}, IP: {data['ip']}")
            print(f"Traffic Sent: {data['traffic']['bytes_sent']} bytes, Received: {data['traffic']['bytes_received']} bytes")
            print("Activity Log:")
            for activity in data["activity"]:
                print(f"  - {activity}")


if __name__ == "__main__":
    main()
