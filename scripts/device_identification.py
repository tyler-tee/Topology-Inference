import json
import requests
from collections import defaultdict

# Function to load MAC vendor data (replace with a proper lookup or API if needed)
def lookup_mac_vendor(mac_address):
    """
    Perform a MAC vendor lookup using the OUI prefix.
    Replace with a vendor API or database for more accurate results.
    """
    mac_prefix = mac_address[:8].upper()  # First 8 characters as OUI
    # Sample vendor mappings; expand or replace with actual data
    vendor_data = {
        "00:1A:2B": "Cisco Systems",
        "D4:6E:0E": "Apple, Inc.",
        "3C:5A:B4": "Samsung Electronics",
    }
    return vendor_data.get(mac_prefix, "Unknown Vendor")

# Function to extract and enrich device data from eve.json
def extract_device_data(log_file):
    """
    Extract devices from eve.json and enrich with basic information.
    """
    devices = defaultdict(lambda: {"mac": None, "ip": None, "vendor": "Unknown", "activity": []})

    try:
        with open(log_file, "r") as f:
            for line in f:
                event = json.loads(line)

                # Process ARP or flow events for MAC and IP
                if event.get("event_type") in ["flow", "arp"]:
                    src_ip = event.get("src_ip")
                    src_mac = event.get("src_mac")
                    dest_ip = event.get("dest_ip")
                    dest_mac = event.get("dest_mac")

                    # Enrich source device
                    if src_mac:
                        devices[src_mac]["mac"] = src_mac
                        devices[src_mac]["ip"] = src_ip
                        devices[src_mac]["vendor"] = lookup_mac_vendor(src_mac)
                        devices[src_mac]["activity"].append(f"Communicated with {dest_ip}")

                    # Enrich destination device
                    if dest_mac:
                        devices[dest_mac]["mac"] = dest_mac
                        devices[dest_mac]["ip"] = dest_ip
                        devices[dest_mac]["vendor"] = lookup_mac_vendor(dest_mac)
                        devices[dest_mac]["activity"].append(f"Communicated with {src_ip}")

        return devices
    except Exception as e:
        print(f"Error processing log file: {e}")
        return None


def main():
    # Path to the Suricata eve.json log file
    log_file = "/var/log/suricata/eve.json"  # Update with your path

    # Extract and print enriched device data
    device_data = extract_device_data(log_file)
    if device_data:
        for mac, data in device_data.items():
            print(f"MAC: {mac}, IP: {data['ip']}, Vendor: {data['vendor']}")
            print("Activity Log:")
            for activity in data["activity"]:
                print(f"  - {activity}")


# Debugging: Print device data
if __name__ == "__main__":
    main()
