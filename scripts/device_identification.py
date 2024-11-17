import json
from collections import defaultdict

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

def extract_device_data(log_file):
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
                            devices[src_mac]["vendor"] = lookup_mac_vendor(src_mac)
                        devices[src_mac]["ip"] = src_ip
                        devices[src_mac]["traffic"]["bytes_sent"] += bytes_toserver
                        devices[src_mac]["activity"].append(f"Sent {bytes_toserver} bytes to {dest_ip}")

                    # Process destination MAC addresses
                    for dest_mac in dest_macs:
                        if dest_mac not in devices:
                            devices[dest_mac]["mac"] = dest_mac
                            devices[dest_mac]["vendor"] = lookup_mac_vendor(dest_mac)
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

    # Extract and print enriched device data
    device_data = extract_device_data(log_file)
    if device_data:
        for mac, data in device_data.items():
            print(f"MAC: {mac}, Vendor: {data['vendor']}, IP: {data['ip']}")
            print(f"Traffic Sent: {data['traffic']['bytes_sent']} bytes, Received: {data['traffic']['bytes_received']} bytes")
            print("Activity Log:")
            for activity in data["activity"]:
                print(f"  - {activity}")


if __name__ == "__main__":
    main()
