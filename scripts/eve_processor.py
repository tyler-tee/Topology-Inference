import json
import requests

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


def prepare_summary_payload(log_file):
    """
    Extract relevant network data from a Suricata eve.json log file and structure it for Tines.
    """
    payload = {"devices": {}, "protocols": {}}

    try:
        with open(log_file, "r") as f:
            for line in f:
                event = json.loads(line)

                # Process only "flow" event types
                if event.get("event_type") != "flow":
                    continue

                src_ip = event.get("src_ip")
                dest_ip = event.get("dest_ip")
                proto = event.get("proto", "unknown")
                flow = event.get("flow", {})
                bytes_toserver = flow.get("bytes_toserver", 0)
                bytes_toclient = flow.get("bytes_toclient", 0)
                pkts_toserver = flow.get("pkts_toserver", 0)
                pkts_toclient = flow.get("pkts_toclient", 0)

                # Initialize devices in the payload if not already present
                if src_ip not in payload["devices"]:
                    payload["devices"][src_ip] = {"traffic_sent": 0, "traffic_received": 0, "packets_sent": 0, "packets_received": 0}
                if dest_ip not in payload["devices"]:
                    payload["devices"][dest_ip] = {"traffic_sent": 0, "traffic_received": 0, "packets_sent": 0, "packets_received": 0}

                # Update traffic and packet counts for source and destination devices
                payload["devices"][src_ip]["traffic_sent"] += bytes_toserver
                payload["devices"][src_ip]["packets_sent"] += pkts_toserver
                payload["devices"][dest_ip]["traffic_received"] += bytes_toclient
                payload["devices"][dest_ip]["packets_received"] += pkts_toclient

                # Track protocols
                if proto:
                    payload["protocols"][proto] = payload["protocols"].get(proto, 0) + 1

        return payload
    except Exception as e:
        print(f"Error preparing summary payload: {e}")
        return None


def send_to_tines(payload, webhook_url):
    """
    Send the structured payload to a Tines webhook.
    """
    try:
        response = requests.post(webhook_url, json=payload)

        if response.status_code == 200:
            print("Data sent to Tines successfully!")
        else:
            print(f"Failed to send data: {response.status_code}, {response.text}")
    except Exception as e:
        print(f"Error sending data to Tines: {e}")


def main():
    # Path to the Suricata eve.json log file
    log_file = "/var/log/suricata/eve.json"  # Change as necessary

    # Path to the JSON configuration file
    config_file = "config.json"

    # Load the webhook URL
    tines_webhook_url = load_webhook_url(config_file)

    if not tines_webhook_url:
        print("Webhook URL could not be loaded. Exiting.")
    else:
        # Prepare the payload
        summary_payload = prepare_summary_payload(log_file)

        # Debugging: Print the payload for validation
        if summary_payload:
            print(json.dumps(summary_payload, indent=4))
        
        # Send the payload if it's not None
        if summary_payload:
            send_to_tines(summary_payload, tines_webhook_url)


if __name__ == "__main__":
    main()
