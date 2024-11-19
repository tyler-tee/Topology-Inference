**Programmatic Network Inference**

A project dedicated to exploring how to programmatically visualize, understand, and describe the layout of a network and its inhabitants. By leveraging Suricata, Python, and an LLM of your choosing, these tools may offer a structured approach to analyzing network activity and generating actionable insights.

This project is intended as a proof of concept and a learning tool for those interested in this sort of thing. It is not designed for production environments but rather as a starting point for exploring the intersection of network monitoring, automation, and AI.

## **Objectives**

- Parse and enrich network traffic data.
- Visualize device relationships and roles.
- Use an LLM to produce human-readable summaries and recommendations for network analysis.

---

## **Features**
- Extracts data from Suricata's `eve.json` logs.
- Identifies devices by MAC address, IP, and vendor.
- Summarizes traffic activity (bytes sent/received) and interaction patterns.
- Visualizes device relationships and network topologies.
- Analyzes behavioral patterns to identify potential anomalies.
- Sends structured data to Tines for LLM-driven analysis.
- Handles missing configuration files and automates OUI database setup.

---

## **Getting Started**

### **1. Clone the Repository**
```bash
git clone https://github.com/tyler-tee/programmatic-network-inference.git
cd programmatic-network-inference
```

### **2. Prerequisites**
- Python 3.8+
- Suricata logs (`eve.json`) configured to include `flow` and `ether` events.
- A valid **Tines Webhook URL**.

### **3. Installation**
Install the required Python dependencies:
```bash
pip install -r requirements.txt
```

---

## **Usage**

### **1. Configure `config.json`**
Create a `config.json` file in the project directory:
```json
{
  "TINES_WEBHOOK_URL": "https://your-tines-webhook-url.com"
}
```

### **2. Run the Scripts**
- **Device identification**:
  ```bash
  python device_identification.py
  ```
- **Generating network topology diagrams**:
  ```bash
  python topology_generation.py
  ```
- **Analyzing network behavior patterns**:
  ```bash
  python net_behavior_analysis.py
  ```

---

## **Scripts Overview**

### **1. `device_identification.py`**
- **Purpose**: Core script for processing Suricata logs and interacting with Tines.
- **Key Functions**:
  - `extract_device_data()`: Extracts device information from `eve.json` logs.
  - `lookup_mac_vendor()`: Resolves MAC vendors using the OUI database or fallback API.
  - `send_to_tines()`: Sends structured data to Tines for LLM analysis.

### **2. `topology_generation.py`**
- **Purpose**: Generates network topology diagrams from Suricata's `eve.json` logs.
- **Key Features**:
  - Parses `eve.json` to identify devices and their connections.
  - Uses Matplotlib and NetworkX to visualize relationships as a network graph.
  - Outputs a PNG diagram (`network_topology.png`) for analysis and reporting.
- **Usage Notes**:
  - Ensure `eve.json` contains `flow` and `ether` events for accurate topology generation.

### **3. `net_behavior_analysis.py`**
- **Purpose**: Analyzes network behavioral patterns to identify potential anomalies.
- **Key Features**:
  - Processes Suricata logs to extract behavioral data (e.g., traffic volume, protocol usage).
  - Compares observed patterns against predefined thresholds or baselines.
  - Outputs structured data for further review or integration with Tines.
- **Example Output**:
  ```json
  {
    "anomalies": [
      {
        "src_ip": "192.168.1.10",
        "issue": "Excessive traffic volume detected",
        "details": {
          "bytes_sent": 1048576,
          "bytes_received": 2097152
        }
      }
    ]
  }
  ```

---

## **Example Outputs**

### **Device Identification Structured Payload**
```json
{
  "devices": [
    {
      "mac": "98:2C:BC:6A:D7:40",
      "ip": "192.168.1.10",
      "vendor": "Cisco Systems",
      "traffic": {
        "bytes_sent": 12345,
        "bytes_received": 67890
      },
      "activity": [
        "Sent 12345 bytes to 192.168.1.1",
        "Received 67890 bytes from 192.168.1.254"
      ]
    }
  ]
}
```

### **Network Topology Diagram**
The `topology_generation.py` script produces a diagram similar to the following:
 ![image](https://github.com/user-attachments/assets/169d724b-1e2f-4eaf-be48-844896e72eac)


---

## **Setup Notes**

1. **Suricata Configuration**:
   - Ensure `eve.json` includes `flow` and `ether` events to capture MAC addresses and traffic data.
   - Refer to [Suricata Configuration](https://suricata.readthedocs.io/en/latest/) for details.

2. **Tines Workflow**:
   - Configure your Tines story to handle the JSON payload and pass it to the LLM for analysis.

3. **Fallback Mechanism**:
   - If the OUI database is unavailable, the script uses `https://api.macvendors.com` for vendor lookups.

---

## **License**
This project is licensed under the [MIT License](LICENSE).