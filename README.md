# **Programmatic Network Inference**

A project dedicated to exploring how to programmatically visualize, understand, and describe the layout of a network and its inhabitants. By leveraging Suricata, Python, and an LLM of your choosing, these tools may offer a structured approach to analyzing network activity and generating actionable insights.

This project is intended as a proof of concept and a learning tool for those interested in this sort of thing. It is not designed for production environments but rather as a starting point for exploring the intersection of network monitoring, automation, and AI.

Objectives:

- Parse and enrich network traffic data.
- Visualize device relationships and roles.
- Use an LLM to produce human-readable summaries and recommendations for network analysis.

 ![image](https://github.com/user-attachments/assets/169d724b-1e2f-4eaf-be48-844896e72eac)


---

## **Features**
- Extracts data from Suricata's `eve.json` logs.
- Identifies devices by MAC address, IP, and vendor.
- Summarizes traffic activity (bytes sent/received) and interaction patterns.
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
- Internet access for downloading the OUI database or using fallback APIs.

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

### **2. Run the Script**
Process your `eve.json` log file and send data to Tines:
```bash
python device_identification.py
```

### **3. Workflow**
The script will:
1. Extract MAC addresses, IPs, and traffic activity from the `eve.json` log.
2. Perform vendor lookups using the OUI database or fallback API.
3. Send structured JSON data to the Tines webhook for LLM analysis.

---

## **Example Outputs**

### **Structured Payload Sent to Tines**
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

### **LLM Prompt in Tines**
```plaintext
You are a network analyst tasked with interpreting network activity summaries and generating clear, concise reports for a non-technical audience.

Here is a summary of network activity:

{{devices}}

Can you summarize this activity in plain language?
```

---

## **Scripts Overview**

### **1. `device_identification.py`**
- **Purpose**: Core script for processing Suricata logs and interacting with Tines.
- **Key Functions**:
  - `load_webhook_url()`: Loads Tines webhook URL from `config.json`.
  - `extract_device_data()`: Extracts device information from `eve.json` logs.
  - `lookup_mac_vendor()`: Resolves MAC vendors using the OUI database or fallback API.
  - `send_to_tines()`: Sends structured data to Tines for LLM analysis.

### **2. Utility Functions**
- **OUI Database Handling**:
  - Downloads the OUI CSV from IEEE and converts it to JSON.
  - Uses the JSON database for fast MAC vendor lookups.
- **Error Handling**:
  - Handles missing logs, config files, and network errors gracefully.

### **3. Prompts**
- Stored in the `prompts/` directory for Tines workflows.
- Includes task-specific guidance for the LLM, e.g., device classification and traffic analysis.

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
