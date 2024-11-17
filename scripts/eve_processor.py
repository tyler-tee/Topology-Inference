import json
import requests
from collections import defaultdict
import networkx as nx
import matplotlib.pyplot as plt

# Configuration
EVE_LOG_PATH = "/var/log/suricata/eve.json"  # Path to eve.json
OUTPUT_GRAPH = "network_topology.png"  # Output graph image
INTERNAL_IP_PREFIX = "192.168."  # Filter to include only internal traffic
EXTERNAL_NODE = "External Network"


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


def parse_eve_json(eve_log_path):
    """
    Parse Suricata's eve.json to extract connections.
    :param eve_log_path: Path to eve.json
    :return: Dictionary of connections and a set of all devices
    """
    connections = defaultdict(set)
    devices = set()
    try:
        with open(eve_log_path, "r") as f:
            for line in f:
                event = json.loads(line.strip())
                if event.get("event_type") == "flow":  # Focus on flow events
                    src_ip = event.get("src_ip")
                    dest_ip = event.get("dest_ip")
                    proto = event.get("proto")
                    if src_ip and dest_ip:
                        if src_ip.startswith(INTERNAL_IP_PREFIX) and dest_ip.startswith(INTERNAL_IP_PREFIX):
                            connections[src_ip].add((dest_ip, proto))
                        else:  # Group external traffic
                            if src_ip.startswith(INTERNAL_IP_PREFIX):
                                connections[src_ip].add((EXTERNAL_NODE, proto))
                            elif dest_ip.startswith(INTERNAL_IP_PREFIX):
                                connections[dest_ip].add((EXTERNAL_NODE, proto))
                        devices.update([src_ip, dest_ip])
    except FileNotFoundError:
        print(f"Error: {eve_log_path} not found.")
    return connections, devices

def deduplicate_connections(connections):
    """
    Deduplicate bidirectional connections (A -> B and B -> A).
    :param connections: Dictionary of connections
    :return: Deduplicated set of connections
    """
    seen = set()
    deduplicated = set()
    for src, conns in connections.items():
        for dest, proto in conns:
            if (src, dest) not in seen and (dest, src) not in seen:
                deduplicated.add((src, dest, proto))
                seen.add((src, dest))
    return deduplicated

def group_by_subnet(ip):
    """
    Groups IPs by their /24 subnet.
    :param ip: IP address as a string
    :return: Subnet string
    """
    if ip.startswith(INTERNAL_IP_PREFIX):
        return '.'.join(ip.split('.')[:3]) + ".0/24"
    return "External"

def visualize_topology(connections, output_graph):
    """
    Visualize the network topology using networkx.
    :param connections: Deduplicated connections
    :param output_graph: Path to save the output graph image
    """
    G = nx.Graph()

    # Add nodes and edges
    for src, dest, proto in connections:
        G.add_edge(src, dest, label=proto)

    # Highlight key nodes based on degree centrality
    centrality = nx.degree_centrality(G)
    node_size = [300 + centrality[node] * 2000 for node in G.nodes()]
    node_color = [
        'skyblue' if group_by_subnet(node) != "External" else 'lightcoral'
        for node in G.nodes()
    ]

    # Subnet-based clustering
    clusters = defaultdict(list)
    for node in G.nodes():
        clusters[group_by_subnet(node)].append(node)

    # Generate positions
    pos = nx.spring_layout(G, seed=42)  # Fixed layout for consistency

    # Draw the graph
    plt.figure(figsize=(12, 8))
    nx.draw(
        G, pos, with_labels=True,
        node_size=node_size, node_color=node_color,
        font_size=8, font_color="black"
    )

    # Optional: Suppress edge labels if too cluttered
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)

    plt.title("Clustered Network Topology with Subnets")
    plt.savefig(output_graph)
    plt.show()


def send_to_webhook(image_path, webhook_url):
    """
    Sends the generated topology diagram to a webhook.
    """
    try:
        with open(image_path, 'rb') as image_file:
            files = {'file': image_file}
            response = requests.post(webhook_url, files=files)
            if response.status_code == 200:
                print(f"Diagram successfully uploaded!")
            else:
                print(f"Failed to send diagram. Status code: {response.status_code}")
                print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error sending to webhook: {e}")


def main():
    WEBHOOK_URL = load_webhook_url("config.json")
    # Parse Suricata logs
    connections, devices = parse_eve_json(EVE_LOG_PATH)
    print(f"Discovered {len(devices)} devices and {sum(len(v) for v in connections.values())} connections.")

    # Deduplicate connections
    deduplicated_connections = deduplicate_connections(connections)
    print(f"Topology includes {len(deduplicated_connections)} unique connections.")

    # Visualize the topology
    visualize_topology(deduplicated_connections, OUTPUT_GRAPH)
    print(f"Clustered topology graph saved to {OUTPUT_GRAPH}")

    # Send the diagram to the webhook
    if WEBHOOK_URL:
        send_to_webhook(OUTPUT_GRAPH, WEBHOOK_URL)

if __name__ == "__main__":
    main()
