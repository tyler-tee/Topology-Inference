import json
from collections import defaultdict
import networkx as nx
import matplotlib.pyplot as plt

# Configuration
EVE_LOG_PATH = "/var/log/suricata/eve.json"  # Path to eve.json
OUTPUT_GRAPH = "network_topology_improved.png"  # Output graph image
INTERNAL_IP_PREFIX = "192.168."  # Filter to include only internal traffic

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
                        # Filter only internal traffic
                        if src_ip.startswith(INTERNAL_IP_PREFIX) or dest_ip.startswith(INTERNAL_IP_PREFIX):
                            connections[src_ip].add((dest_ip, proto))
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

    # Adjust node size based on degree (heavily connected nodes are larger)
    node_size = [G.degree(node) * 300 for node in G.nodes()]

    # Generate positions
    pos = nx.spring_layout(G, seed=42)  # Fixed layout for consistency

    # Draw the graph
    plt.figure(figsize=(12, 8))
    nx.draw(
        G, pos, with_labels=True,
        node_size=node_size, node_color='skyblue',
        font_size=8, font_color="black"
    )

    # Draw edge labels (optional: suppress if too cluttered)
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)

    plt.title("Enhanced Network Topology")
    plt.savefig(output_graph)
    plt.show()

def main():
    # Parse Suricata logs
    connections, devices = parse_eve_json(EVE_LOG_PATH)
    print(f"Discovered {len(devices)} devices and {sum(len(v) for v in connections.values())} connections.")

    # Deduplicate connections
    deduplicated_connections = deduplicate_connections(connections)
    print(f"Topology includes {len(deduplicated_connections)} unique connections.")

    # Visualize the topology
    visualize_topology(deduplicated_connections, OUTPUT_GRAPH)
    print(f"Enhanced topology graph saved to {OUTPUT_GRAPH}")

if __name__ == "__main__":
    main()
