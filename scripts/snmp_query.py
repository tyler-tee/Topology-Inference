from pysnmp.hlapi import *
import networkx as nx

def snmp_walk(ip, community, oid):
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False):

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print(f'{errorStatus.prettyPrint()} at {errorIndex}')
            break
        else:
            for varBind in varBinds:
                yield varBind

def get_lldp_neighbors(ip, community):
    lldp_neighbors = {}
    # OID for LLDP Remote System Name: lldpRemSysName
    lldp_rem_sys_name_oid = '1.0.8802.1.1.2.1.4.1.1.9'
    for varBind in snmp_walk(ip, community, lldp_rem_sys_name_oid):
        oid, value = varBind
        # The OID will contain indices identifying the local port and remote device
        # OID format: lldpRemSysName.<localPortNum>.<lldpRemIndex>
        oid_parts = oid.prettyPrint().split('.')
        local_port_num = oid_parts[-2]
        lldp_rem_index = oid_parts[-1]
        neighbor_sys_name = str(value)
        lldp_neighbors[neighbor_sys_name] = {
            'local_port': local_port_num,
            'remote_index': lldp_rem_index
        }
    return lldp_neighbors

# Initialize graph
G = nx.Graph()

# Seed device
seed_device_ip = '192.168.39.60'
community = 'public'

# Discover neighbors
neighbors = get_lldp_neighbors(seed_device_ip, community)
for neighbor_name, neighbor_info in neighbors.items():
    neighbor_identifier = neighbor_name  # Using system name as identifier
    G.add_edge(seed_device_ip, neighbor_identifier)

    # Optional: Recursively discover neighbors of the neighbor
    # neighbor_ip = resolve_ip_from_sysname(neighbor_identifier)  # Implement DNS lookup if needed
    # Further discovery code...

# Visualize the topology
import matplotlib.pyplot as plt
nx.draw(G, with_labels=True)
plt.show()
