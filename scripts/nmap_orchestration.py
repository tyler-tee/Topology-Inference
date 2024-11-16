import subprocess
import xml.etree.ElementTree as ET

def run_nmap_scan(network_range):
    """
    Runs an Nmap scan and returns the results as XML.
    """
    try:
        output_file = "nmap_scan.xml"
        command = f"nmap -sV -oX {output_file} {network_range}"
        subprocess.run(command, shell=True, check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"Error running Nmap: {e}")
        return None

def parse_nmap_results(xml_file):
    """
    Parses Nmap XML results and extracts hosts and open ports.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts = []

    for host in root.findall('host'):
        ip_address = host.find("address[@addrtype='ipv4']").attrib['addr']
        ports = []
        for port in host.findall(".//port"):
            port_number = port.attrib['portid']
            state = port.find("state").attrib['state']
            service_element = port.find("service")
            service = service_element.attrib['name'] if service_element is not None else 'unknown'
            ports.append({'port': port_number, 'state': state, 'service': service})
        hosts.append({'ip': ip_address, 'ports': ports})
    return hosts


def main():
    # Define the network range
    network_range = "192.168.1.0/24"

    # Run Nmap scan
    xml_file = run_nmap_scan(network_range)
    if not xml_file:
        return

    # Parse Nmap results
    hosts = parse_nmap_results(xml_file)

    # Print results
    for host in hosts:
        print(f"Host: {host['ip']}")
        for port in host['ports']:
            print(f"  Port: {port['port']}, State: {port['state']}, Service: {port['service']}")

if __name__ == "__main__":
    main()
