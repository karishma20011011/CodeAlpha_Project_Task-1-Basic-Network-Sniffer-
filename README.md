# CodeAlpha_Project_Task-1-Basic-Network-Sniffer-
Basic Network Sniffer  Build a network sniffer in Python that captures and analyzes network traffic. This project will help you understand how data flows on a network and how network packets are structured.
pip install scapy
from scapy.all import *

# Callback function to handle packets
def packet_callback(packet):
    print(f"Packet: {packet.summary()}")

# Start sniffing
def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    if interface:
        sniff(iface=interface, prn=packet_callback, store=0)
    else:
        sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    # Replace 'eth0' with your network interface if needed
    # For example, use 'wlan0' for Wi-Fi on Linux, 'en0' on macOS, or 'Ethernet' on Windows.
    start_sniffing('eth0')
 Understanding the Code
Importing scapy: The from scapy.all import * line imports all the necessary functions and classes from scapy.

Callback Function: packet_callback is a function that will be called for every packet captured. It prints a summary of each packet.

Starting Sniffing: The start_sniffing function starts the packet capture. If an interface is provided (like 'eth0' or 'wlan0'), it captures packets only on that interface. Otherwise, it captures on all available interfaces.

4. Running the Sniffer
Run the script with Python. You may need to run it with superuser privileges, especially on Linux or macOS, to allow access to network interfaces:

sudo python your_sniffer_script.py


 Analyzing Packets
To analyze packets more deeply, you can enhance the packet_callback function. For example:
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP Packet: {ip_src} -> {ip_dst}")

    if packet.haslayer(TCP):
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        print(f"TCP Segment: {tcp_sport} -> {tcp_dport}")
        
    if packet.haslayer(UDP):
        udp_sport = packet[UDP].sport
        udp_dport = packet[UDP].dport
        print(f"UDP Datagram: {udp_sport} -> {udp_dport}")

    # Print the packet summary
    print(packet.summary())
Additional Considerations
Permissions: Capturing packets often requires administrative privileges. On Linux/macOS, use sudo. On Windows, run your script as an administrator.

Filters: To capture specific types of packets, you can add filters. For example, to capture only TCP packets, modify sniff to sniff(filter="tcp", prn=packet_callback, store=0).

Performance: Sniffing can be resource-intensive, especially with high network traffic. Consider adding logic to handle high traffic or limit the number of packets to capture.

Legal and Ethical Considerations: Ensure you have permission to capture network traffic on the network you're monitoring. Unauthorized sniffing can be illegal and unethical.

This simple sniffer is a starting point for understanding network traffic. For more advanced features, like parsing specific protocols or handling larger volumes of data, you might explore more complex functionalities in scapy or other network analysis tools.

