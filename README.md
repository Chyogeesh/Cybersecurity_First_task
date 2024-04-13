# Cybersecurity_First_task
#It is a internship assignment
from scapy.all import *

# Define a function to sniff packets
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source IP: {ip_src} --> Destination IP: {ip_dst}")

# Start sniffing packets
print("Starting network sniffer...")
sniff(prn=packet_callback, store=0)
