

from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import logging

# Rule definition
FIREWALL_RULES = {
    "block_ips": ["192.168.1.5"],
    "block_ports": [23, 25],
    "allow_protocols": ["TCP", "UDP"]
}

# Setup logging
logging.basicConfig(filename="firewall_log.txt", level=logging.INFO)

def log_packet(packet, reason):
    src = packet[IP].src if IP in packet else "Unknown"
    dst = packet[IP].dst if IP in packet else "Unknown"
    logging.info(f"{src} -> {dst} | {reason}")

def apply_firewall_rules(packet):
    if IP in packet:
        src_ip = packet[IP].src
        proto = packet[IP].proto
        protocol_name = {6: "TCP", 17: "UDP"}.get(proto, "OTHER")

        if src_ip in FIREWALL_RULES["block_ips"]:
            print(f"[BLOCKED] IP {src_ip}")
            log_packet(packet, "Blocked IP")
            return

        if TCP in packet and packet[TCP].dport in FIREWALL_RULES["block_ports"]:
            print(f"[BLOCKED] TCP port {packet[TCP].dport}")
            log_packet(packet, "Blocked Port")
            return

        if protocol_name not in FIREWALL_RULES["allow_protocols"]:
            print(f"[BLOCKED] Protocol {protocol_name}")
            log_packet(packet, "Disallowed Protocol")
            return

        print(f"[ALLOWED] {packet.summary()}")
        log_packet(packet, "Allowed")

# Start sniffing
print("Firewall is running... Press Ctrl+C to stop.")
sniff(prn=apply_firewall_rules, store=False)
