from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def process_packet(packet):
    print("\n" + "=" * 60)

    if packet.haslayer(IP):
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")
        else:
            print("Protocol       : Other")

        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                print(f"Payload        : {payload}")
            except:
                print("Payload        : Unable to decode")
        else:
            print("Payload        : No Payload")

        print("\nPacket Summary:")
        print(packet.summary())

print("Starting Network Sniffer...")
print("Press Ctrl + C to stop.\n")

sniff(prn=process_packet, store=False)
