from scapy.all import sniff, get_if_list, wrpcap
import time

captured_packets = []

def list_interfaces():
    interfaces = get_if_list()
    print("Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    return interfaces

def sniff_packets(iface):
    global captured_packets
    print(f"\n[+] Starting packet sniffing on interface: {iface}... Press Ctrl+C to stop.\n")
    try:
        while True:
            print("[+] Sniffing packets for 5 seconds...\n")
            packets = sniff(iface=iface, timeout=5)
            captured_packets.extend(packets)
            for pkt in packets:
                print(pkt.summary())
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user. Saving packets to 'captured.pcap'...\n")
        try:
            wrpcap("captured.pcap", captured_packets)
            print("[+] Packets saved successfully to captured.pcap. Now you can open in Wireshark and feel like NSA.")
        except Exception as e:
            print(f"[!] Failed to save packets: {e}")

def main():
    interfaces = list_interfaces()
    try:
        choice = int(input("\nEnter the number of the interface you want to use: "))
        if choice < 0 or choice >= len(interfaces):
            print("Invalid choice, illleda. Interface not found.")
            return
        selected_iface = interfaces[choice]
        sniff_packets(selected_iface)
    except ValueError:
        print("Aiyo da, number la... not your MySejahtera IC.")
    except KeyboardInterrupt:
        print("\n[!] Program interrupted by user. Go drink Milo and relax.")

if __name__ == "__main__":
    main()
