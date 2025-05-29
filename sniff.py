from scapy.all import sniff, get_if_list, wrpcap, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, ARP
from datetime import datetime
import pandas as pd

captured_packets = []
log_rows = []

def list_interfaces():
    interfaces = get_if_list()
    print("Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    return interfaces

def parse_packet(pkt):
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    row = {
        "Timestamp": time_str,
        "Protocol": "UNKNOWN",
        "Source IP": "",
        "Source Port": "",
        "Destination IP": "",
        "Destination Port": "",
        "Flags": "",
        "Length": len(pkt),
        "Info": pkt.summary()
    }

    # IPv4
    if IP in pkt:
        row["Source IP"] = pkt[IP].src
        row["Destination IP"] = pkt[IP].dst

        if TCP in pkt:
            row["Protocol"] = "TCP"
            row["Source Port"] = pkt[TCP].sport
            row["Destination Port"] = pkt[TCP].dport
            row["Flags"] = pkt.sprintf('%TCP.flags%')
            row["Info"] = f"TCP Flags: {row['Flags']} Seq={pkt[TCP].seq} Ack={pkt[TCP].ack}"

        elif UDP in pkt:
            return  # Skip UDP
        elif ICMP in pkt:
            row["Protocol"] = "ICMP"
            row["Info"] = f"ICMP Type: {pkt[ICMP].type} Code: {pkt[ICMP].code}"
        else:
            row["Protocol"] = f"IP(proto={pkt[IP].proto})"

    # IPv6
    elif IPv6 in pkt:
        row["Source IP"] = pkt[IPv6].src
        row["Destination IP"] = pkt[IPv6].dst

        if TCP in pkt:
            row["Protocol"] = "TCPv6"
            row["Source Port"] = pkt[TCP].sport
            row["Destination Port"] = pkt[TCP].dport
            row["Flags"] = pkt.sprintf('%TCP.flags%')
            row["Info"] = f"TCP Flags: {row['Flags']} Seq={pkt[TCP].seq} Ack={pkt[TCP].ack}"

        elif UDP in pkt:
            return  # Skip UDP
        elif ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt:
            row["Protocol"] = "ICMPv6"
            row["Info"] = "ICMPv6 Echo Request/Reply"
        else:
            row["Protocol"] = f"IPv6(nh={pkt[IPv6].nh})"

    elif ARP in pkt:
        row["Protocol"] = "ARP"
        row["Source IP"] = pkt[ARP].psrc
        row["Destination IP"] = pkt[ARP].pdst
        row["Info"] = f"ARP OP: {pkt[ARP].op}"

    log_rows.append(row)

    # Console output
    print(f"[{time_str}] {row['Protocol']} | {row['Source IP']}:{row['Source Port']} → {row['Destination IP']}:{row['Destination Port']} | Info: {row['Info']}")

def sniff_packets(iface):
    global captured_packets
    print(f"\n💻 Sniffing on: {iface} — 30 seconds only, boss\n")
    try:
        # Sniff for 30 seconds
        captured_packets = sniff(iface=iface, prn=parse_packet, store=True, timeout=30)

        # Save to .pcap
        wrpcap("captured.pcap", captured_packets)
        print("✅ Packets saved to captured.pcap.")

        # Convert to DataFrame
        df = pd.DataFrame(log_rows)

        # Save to CSV
        df.to_csv("packets_log.csv", index=False)
        print("✅ Packet details saved to packets_log.csv.")

        # Save to Excel (.xlsx)
        df.to_excel("packets_log.xlsx", index=False)
        print("✅ Packet details also saved to packets_log.xlsx. Power la you now.")

    except Exception as e:
        print(f"❌ Something went wrong la bosku: {e}")


def main():
    interfaces = list_interfaces()
    try:
        choice = int(input("\nEnter the number of the interface you want to use: "))
        if choice < 0 or choice >= len(interfaces):
            print("Invalid choice, illeda. Go drink kopi and try again.")
            return
        selected_iface = interfaces[choice]
        sniff_packets(selected_iface)
    except ValueError:
        print("Aiyo da, number la... not your IC number.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted before sniffing even started. You semangat habis already ke?")

if __name__ == "__main__":
    main()
