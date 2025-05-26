from scapy.all import rdpcap
import pandas as pd


def pcap_to_excel(pcap_file, output_file):
    try:
        packets = rdpcap(pcap_file)
        data = []

        for pkt in packets:
            pkt_info = {
                "Time": pkt.time,
                "Source": pkt[0].src if hasattr(pkt[0], 'src') else None,
                "Destination": pkt[0].dst if hasattr(pkt[0], 'dst') else None,
                "Protocol": pkt.name,
                "Length": len(pkt),
                "Summary": pkt.summary()
            }
            data.append(pkt_info)

        df = pd.DataFrame(data)
        df.to_excel(output_file, index=False)
        print(f"[+] Successfully exported to {output_file}")

    except FileNotFoundError:
        print("[!] File not found da. Check your path la macha.")
    except Exception as e:
        print(f"[!] Something went wrong: {e}")


if __name__ == "__main__":
    pcap_path = "captured.pcap"
    output_excel = "captured.xlsx"
    pcap_to_excel(pcap_path, output_excel)