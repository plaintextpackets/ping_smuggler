import pyshark
import sys

def extract_icmp_data(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='icmp')
    for packet in cap:
        try:
            # Extracting ICMP data payload, which is in hex
            icmp_data_hex = packet.icmp.data
            # Convert hex to bytes then decode to ASCII
            icmp_data_ascii = bytes.fromhex(icmp_data_hex).decode('ascii', errors='ignore')
            print(icmp_data_ascii)
        except AttributeError:
            # In case the packet doesn't have ICMP data payload
            continue

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python icmp_parser.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    extract_icmp_data(pcap_file)
