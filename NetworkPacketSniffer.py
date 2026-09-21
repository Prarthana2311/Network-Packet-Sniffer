import socket
import struct
import sys
import time
from collections import defaultdict

# Statistical counters
stats = {
    "total_packets": 0,
    "total_bytes": 0,
    "protocols": defaultdict(int),
}

LOG_FILE = "traffic_summary.log"


def parse_ip_header(raw_buffer: bytes):
    """
    Parses IPv4 Header:
    First 20 bytes contain Version, IHL, Total Length, Protocol, Src IP, Dst IP.
    """
    ip_header = raw_buffer[:20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4  # Internet Header Length in bytes
    protocol_num = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    return {
        "version": version,
        "ihl": ihl,
        "protocol": protocol_num,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "payload": raw_buffer[ihl:],
    }


def parse_tcp_header(transport_buffer: bytes):
    """Parses TCP Header (first 20 bytes minimum)."""
    tcph = struct.unpack("!HHLLBBHHH", transport_buffer[:20])
    src_port = tcph[0]
    dst_port = tcph[1]
    offset = (tcph[4] >> 4) * 4  # Data offset
    payload = transport_buffer[offset:]
    return src_port, dst_port, payload


def parse_udp_header(transport_buffer: bytes):
    """Parses UDP Header (8 bytes)."""
    udph = struct.unpack("!HHHH", transport_buffer[:8])
    src_port = udph[0]
    dst_port = udph[1]
    length = udph[2]
    payload = transport_buffer[8:length]
    return src_port, dst_port, payload


def log_summary():
    """Writes protocol statistics to a summary file."""
    with open(LOG_FILE, "w") as f:
        f.write("=" * 50 + "\n")
        f.write(f"NETWORK TRAFFIC AUDIT REPORT - {time.ctime()}\n")
        f.write("=" * 50 + "\n")
        f.write(f"Total Packets Processed : {stats['total_packets']}\n")
        f.write(f"Total Bytes Inspected   : {stats['total_bytes']} bytes\n")
        f.write("-" * 50 + "\n")
        f.write("Protocol Breakdown:\n")
        for proto, count in stats["protocols"].items():
            pct = (count / stats["total_packets"] * 100) if stats["total_packets"] else 0
            f.write(f"  - {proto:<8}: {count} packets ({pct:.1f}%)\n")
        f.write("=" * 50 + "\n")


def main():
    # Create raw network socket
    try:
        # Linux: captures raw IPv4 packets
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # Note: To capture all IP protocols on Linux, use socket.ntohs(0x0800) with AF_PACKET
    except PermissionError:
        print("[!] Error: Root/administrator privileges required to open raw sockets.")
        print("    Try running with: sudo python3 packet_sniffer.py")
        sys.exit(1)
    except AttributeError:
        # Fallback for platforms without IPPROTO_TCP raw support
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    print("[*] Sniffer active. Capturing raw buffers... (Press Ctrl+C to stop)")
    print("-" * 75)
    print(f"{'Protocol':<8} | {'Source IP:Port':<25} -> {'Destination IP:Port':<25} | {'Payload'}")
    print("-" * 75)

    try:
        while True:
            raw_data, _ = s.recvfrom(65535)
            stats["total_packets"] += 1
            stats["total_bytes"] += len(raw_data)

            ip = parse_ip_header(raw_data)
            proto = ip["protocol"]

            # TCP
            if proto == 6:
                stats["protocols"]["TCP"] += 1
                src_port, dst_port, payload = parse_tcp_header(ip["payload"])
                src_str = f"{ip['src_ip']}:{src_port}"
                dst_str = f"{ip['dst_ip']}:{dst_port}"
                print(f"{'TCP':<8} | {src_str:<25} -> {dst_str:<25} | {len(payload)} bytes")

            # UDP
            elif proto == 17:
                stats["protocols"]["UDP"] += 1
                src_port, dst_port, payload = parse_udp_header(ip["payload"])
                src_str = f"{ip['src_ip']}:{src_port}"
                dst_str = f"{ip['dst_ip']}:{dst_port}"
                print(f"{'UDP':<8} | {src_str:<25} -> {dst_str:<25} | {len(payload)} bytes")

            # ICMP / Other
            elif proto == 1:
                stats["protocols"]["ICMP"] += 1
                print(f"{'ICMP':<8} | {ip['src_ip']:<25} -> {ip['dst_ip']:<25} | Header only")
            else:
                stats["protocols"][f"Proto-{proto}"] += 1

    except KeyboardInterrupt:
        print("\n[*] Stopping capture. Generating statistics report...")
        log_summary()
        print(f"[+] Audit summary saved to '{LOG_FILE}'.")


if __name__ == "__main__":
    main()