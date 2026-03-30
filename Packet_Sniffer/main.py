from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, Raw
from collections import defaultdict
import sys
import time

# ARP table pentru detectie ARP spoofing
arp_table = {}
# Statistici trafic
stats = defaultdict(int)
start_time = None

COLORS = {
    "TCP":    "\033[94m",   # albastru
    "UDP":    "\033[92m",   # verde
    "ICMP":   "\033[93m",   # galben
    "DNS":    "\033[96m",   # cyan
    "HTTP":   "\033[95m",   # mov
    "ARP":    "\033[91m",   # rosu
    "ALERT":  "\033[1;91m", # rosu bold
    "RESET":  "\033[0m"
}

def colorize(tag, text):
    return f"{COLORS.get(tag, '')}{text}{COLORS['RESET']}"

def detect_arp_spoof(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # ARP reply
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        if src_ip in arp_table and arp_table[src_ip] != src_mac:
            print(colorize("ALERT", f"\n  [!! ARP SPOOF DETECTED !!] {src_ip} changed MAC: {arp_table[src_ip]} -> {src_mac}\n"))
            stats["arp_spoofs"] += 1
        arp_table[src_ip] = src_mac

def process_packet(pkt):
    global start_time
    if start_time is None:
        start_time = time.time()

    # ARP spoofing detection
    if ARP in pkt:
        detect_arp_spoof(pkt)
        stats["ARP"] += 1
        if pkt[ARP].op == 1:
            print(colorize("ARP", f"[ARP]  Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}"))
        elif pkt[ARP].op == 2:
            print(colorize("ARP", f"[ARP]  {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"))
        return

    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    size = len(pkt)

    # DNS
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
        print(colorize("DNS", f"[DNS]  {src:15} -> {dst:15}  Query: {query}"))
        stats["DNS"] += 1
        return

    # HTTP (port 80, cu payload)
    if TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80) and pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors="replace")
        first_line = payload.splitlines()[0] if payload.splitlines() else ""
        if any(method in first_line for method in ["GET", "POST", "PUT", "DELETE", "HEAD"]):
            print(colorize("HTTP", f"[HTTP] {src:15} -> {dst:15}  {first_line[:80]}"))
            stats["HTTP"] += 1
            return

    # TCP
    if TCP in pkt:
        flags = pkt[TCP].flags
        flag_str = str(flags)
        print(f"[TCP]  {src:15}:{pkt[TCP].sport:<5} -> {dst:15}:{pkt[TCP].dport:<5}  Flags: {flag_str:4}  Size: {size}")
        stats["TCP"] += 1
        return

    # UDP
    if UDP in pkt:
        print(colorize("UDP", f"[UDP]  {src:15}:{pkt[UDP].sport:<5} -> {dst:15}:{pkt[UDP].dport:<5}  Size: {size}"))
        stats["UDP"] += 1
        return

    # ICMP
    if ICMP in pkt:
        icmp_type = pkt[ICMP].type
        type_name = {0: "Echo Reply", 8: "Echo Request", 3: "Unreachable", 11: "TTL Expired"}.get(icmp_type, f"Type {icmp_type}")
        print(colorize("ICMP", f"[ICMP] {src:15} -> {dst:15}  {type_name}"))
        stats["ICMP"] += 1
        return

def print_stats():
    elapsed = time.time() - start_time if start_time else 0
    total = sum(v for k, v in stats.items() if k != "arp_spoofs")
    print(f"\n{'='*60}")
    print(f"  Capture Statistics ({elapsed:.1f}s)")
    print(f"{'='*60}")
    print(f"  Total packets:   {total}")
    for proto in ["TCP", "UDP", "ICMP", "DNS", "HTTP", "ARP"]:
        if stats[proto] > 0:
            pct = stats[proto] / total * 100 if total > 0 else 0
            print(f"  {proto:6} packets:  {stats[proto]:5}  ({pct:.1f}%)")
    if stats["arp_spoofs"] > 0:
        print(colorize("ALERT", f"\n  !! ARP Spoof alerts: {stats['arp_spoofs']}"))
    print(f"{'='*60}\n")

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    iface = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"{'='*60}")
    print(f"  Packet Sniffer — capturing {count} packets")
    if iface:
        print(f"  Interface: {iface}")
    print(f"  Press Ctrl+C to stop early")
    print(f"{'='*60}\n")

    try:
        sniff(prn=process_packet, count=count, store=False, iface=iface)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\n[ERROR] Permission denied. Run as Administrator / root:")
        print("  Windows:  Run terminal as Administrator")
        print("  Linux:    sudo python main.py")
        sys.exit(1)

    print_stats()
