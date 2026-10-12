#!/usr/bin/env python3
"""
NetRecon — Network Reconnaissance & Packet Manipulation Toolkit
Coded by cyber security engineer Mr Sabaz Ali Khan

Features:
  - Host discovery (ARP sweep on local subnet)
  - TCP port scanning (connect scan + optional SYN scan via scapy)
  - Service/banner grabbing
  - OS fingerprint hint (TTL-based heuristic)
  - Traceroute
  - Raw packet crafting & manipulation (scapy): custom TCP/UDP/ICMP packets,
    packet replay from pcap, basic packet sniffer with BPF filter
  - DNS lookup helper

Requires: Python 3.8+
Optional (for ARP sweep, SYN scan, raw crafting, sniffing): scapy
    pip install scapy --break-system-packages
Note: Raw sockets / ARP / SYN scans typically require root/administrator privileges.

Legal notice: Use only on networks and systems you own or have explicit
written authorization to test. Unauthorized scanning or packet injection
against systems you do not control may be illegal in your jurisdiction.
"""

import argparse
import ipaddress
import socket
import struct
import sys
import time
import threading
import queue
from datetime import datetime

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, UDP, ICMP, srp, sr1, send, sr,
        conf, rdpcap, sendp, sniff, traceroute as scapy_traceroute
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

BANNER = r"""
⣶⣄⠀⠀⠈⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢋⣡⣾⣿⡿⠛⠁
⠿⣿⣿⣦⣀⠀⠀⠈⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⣡⣴⣿⣿⠟⠋⠀⠀⠀
⣶⣌⡛⢿⣿⣷⣤⡀⠀⠀⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢋⣴⣾⣿⡿⠋⠁⠀⠀⠀⠀⡀
⣿⣿⣿⣦⣍⠻⣿⣿⣦⣄⠀⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⣡⣾⣿⣿⠟⠁⠀⠀⠀⠀⣠⣴⣿⡇
⣿⣿⣿⣿⣿⣷⣬⡙⢿⣿⣷⣦⡀⠀⠀⠈⠛⢿⣿⣿⣿⣿⣿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⣿⣿⣿⣿⠟⣉⣴⣿⣿⠿⠋⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⡇
⣿⣿⣿⣿⣿⣿⣿⣿⣶⣌⠻⢿⣿⣷⣄⠀⠀⠀⠉⠻⣿⣿⣿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⣿⡿⢋⣤⣾⣿⡿⠛⠁⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⡇
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡙⠿⣿⣿⣦⣀⠀⠀⠀⠙⠿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⡿⠟⣡⣶⣿⣿⠟⠋⠀⠀⠀⢀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣌⡛⢿⣿⣷⣤⡀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣴⣿⣿⡿⠋⠁⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣉⠻⣿⣿⣦⣄⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⠟⠁⠀⠀⠀⣀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠈⠉⠉⠉⠁⠀⠀⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁

               N E T R E C O N  —  Network Recon & Packet Manipulation Toolkit
                        Coded by Cyber Security Engineer Mr Sabaz Ali Khan
"""


def print_banner():
    print(BANNER)


# --------------------------------------------------------------------------
# Host discovery
# --------------------------------------------------------------------------
def arp_scan(cidr, timeout=2):
    """ARP sweep of a subnet. Requires scapy + root privileges."""
    if not SCAPY_AVAILABLE:
        print("[!] scapy not installed. Run: pip install scapy --break-system-packages")
        return []

    print(f"[*] ARP sweep on {cidr} ...")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=cidr)
    packet = ether / arp

    result = srp(packet, timeout=timeout, verbose=0)[0]
    hosts = []
    for sent, received in result:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})

    hosts.sort(key=lambda h: tuple(int(p) for p in h["ip"].split(".")))
    return hosts


def ping_sweep(cidr, timeout=1):
    """Fallback host discovery using TCP connect probes (no root required)."""
    print(f"[*] TCP ping sweep on {cidr} (ports 80/443/22) ...")
    net = ipaddress.ip_network(cidr, strict=False)
    alive = []
    probe_ports = [80, 443, 22, 445, 3389]

    def probe(ip):
        for port in probe_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((str(ip), port)) == 0:
                        alive.append(str(ip))
                        return
            except OSError:
                continue

    threads = []
    for ip in net.hosts():
        t = threading.Thread(target=probe, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    return sorted(set(alive), key=lambda ip: tuple(int(p) for p in ip.split(".")))


# --------------------------------------------------------------------------
# Port scanning
# --------------------------------------------------------------------------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]


def grab_banner(ip, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                s.sendall(b"\r\n")
            except OSError:
                pass
            data = s.recv(256)
            return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def tcp_connect_scan(ip, ports, timeout=1.0, grab=True, max_threads=100):
    """Multithreaded TCP connect scan — no root required."""
    open_ports = []
    lock = threading.Lock()
    q = queue.Queue()
    for p in ports:
        q.put(p)

    def worker():
        while not q.empty():
            try:
                port = q.get_nowait()
            except queue.Empty:
                return
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        banner = grab_banner(ip, port) if grab else ""
                        with lock:
                            open_ports.append((port, banner))
            except OSError:
                pass
            q.task_done()

    threads = [threading.Thread(target=worker) for _ in range(min(max_threads, len(ports)))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    open_ports.sort(key=lambda x: x[0])
    return open_ports


def syn_scan(ip, ports, timeout=1.0):
    """Stealth SYN scan via scapy. Requires scapy + root privileges."""
    if not SCAPY_AVAILABLE:
        print("[!] scapy not installed, falling back to TCP connect scan.")
        return tcp_connect_scan(ip, ports, timeout)

    open_ports = []
    for port in ports:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is not None and resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN/ACK
                open_ports.append((port, ""))
                rst = IP(dst=ip) / TCP(dport=port, flags="R")
                send(rst, verbose=0)
    return open_ports


def estimate_os(ip, timeout=1.0):
    """Very rough TTL-based OS guess from an ICMP echo reply."""
    if not SCAPY_AVAILABLE:
        return "unknown (scapy not installed)"
    pkt = IP(dst=ip) / ICMP()
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        return "no response"
    ttl = resp.ttl
    if ttl <= 64:
        return f"Likely Linux/Unix (TTL={ttl})"
    elif ttl <= 128:
        return f"Likely Windows (TTL={ttl})"
    else:
        return f"Likely network device/other (TTL={ttl})"


# --------------------------------------------------------------------------
# Traceroute
# --------------------------------------------------------------------------
def traceroute(ip, max_hops=30, timeout=1.0):
    if SCAPY_AVAILABLE:
        print(f"[*] Scapy traceroute to {ip} ...")
        res, _ = scapy_traceroute(ip, maxttl=max_hops, timeout=timeout, verbose=0)
        hops = []
        for snd, rcv in res:
            hops.append((snd.ttl, rcv.src))
        return hops

    # Raw-socket fallback (UDP based, no scapy)
    print(f"[*] UDP traceroute to {ip} ...")
    hops = []
    dest_addr = socket.gethostbyname(ip)
    port = 33434
    for ttl in range(1, max_hops + 1):
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_sock.settimeout(timeout)
        recv_sock.bind(("", port))
        send_sock.sendto(b"", (dest_addr, port))
        try:
            _, curr_addr = recv_sock.recvfrom(512)
            curr_addr = curr_addr[0]
        except socket.timeout:
            curr_addr = "*"
        finally:
            send_sock.close()
            recv_sock.close()
        hops.append((ttl, curr_addr))
        if curr_addr == dest_addr:
            break
    return hops


# --------------------------------------------------------------------------
# Raw packet crafting & manipulation (scapy)
# --------------------------------------------------------------------------
def craft_and_send_tcp(dst_ip, dst_port, src_port=None, flags="S", payload=b"", count=1):
    if not SCAPY_AVAILABLE:
        print("[!] scapy required for packet crafting.")
        return
    for _ in range(count):
        sport = src_port or (1024 + int.from_bytes(struct.pack("B", 1), "big") * 7)
        pkt = IP(dst=dst_ip) / TCP(sport=sport, dport=dst_port, flags=flags) / payload
        send(pkt, verbose=0)
    print(f"[+] Sent {count} crafted TCP packet(s) to {dst_ip}:{dst_port} flags={flags}")


def craft_and_send_udp(dst_ip, dst_port, payload=b"recon", count=1):
    if not SCAPY_AVAILABLE:
        print("[!] scapy required for packet crafting.")
        return
    pkt = IP(dst=dst_ip) / UDP(dport=dst_port) / payload
    for _ in range(count):
        send(pkt, verbose=0)
    print(f"[+] Sent {count} crafted UDP packet(s) to {dst_ip}:{dst_port}")


def craft_and_send_icmp(dst_ip, count=1):
    if not SCAPY_AVAILABLE:
        print("[!] scapy required for packet crafting.")
        return
    pkt = IP(dst=dst_ip) / ICMP()
    for _ in range(count):
        resp = sr1(pkt, timeout=2, verbose=0)
        if resp:
            print(f"[+] Reply from {resp.src} ttl={resp.ttl}")
        else:
            print("[-] No reply")


def replay_pcap(pcap_path, iface=None, interval=0.01):
    if not SCAPY_AVAILABLE:
        print("[!] scapy required for pcap replay.")
        return
    print(f"[*] Replaying packets from {pcap_path} ...")
    packets = rdpcap(pcap_path)
    for pkt in packets:
        if iface:
            sendp(pkt, iface=iface, verbose=0)
        else:
            send(pkt, verbose=0)
        time.sleep(interval)
    print(f"[+] Replayed {len(packets)} packets.")


def live_sniff(bpf_filter="", count=20, iface=None, timeout=20):
    if not SCAPY_AVAILABLE:
        print("[!] scapy required for live sniffing.")
        return
    print(f"[*] Sniffing (filter='{bpf_filter or 'any'}', count={count}, timeout={timeout}s) ...")

    def handle(pkt):
        summary = pkt.summary()
        print(f"  {datetime.now().strftime('%H:%M:%S')}  {summary}")

    sniff(filter=bpf_filter or None, prn=handle, count=count, iface=iface, timeout=timeout)


# --------------------------------------------------------------------------
# DNS helper
# --------------------------------------------------------------------------
def dns_lookup(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror as e:
        return f"resolution failed: {e}"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="NetRecon — Network Reconnaissance & Packet Manipulation Toolkit "
                    "(coded by Mr Sabaz Ali Khan)"
    )
    sub = p.add_subparsers(dest="command", required=True)

    s1 = sub.add_parser("discover", help="Discover live hosts on a subnet")
    s1.add_argument("cidr", help="e.g. 192.168.1.0/24")
    s1.add_argument("--arp", action="store_true", help="Use ARP scan (needs scapy + root)")

    s2 = sub.add_parser("scan", help="Port scan a target")
    s2.add_argument("target", help="IP or hostname")
    s2.add_argument("-p", "--ports", default=None,
                     help="Comma list or range e.g. 22,80,443 or 1-1024 (default: common ports)")
    s2.add_argument("--syn", action="store_true", help="Use SYN scan (needs scapy + root)")
    s2.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")
    s2.add_argument("--os", action="store_true", help="Attempt TTL-based OS guess")

    s3 = sub.add_parser("traceroute", help="Trace the route to a target")
    s3.add_argument("target")
    s3.add_argument("--max-hops", type=int, default=30)

    s4 = sub.add_parser("craft", help="Craft and send raw packets (needs scapy + root)")
    s4.add_argument("proto", choices=["tcp", "udp", "icmp"])
    s4.add_argument("target")
    s4.add_argument("--port", type=int, default=80)
    s4.add_argument("--flags", default="S", help="TCP flags, e.g. S, SA, F, R")
    s4.add_argument("--count", type=int, default=1)
    s4.add_argument("--payload", default="", help="Payload string for TCP/UDP")

    s5 = sub.add_parser("replay", help="Replay packets from a pcap file (needs scapy + root)")
    s5.add_argument("pcap")
    s5.add_argument("--iface", default=None)
    s5.add_argument("--interval", type=float, default=0.01)

    s6 = sub.add_parser("sniff", help="Live packet sniffer (needs scapy + root)")
    s6.add_argument("--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    s6.add_argument("--count", type=int, default=20)
    s6.add_argument("--iface", default=None)
    s6.add_argument("--timeout", type=int, default=20)

    s7 = sub.add_parser("dns", help="Resolve a hostname")
    s7.add_argument("target")

    return p


def parse_ports(spec):
    if not spec:
        return COMMON_PORTS
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "discover":
        hosts = arp_scan(args.cidr) if args.arp else ping_sweep(args.cidr)
        if not hosts:
            print("[-] No hosts found (or insufficient privileges for ARP scan).")
        else:
            print(f"\n[+] {len(hosts)} host(s) found:")
            for h in hosts:
                if isinstance(h, dict):
                    print(f"    {h['ip']:<16} {h['mac']}")
                else:
                    print(f"    {h}")

    elif args.command == "scan":
        try:
            ip = socket.gethostbyname(args.target)
        except socket.gaierror:
            print(f"[-] Could not resolve {args.target}")
            sys.exit(1)
        ports = parse_ports(args.ports)
        print(f"[*] Scanning {args.target} ({ip}) — {len(ports)} port(s) — "
              f"{'SYN' if args.syn else 'TCP connect'} scan")
        start = time.time()
        results = syn_scan(ip, ports) if args.syn else tcp_connect_scan(
            ip, ports, grab=not args.no_banner)
        elapsed = time.time() - start

        if args.os:
            print(f"[*] OS guess: {estimate_os(ip)}")

        if not results:
            print("[-] No open ports found.")
        else:
            print(f"\n[+] {len(results)} open port(s) on {ip}:")
            for port, banner in results:
                line = f"    {port:<6} OPEN"
                if banner:
                    line += f"   {banner[:80]}"
                print(line)
        print(f"[*] Scan completed in {elapsed:.2f}s")

    elif args.command == "traceroute":
        hops = traceroute(args.target, max_hops=args.max_hops)
        for ttl, addr in hops:
            print(f"  {ttl:>3}  {addr}")

    elif args.command == "craft":
        payload = args.payload.encode()
        if args.proto == "tcp":
            craft_and_send_tcp(args.target, args.port, flags=args.flags,
                                payload=payload, count=args.count)
        elif args.proto == "udp":
            craft_and_send_udp(args.target, args.port, payload=payload or b"recon",
                                count=args.count)
        elif args.proto == "icmp":
            craft_and_send_icmp(args.target, count=args.count)

    elif args.command == "replay":
        replay_pcap(args.pcap, iface=args.iface, interval=args.interval)

    elif args.command == "sniff":
        live_sniff(bpf_filter=args.filter, count=args.count,
                   iface=args.iface, timeout=args.timeout)

    elif args.command == "dns":
        print(f"[*] {args.target} -> {dns_lookup(args.target)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting.")
        sys.exit(0)

# ---------------------------------------------------------------------------
# Coded by Cyber Security Engineer Mr Sabaz Ali Khan
# ---------------------------------------------------------------------------
