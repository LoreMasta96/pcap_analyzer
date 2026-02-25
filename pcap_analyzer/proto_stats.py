from __future__ import annotations

from collections import defaultdict

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS

try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HAVE_HTTP = True
except Exception:
    HAVE_HTTP = False


def compute_protocol_distribution(packets):
    proto_stats = defaultdict(lambda: {"pkts": 0, "bytes": 0})

    for pkt in packets:
        proto_name = "OTHER"

        if IP in pkt:
            # --- Layer 7 prima ---
            if DNS in pkt:
                proto_name = "DNS"
            elif HAVE_HTTP and (HTTPRequest in pkt or HTTPResponse in pkt):
                proto_name = "HTTP"
            # opzionale: TLS grezzo via porta 443
            elif TCP in pkt and (pkt[TCP].sport == 443 or pkt[TCP].dport == 443):
                proto_name = "TLS"
            # --- Layer 4 fallback ---
            elif TCP in pkt:
                proto_name = "TCP"
            elif UDP in pkt:
                proto_name = "UDP"
            elif ICMP in pkt:
                proto_name = "ICMP"
            else:
                proto_name = f"IP(proto={pkt[IP].proto})"
        else:
            proto_name = pkt.__class__.__name__

        proto_stats[proto_name]["pkts"] += 1
        try:
            proto_stats[proto_name]["bytes"] += len(pkt)
        except Exception:
            pass

    return proto_stats


def top_src_ips(packets):
    source_count = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            source_count[src_ip]["pkts"] += 1
            source_count[src_ip]["bytes"] += len(pkt)
    top_src = sorted(source_count.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]
    return top_src


def top_dst_ips(packets):
    dest_count = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    for pkt in packets:
        if IP in pkt:
            dst_ip = pkt[IP].dst
            dest_count[dst_ip]["pkts"] += 1
            dest_count[dst_ip]["bytes"] += len(pkt)
    top_dst = sorted(dest_count.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]
    return top_dst


def top_src_ports(packets):
    source_UDP_ports = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    source_TCP_ports = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    for pkt in packets:
        if TCP in pkt:
            source_TCP_ports[pkt[TCP].sport]["pkts"] += 1
            source_TCP_ports[pkt[TCP].sport]["bytes"] += len(pkt)
        if UDP in pkt:
            source_UDP_ports[pkt[UDP].sport]["pkts"] += 1
            source_UDP_ports[pkt[UDP].sport]["bytes"] += len(pkt)

    top_TCP_ports = sorted(source_TCP_ports.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]
    top_UDP_ports = sorted(source_UDP_ports.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]
    return top_TCP_ports, top_UDP_ports


def top_dst_ports(packets):
    dst_UDP_ports = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    dst_TCP_ports = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    for pkt in packets:
        if UDP in pkt:
            dst_UDP_ports[pkt[UDP].dport]["pkts"] += 1
            dst_UDP_ports[pkt[UDP].dport]["bytes"] += len(pkt)
        if TCP in pkt:
            dst_TCP_ports[pkt[TCP].dport]["pkts"] += 1
            dst_TCP_ports[pkt[TCP].dport]["bytes"] += len(pkt)

    top_TCP_ports = sorted(dst_TCP_ports.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]
    top_UDP_ports = sorted(dst_UDP_ports.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]
    return top_TCP_ports, top_UDP_ports


def compute_conversations(packets):
    """
    Calcola le "conversazioni" 5-tuple:
        (src_ip, src_port, dst_ip, dst_port, proto)

    Ritorna: dict
        key: (src, sport, dst, dport, proto)
        value: {
            "pkts": int,
            "bytes": int,
            "start": float,
            "end": float,
        }
    """
    conv_stats = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = None
        sport = 0
        dport = 0

        if TCP in pkt:
            tcp = pkt[TCP]
            proto = "TCP"
            sport = tcp.sport
            dport = tcp.dport
        elif UDP in pkt:
            udp = pkt[UDP]
            proto = "UDP"
            sport = udp.sport
            dport = udp.dport
        else:
            # altri protocolli IP (ICMP, ecc.)
            proto = f"IP#{ip.proto}"

        key = (src, sport, dst, dport, proto)

        try:
            t = float(pkt.time)
        except Exception:
            continue

        size = 0
        try:
            size = len(pkt)
        except Exception:
            pass

        if key not in conv_stats:
            conv_stats[key] = {
                "pkts": 0,
                "bytes": 0,
                "start": t,
                "end": t,
            }

        c = conv_stats[key]
        c["pkts"] += 1
        c["bytes"] += size
        if t < c["start"]:
            c["start"] = t
        if t > c["end"]:
            c["end"] = t

    return conv_stats
