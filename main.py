#!/usr/bin/env python3
import os
import sys
import tempfile
from datetime import datetime
from collections import defaultdict

# CLI
from pcap_analyzer.cli import parse_args

# PCAP loading
from pcap_analyzer.pcap_io import load_pcap

# Inventory
from pcap_analyzer.host_inventory import build_host_inventory

# DNS
from pcap_analyzer.dns_analysis import compute_dns_stats_advanced

# HTTP
from pcap_analyzer.http_analysis import (
    compute_http_stats,
    compute_http_file_stats,
)

# TLS
from pcap_analyzer.tls_analysis import compute_ja3_stats, HAVE_TLS

# Focus mode
from pcap_analyzer.focus import (
    compute_focus_host_stats,
    filter_focus_suspicious_downloads,
    print_focus_host_report,
    print_focus_timeline,
)

# Proto / conversations 
from pcap_analyzer.proto_stats import (
    compute_protocol_distribution,
    top_src_ips,
    top_dst_ips,
    top_src_ports,
    top_dst_ports,
    compute_conversations,
)

# TShark enrichment
from pcap_analyzer.tshark_enrichment import (
    tshark_export_http_objects,
    tshark_export_http_objects_focus,
    tshark_enrich_hosts_kerberos,
    tshark_enrich_server_roles_tls,
    tshark_enrich_focus_stats,
)

# VirusTotal
from pcap_analyzer.vt_enrichment import (
    hash_exported_objects,
    collect_vt_hashes_from_export,
    vt_load_cache,
    vt_save_cache,
    vt_get_ip,
    vt_get_file,
    collect_vt_ips_mode_b,
    collect_vt_ips_focus,
    print_vt_focus_section,
)

# Reporting (stampa generale)
from pcap_analyzer.reporting import (
    print_host_inventory_summary,
    print_general_ua_correlations,
    print_http_stats,
    print_http_file_stats,
    print_dns_stats_advanced,
    print_ja3_stats,
    generate_final_report,
)

# Costanti colori
from pcap_analyzer.constants import (
    RESET, RED, GREEN, YELLOW,
    BLUE, MAGENTA, CYAN, WHITE, BOLD
)

# Serve per il mapping host->IP nel report generale
try:
    from scapy.layers.http import HTTPRequest
    HAVE_HTTP = True
except Exception:
    HAVE_HTTP = False

from scapy.layers.inet import IP


def main():
    args = parse_args()
    pcap_file = args.pcap_file
    packets = load_pcap(pcap_file)

    hosts = build_host_inventory(packets)

    if args.use_tshark:
        ok = tshark_enrich_hosts_kerberos(pcap_file, hosts, tshark_path=args.tshark_path)
        if ok:
            print(f"{GREEN}[+] tshark: Kerberos identities enriched{RESET}")
        else:
            print(f"{YELLOW}[!] tshark enabled but not found (or failed). Continuing with Scapy only.{RESET}")
        ok_tls = tshark_enrich_server_roles_tls(pcap_file, hosts, tshark_path=args.tshark_path)
        if ok_tls:
            print(f"{GREEN}[+] tshark: TLS server roles enriched (HTTPS/LDAPS){RESET}")
        else:
            print(f"{YELLOW}[!] tshark TLS enrichment skipped (missing/failed).{RESET}")

    if not HAVE_TLS:
        print()
        print(f"{YELLOW}⚠ JA3 disabled:{RESET} install Scapy TLS support and Python Cryptography →  {BLUE}-m pip install 'scapy[tls]'{RESET} and {BLUE}-m pip install cryptography{RESET}")

    # Proto stats
    proto_stats = compute_protocol_distribution(packets)

    # Top IP src/dst
    top_src_ip = top_src_ips(packets)
    top_dst_ip = top_dst_ips(packets)

    # Top ports src/dst
    top_src_tcp, top_src_udp = top_src_ports(packets)
    top_dst_tcp, top_dst_udp = top_dst_ports(packets)

    top_src_port = [(("TCP", p), d) for (p, d) in top_src_tcp] + [(("UDP", p), d) for (p, d) in top_src_udp]
    top_dst_port = [(("TCP", p), d) for (p, d) in top_dst_tcp] + [(("UDP", p), d) for (p, d) in top_dst_udp]


    # Conversation stats (5-tuple)
    conv_stats = compute_conversations(packets)

    # Application layer stats

    # DNS
    (
        top_qnames,
        top_resolvers,
        top_base_domains,
        suspicious_many_subdomains,
        suspicious_high_entropy_labels,
        known_good_high_entropy_labels,
    ) = compute_dns_stats_advanced(packets)

    # HTTP
    (
        top_http_hosts,
        top_http_urls,
        top_http_uas,
        top_http_exts,
        top_http_suspicious,
    ) = compute_http_stats(packets)

    # File-centric HTTP
    stats_by_ext, suspicious_downloads, http_mismatches = compute_http_file_stats(
        packets, large_threshold=args.large_file_threshold
    )

    # ---------------- VT enrichment ----------------
    vt_ip_results = {}
    vt_file_results = {}
    vt_ip_results_focus = {}
    vt_file_results_focus = {}

    if args.vt:
        api_key = args.vt_key or os.environ.get("VT_API_KEY")
        if not api_key:
            print(f"{YELLOW}[!] --vt enabled but no API key provided. Use --vt-key or set VT_API_KEY{RESET}")
        else:
            cache = vt_load_cache(args.vt_cache)
            last_ts = 0.0

            # ---- GENERAL ----
            ips_to_check = collect_vt_ips_mode_b(hosts, max_items=args.vt_max)

            exported_hashes = []
            if args.use_tshark:
                with tempfile.TemporaryDirectory(prefix="http_objects_") as tmpdir:
                    ok_exp = tshark_export_http_objects(pcap_file, tmpdir, tshark_path=args.tshark_path)
                    if ok_exp:
                        exported_hashes = hash_exported_objects(tmpdir, min_bytes=args.vt_min_bytes)
                    else:
                        print(f"{YELLOW}[!] tshark export-objects failed; file hashes will be skipped{RESET}")
            else:
                print(f"{YELLOW}[!] VT file hashing skipped: enable --use-tshark to export full HTTP objects{RESET}")

            hashes_to_check = collect_vt_hashes_from_export(exported_hashes, max_items=args.vt_max)

            print(f"{YELLOW}[VT] Querying {len(ips_to_check)} IPs and {len(hashes_to_check)} file hashes...{RESET}")

            for ip in ips_to_check:
                data, last_ts = vt_get_ip(ip, api_key, cache, last_ts)
                vt_ip_results[ip] = data

            for hv in hashes_to_check:
                data, last_ts = vt_get_file(hv, api_key, cache, last_ts)
                vt_file_results[hv] = data

            # ---- FOCUS (only if focus is active) ----
            if args.focus:
                ips_focus = collect_vt_ips_focus(packets, args.focus, max_items=args.vt_max)

                exported_hashes_focus = []
                if args.use_tshark:
                    with tempfile.TemporaryDirectory(prefix="http_objects_focus_") as tmpdir:
                        ok_exp = tshark_export_http_objects_focus(
                            pcap_file, args.focus, tmpdir, tshark_path=args.tshark_path
                        )
                        if ok_exp:
                            exported_hashes_focus = hash_exported_objects(tmpdir, min_bytes=args.vt_min_bytes)

                hashes_focus = collect_vt_hashes_from_export(exported_hashes_focus, max_items=args.vt_max)

                print(f"{YELLOW}[VT] Focus: querying {len(ips_focus)} IPs and {len(hashes_focus)} file hashes...{RESET}")

                for ip in ips_focus:
                    data, last_ts = vt_get_ip(ip, api_key, cache, last_ts)
                    vt_ip_results_focus[ip] = data

                for hv in hashes_focus:
                    data, last_ts = vt_get_file(hv, api_key, cache, last_ts)
                    vt_file_results_focus[hv] = data

            vt_save_cache(args.vt_cache, cache)

    # JA3 / TLS fingerprint
    top_ja3 = compute_ja3_stats(packets)

    http_host_ips = defaultdict(set)

    # Un solo passaggio sui pacchetti, in ordine temporale
    for pkt in packets:
        # --- HTTP host -> IP mapping (per il report generale) ---
        if HAVE_HTTP and (HTTPRequest in pkt) and (IP in pkt):
            req = pkt[HTTPRequest]
            ip = pkt[IP]

            raw_host = getattr(req, "Host", b"")
            if isinstance(raw_host, bytes):
                host = raw_host.decode(errors="ignore").strip()
            else:
                host = str(raw_host or "").strip()

            if host:
                http_host_ips[host].add(ip.dst)

    if not args.focus:
        generate_final_report(
            file_path=pcap_file,
            packets=packets,
            proto_stats=proto_stats,
            top_src_ip=top_src_ip,
            top_dst_ip=top_dst_ip,
            top_src_port=top_src_port,
            top_dst_port=top_dst_port,
            dns_stats=(
                top_qnames,
                top_resolvers,
                top_base_domains,
                suspicious_many_subdomains,
                suspicious_high_entropy_labels,
                known_good_high_entropy_labels,
            ),
            http_stats=(top_http_hosts, top_http_urls, top_http_uas, top_http_exts, top_http_suspicious),
            stats_by_ext=stats_by_ext,
            suspicious_downloads=suspicious_downloads,
            http_mismatches=http_mismatches,
            http_host_ips=http_host_ips,
            vt_ip_results=vt_ip_results,
            vt_file_results=vt_file_results,
        )

        print_host_inventory_summary(hosts, limit=30)

        print_general_ua_correlations(
            hosts,
            suspicious_high_entropy_labels,
            suspicious_downloads,
            limit=20
        )

    else:
        focus_ip = args.focus

        focus_events = []

        focus_stats = compute_focus_host_stats(packets, focus_ip, event_log=focus_events)

        if args.use_tshark:
            ok2 = tshark_enrich_focus_stats(pcap_file, focus_ip, focus_stats, tshark_path=args.tshark_path)
            if ok2:
                print(f"{GREEN}[+] tshark: focus L7 stats enriched (DNS/HTTP/TLS){RESET}")
            else:
                print(f"{YELLOW}[!] tshark focus enrichment skipped (missing/failed).{RESET}")

        focus_downloads = filter_focus_suspicious_downloads(focus_ip, suspicious_downloads)

        print_focus_host_report(
            focus_ip,
            focus_stats,
            focus_downloads,
            hosts=hosts,
            vt_ip_results_focus=vt_ip_results_focus,
            vt_file_results_focus=vt_file_results_focus,
            suspicious_high_entropy_labels=suspicious_high_entropy_labels,
            known_good_high_entropy_labels=known_good_high_entropy_labels
        )

        use_timeline = (
            args.timeline
            or args.timeline_dns
            or args.timeline_http
            or args.timeline_compact
        )

        if use_timeline:
            print_focus_timeline(focus_ip, focus_events, args)


if __name__ == "__main__":
    main()

