"""
CLI argument parsing for the PCAP Forensic & Behavioral Analyzer.
"""


import argparse



def parse_args():
    parser = argparse.ArgumentParser(
        description="Mini PCAP Analyzer"
    )
    # --- VirusTotal optional ---
    parser.add_argument(
        "--vt",
        action="store_true",
        help="Enable VirusTotal enrichment (sends IPs/hashes to VirusTotal API)"
    )
    parser.add_argument(
        "--vt-key",
        default=None,
        help="VirusTotal API key (or set env VT_API_KEY)"
    )
    parser.add_argument(
        "--vt-cache",
        default="vt_cache.json",
        help="Path to JSON cache file for VT results (default: vt_cache.json)"
    )
    parser.add_argument(
        "--vt-max",
        type=int,
        default=15,
        help="Max number of IPs and hashes to query per run (default: 15)"
    )
    parser.add_argument(
        "--vt-min-bytes",
        type=int,
        default=256,
        help="Min file size (bytes) for hashing exported objects (default: 256)"
    )
    
    
    parser.add_argument(
        "--use-tshark",
        action="store_true",
        help="Use tshark (if installed) to enrich L7 stats (Kerberos/DNS/HTTP/TLS) with higher accuracy"
    )
    parser.add_argument(
        "--tshark-path",
        default=None,
        help="Optional full path to tshark.exe (if not in PATH)"
    )
    parser.add_argument(
        "pcap_file",
        help=".pcap or .pcapng file path to analyze"
    )

    parser.add_argument(
        "--large-file-threshold", "--large",
        type=int,
        default=5 * 1000 * 1000,  # 5 MB
        help="Size threshold in bytes for marking large HTTP file downloads (default: 5MB)"
    )
    parser.add_argument(
        "--focus",
        help="Analyze only the traffic of the specified IP address"
    )
    parser.add_argument(
    "--timeline",
    action="store_true",
    help="Include detailed event timeline in focus host report (may be very verbose)"
    )
    parser.add_argument(
        "--timeline-dns",
        action="store_true",
        help="Limit timeline to DNS-related events"
    )
    parser.add_argument(
        "--timeline-http",
        action="store_true",
        help="Limit timeline to HTTP/file-related events"
    )
    parser.add_argument(
        "--timeline-compact",
        action="store_true",
        help="Compact timeline: mostly DNS, downloads, scans and sweeps"
    )
    
    
    return parser.parse_args()
