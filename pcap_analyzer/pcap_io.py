"""
PCAP loading utilities.
"""
import sys

from pcap_analyzer.constants import RESET, RED, BLUE, YELLOW, GREEN, MAGENTA, CYAN, BOLD

try:
    from scapy.all import rdpcap
except ImportError:
    print(f"{RED}[!]Scapy not found!{RESET}")
    print(f"{BLUE}Install with: python -m pip install scapy{RESET}")
    sys.exit(1)


def load_pcap(pcap_file):
    try:
        print()
        print(f"{YELLOW}[+]Loading pcap:{RESET} {pcap_file}")
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"{RED}[!] File {pcap_file} not found{RESET}")
        sys.exit(1)
    except PermissionError:
        print(f"{RED}[!] Permission denied for the file {pcap_file}{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}[!] Error during PCAP reading: {e}{RESET}")
        sys.exit(1)

    if not (pcap_file.endswith(".pcap") or pcap_file.endswith(".pcapng")):
        print(f"{RED}[!] Error! File {pcap_file} is not a PCAP{RESET}")
        sys.exit(1)

    if not packets:
        print(f"{RED}pcap file {pcap_file} is empty.{RESET}")
        sys.exit(1)
    print()    
    print(f"{GREEN}{len(packets)} packets loaded{RESET}")
    return packets