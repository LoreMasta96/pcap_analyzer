"""
Host inventory & identity correlation (upgraded towards legacy 1.4).

Adds higher-fidelity extraction for:
- DHCP identity (hostname/vendor, MAC->IP mapping)
- NBNS name -> IP and NBSTAT names
- Kerberos principals best-effort (port 88)
- NTLM Type3 username extraction (raw + HTTP Authorization NTLM)
- LLMNR/mDNS hostname candidates

No printing here: reporting happens elsewhere.
"""

from __future__ import annotations

from collections import defaultdict

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

try:
    from scapy.layers.dhcp import DHCP
except Exception:
    DHCP = None

try:
    from scapy.layers.dns import DNS
except Exception:
    DNS = None

try:
    from scapy.layers.http import HTTPRequest
    HAVE_HTTP = True
except Exception:
    HAVE_HTTP = False

from pcap_analyzer.models import HostProfile
from pcap_analyzer.utils import (
    parse_dhcp_identity_strict,
    parse_nbns_name_ip,
    parse_nbns_nbstat,
    extract_llmnr_mdns_hostnames,
    extract_kerberos_principals_best_effort,
    extract_netbios_candidates,
    extract_username_candidates,
    extract_ntlm_usernames,
    mark_role,
)




# -------------------------
# Main builder
# -------------------------

def build_host_inventory(packets):
    """
    Ritorna: dict ip -> HostProfile
    """
    hosts = {}
    dhcp_mac_to_ip = {}
    dhcp_mac_identity_cache = {}  # mac -> {"hostnames": set(), "vendors": set()}

    def get_host(ip: str) -> HostProfile:
        if ip not in hosts:
            hosts[ip] = HostProfile(
                ip=ip,
                macs=set(),
                ttl_samples=[],
                first_ts=None,
                last_ts=None,
                netbios_names=set(),
                hostnames=set(),
                dhcp_hostnames=set(),
                dhcp_vendors=set(),
                kerberos_principals=set(),
                username_candidates=set(),
                server_roles=set(),
                server_evidence=defaultdict(int),
                user_agents=set(),
                ua_domains=defaultdict(set),

            )
        return hosts[ip]

    for pkt in packets:
        try:
            t = int(pkt.time)
        except Exception:
            t = None
            
        info = parse_dhcp_identity_strict(pkt)
        if info:
            mac = info["client_mac"]
            if mac:
                cache = dhcp_mac_identity_cache.setdefault(mac, {"hostnames": set(), "vendors": set()})
                if info["hostname"]:
                    cache["hostnames"].add(info["hostname"])
                if info["vendor"]:
                    cache["vendors"].add(info["vendor"])

                # Se abbiamo yiaddr valido, quello è l'IP assegnato (OFFER/ACK)
                yi = info["yiaddr"]
                if yi and yi != "0.0.0.0":
                    dhcp_mac_to_ip[mac] = yi

                    # Applica immediatamente identity all'host IP "vero"
                    h = get_host(yi)
                    h.macs.add(mac)

                    for hn in cache["hostnames"]:
                        h.dhcp_hostnames.add(hn)

                    for vd in cache["vendors"]:
                        h.dhcp_vendors.add(vd)   

                else:
                    # renew / rebind: usa ciaddr se presente
                    ci = info["ciaddr"]
                    if ci and ci != "0.0.0.0":
                        dhcp_mac_to_ip[mac] = ci
                        h = get_host(ci)
                        h.macs.add(mac)
                        for hn in cache["hostnames"]:
                            h.dhcp_hostnames.add(hn)
                        for vd in cache["vendors"]:
                            h.dhcp_vendors.add(vd)

      

        # ARP -> associa IP<->MAC in LAN
        if ARP in pkt:
            arp = pkt[ARP]
            try:
                if arp.psrc and arp.hwsrc:
                    get_host(arp.psrc).macs.add(arp.hwsrc.lower())
                if arp.pdst and getattr(arp, "hwdst", None):
                    if arp.hwdst and arp.hwdst != "00:00:00:00:00:00":
                        get_host(arp.pdst).macs.add(arp.hwdst.lower())
            except Exception:
                pass 

        # --- NBNS strict mapping: name -> ip ---
        for nb_name, nb_ip in parse_nbns_name_ip(pkt):
              h = get_host(nb_ip)
              h.netbios_names.add(nb_name)  

        for nb_name, nb_ip in parse_nbns_nbstat(pkt):
            h = get_host(nb_ip)
            h.netbios_names.add(nb_name)

        if DNS in pkt and IP in pkt:
            dns = pkt[DNS]
            if dns.qr == 1:  # response
                # spesso src è il DNS server
                if UDP in pkt and pkt[UDP].sport == 53:
                    mark_role(get_host(pkt[IP].src), "dns", "udp_sport53_response")
                elif TCP in pkt and pkt[TCP].sport == 53:
                    mark_role(get_host(pkt[IP].src), "dns", "tcp_sport53_response")            
            
        # IP -> TTL + tempo + MAC via Ether (se presente)
        if IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst

            hs = get_host(src)
            hd = get_host(dst)

            if t is not None:
                for h in (hs, hd):
                    if h.first_ts is None or t < h.first_ts:
                        h.first_ts = t
                    if h.last_ts is None or t > h.last_ts:
                        h.last_ts = t
                        
            # ------------------------------------------------------------
            # Server-like detectors (evidence-based)
            # ------------------------------------------------------------            
            
            # KDC/Kerberos server candidate: port 88
            if TCP in pkt:
                if pkt[TCP].dport == 88:
                    mark_role(hd, "kdc", "dstport88")
                if pkt[TCP].sport == 88:
                    mark_role(hs, "kdc", "sport88")
            elif UDP in pkt:
                if pkt[UDP].dport == 88:
                    mark_role(hd, "kdc", "dstport88")
                if pkt[UDP].sport == 88:
                    mark_role(hs, "kdc", "sport88")
                    
            # DHCP server candidate
            if DHCP in pkt and IP in pkt:
                ip = pkt[IP]

                # DHCP OFFER / ACK → server → client
                if UDP in pkt:
                    udp = pkt[UDP]

                    # Server → client (67 → 68)
                    if udp.sport == 67 and udp.dport == 68:
                        hs = get_host(ip.src)
                        mark_role(hs, "dhcp_server", "udp67_to_68")

                    # (raro) client → server ma utile come rinforzo
                    elif udp.sport == 68 and udp.dport == 67:
                        hd = get_host(ip.dst)
                        mark_role(hd, "dhcp_server", "udp68_to_67_seen")
                        
            ip = pkt[IP]

            tcp = pkt[TCP] if TCP in pkt else None
            udp = pkt[UDP] if UDP in pkt else None

            payload = b""
            if Raw in pkt:
                try:
                    payload = bytes(pkt[Raw].load)
                except Exception:
                    payload = b""

            # --- HTTP server (response starts with HTTP/1.x or HTTP/2) ---
            if tcp and payload:
                if tcp.sport in (80, 8080, 8000, 8888):
                    head = payload[:12]
                    if head.startswith(b"HTTP/1.") or head.startswith(b"HTTP/2"):
                         mark_role(get_host(ip.src), "http_server", f"http_response_sport{tcp.sport}")

            # --- SMTP server (banner 220) ---
            if tcp and payload and tcp.sport == 25:
                if payload.startswith(b"220 "):
                    mark_role(get_host(ip.src), "smtp_server", "smtp_banner_220")

            # --- IMAP server (banner "* OK") ---
            if tcp and payload and tcp.sport == 143:
                if payload.startswith(b"* OK"):
                    mark_role(get_host(ip.src), "imap_server", "imap_banner_ok")

            # --- POP3 server (banner "+OK") ---
            if tcp and payload and tcp.sport == 110:
                if payload.startswith(b"+OK"):
                    mark_role(get_host(ip.src), "pop3_server", "pop3_banner_ok")

            # --- SSH server (banner starts with SSH-) ---
            if tcp and payload and tcp.sport == 22:
                if payload.startswith(b"SSH-"):
                    mark_role(get_host(ip.src), "ssh_server", "ssh_banner")

            # --- RDP server (heuristic: server speaks first with TPKT 03 00) ---
            # This is weaker than banners above but still evidence-based.
            if tcp and payload and tcp.sport == 3389:
                if len(payload) >= 2 and payload[0:2] == b"\x03\x00":
                    mark_role(get_host(ip.src), "rdp_server", "rdp_tpkt")

            # --- SMB server (weak but useful): response from sport 445 with SMB signature ---
            # SMB1 signature: 0xFF 'SMB' ; SMB2 signature: 0xFE 'SMB'
            if tcp and payload and tcp.sport == 445:
                if len(payload) >= 8:
                    if b"\xffSMB" in payload[:64] or b"\xfeSMB" in payload[:64]:
                        mark_role(get_host(ip.src), "smb_server", "smb_signature")

            # --- LDAP server (very light heuristic): response from sport 389 ---
            # LDAP BER can start with 0x30 (SEQUENCE). Not perfect; keep as candidate.
            if tcp and payload and tcp.sport == 389:
                if len(payload) >= 1 and payload[0] == 0x30:
                    mark_role(get_host(ip.src), "ldap_server", "ldap_ber_seq")

            # --- LDAPS server (TLS on 636) ---
            # Without tshark/TLS parsing we can't be sure; mark only if payload looks like TLS record (0x16).
            if tcp and payload and tcp.sport == 636:
                if len(payload) >= 1 and payload[0] == 0x16:
                    mark_role(get_host(ip.src), "ldaps_server", "tls_record_on_636")

            # --- NTP server: UDP sport 123 and looks like NTP (first byte LI/VN/Mode) ---
            # Mode 4 = server; mode is lower 3 bits of first byte.
            if udp and payload and udp.sport == 123:
                first = payload[0]
                mode = first & 0x07
                if mode == 4:
                    mark_role(get_host(ip.src), "ntp_server", "ntp_mode4_response")

            # --- Database servers (optional but you asked "all listed") ---
            # MySQL: server greeting often starts with protocol version (0x0A) in first byte.
            if tcp and payload and tcp.sport == 3306:
                if payload[:1] == b"\x0a":
                    mark_role(get_host(ip.src), "mysql_server", "mysql_greeting")

            # PostgreSQL: server often responds with 'R' (Authentication) or 'E' (Error) message type.
            if tcp and payload and tcp.sport == 5432:
                if payload[:1] in (b"R", b"E"):
                    mark_role(get_host(ip.src), "postgres_server", "pg_response_type")            
        
            
            # TTL solo per src (è il TTL “dell’host” visto in uscita da lui)
            try:
                if hasattr(ip, "ttl") and ip.ttl is not None:
                    hs.ttl_samples.append(int(ip.ttl))
                    # tieni la lista piccola
                    if len(hs.ttl_samples) > 200:
                        hs.ttl_samples = hs.ttl_samples[-200:]
            except Exception:
                pass

            # MAC da Ethernet (solo se il pcap ha Ether)
            if Ether in pkt:
                eth = pkt[Ether]
                try:
                    if eth.src:
                        hs.macs.add(str(eth.src).lower())
                    if eth.dst:
                        hd.macs.add(str(eth.dst).lower())
                except Exception:
                    pass
                    
                # Se questa MAC ha già un IP DHCP assegnato, rinforza la correlazione
                mac_src = str(eth.src).lower() if eth.src else None
                if mac_src and mac_src in dhcp_mac_to_ip:
                    get_host(dhcp_mac_to_ip[mac_src]).macs.add(mac_src)
                    

            # --- LLMNR/mDNS best-effort hostnames ---
            hs.hostnames |= extract_llmnr_mdns_hostnames(pkt) 
            
            # --- Kerberos principals best-effort (assign to client side only) ---
            k = extract_kerberos_principals_best_effort(pkt)
            if k:
                # Decide direction using port 88 (client -> server is dport==88)
                if (TCP in pkt and pkt[TCP].dport == 88) or (UDP in pkt and pkt[UDP].dport == 88):
                    hs.kerberos_principals |= k
                    hs.username_candidates |= k
            
            # NetBIOS candidates (NBNS) + username candidates
            nb_hs = extract_netbios_candidates(pkt)
            if nb_hs:
                hs.netbios_names |= nb_hs

            nb_hd = extract_netbios_candidates(pkt)
            if nb_hd:
                hd.netbios_names |= nb_hd

            u1 = extract_username_candidates(pkt)
            if u1:
                hs.username_candidates |= u1

            nt = extract_ntlm_usernames(pkt)
            if nt:
                hs.username_candidates |= nt
                
            # ---------------- UA correlation (client side) ----------------
            if HAVE_HTTP and HTTPRequest in pkt:
                req = pkt[HTTPRequest]

                raw_ua = getattr(req, "User_Agent", b"")
                ua = raw_ua.decode(errors="ignore").strip() if isinstance(raw_ua, bytes) else str(raw_ua or "").strip()

                raw_host = getattr(req, "Host", b"")
                host = raw_host.decode(errors="ignore").strip() if isinstance(raw_host, bytes) else str(raw_host or "").strip()

                if ua:
                    hs.user_agents.add(ua)

                if ua and host:
                    hs.ua_domains[ua].add(host)    
            
    return hosts