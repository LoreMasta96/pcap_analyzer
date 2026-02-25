"""
Focus host deep analysis.

Compute per-host behavioral stats and a timeline of events.
No printing here: reporting happens in reporting/ modules.
"""

from __future__ import annotations
from datetime import datetime

from collections import Counter, defaultdict
from typing import Dict, List, Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.packet import Raw

try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HAVE_HTTP = True
except Exception:
    HAVE_HTTP = False

from pcap_analyzer.models import FocusEvent
from pcap_analyzer.constants import (
    RESET, RED, GREEN, YELLOW,
    BLUE, MAGENTA, CYAN, WHITE, BOLD,
    UA_SCORE_WEIGHTS
)
from pcap_analyzer.utils import (
    get_base_domain_best_effort,
    ttl_mode,
    os_hint_from_ttl
)

from pcap_analyzer.vt_enrichment import print_vt_focus_section

from pcap_analyzer.tls_analysis import *


def compute_focus_host_stats(packets, focus_ip, event_log=None):
    focus = {
        "pkts_total": 0,
        "bytes_total": 0,
        "pkts_out": 0,
        "pkts_in": 0,
        "bytes_out": 0,
        "bytes_in": 0,
        "proto_out": defaultdict(int),
        "proto_in": defaultdict(int),
        "peers": defaultdict(lambda: {
            "pkts_out": 0,
            "pkts_in": 0,
            "bytes_out": 0,
            "bytes_in": 0,
            "sports": set(),
            "dports": set(),
            "first_ts": None,
            "last_ts": None,
            "ja3_client": set(),
            "sni_seen": set(),
        }),
        "dns_queries": defaultdict(int),
        "dns_resolvers": defaultdict(int),
        "dns_answers": defaultdict(int),
        "http_hosts": defaultdict(lambda: {
            "total": 0,
            "methods": defaultdict(int),
            "bytes_out": 0,
            "bytes_in": 0,
        }),
        "http_server": defaultdict(lambda: {
            "total_reqs": 0,
            "methods": defaultdict(int),
            "urls": defaultdict(int),     # path -> count
            "clients": defaultdict(int),  # client_ip -> count
            "bytes_in": 0,                # request bytes (client->server)
            "bytes_out": 0,            # response bytes (server->client) stima / content-length
            "status": defaultdict(int),
        }),
        "http_urls": defaultdict(lambda: {
            "total": 0,
            "methods": defaultdict(int),
            "bytes_out": 0,
            "bytes_in": 0,
        }),

        "http_user_agents": defaultdict(int),
        "ja3_client_global": defaultdict(int),  # fingerprint -> count
        "ja3_server_global": defaultdict(int),
        "tls_sni_seen": defaultdict(int),            # sni -> count (globale)
        "tls_sni_as_server": defaultdict(int),       # sni -> count quando focus è dst (server)
        "tls_sni_clients": defaultdict(lambda: defaultdict(int)),  # sni -> client_ip -> count
    }
    
        # per associare response alle request HTTP del focus
    pending_http_client = {}   # focus client: (focus->server) request
    pending_http_server = {}   # focus server: (client->focus) request 


    for pkt in packets:
        
        if IP not in pkt:
            continue

        ip = pkt[IP]
        try:
            length = len(pkt)
        except Exception:
            length = 0

        try:
            t = int(pkt.time)
        except Exception:
            t = None

        src = ip.src
        dst = ip.dst
        
        tcp = pkt[TCP] if TCP in pkt else None
        flow_key = (src, dst, tcp.sport, tcp.dport) if (HAVE_HTTP and tcp is not None) else None

        if src != focus_ip and dst != focus_ip:
            continue

        outgoing = (src == focus_ip)

        focus["pkts_total"] += 1
        focus["bytes_total"] += length

        if outgoing:
            focus["pkts_out"] += 1
            focus["bytes_out"] += length
        else:
            focus["pkts_in"] += 1
            focus["bytes_in"] += length

        proto_name = None
        if TCP in pkt:
            proto_name = "TCP"
        elif UDP in pkt:
            proto_name = "UDP"
        elif ICMP in pkt:
            proto_name = "ICMP"
        else:
            proto_name = f"IP(proto={ip.proto})"

        if outgoing:
            focus["proto_out"][proto_name] += 1
        else:
            focus["proto_in"][proto_name] += 1

        # ---------- conversazioni / peers ----------
        peer_ip = dst if outgoing else src
        peer = focus["peers"][peer_ip]

        

        if outgoing:
            peer["pkts_out"] += 1
            peer["bytes_out"] += length
        else:
            peer["pkts_in"] += 1
            peer["bytes_in"] += length

        if TCP in pkt:
            tcp = pkt[TCP]
            peer["sports"].add(tcp.sport)
            peer["dports"].add(tcp.dport)
        elif UDP in pkt:
            udp = pkt[UDP]
            peer["sports"].add(udp.sport)
            peer["dports"].add(udp.dport)

        # timestamps conversazione
        if t is not None:
            if peer["first_ts"] is None or t < peer["first_ts"]:
                peer["first_ts"] = t
            if peer["last_ts"] is None or t > peer["last_ts"]:
                peer["last_ts"] = t
                
        # ---------- JA3: client fingerprint del focus host ----------
        ja3_fp = extract_ja3_from_packet(pkt)
        if ja3_fp and outgoing:
            # consideriamo JA3 solo quando il focus è sorgente (client TLS)
            focus["ja3_client_global"][ja3_fp] += 1
            peer["ja3_client"].add(ja3_fp) 

        # ---------- TLS SNI: hostname richiesti via ClientHello ----------
        sni = extract_sni_from_packet(pkt)
        if sni:
            focus["tls_sni_seen"][sni] += 1

            # focus come server: ClientHello in ingresso (client -> focus)
            if not outgoing:
                focus["tls_sni_as_server"][sni] += 1
                focus["tls_sni_clients"][sni][src] += 1  # src è il client
        if sni and (not outgoing):
            peer["sni_seen"].add(sni)    


        # ---------------- DNS focus ----------------
        if DNS in pkt:
            dns = pkt[DNS]
            # query dall'host
            if outgoing and dns.qr == 0 and dns.qd is not None:
                qd = dns.qd
                # supporta eventuali record multipli
                qnames = []
                cur = qd
                while cur is not None and hasattr(cur, "qname"):
                    try:
                        qname = cur.qname.decode(errors="ignore").rstrip(".")
                    except Exception:
                        qname = ""
                    if qname:
                        qnames.append(qname)
                    cur = getattr(cur, "payload", None)

                for qn in qnames:
                    focus["dns_queries"][qn] += 1
                focus["dns_resolvers"][dst] += 1
                
                if event_log is not None and t is not None and qnames:
                    event_log.append(FocusEvent(
                        ts=t,
                        type="DNS_QUERY",
                        src=src,
                        dst=dst,
                        details={"qnames": qnames}
                    ))

            # risposte verso l'host
            if not outgoing and dns.qr == 1 and dns.qd is not None:
                qd = dns.qd
                try:
                    qname = qd.qname.decode(errors="ignore").rstrip(".")
                except Exception:
                    qname = ""
                if qname:
                    focus["dns_answers"][qname] += 1
                    
                    if event_log is not None and t is not None:
                        event_log.append(FocusEvent(
                            ts=t,
                            type="DNS_ANSWER",
                            src=src,   # resolver
                            dst=dst,   # focus host
                            details={"qname": qname}
                        ))

                # ---------------- HTTP focus (richieste dal focus) ----------------

        if HTTPRequest in pkt and outgoing:
            req = pkt[HTTPRequest]

            raw_host = getattr(req, "Host", b"")
            host = raw_host.decode(errors="ignore") if isinstance(raw_host, bytes) else str(raw_host or "")
            host = host.strip()

            raw_path = getattr(req, "Path", b"/")
            path = raw_path.decode(errors="ignore") if isinstance(raw_path, bytes) else str(raw_path or "/")
            path = path or "/"

            raw_method = getattr(req, "Method", b"")
            method = raw_method.decode(errors="ignore").upper() if isinstance(raw_method, bytes) else str(raw_method or "").upper()
            if not method:
                method = "UNKNOWN"

            raw_ua = getattr(req, "User_Agent", b"")
            ua = raw_ua.decode(errors="ignore").strip() if isinstance(raw_ua, bytes) else str(raw_ua or "").strip()

            # host stats
            hdata = focus["http_hosts"][host]
            hdata["total"] += 1
            hdata["methods"][method] += 1
            hdata["bytes_out"] += length   # stima bytes out request
            hdata.setdefault("ips", set()).add(dst)  # Associa host → IP (server)

            # url stats
            url = f"{host}{path}"
            udata = focus["http_urls"][url]
            udata["total"] += 1
            udata["methods"][method] += 1
            udata["bytes_out"] += length

            if ua:
                focus["http_user_agents"][ua] += 1

            # salva per associare la response
            if HAVE_HTTP and tcp is not None:
                pending_http_client[flow_key] = {
                    "host": host,
                    "path": path,
                }
                
            if event_log is not None and t is not None:
                event_log.append(FocusEvent(
                    ts=t,
                    type="HTTP_REQUEST",
                    src=src,
                    dst=dst,
                    details={
                        "method": method,
                        "host": host,
                        "path": path,
                        "user_agent": ua,
                        "bytes_out": length,
                    }
                ))  

        if HTTPRequest in pkt and (not outgoing):
            req = pkt[HTTPRequest]

            raw_host = getattr(req, "Host", b"")
            host = raw_host.decode(errors="ignore") if isinstance(raw_host, bytes) else str(raw_host or "")
            host = host.strip() or "<no-host-header>"

            raw_path = getattr(req, "Path", b"/")
            path = raw_path.decode(errors="ignore") if isinstance(raw_path, bytes) else str(raw_path or "/")
            path = path or "/"

            raw_method = getattr(req, "Method", b"")
            method = raw_method.decode(errors="ignore").upper() if isinstance(raw_method, bytes) else str(raw_method or "").upper()
            method = method or "UNKNOWN"

            client_ip = src  # perché outgoing=False => src è il client

            s = focus["http_server"][host]
            s["total_reqs"] += 1
            s["methods"][method] += 1
            s["urls"][path] += 1
            s["clients"][client_ip] += 1
            s["bytes_in"] += length

            if HAVE_HTTP and tcp is not None and flow_key is not None:
                pending_http_server[flow_key] = {"host": host, "path": path, "client": client_ip}            

        # ---------------- HTTP focus (response verso il focus) ----------------
        if HTTPResponse in pkt and outgoing and HAVE_HTTP and tcp is not None:
            resp = pkt[HTTPResponse]

        # reverse della response (focus->client) per tornare a (client->focus)
            rev_key = (dst, src, tcp.dport, tcp.sport)
            req_info = pending_http_server.get(rev_key)
            if not req_info:
                continue

            host = req_info["host"]
            path = req_info["path"]

            raw_cl = getattr(resp, "Content_Length", b"")
            cl_str = raw_cl.decode(errors="ignore").strip() if isinstance(raw_cl, bytes) else str(raw_cl or "").strip()
            size = int(cl_str) if cl_str.isdigit() else length

            s = focus["http_server"][host]
            s["bytes_out"] += size

            # opzionale: status code
            raw_sc = getattr(resp, "Status_Code", b"")
            sc = raw_sc.decode(errors="ignore").strip() if isinstance(raw_sc, bytes) else str(raw_sc or "").strip()
            if sc:
                s["status"][sc] += 1

            pending_http_server.pop(rev_key, None)

        
        if HTTPResponse in pkt and not outgoing and HAVE_HTTP and tcp is not None:
            resp = pkt[HTTPResponse]
            rev_key = (dst, src, tcp.dport, tcp.sport)  # server->client, inversione
            req_info = pending_http_client.get(rev_key)
            if not req_info:
                continue

            host = req_info["host"]
            path = req_info["path"]
            url = f"{host}{path}"

            raw_cl = getattr(resp, "Content_Length", b"")
            if isinstance(raw_cl, bytes):
                cl_str = raw_cl.decode(errors="ignore").strip()
            else:
                cl_str = str(raw_cl or "").strip()

            if cl_str.isdigit():
                size = int(cl_str)
            else:
                size = length  # fallback: dimensione pacchetto

            hdata = focus["http_hosts"][host]
            hdata["bytes_in"] += size

            udata = focus["http_urls"][url]
            udata["bytes_in"] += size
            
            if event_log is not None and t is not None:
                event_log.append(FocusEvent(
                    ts=t,
                    type="HTTP_RESPONSE",
                    src=src,   # server
                    dst=dst,   # focus host
                    details={
                        "host": host,
                        "path": path,
                        "url": url,
                        "content_length": size,
                    }
                ))


            pending_http_client.pop(rev_key, None)


    return focus
    
    
def filter_focus_suspicious_downloads(focus_ip, suspicious_downloads):
    focus_dl = []
    for item in suspicious_downloads:
        if item.get("client_ip") == focus_ip:
            focus_dl.append(item)
    return focus_dl
    
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

def print_top_conversations_by_bytes(conv_stats, limit=5):
    """
    Stampa le top conversazioni per bytes totali (direzione src->dst).
    """
    if not conv_stats:
        return

    print("Top 5 conversations by bytes (5-tuple):\n")

    # ordina per bytes decrescente
    items = sorted(
        conv_stats.items(),
        key=lambda x: x[1]["bytes"],
        reverse=True
    )[:limit]

    for (src, sport, dst, dport, proto), data in items:
        duration = data["end"] - data["start"]
        print(f"   - {src}:{sport} -> {dst}:{dport} [{proto}]")
        print(f"       {data['pkts']} pkts, {data['bytes']} bytes, duration ~{duration:.1f}s")
        print()
    print("------------------------------------------------------------------------")


def print_top_conversations_by_duration(conv_stats, limit=5):
    """
    Stampa le top conversazioni per durata (end - start).
    """
    if not conv_stats:
        return

    print("Top 5 conversations by duration (5-tuple):\n")

    items = sorted(
        conv_stats.items(),
        key=lambda x: (x[1]["end"] - x[1]["start"]),
        reverse=True
    )[:limit]

    for (src, sport, dst, dport, proto), data in items:
        duration = data["end"] - data["start"]
        print(f"   - {src}:{sport} -> {dst}:{dport} [{proto}]")
        print(f"       {data['pkts']} pkts, {data['bytes']} bytes, duration ~{duration:.1f}s")
        print()
    print("------------------------------------------------------------------------")

def ua_family(ua: str) -> str:
    u = (ua or "").lower()
    if not u:
        return "unknown"
    if "curl" in u:
        return "curl"
    if "python-requests" in u or "python" in u or "aiohttp" in u:
        return "python"
    if "powershell" in u:
        return "powershell"
    if "wget" in u:
        return "wget"
    if "java" in u or "okhttp" in u:
        return "java"
    if "edg/" in u or "edge" in u:
        return "edge"
    if "chrome/" in u and "chromium" not in u:
        return "chrome"
    if "firefox/" in u:
        return "firefox"
    if "safari/" in u and "chrome/" not in u:
        return "safari"
    return "other"

def assess_ua_ja3_mismatch(focus_stats: dict) -> tuple[int, list[str]]:
    """
    Heuristic mismatch detector:
    - many UA families but only 1 JA3 -> potential UA spoof / proxies / multi-app same TLS stack
    - 1 UA family but many JA3 -> potential multiple stacks behind same UA / interception / weirdness
    Returns (score, reasons[])
    """
    reasons = []
    score = 0

    # UA families (from focus_stats)
    uas = list((focus_stats.get("http_user_agents") or {}).keys())
    fams = {ua_family(u) for u in uas if u}
    fams.discard("unknown")

    # JA3 count (from focus_stats["ja3_client_global"])
    ja3c = focus_stats.get("ja3_client_global") or {}
    ja3_cnt = len(ja3c)

    fam_cnt = len(fams)

    # guardrails: need *some* data
    if fam_cnt == 0 or ja3_cnt == 0:
        return (0, [])

    # mismatch patterns
    if fam_cnt >= 4 and ja3_cnt <= 1:
        score += 3
        reasons.append(f"UA families={fam_cnt} but JA3 fingerprints={ja3_cnt} (many UA, single TLS stack)")
    if fam_cnt <= 1 and ja3_cnt >= 4:
        score += 3
        reasons.append(f"UA families={fam_cnt} but JA3 fingerprints={ja3_cnt} (single UA, many TLS stacks)")
    if fam_cnt >= 6 and ja3_cnt >= 6:
        score += 2
        reasons.append(f"High diversity: UA families={fam_cnt}, JA3={ja3_cnt} (multi-actor host/proxy?)")

    return (score, reasons)

def ua_high_churn(host) -> bool:
    return len(host.user_agents) >= 5


def ua_used_with_domains(host, domains: set) -> list[tuple[str, str]]:
    hits = []
    for ua, ds in host.ua_domains.items():
        for d in ds:
            if d in domains:
                hits.append((ua, d))
    return hits


def ua_browser_downloading_exec(host, downloads: list[dict]) -> bool:
    for d in downloads:
        ua = d.get("ua") or d.get("user_agent") or ""
        ext = (d.get("ext") or "").lower()
        if not ua:
            continue
        if ext in {"exe", "dll", "ps1", "bat"} and "mozilla" in ua.lower():
            return True
    return False

def compute_ua_score(host, suspicious_domains, downloads):
    score = 0
    reasons = []

    if ua_high_churn(host):
        score += UA_SCORE_WEIGHTS["high_ua_churn"]
        reasons.append("high_user_agent_churn")

    hits = ua_used_with_domains(host, suspicious_domains)
    if hits:
        score += UA_SCORE_WEIGHTS["ua_suspicious_domain"]
        reasons.append("ua_used_with_high_entropy_domain")

    if ua_browser_downloading_exec(host, downloads):
        score += UA_SCORE_WEIGHTS["ua_exec_download"]
        reasons.append("browser_user_agent_downloaded_executable")

    return score, reasons

def print_focus_host_report(
    focus_ip,
    focus_stats,
    focus_downloads,
    hosts=None,
    vt_ip_results_focus=None,
    vt_file_results_focus=None,
    suspicious_high_entropy_labels=None,
    known_good_high_entropy_labels=None):
      
    h = None
    ttl_m = None
    hint, conf = ("unknown", 0.0)
    
    if hosts is not None and focus_ip in hosts:
        h = hosts[focus_ip]
        ttl_m = ttl_mode(h.ttl_samples)
        hint, conf = os_hint_from_ttl(ttl_m)          
        
    print()
    print("="*70)
    print(f"{GREEN}                 FOCUS HOST REPORT: {focus_ip}{RESET}")
    print("="*70)
    print()
    
    print(f"{YELLOW}Host identity (best-effort):{RESET}")
    
    if h is None:
        print("   <host profile not available>")
    else:    
        # --- Server role candidates ---
        if hasattr(h, "server_roles") and h.server_roles:
            roles = ", ".join(sorted(h.server_roles))
            print(f"   Server roles (candidates): {roles}") 
            
            if hasattr(h, "server_evidence") and h.server_evidence:
                evid = sorted(h.server_evidence.items(), key=lambda x: x[1], reverse=True)[:3]
                for k, v in evid:
                    print(f"         - {k}: {v}")

        if h.macs:
            print(f"   {BLUE}MACs{RESET}: {', '.join(sorted(h.macs))}") 
        else:
            print(f"   MACs: <not observed>") 

        if ttl_m is not None:
            print(f"   TTL(mode): {ttl_m} -> {BLUE}OS hint{RESET}: {hint} (conf {conf})")
        else:
            print(f"   TTL(mode): <not observed>")

        if h.netbios_names:
            print(f"   {BLUE}NetBIOS candidates{RESET}: {', '.join(sorted(h.netbios_names))}")
        else:
            print(f"   NetBIOS candidates: <none>")

        if h.dhcp_hostnames:
            print(f"   {BLUE}DHCP hostnames{RESET}: {', '.join(sorted(h.dhcp_hostnames))}")
        else:
            print(f"   DHCP hostnames: <none>")

        if h.dhcp_vendors:
            print(f"   {BLUE}DHCP vendors{RESET}: {', '.join(sorted(h.dhcp_vendors))}")
        else:
            print(f"   DHCP vendors: <none>")

        if h.hostnames:
            print(f"   {BLUE}Hostnames{RESET} (LLMNR/mDNS best-effort): {', '.join(sorted(h.hostnames))}")
        else:
            print(f"   Hostnames (LLMNR/mDNS best-effort): <none>")

        if h.kerberos_principals:
            print(f"   {BLUE}Kerberos principals{RESET}: {', '.join(sorted(h.kerberos_principals))}")
        else:
            print(f"   Kerberos principals: <none>")

        if h.username_candidates:
            print(f"   {BLUE}Username candidates{RESET}: {', '.join(sorted(h.username_candidates))}")
        else:
            print(f"   Username candidates: <none>")
            
        # Seen (first/last)
        if h.first_ts is not None and h.last_ts is not None:
            print(f"   {BLUE}Seen{RESET}: {datetime.fromtimestamp(h.first_ts)} -> {datetime.fromtimestamp(h.last_ts)}")
        else:
            print("   Seen: <not observed>")
        print()

    print()
     

    # ---- OVERVIEW ----
    print(f"{YELLOW}Overview:{RESET}")
    print(f"   Packets total: {GREEN}{focus_stats['pkts_total']}{RESET}")
    print(f"   Bytes total:   {GREEN}{focus_stats['bytes_total']}{RESET}")
    print(f"   Outgoing:      {GREEN}{focus_stats['pkts_out']} pkts, {focus_stats['bytes_out']} bytes{RESET}")
    print(f"   Incoming:      {GREEN}{focus_stats['pkts_in']} pkts, {focus_stats['bytes_in']} bytes{RESET}")
    print()

    print(f"{YELLOW}Protocol distribution (outgoing):{RESET}")
    for proto, c in focus_stats["proto_out"].items():
        print(f"   - {proto}: {c} pkts")
    print()

    print(f"{YELLOW}Protocol distribution (incoming):{RESET}")
    for proto, c in focus_stats["proto_in"].items():
        print(f"   - {proto}: {c} pkts")
    print()

    # -------------------- Conversations / Peers --------------------
    print(f"{GREEN}-------------------- Conversations / Peers --------------------{RESET}")
    print()

    peers = focus_stats["peers"]

    # ordina per totale bytes (in+out)
    sorted_peers = sorted(
        peers.items(),
        key=lambda x: x[1]["bytes_out"] + x[1]["bytes_in"],
        reverse=True
    )

    for peer_ip, info in sorted_peers[:20]:
        total_bytes = info["bytes_out"] + info["bytes_in"]
        total_pkts  = info["pkts_out"] + info["pkts_in"]

        first_ts = info["first_ts"]
        last_ts  = info["last_ts"]

        if first_ts is not None and last_ts is not None and last_ts >= first_ts:
            duration = last_ts - first_ts
            first_dt = datetime.fromtimestamp(first_ts)
            last_dt  = datetime.fromtimestamp(last_ts)
        else:
            duration = None
            first_dt = last_dt = None

        if duration and duration > 0:
            bps = total_bytes / duration
        else:
            bps = None

        print(f"{YELLOW}Peer {peer_ip}:{RESET}")
        print(f"   {BLUE}Out{RESET}:  {info['pkts_out']} pkts, {info['bytes_out']} bytes")
        print(f"   {BLUE}In{RESET}:   {info['pkts_in']} pkts, {info['bytes_in']} bytes")
        print(f"   {BLUE}Total{RESET}: {total_pkts} pkts, {total_bytes} bytes")

        if info["sports"] or info["dports"]:
            print(f"   {BLUE}Ports seen{RESET} (s/d): sports={sorted(info['sports'])}, dports={sorted(info['dports'])}")

        if first_dt and last_dt:
            print(f"   {BLUE}First seen{RESET}: {first_dt}")
            print(f"   {BLUE}Last seen{RESET}:  {last_dt}")
            print(f"   {BLUE}Duration{RESET}:   {duration} s")
            if bps is not None:
                print(f"   {BLUE}Avg rate{RESET}:   {bps:.1f} bytes/s")
                
        if info.get("ja3_client"):
            hashes = [fp[0] for fp in sorted(info["ja3_client"])]
            print(f"   {BLUE}JA3 as client to{RESET} {GREEN}{peer_ip}{RESET}: {hashes}")
        if info.get("sni_seen"):
            print(f"   {BLUE}SNI seen from{RESET} {GREEN}{peer_ip}{RESET}: {sorted(info['sni_seen'])[:5]}")
    
        
        print()
    
    print(f"{GREEN}---------------------- TLS Fingerprints (JA3) ----------------------{RESET}")
    print()

    ja3c = focus_stats["ja3_client_global"]

    print(f"{YELLOW}Client JA3 used by this host:{RESET}")
    if not ja3c:
        print("   None")
    else:
        for (fp_hash, fp_str), cnt in sorted(ja3c.items(), key=lambda x: x[1], reverse=True):
            # fp_str può essere lunghissima, mostriamo solo l'hash e magari un pezzo
            print(f"   - {fp_hash}: {cnt} handshakes")
            
    print()
    
    print(f"{YELLOW}TLS SNI requested from this host (server view):{RESET}")
    sni_srv = focus_stats.get("tls_sni_as_server", {})
    if not sni_srv:
        print("   None")
    else:
        for sni, cnt in sorted(sni_srv.items(), key=lambda x: x[1], reverse=True)[:20]:
            print(f"   - {sni}: {cnt} client hellos")

            top_clients = focus_stats.get("tls_sni_clients", {}).get(sni, {})
            if top_clients:
                top5 = sorted(top_clients.items(), key=lambda x: x[1], reverse=True)[:5]
                print("       Top clients:", ", ".join([f"{ip}:{c}" for ip, c in top5]))
    print()

    # ---- UA ↔ JA3 mismatch (heuristic) ----
    mismatch_score, mismatch_reasons = assess_ua_ja3_mismatch(focus_stats)
    if mismatch_reasons:
        print(f"{YELLOW}UA ↔ JA3 consistency (heuristic):{RESET}")
        for r in mismatch_reasons[:5]:
            print(f"   {RED}- {r}{RESET}")
        print()
        
    # ---------------- User-Agent correlation ----------------
    print(f"{YELLOW}User-Agent correlations:{RESET}")

    if h is None:
        print("   <no host profile>")
    else:
        # domini DNS high-entropy già calcolati globalmente
        suspicious_domains = set()
        if suspicious_high_entropy_labels:
            suspicious_domains = set(d for d, _, _ in suspicious_high_entropy_labels)

        score, reasons = compute_ua_score(h, suspicious_domains, focus_downloads)

        if score == 0:
            print("   No suspicious UA correlations observed")
        else:
            print(f"   UA Risk Score: {score}")
            for r in reasons:
                print(f"      - {r}")

            hits = ua_used_with_domains(h, suspicious_domains)
            if hits:
                print("   UA ↔ suspicious domains (examples):")
                for ua, d in hits[:5]:
                    ua_short = ua if len(ua) <= 120 else (ua[:117] + "...")
                    print(f"      - domain: {d}")
                    print(f"        ua: {ua_short}")
            else:
                print("   UA ↔ suspicious domains: none")
    print()            

    print(f"{YELLOW}HTTP User-Agents from this host:{RESET}")
    for ua, c in sorted(focus_stats["http_user_agents"].items(), key=lambda x: x[1], reverse=True):
        print(f"   - {ua}: {c} requests")
    print()

    # ---- DNS ----
    print(f"{GREEN}-------------------------- DNS --------------------------{RESET}")
    print()

    print(f"{YELLOW}DNS queries by this host:{RESET}")
    for qn, c in sorted(focus_stats["dns_queries"].items(), key=lambda x: x[1], reverse=True)[:20]:
        print(f"   - {BLUE}{qn}{RESET}: {c} queries")

    # Known-good high-entropy domains (context only)
    if known_good_high_entropy_labels:
        qset = set((q or "").lower() for q in focus_stats.get("dns_queries", {}).keys())
        kg_hits = [(q, c, e) for (q, c, e) in known_good_high_entropy_labels if (q or "").lower() in qset]
        if kg_hits:
            print()
            print(f"{YELLOW}Known-good high-entropy domains seen (context, not suspicious):{RESET}")
            for q, c, e in kg_hits[:10]:
                print(f"   - {q}: {c} queries (entropy={e:.2f})")

    print()

    print(f"{YELLOW}DNS resolvers used by this host:{RESET}")
    for r, c in sorted(focus_stats["dns_resolvers"].items(), key=lambda x: x[1], reverse=True):
        print(f"   - {r}: {c} queries")
    print()

    print(f"{YELLOW}DNS answers received by this host:{RESET}")
    for qn, c in sorted(focus_stats["dns_answers"].items(), key=lambda x: x[1], reverse=True)[:20]:
        print(f"   - {BLUE}{qn}{RESET}: {c} answers")
    print()

    # ---- HTTP ----
    print(f"{GREEN}-------------------------- HTTP --------------------------{RESET}")
    print()

    print(f"{YELLOW}HTTP hosts contacted by this host:{RESET}")
    for host, data in sorted(focus_stats["http_hosts"].items(), key=lambda x: x[1]["total"], reverse=True)[:20]:
        methods = ", ".join([f"{m}:{v}" for m, v in data["methods"].items()])
        print(f"   - {BLUE}{host}{RESET}: {data['total']} requests {MAGENTA}({methods}){RESET}, "
              f"bytes_out={data['bytes_out']}, bytes_in={data['bytes_in']}")
        ips = ", ".join(data.get("ips", []))
        if ips:
            print(f"       Resolved IPs: {ips}")
      
    print()
    
    print(f"{YELLOW}HTTP requests received by this host (server view):{RESET}")
    srv = focus_stats.get("http_server", {})
    if not srv:
        print("   None")
    else:
        for host, data in sorted(srv.items(), key=lambda x: x[1]["total_reqs"], reverse=True)[:20]:
            methods = ", ".join([f"{m}:{v}" for m, v in data["methods"].items()])
            print(f"   - {BLUE}{host}{RESET}: {data['total_reqs']} reqs {MAGENTA}({methods}){RESET}, "
                f"bytes_in={data['bytes_in']}, bytes_out={data['bytes_out']}")

            top_clients = sorted(data["clients"].items(), key=lambda x: x[1], reverse=True)[:5]
            if top_clients:
                print("       Top clients:", ", ".join([f"{ip}:{c}" for ip, c in top_clients]))

            top_paths = sorted(data["urls"].items(), key=lambda x: x[1], reverse=True)[:5]
            if top_paths:
                print("       Top paths:  ", ", ".join([f"{p}:{c}" for p, c in top_paths]))

            top_status = sorted(data["status"].items(), key=lambda x: x[1], reverse=True)[:5]
            if top_status:
                print("       Status:     ", ", ".join([f"{s}:{c}" for s, c in top_status]))
    print()


    print(f"{YELLOW}Top HTTP URLs:{RESET}")
    for url, data in sorted(focus_stats["http_urls"].items(), key=lambda x: x[1]["total"], reverse=True)[:20]:
        methods = ", ".join([f"{m}:{v}" for m, v in data["methods"].items()])
        print(f"   - {BLUE}{url}{RESET}: {data['total']} requests {MAGENTA}({methods}){RESET}, "
              f"bytes_out={data['bytes_out']}, bytes_in={data['bytes_in']}")
    print()


    # ---- FILE DOWNLOADS ----
    print(f"{GREEN}------------------ Suspicious HTTP Downloads ------------------{RESET}")
    print()
    if not focus_downloads:
        print("   None")
    else:
        for d in focus_downloads:
            size = d["size"]
            cat = d["category"] or "unknown"
            large = "LARGE" if d["large"] else ""
            print(f"   - {RED}{d['server_ip']} ({d['host']}{d['path']})  ext=.{d['ext']}  size={size}  category={cat} {large}{RESET}")
    print()
    
    # --- VirusTotal enrichment (focus) ---
    print_vt_focus_section(vt_ip_results_focus, vt_file_results_focus)
    
    
    print(f"{RED}---------------------- END FOCUS REPORT -----------------------{RESET}")
    print()
    
def print_focus_timeline(focus_ip, focus_events, args):
    if not focus_events:
        print()
        print(f"{RED}No timeline events recorded for {focus_ip}.{RESET}")
        print()
        return

    # ---- filtri da CLI ----
    dns_only = args.timeline_dns
    http_only = args.timeline_http
    compact = args.timeline_compact

    # se non è settato nessun filtro specifico, mostriamo tutte le categorie
    if dns_only or http_only:
        allowed_categories = set()
        if dns_only:
            allowed_categories.add("dns")
        if http_only:
            allowed_categories.add("http")
    else:
        allowed_categories = {"dns", "http", "other"}

    def event_category(ev_type: str) -> str:
        if ev_type in ("DNS_QUERY", "DNS_ANSWER"):
            return "dns"
        if ev_type.startswith("HTTP_") or ev_type == "FILE_DOWNLOAD":
            return "http"
        return "other"

    print()
    print(f"{RED}=============== FOCUS HOST TIMELINE ==============={RESET}")
    print(f"{RED}Host:{RESET}{GREEN} {focus_ip}{RESET}")
    print(f"{RED}=================================================={RESET}")
    print()

    # ordina per timestamp
    focus_events.sort(key=lambda e: e.ts)

    for ev in focus_events:
        cat = event_category(ev.type)
        if cat not in allowed_categories:
            continue

        # modalità compatta: salta gli eventi HTTP troppo “di dettaglio”
        if compact:
            if ev.type in ("HTTP_REQUEST", "HTTP_RESPONSE"):
                # li vediamo indirettamente tramite FILE_DOWNLOAD, scans, ecc.
                continue

        dt = datetime.fromtimestamp(ev.ts)

        line = None

        if ev.type == "DNS_QUERY":
            qnames = ev.details.get("qnames", [])
            if qnames:
                line = f"{ev.src} -> {ev.dst} DNS {', '.join(qnames)}"
        elif ev.type == "DNS_ANSWER":
            qname = ev.details.get("qname", "?")
            line = f"{ev.src} -> {ev.dst} DNS answer for {qname}"
        elif ev.type == "HTTP_REQUEST":
            method = ev.details.get("method", "?")
            path = ev.details.get("path", "/")
            host = ev.details.get("host", "")
            if host:
                line = f"{ev.src} -> {ev.dst} HTTP {method} {host}{path}"
            else:
                line = f"{ev.src} -> {ev.dst} HTTP {method} {path}"
        elif ev.type == "HTTP_RESPONSE":
            url = ev.details.get("url")
            size = ev.details.get("content_length")
            size_str = f"{size} B" if size is not None else "unknown size"
            if url:
                line = f"{ev.src} -> {ev.dst} HTTP response for {url} ({size_str})"
            else:
                line = f"{ev.src} -> {ev.dst} HTTP response ({size_str})"
        elif ev.type == "FILE_DOWNLOAD":
            url = ev.details.get("url", "")
            size = ev.details.get("bytes")
            if size is not None:
                kb = size // 1024
                size_str = f"{kb} KB"
            else:
                size_str = "unknown size"
            line = f"{ev.src} -> {ev.dst} File download {url} {size_str}"
        else:
            # fallback generico
            line = f"{ev.src} -> {ev.dst} {ev.type}"

        if line:
            print(f"[{dt}] {line}")

    print()    