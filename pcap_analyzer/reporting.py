from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Tuple

from pcap_analyzer.constants import (
    RESET, RED, GREEN, YELLOW,
    BLUE, MAGENTA, CYAN, WHITE, BOLD
)

from pcap_analyzer.utils import (
    ttl_mode,
    os_hint_from_ttl,
)

from pcap_analyzer.models import HostProfile
from pcap_analyzer.utils import is_private_ipv4
from pcap_analyzer.focus import (
    compute_ua_score,
    ua_family,
    ua_used_with_domains,
    ua_browser_downloading_exec,
)
from pcap_analyzer.vt_enrichment import (
    vt_summarize_ip,
    vt_summarize_file,
)





def print_host_inventory_summary(hosts, limit=30):
    """
    Stampa una vista “attori coinvolti” (top per last_seen-first_seen e #mac/nb/user).
    """
    if not hosts:
        return

    items = list(hosts.values())
    # ordina: prima quelli con più “identità” + durata osservata
    def score(h: HostProfile):
        dur = 0
        if h.first_ts is not None and h.last_ts is not None:
            dur = max(0, h.last_ts - h.first_ts)
        return (
            len(h.macs) + len(h.netbios_names) + len(h.username_candidates),
            dur
        )

    items.sort(key=score, reverse=True)
    items = items[:limit]

    print(f"{GREEN}-------------------- HOST INVENTORY (actors) --------------------{RESET}")
    print()

    for h in items:
        ttl_m = ttl_mode(h.ttl_samples)
        hint, conf = os_hint_from_ttl(ttl_m)

        side = "internal" if is_private_ipv4(h.ip) else "external"
        print(f"{YELLOW}{h.ip}{RESET}  {MAGENTA}[{side}]{RESET}")

        # --- Server roles (candidates) ---
        if getattr(h, "server_roles", None):
            roles = ", ".join(sorted(h.server_roles))
            print(f"   {BLUE}Server roles (candidates): {roles}{RESET}")

        if h.macs:
            print(f"   MACs: {', '.join(sorted(list(h.macs))[:4])}" + (f" ... (+{len(h.macs)-4})" if len(h.macs)>4 else ""))

        if ttl_m is not None:
            print(f"   TTL(mode): {ttl_m}  -> OS hint: {hint} (conf {conf})")
        else:
            print(f"   TTL(mode): None  -> OS hint: unknown")

        if h.netbios_names:
            print(f"   NetBIOS candidates: {', '.join(sorted(list(h.netbios_names))[:6])}" + (f" ... (+{len(h.netbios_names)-6})" if len(h.netbios_names)>6 else ""))

        if h.username_candidates:
            print(f"   Username candidates: {', '.join(sorted(list(h.username_candidates))[:6])}" + (f" ... (+{len(h.username_candidates)-6})" if len(h.username_candidates)>6 else ""))

        if h.dhcp_hostnames:
            print(f"   DHCP hostnames: {', '.join(sorted(list(h.dhcp_hostnames))[:6])}" + (f" ... (+{len(h.dhcp_hostnames)-6})" if len(h.dhcp_hostnames)>6 else ""))

        if h.dhcp_vendors:
            print(f"   DHCP vendors: {', '.join(sorted(list(h.dhcp_vendors))[:4])}" + (f" ... (+{len(h.dhcp_vendors)-4})" if len(h.dhcp_vendors)>4 else ""))

        if h.kerberos_principals:
            print(f"   Kerberos principals (best-effort): {', '.join(sorted(list(h.kerberos_principals))[:6])}" + (f" ... (+{len(h.kerberos_principals)-6})" if len(h.kerberos_principals)>6 else ""))

        if h.hostnames:
            print(f"   Hostnames (LLMNR/mDNS best-effort): {', '.join(sorted(list(h.hostnames))[:6])}" + (f" ... (+{len(h.hostnames)-6})" if len(h.hostnames)>6 else ""))
        
        if h.first_ts and h.last_ts:
            print(f"   Seen: {datetime.fromtimestamp(h.first_ts)} -> {datetime.fromtimestamp(h.last_ts)}")

        print()

    print("------------------------------------------------------------------------")
    
def print_general_ua_correlations(hosts: dict, suspicious_high_entropy_labels, suspicious_downloads: list[dict], limit: int = 20):
    """
    Stampa top host (interni) con correlazioni UA forensi:
    - UA churn / famiglie
    - UA usati con domini high-entropy
    - browser UA che scarica eseguibili/script
    """
    suspicious_domains = set()
    if suspicious_high_entropy_labels:
        suspicious_domains = set(d for d, _, _ in suspicious_high_entropy_labels)

    scored = []
    for ip, h in hosts.items():
        if not is_private_ipv4(ip):
            continue  # di solito l'UA interessante è lato client interno

        score, reasons = compute_ua_score(h, suspicious_domains, suspicious_downloads)
        if score <= 0:
            continue

        fams = {ua_family(u) for u in (h.user_agents or [])}
        fams.discard("unknown")
        scored.append((score, ip, h, reasons, len(h.user_agents), len(fams)))

    scored.sort(reverse=True, key=lambda x: x[0])

    if not scored:
        return

    print()
    print(f"{GREEN}-------------------- USER-AGENT CORRELATIONS (GENERAL) --------------------{RESET}")
    print()

    for score, ip, h, reasons, ua_cnt, fam_cnt in scored[:limit]:
        print(f"{YELLOW}{ip}{RESET}  UA_Risk_Score={score}  uas={ua_cnt}  ua_families={fam_cnt}")
        print(f"   Reasons: {', '.join(reasons)}")

        # show a few UAs
        if h.user_agents:
            sample = sorted(list(h.user_agents))[:5]
            print(f"   UA sample: {sample}" + (f" ... (+{len(h.user_agents)-5})" if len(h.user_agents) > 5 else ""))

        # show UA->domain hits
        hits = ua_used_with_domains(h, suspicious_domains)
        if hits:
            for ua, dom in hits[:5]:
                print(f"   - UA used with high-entropy domain: {dom}")

        # show browser downloading exec/script
        if ua_browser_downloading_exec(h, suspicious_downloads):
            print(f"   - Browser-like UA downloaded executable/script (review downloads list)")

        print()

    print("------------------------------------------------------------------------")

def print_http_stats(
    top_hosts,
    top_urls,
    top_user_agents,
    top_extensions,
    top_suspicious_requests,
    ):
    # se non c'è niente, non stampo
    if not (top_hosts or top_urls or top_user_agents or top_extensions or top_suspicious_requests):
        return

    print("HTTP stats:\n")

    # --- Top host ---
    if top_hosts:
        print("   Top HTTP hosts:\n")
        for host, data in top_hosts:
            total = data["total"]
            methods = data["methods"]
            methods_str = ", ".join(
                f"{count} {m}"
                for m, count in sorted(methods.items(), key=lambda x: x[1], reverse=True)
            )
            print(f"      - {host}: {total} requests ({methods_str})")
        print()

    # --- Top URL ---
    if top_urls:
        print("   Top HTTP URLs:\n")
        for url, data in top_urls:
            total = data["total"]
            methods = data["methods"]
            methods_str = ", ".join(
                f"{count} {m}"
                for m, count in sorted(methods.items(), key=lambda x: x[1], reverse=True)
            )
            print(f"      - {url}: {total} requests ({methods_str})")
        print()

    # --- Top User-Agent ---
    if top_user_agents:
        print("   Top HTTP User-Agents:\n")
        for ua, count in top_user_agents:
            print(f"      - {ua}: {count} requests")
        print()

    # --- Top estensioni richieste ---
    if top_extensions:
        print("   Top requested file extensions (by path):\n")
        for ext, count in top_extensions:
            print(f"      - .{ext}: {count} requests")
        print()

    # --- Metodi sospetti ---
    if top_suspicious_requests:
        print("   Suspicious HTTP methods (non-GET/POST) by host/path:\n")
        for (method, host, path), count in top_suspicious_requests:
            print(f"      - {method} {host}{path}: {count} requests")
        print()

    print("------------------------------------------------------------------------")
    
def print_http_file_stats(stats_by_ext, suspicious_downloads, large_threshold = 5 * 1024 * 1024):
    if not stats_by_ext and not suspicious_downloads:
        return

    print("HTTP file-centric view:")
    print()

    if stats_by_ext:
        print("   Top file extensions by bytes:")
        print()
        top_by_bytes = sorted(
            stats_by_ext.items(),
            key=lambda x: x[1]["bytes"],
            reverse=True
        )[:10]
        for ext, data in top_by_bytes:
            print(f"      - .{ext}: {data['count']} files, {data['bytes']} bytes")
        print()

    # evidenzia sospetti
    if suspicious_downloads:
        print("   Potentially interesting/suspicious file transfers:")
        print()
        for d in suspicious_downloads[:20]:
            size_str = f"{d['size']} B" if d['size'] is not None else "unknown size"
            cat = d["category"] or "other"
            flags = []
            if d["category"]:
                flags.append(cat)
            if d["large"]:
                flags.append(f"large (>{large_threshold} B)")
            flags_str = ", ".join(flags) if flags else "generic"

            print(
                f"      - {d['client_ip']} <- {d['server_ip']} "
                f"({d['host']}{d['path']})  .{d['ext']}  {size_str}  [{flags_str}]"
            )
        if len(suspicious_downloads) > 20:
            print(f"      ... +{len(suspicious_downloads) - 20} more")
        print()

    print("------------------------------------------------------------------------")
    

    
def print_dns_stats_advanced(
    top_qnames,
    top_resolvers,
    top_base_domains,
    suspicious_many_subdomains,
    suspicious_high_entropy_labels,
    ):
    if not top_qnames and not top_resolvers and not top_base_domains and not suspicious_many_subdomains and not suspicious_high_entropy_labels:
        return
    print("DNS Stats:\n")
    if top_qnames:
        
        print("   Top DNS queried FQDNs:\n")
        for name, count in top_qnames:
            print(f"      - {name}: {count} queries")
        print()

    if top_resolvers:
        
        print("   Top DNS resolvers (by queries sent):\n")
        for ip, count in top_resolvers:
            print(f"      - {ip}: {count} queries")
        print()

    if top_base_domains:
        
        print("   Top DNS base domains:\n")
        for dom, count in top_base_domains:
            print(f"      - {dom}: {count} queries")
        print()

    if suspicious_many_subdomains:
        
        print("   DNS domains with many unique subdomains (possible tracking / exfil / DGA):\n")
        for dom, subs_count in suspicious_many_subdomains:
            print(f"      - {dom}: {subs_count} unique subdomains")
        print()

    if suspicious_high_entropy_labels:
        
        print("   DNS FQDNs with high-entropy labels (possible DGA / tunneling):\n")
        for qn, cnt, ent in suspicious_high_entropy_labels:
            print(f"      - {qn}: {cnt} queries, entropy={ent:.2f}")
        print()

    
    print("------------------------------------------------------------------------")    
    

def print_ja3_stats(top_ja3):
    if not top_ja3:
        return

    print("Top 5 TLS JA3 fingerprints:\n")
    for (ja3_hash, ja3_str), count in top_ja3:
        print(f"   - {ja3_hash} : {count} connections")
        print(f"       {ja3_str}")
        print()
    print("------------------------------------------------------------------------")
    

def print_protocol_stats(proto_count):
    print()
    print("Protocol distribution (by packets and bytes):")
    print()
    sorted_items = sorted(proto_count.items(), key=lambda x: x[1]["bytes"], reverse=True)
    for proto_name, pkts_bytes_count in sorted_items:
        pkts = pkts_bytes_count["pkts"]
        bytes_ = pkts_bytes_count["bytes"]
        print(f"   - {proto_name}: {pkts} pkts, {bytes_} bytes")
    print("------------------------------------------------------------------------")


def print_top_list(title, items, label_fmt):
    print(title)
    print()
    for item in items:
        print("   " + label_fmt(item))
    print("------------------------------------------------------------------------")

    
def generate_final_report(
    file_path,
    packets,
    proto_stats,
    top_src_ip,
    top_dst_ip,
    top_src_port,
    top_dst_port,
    dns_stats,
    http_stats,
    stats_by_ext,                
    suspicious_downloads,
    http_mismatches,
    http_host_ips,
    vt_ip_results=None,
    vt_file_results=None,
    hosts=None
    ):
    print()
    print("="*70)
    print(f"{RED}                 FINAL PCAP FORENSIC REPORT{RESET}")
    print("="*70)
    print()

    # ----- METADATA -----
    print(f"PCAP File: {GREEN}{file_path}{RESET}")
    print(f"Packets: {GREEN}{len(packets)}{RESET}")

    try:
        first_ts = datetime.fromtimestamp(int(packets[0].time))
        last_ts  = datetime.fromtimestamp(int(packets[-1].time))
        print(f"Time range: {GREEN}{first_ts}  ->  {last_ts}{RESET}")
    except:
        pass

    # SHA256
    import hashlib
    try:
        with open(file_path, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        print(f"SHA256: {GREEN}{sha}{RESET}")
    except:
        print("SHA256: <unavailable>")

    print()
    print(f"{GREEN}--------------------- NETWORK SUMMARY ---------------------{RESET}")
    print()

    # Protocol distribution
    print(f"{YELLOW}Protocol distribution:{RESET}")
    for proto, vals in sorted(proto_stats.items(), key=lambda x: x[1]["bytes"], reverse=True):
        print(f"   - {proto}: {vals['pkts']} pkts, {vals['bytes']} bytes")
    print()

    # Top IPs and ports
    print(f"{YELLOW}Top Source IPs:{RESET}")
    for item in top_src_ip:
        ip, d = item
        print(f"   - {BLUE}{ip}{RESET}: {d['pkts']} pkts, {d['bytes']} bytes")
    print()

    print(f"{YELLOW}Top Destination IPs:{RESET}")
    for item in top_dst_ip:
        ip, d = item
        print(f"   - {BLUE}{ip}{RESET}: {d['pkts']} pkts, {d['bytes']} bytes")
    print()

    print(f"{YELLOW}Top Source Ports:{RESET}")
    for ((proto, port), d) in top_src_port:
        print(f"   - {proto}/{port}: {d['pkts']} pkts, {d['bytes']} bytes")
    print()

    print(f"{YELLOW}Top Destination Ports:{RESET}")
    for ((proto, port), d) in top_dst_port:
        print(f"   - {proto}/{port}: {d['pkts']} pkts, {d['bytes']} bytes")
    print()
    
    

    print(f"{GREEN}----------------------- DNS SUMMARY ------------------------{RESET}")
    print()

    (
        top_qnames,
        top_resolvers,
        top_base_domains,
        suspicious_many_subdomains,
        suspicious_high_entropy_labels,
        known_good_high_entropy_labels,
    ) = dns_stats

    print(f"{YELLOW}Top DNS Queries:{RESET}")
    for q, c in top_qnames:
        print(f"   - {BLUE}{q}{RESET}: {c}")
    print()

    print(f"{YELLOW}Top Resolvers:{RESET}")
    for r, c in top_resolvers:
        print(f"   - {r}: {c}")
    print()

    print(f"{YELLOW}Top Base Domains:{RESET}")
    for d, c in top_base_domains:
        print(f"   - {BLUE}{d}{RESET}: {c}")
    print()

    print(f"{YELLOW}Suspicious (many subdomains):{RESET}")
    for d, n in suspicious_many_subdomains:
        print(f"   - {RED}{d}{RESET}: {n} subdomains")
    print()

    print(f"{YELLOW}High-entropy domains (unknown / interesting):{RESET}")
    for q, c, e in suspicious_high_entropy_labels:
        print(f"   - {RED}{q}{RESET}: {c} queries (entropy={e:.2f})")
    if known_good_high_entropy_labels:
        print(f"   (suppressed {len(known_good_high_entropy_labels)} known-good vendor/CDN high-entropy domains; shown in focus)")
    print()

    print(f"{GREEN}----------------------- HTTP SUMMARY -----------------------{RESET}")
    print()

    (
        top_hosts,
        top_urls,
        top_user_agents,
        top_extensions,
        top_suspicious_methods
    ) = http_stats

    print(f"{YELLOW}Top HTTP Hosts:{RESET}")   
    for host, data in top_hosts:
        methods = ", ".join([f"{m}:{v}" for m, v in data["methods"].items()])
        bytes_out = data.get("bytes_out", 0)
        bytes_in = data.get("bytes_in", 0)

        ips = sorted(http_host_ips.get(host, []))
        if ips:
            ip_str = ", ".join(ips[:5])
            if len(ips) > 5:
                ip_str += f" ... (+{len(ips)-5} more)"
            host_label = f"{host} [{ip_str}]"
        else:
            host_label = host

        print(f"   - {BLUE}{host_label}{RESET}: {data['total']} requests {MAGENTA}({methods}){RESET}, "
              f"bytes_out={bytes_out}, bytes_in={bytes_in}")
    print()          


    print(f"{YELLOW}Top HTTP URLs:{RESET}")
    for url, data in top_urls:
        methods = ", ".join([f"{m}:{v}" for m, v in data["methods"].items()])
        bytes_out = data.get("bytes_out", 0)
        bytes_in = data.get("bytes_in", 0)
        print(f"   - {BLUE}{url}{RESET}: {data['total']} requests {MAGENTA}({methods}){RESET}, "
              f"bytes_out={bytes_out}, bytes_in={bytes_in}")
    print()


    print(f"{YELLOW}Top User Agents:{RESET}")
    for ua, c in top_user_agents:
        print(f"   - {ua}: {c}")
    print()

    print(f"{YELLOW}Top File Extensions:{RESET}")
    for ext, c in top_extensions:
        print(f"   - .{ext}: {c} requests")
    print()

    print(f"{YELLOW}Suspicious HTTP Methods:{RESET}")
    for (method, host, path), c in top_suspicious_methods:
        print(f"   {RED}- {method} {host}{path}: {c} requests{RESET}")
    print()

    
    print(f"{GREEN}-------------------- HTTP FILE TRANSFERS --------------------{RESET}")
    print()

# === 1. Stats by extension ===
    print(f"{YELLOW}Downloaded file types (by extension):{RESET}")
    if not stats_by_ext:
        print("   None detected")
    else:
        for ext, data in sorted(stats_by_ext.items(), key=lambda x: x[1]["bytes"], reverse=True):
            count = data.get("count", 0)
            bytes_ = data.get("bytes", 0)
            print(f"   - {BLUE}{ext}{RESET}: {count} files, {bytes_} bytes total")
    print()
    
    print(f"{YELLOW}Content-Type ↔ Extension mismatches:{RESET}")
    if not http_mismatches:
        print("   None detected")
    else:
        for m in http_mismatches[:20]:
            url = f"{m['host']}{m['path']}"
            ext_show = f".{m['ext']}" if m["ext"] else "(no ext)"
            size = m.get("size")
            size_show = f"{size} B" if size is not None else "unknown size"
            print(f"   - {RED}{m['client_ip']} <- {m['server_ip']}  ({url})  ext={ext_show}  ct={m['content_type']}  {size_show}  [{m['kind']}]{RESET}")
    print()


    # === 2. Suspicious downloads ===
    print(f"{YELLOW}Suspicious or interesting file downloads:{RESET}")
    if not suspicious_downloads:
        print("   None")
    else:
        for entry in suspicious_downloads:
            client = entry["client_ip"]
            server = entry["server_ip"]
            url = f"{entry['host']}{entry['path']}"
            size = entry["size"]
            ext = entry["ext"]
            reasons = []
            if entry.get("category"):
                reasons.append(entry["category"])
            if entry.get("large"):
                reasons.append("large")
            reason_str = ", ".join(reasons) if reasons else "generic"

            print(f"   {RED}- {client} <- {server}  ({url})  .{ext}  {size} B  [reason: {reason_str}]{RESET}")
    print()
    
    # ---------------- VT ----------------
    if vt_ip_results or vt_file_results:
        print()
        print(f"{GREEN}------------------- VIRUSTOTAL ENRICHMENT -------------------{RESET}")
        print()

        if vt_ip_results:
            print(f"{YELLOW}VT IP checks (mode B):{RESET}")
            for ip, data in vt_ip_results.items():
                if data is None:
                    print(f"   - {ip}: <no data / error>")
                else:
                    print(f"   - {BLUE}{ip}{RESET}: {MAGENTA}{vt_summarize_ip(data)}{RESET}")
            print()

        if vt_file_results:
            print(f"{YELLOW}VT file hash checks (HTTP exported objects):{RESET}")
            for hv, data in vt_file_results.items():
                if data is None:
                    print(f"   - {hv}: <no data / not found / error>")
                else:
                    print(f"   - {hv}: {vt_summarize_file(data)}")
            print()

        print("------------------------------------------------------------------------")