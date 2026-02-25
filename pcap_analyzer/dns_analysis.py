"""
DNS analysis module.

Provides advanced DNS stats with high-entropy domain heuristics.
"""

from __future__ import annotations

from collections import Counter, defaultdict

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    HAVE_DNS = True
except Exception:
    HAVE_DNS = False
from scapy.layers.inet import IP, UDP, TCP

from pcap_analyzer.constants import KNOWN_GOOD_BASE_DOMAINS
from pcap_analyzer.utils import (
    get_base_domain_best_effort,
    classify_high_entropy_domain,
    _shannon_entropy
)





def compute_dns_stats_advanced(packets):
    
    """
    DNS avanzato per forensics.

    Ritorna:
      - top_qnames: lista (qname, count)
      - top_resolvers: lista (resolver_ip, count)
      - top_base_domains: lista (base_domain, count)
      - suspicious_many_subdomains: lista (base_domain, num_subdomains)
      - suspicious_high_entropy_labels: lista (qname, count, entropy)
    """

    qname_count = defaultdict(int)             # fqdn completo -> count
    resolver_count = defaultdict(int)          # IP del resolver -> count
    base_domain_count = defaultdict(int)       # base domain (es: example.com) -> count
    base_domain_subs = defaultdict(set)        # base domain -> set di sottodomini diversi

    qname_entropy_info = {}                    # qname -> [count, entropy_media]

    for pkt in packets:
        if DNS not in pkt:
            continue

        dns = pkt[DNS]

        # se non c'è sezione di domanda, salta
        if dns.qd is None:
            continue

        qd = dns.qd

        # Normalizziamo in una lista di "query-like"
        queries = []

        # ⚠ Scapy a volte rappresenta qd in modo "strano":
        # l'accesso a qname può sollevare IndexError se la lista interna è vuota.
        try:
            _ = qd.qname
            has_qname = True
        except Exception:
            has_qname = False

        if not has_qname:
            # niente qname utilizzabile → saltiamo questo pacchetto DNS
            continue

        # caso "normale": un DNSQR con possibile catena via payload
        queries.append(qd)
        cur = getattr(qd, "payload", None)
        while cur is not None:
            try:
                _ = cur.qname
            except Exception:
                break
            queries.append(cur)
            cur = getattr(cur, "payload", None)


        # Resolver:
        # qr == 0 → query: resolver è dst
        # qr == 1 → response: resolver è src
        resolver_ip = None
        if IP in pkt:
            ip = pkt[IP]
            if dns.qr == 0:
                resolver_ip = ip.dst
            else:
                resolver_ip = ip.src

        for q in queries:
            try:
                qname = q.qname.decode(errors="ignore").rstrip(".")
            except Exception:
                continue

            if not qname:
                continue

            # --- conteggio fqdn ---
            qname_count[qname] += 1

            # --- conteggio resolver ---
            if resolver_ip is not None:
                resolver_count[resolver_ip] += 1

            # --- base domain + sottodomini ---
            labels = qname.split(".")
            base_domain = get_base_domain_best_effort(qname)
            if base_domain and qname.lower().endswith(base_domain.lower()) and qname.lower() != base_domain.lower():
                # everything before the base domain
                sub = qname[:-(len(base_domain) + 1)]
            else:
                sub = ""

            base_domain_count[base_domain] += 1
            if sub:
                base_domain_subs[base_domain].add(sub)

            # --- entropia della leftmost label ---
            left_label = labels[0]
            ent = _shannon_entropy(left_label)

            prev = qname_entropy_info.get(qname)
            if prev is None:
                qname_entropy_info[qname] = [1, ent]
            else:
                prev[0] += 1
                prev[1] = (prev[1] + ent) / 2.0

    # --- Top liste ---

    top_qnames = sorted(qname_count.items(), key=lambda x: x[1], reverse=True)[:10]
    top_resolvers = sorted(resolver_count.items(), key=lambda x: x[1], reverse=True)[:10]
    top_base_domains = sorted(base_domain_count.items(), key=lambda x: x[1], reverse=True)[:10]

    # domini con molti sottodomini
    many_subdomains = [(bd, len(subs)) for bd, subs in base_domain_subs.items()]
    suspicious_many_subdomains = sorted(many_subdomains, key=lambda x: x[1], reverse=True)[:10]

    # label ad alta entropia (split: unknown vs known-good)
    high_entropy_unknown = []
    high_entropy_known_good = []

    for qn, (cnt, ent) in qname_entropy_info.items():
        labels = qn.split(".")
        left = labels[0] if labels else ""
        if len(left) >= 10 and ent >= 3.5:
            cls = classify_high_entropy_domain(qn)
            if cls == "known_good":
                high_entropy_known_good.append((qn, cnt, ent))
            else:
                high_entropy_unknown.append((qn, cnt, ent))

    suspicious_high_entropy_labels = sorted(
        high_entropy_unknown,
        key=lambda x: (x[2], x[1]),
        reverse=True
    )[:10]

    known_good_high_entropy_labels = sorted(
        high_entropy_known_good,
        key=lambda x: (x[2], x[1]),
        reverse=True
    )[:10]

    return (
        top_qnames,
        top_resolvers,
        top_base_domains,
        suspicious_many_subdomains,
        suspicious_high_entropy_labels,          # unknown only
        known_good_high_entropy_labels,          # known-good only
    )
