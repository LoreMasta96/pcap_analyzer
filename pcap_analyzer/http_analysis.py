"""
HTTP analysis module.

Best-effort parsing using Scapy's HTTP layers.
If Scapy HTTP is not available, functions return empty stats.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Tuple

from scapy.layers.inet import IP, TCP

try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HAVE_HTTP = True
except Exception:
    HAVE_HTTP = False

from pcap_analyzer.constants import (
    CONTENT_TYPE_TO_EXT,
    DANGEROUS_EXT,
    ARCHIVE_EXT,
    DOC_EXT,
)

from pcap_analyzer.utils import is_private_ipv4



def extract_file_extension(path: str):
    """
    Estrae una *vera* estensione di file da un URL path HTTP.

    Ritorna:
      - ext (str) se valida (senza il punto, lowercase)
      - None se non sembra un file reale
    """

    if not path:
        return None

    # Rimuovi query string e fragment
    # es: /file.exe?x=y#abc → /file.exe
    clean_path = path.split("?", 1)[0].split("#", 1)[0]

    # Prendi solo l'ultimo segmento
    # es: /a/b/c/file.exe → file.exe
    filename = clean_path.rsplit("/", 1)[-1]

    if not filename or "." not in filename:
        return None

    # Estrai l'estensione candidata
    name, ext = filename.rsplit(".", 1)
    ext = ext.lower()

    # Validazioni forti (anti-false-positive)
    # - lunghezza ragionevole
    # - solo caratteri alfanumerici
    # - niente hash / token
    if not (1 <= len(ext) <= 6):
        return None

    if not ext.isalnum():
        return None

    # opzionale: evita estensioni "endpoint"
    DYNAMIC_ENDPOINTS = {"php", "asp", "aspx", "jsp"}
    if ext in DYNAMIC_ENDPOINTS:
        return None

    return ext
    
def normalize_content_type(ct: str) -> str:
    if not ct:
        return ""
    ct = ct.strip().lower()
    return ct.split(";", 1)[0].strip()
    
def compute_http_stats(packets):
    """
    HTTP avanzato per forensics.

    Ritorna:
      - top_hosts: [(host, data), ...]
      - top_urls: [(url, data), ...]
      - top_user_agents: [(ua, count), ...]
      - top_extensions: [(ext, count), ...]
      - top_suspicious_requests: [((method, host, path), count), ...]

    dove data per host/url è:
      {
        "total": int,
        "methods": {method: count},
        "bytes_out": int,   # request (client -> server)
        "bytes_in": int,    # response (server -> client)
      }
    """

    if not HAVE_HTTP or HTTPRequest is None:
        return [], [], [], [], []

    # host -> {total, methods, bytes_out, bytes_in}
    host_stats = defaultdict(lambda: {
        "total": 0,
        "methods": defaultdict(int),
        "bytes_out": 0,
        "bytes_in": 0,
    })

    # url (host+path) -> {total, methods, bytes_out, bytes_in}
    url_stats = defaultdict(lambda: {
        "total": 0,
        "methods": defaultdict(int),
        "bytes_out": 0,
        "bytes_in": 0,
    })

    # User-Agent globali
    ua_counts = defaultdict(int)

    # estensioni file (da Path)
    ext_counts = defaultdict(int)

    # richieste con metodi "sospetti"
    SUSPICIOUS_METHODS = {
        "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"
    }
    suspicious_req_counts = defaultdict(int)  # (method, host, path) -> count

    # per associare response alla request: key = (src, dst, sport, dport)
    pending_requests = {}  # flow_key -> {host, path}

    for pkt in packets:
        # ci servono IP/TCP per correlare request/response
        has_ip_tcp = IP in pkt and TCP in pkt
        if not has_ip_tcp and HTTPRequest not in pkt and HTTPResponse not in pkt:
            continue

        length = 0
        try:
            length = len(pkt)
        except Exception:
            pass

        # --- HTTP REQUEST ---
        if HTTPRequest in pkt and has_ip_tcp:
            ip = pkt[IP]
            tcp = pkt[TCP]
            req = pkt[HTTPRequest]

            # Host
            raw_host = getattr(req, "Host", b"")
            if isinstance(raw_host, bytes):
                host = raw_host.decode(errors="ignore")
            else:
                host = str(raw_host or "")
            host = host.strip()

            # Path
            raw_path = getattr(req, "Path", b"/")
            if isinstance(raw_path, bytes):
                path = raw_path.decode(errors="ignore")
            else:
                path = str(raw_path or "/")
            path = path or "/"

            # Metodo
            raw_method = getattr(req, "Method", b"")
            if isinstance(raw_method, bytes):
                method = raw_method.decode(errors="ignore").upper()
            else:
                method = str(raw_method or "").upper()
            if not method:
                method = "UNKNOWN"

            # User-Agent
            raw_ua = getattr(req, "User_Agent", b"")
            if isinstance(raw_ua, bytes):
                ua = raw_ua.decode(errors="ignore").strip()
            else:
                ua = str(raw_ua or "").strip()

            if ua:
                ua_counts[ua] += 1

            # Estensione (dall'ultima parte del path)
            ext = extract_file_extension(path)
            if ext:
                ext_counts[ext] += 1

            # URL logico host+path
            url = f"{host}{path}"

            # aggiorna stats host
            hdata = host_stats[host]
            hdata["total"] += 1
            hdata["methods"][method] += 1
            hdata["bytes_out"] += length   # request = traffico in uscita dal client

            # aggiorna stats url
            udata = url_stats[url]
            udata["total"] += 1
            udata["methods"][method] += 1
            udata["bytes_out"] += length

            # metodi sospetti
            if method in SUSPICIOUS_METHODS:
                suspicious_req_counts[(method, host, path)] += 1

            # salva per associare la response
            flow_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
            pending_requests[flow_key] = {
                "host": host,
                "path": path,
            }

        # --- HTTP RESPONSE ---
        elif HTTPResponse in pkt and has_ip_tcp:
            ip = pkt[IP]
            tcp = pkt[TCP]
            resp = pkt[HTTPResponse]

            # la response viaggia in direzione opposta: server -> client
            rev_key = (ip.dst, ip.src, tcp.dport, tcp.sport)
            req_info = pending_requests.get(rev_key)
            if not req_info:
                continue  # non abbiamo la request associata

            host = req_info["host"]
            path = req_info["path"]
            url = f"{host}{path}"

            # Content-Length (se presente)
            raw_cl = getattr(resp, "Content_Length", b"")
            if isinstance(raw_cl, bytes):
                cl_str = raw_cl.decode(errors="ignore").strip()
            else:
                cl_str = str(raw_cl or "").strip()

            if cl_str.isdigit():
                try:
                    size = int(cl_str)
                except ValueError:
                    size = length
            else:
                size = length  # fallback: dimensione pacchetto

            # aggiorna bytes_in per host/url
            hdata = host_stats[host]
            hdata["bytes_in"] += size

            udata = url_stats[url]
            udata["bytes_in"] += size

            # una volta usata, possiamo rimuovere la request
            pending_requests.pop(rev_key, None)

    # --- Top liste ---

    top_hosts = sorted(
        host_stats.items(),
        key=lambda x: x[1]["total"],
        reverse=True
    )[:10]

    top_urls = sorted(
        url_stats.items(),
        key=lambda x: x[1]["total"],
        reverse=True
    )[:10]

    top_user_agents = sorted(
        ua_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    top_extensions = sorted(
        ext_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    top_suspicious_requests = sorted(
        suspicious_req_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    return (
        top_hosts,
        top_urls,
        top_user_agents,
        top_extensions,
        top_suspicious_requests,
    )

    
def compute_http_file_stats(packets, large_threshold = 5 * 1000 * 1000):
    """
    Analisi "file-centric" basata su HTTP request/response.

    Ritorna:
      - stats_by_ext: ext -> {"count": int, "bytes": int}
      - suspicious_downloads: lista di dict con info su file "interessanti"
    """

    if not HAVE_HTTP or HTTPRequest is None or HTTPResponse is None:
        return {}, []


    stats_by_ext = defaultdict(lambda: {"count": 0, "bytes": 0})
    suspicious_downloads = []

    # per associare response alla request: key = (src, dst, sport, dport)
    pending_requests = {}  # flow_key -> {host, path, method, ua, client_ip, server_ip}
    
    http_mismatches = []

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]
        flow_key = (ip.src, ip.dst, tcp.sport, tcp.dport)

        # --- HTTP REQUEST ---
        if HTTPRequest in pkt:
            req = pkt[HTTPRequest]

            # Host
            raw_host = getattr(req, "Host", b"")
            host = raw_host.decode(errors="ignore") if isinstance(raw_host, bytes) else str(raw_host or "")
            host = host.strip()

            # Path
            raw_path = getattr(req, "Path", b"/")
            path = raw_path.decode(errors="ignore") if isinstance(raw_path, bytes) else str(raw_path or "/")
            path = path or "/"

            # Method
            raw_method = getattr(req, "Method", b"")
            method = raw_method.decode(errors="ignore").upper() if isinstance(raw_method, bytes) else str(raw_method or "").upper()
            if not method:
                method = "UNKNOWN"

            # User-Agent
            raw_ua = getattr(req, "User_Agent", b"")
            ua = raw_ua.decode(errors="ignore").strip() if isinstance(raw_ua, bytes) else str(raw_ua or "").strip()

            pending_requests[flow_key] = {
                "host": host,
                "path": path,
                "method": method,
                "ua": ua,
                "client_ip": ip.src,
                "server_ip": ip.dst,
            }

        # --- HTTP RESPONSE ---
        elif HTTPResponse in pkt:
            resp = pkt[HTTPResponse]

            # la response viaggia in direzione opposta: server->client
            rev_key = (ip.dst, ip.src, tcp.dport, tcp.sport)
            req_info = pending_requests.get(rev_key)
            if not req_info:
                continue  # non abbiamo la request associata

            host = req_info["host"]
            path = req_info["path"]
            method = req_info["method"]
            client_ip = req_info["client_ip"]
            server_ip = req_info["server_ip"]

            # estensione dal path
            ext = extract_file_extension(path) or ""

            # Content-Length (se presente)
            raw_cl = getattr(resp, "Content_Length", b"")
            if isinstance(raw_cl, bytes):
                cl_str = raw_cl.decode(errors="ignore").strip()
            else:
                cl_str = str(raw_cl or "").strip()

            size = None
            if cl_str.isdigit():
                try:
                    size = int(cl_str)
                except ValueError:
                    size = None

            
            # Content-Type (se presente)
            raw_ct = getattr(resp, "Content_Type", b"")
            if isinstance(raw_ct, bytes):
                ct_raw = raw_ct.decode(errors="ignore").strip()
            else:
                ct_raw = str(raw_ct or "").strip()

            ct = normalize_content_type(ct_raw)

            expected_exts = CONTENT_TYPE_TO_EXT.get(ct)

            # mismatch classico: estensione presente ma non compatibile col Content-Type
            if expected_exts and ext and (ext not in expected_exts):
                http_mismatches.append({
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "host": host,
                    "path": path,
                    "ext": ext,
                    "content_type": ct,
                   "size": size,
                    "kind": "ext_vs_ct",
                })

            # caso interessante: niente estensione ma Content-Type ad alto rischio
            SUSPICIOUS_CT = {
                "application/x-dosexec",
                "application/x-msdownload",
                "application/vnd.microsoft.portable-executable",
                "application/vnd.ms-cab-compressed",
                "application/zip",
                "application/x-7z-compressed",
            }
            if (not ext) and (ct in SUSPICIOUS_CT):
                http_mismatches.append({
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "host": host,
                    "path": path,
                    "ext": "",
                    "content_type": ct,
                    "size": size,
                    "kind": "no_ext_high_risk_ct",
                })

            
            # aggiorna stats_by_ext
            if ext:
                stats_by_ext[ext]["count"] += 1
                if size is not None:
                    stats_by_ext[ext]["bytes"] += size

            # classifica "sospetto"
            category = None
            if ext in DANGEROUS_EXT:
                category = "executable/script"
            elif ext in ARCHIVE_EXT:
                category = "archive"
            elif ext in DOC_EXT:
                category = "document"

            is_large = size is not None and size >= large_threshold

            if category or is_large:
                suspicious_downloads.append({
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "host": host,
                    "path": path,
                    "method": method,
                    "ext": ext,
                    "size": size,
                    "content_type": ct,
                    "category": category,
                    "large": is_large,
                    "ua": ua,
                })

           
            pending_requests.pop(rev_key, None)

    return stats_by_ext, suspicious_downloads, http_mismatches