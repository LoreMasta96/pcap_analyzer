"""
tshark enrichment helpers.

Supports:
- HTTP object export
- Kerberos principal extraction via tshark fields (best-effort)
- Basic availability checks

No printing here: return structures; reporting/main decide what to show.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple

from pcap_analyzer.utils import mark_role



def _find_tshark(tshark_path: str | None = None) -> str | None:
    if tshark_path:
        return tshark_path
    return shutil.which("tshark")
    
def tshark_export_http_objects(pcap_file: str, out_dir: str, tshark_path: str | None = None) -> bool:
    exe = _find_tshark(tshark_path)
    if not exe:
        return False

    # -Q: quiet (evita spam su stdout)
    # --export-objects http,<dir>: esporta oggetti HTTP in directory :contentReference[oaicite:4]{index=4}
    cmd = [exe, "-Q", "-r", pcap_file, "--export-objects", f"http,{out_dir}"]
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    return p.returncode == 0
    
def tshark_export_http_objects_focus(pcap_file: str, focus_ip: str, out_dir: str, tshark_path: str | None = None) -> bool:
    exe = _find_tshark(tshark_path)
    if not exe:
        return False

    # 1) write a filtered pcap containing only http traffic involving focus
    with tempfile.TemporaryDirectory(prefix="focus_pcap_") as tmp:
        filtered_pcap = os.path.join(tmp, "focus_http.pcap")

        cmd1 = [
            exe, "-Q",
            "-r", pcap_file,
            "-Y", f"(ip.addr=={focus_ip}) && http",
            "-w", filtered_pcap
        ]
        p1 = subprocess.run(cmd1, capture_output=True, text=True, errors="replace")
        if p1.returncode != 0:
            return False

        # 2) export objects from the filtered pcap
        cmd2 = [exe, "-Q", "-r", filtered_pcap, "--export-objects", f"http,{out_dir}"]
        p2 = subprocess.run(cmd2, capture_output=True, text=True, errors="replace")
        return p2.returncode == 0
    
    
def _run_tshark_fields(exe: str, pcap_file: str, display_filter: str, fields: list[str]) -> list[list[str]]:
    """
    Ritorna righe come lista di colonne (tab-separated).
    """
    cmd = [
        exe, "-r", pcap_file,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "quote=n",
    ]
    for f in fields:
        cmd += ["-e", f]

    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if p.returncode != 0:
        return []
    rows = []
    for line in p.stdout.splitlines():
        rows.append(line.split("\t"))
    return rows 

def tshark_enrich_hosts_kerberos(pcap_file: str, hosts: dict, tshark_path: str | None = None) -> bool:
    exe = _find_tshark(tshark_path)
    if not exe:
        return False

    # kerberos.CNameString è un field standard del dissector Wireshark/tshark :contentReference[oaicite:7]{index=7}
    rows = _run_tshark_fields(
        exe,
        pcap_file,
        "kerberos.CNameString && (tcp.dstport==88 || udp.dstport==88)",
        ["ip.src", "kerberos.CNameString", "kerberos.crealm"]
    )

    for cols in rows:
        if len(cols) < 2:
            continue
        ip_src = cols[0].strip()
        cname = cols[1].strip()
        realm = cols[2].strip() if len(cols) >= 3 else ""

        if not ip_src or not cname:
            continue
        principal = f"{cname}@{realm}" if realm else cname

        if ip_src in hosts:
            h = hosts[ip_src]
            h.kerberos_principals.add(principal)
            h.username_candidates.add(principal)

    return True
    
def tshark_enrich_server_roles_tls(pcap_file: str, hosts: dict, tshark_path: str | None = None) -> bool:
    """
    Mark TLS servers using strong evidence from tshark dissector:
    - tls.handshake.type == 2 (ServerHello) or 11 (Certificate) coming from ip.src
    Then classify by tcp.srcport:
      - 443 -> https_server
      - 636 -> ldaps_server
    """
    exe = _find_tshark(tshark_path)
    if not exe:
        return False

    # ServerHello (2) or Certificate (11) indicates server side of TLS handshake
    display_filter = "tls.handshake && (tls.handshake.type==2 || tls.handshake.type==11) && tcp.srcport"

    rows = _run_tshark_fields(
        exe,
        pcap_file,
        display_filter,
        ["ip.src", "tcp.srcport", "tls.handshake.type"]
    )
    if not rows:
        return True  # tshark ok but nothing found

    for cols in rows:
        if len(cols) < 2:
            continue
        ip_src = (cols[0] or "").strip()
        sport_s = (cols[1] or "").strip()
        htype = (cols[2] or "").strip() if len(cols) >= 3 else ""

        if not ip_src or not sport_s:
            continue
        try:
            sport = int(sport_s)
        except Exception:
            continue

        if ip_src not in hosts:
            continue

        h = hosts[ip_src]

        # evidenza forte: risposta handshake TLS
        # (se hai già mark_role(host, role, reason), usa quella)
        if hasattr(h, "server_roles") and hasattr(h, "server_evidence"):
            if sport == 443:
                mark_role(h, "https_server", f"tshark:tls_handshake_type{htype}_sport443")
            elif sport == 636:
                mark_role(h, "ldaps_server", f"tshark:tls_handshake_type{htype}_sport636")
            else:
                mark_role(h, "tls_server", f"tshark:tls_handshake_type{htype}_sport{sport}")
        else:
            # fallback minimale se non hai ancora server_roles/server_evidence nel dataclass
            try:
                h.server_roles.add("tls_server")
            except Exception:
                pass

    return True
    
 
def tshark_enrich_focus_stats(pcap_file: str, focus_ip: str, focus_stats: dict, tshark_path: str | None = None) -> bool:
    exe = _find_tshark(tshark_path)
    if not exe:
        return False

    # --- DNS queries dal focus ---
    dns_q_rows = _run_tshark_fields(
        exe,
        pcap_file,
        f"ip.src=={focus_ip} && dns.flags.response==0 && dns.qry.name",
        ["dns.qry.name"]
    )
    for cols in dns_q_rows:
        if not cols:
            continue
        qn = (cols[0] or "").strip().rstrip(".")
        if qn:
            focus_stats["dns_queries"][qn] += 1

    # --- DNS answers verso il focus (conteggio per qname) ---
    dns_a_rows = _run_tshark_fields(
        exe,
        pcap_file,
        f"ip.dst=={focus_ip} && dns.flags.response==1 && dns.qry.name",
        ["dns.qry.name"]
    )
    for cols in dns_a_rows:
        if not cols:
            continue
        qn = (cols[0] or "").strip().rstrip(".")
        if qn:
            focus_stats["dns_answers"][qn] += 1

    # --- HTTP requests dal focus ---
    http_rows = _run_tshark_fields(
        exe,
        pcap_file,
        f"ip.src=={focus_ip} && http.request",
        ["http.host", "http.request.method", "http.request.uri"]
    )
    for cols in http_rows:
        host = (cols[0] if len(cols) > 0 else "").strip() or "<no-host>"
        method = (cols[1] if len(cols) > 1 else "").strip().upper() or "UNKNOWN"
        uri = (cols[2] if len(cols) > 2 else "").strip() or "/"

        hdata = focus_stats["http_hosts"][host]
        hdata["total"] += 1
        hdata["methods"][method] += 1

        url = f"{host}{uri}"
        udata = focus_stats["http_urls"][url]
        udata["total"] += 1
        udata["methods"][method] += 1

    # --- TLS SNI (ClientHello) dal focus ---
    sni_rows = _run_tshark_fields(
        exe,
        pcap_file,
        f"ip.src=={focus_ip} && tls.handshake.type==1 && tls.handshake.extensions_server_name",
        ["tls.handshake.extensions_server_name"]
    )
    for cols in sni_rows:
        if not cols:
            continue
        sni = (cols[0] or "").strip().rstrip(".")
        if sni:
            focus_stats["tls_sni_seen"][sni] += 1

    return True    