"""
VirusTotal enrichment (best-effort).

- IP reputation lookup
- File hash lookup (SHA256 preferred)
- Local JSON cache support to reduce API calls

Uses urllib (no extra deps).
"""

from __future__ import annotations

import os
import json
import time
import hashlib
from typing import Dict, List, Optional, Tuple

from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from pcap_analyzer.utils import is_private_ipv4
from pcap_analyzer.constants import (
    RESET, RED, GREEN, YELLOW,
    BLUE, MAGENTA, CYAN, WHITE, BOLD
)



VT_BASE = "https://www.virustotal.com/api/v3"


def collect_vt_hashes_from_export(exported_hashes: list[dict], max_items: int) -> list[str]:
    # prefer SHA256 when available (VT /files/<hash> works best with sha256)
    out = []
    for item in exported_hashes:
        sha256 = item.get("sha256")
        if sha256:
            out.append(sha256)
        if len(out) >= max_items:
            break
    return out

def hash_file(path: str) -> dict:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            sha256.update(chunk)
            md5.update(chunk)
    return {
        "path": path,
        "size": size,
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
    }

def hash_exported_objects(dir_path: str, min_bytes: int = 1) -> list[dict]:
    out = []
    for name in os.listdir(dir_path):
        fp = os.path.join(dir_path, name)
        if not os.path.isfile(fp):
            continue
        st = os.stat(fp)
        if st.st_size < min_bytes:
            continue
        try:
            out.append(hash_file(fp))
        except OSError:
            continue

    return out
    
def vt_http_get(path: str, api_key: str, timeout=25):
    req = Request(VT_BASE + path, headers={"x-apikey": api_key})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))

def vt_load_cache(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict) and "ip" in data and "file" in data:
                return data
    except Exception:
        pass
    return {"ip": {}, "file": {}}

def vt_save_cache(path: str, cache: dict):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except Exception:
        pass

def vt_throttle(last_ts: float, min_interval_sec: float) -> float:
    now = time.time()
    wait = (last_ts + min_interval_sec) - now
    if wait > 0:
        time.sleep(wait)
    return time.time()

def vt_get_ip(ip: str, api_key: str, cache: dict, last_ts: float, min_interval_sec: float = 15.0):
    if ip in cache["ip"]:
        return cache["ip"][ip], last_ts

    last_ts = vt_throttle(last_ts, min_interval_sec)
    try:
        data = vt_http_get(f"/ip_addresses/{ip}", api_key)
        cache["ip"][ip] = data
        return data, last_ts
    except (HTTPError, URLError):
        cache["ip"][ip] = None
        return None, last_ts

def vt_get_file(hash_value: str, api_key: str, cache: dict, last_ts: float, min_interval_sec: float = 15.0):
    hv = (hash_value or "").lower().strip()
    if not hv:
        return None, last_ts
    if hv in cache["file"]:
        return cache["file"][hv], last_ts

    last_ts = vt_throttle(last_ts, min_interval_sec)
    try:
        data = vt_http_get(f"/files/{hv}", api_key)
        cache["file"][hv] = data
        return data, last_ts
    except (HTTPError, URLError):
        cache["file"][hv] = None
        return None, last_ts

def vt_summarize_ip(vt_json) -> str:
    try:
        attrs = vt_json.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        rep = attrs.get("reputation", None)
        as_owner = attrs.get("as_owner", "")
        country = attrs.get("country", "")
        return f"mal={stats.get('malicious',0)} susp={stats.get('suspicious',0)} harmless={stats.get('harmless',0)} undet={stats.get('undetected',0)} rep={rep} {country} {as_owner}".strip()
    except Exception:
        return "unparsed"

def vt_summarize_file(vt_json) -> str:
    try:
        attrs = vt_json.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        name = attrs.get("meaningful_name", "") or attrs.get("names", [""])[0]
        ftype = attrs.get("type_description", "")
        return f"mal={stats.get('malicious',0)} susp={stats.get('suspicious',0)} harmless={stats.get('harmless',0)} undet={stats.get('undetected',0)} {ftype} {name}".strip()
    except Exception:
        return "unparsed"
        
def vt_get_mal_susp(vt_json) -> tuple[int, int]:
    """
    Return (malicious, suspicious) from VT v3 JSON.
    If vt_json is None or malformed -> (0, 0)
    """
    try:
        stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal = int(stats.get("malicious", 0) or 0)
        susp = int(stats.get("suspicious", 0) or 0)
        return mal, susp
    except Exception:
        return 0, 0


def print_vt_focus_section(vt_ip_results_focus: dict | None, vt_file_results_focus: dict | None, max_lines: int = 30):
    """
    Print VT enrichment in focus report.
    Prints only items with malicious+suspicious > 0, to avoid noise.
    """
    vt_ip_results_focus = vt_ip_results_focus or {}
    vt_file_results_focus = vt_file_results_focus or {}

    if not vt_ip_results_focus and not vt_file_results_focus:
        return

    print()
    print(f"{GREEN}------------------- VIRUSTOTAL (FOCUS) -------------------{RESET}")
    print()

    # --- IPs ---
    if vt_ip_results_focus:
        hits = []
        for ip, data in vt_ip_results_focus.items():
            mal, susp = vt_get_mal_susp(data) if data else (0, 0)
            if mal + susp > 0:
                hits.append((mal, susp, ip, data))

        if hits:
            hits.sort(reverse=True)  # most malicious first
            print(f"{YELLOW}VT IP hits (mal/susp > 0):{RESET}")
            for mal, susp, ip, data in hits[:max_lines]:
                print(f"   - {ip}: {vt_summarize_ip(data)}")
        else:
            print(f"{YELLOW}VT IP hits:{RESET} none (no malicious/suspicious detections)")

        print()

    # --- Files ---
    if vt_file_results_focus:
        hits = []
        for hv, data in vt_file_results_focus.items():
            mal, susp = vt_get_mal_susp(data) if data else (0, 0)
            if mal + susp > 0:
                hits.append((mal, susp, hv, data))

        if hits:
            hits.sort(reverse=True)
            print(f"{YELLOW}VT file hash hits (mal/susp > 0):{RESET}")
            for mal, susp, hv, data in hits[:max_lines]:
                # hv could be sha256
                print(f"   - {hv}: {vt_summarize_file(data)}")
        else:
            print(f"{YELLOW}VT file hash hits:{RESET} none (no malicious/suspicious detections)")

        print()

    print("------------------------------------------------------------------------")
        

def collect_vt_ips_mode_b(hosts: dict, max_items: int) -> list[str]:
    """
    - external IPs
    - plus server-role candidates (even if internal)
    """
    external = []
    servers = []

    for ip, h in hosts.items():
        if not is_private_ipv4(ip):
            external.append(ip)
        if getattr(h, "server_roles", None):
            if len(h.server_roles) > 0:
                servers.append(ip)

    # dedup preserving priority: external first, then servers
    out = []
    seen = set()
    for ip in external + servers:
        if ip not in seen:
            out.append(ip)
            seen.add(ip)
        if len(out) >= max_items:
            break
    return out
    
def collect_vt_ips_focus(packets, focus_ip: str, max_items: int) -> list[str]:
    peers = []
    seen = set()

    # always include focus
    peers.append(focus_ip)
    seen.add(focus_ip)

    for pkt in packets:
        if IP not in pkt:
            continue
        src = pkt[IP].src
        dst = pkt[IP].dst

        if src == focus_ip:
            other = dst
        elif dst == focus_ip:
            other = src
        else:
            continue

        # in focus mode we mostly care about external peers
        if not is_private_ipv4(other):
            if other not in seen:
                peers.append(other)
                seen.add(other)
                if len(peers) >= max_items:
                    break

    return peers    