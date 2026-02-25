"""
Generic utility helpers used across the PCAP Forensic & Behavioral Analyzer.
"""

from __future__ import annotations
from typing import Iterable


import re
import math
import base64
import struct
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple

from scapy.packet import Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP

try:
    from scapy.layers.dhcp import DHCP, BOOTP
    HAVE_DHCP = True
except Exception:
    HAVE_DHCP = False

try:
    from scapy.layers.dns import DNS
    HAVE_DNS = True
except Exception:
    HAVE_DNS = False

try:
    from scapy.layers.http import HTTPRequest
    HAVE_HTTP = True
except Exception:
    HAVE_HTTP = False
    
from pcap_analyzer.constants import KNOWN_GOOD_BASE_DOMAINS    



# ===============================
# IP helpers
# ===============================

def is_private_ipv4(ip: str) -> bool:
    # semplice RFC1918 + loopback/link-local
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4: 
            return False
        a,b,c,d = parts
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
        if a == 169 and b == 254:
            return True
        return False
    except Exception:
        return False


# ===============================
# TTL / OS hint helpers
# ===============================

def ttl_mode(ttls: list) -> Optional[int]:
    if not ttls:
        return None
    # mode robusto con Counter
    cnt = Counter(ttls)
    return cnt.most_common(1)[0][0]

def os_hint_from_ttl(ttl_m: Optional[int]) -> tuple[str, float]:
    if ttl_m is None:
        return ("unknown", 0.0)
    # confidenze volutamente basse (TTL non è prova)
    if 50 <= ttl_m <= 70:
        return ("unix-like (ttl≈64)", 0.4)
    if 115 <= ttl_m <= 140:
        return ("windows-like (ttl≈128)", 0.4)
    if 240 <= ttl_m <= 255:
        return ("network device (ttl≈255)", 0.3)
    return ("unknown", 0.1)


# ===============================
# DNS helpers
# ===============================

_DOMAIN_RE = re.compile(r"(?i)^[a-z0-9][a-z0-9\-\.]{0,252}[a-z0-9]$")


def get_base_domain_best_effort(domain: str) -> str:
    """
    Best-effort base domain without public suffix list.
    For most common cases: take last 2 labels.
    Handles some common 2-level TLDs (co.uk, com.au, etc.) minimally.
    """
    d = (domain or "").strip().lower().strip(".")
    if not d:
        return ""
    parts = [p for p in d.split(".") if p]
    if len(parts) < 2:
        return d

    two_level_suffixes = {
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "com.au", "net.au", "org.au",
        "co.jp", "ne.jp", "or.jp",
        "com.br", "com.mx",
        "co.in", "com.sg",
    }
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in two_level_suffixes and len(parts) >= 3:
        # e.g. x.y.co.uk -> y.co.uk
        return ".".join(parts[-3:])
    if last3 in two_level_suffixes and len(parts) >= 4:
        return ".".join(parts[-4:])
    return last2


def _shannon_entropy(s):
    """
    Entropia di Shannon di una stringa s.
    Utile per trovare label "random-like" (DGA / tunneling).
    """
    if not s:
        return 0.0
    # consideriamo direttamente i byte/char
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    length = len(s)
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def classify_high_entropy_domain(domain: str) -> str:
    """
    Returns:
      - "known_good" if base domain is in allowlist
      - "unknown" otherwise
    """
    base = get_base_domain_best_effort(domain)
    if base in KNOWN_GOOD_BASE_DOMAINS:
        return "known_good"
    return "unknown"


# ===============================
# HTTP / file helpers
# ===============================

def normalize_content_type(ct: str) -> str:
    if not ct:
        return ""
    ct = ct.strip().lower()
    return ct.split(";", 1)[0].strip()


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


# ===============================
# Strings extraction (binary blobs)
# ===============================

def extract_ascii_strings(raw: bytes, min_len: int = 4):
    out = []
    cur = bytearray()
    for b in raw:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="ignore"))
    return out


def extract_utf16le_strings(raw: bytes, min_len: int = 4):
    # prende solo sequenze UTF-16LE stampabili (byte basso ASCII + byte alto 0x00)
    out = []
    cur = []
    i = 0
    while i + 1 < len(raw):
        lo = raw[i]
        hi = raw[i+1]
        if hi == 0x00 and 32 <= lo <= 126:
            cur.append(lo)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii", errors="ignore"))
            cur = []
        i += 2
    if len(cur) >= min_len:
        out.append(bytes(cur).decode("ascii", errors="ignore"))
    return out   
    
def extract_netbios_candidates(pkt) -> set:
    """
    Best-effort:
    - se UDP 137 (NBNS) prova a estrarre token ASCII plausibili.
    Non è un parser NBNS completo, ma funziona bene per “vedere nomi”.
    """
    out = set()
    if UDP not in pkt:
        return out
    udp = pkt[UDP]
    if udp.sport != 137 and udp.dport != 137:
        return out
    try:
        raw = bytes(udp.payload)
        if not raw:
            return out
        s = raw.decode("ascii", errors="ignore")
        for m in _NETBIOS_CANDIDATE_RE.finditer(s.upper()):
            name = m.group(1).strip("-_")
            if 3 <= len(name) <= 15:
                # evita rumore troppo comune
                if name not in {"WORKGROUP", "MSHOME", "NETBIOS"}:
                    out.add(name)
    except Exception:
        pass
    return out

_USER_CANDIDATE_RE = re.compile(r"(?i)\b(user(name)?|login)\b\s*[:=]\s*([a-z0-9_.\\-]{2,64})")


def extract_username_candidates(pkt) -> set:
    """
    Best-effort:
    - cerca pattern user=, username:, login= in payload TCP/UDP.
    - non sostituisce parsing NTLM/Kerberos/SMB (che è più affidabile).
    """
    out = set()
    try:
        # prova a estrarre un payload “grezzo”
        raw = b""
        if TCP in pkt:
            raw = bytes(pkt[TCP].payload)
        elif UDP in pkt:
            raw = bytes(pkt[UDP].payload)
        if not raw:
            return out
        s = raw.decode("utf-8", errors="ignore")
        for m in _USER_CANDIDATE_RE.finditer(s):
            cand = m.group(3)
            if cand:
                out.add(cand)
        # Basic auth quick check
        if "authorization: basic" in s.lower():
            out.add("<http_basic_auth_present>")
        # NTLM signature quick check
        if "NTLMSSP" in s:
            out.add("<ntlm_present>")
    except Exception:
        pass
    return out


def parse_ntlm_type3_user(raw: bytes) -> list[tuple[str, str, str]]:
    """
    Cerca NTLMSSP Type 3 dentro raw (bytes).
    Ritorna lista di tuple (domain, user, workstation).
    """
    out = []
    sig = b"NTLMSSP\x00"
    start = 0

    while True:
        idx = raw.find(sig, start)
        if idx == -1:
            break
        # almeno fino ai campi minimi
        if idx + 64 > len(raw):
            break

        msg_type = int.from_bytes(raw[idx+8:idx+12], "little")
        if msg_type != 3:
            start = idx + 1
            continue

        # Offsets NTLM Type 3:
        # 12 LMResp, 20 NTResp, 28 Domain, 36 User, 44 Workstation, 52 SessionKey, 60 Flags
        dom_len, dom_off = _read_sec_buf(raw, idx + 28)
        usr_len, usr_off = _read_sec_buf(raw, idx + 36)
        wk_len,  wk_off  = _read_sec_buf(raw, idx + 44)

        dom_b = _safe_slice(raw, idx + dom_off, dom_len)
        usr_b = _safe_slice(raw, idx + usr_off, usr_len)
        wk_b  = _safe_slice(raw, idx + wk_off,  wk_len)

        def dec(b: bytes) -> str:
            if not b:
                return ""
            # quasi sempre UTF-16LE
            try:
                s = b.decode("utf-16le", errors="ignore").strip("\x00").strip()
                if s:
                    return s
            except Exception:
                pass
            # fallback ascii
            return b.decode("ascii", errors="ignore").strip("\x00").strip()

        dom = dec(dom_b)
        usr = dec(usr_b)
        wk  = dec(wk_b)

        if usr:
            out.append((dom, usr, wk))

        start = idx + 1

    return out


def extract_ntlm_usernames(pkt) -> set[str]:
    """
    Estrae username NTLM Type3 da:
    - payload TCP/UDP raw
    - header HTTP Authorization: NTLM <base64> (se presente con scapy HTTPRequest)
    """
    out = set()

    # 1) raw payload (SMB ecc.)
    raw = b""
    if TCP in pkt:
        raw = bytes(pkt[TCP].payload)
    elif UDP in pkt:
        raw = bytes(pkt[UDP].payload)

    if raw:
        for dom, usr, wk in parse_ntlm_type3_user(raw):
            # formato forense: DOMAIN\user se dominio presente
            out.add(f"{dom}\\{usr}" if dom else usr)

    # 2) HTTP Authorization: NTLM base64 (se scapy HTTP è attivo)
    if HAVE_HTTP and HTTPRequest in pkt:
        req = pkt[HTTPRequest]
        auth = getattr(req, "Authorization", b"")
        if isinstance(auth, bytes):
            auth_s = auth.decode(errors="ignore")
        else:
            auth_s = str(auth or "")
        auth_s = auth_s.strip()
        if auth_s.lower().startswith("ntlm "):
            b64 = auth_s[5:].strip()
            try:
                blob = base64.b64decode(b64, validate=False)
                for dom, usr, wk in parse_ntlm_type3_user(blob):
                    out.add(f"{dom}\\{usr}" if dom else usr)
            except Exception:
                pass

    return out
    

def extract_ascii_strings(raw: bytes, min_len: int = 4):
    out = []
    cur = bytearray()
    for b in raw:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="ignore"))
    return out

def extract_utf16le_strings(raw: bytes, min_len: int = 4):
    # prende solo sequenze UTF-16LE stampabili (byte basso ASCII + byte alto 0x00)
    out = []
    cur = []
    i = 0
    while i + 1 < len(raw):
        lo = raw[i]
        hi = raw[i+1]
        if hi == 0x00 and 32 <= lo <= 126:
            cur.append(lo)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii", errors="ignore"))
            cur = []
        i += 2
    if len(cur) >= min_len:
        out.append(bytes(cur).decode("ascii", errors="ignore"))
    return out   

def _decode_nbns_name_32(enc32: bytes) -> str:
    """
    NBNS name encoding (RFC1002): 32 bytes ASCII 'A'..'P' -> 16 bytes name.
    """
    if len(enc32) < 32:
        return ""
    out = bytearray()
    for i in range(0, 32, 2):
        c1 = enc32[i] - 0x41
        c2 = enc32[i + 1] - 0x41
        out.append(((c1 & 0x0F) << 4) | (c2 & 0x0F))
    # NB names are padded; strip nulls/spaces
    try:
        s = out.decode("ascii", errors="ignore")
    except Exception:
        s = ""
    return s.rstrip("\x00").strip()
    
def parse_nbstat_names(rdata: bytes) -> list[str]:
    names = []
    if not rdata or len(rdata) < 1:
        return names
    count = rdata[0]
    off = 1
    for _ in range(count):
        if off + 18 > len(rdata):
            break
        name15 = rdata[off:off+15]
        suffix = rdata[off+15]
        # flags = rdata[off+16:off+18]
        off += 18
        base = name15.decode("ascii", errors="ignore").rstrip().strip("\x00").strip()
        if base:
            # NB: puoi includere suffix se vuoi distinguere tipi
            names.append(base)
    return names
    

def parse_nbns_name_ip(pkt) -> list[tuple[str, str]]:
    """
    Parsing NBNS response (UDP/137) per ottenere mapping name -> IPv4.
    Ritorna lista di (name, ip).
    """
    if UDP not in pkt:
        return []
    u = pkt[UDP]
    # NBNS responses typically come from sport 137 (server)
    if u.sport != 137 and u.dport != 137:
        return []

    raw = bytes(u.payload)
    if len(raw) < 12:
        return []

    # Header: TransactionID(2), Flags(2), QD(2), AN(2), NS(2), AR(2)
    flags = struct.unpack(">H", raw[2:4])[0]
    is_response = (flags & 0x8000) != 0
    if not is_response:
        return []

    qdcount, ancount, nscount, arcount = struct.unpack(">HHHH", raw[4:12])
    offset = 12

    # Skip questions
    for _ in range(qdcount):
        # Name (compressed or label form). NBNS often uses 0x20 + 32 bytes, but questions can vary.
        if offset >= len(raw):
            return []
        # If it's a pointer (compression), skip 2 bytes; else walk labels until 0x00
        if raw[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(raw) and raw[offset] != 0:
                lab_len = raw[offset]
                offset += 1 + lab_len
            offset += 1  # null
        offset += 4  # qtype+qclass
        if offset > len(raw):
            return []

    out = []

    def parse_rr(count: int):
        nonlocal offset
        for _ in range(count):
            if offset >= len(raw):
                return
            # Name field: often 0x20 + 32 bytes, or compression pointer
            name = ""
            if raw[offset] & 0xC0 == 0xC0:
                # compressed pointer: skip
                offset += 2
            elif raw[offset] == 0x20 and offset + 1 + 32 <= len(raw):
                offset += 1
                enc = raw[offset:offset + 32]
                offset += 32
                name = _decode_nbns_name_32(enc)
            else:
                # fallback: walk labels
                while offset < len(raw) and raw[offset] != 0:
                    lab_len = raw[offset]
                    offset += 1
                    if offset + lab_len <= len(raw):
                        # NBNS labels often not human; ignore
                        offset += lab_len
                    else:
                        return
                offset += 1

            if offset + 10 > len(raw):
                return
            rr_type, rr_class, rr_ttl, rdlen = struct.unpack(">HHIH", raw[offset:offset + 10])
            offset += 10
            if offset + rdlen > len(raw):
                return

            rdata = raw[offset:offset + rdlen]
            offset += rdlen


            # NB record type is 0x0020; RDATA format: 2 bytes flags + 4 bytes IPv4 (first address)
            if rr_type == 0x0020 and rdlen >= 6:
                ip_b = rdata[2:6]
                ip_s = ".".join(str(b) for b in ip_b)
                if name:
                    out.append((name, ip_s))

    # Parse Answer, Authority, Additional (a volte i record utili finiscono qui)
    parse_rr(ancount)
    parse_rr(nscount)
    parse_rr(arcount)

    return out
    
def parse_nbns_nbstat(pkt) -> list[tuple[str, str]]:
    """
    Estrae nomi NetBIOS da NBSTAT (type 0x0021) e li associa a ip.src.
    """
    if UDP not in pkt or IP not in pkt:
        return []
    u = pkt[UDP]
    if u.sport != 137 and u.dport != 137:
        return []
    raw = bytes(u.payload)
    if len(raw) < 12:
        return []

    flags = struct.unpack(">H", raw[2:4])[0]
    if (flags & 0x8000) == 0:
        return []  # non è response

    qdcount, ancount, nscount, arcount = struct.unpack(">HHHH", raw[4:12])
    offset = 12

    # skip questions
    for _ in range(qdcount):
        if offset >= len(raw):
            return []
        if raw[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(raw) and raw[offset] != 0:
                lab_len = raw[offset]
                offset += 1 + lab_len
            offset += 1
        offset += 4
        if offset > len(raw):
            return []

    def walk_rr(count: int):
        nonlocal offset
        found = []
        for _ in range(count):
            if offset >= len(raw):
                break

            # skip NAME (compressed/pattern)
            if raw[offset] & 0xC0 == 0xC0:
                offset += 2
            elif raw[offset] == 0x20 and offset + 33 <= len(raw):
                offset += 33
            else:
                while offset < len(raw) and raw[offset] != 0:
                    lab_len = raw[offset]
                    offset += 1 + lab_len
                offset += 1

            if offset + 10 > len(raw):
                break
            rr_type, rr_class, rr_ttl, rdlen = struct.unpack(">HHIH", raw[offset:offset+10])
            offset += 10
            if offset + rdlen > len(raw):
                break
            rdata = raw[offset:offset+rdlen]
            offset += rdlen

            if rr_type == 0x0021:  # NBSTAT
                found.extend(parse_nbstat_names(rdata))

        return found

    names = []
    names += walk_rr(ancount)
    names += walk_rr(nscount)
    names += walk_rr(arcount)

    ip_src = pkt[IP].src
    return [(n, ip_src) for n in names]    

def parse_dhcp_identity(pkt) -> tuple[str | None, str | None]:
    """
    Ritorna (hostname, vendor_class_id) se presente.
    """
    if DHCP not in pkt:
        return (None, None)

    hostname = None
    vendor = None

    try:
        for opt in pkt[DHCP].options:
            if not isinstance(opt, tuple) or len(opt) < 2:
                continue
            k, v = opt[0], opt[1]
            if k == "hostname":
                if isinstance(v, bytes):
                    hostname = v.decode(errors="ignore").strip()
                else:
                    hostname = str(v).strip()
            elif k == "vendor_class_id":
                if isinstance(v, bytes):
                    vendor = v.decode(errors="ignore").strip()
                else:
                    vendor = str(v).strip()
    except Exception:
        pass

    return (hostname or None, vendor or None)

_HOST_TOKEN_RE = re.compile(r"(?i)\b([a-z0-9][a-z0-9\-]{2,31})\b")

def dhcp_client_mac_from_chaddr(chaddr) -> str | None:
    """
    Scapy può dare chaddr in formati diversi.
    Qui normalizziamo a 'aa:bb:cc:dd:ee:ff' prendendo i primi 6 byte.
    """
    try:
        if chaddr is None:
            return None
        if isinstance(chaddr, bytes):
            b = chaddr[:6]
        else:
            # a volte è stringa/bytearray
            b = bytes(chaddr)[:6]
        if len(b) < 6:
            return None
        return ":".join(f"{x:02x}" for x in b)
    except Exception:
        return None


def parse_dhcp_identity_strict(pkt):
    """
    Ritorna dict con:
      - client_mac
      - ip_assigned (yiaddr) se presente
      - ip_client (ciaddr) se presente
      - msg_type (discover/offer/request/ack...)
      - hostname (option 12)
      - vendor (option 60)
    """
    if DHCP not in pkt or BOOTP not in pkt:
        return None

    bootp = pkt[BOOTP]
            
    client_mac = dhcp_client_mac_from_chaddr(getattr(bootp, "chaddr", None))

    ciaddr = getattr(bootp, "ciaddr", None)
    yiaddr = getattr(bootp, "yiaddr", None)

    hostname = None
    vendor = None
    msg_type = None

    try:
        for opt in pkt[DHCP].options:
            if not isinstance(opt, tuple) or len(opt) < 2:
                continue
            k, v = opt[0], opt[1]
            if k == "message-type":
                msg_type = v  # scapy spesso dà int o stringa
            elif k == "hostname":
                hostname = v.decode(errors="ignore").strip() if isinstance(v, bytes) else str(v).strip()
            elif k == "vendor_class_id":
                vendor = v.decode(errors="ignore").strip() if isinstance(v, bytes) else str(v).strip()
    except Exception:
        pass

    return {
        "client_mac": client_mac,
        "ciaddr": ciaddr,
        "yiaddr": yiaddr,
        "msg_type": msg_type,
        "hostname": hostname,
        "vendor": vendor,
    }   

def extract_llmnr_mdns_hostnames(pkt) -> set:
    out = set()
    if UDP not in pkt:
        return out
    u = pkt[UDP]
    if u.sport not in (5353, 5355) and u.dport not in (5353, 5355):
        return out

    try:
        raw = bytes(u.payload)
        if not raw:
            return out

        s = raw.decode("ascii", errors="ignore").lower()

        # 1) Caso mDNS classico: cattura SOLO la label prima di ".local"
        # es: "desktop-5ave44c.local" -> "desktop-5ave44c"
        for m in re.finditer(r"\b([a-z0-9][a-z0-9\-]{2,31})\.local\b", s):
            out.add(m.group(1).strip("-"))

        # 2) Fallback: token generici, ma filtra "local" e simili
        for m in _HOST_TOKEN_RE.finditer(s):
            token = m.group(1).strip().strip("-")
            if not (3 <= len(token) <= 32):
                continue

            # filtri anti-rumore / anti-falsi host
            if token in {"local", "localhost"}:
                continue

            out.add(token)

    except Exception:
        pass

    return out

_KRB_HOST_DOLLAR_STRICT = re.compile(r"\b(?:DESKTOP|LAPTOP|WIN|PC)-[A-Z0-9\-]{3,30}\$\b", re.IGNORECASE)

    
def extract_kerberos_principals_best_effort(pkt, focus_ip: str | None = None) -> set:
    """
    Best-effort ma molto più forense:
    - guarda solo pacchetti verso porta 88 (client -> KDC) per evitare stringhe casuali nelle risposte
    - estrae stringhe ASCII/UTF16LE e applica pattern Windows computer account con '-'
    """
    out = set()

    raw = b""
    src_ip = None
    dst_ip = None

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

    if TCP in pkt:
        t = pkt[TCP]
        if t.dport != 88:
            return out
        raw = bytes(t.payload)
    elif UDP in pkt:
        u = pkt[UDP]
        if u.dport != 88:
            return out
        raw = bytes(u.payload)
    else:
        return out

    # opzionale: se stai calcolando focus, attribuisci i principals solo al focus come client
    if focus_ip is not None and src_ip != focus_ip:
        return out

    if not raw:
        return out

    candidates = []
    candidates += extract_ascii_strings(raw, min_len=5)
    candidates += extract_utf16le_strings(raw, min_len=5)

    for s in candidates:
        m = _KRB_HOST_DOLLAR_STRICT.search(s)
        if m:
            out.add(m.group(0).upper())

    return out
    
def mark_role(host, role: str, reason: str):
    host.server_roles.add(role)
    host.server_evidence[f"{role}:{reason}"] += 1    
    
def _read_sec_buf(raw: bytes, base: int) -> tuple[int, int]:
    """
    NTLM security buffer: 2 bytes len, 2 bytes maxlen, 4 bytes offset (LE)
    ritorna (length, offset)
    """
    if base + 8 > len(raw):
        return (0, 0)
    ln = int.from_bytes(raw[base:base+2], "little")
    off = int.from_bytes(raw[base+4:base+8], "little")
    return (ln, off)

def _safe_slice(raw: bytes, off: int, ln: int) -> bytes:
    if off < 0 or ln <= 0 or off + ln > len(raw):
        return b""
    return raw[off:off+ln]

def parse_ntlm_type3_user(raw: bytes) -> list[tuple[str, str, str]]:
    """
    Cerca NTLMSSP Type 3 dentro raw (bytes).
    Ritorna lista di tuple (domain, user, workstation).
    """
    out = []
    sig = b"NTLMSSP\x00"
    start = 0

    while True:
        idx = raw.find(sig, start)
        if idx == -1:
            break
        # almeno fino ai campi minimi
        if idx + 64 > len(raw):
            break

        msg_type = int.from_bytes(raw[idx+8:idx+12], "little")
        if msg_type != 3:
            start = idx + 1
            continue

        # Offsets NTLM Type 3:
        # 12 LMResp, 20 NTResp, 28 Domain, 36 User, 44 Workstation, 52 SessionKey, 60 Flags
        dom_len, dom_off = _read_sec_buf(raw, idx + 28)
        usr_len, usr_off = _read_sec_buf(raw, idx + 36)
        wk_len,  wk_off  = _read_sec_buf(raw, idx + 44)

        dom_b = _safe_slice(raw, idx + dom_off, dom_len)
        usr_b = _safe_slice(raw, idx + usr_off, usr_len)
        wk_b  = _safe_slice(raw, idx + wk_off,  wk_len)

        def dec(b: bytes) -> str:
            if not b:
                return ""
            # quasi sempre UTF-16LE
            try:
                s = b.decode("utf-16le", errors="ignore").strip("\x00").strip()
                if s:
                    return s
            except Exception:
                pass
            # fallback ascii
            return b.decode("ascii", errors="ignore").strip("\x00").strip()

        dom = dec(dom_b)
        usr = dec(usr_b)
        wk  = dec(wk_b)

        if usr:
            out.append((dom, usr, wk))

        start = idx + 1

    return out    