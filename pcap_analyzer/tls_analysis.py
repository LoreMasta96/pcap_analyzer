"""
TLS / JA3 analysis helpers.

Best-effort extraction: not all PCAPs contain visible TLS handshakes.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, Tuple

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

try:
    from scapy.layers.tls.all import *  
    HAVE_TLS = True
except Exception:
    HAVE_TLS = False



def _build_ja3_string(client_hello):
    """
    Costruisce la stringa JA3:
    version,ciphers,extensions,elliptic_curves,ec_point_formats

    Nota: i nomi degli attributi possono variare leggermente tra versioni di Scapy.
    Se qualcosa non va, fai `client_hello.show()` su un pcap e adatta i campi.
    """

    # --- versione TLS ---
    # in Scapy spesso è una int (es. 0x0303), JA3 vuole il valore decimale (771)
    version = getattr(client_hello, "version", None)
    if version is None:
        ja3_version = ""
    else:
        try:
            ja3_version = str(int(version))
        except Exception:
            # se è tipo b"\x03\x03"
            try:
                ja3_version = str(int.from_bytes(version, "big"))
            except Exception:
                ja3_version = ""

    # --- cipher suites ---
    ciphers = []
    cipher_attr = getattr(client_hello, "ciphers", None) or getattr(client_hello, "cipher_suites", None)
    if cipher_attr is not None:
        for c in cipher_attr:
            try:
                ciphers.append(str(int(c)))
            except Exception:
                # fallback: prova ad usare .val o .id se esistono
                val = getattr(c, "val", None)
                if val is None:
                    val = getattr(c, "id", None)
                if val is not None:
                    ciphers.append(str(int(val)))
    ja3_ciphers = "-".join(ciphers)

    # --- estensioni, elliptic curves, ec point formats ---
    ext_ids = []
    elliptic_curves = []
    ec_point_formats = []

    exts = getattr(client_hello, "ext", []) or getattr(client_hello, "extensions", [])
    for ext in exts:
        # ID estensione
        etype = getattr(ext, "type", None)
        if etype is None:
            etype = getattr(ext, "ext_type", None)
        if etype is not None:
            try:
                ext_ids.append(str(int(etype)))
            except Exception:
                pass

        # elliptic curves (Supported Groups)
        # spesso c'è attributo .groups o .elliptic_curves
        groups = getattr(ext, "groups", None) or getattr(ext, "elliptic_curves", None)
        if groups is not None:
            for g in groups:
                try:
                    elliptic_curves.append(str(int(g)))
                except Exception:
                    val = getattr(g, "val", None)
                    if val is not None:
                        elliptic_curves.append(str(int(val)))

        # EC point formats
        pfmts = getattr(ext, "ec_point_formats", None) or getattr(ext, "point_formats", None)
        if pfmts is not None:
            for pf in pfmts:
                try:
                    ec_point_formats.append(str(int(pf)))
                except Exception:
                    val = getattr(pf, "val", None)
                    if val is not None:
                        ec_point_formats.append(str(int(val)))

    ja3_ext = "-".join(ext_ids)
    ja3_curves = "-".join(elliptic_curves)
    ja3_pf = "-".join(ec_point_formats)

    ja3_str = ",".join([ja3_version, ja3_ciphers, ja3_ext, ja3_curves, ja3_pf])
    return ja3_str
    
def extract_ja3_from_packet(pkt):
    """
    Usa la stessa logica di compute_ja3_stats, ma su UN solo pacchetto.
    Ritorna (ja3_hash, ja3_str) oppure None se non è un TLS ClientHello.
    """
    if not HAVE_TLS or TLSClientHello is None:
        return None

    if TLSClientHello not in pkt:
        return None

    ch = pkt[TLSClientHello]
    try:
        ja3_str = _build_ja3_string(ch)
        if not ja3_str:
            return None
        ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
        return (ja3_hash, ja3_str)
    except Exception:
        return None  

def extract_sni_from_packet(pkt):
    """
    Ritorna SNI (hostname) se il pacchetto contiene un TLS ClientHello con estensione server_name.
    Altrimenti None.
    """
    if not HAVE_TLS or TLSClientHello is None:
        return None
    if TLSClientHello not in pkt:
        return None

    ch = pkt[TLSClientHello]

    # Scapy: le estensioni possono stare in .ext o .extensions
    exts = getattr(ch, "ext", None) or getattr(ch, "extensions", None) or []
    if not exts:
        return None

    for ext in exts:
        # Cerchiamo l'estensione "server_name"
        etype = getattr(ext, "type", None)
        if etype is None:
            etype = getattr(ext, "ext_type", None)

        # In alcune versioni Scapy: type può essere string/enum oppure numero.
        # 0 è "server_name" (SNI)
        is_sni = False
        try:
            if int(etype) == 0:
                is_sni = True
        except Exception:
            # fallback: prova a matchare stringa
            if str(etype).lower() in ("server_name", "servername", "sni"):
                is_sni = True

        if not is_sni:
            continue

        # Ora estraiamo i nomi. I campi variano tra versioni:
        # tipici: .servernames, .server_names, .names
        candidates = (
            getattr(ext, "servernames", None)
            or getattr(ext, "server_names", None)
            or getattr(ext, "names", None)
        )

        if not candidates:
            # ultimo fallback: prova un campo singolo tipo .servername
            one = getattr(ext, "servername", None)
            if one:
                candidates = [one]

        if not candidates:
            return None

        # candidates può contenere oggetti con .servername/.name oppure bytes/str
        for item in candidates:
            name = (
                getattr(item, "servername", None)
                or getattr(item, "name", None)
                or item
            )
            if isinstance(name, bytes):
                sni = name.decode(errors="ignore").strip()
            else:
                sni = str(name or "").strip()

            # pulizia base
            sni = sni.rstrip(".")
            if sni:
                return sni

    return None
        
 
def compute_ja3_stats(packets):
    """
    Estrae JA3 dalle ClientHello TLS e ritorna i top fingerprint.

    Ritorna: lista di tuple [ ((ja3_hash, ja3_str), count), ... ]
    """
    if not HAVE_TLS or TLSClientHello is None:
        return []

    ja3_counts = defaultdict(int)

    for pkt in packets:
        if TLSClientHello in pkt:
            ch = pkt[TLSClientHello]
            try:
                ja3_str = _build_ja3_string(ch)
                if not ja3_str:
                    continue
                ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
                ja3_counts[(ja3_hash, ja3_str)] += 1
            except Exception:
                # se qualche ClientHello è malformato, lo saltiamo
                continue

    top_ja3 = sorted(ja3_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    return top_ja3
