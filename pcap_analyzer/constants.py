"""
Global constants used across the PCAP Forensic & Behavioral Analyzer.
"""

# ===============================
# ANSI Colors (CLI Output)
# ===============================

RESET = "\033[0m"
BOLD = "\033[1m"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"


# ===============================
# DNS Analysis
# ===============================

# Known good high-entropy base domains
KNOWN_GOOD_BASE_DOMAINS = {
    # Microsoft / Azure / M365 / Edge / Bing / telemetry
    "microsoft.com",
    "microsoftonline.com",
    "microsoftds.com",
    "windows.net",
    "azureedge.net",
    "msedge.net",
    "bing.com",
    "msn.com",
    "live.com",
    "office.com",
    "office.net",
    "sharepoint.com",
    "trafficmanager.net",

    # Google
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googlesyndication.com",
    "googleusercontent.com",
    "doubleclick.net",

    # Cloud/CDN comuni
    "cloudflare.com",
    "cloudfront.net",
    "akamai.net",
    "akamaihd.net",
    "fastly.net",
    "fastlylb.net",
    "edgekey.net",
    "edgesuite.net",
}


# ===============================
# HTTP / File Analysis
# ===============================

# Content-Type → Expected file extension mapping
CONTENT_TYPE_TO_EXT = {
    # executables
    "application/x-dosexec": {"exe", "dll"},
    "application/x-msdownload": {"exe", "dll"},
    "application/vnd.microsoft.portable-executable": {"exe", "dll"},
    "application/octet-stream": {"exe", "dll", "bin", "dat"},

    # archives
    "application/zip": {"zip"},
    "application/x-zip-compressed": {"zip"},
    "application/x-rar-compressed": {"rar"},
    "application/x-7z-compressed": {"7z"},
    "application/gzip": {"gz"},
    "application/x-tar": {"tar"},
    "application/vnd.ms-cab-compressed": {"cab"},

    # documents
    "application/pdf": {"pdf"},
    "application/msword": {"doc"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {"docx"},
    "application/vnd.ms-excel": {"xls"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {"xlsx"},
    "application/vnd.ms-powerpoint": {"ppt"},
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {"pptx"},

    # web
    "text/html": {"html", "htm"},
    "text/plain": {"txt", "log"},
    "text/css": {"css"},
    "application/javascript": {"js"},
    "text/javascript": {"js"},

    # images
    "image/jpeg": {"jpg", "jpeg"},
    "image/png": {"png"},
    "image/gif": {"gif"},
    "image/webp": {"webp"},
    "image/x-icon": {"ico"},
}

# Potentially dangerous file extensions
DANGEROUS_EXT = {
    "exe", "dll", "msi", "scr", "com", "ps1", "bat", "vbs", "js", "jar", "hta"
}

# Archive extensions
ARCHIVE_EXT = {
    "zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "iso"
}

# Document extensions
DOC_EXT = {
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "odt", "ods"
}


# ===============================
# Focus / Behavioral Scoring
# ===============================

UA_SCORE_WEIGHTS = {
    "high_ua_churn": 2,
    "ua_suspicious_domain": 3,
    "ua_exec_download": 4,
}

import re

_NETBIOS_CANDIDATE_RE = re.compile(r"(?<![A-Z0-9_-])([A-Z0-9][A-Z0-9_-]{2,15})(?![A-Z0-9_-])")
_USER_CANDIDATE_RE = re.compile(r"(?i)\b(user(name)?|login)\b\s*[:=]\s*([a-z0-9_.\\-]{2,64})")
_HOST_TOKEN_RE = re.compile(r"(?i)\b([a-z0-9][a-z0-9\-]{2,31})\b")
_KRB_HOST_DOLLAR_STRICT = re.compile(r"\b(?:DESKTOP|LAPTOP|WIN|PC)-[A-Z0-9\-]{3,30}\$\b", re.IGNORECASE)
