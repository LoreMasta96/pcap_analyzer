"""
Data models used across the PCAP Forensic & Behavioral Analyzer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from typing import Dict, List, Optional, Set, Any



# ===============================
# Focus Timeline Event
# ===============================

@dataclass
class FocusEvent:
    ts: float
    type: str
    src: str
    dst: str
    details: str


# ===============================
# Host Profile
# ===============================

@dataclass
class HostProfile:
    ip: str

    macs: Set[str] = field(default_factory=set)
    ttl_samples: List[int] = field(default_factory=list)

    first_ts: int | None = None
    last_ts: int | None = None

    netbios_names: Set[str] = field(default_factory=set)
    hostnames: Set[str] = field(default_factory=set)

    dhcp_hostnames: Set[str] = field(default_factory=set)
    dhcp_vendors: Set[str] = field(default_factory=set)

    kerberos_principals: Set[str] = field(default_factory=set)
    username_candidates: Set[str] = field(default_factory=set)

    server_roles: Set[str] = field(default_factory=set)
    server_evidence: dict = field(default_factory=lambda: defaultdict(int))

    user_agents: Set[str] = field(default_factory=set)
    ua_domains: dict = field(default_factory=lambda: defaultdict(set))


    def add_role(self, role: str, reason: str | None = None):
        self.roles.add(role)
        if reason:
            self.evidence.append(f"{role}: {reason}")

    def add_ttl(self, ttl: int):
        self.ttl_values.append(ttl)

    def add_hostname(self, name: str):
        if name:
            self.hostnames.add(name)

    def add_username(self, username: str):
        if username:
            self.usernames.add(username)
            
    def add_netbios_name(self, name: str):
        if name:
            self.netbios_names.add(name)

    def add_kerberos_principal(self, principal: str):
        if principal:
            self.kerberos_principals.add(principal)
        
