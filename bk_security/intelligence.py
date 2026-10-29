from __future__ import annotations
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Any

@dataclass(slots=True)
class ThreatIntelMatch:
    indicator: str
    indicator_type: str
    matched: bool
    confidence: float = 0.0
    source: str = "local"
    tags: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

class ThreatIntelEngine:
    """Offline-first IOC matcher. External feeds can be plugged in later."""
    def __init__(self) -> None:
        self.ip_iocs: dict[str, ThreatIntelMatch] = {}
        self.domain_iocs: dict[str, ThreatIntelMatch] = {}
        self._networks: list[tuple[Any, ThreatIntelMatch]] = []

    def add_ip(self, value: str, *, confidence: float = .95, tags: list[str] | None = None, source: str = "local") -> None:
        match = ThreatIntelMatch(value, "ip", True, confidence, source, tags or [])
        self.ip_iocs[value] = match
        try: self._networks.append((ip_network(value, strict=False), match))
        except ValueError: pass

    def add_domain(self, value: str, *, confidence: float = .9, tags: list[str] | None = None, source: str = "local") -> None:
        self.domain_iocs[value.lower().rstrip(".")] = ThreatIntelMatch(value, "domain", True, confidence, source, tags or [])

    def lookup_ip(self, value: str | None) -> ThreatIntelMatch | None:
        if not value: return None
        if value in self.ip_iocs: return self.ip_iocs[value]
        try: addr = ip_address(value)
        except ValueError: return None
        for network, match in self._networks:
            if addr in network: return match
        return None

    def lookup_domain(self, value: str | None) -> ThreatIntelMatch | None:
        if not value: return None
        domain = value.lower().rstrip(".")
        return self.domain_iocs.get(domain) or next((m for d,m in self.domain_iocs.items() if domain.endswith("." + d)), None)

    def enrich_event(self, event) -> dict[str, Any]:
        dst = event.network.get("dst_ip") or event.data.get("dst_ip")
        domain = event.network.get("domain") or event.data.get("domain")
        match = self.lookup_ip(dst) or self.lookup_domain(domain)
        if not match: return {}
        return {"matched": True, "indicator": match.indicator, "indicator_type": match.indicator_type,
                "confidence": match.confidence, "source": match.source, "tags": match.tags}
