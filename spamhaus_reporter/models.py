from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable


@dataclass(frozen=True)
class Event:
    zone: str
    zone_id: str
    host: str
    client_ip: str
    path: str
    query: str
    action: str
    source: str
    user_agent: str
    country: str
    asn: int | None
    observed_at: datetime


@dataclass
class Finding:
    category: str
    matched_paths: list[str] = field(default_factory=list)
    unique_count: int = 0


@dataclass
class Candidate:
    ip: str
    host: str
    zone: str
    first_seen: datetime
    last_seen: datetime
    request_count: int
    unique_paths: list[str]
    findings: list[Finding]
    status: str
    primary_category: str
    confidence: int
    reason: str
    countries: list[str]
    asns: list[int]
    sources: list[str]
    user_agents: list[str]

    @property
    def category_names(self) -> list[str]:
        return [f.category for f in self.findings]


def unique_preserve_order(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            out.append(value)
            seen.add(value)
    return out
