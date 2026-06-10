from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, s: str) -> "Severity":
        return cls[s.strip().upper()]

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class Target:
    """Normalized snapshot of an agent stack's security-relevant config.
    `recognized` distinguishes a clean target (scanned, no findings) from a
    typo'd/empty path (nothing to scan)."""
    root: Path
    recognized: bool = False
    claude_md: str | None = None
    settings: dict[str, Any] = field(default_factory=dict)
    mcp_servers: list[dict[str, Any]] = field(default_factory=list)
    hooks: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass
class Hit:
    """Richer return type a check MAY emit instead of a bare location string.
    `severity` (if set) overrides the rule's severity for this finding — this is
    what lets one rule (e.g. the active corpus) fan out to findings of differing
    severity. `detail` is appended to the rule's rationale."""
    location: str
    severity: "Severity | None" = None
    detail: str | None = None


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: Severity
    category: str
    location: str
    rationale: str
    remediation: str
    maps_to: list[str] = field(default_factory=list)  # EMPTY in OSS; paid attestation fills it

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = str(self.severity)
        return d
