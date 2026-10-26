"""Portable, deterministic report model. No secrets should be stored in evidence."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from . import __version__


@dataclass
class Finding:
    id: str
    category: str
    title: str
    status: str  # PASS, WARN, FAIL, INFO, UNKNOWN
    severity: str  # critical, high, medium, low, info
    summary: str
    evidence: str = ""
    recommendation: str = ""
    action_id: str | None = None
    reference: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    profile: str
    inventory: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    created_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = __version__
    cancelled: bool = False
    completed_utc: str = ""
    probe_errors: list[str] = field(default_factory=list)
    incomplete: bool = False

    def counts(self) -> dict[str, int]:
        return {s: sum(x.status == s for x in self.findings)
                for s in ("FAIL", "WARN", "PASS", "INFO", "UNKNOWN")}

    def as_dict(self) -> dict[str, Any]:
        return {"app": "LinFo", "version": self.version, "created_utc": self.created_utc,
                "profile": self.profile, "inventory": self.inventory,
                "counts": self.counts(), "findings": [x.as_dict() for x in self.findings],
                "cancelled": self.cancelled, "completed_utc": self.completed_utc,
                "probe_errors": self.probe_errors, "incomplete": self.incomplete}
