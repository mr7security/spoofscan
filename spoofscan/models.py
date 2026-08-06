"""Core data types: bilingual text, severities, control references and findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """Finding severity. ``weight`` is the score penalty applied by scoring.py."""

    CRITICAL = ("CRITICAL", 40, "#b3202e")
    HIGH = ("HIGH", 20, "#d9531e")
    MEDIUM = ("MEDIUM", 10, "#d9a21e")
    LOW = ("LOW", 4, "#3f7fb5")
    INFO = ("INFO", 0, "#6b7280")

    def __init__(self, label: str, weight: int, colour: str) -> None:
        self.label = label
        self.weight = weight
        self.colour = colour

    @property
    def order(self) -> int:
        return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(self.label)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.label


class Status(Enum):
    """Compliance status of a control in the Statement of Applicability."""

    COMPLIANT = ("COMPLIANT", "CUMPLE")
    PARTIAL = ("PARTIAL", "PARCIAL")
    NON_COMPLIANT = ("NON_COMPLIANT", "NO CUMPLE")
    NOT_ASSESSED = ("NOT_ASSESSED", "NO EVALUADO")

    def __init__(self, en: str, es: str) -> None:
        self.en = en
        self.es = es

    def text(self, lang: str = "en") -> str:
        return self.es if lang == "es" else self.en


@dataclass(frozen=True)
class T:
    """A short piece of bilingual text (English / Spanish)."""

    en: str
    es: str

    def get(self, lang: str = "en") -> str:
        return self.es if lang == "es" else self.en

    def as_dict(self) -> Dict[str, str]:
        return {"en": self.en, "es": self.es}


@dataclass(frozen=True)
class Control:
    """A single control of a compliance framework."""

    framework: str          # "ENS" or "ISO"
    code: str               # "op.exp.8" / "8.15"
    title: T
    family: T

    @property
    def ref(self) -> str:
        return f"{self.framework} {self.code}"

    def as_dict(self, lang: str = "en") -> Dict[str, str]:
        return {
            "framework": self.framework,
            "code": self.code,
            "title": self.title.get(lang),
            "family": self.family.get(lang),
        }


@dataclass
class Finding:
    """A single audit finding, always tied to at least one control."""

    id: str
    severity: Severity
    title: T
    detail: T
    recommendation: T
    controls: List[str] = field(default_factory=list)   # control refs, e.g. "ENS:op.exp.8"
    evidence: Optional[str] = None
    #: The normative text the finding leans on: an RFC section or an ENS
    #: requirement, so the report can be defended, e.g. "RFC 7489 §6.3".
    reference: Optional[str] = None

    @property
    def short_evidence(self) -> Optional[str]:
        """One-line, length-capped evidence suitable for a report cell."""
        if not self.evidence:
            return None
        flat = " ".join(str(self.evidence).split())
        return flat if len(flat) <= 160 else flat[:157] + "..."

    def as_dict(self, lang: str = "en") -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity.label,
            "title": self.title.get(lang),
            "detail": self.detail.get(lang),
            "recommendation": self.recommendation.get(lang),
            "controls": list(self.controls),
            "reference": self.reference,
            "evidence": self.evidence,
        }


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Most severe first, then by identifier for a stable report order."""
    return sorted(findings, key=lambda f: (f.severity.order, f.id))
