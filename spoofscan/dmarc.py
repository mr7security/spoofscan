"""DMARC record parsing (RFC 7489), as pure functions."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

VALID_POLICIES = ("none", "quarantine", "reject")


@dataclass
class DMARCRecord:
    raw: str
    tags: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def policy(self) -> Optional[str]:
        value = self.tags.get("p")
        return value.lower() if value else None

    @property
    def subdomain_policy(self) -> Optional[str]:
        value = self.tags.get("sp")
        return value.lower() if value else None

    @property
    def effective_subdomain_policy(self) -> Optional[str]:
        return self.subdomain_policy or self.policy

    @property
    def percentage(self) -> int:
        try:
            return int(self.tags.get("pct", "100"))
        except ValueError:
            return 100

    @property
    def aggregate_reports(self) -> List[str]:
        return _addresses(self.tags.get("rua", ""))

    @property
    def forensic_reports(self) -> List[str]:
        return _addresses(self.tags.get("ruf", ""))

    @property
    def spf_alignment(self) -> str:
        return (self.tags.get("aspf") or "r").lower()

    @property
    def dkim_alignment(self) -> str:
        return (self.tags.get("adkim") or "r").lower()

    @property
    def enforcing(self) -> bool:
        return self.policy in ("quarantine", "reject") and self.percentage == 100


def _addresses(value: str) -> List[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def is_dmarc(txt: str) -> bool:
    return txt.strip().lower().startswith("v=dmarc1")


def parse(raw: str) -> DMARCRecord:
    record = DMARCRecord(raw=raw.strip())
    parts = [p.strip() for p in record.raw.split(";") if p.strip()]
    if not parts or parts[0].replace(" ", "").lower() != "v=dmarc1":
        record.errors.append("record does not start with v=DMARC1")
        return record
    for part in parts[1:]:
        name, _, value = part.partition("=")
        name = name.strip().lower()
        if not name:
            continue
        record.tags[name] = value.strip()
    if "p" not in record.tags:
        record.errors.append("mandatory tag p= is missing")
    elif record.policy not in VALID_POLICIES:
        record.errors.append(f"invalid policy p={record.tags['p']}")
    if "pct" in record.tags:
        try:
            pct = int(record.tags["pct"])
            if not 0 <= pct <= 100:
                record.errors.append("pct outside 0-100")
        except ValueError:
            record.errors.append("pct is not a number")
    return record


def find_records(txts: List[str]) -> List[str]:
    return [txt for txt in txts if is_dmarc(txt)]


def external_report_domains(record: DMARCRecord, domain: str) -> List[str]:
    """Report destinations outside the audited domain.

    RFC 7489 section 7.1 requires those third parties to publish an
    authorisation record, and a missing one silently drops the reports.
    """
    out: List[str] = []
    for address in record.aggregate_reports + record.forensic_reports:
        target = address.split("!", 1)[0]
        if target.lower().startswith("mailto:"):
            target = target[7:]
        _, _, host = target.partition("@")
        host = host.lower().rstrip(".")
        if host and host != domain.lower() and not host.endswith("." + domain.lower()):
            out.append(host)
    return sorted(set(out))
