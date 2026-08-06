"""Posture score, spoofability verdict and per-control compliance status."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import catalog, checks
from .models import Finding, Severity, Status


def score(findings: List[Finding], posture: Optional[Dict[str, Any]] = None) -> Optional[int]:
    """Start from 100 and subtract the weight of every finding, floored at 0.

    Deliberately absolute rather than normalised, as in webscan: the rules here
    preclude each other in ways that make any denominator misleading (a domain
    with no SPF record can never also fail the SPF syntax rules), and an
    absolute scale reads the way the reader expects — no DMARC costs 40 points,
    every time, on every domain.

    Returns ``None`` when nothing could be evaluated. A domain whose DNS never
    answered produces no findings, and reporting that as 100/A would be the most
    misleading number this tool could print.
    """
    if posture is not None and not evaluable_rules(posture):
        return None
    return max(0, 100 - sum(f.severity.weight for f in findings))


def grade(value: Optional[int]) -> str:
    if value is None:
        return "n/a"
    if value >= 90:
        return "A"
    if value >= 75:
        return "B"
    if value >= 60:
        return "C"
    if value >= 40:
        return "D"
    return "E"


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts = {s.label: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.label] += 1
    return counts


def evaluable_rules(posture: Dict[str, Any]) -> set:
    """Rules whose input data could actually be resolved for this domain."""
    posture = posture or {}

    def section(name: str) -> Dict[str, Any]:
        value = posture.get(name)
        return value if isinstance(value, dict) else {}

    spf, dkim = section("spf"), section("dkim")
    dmarc, mx = section("dmarc"), section("mx")
    dnssec, mta_sts = section("dnssec"), section("mta_sts")
    tls_rpt, dane = section("tls_rpt"), section("dane")
    lookalike = section("lookalike")
    # Mirrors checks.check_transport: no MX means the A record receives mail.
    resolvable = (posture.get("collection") or {}).get("resolvable")
    has_mail = not mx.get("null_mx") and (bool(mx.get("records")) or resolvable is True)

    ready = {
        "SPF-01": spf.get("determinable") is True,
        "SPF-02": spf.get("determinable") is True,
        "SPF-03": spf.get("determinable") is True,
        "SPF-04": spf.get("determinable") is True,
        "SPF-05": spf.get("lookups") is not None,
        "SPF-06": spf.get("parsed") is not None,
        "SPF-07": spf.get("unresolved_includes") is not None,
        "DKI-01": dkim.get("determinable") is True,
        "DKI-02": bool(dkim.get("found")),
        "DKI-03": bool(dkim.get("found")),
        "DKI-04": bool(dkim.get("found")),
        "DMA-01": dmarc.get("determinable") is True,
        "DMA-02": dmarc.get("determinable") is True,
        "DMA-03": dmarc.get("determinable") is True,
        "DMA-04": dmarc.get("parsed") is not None,
        "DMA-05": dmarc.get("parsed") is not None,
        "DMA-06": dmarc.get("determinable") is True,
        "DMA-07": dmarc.get("parsed") is not None,
        "DMA-08": bool(dmarc.get("external_reports")),
        "TRA-01": mta_sts.get("determinable") is True and has_mail,
        "TRA-02": mta_sts.get("determinable") is True and has_mail,
        "TRA-03": tls_rpt.get("determinable") is True and has_mail,
        "TRA-04": dnssec.get("determinable") is True and dnssec.get("ds") is not None,
        "TRA-05": dane.get("determinable") is True and has_mail,
        "TRA-06": mta_sts.get("determinable") is True and bool(mta_sts.get("record")),
        "MX-01": mx.get("determinable") is True,
        "LKA-01": lookalike.get("determinable") is True,
        "LKA-02": lookalike.get("determinable") is True,
    }
    return {rule for rule, ok in ready.items() if ok}


def coverage(posture: Dict[str, Any]) -> Dict[str, int]:
    return {
        "evaluated": len(evaluable_rules(posture)),
        "applicable": len(checks.DOMAIN_RULES),
    }


def assessed_controls(posture: Dict[str, Any], with_message: bool = False) -> set:
    refs = set()
    for rule in evaluable_rules(posture):
        refs.update(checks.RULE_CONTROLS[rule])
    if with_message:
        for rule in checks.MESSAGE_RULES:
            refs.update(checks.RULE_CONTROLS[rule])
    return refs


def control_status(
    findings: List[Finding],
    posture: Optional[Dict[str, Any]] = None,
    with_message: bool = False,
) -> Dict[str, Dict]:
    """Compliance status per control, conservative by design.

    A control is only COMPLIANT when a rule covering it could actually run and
    raised nothing. Everything else is NOT ASSESSED: claiming compliance for a
    check that never executed would be the one error an auditor cannot forgive.
    """
    posture = posture or {}
    covered = assessed_controls(posture, with_message)
    resolvable = (posture.get("collection") or {}).get("resolvable")

    result: Dict[str, Dict] = {}
    for ref in catalog.IN_SCOPE:
        initial = (
            Status.COMPLIANT
            if (ref in covered and resolvable is not False)
            else Status.NOT_ASSESSED
        )
        result[ref] = {"control": catalog.get(ref), "status": initial, "findings": []}

    for finding in findings:
        for ref in finding.controls:
            if ref not in result:
                continue
            entry = result[ref]
            entry["findings"].append(finding)
            if finding.severity is Severity.INFO:
                if entry["status"] is Status.COMPLIANT:
                    entry["status"] = Status.NOT_ASSESSED
            elif finding.severity in (Severity.CRITICAL, Severity.HIGH):
                entry["status"] = Status.NON_COMPLIANT
            elif entry["status"] is not Status.NON_COMPLIANT:
                entry["status"] = Status.PARTIAL
    return result


def exit_code(findings: List[Finding]) -> int:
    """0 clean or minor, 2 at least one HIGH/CRITICAL. Useful as a CI gate."""
    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
        return 2
    return 0
