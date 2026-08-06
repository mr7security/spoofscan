"""Plain text console report."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import catalog, checks, scoring
from .models import Finding, Status, sort_findings

_MARK = {"CRITICAL": "[!!]", "HIGH": "[! ]", "MEDIUM": "[~ ]", "LOW": "[. ]", "INFO": "[i ]"}

_TXT = {
    "en": {
        "header": "spoofscan - email spoofing & authentication audit",
        "domain": "Domain", "when": "Checked", "score": "Posture score",
        "coverage": "Checks evaluated", "verdict": "Spoofable",
        "findings": "Findings", "controls": "Control status",
        "none": "No findings: the domain is as hard to spoof as DNS allows.",
        "yes": "YES - a stranger can send mail as this domain",
        "no": "NO - an enforcing DMARC policy is in place",
        "unknown": "UNKNOWN - DMARC could not be resolved",
        "message": "Analysed message",
        "unresolved": "The domain does not resolve: nothing could be assessed.",
        "noscore": "not scored - no check could be evaluated",
        "nonone": "No findings, but no check ran either: absence of evidence, not evidence "
                  "of absence.",
        "legend": "Severity weights: CRITICAL -40, HIGH -20, MEDIUM -10, LOW -4",
    },
    "es": {
        "header": "spoofscan - auditoria de suplantacion y autenticacion de correo",
        "domain": "Dominio", "when": "Comprobado", "score": "Puntuacion",
        "coverage": "Comprobaciones", "verdict": "Suplantable",
        "findings": "Hallazgos", "controls": "Estado de los controles",
        "none": "Sin hallazgos: el dominio es tan dificil de suplantar como permite el DNS.",
        "yes": "SI - un tercero puede enviar correo como este dominio",
        "no": "NO - hay una politica DMARC en aplicacion",
        "unknown": "DESCONOCIDO - no se ha podido resolver DMARC",
        "message": "Mensaje analizado",
        "unresolved": "El dominio no resuelve: no se ha podido evaluar nada.",
        "noscore": "sin nota - no se ha podido evaluar ninguna comprobacion",
        "nonone": "Sin hallazgos, pero tampoco se ha ejecutado ninguna comprobacion: ausencia "
                  "de evidencia, no evidencia de ausencia.",
        "legend": "Pesos: CRITICAL -40, HIGH -20, MEDIUM -10, LOW -4",
    },
}


def render(
    posture: Dict[str, Any],
    findings: List[Finding],
    lang: str = "es",
    message: Optional[Dict[str, Any]] = None,
) -> str:
    t = _TXT.get(lang, _TXT["es"])
    value = scoring.score(findings, posture)
    cov = scoring.coverage(posture)
    verdict = checks.spoofable(posture)

    lines: List[str] = ["=" * 72, t["header"], "=" * 72]
    width = max(len(t[k]) for k in ("domain", "when", "score", "coverage", "verdict"))
    lines.append(f"{t['domain']:<{width}} : {posture.get('domain')}")
    lines.append(f"{t['when']:<{width}} : {posture.get('collected_at')}")
    shown = f"{value}/100  ({scoring.grade(value)})" if value is not None else t["noscore"]
    lines.append(f"{t['score']:<{width}} : {shown}")
    lines.append(f"{t['coverage']:<{width}} : {cov['evaluated']}/{cov['applicable']}")
    verdict_text = t["yes"] if verdict else (t["no"] if verdict is False else t["unknown"])
    lines.append(f"{t['verdict']:<{width}} : {verdict_text}")

    if (posture.get("collection") or {}).get("resolvable") is False:
        lines.append("")
        lines.append("  " + t["unresolved"])

    if message:
        lines.append("")
        lines.append(f"{t['message']}: {message.get('subject', '')[:60]}")
        lines.append(f"  From: {message.get('from_display', '')} <{message.get('from_address', '')}>")
        auth = message.get("auth_results") or {}
        if auth:
            lines.append("  " + "  ".join(f"{k}={v}" for k, v in auth.items()))

    lines.append("")
    counts = scoring.severity_counts(findings)
    summary = "  ".join(f"{k}:{v}" for k, v in counts.items() if v)
    lines.append(f"{t['findings']} ({len(findings)})  {summary}")
    lines.append("-" * 72)
    if not findings:
        lines.append(t["none"] if value is not None else t["nonone"])
    for finding in sort_findings(findings):
        lines.append(f"{_MARK[finding.severity.label]} {finding.id}  {finding.title.get(lang)}")
        lines.append(f"      {catalog.pretty(finding.controls)}")
        if finding.reference:
            lines.append(f"      [{finding.reference}]")
        if finding.short_evidence:
            lines.append(f"      > {finding.short_evidence}")
        lines.append("")

    lines.append(t["controls"])
    lines.append("-" * 72)
    statuses = scoring.control_status(findings, posture, with_message=bool(message))
    for ref in catalog.IN_SCOPE:
        entry = statuses[ref]
        control, state = entry["control"], entry["status"]
        lines.append(f"  {control.ref:<14} {state.text(lang):<12} {control.title.get(lang)}")
    lines.append("")
    lines.append(t["legend"])
    return "\n".join(lines)


def render_summary(results: List[Dict[str, Any]], lang: str = "es") -> str:
    """Comparative table for a multi-domain run."""
    header = ("Dominio", "Nota", "Suplantable", "SPF", "DKIM", "DMARC", "Similares")
    if lang == "en":
        header = ("Domain", "Score", "Spoofable", "SPF", "DKIM", "DMARC", "Lookalikes")
    rows = [header]
    for item in results:
        posture, findings = item["posture"], item["findings"]
        value = scoring.score(findings, posture)
        verdict = checks.spoofable(posture)
        spf = posture.get("spf") or {}
        dkim = posture.get("dkim") or {}
        dmarc = (posture.get("dmarc") or {}).get("parsed") or {}
        lookalike = posture.get("lookalike") or {}
        rows.append((
            str(posture.get("domain")),
            f"{value} ({scoring.grade(value)})" if value is not None else "n/a",
            {True: "SI" if lang == "es" else "YES",
             False: "NO", None: "?"}[verdict],
            "ok" if (spf.get("records") or []) else "-",
            str(len(dkim.get("found") or [])) if dkim.get("determinable") else "?",
            dmarc.get("policy") or "-",
            str(len(lookalike.get("registered") or [])),
        ))
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    out = []
    for index, row in enumerate(rows):
        out.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
        if index == 0:
            out.append("  ".join("-" * w for w in widths))
    return "\n".join(out)
