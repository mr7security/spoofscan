"""Audit rules.

Pure functions over the posture produced by :mod:`spoofscan.collector` and over
a message parsed by :mod:`spoofscan.eml`. As in the rest of the suite, ``None``
means *not determinable* and never produces a finding.

The headline question the rule set answers is narrow on purpose: can a stranger
put this domain in the From: of a message and have it delivered? That is what
SPF, DKIM and DMARC decide, and it is decided almost entirely by the DMARC
policy.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .eml import (Message, alignment, display_name_spoof, risky_attachments,
                  suspicious_urls)
from .models import Finding, Severity, T

#: Control coverage per rule.
RULE_CONTROLS: Dict[str, List[str]] = {
    "SPF-01": ["ENS:mp.s.1", "ISO:5.14", "ISO:8.20"],
    "SPF-02": ["ENS:mp.s.1", "ISO:5.14", "ISO:8.20"],
    "SPF-03": ["ENS:mp.s.1", "ISO:5.14"],
    "SPF-04": ["ENS:mp.s.1", "ISO:5.14"],
    "SPF-05": ["ENS:mp.s.1", "ISO:5.14"],
    "SPF-06": ["ENS:mp.s.1", "ISO:5.14"],
    "SPF-07": ["ENS:mp.s.1", "ISO:5.14"],
    "DKI-01": ["ENS:mp.s.1", "ENS:mp.com.3", "ISO:8.24"],
    "DKI-02": ["ENS:mp.com.3", "ISO:8.24"],
    "DKI-03": ["ENS:mp.com.3", "ISO:8.24"],
    "DKI-04": ["ENS:mp.com.3", "ISO:8.24"],
    "DMA-01": ["ENS:mp.s.1", "ENS:mp.com.3", "ISO:5.14", "ISO:8.20"],
    "DMA-02": ["ENS:mp.s.1", "ENS:mp.com.3", "ISO:5.14"],
    "DMA-03": ["ENS:mp.s.1", "ISO:5.14"],
    "DMA-04": ["ENS:mp.s.1", "ISO:8.16"],
    "DMA-05": ["ENS:mp.s.1", "ISO:5.14"],
    "DMA-06": ["ENS:mp.s.1", "ISO:8.16"],
    "DMA-07": ["ENS:mp.s.1", "ISO:5.14"],
    "DMA-08": ["ENS:mp.s.1", "ISO:8.16"],
    "TRA-01": ["ENS:mp.com.2", "ISO:8.24", "ISO:8.21"],
    "TRA-02": ["ENS:mp.com.2", "ISO:8.24"],
    "TRA-03": ["ENS:mp.com.2", "ISO:8.16"],
    "TRA-04": ["ENS:mp.com.3", "ISO:8.21"],
    "TRA-05": ["ENS:mp.com.2", "ISO:8.24"],
    "TRA-06": ["ENS:mp.com.2", "ISO:8.21", "ISO:8.24"],
    "MX-01": ["ENS:mp.s.1", "ISO:5.14"],
    "LKA-01": ["ENS:mp.s.1", "ENS:op.mon.3", "ISO:5.14"],
    "LKA-02": ["ENS:op.mon.3", "ISO:5.14"],
    "EML-01": ["ENS:mp.s.1", "ENS:op.exp.7", "ISO:5.26"],
    "EML-02": ["ENS:mp.s.1", "ENS:op.exp.7", "ISO:5.26"],
    "EML-03": ["ENS:mp.s.1", "ISO:5.14"],
    "EML-04": ["ENS:mp.s.1", "ISO:5.14"],
    "EML-05": ["ENS:op.exp.6", "ISO:8.7"],
    "EML-06": ["ENS:mp.s.1", "ISO:5.14"],
    "EML-07": ["ENS:op.exp.7", "ISO:5.26"],
    "EML-08": ["ENS:mp.s.1", "ENS:op.exp.7", "ISO:5.26"],
}

_SEVERITY: Dict[str, Severity] = {
    "SPF-01": Severity.HIGH, "SPF-02": Severity.CRITICAL, "SPF-03": Severity.MEDIUM,
    "SPF-04": Severity.HIGH, "SPF-05": Severity.MEDIUM, "SPF-06": Severity.LOW,
    "SPF-07": Severity.MEDIUM,
    "DKI-01": Severity.MEDIUM, "DKI-02": Severity.HIGH, "DKI-03": Severity.LOW,
    "DKI-04": Severity.LOW,
    "DMA-01": Severity.CRITICAL, "DMA-02": Severity.HIGH, "DMA-03": Severity.MEDIUM,
    "DMA-04": Severity.MEDIUM, "DMA-05": Severity.MEDIUM, "DMA-06": Severity.MEDIUM,
    "DMA-07": Severity.LOW, "DMA-08": Severity.MEDIUM,
    "TRA-01": Severity.MEDIUM, "TRA-02": Severity.LOW, "TRA-03": Severity.LOW,
    "TRA-04": Severity.MEDIUM, "TRA-05": Severity.LOW, "TRA-06": Severity.MEDIUM,
    "MX-01": Severity.MEDIUM,
    "LKA-01": Severity.HIGH, "LKA-02": Severity.MEDIUM,
    "EML-01": Severity.HIGH, "EML-02": Severity.HIGH, "EML-03": Severity.MEDIUM,
    "EML-04": Severity.MEDIUM, "EML-05": Severity.MEDIUM, "EML-06": Severity.LOW,
    "EML-07": Severity.INFO, "EML-08": Severity.MEDIUM,
}

DOMAIN_RULES = [r for r in RULE_CONTROLS if not r.startswith("EML")]
MESSAGE_RULES = [r for r in RULE_CONTROLS if r.startswith("EML")]

def _f(
    fid: str,
    title_en: str, title_es: str,
    detail_en: str, detail_es: str,
    rec_en: str, rec_es: str,
    evidence: Optional[str] = None,
    reference: Optional[str] = None,
    severity: Optional[Severity] = None,
) -> Finding:
    return Finding(
        id=fid,
        severity=severity or _SEVERITY[fid],
        title=T(title_en, title_es),
        detail=T(detail_en, detail_es),
        recommendation=T(rec_en, rec_es),
        controls=list(RULE_CONTROLS[fid]),
        evidence=evidence,
        reference=reference,
    )


def _get(posture: Dict[str, Any], *path: str, default: Any = None) -> Any:
    node: Any = posture
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    if node is None:
        return default
    if default is not None and not isinstance(node, type(default)):
        return default
    return node


# --------------------------------------------------------------------------
# SPF
# --------------------------------------------------------------------------

def check_spf(posture: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    spf = _get(posture, "spf", default={})
    if spf.get("determinable") is not True:
        return findings

    records = spf.get("records")
    if records is not None and not records:
        findings.append(_f(
            "SPF-01",
            "No SPF record published",
            "Sin registro SPF publicado",
            "The domain does not tell receiving servers which hosts may send on its "
            "behalf. Every message claiming to come from it has to be judged on other "
            "evidence, and most receivers will accept it.",
            "El dominio no indica a los servidores receptores que equipos pueden enviar en "
            "su nombre. Cualquier mensaje que diga proceder de el debe juzgarse por otros "
            "indicios, y la mayoria de receptores lo aceptaran.",
            "Publish a TXT record starting with v=spf1 that lists the legitimate senders and "
            "ends in -all.",
            "Publique un registro TXT que empiece por v=spf1, liste los emisores legitimos y "
            "termine en -all.",
            reference="RFC 7208 §3",
        ))
        return findings

    if records is not None and len(records) > 1:
        findings.append(_f(
            "SPF-03",
            "More than one SPF record",
            "Mas de un registro SPF",
            "RFC 7208 requires exactly one. When a domain publishes several, receivers must "
            "return permerror and the whole policy is discarded, which is worse than having "
            "no SPF at all because it looks configured.",
            "RFC 7208 exige exactamente uno. Cuando un dominio publica varios, los receptores "
            "deben devolver permerror y toda la politica se descarta, lo que es peor que no "
            "tener SPF porque aparenta estar configurado.",
            "Merge the records into a single TXT value.",
            "Fusione los registros en un unico valor TXT.",
            evidence=" | ".join(records)[:200],
            reference="RFC 7208 §4.5",
        ))

    parsed = spf.get("parsed") or {}
    qualifier = parsed.get("all")

    if qualifier == "+":
        findings.append(_f(
            "SPF-02",
            "SPF authorises the entire internet (+all)",
            "El SPF autoriza a todo internet (+all)",
            "The record ends in +all, which states that any host on the internet is a "
            "legitimate sender for this domain. It is worse than publishing nothing: it "
            "actively vouches for the attacker.",
            "El registro termina en +all, lo que declara que cualquier equipo de internet es "
            "un emisor legitimo del dominio. Es peor que no publicar nada: avala activamente "
            "al atacante.",
            "Replace +all with -all, or with ~all while the legitimate senders are being "
            "confirmed.",
            "Sustituya +all por -all, o por ~all mientras se confirman los emisores legitimos.",
            evidence=parsed.get("raw"),
            reference="RFC 7208 §5.1",
        ))
    elif qualifier == "?" or (qualifier is None and not parsed.get("redirect")):
        findings.append(_f(
            "SPF-04",
            "SPF does not close: neutral or missing 'all'",
            "El SPF no cierra: 'all' neutro o ausente",
            "Without a closing -all or ~all the record expresses no opinion about hosts that "
            "are not listed, so a message from anywhere else is neither authorised nor "
            "rejected and DMARC has nothing to align against.",
            "Sin un -all o ~all de cierre el registro no opina sobre los equipos no listados, "
            "de modo que un mensaje desde cualquier otro sitio ni se autoriza ni se rechaza y "
            "DMARC no tiene nada con lo que alinear.",
            "End the record with -all once the legitimate senders are confirmed.",
            "Termine el registro con -all una vez confirmados los emisores legitimos.",
            evidence=parsed.get("raw"),
            reference="RFC 7208 §5.1",
        ))

    lookups = spf.get("lookups")
    if isinstance(lookups, int) and lookups > 10:
        findings.append(_f(
            "SPF-05",
            f"SPF exceeds the 10 DNS lookup limit ({lookups})",
            f"El SPF supera el limite de 10 consultas DNS ({lookups})",
            "RFC 7208 caps the DNS-querying terms at ten. Beyond that receivers return "
            "permerror and treat the domain as having no usable policy, so the record silently "
            "stops protecting anything.",
            "RFC 7208 limita a diez los terminos que consultan DNS. Por encima de esa cifra "
            "los receptores devuelven permerror y tratan al dominio como si no tuviera "
            "politica utilizable, de modo que el registro deja de proteger en silencio.",
            "Flatten or remove includes until the count is ten or fewer; audit which providers "
            "still need to be authorised.",
            "Aplane o elimine includes hasta dejar el recuento en diez o menos; revise que "
            "proveedores siguen necesitando autorizacion.",
            evidence=f"{lookups} lookups: {', '.join(parsed.get('includes') or [])}"[:200],
            reference="RFC 7208 §4.6.4",
        ))

    if parsed.get("has_ptr"):
        findings.append(_f(
            "SPF-06",
            "SPF uses the deprecated ptr mechanism",
            "El SPF usa el mecanismo ptr, obsoleto",
            "RFC 7208 discourages ptr: it is slow, unreliable and some receivers ignore it "
            "entirely, so the hosts it was meant to authorise may fail.",
            "RFC 7208 desaconseja ptr: es lento, poco fiable y algunos receptores lo ignoran "
            "por completo, por lo que los equipos que pretendia autorizar pueden fallar.",
            "Replace ptr with explicit ip4/ip6 or a/mx mechanisms.",
            "Sustituya ptr por mecanismos ip4/ip6 o a/mx explicitos.",
            reference="RFC 7208 §5.5",
        ))

    unresolved = spf.get("unresolved_includes")
    if unresolved:
        findings.append(_f(
            "SPF-07",
            "SPF includes a domain with no SPF record",
            "El SPF incluye un dominio sin registro SPF",
            "These includes do not resolve to an SPF record: " + ", ".join(unresolved) + ". "
            "Each one is a permerror waiting to happen, and usually marks a provider that was "
            "decommissioned without updating DNS.",
            "Estos includes no resuelven a un registro SPF: " + ", ".join(unresolved) + ". "
            "Cada uno es un permerror en potencia y suele senalar a un proveedor dado de baja "
            "sin actualizar el DNS.",
            "Remove the stale includes, or fix the provider record they point at.",
            "Elimine los includes obsoletos, o corrija el registro del proveedor al que apuntan.",
            evidence=", ".join(unresolved)[:200],
            reference="RFC 7208 §4.6.4",
        ))
    return findings


# --------------------------------------------------------------------------
# DKIM
# --------------------------------------------------------------------------

def check_dkim(posture: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    dkim = _get(posture, "dkim", default={})
    if dkim.get("determinable") is not True:
        return findings

    found = dkim.get("found")
    if found is None:
        return findings

    if not found:
        findings.append(_f(
            "DKI-01",
            "No DKIM key found on the common selectors",
            "Sin clave DKIM en los selectores habituales",
            "None of the probed selectors published a key. Selectors cannot be enumerated "
            "from DNS, so this is not proof that DKIM is absent — but it does mean an auditor "
            "cannot verify it either, and a DMARC policy that relies on DKIM alignment cannot "
            "be evidenced.",
            "Ninguno de los selectores probados publica clave. Los selectores no se pueden "
            "enumerar desde DNS, asi que esto no prueba que DKIM falte, pero si significa que "
            "un auditor tampoco puede verificarlo, y una politica DMARC que dependa de la "
            "alineacion DKIM no se puede evidenciar.",
            "Confirm the selector with the mail provider and document it; re-run with "
            "--selectors to verify.",
            "Confirme el selector con el proveedor de correo y documentelo; vuelva a ejecutar "
            "con --selectors para verificarlo.",
            evidence=f"probed: {', '.join(dkim.get('probed') or [])}"[:200],
            reference="RFC 6376 §3.6.2",
        ))
        return findings

    weak = [k for k in found if isinstance(k.get("bits"), int) and k["bits"] < 1024]
    if weak:
        findings.append(_f(
            "DKI-02",
            "DKIM key shorter than 1024 bits",
            "Clave DKIM de menos de 1024 bits",
            "Keys below 1024 bits are considered forgeable and some receivers ignore the "
            "signature entirely, which silently removes the DKIM leg of DMARC.",
            "Las claves por debajo de 1024 bits se consideran falsificables y algunos "
            "receptores ignoran la firma por completo, lo que elimina en silencio la pata DKIM "
            "de DMARC.",
            "Rotate to a 2048 bit RSA key.",
            "Rote a una clave RSA de 2048 bits.",
            evidence=", ".join(f"{k['selector']}={k['bits']}b" for k in weak),
            reference="RFC 8301 §3.2",
        ))

    legacy = [k for k in found if isinstance(k.get("bits"), int) and 1024 <= k["bits"] < 2048]
    if legacy:
        findings.append(_f(
            "DKI-04",
            "DKIM key of 1024 bits",
            "Clave DKIM de 1024 bits",
            "1024 bits is the floor RFC 8301 still accepts, but it recommends 2048 and the "
            "margin has been shrinking for a decade.",
            "1024 bits es el minimo que RFC 8301 todavia acepta, pero recomienda 2048 y el "
            "margen lleva una decada estrechandose.",
            "Plan a rotation to 2048 bits at the next key change.",
            "Planifique la rotacion a 2048 bits en el proximo cambio de clave.",
            evidence=", ".join(f"{k['selector']}={k['bits']}b" for k in legacy),
            reference="RFC 8301 §3.2",
        ))

    testing = [k for k in found if k.get("testing")]
    revoked = [k for k in found if k.get("revoked")]
    if testing or revoked:
        detail = []
        if testing:
            detail.append("in test mode (t=y): " + ", ".join(k["selector"] for k in testing))
        if revoked:
            detail.append("revoked (empty p=): " + ", ".join(k["selector"] for k in revoked))
        findings.append(_f(
            "DKI-03",
            "DKIM selector in test mode or revoked",
            "Selector DKIM en modo prueba o revocado",
            "A key flagged t=y asks receivers to ignore failures, and a key with an empty p= "
            "is revoked. Either way the signature carries no weight. " + "; ".join(detail),
            "Una clave marcada t=y pide a los receptores que ignoren los fallos, y una clave "
            "con p= vacio esta revocada. En ambos casos la firma no aporta nada. "
            + "; ".join(detail),
            "Remove t=y once the deployment is validated, and delete revoked selectors from DNS.",
            "Elimine t=y cuando el despliegue este validado, y borre del DNS los selectores "
            "revocados.",
            evidence="; ".join(detail)[:200],
            reference="RFC 6376 §3.6.1",
        ))
    return findings


# --------------------------------------------------------------------------
# DMARC - the control that actually decides spoofability
# --------------------------------------------------------------------------

def check_dmarc(posture: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    dmarc = _get(posture, "dmarc", default={})
    if dmarc.get("determinable") is not True:
        return findings

    records = dmarc.get("records")
    if records is not None and not records:
        findings.append(_f(
            "DMA-01",
            "No DMARC record: the domain can be spoofed",
            "Sin registro DMARC: el dominio es suplantable",
            "Without DMARC there is no instruction telling receivers what to do with a "
            "message that fails authentication, and no report telling the organisation it "
            "happened. Anyone can put this domain in the From: line and most receivers will "
            "deliver the message.",
            "Sin DMARC no hay ninguna instruccion que diga a los receptores que hacer con un "
            "mensaje que falla la autenticacion, ni informe que avise a la organizacion de "
            "que ha ocurrido. Cualquiera puede poner este dominio en el From: y la mayoria de "
            "receptores entregaran el mensaje.",
            "Publish _dmarc.<domain> with v=DMARC1; p=none; rua=mailto:... , read the reports "
            "for a few weeks, then move to p=quarantine and finally p=reject.",
            "Publique _dmarc.<dominio> con v=DMARC1; p=none; rua=mailto:... , lea los informes "
            "durante unas semanas y pase despues a p=quarantine y finalmente a p=reject.",
            reference="RFC 7489 §6.3",
        ))
        return findings

    parsed = dmarc.get("parsed") or {}
    if len(records or []) > 1:
        findings.append(_f(
            "DMA-06",
            "More than one DMARC record",
            "Mas de un registro DMARC",
            "RFC 7489 requires receivers to ignore the domain's policy entirely when several "
            "DMARC records are published, so the protection silently disappears.",
            "RFC 7489 exige que los receptores ignoren por completo la politica del dominio "
            "cuando se publican varios registros DMARC, con lo que la proteccion desaparece "
            "en silencio.",
            "Keep exactly one TXT record at _dmarc.<domain>.",
            "Mantenga exactamente un registro TXT en _dmarc.<dominio>.",
            evidence=" | ".join(records or [])[:200],
            reference="RFC 7489 §6.6.3",
        ))

    policy = parsed.get("policy")
    percentage = parsed.get("percentage", 100)

    if policy == "none":
        findings.append(_f(
            "DMA-02",
            "DMARC policy is p=none: nothing is blocked",
            "Politica DMARC p=none: no se bloquea nada",
            "The domain is in monitoring mode. Reports arrive, but a forged message is still "
            "delivered to the recipient's inbox. This is the correct first step and the wrong "
            "final state; most domains never leave it.",
            "El dominio esta en modo monitorizacion. Llegan informes, pero un mensaje "
            "falsificado sigue entregandose en la bandeja del destinatario. Es el primer paso "
            "correcto y el estado final equivocado; la mayoria de dominios nunca sale de ahi.",
            "Once the aggregate reports show the legitimate senders passing, move to "
            "p=quarantine and then p=reject.",
            "Cuando los informes agregados muestren que los emisores legitimos pasan, cambie a "
            "p=quarantine y despues a p=reject.",
            evidence=parsed.get("raw"),
            reference="RFC 7489 §6.3",
        ))
    elif policy == "quarantine":
        findings.append(_f(
            "DMA-03",
            "DMARC policy stops at quarantine",
            "La politica DMARC se queda en quarantine",
            "Forged messages land in the spam folder rather than being refused. That is a real "
            "improvement, but the message still reaches the recipient, and users do open the "
            "spam folder.",
            "Los mensajes falsificados acaban en la carpeta de spam en lugar de rechazarse. Es "
            "una mejora real, pero el mensaje sigue llegando al destinatario, y los usuarios si "
            "abren la carpeta de spam.",
            "Move to p=reject once the reports show no legitimate sender failing.",
            "Pase a p=reject cuando los informes no muestren ningun emisor legitimo fallando.",
            evidence=parsed.get("raw"),
            reference="RFC 7489 §6.3",
        ))

    if isinstance(percentage, int) and percentage < 100 and policy in ("quarantine", "reject"):
        findings.append(_f(
            "DMA-05",
            f"DMARC applies to only {percentage}% of messages",
            f"DMARC se aplica solo al {percentage}% de los mensajes",
            "pct< 100 was designed as a temporary ramp. While it is in place, the stated "
            "fraction of forged messages is still delivered normally.",
            "pct< 100 se diseno como una rampa temporal. Mientras siga puesto, la fraccion "
            "indicada de mensajes falsificados se sigue entregando con normalidad.",
            "Raise pct to 100 once the ramp has been validated.",
            "Suba pct a 100 cuando la rampa este validada.",
            evidence=f"pct={percentage}",
            reference="RFC 7489 §6.3",
        ))

    if not parsed.get("rua"):
        findings.append(_f(
            "DMA-04",
            "No DMARC aggregate reports requested",
            "No se solicitan informes agregados DMARC",
            "Without a rua= address the organisation never learns who is sending on its "
            "behalf, legitimately or not, and has no evidence on which to tighten the policy.",
            "Sin una direccion rua= la organizacion nunca sabe quien envia en su nombre, "
            "legitimamente o no, y carece de evidencia sobre la que endurecer la politica.",
            "Add rua=mailto:dmarc@<domain> and route it to a mailbox or a report processor "
            "that somebody actually reads.",
            "Anada rua=mailto:dmarc@<dominio> y dirijalo a un buzon o procesador de informes "
            "que alguien lea de verdad.",
            reference="RFC 7489 §7.1",
        ))

    subdomain = parsed.get("effective_subdomain_policy")
    if policy in ("quarantine", "reject") and subdomain == "none":
        findings.append(_f(
            "DMA-07",
            "Subdomains are left unprotected (sp=none)",
            "Los subdominios quedan sin proteccion (sp=none)",
            "The organisational domain is protected but its subdomains are not, and an "
            "attacker only needs a plausible one — invoices.<domain> reads as legitimate to "
            "any recipient.",
            "El dominio organizativo esta protegido pero sus subdominios no, y a un atacante "
            "le basta con uno verosimil: facturas.<dominio> le parecera legitimo a cualquier "
            "destinatario.",
            "Remove sp=none so subdomains inherit the policy, or set sp=reject explicitly.",
            "Elimine sp=none para que los subdominios hereden la politica, o fije sp=reject de "
            "forma explicita.",
            evidence=f"p={policy} sp={parsed.get('subdomain_policy')}",
            reference="RFC 7489 §6.3",
        ))

    external = dmarc.get("external_reports") or {}
    unauthorised = [host for host, ok in external.items() if ok is False]
    if unauthorised:
        findings.append(_f(
            "DMA-08",
            "External report destination is not authorised",
            "Destino externo de informes sin autorizar",
            "Reports are addressed to " + ", ".join(unauthorised) + ", which does not publish "
            "the authorisation record RFC 7489 requires. Compliant senders will not deliver "
            "the reports, so the organisation is blind while believing it is monitored.",
            "Los informes se dirigen a " + ", ".join(unauthorised) + ", que no publica el "
            "registro de autorizacion que exige RFC 7489. Los emisores conformes no enviaran "
            "los informes, de modo que la organizacion esta ciega creyendose vigilada.",
            "Ask the provider to publish <domain>._report._dmarc.<their-domain> with "
            "v=DMARC1.",
            "Pida al proveedor que publique <dominio>._report._dmarc.<su-dominio> con "
            "v=DMARC1.",
            evidence=", ".join(unauthorised)[:200],
            reference="RFC 7489 §7.1",
        ))
    return findings


# --------------------------------------------------------------------------
# Transport: MTA-STS, TLS-RPT, DANE, DNSSEC
# --------------------------------------------------------------------------

def check_transport(posture: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    mx = _get(posture, "mx", default={})
    # RFC 5321 section 5.1: with no MX, mail is delivered to the address record,
    # so a domain that resolves is a mail destination unless it says otherwise.
    has_mail = not mx.get("null_mx") and (
        bool(mx.get("records"))
        or (posture.get("collection") or {}).get("resolvable") is True
    )

    mta_sts = _get(posture, "mta_sts", default={})
    if has_mail and mta_sts.get("determinable") is True and not mta_sts.get("record"):
        findings.append(_f(
            "TRA-01",
            "No MTA-STS policy",
            "Sin politica MTA-STS",
            "SMTP still falls back to plain text when TLS cannot be negotiated, and an "
            "attacker positioned in the path can force exactly that. MTA-STS is what tells "
            "senders to refuse the downgrade.",
            "SMTP sigue cayendo a texto claro cuando no se puede negociar TLS, y un atacante "
            "situado en la ruta puede forzar precisamente eso. MTA-STS es lo que indica a los "
            "emisores que rechacen la degradacion.",
            "Publish _mta-sts.<domain> and the policy at "
            "https://mta-sts.<domain>/.well-known/mta-sts.txt, starting in testing mode.",
            "Publique _mta-sts.<dominio> y la politica en "
            "https://mta-sts.<dominio>/.well-known/mta-sts.txt, empezando en modo testing.",
            reference="RFC 8461 §3",
        ))
    elif mta_sts.get("record") and mta_sts.get("policy_error"):
        findings.append(_f(
            "TRA-06",
            "MTA-STS is announced but the policy cannot be used",
            "MTA-STS esta anunciado pero la politica no se puede usar",
            "The DNS record advertises MTA-STS while the policy file could not be retrieved or "
            "is not conformant: " + str(mta_sts.get("policy_error")) + ". Senders fall back to "
            "opportunistic TLS, so the protection is announced but absent.",
            "El registro DNS anuncia MTA-STS mientras que el fichero de politica no se ha "
            "podido recuperar o no es conforme: " + str(mta_sts.get("policy_error")) + ". Los "
            "emisores vuelven a TLS oportunista, de modo que la proteccion se anuncia pero no "
            "existe.",
            "Serve the policy at https://mta-sts.<domain>/.well-known/mta-sts.txt as text/plain, "
            "with version, mode, max_age and at least one mx, and without redirects.",
            "Sirva la politica en https://mta-sts.<dominio>/.well-known/mta-sts.txt como "
            "text/plain, con version, mode, max_age y al menos un mx, y sin redirecciones.",
            evidence=str(mta_sts.get("policy_error"))[:200],
            reference="RFC 8461 §3.3",
        ))
    elif mta_sts.get("mode") == "testing":
        findings.append(_f(
            "TRA-02",
            "MTA-STS policy is still in testing mode",
            "La politica MTA-STS sigue en modo testing",
            "In testing mode senders report failures but deliver anyway, so the downgrade "
            "attack MTA-STS exists to stop still works.",
            "En modo testing los emisores informan de los fallos pero entregan igualmente, de "
            "modo que el ataque de degradacion que MTA-STS existe para impedir sigue "
            "funcionando.",
            "Move the policy to mode: enforce once the reports are clean.",
            "Pase la politica a mode: enforce cuando los informes esten limpios.",
            evidence="mode=testing",
            reference="RFC 8461 §3.2",
        ))

    tls_rpt = _get(posture, "tls_rpt", default={})
    if has_mail and tls_rpt.get("determinable") is True and not tls_rpt.get("record"):
        findings.append(_f(
            "TRA-03",
            "No TLS-RPT reporting configured",
            "Sin informes TLS-RPT configurados",
            "Nothing tells the organisation when another server failed to establish TLS with "
            "its mail servers, which is the first symptom of both a misconfiguration and an "
            "interception attempt.",
            "Nada avisa a la organizacion de que otro servidor no ha podido establecer TLS con "
            "sus servidores de correo, que es el primer sintoma tanto de un error de "
            "configuracion como de un intento de interceptacion.",
            "Publish _smtp._tls.<domain> with v=TLSRPTv1 and a rua= destination.",
            "Publique _smtp._tls.<dominio> con v=TLSRPTv1 y un destino rua=.",
            reference="RFC 8460 §3",
        ))

    dnssec = _get(posture, "dnssec", default={})
    if dnssec.get("determinable") is True and dnssec.get("ds") is False:
        findings.append(_f(
            "TRA-04",
            "The zone is not signed with DNSSEC",
            "La zona no esta firmada con DNSSEC",
            "Every control above lives in DNS. Without DNSSEC an attacker who can tamper with "
            "resolution can replace the SPF, DKIM and DMARC answers themselves, and DANE "
            "cannot be used at all.",
            "Todos los controles anteriores viven en el DNS. Sin DNSSEC, un atacante capaz de "
            "manipular la resolucion puede sustituir las propias respuestas de SPF, DKIM y "
            "DMARC, y DANE no se puede utilizar en absoluto.",
            "Sign the zone and publish the DS record at the registrar.",
            "Firme la zona y publique el registro DS en el registrador.",
            reference="RFC 4033",
        ))

    dane = _get(posture, "dane", default={})
    if has_mail and dane.get("determinable") is True:
        hosts = dane.get("hosts") or {}
        missing = [h for h, present in hosts.items() if present is False]
        if missing and len(missing) == len([h for h in hosts.values() if h is not None]):
            findings.append(_f(
                "TRA-05",
                "No DANE (TLSA) records for the mail servers",
                "Sin registros DANE (TLSA) en los servidores de correo",
                "DANE pins the certificate of each mail server in signed DNS. It is optional "
                "and only works on a signed zone, but it is the strongest available guarantee "
                "that mail to this domain is not intercepted.",
                "DANE ancla el certificado de cada servidor de correo en un DNS firmado. Es "
                "opcional y solo funciona sobre zona firmada, pero es la garantia mas fuerte "
                "disponible de que el correo a este dominio no se intercepta.",
                "Once the zone is signed, publish TLSA records at _25._tcp.<mx>.",
                "Cuando la zona este firmada, publique registros TLSA en _25._tcp.<mx>.",
                evidence=", ".join(missing)[:200],
                reference="RFC 7672 §3",
            ))
    return findings


def check_mx(posture: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    mx = _get(posture, "mx", default={})
    if mx.get("determinable") is not True:
        return findings
    spf = _get(posture, "spf", default={})
    dmarc = _get(posture, "dmarc", default={})

    no_mail = not mx.get("records")
    parked_unprotected = (
        no_mail
        and not mx.get("null_mx")
        and spf.get("determinable") is True
        and dmarc.get("determinable") is True
        and not (dmarc.get("records") or [])
    )
    if parked_unprotected:
        findings.append(_f(
            "MX-01",
            "Domain receives no mail but is not marked as such",
            "El dominio no recibe correo pero no esta marcado como tal",
            "There is no MX record and no null MX. A domain that never sends or receives mail "
            "is the easiest one to abuse, precisely because nobody notices: publish the "
            "records that say so explicitly.",
            "No hay registro MX ni null MX. Un dominio que ni envia ni recibe correo es el mas "
            "facil de abusar, precisamente porque nadie se da cuenta: publique los registros "
            "que lo declaren de forma explicita.",
            "Publish MX '.' (null MX), v=spf1 -all and a DMARC record with p=reject.",
            "Publique MX '.' (null MX), v=spf1 -all y un registro DMARC con p=reject.",
            reference="RFC 7505 §3",
        ))
    return findings


# --------------------------------------------------------------------------
# Lookalike domains
# --------------------------------------------------------------------------

def check_lookalike(posture: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lookalike = _get(posture, "lookalike", default={})
    if lookalike.get("determinable") is not True:
        return findings

    registered = lookalike.get("registered") or []
    with_mx = [d for d in registered if d.get("can_receive_mail")]

    if with_mx:
        listing = ", ".join(d["domain"] for d in with_mx[:8])
        findings.append(_f(
            "LKA-01",
            f"{len(with_mx)} similar domain(s) can send and receive mail",
            f"{len(with_mx)} dominio(s) parecido(s) pueden enviar y recibir correo",
            "These registered domains resemble the audited one and have mail servers: "
            + listing + ". A message from one of them passes every authentication check, "
            "because it is genuinely authenticated — for a domain that is not yours.",
            "Estos dominios registrados se parecen al auditado y tienen servidores de correo: "
            + listing + ". Un mensaje enviado desde uno de ellos supera todas las "
            "comprobaciones de autenticacion, porque esta autenticado de verdad, solo que para "
            "un dominio que no es el suyo.",
            "Check who owns them; consider defensive registration of the closest ones and add "
            "the rest to the mail gateway's watchlist.",
            "Compruebe quien los posee; valore el registro defensivo de los mas cercanos y "
            "anada el resto a la lista de vigilancia de la pasarela de correo.",
            evidence=listing[:200],
            reference="op.mon.3.r4.1",
        ))

    only_web = [d for d in registered if not d.get("can_receive_mail")]
    if only_web:
        listing = ", ".join(d["domain"] for d in only_web[:8])
        findings.append(_f(
            "LKA-02",
            f"{len(only_web)} similar domain(s) registered without mail",
            f"{len(only_web)} dominio(s) parecido(s) registrados sin correo",
            "These resolve but publish no MX: " + listing + ". They cannot receive mail today, "
            "but they can host a credential harvesting page, and an MX record is one edit away.",
            "Estos resuelven pero no publican MX: " + listing + ". Hoy no pueden recibir "
            "correo, pero si alojar una pagina de robo de credenciales, y anadir un MX es "
            "cuestion de una edicion.",
            "Review ownership and monitor them for changes.",
            "Revise su titularidad y vigile si cambian.",
            evidence=listing[:200],
            reference="op.mon.3.r4.1",
        ))
    return findings


# --------------------------------------------------------------------------
# Received message
# --------------------------------------------------------------------------

def check_message(message: Message) -> List[Finding]:
    findings: List[Finding] = []
    if message.parse_error:
        return findings

    results = message.auth_results or {}
    aligned = alignment(message)
    if results and not message.auth_verified and message.auth_headers > 1:
        # More than one stamp and no way to tell which one our own MTA wrote.
        results = {}

    dmarc_result = results.get("dmarc")
    spf_result = results.get("spf")
    dkim_result = results.get("dkim")

    if dmarc_result in ("fail", "permerror", "temperror"):
        findings.append(_f(
            "EML-01",
            "The message failed DMARC and was delivered anyway",
            "El mensaje fallo DMARC y aun asi se entrego",
            f"The receiving server recorded dmarc={dmarc_result} and the message still reached "
            "the mailbox. Either the sending domain publishes p=none, or the local gateway is "
            "configured to ignore the policy.",
            f"El servidor receptor anoto dmarc={dmarc_result} y el mensaje llego igualmente al "
            "buzon. O el dominio remitente publica p=none, o la pasarela local esta configurada "
            "para ignorar la politica.",
            "Check the sending domain's policy and make the gateway honour DMARC.",
            "Compruebe la politica del dominio remitente y haga que la pasarela respete DMARC.",
            evidence=f"dmarc={dmarc_result} spf={spf_result} dkim={dkim_result}",
            reference="RFC 7489 §6.6",
        ))
    elif spf_result in ("fail", "softfail") and dkim_result in (None, "fail", "none"):
        findings.append(_f(
            "EML-02",
            "Neither SPF nor DKIM authenticated the sender",
            "Ni SPF ni DKIM autenticaron al remitente",
            f"The receiving server recorded spf={spf_result} and dkim={dkim_result or 'absent'}. "
            "Nothing in the message ties it to the domain it claims to come from.",
            f"El servidor receptor anoto spf={spf_result} y dkim={dkim_result or 'ausente'}. "
            "Nada en el mensaje lo vincula al dominio del que dice proceder.",
            "Treat the message as forged until proven otherwise and audit the sending domain.",
            "Trate el mensaje como falsificado mientras no se demuestre lo contrario y audite "
            "el dominio remitente.",
            evidence=f"spf={spf_result} dkim={dkim_result}",
            reference="RFC 7489 §3.1",
        ))

    if not results:
        # No verdict from the receiving side: fall back to what the message
        # itself shows. Weaker evidence, so a lower severity, but silence here
        # would be worse — this is exactly the case a forged message produces.
        unaligned = [
            name for name, value in (("Return-Path", aligned.get("spf")),
                                     ("DKIM d=", aligned.get("dkim")))
            if value is False
        ]
        if unaligned:
            findings.append(_f(
                "EML-08",
                "Sender identities do not match the visible From",
                "Las identidades del remitente no coinciden con el From visible",
                "No receiving server recorded a verdict, but the message itself shows "
                + " and ".join(unaligned) + " on a different domain from the address the "
                f"recipient sees ({message.from_domain}). That is what a forged message "
                "looks like from the inside.",
                "Ningun servidor receptor dejo veredicto, pero el propio mensaje muestra "
                + " y ".join(unaligned) + " en un dominio distinto del de la direccion que ve "
                f"el destinatario ({message.from_domain}). Es el aspecto que tiene un mensaje "
                "falsificado visto por dentro.",
                "Confirm with the mail gateway logs before acting: these headers are supplied "
                "by the sender.",
                "Confirmelo con los registros de la pasarela antes de actuar: estas cabeceras "
                "las aporta el remitente.",
                evidence=f"From={message.from_domain} Return-Path={message.return_path_domain} "
                         f"DKIM={','.join(message.dkim_domains) or '-'}",
                reference="RFC 7489 §3.1.2",
            ))

    embedded = display_name_spoof(message)
    if embedded:
        findings.append(_f(
            "EML-03",
            "The display name contains a different address",
            "El nombre mostrado contiene una direccion distinta",
            f"The message is shown as coming from '{message.from_display}' while it was "
            f"actually sent by {message.from_address}. Most mail clients on a phone show only "
            "the display name, so the recipient never sees the real address.",
            f"El mensaje se muestra como procedente de '{message.from_display}' cuando en "
            f"realidad lo envio {message.from_address}. La mayoria de clientes de correo en el "
            "movil muestran solo el nombre, asi que el destinatario nunca ve la direccion real.",
            "Configure the gateway to rewrite or flag display names that contain an address.",
            "Configure la pasarela para reescribir o marcar los nombres que contengan una "
            "direccion.",
            evidence=f"{message.from_display} != {message.from_address}",
        ))

    if aligned.get("reply_to") is False:
        findings.append(_f(
            "EML-04",
            "Replies would go to a different domain",
            "Las respuestas irian a otro dominio",
            f"From: is {message.from_domain} but Reply-To: points at "
            f"{message.reply_to_domain}. This is the classic shape of CEO fraud: the message "
            "looks internal and the answer leaves the organisation.",
            f"El From: es {message.from_domain} pero el Reply-To: apunta a "
            f"{message.reply_to_domain}. Es la forma clasica del fraude del CEO: el mensaje "
            "parece interno y la respuesta sale de la organizacion.",
            "Flag or quarantine messages whose Reply-To domain differs from the From domain.",
            "Marque o ponga en cuarentena los mensajes cuyo dominio Reply-To difiera del "
            "dominio From.",
            evidence=f"From={message.from_domain} Reply-To={message.reply_to_domain}",
        ))

    risky = risky_attachments(message)
    if risky:
        listing = ", ".join(f"{a.filename} ({why})" for a, why in risky[:6])
        findings.append(_f(
            "EML-05",
            "The message carries risky attachments",
            "El mensaje lleva adjuntos de riesgo",
            "Attachments that execute code, carry macros or hide behind a second extension: "
            + listing + ".",
            "Adjuntos que ejecutan codigo, llevan macros o se esconden tras una segunda "
            "extension: " + listing + ".",
            "Block these types at the gateway and detonate the rest in a sandbox.",
            "Bloquee estos tipos en la pasarela y detone el resto en un entorno aislado.",
            evidence=listing[:200],
        ))

    suspicious = suspicious_urls(message)
    if suspicious:
        listing = ", ".join(f"{url[:60]} ({why})" for url, why in suspicious[:5])
        findings.append(_f(
            "EML-06",
            "The message contains suspicious links",
            "El mensaje contiene enlaces sospechosos",
            "Links that point at a bare IP address, use punycode, bury the real host under "
            "many subdomains or hide credentials in the URL: " + listing + ".",
            "Enlaces que apuntan a una IP desnuda, usan punycode, entierran el host real bajo "
            "muchos subdominios u ocultan credenciales en la URL: " + listing + ".",
            "Rewrite links at the gateway and check the destinations before anyone clicks.",
            "Reescriba los enlaces en la pasarela y compruebe los destinos antes de que nadie "
            "pulse.",
            evidence=listing[:200],
        ))

    if not results:
        findings.append(_f(
            "EML-07",
            "The message carries no Authentication-Results header",
            "El mensaje no lleva cabecera Authentication-Results",
            "The receiving infrastructure recorded no verdict, so this analysis rests only on "
            "the message's own headers, which the sender controls. Nothing here can be taken "
            "as proof either way.",
            "La infraestructura receptora no dejo constancia de ningun veredicto, asi que este "
            "analisis se apoya solo en las cabeceras del propio mensaje, que controla el "
            "remitente. Nada de lo anterior puede tomarse como prueba en ningun sentido.",
            "Enable authentication result stamping on the mail gateway, and pass its "
            "identifier with --authserv-id so the header can be trusted.",
            "Habilite el sellado de resultados de autenticacion en la pasarela de correo, y "
            "pase su identificador con --authserv-id para poder fiarse de la cabecera.",
            evidence=f"{message.auth_headers} Authentication-Results header(s) present",
            reference="RFC 8601 §2",
        ))
    return findings


# --------------------------------------------------------------------------

def run_domain(posture: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    findings += check_spf(posture)
    findings += check_dkim(posture)
    findings += check_dmarc(posture)
    findings += check_transport(posture)
    findings += check_mx(posture)
    findings += check_lookalike(posture)
    return findings


def spoofable(posture: Dict[str, Any]) -> Optional[bool]:
    """The headline verdict: can a stranger send mail as this domain?

    ``None`` when DMARC could not be resolved. Anything short of an enforcing
    DMARC policy at 100% means yes, regardless of how good the SPF record is:
    SPF alone is not checked against the visible From: header.
    """
    dmarc = _get(posture, "dmarc", default={})
    if dmarc.get("determinable") is not True:
        return None
    if not (dmarc.get("records") or []):
        return True
    parsed = dmarc.get("parsed") or {}
    return not parsed.get("enforcing", False)
