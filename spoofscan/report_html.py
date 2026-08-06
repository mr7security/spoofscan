"""Self-contained bilingual (EN/ES) HTML report."""
from __future__ import annotations

import html
from typing import Any, Dict, List, Optional

from . import catalog, checks, scoring
from .lookalike import kind_label
from .models import Finding, Severity, Status, sort_findings

CSS = """
:root{--bg:#0f1218;--panel:#161b24;--panel2:#1c2230;--line:#273042;--fg:#e6ebf2;
--muted:#93a0b4;--accent:#4da3ff;--ok:#2eb872;--crit:#b3202e;--high:#d9531e;
--med:#d9a21e;--low:#3f7fb5;--info:#6b7280}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px 64px}
header{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;
border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:28px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.4px}
h2{font-size:18px;margin:36px 0 14px}
.sub{color:var(--muted);font-size:14px;margin:0}
.toggle{border:1px solid var(--line);background:var(--panel);border-radius:8px;padding:6px;
display:flex;gap:4px}
.toggle button{background:none;border:0;color:var(--muted);padding:6px 14px;border-radius:6px;
cursor:pointer;font:inherit;font-size:13px}
.toggle button.on{background:var(--accent);color:#04101f;font-weight:600}
.verdict{border-radius:12px;padding:22px 24px;margin-bottom:20px;border:1px solid var(--line)}
.verdict.yes{background:linear-gradient(90deg,rgba(179,32,46,.28),rgba(179,32,46,.05));
border-color:var(--crit)}
.verdict.no{background:linear-gradient(90deg,rgba(46,184,114,.22),rgba(46,184,114,.04));
border-color:var(--ok)}
.verdict.unknown{background:var(--panel2)}
.verdict .q{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.08em}
.verdict .a{font-size:26px;font-weight:700;margin:4px 0 6px;letter-spacing:-.3px}
.verdict .why{color:#cfd8e5;font-size:14px;margin:0}
.grid{display:grid;grid-template-columns:220px 1fr;gap:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}
.gauge{display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge .val{font-size:34px;font-weight:700}
.gauge .grade{color:var(--muted);font-size:13px}
.meta{display:grid;grid-template-columns:repeat(2,1fr);gap:10px 24px;font-size:14px}
.meta div span{color:var(--muted);display:block;font-size:12px;text-transform:uppercase;
letter-spacing:.06em}
.pills{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}
.pill{border-radius:999px;padding:5px 13px;font-size:13px;font-weight:600;color:#06090f}
.f{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;
padding:18px 20px;margin-bottom:12px}
.f h3{margin:0 0 6px;font-size:16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.tag{font-size:11px;font-weight:700;letter-spacing:.08em;padding:3px 8px;border-radius:5px;color:#fff}
.fid{color:var(--muted);font-size:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.f p{margin:8px 0 0;color:#cfd8e5}
.rec{margin-top:12px;padding:11px 14px;background:var(--panel2);border-radius:8px;font-size:14px}
.rec b{color:var(--accent);font-weight:600}
.ctrl{margin-top:10px;display:flex;gap:6px;flex-wrap:wrap}
.ctrl span{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;
border:1px solid var(--line);border-radius:5px;padding:2px 7px;color:var(--muted)}
.ev{margin-top:10px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
color:var(--muted);word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-weight:600}
td.code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;white-space:nowrap}
.st{font-weight:600;font-size:13px;white-space:nowrap}
.st.COMPLIANT{color:var(--ok)}.st.PARTIAL{color:var(--med)}
.st.NON_COMPLIANT{color:var(--high)}.st.NOT_ASSESSED{color:var(--muted)}
.rec-dns{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;
background:var(--panel2);border-radius:8px;padding:12px 14px;white-space:pre-wrap;
word-break:break-all;color:#cfd8e5;margin-top:8px}
footer{margin-top:44px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);
font-size:12.5px}
.es{display:none}
body.lang-es .en{display:none}body.lang-es .es{display:inline}
body.lang-es p.es,body.lang-es div.es{display:block}
@media print{body{background:#fff;color:#111}.toggle{display:none}
.card,.f{border-color:#ccc;background:#fff}}
@media(max-width:720px){.grid{grid-template-columns:1fr}.meta{grid-template-columns:1fr}}
"""

JS = """
function setLang(l){document.body.classList.toggle('lang-es',l==='es');
document.querySelectorAll('.toggle button').forEach(function(b){
b.classList.toggle('on',b.dataset.lang===l)});}
document.querySelectorAll('.toggle button').forEach(function(b){
b.addEventListener('click',function(){setLang(b.dataset.lang)})});
"""


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _bi(item, cls: str = "") -> str:
    klass = (cls + " ") if cls else ""
    return (f'<span class="{klass}en">{_e(item.en)}</span>'
            f'<span class="{klass}es">{_e(item.es)}</span>')


def _gauge(value: Optional[int]) -> str:
    circumference = 2 * 3.14159 * 52
    if value is None:
        return f"""<svg width="128" height="128" viewBox="0 0 128 128">
  <circle cx="64" cy="64" r="52" fill="none" stroke="var(--line)" stroke-width="11"/></svg>"""
    filled = circumference * value / 100
    colour = "var(--ok)" if value >= 75 else ("var(--med)" if value >= 50 else "var(--high)")
    return f"""<svg width="128" height="128" viewBox="0 0 128 128">
  <circle cx="64" cy="64" r="52" fill="none" stroke="var(--line)" stroke-width="11"/>
  <circle cx="64" cy="64" r="52" fill="none" stroke="{colour}" stroke-width="11"
    stroke-linecap="round" stroke-dasharray="{filled:.1f} {circumference:.1f}"
    transform="rotate(-90 64 64)"/></svg>"""


def _verdict_block(posture: Dict[str, Any]) -> str:
    verdict = checks.spoofable(posture)
    dmarc = (posture.get("dmarc") or {}).get("parsed") or {}
    policy = dmarc.get("policy")
    if verdict is True:
        klass = "yes"
        answer_en, answer_es = "Yes", "Si"
        why_en = (
            "There is no enforcing DMARC policy, so a message with this domain in the "
            "From: header is delivered by most receivers." if not policy else
            f"The DMARC policy is p={policy}, which does not refuse a forged message."
        )
        why_es = (
            "No hay una politica DMARC en aplicacion, de modo que un mensaje con este dominio "
            "en el From: lo entregan la mayoria de receptores." if not policy else
            f"La politica DMARC es p={policy}, que no rechaza un mensaje falsificado."
        )
    elif verdict is False:
        klass = "no"
        answer_en, answer_es = "No", "No"
        why_en = (f"DMARC is published with p={policy} applied to 100% of messages, so a "
                  "receiver following the standard refuses a forged message.")
        why_es = (f"DMARC esta publicado con p={policy} aplicado al 100% de los mensajes, por "
                  "lo que un receptor que siga el estandar rechaza un mensaje falsificado.")
    else:
        klass = "unknown"
        answer_en, answer_es = "Not determinable", "No determinable"
        why_en = "The DMARC record could not be resolved, so no verdict can be given."
        why_es = "No se ha podido resolver el registro DMARC, asi que no cabe veredicto."
    return f"""<div class="verdict {klass}">
  <div class="q"><span class="en">Can a stranger send mail as this domain?</span>
    <span class="es">¿Puede un tercero enviar correo como este dominio?</span></div>
  <div class="a"><span class="en">{answer_en}</span><span class="es">{answer_es}</span></div>
  <p class="why en">{_e(why_en)}</p><p class="why es">{_e(why_es)}</p>
</div>"""


def _suggested_records(posture: Dict[str, Any]) -> str:
    domain = posture.get("domain", "example.org")
    spf = (posture.get("spf") or {}).get("records") or []
    dmarc = (posture.get("dmarc") or {}).get("records") or []
    lines = []
    if not spf:
        lines.append(f"{domain}.                 IN TXT  \"v=spf1 mx -all\"")
    if not dmarc:
        lines.append(f"_dmarc.{domain}.          IN TXT  \"v=DMARC1; p=none; "
                     f"rua=mailto:dmarc@{domain}; adkim=s; aspf=s\"")
    if not (posture.get("mta_sts") or {}).get("record"):
        lines.append(f"_mta-sts.{domain}.        IN TXT  \"v=STSv1; id=20260101000000\"")
    if not (posture.get("tls_rpt") or {}).get("record"):
        lines.append(f"_smtp._tls.{domain}.      IN TXT  \"v=TLSRPTv1; "
                     f"rua=mailto:tlsrpt@{domain}\"")
    if not lines:
        return ""
    body = "\n".join(lines)
    return f"""<h2><span class="en">Records to publish</span>
<span class="es">Registros que publicar</span></h2>
<div class="card">
<p class="en" style="margin:0">A starting point, to be adjusted to the real senders. Move the
DMARC policy to quarantine and then reject once the aggregate reports are clean.</p>
<p class="es" style="margin:0">Un punto de partida, a ajustar a los emisores reales. Pase la
politica DMARC a quarantine y despues a reject cuando los informes agregados esten limpios.</p>
<div class="rec-dns">{_e(body)}</div></div>"""


def _lookalike_block(posture: Dict[str, Any]) -> str:
    lookalike = posture.get("lookalike") or {}
    registered = lookalike.get("registered") or []
    if not registered:
        return ""
    rows = []
    for item in sorted(registered, key=lambda d: (not d.get("can_receive_mail"), d["domain"])):
        en, es = kind_label(item.get("kind", ""))
        mail_en = "yes" if item.get("can_receive_mail") else "no"
        mail_es = "si" if item.get("can_receive_mail") else "no"
        rows.append(f"""<tr>
  <td class="code">{_e(item['domain'])}</td>
  <td><span class="en">{_e(en)}</span><span class="es">{_e(es)}</span></td>
  <td class="st {'NON_COMPLIANT' if item.get('can_receive_mail') else 'PARTIAL'}">
    <span class="en">{mail_en}</span><span class="es">{mail_es}</span></td>
  <td class="code">{_e(", ".join(item.get('mx') or item.get('addresses') or []))}</td>
</tr>""")
    return f"""<h2><span class="en">Similar registered domains</span>
<span class="es">Dominios parecidos registrados</span></h2>
<div class="card"><table><thead><tr>
  <th><span class="en">Domain</span><span class="es">Dominio</span></th>
  <th><span class="en">Similarity</span><span class="es">Parecido</span></th>
  <th><span class="en">Mail</span><span class="es">Correo</span></th>
  <th>MX / A</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<p class="en" style="color:var(--muted);font-size:13px;margin:12px 0 0">
{lookalike.get('checked', 0)} of {lookalike.get('generated', 0)} generated candidates
resolved.</p>
<p class="es" style="color:var(--muted);font-size:13px;margin:12px 0 0">
Resolvieron {lookalike.get('checked', 0)} de {lookalike.get('generated', 0)} candidatos
generados.</p></div>"""


def _message_block(message: Optional[Dict[str, Any]]) -> str:
    if not message:
        return ""
    auth = message.get("auth_results") or {}
    chips = "".join(f"<span>{_e(k)}={_e(v)}</span>" for k, v in auth.items()) or (
        '<span class="en">no Authentication-Results</span>')
    attachments = ", ".join(a["filename"] for a in message.get("attachments") or []) or "—"
    return f"""<h2><span class="en">Analysed message</span>
<span class="es">Mensaje analizado</span></h2>
<div class="card">
<div class="meta">
  <div><span>Subject / Asunto</span>{_e(message.get('subject'))}</div>
  <div><span>Date / Fecha</span>{_e(message.get('date'))}</div>
  <div><span>From</span>{_e(message.get('from_display'))} &lt;{_e(message.get('from_address'))}&gt;</div>
  <div><span>Return-Path</span>{_e(message.get('return_path')) or '—'}</div>
  <div><span>Reply-To</span>{_e(message.get('reply_to')) or '—'}</div>
  <div><span>DKIM d=</span>{_e(', '.join(message.get('dkim_domains') or [])) or '—'}</div>
  <div><span>Hops / Saltos</span>{_e(message.get('received_hops'))}</div>
  <div><span>Attachments / Adjuntos</span>{_e(attachments)}</div>
</div>
<div class="ctrl" style="margin-top:14px">{chips}</div></div>"""


def render(
    posture: Dict[str, Any],
    findings: List[Finding],
    message: Optional[Dict[str, Any]] = None,
) -> str:
    value = scoring.score(findings, posture)
    counts = scoring.severity_counts(findings)
    statuses = scoring.control_status(findings, posture, with_message=bool(message))
    cov = scoring.coverage(posture)

    pills = "".join(
        f'<span class="pill" style="background:{s.colour}">{s.label} {counts[s.label]}</span>'
        for s in Severity if counts[s.label]
    ) or '<span class="pill" style="background:var(--ok)">0</span>'

    finding_html = []
    for finding in sort_findings(findings):
        controls = "".join(f"<span>{_e(c.ref)}</span>"
                           for c in catalog.resolve(finding.controls))
        if finding.reference:
            controls += (f'<span style="border-color:var(--accent);color:var(--accent)">'
                         f'{_e(finding.reference)}</span>')
        evidence = (f'<div class="ev">{_e(finding.short_evidence)}</div>'
                    if finding.short_evidence else "")
        finding_html.append(f"""
<article class="f" style="border-left-color:{finding.severity.colour}">
  <h3><span class="tag" style="background:{finding.severity.colour}">
    {finding.severity.label}</span>{_bi(finding.title)}
    <span class="fid">{_e(finding.id)}</span></h3>
  <p class="en">{_e(finding.detail.en)}</p>
  <p class="es">{_e(finding.detail.es)}</p>
  <div class="rec"><b class="en">Recommendation</b><b class="es">Recomendacion</b>
    <span class="en"> — {_e(finding.recommendation.en)}</span>
    <span class="es"> — {_e(finding.recommendation.es)}</span></div>
  <div class="ctrl">{controls}</div>{evidence}
</article>""")

    rows = []
    for ref in catalog.IN_SCOPE:
        entry = statuses[ref]
        control, state = entry["control"], entry["status"]
        related = ", ".join(f.id for f in entry["findings"]) or "—"
        rows.append(f"""<tr>
  <td class="code">{_e(control.ref)}</td>
  <td>{_bi(control.title)}</td>
  <td class="st {state.name}"><span class="en">{_e(state.en)}</span>
      <span class="es">{_e(state.es)}</span></td>
  <td class="code">{_e(related)}</td></tr>""")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>spoofscan — {_e(posture.get('domain'))}</title>
<style>{CSS}</style></head><body><div class="wrap">
<header><div><h1>spoofscan</h1>
  <p class="sub en">Email spoofing &amp; authentication audit — {_e(posture.get('domain'))}</p>
  <p class="sub es">Auditoria de suplantacion y autenticacion de correo — {_e(posture.get('domain'))}</p></div>
  <div class="toggle"><button data-lang="en" class="on">EN</button>
    <button data-lang="es">ES</button></div></header>

{_verdict_block(posture)}

<div class="grid">
  <div class="card gauge">{_gauge(value)}
    <div class="val">{value if value is not None else '—'}<span
      style="font-size:16px;color:var(--muted)">{'/100' if value is not None else ''}</span></div>
    <div class="grade">{
      f'<span class="en">grade {scoring.grade(value)}</span>'
      f'<span class="es">nota {scoring.grade(value)}</span>'
      if value is not None else
      '<span class="en">not scored: nothing could be evaluated</span>'
      '<span class="es">sin nota: no se ha evaluado nada</span>'
    }</div></div>
  <div class="card"><div class="meta">
    <div><span class="en">Domain</span><span class="es">Dominio</span>{_e(posture.get('domain'))}</div>
    <div><span class="en">Checked</span><span class="es">Comprobado</span>{_e(posture.get('collected_at'))}</div>
    <div><span class="en">Checks evaluated</span><span class="es">Comprobaciones</span>{cov['evaluated']}/{cov['applicable']}</div>
    <div><span class="en">DNS queries</span><span class="es">Consultas DNS</span>{_e((posture.get('collection') or {}).get('queries'))}</div>
  </div><div class="pills">{pills}</div></div>
</div>

{_message_block(message)}

<h2><span class="en">Findings</span><span class="es">Hallazgos</span></h2>
{''.join(finding_html) or (
  '<div class="card"><p class="en">No findings.</p>'
  '<p class="es">Sin hallazgos.</p></div>' if value is not None else
  '<div class="card"><p class="en">No findings, but no check ran either: absence of '
  'evidence, not evidence of absence.</p><p class="es">Sin hallazgos, pero tampoco se ha '
  'ejecutado ninguna comprobacion: ausencia de evidencia, no evidencia de ausencia.</p></div>'
)}

{_lookalike_block(posture)}
{_suggested_records(posture)}

<h2><span class="en">Control status (Statement of Applicability)</span>
    <span class="es">Estado de los controles (declaracion de aplicabilidad)</span></h2>
<div class="card"><table><thead><tr>
  <th>Control</th>
  <th><span class="en">Title</span><span class="es">Titulo</span></th>
  <th><span class="en">Status</span><span class="es">Estado</span></th>
  <th><span class="en">Findings</span><span class="es">Hallazgos</span></th>
</tr></thead><tbody>{''.join(rows)}</tbody></table></div>

<footer>
<p class="en">Read-only assessment built from public DNS records and, where published, the
domain's own MTA-STS policy. No mail was sent and no system was accessed. The ENS / ISO
cross-mapping is orientative and does not replace the organisation's Statement of
Applicability.</p>
<p class="es">Evaluacion de solo lectura a partir de registros DNS publicos y, cuando esta
publicada, la propia politica MTA-STS del dominio. No se ha enviado ningun correo ni se ha
accedido a ningun sistema. El mapeo ENS / ISO es orientativo y no sustituye a la declaracion de
aplicabilidad de la organizacion.</p>
</footer></div><script>{JS}</script></body></html>"""
