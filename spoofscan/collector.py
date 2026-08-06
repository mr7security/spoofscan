"""Read-only collection of the email authentication posture of a domain.

Everything here is a public DNS query plus, for MTA-STS, one HTTPS GET of a
policy file that the standard requires to be published. No mail is sent, no
account is touched, and nothing identifies the audited organisation to anyone
other than the resolver already in use.

As in the rest of the suite, a value that could not be determined is ``None``
and never a default that a rule could mistake for evidence.
"""
from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import dkim as dkim_mod
from . import dmarc as dmarc_mod
from . import dns as dns_mod
from . import lookalike as lookalike_mod
from . import spf as spf_mod

MTA_STS_TIMEOUT = 8


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """RFC 8461 section 3.3: an MTA-STS policy must not be fetched via a redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            newurl, code, "redirect refused: the policy must be served directly",
            headers, fp,
        )


def _txt_strings(answer: dns_mod.Answer) -> Optional[List[str]]:
    if not answer.determinable:
        return None
    return [r for r in answer.records if isinstance(r, str)]


def collect_spf(resolver: dns_mod.Resolver, domain: str) -> Dict[str, Any]:
    answer = resolver.txt(domain)
    strings = _txt_strings(answer)
    if strings is None:
        return {"determinable": False, "records": None, "parsed": None,
                "lookups": None, "unresolved_includes": None}

    records = spf_mod.find_records(strings)
    if not records:
        return {"determinable": True, "records": [], "parsed": None,
                "lookups": None, "unresolved_includes": None}

    parsed = spf_mod.parse(records[0])
    unresolved: List[str] = []
    cache: Dict[str, Optional[spf_mod.SPFRecord]] = {}

    def resolve_include(name: str) -> Optional[spf_mod.SPFRecord]:
        if spf_mod.has_macro(name):
            # Expands per message; it is not a broken include.
            return None
        if name in cache:
            return cache[name]
        nested_answer = resolver.txt(name)
        nested_strings = _txt_strings(nested_answer)
        nested = None
        if nested_strings is not None:
            nested_records = spf_mod.find_records(nested_strings)
            if nested_records:
                nested = spf_mod.parse(nested_records[0])
            else:
                unresolved.append(name)
        cache[name] = nested
        return nested

    lookups = spf_mod.count_lookups(parsed, resolve_include)
    return {
        "determinable": True,
        "records": records,
        "parsed": {
            "raw": parsed.raw,
            "all": parsed.all_qualifier,
            "includes": parsed.includes,
            "redirect": parsed.redirect,
            "has_ptr": parsed.has_ptr,
            "mechanisms": [str(m) for m in parsed.mechanisms],
            "errors": parsed.errors,
        },
        "lookups": lookups,
        "unresolved_includes": sorted(set(unresolved)),
    }


def collect_dmarc(resolver: dns_mod.Resolver, domain: str) -> Dict[str, Any]:
    answer = resolver.txt(f"_dmarc.{domain}")
    strings = _txt_strings(answer)
    if strings is None:
        return {"determinable": False, "records": None, "parsed": None,
                "external_reports": None}

    records = dmarc_mod.find_records(strings)
    if not records:
        return {"determinable": True, "records": [], "parsed": None, "external_reports": None}

    parsed = dmarc_mod.parse(records[0])
    external: Dict[str, Optional[bool]] = {}
    for host in dmarc_mod.external_report_domains(parsed, domain):
        auth = resolver.txt(f"{domain}._report._dmarc.{host}")
        strings = _txt_strings(auth)
        external[host] = None if strings is None else any(
            s.strip().lower().startswith("v=dmarc1") for s in strings
        )
    return {
        "determinable": True,
        "records": records,
        "parsed": {
            "raw": parsed.raw,
            "policy": parsed.policy,
            "subdomain_policy": parsed.subdomain_policy,
            "effective_subdomain_policy": parsed.effective_subdomain_policy,
            "percentage": parsed.percentage,
            "rua": parsed.aggregate_reports,
            "ruf": parsed.forensic_reports,
            "aspf": parsed.spf_alignment,
            "adkim": parsed.dkim_alignment,
            "enforcing": parsed.enforcing,
            "errors": parsed.errors,
        },
        "external_reports": external or None,
    }


def collect_dkim(
    resolver: dns_mod.Resolver, domain: str, selectors: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Probe well-known selectors.

    DKIM selectors cannot be enumerated from DNS, so finding none proves
    nothing: the result says ``found: []`` and the rules treat the absence as
    undetermined rather than as a failure.
    """
    probed = list(selectors or dkim_mod.COMMON_SELECTORS)
    found: List[Dict[str, Any]] = []
    determinable = False
    for selector in probed:
        answer = resolver.txt(f"{selector}._domainkey.{domain}")
        strings = _txt_strings(answer)
        if strings is None:
            continue
        determinable = True
        for value in strings:
            if not dkim_mod.is_dkim(value):
                continue
            key = dkim_mod.parse(selector, value)
            found.append({
                "selector": selector,
                "key_type": key.key_type,
                "bits": key.bits,
                "revoked": key.revoked,
                "testing": key.testing,
                "errors": key.errors,
            })
    return {"determinable": determinable, "probed": probed, "found": found}


def collect_mx(resolver: dns_mod.Resolver, domain: str) -> Dict[str, Any]:
    answer = resolver.mx(domain)
    if not answer.determinable:
        return {"determinable": False, "records": None, "null_mx": None}
    records = [
        {"preference": r.preference, "exchange": r.exchange.rstrip(".")}
        for r in answer.records if isinstance(r, dns_mod.MXRecord)
    ]
    # RFC 7505: the null MX is exactly one record, preference 0, exchange root.
    null_mx = (
        len(records) == 1
        and records[0]["exchange"] in ("", ".")
        and records[0]["preference"] == 0
    )
    return {"determinable": True, "records": records, "null_mx": null_mx}


def collect_dnssec(resolver: dns_mod.Resolver, domain: str) -> Dict[str, Any]:
    """DNSSEC state as far as the configured resolver can tell.

    ``authenticated`` reflects the AD flag, which is only meaningful when the
    resolver validates; ``ds`` is the delegation signer at the parent.
    """
    soa = resolver.query(domain, dns_mod.SOA)
    ds = resolver.query(domain, dns_mod.DS)
    return {
        "determinable": soa.determinable and ds.determinable,
        "authenticated": soa.authenticated if soa.determinable else None,
        "ds": bool(ds.records) if ds.determinable else None,
    }


def collect_mta_sts(resolver: dns_mod.Resolver, domain: str, fetch: bool = True) -> Dict[str, Any]:
    answer = resolver.txt(f"_mta-sts.{domain}")
    strings = _txt_strings(answer)
    if strings is None:
        return {"determinable": False, "record": None, "policy": None, "mode": None}
    records = [s for s in strings if s.strip().lower().startswith("v=stsv1")]
    result: Dict[str, Any] = {
        "determinable": True,
        "record": records[0] if records else None,
        "policy": None,
        "mode": None,
        "policy_error": None,
    }
    if not records or not fetch:
        return result

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        context = ssl.create_default_context()
        request = urllib.request.Request(url, headers={"User-Agent": "spoofscan"})
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(request, timeout=MTA_STS_TIMEOUT) as response:
            if response.status != 200:
                result["policy_error"] = f"HTTP {response.status}"
                return result
            content_type = (response.headers.get("Content-Type") or "").split(";")[0].strip()
            body = response.read(65536).decode("utf-8", "replace")
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError, ValueError) as exc:
        result["policy_error"] = f"{type(exc).__name__}: {exc}"
        return result

    del context  # the default opener already validates the certificate chain
    if content_type and content_type != "text/plain":
        result["policy_error"] = f"unexpected Content-Type {content_type}"
        return result

    policy: Dict[str, Any] = {"mx": []}
    for line in body.splitlines():
        name, _, value = line.partition(":")
        name, value = name.strip().lower(), value.strip()
        if name == "mx":
            policy["mx"].append(value)
        elif name:
            policy[name] = value

    missing = [tag for tag in ("version", "mode", "max_age") if tag not in policy]
    if not policy["mx"]:
        missing.append("mx")
    if missing:
        result["policy_error"] = "policy missing mandatory field(s): " + ", ".join(missing)
        return result

    result["policy"] = policy
    result["mode"] = (policy.get("mode") or "").lower() or None
    return result


def collect_tls_rpt(resolver: dns_mod.Resolver, domain: str) -> Dict[str, Any]:
    answer = resolver.txt(f"_smtp._tls.{domain}")
    strings = _txt_strings(answer)
    if strings is None:
        return {"determinable": False, "record": None}
    records = [s for s in strings if s.strip().lower().startswith("v=tlsrptv1")]
    return {"determinable": True, "record": records[0] if records else None}


def collect_dane(resolver: dns_mod.Resolver, mx_hosts: List[str]) -> Dict[str, Any]:
    if not mx_hosts:
        return {"determinable": False, "hosts": {}}
    hosts: Dict[str, Optional[bool]] = {}
    for host in mx_hosts[:5]:
        answer = resolver.query(f"_25._tcp.{host}", dns_mod.TLSA)
        hosts[host] = bool(answer.records) if answer.determinable else None
    return {"determinable": any(v is not None for v in hosts.values()), "hosts": hosts}


def collect_lookalikes(
    resolver: dns_mod.Resolver, domain: str, limit: int = 400
) -> Dict[str, Any]:
    """Which impersonation candidates are actually registered and mail-capable."""
    candidates = lookalike_mod.generate(domain, limit=limit)
    registered: List[Dict[str, Any]] = []
    checked = 0
    for candidate in candidates:
        name = candidate["domain"]
        a_answer = resolver.a(name)
        mx_answer = resolver.mx(name)
        if not a_answer.determinable and not mx_answer.determinable:
            continue
        checked += 1
        has_a = bool(a_answer.records)
        has_mx = bool(mx_answer.records)
        if not (has_a or has_mx):
            continue
        registered.append({
            "domain": name,
            "kind": candidate["kind"],
            "addresses": [r for r in a_answer.records if isinstance(r, str)][:3],
            "mx": [r.exchange.rstrip(".") for r in mx_answer.records
                   if isinstance(r, dns_mod.MXRecord)][:3],
            "can_receive_mail": has_mx,
        })
    return {
        "determinable": checked > 0,
        "generated": len(candidates),
        "checked": checked,
        "registered": registered,
    }


def collect(
    domain: str,
    resolver: Optional[dns_mod.Resolver] = None,
    selectors: Optional[List[str]] = None,
    check_lookalikes: bool = True,
    lookalike_limit: int = 400,
    fetch_mta_sts: bool = True,
) -> Dict[str, Any]:
    """Collect the full posture of one domain."""
    resolver = resolver or dns_mod.Resolver()
    domain = domain.strip().lower().rstrip(".")

    soa = resolver.query(domain, dns_mod.SOA)
    a_answer = resolver.a(domain)
    resolvable = soa.determinable and (
        bool(soa.records) or bool(a_answer.records) or not soa.nxdomain
    )

    mx = collect_mx(resolver, domain)
    mx_hosts = [r["exchange"] for r in (mx["records"] or []) if r["exchange"]]

    posture: Dict[str, Any] = {
        "domain": domain,
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "collection": {
            "resolvers": list(resolver.servers),
            "resolvable": bool(resolvable),
            "nxdomain": soa.nxdomain,
            "queries": resolver.queries,
        },
        "spf": collect_spf(resolver, domain),
        "dkim": collect_dkim(resolver, domain, selectors),
        "dmarc": collect_dmarc(resolver, domain),
        "mx": mx,
        "dnssec": collect_dnssec(resolver, domain),
        "mta_sts": collect_mta_sts(resolver, domain, fetch=fetch_mta_sts),
        "tls_rpt": collect_tls_rpt(resolver, domain),
        "dane": collect_dane(resolver, mx_hosts),
        "lookalike": (
            collect_lookalikes(resolver, domain, lookalike_limit)
            if check_lookalikes else
            {"determinable": False, "generated": 0, "checked": 0, "registered": []}
        ),
    }
    posture["collection"]["queries"] = resolver.queries
    return posture


def load_posture(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)
