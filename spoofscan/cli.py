"""Command line interface: argument parsing and orchestration."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from . import __version__, catalog, checks, collector, dns, eml, report_console, report_html, scoring
from .models import Finding, sort_findings

BANNER = {
    "en": "spoofscan - can someone send mail as your domain?",
    "es": "spoofscan - puede alguien enviar correo como su dominio?",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spoofscan",
        description=(
            "Read-only audit of the email authentication posture of a domain (SPF, DKIM, "
            "DMARC, MTA-STS, TLS-RPT, DNSSEC), of the domains that could impersonate it, "
            "and optionally of a received message, mapped to ENS and ISO/IEC 27001 controls."
        ),
        epilog="Only audit domains you own or are authorised to assess.",
    )
    parser.add_argument("domain", nargs="*", help="domain(s) to audit")
    parser.add_argument("--domains-file", metavar="PATH",
                        help="read domains from a file, one per line")
    parser.add_argument("-o", "--output", default="report.html",
                        help="HTML report path (default: report.html); with several domains "
                             "the name is used as a prefix")
    parser.add_argument("--no-report", action="store_true", help="do not write the HTML report")
    parser.add_argument("--json", nargs="?", const="-", metavar="PATH",
                        help="write JSON results to PATH, or stdout if PATH is omitted")
    parser.add_argument("--soa", nargs="?", const="soa.xlsx", metavar="PATH",
                        help="write the Statement of Applicability workbook (needs openpyxl)")
    parser.add_argument("--posture", metavar="PATH",
                        help="save the raw collected posture, for evidence archival")
    parser.add_argument("--from-posture", metavar="PATH",
                        help="re-evaluate a saved posture instead of querying DNS")
    parser.add_argument("--eml", metavar="PATH",
                        help="also analyse a received message (.eml)")
    parser.add_argument("--authserv-id", metavar="ID",
                        help="identifier of your own mail gateway, so that only the "
                             "Authentication-Results header it wrote is trusted")
    parser.add_argument("--selectors", metavar="LIST",
                        help="comma separated DKIM selectors to probe instead of the defaults")
    parser.add_argument("--no-lookalike", action="store_true",
                        help="skip the search for similar registered domains")
    parser.add_argument("--lookalike-limit", type=int, default=400, metavar="N",
                        help="maximum number of similar domains to test (default: 400)")
    parser.add_argument("--no-mta-sts-fetch", action="store_true",
                        help="do not fetch the MTA-STS policy over HTTPS, DNS only")
    parser.add_argument("--resolver", metavar="IP", action="append",
                        help="DNS server to use; repeat for several (default: system)")
    parser.add_argument("--timeout", type=float, default=dns.DEFAULT_TIMEOUT, metavar="SECONDS",
                        help="DNS timeout in seconds (default: 5)")
    parser.add_argument("--lang", choices=["en", "es"], default="es",
                        help="console language; the HTML report is always bilingual")
    parser.add_argument("--quiet", action="store_true", help="suppress the console report")
    parser.add_argument("--version", action="version", version=f"spoofscan {__version__}")
    return parser


def _domains(args: argparse.Namespace) -> List[str]:
    domains = list(args.domain)
    if args.domains_file:
        with open(args.domains_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.split("#", 1)[0].strip()
                if line:
                    domains.append(line)
    seen, unique = set(), []
    for domain in domains:
        key = domain.lower().strip().rstrip(".")
        if key and key not in seen:
            seen.add(key)
            unique.append(key)
    return unique


_SECTIONS = ("collection", "spf", "dkim", "dmarc", "mx", "dnssec", "mta_sts",
             "tls_rpt", "dane", "lookalike")


def _sanitise(posture: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise an externally supplied posture: it is evidence, not input we trust."""
    clean = dict(posture)
    domain = clean.get("domain")
    clean["domain"] = domain if isinstance(domain, str) else ""
    for section in _SECTIONS:
        if not isinstance(clean.get(section), dict):
            clean[section] = {}
    return clean


def _serialise(
    posture: Dict[str, Any],
    findings: List[Finding],
    message: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    statuses = scoring.control_status(findings, posture, with_message=bool(message))
    value = scoring.score(findings, posture)
    return {
        "tool": "spoofscan",
        "version": __version__,
        "domain": posture.get("domain"),
        "collected_at": posture.get("collected_at"),
        "spoofable": checks.spoofable(posture),
        "score": value,
        "grade": scoring.grade(value),
        "coverage": scoring.coverage(posture),
        "severity_counts": scoring.severity_counts(findings),
        "findings": [f.as_dict("en") for f in sort_findings(findings)],
        "findings_es": [f.as_dict("es") for f in sort_findings(findings)],
        "controls": [
            {
                **statuses[ref]["control"].as_dict("en"),
                "status": statuses[ref]["status"].en,
                "findings": [f.id for f in statuses[ref]["findings"]],
            }
            for ref in catalog.IN_SCOPE
        ],
        "message": message,
        "posture": posture,
    }


def _write(path: str, content: str, label: str, quiet: bool) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
    except OSError as exc:
        print(f"error: cannot write the {label}: {exc}", file=sys.stderr)
        return False
    if not quiet:
        print(f"[+] {label:<8}-> {path}")
    return True


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    lang = args.lang

    if args.lookalike_limit < 0:
        print("error: --lookalike-limit cannot be negative", file=sys.stderr)
        return 1

    message: Optional[Dict[str, Any]] = None
    message_findings: List[Finding] = []
    if args.eml:
        try:
            with open(args.eml, "rb") as handle:
                raw = handle.read()
        except OSError as exc:
            print(f"error: cannot read the message: {exc}", file=sys.stderr)
            return 1
        parsed_message = eml.load(raw, args.authserv_id)
        message = parsed_message.as_dict()
        message_findings = checks.check_message(parsed_message)

    postures: List[Dict[str, Any]] = []
    if args.from_posture:
        try:
            loaded = collector.load_posture(args.from_posture)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read the posture file: {exc}", file=sys.stderr)
            return 1
        if not isinstance(loaded, dict):
            print("error: the posture file must contain a JSON object", file=sys.stderr)
            return 1
        postures.append(_sanitise(loaded))
    else:
        try:
            domains = _domains(args)
        except OSError as exc:
            print(f"error: cannot read the domain list: {exc}", file=sys.stderr)
            return 1
        if not domains:
            print("error: give at least one domain, or use --from-posture", file=sys.stderr)
            return 1
        resolver = dns.Resolver(servers=args.resolver, timeout=args.timeout)
        if not resolver.servers:
            print("error: no DNS resolver found; pass --resolver 9.9.9.9", file=sys.stderr)
            return 1
        selectors = [s.strip() for s in args.selectors.split(",")] if args.selectors else None
        if not args.quiet:
            print(BANNER[lang])
        for domain in domains:
            if not args.quiet:
                print(f"  · {domain}")
            resolver.queries = 0
            postures.append(collector.collect(
                domain,
                resolver=resolver,
                selectors=selectors,
                check_lookalikes=not args.no_lookalike,
                lookalike_limit=args.lookalike_limit,
                fetch_mta_sts=not args.no_mta_sts_fetch,
            ))

    results = []
    for index, posture in enumerate(postures):
        findings = checks.run_domain(posture)
        # The message is analysed once and attached to the first domain audited.
        attached = message if index == 0 else None
        if attached:
            findings = findings + message_findings
        results.append({"posture": posture, "findings": findings, "message": attached})

    if not args.quiet:
        print()
        for item in results:
            print(report_console.render(
                item["posture"], item["findings"], lang, item["message"]))
            print()
        if len(results) > 1:
            print(report_console.render_summary(results, lang))

    exit_status = 0
    for item in results:
        exit_status = max(exit_status, scoring.exit_code(item["findings"]))

    multiple = len(results) > 1
    if not args.no_report:
        for item in results:
            path = args.output
            if multiple:
                stem, _, extension = args.output.rpartition(".")
                stem = stem or args.output
                path = f"{stem}-{item['posture'].get('domain')}.{extension or 'html'}"
            document = report_html.render(item["posture"], item["findings"], item["message"])
            if not _write(path, document, "HTML", args.quiet):
                return 1

    if args.json:
        payload = [_serialise(i["posture"], i["findings"], i["message"]) for i in results]
        text = json.dumps(payload if multiple else payload[0], indent=2, default=str)
        if args.json == "-":
            print(text)
        elif not _write(args.json, text, "JSON", args.quiet):
            return 1

    if args.posture:
        text = json.dumps(
            [i["posture"] for i in results] if multiple else results[0]["posture"],
            indent=2, default=str,
        )
        if not _write(args.posture, text, "Posture", args.quiet):
            return 1

    if args.soa:
        from . import report_soa
        for item in results:
            path = args.soa
            if multiple:
                stem, _, extension = args.soa.rpartition(".")
                stem = stem or args.soa
                path = f"{stem}-{item['posture'].get('domain')}.{extension or 'xlsx'}"
            try:
                report_soa.write(path, item["posture"], item["findings"], lang,
                                 with_message=bool(item["message"]))
            except (RuntimeError, OSError) as exc:
                print(f"error: cannot write the SoA workbook: {exc}", file=sys.stderr)
                return 1
            if not args.quiet:
                print(f"[+] {'SoA':<8}-> {path}")

    return exit_status


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
