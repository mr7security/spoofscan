"""Forensic reading of a received message (.eml), as pure functions.

This answers the question asked the morning after: *this got through, why?*
It never contacts the network and never renders anything; it only parses the
file with the standard library and reports what the headers already say.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_bytes, message_from_string, policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from typing import Any, Dict, List, Optional, Tuple

#: Extensions that execute or can carry macros.
DANGEROUS_EXTENSIONS = (
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".wsh", ".hta", ".msi", ".msp", ".jar", ".ps1", ".lnk",
    ".reg", ".cpl", ".dll", ".iso", ".img", ".vhd", ".chm", ".application",
)
MACRO_EXTENSIONS = (".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xls", ".doc")
ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z", ".gz", ".ace", ".cab")

URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)
IP_URL_RE = re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}(?::\d+)?(/|$)", re.IGNORECASE)


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int

    @property
    def extension(self) -> str:
        _, _, ext = self.filename.lower().rpartition(".")
        return f".{ext}" if ext else ""

    @property
    def double_extension(self) -> bool:
        parts = self.filename.lower().split(".")
        if len(parts) < 3:
            return False
        return f".{parts[-2]}" in (".pdf", ".doc", ".docx", ".jpg", ".png", ".txt", ".xls")


@dataclass
class Message:
    """Everything spoofscan needs to know about a received message."""

    subject: str = ""
    date: str = ""
    message_id: str = ""
    from_display: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: List[str] = field(default_factory=list)
    auth_results: Dict[str, str] = field(default_factory=dict)
    dkim_domains: List[str] = field(default_factory=list)
    received: List[str] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    headers_present: List[str] = field(default_factory=list)
    auth_headers: int = 0
    auth_verified: bool = False
    from_headers: int = 0
    parse_error: Optional[str] = None

    @property
    def from_domain(self) -> str:
        return _domain_of(self.from_address)

    @property
    def return_path_domain(self) -> str:
        return _domain_of(self.return_path)

    @property
    def reply_to_domain(self) -> str:
        return _domain_of(self.reply_to)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "date": self.date,
            "message_id": self.message_id,
            "from_display": self.from_display,
            "from_address": self.from_address,
            "from_domain": self.from_domain,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "to": self.to,
            "auth_results": self.auth_results,
            "dkim_domains": self.dkim_domains,
            "received_hops": len(self.received),
            "auth_headers": self.auth_headers,
            "auth_verified": self.auth_verified,
            "from_headers": self.from_headers,
            "received": self.received,
            "attachments": [
                {"filename": a.filename, "content_type": a.content_type, "size": a.size}
                for a in self.attachments
            ],
            "urls": self.urls,
            "parse_error": self.parse_error,
        }


def _domain_of(address: str) -> str:
    _, _, domain = (address or "").partition("@")
    return domain.strip().strip(">").lower()


def _clean(value: Optional[str]) -> str:
    return " ".join(str(value).split()) if value else ""


def parse_authentication_results(
    headers: List[str], authserv_id: Optional[str] = None
) -> Dict[str, str]:
    """Extract the spf/dkim/dmarc verdicts written by the receiving MTA.

    Only the first (topmost) header is authoritative: anything below it was
    added before the message reached the recipient's boundary and can have been
    forged by the sender. When ``authserv_id`` is given, headers that do not
    carry it are ignored entirely — without it, a message can arrive with a
    self-issued "everything passed" header and no way to tell.

    For each method the *worst* verdict in the header is kept, so a header that
    states ``dkim=pass ... dkim=fail`` is not read as a pass.
    """
    results: Dict[str, str] = {}
    if not headers:
        return results
    top = headers[0]
    if authserv_id:
        matching = [h for h in headers
                    if h.split(";")[0].strip().lower().startswith(authserv_id.lower())]
        if not matching:
            return results
        top = matching[0]
    for method in ("spf", "dkim", "dmarc", "arc", "compauth"):
        verdicts = [m.lower() for m in
                    re.findall(rf"(?<![\w.-]){method}\s*=\s*([a-zA-Z]+)", top)]
        if verdicts:
            results[method] = min(verdicts, key=_verdict_rank)
    match = re.search(r"header\.from\s*=\s*([^\s;()]+)", top, re.IGNORECASE)
    if match:
        results["header.from"] = match.group(1).lower().strip('"')
    match = re.search(r"smtp\.mailfrom\s*=\s*([^\s;()]+)", top, re.IGNORECASE)
    if match:
        results["smtp.mailfrom"] = match.group(1).lower().strip('"')
    return results


#: Worst first, so that min() picks the least favourable verdict present.
_VERDICT_ORDER = ("fail", "permerror", "temperror", "softfail", "policy",
                  "neutral", "none", "bestguesspass", "pass")


def _verdict_rank(verdict: str) -> int:
    try:
        return _VERDICT_ORDER.index(verdict)
    except ValueError:
        return len(_VERDICT_ORDER)


def _dkim_domains(headers: List[str]) -> List[str]:
    domains = []
    for header in headers:
        match = re.search(r"\bd\s*=\s*([^\s;]+)", header)
        if match:
            domains.append(match.group(1).lower().rstrip("."))
    return domains


def load(raw: bytes, authserv_id: Optional[str] = None) -> Message:
    """Parse a raw .eml. A malformed file yields a Message with parse_error set."""
    try:
        parsed: EmailMessage = message_from_bytes(raw, policy=policy.default)
    except Exception as exc:                       # pragma: no cover - defensive
        try:
            parsed = message_from_string(raw.decode("latin-1"), policy=policy.default)
        except Exception:
            return Message(parse_error=f"{type(exc).__name__}: {exc}")

    message = Message()
    try:
        message.subject = _clean(parsed.get("Subject"))
        message.date = _clean(parsed.get("Date"))
        message.message_id = _clean(parsed.get("Message-ID"))
        display, address = parseaddr(_clean(parsed.get("From")))
        message.from_display, message.from_address = display, address.lower()
        message.reply_to = parseaddr(_clean(parsed.get("Reply-To")))[1].lower()
        message.return_path = parseaddr(_clean(parsed.get("Return-Path")))[1].lower()
        message.to = [a.lower() for _, a in getaddresses(parsed.get_all("To") or []) if a]
        auth_headers = [_clean(h) for h in parsed.get_all("Authentication-Results") or []]
        message.auth_results = parse_authentication_results(auth_headers, authserv_id)
        message.auth_headers = len(auth_headers)
        message.auth_verified = bool(authserv_id) and bool(message.auth_results)
        message.from_headers = len(parsed.get_all("From") or [])
        message.dkim_domains = _dkim_domains(
            [_clean(h) for h in parsed.get_all("DKIM-Signature") or []]
        )
        message.received = [_clean(h) for h in parsed.get_all("Received") or []]
        message.headers_present = [name for name, _ in parsed.items()]
        message.attachments = _attachments(parsed)
        message.urls = _urls(parsed)
    except Exception as exc:                       # pragma: no cover - defensive
        message.parse_error = f"{type(exc).__name__}: {exc}"
    return message


def _attachments(parsed: EmailMessage) -> List[Attachment]:
    out: List[Attachment] = []
    for part in parsed.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        if not filename and disposition != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        out.append(Attachment(
            filename=_clean(filename) or "(unnamed)",
            content_type=part.get_content_type(),
            size=len(payload),
        ))
    return out


def _urls(parsed: EmailMessage) -> List[str]:
    found: List[str] = []
    for part in parsed.walk():
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        try:
            text = payload.decode(part.get_content_charset() or "utf-8", "replace")
        except (LookupError, UnicodeError):
            # A charset the sender invented must not disable the analysis.
            text = payload.decode("latin-1", "replace")
        found.extend(URL_RE.findall(text))
    seen, unique = set(), []
    for url in found:
        url = url.rstrip('.,;")')
        if url.lower() not in seen:
            seen.add(url.lower())
            unique.append(url)
    return unique[:200]


# --------------------------------------------------------------------------
# Derived observations, all pure
# --------------------------------------------------------------------------

def display_name_spoof(message: Message) -> Optional[str]:
    """A display name that itself contains a different address."""
    match = re.search(r"[\w\.\-\+]+@[\w\.\-]+", message.from_display or "")
    if not match:
        return None
    embedded = match.group(0).lower()
    if embedded != message.from_address:
        return embedded
    return None


def alignment(message: Message) -> Dict[str, Optional[bool]]:
    """DMARC-style alignment between the visible From and the other identities."""
    from_domain = message.from_domain
    result: Dict[str, Optional[bool]] = {"spf": None, "dkim": None, "reply_to": None}
    if from_domain and message.return_path_domain:
        result["spf"] = _aligned(from_domain, message.return_path_domain)
    if from_domain and message.dkim_domains:
        result["dkim"] = any(_aligned(from_domain, d) for d in message.dkim_domains)
    if from_domain and message.reply_to_domain:
        result["reply_to"] = _aligned(from_domain, message.reply_to_domain)
    return result


def _aligned(a: str, b: str) -> bool:
    """Relaxed DMARC alignment (RFC 7489 section 3.1.2).

    Both identifiers align when they share an organisational domain, so
    ``news.corp.example`` and ``mail.corp.example`` align with each other and
    not only with their parent. The organisational domain is approximated from
    the public suffix heuristics in :mod:`spoofscan.lookalike` rather than from
    the full Public Suffix List, which is documented as a limitation.
    """
    from .lookalike import split_domain

    a, b = (a or "").lower().rstrip("."), (b or "").lower().rstrip(".")
    if not a or not b:
        return False
    if a == b:
        return True
    label_a, suffix_a = split_domain(a)
    label_b, suffix_b = split_domain(b)
    return (label_a, suffix_a) == (label_b, suffix_b)


def suspicious_urls(message: Message) -> List[Tuple[str, str]]:
    """URLs worth a second look, each with the reason."""
    out: List[Tuple[str, str]] = []
    for url in message.urls:
        host = re.sub(r"^https?://", "", url).split("/")[0].split("@")[-1].lower()
        if IP_URL_RE.match(url):
            out.append((url, "ip-literal"))
        elif "xn--" in host:
            out.append((url, "punycode"))
        elif host.count(".") >= 4:
            out.append((url, "deep-subdomain"))
        elif "@" in url.split("//", 1)[-1].split("/")[0]:
            out.append((url, "userinfo"))
    return out


def risky_attachments(message: Message) -> List[Tuple[Attachment, str]]:
    out: List[Tuple[Attachment, str]] = []
    for attachment in message.attachments:
        if attachment.extension in DANGEROUS_EXTENSIONS:
            reason = "executable-double-extension" if attachment.double_extension else "executable"
            out.append((attachment, reason))
        elif attachment.double_extension:
            out.append((attachment, "double-extension"))
        elif attachment.extension in MACRO_EXTENSIONS:
            out.append((attachment, "macro-capable"))
        elif attachment.extension in ARCHIVE_EXTENSIONS:
            out.append((attachment, "archive"))
    return out
