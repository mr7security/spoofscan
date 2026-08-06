"""A small DNS client built on the standard library.

spoofscan asks for record types that no standard library function exposes
(TXT, MX, DS, TLSA), so rather than depend on dnspython the wire format is
built and parsed here. That keeps the tool installable on a locked-down
machine with nothing but Python, which is usually the machine you are asked
to audit from.

The parser is deliberately strict about lengths and pointer loops: it reads
data that comes from the network.
"""
from __future__ import annotations

import os
import random
import re
import shutil
import socket
import struct
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

A, AAAA, CNAME, DS, MX, NS, SOA, TLSA, TXT = 1, 28, 5, 43, 15, 2, 6, 52, 16

TYPE_NAMES = {A: "A", AAAA: "AAAA", CNAME: "CNAME", DS: "DS", MX: "MX",
              NS: "NS", SOA: "SOA", TLSA: "TLSA", TXT: "TXT"}

#: DNS RCODEs we care to tell apart.
NOERROR, FORMERR, SERVFAIL, NXDOMAIN = 0, 1, 2, 3

DEFAULT_TIMEOUT = 5.0
MAX_UDP = 4096


class DNSError(Exception):
    """Raised when a query cannot be completed at all."""


@dataclass
class Answer:
    """The outcome of one query. ``records`` is empty on NXDOMAIN/NODATA."""

    name: str
    qtype: int
    rcode: int = NOERROR
    records: List[object] = field(default_factory=list)
    authenticated: bool = False   # AD flag: the resolver validated DNSSEC
    truncated: bool = False
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.rcode == NOERROR

    @property
    def exists(self) -> bool:
        return self.ok and bool(self.records)

    @property
    def nxdomain(self) -> bool:
        return self.rcode == NXDOMAIN

    @property
    def determinable(self) -> bool:
        """False when the query failed outright, so no conclusion is possible."""
        return self.error is None and self.rcode in (NOERROR, NXDOMAIN)


@dataclass
class MXRecord:
    preference: int
    exchange: str


# --------------------------------------------------------------------------
# Wire format
# --------------------------------------------------------------------------

def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        if len(raw) > 63:
            raise DNSError(f"label too long: {label}")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode a possibly compressed name; returns (name, offset after it)."""
    labels: List[str] = []
    jumped = False
    end = offset
    seen = set()
    while True:
        if offset >= len(data):
            raise DNSError("truncated name")
        length = data[offset]
        if length & 0xC0 == 0xC0:                      # compression pointer
            if offset + 1 >= len(data):
                raise DNSError("truncated pointer")
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            if pointer in seen:
                raise DNSError("compression loop")
            seen.add(pointer)
            if not jumped:
                end = offset + 2
                jumped = True
            offset = pointer
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("latin-1"))
        offset += length
    if not jumped:
        end = offset
    return ".".join(labels), end


def build_query(name: str, qtype: int, want_ad: bool = True) -> Tuple[bytes, int]:
    """Build a recursive query.

    The AD bit is set in the request, which RFC 6840 section 5.7 redefines as
    "tell me whether you validated" — that is all spoofscan needs. The DO bit is
    deliberately not set: asking for the DNSSEC records themselves would bloat
    every answer with signatures this tool never reads.
    """
    tid = random.SystemRandom().randint(0, 0xFFFF)
    flags = 0x0100                                    # RD
    if want_ad:
        flags |= 0x0020                               # AD
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 1)
    question = encode_name(name) + struct.pack(">HH", qtype, 1)
    # EDNS0 OPT: root name, type 41, class = advertised UDP payload size.
    additional = b"\x00" + struct.pack(">HHIH", 41, MAX_UDP, 0, 0)
    return header + question + additional, tid


def parse_response(
    data: bytes,
    tid: Optional[int] = None,
    expect_name: Optional[str] = None,
    expect_type: Optional[int] = None,
) -> Answer:
    """Parse a response, refusing anything that does not answer what was asked.

    Off-path spoofing of a UDP response only has to beat the transaction id, so
    everything else that can be checked is checked: the QR bit, the id, and the
    question echoed back.
    """
    if len(data) < 12:
        raise DNSError("response too short")
    rid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if tid is not None and rid != tid:
        raise DNSError("transaction id mismatch")
    if not flags & 0x8000:
        raise DNSError("not a response")

    answer = Answer(
        name=expect_name or "",
        qtype=expect_type if expect_type is not None else 0,
        rcode=flags & 0x000F,
        authenticated=bool(flags & 0x0020),
        truncated=bool(flags & 0x0200),
    )
    offset = 12
    for _ in range(qdcount):
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise DNSError("truncated question")
        qtype = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 4
        if expect_name is not None and name.lower().rstrip(".") != expect_name.lower().rstrip("."):
            raise DNSError("answer to a different question")
        if expect_type is not None and qtype != expect_type:
            raise DNSError("answer of a different type")
        answer.name, answer.qtype = name, qtype
    if expect_type is not None and qdcount == 0:
        raise DNSError("response carries no question section")

    for _ in range(ancount):
        _, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            raise DNSError("truncated record header")
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            raise DNSError("record data beyond the end of the message")
        rdata = data[offset:offset + rdlength]
        value = _parse_rdata(rtype, rdata, data, offset, rdlength)
        if value is not None and rtype == answer.qtype:
            answer.records.append(value)
        offset += rdlength
    return answer


def _parse_rdata(rtype: int, rdata: bytes, message: bytes, offset: int, rdlength: int):
    """Decode one record, refusing anything whose length does not add up."""
    if rtype == A:
        return socket.inet_ntop(socket.AF_INET, rdata) if len(rdata) == 4 else None
    if rtype == AAAA:
        return socket.inet_ntop(socket.AF_INET6, rdata) if len(rdata) == 16 else None
    if rtype in (CNAME, NS):
        name, end = decode_name(message, offset)
        if end > offset + rdlength:
            raise DNSError("name runs past the end of its record")
        return name
    if rtype == MX:
        if rdlength < 3:
            return None
        preference = struct.unpack(">H", rdata[:2])[0]
        name, end = decode_name(message, offset + 2)
        if end > offset + rdlength:
            raise DNSError("exchange runs past the end of its record")
        return MXRecord(preference, name)
    if rtype == TXT:
        parts, index = [], 0
        while index < len(rdata):
            length = rdata[index]
            if index + 1 + length > len(rdata):
                raise DNSError("character string runs past the end of its record")
            parts.append(rdata[index + 1:index + 1 + length].decode("utf-8", "replace"))
            index += 1 + length
        return "".join(parts)          # RFC 7208 section 3.3: strings are concatenated
    if rtype == DS:
        return rdata.hex() if rdlength >= 5 else None      # key tag, algo, digest type
    if rtype == TLSA:
        return rdata.hex() if rdlength >= 4 else None      # usage, selector, type, data
    return None


# --------------------------------------------------------------------------
# Resolver
# --------------------------------------------------------------------------

def system_resolvers() -> List[str]:
    """Nameservers configured on this machine, best effort."""
    servers: List[str] = []
    try:
        with open("/etc/resolv.conf") as handle:
            for line in handle:
                match = re.match(r"^\s*nameserver\s+(\S+)", line)
                if match:
                    servers.append(match.group(1))
    except OSError:
        pass
    if not servers and os.name == "nt" and shutil.which("powershell"):
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses"],
                capture_output=True, text=True, timeout=15, check=False,
            ).stdout
            servers = [ln.strip() for ln in out.splitlines() if ln.strip()]
        except (subprocess.SubprocessError, OSError):
            pass
    return [s for s in servers if not s.startswith("fe80")]


class Resolver:
    """Stub resolver with a per-run cache.

    The cache matters: a full audit asks for the same records repeatedly while
    following SPF includes, and typosquatting checks fire hundreds of queries.
    """

    def __init__(
        self,
        servers: Optional[List[str]] = None,
        timeout: float = DEFAULT_TIMEOUT,
        attempts: int = 2,
    ) -> None:
        self.servers = servers or system_resolvers()
        self.timeout = timeout
        self.attempts = attempts
        self.cache: Dict[Tuple[str, int], Answer] = {}
        self.queries = 0

    def query(self, name: str, qtype: int) -> Answer:
        key = (name.lower().rstrip("."), qtype)
        if key in self.cache:
            return self.cache[key]
        answer = self._query_uncached(name, qtype)
        self.cache[key] = answer
        return answer

    #: Everything a hostile or broken packet can raise on the parsing path.
    _PARSE_ERRORS = (DNSError, OSError, socket.timeout, struct.error,
                     UnicodeError, ValueError, IndexError)

    def _query_uncached(self, name: str, qtype: int) -> Answer:
        if not self.servers:
            return Answer(name, qtype, error="no resolver configured")
        last_error = "no answer"
        for server in self.servers:
            for _ in range(self.attempts):
                try:
                    answer = self._exchange(server, name, qtype)
                    if answer.truncated:
                        answer = self._exchange(server, name, qtype, tcp=True)
                except self._PARSE_ERRORS as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                    continue
                self.queries += 1
                if answer.rcode not in (NOERROR, NXDOMAIN):
                    # A broken or refusing resolver is not an answer about the
                    # domain: try the next one before giving up.
                    last_error = f"rcode {answer.rcode} from {server}"
                    break
                return answer
        return Answer(name, qtype, error=last_error)

    def _exchange(self, server: str, name: str, qtype: int, tcp: bool = False) -> Answer:
        packet, tid = build_query(name, qtype)
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        if tcp:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((server, 53))
                sock.sendall(struct.pack(">H", len(packet)) + packet)
                length = struct.unpack(">H", _recv_exactly(sock, 2))[0]
                data = _recv_exactly(sock, length)
        else:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                # connect() so the kernel drops datagrams from any other source.
                sock.connect((server, 53))
                sock.send(packet)
                data = sock.recv(MAX_UDP)
        return parse_response(data, tid, expect_name=name, expect_type=qtype)

    # convenience wrappers -------------------------------------------------

    def txt(self, name: str) -> Answer:
        return self.query(name, TXT)

    def mx(self, name: str) -> Answer:
        return self.query(name, MX)

    def a(self, name: str) -> Answer:
        return self.query(name, A)

    def exists(self, name: str) -> bool:
        """True when the name resolves to something at all."""
        for qtype in (A, AAAA, MX):
            answer = self.query(name, qtype)
            if answer.exists:
                return True
        return False


def _recv_exactly(sock: socket.socket, count: int) -> bytes:
    chunks = b""
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise DNSError("connection closed early")
        chunks += chunk
    return chunks
