"""SPF record parsing and evaluation (RFC 7208), as pure functions."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

#: Mechanisms that cost a DNS lookup against the limit of RFC 7208 section 4.6.4.
LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists")
#: Modifiers that also cost a lookup.
LOOKUP_MODIFIERS = ("redirect",)

QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


@dataclass
class Mechanism:
    qualifier: str
    name: str
    value: Optional[str] = None

    @property
    def costs_lookup(self) -> bool:
        return self.name in LOOKUP_MECHANISMS

    def __str__(self) -> str:
        prefix = "" if self.qualifier == "+" else self.qualifier
        return f"{prefix}{self.name}" + (f":{self.value}" if self.value else "")


@dataclass
class SPFRecord:
    raw: str
    mechanisms: List[Mechanism] = field(default_factory=list)
    modifiers: List[Tuple[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def all_qualifier(self) -> Optional[str]:
        for mechanism in self.mechanisms:
            if mechanism.name == "all":
                return mechanism.qualifier
        return None

    @property
    def redirect(self) -> Optional[str]:
        """The redirect target, or None when it does not apply.

        RFC 7208 section 6.1: when an ``all`` mechanism is present the redirect
        modifier must be ignored, so it is not reported and does not cost a
        lookup either.
        """
        if self.all_qualifier is not None:
            return None
        for name, value in self.modifiers:
            if name == "redirect":
                return value
        return None

    @property
    def includes(self) -> List[str]:
        return [m.value for m in self.mechanisms
                if m.name == "include" and m.value]

    @property
    def has_ptr(self) -> bool:
        return any(m.name == "ptr" for m in self.mechanisms)


def is_spf(txt: str) -> bool:
    """RFC 7208 section 4.5: the version tag is case insensitive."""
    return txt.strip().lower().startswith("v=spf1")


def parse(raw: str) -> SPFRecord:
    record = SPFRecord(raw=raw.strip())
    terms = record.raw.split()
    if not terms or terms[0].lower() != "v=spf1":
        record.errors.append("record does not start with v=spf1")
        return record

    for term in terms[1:]:
        if "=" in term and not term[0] in "+-~?":
            name, _, value = term.partition("=")
            record.modifiers.append((name.lower(), value))
            continue
        qualifier = "+"
        if term[0] in QUALIFIERS:
            qualifier, term = term[0], term[1:]
        name, _, value = term.partition(":")
        name = name.lower()
        if "/" in name and not value:            # ip4/ip6 CIDR without colon
            name, _, value = name.partition("/")
        record.mechanisms.append(Mechanism(qualifier, name, value or None))
    if record.all_qualifier is None and record.redirect is None:
        record.errors.append("no 'all' mechanism and no redirect modifier")
    return record


#: Above this the record is already invalid, so counting further is pointless
#: and, on a cyclic or fan-out include graph, ruinous.
LOOKUP_LIMIT = 10
_CEILING = 100


def count_lookups(
    record: SPFRecord,
    resolve_include=None,
    _visiting: Optional[set] = None,
    _memo: Optional[dict] = None,
) -> int:
    """DNS-querying terms consumed by this record, following includes.

    ``resolve_include`` receives a domain and returns its SPFRecord or None; when
    it is omitted only the terms of this record are counted, which is the lower
    bound and still enough to catch the usual offenders.

    Include graphs in the wild are diamonds, not trees, and occasionally cycles,
    so results are memoised per domain and domains already on the stack are not
    re-entered. Counting also stops once the record is beyond saving.
    """
    _visiting = set() if _visiting is None else _visiting
    _memo = {} if _memo is None else _memo

    total = sum(1 for m in record.mechanisms if m.costs_lookup)
    targets = list(record.includes)
    if record.redirect:
        total += 1
        targets.append(record.redirect)
    if resolve_include is None:
        return total

    for domain in targets:
        if total > _CEILING:
            break
        if domain in _visiting:          # cycle: the record is broken anyway
            continue
        if domain in _memo:
            total += _memo[domain]
            continue
        nested = resolve_include(domain)
        if nested is None:
            continue
        _visiting.add(domain)
        cost = count_lookups(nested, resolve_include, _visiting, _memo)
        _visiting.discard(domain)
        _memo[domain] = cost
        total += cost
    return min(total, _CEILING)


def find_records(txts: List[str]) -> List[str]:
    """SPF records among a set of TXT strings."""
    return [txt for txt in txts if is_spf(txt)]


MACRO = re.compile(r"%\{[^}]*\}")


def has_macro(value: str) -> bool:
    """True when a term expands at evaluation time and cannot be resolved here.

    RFC 7208 section 7 macros such as ``include:%{d}.spf.example`` are perfectly
    valid; querying them literally would report a broken include that is not.
    """
    return bool(MACRO.search(value or ""))
