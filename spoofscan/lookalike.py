"""Generation of domains that could be mistaken for the audited one.

The permutations follow the families that show up in real phishing against
Spanish organisations: a mistyped key, a doubled or dropped letter, a swapped
pair, a homoglyph, an added or removed hyphen, and above all a different top
level domain. Generation is pure; resolution is done by the collector.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Set, Tuple

#: Keys physically adjacent on a QWERTY keyboard, Spanish layout included.
_ADJACENT: Dict[str, str] = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
    "k": "jiolm", "l": "kopñ", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu",
    "z": "asx", "0": "9o", "1": "2q", "2": "13", "3": "24", "4": "35",
    "5": "46", "6": "57", "7": "68", "8": "79", "9": "80",
}

#: Characters that look alike in a browser address bar or a mail client.
_HOMOGLYPHS: Dict[str, Tuple[str, ...]] = {
    "a": ("4",), "b": ("6", "8"), "c": ("(",), "e": ("3",), "g": ("9", "q"),
    "i": ("1", "l", "j"), "l": ("1", "i"), "m": ("rn", "nn"), "n": ("m",),
    "o": ("0",), "q": ("g",), "s": ("5", "$"), "u": ("v",), "v": ("u",),
    "w": ("vv",), "z": ("2",),
}

#: Top level domains a Spanish organisation is most often impersonated on.
_TLDS: Tuple[str, ...] = (
    "com", "net", "org", "es", "eu", "info", "online", "site", "cloud",
    "app", "cat", "gal", "shop", "top", "xyz", "click", "email", "support",
)

#: Words appended or prefixed to make a domain look like a service portal.
_AFFIXES: Tuple[str, ...] = (
    "seguro", "secure", "soporte", "support", "portal", "acceso", "login",
    "correo", "mail", "cliente", "facturacion", "pagos", "sede", "online",
)


#: Second level domains that behave as suffixes, so the registrable name is the
#: label before them. Not exhaustive: this is a pragmatic list, not the PSL.
_SUFFIXES = ("co", "com", "org", "gob", "gov", "edu", "net", "ac", "nom")


def split_domain(domain: str) -> Tuple[str, str]:
    """Return ``(registrable label, suffix)``, discarding any subdomain.

    Impersonation targets the registrable name, so ``sede.ayuntamiento.gob.es``
    is reduced to ``ayuntamiento`` + ``gob.es``.
    """
    domain = domain.lower().strip(".")
    parts = [p for p in domain.split(".") if p]
    if len(parts) < 2:
        return domain, ""
    if len(parts) >= 3 and parts[-2] in _SUFFIXES and len(parts[-1]) == 2:
        return parts[-3], ".".join(parts[-2:])
    return parts[-2], parts[-1]


def _typos(label: str) -> Set[str]:
    out: Set[str] = set()
    for index, char in enumerate(label):
        for replacement in _ADJACENT.get(char, ""):
            out.add(label[:index] + replacement + label[index + 1:])
        out.add(label[:index] + label[index + 1:])                      # omission
        out.add(label[:index] + char + char + label[index:])            # repetition
        if index + 1 < len(label):                                      # transposition
            out.add(label[:index] + label[index + 1] + char + label[index + 2:])
    return {o for o in out if len(o) > 1}


def _homoglyphs(label: str) -> Set[str]:
    out: Set[str] = set()
    for index, char in enumerate(label):
        for replacement in _HOMOGLYPHS.get(char, ()):
            out.add(label[:index] + replacement + label[index + 1:])
    return out


def _structure(label: str) -> Set[str]:
    out: Set[str] = set()
    if "-" in label:
        out.add(label.replace("-", ""))
    for index in range(1, len(label)):
        out.add(label[:index] + "-" + label[index:])
    out.add(label + "s")
    return out


def _affixed(label: str) -> Set[str]:
    out: Set[str] = set()
    for affix in _AFFIXES:
        out.add(f"{label}-{affix}")
        out.add(f"{affix}-{label}")
    return out


def generate(domain: str, limit: int = 400, include_affixes: bool = True) -> List[Dict[str, str]]:
    """Candidate impersonation domains, each tagged with the family it belongs to.

    ``limit`` bounds the number of DNS queries the audit will make: the point is
    to find the registered impostors, not to enumerate the whole space.
    """
    label, tld = split_domain(domain)
    base = f"{label}.{tld}"
    candidates: List[Dict[str, str]] = []
    seen: Set[str] = {base}

    def add(name: str, kind: str) -> None:
        name = name.lower()
        if name in seen or not name or name.startswith("-") or ".." in name:
            return
        seen.add(name)
        candidates.append({"domain": name, "kind": kind})

    for other in _TLDS:                                  # different TLD, same name
        if other != tld:
            add(f"{label}.{other}", "tld")
    for variant in sorted(_homoglyphs(label)):
        add(f"{variant}.{tld}", "homoglyph")
    for variant in sorted(_typos(label)):
        add(f"{variant}.{tld}", "typo")
    for variant in sorted(_structure(label)):
        add(f"{variant}.{tld}", "structure")
    if include_affixes:
        for variant in sorted(_affixed(label)):
            add(f"{variant}.{tld}", "affix")
    return candidates[:limit]


def kind_label(kind: str) -> Tuple[str, str]:
    return {
        "tld": ("same name, different TLD", "mismo nombre, otro dominio de primer nivel"),
        "homoglyph": ("visually similar characters", "caracteres visualmente similares"),
        "typo": ("keyboard typo", "error de tecleo"),
        "structure": ("hyphen or plural variant", "variante con guion o plural"),
        "affix": ("service-looking prefix or suffix", "prefijo o sufijo con aspecto de servicio"),
    }.get(kind, (kind, kind))
