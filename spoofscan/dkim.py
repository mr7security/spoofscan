"""DKIM public key record parsing (RFC 6376), as pure functions."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Dict, List, Optional

#: Selectors published by the mail platforms most common in Spanish public
#: sector and SME environments. DKIM selectors cannot be enumerated from DNS,
#: so a miss here proves nothing and is reported as such.
COMMON_SELECTORS = (
    "default", "selector1", "selector2", "google", "k1", "k2", "k3",
    "mail", "dkim", "s1", "s2", "smtp", "mandrill", "everlytickey1",
    "zoho", "protonmail", "protonmail2", "pm", "sendgrid", "mailjet",
    "amazonses", "hs1", "hs2", "cm", "sig1", "sm", "ctct1", "ctct2",
    "mimecast20230101", "acoustic", "dkim1024", "mxvault",
)


@dataclass
class DKIMKey:
    selector: str
    raw: str
    tags: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def key_type(self) -> str:
        return (self.tags.get("k") or "rsa").lower()

    @property
    def public_key(self) -> str:
        return self.tags.get("p", "")

    @property
    def revoked(self) -> bool:
        return "p" in self.tags and self.tags["p"].strip() == ""

    @property
    def testing(self) -> bool:
        return "y" in [f.strip().lower() for f in (self.tags.get("t") or "").split(":")]

    @property
    def bits(self) -> Optional[int]:
        """Approximate RSA modulus size from the DER encoded SubjectPublicKeyInfo."""
        if self.key_type != "rsa" or not self.public_key:
            return None
        try:
            der = base64.b64decode(self.public_key + "===", validate=False)
        except (ValueError, base64.binascii.Error):
            return None
        # The modulus is the longest INTEGER in the structure; find the first
        # long form length after the algorithm identifier and derive the bits.
        marker = der.find(b"\x02\x82")
        if marker == -1 or marker + 4 > len(der):
            marker = der.find(b"\x02\x81")
            if marker == -1 or marker + 3 > len(der):
                return None
            length = der[marker + 2]
        else:
            length = int.from_bytes(der[marker + 2:marker + 4], "big")
        modulus = der[marker + (4 if der[marker + 1] == 0x82 else 3):]
        modulus = modulus[:length].lstrip(b"\x00")
        return len(modulus) * 8 if modulus else None


def is_dkim(txt: str) -> bool:
    stripped = txt.strip().lower()
    return stripped.startswith("v=dkim1") or (
        "p=" in stripped and "k=" in stripped and "v=" not in stripped
    )


def parse(selector: str, raw: str) -> DKIMKey:
    key = DKIMKey(selector=selector, raw=raw.strip())
    for part in key.raw.split(";"):
        name, _, value = part.partition("=")
        name = name.strip().lower()
        if name:
            key.tags[name] = value.strip()
    if "p" not in key.tags:
        key.errors.append("no p= tag: the record carries no public key")
    return key
