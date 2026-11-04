"""Canary token generation and correlation.

Every decoy secret airlock plants contains a unique, high-entropy canary string.
If that exact string appears anywhere it should not -- an outbound TCP payload, a
DNS query, a newly written file, the skill's stdout -- then exfiltration is not
inferred, it is *proven*. There is no heuristic and no false positive: the string
did not exist before the run and existed nowhere else on the machine.

This is the detection primitive that signature scanners structurally cannot
replicate. A YARA rule looks for the word `id_rsa`; a canary looks for the
actual secret bytes leaving the box.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass

_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"
CANARY_PREFIX = "alck"


def _rand_token(nbytes: int = 12) -> str:
    raw = os.urandom(nbytes)
    return "".join(_ALPHABET[b % len(_ALPHABET)] for b in raw)


def new_canary(secret_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "", secret_id.lower())[:12] or "sec"
    return f"{CANARY_PREFIX}_{slug}_{_rand_token()}"


def b64_variants(canary: str) -> list[str]:
    """Encodings an exfiltrating skill is likely to use."""
    out = {canary, canary.upper()}
    out.add(base64.b64encode(canary.encode()).decode().rstrip("="))
    out.add(base64.b64encode(canary.encode()).decode())
    out.add(canary.encode().hex())
    out.add(base64.urlsafe_b64encode(canary.encode()).decode().rstrip("="))
    out.add(canary[::-1])
    # DNS labels and hostnames cannot carry underscores, so a tunnelling payload
    # swaps them. Both substitutions are common enough to be worth indexing.
    out.add(canary.replace("_", "."))
    out.add(canary.replace("_", "-"))
    return [v for v in out if v]


@dataclass(frozen=True)
class CanaryHit:
    secret_id: str
    canary: str
    variant: str
    surface: str
    detail: str
    offset: int = -1

    @property
    def obfuscated(self) -> bool:
        return self.variant != self.canary


class CanaryIndex:
    def __init__(self) -> None:
        self._variant_to_secret: dict[str, tuple[str, str]] = {}

    def register(self, secret_id: str, canary: str) -> None:
        for variant in b64_variants(canary):
            self._variant_to_secret[variant] = (secret_id, canary)

    @property
    def variants(self) -> list[str]:
        return sorted(self._variant_to_secret, key=len, reverse=True)

    def lookup(self, variant: str) -> tuple[str, str] | None:
        return self._variant_to_secret.get(variant)

    def scan_bytes(self, surface: str, blob: bytes, detail: str) -> list[CanaryHit]:
        hits: list[CanaryHit] = []
        seen: set[str] = set()
        if not blob:
            return hits
        text = blob.decode("utf-8", errors="replace")
        for variant in self.variants:
            if variant in seen:
                continue
            idx = text.find(variant)
            if idx == -1:
                continue
            entry = self._variant_to_secret.get(variant)
            if not entry:
                continue
            secret_id, canary = entry
            seen.add(secret_id)
            hits.append(CanaryHit(secret_id=secret_id, canary=canary, variant=variant,
                                  surface=surface, detail=detail, offset=idx))
        return hits
