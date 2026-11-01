"""API key issuance, hashing and verification.

Design decisions that matter in production:
- The plaintext key is shown exactly once. Only a hash is stored, so a database
  leak does not hand over working credentials.
- Keys carry a visible prefix (kf_live_ / kf_test_) so a leaked key is
  identifiable in a log or a GitHub commit.
- Verification is constant-time to avoid a timing oracle on the hash.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

PREFIX_LIVE = "kf_live_"
PREFIX_TEST = "kf_test_"
KEY_BYTES = 24  # 32 chars urlsafe -> ~192 bits of entropy


@dataclass
class ApiKey:
    id: str
    name: str
    prefix: str
    key_hash: str
    created_at: float
    last_used_at: Optional[float] = None
    revoked: bool = False
    scopes: List[str] = field(default_factory=list)
    rate_limit_per_min: int = 60
    usage: int = 0

    @property
    def masked(self) -> str:
        """What you show in a UI list — never the full key."""
        return f"{self.prefix}...{self.id[:4]}"

    def as_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "masked": self.masked,
            "created_at": self.created_at, "last_used_at": self.last_used_at,
            "revoked": self.revoked, "scopes": self.scopes,
            "rate_limit_per_min": self.rate_limit_per_min, "usage": self.usage,
        }


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_key(live: bool = True) -> tuple[str, str, str]:
    """Return (raw_key, prefix, hash). The raw key is never stored."""
    prefix = PREFIX_LIVE if live else PREFIX_TEST
    raw = prefix + secrets.token_urlsafe(KEY_BYTES)
    return raw, prefix, hash_key(raw)


class KeyStore:
    def __init__(self):
        self._by_hash: Dict[str, ApiKey] = {}
        self._by_id: Dict[str, ApiKey] = {}

    def create(self, name: str, live: bool = True, scopes: Optional[List[str]] = None,
               rate_limit_per_min: int = 60) -> tuple[ApiKey, str]:
        raw, prefix, h = generate_key(live)
        key = ApiKey(
            id=secrets.token_hex(4),
            name=name,
            prefix=prefix,
            key_hash=h,
            created_at=time.time(),
            scopes=scopes or ["read"],
            rate_limit_per_min=rate_limit_per_min,
        )
        self._by_hash[h] = key
        self._by_id[key.id] = key
        return key, raw

    def verify(self, raw: str) -> Optional[ApiKey]:
        """Constant-time lookup. Returns None for unknown, revoked or malformed keys."""
        if not raw or not isinstance(raw, str):
            return None
        h = hash_key(raw)
        # Compare against every stored hash in constant time so an attacker
        # cannot learn how close a guess was from response timing.
        found: Optional[ApiKey] = None
        for stored_hash, key in self._by_hash.items():
            if hmac.compare_digest(stored_hash, h):
                found = key
        if found is None or found.revoked:
            return None
        found.last_used_at = time.time()
        found.usage += 1
        return found

    def revoke(self, key_id: str) -> bool:
        k = self._by_id.get(key_id)
        if not k:
            return False
        k.revoked = True
        return True

    def list(self) -> List[ApiKey]:
        return sorted(self._by_id.values(), key=lambda k: k.created_at, reverse=True)

    def get(self, key_id: str) -> Optional[ApiKey]:
        return self._by_id.get(key_id)


class RateLimiter:
    """Fixed-window counter. Simple, predictable, and good enough for API keys.

    A sliding window is more accurate but needs per-request timestamps; for
    per-minute key limits the extra memory is not worth it.
    """

    def __init__(self):
        self._windows: Dict[str, tuple[int, int]] = {}

    def check(self, key_id: str, limit: int, now: Optional[float] = None) -> tuple[bool, int]:
        """Return (allowed, remaining)."""
        now = now if now is not None else time.time()
        window = int(now // 60)
        cur_window, count = self._windows.get(key_id, (window, 0))
        if cur_window != window:
            cur_window, count = window, 0
        if count >= limit:
            self._windows[key_id] = (cur_window, count)
            return False, 0
        count += 1
        self._windows[key_id] = (cur_window, count)
        return True, limit - count
