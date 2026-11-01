"""Key lifecycle tests — the security properties, not just the happy path."""
import pytest

from keyforge.keys import (
    PREFIX_LIVE,
    PREFIX_TEST,
    KeyStore,
    RateLimiter,
    generate_key,
    hash_key,
)


class TestGeneration:
    def test_live_prefix(self):
        raw, prefix, _ = generate_key(live=True)
        assert raw.startswith(PREFIX_LIVE) and prefix == PREFIX_LIVE

    def test_test_prefix(self):
        raw, prefix, _ = generate_key(live=False)
        assert raw.startswith(PREFIX_TEST)

    def test_keys_are_unique(self):
        raws = {generate_key()[0] for _ in range(200)}
        assert len(raws) == 200, "key collision — entropy is too low"

    def test_hash_is_sha256_hex(self):
        h = hash_key("abc")
        assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)

    def test_hash_is_deterministic(self):
        assert hash_key("abc") == hash_key("abc")


class TestStore:
    def test_create_returns_raw_once(self):
        s = KeyStore()
        key, raw = s.create("ci")
        assert raw.startswith(PREFIX_LIVE)
        assert key.key_hash == hash_key(raw)

    def test_raw_key_is_not_stored(self):
        """A database dump must not contain a usable credential."""
        s = KeyStore()
        _, raw = s.create("ci")
        assert raw not in s._by_hash
        assert all(raw != k.key_hash for k in s.list())

    def test_verify_accepts_valid(self):
        s = KeyStore()
        key, raw = s.create("ci")
        assert s.verify(raw).id == key.id

    def test_verify_rejects_unknown(self):
        s = KeyStore()
        s.create("ci")
        assert s.verify("kf_live_totallymadeup") is None

    def test_verify_rejects_empty_and_none(self):
        s = KeyStore()
        assert s.verify("") is None
        assert s.verify(None) is None

    def test_verify_rejects_revoked(self):
        s = KeyStore()
        key, raw = s.create("ci")
        s.revoke(key.id)
        assert s.verify(raw) is None

    def test_verify_updates_usage(self):
        s = KeyStore()
        key, raw = s.create("ci")
        s.verify(raw)
        s.verify(raw)
        assert s.get(key.id).usage == 2
        assert s.get(key.id).last_used_at is not None

    def test_masked_never_leaks_full_key(self):
        s = KeyStore()
        key, raw = s.create("ci")
        assert raw not in key.masked
        assert key.masked.startswith(PREFIX_LIVE)

    def test_revoke_unknown_returns_false(self):
        assert KeyStore().revoke("nope") is False

    def test_list_newest_first(self):
        s = KeyStore()
        s.create("first")
        s.create("second")
        assert s.list()[0].name == "second"

    def test_scopes_default_to_read(self):
        s = KeyStore()
        key, _ = s.create("ci")
        assert key.scopes == ["read"]


class TestRateLimiter:
    def test_allows_up_to_limit(self):
        rl = RateLimiter()
        for i in range(5):
            allowed, remaining = rl.check("k", 5, now=1000.0)
            assert allowed
            assert remaining == 4 - i

    def test_blocks_over_limit(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.check("k", 5, now=1000.0)
        allowed, remaining = rl.check("k", 5, now=1000.0)
        assert not allowed and remaining == 0

    def test_window_resets(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.check("k", 5, now=1000.0)
        allowed, _ = rl.check("k", 5, now=1061.0)  # next minute
        assert allowed

    def test_keys_are_independent(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.check("a", 5, now=1000.0)
        assert rl.check("b", 5, now=1000.0)[0] is True
