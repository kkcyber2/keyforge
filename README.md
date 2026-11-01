# keyforge

[![tests](https://github.com/kkcyber2/keyforge/actions/workflows/tests.yml/badge.svg)](https://github.com/kkcyber2/keyforge/actions/workflows/tests.yml)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Issue API keys, show them once, store only a hash, meter usage, revoke on demand.

```bash
pip install -r requirements.txt
uvicorn keyforge.app:app --port 8080
```

```bash
# issue
curl -X POST localhost:8080/api/keys -H 'content-type: application/json' \
  -d '{"name":"ci","rate_limit_per_min":60}'
# -> {"key":"kf_live_9xQ...","id":"a1b2c3d4","warning":"Store this now..."}

# use
curl localhost:8080/api/protected -H 'Authorization: Bearer kf_live_9xQ...'
# -> {"ok":true,"key":"kf_live_...a1b2","remaining":59,"usage":1}

# revoke
curl -X DELETE localhost:8080/api/keys/a1b2c3d4
```

## The four decisions that matter

**Only a hash is stored.** `sha256(raw)` goes in the store; the plaintext is
returned once at creation. A database dump yields no working credentials.
`test_raw_key_is_not_stored` asserts this.

**Constant-time verification.** `hmac.compare_digest`, not `==`. A naive compare
leaks the expected hash one byte at a time under timing analysis.

**Visible prefixes.** `kf_live_` / `kf_test_` means a key pasted into a GitHub
issue or a log is instantly recognisable — and secret scanners can match it.

**Masked in every list response.** `kf_live_...a1b2`. `test_list_never_returns_raw_key`
asserts the raw key never appears in the list endpoint's body.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/keys` | Issue a key. Returns plaintext once. |
| GET | `/api/keys` | List keys, masked |
| DELETE | `/api/keys/{id}` | Revoke |
| GET | `/api/protected` | Demo endpoint: verify + meter + 429 |
| GET | `/healthz` | Liveness |

Rate limiting is a fixed-window counter per key per minute, returning `429` with
`Retry-After: 60`.

## Tests

```bash
python -m pytest -q     # 33 passed
```

## Limitations — read this

- **In-memory store.** Restart and every key is gone. Swap `KeyStore` for a real
  table before production; the interface is four methods.
- **No auth on the admin API.** Anyone who can reach `/api/keys` can mint keys.
  Put it behind your own auth.
- **Fixed-window rate limiting** allows a 2x burst across a window boundary. Use
  a sliding window or a token bucket if that matters.
- **No key rotation or expiry.** Revoke and reissue is the only path.
- **Scopes are stored but not enforced** — the demo endpoint checks presence, not
  permission. Wire `scopes` into your own authorisation layer.

## License

MIT — see [LICENSE](LICENSE).
