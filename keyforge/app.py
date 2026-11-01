"""FastAPI portal: issue keys, list them masked, revoke, and meter usage."""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .keys import KeyStore, RateLimiter

app = FastAPI(title="keyforge", version="1.0.0")
store = KeyStore()
limiter = RateLimiter()


class CreateKey(BaseModel):
    name: str
    live: bool = True
    scopes: list[str] = ["read"]
    rate_limit_per_min: int = 60


@app.get("/healthz")
def healthz():
    return {"status": "ok", "keys": len(store.list())}


@app.post("/api/keys")
def create_key(body: CreateKey):
    if not body.name.strip():
        raise HTTPException(400, "name required")
    if body.rate_limit_per_min < 1:
        raise HTTPException(400, "rate_limit_per_min must be >= 1")
    key, raw = store.create(body.name.strip(), body.live, body.scopes,
                            body.rate_limit_per_min)
    # The only time the raw key is ever returned.
    return {"key": raw, "id": key.id, "name": key.name,
            "warning": "Store this now. It cannot be shown again."}


@app.get("/api/keys")
def list_keys():
    return {"keys": [k.as_dict() for k in store.list()]}


@app.delete("/api/keys/{key_id}")
def revoke_key(key_id: str):
    if not store.revoke(key_id):
        raise HTTPException(404, "key not found")
    return {"revoked": key_id}


@app.get("/api/protected")
def protected(request: Request, authorization: str = Header(default="")):
    """A demo protected endpoint showing verification + metering in one place."""
    raw = authorization.replace("Bearer ", "").strip()
    key = store.verify(raw)
    if key is None:
        return JSONResponse({"error": "invalid or revoked key"}, status_code=401)

    allowed, remaining = limiter.check(key.id, key.rate_limit_per_min)
    if not allowed:
        return JSONResponse(
            {"error": "rate limit exceeded", "limit": key.rate_limit_per_min},
            status_code=429,
            headers={"Retry-After": "60"},
        )
    return {"ok": True, "key": key.masked, "scopes": key.scopes,
            "remaining": remaining, "usage": key.usage}


@app.get("/", response_class=HTMLResponse)
def index():
    rows = "".join(
        f"<tr><td><code>{k.masked}</code></td><td>{k.name}</td>"
        f"<td>{k.rate_limit_per_min}/min</td><td>{k.usage}</td>"
        f"<td>{'revoked' if k.revoked else 'active'}</td></tr>"
        for k in store.list()
    ) or '<tr><td colspan="5">No keys yet.</td></tr>'
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>keyforge</title>
<style>
body{{font:15px/1.6 system-ui,sans-serif;max-width:52rem;margin:3rem auto;
padding:0 1.25rem;background:#0f1115;color:#e6e6e6}}
h1{{font-size:1.4rem;letter-spacing:-.02em}}
table{{width:100%;border-collapse:collapse;margin-top:1.5rem;font-size:.9rem}}
th,td{{text-align:left;padding:.6rem .5rem;border-bottom:1px solid #232833}}
th{{color:#8b93a1;font-weight:500;font-size:.78rem;text-transform:uppercase;
letter-spacing:.06em}}
code{{background:#1b1f27;padding:.15em .4em;border-radius:4px;color:#8fd6a0}}
.note{{color:#8b93a1;font-size:.85rem;border-left:2px solid #2a3140;
padding-left:.8rem;margin-top:2rem}}
</style></head><body>
<h1>keyforge</h1>
<p>Issue, mask, meter and revoke API keys.</p>
<table><thead><tr><th>Key</th><th>Name</th><th>Limit</th><th>Uses</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody></table>
<p class="note">Keys are stored as SHA-256 hashes. The plaintext is returned once,
at creation, and never again — a database leak does not yield working credentials.</p>
</body></html>"""
