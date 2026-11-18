# cf-token – M2M JWT Issuance Service

A Cloudflare Worker that issues RS256 JWTs to authenticated bridge clients. Used by ACP Bridge instances to obtain short-lived tokens for calling cf-push-relay without embedding long-lived secrets in request bodies.

## Why cf-token?

Push relay requests must be tied to a specific bridge identity so that device tokens are isolated per bridge (no cross-bridge notification leakage). cf-token provides:

- **M2M OAuth2-style token issuance** — bridges exchange `client_id`/`client_secret` for a short-lived RS256 JWT
- **RS256 public key verification** — the relay verifies JWTs against a published JWKS, with no shared secret between the two workers
- **Client lifecycle management** — admin endpoints to create and revoke bridge clients

## Architecture

```
Bridge ──POST /token──→ [ cf-token Worker ] ──→ RS256 JWT (1h TTL)
         {client_id,             │
          client_secret}         │
                      KV: CLIENT_REGISTRY  (hashed secrets)
                      Secret: RS_PRIVATE_KEY  (RSA-2048 PEM)

cf-push-relay ──GET /.well-known/jwks.json──→ [ cf-token Worker ]
               (on first request or cache miss)
```

## API

### `GET /health`
Health check. No auth required.
```json
{ "ok": true, "status": "healthy", "timestamp": "2024-01-01T00:00:00.000Z" }
```

### `GET /.well-known/jwks.json`
Public RS256 key set. No auth required. `Cache-Control: public, max-age=3600`.
```json
{ "keys": [{ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "...", "n": "...", "e": "AQAB" }] }
```

### `POST /token`
Issue a JWT. No auth header required — credentials are in the body.
```json
{ "client_id": "bridge-home-office", "client_secret": "<secret>" }
```
Response:
```json
{ "access_token": "<rs256-jwt>", "token_type": "Bearer", "expires_in": 3600 }
```
- Admin client (`ADMIN_CLIENT_ID`) → scope `"admin"`, verified against `ADMIN_CLIENT_SECRET`
- KV clients → scope from stored record (`"push:write"` or `"admin"`), verified via PBKDF2-SHA256
- On failure: `401 { "ok": false, "error": "invalid_client" }`

### `POST /clients`
Create a bridge client. Requires admin JWT (`Authorization: Bearer <admin_jwt>`).
```json
{ "client_id": "bridge-home-office", "scope": "push:write" }
```
Response (`201`):
```json
{ "ok": true, "client_id": "bridge-home-office", "client_secret": "<hex-secret>" }
```
The `client_secret` is shown **once** — store it immediately in `common.toml [push_relay]`.

### `DELETE /clients/:id`
Revoke a client. Requires admin JWT.
```json
{ "ok": true, "message": "Client deleted" }
```

## Setup

### Prerequisites
- [Node.js](https://nodejs.org/) >= 20
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) (`npm i -g wrangler`)
- A Cloudflare account

### 1. Install dependencies
```bash
cd cf-token
npm install
```

### 2. Generate RSA key pair
```bash
node scripts/generate-keys.mjs
```
Copy the printed PEM private key — you'll need it in step 4.

### 3. Create KV namespace
```bash
wrangler kv namespace create CLIENT_REGISTRY
```
Copy the ID into `wrangler.toml`.

### 4. Set secrets
```bash
wrangler secret put RS_PRIVATE_KEY       # paste PEM from step 2
wrangler secret put ADMIN_CLIENT_SECRET  # choose a strong random secret
```

### 5. Configure variables
Edit `wrangler.toml`:
```toml
[vars]
TOKEN_ISSUER    = "https://token.aptove.com"
TOKEN_AUDIENCE  = "https://push.aptove.com"
ADMIN_CLIENT_ID = "admin"  # change to a non-guessable value for production
```

### 6. Deploy
```bash
npm run deploy
# or: wrangler deploy
```

### 7. Create bridge clients
After deployment, use the admin credentials to register each bridge:
```bash
# 1. Get admin JWT (never echo the value — it will appear in shell history and logs)
ADMIN_JWT=$(curl -s -X POST https://token.aptove.com/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"admin","client_secret":"<ADMIN_CLIENT_SECRET>"}' \
  | jq -r .access_token)
[ -n "$ADMIN_JWT" ] && echo "Token acquired." || echo "ERROR: token is empty — check credentials."

# 2. Create a bridge client
curl -s -X POST https://token.aptove.com/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"client_id":"bridge-home-office","scope":"push:write"}'

# 3. Unset the token when done
unset ADMIN_JWT
```

> **Security note:** Admin JWTs have a 1-hour lifetime (3600 s). Never print `$ADMIN_JWT` directly — use `[ -n "$ADMIN_JWT" ]` to verify it was set.
Copy the returned `client_id` and `client_secret` into Aptove Router's `common.toml`:
```toml
push_selection = "aptove"

[aptove_push_relay]
url           = "https://push.aptove.com"
token_url     = "https://token.aptove.com"
client_id     = "bridge-home-office"
client_secret = "<secret from above>"
```

### 8. Local development
```bash
# Create .dev.vars
cat > .dev.vars << 'EOF'
RS_PRIVATE_KEY=<paste PEM here>
ADMIN_CLIENT_SECRET=local-dev-secret
EOF

npm run dev
```

### 9. CI/CD (GitHub Actions)

**Required GitHub Secrets**:

| Secret | Description |
|--------|-------------|
| `CLOUDFLARE_API_TOKEN` | Scoped API token — use "Edit Cloudflare Workers" template |
| `CLOUDFLARE_ACCOUNT_ID` | Your Cloudflare account ID (32-char hex) |

## Testing
```bash
npm test           # run all tests
npm run test:watch # watch mode
npm run typecheck  # TypeScript type checking
```

Tests run on [Miniflare](https://miniflare.dev/) (Cloudflare's local Worker simulator) via `@cloudflare/vitest-pool-workers` — entirely in-memory, no Cloudflare account or network access needed. Tests generate a fresh RSA key pair via `crypto.subtle.generateKey` so they run entirely offline.

### Test configuration

Tests use a separate `wrangler.test.toml` (referenced by `vitest.config.mts`) instead of the production `wrangler.toml`. This test config provides:

- **Permissive Cloudflare native rate limits** (`limit = 1000` instead of `1`) so Tier 1 abuse ceilings don't interfere with tests that make multiple requests.
- **Permissive token bucket parameters** via `miniflare.bindings` overrides (`TOKEN_BUCKET_CAPACITY = "999999"`, `TOKEN_REFILL_INTERVAL_MS = "1"`) so Tier 2 token buckets are effectively unlimited.
- **Fake KV namespace ID** (`test-client-registry`) that doesn't correspond to a real Cloudflare namespace — Miniflare creates an in-memory store for it.

This separation ensures existing tests (JWT issuance, client CRUD, JWKS endpoint, etc.) exercise the real application logic without being blocked by rate limits, while production deployments via `wrangler deploy` always use the restrictive `wrangler.toml` config.

## Rate Limiting

Every endpoint has rate limiting to prevent abuse and brute-force attacks.

| Tier | Mechanism | Purpose |
|------|-----------|---------|
| **Tier 1 — Abuse ceiling** | Cloudflare native `[[ratelimits]]` binding | Hard cutoff for burst abuse/DoS. Zero KV cost. |
| **Tier 2 — Token bucket** | KV-backed token bucket | Sustained rate control with configurable burst. |

### Per-endpoint limits

| Endpoint | Tier 1 (native) | Tier 2 bucket capacity | Tier 2 refill rate | Sustained max |
|----------|-----------------|------------------------|--------------------|--------------:|
| `POST /token` | 1 req/min per `client_id` | 5 | 1 token per 1 hr | 1/hr |
| `GET /health` | 1 req/min per IP | — | — | 1/min |
| `GET /.well-known/jwks.json` | 1 req/min per IP | — | — | 1/min |

**Brute-force protection:** Rate limiting on `POST /token` fires *before* the PBKDF2-SHA256 credential check. This prevents attackers from using the endpoint to test secrets at high speed — they are limited to 1 attempt per minute regardless of whether the secret is correct.

### Configuration

Token bucket parameters are configurable via `[vars]` in `wrangler.toml`:

```toml
[vars]
TOKEN_BUCKET_CAPACITY = "5"
TOKEN_REFILL_INTERVAL_MS = "3600000"  # 1 hour
```

### Expected usage

Aptove Router caches JWTs for ~1 hour and requests a new one when < 60s TTL remains. Normal usage is ~1 token request per bridge per hour — well within the 5-token burst capacity.

## Security Model

- The RSA-2048 private key lives only in Cloudflare Secrets (`RS_PRIVATE_KEY`) — never in source code or KV
- Client secrets are stored hashed (PBKDF2-SHA256, 100k iterations, 16-byte random salt) — the plaintext is never persisted
- Admin credentials are compared byte-by-byte in constant time to prevent timing attacks
- JWTs expire after 1 hour; Aptove Router fetches a new one when < 60 seconds remain
- Revoking a client prevents new JWTs but does not invalidate already-issued ones (stateless JWTs); for immediate revocation, also rotate the RSA key pair

## Key Rotation

1. Generate a new key pair: `node scripts/generate-keys.mjs`
2. Update the secret: `wrangler secret put RS_PRIVATE_KEY`
3. Redeploy: `npm run deploy`
4. cf-push-relay automatically detects the new `kid` on the next request, invalidates its JWKS KV cache, and fetches the updated JWKS — zero downtime required