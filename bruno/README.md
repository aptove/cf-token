# Token Service API - Bruno Collection

This Bruno collection covers all endpoints of the cf-token Cloudflare Worker — the M2M JWT issuance service used by ACP Bridge instances to authenticate with cf-push-relay.

## Setup

1. **Install Bruno**: Download from [usebruno.com](https://www.usebruno.com/)
2. **Open Collection**: File → Open Collection → Select this `bruno` folder
3. **Configure Environment**:
   - Select **Local** environment for local development (`npm run dev` in `cf-token/`)
   - Select **Production** for the deployed worker
   - Update environment variables (see below)

## Environment Variables

| Variable | Description |
|----------|-------------|
| `base_url` | `http://localhost:8787` (local) or `https://token.aptove.com` (production) |
| `admin_client_id` | Admin client ID — matches `ADMIN_CLIENT_ID` in `wrangler.toml [vars]` (default: `admin`) |
| `admin_client_secret` | Admin client secret — matches `ADMIN_CLIENT_SECRET` Wrangler secret |
| `admin_access_token` | Admin JWT — obtained by running "Get Token (Admin)" and copying `access_token` |
| `new_client_id` | Client ID to create or delete (e.g. `bridge-home-office`) |
| `new_client_secret` | Secret returned by "Create Client" (shown once — paste it here for "Get Token (Push Client)") |

## API Endpoints

1. **Health Check** — Verify the token service is running (no auth)
2. **Get JWKS** — Fetch the public RS256 key set used by cf-push-relay to verify JWTs (no auth)
3. **Get Token (Admin)** — Obtain an admin-scoped JWT using admin credentials
4. **Create Client** — Register a new bridge client; returns its one-time secret (admin JWT required)
5. **Get Token (Push Client)** — Obtain a push:write JWT for a bridge client
6. **Delete Client** — Revoke a client from the registry (admin JWT required)

## Typical Workflow

### First-time setup (one-off per deployment)

```
1. Health Check          — confirm the worker is live
2. Get Token (Admin)     — paste admin_client_id + admin_client_secret → copy access_token
                           → set admin_access_token env var
3. Create Client         — set new_client_id (e.g. "bridge-home-office"), scope "push:write"
                           → response contains client_id + client_secret (shown ONCE)
                           → copy both into common.toml [push_relay] on the bridge
```

### Verifying a bridge client token

```
4. Get Token (Push Client) — set new_client_id + new_client_secret
                             → copy access_token into cf-push-relay Bruno's access_token var
5. Open cf-push-relay collection → Register iOS/Android Device → Send Push Notification
```

### Revoking a client

```
1. Get Token (Admin)     — refresh admin_access_token if expired (1h TTL)
2. Delete Client         — set new_client_id to the client being revoked
```

## Obtaining Admin Credentials

Admin credentials are set at deployment time:
- `ADMIN_CLIENT_ID` — in `wrangler.toml` under `[vars]` (plaintext, default: `"admin"`)
- `ADMIN_CLIENT_SECRET` — set via `wrangler secret put ADMIN_CLIENT_SECRET`

For local development, set both in `.dev.vars`:
```
ADMIN_CLIENT_ID=admin
ADMIN_CLIENT_SECRET=your-local-secret
```

## Notes

- JWTs expire after **1 hour** — re-run "Get Token" requests when expired
- The `client_secret` from "Create Client" is shown **once** and cannot be retrieved again
- `admin` scope tokens can create/delete clients; `push:write` tokens can only call cf-push-relay
- The JWKS endpoint (`/.well-known/jwks.json`) is public and cached for 1h — cf-push-relay uses it to verify incoming Bearer tokens
