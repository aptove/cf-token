# Deployment Guide — cf-token

Token Service deploys automatically to Cloudflare Workers when you push a version tag (e.g. `v1.0.0`) to GitHub. The workflow runs tests first, then deploys only on success.

---

## Prerequisites

- A Cloudflare account with Workers enabled
- The KV namespace and secrets provisioned (one-time setup below)
- GitHub repository secrets configured

---

## One-time Cloudflare setup

### 1. Create the KV namespace

```bash
cd cf-token

npx wrangler kv namespace create CLIENT_REGISTRY
```

The command prints an `id`. Copy it into `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "CLIENT_REGISTRY"
id = "<id from command above>"
```

Commit the updated `wrangler.toml`.

### 2. Generate the RSA signing key pair

The token service signs JWTs with an RSA-2048 private key. Generate one:

```bash
node scripts/generate-keys.mjs
```

This prints a PEM private key and the corresponding JWKS public key. The private key is stored as a Worker secret; the public key is derived at runtime and served at `/.well-known/jwks.json`.

### 3. Set Worker secrets

```bash
npx wrangler secret put RS_PRIVATE_KEY       # paste the PEM private key from step 2
npx wrangler secret put ADMIN_CLIENT_SECRET  # choose a strong random secret for the admin client
```

Generate a strong `ADMIN_CLIENT_SECRET` with:
```bash
openssl rand -hex 32
```

> Secrets persist in Cloudflare across deployments — they only need to be set once (or when rotating).

### 4. Create a Cloudflare API token

1. Go to [Cloudflare Dashboard → My Profile → API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token**
3. Use the **Edit Cloudflare Workers** template
4. Scope it to your account and zone (or all zones)
5. Copy the generated token — you won't see it again

### 5. Find your Account ID

On the Cloudflare dashboard, select any zone. The Account ID is visible in the right-hand sidebar under **API**.

---

## GitHub repository secrets

In your GitHub repo: **Settings → Secrets and variables → Actions → New repository secret**

| Secret name              | Value                                      |
|--------------------------|--------------------------------------------|
| `CLOUDFLARE_API_TOKEN`   | API token from step 4 above               |
| `CLOUDFLARE_ACCOUNT_ID`  | Account ID from step 5 above              |

---

## Deploying a release

```bash
git tag v1.0.0
git push origin v1.0.0
```

The GitHub Actions workflow (`.github/workflows/deploy.yml`) will:
1. Run `npm run typecheck`
2. Run `npm test`
3. Deploy to Cloudflare Workers via `wrangler deploy`

The Worker is served at `token.aptove.com` (configured via `routes` in `wrangler.toml`).

---

## Manual deployment

To deploy from your local machine without tagging:

```bash
cd cf-token
npm ci
npx wrangler deploy
```

---

## Variables vs secrets

| Name                  | Where set          | Secret? |
|-----------------------|--------------------|---------|
| `TOKEN_ISSUER`        | `wrangler.toml`    | No      |
| `TOKEN_AUDIENCE`      | `wrangler.toml`    | No      |
| `ADMIN_CLIENT_ID`     | `wrangler.toml`    | No      |
| `RS_PRIVATE_KEY`      | `wrangler secret`  | **Yes** |
| `ADMIN_CLIENT_SECRET` | `wrangler secret`  | **Yes** |

---

## Key rotation

To rotate the RSA signing key:

1. Run `node scripts/generate-keys.mjs` to generate a new key pair
2. Update the secret: `npx wrangler secret put RS_PRIVATE_KEY`
3. Push a new tag to trigger a deployment

> After key rotation all previously issued JWTs will fail verification (the old public key is gone from JWKS). Clients (e.g. cf-push-relay) will need to re-fetch a new token. Plan accordingly.
