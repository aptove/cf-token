import type { Env, JwtClaims, ClientRecord } from "./types";
import { signJwt, getJwks } from "./keys";
import { verifyAdminJwt } from "./auth";
import { createClient, getClient, deleteClient, verifySecret, hashSecret, verifyHash } from "./clients";
import { checkTokenBucket, type BucketConfig } from "./ratelimit";

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const { pathname } = url;
  const method = request.method;

  // GET /health (no auth — IP-based rate limit only)
  if (method === "GET" && pathname === "/health") {
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const { success } = await env.HEALTH_LIMITER.limit({ key: ip });
    if (!success) return rateLimitResponse();
    return json({ ok: true, status: "healthy", timestamp: new Date().toISOString() });
  }

  // GET /.well-known/jwks.json (no auth — IP-based rate limit only)
  if (method === "GET" && pathname === "/.well-known/jwks.json") {
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const { success } = await env.JWKS_LIMITER.limit({ key: ip });
    if (!success) return rateLimitResponse();
    const jwks = await getJwks(env);
    return new Response(jwks, {
      headers: {
        "content-type": "application/json",
        "cache-control": "public, max-age=3600",
      },
    });
  }

  // POST /token — issue JWT (no auth required, credentials in body)
  if (method === "POST" && pathname === "/token") {
    return handleToken(request, env);
  }

  // POST /clients — create client (admin JWT required)
  if (method === "POST" && pathname === "/clients") {
    return handleCreateClient(request, env);
  }

  // DELETE /clients/:id — revoke client (admin JWT required)
  if (method === "DELETE" && pathname.startsWith("/clients/")) {
    const clientId = pathname.slice("/clients/".length);
    if (!clientId) return json({ ok: false, error: "Not found" }, 404);
    return handleDeleteClient(clientId, request, env);
  }

  // GET /admin/clients — list all clients with binding metadata (admin JWT required)
  if (method === "GET" && pathname === "/admin/clients") {
    return handleAdminListClients(request, env);
  }

  // GET /admin/device-overlaps — find same device_id across multiple clients (admin JWT required)
  if (method === "GET" && pathname === "/admin/device-overlaps") {
    return handleAdminDeviceOverlaps(request, env);
  }

  return json({ ok: false, error: "Not found" }, 404);
}

// ───────────────────────────────────────────────────────────────────────────────
// POST /token
// ───────────────────────────────────────────────────────────────────────────────

async function handleToken(request: Request, env: Env): Promise<Response> {
  let body: {
    client_id?: string;
    client_secret?: string;
    agent_id?: string;
    device_id?: string;
    binding_secret?: string;
  };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return json({ ok: false, error: "invalid_client" }, 401);
  }

  const { client_id, client_secret } = body;
  if (!client_id || !client_secret) {
    return json({ ok: false, error: "invalid_client" }, 401);
  }

  let scope: "push:write" | "admin";
  let verified = false;

  // For regular clients: verify the client_id exists before touching any rate-limit KV.
  // Unknown client_ids return 401 immediately — no bucket write, no KV cost.
  let record: ClientRecord | null = null;
  if (client_id !== env.ADMIN_CLIENT_ID) {
    record = await getClient(env.CLIENT_REGISTRY, client_id);
    if (!record) return json({ ok: false, error: "invalid_client" }, 401);
  }

  // Tier 1: Cloudflare native hard spacing (1/min per client)
  const { success: abuseOk } = await env.TOKEN_ABUSE_LIMITER.limit({ key: client_id });
  if (!abuseOk) return rateLimitResponse();

  // Tier 2: Token bucket (capacity 5, refill 1/hr) — brute-force protection for verified clients
  const tokenConfig: BucketConfig = {
    capacity: parseInt(env.TOKEN_BUCKET_CAPACITY) || 5,
    refillIntervalMs: parseInt(env.TOKEN_REFILL_INTERVAL_MS) || 3600000,
  };
  const bucket = await checkTokenBucket(env.CLIENT_REGISTRY, `token:${client_id}`, tokenConfig);
  if (!bucket.allowed) return rateLimitResponse(bucket.retryAfterSeconds);

  if (client_id === env.ADMIN_CLIENT_ID) {
    // Timing-safe comparison for the built-in admin credential
    const secretBytes = new TextEncoder().encode(client_secret);
    const adminBytes = new TextEncoder().encode(env.ADMIN_CLIENT_SECRET);
    if (secretBytes.length === adminBytes.length) {
      let diff = 0;
      for (let i = 0; i < secretBytes.length; i++) {
        diff |= secretBytes[i]! ^ adminBytes[i]!;
      }
      verified = diff === 0;
    } else {
      // Consume time even on length mismatch to prevent timing leak
      await crypto.subtle.digest("SHA-256", secretBytes);
    }
    scope = "admin";
  } else {
    // record was already fetched and validated above
    verified = await verifySecret(client_secret, record!);
    scope = record!.scope;
  }

  if (!verified) {
    return json({ ok: false, error: "invalid_client" }, 401);
  }

  // ── Binding secret enforcement (regular clients only) ──
  let returnBindingSecret: string | undefined;

  if (record && client_id !== env.ADMIN_CLIENT_ID) {
    const enforcing = env.ENFORCE_BINDING === "true";

    if (enforcing && record.bound_secret_hash) {
      // Client already bound — require binding_secret
      if (!body.binding_secret) {
        return json({ ok: false, error: "binding_secret_required" }, 403);
      }
      const bindingValid = await verifyHash(body.binding_secret, record.bound_secret_hash, record.bound_secret_salt!);
      if (!bindingValid) {
        return json({ ok: false, error: "invalid_binding_secret" }, 403);
      }
    } else if (enforcing && !record.bound_secret_hash) {
      // First use — generate and store binding_secret
      const bindingBytes = crypto.getRandomValues(new Uint8Array(32));
      returnBindingSecret = Array.from(bindingBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const { hashed_secret: bHash, salt: bSalt } = await hashSecret(returnBindingSecret);
      record.bound_secret_hash = bHash;
      record.bound_secret_salt = bSalt;
    }

    // Always update monitoring metadata (regardless of ENFORCE_BINDING)
    if (body.agent_id) record.bound_agent_id = body.agent_id;
    if (body.device_id) record.last_device_id = body.device_id;
    record.last_ip = request.headers.get("cf-connecting-ip") || undefined;
    record.last_seen = new Date().toISOString();

    // Persist updated record
    await env.CLIENT_REGISTRY.put(`client:${client_id}`, JSON.stringify(record));
  }

  const iat = Math.floor(Date.now() / 1000);
  const claims: JwtClaims = {
    iss: env.TOKEN_ISSUER,
    sub: client_id,
    aud: env.TOKEN_AUDIENCE,
    iat,
    exp: iat + 3600,
    scope,
  };

  const access_token = await signJwt(claims, env);
  const response: Record<string, unknown> = { access_token, token_type: "Bearer", expires_in: 3600 };
  if (returnBindingSecret) {
    response.binding_secret = returnBindingSecret;
  }
  return json(response);
}

// ───────────────────────────────────────────────────────────────────────────────
// POST /clients
// ───────────────────────────────────────────────────────────────────────────────

async function handleCreateClient(request: Request, env: Env): Promise<Response> {
  const auth = await verifyAdminJwt(request, env);
  if (!auth.ok) return json({ ok: false, error: auth.error }, 401);

  let body: { client_id?: string; scope?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return json({ ok: false, error: "Invalid JSON" }, 400);
  }

  const { client_id, scope } = body;
  if (!client_id) {
    return json({ ok: false, error: "Missing client_id" }, 400);
  }
  if (scope !== "push:write" && scope !== "admin") {
    return json({ ok: false, error: 'scope must be "push:write" or "admin"' }, 400);
  }

  const existing = await getClient(env.CLIENT_REGISTRY, client_id);
  if (existing) {
    return json({ ok: false, error: "Client already exists" }, 409);
  }

  const client_secret = await createClient(env.CLIENT_REGISTRY, client_id, scope);
  return json({ ok: true, client_id, client_secret }, 201);
}

// ───────────────────────────────────────────────────────────────────────────────
// DELETE /clients/:id
// ───────────────────────────────────────────────────────────────────────────────

async function handleDeleteClient(
  clientId: string,
  request: Request,
  env: Env,
): Promise<Response> {
  const auth = await verifyAdminJwt(request, env);
  if (!auth.ok) return json({ ok: false, error: auth.error }, 401);

  await deleteClient(env.CLIENT_REGISTRY, clientId);
  return json({ ok: true, message: "Client deleted" });
}

// ───────────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────────

function json(data: object, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}

// ───────────────────────────────────────────────────────────────────────────────
// GET /admin/clients — list all clients with binding metadata
// ───────────────────────────────────────────────────────────────────────────────

async function handleAdminListClients(
  request: Request,
  env: Env,
): Promise<Response> {
  const auth = await verifyAdminJwt(request, env);
  if (!auth.ok) return json({ ok: false, error: auth.error }, 401);

  const url = new URL(request.url);
  const cursorParam = url.searchParams.get("cursor") || undefined;
  const PREFIX = "client:";

  const list = await env.CLIENT_REGISTRY.list({ prefix: PREFIX, cursor: cursorParam, limit: 100 });
  const clients: Array<{
    client_id: string;
    scope: string;
    created_at: string;
    bound_agent_id?: string;
    last_device_id?: string;
    last_ip?: string;
    last_seen?: string;
    has_binding: boolean;
  }> = [];

  for (const key of list.keys) {
    const record = await env.CLIENT_REGISTRY.get<ClientRecord>(key.name, "json");
    if (!record) continue;
    const clientId = key.name.slice(PREFIX.length);
    clients.push({
      client_id: clientId,
      scope: record.scope,
      created_at: record.created_at,
      bound_agent_id: record.bound_agent_id,
      last_device_id: record.last_device_id,
      last_ip: record.last_ip,
      last_seen: record.last_seen,
      has_binding: !!record.bound_secret_hash,
    });
  }

  return json({
    ok: true,
    clients,
    cursor: list.list_complete ? undefined : list.cursor,
  });
}

// ───────────────────────────────────────────────────────────────────────────────
// GET /admin/device-overlaps — find same device_id across multiple clients
// ───────────────────────────────────────────────────────────────────────────────

async function handleAdminDeviceOverlaps(
  request: Request,
  env: Env,
): Promise<Response> {
  const auth = await verifyAdminJwt(request, env);
  if (!auth.ok) return json({ ok: false, error: auth.error }, 401);

  const url = new URL(request.url);
  const minClients = parseInt(url.searchParams.get("min_clients") || "2") || 2;
  const PREFIX = "client:";

  // Scan all clients, group by last_device_id
  const deviceMap = new Map<string, Array<{ client_id: string; bound_agent_id?: string; last_seen?: string }>>();
  let cursor: string | undefined;

  do {
    const list = await env.CLIENT_REGISTRY.list({ prefix: PREFIX, cursor, limit: 100 });
    for (const key of list.keys) {
      const record = await env.CLIENT_REGISTRY.get<ClientRecord>(key.name, "json");
      if (!record?.last_device_id) continue;
      const clientId = key.name.slice(PREFIX.length);
      const group = deviceMap.get(record.last_device_id) || [];
      group.push({ client_id: clientId, bound_agent_id: record.bound_agent_id, last_seen: record.last_seen });
      deviceMap.set(record.last_device_id, group);
    }
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);

  // Filter to groups with >= minClients
  const overlaps: Array<{ device_id: string; clients: Array<{ client_id: string; bound_agent_id?: string; last_seen?: string }> }> = [];
  for (const [deviceId, clients] of deviceMap) {
    if (clients.length >= minClients) {
      overlaps.push({ device_id: deviceId, clients });
    }
  }

  return json({ ok: true, overlaps });
}

// ───────────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────────

function rateLimitResponse(retryAfterSeconds?: number): Response {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "cache-control": "no-store",
  };
  if (retryAfterSeconds !== undefined && retryAfterSeconds > 0) {
    headers["Retry-After"] = String(retryAfterSeconds);
  }
  return new Response(
    JSON.stringify({ ok: false, error: "Rate limit exceeded" }),
    { status: 429, headers },
  );
}
