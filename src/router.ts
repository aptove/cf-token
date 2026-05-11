import type { Env, JwtClaims } from "./types";
import { signJwt, getJwks } from "./keys";
import { verifyAdminJwt } from "./auth";
import { createClient, getClient, deleteClient, verifySecret } from "./clients";

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const { pathname } = url;
  const method = request.method;

  // GET /health
  if (method === "GET" && pathname === "/health") {
    return json({ ok: true, status: "healthy", timestamp: new Date().toISOString() });
  }

  // GET /.well-known/jwks.json
  if (method === "GET" && pathname === "/.well-known/jwks.json") {
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

  return json({ ok: false, error: "Not found" }, 404);
}

// ───────────────────────────────────────────────────────────────────────────────
// POST /token
// ───────────────────────────────────────────────────────────────────────────────

async function handleToken(request: Request, env: Env): Promise<Response> {
  let body: { client_id?: string; client_secret?: string };
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
    const record = await getClient(env.CLIENT_REGISTRY, client_id);
    if (!record) {
      return json({ ok: false, error: "invalid_client" }, 401);
    }
    verified = await verifySecret(client_secret, record);
    scope = record.scope;
  }

  if (!verified) {
    return json({ ok: false, error: "invalid_client" }, 401);
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
  return json({ access_token, token_type: "Bearer", expires_in: 3600 });
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
