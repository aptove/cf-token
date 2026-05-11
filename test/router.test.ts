import { describe, it, expect } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index";

async function call(
  method: string,
  path: string,
  body?: unknown,
  headers?: Record<string, string>,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const init: RequestInit = {
    method,
    headers: { "content-type": "application/json", ...headers },
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  const ctx = createExecutionContext();
  const res = await worker.fetch(
    new Request(`https://token.aptove.com${path}`, init),
    env,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

/** Obtain a fresh admin JWT using the test admin credentials from env. */
async function getAdminJwt(): Promise<string> {
  const { json } = await call("POST", "/token", {
    client_id: env.ADMIN_CLIENT_ID,
    client_secret: env.ADMIN_CLIENT_SECRET,
  });
  return json.access_token as string;
}

// ────────────────────────────────────────
// GET /health
// ────────────────────────────────────────

describe("GET /health", () => {
  it("returns healthy status", async () => {
    const { status, json } = await call("GET", "/health");
    expect(status).toBe(200);
    expect(json.ok).toBe(true);
    expect(json.status).toBe("healthy");
    expect(typeof json.timestamp).toBe("string");
  });
});

// ────────────────────────────────────────
// GET /.well-known/jwks.json
// ────────────────────────────────────────

describe("GET /.well-known/jwks.json", () => {
  it("returns a JWKS document", async () => {
    const { status, json } = await call("GET", "/.well-known/jwks.json");
    expect(status).toBe(200);
    expect(Array.isArray(json.keys)).toBe(true);
    const key = (json.keys as unknown[])[0] as Record<string, string>;
    expect(key.kty).toBe("RSA");
    expect(key.alg).toBe("RS256");
  });
});

// ────────────────────────────────────────
// POST /token
// ────────────────────────────────────────

describe("POST /token — admin", () => {
  it("issues an admin JWT with correct credentials", async () => {
    const { status, json } = await call("POST", "/token", {
      client_id: env.ADMIN_CLIENT_ID,
      client_secret: env.ADMIN_CLIENT_SECRET,
    });
    expect(status).toBe(200);
    expect(typeof json.access_token).toBe("string");
    expect(json.token_type).toBe("Bearer");
    expect(json.expires_in).toBe(3600);

    // Decode and check claims
    const token = json.access_token as string;
    const payloadB64 = token.split(".")[1]!;
    const padded = payloadB64 + "=".repeat((4 - (payloadB64.length % 4)) % 4);
    const payload = JSON.parse(atob(padded.replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.sub).toBe(env.ADMIN_CLIENT_ID);
    expect(payload.scope).toBe("admin");
  });

  it("rejects wrong admin secret", async () => {
    const { status, json } = await call("POST", "/token", {
      client_id: env.ADMIN_CLIENT_ID,
      client_secret: "wrong-secret",
    });
    expect(status).toBe(401);
    expect(json.error).toBe("invalid_client");
  });

  it("rejects missing credentials", async () => {
    const { status, json } = await call("POST", "/token", {});
    expect(status).toBe(401);
    expect(json.error).toBe("invalid_client");
  });
});

// ────────────────────────────────────────
// POST /clients + DELETE /clients/:id
// ────────────────────────────────────────

describe("POST /clients", () => {
  it("creates a push:write client with admin JWT", async () => {
    const adminJwt = await getAdminJwt();
    const clientId = `ci-client-${Date.now()}`;
    const { status, json } = await call(
      "POST",
      "/clients",
      { client_id: clientId, scope: "push:write" },
      { Authorization: `Bearer ${adminJwt}` },
    );
    expect(status).toBe(201);
    expect(json.ok).toBe(true);
    expect(json.client_id).toBe(clientId);
    expect(typeof json.client_secret).toBe("string");
    expect((json.client_secret as string).length).toBe(64);
  });

  it("rejects duplicate client_id", async () => {
    const adminJwt = await getAdminJwt();
    const clientId = `dup-client-${Date.now()}`;
    await call(
      "POST",
      "/clients",
      { client_id: clientId, scope: "push:write" },
      { Authorization: `Bearer ${adminJwt}` },
    );
    const { status, json } = await call(
      "POST",
      "/clients",
      { client_id: clientId, scope: "push:write" },
      { Authorization: `Bearer ${adminJwt}` },
    );
    expect(status).toBe(409);
    expect(json.ok).toBe(false);
  });

  it("rejects without admin JWT", async () => {
    const { status } = await call("POST", "/clients", {
      client_id: "no-auth-client",
      scope: "push:write",
    });
    expect(status).toBe(401);
  });

  it("rejects invalid scope", async () => {
    const adminJwt = await getAdminJwt();
    const { status } = await call(
      "POST",
      "/clients",
      { client_id: "bad-scope-client", scope: "read:all" },
      { Authorization: `Bearer ${adminJwt}` },
    );
    expect(status).toBe(400);
  });
});

describe("POST /token — push:write client", () => {
  it("issues a push:write JWT for a registered client", async () => {
    const adminJwt = await getAdminJwt();
    const clientId = `push-client-${Date.now()}`;
    const { json: createJson } = await call(
      "POST",
      "/clients",
      { client_id: clientId, scope: "push:write" },
      { Authorization: `Bearer ${adminJwt}` },
    );
    const clientSecret = createJson.client_secret as string;

    const { status, json } = await call("POST", "/token", {
      client_id: clientId,
      client_secret: clientSecret,
    });
    expect(status).toBe(200);
    expect(typeof json.access_token).toBe("string");

    const token = json.access_token as string;
    const payloadB64 = token.split(".")[1]!;
    const padded = payloadB64 + "=".repeat((4 - (payloadB64.length % 4)) % 4);
    const payload = JSON.parse(atob(padded.replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.scope).toBe("push:write");
    expect(payload.sub).toBe(clientId);
  });
});

describe("DELETE /clients/:id", () => {
  it("revokes a client", async () => {
    const adminJwt = await getAdminJwt();
    const clientId = `delete-client-${Date.now()}`;
    await call(
      "POST",
      "/clients",
      { client_id: clientId, scope: "push:write" },
      { Authorization: `Bearer ${adminJwt}` },
    );

    const { status, json } = await call(
      "DELETE",
      `/clients/${clientId}`,
      undefined,
      { Authorization: `Bearer ${adminJwt}` },
    );
    expect(status).toBe(200);
    expect(json.ok).toBe(true);
  });
});

describe("Unknown routes", () => {
  it("returns 404 for unknown path", async () => {
    const { status, json } = await call("GET", "/unknown");
    expect(status).toBe(404);
    expect(json.ok).toBe(false);
  });
});
