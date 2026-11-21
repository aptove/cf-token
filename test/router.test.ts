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

// ────────────────────────────────────────
// Binding secret enforcement
// ────────────────────────────────────────

describe("POST /token — binding_secret enforcement", () => {
  it("returns binding_secret on first token request", async () => {
    const adminJwt = await getAdminJwt();
    const clientId = `bind-first-${Date.now()}`;
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
      agent_id: "test-agent-uuid",
      device_id: "test-device-hash",
    });
    expect(status).toBe(200);
    expect(typeof json.binding_secret).toBe("string");
    expect((json.binding_secret as string).length).toBe(64);
    expect(typeof json.access_token).toBe("string");
  });

  it("requires binding_secret on subsequent requests", async () => {
    const adminJwt = await getAdminJwt();
    const clientId = `bind-require-${Date.now()}`;
    const { json: createJson } = await call(
      "POST",
      "/clients",
      { client_id: clientId, scope: "push:write" },
      { Authorization: `Bearer ${adminJwt}` },
    );
    const clientSecret = createJson.client_secret as string;

    // First request — get binding_secret
    const { json: firstJson } = await call("POST", "/token", {
      client_id: clientId,
      client_secret: clientSecret,
    });
    const bindingSecret = firstJson.binding_secret as string;
    expect(typeof bindingSecret).toBe("string");

    // Second request without binding_secret → 403
    const { status: status2, json: json2 } = await call("POST", "/token", {
      client_id: clientId,
      client_secret: clientSecret,
    });
    expect(status2).toBe(403);
    expect(json2.error).toBe("binding_secret_required");
  });

  it("accepts correct binding_secret on subsequent requests", async () => {
    const adminJwt = await getAdminJwt();
    const clientId = `bind-correct-${Date.now()}`;
    const { json: createJson } = await call(
      "POST",
      "/clients",
      { client_id: clientId, scope: "push:write" },
      { Authorization: `Bearer ${adminJwt}` },
    );
    const clientSecret = createJson.client_secret as string;

    // First request
    const { json: firstJson } = await call("POST", "/token", {
      client_id: clientId,
      client_secret: clientSecret,
    });
    const bindingSecret = firstJson.binding_secret as string;

    // Second request with correct binding_secret
    const { status, json } = await call("POST", "/token", {
      client_id: clientId,
      client_secret: clientSecret,
      binding_secret: bindingSecret,
    });
    expect(status).toBe(200);
    expect(typeof json.access_token).toBe("string");
    // Should NOT return binding_secret again
    expect(json.binding_secret).toBeUndefined();
  });

  it("rejects wrong binding_secret", async () => {
    const adminJwt = await getAdminJwt();
    const clientId = `bind-wrong-${Date.now()}`;
    const { json: createJson } = await call(
      "POST",
      "/clients",
      { client_id: clientId, scope: "push:write" },
      { Authorization: `Bearer ${adminJwt}` },
    );
    const clientSecret = createJson.client_secret as string;

    // First request — establish binding
    await call("POST", "/token", {
      client_id: clientId,
      client_secret: clientSecret,
    });

    // Second request with wrong binding_secret
    const { status, json } = await call("POST", "/token", {
      client_id: clientId,
      client_secret: clientSecret,
      binding_secret: "0".repeat(64),
    });
    expect(status).toBe(403);
    expect(json.error).toBe("invalid_binding_secret");
  });

  it("stores monitoring metadata (agent_id, device_id, last_seen, last_ip)", async () => {
    const adminJwt = await getAdminJwt();
    const clientId = `meta-${Date.now()}`;
    const { json: createJson } = await call(
      "POST",
      "/clients",
      { client_id: clientId, scope: "push:write" },
      { Authorization: `Bearer ${adminJwt}` },
    );
    const clientSecret = createJson.client_secret as string;

    await call("POST", "/token", {
      client_id: clientId,
      client_secret: clientSecret,
      agent_id: "agent-uuid-123",
      device_id: "device-hash-456",
    });

    // Read the client record directly from KV
    const record = await env.CLIENT_REGISTRY.get<Record<string, unknown>>(`client:${clientId}`, "json");
    expect(record).not.toBeNull();
    expect(record!.bound_agent_id).toBe("agent-uuid-123");
    expect(record!.last_device_id).toBe("device-hash-456");
    expect(typeof record!.last_seen).toBe("string");
  });
});

// ────────────────────────────────────────
// Admin endpoints
// ────────────────────────────────────────

describe("GET /admin/clients", () => {
  it("lists clients with binding metadata", async () => {
    const adminJwt = await getAdminJwt();
    const clientId = `admin-list-${Date.now()}`;
    const { json: createJson } = await call(
      "POST",
      "/clients",
      { client_id: clientId, scope: "push:write" },
      { Authorization: `Bearer ${adminJwt}` },
    );
    const clientSecret = createJson.client_secret as string;

    // Make a token request to populate monitoring metadata
    await call("POST", "/token", {
      client_id: clientId,
      client_secret: clientSecret,
      agent_id: "list-test-agent",
    });

    const { status, json } = await call(
      "GET",
      "/admin/clients",
      undefined,
      { Authorization: `Bearer ${adminJwt}` },
    );
    expect(status).toBe(200);
    expect(json.ok).toBe(true);
    expect(Array.isArray(json.clients)).toBe(true);

    const clients = json.clients as Array<Record<string, unknown>>;
    const found = clients.find((c) => c.client_id === clientId);
    expect(found).toBeDefined();
    expect(found!.bound_agent_id).toBe("list-test-agent");
    expect(found!.has_binding).toBe(true);
  });

  it("rejects without admin JWT", async () => {
    const { status } = await call("GET", "/admin/clients");
    expect(status).toBe(401);
  });
});

describe("GET /admin/device-overlaps", () => {
  it("detects same device_id across multiple clients", async () => {
    const adminJwt = await getAdminJwt();
    const sharedDeviceId = `shared-device-${Date.now()}`;

    // Create two clients with the same device_id
    for (let i = 0; i < 2; i++) {
      const clientId = `overlap-${i}-${Date.now()}`;
      const { json: createJson } = await call(
        "POST",
        "/clients",
        { client_id: clientId, scope: "push:write" },
        { Authorization: `Bearer ${adminJwt}` },
      );
      const clientSecret = createJson.client_secret as string;

      // First token request gets binding_secret
      const { json: tokenJson } = await call("POST", "/token", {
        client_id: clientId,
        client_secret: clientSecret,
        device_id: sharedDeviceId,
      });

      // Second token request uses binding_secret (to avoid 403)
      if (tokenJson.binding_secret) {
        await call("POST", "/token", {
          client_id: clientId,
          client_secret: clientSecret,
          device_id: sharedDeviceId,
          binding_secret: tokenJson.binding_secret,
        });
      }
    }

    const { status, json } = await call(
      "GET",
      "/admin/device-overlaps?min_clients=2",
      undefined,
      { Authorization: `Bearer ${adminJwt}` },
    );
    expect(status).toBe(200);
    expect(json.ok).toBe(true);
    expect(Array.isArray(json.overlaps)).toBe(true);

    const overlaps = json.overlaps as Array<Record<string, unknown>>;
    const found = overlaps.find((o) => o.device_id === sharedDeviceId);
    expect(found).toBeDefined();
    expect((found!.clients as unknown[]).length).toBeGreaterThanOrEqual(2);
  });

  it("rejects without admin JWT", async () => {
    const { status } = await call("GET", "/admin/device-overlaps");
    expect(status).toBe(401);
  });
});

// ────────────────────────────────────────
// Unknown routes
// ────────────────────────────────────────

describe("Unknown routes", () => {
  it("returns 404 for unknown path", async () => {
    const { status, json } = await call("GET", "/unknown");
    expect(status).toBe(404);
    expect(json.ok).toBe(false);
  });
});
