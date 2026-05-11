import { describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import { hashSecret, verifySecret, createClient, getClient, deleteClient } from "../src/clients";

describe("hashSecret / verifySecret", () => {
  it("verifies correct secret", async () => {
    const secret = "my-super-secret";
    const { hashed_secret, salt } = await hashSecret(secret);
    const record = {
      hashed_secret,
      salt,
      scope: "push:write" as const,
      created_at: new Date().toISOString(),
    };
    expect(await verifySecret(secret, record)).toBe(true);
  });

  it("rejects wrong secret", async () => {
    const { hashed_secret, salt } = await hashSecret("correct-secret");
    const record = {
      hashed_secret,
      salt,
      scope: "push:write" as const,
      created_at: new Date().toISOString(),
    };
    expect(await verifySecret("wrong-secret", record)).toBe(false);
  });

  it("produces different hashes for different salts", async () => {
    const secret = "same-secret";
    const a = await hashSecret(secret);
    const b = await hashSecret(secret);
    expect(a.hashed_secret).not.toBe(b.hashed_secret);
    expect(a.salt).not.toBe(b.salt);
  });
});

describe("createClient / getClient / deleteClient", () => {
  it("creates a client and retrieves it", async () => {
    const clientId = `test-client-${Date.now()}`;
    const secret = await createClient(env.CLIENT_REGISTRY, clientId, "push:write");

    expect(typeof secret).toBe("string");
    expect(secret.length).toBe(64); // 32 bytes hex

    const record = await getClient(env.CLIENT_REGISTRY, clientId);
    expect(record).not.toBeNull();
    expect(record?.scope).toBe("push:write");
    expect(typeof record?.hashed_secret).toBe("string");
  });

  it("verifies the returned secret against the stored record", async () => {
    const clientId = `verify-client-${Date.now()}`;
    const secret = await createClient(env.CLIENT_REGISTRY, clientId, "push:write");
    const record = await getClient(env.CLIENT_REGISTRY, clientId);
    expect(record).not.toBeNull();
    expect(await verifySecret(secret, record!)).toBe(true);
  });

  it("returns null for unknown client", async () => {
    const record = await getClient(env.CLIENT_REGISTRY, "nonexistent-client-xyz");
    expect(record).toBeNull();
  });

  it("deletes a client", async () => {
    const clientId = `delete-client-${Date.now()}`;
    await createClient(env.CLIENT_REGISTRY, clientId, "push:write");
    await deleteClient(env.CLIENT_REGISTRY, clientId);
    const record = await getClient(env.CLIENT_REGISTRY, clientId);
    expect(record).toBeNull();
  });
});
