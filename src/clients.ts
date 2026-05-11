import type { ClientRecord } from "./types";

const PREFIX = "client:";

/** Hash a secret with PBKDF2-SHA256 and a fresh random salt. */
export async function hashSecret(
  secret: string,
): Promise<{ hashed_secret: string; salt: string }> {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = btoa(String.fromCharCode(...saltBytes));

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const hashBuf = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: 100_000 },
    keyMaterial,
    256,
  );
  const hashed_secret = btoa(String.fromCharCode(...new Uint8Array(hashBuf)));
  return { hashed_secret, salt };
}

/** Re-derive the PBKDF2 hash and compare byte-by-byte (constant time). */
export async function verifySecret(
  secret: string,
  record: ClientRecord,
): Promise<boolean> {
  const saltBytes = Uint8Array.from(atob(record.salt), (c) => c.charCodeAt(0));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const hashBuf = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: 100_000 },
    keyMaterial,
    256,
  );
  const derived = btoa(String.fromCharCode(...new Uint8Array(hashBuf)));

  // Constant-time byte comparison
  const aBytes = Uint8Array.from(atob(derived), (c) => c.charCodeAt(0));
  const bBytes = Uint8Array.from(atob(record.hashed_secret), (c) => c.charCodeAt(0));
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) {
    diff |= aBytes[i]! ^ bBytes[i]!;
  }
  return diff === 0;
}

/**
 * Create a new client in KV. Returns the plaintext secret (shown exactly once).
 * The secret is 32 random bytes encoded as 64 hex characters.
 */
export async function createClient(
  kv: KVNamespace,
  clientId: string,
  scope: "push:write" | "admin",
): Promise<string> {
  const secretBytes = crypto.getRandomValues(new Uint8Array(32));
  const secret = Array.from(secretBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const { hashed_secret, salt } = await hashSecret(secret);
  const record: ClientRecord = {
    hashed_secret,
    salt,
    scope,
    created_at: new Date().toISOString(),
  };
  await kv.put(`${PREFIX}${clientId}`, JSON.stringify(record));
  return secret;
}

export async function getClient(
  kv: KVNamespace,
  clientId: string,
): Promise<ClientRecord | null> {
  return kv.get<ClientRecord>(`${PREFIX}${clientId}`, "json");
}

export async function deleteClient(kv: KVNamespace, clientId: string): Promise<void> {
  await kv.delete(`${PREFIX}${clientId}`);
}
