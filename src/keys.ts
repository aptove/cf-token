import type { Env, JwtClaims } from "./types";

// Module-level caches — reused across requests in the same isolate warm state.
let cachedPrivateKey: CryptoKey | null = null;
let cachedPublicKey: CryptoKey | null = null;
let cachedJwks: string | null = null;
let cachedKid: string | null = null;

/** Decode a base64url string to Uint8Array. */
function b64urlToBytes(s: string): Uint8Array {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/** Encode bytes (Uint8Array or ArrayBuffer) to base64url. */
function bytesToB64url(input: Uint8Array | ArrayBuffer): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/** Convert PEM-encoded PKCS8 private key to DER bytes. */
function pemToDer(pem: string): ArrayBuffer {
  const b64 = pem
    .split("\n")
    .filter((l) => !l.startsWith("-----"))
    .join("");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/** Import and cache the RSA private key from env. */
async function getPrivateKey(env: Env): Promise<CryptoKey> {
  if (cachedPrivateKey) return cachedPrivateKey;
  const der = pemToDer(env.RS_PRIVATE_KEY);
  cachedPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true, // extractable so we can derive public key components
    ["sign"],
  );
  return cachedPrivateKey;
}

/** Derive and cache the RSA public CryptoKey for verification. */
export async function getPublicCryptoKey(env: Env): Promise<CryptoKey> {
  if (cachedPublicKey) return cachedPublicKey;
  const privateKey = await getPrivateKey(env);
  const jwk = await crypto.subtle.exportKey("jwk", privateKey) as JsonWebKey;
  cachedPublicKey = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", key_ops: ["verify"] },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return cachedPublicKey;
}

/** Derive and cache the key ID (kid): first 16 hex chars of SHA-256 of modulus. */
async function getKid(env: Env): Promise<string> {
  if (cachedKid) return cachedKid;
  const privateKey = await getPrivateKey(env);
  const jwk = await crypto.subtle.exportKey("jwk", privateKey) as JsonWebKey;
  const nBytes = b64urlToBytes(jwk.n as string);
  const hashBuf = await crypto.subtle.digest("SHA-256", nBytes);
  const hashHex = Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  cachedKid = hashHex.slice(0, 16);
  return cachedKid;
}

/** Return the JWKS JSON string (cached in module scope). */
export async function getJwks(env: Env): Promise<string> {
  if (cachedJwks) return cachedJwks;
  const privateKey = await getPrivateKey(env);
  const jwk = await crypto.subtle.exportKey("jwk", privateKey) as JsonWebKey;
  const kid = await getKid(env);
  const jwksDoc = {
    keys: [
      {
        kty: "RSA",
        use: "sig",
        alg: "RS256",
        kid,
        n: jwk.n,
        e: jwk.e,
      },
    ],
  };
  cachedJwks = JSON.stringify(jwksDoc);
  return cachedJwks;
}

/** Sign a JWT with RS256 using the cached private key. */
export async function signJwt(claims: JwtClaims, env: Env): Promise<string> {
  const kid = await getKid(env);
  const header = { alg: "RS256", typ: "JWT", kid };

  const headerB64 = bytesToB64url(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = bytesToB64url(new TextEncoder().encode(JSON.stringify(claims)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const privateKey = await getPrivateKey(env);
  const signatureBuf = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(signingInput),
  );

  return `${signingInput}.${bytesToB64url(signatureBuf)}`;
}
