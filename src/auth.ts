import type { Env, JwtClaims } from "./types";
import { getPublicCryptoKey } from "./keys";

export type AdminAuthResult =
  | { ok: true; claims: JwtClaims }
  | { ok: false; error: string };

function b64urlToBytes(s: string): Uint8Array {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/**
 * Verify that the request carries a valid admin-scoped JWT.
 * Extracts the Bearer token, verifies the RS256 signature using the
 * module-cached public key, and checks iss, aud, exp, scope.
 */
export async function verifyAdminJwt(
  request: Request,
  env: Env,
): Promise<AdminAuthResult> {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return { ok: false, error: "Missing Bearer token" };
  }

  const token = authHeader.slice(7);
  const parts = token.split(".");
  if (parts.length !== 3) {
    return { ok: false, error: "Malformed JWT" };
  }

  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

  let claims: JwtClaims;
  try {
    claims = JSON.parse(
      new TextDecoder().decode(b64urlToBytes(payloadB64)),
    ) as JwtClaims;
  } catch {
    return { ok: false, error: "Invalid JWT payload" };
  }

  if (claims.exp < Math.floor(Date.now() / 1000)) {
    return { ok: false, error: "JWT expired" };
  }
  if (claims.iss !== env.TOKEN_ISSUER) {
    return { ok: false, error: "Invalid issuer" };
  }
  if (claims.aud !== env.TOKEN_AUDIENCE) {
    return { ok: false, error: "Invalid audience" };
  }
  if (claims.scope !== "admin") {
    return { ok: false, error: "Insufficient scope (admin required)" };
  }

  const publicKey = await getPublicCryptoKey(env);
  const signingInput = `${headerB64}.${payloadB64}`;
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    b64urlToBytes(signatureB64),
    new TextEncoder().encode(signingInput),
  );

  if (!valid) {
    return { ok: false, error: "Invalid signature" };
  }
  return { ok: true, claims };
}
