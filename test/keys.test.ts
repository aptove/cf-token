import { describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import { getJwks, signJwt, getPublicCryptoKey } from "../src/keys";
import type { JwtClaims } from "../src/types";

function b64urlToBytes(s: string): Uint8Array {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

describe("getJwks", () => {
  it("returns a JWKS with an RSA key", async () => {
    const jwksStr = await getJwks(env);
    const jwks = JSON.parse(jwksStr) as { keys: unknown[] };
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys.length).toBe(1);
    const key = jwks.keys[0] as Record<string, string>;
    expect(key.kty).toBe("RSA");
    expect(key.alg).toBe("RS256");
    expect(key.use).toBe("sig");
    expect(typeof key.n).toBe("string");
    expect(typeof key.e).toBe("string");
    expect(typeof key.kid).toBe("string");
    expect(key.kid).toHaveLength(16);
  });

  it("returns the same kid on repeated calls (module cache)", async () => {
    const jwks1 = JSON.parse(await getJwks(env)) as { keys: Array<{ kid: string }> };
    const jwks2 = JSON.parse(await getJwks(env)) as { keys: Array<{ kid: string }> };
    expect(jwks1.keys[0]?.kid).toBe(jwks2.keys[0]?.kid);
  });
});

describe("signJwt + verify", () => {
  it("produces a JWT that can be verified with the public key", async () => {
    const iat = Math.floor(Date.now() / 1000);
    const claims: JwtClaims = {
      iss: env.TOKEN_ISSUER,
      sub: "test-client",
      aud: env.TOKEN_AUDIENCE,
      iat,
      exp: iat + 3600,
      scope: "push:write",
    };

    const token = await signJwt(claims, env);
    const parts = token.split(".");
    expect(parts).toHaveLength(3);

    // Verify using the public key
    const publicKey = await getPublicCryptoKey(env);
    const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
    const signingInput = `${headerB64}.${payloadB64}`;
    const valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      b64urlToBytes(signatureB64),
      new TextEncoder().encode(signingInput),
    );
    expect(valid).toBe(true);

    // Decode payload and verify claims
    const decoded = JSON.parse(
      new TextDecoder().decode(b64urlToBytes(payloadB64)),
    ) as JwtClaims;
    expect(decoded.sub).toBe("test-client");
    expect(decoded.scope).toBe("push:write");
    expect(decoded.iss).toBe(env.TOKEN_ISSUER);
    expect(decoded.aud).toBe(env.TOKEN_AUDIENCE);
  });
});
