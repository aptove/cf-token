#!/usr/bin/env node
/**
 * Generate RSA-2048 key pair for cf-token.
 * Run once locally: node scripts/generate-keys.mjs
 *
 * Then deploy the private key as a Wrangler secret:
 *   wrangler secret put RS_PRIVATE_KEY
 *   (paste the PEM output when prompted)
 *
 * The kid value is derived at runtime inside the Worker from the key modulus.
 */

import { generateKeyPairSync, createPublicKey, createHash } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Derive kid: first 16 hex chars of SHA-256 of public key modulus
const jwk = createPublicKey(publicKey).export({ format: "jwk" });
const modulusBytes = Buffer.from(jwk.n, "base64url");
const kid = createHash("sha256").update(modulusBytes).digest("hex").slice(0, 16);

console.log("=== RSA-2048 Private Key (paste as RS_PRIVATE_KEY secret) ===");
console.log(privateKey);
console.log("=== Key ID (kid) — derived at runtime, shown here for reference ===");
console.log(kid);
console.log("\nNext steps:");
console.log("  wrangler secret put RS_PRIVATE_KEY");
console.log("  wrangler secret put ADMIN_CLIENT_SECRET");
