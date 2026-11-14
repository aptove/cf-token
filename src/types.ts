export interface Env {
  CLIENT_REGISTRY: KVNamespace;
  RS_PRIVATE_KEY: string;       // PEM private key (wrangler secret put RS_PRIVATE_KEY)
  ADMIN_CLIENT_SECRET: string;  // secret for the admin client (wrangler secret put ADMIN_CLIENT_SECRET)
  ADMIN_CLIENT_ID: string;      // [vars] — configurable admin client identifier
  TOKEN_ISSUER: string;         // "https://token.aptove.com"
  TOKEN_AUDIENCE: string;       // "https://push.aptove.com"

  // Cloudflare native rate limiters (Tier 1 — hard spacing)
  TOKEN_ABUSE_LIMITER: RateLimit;
  HEALTH_LIMITER: RateLimit;
  JWKS_LIMITER: RateLimit;

  // Token bucket configuration (Tier 2 — precise enforcement)
  TOKEN_BUCKET_CAPACITY: string;       // default "5"
  TOKEN_REFILL_INTERVAL_MS: string;    // default "3600000" (1 hr)
}

/** Client record stored in KV under "client:<client_id>" */
export interface ClientRecord {
  hashed_secret: string; // PBKDF2-SHA256 output, base64
  salt: string;          // 16 random bytes, base64
  scope: "push:write" | "admin";
  created_at: string;    // ISO 8601
}

/** Claims embedded in every issued JWT */
export interface JwtClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  scope: "push:write" | "admin";
}
