import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const testPrivateKey = readFileSync(
  join(__dirname, "test/fixtures/test-private.pem"),
  "utf-8",
);

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          kvNamespaces: ["CLIENT_REGISTRY"],
          bindings: {
            RS_PRIVATE_KEY: testPrivateKey,
            ADMIN_CLIENT_SECRET: "test-admin-secret-at-least-32-chars-long",
            ADMIN_CLIENT_ID: "test-admin",
            TOKEN_ISSUER: "https://token.aptove.com",
            TOKEN_AUDIENCE: "https://push.aptove.com",
          },
        },
      },
    },
  },
});
