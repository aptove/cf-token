const test = require("node:test");
const assert = require("node:assert/strict");
const { TokenService } = require("../src/token-service");

test("TokenService caches token until expiration", async () => {
  let calls = 0;
  let nowMs = 1700000000000;
  const service = new TokenService({
    now: () => nowMs,
    fetchImpl: async () => {
      calls += 1;
      return {
        ok: true,
        status: 200,
        json: async () => ({ access_token: `token-${calls}`, expires_in: 60 })
      };
    }
  });

  const config = {
    tokenUrl: "https://example.com/oauth/token",
    clientId: "id",
    clientSecret: "secret"
  };

  const tokenA = await service.getToken(config);
  nowMs += 30 * 1000;
  const tokenB = await service.getToken(config);

  assert.equal(tokenA, "token-1");
  assert.equal(tokenB, "token-1");
  assert.equal(calls, 1);
});

test("TokenService refreshes token when cache is expired", async () => {
  let calls = 0;
  let nowMs = 1700000000000;
  const service = new TokenService({
    now: () => nowMs,
    fetchImpl: async () => {
      calls += 1;
      return {
        ok: true,
        status: 200,
        json: async () => ({ access_token: `token-${calls}`, expires_in: 5 })
      };
    }
  });

  const config = {
    tokenUrl: "https://example.com/oauth/token",
    clientId: "id",
    clientSecret: "secret"
  };

  const tokenA = await service.getToken(config);
  nowMs += 6 * 1000;
  const tokenB = await service.getToken(config);

  assert.equal(tokenA, "token-1");
  assert.equal(tokenB, "token-2");
  assert.equal(calls, 2);
});
