const test = require("node:test");
const assert = require("node:assert/strict");
const { createServer } = require("../src/server");

async function startServer(tokenService) {
  const server = createServer({
    tokenService,
    env: {
      CF_TOKEN_URL: "https://example.com/oauth/token",
      CF_CLIENT_ID: "id",
      CF_CLIENT_SECRET: "secret"
    }
  });

  await new Promise((resolve) => server.listen(0, resolve));
  return server;
}

test("GET /health returns OK", async (t) => {
  const tokenService = { getToken: async () => "unused" };
  const server = await startServer(tokenService);
  t.after(() => server.close());

  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/health`);

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: "ok" });
});

test("POST /token returns access token", async (t) => {
  const tokenService = { getToken: async () => "abc123" };
  const server = await startServer(tokenService);
  t.after(() => server.close());

  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/token`, {
    method: "POST"
  });

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    access_token: "abc123",
    token_type: "Bearer"
  });
});

test("POST /token returns 500 on service error", async (t) => {
  const tokenService = {
    getToken: async () => {
      throw new Error("bad credentials");
    }
  };
  const server = await startServer(tokenService);
  t.after(() => server.close());

  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/token`, {
    method: "POST"
  });

  assert.equal(response.status, 500);
  assert.deepEqual(await response.json(), { error: "bad credentials" });
});
