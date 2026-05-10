const http = require("node:http");
const { TokenService } = require("./token-service");

function writeJson(response, statusCode, payload) {
  response.writeHead(statusCode, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload));
}

function createServer({ tokenService = new TokenService(), env = process.env } = {}) {
  const tokenConfig = {
    tokenUrl: env.CF_TOKEN_URL,
    clientId: env.CF_CLIENT_ID,
    clientSecret: env.CF_CLIENT_SECRET,
    audience: env.CF_AUDIENCE,
    scope: env.CF_SCOPE
  };

  return http.createServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/health") {
      writeJson(response, 200, { status: "ok" });
      return;
    }

    if (request.method === "POST" && request.url === "/token") {
      try {
        const accessToken = await tokenService.getToken(tokenConfig);
        writeJson(response, 200, { access_token: accessToken, token_type: "Bearer" });
      } catch (error) {
        writeJson(response, 500, { error: error.message });
      }
      return;
    }

    writeJson(response, 404, { error: "Not found" });
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  const server = createServer();
  server.listen(port, () => {
    console.log(`cf-token service listening on port ${port}`);
  });
}

module.exports = { createServer };
