class TokenService {
  constructor({ fetchImpl = fetch, now = () => Date.now() } = {}) {
    this.fetchImpl = fetchImpl;
    this.now = now;
    this.cache = null;
  }

  async getToken({ tokenUrl, clientId, clientSecret, audience, scope }) {
    if (!tokenUrl || !clientId || !clientSecret) {
      throw new Error("Missing Cloudflare token configuration");
    }

    if (this.cache && this.cache.expiresAtMs > this.now() + 5000) {
      return this.cache.token;
    }

    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret
    });

    if (audience) {
      body.set("audience", audience);
    }

    if (scope) {
      body.set("scope", scope);
    }

    const response = await this.fetchImpl(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    });

    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      const errorMessage = payload.error_description || payload.error || "Token request failed";
      throw new Error(`Cloudflare token request failed (${response.status}): ${errorMessage}`);
    }

    if (!payload.access_token || typeof payload.expires_in !== "number") {
      throw new Error("Cloudflare response missing access_token or expires_in");
    }

    this.cache = {
      token: payload.access_token,
      expiresAtMs: this.now() + payload.expires_in * 1000
    };

    return payload.access_token;
  }
}

module.exports = { TokenService };
