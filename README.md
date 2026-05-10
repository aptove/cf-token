# cf-token

Cloudflare M2M token service.

## Endpoints

- `GET /health` returns service status.
- `POST /token` returns an access token from the configured Cloudflare OAuth endpoint.

## Configuration

Set these environment variables before starting:

- `CF_TOKEN_URL` (required) - OAuth token endpoint.
- `CF_CLIENT_ID` (required) - service client ID.
- `CF_CLIENT_SECRET` (required) - service client Secret.
- `CF_AUDIENCE` (optional) - audience for the token request.
- `CF_SCOPE` (optional) - scope for the token request.
- `PORT` (optional) - server port, defaults to `3000`.

## Run

```bash
npm start
```

## Test

```bash
npm test
```
