# forgejo-mcp-gateway

An [MCP](https://modelcontextprotocol.io) server for [Forgejo](https://forgejo.org) that many people can share, and that hosted assistants such as ChatGPT can connect to.

Every request acts as one Forgejo user, with that user's own access token, so an assistant can do exactly what the token allows and nothing more. The gateway accepts two kinds of connection:

- **OAuth, for hosted assistants.** ChatGPT connects through the gateway's built-in OAuth server. On the consent page, the person pastes a Forgejo access token. The gateway checks it with Forgejo, stores it encrypted and acts with it from then on.
- **Tokens, for everything else.** Claude Code, scripts and other MCP clients send a Forgejo access token as the bearer token, and the gateway passes it through.

The gateway is the only thing you expose. Forgejo itself can stay on your private network: the gateway talks to it over the LAN, and the internet only ever reaches the gateway's MCP and OAuth paths.

```
ChatGPT ──HTTPS──▶ /mcp, /oauth/*, /.well-known/*  ┐
Claude Code ─────▶ /mcp (Forgejo token)            ├─ forgejo-mcp-gateway ──LAN──▶ Forgejo /api/v1
                                                   ┘   (SQLite: grants, encrypted tokens)
```

## Tools

| Read | Write |
|---|---|
| `get_me`, `search_repositories`, `list_owner_repositories`, `get_repository`, `list_branches` | `create_issue`, `update_issue`, `add_comment` |
| `list_directory`, `get_file`, `list_commits`, `get_commit`, `compare` | `create_branch`, `write_file` |
| `search_issues`, `list_issues`, `get_issue`, `list_pull_requests`, `get_pull_request` | `create_pull_request`, `review_pull_request`, `merge_pull_request` |
| `list_action_runs`, `list_releases` | |

There are no admin, delete or settings tools. Writes are guarded against races:

- `write_file` needs the file's current `sha` to replace it, so it never overwrites a file blind.
- `merge_pull_request` accepts the head commit the reviewer saw, and refuses the merge if anything was pushed since.

List tools page through results and say when more pages exist. File contents, issue bodies and diffs always come back whole.

## Quick start

```sh
cp .env.example .env        # set FORGEJO_URL, and PUBLIC_URL + SECRET_KEY for OAuth
openssl rand -hex 32        # a SECRET_KEY
docker compose -f docker-compose.example.yml up -d
curl http://localhost:8080/healthz
```

The container runs as a non-root user on a read-only filesystem. It keeps its state in one SQLite file on the `/data` volume: pending authorization requests, connections, hashed OAuth tokens and encrypted Forgejo tokens.

## Configuration

| Variable | Default | |
|---|---|---|
| `FORGEJO_URL` | required | How the gateway reaches Forgejo, e.g. `http://forgejo:3000`. |
| `FORGEJO_PUBLIC_URL` | `FORGEJO_URL` | The Forgejo address people open in a browser. Used for links on the consent page. |
| `PUBLIC_URL` | unset | This gateway's public HTTPS address, which is also the OAuth issuer. Set it together with `SECRET_KEY` to turn OAuth on. |
| `SECRET_KEY` | unset | At least 32 random bytes, hex or base64. It keys every stored hash and encrypts stored Forgejo tokens. Changing it disconnects every OAuth connection. |
| `ALLOW_FORGEJO_TOKENS` | `true` | Accept a Forgejo access token directly as the bearer token. |
| `OAUTH_CLIENTS` | ChatGPT | JSON list of `{client_id, name, redirect_uris}`. Clients are matched exactly and never registered dynamically. |
| `TRUSTED_CLIENT_IP_HEADER` | unset | The header your proxy sets to the caller's address, e.g. `CF-Connecting-IP`. Set it only when every request comes through that proxy. |
| `DATABASE_PATH` | `/data/gateway.sqlite3` | |
| `RATE_LIMIT_PER_MINUTE` / `RATE_LIMIT_BURST` | `120` / `60` | Limits `/mcp` per token. The limit per caller address is four times higher. |
| `OAUTH_RATE_LIMIT_PER_MINUTE` | `30` | Limits the OAuth pages and the token endpoint per caller address. |
| `FORGEJO_TIMEOUT_SECONDS` / `FORGEJO_MAX_ATTEMPTS` | `20` / `3` | Reads are retried with backoff on timeouts, 429 and 5xx. Writes are never retried. |
| `TOKEN_CACHE_SECONDS` | `60` | How long a verified Forgejo token is trusted before Forgejo is asked again. |
| `LOG_LEVEL` | `INFO` | Logs are JSON, one line per event. Each tool call logs the user, tool, outcome and latency. |

## Exposing it

Hosted assistants call the gateway from their own servers, so it needs a public HTTPS address. Route only these paths to it, and keep everything else (including Forgejo itself) private:

```
^/(mcp$|\.well-known/oauth-(authorization-server|protected-resource)|oauth/)
```

With Cloudflare Tunnel, that is an ingress rule with this `path`, and the service pointing at the gateway, never at Forgejo. With Caddy:

```
forgejo-mcp.example.com {
	@gateway path_regexp ^/(mcp$|\.well-known/oauth-(authorization-server|protected-resource)|oauth/)
	handle @gateway {
		reverse_proxy gateway:8080
	}
	handle {
		respond 404
	}
}
```

`/healthz` is meant for your own monitoring, so leave it off the public route.

## Connecting

**ChatGPT.** Add a connector with the MCP server URL `https://<PUBLIC_URL>/mcp` and OAuth authentication. ChatGPT finds the authorization server on its own. When the consent page opens, create a Forgejo access token under *Settings → Applications* and paste it. The token needs at least `read:user`, plus the repository and issue scopes you want ChatGPT to have. To disconnect, remove the connector in ChatGPT. Deleting the token in Forgejo cuts the connection off at once, and the gateway then revokes it.

**Claude Code** and other clients that can send a header:

```sh
claude mcp add --transport http forgejo https://<PUBLIC_URL>/mcp \
  --header "Authorization: Bearer <forgejo-access-token>"
```

## Security model

- **Permissions.** A connection can do what its Forgejo token can do, and no more.
- **OAuth.** The OAuth server is a fixed subset of OAuth 2.1:
  - authorization code with PKCE S256 only;
  - exact client and redirect matching (no dynamic registration, no outbound fetches);
  - resource indicators (RFC 8707) and `iss` on responses (RFC 9207).
- **Consent page.** The consent request is bound to the browser that started it. The page refuses cross-origin posts and can't be framed.
- **Token lifetimes.** Access tokens are opaque and last one hour. They're checked on every call, so a revoked connection stops working at once.
- **Replay protection.** Refresh tokens rotate, and each works once. Reusing a refresh token or an authorization code revokes the whole connection.
- **Storage.** Nothing secret is stored in the clear. OAuth tokens, codes and browser secrets are stored as keyed hashes. Forgejo tokens are encrypted with AES-256-GCM, and each ciphertext is bound to its row.
- **Refused tokens.** If Forgejo stops accepting a connection's token, the gateway revokes that connection, and the assistant has to reconnect.

## Development

```sh
uv sync
uv run pytest                 # offline: OAuth refusal paths, settings, crypto
uv run ruff check && uv run mypy
```

The live suite runs every tool and the full ChatGPT connection flow against a running gateway and a real Forgejo. Give it a scratch repository owned by the token's user; the suite opens branches, files, issues and pull requests there, and merges them.

```sh
GATEWAY_URL=http://localhost:8080 FORGEJO_TEST_TOKEN=... FORGEJO_TEST_REPO=user/sandbox \
  uv run pytest -m live
```

The gateway keeps its state in SQLite, so run a single replica. Rate limits are also kept in that process's memory.

## License

Apache-2.0
