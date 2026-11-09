# Changelog

## 0.1.0

First release.

- MCP over streamable HTTP at `/mcp`, with 25 tools covering repositories, files, history, issues, pull requests, reviews, merges, Actions runs and releases.
- Forgejo access tokens accepted directly as bearer tokens.
- A built-in OAuth 2.1 authorization server for hosted assistants (ChatGPT by default). The person pastes a Forgejo access token on the consent page; the gateway stores it encrypted and acts with it.
- Rate limits per token and per caller address, JSON logs with one line per tool call, and a non-root, read-only container image.
