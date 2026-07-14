# Codex And ChatGPT Desktop Setup

## OAuth Mode
Add the MCP server to Codex config:

```toml
[mcp_servers.agent_credential_gateway]
url = "https://gateway.example.org/mcp"
enabled = true
auth = "oauth"
default_tools_approval_mode = "prompt"
tool_timeout_sec = 60

[mcp_servers.agent_credential_gateway.tools.list_services]
approval_mode = "auto"

[mcp_servers.agent_credential_gateway.tools.explain_denial]
approval_mode = "auto"

[mcp_servers.agent_credential_gateway.tools.request_tokens]
approval_mode = "prompt"

[mcp_servers.agent_credential_gateway.tools.service_request]
approval_mode = "prompt"
```

Then run:

```bash
codex mcp login agent_credential_gateway
```

Register the Codex OAuth callback URL and port with the chosen identity provider according to that provider's instructions.

## Bearer Development Mode

```toml
[mcp_servers.agent_credential_gateway]
url = "http://localhost:8080/mcp"
bearer_token_env_var = "AGENT_GATEWAY_MCP_TOKEN"
enabled = true
default_tools_approval_mode = "prompt"
```

## ChatGPT Desktop
ChatGPT desktop uses the shared Codex MCP host configuration. Configure the server for Codex, then restart or refresh ChatGPT desktop so it can see the MCP server.

## ChatGPT Web
ChatGPT web developer-mode apps connect to the hosted MCP endpoint. The ChatGPT app Server URL must be the full MCP endpoint URL, including the configured `server.mcp_path`:

```text
https://mcp.example.org/mcp
```

Do not enter only the public origin as the app Server URL. `server.resource` and `auth.builtin_oauth.issuer` use the origin, such as `https://mcp.example.org`; the ChatGPT Server URL uses that origin plus `/mcp`.

Use `auth.mode: builtin_oauth` or an external OAuth provider for hosted ChatGPT. Bearer mode publishes protected resource metadata with `authorization_servers: []`, so ChatGPT cannot start an OAuth login flow and may report "No OAuth" during setup.

For the built-in private OAuth mode:

1. Set `server.resource` and `auth.builtin_oauth.issuer` to the public HTTPS origin, for example `https://mcp.example.org`.
2. Configure one admin username and a PBKDF2 password hash through environment variables or mounted secret files.
3. Mount an RSA private signing key at `auth.builtin_oauth.signing_key_file`.
4. Add ChatGPT's CIMD origin or exact client metadata URL to `auth.builtin_oauth.allowed_clients`.
5. In ChatGPT developer mode, create the app with the public `/mcp` URL.

Use these values in the ChatGPT developer-mode app form:

1. Set Connection to Server URL.
2. Set Server URL to `https://mcp.example.org/mcp`.
3. Set Authentication to OAuth.
4. Open Advanced OAuth settings, allow the discovered OAuth settings, and select the required scopes, usually `gateway.read`, `gateway.tokens`, and `gateway.request`.
5. Complete the OAuth login.
6. Confirm the app shows actions after OAuth completes: `list_services`, `request_tokens`, `service_request`, and `explain_denial`.

If ChatGPT says the app is connected but shows "No app actions available yet", OAuth probably completed but ChatGPT did not reach MCP `initialize` or `tools/list`. Check that the app Server URL ends with `/mcp`, and that the reverse proxy forwards `/mcp` to the gateway unchanged.
