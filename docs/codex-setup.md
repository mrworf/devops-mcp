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
ChatGPT web developer-mode apps connect to the hosted MCP endpoint, for example:

```text
https://mcp.example.org/mcp
```

Use `auth.mode: builtin_oauth` or an external OAuth provider for hosted ChatGPT. Bearer mode publishes protected resource metadata with `authorization_servers: []`, so ChatGPT cannot start an OAuth login flow and may report "No OAuth" during setup.

For the built-in private OAuth mode:

1. Set `server.resource` and `auth.builtin_oauth.issuer` to the public HTTPS origin, for example `https://mcp.example.org`.
2. Configure one admin username and a PBKDF2 password hash through environment variables or mounted secret files.
3. Mount an RSA private signing key at `auth.builtin_oauth.signing_key_file`.
4. Add ChatGPT's CIMD origin or exact client metadata URL to `auth.builtin_oauth.allowed_clients`.
5. In ChatGPT developer mode, create the app with the public `/mcp` URL.
