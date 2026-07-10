# Codex And ChatGPT Desktop Setup

## OAuth Mode
Add the MCP server to Codex config:

```toml
[mcp_servers.agent_credential_gateway]
url = "https://gateway.home.arpa/mcp"
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
ChatGPT web does not read local Codex MCP configuration. Web support requires a separate hosted or plugin integration path and is post-MVP.
