import { validateConfig } from "../src/config.js";
import type { AuthContext, GatewayConfig } from "../src/types.js";

export function registryConfig(): GatewayConfig {
  return validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
    services: {
      "portainer-prod": {
        type: "http",
        name: "Portainer Production",
        description: "Main Portainer instance",
        api_docs_url: "https://api.example.org/portainer/openapi.json",
        destinations: [{
          name: "primary",
          base_url: "https://portainer.internal:9443",
          schemes: ["https"],
          hosts: [
            { exact: "portainer.internal" },
            { suffix: ".home.arpa" },
            { regex: "^portainer-[a-z0-9-]+\\.internal$" },
          ],
          ports: [9443],
        }],
        tls: { verify: false },
        credentials: [{
          id: "api_key",
          usage: { kind: "header", name: "X-API-Key" },
          source: { kind: "env", name: "PORTAINER_API_KEY" },
        }],
        access: { users: ["henric@example.com"] },
        policy: { mode: "deny", rules: [] },
      },
      "opnsense-home": {
        type: "http",
        name: "OPNsense Home",
        destinations: [{ name: "primary", base_url: "https://opnsense.internal" }],
        credentials: [{
          id: "api_key",
          usage: { kind: "header", name: "X-API-Key" },
          source: { kind: "env", name: "OPNSENSE_API_KEY" },
        }],
        access: { users: ["ada@example.com"] },
      },
    },
  }, {
    TEST_GATEWAY_TOKEN: "dev-token",
    PORTAINER_API_KEY: "portainer-secret",
    OPNSENSE_API_KEY: "opnsense-secret",
  });
}

export function auth(subject: string, sessionId?: string): AuthContext {
  return {
    subject,
    scopes: ["gateway.read", "gateway.request"],
    mode: "bearer",
    ...(sessionId === undefined ? {} : { sessionId }),
  };
}
