import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";

describe("documentation examples", () => {
  it("loads the example config with container-provided credentials", () => {
    const dir = join(tmpdir(), `gateway-docs-${process.pid}`);
    mkdirSync(dir, { recursive: true });
    const secretPath = join(dir, "portainer_api_key");
    writeFileSync(secretPath, "example-secret\n");
    const raw = parse(readFileSync("examples/config.yaml", "utf8")) as any;
    raw.services["portainer-prod"].credentials[0].source.path = secretPath;

    const config = validateConfig(raw, {
      AGENT_GATEWAY_MCP_TOKEN: "dev-token",
    });

    expect(config.services["portainer-prod"]?.credentials[0]?.secret).toBe("example-secret");
  });

  it("does not include example raw downstream credentials in docs", () => {
    const files = [
      "docker-compose.example.yaml",
      "examples/config.yaml",
      "docs/config-reference.md",
      "docs/codex-setup.md",
      "docs/security-notes.md",
    ];
    const joined = files.map((file) => readFileSync(file, "utf8")).join("\n");

    expect(joined).not.toContain("portainer-secret");
    expect(joined).not.toContain("raw-secret");
    expect(joined).not.toContain("super-secret-api-key");
  });
});
