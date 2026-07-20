import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
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
      SECRETSAUCE_MCP_TOKEN: "dev-token",
    });

    expect(config.services["portainer-prod"]?.credentials[0]?.secret).toBe("example-secret");
  });

  it("does not include example raw downstream credentials in docs", () => {
    const files = [
      "README.md",
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

  it("documents response scanning as defense in depth rather than an absolute isolation guarantee", () => {
    const readme = readFileSync("README.md", "utf8");
    const securityNotes = readFileSync("docs/security-notes.md", "utf8");
    const securityReview = readFileSync("docs/audits/security-review-2026-07-19.md", "utf8");

    expect(readme).toContain("Approved endpoints are part of the credential security boundary");
    expect(readme).toContain("it cannot recognize every reversible transformation");
    expect(securityNotes).toContain("Response scanning is defense in depth, not a sandbox");
    expect(securityNotes).toContain("Treat allowed methods and routes as part of the credential security boundary");
    expect(securityReview).toContain("| SEC-002 | Medium | 5.3 | Confirmed | Invertible response transformations bypass credential scanning | Accepted risk |");
    expect(readme).not.toContain("Agents are never entrusted with raw");
    expect(securityReview).not.toContain("CHAIN-001");
  });

  it("documents the full ChatGPT web MCP endpoint URL", () => {
    const docs = readFileSync("docs/codex-setup.md", "utf8");
    const chatgptWeb = docs.slice(docs.indexOf("## ChatGPT Web"));

    expect(chatgptWeb).toContain("Server URL to `https://mcp.example.org/mcp`");
    expect(chatgptWeb).toContain("origin plus `/mcp`");
    expect(chatgptWeb).not.toMatch(/Server URL to `https:\/\/mcp\.example\.org`/);
  });

  it("uses the SecretSauce identity outside preserved historical records", () => {
    const readme = readFileSync("README.md", "utf8");
    expect(readme).toContain("SecretSauce MCP — Give agents access, not secrets");
    expect(readme).toContain("Give agents access, not secrets");
    expect(readme).toContain("ghcr.io/mrworf/secretsauce-mcp");

    const activeFiles = collectFiles(".").filter((file) =>
      !file.startsWith("docs/audits/") && !file.startsWith("docs/milestones/"),
    );
    const legacyBrand = new RegExp(["agent", "credential", "gateway"].join("[ _-]"), "i");
    const legacyRepository = new RegExp(["devops", "mcp"].join("-"), "i");
    const offenders = activeFiles.filter((file) => {
      const source = readFileSync(file, "utf8");
      return legacyBrand.test(source) || legacyRepository.test(source);
    });
    expect(offenders).toEqual([]);
  });

  it("references accessible, theme-safe documentation branding assets", () => {
    const readme = readFileSync("README.md", "utf8");
    const setup = readFileSync("docs/codex-setup.md", "utf8");
    const expectedAssets = [
      "assets/brand/secretsauce-primary.png",
      "assets/brand/secretsauce-primary-docs-dark.png",
      "assets/brand/secretsauce-chef.png",
      "assets/brand/secretsauce-lockup.png",
      "assets/brand/secretsauce-lockup-docs-dark.png",
    ];

    for (const asset of expectedAssets) expect(statSync(asset).isFile()).toBe(true);
    expect(readme).toContain('alt="SecretSauce MCP — Give agents access, not secrets"');
    expect(readme).toContain('alt="SecretSauce chef holding a protected secret recipe"');
    expect(readme).toContain('media="(prefers-color-scheme: dark)"');
    expect(setup).toContain('alt="SecretSauce MCP"');
    expect(setup).toContain('media="(prefers-color-scheme: dark)"');
  });
});

function collectFiles(root: string): string[] {
  const ignored = new Set([".git", "dist", "node_modules"]);
  return readdirSync(root).flatMap((entry) => {
    if (ignored.has(entry)) return [];
    const path = root === "." ? entry : join(root, entry);
    return statSync(path).isDirectory() ? collectFiles(path) : [path];
  });
}
