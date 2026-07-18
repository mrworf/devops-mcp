import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { runDockerMetadata } from "../scripts/docker-metadata.mjs";

const sha = "0123456789abcdef0123456789abcdef01234567";

describe("Docker CI metadata", () => {
  it("generates main, SHA, and latest tags with OCI labels for main pushes", () => {
    const output = runMetadata({ GITHUB_EVENT_NAME: "push", GITHUB_REF: "refs/heads/main", GITHUB_REF_NAME: "main" });

    expect(output.tags).toEqual([
      "ghcr.io/exampleowner/secretsauce-mcp:main",
      "ghcr.io/exampleowner/secretsauce-mcp:sha-0123456",
      "ghcr.io/exampleowner/secretsauce-mcp:latest",
    ]);
    expect(output.labels).toContain("org.opencontainers.image.version=main");
    expect(output.labels).toContain(`org.opencontainers.image.revision=${sha}`);
    expect(output.labels).toContain("org.opencontainers.image.licenses=GPL-3.0-only");
    expect(output.labels).toContain("org.opencontainers.image.title=SecretSauce (MCP)");
    expect(output.labels).toContain("org.opencontainers.image.description=Give agents access, not secrets");
    expect(output.labels).toContain("org.opencontainers.image.source=https://github.com/ExampleOwner/secretsauce-mcp");
    expect(output.labels).not.toContain(["Agent", "Credential", "Gateway"].join(" "));
  });

  it("sanitizes feature branches and omits latest", () => {
    const output = runMetadata({
      GITHUB_EVENT_NAME: "push",
      GITHUB_REF: "refs/heads/Feature/oauth refresh",
      GITHUB_REF_NAME: "Feature/oauth refresh",
    });

    expect(output.tags).toEqual([
      "ghcr.io/exampleowner/secretsauce-mcp:Feature-oauth-refresh",
      "ghcr.io/exampleowner/secretsauce-mcp:sha-0123456",
    ]);
    expect(output.labels).toContain("org.opencontainers.image.version=Feature-oauth-refresh");
  });

  it("generates only a SHA tag for pull-request validation", () => {
    const output = runMetadata({ GITHUB_EVENT_NAME: "pull_request", GITHUB_REF: "refs/pull/42/merge", GITHUB_REF_NAME: "42/merge" });

    expect(output.tags).toEqual(["ghcr.io/exampleowner/secretsauce-mcp:sha-0123456"]);
    expect(output.labels).toContain("org.opencontainers.image.version=sha-0123456");
  });

  it("rejects missing and malformed Actions inputs without writing outputs", () => {
    for (const overrides of [
      { GITHUB_REPOSITORY: "" },
      { IMAGE_NAME: "bad/image" },
      { GITHUB_EVENT_NAME: "workflow_dispatch" },
      { GITHUB_SHA: "not-a-sha" },
      { GITHUB_REF: "refs/tags/v1" },
      { GITHUB_OUTPUT: "" },
    ]) {
      expect(() => runMetadata(overrides), JSON.stringify(overrides)).toThrow();
    }
  });

  it("uses local metadata generation and Node 24 Docker action majors", () => {
    const source = readFileSync(".github/workflows/ci.yml", "utf8");
    const workflow = parse(source) as any;
    const steps = workflow.jobs["docker-image"].steps as Array<Record<string, unknown>>;

    expect(source).not.toContain("docker/metadata-action");
    expect(source).toContain("docker/setup-qemu-action@v4");
    expect(source).toContain("docker/setup-buildx-action@v4");
    expect(source).toContain("docker/login-action@v4");
    expect(source).toContain("docker/build-push-action@v6");
    expect(steps.some((step) => step.uses === "actions/setup-node@v5")).toBe(true);
    expect(steps.find((step) => step.id === "meta")?.run).toBe("node scripts/docker-metadata.mjs");
  });
});

function runMetadata(overrides: Record<string, string>): Record<string, string[]> {
  const directory = mkdtempSync(join(tmpdir(), "gateway-docker-metadata-"));
  const outputPath = join(directory, "github-output");
  runDockerMetadata({
    GITHUB_EVENT_NAME: "push",
    GITHUB_REF: "refs/heads/main",
    GITHUB_REF_NAME: "main",
    GITHUB_REPOSITORY_OWNER: "ExampleOwner",
    GITHUB_REPOSITORY: "ExampleOwner/secretsauce-mcp",
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_SHA: sha,
    GITHUB_OUTPUT: outputPath,
    REGISTRY: "GHCR.IO",
    IMAGE_NAME: "SecretSauce-MCP",
    ...overrides,
  }, new Date("2026-07-16T00:00:00.000Z"));
  return parseOutputs(readFileSync(outputPath, "utf8"));
}

function parseOutputs(source: string): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  const lines = source.trimEnd().split("\n");
  for (let index = 0; index < lines.length;) {
    const match = /^(\w+)<<(.+)$/.exec(lines[index] ?? "");
    if (!match) throw new Error(`Invalid output line: ${lines[index]}`);
    const values: string[] = [];
    index += 1;
    while (index < lines.length && lines[index] !== match[2]) values.push(lines[index++] ?? "");
    if (index >= lines.length) throw new Error(`Missing output delimiter: ${match[2]}`);
    result[match[1] ?? ""] = values;
    index += 1;
  }
  return result;
}
