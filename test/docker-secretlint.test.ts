import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

describe("Secretlint container packaging", () => {
  it("packages immutable defaults and a mountable active rules path", () => {
    const dockerfile = readFileSync("Dockerfile", "utf8");
    expect(dockerfile).toContain("COPY config/secretlint.yaml /app/config/secretlint.yaml");
    expect(dockerfile).toContain("COPY config/secretlint.yaml /config/secretlint.yaml");
    expect(dockerfile).toContain("ENV SECRETLINT_CONFIG_PATH=/config/secretlint.yaml");
  });

  it("mounts the rules file read-only in the compose example", () => {
    const compose = parse(readFileSync("docker-compose.example.yaml", "utf8")) as any;
    const service = compose.services["agent-credential-gateway"];
    expect(service.volumes).toContain("./config/secretlint.yaml:/config/secretlint.yaml:ro");
    expect(service.environment.SECRETLINT_CONFIG_PATH).toBe("/config/secretlint.yaml");
  });
});
