import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { PACKAGE_VERSION, readPackageVersion } from "../src/version.js";

describe("package version", () => {
  it("reads the package version from source and compiled layouts", () => {
    const expected = JSON.parse(readFileSync("package.json", "utf8")).version as string;
    const compiledMetadataUrl = new URL("../package.json", pathToFileURL(resolve("dist/version.js")));

    expect(PACKAGE_VERSION).toBe(expected);
    expect(readPackageVersion((url) => readFileSync(url, "utf8"), compiledMetadataUrl)).toBe(expected);
  });

  it("rejects missing, malformed, empty, and non-string versions without exposing metadata", () => {
    const privateValue = "unrelated-private-package-content";
    const attempts = [
      () => readPackageVersion(() => { throw new Error(privateValue); }),
      () => readPackageVersion(() => `{${privateValue}`),
      () => readPackageVersion(() => JSON.stringify({ version: "", internal: privateValue })),
      () => readPackageVersion(() => JSON.stringify({ version: 7, internal: privateValue })),
    ];

    for (const attempt of attempts) {
      let message = "";
      try {
        attempt();
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toMatch(/package metadata/);
      expect(message).not.toContain(privateValue);
    }
  });
});
