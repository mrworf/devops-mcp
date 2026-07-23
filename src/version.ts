import { readFileSync } from "node:fs";

export type PackageMetadataReader = (url: URL) => string;

const packageMetadataUrl = new URL("../package.json", import.meta.url);

export function readPackageVersion(
  readMetadata: PackageMetadataReader = (url) => readFileSync(url, "utf8"),
  metadataUrl = packageMetadataUrl,
): string {
  let source: string;
  try {
    source = readMetadata(metadataUrl);
  } catch {
    throw new Error("Unable to read SecretSauce package metadata.");
  }

  let metadata: unknown;
  try {
    metadata = JSON.parse(source);
  } catch {
    throw new Error("SecretSauce package metadata is malformed.");
  }
  if (!isRecord(metadata) || typeof metadata.version !== "string" || metadata.version.trim().length === 0) {
    throw new Error("SecretSauce package metadata has no valid version.");
  }
  return metadata.version;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export const PACKAGE_VERSION = readPackageVersion();
