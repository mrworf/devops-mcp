import { appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export function generateDockerMetadata(env, now = new Date()) {
  const eventName = required(env, "GITHUB_EVENT_NAME");
  if (eventName !== "push" && eventName !== "pull_request") fail("GITHUB_EVENT_NAME must be push or pull_request");

  const repositoryOwner = required(env, "GITHUB_REPOSITORY_OWNER");
  const repository = required(env, "GITHUB_REPOSITORY");
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(repositoryOwner)) fail("GITHUB_REPOSITORY_OWNER is invalid");
  if (!new RegExp(`^${escapeRegex(repositoryOwner)}/[A-Za-z0-9_.-]+$`, "i").test(repository)) fail("GITHUB_REPOSITORY is invalid");

  const registry = required(env, "REGISTRY").toLowerCase();
  const imageName = required(env, "IMAGE_NAME").toLowerCase();
  if (!/^[a-z0-9.-]+(?::[0-9]+)?$/.test(registry)) fail("REGISTRY is invalid");
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(imageName)) fail("IMAGE_NAME is invalid");

  const sha = required(env, "GITHUB_SHA").toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(sha)) fail("GITHUB_SHA must be a 40-character hexadecimal commit ID");
  const shortShaTag = `sha-${sha.slice(0, 7)}`;

  const ref = required(env, "GITHUB_REF");
  let version = shortShaTag;
  const tags = [];
  if (eventName === "push") {
    if (!ref.startsWith("refs/heads/")) fail("push GITHUB_REF must identify a branch");
    const branchTag = sanitizeTag(required(env, "GITHUB_REF_NAME"));
    tags.push(branchTag);
    version = branchTag;
  } else if (!/^refs\/pull\/[1-9][0-9]*\/merge$/.test(ref)) {
    fail("pull_request GITHUB_REF must identify a pull request merge ref");
  }
  tags.push(shortShaTag);
  if (eventName === "push" && ref === "refs/heads/main") tags.push("latest");

  const serverUrl = new URL(required(env, "GITHUB_SERVER_URL"));
  if ((serverUrl.protocol !== "https:" && serverUrl.protocol !== "http:") || serverUrl.username || serverUrl.password) {
    fail("GITHUB_SERVER_URL must be an HTTP(S) URL without credentials");
  }
  const source = `${serverUrl.toString().replace(/\/$/, "")}/${repository}`;
  const image = `${registry}/${repositoryOwner.toLowerCase()}/${imageName}`;
  return {
    tags: tags.map((tag) => `${image}:${tag}`),
    labels: [
      "org.opencontainers.image.title=Agent Credential Gateway MCP",
      "org.opencontainers.image.description=Self-hosted MCP credential gateway for policy-controlled HTTP services",
      `org.opencontainers.image.url=${source}`,
      `org.opencontainers.image.source=${source}`,
      `org.opencontainers.image.version=${version}`,
      `org.opencontainers.image.created=${now.toISOString()}`,
      `org.opencontainers.image.revision=${sha}`,
      "org.opencontainers.image.licenses=GPL-3.0-only",
    ],
  };
}

export function runDockerMetadata(env = process.env, now = new Date()) {
  const metadata = generateDockerMetadata(env, now);
  const output = required(env, "GITHUB_OUTPUT");
  if (output.includes("\n") || output.includes("\r")) fail("GITHUB_OUTPUT is invalid");
  writeMultiline(output, "tags", metadata.tags);
  writeMultiline(output, "labels", metadata.labels);
  return metadata;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    runDockerMetadata();
  } catch (error) {
    console.error(`docker-metadata: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}

function required(env, name) {
  const value = env[name];
  if (value === undefined || value.trim() === "") fail(`${name} is required`);
  if (value.includes("\n") || value.includes("\r")) fail(`${name} must be a single line`);
  return value;
}

function sanitizeTag(value) {
  const tag = value.replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^[.-]+/, "").slice(0, 128);
  if (tag === "") fail("GITHUB_REF_NAME does not produce a valid Docker tag");
  return tag;
}

function writeMultiline(path, name, values) {
  const delimiter = `DOCKER_METADATA_${name.toUpperCase()}`;
  appendFileSync(path, `${name}<<${delimiter}\n${values.join("\n")}\n${delimiter}\n`, "utf8");
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function fail(message) {
  throw new Error(message);
}
