import { GatewayError } from "./errors.js";
import type { DestinationConfig, HostMatcherConfig, ServiceConfig, TlsConfig } from "./types.js";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

export interface TargetInput {
  path?: string;
  url?: string;
}

export interface ResolvedTarget {
  destination: DestinationConfig;
  url: URL;
  methodPath: string;
  tls: TlsConfig;
}

export function resolveDestinationTarget(
  service: ServiceConfig,
  destinationId: string | undefined,
  input: TargetInput,
): ResolvedTarget {
  const destination = selectDestination(service, destinationId);
  const url = resolveTargetUrl(destination, input);
  validateScheme(destination, url);
  validateHost(destination, url);
  validatePort(destination, url);
  validateBaseUrl(destination, url);

  return {
    destination,
    url,
    methodPath: normalizePath(url.pathname),
    tls: destination.tls,
  };
}

export function normalizeHost(host: string): string {
  const normalized = host.toLowerCase().replace(/\.$/, "");
  const ipCandidate = normalized.startsWith("[") && normalized.endsWith("]") ? normalized.slice(1, -1) : normalized;
  if (isIP(ipCandidate) !== 0) return normalized;
  return domainToASCII(normalized) || normalized;
}

export function matchesHost(matcher: HostMatcherConfig, host: string): boolean {
  const normalized = normalizeHost(host);
  if (matcher.type === "exact") return normalized === matcher.value;
  if (matcher.type === "suffix") return normalized === matcher.value || normalized.endsWith(`.${matcher.value}`);
  return matcher.regex.test(normalized);
}

function selectDestination(service: ServiceConfig, destinationId: string | undefined): DestinationConfig {
  if (destinationId !== undefined) {
    const destination = service.destinations.find((candidate) => candidate.id === destinationId);
    if (!destination) throw new GatewayError("unknown_destination", `Unknown destination: ${destinationId}`);
    return destination;
  }
  if (service.destinations.length === 1) return service.destinations[0] as DestinationConfig;
  throw new GatewayError("unknown_destination", "destination is required when a service has multiple destinations");
}

function resolveTargetUrl(destination: DestinationConfig, input: TargetInput): URL {
  if ((input.path === undefined && input.url === undefined) || (input.path !== undefined && input.url !== undefined)) {
    throw new GatewayError("destination_not_allowed", "Provide exactly one of path or url.");
  }
  if (input.url !== undefined) {
    assertUnambiguousPathEncoding(rawAbsolutePath(input.url));
    return canonicalizeTargetPath(new URL(input.url));
  }
  const path = input.path ?? "/";
  if (!path.startsWith("/")) throw new GatewayError("destination_not_allowed", "path must start with /");
  assertUnambiguousPathEncoding(path.split(/[?#]/, 1)[0] ?? "/");
  return canonicalizeTargetPath(new URL(path, destination.baseUrl));
}

function canonicalizeTargetPath(url: URL): URL {
  url.pathname = normalizePath(url.pathname);
  return url;
}

function rawAbsolutePath(input: string): string {
  const match = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*(\/[^?#]*)?/.exec(input);
  return match?.[1] ?? "/";
}

function assertUnambiguousPathEncoding(pathname: string): void {
  for (let index = 0; index < pathname.length; index += 1) {
    if (pathname[index] !== "%") continue;
    const escape = pathname.slice(index + 1, index + 3);
    if (!/^[0-9a-f]{2}$/i.test(escape)) {
      throw new GatewayError("destination_not_allowed", "URL path contains an ambiguous percent escape.");
    }
    const byte = Number.parseInt(escape, 16);
    const character = String.fromCharCode(byte);
    if (/^[A-Za-z0-9._~-]$/.test(character) || byte === 0x2f || byte === 0x5c || byte === 0x00 || byte === 0x25) {
      throw new GatewayError("destination_not_allowed", "URL path contains an ambiguous percent escape.");
    }
    index += 2;
  }
}

function validateScheme(destination: DestinationConfig, url: URL): void {
  const scheme = url.protocol.replace(/:$/, "");
  if (!destination.schemes.includes(scheme)) {
    throw new GatewayError("scheme_not_allowed", `Scheme is not allowed: ${scheme}`);
  }
}

function validateHost(destination: DestinationConfig, url: URL): void {
  const host = normalizeHost(url.hostname);
  if (!destination.hosts.some((matcher) => matchesHost(matcher, host))) {
    throw new GatewayError("host_not_allowed", `Host is not allowed: ${host}`);
  }
}

function validatePort(destination: DestinationConfig, url: URL): void {
  const port = Number(url.port || defaultPort(url.protocol));
  if (!destination.ports.includes(port)) {
    throw new GatewayError("port_not_allowed", `Port is not allowed: ${port}`);
  }
}

function validateBaseUrl(destination: DestinationConfig, url: URL): void {
  const base = new URL(destination.baseUrl);
  const basePath = normalizePath(base.pathname);
  const targetPath = normalizePath(url.pathname);
  if (basePath !== "/" && targetPath !== basePath && !targetPath.startsWith(`${basePath}/`)) {
    throw new GatewayError("destination_not_allowed", "URL path is outside the configured destination base path.");
  }
}

function normalizePath(path: string): string {
  const segments: string[] = [];
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (segments.length > 0) segments.pop();
      continue;
    }
    segments.push(segment);
  }
  return `/${segments.join("/")}`;
}

function defaultPort(protocol: string): string {
  if (protocol === "https:") return "443";
  if (protocol === "http:") return "80";
  return "";
}
