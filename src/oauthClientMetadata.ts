import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP, type LookupFunction } from "node:net";
import { InflightLimiter } from "./inflightLimiter.js";

const MAX_BODY_BYTES = 5 * 1024;
const REQUEST_TIMEOUT_MS = 5000;
const MAX_CACHE_RECORDS = 1000;
const MAX_CACHE_TTL_MS = 60 * 60 * 1000;
const MAX_CLIENT_NAME_LENGTH = 120;
let testMetadataFetch: typeof fetch | undefined;

export function setOAuthClientMetadataTestFetch(fetcher: typeof fetch | undefined): void {
  testMetadataFetch = fetcher;
}

export interface VerifiedClientMetadata {
  clientId: string;
  redirectUris: string[];
  clientName: string | null;
}

export interface MetadataAddress {
  address: string;
  family: 4 | 6;
}

export interface MetadataResponse {
  status: number;
  headers: Headers;
  body: Uint8Array;
  url: string;
}

export interface OAuthClientMetadataNetwork {
  resolve(hostname: string): Promise<MetadataAddress[]>;
  request(url: URL, address: MetadataAddress): Promise<MetadataResponse>;
}

interface CacheRecord {
  metadata: VerifiedClientMetadata;
  expiresAt: number;
}

export class OAuthClientMetadataFetcher {
  private readonly limiter: InflightLimiter;
  private readonly cache = new Map<string, CacheRecord>();
  private readonly pending = new Map<string, Promise<VerifiedClientMetadata | undefined>>();

  constructor(
    maxInflight: number,
    maxInflightPerOrigin: number,
    private readonly network: OAuthClientMetadataNetwork = productionMetadataNetwork,
    private readonly now: () => number = () => Date.now(),
  ) {
    this.limiter = new InflightLimiter(maxInflight, maxInflightPerOrigin);
  }

  async fetch(clientId: string): Promise<VerifiedClientMetadata | undefined> {
    const cached = this.cache.get(clientId);
    if (cached !== undefined) {
      if (cached.expiresAt > this.now()) {
        this.cache.delete(clientId);
        this.cache.set(clientId, cached);
        return cached.metadata;
      }
      this.cache.delete(clientId);
    }
    const existing = this.pending.get(clientId);
    if (existing !== undefined) return existing;

    const origin = new URL(clientId).origin;
    const release = this.limiter.acquire(origin);
    if (release === undefined) return undefined;
    const operation = this.fetchUncached(clientId).finally(() => {
      release();
      this.pending.delete(clientId);
    });
    this.pending.set(clientId, operation);
    return operation;
  }

  private async fetchUncached(clientId: string): Promise<VerifiedClientMetadata | undefined> {
    try {
      const url = new URL(clientId);
      if (url.protocol !== "https:") return undefined;
      const response = testMetadataFetch !== undefined
        ? await responseFromTestFetch(clientId, testMetadataFetch)
        : await fetchPinnedResponse(url, this.network);
      const metadata = verifyMetadataResponse(response, clientId);
      if (metadata === undefined) return undefined;
      const ttlMs = cacheTtl(response.headers);
      if (ttlMs !== undefined) this.cacheResult(clientId, metadata, ttlMs);
      return metadata;
    } catch {
      return undefined;
    }
  }

  private cacheResult(clientId: string, metadata: VerifiedClientMetadata, ttlMs: number): void {
    while (this.cache.size >= MAX_CACHE_RECORDS) {
      const oldest = this.cache.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.cache.delete(oldest);
    }
    this.cache.set(clientId, { metadata, expiresAt: this.now() + ttlMs });
  }
}

async function fetchPinnedResponse(url: URL, network: OAuthClientMetadataNetwork): Promise<MetadataResponse> {
  const hostname = stripIpv6Brackets(url.hostname);
  const literalFamily = isIP(hostname);
  const addresses = literalFamily === 0
    ? await network.resolve(hostname)
    : [{ address: hostname, family: literalFamily as 4 | 6 }];
  if (addresses.length === 0 || addresses.some((entry) => !isPublicMetadataAddress(entry.address))) {
    throw new Error("OAuth client metadata address is not public");
  }
  return network.request(url, addresses[0] as MetadataAddress);
}

function verifyMetadataResponse(response: MetadataResponse, clientId: string): VerifiedClientMetadata | undefined {
  if (response.url !== clientId || response.status < 200 || response.status >= 300) return undefined;
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json" && !(contentType?.startsWith("application/") && contentType.endsWith("+json"))) {
    return undefined;
  }
  if (response.body.byteLength > MAX_BODY_BYTES) return undefined;
  let metadata: unknown;
  try {
    metadata = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(response.body));
  } catch {
    return undefined;
  }
  if (typeof metadata !== "object" || metadata === null || Array.isArray(metadata)) return undefined;
  const record = metadata as Record<string, unknown>;
  if (record.client_id !== clientId || !Array.isArray(record.redirect_uris) || record.redirect_uris.length === 0) return undefined;
  if (!record.redirect_uris.every((value) => typeof value === "string" && value.trim() !== "")) return undefined;
  const rawClientName = record.client_name;
  const trimmedClientName = typeof rawClientName === "string" ? rawClientName.trim() : "";
  return {
    clientId,
    redirectUris: record.redirect_uris as string[],
    clientName: trimmedClientName !== "" && [...trimmedClientName].length <= MAX_CLIENT_NAME_LENGTH ? trimmedClientName : null,
  };
}

function cacheTtl(headers: Headers): number | undefined {
  const cacheControl = headers.get("cache-control")?.toLowerCase();
  if (cacheControl === undefined || /(?:^|,)\s*no-store\s*(?:,|$)/.test(cacheControl)) return undefined;
  const match = /(?:^|,)\s*(?:s-maxage|max-age)\s*=\s*(\d+)/.exec(cacheControl);
  if (match?.[1] === undefined) return undefined;
  const seconds = Number(match[1]);
  if (!Number.isSafeInteger(seconds) || seconds <= 0) return undefined;
  return Math.min(seconds * 1000, MAX_CACHE_TTL_MS);
}

const blockedAddresses = createBlockedAddressList();

export function isPublicMetadataAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 0) return false;
  return !blockedAddresses.check(address, family === 4 ? "ipv4" : "ipv6");
}

function createBlockedAddressList(): BlockList {
  const block = new BlockList();
  for (const [network, prefix] of [
    ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
    ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
    ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
  ] as const) block.addSubnet(network, prefix, "ipv4");
  for (const [network, prefix] of [
    ["::", 128], ["::1", 128], ["64:ff9b:1::", 48], ["100::", 64],
    ["2001:2::", 48], ["2001:10::", 28], ["2001:db8::", 32], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8],
  ] as const) block.addSubnet(network, prefix, "ipv6");
  return block;
}

function stripIpv6Brackets(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}

const productionMetadataNetwork: OAuthClientMetadataNetwork = {
  async resolve(hostname) {
    const results = await dnsLookup(hostname, { all: true, verbatim: true });
    return results.map(({ address, family }) => ({ address, family: family as 4 | 6 }));
  },
  request(url, address) {
    return requestPinned(url, address);
  },
};

async function requestPinned(url: URL, address: MetadataAddress): Promise<MetadataResponse> {
  return await new Promise((resolve, reject) => {
    const lookup: LookupFunction = (_hostname, _options, callback) => callback(null, address.address, address.family);
    const request = httpsRequest(url, {
      method: "GET",
      headers: { accept: "application/json" },
      lookup,
      servername: stripIpv6Brackets(url.hostname),
    }, (response) => {
      const declaredLength = response.headers["content-length"];
      if (declaredLength !== undefined && /^\d+$/.test(declaredLength) && Number(declaredLength) > MAX_BODY_BYTES) {
        response.destroy();
        reject(new Error("OAuth client metadata response is too large"));
        return;
      }
      const chunks: Buffer[] = [];
      let total = 0;
      response.on("data", (chunk) => {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        total += bytes.byteLength;
        if (total > MAX_BODY_BYTES) {
          response.destroy();
          request.destroy();
          reject(new Error("OAuth client metadata response is too large"));
          return;
        }
        chunks.push(bytes);
      });
      response.on("error", reject);
      response.on("end", () => resolve({
        status: response.statusCode ?? 0,
        headers: new Headers(Object.entries(response.headers).flatMap(([name, value]) => value === undefined ? [] : [[name, Array.isArray(value) ? value.join(", ") : value]])),
        body: Buffer.concat(chunks),
        url: url.toString(),
      }));
    });
    request.setTimeout(REQUEST_TIMEOUT_MS, () => request.destroy(new Error("OAuth client metadata request timed out")));
    request.on("error", reject);
    request.end();
  });
}

async function responseFromTestFetch(clientId: string, fetcher: typeof fetch): Promise<MetadataResponse> {
  const response = await fetcher(clientId, { redirect: "error", signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  const body = new Uint8Array(await response.arrayBuffer());
  return { status: response.status, headers: response.headers, body, url: response.url || clientId };
}
