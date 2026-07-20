import { describe, expect, it, vi } from "vitest";
import {
  isPublicMetadataAddress,
  OAuthClientMetadataFetcher,
  type MetadataAddress,
  type MetadataResponse,
  type OAuthClientMetadataNetwork,
} from "../src/oauthClientMetadata.js";

const CLIENT = "https://client.example.org/oauth/metadata";

describe("OAuth client metadata fetching", () => {
  it.each([
    "0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.168.1.1",
    "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::", "::1",
    "::ffff:127.0.0.1", "2001:db8::1", "fc00::1", "fe80::1", "ff00::1",
  ])("rejects special-use metadata address %s", (address) => {
    expect(isPublicMetadataAddress(address)).toBe(false);
  });

  it.each(["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])("accepts public metadata address %s", (address) => {
    expect(isPublicMetadataAddress(address)).toBe(true);
  });

  it("resolves all addresses, pins a validated address, and verifies JSON metadata", async () => {
    const request = vi.fn(async (_url: URL, address: MetadataAddress) => {
      expect(address).toEqual({ address: "93.184.216.34", family: 4 });
      return response(CLIENT, 200, metadata(CLIENT), { "content-type": "application/oauth-client-id-metadata+json" });
    });
    const fetcher = new OAuthClientMetadataFetcher(4, 2, network(
      [{ address: "93.184.216.34", family: 4 }, { address: "2606:4700:4700::1111", family: 6 }],
      request,
    ));

    await expect(fetcher.fetch(CLIENT)).resolves.toEqual({
      clientId: CLIENT, redirectUris: ["https://client.example.org/callback"], clientName: "Example client",
    });
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("rejects mixed DNS answers and literal private addresses before connecting", async () => {
    const request = vi.fn();
    const mixed = new OAuthClientMetadataFetcher(4, 2, network([
      { address: "93.184.216.34", family: 4 }, { address: "127.0.0.1", family: 4 },
    ], request));
    await expect(mixed.fetch(CLIENT)).resolves.toBeUndefined();
    const literal = new OAuthClientMetadataFetcher(4, 2, network([], request));
    await expect(literal.fetch("https://127.0.0.1/metadata")).resolves.toBeUndefined();
    expect(request).not.toHaveBeenCalled();
  });

  it.each([300, 301, 302, 303, 304, 305, 306, 307, 308])("rejects HTTP %i without following it", async (status) => {
    const request = vi.fn(async () => response(CLIENT, status, metadata(CLIENT)));
    const fetcher = new OAuthClientMetadataFetcher(4, 2, network(publicAddress(), request));
    await expect(fetcher.fetch(CLIENT)).resolves.toBeUndefined();
    expect(request).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["final URL mismatch", response("https://other.example.org/metadata", 200, metadata(CLIENT))],
    ["wrong media type", response(CLIENT, 200, metadata(CLIENT), { "content-type": "text/plain" })],
    ["invalid UTF-8", response(CLIENT, 200, new Uint8Array([0xc3, 0x28]))],
    ["malformed JSON", response(CLIENT, 200, "{")],
    ["oversized body", response(CLIENT, 200, "x".repeat(5121))],
    ["mismatched client", response(CLIENT, 200, metadata("https://other.example.org/metadata"))],
    ["non-string redirect", response(CLIENT, 200, JSON.stringify({ client_id: CLIENT, redirect_uris: [42] }))],
  ])("rejects %s", async (_label, result) => {
    const fetcher = new OAuthClientMetadataFetcher(4, 2, network(publicAddress(), async () => result));
    await expect(fetcher.fetch(CLIENT)).resolves.toBeUndefined();
  });

  it("deduplicates concurrent fetches and enforces global/per-origin admission", async () => {
    let finish!: (value: MetadataResponse) => void;
    const pending = new Promise<MetadataResponse>((resolve) => { finish = resolve; });
    const request = vi.fn(async () => pending);
    const fetcher = new OAuthClientMetadataFetcher(2, 1, network(publicAddress(), request));
    const first = fetcher.fetch(CLIENT);
    const duplicate = fetcher.fetch(CLIENT);
    await expect(fetcher.fetch("https://client.example.org/other")).resolves.toBeUndefined();
    const otherOrigin = fetcher.fetch("https://other.example.org/metadata");
    await expect(fetcher.fetch("https://third.example.org/metadata")).resolves.toBeUndefined();
    finish(response(CLIENT, 200, metadata(CLIENT)));
    await expect(first).resolves.toBeDefined();
    await expect(duplicate).resolves.toBeDefined();
    await expect(otherOrigin).resolves.toBeUndefined();
    expect(request).toHaveBeenCalledTimes(2);
  });

  it("honors freshness, no-store, expiry, and the one-hour cache ceiling", async () => {
    let now = 1000;
    const request = vi.fn(async () => response(CLIENT, 200, metadata(CLIENT), { "cache-control": "max-age=7200" }));
    const fetcher = new OAuthClientMetadataFetcher(4, 2, network(publicAddress(), request), () => now);
    await fetcher.fetch(CLIENT);
    now += 3_599_000;
    await fetcher.fetch(CLIENT);
    expect(request).toHaveBeenCalledTimes(1);
    now += 2_000;
    await fetcher.fetch(CLIENT);
    expect(request).toHaveBeenCalledTimes(2);

    const noStoreRequest = vi.fn(async () => response(CLIENT, 200, metadata(CLIENT), { "cache-control": "no-store, max-age=60" }));
    const noStore = new OAuthClientMetadataFetcher(4, 2, network(publicAddress(), noStoreRequest));
    await noStore.fetch(CLIENT);
    await noStore.fetch(CLIENT);
    expect(noStoreRequest).toHaveBeenCalledTimes(2);
  });

  it("fails closed on resolver, network, and timeout-style errors", async () => {
    const resolverFailure: OAuthClientMetadataNetwork = {
      resolve: async () => { throw new Error("resolver failure"); },
      request: async () => { throw new Error("unexpected"); },
    };
    await expect(new OAuthClientMetadataFetcher(4, 2, resolverFailure).fetch(CLIENT)).resolves.toBeUndefined();
    await expect(new OAuthClientMetadataFetcher(4, 2, network(publicAddress(), async () => {
      throw new Error("request timed out");
    })).fetch(CLIENT)).resolves.toBeUndefined();
  });
});

function network(
  addresses: MetadataAddress[],
  request: OAuthClientMetadataNetwork["request"],
): OAuthClientMetadataNetwork {
  return { resolve: async () => addresses, request };
}

function publicAddress(): MetadataAddress[] {
  return [{ address: "93.184.216.34", family: 4 }];
}

function metadata(clientId: string): string {
  return JSON.stringify({
    client_id: clientId,
    redirect_uris: ["https://client.example.org/callback"],
    client_name: " Example client ",
  });
}

function response(
  url: string,
  status: number,
  body: string | Uint8Array,
  headers: Record<string, string> = {},
): MetadataResponse {
  return {
    url,
    status,
    headers: new Headers({ "content-type": "application/json; charset=utf-8", ...headers }),
    body: typeof body === "string" ? new TextEncoder().encode(body) : body,
  };
}
