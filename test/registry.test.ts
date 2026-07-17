import { describe, expect, it } from "vitest";
import { GatewayError } from "../src/errors.js";
import { getCredential, getService, listVisibleServices } from "../src/registry.js";
import { auth, registryConfig } from "./helpers.js";

describe("service registry", () => {
  it("lists only services allowed for the authenticated subject without raw credentials", () => {
    const config = registryConfig();
    const services = listVisibleServices(config, auth("henric@example.com"));

    expect(services.map((service) => service.id)).toEqual(["portainer-prod"]);
    expect(services[0]).toMatchObject({
      description: "Main Portainer instance",
      api_docs_url: "https://api.example.org/portainer/openapi.json",
    });
    expect(services[0]?.destinations[0]).toMatchObject({
      id: "primary",
      base_url_hint: "https://portainer.internal:9443",
      tls_verify: false,
    });
    expect(services[0]?.access_methods).toEqual([{ id: "api_key", usage_hint: "Use reference as X-API-Key header" }]);
    expect(JSON.stringify(services)).not.toContain('"credentials"');
    expect(JSON.stringify(services)).not.toContain("portainer-secret");
  });

  it("denies unknown and unauthorized services", () => {
    const config = registryConfig();

    expectGatewayError(() => getService(config, "missing", auth("henric@example.com")), "unknown_service");
    expectGatewayError(() => getService(config, "portainer-prod", auth("ada@example.com")), "unauthorized_service");
  });

  it("returns credentials by id without leaking them in summaries", () => {
    const config = registryConfig();
    const service = getService(config, "portainer-prod", auth("henric@example.com"));

    expect(getCredential(service, "api_key").secret).toBe("portainer-secret");
    expectGatewayError(() => getCredential(service, "missing"), "unknown_access");
  });
});

function expectGatewayError(fn: () => unknown, code: GatewayError["code"]) {
  try {
    fn();
    throw new Error("Expected gateway error");
  } catch (error) {
    expect(error).toBeInstanceOf(GatewayError);
    expect((error as GatewayError).code).toBe(code);
  }
}
