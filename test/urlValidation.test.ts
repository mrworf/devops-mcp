import { describe, expect, it } from "vitest";
import { GatewayError } from "../src/errors.js";
import { resolveDestination } from "../src/registry.js";
import { auth, registryConfig } from "./helpers.js";

describe("destination validation", () => {
  it("resolves relative paths against the configured destination", () => {
    const target = resolveDestination(registryConfig(), auth("henric@example.com"), "portainer-prod", "primary", {
      path: "/api/stacks",
    });

    expect(target.url.href).toBe("https://portainer.internal:9443/api/stacks");
    expect(target.methodPath).toBe("/api/stacks");
    expect(target.tls.verify).toBe(false);
  });

  it("allows exact, suffix, and regex host matches after normalization", () => {
    const config = registryConfig();

    expect(resolveDestination(config, auth("henric@example.com"), "portainer-prod", "primary", {
      url: "https://PORTAINER.INTERNAL.:9443/api/stacks",
    }).url.hostname).toBe("portainer.internal.");
    expect(resolveDestination(config, auth("henric@example.com"), "portainer-prod", "primary", {
      url: "https://service.home.arpa:9443/api/stacks",
    }).url.hostname).toBe("service.home.arpa");
    expect(resolveDestination(config, auth("henric@example.com"), "portainer-prod", "primary", {
      url: "https://HOME.ARPA.:9443/api/stacks",
    }).url.hostname).toBe("home.arpa.");
    expect(resolveDestination(config, auth("henric@example.com"), "portainer-prod", "primary", {
      url: "https://portainer-lab.internal:9443/api/stacks",
    }).url.hostname).toBe("portainer-lab.internal");
  });

  it("enforces DNS label boundaries for suffix matches", () => {
    const config = registryConfig();
    const user = auth("henric@example.com");

    for (const hostname of ["attackerhome.arpa", "home.arpa.attacker.invalid"]) {
      expectGatewayError(() => resolveDestination(config, user, "portainer-prod", "primary", {
        url: `https://${hostname}:9443/api/stacks`,
      }), "host_not_allowed");
    }
  });

  it("denies wrong scheme, host, port, and outside absolute URLs", () => {
    const config = registryConfig();
    const user = auth("henric@example.com");

    expectGatewayError(() => resolveDestination(config, user, "portainer-prod", "primary", {
      url: "http://portainer.internal:9443/api/stacks",
    }), "scheme_not_allowed");
    expectGatewayError(() => resolveDestination(config, user, "portainer-prod", "primary", {
      url: "https://evil.internal:9443/api/stacks",
    }), "host_not_allowed");
    expectGatewayError(() => resolveDestination(config, user, "portainer-prod", "primary", {
      url: "https://portainer.internal:443/api/stacks",
    }), "port_not_allowed");
    expectGatewayError(() => resolveDestination(config, user, "portainer-prod", "missing", {
      path: "/api/stacks",
    }), "unknown_destination");
    expectGatewayError(() => resolveDestination(config, user, "missing", "primary", {
      path: "/api/stacks",
    }), "unknown_service");
  });

  it("rejects routing-ambiguous escapes and canonicalizes the path sent downstream", () => {
    const config = registryConfig();
    const user = auth("henric@example.com");
    const accepted = resolveDestination(config, user, "portainer-prod", "primary", {
      url: "https://portainer.internal:9443/api//snow%20%E9%9B%AA/?view=%61dmin",
    });
    expect(accepted.methodPath).toBe("/api/snow%20%E9%9B%AA");
    expect(accepted.url.pathname).toBe(accepted.methodPath);
    expect(accepted.url.search).toBe("?view=%61dmin");

    for (const path of [
      "/%61dmin", "/%2e%2e/admin", "/%2Fadmin", "/%5cadmin", "/%00admin", "/%252e%252e/admin", "/bad%escape",
      "/%7Eadmin", "/%2fadmin", "/%5Cadmin",
    ]) {
      expectGatewayError(() => resolveDestination(config, user, "portainer-prod", "primary", { path }), "destination_not_allowed");
    }
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
