import { fileURLToPath } from "node:url";
import { loadSecretlintConfig, resolveSecretlintRules } from "./secretlintConfig.js";
import { ResponseTokenizer } from "./responseTokenizer.js";
import { SecretScannerPool } from "./secretScannerPool.js";
import { getTokenBroker } from "./tokens.js";
import type { GatewayConfig } from "./types.js";

interface SecretRuntime {
  pool: SecretScannerPool;
  tokenizer: ResponseTokenizer;
}

const runtimes = new WeakMap<GatewayConfig, SecretRuntime>();

export function initializeSecretRuntime(config: GatewayConfig): SecretRuntime {
  const existing = runtimes.get(config);
  if (existing) return existing;
  const bundledPath = fileURLToPath(new URL("../config/secretlint.yaml", import.meta.url));
  const bundled = loadSecretlintConfig(bundledPath);
  const configured = process.env.SECRETLINT_CONFIG_PATH ? loadSecretlintConfig(process.env.SECRETLINT_CONFIG_PATH) : bundled;
  const rules = resolveSecretlintRules(configured, bundled.rules);
  const pool = new SecretScannerPool();
  const runtime = {
    pool,
    tokenizer: new ResponseTokenizer(getTokenBroker(config), pool, rules, configured.limits.maxUniqueSecrets, configured.limits.timeoutMs),
  };
  runtimes.set(config, runtime);
  return runtime;
}

export function getResponseTokenizer(config: GatewayConfig): ResponseTokenizer {
  return initializeSecretRuntime(config).tokenizer;
}
