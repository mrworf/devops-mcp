import { fileURLToPath } from "node:url";
import { loadSecretlintConfig, resolveSecretlintRules } from "./secretlintConfig.js";
import { ResponseTokenizer } from "./responseTokenizer.js";
import { SecretScannerPool } from "./secretScannerPool.js";
import type { TokenBroker } from "./tokens.js";
import type { GatewayConfig } from "./types.js";
import { loadSensitiveNameConfig, resolveSensitiveNameConfig, SensitiveNameMatcher } from "./sensitiveNames.js";

export interface SecretRuntime {
  pool: SecretScannerPool;
  tokenizer: ResponseTokenizer;
  rules: ReturnType<typeof resolveSecretlintRules>;
}

const runtimes = new WeakMap<GatewayConfig, SecretRuntime>();

export function initializeSecretRuntime(config: GatewayConfig, tokenBroker: TokenBroker): SecretRuntime {
  const existing = runtimes.get(config);
  if (existing) return existing;
  const bundledPath = fileURLToPath(new URL("../config/secretlint.yaml", import.meta.url));
  const bundled = loadSecretlintConfig(bundledPath);
  const configured = process.env.SECRETLINT_CONFIG_PATH ? loadSecretlintConfig(process.env.SECRETLINT_CONFIG_PATH) : bundled;
  const bundledSensitivePath = fileURLToPath(new URL("../config/sensitive-names.yaml", import.meta.url));
  const bundledSensitive = loadSensitiveNameConfig(bundledSensitivePath);
  const configuredSensitive = process.env.SENSITIVE_NAMES_CONFIG_PATH
    ? loadSensitiveNameConfig(process.env.SENSITIVE_NAMES_CONFIG_PATH)
    : bundledSensitive;
  const sensitiveNames = new SensitiveNameMatcher(resolveSensitiveNameConfig(configuredSensitive, bundledSensitive));
  const rules = resolveSecretlintRules(configured, bundled.rules);
  const pool = new SecretScannerPool();
  const runtime = {
    pool,
    rules,
    tokenizer: new ResponseTokenizer(
      tokenBroker, pool, rules, configured.limits.maxUniqueSecrets, configured.limits.timeoutMs, sensitiveNames,
    ),
  };
  runtimes.set(config, runtime);
  return runtime;
}

export function getResponseTokenizer(config: GatewayConfig, tokenBroker: TokenBroker): ResponseTokenizer {
  return initializeSecretRuntime(config, tokenBroker).tokenizer;
}

export function getResponseTokenizerRuleIds(config: GatewayConfig, tokenBroker: TokenBroker): string[] {
  return initializeSecretRuntime(config, tokenBroker).rules.map((rule) => rule.id);
}

export function getSecretScannerPoolStats(config: GatewayConfig, tokenBroker: TokenBroker) {
  return initializeSecretRuntime(config, tokenBroker).pool.stats();
}
