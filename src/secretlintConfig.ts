import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { configError } from "./errors.js";

export const SECRET_RULE_IDS = [
  "@secretlint/secretlint-rule-aws",
  "@secretlint/secretlint-rule-gcp",
  "@secretlint/secretlint-rule-privatekey",
  "@secretlint/secretlint-rule-npm",
  "@secretlint/secretlint-rule-basicauth",
  "@secretlint/secretlint-rule-slack",
  "@secretlint/secretlint-rule-sendgrid",
  "@secretlint/secretlint-rule-shopify",
  "@secretlint/secretlint-rule-stripe",
  "@secretlint/secretlint-rule-github",
  "@secretlint/secretlint-rule-gitlab",
  "@secretlint/secretlint-rule-grafana",
  "@secretlint/secretlint-rule-openai",
  "@secretlint/secretlint-rule-anthropic",
  "@secretlint/secretlint-rule-groq",
  "@secretlint/secretlint-rule-huggingface",
  "@secretlint/secretlint-rule-linear",
  "@secretlint/secretlint-rule-notion",
  "@secretlint/secretlint-rule-1password",
  "@secretlint/secretlint-rule-database-connection-string",
  "@secretlint/secretlint-rule-hashicorp-vault",
  "@secretlint/secretlint-rule-vercel",
  "@secretlint/secretlint-rule-databricks",
  "@secretlint/secretlint-rule-docker",
  "@secretlint/secretlint-rule-figma",
  "@secretlint/secretlint-rule-cloudflare",
  "@secretlint/secretlint-rule-tailscale",
  "@secretlint/secretlint-rule-pattern",
] as const;

export type SecretRuleId = typeof SECRET_RULE_IDS[number];

export interface SecretlintRuleConfig {
  id: SecretRuleId;
  options?: Record<string, unknown>;
  allowMessageIds?: string[];
}

export interface SecretlintConfig {
  version: 1;
  mode: "extend" | "replace";
  limits: {
    maxUniqueSecrets: number;
    timeoutMs: number;
  };
  rules: SecretlintRuleConfig[];
}

const durationPattern = /^(\d+)(ms|s)$/;
const ruleSchema = z.object({
  id: z.enum(SECRET_RULE_IDS),
  options: z.record(z.string(), z.unknown()).optional(),
  allowMessageIds: z.array(z.string().min(1)).optional(),
}).strict();

const schema = z.object({
  version: z.literal(1),
  mode: z.enum(["extend", "replace"]).default("extend"),
  limits: z.object({
    max_unique_secrets: z.number().int().min(1).max(10_000).default(100),
    timeout: z.string().regex(durationPattern).default("5s"),
  }).strict().default({ max_unique_secrets: 100, timeout: "5s" }),
  rules: z.array(ruleSchema).default([]),
}).strict();

export const DEFAULT_SECRETLINT_CONFIG_PATH = "/config/secretlint.yaml";

export function loadSecretlintConfig(path = process.env.SECRETLINT_CONFIG_PATH ?? DEFAULT_SECRETLINT_CONFIG_PATH): SecretlintConfig {
  let raw: unknown;
  try {
    raw = parseYaml(readFileSync(path, "utf8"));
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw configError(`Failed to read or parse Secretlint config: ${detail}`);
  }
  return validateSecretlintConfig(raw);
}

export function validateSecretlintConfig(raw: unknown): SecretlintConfig {
  const result = schema.safeParse(raw);
  if (!result.success) {
    throw configError(`Invalid Secretlint config: ${result.error.issues.map((issue) => issue.message).join("; ")}`);
  }
  const ids = result.data.rules.map((rule) => rule.id);
  if (new Set(ids).size !== ids.length) throw configError("Invalid Secretlint config: rule ids must be unique");
  return {
    version: 1,
    mode: result.data.mode,
    limits: {
      maxUniqueSecrets: result.data.limits.max_unique_secrets,
      timeoutMs: parseDuration(result.data.limits.timeout),
    },
    rules: result.data.rules as SecretlintRuleConfig[],
  };
}

function parseDuration(value: string): number {
  const match = durationPattern.exec(value);
  if (!match) throw configError("Invalid Secretlint timeout");
  const amount = Number(match[1]);
  return amount * (match[2] === "s" ? 1000 : 1);
}
