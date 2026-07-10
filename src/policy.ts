import type { PolicyRuleConfig, ServiceConfig } from "./types.js";
import type { ResolvedTarget } from "./urlValidation.js";
import { normalizeHost } from "./urlValidation.js";

export interface PolicyDecision {
  allowed: boolean;
  matchedRule?: string;
  policyMode: "allow" | "deny";
  reason: string;
  suggestion?: string;
}

export function evaluatePolicy(service: ServiceConfig, target: ResolvedTarget, method: string): PolicyDecision {
  const normalizedMethod = method.toUpperCase();
  const matches = service.policy.rules.filter((rule) => ruleMatches(rule, target, normalizedMethod));

  if (matches.length > 0) {
    const selected = selectHighestPriority(matches);
    const allowed = selected.effect === "allow";
    return {
      allowed,
      matchedRule: selected.id,
      policyMode: service.policy.mode,
      reason: selected.reason ?? `${allowed ? "Allowed" : "Denied"} by policy rule ${selected.id}.`,
      ...(allowed ? {} : { suggestion: "Use an allowed request or ask the user to update service policy." }),
    };
  }

  const allowed = service.policy.mode === "allow";
  return {
    allowed,
    policyMode: service.policy.mode,
    reason: allowed ? "Allowed by default policy mode." : "Denied by default policy mode.",
    ...(allowed ? {} : { suggestion: "Use an allowed request or ask the user to update service policy." }),
  };
}

function ruleMatches(rule: PolicyRuleConfig, target: ResolvedTarget, method: string): boolean {
  return matchesMethod(rule, method) && matchesHost(rule, target.url.hostname) && matchesPath(rule, target.methodPath);
}

function matchesMethod(rule: PolicyRuleConfig, method: string): boolean {
  return rule.methods.length === 0 || rule.methods.map((value) => value.toUpperCase()).includes(method);
}

function matchesHost(rule: PolicyRuleConfig, host: string): boolean {
  if (rule.hosts.length === 0) return true;
  const normalized = normalizeHost(host);
  return rule.hosts.some((pattern) => new RegExp(pattern).test(normalized));
}

function matchesPath(rule: PolicyRuleConfig, path: string): boolean {
  if (rule.paths.length === 0) return true;
  return rule.paths.some((pattern) => new RegExp(pattern).test(path));
}

function selectHighestPriority(rules: PolicyRuleConfig[]): PolicyRuleConfig {
  return [...rules].sort((a, b) => {
    if (a.priority !== b.priority) return b.priority - a.priority;
    if (a.effect === b.effect) return 0;
    return a.effect === "deny" ? -1 : 1;
  })[0] as PolicyRuleConfig;
}
