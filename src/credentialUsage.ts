import type { CredentialUsageConfig } from "./types.js";

export function credentialUsageHint(usage: CredentialUsageConfig): string {
  const prefix = usage.prefix ?? "";
  const suffix = usage.suffix ?? "";
  if (prefix.length > 0 || suffix.length > 0) {
    const template = JSON.stringify(`${prefix}<reference>${suffix}`);
    if (usage.kind.toLowerCase() === "header" && usage.name !== undefined) {
      return `Set the ${usage.name} header value to ${template}.`;
    }
    if (usage.name !== undefined) return `Use ${template} as ${usage.name} ${usage.kind}`;
    return `Use ${template} as ${usage.kind}`;
  }
  if (usage.name !== undefined) return `Use reference as ${usage.name} ${usage.kind}`;
  return `Use reference as ${usage.kind}`;
}

export function credentialReferenceTemplate(usage: CredentialUsageConfig, reference: string): string {
  return `${usage.prefix ?? ""}${reference}${usage.suffix ?? ""}`;
}
