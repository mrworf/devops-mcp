import { Worker } from "node:worker_threads";
import type { SecretlintRuleConfig } from "./secretlintConfig.js";

export interface SecretFinding {
  start: number;
  end: number;
  ruleId: string;
  messageId: string;
}

interface WorkerResult {
  findings?: unknown;
  error?: string;
}

export const SECRET_SCANNER_WORKER_SOURCE = `
const { parentPort } = require("node:worker_threads");
let runtime;
async function getRuntime() {
  if (runtime) return runtime;
  const [{ lintSource }, preset, pattern] = await Promise.all([
    import("@secretlint/core"),
    import("@secretlint/secretlint-rule-preset-recommend"),
    import("@secretlint/secretlint-rule-pattern"),
  ]);
  const catalog = new Map(preset.rules.map((rule) => [rule.meta.id, rule]));
  catalog.set("@secretlint/secretlint-rule-pattern", pattern.creator);
  runtime = { lintSource, catalog };
  return runtime;
}
parentPort.on("message", async ({ id, text, rules: configuredRules }) => {
 try {
  const { lintSource, catalog } = await getRuntime();
  const rules = configuredRules.map((configured) => {
    const rule = catalog.get(configured.id);
    if (!rule) throw new Error("Unknown Secretlint rule");
    return {
      id: configured.id,
      rule,
      ...(configured.options === undefined ? {} : { options: configured.options }),
      ...(configured.allowMessageIds === undefined ? {} : { allowMessageIds: configured.allowMessageIds }),
    };
  });
  const result = await lintSource({
    source: { content: text, filePath: "response.txt", ext: ".txt", contentType: "text" },
    options: { config: { rules }, noPhysicFilePath: true, maskSecrets: true },
  });
  parentPort.postMessage({ id, findings: result.messages.map((message) => ({
    start: message.range[0],
    end: message.range[1],
    ruleId: message.ruleId,
    messageId: message.messageId,
  })) });
 } catch { parentPort.postMessage({ id, error: "scan_failed" }); }
});
`;

export function readSecretlintDebug(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env.SECRETLINT_DEBUG;
  if (raw === undefined || raw === "false") return false;
  if (raw === "true") return true;
  throw new Error("SECRETLINT_DEBUG must be true or false");
}

export function secretScannerWorkerEnv(
  enabled: boolean,
  env: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const workerEnv = { ...env };
  if (enabled) workerEnv.DEBUG = "@secretlint/*";
  else delete workerEnv.DEBUG;
  return workerEnv;
}

export async function scanSecretText(
  text: string,
  rules: SecretlintRuleConfig[],
  timeoutMs: number,
  env: NodeJS.ProcessEnv = process.env,
): Promise<SecretFinding[]> {
  return await new Promise<SecretFinding[]>((resolve, reject) => {
    const worker = new Worker(SECRET_SCANNER_WORKER_SOURCE, {
      eval: true,
      env: secretScannerWorkerEnv(readSecretlintDebug(env), env),
    });
    const timeout = setTimeout(() => {
      void worker.terminate();
      reject(new Error("Secretlint scan timed out"));
    }, timeoutMs);
    worker.once("message", (message: WorkerResult) => {
      clearTimeout(timeout);
      void worker.terminate();
      if (message.error !== undefined) {
        reject(new Error("Secretlint scan failed"));
        return;
      }
      try {
        resolve(validateFindings(message.findings, text.length));
      } catch (error) {
        reject(error);
      }
    });
    worker.once("error", () => {
      clearTimeout(timeout);
      reject(new Error("Secretlint worker failed"));
    });
    worker.postMessage({ id: 1, text, rules });
  });
}

export function validateFindings(value: unknown, sourceLength: number): SecretFinding[] {
  if (!Array.isArray(value)) throw new Error("Secretlint returned invalid findings");
  return value.map((finding) => {
    if (!finding || typeof finding !== "object") throw new Error("Secretlint returned invalid finding");
    const item = finding as Record<string, unknown>;
    if (!Number.isInteger(item.start) || !Number.isInteger(item.end)
      || (item.start as number) < 0 || (item.end as number) <= (item.start as number)
      || (item.end as number) > sourceLength
      || typeof item.ruleId !== "string" || typeof item.messageId !== "string") {
      throw new Error("Secretlint returned invalid finding range");
    }
    return {
      start: item.start as number,
      end: item.end as number,
      ruleId: item.ruleId,
      messageId: item.messageId,
    };
  });
}

export function decodeUtf8(input: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(input);
}
