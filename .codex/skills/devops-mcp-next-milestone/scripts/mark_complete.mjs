#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const id = process.argv[2];
if (!id) {
  console.error("Usage: mark_complete.mjs <milestone-id> [--notes \"summary\"]");
  process.exit(1);
}

const notesIndex = process.argv.indexOf("--notes");
const notes = notesIndex >= 0 ? process.argv[notesIndex + 1] ?? "" : "";

function gitCommitHash() {
  try {
    return execFileSync("git", ["rev-parse", "--short", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

const statusPath = resolve("docs/milestones/status.yaml");
const text = readFileSync(statusPath, "utf8");
const lines = text.split("\n");
let inTarget = false;
let changed = false;
const completedAt = new Date().toISOString();
const commitHash = gitCommitHash();

const next = lines.map((line) => {
  const idMatch = line.match(/^  - id: "([^"]+)"/);
  if (idMatch) inTarget = idMatch[1] === id;
  if (!inTarget) return line;
  if (line.match(/^    status:/)) {
    changed = true;
    return '    status: "completed"';
  }
  if (line.match(/^    completed_at:/)) return `    completed_at: "${completedAt}"`;
  if (line.match(/^    commit_hash:/)) return commitHash ? `    commit_hash: "${commitHash}"` : "    commit_hash: null";
  if (line.match(/^    notes:/)) return `    notes: "${notes.replaceAll('"', '\\"')}"`;
  return line;
});

if (!changed) {
  console.error(`Milestone ${id} was not found.`);
  process.exit(1);
}

writeFileSync(statusPath, `${next.join("\n").replace(/\n*$/, "")}\n`);
console.log(`Marked milestone ${id} completed.`);
