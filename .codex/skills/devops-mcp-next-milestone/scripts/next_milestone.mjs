#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const statusPath = resolve("docs/milestones/status.yaml");
const text = readFileSync(statusPath, "utf8");

const blocks = text.split(/\n  - id: /).slice(1).map((block) => `id: ${block}`);

function field(block, name) {
  const match = block.match(new RegExp(`^\\s*${name}:\\s*(.+)$`, "m"));
  if (!match) return "";
  return match[1].trim().replace(/^"|"$/g, "");
}

const milestones = blocks.map((block) => ({
  id: field(block, "id"),
  title: field(block, "title"),
  file: field(block, "file"),
  status: field(block, "status"),
}));

const requested = process.argv[2];
const selected = requested
  ? milestones.find((milestone) => milestone.id === requested || milestone.title.toLowerCase().includes(requested.toLowerCase()))
  : milestones.find((milestone) => milestone.status === "pending");

if (!selected) {
  console.error(requested ? `No milestone matched ${requested}.` : "No pending milestones found.");
  process.exit(1);
}

console.log(JSON.stringify(selected, null, 2));
