#!/usr/bin/env node
// Copy Tracker's latest signed checkpoints into this repo: verify each one,
// append it to checkpoints/<projectKey>.jsonl and commit it on its own. Lines
// are only ever appended. A checkpoint that does not move its project forward
// (lower seq, or the same seq with a different hash) is refused and reported:
// that is what a rewritten ledger looks like from here.
//
//   node update.mjs                 # what .github/workflows/record.yml runs
//   node update.mjs --no-commit     # write files, leave committing to you
//   TRACKER_URL=http://127.0.0.1:8790 node update.mjs --no-commit
//
// Exit status 1 when anything was refused; everything valid is still recorded.

import { execFileSync } from "node:child_process";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CHECKPOINTS, KEYS, ROOT, canonicalJson, keyProblems, recorded, recordedKeys, shapeProblems, signatureValid } from "./verify.mjs";

const BASE = (process.env.TRACKER_URL ?? "https://tracker.zagware.io").replace(/\/+$/, "");
const commit = !process.argv.includes("--no-commit");

async function get(path) {
  const res = await fetch(BASE + path, { headers: { accept: "application/json" } });
  const body = await res.text();
  if (!res.ok) throw new Error(`GET ${BASE}${path}: ${res.status} ${body.slice(0, 300)}`);
  return JSON.parse(body);
}

function record(file, message) {
  if (!commit) return;
  execFileSync("git", ["add", file], { cwd: ROOT, stdio: "inherit" });
  execFileSync("git", ["commit", "--quiet", ...message.flatMap((m) => ["-m", m])], { cwd: ROOT, stdio: "inherit" });
}

const key = await get("/.well-known/tracker-checkpoint-key");
const keyBad = await keyProblems(key);
if (keyBad.length) throw new Error(`${BASE}/.well-known/tracker-checkpoint-key: ${keyBad.join("; ")}`);
const keys = recordedKeys();
if (!keys.has(key.keyId)) {
  mkdirSync(KEYS, { recursive: true });
  const file = join(KEYS, `${key.keyId}.json`);
  const entry = { alg: key.alg, keyId: key.keyId, publicKey: key.publicKey, firstSeen: new Date().toISOString() };
  writeFileSync(file, `${JSON.stringify(entry, null, 2)}\n`);
  keys.set(key.keyId, entry);
  record(file, [`key ${key.keyId}`, `First published at ${BASE}/.well-known/tracker-checkpoint-key`]);
  console.log(`recorded key ${key.keyId}`);
}

const latest = await get("/api/checkpoints");
if (!Array.isArray(latest)) throw new Error(`${BASE}/api/checkpoints: not a list`);

const problems = [];
const valid = [];
for (const c of latest) {
  const shape = shapeProblems(c);
  if (shape.length) problems.push(`${canonicalJson(c).slice(0, 120)}: ${shape.join("; ")}`);
  else valid.push(c);
}
valid.sort((a, b) => a.payload.at.localeCompare(b.payload.at) || a.payload.project.localeCompare(b.payload.project));

let added = 0;
for (const c of valid) {
  const { project, seq, hash } = c.payload;
  const where = `${project} seq ${seq}`;
  const k = keys.get(c.keyId);
  if (!k) {
    problems.push(`${where}: signed by key ${c.keyId}, which this repo has never seen`);
    continue;
  }
  if (!(await signatureValid(k.publicKey, c.payload, c.signature))) {
    problems.push(`${where}: signature does not verify`);
    continue;
  }
  const last = recorded(project).at(-1)?.payload;
  if (last && seq === last.seq) {
    if (hash !== last.hash || canonicalJson(c.payload) !== canonicalJson(last)) problems.push(`${where}: already recorded with a different payload (hash ${last.hash})`);
    continue;
  }
  if (last && seq < last.seq) {
    problems.push(`${where}: behind the recorded seq ${last.seq}`);
    continue;
  }
  mkdirSync(CHECKPOINTS, { recursive: true });
  const file = join(CHECKPOINTS, `${project}.jsonl`);
  appendFileSync(file, `${canonicalJson({ payload: c.payload, signature: c.signature, keyId: c.keyId })}\n`);
  record(file, [`${project.slice(0, 12)} seq ${seq}`, `project ${project}\nseq ${seq}\nhash ${hash}\nat ${c.payload.at}\nkey ${c.keyId}`]);
  added++;
}

for (const p of problems) console.error(`refused ${p}`);
console.log(`${latest.length} published, ${added} new, ${problems.length} refused`);
process.exitCode = problems.length ? 1 : 0;
