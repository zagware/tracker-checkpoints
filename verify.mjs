#!/usr/bin/env node
// Verify every recorded checkpoint: each line of checkpoints/<projectKey>.jsonl
// must be signed by a key recorded in keys/, belong to the file it is in, and
// move its project's ledger forward. Dependency-free; Node 24 or later.
//
//   node verify.mjs
//
// Exit status 0 when everything verifies, 1 otherwise (problems on stderr).

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = fileURLToPath(new URL(".", import.meta.url));
export const KEYS = join(ROOT, "keys");
export const CHECKPOINTS = join(ROOT, "checkpoints");

/** Tracker's canonical JSON: keys sorted, no whitespace (packages/core/src/ledger.ts). */
export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

/** First 16 hex digits of SHA-256 over the raw public key. */
export async function keyIdOf(publicKeyBase64) {
  const digest = await crypto.subtle.digest("SHA-256", Buffer.from(publicKeyBase64, "base64"));
  return Buffer.from(digest).subarray(0, 8).toString("hex");
}

/** Problems with a published key ({alg, keyId, publicKey}); empty when it is well formed and its id is honest. */
export async function keyProblems(key) {
  if (key?.alg !== "Ed25519") return ["key: alg is not Ed25519"];
  if (typeof key.publicKey !== "string" || Buffer.from(key.publicKey, "base64").length !== 32) return ["key: publicKey is not 32 bytes of base64"];
  const id = await keyIdOf(key.publicKey);
  return id === key.keyId ? [] : [`key: keyId ${key.keyId} does not match its public key (${id})`];
}

/** True when `signature` is the key's Ed25519 signature over canonicalJson(payload). */
export async function signatureValid(publicKeyBase64, payload, signature) {
  try {
    const key = await crypto.subtle.importKey("raw", Buffer.from(publicKeyBase64, "base64"), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, Buffer.from(signature, "base64"), new TextEncoder().encode(canonicalJson(payload)));
  } catch {
    return false;
  }
}

/** Problems with one checkpoint's shape ({payload: {v, project, seq, hash, at}, signature, keyId}). */
export function shapeProblems(c) {
  const p = c?.payload;
  const out = [];
  if (p?.v !== 1) out.push("payload.v is not 1");
  if (!/^[0-9a-f]{64}$/.test(p?.project ?? "")) out.push("payload.project is not a project key");
  if (!Number.isInteger(p?.seq) || p.seq < 1) out.push("payload.seq is not a positive integer");
  if (!/^[0-9a-f]{64}$/.test(p?.hash ?? "")) out.push("payload.hash is not a SHA-256 hex digest");
  if (typeof p?.at !== "string" || Number.isNaN(Date.parse(p.at))) out.push("payload.at is not a timestamp");
  if (typeof c?.signature !== "string") out.push("signature missing");
  if (!/^[0-9a-f]{16}$/.test(c?.keyId ?? "")) out.push("keyId is not 16 hex digits");
  return out;
}

/** The keys recorded in keys/, by id. */
export function recordedKeys() {
  const keys = new Map();
  if (!existsSync(KEYS)) return keys;
  for (const f of readdirSync(KEYS).filter((f) => f.endsWith(".json"))) {
    const key = JSON.parse(readFileSync(join(KEYS, f), "utf8"));
    keys.set(f.slice(0, -".json".length), key);
  }
  return keys;
}

/** A project's recorded checkpoints, oldest first. */
export function recorded(projectKey) {
  const file = join(CHECKPOINTS, `${projectKey}.jsonl`);
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

async function main() {
  const problems = [];
  const keys = recordedKeys();
  for (const [id, key] of keys) {
    for (const p of await keyProblems(key)) problems.push(`keys/${id}.json: ${p}`);
    if (key.keyId !== id) problems.push(`keys/${id}.json: holds key ${key.keyId}`);
  }
  const files = existsSync(CHECKPOINTS) ? readdirSync(CHECKPOINTS).filter((f) => f.endsWith(".jsonl")).sort() : [];
  let count = 0;
  for (const f of files) {
    const projectKey = f.slice(0, -".jsonl".length);
    let prev = 0;
    for (const [i, c] of recorded(projectKey).entries()) {
      const where = `checkpoints/${f}:${i + 1}`;
      count++;
      const shape = shapeProblems(c);
      if (shape.length) {
        problems.push(...shape.map((p) => `${where}: ${p}`));
        continue;
      }
      if (c.payload.project !== projectKey) problems.push(`${where}: belongs to project ${c.payload.project}`);
      if (c.payload.seq <= prev) problems.push(`${where}: seq ${c.payload.seq} does not move past ${prev}`);
      prev = c.payload.seq;
      const key = keys.get(c.keyId);
      if (!key) problems.push(`${where}: key ${c.keyId} is not in keys/`);
      else if (!(await signatureValid(key.publicKey, c.payload, c.signature))) problems.push(`${where}: signature does not verify`);
    }
  }
  for (const p of problems) console.error(p);
  console.log(`${count} checkpoint(s) in ${files.length} project(s), ${keys.size} key(s): ${problems.length ? `${problems.length} problem(s)` : "all verify"}`);
  process.exitCode = problems.length ? 1 : 0;
}

if (import.meta.main) await main();
