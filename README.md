# Tracker checkpoints

Public, append-only witness for the evidence ledger of
[Tracker](https://tracker.zagware.io).

Every write to a Tracker project is recorded in that project's ledger: a
hash chain in which each entry's SHA-256 covers its content and the previous
entry's hash. Once a day Tracker signs each project's latest entry (its
*head*) with an Ed25519 key. An hour later the workflow in this repository
fetches those signed checkpoints, verifies them, and commits each new one on
its own.

Git history here is the part Tracker does not control: the commits and their
GitHub timestamps show that, by that date, the project's ledger contained
that entry at that position. If Tracker later served a ledger that does not
contain it, the ledger was rewritten after the fact.

## What is published

Only hashes, never project content:

```json
{"keyId":"…","payload":{"at":"2026-10-28T03:15:00.000Z","hash":"<sha-256 of ledger entry>","project":"<project key>","seq":42,"v":1},"signature":"<base64>"}
```

- `project` is the *project key*, `sha256hex("tracker-checkpoint:" + projectId)`,
  so project ids are not published. Anyone who can guess an id can compute its
  key, and every key shows how many entries its ledger has; nothing else about
  a project is visible here.
- `seq` and `hash` are the ledger head when the checkpoint was taken; `at` is
  when Tracker signed it.
- `signature` is Ed25519 over the canonical JSON of `payload` (keys sorted, no
  whitespace) as UTF-8; `keyId` is the first 16 hex digits of SHA-256 over the
  raw 32-byte public key.

Layout:

- `checkpoints/<projectKey>.jsonl`: one line per checkpoint, oldest first; lines are only ever appended.
- `keys/<keyId>.json`: each signing key, recorded the first time it was seen.
- `verify.mjs`: checks every recorded checkpoint (Node 24, no dependencies).
- `update.mjs`: what the workflow runs to fetch and record new checkpoints.

## Verifying

1. **The key.** Compare `keys/<keyId>.json` with what Tracker serves now:

   ```sh
   curl -s https://tracker.zagware.io/.well-known/tracker-checkpoint-key
   ```

2. **The signatures.** Every line in this repository:

   ```sh
   node verify.mjs
   ```

   It checks each signature against the recorded key, that each checkpoint is
   in its project's file, and that `seq` only moves forward.

3. **A project's ledger.** If you can read the project in Tracker, export its
   ledger and check it against the checkpoints recorded here. With the `trk`
   CLI this will be `trk verify --checkpoints`. By hand:

   - `GET https://tracker.zagware.io/api/p/<projectId>/checkpoints` gives the
     project's key (or compute it: `printf 'tracker-checkpoint:%s' <projectId> | shasum -a 256`);
   - `GET https://tracker.zagware.io/api/p/<projectId>/ledger?after=N` pages
     through the ledger export;
   - for every line in `checkpoints/<projectKey>.jsonl`, the export's entry at
     `payload.seq` must have hash `payload.hash`. Each entry's hash covers the
     previous entry's, so a match vouches for the whole chain up to that point;
     recomputing those hashes is what `trk verify` does.

## How this repository is written

Only the [`record checkpoints`](.github/workflows/record.yml) workflow
commits here, daily at 04:15 UTC (and on manual dispatch), using its own
`GITHUB_TOKEN`; it holds no secrets. A ruleset forbids force-pushes to and
deletion of `main`. A checkpoint that would move a project backwards, or
re-sign a recorded position with a different hash, is refused and fails the
run; it is never recorded.

Please report problems privately via **Security → Report a vulnerability**.

## License

[MIT](LICENSE)
