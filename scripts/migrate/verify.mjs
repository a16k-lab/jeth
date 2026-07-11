#!/usr/bin/env node
// Capture-diff verifier for the decorator-removal migration (P0c).
//
// Usage:  node scripts/migrate/verify.mjs <baseline-capture-dir> <post-capture-dir>
//
// Both dirs hold JSONL files written by the compile() capture hook (JETH_MIGRATE_CAPTURE=<dir>
// npx vitest run ...): one file per worker PID, one record per compile() call:
//   { testFile, ordinal, fileName, source, sources, outcome }
//   outcome = { ok: true, creationBytecode } | { ok: false, codes: sorted[] }
//
// THE MIGRATION INVARIANT: grouped by testFile and zipped by ordinal,
//   - per-file record COUNTS must be equal (a count drift means the runs diverged structurally),
//   - ok/ok   -> creationBytecode STRICTLY EQUAL,
//   - rej/rej -> sorted diagnostic-code lists EQUAL,
//   - ok/rej or rej/ok -> HARD FAIL (a reject->accept or accept->reject flip).
// A multi-file compilation ({sources} bundle) is ONE record; its entry fileName + source + sources
// all travel with the outcome, so a bundle mismatch prints the whole bundle context.
//
// Exit codes: 0 = perfectly clean; 1 = HARD FAIL (flips and/or count mismatches); 2 = only
// adjudication rows (same-kind outcomes that differ: bytecode or code-list mismatches).
import fs from 'node:fs';
import path from 'node:path';

const [baseDir, postDir] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
if (!baseDir || !postDir) {
  console.error('usage: node scripts/migrate/verify.mjs <baseline-capture-dir> <post-capture-dir>');
  process.exit(2);
}

function readCaptures(dir) {
  const byFile = new Map(); // testFile -> records[]
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith('.jsonl')) continue;
    const lines = fs.readFileSync(path.join(dir, f), 'utf8').split('\n');
    for (const line of lines) {
      if (!line.trim()) continue;
      const rec = JSON.parse(line);
      let arr = byFile.get(rec.testFile);
      if (!arr) byFile.set(rec.testFile, (arr = []));
      arr.push(rec);
    }
  }
  // ordinals are per-worker-module counters; within one run a testFile lives in exactly one worker,
  // so sorting by ordinal reconstructs that file's deterministic compile order.
  for (const arr of byFile.values()) arr.sort((a, b) => a.ordinal - b.ordinal);
  return byFile;
}

const base = readCaptures(baseDir);
const post = readCaptures(postDir);

let hardFails = 0;
let rows = 0;
let pairs = 0;
let okEqual = 0;
let rejEqual = 0;

const short = (s, n = 220) => (s.length > n ? s.slice(0, n) + ` ...[${s.length} chars]` : s);
const describe = (rec) =>
  `fileName=${rec.fileName}${rec.sources ? ` sources={${Object.keys(rec.sources).join(', ')}}` : ''}\n    source: ${short(rec.source.replace(/\n/g, '\\n'))}`;

const allFiles = [...new Set([...base.keys(), ...post.keys()])].sort();
for (const tf of allFiles) {
  const b = base.get(tf) ?? [];
  const p = post.get(tf) ?? [];
  if (b.length !== p.length) {
    hardFails++;
    console.log(`HARD FAIL  ${tf}: record count mismatch (baseline ${b.length} vs post ${p.length})`);
    continue;
  }
  for (let i = 0; i < b.length; i++) {
    pairs++;
    const rb = b[i];
    const rp = p[i];
    const ob = rb.outcome;
    const op = rp.outcome;
    if (ob.ok && op.ok) {
      if (ob.creationBytecode === op.creationBytecode) {
        okEqual++;
        continue;
      }
      rows++;
      console.log(`MISMATCH   ${tf} ordinal ${i}: both accept, bytecode DIFFERS (${ob.creationBytecode.length} vs ${op.creationBytecode.length} hex chars)`);
      console.log(`  baseline ${describe(rb)}`);
      console.log(`  post     ${describe(rp)}`);
    } else if (!ob.ok && !op.ok) {
      if (ob.codes.join(',') === op.codes.join(',')) {
        rejEqual++;
        continue;
      }
      rows++;
      console.log(`MISMATCH   ${tf} ordinal ${i}: both reject, code lists differ [${ob.codes}] vs [${op.codes}]`);
      console.log(`  baseline ${describe(rb)}`);
      console.log(`  post     ${describe(rp)}`);
    } else {
      hardFails++;
      console.log(`HARD FAIL  ${tf} ordinal ${i}: ${ob.ok ? 'accept' : `reject[${ob.codes}]`} -> ${op.ok ? 'accept' : `reject[${op.codes}]`} FLIP`);
      console.log(`  baseline ${describe(rb)}`);
      console.log(`  post     ${describe(rp)}`);
    }
  }
}

console.log(
  `\n${pairs} compile-call pairs over ${allFiles.length} test files: ` +
    `${okEqual} bytecode-equal accepts, ${rejEqual} code-list-equal rejects, ${rows} adjudication rows, ${hardFails} hard fails`,
);
process.exit(hardFails > 0 ? 1 : rows > 0 ? 2 : 0);
