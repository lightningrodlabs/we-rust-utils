#!/usr/bin/env node
// Verifies that the legacy happ sha256 matches what current published
// tool-list entries record (whereas the new unpack/repack hash does not).
//
// Usage:
//   node scripts/verify-legacy-hash.mjs [tool-list-url]
//
// Defaults to the Holochain 0.6 tool-list curated by Lightning Rod Labs.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const rustUtils = await import('../index.js');

const TOOL_LIST_URL =
  process.argv[2] ||
  'https://lightningrodlabs.org/weave-tool-curation/0.15/tool-list-0.15.json';

// How many distinct published versions to test (one per tool, latest version).
const MAX_TOOLS = Number(process.env.MAX_TOOLS || 5);

async function main() {
  console.log(`Fetching tool list: ${TOOL_LIST_URL}`);
  const res = await fetch(TOOL_LIST_URL);
  if (!res.ok) {
    throw new Error(`Failed to fetch tool list: ${res.status} ${res.statusText}`);
  }
  const toolList = await res.json();
  const tools = toolList.tools || [];
  console.log(`Found ${tools.length} tool entries`);

  // Pick the latest version of each distinct tool id, up to MAX_TOOLS.
  const picked = [];
  const seenIds = new Set();
  for (const t of tools) {
    if (!t.versions || t.versions.length === 0) continue;
    const key = t.id;
    if (seenIds.has(key)) continue;
    seenIds.add(key);
    const latest = t.versions[t.versions.length - 1];
    picked.push({ id: t.id, version: latest });
    if (picked.length >= MAX_TOOLS) break;
  }

  console.log(`\nTesting ${picked.length} published versions:`);
  let okNew = 0;
  let okLegacy = 0;
  let fail = 0;
  for (const { id, version } of picked) {
    const expectedHapp = version.hashes?.happSha256;
    const expectedWebhapp = version.hashes?.webhappSha256;
    if (!expectedHapp) {
      console.log(`  [skip] ${id}@${version.version} (no happSha256)`);
      continue;
    }

    process.stdout.write(`\n--- ${id}@${version.version} ---\n`);
    process.stdout.write(`  url:     ${version.url}\n`);
    process.stdout.write(`  expHapp: ${expectedHapp}\n`);

    let bytes;
    try {
      const r = await fetch(version.url);
      if (!r.ok) {
        throw new Error(`HTTP ${r.status} ${r.statusText}`);
      }
      bytes = new Uint8Array(await r.arrayBuffer());
    } catch (e) {
      console.log(`  [download failed] ${e.message}`);
      continue;
    }
    process.stdout.write(`  bytes:   ${bytes.length}\n`);

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-legacy-'));
    const fileExt = expectedWebhapp ? '.webhapp' : '.happ';
    const tmpPath = path.join(tmpDir, `bundle${fileExt}`);
    fs.writeFileSync(tmpPath, bytes);

    try {
      const { happSha256: newHapp, webhappSha256: newWebhapp } =
        await rustUtils.validateHappOrWebhapp(Array.from(bytes));
      process.stdout.write(`  newHapp: ${newHapp}\n`);
      if (expectedWebhapp) {
        process.stdout.write(`  expWeb:  ${expectedWebhapp}\n`);
        process.stdout.write(`  gotWeb:  ${newWebhapp} ${newWebhapp === expectedWebhapp ? 'OK' : 'MISMATCH'}\n`);
      }

      const legacyHapp = await rustUtils.legacyHappSha256FromPath(tmpPath);
      process.stdout.write(`  lgcHapp: ${legacyHapp}\n`);

      if (newHapp === expectedHapp) {
        process.stdout.write(`  RESULT:  matches via current hash\n`);
        okNew++;
      } else if (legacyHapp === expectedHapp) {
        process.stdout.write(`  RESULT:  matches via LEGACY hash\n`);
        okLegacy++;
      } else {
        process.stdout.write(`  RESULT:  NEITHER MATCHES\n`);
        fail++;
      }
    } finally {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch (_) {}
    }
  }

  console.log('\n=== Summary ===');
  console.log(`  current-hash matches: ${okNew}`);
  console.log(`  legacy-hash matches:  ${okLegacy}`);
  console.log(`  no match:             ${fail}`);
  if (fail > 0) {
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
