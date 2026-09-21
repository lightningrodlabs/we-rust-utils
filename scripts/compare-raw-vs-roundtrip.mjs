#!/usr/bin/env node
// For each published version, compares the published happSha256 against:
//  - sha256 of the raw inner-happ resource bytes (no unpack/repack at all)
//  - sha256 from rustUtils.validateHappOrWebhapp (current code)
//  - sha256 from rustUtils.legacyHappSha256FromPath (rmpv roundtrip)

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { decode } from '@msgpack/msgpack';

const rustUtils = await import('../index.js');

const TOOL_LIST_URL =
  process.argv[2] ||
  'https://lightningrodlabs.org/weave-tool-curation/0.15/tool-list-0.15.json';

const MAX_TOOLS = Number(process.env.MAX_TOOLS || 20);

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

async function main() {
  const res = await fetch(TOOL_LIST_URL);
  const toolList = await res.json();
  const tools = (toolList.tools || []).filter(t => t.versions && t.versions.length);
  const picked = [];
  const seen = new Set();
  for (const t of tools) {
    if (seen.has(t.id)) continue;
    seen.add(t.id);
    picked.push({ id: t.id, version: t.versions[t.versions.length - 1] });
    if (picked.length >= MAX_TOOLS) break;
  }

  console.log(`Testing ${picked.length} versions:\n`);
  const summary = [];
  for (const { id, version } of picked) {
    const exp = version.hashes?.happSha256;
    if (!exp) continue;

    let bytes;
    try {
      const r = await fetch(version.url);
      if (!r.ok) throw new Error(`${r.status}`);
      bytes = Buffer.from(await r.arrayBuffer());
    } catch (e) {
      console.log(`${id}@${version.version}: download failed: ${e.message}`);
      continue;
    }

    // Extract inner happ resource bytes by decoding the webhapp directly.
    let innerHappBytes;
    try {
      const outer = decode(zlib.gunzipSync(bytes));
      const happKey = Object.keys(outer.resources).find(k =>
        k.endsWith('.happ') || k.includes('happ-bundle')
      );
      innerHappBytes = Buffer.from(outer.resources[happKey]);
    } catch (e) {
      console.log(`${id}@${version.version}: could not extract inner happ: ${e.message}`);
      continue;
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cmp-'));
    const tmpPath = path.join(tmpDir, 'bundle.webhapp');
    fs.writeFileSync(tmpPath, bytes);

    try {
      const rawInner = sha256(innerHappBytes);
      const { happSha256: newH } = await rustUtils.validateHappOrWebhapp(Array.from(bytes));
      const legacyH = await rustUtils.legacyHappSha256FromPath(tmpPath);

      const match =
        rawInner === exp ? 'RAW' :
        newH === exp ? 'NEW' :
        legacyH === exp ? 'LEGACY' :
        'NONE';

      summary.push({ id, version: version.version, match, exp, rawInner, newH, legacyH });
      console.log(`${id}@${version.version}: ${match}`);
      if (match === 'NONE') {
        console.log(`  exp:    ${exp}`);
        console.log(`  raw:    ${rawInner}`);
        console.log(`  new:    ${newH}`);
        console.log(`  legacy: ${legacyH}`);
      }
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  }

  console.log('\n=== Summary ===');
  const counts = {};
  for (const s of summary) counts[s.match] = (counts[s.match] || 0) + 1;
  for (const [k, v] of Object.entries(counts)) console.log(`  ${k}: ${v}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
