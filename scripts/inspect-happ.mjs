#!/usr/bin/env node
// Dumps the inner happ bundle's manifest as JSON for inspection.
//
// Usage: node scripts/inspect-happ.mjs <url-or-path>

import fs from 'node:fs';
import zlib from 'node:zlib';
import { decode } from '@msgpack/msgpack';

const src = process.argv[2];
if (!src) {
  console.error('Usage: node scripts/inspect-happ.mjs <url-or-path>');
  process.exit(1);
}

async function readBytes() {
  if (src.startsWith('http')) {
    const r = await fetch(src);
    return new Uint8Array(await r.arrayBuffer());
  }
  return fs.readFileSync(src);
}

function decodeBundle(bytes) {
  const inflated = zlib.gunzipSync(Buffer.from(bytes));
  return decode(inflated);
}

const bytes = await readBytes();
const outer = decodeBundle(bytes);
console.log('Outer manifest keys:', Object.keys(outer.manifest || {}));

if (outer.manifest && outer.manifest.happ && outer.resources) {
  // It's a webhapp — find the inner happ resource
  const happKey = Object.keys(outer.resources).find(k =>
    k.endsWith('.happ') || k.includes('happ-bundle')
  );
  const happBytes = outer.resources[happKey];
  console.log('Inner happ resource key:', happKey, 'bytes:', happBytes.length);
  const inner = decodeBundle(happBytes);
  console.log('Inner manifest:', JSON.stringify(inner.manifest, null, 2));
  console.log('Inner resource keys:', Object.keys(inner.resources));
} else {
  console.log('Manifest:', JSON.stringify(outer.manifest, null, 2));
  console.log('Resource keys:', Object.keys(outer.resources || {}));
}
