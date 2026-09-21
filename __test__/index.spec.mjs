import test from 'ava'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const {
  saveHappOrWebhapp,
  validateHappOrWebhapp,
  happBytesWithCustomProperties,
  legacyHappSha256FromPath,
  legacyHappSha256FromBytes,
} = require('../index.js')

// Fixtures are packed with hc 0.7.0 from __test__/fixtures/src and committed as
// bytes. The happ sha256 values below are what the published Moss tool lists
// depend on: Moss identifies a tool by the sha256 of its happ after this crate
// unpacks and repacks it. If a holochain_types bump changes any of them,
// previously published tools no longer verify, so the bump needs a migration
// (as the legacy hash exports provide for pre-0.6.1 bundles), not a new golden.
const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures')
const HAPP = join(fixtures, 'fixture.happ')
const WEBHAPP = join(fixtures, 'fixture.webhapp')

const GOLDEN = {
  happSha256: '8173dca540907b8f4e4ef912f0dd3921139915e3ea0a1f1a955b5423e8bdef5f',
  webhappSha256: '3482d23c9ab7ff40732fabf4148d37657ddff6211b84c39644173db6cbf88c20',
  uiSha256: '4ec4bcf20cb07dc5fe6774efc0226866ad91f51a974bb1c17f4f89178664385d',
  customPropertiesSha256: '219e98d458e6a325caf93882e4f45786adb92b518af25bd59d17038223d199ea',
  legacyHappSha256: 'a9aa25568f595ed8008ab00b606504d142aecfe9fd1785c5d609fcef233949a6',
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const tmp = () => mkdtempSync(join(tmpdir(), 'we-rust-utils-test-'))

test('saving a happ reports the repacked happ sha256', async (t) => {
  const stored = await saveHappOrWebhapp(HAPP, tmp())
  t.is(stored.happSha256, GOLDEN.happSha256)
  t.is(sha256(readFileSync(stored.happPath)), stored.happSha256)
  t.is(stored.webhappSha256, undefined)
  t.is(stored.uiSha256, undefined)
})

test('saving a webhapp reports happ, webhapp and ui sha256', async (t) => {
  const stored = await saveHappOrWebhapp(WEBHAPP, tmp(), tmp())
  t.is(stored.happSha256, GOLDEN.happSha256)
  t.is(stored.webhappSha256, GOLDEN.webhappSha256)
  t.is(stored.webhappSha256, sha256(readFileSync(WEBHAPP)))
  t.is(stored.uiSha256, GOLDEN.uiSha256)
})

test('repacking is stable: a saved happ saves to the same sha256', async (t) => {
  const first = await saveHappOrWebhapp(HAPP, tmp())
  const second = await saveHappOrWebhapp(first.happPath, tmp())
  t.is(second.happSha256, first.happSha256)
})

test('validation reports the same hashes as saving', async (t) => {
  const happ = await validateHappOrWebhapp([...readFileSync(HAPP)])
  t.is(happ.happSha256, GOLDEN.happSha256)
  const webhapp = await validateHappOrWebhapp([...readFileSync(WEBHAPP)])
  t.is(webhapp.happSha256, GOLDEN.happSha256)
  t.is(webhapp.webhappSha256, GOLDEN.webhappSha256)
  t.is(webhapp.uiSha256, GOLDEN.uiSha256)
})

test('custom properties repack to a stable sha256', async (t) => {
  const bytes = await happBytesWithCustomProperties(HAPP, {
    fixture: 'progenitor: uhCAkfixture\nextra: [a, b]',
  })
  t.is(sha256(Buffer.from(bytes)), GOLDEN.customPropertiesSha256)
})

test('legacy sha256 strips the network url fields', async (t) => {
  const legacy = await legacyHappSha256FromPath(HAPP)
  t.is(legacy, GOLDEN.legacyHappSha256)
  t.not(legacy, GOLDEN.happSha256)
  t.is(await legacyHappSha256FromBytes([...readFileSync(HAPP)]), legacy)
})
