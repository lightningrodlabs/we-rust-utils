import test from 'ava'
import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// A process that has loaded the addon must exit cleanly. On Windows, shutting
// the async runtime down after the OS has already terminated its threads
// crashes the process on exit (0xC0000005) some of the time, so each probe
// runs several times in a fresh process.
const here = dirname(fileURLToPath(import.meta.url))
const RUNS = 10

for (const probe of ['exit-probe.cjs', 'exit-probe-worker.cjs']) {
  test(`${probe} exits cleanly across ${RUNS} runs`, (t) => {
    const codes = []
    for (let i = 0; i < RUNS; i++) {
      codes.push(spawnSync(process.execPath, [join(here, probe)], { stdio: 'ignore' }).status)
    }
    t.deepEqual(codes, Array(RUNS).fill(0))
  })
}
