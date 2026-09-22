// Runs exit-probe.cjs in a worker thread that finishes before the main thread
// exits: the teardown order under which the async runtime's shutdown matters.
const { Worker } = require('node:worker_threads')

const worker = new Worker(require.resolve('./exit-probe.cjs'))
worker.on('exit', (code) => {
  if (code !== 0) process.exitCode = 3
})
