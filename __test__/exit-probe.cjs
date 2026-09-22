// Loads the addon on this thread, makes one async (tokio-backed) call, and
// lets the process exit normally.
const fs = require('node:fs')
const path = require('node:path')
const { validateHappOrWebhapp } = require('../index.js')

const happ = fs.readFileSync(path.join(__dirname, 'fixtures', 'fixture.happ'))
validateHappOrWebhapp([...happ]).then((r) => {
  if (!r.happSha256) process.exit(2)
})
