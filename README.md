# @lightningrodlabs/we-rust-utils

Native Node.js bindings for Rust utilities used by [Moss](https://theweave.social) (formerly "We"), built with [NAPI-RS](https://napi.rs).

This package exposes Holochain-related functionality that needs to run in Rust — signing zome calls against a [lair keystore](https://github.com/holochain/lair) and inspecting/repackaging `.happ` and `.webhapp` bundles — as an async, promise-based JavaScript API.

## Installation

```sh
npm install @lightningrodlabs/we-rust-utils
```

Prebuilt binaries are published for the following platforms:

- macOS — `aarch64` (Apple Silicon) and `x86_64`
- Linux — `aarch64` and `x86_64` (gnu)
- Windows — `x86_64` (msvc)

## API

### `WeRustHandler`

Handler for signing zome calls via a lair keystore.

```js
import { WeRustHandler } from '@lightningrodlabs/we-rust-utils'

const handler = await WeRustHandler.connect(keystoreUrl, passphrase)
const signature = await handler.signZomeCall(payload, pubKey)
```

- **`WeRustHandler.connect(keystoreUrl, passphrase)`** — Connects to a running lair keystore at the given URL and returns a `WeRustHandler`.
- **`handler.signZomeCall(payload, pubKey)`** — Signs a zome call payload with the agent key identified by `pubKey`. Returns the signature bytes.

### happ / webhapp utilities

```js
import {
  saveHappOrWebhapp,
  validateHappOrWebhapp,
  happBytesWithCustomProperties,
} from '@lightningrodlabs/we-rust-utils'
```

- **`saveHappOrWebhapp(happOrWebHappPath, happsDir, uisDir?)`** — Saves a `.happ` or `.webhapp` file. If `uisDir` is given and the file is a webhapp, the UI is stored in `[uisDir]/[sha256 of UI]/assets`. Returns the stored happ path and the SHA-256 hashes.
- **`validateHappOrWebhapp(happOrWebhappBytes)`** — Checks that the given bytes are a correctly formatted happ or webhapp and returns its hashes.
- **`happBytesWithCustomProperties(happPath, properties)`** — Reads a happ bundle and returns its bytes with the given DNA properties applied.

See [`index.d.ts`](index.d.ts) for the full type definitions.

## Development

This package is built with [NAPI-RS](https://napi.rs). You need a [Rust toolchain](https://rustup.rs) and Node.js installed.

```sh
# build a debug binary for the current platform
npm run build:debug

# build a release binary for the current platform
npm run build

# run the tests
npm test
```

## License

[Apache-2.0](LICENSE) © Lightning Rod Labs
