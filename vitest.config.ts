import { defineConfig } from 'vitest/config';
// JETH_COMPILE_CACHE enables the (transparent, content-addressed) solc Yul-backend cache in
// src/solc.ts for the test run only - the production `jethc` CLI never sets it. See src/solc.ts.
//
// isolate:false reuses each fork worker's module registry across files instead of tearing it down
// per file - the biggest remaining win (no re-import of ethereumjs + solc-js WASM x415). PROVEN
// SAFE for this suite: under `--sequence.shuffle.files` (randomized FILE order, the correct
// cross-file-isolation gate) it is green across repeated runs, i.e. no module state leaks between
// files. NOTE: `--sequence.shuffle` (which ALSO reorders tests WITHIN a file) fails here in EVERY
// pool including the isolated default - that is a pre-existing, legitimate property of the stateful
// storage/scenario tests (they run a sequence of ops on one deployed contract across `it()`s), NOT
// a cross-file leak. To revert to full per-file isolation, delete `isolate: false`. INVARIANT: a
// test file must not depend on module-level state resetting between files (validate new suites with
// `vitest run --sequence.shuffle.files`).
export default defineConfig({
  test: { include: ['test/**/*.test.ts'], testTimeout: 60000, env: { JETH_COMPILE_CACHE: '1' }, isolate: false },
});
