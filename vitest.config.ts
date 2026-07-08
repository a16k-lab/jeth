import { defineConfig } from 'vitest/config';
// JETH_COMPILE_CACHE enables the (transparent, content-addressed) solc Yul-backend cache in
// src/solc.ts for the test run only - the production `jethc` CLI never sets it. See src/solc.ts.
export default defineConfig({
  test: { include: ['test/**/*.test.ts'], testTimeout: 60000, env: { JETH_COMPILE_CACHE: '1' } },
});
