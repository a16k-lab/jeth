// Test-only KZG trusted-setup wiring for the point-evaluation precompile (0x0a).
//
// @ethereumjs 10.x leaves `common.customCrypto.kzg` unset by default, so 0x0a throws "kzg not
// initialized". We load the mainnet trusted setup from `kzg-wasm` (a self-contained WASM build of
// c-kzg, a devDependency - it never reaches the compiler, which does not import this module) ONCE,
// memoized, and inject it into a harness's Common. The default hardfork is already prague, so 0x0a is
// active; only the crypto needs supplying.
import { loadKZG } from 'kzg-wasm';
import type { Harness } from '../src/evm.js';

type LoadedKZG = Awaited<ReturnType<typeof loadKZG>>;
let cached: Promise<LoadedKZG> | undefined;

/** Load (and memoize) the WASM KZG instance with the mainnet trusted setup. */
export function getKZG(): Promise<LoadedKZG> {
  if (!cached) cached = loadKZG();
  return cached;
}

/** Inject the loaded KZG into a harness's Common so the 0x0a precompile can run. Returns the harness. */
export async function enableKzg(h: Harness): Promise<Harness> {
  const kzg = await getKZG();
  const common = (h.evm as unknown as { common: { customCrypto?: Record<string, unknown> } }).common;
  common.customCrypto = { ...common.customCrypto, kzg };
  return h;
}

// The zero-polynomial / point-at-infinity vector: a real, canonical KZG proof (the commitment to the
// zero blob is the compressed G1 infinity 0xc0||47 zero bytes; its proof of evaluating to 0 at any z is
// also infinity). Verified valid by kzg-wasm's own verifyProof, so the precompile accepts it.
export const KZG_INFINITY = 'c0' + '00'.repeat(47); // 48-byte compressed G1 infinity
