// Round-2.5 fixes: narrow unchecked signed-div wrap (#1), and the gate for pushing a whole
// array element into a nested storage array (#3, was a silent miscompile).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
function diags(src: string): string[] {
  try { compile(src, { fileName: 'G.jeth' }); return []; }
  catch (e: any) { return (e.diagnostics ?? e.items ?? []).map((d: any) => d.code); }
}

const JETH = `@contract class UD {
  @external @pure d8(a: i8, b: i8): i8 { unchecked: { return a / b; } }
  @external @pure d16(a: i16, b: i16): i16 { unchecked: { return a / b; } }
  @external @pure d64(a: i64, b: i64): i64 { unchecked: { return a / b; } }
  @external @pure d128(a: i128, b: i128): i128 { unchecked: { return a / b; } }
  @external @pure d256(a: i256, b: i256): i256 { unchecked: { return a / b; } }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract UD {
  function d8(int8 a, int8 b) external pure returns (int8){ unchecked { return a / b; } }
  function d16(int16 a, int16 b) external pure returns (int16){ unchecked { return a / b; } }
  function d64(int64 a, int64 b) external pure returns (int64){ unchecked { return a / b; } }
  function d128(int128 a, int128 b) external pure returns (int128){ unchecked { return a / b; } }
  function d256(int256 a, int256 b) external pure returns (int256){ unchecked { return a / b; } }
}`;

describe('round-2.5 fixes', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, sig: string, args: bigint[]) {
    const data = '0x' + sel(sig) + args.map(pad).join('');
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'UD.jeth' });
    const sb = compileSolidity(SOL, 'UD');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('#1 narrow unchecked signed div INT_MIN/-1 wraps + sign-extends like solc', async () => {
    await eq('d8 min/-1', 'd8(int8,int8)', [1n << 7n, M - 1n]); // -128 / -1 -> -128
    await eq('d16 min/-1', 'd16(int16,int16)', [1n << 15n, M - 1n]);
    await eq('d64 min/-1', 'd64(int64,int64)', [1n << 63n, M - 1n]);
    await eq('d128 min/-1', 'd128(int128,int128)', [1n << 127n, M - 1n]);
    await eq('d256 min/-1', 'd256(int256,int256)', [1n << 255n, M - 1n]);
    // sanity: normal narrow signed division still correct
    await eq('d8 -100/7', 'd8(int8,int8)', [M - 100n, 7n]);
  });

  it('#3 pushing a whole array element into a nested storage array now COMPILES (deep copy; see push-array-elem.test.ts)', () => {
    expect(diags(`@contract class G {
  @state dd: u256[][];
  @external f(): void { let xs: u256[] = [1n, 2n]; this.dd.push(xs); }
}`)).toEqual([]);
    expect(diags(`@contract class G { @state dd: u256[][]; @external f(): void { this.dd.push(); } }`)).toEqual([]);
  });
});
