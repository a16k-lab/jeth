// TRAILING-HOLE: `let [p, ] = g()` (a destructuring pattern that ends in a trailing comma TS drops)
// binds an m-component tuple discarding the final slot, exactly like solc's `(uint p, ) = g()`. The
// LEADING (`[, q]`) and MIDDLE (`[p, , r]`) holes already worked; this closes the trailing case.
// Byte-identical to solc across internal-call / external-self-call / abi.decode / tuple-literal
// sources and multiple arities, including discarded components whose evaluation has side effects,
// verified by run+decode AND raw storage under state. Guards: a genuine arity mismatch (`[p] = g2()`,
// `[p, ] = g3()`, `[a,b,c] = g2()`) still rejects, matching solc's exact component-count rule.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

// (77,88) abi-encoded as the `bytes` argument to decT(bytes): offset, length(64), payload.
const decBytesArg =
  '0000000000000000000000000000000000000000000000000000000000000020' +
  '0000000000000000000000000000000000000000000000000000000000000040' +
  (77n).toString(16).padStart(64, '0') +
  (88n).toString(16).padStart(64, '0');

const JETH = `class C {
  x: u256;
  c: u256;
  y: u256;
  mk2(): [u256, u256] { return [3n, 4n]; }
  mk3(): [u256, u256, u256] { return [5n, 6n, 7n]; }
  bump(): u256 { this.c = this.c + 1n; return this.c; }
  bumpPair(): [u256, u256] { this.c = this.c + 10n; return [this.c, this.c * 2n]; }
  get pairExt(): External<[u256, u256]> { return [42n, 43n]; }
  get t2(): External<u256> { let [p, ] = this.mk2(); return p; }
  get t3a(): External<u256> { let [p, q, ] = this.mk3(); return p * 100n + q; }
  get t3b(): External<u256> { let [p, , ] = this.mk3(); return p; }
  sideLit(): External<u256> { this.c = 0n; let [p, ] = [this.bump(), this.bump()]; return p * 1000n + this.c; }
  sideCall(): External<u256> { this.c = 0n; let [p, ] = this.bumpPair(); return p * 1000n + this.c; }
  storeIt(): External<u256> { let [p, ] = this.mk2(); this.x = p; return this.x; }
  get readX(): External<u256> { return this.x; }
  extT(): External<u256> { let [p, ] = this.pairExt(); this.y = p; return p; }
  get decT(data: bytes): External<u256> { let [p, ] = abi.decode(data, [u256, u256]); return p; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  uint256 x;
  uint256 c;
  uint256 y;
  function mk2() internal pure returns (uint256, uint256) { return (3, 4); }
  function mk3() internal pure returns (uint256, uint256, uint256) { return (5, 6, 7); }
  function bump() internal returns (uint256) { c = c + 1; return c; }
  function bumpPair() internal returns (uint256, uint256) { c = c + 10; return (c, c * 2); }
  function pairExt() external pure returns (uint256, uint256) { return (42, 43); }
  function t2() external pure returns (uint256) { (uint256 p, ) = mk2(); return p; }
  function t3a() external pure returns (uint256) { (uint256 p, uint256 q, ) = mk3(); return p * 100 + q; }
  function t3b() external pure returns (uint256) { (uint256 p, , ) = mk3(); return p; }
  function sideLit() external returns (uint256) { c = 0; (uint256 p, ) = (bump(), bump()); return p * 1000 + c; }
  function sideCall() external returns (uint256) { c = 0; (uint256 p, ) = bumpPair(); return p * 1000 + c; }
  function storeIt() external returns (uint256) { (uint256 p, ) = mk2(); x = p; return x; }
  function readX() external view returns (uint256) { return x; }
  function extT() external returns (uint256) { (uint256 p, ) = this.pairExt(); y = p; return p; }
  function decT(bytes calldata data) external pure returns (uint256) { (uint256 p, ) = abi.decode(data, (uint256, uint256)); return p; }
}`;

function jethCodes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return ['OK'];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.filter((d) => d.severity === 'error').map((d) => d.code);
    return ['CRASH:' + (e as Error).message];
  }
}
const wrap = (body: string) =>
  `class C { mk2(): [u256,u256] { return [3n,4n]; } mk3(): [u256,u256,u256] { return [5n,6n,7n]; } get h(): External<u256> { ${body} } }`;

describe('trailing-hole tuple destructuring vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, sig: string, args = '') {
    const data = '0x' + sel(sig) + args;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('internal-call trailing holes bind + discard byte-identically', async () => {
    await eq('t2 [p, ] <- 2-tuple', 't2()');
    await eq('t3a [p, q, ] <- 3-tuple', 't3a()');
    await eq('t3b [p, , ] <- 3-tuple (discard 2)', 't3b()');
  });

  it('a discarded component is still evaluated (side effects run)', async () => {
    // sideLit binds p=1 but the DISCARDED second bump() must also run -> c ends at 2 -> 1002.
    await eq('sideLit [p, ] = [bump(), bump()]', 'sideLit()');
    await eq('sideCall [p, ] = bumpPair()', 'sideCall()');
  });

  it('external-self-call + abi.decode trailing holes', async () => {
    await eq('extT [p, ] <- this.pairExt()', 'extT()');
    await eq('decT [p, ] <- abi.decode', 'decT(bytes)', decBytesArg);
  });

  it('the bound component writes storage byte-identically (raw slots)', async () => {
    await eq('storeIt', 'storeIt()');
    await eq('readX', 'readX()');
    // slot0=x (storeIt), slot1=c (sideCall left it at 10), slot2=y (extT left it at 42).
    for (const slot of [0n, 1n, 2n]) {
      const j = await readSlot(jeth, aj, slot);
      const s = await readSlot(sol, as, slot);
      expect(j, `raw slot ${slot}`).toBe(s);
    }
  });

  it('a trailing hole lowers to exactly the explicit-workaround discard (byte-identical bytecode)', () => {
    const bTrail = compile(wrap('let [p, ] = this.mk2(); return p;'), { fileName: 'C.jeth' }).creationBytecode;
    const bWork = compile(wrap('let [p, ,] = this.mk2(); return p;'), { fileName: 'C.jeth' }).creationBytecode;
    expect(bTrail).toBe(bWork);
  });

  it('GUARD: a genuine arity mismatch still rejects (matches solc exact component count)', () => {
    // one short WITHOUT a trailing comma: solc `(uint p) = g2()` rejects.
    expect(jethCodes(wrap('let [p] = this.mk2(); return p;'))).toContain('JETH066');
    // more than one short WITH a trailing comma: solc `(uint p, ) = g3()` rejects (2 != 3).
    expect(jethCodes(wrap('let [p, ] = this.mk3(); return p;'))).toContain('JETH066');
    // over-arity: solc `(uint a, uint b, uint cc) = g2()` rejects.
    expect(jethCodes(wrap('let [a, b, cc] = this.mk2(); return a;'))).toContain('JETH066');
    // under-arity, no trailing comma: solc `(uint p, uint q) = g3()` rejects.
    expect(jethCodes(wrap('let [p, q] = this.mk3(); return p;'))).toContain('JETH066');
  });

  it('GUARD: a decorative trailing comma when the pattern already matches stays accepted (JS semantics)', () => {
    // `[p, q, ] <- 2-tuple` is faithful `(p, q)` = accept (trailing comma decorative); `[ , b, ,]`
    // (existing skipEnds shape) binds the middle of a 3-tuple. Both must still compile.
    expect(jethCodes(wrap('let [p, q, ] = this.mk2(); return p + q;'))).toEqual(['OK']);
    expect(jethCodes(wrap('let [ , b, ,] = this.mk3(); return b;'))).toEqual(['OK']);
  });
});
