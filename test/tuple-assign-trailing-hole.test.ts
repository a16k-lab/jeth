// TRAILING-HOLE (ASSIGNMENT twin of the `let [p, ] = g()` decl lift): `[a, ] = g()` (a tuple
// ASSIGNMENT to existing lvalues, NO `let`, ending in a trailing comma TS drops) binds an m-component
// tuple discarding the final slot, exactly like solc's `(a, ) = g()`. The LEADING (`[, b]`) and MIDDLE
// (`[a, , c]`) assignment holes already worked; this closes the trailing case, reusing the shared
// tupleArityMatch + a discarded-target skip in the tupleAssign lowering. Byte-identical to solc across
// internal-call / external-self-call / abi.decode / interface-call / tuple-literal sources and multiple
// arities, including discarded components whose evaluation has side effects (raw-storage witness), and a
// MIXED field+local target. Guards: a genuine arity mismatch still rejects. The decorative-trailing-comma
// JS-array acceptance matches the decl path (documented in the trailing-hole decl test).
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

const selfArg = (addr: Address) => addr.toString().slice(2).padStart(64, '0');

const JETH = `class C {
  x: u256;
  c: u256;
  y: u256;
  mk2(): [u256, u256] { return [3n, 4n]; }
  mk3(): [u256, u256, u256] { return [5n, 6n, 7n]; }
  bump(): u256 { this.c = this.c + 1n; return this.c; }
  bumpPair(): [u256, u256] { this.c = this.c + 10n; return [this.c, this.c * 2n]; }
  get pairExt(): External<[u256, u256]> { return [42n, 43n]; }
  get t2(): External<u256> { let p: u256 = 0n; [p, ] = this.mk2(); return p; }
  get t3a(): External<u256> { let p: u256 = 0n; let q: u256 = 0n; [p, q, ] = this.mk3(); return p * 100n + q; }
  get t3b(): External<u256> { let p: u256 = 0n; [p, , ] = this.mk3(); return p; }
  sideLit(): External<u256> { this.c = 0n; let p: u256 = 0n; [p, ] = [this.bump(), this.bump()]; return p * 1000n + this.c; }
  sideCall(): External<u256> { this.c = 0n; let p: u256 = 0n; [p, ] = this.bumpPair(); return p * 1000n + this.c; }
  storeIt(): External<u256> { let p: u256 = 0n; [p, ] = this.mk2(); this.x = p; return this.x; }
  get readX(): External<u256> { return this.x; }
  extT(): External<u256> { let p: u256 = 0n; [p, ] = this.pairExt(); this.y = p; return p; }
  get decT(data: bytes): External<u256> { let p: u256 = 0n; [p, ] = abi.decode(data, [u256, u256]); return p; }
  mixed(): External<u256> { let b: u256 = 0n; [this.x, b, ] = this.mk3(); return this.x * 1000n + b; }
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
  function t2() external pure returns (uint256) { uint256 p; (p, ) = mk2(); return p; }
  function t3a() external pure returns (uint256) { uint256 p; uint256 q; (p, q, ) = mk3(); return p * 100 + q; }
  function t3b() external pure returns (uint256) { uint256 p; (p, , ) = mk3(); return p; }
  function sideLit() external returns (uint256) { c = 0; uint256 p; (p, ) = (bump(), bump()); return p * 1000 + c; }
  function sideCall() external returns (uint256) { c = 0; uint256 p; (p, ) = bumpPair(); return p * 1000 + c; }
  function storeIt() external returns (uint256) { uint256 p; (p, ) = mk2(); x = p; return x; }
  function readX() external view returns (uint256) { return x; }
  function extT() external returns (uint256) { uint256 p; (p, ) = this.pairExt(); y = p; return p; }
  function decT(bytes calldata data) external pure returns (uint256) { uint256 p; (p, ) = abi.decode(data, (uint256, uint256)); return p; }
  function mixed() external returns (uint256) { uint256 b; (x, b, ) = mk3(); return x * 1000 + b; }
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
// a body wrapped in an assignment context with several pre-declared value locals (the assignment path
// requires the LHS targets to be existing lvalues). A `get` accessor since the bodies are read-only.
const wrapA = (body: string) =>
  `class C { z: u256; mk2(): [u256,u256] { return [3n,4n]; } mk3(): [u256,u256,u256] { return [5n,6n,7n]; } get run(): External<u256> { let p: u256 = 0n; let q: u256 = 0n; let a: u256 = 0n; let b: u256 = 0n; let cc: u256 = 0n; ${body} } }`;

describe('trailing-hole tuple ASSIGNMENT (no let) vs Solidity', () => {
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

  it('a MIXED field+local target with a trailing hole assigns byte-identically', async () => {
    await eq('mixed [this.x, b, ] <- 3-tuple', 'mixed()');
  });

  it('the bound components write storage byte-identically (raw slots)', async () => {
    // Re-run the state-touching methods so the slots are populated on both, then compare raw storage.
    await eq('storeIt', 'storeIt()'); // slot0 = x <- 3
    await eq('readX', 'readX()');
    await eq('sideCall (leaves c=10)', 'sideCall()'); // slot1 = c
    await eq('extT (leaves y=42)', 'extT()'); // slot2 = y
    await eq('mixed (x<-5)', 'mixed()'); // slot0 = x <- 5
    for (const slot of [0n, 1n, 2n]) {
      const j = await readSlot(jeth, aj, slot);
      const s = await readSlot(sol, as, slot);
      expect(j, `raw slot ${slot}`).toBe(s);
    }
  });

  it('an interface-call trailing hole assigns byte-identically (target = self)', async () => {
    // deploy fresh so the interface target (C's own address) has a matching pair() selector.
    const IJ = `interface IPair { pair(): [u256,u256]; }
class C { x: u256; get pair(): External<[u256,u256]> { return [55n,66n]; } run(a: address): External<void> { let v: u256 = 0n; [v, ] = IPair(a).pair(); this.x = v; } get gx(): External<u256> { return this.x; } }`;
    const IS = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
interface IPair { function pair() external returns (uint256,uint256); }
contract C { uint256 x; function pair() external pure returns(uint256,uint256){return (55,66);} function run(address a) external { uint256 v; (v,) = IPair(a).pair(); x=v; } function gx() external view returns(uint256){return x;} }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const ajI = await hj.deploy(compile(IJ, { fileName: 'C.jeth' }).creationBytecode);
    const asI = await hs.deploy(compileSolidity(IS, 'C').creation);
    await hj.call(ajI, '0x' + sel('run(address)') + selfArg(ajI));
    await hs.call(asI, '0x' + sel('run(address)') + selfArg(asI));
    const gj = await hj.call(ajI, '0x' + sel('gx()'));
    const gs = await hs.call(asI, '0x' + sel('gx()'));
    expect(gj.returnHex, 'iface gx returndata').toBe(gs.returnHex);
    expect(await readSlot(hj, ajI, 0n), 'iface slot0').toBe(await readSlot(hs, asI, 0n));
  });

  it('a trailing-hole ASSIGNMENT lowers to exactly the explicit-workaround discard (byte-identical bytecode)', () => {
    const bTrail = compile(wrapA('[p, ] = this.mk2(); return p;'), { fileName: 'C.jeth' }).creationBytecode;
    const bWork = compile(wrapA('[p, ,] = this.mk2(); return p;'), { fileName: 'C.jeth' }).creationBytecode;
    expect(bTrail).toBe(bWork);
  });

  it('NON-VACUITY: the trailing comma is load-bearing (pre-fix `[a, ] = g()` rejected JETH066)', () => {
    // On the base (pre-fix) analyzer `[p, ] = this.mk2()` threw JETH066 ("expected 1 target(s)"). It now
    // compiles; the plain one-short form WITHOUT the trailing comma (`[p] = this.mk2()`) still rejects.
    // So the accept is driven by the trailing comma, not by loosening the arity gate generally.
    expect(jethCodes(wrapA('[p, ] = this.mk2(); return p;'))).toEqual(['OK']);
    expect(jethCodes(wrapA('[p] = this.mk2(); return p;'))).toContain('JETH066');
  });

  it('GUARD: a genuine arity mismatch still rejects (matches solc exact component count)', () => {
    // one short WITHOUT a trailing comma: solc `(p) = g2()` rejects.
    expect(jethCodes(wrapA('[p] = this.mk2(); return p;'))).toContain('JETH066');
    // more than one short WITH a trailing comma: solc `(p, ) = g3()` rejects (2 != 3).
    expect(jethCodes(wrapA('[p, ] = this.mk3(); return p;'))).toContain('JETH066');
    // over-arity: solc `(a, b, cc) = g2()` rejects.
    expect(jethCodes(wrapA('[a, b, cc] = this.mk2(); return a;'))).toContain('JETH066');
    // under-arity, no trailing comma: solc `(p, q) = g3()` rejects.
    expect(jethCodes(wrapA('[p, q] = this.mk3(); return p;'))).toContain('JETH066');
  });

  it('GUARD: a decorative trailing comma when the pattern already matches stays accepted (JS semantics)', () => {
    // Mirrors the decl-path position: `[p, q, ] <- 2-tuple` (comma decorative, already 2 targets) and
    // `[ , b, ,] <- 3-tuple` (leading + middle holes) both compile - JETH's surface is TS array literals.
    expect(jethCodes(wrapA('[p, q, ] = this.mk2(); return p + q;'))).toEqual(['OK']);
    expect(jethCodes(wrapA('[ , b, ,] = this.mk3(); return b;'))).toEqual(['OK']);
  });

  it('ADJACENT: leading + middle assignment holes stay byte-identical', async () => {
    // (verified against solc via the dedicated harness above; here assert they still compile clean.)
    expect(jethCodes(wrapA('[, q] = this.mk2(); return q;'))).toEqual(['OK']);
    expect(jethCodes(wrapA('[a, , cc] = this.mk3(); return a * 10n + cc;'))).toEqual(['OK']);
  });
});
