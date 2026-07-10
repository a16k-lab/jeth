// ATTACHED-CALL EVALUATION ORDER. For an attached library call `recv.fn(args...)` - BOTH channels:
// legacy `@using(L)` and the native `self` convention - solc's LEGACY pipeline evaluates the explicit
// ARGUMENTS first (left-to-right), THEN the receiver expression (the same argument-before-function-
// expression rule the Batch C funcRefCall fix pinned). JETH used to lower the receiver (args[0] of the
// desugared internal call) FIRST, a silent wrong-returndata miscompile whenever an argument mutated
// state the receiver read (seeded n=9, `this.n.tag2(this.bump())` with bump() adding 11: JETH returned
// 9006, solc 20006). Pinned at 0.8.35 across storage / mapping / call-result / side-effecting-index /
// struct / bytes receivers, in value AND statement position, composing recursively through chains.
// EXCEPTION (also pinned): an @external (DELEGATECALL) library attached call evaluates its receiver
// FIRST in solc legacy - that channel is deliberately NOT reordered.
// Every anchor below asserts the solc-pinned decoded VALUE (not just jeth == solc), so a vacuous pair
// (both wrong the same way) cannot pass. tr() returns a trace: each mark(id) does t = t*100 + id.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity, compileSolidityLinked, deploySolLinked } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));

/** Deploy the JETH source and its solc mirror, run `calls` on both, assert byte-identical
 *  success+returndata per call, and return the DECODED (bigint) results for value anchors. */
async function pair(jethSrc: string, solSrc: string, calls: [string, string?][]): Promise<bigint[]> {
  const jb = compile(jethSrc, { fileName: 'C.jeth' }).creationBytecode;
  const sb = compileSolidity(SPDX + solSrc, 'C').creation;
  const h = await Harness.create();
  const aj = await h.deploy(jb);
  const as = await h.deploy(sb);
  const out: bigint[] = [];
  for (const [sig, args] of calls) {
    const data = sel(sig) + (args ?? '');
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect({ sig, success: rj.success, ret: rj.returnHex }).toEqual({ sig, success: rs.success, ret: rs.returnHex });
    out.push(rj.returnHex === '0x' ? 0n : BigInt(rj.returnHex));
  }
  return out;
}

// Shared library + contract scaffolding. mark trace: t = t*100 + id.
const LIB = `@library class L {
  tag2(v: u256, k: u256): u256 { return v * 1000n + k; }
  tag3(v: u256, a: u256, b: u256): u256 { return v * 1000000n + a * 1000n + b; }
  f(v: u256, a: u256): u256 { return v * 10n + a; }
  h(v: u256, a: u256): u256 { return v * 100n + a; }
  sink(v: u256, k: u256): void { }
}`;
const SLIB = `library L {
  function tag2(uint256 v, uint256 k) internal pure returns (uint256) { return v * 1000 + k; }
  function tag3(uint256 v, uint256 a, uint256 b) internal pure returns (uint256) { return v * 1000000 + a * 1000 + b; }
  function f(uint256 v, uint256 a) internal pure returns (uint256) { return v * 10 + a; }
  function h(uint256 v, uint256 a) internal pure returns (uint256) { return v * 100 + a; }
  function sink(uint256 v, uint256 k) internal pure { }
}`;
const LC = (body: string) => `// use @decorators
${LIB}
@using(L) @contract class C {
  @state t: u256; @state n: u256;
  mk(id: u256): u256 { this.t = this.t * 100n + id; return id; }
  bump(): u256 { this.mk(1n); this.n = this.n + 11n; return 6n; }
  @external seed(x: u256): void { this.n = x; }
  @external @view rdN(): u256 { return this.n; }
  @external @view tr(): u256 { return this.t; }
  ${body}
}`;
const SC = (body: string, extra = '') => `${SLIB}
contract C {
  using L for uint256; ${extra}
  uint256 t; uint256 n;
  function mk(uint256 id) internal returns (uint256) { t = t * 100 + id; return id; }
  function bump() internal returns (uint256) { mk(1); n = n + 11; return 6; }
  function seed(uint256 x) external { n = x; }
  function rdN() external view returns (uint256) { return n; }
  function tr() external view returns (uint256) { return t; }
  ${body}
}`;
const NLIB = `static class L {
  tag2(self: u256, k: u256): u256 { return self * 1000n + k; }
  tag3(self: u256, a: u256, b: u256): u256 { return self * 1000000n + a * 1000n + b; }
  sink(self: u256, k: u256): void { }
}`;
const NC = (body: string) => `${NLIB}
class C {
  t: u256; n: u256;
  mk(id: u256): u256 { this.t = this.t * 100n + id; return id; }
  bump(): u256 { this.mk(1n); this.n = this.n + 11n; return 6n; }
  seed(x: u256): External<void> { this.n = x; }
  get tr(): External<u256> { return this.t; }
  ${body}
}`;

const seedGoTr: [string, string?][] = [['seed(uint256)', W(9)], ['go()'], ['tr()']];

describe('attached-call evaluation order (args first, receiver LAST - solc legacy)', () => {
  it('legacy @using: a state-mutating arg runs BEFORE the storage receiver read (the adjudicated repro)', async () => {
    const [, go, tr, n] = await pair(
      LC(`@external go(): u256 { return this.n.tag2(this.bump()); }`),
      SC(`function go() external returns (uint256) { return n.tag2(bump()); }`),
      [...seedGoTr, ['rdN()']],
    );
    expect(go).toBe(20006n); // (9+11)*1000+6: bump() FIRST, receiver read second (was 9006)
    expect(tr).toBe(1n);
    expect(n).toBe(20n); // storage agrees afterward
  });

  it('native self convention: the same shape and the same order', async () => {
    const [, go, tr] = await pair(
      NC(`go(): External<u256> { return this.n.tag2(this.bump()); }`),
      SC(`function go() external returns (uint256) { return n.tag2(bump()); }`),
      seedGoTr,
    );
    expect(go).toBe(20006n);
    expect(tr).toBe(1n);
  });

  it('TWO mutating args evaluate left-to-right, receiver after BOTH (both channels)', async () => {
    const legacy = await pair(
      LC(`bumpB(): u256 { this.mk(2n); this.n = this.n + 300n; return 8n; }
  @external go(): u256 { return this.n.tag3(this.bump(), this.bumpB()); }`),
      SC(`function bumpB() internal returns (uint256) { mk(2); n = n + 300; return 8; }
  function go() external returns (uint256) { return n.tag3(bump(), bumpB()); }`),
      seedGoTr,
    );
    expect(legacy[1]).toBe(320006008n); // n=(9+11+300), args 6 and 8
    expect(legacy[2]).toBe(102n); // mk(1) then mk(2): left-to-right
    const native = await pair(
      NC(`bumpB(): u256 { this.mk(2n); this.n = this.n + 300n; return 8n; }
  go(): External<u256> { return this.n.tag3(this.bump(), this.bumpB()); }`),
      SC(`function bumpB() internal returns (uint256) { mk(2); n = n + 300; return 8; }
  function go() external returns (uint256) { return n.tag3(bump(), bumpB()); }`),
      seedGoTr,
    );
    expect(native[1]).toBe(320006008n);
    expect(native[2]).toBe(102n);
  });

  it('a CALL-RESULT receiver evaluates after the args (trace order, not just values)', async () => {
    const [go, tr] = await pair(
      LC(`pick(): u256 { this.mk(7n); return 4n; }
  @external go(): u256 { return this.pick().tag2(this.mk(3n)); }`),
      SC(`function pick() internal returns (uint256) { mk(7); return 4; }
  function go() external returns (uint256) { return pick().tag2(mk(3)); }`),
      [['go()'], ['tr()']],
    );
    expect(go).toBe(4003n);
    expect(tr).toBe(307n); // arg mk(3) FIRST, then the receiver call's mk(7)
  });

  it('a receiver with a side effect in ITS OWN expression (arr[bumpI()]) still runs after the args', async () => {
    const [, go, tr] = await pair(
      LC(`@state arr: Arr<u256, 3>;
  bumpI(): u256 { this.mk(7n); this.arr[2n] = this.arr[2n] + 5n; return 2n; }
  @external seedA(): void { this.arr[0n] = 50n; this.arr[1n] = 60n; this.arr[2n] = 70n; }
  @external go(): u256 { return this.arr[this.bumpI()].tag2(this.mk(3n)); }`),
      SC(`uint256[3] arr;
  function bumpI() internal returns (uint256) { mk(7); arr[2] = arr[2] + 5; return 2; }
  function seedA() external { arr[0] = 50; arr[1] = 60; arr[2] = 70; }
  function go() external returns (uint256) { return arr[bumpI()].tag2(mk(3)); }`),
      [['seedA()'], ['go()'], ['tr()']],
    );
    expect(go).toBe(75003n); // arr[2] read as 70+5 (index call after the arg)
    expect(tr).toBe(307n);
  });

  it('chained attachments x.f(g()).h(k()) compose the rule recursively', async () => {
    const [, go, tr] = await pair(
      LC(`g(): u256 { this.mk(3n); this.n = this.n + 11n; return 2n; }
  k(): u256 { this.mk(4n); return 5n; }
  @external go(): u256 { return this.n.f(this.g()).h(this.k()); }`),
      SC(`function g() internal returns (uint256) { mk(3); n = n + 11; return 2; }
  function k() internal returns (uint256) { mk(4); return 5; }
  function go() external returns (uint256) { return n.f(g()).h(k()); }`),
      seedGoTr,
    );
    expect(go).toBe(20205n); // h's arg k() first, then its receiver n.f(g()): g(), then n read (=20)
    expect(tr).toBe(403n); // mk(4) BEFORE mk(3)
  });

  it('an attached call as the ARGUMENT of another attached call (nested rule)', async () => {
    const [, , go, tr] = await pair(
      LC(`@state kk: u256;
  bumpBoth(): u256 { this.mk(1n); this.n = this.n + 11n; this.kk = this.kk + 2n; return 6n; }
  @external seedK(x: u256): void { this.kk = x; }
  @external go(): u256 { return this.n.tag2(this.kk.tag2(this.bumpBoth())); }`),
      SC(`uint256 kk;
  function bumpBoth() internal returns (uint256) { mk(1); n = n + 11; kk = kk + 2; return 6; }
  function seedK(uint256 x) external { kk = x; }
  function go() external returns (uint256) { return n.tag2(kk.tag2(bumpBoth())); }`),
      [['seed(uint256)', W(9)], ['seedK(uint256)', W(3)], ['go()'], ['tr()']],
    );
    expect(go).toBe(25006n); // inner: bumpBoth then kk read (=5) -> 5006; outer: n read (=20) -> 25006
    expect(tr).toBe(1n);
  });

  it('STATEMENT position (void attached call) keeps the same order - both channels', async () => {
    const legacy = await pair(
      LC(`rd(): u256 { this.mk(9n); return this.n; }
  @external go(): void { this.rd().sink(this.bump()); }`),
      SC(`function rd() internal returns (uint256) { mk(9); return n; }
  function go() external { rd().sink(bump()); }`),
      seedGoTr,
    );
    expect(legacy[2]).toBe(109n); // bump's mk(1) BEFORE the receiver call's mk(9)
    const native = await pair(
      NC(`rd(): u256 { this.mk(9n); return this.n; }
  go(): External<void> { this.rd().sink(this.bump()); }`),
      SC(`function rd() internal returns (uint256) { mk(9); return n; }
  function go() external { rd().sink(bump()); }`),
      seedGoTr,
    );
    expect(native[2]).toBe(109n);
  });

  it('a STRUCT receiver copies storage->memory AFTER the args; a BYTES receiver likewise', async () => {
    const [, goS, trS] = await pair(
      `// use @decorators
@struct class P { x: u256; y: u256; }
@library class LP { getx(p: P, k: u256): u256 { return p.x * 1000n + k; } }
@using(LP) @contract class C {
  @state t: u256; @state s: P;
  mk(id: u256): u256 { this.t = this.t * 100n + id; return id; }
  bumpX(): u256 { this.mk(1n); this.s.x = this.s.x + 11n; return 6n; }
  @external seed(x: u256): void { this.s.x = x; this.s.y = 1n; }
  @external go(): u256 { return this.s.getx(this.bumpX()); }
  @external @view tr(): u256 { return this.t; }
}`,
      `library LP { struct P { uint256 x; uint256 y; }
  function getx(P memory p, uint256 k) internal pure returns (uint256) { return p.x * 1000 + k; } }
contract C { using LP for LP.P;
  uint256 t; LP.P s;
  function mk(uint256 id) internal returns (uint256) { t = t * 100 + id; return id; }
  function bumpX() internal returns (uint256) { mk(1); s.x = s.x + 11; return 6; }
  function seed(uint256 x) external { s.x = x; s.y = 1; }
  function go() external returns (uint256) { return s.getx(bumpX()); }
  function tr() external view returns (uint256) { return t; }
}`,
      seedGoTr,
    );
    expect(goS).toBe(20006n); // p.x sees the mutated value: the memory copy is made after the arg
    expect(trS).toBe(1n);
    const [, goB, trB] = await pair(
      `// use @decorators
@library class LB { blen(b: bytes, k: u256): u256 { return b.length * 1000n + k; } }
@using(LB) @contract class C {
  @state t: u256; @state b: bytes;
  mk(id: u256): u256 { this.t = this.t * 100n + id; return id; }
  grow(): u256 { this.mk(1n); this.b.push(0x22n); return 6n; }
  @external seed(x: u256): void { this.b.push(0x11n); this.b.push(0x11n); }
  @external go(): u256 { return this.b.blen(this.grow()); }
  @external @view tr(): u256 { return this.t; }
}`,
      `library LB { function blen(bytes memory b, uint256 k) internal pure returns (uint256) { return b.length * 1000 + k; } }
contract C { using LB for bytes;
  uint256 t; bytes b;
  function mk(uint256 id) internal returns (uint256) { t = t * 100 + id; return id; }
  function grow() internal returns (uint256) { mk(1); b.push(0x22); return 6; }
  function seed(uint256 x) external { b.push(0x11); b.push(0x11); }
  function go() external returns (uint256) { return b.blen(grow()); }
  function tr() external view returns (uint256) { return t; }
}`,
      seedGoTr,
    );
    expect(goB).toBe(3006n); // length 3: the push landed before the copy
    expect(trB).toBe(1n);
  });

  it('a side-effect-free attached call is unregressed (plain literal arg)', async () => {
    const [, go, tr] = await pair(
      LC(`@external go(): u256 { return this.n.tag2(5n); }`),
      SC(`function go() external returns (uint256) { return n.tag2(5); }`),
      seedGoTr,
    );
    expect(go).toBe(9005n);
    expect(tr).toBe(0n);
  });

  it('the @external (DELEGATECALL) library channel is NOT reordered: solc evaluates ITS receiver FIRST', async () => {
    const jeth = `// use @decorators
@library class L { @external @pure tag2(v: u256, k: u256): u256 { return v * 1000n + k; } }
@using(L) @contract class C {
  @state t: u256; @state n: u256;
  mk(id: u256): u256 { this.t = this.t * 100n + id; return id; }
  bump(): u256 { this.mk(1n); this.n = this.n + 11n; return 6n; }
  @external seed(x: u256): void { this.n = x; }
  @external go(): u256 { return this.n.tag2(this.bump()); }
  @external @view tr(): u256 { return this.t; }
}`;
    const sol = `${SPDX}
library L { function tag2(uint256 v, uint256 k) external pure returns (uint256) { return v * 1000 + k; } }
contract C { using L for uint256;
  uint256 t; uint256 n;
  function mk(uint256 id) internal returns (uint256) { t = t * 100 + id; return id; }
  function bump() internal returns (uint256) { mk(1); n = n + 11; return 6; }
  function seed(uint256 x) external { n = x; }
  function go() external returns (uint256) { return n.tag2(bump()); }
  function tr() external view returns (uint256) { return t; }
}`;
    const jb = compile(jeth, { fileName: 'C.jeth' });
    const sb = compileSolidityLinked(sol, 'C', ['L']);
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = (await hj.deployLinked(jb)).address;
    const as = await deploySolLinked(hs, sb);
    const decoded: bigint[] = [];
    for (const [sig, args] of seedGoTr) {
      const data = sel(sig) + (args ?? '');
      const rj = await hj.call(aj, data);
      const rs = await hs.call(as, data);
      expect({ sig, success: rj.success, ret: rj.returnHex }).toEqual({ sig, success: rs.success, ret: rs.returnHex });
      decoded.push(rj.returnHex === '0x' ? 0n : BigInt(rj.returnHex));
    }
    expect(decoded[1]).toBe(9006n); // receiver read (9) BEFORE bump: the opposite order, per solc
    expect(decoded[2]).toBe(1n);
  });
});
