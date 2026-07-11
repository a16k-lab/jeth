// REGRESSION (coverage-slice companion to ext-call-result-static-struct-array-direct-encode):
// the SAME external-call-result-of-Arr<In,N> pointer-headed transcode, now consumed by the
// STORAGE / EVENTS / ERRORS / GETTERS surfaces rather than a bare abi.encode / call-arg.
//
// emit(E(m)) and revert(Err(m)) both serialize their aggregate argument through the same
// abi-encode path prepEncodeComponent feeds; a getter / mapping-value read of a stored Arr<In,N>
// materializes the pointer-headed image from storage. Every case here asserts the EXACT solc bytes
// with DISTINCT non-zero seeds, so a leaked absolute-pointer word (the fixed miscompile) would fail.
// The whole-aggregate mem->storage store (this.s = m) and push (arr.push(m)) are a BOTH-REJECT:
// solc's legacy pipeline cannot copy a memory struct-array to storage (UnimplementedFeatureError),
// JETH rejects with JETH470 - byte-for-byte a clean reject on both sides.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (v: bigint | number) => BigInt(v).toString(16).padStart(64, '0');

let h: Harness;
beforeAll(async () => {
  h = await Harness.create();
});

function tryCompileJeth(src: string): { ok: boolean; codes: string[]; bc?: string } {
  try {
    return { ok: true, codes: [], bc: compile(src, { fileName: 'C.jeth' }).creationBytecode };
  } catch (e: any) {
    return { ok: false, codes: (e?.diagnostics ?? []).map((d: any) => d.code) };
  }
}
function tryCompileSol(src: string): { ok: boolean; creation?: string } {
  try {
    return { ok: true, creation: compileSolidity(SPDX + src, 'C').creation };
  } catch {
    return { ok: false };
  }
}
async function pair(jeth: string, sol: string) {
  const aj = await h.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { aj, as };
}
async function callOne(addr: Address, sig: string, cd: string) {
  try {
    const r = await h.call(addr, '0x' + sel(sig) + cd, {});
    return { s: r.success, r: r.returnHex, logs: (r.logs ?? []).map((l: any) => ({ t: l.topics, d: l.data })) };
  } catch {
    return { s: false, r: 'THROW', logs: [] };
  }
}
async function expectSame(a: { aj: Address; as: Address }, sig: string, cd = '') {
  const j = await callOne(a.aj, sig, cd);
  const s = await callOne(a.as, sig, cd);
  expect({ success: j.s, ret: j.r, logs: j.logs }).toEqual({ success: s.s, ret: s.r, logs: s.logs });
  return { j, s };
}

const IN = `type In = { a: u256; b: u256 };`;
const SIN = `struct In { uint256 a; uint256 b; }`;
const SEED = W(11) + W(12) + W(21) + W(22) + W(31) + W(32); // distinct non-zero element data

describe('external-call-result Arr<In,N> through storage / events / errors / getters', () => {
  it('emit(E(m)) bound + emit(E(this.produce())) direct: log data is the flat inline body', async () => {
    const a = await pair(
      `${IN}
       @contract class C {
         @event E(v: Arr<In,3>);
         @external @pure produce(): Arr<In,3> { return [In(11n,12n),In(21n,22n),In(31n,32n)]; }
         @external emitBound(): void { let m: Arr<In,3> = this.produce(); emit(E(m)); }
         @external emitDirect(): void { emit(E(this.produce())); } }`,
      `${SIN}
       contract C {
         event E(In[3] v);
         function produce() external pure returns (In[3] memory) { return [In(11,12),In(21,22),In(31,32)]; }
         function emitBound() external { In[3] memory m = this.produce(); emit E(m); }
         function emitDirect() external { emit E(this.produce()); } }`,
    );
    const { j: jB } = await expectSame(a, 'emitBound()');
    // one non-anonymous event -> one log; data is the flat 6-word body (NO leaked pointers).
    expect(jB.logs.map((l) => l.d)).toEqual(['0x' + SEED]);
    const { j: jD } = await expectSame(a, 'emitDirect()');
    expect(jD.logs.map((l) => l.d)).toEqual(['0x' + SEED]);
  });

  it('emit(E(indexed k, this.produce())): indexed topic + flat data body', async () => {
    const a = await pair(
      `${IN}
       @contract class C {
         @event E(@indexed k: u256, v: Arr<In,3>);
         @external @pure produce(): Arr<In,3> { return [In(11n,12n),In(21n,22n),In(31n,32n)]; }
         @external emitDirect(): void { emit(E(7n, this.produce())); } }`,
      `${SIN}
       contract C {
         event E(uint256 indexed k, In[3] v);
         function produce() external pure returns (In[3] memory) { return [In(11,12),In(21,22),In(31,32)]; }
         function emitDirect() external { emit E(7, this.produce()); } }`,
    );
    const { j } = await expectSame(a, 'emitDirect()');
    expect(j.logs.map((l) => l.d)).toEqual(['0x' + SEED]);
  });

  it('revert(Err(m)) bound + revert(Err(this.produce())) direct: revert data is selector + flat body', async () => {
    const a = await pair(
      `${IN}
       @contract class C {
         @error Bad(v: Arr<In,3>);
         @external @pure produce(): Arr<In,3> { return [In(11n,12n),In(21n,22n),In(31n,32n)]; }
         @external revBound(): void { let m: Arr<In,3> = this.produce(); revert(Bad(m)); }
         @external revDirect(): void { revert(Bad(this.produce())); } }`,
      `${SIN}
       contract C {
         error Bad(In[3] v);
         function produce() external pure returns (In[3] memory) { return [In(11,12),In(21,22),In(31,32)]; }
         function revBound() external { In[3] memory m = this.produce(); revert Bad(m); }
         function revDirect() external { revert Bad(this.produce()); } }`,
    );
    // Bad(In[3]) selector then the flat 6-word body, both revert.
    const badSel = sel('Bad((uint256,uint256)[3])');
    const { j: jB } = await expectSame(a, 'revBound()');
    expect(jB.s).toBe(false);
    expect(jB.r).toBe('0x' + badSel + SEED);
    const { j: jD } = await expectSame(a, 'revDirect()');
    expect(jD.r).toBe('0x' + badSel + SEED);
  });

  it('@external @view getter of a stored Arr<In,3>: whole + per-element + solc public auto-getter parity', async () => {
    const a = await pair(
      `${IN}
       class C {
         s: Arr<In,3>;
         constructor() { this.s[0n].a = 11n; this.s[0n].b = 12n; this.s[1n].a = 21n; this.s[1n].b = 22n; this.s[2n].a = 31n; this.s[2n].b = 32n; }
         get getArr(): External<Arr<In,3>> { return this.s; }
         get getS(i: u256): External<In> { return this.s[i]; } }`,
      `${SIN}
       contract C {
         In[3] public s;
         constructor() { s[0].a=11; s[0].b=12; s[1].a=21; s[1].b=22; s[2].a=31; s[2].b=32; }
         function getArr() external view returns (In[3] memory) { return s; } }`,
    );
    const { j: jArr } = await expectSame(a, 'getArr()');
    expect(jArr.r).toBe('0x' + SEED);
    // JETH getS(i) == solc public auto-getter s(i) (element tuple), all 3 indices.
    for (const [i, ea, eb] of [[0, 11, 12], [1, 21, 22], [2, 31, 32]] as const) {
      const arg = W(i);
      const jr = await callOne(a.aj, 'getS(uint256)', arg);
      const sr = await callOne(a.as, 's(uint256)', arg);
      expect(jr.r).toBe(sr.r);
      expect(jr.r).toBe('0x' + W(ea) + W(eb));
    }
  });

  it('mapping<u256, Arr<In,3>> value read: whole + per-element are byte-identical', async () => {
    const a = await pair(
      `${IN}
       class C {
         m: mapping<u256, Arr<In,3>>;
         constructor() { this.m[5n][0n].a = 11n; this.m[5n][0n].b = 12n; this.m[5n][1n].a = 21n; this.m[5n][1n].b = 22n; this.m[5n][2n].a = 31n; this.m[5n][2n].b = 32n; }
         get readMap(k: u256): External<Arr<In,3>> { return this.m[k]; }
         get readElem(k: u256, i: u256): External<u256> { return this.m[k][i].b; } }`,
      `${SIN}
       contract C {
         mapping(uint256 => In[3]) m;
         constructor() { m[5][0].a=11; m[5][0].b=12; m[5][1].a=21; m[5][1].b=22; m[5][2].a=31; m[5][2].b=32; }
         function readMap(uint256 k) external view returns (In[3] memory) { return m[k]; }
         function readElem(uint256 k, uint256 i) external view returns (uint256) { return m[k][i].b; } }`,
    );
    const { j: jMap } = await expectSame(a, 'readMap(uint256)', W(5));
    expect(jMap.r).toBe('0x' + SEED);
    const { j: jElem } = await expectSame(a, 'readElem(uint256,uint256)', W(5) + W(2));
    expect(jElem.r).toBe('0x' + W(32)); // m[5][2].b
  });

  it('whole-aggregate mem->storage store (this.s = this.produce()) is a BOTH-REJECT (JETH470 / solc legacy Unimplemented)', () => {
    const J = `${IN}
       class C {
         s: Arr<In,3>;
         get produce(): External<Arr<In,3>> { return [In(11n,12n),In(21n,22n),In(31n,32n)]; }
         setAll(): External<void> { this.s = this.produce(); } }`;
    const S = `${SIN}
       contract C {
         In[3] s;
         function produce() external pure returns (In[3] memory) { return [In(11,12),In(21,22),In(31,32)]; }
         function setAll() external { s = this.produce(); } }`;
    const cj = tryCompileJeth(J);
    const cs = tryCompileSol(S);
    expect(cj.ok).toBe(false);
    expect(cj.codes).toContain('JETH470');
    expect(cs.ok).toBe(false);
  });

  it('whole struct-array push (arr.push(this.produce())) is a BOTH-REJECT (JETH470 / solc legacy Unimplemented)', () => {
    const J = `${IN}
       class C {
         arr: Arr<In,3>[];
         get produce(): External<Arr<In,3>> { return [In(11n,12n),In(21n,22n),In(31n,32n)]; }
         pushIt(): External<void> { this.arr.push(this.produce()); } }`;
    const S = `${SIN}
       contract C {
         In[3][] arr;
         function produce() external pure returns (In[3] memory) { return [In(11,12),In(21,22),In(31,32)]; }
         function pushIt() external { arr.push(this.produce()); } }`;
    const cj = tryCompileJeth(J);
    const cs = tryCompileSol(S);
    expect(cj.ok).toBe(false);
    expect(cj.codes).toContain('JETH470');
    expect(cs.ok).toBe(false);
  });
});
