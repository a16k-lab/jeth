// Tier-3 Batch-1 lifts from docs/OR-CATALOGUE.md, each verified byte-identical to solc 0.8.35:
// L9    ref-element array literal (let m: Arr<u256[],2> = [a, b]): buildNestedMemArrayValue's tail
//       now routes through aggArgToMemPtr - a MEMORY element ALIASES (pointer, mutations visible),
//       a CALLDATA/STORAGE element DEEP-COPIES. Plus the solc PARITY GATE: literal elements mixing
//       calldata and storage locations reject ("Unable to deduce common type"), everything else
//       (cd|cd, cd|mem, mem|st, st|st) unifies - probed at 0.8.35.
// L2-a  both-literal ternary encode (abi.encode(c ? [In(1n,2n)] : [In(3n,4n)])): the ternary checker
//       self-types the literals from INTRINSIC-typed elements (struct ctors); bare int/bool literal
//       elements are refused (solc's mobile-type rule would diverge from u256).
// L2-b  bytes-typed member on a struct ternary ((c ? a : b).t): the access-chain desugar's final-type
//       gate widened to isBytesLike (a bytes value ternary is fully supported).
// L2-c  ternary-chain LVALUE ((c ? this.A : this.B2)[i].y = v): desugared to tmp = v; if (c)
//       { A-chain = tmp } else { B-chain = tmp } - solc's exact order (RHS, cond, index once on the
//       selected target), reusing the full assignment machinery per branch. Side-effect-count parity
//       proven with a shared counter in both the index and the RHS.
// L6    RECLASSIFIED DELIBERATE (not lifted): o[0n] = this.psv[0n].vals on an inline value-word
//       element. The prior-alias witness (let r = o[0n]; o[0n] = <storage>; r keeps the OLD values in
//       solc via re-point, but would see the NEW values under JETH's inline copy) proves NO RHS
//       source is liftable - solc re-points where a flat layout can only copy.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const run = async (J: string, S: string, calls: ReadonlyArray<readonly [string, string]>) => {
  const h = await Harness.create();
  await h.fund(me, 10n ** 20n);
  const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
  const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
  for (const [sg, args] of calls) {
    const jr = await h.call(ja, sel(sg) + args);
    const sr = await h.call(sa, sel(sg) + args);
    expect(jr.returnHex, `${sg} ${args.slice(0, 12)}`).toBe(sr.returnHex);
    expect(jr.success, sg).toBe(sr.success);
  }
};
const rejects = (src: string): boolean => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
};

describe('Tier-3 Batch-1 lifts byte-identical to solc 0.8.35', () => {
  it('L9: ref-element array literals (cd copy, storage copy, legal mixes, memory alias) + parity gate', async () => {
    const J = `class C {
  s1: u256[]; s2: u256[];
  seed(): External<void> { this.s1.push(71n); this.s1.push(72n); this.s2.push(81n); }
  get f(a: u256[], b: u256[]): External<u256> { let m: Arr<u256[],2> = [a, b]; return m[0n][1n] + m[1n][0n]; }
  get fr(a: u256[], b: u256[]): External<Arr<u256[],2>> { let m: Arr<u256[],2> = [a, b]; return m; }
  get fst(): External<u256> { let m: Arr<u256[],2> = [this.s1, this.s2]; return m[0n][1n] + m[1n][0n]; }
  get fcm(a: u256[]): External<u256> { let x: u256[] = [5n,6n]; let m: Arr<u256[],2> = [a, x]; return m[0n][0n] + m[1n][1n]; }
  get fms(): External<u256> { let x: u256[] = [5n]; let m: Arr<u256[],2> = [x, this.s1]; return m[0n][0n] + m[1n][0n]; }
  get ali(): External<u256> { let x: u256[] = [1n,2n]; let m: Arr<u256[],2> = [x, x]; m[0n][0n] = 9n; return x[0n] + m[1n][0n]; } }`;
    const S = `contract C {
  uint256[] s1; uint256[] s2;
  function seed() external { s1.push(71); s1.push(72); s2.push(81); }
  function f(uint256[] calldata a, uint256[] calldata b) external pure returns(uint256){ uint256[][2] memory m = [a, b]; return m[0][1] + m[1][0]; }
  function fr(uint256[] calldata a, uint256[] calldata b) external pure returns(uint256[][2] memory){ uint256[][2] memory m = [a, b]; return m; }
  function fst() external view returns(uint256){ uint256[][2] memory m = [s1, s2]; return m[0][1] + m[1][0]; }
  function fcm(uint256[] calldata a) external pure returns(uint256){ uint256[] memory x = new uint256[](2); x[0]=5;x[1]=6; uint256[][2] memory m = [a, x]; return m[0][0] + m[1][1]; }
  function fms() external view returns(uint256){ uint256[] memory x = new uint256[](1); x[0]=5; uint256[][2] memory m = [x, s1]; return m[0][0] + m[1][0]; }
  function ali() external pure returns(uint256){ uint256[] memory x = new uint256[](2); x[0]=1;x[1]=2; uint256[][2] memory m = [x, x]; m[0][0] = 9; return x[0] + m[1][0]; } }`;
    const two = (x: number[], y: number[]) => {
      const ax = W(x.length) + x.map(W).join('');
      const ay = W(y.length) + y.map(W).join('');
      return W(0x40) + W(0x40 + 32 * (1 + x.length)) + ax + ay;
    };
    const one = (x: number[]) => W(0x20) + W(x.length) + x.map(W).join('');
    await run(J, S, [
      ['seed()', ''], ['f(uint256[],uint256[])', two([11, 12], [13, 14])],
      ['fr(uint256[],uint256[])', two([21, 22], [23])], ['fst()', ''],
      ['fcm(uint256[])', one([41, 42])], ['fms()', ''], ['ali()', ''],
    ] as const);
    // the solc parity gate: calldata + storage elements cannot unify.
    expect(rejects(`class C { s1: u256[]; get f(a: u256[]): External<u256> { let m: Arr<u256[],2> = [a, this.s1]; return m[0n][0n]; } }`)).toBe(true);
  });

  it('L2 residuals: lit|lit ternary encode, bytes-member ternary, ternary-chain lvalue', async () => {
    const D = `type In = { x: u256; y: u256 };`;
    const SD = `struct In { uint256 x; uint256 y; }`;
    const J = `${D} type B = { t: bytes; n: u256 };
class C {
  A: Arr<In,2>; B2: Arr<In,2>; hits: u256;
  seed(): External<void> { this.A[0n]=In(1n,2n); this.A[1n]=In(3n,4n); this.B2[0n]=In(5n,6n); this.B2[1n]=In(7n,8n); }
  bump(): u256 { this.hits = this.hits + 1n; return 1n; }
  get litlit(c: bool): External<bytes> { return abi.encode(c ? [In(1n,2n)] : [In(3n,4n)]); }
  get litlit2(c: bool): External<bytes> { return abi.encode(c ? [In(1n,2n),In(3n,4n)] : [In(5n,6n),In(7n,8n)]); }
  get bmem(c: bool): External<bytes> { let a: B = B(bytes("aa"), 1n); let b: B = B(bytes("bbbb"), 2n); return (c ? a : b).t; }
  lv(c: bool, i: u256, v: u256): External<void> { (c ? this.A : this.B2)[i].y = v; }
  lvEff(c: bool): External<u256> { (c ? this.A : this.B2)[this.bump()].y = this.bump(); return this.hits; }
  get g(): External<u256> { return this.A[1n].y + 1000n*this.B2[1n].y + 1000000n*this.A[1n].x; } }`;
    const S = `${SD} struct B { bytes t; uint256 n; }
contract C {
  In[2] A; In[2] B2; uint256 hits;
  function seed() external { A[0]=In(1,2); A[1]=In(3,4); B2[0]=In(5,6); B2[1]=In(7,8); }
  function bump() internal returns(uint256){ hits = hits + 1; return 1; }
  function litlit(bool c) external pure returns(bytes memory){ return abi.encode(c ? [In(1,2)] : [In(3,4)]); }
  function litlit2(bool c) external pure returns(bytes memory){ return abi.encode(c ? [In(1,2),In(3,4)] : [In(5,6),In(7,8)]); }
  function bmem(bool c) external pure returns(bytes memory){ B memory a = B("aa", 1); B memory b = B("bbbb", 2); return (c ? a : b).t; }
  function lv(bool c, uint256 i, uint256 v) external { (c ? A : B2)[i].y = v; }
  function lvEff(bool c) external returns(uint256){ (c ? A : B2)[bump()].y = bump(); return hits; }
  function g() external view returns(uint256){ return A[1].y + 1000*B2[1].y + 1000000*A[1].x; } }`;
    await run(J, S, [
      ['seed()', ''], ['litlit(bool)', W(1)], ['litlit(bool)', W(0)], ['litlit2(bool)', W(1)], ['litlit2(bool)', W(0)],
      ['bmem(bool)', W(1)], ['bmem(bool)', W(0)],
      ['lv(bool,uint256,uint256)', W(1) + W(1) + W(77)], ['g()', ''],
      ['lv(bool,uint256,uint256)', W(0) + W(1) + W(88)], ['g()', ''],
      ['lv(bool,uint256,uint256)', W(1) + W(9) + W(1)], // OOB parity
      ['lvEff(bool)', W(1)], ['g()', ''],
    ] as const);
    // bare-int-literal elements now self-type to the mobile common type (L2-MOBILE lifted, OR cluster 4):
    // all-nonneg -> u256, byte-identical to solc's uint8[2] (abi.encode pads every element to a 32-byte
    // word regardless of width, so the encoding is width-independent). The ternary of two bare-literal
    // arrays likewise compiles and is byte-identical (verified per branch).
    expect(rejects(`class C { get f(c: bool): External<bytes> { return abi.encode(c ? [1n,2n] : [3n,4n]); } }`)).toBe(false);
  });

  it('L6 stays a deliberate reject: the prior-alias witness makes any lift a miscompile', () => {
    expect(rejects(`class C { psv: Arr<u256,2>; get w(): External<u256> { let o: Arr<u256,2>[] = [[1n,2n]]; let r: Arr<u256,2> = o[0n]; o[0n] = this.psv; return r[0n]; } }`)).toBe(true);
  });
});
