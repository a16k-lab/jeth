import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

// AREA: evalorder. solc evaluates BINARY operands RIGHT-to-LEFT and argument lists
// LEFT-to-RIGHT. We pack distinct-digit accumulators (s = s*10 + k) so any order
// divergence surfaces in the returndata.
const JETH = `type P = { a: u128; b: u128; };
class C {
  seq: u256;
  si: i256;
  arr: u256[];
  p: P;
  Ev3: event<{ x: u256; y: u256; z: u256 }>;
  Ev4: event<{ a: u256; b: u256; c: u256; d: u256 }>;
  Er2: error<{ x: u256; y: u256 }>;
  Er3: error<{ x: u256; y: u256; z: u256 }>;

  // ---- binary operand order: RIGHT before LEFT ----
  // subtraction: distinct accumulator, left side mutated by right
  get subOrder(): External<u256> { let s: u256 = 0n; let r: u256 = (s = s * 10n + 1n) - (s = s * 10n + 2n) + 100n; return s * 1000n + r; }
  get subOrder2(): External<u256> { unchecked: { let s: u256 = 0n; let r: u256 = (s = s * 10n + 3n) - (s = s * 10n + 7n); return s * 1000n + r; } }
  get divOrder(): External<u256> { let s: u256 = 0n; let r: u256 = (s = s * 10n + 8n) / (s = s * 10n + 2n); return s * 1000n + r; }
  get modOrder(): External<u256> { let s: u256 = 0n; let r: u256 = (s = s * 10n + 9n) % (s = s * 10n + 4n); return s * 1000n + r; }
  get mulOrder(): External<u256> { let s: u256 = 0n; let r: u256 = (s = s * 10n + 3n) * (s = s * 10n + 5n); return s * 1000n + r; }
  // ++ prefix vs postfix mixed in operands
  get incBin(): External<u256> { let x: u256 = 5n; let y: u256 = (++x) * 100n + (++x); return x * 100000n + y; }
  get postBin(): External<u256> { let x: u256 = 5n; let y: u256 = (x++) * 100n + (x++); return x * 100000n + y; }
  get mixBin(): External<u256> { let x: u256 = 5n; let y: u256 = (x++) * 100n + (++x); return x * 100000n + y; }
  get postSub(): External<u256> { unchecked: { let x: u256 = 9n; let y: u256 = (x--) - (x--); return x * 100n + y; } }
  // compound-assign yields in operands
  get compBin(a: u256): External<u256> { let x: u256 = a; x += 5n; let y: u256 = (x *= 2n) - (x -= 3n); return x * 1000n + y; }
  get leftMutRightRead(v: u256): External<u256> { let x: u256 = 0n; let r: u256 = (x = v) + x; return r; }
  get rightMutLeftRead(v: u256): External<u256> { let x: u256 = 0n; let r: u256 = x + (x = v); return r; }

  // ---- nested binary trees: 3 distinct digits, mutating accumulator ----
  get tree3(): External<u256> { let x: u256 = 0n; let r: u256 = (++x) * 100n + (++x) * 10n + (++x); return x * 100000n + r; }
  get tree3post(): External<u256> { let x: u256 = 0n; let r: u256 = (x++) * 100n + (x++) * 10n + (x++); return x * 100000n + r; }
  get treeSub(): External<u256> { unchecked: { let x: u256 = 100n; let r: u256 = (x--) - (x--) - (x--); return x * 100000n + r; } }
  get treeMixed(): External<u256> { let x: u256 = 0n; let r: u256 = ((++x) + (++x)) * ((++x) + (++x)); return x * 100000n + r; }
  get treeDeep(): External<u256> { let s: u256 = 0n; let r: u256 = (((s = s * 10n + 1n) + (s = s * 10n + 2n)) - (s = s * 10n + 3n)) + ((s = s * 10n + 4n) - (s = s * 10n + 5n)); return s * 1000000n + r; }

  // ---- comparison operand order ----
  get cmpOrder(v: u256): External<u256> { let s: u256 = 0n; let b: bool = (s = s * 10n + 1n) < (s = s * 10n + 2n); return s * 10n + (b ? 1n : 0n); }
  get cmpEq(v: u256): External<u256> { let s: u256 = 0n; let b: bool = (s = s * 10n + 4n) == (s = s * 10n + 4n); return s * 10n + (b ? 1n : 0n); }

  // ---- argument lists: LEFT to RIGHT ----
  get arrLit(): External<u256> { let s: u256 = 0n; let xs: u256[] = [(s = s * 10n + 1n), (s = s * 10n + 2n), (s = s * 10n + 3n)]; return s * 1000n + xs[0n] * 100n + xs[1n] * 10n + xs[2n]; }
  get retTuple(): External<[u256, u256, u256]> { let s: u256 = 0n; return [(s = s * 10n + 1n), (s = s * 10n + 2n), s]; }
  get internalArgs(): External<u256> { let s: u256 = 0n; return this.sub3((s = s * 10n + 1n), (s = s * 10n + 2n), (s = s * 10n + 3n)) * 10000n + s; }
  sub3(a: u256, b: u256, c: u256): u256 { return a * 100n + b * 10n + c; }
  get incArgs(): External<u256> { let x: u256 = 0n; return this.sub3((++x), (++x), (++x)) * 10n + x; }
  get postArgs(): External<u256> { let x: u256 = 0n; return this.sub3((x++), (x++), (x++)) * 10n + x; }
  get nestedCallArgs(): External<u256> { let s: u256 = 0n; return this.sub3(this.sub3((s = s*10n+1n),(s = s*10n+2n),(s = s*10n+3n)), (s = s*10n+4n), (s = s*10n+5n)) % 1000000n; }

  // ---- ternary branches with side effects (only chosen branch runs) ----
  get ternTrue(): External<u256> { let s: u256 = 0n; let cond: bool = true; let r: u256 = cond ? (s = s * 10n + 1n) : (s = s * 10n + 2n); return s * 10n + r; }
  get ternFalse(): External<u256> { let s: u256 = 0n; let cond: bool = false; let r: u256 = cond ? (s = s * 10n + 1n) : (s = s * 10n + 2n); return s * 10n + r; }
  get ternCondSide(v: u256): External<u256> { let s: u256 = 0n; let r: u256 = ((s = s * 10n + 9n) > 0n) ? (s = s * 10n + 1n) : (s = s * 10n + 2n); return s * 10n + r; }
  get ternNested(c: bool): External<u256> { let x: u256 = 0n; let r: u256 = c ? ((++x) * 10n + (++x)) : ((x += 5n) * 10n + (x += 5n)); return x * 1000n + r; }

  // ---- assignment-expression LHS = state var ----
  setSeqOrd(): External<u256> { this.seq = 0n; let r: u256 = (this.seq = this.seq * 10n + 1n) - (this.seq = this.seq * 10n + 2n) + 1000n; return this.seq * 10000n + r; }
  setSeqArgs(): External<u256> { this.seq = 0n; emit(Ev3((this.seq = this.seq * 10n + 1n), (this.seq = this.seq * 10n + 2n), (this.seq = this.seq * 10n + 3n))); return this.seq; }
  setSeqBinRtoL(): External<u256> { this.seq = 0n; let r: u256 = (this.seq = this.seq * 10n + 1n) + (this.seq = this.seq * 10n + 2n) * 100n; return this.seq * 100000n + r; }

  // ---- assignment-expression LHS = array element ----
  arrElemOrd(): External<u256> { this.arr = [0n, 0n]; let r: u256 = (this.arr[0n] = 3n) - (this.arr[1n] = 7n) + 1000n; return this.arr[0n] * 10000n + this.arr[1n] * 100n + r; }
  arrElemSide(): External<u256> { this.arr = [0n, 0n, 0n]; let s: u256 = 0n; this.arr[0n] = (s = s * 10n + 1n); this.arr[1n] = (s = s * 10n + 2n); let r: u256 = (this.arr[(s = s * 10n + 0n) % 3n]); return s * 10n + r; }

  // ---- assignment-expression LHS = packed struct field ----
  packFieldOrd(): External<u256> { this.p = P(0n, 0n); let r: u256 = (this.p.a = 3n) + (this.p.b = 7n) * 100n; return r; }
  packFieldBin(): External<u256> { this.p = P(0n, 0n); unchecked: { let r: u256 = u256((this.p.a = 9n)) - u256((this.p.b = 4n)); return r; } }

  // ---- chained assignment x = y = a ----
  get chainOrd(a: u256): External<u256> { let x: u256 = 0n; let y: u256 = 0n; let z: u256 = 0n; x = y = z = a; return x * 1000000n + y * 1000n + z; }
  get chainSide(): External<u256> { let x: u256 = 0n; let s: u256 = 0n; x = (s = s * 10n + 1n); let y: u256 = x + (s = s * 10n + 2n); return s * 1000n + y; }

  // ---- signed / narrow-type yields in operands ----
  get signedSub(a: i64, b: i64): External<i256> { let x: i64 = 0n; let r: i256 = i256(x = a) - i256(x = b); return r; }
  get narrowOrd(a: u8, b: u8): External<u256> { let x: u8 = 0n; let r: u256 = u256(x = a) * 1000n + u256(x = b); return u256(x) * 1000000n + r; }
  get signedDiv(a: i64, b: i64): External<i256> { let x: i64 = 0n; let r: i256 = i256(x = a) / i256(x = b); return r; }

  // ---- require / revert / error arg eager left-to-right eval ----
  get reqArgsOrd(cond: bool): External<u256> { let s: u256 = 0n; require(cond, Er2((s = s * 10n + 1n), (s = s * 10n + 2n))); return s; }
  get revertArgsOrd(): External<u256> { let s: u256 = 0n; revert(Er3((s = s * 10n + 1n), (s = s * 10n + 2n), (s = s * 10n + 3n))); }
  emitOrd4(): External<u256> { let s: u256 = 0n; emit(Ev4((s=s*10n+1n),(s=s*10n+2n),(s=s*10n+3n),(s=s*10n+4n))); return s; }

  // ---- side effect in array index expression ----
  get idxSide(): External<u256> { let s: u256 = 0n; let xs: u256[] = [10n, 20n, 30n]; let r: u256 = xs[(s = s * 10n + 1n) % 3n] + xs[(s = s * 10n + 2n) % 3n]; return s * 1000n + r; }

  // ---- assignment value used by subsequent operand (read-after-write within expr) ----
  get raw(v: u256): External<u256> { let x: u256 = 0n; let r: u256 = (x = v) * 100n + x * 10n + (x = x + 1n); return r; }
  get rawRight(v: u256): External<u256> { let x: u256 = 0n; let r: u256 = (x = x + 1n) + x * 10n + (x = v) * 100n; return r; }

  // helper for reading state
  get getSeq(): External<u256> { return this.seq; }
  get getArr(i: u256): External<u256> { return this.arr[i]; }
  get getPA(): External<u128> { return this.p.a; }
  get getPB(): External<u128> { return this.p.b; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256 seq;
  int256 si;
  uint256[] arr;
  struct P { uint128 a; uint128 b; }
  P p;
  event Ev3(uint256 x, uint256 y, uint256 z);
  event Ev4(uint256 a, uint256 b, uint256 c, uint256 d);
  error Er2(uint256 x, uint256 y);
  error Er3(uint256 x, uint256 y, uint256 z);

  function subOrder() external pure returns (uint256){ uint256 s = 0; uint256 r = (s = s * 10 + 1) - (s = s * 10 + 2) + 100; return s * 1000 + r; }
  function subOrder2() external pure returns (uint256){ unchecked { uint256 s = 0; uint256 r = (s = s * 10 + 3) - (s = s * 10 + 7); return s * 1000 + r; } }
  function divOrder() external pure returns (uint256){ uint256 s = 0; uint256 r = (s = s * 10 + 8) / (s = s * 10 + 2); return s * 1000 + r; }
  function modOrder() external pure returns (uint256){ uint256 s = 0; uint256 r = (s = s * 10 + 9) % (s = s * 10 + 4); return s * 1000 + r; }
  function mulOrder() external pure returns (uint256){ uint256 s = 0; uint256 r = (s = s * 10 + 3) * (s = s * 10 + 5); return s * 1000 + r; }
  function incBin() external pure returns (uint256){ uint256 x = 5; uint256 y = (++x) * 100 + (++x); return x * 100000 + y; }
  function postBin() external pure returns (uint256){ uint256 x = 5; uint256 y = (x++) * 100 + (x++); return x * 100000 + y; }
  function mixBin() external pure returns (uint256){ uint256 x = 5; uint256 y = (x++) * 100 + (++x); return x * 100000 + y; }
  function postSub() external pure returns (uint256){ unchecked { uint256 x = 9; uint256 y = (x--) - (x--); return x * 100 + y; } }
  function compBin(uint256 a) external pure returns (uint256){ uint256 x = a; x += 5; uint256 y = (x *= 2) - (x -= 3); return x * 1000 + y; }
  function leftMutRightRead(uint256 v) external pure returns (uint256){ uint256 x = 0; uint256 r = (x = v) + x; return r; }
  function rightMutLeftRead(uint256 v) external pure returns (uint256){ uint256 x = 0; uint256 r = x + (x = v); return r; }

  function tree3() external pure returns (uint256){ uint256 x = 0; uint256 r = (++x) * 100 + (++x) * 10 + (++x); return x * 100000 + r; }
  function tree3post() external pure returns (uint256){ uint256 x = 0; uint256 r = (x++) * 100 + (x++) * 10 + (x++); return x * 100000 + r; }
  function treeSub() external pure returns (uint256){ unchecked { uint256 x = 100; uint256 r = (x--) - (x--) - (x--); return x * 100000 + r; } }
  function treeMixed() external pure returns (uint256){ uint256 x = 0; uint256 r = ((++x) + (++x)) * ((++x) + (++x)); return x * 100000 + r; }
  function treeDeep() external pure returns (uint256){ uint256 s = 0; uint256 r = (((s = s * 10 + 1) + (s = s * 10 + 2)) - (s = s * 10 + 3)) + ((s = s * 10 + 4) - (s = s * 10 + 5)); return s * 1000000 + r; }

  function cmpOrder(uint256 v) external pure returns (uint256){ uint256 s = 0; bool b = (s = s * 10 + 1) < (s = s * 10 + 2); return s * 10 + (b ? 1 : 0); }
  function cmpEq(uint256 v) external pure returns (uint256){ uint256 s = 0; bool b = (s = s * 10 + 4) == (s = s * 10 + 4); return s * 10 + (b ? 1 : 0); }

  function arrLit() external pure returns (uint256){ uint256 s = 0; uint256[3] memory xs = [(s = s * 10 + 1), (s = s * 10 + 2), (s = s * 10 + 3)]; return s * 1000 + xs[0] * 100 + xs[1] * 10 + xs[2]; }
  function retTuple() external pure returns (uint256, uint256, uint256){ uint256 s = 0; return ((s = s * 10 + 1), (s = s * 10 + 2), s); }
  function internalArgs() external pure returns (uint256){ uint256 s = 0; return sub3((s = s * 10 + 1), (s = s * 10 + 2), (s = s * 10 + 3)) * 10000 + s; }
  function sub3(uint256 a, uint256 b, uint256 c) internal pure returns (uint256){ return a * 100 + b * 10 + c; }
  function incArgs() external pure returns (uint256){ uint256 x = 0; return sub3((++x), (++x), (++x)) * 10 + x; }
  function postArgs() external pure returns (uint256){ uint256 x = 0; return sub3((x++), (x++), (x++)) * 10 + x; }
  function nestedCallArgs() external pure returns (uint256){ uint256 s = 0; return sub3(sub3((s = s*10+1),(s = s*10+2),(s = s*10+3)), (s = s*10+4), (s = s*10+5)) % 1000000; }

  function ternTrue() external pure returns (uint256){ uint256 s = 0; bool cond = true; uint256 r = cond ? (s = s * 10 + 1) : (s = s * 10 + 2); return s * 10 + r; }
  function ternFalse() external pure returns (uint256){ uint256 s = 0; bool cond = false; uint256 r = cond ? (s = s * 10 + 1) : (s = s * 10 + 2); return s * 10 + r; }
  function ternCondSide(uint256 v) external pure returns (uint256){ uint256 s = 0; uint256 r = ((s = s * 10 + 9) > 0) ? (s = s * 10 + 1) : (s = s * 10 + 2); return s * 10 + r; }
  function ternNested(bool c) external pure returns (uint256){ uint256 x = 0; uint256 r = c ? ((++x) * 10 + (++x)) : ((x += 5) * 10 + (x += 5)); return x * 1000 + r; }

  function setSeqOrd() external returns (uint256){ seq = 0; uint256 r = (seq = seq * 10 + 1) - (seq = seq * 10 + 2) + 1000; return seq * 10000 + r; }
  function setSeqArgs() external returns (uint256){ seq = 0; emit Ev3((seq = seq * 10 + 1), (seq = seq * 10 + 2), (seq = seq * 10 + 3)); return seq; }
  function setSeqBinRtoL() external returns (uint256){ seq = 0; uint256 r = (seq = seq * 10 + 1) + (seq = seq * 10 + 2) * 100; return seq * 100000 + r; }

  function arrElemOrd() external returns (uint256){ arr = [uint256(0), 0]; uint256 r = (arr[0] = 3) - (arr[1] = 7) + 1000; return arr[0] * 10000 + arr[1] * 100 + r; }
  function arrElemSide() external returns (uint256){ arr = [uint256(0), 0, 0]; uint256 s = 0; arr[0] = (s = s * 10 + 1); arr[1] = (s = s * 10 + 2); uint256 r = (arr[(s = s * 10 + 0) % 3]); return s * 10 + r; }

  function packFieldOrd() external returns (uint256){ p = P(0, 0); uint256 r = (p.a = 3) + uint256(p.b = 7) * 100; return r; }
  function packFieldBin() external returns (uint256){ p = P(0, 0); unchecked { uint256 r = uint256(p.a = 9) - uint256(p.b = 4); return r; } }

  function chainOrd(uint256 a) external pure returns (uint256){ uint256 x = 0; uint256 y = 0; uint256 z = 0; x = y = z = a; return x * 1000000 + y * 1000 + z; }
  function chainSide() external pure returns (uint256){ uint256 x = 0; uint256 s = 0; x = (s = s * 10 + 1); uint256 y = x + (s = s * 10 + 2); return s * 1000 + y; }

  function signedSub(int64 a, int64 b) external pure returns (int256){ int64 x = 0; int256 r = int256(x = a) - int256(x = b); return r; }
  function narrowOrd(uint8 a, uint8 b) external pure returns (uint256){ uint8 x = 0; uint256 r = uint256(x = a) * 1000 + uint256(x = b); return uint256(x) * 1000000 + r; }
  function signedDiv(int64 a, int64 b) external pure returns (int256){ int64 x = 0; int256 r = int256(x = a) / int256(x = b); return r; }

  function reqArgsOrd(bool cond) external pure returns (uint256){ uint256 s = 0; require(cond, Er2((s = s * 10 + 1), (s = s * 10 + 2))); return s; }
  function revertArgsOrd() external pure returns (uint256){ uint256 s = 0; revert Er3((s = s * 10 + 1), (s = s * 10 + 2), (s = s * 10 + 3)); }
  function emitOrd4() external returns (uint256){ uint256 s = 0; emit Ev4((s=s*10+1),(s=s*10+2),(s=s*10+3),(s=s*10+4)); return s; }

  function idxSide() external pure returns (uint256){ uint256 s = 0; uint256[3] memory xs = [uint256(10), 20, 30]; uint256 r = xs[(s = s * 10 + 1) % 3] + xs[(s = s * 10 + 2) % 3]; return s * 1000 + r; }

  function raw(uint256 v) external pure returns (uint256){ uint256 x = 0; uint256 r = (x = v) * 100 + x * 10 + (x = x + 1); return r; }
  function rawRight(uint256 v) external pure returns (uint256){ uint256 x = 0; uint256 r = (x = x + 1) + x * 10 + (x = v) * 100; return r; }

  function getSeq() external view returns (uint256){ return seq; }
  function getArr(uint256 i) external view returns (uint256){ return arr[i]; }
  function getPA() external view returns (uint128){ return p.a; }
  function getPB() external view returns (uint128){ return p.b; }
}`;

describe('probe', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(
        label +
          ': jeth{ok=' +
          j.success +
          ',ret=' +
          j.returnHex +
          ',err=' +
          j.exceptionError +
          '} sol{ok=' +
          s.success +
          ',ret=' +
          s.returnHex +
          '}',
      );
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('runs', async () => {
    // binary operand order
    for (const n of [
      'subOrder',
      'subOrder2',
      'divOrder',
      'modOrder',
      'mulOrder',
      'incBin',
      'postBin',
      'mixBin',
      'postSub',
    ])
      await eq(n, encodeCall(sel(n + '()'), []));
    for (const v of [0n, 1n, 3n, 7n, 99n, M - 1n]) {
      await eq(`compBin(${v})`, encodeCall(sel('compBin(uint256)'), [v]));
      await eq(`leftMutRightRead(${v})`, encodeCall(sel('leftMutRightRead(uint256)'), [v]));
      await eq(`rightMutLeftRead(${v})`, encodeCall(sel('rightMutLeftRead(uint256)'), [v]));
      await eq(`raw(${v})`, encodeCall(sel('raw(uint256)'), [v]));
      await eq(`rawRight(${v})`, encodeCall(sel('rawRight(uint256)'), [v]));
    }
    // nested trees
    for (const n of ['tree3', 'tree3post', 'treeSub', 'treeMixed', 'treeDeep'])
      await eq(n, encodeCall(sel(n + '()'), []));
    // comparisons
    await eq('cmpOrder', encodeCall(sel('cmpOrder(uint256)'), [0n]));
    await eq('cmpEq', encodeCall(sel('cmpEq(uint256)'), [0n]));
    // argument lists
    for (const n of [
      'arrLit',
      'retTuple',
      'internalArgs',
      'incArgs',
      'postArgs',
      'nestedCallArgs',
      'idxSide',
      'emitOrd4',
    ])
      await eq(n, encodeCall(sel(n + '()'), []));
    // ternary
    for (const n of ['ternTrue', 'ternFalse']) await eq(n, encodeCall(sel(n + '()'), []));
    await eq('ternCondSide', encodeCall(sel('ternCondSide(uint256)'), [0n]));
    await eq('ternNested(true)', encodeCall(sel('ternNested(bool)'), [1n]));
    await eq('ternNested(false)', encodeCall(sel('ternNested(bool)'), [0n]));
    // state-LHS assignment expressions (stateful, run + read back)
    for (const n of ['setSeqOrd', 'setSeqArgs', 'setSeqBinRtoL']) {
      await eq(n, encodeCall(sel(n + '()'), []));
      await eq(n + '/getSeq', encodeCall(sel('getSeq()'), []));
    }
    // array-element LHS
    await eq('arrElemOrd', encodeCall(sel('arrElemOrd()'), []));
    await eq('arrElemOrd/getArr0', encodeCall(sel('getArr(uint256)'), [0n]));
    await eq('arrElemOrd/getArr1', encodeCall(sel('getArr(uint256)'), [1n]));
    await eq('arrElemSide', encodeCall(sel('arrElemSide()'), []));
    // packed struct field LHS
    await eq('packFieldOrd', encodeCall(sel('packFieldOrd()'), []));
    await eq('packFieldOrd/getPA', encodeCall(sel('getPA()'), []));
    await eq('packFieldOrd/getPB', encodeCall(sel('getPB()'), []));
    await eq('packFieldBin', encodeCall(sel('packFieldBin()'), []));
    // chained
    for (const v of [0n, 5n, 12345n, M - 1n]) await eq(`chainOrd(${v})`, encodeCall(sel('chainOrd(uint256)'), [v]));
    await eq('chainSide', encodeCall(sel('chainSide()'), []));
    // signed / narrow yields
    for (const a of [0n, 1n, -1n, 100n, -100n, (1n << 63n) - 1n, -(1n << 63n)])
      for (const b of [1n, -1n, 7n, -7n, (1n << 63n) - 1n]) {
        await eq(`signedSub(${a},${b})`, encodeCall(sel('signedSub(int64,int64)'), [a, b]));
        await eq(`signedDiv(${a},${b})`, encodeCall(sel('signedDiv(int64,int64)'), [a, b]));
      }
    for (const a of [0n, 1n, 200n, 255n])
      for (const b of [0n, 7n, 128n, 255n])
        await eq(`narrowOrd(${a},${b})`, encodeCall(sel('narrowOrd(uint8,uint8)'), [a, b]));
    // require/revert/error arg order (cond true: no revert; cond false: revert with args)
    await eq('reqArgsOrd(true)', encodeCall(sel('reqArgsOrd(bool)'), [1n]));
    await eq('reqArgsOrd(false)', encodeCall(sel('reqArgsOrd(bool)'), [0n]));
    await eq('revertArgsOrd', encodeCall(sel('revertArgsOrd()'), []));

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
