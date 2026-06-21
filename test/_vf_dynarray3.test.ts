// _vf_dynarray3: third adversarial batch. self-copy aliasing this.a=this.a,
// signed arrays i256[]/i128[] whole-return sign-extension, packed u16[] (16/slot),
// bytes32[] whole return, mapping<K, u256[][]> nested, u256[] as a struct field,
// Arr<string,N> / Arr<bytes,N> fixed-of-dynamic-element. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const MAX = M - 1n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

function encIStr(sig: string, i: bigint, s: string): string {
  const b = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(b.length / 32);
  let data = '';
  for (let w = 0; w < nwords; w++) data += Buffer.concat([b.subarray(w * 32, w * 32 + 32), Buffer.alloc(32)]).subarray(0, 32).toString('hex');
  return '0x' + sel(sig) + pad(i) + pad(0x40n) + pad(BigInt(b.length)) + data;
}

const JETH = `@struct class S { xs: u256[]; n: u256; }
@contract class C {
  @state a: u256[];
  @state si: i256[];
  @state si8: i128[];
  @state w16: u16[];
  @state b32: bytes32[];
  @state mm: mapping<u256, u256[][]>;
  @state s: S;
  @state fs: Arr<string, 3>;
  @state fb: Arr<bytes, 2>;

  @external push(v: u256): void { this.a.push(v); }
  @external self(): void { this.a = this.a; }                 // aliasing self-copy (no-op)
  @external @view all(): u256[] { return this.a; }

  @external pushI(v: i256): void { this.si.push(v); }
  @external popI(): void { this.si.pop(); }
  @external @view getI(i: u256): i256 { return this.si[i]; }
  @external @view allI(): i256[] { return this.si; }

  @external pushI8(v: i128): void { this.si8.push(v); }
  @external popI8(): void { this.si8.pop(); }
  @external @view getI8(i: u256): i128 { return this.si8[i]; }
  @external @view allI8(): i128[] { return this.si8; }

  @external pushW(v: u16): void { this.w16.push(v); }
  @external popW(): void { this.w16.pop(); }
  @external @view getW(i: u256): u16 { return this.w16[i]; }
  @external @view allW(): u16[] { return this.w16; }

  @external pushB32(v: bytes32): void { this.b32.push(v); }
  @external @view allB32(): bytes32[] { return this.b32; }

  @external mmPushOuter(k: u256): void { this.mm[k].push(); }
  @external mmPushInner(k: u256, i: u256, v: u256): void { this.mm[k][i].push(v); }
  @external @view mmAll(k: u256): u256[][] { return this.mm[k]; }

  @external sPush(v: u256): void { this.s.xs.push(v); }
  @external sSetN(n: u256): void { this.s.n = n; }
  @external @view sAll(): S { return this.s; }

  @external fsSet(i: u256, v: string): void { this.fs[i] = v; }
  @external @view fsAll(): Arr<string, 3> { return this.fs; }
  @external @view fsGet(i: u256): string { return this.fs[i]; }

  @external fbSet(i: u256, v: bytes): void { this.fb[i] = v; }
  @external @view fbAll(): Arr<bytes, 2> { return this.fb; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint256[] xs; uint256 n; }
  uint256[] a; int256[] si; int128[] si8; uint16[] w16; bytes32[] b32;
  mapping(uint256 => uint256[][]) mm; S s; string[3] fs; bytes[2] fb;

  function push(uint256 v) external { a.push(v); }
  function self() external { a = a; }
  function all() external view returns (uint256[] memory){ return a; }

  function pushI(int256 v) external { si.push(v); }
  function popI() external { si.pop(); }
  function getI(uint256 i) external view returns (int256){ return si[i]; }
  function allI() external view returns (int256[] memory){ return si; }

  function pushI8(int128 v) external { si8.push(v); }
  function popI8() external { si8.pop(); }
  function getI8(uint256 i) external view returns (int128){ return si8[i]; }
  function allI8() external view returns (int128[] memory){ return si8; }

  function pushW(uint16 v) external { w16.push(v); }
  function popW() external { w16.pop(); }
  function getW(uint256 i) external view returns (uint16){ return w16[i]; }
  function allW() external view returns (uint16[] memory){ return w16; }

  function pushB32(bytes32 v) external { b32.push(v); }
  function allB32() external view returns (bytes32[] memory){ return b32; }

  function mmPushOuter(uint256 k) external { mm[k].push(); }
  function mmPushInner(uint256 k, uint256 i, uint256 v) external { mm[k][i].push(v); }
  function mmAll(uint256 k) external view returns (uint256[][] memory){ return mm[k]; }

  function sPush(uint256 v) external { s.xs.push(v); }
  function sSetN(uint256 n) external { s.n = n; }
  function sAll() external view returns (S memory){ return s; }

  function fsSet(uint256 i, string calldata v) external { fs[i] = v; }
  function fsAll() external view returns (string[3] memory){ return fs; }
  function fsGet(uint256 i) external view returns (string memory){ return fs[i]; }

  function fbSet(uint256 i, bytes calldata v) external { fb[i] = v; }
  function fbAll() external view returns (bytes[2] memory){ return fb; }
}`;

describe('_vf_dynarray3 probe', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(label + ': jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError + '} sol{ok=' + s.success + ',ret=' + s.returnHex + '}');
  }
  const send = eq;

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    // self-copy aliasing
    for (const v of [1n, 2n, 3n]) await send('push', encodeCall(sel('push(uint256)'), [v]));
    await send('self-copy (no-op)', encodeCall(sel('self()')));
    await eq('all after self-copy', encodeCall(sel('all()')));

    // i256[] sign-extension whole return
    for (const v of [0n, 1n, MAX /*-1*/, (1n << 255n) /*INT_MIN*/, (1n << 255n) - 1n /*INT_MAX*/, M - 100n /*-100*/]) {
      await send('pushI', encodeCall(sel('pushI(int256)'), [v]));
    }
    await eq('allI sign array', encodeCall(sel('allI()')));
    await eq('getI[2]==-1', encodeCall(sel('getI(uint256)'), [2n]));
    await eq('getI[3]==INT_MIN', encodeCall(sel('getI(uint256)'), [3n]));
    await eq('getI OOB', encodeCall(sel('getI(uint256)'), [99n]));
    await send('popI', encodeCall(sel('popI()')));
    await eq('allI after pop', encodeCall(sel('allI()')));

    // i128[] packed (2/slot) sign-extension
    const I128MIN = M - (1n << 127n); // two's-comp of -2^127 in 256-bit
    const I128MAX = (1n << 127n) - 1n;
    for (const v of [0n, 1n, M - 1n /*-1 masked to int128 = -1*/, I128MIN & ((1n << 128n) - 1n), I128MAX, M - 5n]) {
      await send('pushI8', encodeCall(sel('pushI8(int128)'), [v]));
    }
    await eq('allI8 packed sign', encodeCall(sel('allI8()')));
    await eq('getI8[2]', encodeCall(sel('getI8(uint256)'), [2n]));
    await send('popI8 (boundary clear)', encodeCall(sel('popI8()')));
    await eq('allI8 after pop', encodeCall(sel('allI8()')));

    // u16[] packed 16/slot
    for (let i = 0; i < 20; i++) await send('pushW', encodeCall(sel('pushW(uint16)'), [BigInt(1000 + i)]));
    await eq('allW 20 elems (2 slots)', encodeCall(sel('allW()')));
    await eq('getW[15]', encodeCall(sel('getW(uint256)'), [15n]));
    await eq('getW[16]', encodeCall(sel('getW(uint256)'), [16n]));
    await eq('getW OOB', encodeCall(sel('getW(uint256)'), [20n]));
    // dirty high bits for u16 push (solc masks to 16 bits)
    await send('pushW dirty 0x1ffff', '0x' + sel('pushW(uint16)') + pad(0x1ffffn));
    await eq('allW dirty masked', encodeCall(sel('allW()')));
    for (let i = 0; i < 5; i++) await send('popW (cross boundary 21->16)', encodeCall(sel('popW()')));
    await eq('allW after pops', encodeCall(sel('allW()')));
    for (let i = 0; i < 3; i++) await send('regrow W', encodeCall(sel('pushW(uint16)'), [BigInt(9000 + i)]));
    await eq('allW regrow no-stale', encodeCall(sel('allW()')));

    // bytes32[] whole return (left-aligned full word)
    for (const v of [0n, MAX, 0xdeadbeefn << 224n, 1n]) await send('pushB32', encodeCall(sel('pushB32(bytes32)'), [v]));
    await eq('allB32', encodeCall(sel('allB32()')));

    // mapping<u256, u256[][]> nested
    const K = 0x777n;
    await send('mm push outer', encodeCall(sel('mmPushOuter(uint256)'), [K]));
    await send('mm push outer', encodeCall(sel('mmPushOuter(uint256)'), [K]));
    await send('mm[K][0] push', encodeCall(sel('mmPushInner(uint256,uint256,uint256)'), [K, 0n, 11n]));
    await send('mm[K][0] push', encodeCall(sel('mmPushInner(uint256,uint256,uint256)'), [K, 0n, 12n]));
    await send('mm[K][1] push', encodeCall(sel('mmPushInner(uint256,uint256,uint256)'), [K, 1n, 21n]));
    await eq('mmAll[K]', encodeCall(sel('mmAll(uint256)'), [K]));
    await eq('mmAll[empty key]', encodeCall(sel('mmAll(uint256)'), [0x999n]));

    // u256[] as a struct field (S { xs: u256[]; n: u256 })
    await send('s.n = 42', encodeCall(sel('sSetN(uint256)'), [42n]));
    for (const v of [5n, 6n, 7n]) await send('s.xs push', encodeCall(sel('sPush(uint256)'), [v]));
    await eq('sAll (struct w/ dyn field)', encodeCall(sel('sAll()')));

    // Arr<string,3> fixed array of dynamic string elements
    await send('fs[0]=hi', encIStr('fsSet(uint256,string)', 0n, 'hi'));
    const LONG = 'a definitely-longer-than-thirty-two-byte string in a fixed array slot for the test';
    await send('fs[1]=LONG', encIStr('fsSet(uint256,string)', 1n, LONG));
    // fs[2] left empty (default "")
    await eq('fsGet[0]', encodeCall(sel('fsGet(uint256)'), [0n]));
    await eq('fsGet[1] LONG', encodeCall(sel('fsGet(uint256)'), [1n]));
    await eq('fsGet[2] default empty', encodeCall(sel('fsGet(uint256)'), [2n]));
    await eq('fsGet OOB', encodeCall(sel('fsGet(uint256)'), [3n]));
    await eq('fsAll (fixed array of strings)', encodeCall(sel('fsAll()')));
    // overwrite fs[1] LONG with a short -> must clear old data slots
    await send('fs[1]=short overwrite', encIStr('fsSet(uint256,string)', 1n, 'x'));
    await eq('fsAll after shrink overwrite (no stale)', encodeCall(sel('fsAll()')));

    // Arr<bytes,2> fixed array of dynamic bytes
    await send('fb[0]=ab', encIStr('fbSet(uint256,bytes)', 0n, 'ab'));
    await send('fb[1]=LONG', encIStr('fbSet(uint256,bytes)', 1n, LONG));
    await eq('fbAll', encodeCall(sel('fbAll()')));
    await send('fb[1]=short overwrite', encIStr('fbSet(uint256,bytes)', 1n, 'q'));
    await eq('fbAll after shrink overwrite (no stale)', encodeCall(sel('fbAll()')));

    if (mism.length) { process.stderr.write('MISMATCHES ' + mism.length + '/' + count + '\n'); for (const m of mism.slice(0, 40)) process.stderr.write(m + '\n'); }
    else process.stderr.write('ALL3 ' + count + ' byte-identical\n');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });

  // ---- STORAGE array compositions now supported (G6); byte-identical incl. raw slots in
  // test/array-compositions.test.ts. Whole calldata-param / return of these shapes stays gated.
  it('Arr<u256[],N> (uint256[][N]) storage access now compiles (G6)', () => {
    expect(() => compile(`@contract class C { @state a: Arr<u256[], 2>; @external p(i: u256, v: u256): void { this.a[i].push(v); } @view g(i: u256, j: u256): u256 { return this.a[i][j]; } }`, { fileName: 'C.jeth' })).not.toThrow();
    // a whole-array calldata PARAM / return + element access of this shape now compile too
    // (JETH210/151, byte-identical incl. malformed-offset parity in test/calldata-composite-index).
    expect(() => compile(`@contract class C { @external @pure f(a: Arr<u256[], 2>, i: u256, j: u256): u256 { return a[i][j]; } }`, { fileName: 'C.jeth' })).not.toThrow();
  });

  it('Arr<u256,2>[] (uint256[2][]) storage access now compiles (G6)', () => {
    expect(() => compile(`@contract class C { @state a: Arr<u256,2>[]; @external p(): void { this.a.push(); } @external s(i: u256, j: u256, v: u256): void { this.a[i][j] = v; } @view g(i: u256, j: u256): u256 { return this.a[i][j]; } }`, { fileName: 'C.jeth' })).not.toThrow();
    // whole-array RETURN and calldata-param ECHO of this shape now compile too (G6, byte-identical
    // in test/array-composition-abi.test.ts).
    expect(() => compile(`@contract class C { @state a: Arr<u256,2>[]; @view all(): Arr<u256,2>[] { return this.a; } }`, { fileName: 'C.jeth' })).not.toThrow();
    expect(() => compile(`@contract class C { @external @pure e(x: Arr<u256,2>[]): Arr<u256,2>[] { return x; } }`, { fileName: 'C.jeth' })).not.toThrow();
  });
});
