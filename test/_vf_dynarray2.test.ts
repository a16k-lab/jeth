// _vf_dynarray2: deeper adversarial differential test for dynamic arrays.
// checked-arith on storage elements (panic 0x11), this.u = [] clear, struct-array
// field RMW, nested string[][] / D[][] return, memory OOB write, ternary index,
// length arithmetic underflow (panic 0x11), dirty index high bits, push-in-loop,
// bytes16[] exact slot-boundary pop, deep nesting, overwrite-longer-with-shorter.
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

function encArr(sig: string, elems: bigint[]): string {
  return '0x' + sel(sig) + pad(0x20n) + pad(BigInt(elems.length)) + elems.map(pad).join('');
}
function encIStr(sig: string, i: bigint, s: string): string {
  const b = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(b.length / 32);
  let data = '';
  for (let w = 0; w < nwords; w++) data += Buffer.concat([b.subarray(w * 32, w * 32 + 32), Buffer.alloc(32)]).subarray(0, 32).toString('hex');
  return '0x' + sel(sig) + pad(i) + pad(0x40n) + pad(BigInt(b.length)) + data;
}
function encStr(sig: string, s: string): string {
  const b = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(b.length / 32);
  let data = '';
  for (let w = 0; w < nwords; w++) data += Buffer.concat([b.subarray(w * 32, w * 32 + 32), Buffer.alloc(32)]).subarray(0, 32).toString('hex');
  return '0x' + sel(sig) + pad(0x20n) + pad(BigInt(b.length)) + data;
}

const JETH = `@struct class P { x: u128; y: u128; }
@struct class D { a: u256; s: string; }
@contract class C {
  @state u: u256[];
  @state pa: P[];
  @state ss: string[][];
  @state da: D[][];
  @state b16: bytes16[];

  @external pushU(v: u256): void { this.u.push(v); }
  @external clearU(): void { this.u = []; }
  @external incU(i: u256, v: u256): void { this.u[i] = this.u[i] + v; }       // checked add
  @external decU(i: u256, v: u256): void { this.u[i] = this.u[i] - v; }       // checked sub
  @external mulU(i: u256, v: u256): void { this.u[i] = this.u[i] * v; }       // checked mul
  @external @view getU(i: u256): u256 { return this.u[i]; }
  @external @view lenU(): u256 { return this.u.length; }
  @external @view lenM1(): u256 { return this.u.length - 1n; }                          // underflow if empty
  @external @view allU(): u256[] { return this.u; }
  // dirty-high-bit index: index passed as full word, only low matters but value used as-is
  @external @view getUTernary(c: bool): u256 { return this.u[c ? 0n : 1n]; }
  @external pushNloop(n: u256, base: u256): void {
    for (let i: u256 = 0n; i < n; i += 1n) { this.u.push(base + i); }
  }

  @external pushPa(x: u128, y: u128): void { this.pa.push(P(x, y)); }
  @external bumpY(i: u256, d: u128): void { this.pa[i].y += d; }              // field RMW, u128 wrap-in-unchecked? checked
  @external setX(i: u256, x: u128): void { this.pa[i].x = x; }
  @external @view getY(i: u256): u128 { return this.pa[i].y; }
  @external @view getX(i: u256): u128 { return this.pa[i].x; }
  @external @view allPa(): P[] { return this.pa; }

  @external pushSOuter(): void { this.ss.push(); }
  @external pushSInner(i: u256, s: string): void { this.ss[i].push(s); }
  @external popSInner(i: u256): void { this.ss[i].pop(); }
  @external @view allSS(): string[][] { return this.ss; }
  @external @view ssAt(i: u256, j: u256): string { return this.ss[i][j]; }

  @external pushDAOuter(): void { this.da.push(); }
  @external pushDAInner(i: u256, a: u256, s: string): void { this.da[i].push(D(a, s)); }
  @external @view allDA(): D[][] { return this.da; }

  @external pushB16(v: bytes16): void { this.b16.push(v); }
  @external popB16(): void { this.b16.pop(); }
  @external @view allB16(): bytes16[] { return this.b16; }

  @external @pure memOOBWrite(): u256 { let xs: u256[] = [1n, 2n]; xs[5n] = 9n; return xs[0n]; }
  @external @pure memOOBRead(): u256 { let xs: u256[] = [1n, 2n]; return xs[5n]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint128 x; uint128 y; }
  struct D { uint256 a; string s; }
  uint256[] u; P[] pa; string[][] ss; D[][] da; bytes16[] b16;

  function pushU(uint256 v) external { u.push(v); }
  function clearU() external { delete u; }
  function incU(uint256 i, uint256 v) external { u[i] = u[i] + v; }
  function decU(uint256 i, uint256 v) external { u[i] = u[i] - v; }
  function mulU(uint256 i, uint256 v) external { u[i] = u[i] * v; }
  function getU(uint256 i) external view returns (uint256){ return u[i]; }
  function lenU() external view returns (uint256){ return u.length; }
  function lenM1() external view returns (uint256){ return u.length - 1; }
  function allU() external view returns (uint256[] memory){ return u; }
  function getUTernary(bool c) external view returns (uint256){ return u[c ? 0 : 1]; }
  function pushNloop(uint256 n, uint256 base) external { for (uint256 i=0;i<n;i+=1){ u.push(base+i); } }

  function pushPa(uint128 x, uint128 y) external { pa.push(P(x, y)); }
  function bumpY(uint256 i, uint128 d) external { pa[i].y += d; }
  function setX(uint256 i, uint128 x) external { pa[i].x = x; }
  function getY(uint256 i) external view returns (uint128){ return pa[i].y; }
  function getX(uint256 i) external view returns (uint128){ return pa[i].x; }
  function allPa() external view returns (P[] memory){ return pa; }

  function pushSOuter() external { ss.push(); }
  function pushSInner(uint256 i, string calldata s) external { ss[i].push(s); }
  function popSInner(uint256 i) external { ss[i].pop(); }
  function allSS() external view returns (string[][] memory){ return ss; }
  function ssAt(uint256 i, uint256 j) external view returns (string memory){ return ss[i][j]; }

  function pushDAOuter() external { da.push(); }
  function pushDAInner(uint256 i, uint256 a, string calldata s) external { da[i].push(D(a, s)); }
  function allDA() external view returns (D[][] memory){ return da; }

  function pushB16(bytes16 v) external { b16.push(v); }
  function popB16() external { b16.pop(); }
  function allB16() external view returns (bytes16[] memory){ return b16; }

  function memOOBWrite() external pure returns (uint256){ uint256[] memory xs = new uint256[](2); xs[0]=1;xs[1]=2; xs[5]=9; return xs[0]; }
  function memOOBRead() external pure returns (uint256){ uint256[] memory xs = new uint256[](2); xs[0]=1;xs[1]=2; return xs[5]; }
}`;

describe('_vf_dynarray2 probe', () => {
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
    // ---- checked arithmetic on storage element -> panic 0x11 parity ----
    await send('pushU max', encodeCall(sel('pushU(uint256)'), [MAX]));
    await send('pushU 0', encodeCall(sel('pushU(uint256)'), [0n]));
    await send('pushU 5', encodeCall(sel('pushU(uint256)'), [5n]));
    await eq('incU[0] +1 overflow -> 0x11', encodeCall(sel('incU(uint256,uint256)'), [0n, 1n]));
    await eq('incU[2] +1 ok', encodeCall(sel('incU(uint256,uint256)'), [2n, 1n]));
    await eq('getU[2]==6', encodeCall(sel('getU(uint256)'), [2n]));
    await eq('decU[1] -1 underflow -> 0x11', encodeCall(sel('decU(uint256,uint256)'), [1n, 1n]));
    await eq('mulU[2] *max overflow', encodeCall(sel('mulU(uint256,uint256)'), [2n, MAX]));
    await eq('incU OOB index -> 0x32', encodeCall(sel('incU(uint256,uint256)'), [9n, 1n]));
    await eq('allU after checked ops', encodeCall(sel('allU()')));

    // ---- length arithmetic underflow on empty ----
    await eq('lenM1 with 3 elems', encodeCall(sel('lenM1()')));
    await send('clearU (delete)', encodeCall(sel('clearU()')));
    await eq('lenU after clear == 0', encodeCall(sel('lenU()')));
    await eq('allU after clear empty', encodeCall(sel('allU()')));
    await eq('lenM1 on empty -> 0x11', encodeCall(sel('lenM1()')));
    await eq('getU[0] on empty -> 0x32', encodeCall(sel('getU(uint256)'), [0n]));

    // ---- clear then regrow: freed slots must read clean ----
    for (const v of [0xaaaan, 0xbbbbn, 0xccccn, 0xddddn]) await send('regrow after clear', encodeCall(sel('pushU(uint256)'), [v]));
    await eq('allU regrow after clear', encodeCall(sel('allU()')));

    // ---- this.u = [] empty clear then check stale ----
    await send('clearU again', encodeCall(sel('clearU()')));
    for (const v of [1n, 2n]) await send('two after clear', encodeCall(sel('pushU(uint256)'), [v]));
    await eq('allU two after second clear (no stale)', encodeCall(sel('allU()')));

    // ---- ternary index + clear underflow paths ----
    await eq('ternary idx true ->u[0]', encodeCall(sel('getUTernary(bool)'), [1n]));
    await eq('ternary idx false ->u[1]', encodeCall(sel('getUTernary(bool)'), [0n]));
    // dirty-bit bool: nonzero -> true in solc
    await eq('ternary dirty bool 0xff', '0x' + sel('getUTernary(bool)') + pad(0xffn));

    // ---- push in a loop (build then verify) ----
    await send('clearU pre-loop', encodeCall(sel('clearU()')));
    await send('pushNloop n=10', encodeCall(sel('pushNloop(uint256,uint256)'), [10n, 1000n]));
    await eq('lenU=10 after loop', encodeCall(sel('lenU()')));
    await eq('allU after loop push', encodeCall(sel('allU()')));
    await eq('getU[7] from loop', encodeCall(sel('getU(uint256)'), [7n]));
    await send('pushNloop n=0 (no-op)', encodeCall(sel('pushNloop(uint256,uint256)'), [0n, 0n]));
    await eq('allU after n=0 loop', encodeCall(sel('allU()')));

    // ---- struct array field RMW (u128 packed) checked overflow ----
    await send('pushPa(1,2)', encodeCall(sel('pushPa(uint128,uint128)'), [1n, 2n]));
    await send('pushPa(max128,max128)', encodeCall(sel('pushPa(uint128,uint128)'), [(1n << 128n) - 1n, (1n << 128n) - 1n]));
    await eq('bumpY[0] +5', encodeCall(sel('bumpY(uint256,uint128)'), [0n, 5n]));
    await eq('getY[0]==7', encodeCall(sel('getY(uint256)'), [0n]));
    await eq('bumpY[1] +1 -> u128 overflow 0x11', encodeCall(sel('bumpY(uint256,uint128)'), [1n, 1n]));
    await eq('setX[0]=0x9999 (does not corrupt y)', encodeCall(sel('setX(uint256,uint128)'), [0n, 0x9999n]));
    await eq('getX[0]==0x9999', encodeCall(sel('getX(uint256)'), [0n]));
    await eq('getY[0] still 7 after setX (no straddle corruption)', encodeCall(sel('getY(uint256)'), [0n]));
    await eq('allPa', encodeCall(sel('allPa()')));
    await eq('bumpY OOB -> 0x32', encodeCall(sel('bumpY(uint256,uint128)'), [9n, 1n]));

    // ---- nested string[][] return + per-inner pop clear ----
    await send('ss push outer', encodeCall(sel('pushSOuter()')));
    await send('ss push outer', encodeCall(sel('pushSOuter()')));
    const LONG = 'this nested string is definitely longer than thirty-two bytes to force multiword';
    await send('ss[0] push hi', encIStr('pushSInner(uint256,string)', 0n, 'hi'));
    await send('ss[0] push LONG', encIStr('pushSInner(uint256,string)', 0n, LONG));
    await send('ss[0] push empty', encIStr('pushSInner(uint256,string)', 0n, ''));
    await send('ss[1] push abc', encIStr('pushSInner(uint256,string)', 1n, 'abc'));
    await eq('ssAt[0][1] LONG', encodeCall(sel('ssAt(uint256,uint256)'), [0n, 1n]));
    await eq('ssAt OOB inner', encodeCall(sel('ssAt(uint256,uint256)'), [1n, 5n]));
    await eq('ssAt OOB outer', encodeCall(sel('ssAt(uint256,uint256)'), [9n, 0n]));
    await eq('allSS', encodeCall(sel('allSS()')));
    await send('ss[0] pop LONG (clears data slots)', encodeCall(sel('popSInner(uint256)'), [0n]));
    await eq('allSS after inner pop (no stale)', encodeCall(sel('allSS()')));
    await send('ss[0] re-push short into freed slots', encIStr('pushSInner(uint256,string)', 0n, 'z'));
    await eq('allSS after re-push (no stale data)', encodeCall(sel('allSS()')));

    // ---- nested D[][] return ----
    await send('da push outer', encodeCall(sel('pushDAOuter()')));
    await send('da push outer', encodeCall(sel('pushDAOuter()')));
    // pushDAInner(uint256 i, uint256 a, string): build manually
    {
      const s = 'hi';
      const b = Buffer.from(s, 'utf8');
      const data = Buffer.concat([b, Buffer.alloc(32 - b.length)]).subarray(0, 32).toString('hex');
      const dd = '0x' + sel('pushDAInner(uint256,uint256,string)') + pad(0n) + pad(5n) + pad(0x60n) + pad(BigInt(b.length)) + data;
      await send('da[0] push (5,hi) proper', dd);
    }
    {
      const s = LONG;
      const b = Buffer.from(s, 'utf8');
      const nwords = Math.ceil(b.length / 32);
      let data = '';
      for (let w = 0; w < nwords; w++) data += Buffer.concat([b.subarray(w * 32, w * 32 + 32), Buffer.alloc(32)]).subarray(0, 32).toString('hex');
      const dd = '0x' + sel('pushDAInner(uint256,uint256,string)') + pad(0n) + pad(6n) + pad(0x60n) + pad(BigInt(b.length)) + data;
      await send('da[0] push (6,LONG) proper', dd);
    }
    await eq('allDA', encodeCall(sel('allDA()')));

    // ---- bytes16[] packed 2/slot, pop at exact boundary ----
    for (const v of [0n, MAX, (1n << 255n), 0xabcdn, 1n]) await send('pushB16', encodeCall(sel('pushB16(bytes16)'), [v << 128n]));
    await eq('allB16 5 elems', encodeCall(sel('allB16()')));
    // pop from 5->4 (4 is in slot index 2 lower half) -> the half must be cleared
    await send('popB16 5->4', encodeCall(sel('popB16()')));
    await eq('allB16 after pop', encodeCall(sel('allB16()')));
    // pop 4->3 then regrow, no stale upper half
    await send('popB16 4->3', encodeCall(sel('popB16()')));
    await send('pushB16 regrow', encodeCall(sel('pushB16(bytes16)'), [(0x7777n) << 128n]));
    await eq('allB16 regrow no-stale', encodeCall(sel('allB16()')));

    // ---- memory OOB write/read -> panic 0x32 ----
    await eq('memOOBWrite -> 0x32', encodeCall(sel('memOOBWrite()')));
    await eq('memOOBRead -> 0x32', encodeCall(sel('memOOBRead()')));

    // ---- ABI: dirty-bit index in calldata for getU (high bits beyond len use full value) ----
    await send('clearU final', encodeCall(sel('clearU()')));
    for (const v of [7n, 8n, 9n]) await send('seed u', encodeCall(sel('pushU(uint256)'), [v]));
    await eq('getU idx with dirty top (huge) -> 0x32', '0x' + sel('getU(uint256)') + pad((1n << 255n) + 1n));
    await eq('getU idx exactly len -> 0x32', encodeCall(sel('getU(uint256)'), [3n]));
    await eq('getU idx max -> 0x32', encodeCall(sel('getU(uint256)'), [MAX]));

    if (mism.length) { process.stderr.write('MISMATCHES ' + mism.length + '/' + count + '\n'); for (const m of mism.slice(0, 40)) process.stderr.write(m + '\n'); }
    else process.stderr.write('ALL2 ' + count + ' byte-identical\n');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
