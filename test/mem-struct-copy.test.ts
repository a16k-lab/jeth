// G9: copying a STORAGE struct (let p: P = this.s) or a calldata struct param into a memory
// local - a COPY (mutating the memory local must NOT change storage), with packed/narrow/signed
// fields transcoded from packed storage to the memory image. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const call = (sig: string, words: bigint[]) => '0x' + sel(sig) + words.map(pad).join('');

const JETH = `@struct class P { a: u256; b: u8; c: i64; d: address; }
@contract class C {
  @state s: P;
  @external setS(a: u256, b: u8, c: i64, d: address): void { this.s.a = a; this.s.b = b; this.s.c = c; this.s.d = d; }
  // copy storage -> memory, mutate the copy, return both copy and storage to prove COPY semantics
  @external copyMutate(na: u256): u256 {
    let p: P = this.s;       // fresh copy of storage
    p.a = na; p.b = 7n;      // mutate the copy only
    return p.a + u256(p.b) + u256(u64(p.c)) + this.s.a; // copy.a(=na) + copy.b(7) + copy.c + STORAGE.a (unchanged)
  }
  // copy storage struct and return it whole
  @external @view snapshot(): P { let p: P = this.s; return p; }
  // copy a CALLDATA struct param to a memory local, mutate, return
  @external @pure fromParam(q: P, na: u256): P { let p: P = q; p.a = na; p.d = address(0x999n); return p; }
  // confirm storage is untouched by reading it back after copyMutate
  @external @view getSA(): u256 { return this.s.a; }
  @external @view getSB(): u8 { return this.s.b; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; int64 c; address d; }
  P s;
  function setS(uint256 a, uint8 b, int64 c, address d) external { s.a = a; s.b = b; s.c = c; s.d = d; }
  function copyMutate(uint256 na) external returns (uint256){
    P memory p = s;
    p.a = na; p.b = 7;
    return p.a + uint256(p.b) + uint256(uint64(p.c)) + s.a;
  }
  function snapshot() external view returns (P memory){ P memory p = s; return p; }
  function fromParam(P calldata q, uint256 na) external pure returns (P memory){ P memory p = q; p.a = na; p.d = address(0x999); return p; }
  function getSA() external view returns (uint256){ return s.a; }
  function getSB() external view returns (uint8){ return s.b; }
}`;

describe('struct memory-local copy from storage/calldata (G9) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function send(data: string) { const j = await jeth.call(aj, data); const s = await sol.call(as, data); expect(j.success, `${j.exceptionError}`).toBe(s.success); }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('storage -> memory copy + mutate (copy semantics) + snapshot', async () => {
    for (const [a, b, c, d] of [[100n, 5n, 9n, 0x1234n], [M - 1n, 255n, M - (1n << 63n), 0xbeefn], [0n, 0n, 0n, 0n]] as [bigint, bigint, bigint, bigint][]) {
      await send(call('setS(uint256,uint8,int64,address)', [a, b, c, d]));
      await eq(`copyMutate`, call('copyMutate(uint256)', [42n]));
      // storage must be unchanged by the mutated memory copy
      await eq('getSA (storage unchanged)', call('getSA()', []));
      await eq('getSB (storage unchanged)', call('getSB()', []));
      await eq('snapshot', call('snapshot()', []));
    }
  });
  it('calldata param -> memory copy + mutate', async () => {
    // fromParam(P calldata q, uint256 na): static struct param = 4 inline words + na
    await eq('fromParam', call('fromParam((uint256,uint8,int64,address),uint256)', [7n, 3n, M - 2n, 0x55n, 88n]));
  });
});
