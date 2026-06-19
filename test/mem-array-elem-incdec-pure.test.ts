// Regression: a compound-assignment / increment whose TARGET is a MEMORY-array element inside a
// @pure function must be accepted (a memory write is not a state access) and run byte-identical to
// solc, including the checked-arithmetic Panic(0x11) at u8 boundaries. Guards against a purity-
// classifier regression that would route the indexed place through the storage-read path and reject
// it with JETH055, and against any codegen drift. The plain-assignment form `xs[i] = xs[i] + 1n` and
// the storage-element `this.nums[i]++` (correctly rejected in @view) are the reference behaviors.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => v.toString(16).padStart(64, '0');

// All targets are a MEMORY-array element in a @pure function (no state touched).
const J = `@contract class G {
  @external @pure inc(a: u8): u8 { let xs: u8[] = [a, a]; xs[0n]++; return xs[0n]; }
  @external @pure dec(a: u8): u8 { let xs: u8[] = [a, a]; xs[0n]--; return xs[0n]; }
  @external @pure preInc(a: u8): u8 { let xs: u8[] = [a, a]; let r: u8 = ++xs[0n]; return r; }
  @external @pure preDec(a: u8): u8 { let xs: u8[] = [a, a]; let r: u8 = --xs[0n]; return r; }
  @external @pure addAssign(a: u8, b: u8): u8 { let xs: u8[] = [a, b]; xs[0n] += xs[1n]; return xs[0n]; }
  @external @pure addAssignLit(a: u8): u8 { let xs: u8[] = [a, a]; xs[0n] += 1n; return xs[0n]; }
}`;
const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract G {
  function inc(uint8 a) external pure returns (uint8) { uint8[] memory xs = new uint8[](2); xs[0]=a; xs[1]=a; xs[0]++; return xs[0]; }
  function dec(uint8 a) external pure returns (uint8) { uint8[] memory xs = new uint8[](2); xs[0]=a; xs[1]=a; xs[0]--; return xs[0]; }
  function preInc(uint8 a) external pure returns (uint8) { uint8[] memory xs = new uint8[](2); xs[0]=a; xs[1]=a; uint8 r = ++xs[0]; return r; }
  function preDec(uint8 a) external pure returns (uint8) { uint8[] memory xs = new uint8[](2); xs[0]=a; xs[1]=a; uint8 r = --xs[0]; return r; }
  function addAssign(uint8 a, uint8 b) external pure returns (uint8) { uint8[] memory xs = new uint8[](2); xs[0]=a; xs[1]=b; xs[0]+=xs[1]; return xs[0]; }
  function addAssignLit(uint8 a) external pure returns (uint8) { uint8[] memory xs = new uint8[](2); xs[0]=a; xs[1]=a; xs[0]+=1; return xs[0]; }
}`;

function codes(src: string): string[] {
  try { compile(src, { fileName: 'C.jeth' }); return []; }
  catch (e) { if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e; }
}

describe('memory-array element ++/--/+= in @pure', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(J, { fileName: 'C.jeth' }); const sb = compileSolidity(S, 'G');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('compiles in @pure (a memory-element write is not a state access)', () => {
    expect(codes(J)).toEqual([]);
  });

  it('++ / pre-++ match solc across u8 boundaries (255++ -> Panic 0x11)', async () => {
    for (const a of [0n, 126n, 127n, 200n, 254n, 255n]) {
      await eq(`inc(${a})`, '0x' + sel('inc(uint8)') + pad(a));
      await eq(`preInc(${a})`, '0x' + sel('preInc(uint8)') + pad(a));
    }
  });

  it('-- / pre--- match solc across u8 boundaries (0-- -> Panic 0x11)', async () => {
    for (const a of [0n, 1n, 127n, 128n, 255n]) {
      await eq(`dec(${a})`, '0x' + sel('dec(uint8)') + pad(a));
      await eq(`preDec(${a})`, '0x' + sel('preDec(uint8)') + pad(a));
    }
  });

  it('+= (element and literal) match solc incl. overflow Panic 0x11', async () => {
    for (const [a, b] of [[0n, 0n], [100n, 27n], [200n, 55n], [200n, 56n], [255n, 1n]] as const) {
      await eq(`addAssign(${a},${b})`, '0x' + sel('addAssign(uint8,uint8)') + pad(a) + pad(b));
    }
    for (const a of [0n, 126n, 254n, 255n]) {
      await eq(`addAssignLit(${a})`, '0x' + sel('addAssignLit(uint8)') + pad(a));
    }
  });

  it('control: storage-element ++ is still correctly rejected in @view (JETH054), not memory', () => {
    expect(codes('@contract class G { @state nums: u8[]; @external @view f(): u8 { this.nums[0n]++; return this.nums[0n]; } }')).toContain('JETH054');
  });
});
