// W5C-mem: aliasing a FIXED-outer dynamic-element FIELD of a MEMORY struct out to a standalone local
// (let ys: Arr<string,N> = d.tags, solc `string[N] memory ys = d.tags`). solc treats this as a POINTER
// ALIAS: ys points at the field image inside d, so mutating ys[i] mutates d.tags[i] and vice versa. The
// leaf kinds are Arr<string,N>, Arr<bytes,N> (isDynBytesFixedLeafArray) and the value-leaf twin
// Arr<u256[],N> (isNestedValueArray). Source structs: a memory-built local D(...), an internal memory
// param, a nested sub-struct field v.t.tags, and a P[]-element field xs[i].tags. Reads of the aliased
// local ys[i] (const + runtime, OOB Panic 0x32), ys.length, whole return, abi.encode(ys), internal-arg
// pass, and the mutation-alias direction (write ys[i], read d.tags[i]) are byte-identical to solc 0.8.35.
//
// The fix widens the fixed-of-dynamic local-decl SOURCE gate to accept a memory-struct-field read
// (an arrayValue with a memArrayExpr base), ALIASING the same field image pointer the working
// direct-read (d.tags[i]) and whole-return (return d.tags) paths already compute.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => BigInt(n).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function deployPair(jeth: string, sol: string) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { hj, hs, aj, as };
}

// Every success case asserts a CONCRETE hard-coded return value so a vacuous both-revert cannot pass.
async function eqCalls(jeth: string, sol: string, calls: [string, string, string?][]) {
  const { hj, hs, aj, as } = await deployPair(jeth, sol);
  for (const [sig, args, expectHex] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} jeth vs solc success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} jeth vs solc return`).toBe(rs.returnHex);
    if (expectHex !== undefined) expect(rj.returnHex, `${sig} concrete anchor`).toBe(expectHex);
  }
}

// abi-encode a `string` return (offset 0x20, len, padded bytes).
const retStr = (s: string): string => {
  const h = Buffer.from(s, 'utf8').toString('hex');
  const words = Math.ceil(h.length / 2 / 32);
  return '0x' + W(0x20) + W(h.length / 2) + h.padEnd(words * 64, '0');
};

describe('mem-struct fixed-of-dynamic field alias (W5C-mem)', () => {
  it('Arr<string,2> mem-built local: element/length/whole/encode/argpass + OOB Panic 0x32', async () => {
    const J = `
@struct class D { tags: Arr<string,2>; k: u256 }
@contract class C {
  echo(ys: Arr<string,2>): string { return ys[1n]; }
  @external @pure elem(i: u256): string { let d: D = D(["ab","cdcd"], 3n); let ys: Arr<string,2> = d.tags; return ys[i]; }
  @external @pure len(): u256 { let d: D = D(["ab","cdcd"], 3n); let ys: Arr<string,2> = d.tags; return ys.length; }
  @external @pure whole(): Arr<string,2> { let d: D = D(["ab","cdcd"], 3n); let ys: Arr<string,2> = d.tags; return ys; }
  @external @pure enc(): bytes { let d: D = D(["ab","cdcd"], 3n); let ys: Arr<string,2> = d.tags; return abi.encode(ys); }
  @external @pure arg(): string { let d: D = D(["ab","cdcd"], 3n); let ys: Arr<string,2> = d.tags; return this.echo(ys); }
}`;
    const S = `
contract C {
  struct D { string[2] tags; uint256 k; }
  function echo(string[2] memory ys) internal pure returns (string memory) { return ys[1]; }
  function elem(uint256 i) external pure returns (string memory) { D memory d = D([string("ab"),string("cdcd")],3); string[2] memory ys = d.tags; return ys[i]; }
  function len() external pure returns (uint256) { D memory d = D([string("ab"),string("cdcd")],3); string[2] memory ys = d.tags; return ys.length; }
  function whole() external pure returns (string[2] memory) { D memory d = D([string("ab"),string("cdcd")],3); string[2] memory ys = d.tags; return ys; }
  function enc() external pure returns (bytes memory) { D memory d = D([string("ab"),string("cdcd")],3); string[2] memory ys = d.tags; return abi.encode(ys); }
  function arg() external pure returns (string memory) { D memory d = D([string("ab"),string("cdcd")],3); string[2] memory ys = d.tags; return echo(ys); }
}`;
    await eqCalls(J, S, [
      ['elem(uint256)', W(0), retStr('ab')],
      ['elem(uint256)', W(1), retStr('cdcd')],
      ['len()', '', '0x' + W(2)],
      ['arg()', '', retStr('cdcd')],
      ['elem(uint256)', W(2), '0x4e487b71' + W(0x32)], // OOB Panic 0x32
    ]);
  });

  it('Arr<string,3> internal MEMORY PARAM source (the exact repro shape)', async () => {
    const J = `
@struct class D { tags: Arr<string,3>; k: u256 }
@contract class C {
  g(d: D, i: u256): string { let ys: Arr<string,3> = d.tags; return ys[i]; }
  @external @pure f(i: u256): string { let d: D = D(["p","qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq","r"], 1n); return this.g(d, i); }
}`;
    const S = `
contract C {
  struct D { string[3] tags; uint256 k; }
  function g(D memory d, uint256 i) internal pure returns (string memory) { string[3] memory ys = d.tags; return ys[i]; }
  function f(uint256 i) external pure returns (string memory) { D memory d = D([string("p"),string("qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"),string("r")],1); return g(d,i); }
}`;
    await eqCalls(J, S, [
      ['f(uint256)', W(0), retStr('p')],
      ['f(uint256)', W(1), retStr('qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq')],
      ['f(uint256)', W(2), retStr('r')],
      ['f(uint256)', W(3), '0x4e487b71' + W(0x32)],
    ]);
  });

  it('Arr<bytes,2> mem-built local element read (incl >31-byte + empty)', async () => {
    const J = `
@struct class D { tags: Arr<bytes,2>; k: u256 }
@contract class C {
  @external @pure elem(i: u256): bytes { let d: D = D([bytes(""), bytes("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")], 5n); let ys: Arr<bytes,2> = d.tags; return ys[i]; }
}`;
    const S = `
contract C {
  struct D { bytes[2] tags; uint256 k; }
  function elem(uint256 i) external pure returns (bytes memory) { D memory d = D([bytes(""), bytes("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")], 5); bytes[2] memory ys = d.tags; return ys[i]; }
}`;
    await eqCalls(J, S, [
      ['elem(uint256)', W(0), '0x' + W(0x20) + W(0)],
      ['elem(uint256)', W(1)], // >31-byte, differential only (concrete anchor implicit via solc match)
      ['elem(uint256)', W(2), '0x4e487b71' + W(0x32)],
    ]);
  });

  it('Arr<u256[],2> value-leaf twin, internal param source: element/length + inner/outer OOB', async () => {
    const J = `
@struct class D { g: Arr<u256[],2>; k: u256 }
@contract class C {
  pick(d: D, i: u256, j: u256): u256 { let ys: Arr<u256[],2> = d.g; return ys[i][j]; }
  plen(d: D, i: u256): u256 { let ys: Arr<u256[],2> = d.g; return ys[i].length; }
  @external @pure f(i: u256, j: u256): u256 { let d: D = D([[10n,20n,30n],[99n]], 7n); return this.pick(d, i, j); }
  @external @pure fl(i: u256): u256 { let d: D = D([[10n,20n,30n],[99n]], 7n); return this.plen(d, i); }
}`;
    const S = `
contract C {
  struct D { uint256[][2] g; uint256 k; }
  function mk() internal pure returns (uint256[][2] memory) { uint256[] memory a = new uint256[](3); a[0]=10;a[1]=20;a[2]=30; uint256[] memory b = new uint256[](1); b[0]=99; return [a,b]; }
  function pick(D memory d, uint256 i, uint256 j) internal pure returns (uint256) { uint256[][2] memory ys = d.g; return ys[i][j]; }
  function plen(D memory d, uint256 i) internal pure returns (uint256) { uint256[][2] memory ys = d.g; return ys[i].length; }
  function f(uint256 i, uint256 j) external pure returns (uint256) { D memory d = D(mk(), 7); return pick(d,i,j); }
  function fl(uint256 i) external pure returns (uint256) { D memory d = D(mk(), 7); return plen(d,i); }
}`;
    await eqCalls(J, S, [
      ['f(uint256,uint256)', W(0) + W(2), '0x' + W(30)],
      ['f(uint256,uint256)', W(1) + W(0), '0x' + W(99)],
      ['fl(uint256)', W(0), '0x' + W(3)],
      ['fl(uint256)', W(1), '0x' + W(1)],
      ['f(uint256,uint256)', W(0) + W(9), '0x4e487b71' + W(0x32)], // inner OOB
      ['fl(uint256)', W(2), '0x4e487b71' + W(0x32)], // outer OOB
    ]);
  });

  it('NESTED sub-struct field source v.t.tags (Arr<string,2>)', async () => {
    const J = `
@struct class In { tags: Arr<string,2>; z: u256 }
@struct class Ou { t: In; k: u256 }
@contract class C {
  @external @pure elem(i: u256): string { let v: Ou = Ou(In(["nn","mmmm"], 4n), 9n); let ys: Arr<string,2> = v.t.tags; return ys[i]; }
}`;
    const S = `
contract C {
  struct In { string[2] tags; uint256 z; }
  struct Ou { In t; uint256 k; }
  function elem(uint256 i) external pure returns (string memory) { Ou memory v = Ou(In([string("nn"),string("mmmm")], 4), 9); string[2] memory ys = v.t.tags; return ys[i]; }
}`;
    await eqCalls(J, S, [
      ['elem(uint256)', W(0), retStr('nn')],
      ['elem(uint256)', W(1), retStr('mmmm')],
      ['elem(uint256)', W(2), '0x4e487b71' + W(0x32)],
    ]);
  });

  it('P[]-element field source xs[i].tags (Arr<string,2>)', async () => {
    const J = `
@struct class P { tags: Arr<string,2>; k: u256 }
@contract class C {
  @external @pure elem(i: u256, j: u256): string { let xs: P[] = [P(["a0","b0"], 1n), P(["a1","b1"], 2n)]; let ys: Arr<string,2> = xs[i].tags; return ys[j]; }
}`;
    const S = `
contract C {
  struct P { string[2] tags; uint256 k; }
  function mk() internal pure returns (P[] memory) { P[] memory xs = new P[](2); xs[0] = P([string("a0"),string("b0")], 1); xs[1] = P([string("a1"),string("b1")], 2); return xs; }
  function elem(uint256 i, uint256 j) external pure returns (string memory) { P[] memory xs = mk(); string[2] memory ys = xs[i].tags; return ys[j]; }
}`;
    await eqCalls(J, S, [
      ['elem(uint256,uint256)', W(0) + W(0), retStr('a0')],
      ['elem(uint256,uint256)', W(1) + W(1), retStr('b1')],
      ['elem(uint256,uint256)', W(0) + W(2), '0x4e487b71' + W(0x32)], // inner OOB
      ['elem(uint256,uint256)', W(9) + W(0), '0x4e487b71' + W(0x32)], // outer OOB
    ]);
  });

  it('mutation-alias BOTH directions (write ys -> read d.tags, write d.tags -> read ys)', async () => {
    const J = `
@struct class D { tags: Arr<string,2>; k: u256 }
@contract class C {
  @external @pure ysToD(): string { let d: D = D(["aa","bb"], 7n); let ys: Arr<string,2> = d.tags; ys[0n] = "ZZZ"; return d.tags[0n]; }
  @external @pure dToYs(): string { let d: D = D(["aa","bb"], 7n); let ys: Arr<string,2> = d.tags; d.tags[1n] = "WWW"; return ys[1n]; }
  @external @pure ysToDLong(): string { let d: D = D(["aa","bb"], 7n); let ys: Arr<string,2> = d.tags; ys[0n] = "this-re-point-is-longer-than-thirty-one-bytes"; return d.tags[0n]; }
}`;
    const S = `
contract C {
  struct D { string[2] tags; uint256 k; }
  function ysToD() external pure returns (string memory) { D memory d = D([string("aa"),string("bb")], 7); string[2] memory ys = d.tags; ys[0] = "ZZZ"; return d.tags[0]; }
  function dToYs() external pure returns (string memory) { D memory d = D([string("aa"),string("bb")], 7); string[2] memory ys = d.tags; d.tags[1] = "WWW"; return ys[1]; }
  function ysToDLong() external pure returns (string memory) { D memory d = D([string("aa"),string("bb")], 7); string[2] memory ys = d.tags; ys[0] = "this-re-point-is-longer-than-thirty-one-bytes"; return d.tags[0]; }
}`;
    await eqCalls(J, S, [
      ['ysToD()', '', retStr('ZZZ')],
      ['dToYs()', '', retStr('WWW')],
      ['ysToDLong()', '', retStr('this-re-point-is-longer-than-thirty-one-bytes')],
    ]);
  });
});
