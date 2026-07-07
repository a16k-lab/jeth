// Tier-3 inline lifts (implemented alongside the batch-2/3 agent work), byte-identical to solc 0.8.35:
// L10a  a bytes/string-returning FUNCREF call (let g: (x) => string = this.pick; g(x)): lowerDynamic
//       gained the funcRefCall case (the dispatcher already forwards the [len][data] pointer word).
// L11b  a ternary over FUNCREF-FIELD structs (c ? a : b then p.f(10n)): the ternary's static-aggregate
//       clause widened to isValueWordAggregate (a funcref field is one flat id word); every ABI
//       boundary still rejects funcref aggregates (isStaticType stays false) - solc parity.
// L13   a byte-write into a bytes[] FIELD element of a memory struct (p.tags[0n][1n] = 0x21n): the
//       memByteIndexStore branch now keys on a memory-based resolveArrayExpr base (memArray local OR
//       the field's memArrayExpr), subsuming the old local-only gate. In-place mstore8 semantics:
//       the write is visible through a previously-taken bytes alias, exactly like solc.
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

describe('Tier-3 inline lifts (L10a, L11b, L13) byte-identical to solc 0.8.35', () => {
  it('L10a: dynamic-return funcref call + L11b: funcref-struct ternary', async () => {
    const J = `@struct class FSt { f: (x: u256) => u256; tag: u256 }
@contract class C {
  inc(x: u256): u256 { return x + 1n; }
  dec(x: u256): u256 { return x - 1n; }
  pick(x: u256): string { return x > 0n ? "hi" : "lo"; }
  @external @pure l10a(x: u256): string { let g: (x: u256) => string = this.pick; return g(x); }
  @external @pure l11b(c: bool): u256 { let a: FSt = FSt(this.inc, 2n); let b: FSt = FSt(this.dec, 1n); let p: FSt = c ? a : b; return p.f(10n) + p.tag; } }`;
    const S = `contract C {
  function inc(uint256 x) internal pure returns(uint256){ return x + 1; }
  function dec(uint256 x) internal pure returns(uint256){ return x - 1; }
  function pick(uint256 x) internal pure returns(string memory){ return x > 0 ? "hi" : "lo"; }
  struct FSt { function(uint256) pure returns(uint256) f; uint256 tag; }
  function l10a(uint256 x) external pure returns(string memory){ function(uint256) pure returns(string memory) g = pick; return g(x); }
  function l11b(bool c) external pure returns(uint256){ FSt memory a = FSt(inc, 2); FSt memory b = FSt(dec, 1); FSt memory p = c ? a : b; return p.f(10) + p.tag; } }`;
    await run(J, S, [['l10a(uint256)', W(1)], ['l10a(uint256)', W(0)], ['l11b(bool)', W(1)], ['l11b(bool)', W(0)]] as const);
    // ABI boundaries keep rejecting funcref aggregates (solc parity).
    const rejects = (src: string): boolean => {
      try {
        compile(src, { fileName: 'C.jeth' });
        return false;
      } catch {
        return true;
      }
    };
    expect(rejects(`@struct class FSt { f: (x: u256) => u256; tag: u256 } @contract class C { inc(x:u256):u256{return x;} @external @pure f(): bytes { let a: FSt = FSt(this.inc, 2n); return abi.encode(a); } }`)).toBe(true);
  });

  it('L13: byte-write into a bytes[] field element (write, OOB Panic, alias-through, storage control)', async () => {
    const J = `@struct class Pt6 { tags: bytes[]; n: u256 }
@contract class C {
  @state ss: bytes[];
  @external seedS(): void { this.ss.push(bytes("qq")); }
  @external @pure f(): bytes { let t: bytes[] = [bytes("aabbcc"), bytes("dd")]; let p: Pt6 = Pt6(t, 9n); p.tags[0n][1n] = 0x21n; return p.tags[0n]; }
  @external @pure fo(): bytes { let t: bytes[] = [bytes("aabbcc")]; let p: Pt6 = Pt6(t, 9n); p.tags[0n][9n] = 0x21n; return p.tags[0n]; }
  @external @pure loc(): u256 { let t: bytes[] = [bytes("ab")]; let p: Pt6 = Pt6(t, 9n); let al: bytes = p.tags[0n]; p.tags[0n][0n] = 0x5an; return al[0n] == 0x5an ? 1n : 0n; }
  @external ctlSt(): bytes { this.ss[0n][1n] = 0x22n; return this.ss[0n]; } }`;
    const S = `struct Pt6 { bytes[] tags; uint256 n; }
contract C {
  bytes[] ss;
  function seedS() external { ss.push(bytes("qq")); }
  function f() external pure returns(bytes memory){ bytes[] memory t = new bytes[](2); t[0]=bytes("aabbcc"); t[1]=bytes("dd"); Pt6 memory p = Pt6(t, 9); p.tags[0][1] = 0x21; return p.tags[0]; }
  function fo() external pure returns(bytes memory){ bytes[] memory t = new bytes[](1); t[0]=bytes("aabbcc"); Pt6 memory p = Pt6(t, 9); p.tags[0][9] = 0x21; return p.tags[0]; }
  function loc() external pure returns(uint256){ bytes[] memory t = new bytes[](1); t[0]=bytes("ab"); Pt6 memory p = Pt6(t, 9); bytes memory al = p.tags[0]; p.tags[0][0] = 0x5a; return al[0] == 0x5a ? 1 : 0; }
  function ctlSt() external returns(bytes memory){ ss[0][1] = 0x22; return ss[0]; } }`;
    await run(J, S, [['f()', ''], ['fo()', ''], ['loc()', ''], ['seedS()', ''], ['ctlSt()', '']] as const);
  });
});
