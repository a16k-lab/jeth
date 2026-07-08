// Fixes found by the final-5 long-tail adversarial verification workflow (230 cases). The LT1-LT4
// lifts themselves verified clean; the workflow surfaced two adjacent issues, both closed here:
//
// BYTE-CD-1 (pre-existing silent MISCOMPILE): a byte read of a `bytes` field of a CALLDATA
//   struct-ARRAY element (xs[i].b[j], xs: Q[] / Arr<Q,N> calldata) compiled and returned 0x00 for
//   every index with no OOB Panic, while solc returns the byte / reverts Panic 0x32. The field was
//   mis-routed through resolveCdDynArrayField (the value-array-field path) which read a zero base.
//   Now rejects JETH217 (bind the field to a `bytes` local first, which is byte-identical). A plain
//   calldata dyn-struct PARAM field byte read (d.b[j]) resolves correctly and is unaffected.
//
// FUNCREF-NOTE-1 (compiler CRASH): declaring an uninitialized funcref-bearing STATIC struct local
//   (let d: Fd; Fd{f}) crashed defaultStaticValue (a funcref is not isStaticValueType, so it fell to
//   the fixed-array branch and dereferenced an absent .element). A funcref now defaults to the zero
//   id (an uninitialized internal function pointer), byte-identical to solc: reassign+call works, and
//   calling the zero funcref reverts Panic 0x51.
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

describe('final-5 verification fixes (byte-identical to solc 0.8.35)', () => {
  it('BYTE-CD-1: calldata struct-array element byte read is now byte-identical (OR cluster 3); controls MATCH', async () => {
    // OR cluster 3 (CD-STRUCTARR-BYTE): the direct xs[i].b[j] read now resolves the bytes field to its
    // calldata base and byte-indexes it (Panic 0x32 on OOB), byte-identical to the bind-a-local workaround
    // and to solc. Verify the direct form (dynamic outer Q[], the b-first field order) matches solc.
    await run(
      `@struct class Q{b:bytes;n:u256}
@contract class C{ @external @pure rd(xs:Q[],i:u256,j:u256):u256{ return u256(u8(xs[i].b[j])); } }`,
      `contract C{ struct Q{bytes b;uint256 n;} function rd(Q[] calldata xs,uint256 i,uint256 j) external pure returns(uint256){ return uint256(uint8(xs[i].b[j])); } }`,
      [['rd((bytes,uint256)[],uint256,uint256)', W(0x60) + W(0) + W(0) + W(1) + W(0x20) + W(0x40) + W(7) + W(4) + '5758596000000000000000000000000000000000000000000000000000000000']] as const,
    );
    // the bind-a-local workaround stays byte-identical.
    await run(
      `@struct class Q{b:bytes;n:u256}
@contract class C{ @external @pure rd(xs:Q[],i:u256,j:u256):u256{ let al:bytes=xs[i].b; return u256(u8(al[j])); } }`,
      `contract C{ struct Q{bytes b;uint256 n;} function rd(Q[] calldata xs,uint256 i,uint256 j) external pure returns(uint256){ bytes memory al=xs[i].b; return uint256(uint8(al[j])); } }`,
      [['rd((bytes,uint256)[],uint256,uint256)', W(0x60) + W(0) + W(0) + W(1) + W(0x20) + W(0x40) + W(7) + W(4) + '5758596000000000000000000000000000000000000000000000000000000000']] as const,
    );
    // a plain calldata dyn-struct PARAM field byte read still works (object is an Identifier).
    await run(
      `@struct class Q{b:bytes;n:u256}
@contract class C{ @external @pure rd(d:Q,j:u256):u256{ return u256(u8(d.b[j])); } }`,
      `contract C{ struct Q{bytes b;uint256 n;} function rd(Q calldata d,uint256 j) external pure returns(uint256){ return uint256(uint8(d.b[j])); } }`,
      [['rd((bytes,uint256),uint256)', W(0x40) + W(0) + W(0x40) + W(4) + '5758596000000000000000000000000000000000000000000000000000000000']] as const,
    );
    // a calldata value-array field element (different resolver branch) still works.
    await run(
      `@struct class S{xs:u256[];n:u256}
@contract class C{ @external @pure rd(s:S,i:u256):u256{ return s.xs[i]; } }`,
      `contract C{ struct S{uint256[] xs;uint256 n;} function rd(S calldata s,uint256 i) external pure returns(uint256){ return s.xs[i]; } }`,
      [['rd((uint256[],uint256),uint256)', W(0x40) + W(0) + W(0x40) + W(2) + W(11) + W(12)]] as const,
    );
  });

  it('FUNCREF-NOTE-1: uninitialized funcref-bearing static struct local no longer crashes, byte-identical', async () => {
    // declaration-only compiles (no crash).
    expect(
      rejects(`@struct class Fd{f:(x:u256)=>u256}
@contract class C{ @external @pure g():u256{ let d:Fd; return 1n; } }`),
    ).toBe(false);
    // reassign then call is byte-identical; calling the UNINITIALIZED field reverts Panic 0x51 like solc.
    await run(
      `@struct class Fd{f:(x:u256)=>u256}
@contract class C{ inc(x:u256):u256{return x+1n;}
  @external @pure ok(v:u256):u256{ let d:Fd; d=Fd(this.inc); return d.f(v); }
  @external @pure panic(v:u256):u256{ let d:Fd; return d.f(v); } }`,
      `contract C{ struct Fd{function(uint256) pure returns(uint256) f;} function inc(uint256 x) internal pure returns(uint256){return x+1;}
  function ok(uint256 v) external pure returns(uint256){ Fd memory d; d=Fd(inc); return d.f(v); }
  function panic(uint256 v) external pure returns(uint256){ Fd memory d; return d.f(v); } }`,
      [['ok(uint256)', W(10)], ['panic(uint256)', W(10)]] as const,
    );
  });
});
