// Three pre-existing calldata dyn-struct divergences, fixed byte-identical to solc 0.8.35. The crux is
// the CONTEXT SPLIT: a malformed inner length/offset in a calldata dyn-struct field produces DIFFERENT
// revert flavors depending on the consumer context (all probe-verified vs solc 0.8.35):
//   - BIND / abi_decode-to-memory  (let m: R = p)      -> Panic 0x41 (solc's memory allocation guard).
//   - abi.encode(p) / emit E(p) / revert Er(p) RE-ENCODE -> EMPTY revert (ABI-decode-failure flavor).
//   - RETURN-ECHO (return p)                             -> Panic 0x41 (unchanged; already matched solc).
// DIVERGENCE 1: BIND with a huge inner string/bytes/u256[] length used to revert EMPTY; now Panics 0x41.
// DIVERGENCE 2: abi.encode/emit/error of a bytes/string field with a huge inner length used to Panic
//   0x41; now reverts EMPTY. DIVERGENCE 3: a NESTED-DYNAMIC-STRUCT field bind (let m: S = p, S{a; t:T},
//   T{s:string}) used to crash JETH900 on VALID input; now decodes byte-identically (and its malformed
//   flavor follows divergences 1/2). WELL-FORMED round-trips are the non-vacuity anchor.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => pad32(n);
const MAX = (2n ** 256n) - 1n;
const HUGE64 = 0x10000000000000000n;
const SIGNBIT = 1n << 255n;

async function diff(J: string, S: string, calls: [string, string][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sig, args] of calls) {
    const data = sel(sig) + args;
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sig + ' ' + args.slice(0, 20)).toBe(rs.success);
    expect(rj.returnHex, sig + ' ' + args.slice(0, 20)).toBe(rs.returnHex);
  }
}

// well-formed tail builders -----------------------------------------------------------------
const encBytes = (hex: string) => W(BigInt(hex.length / 2)) + hex.padEnd(Math.ceil(hex.length / 64) * 64, '0');

describe('calldata dyn-struct revert-flavor context split vs solc 0.8.35', () => {
  // --- DIVERGENCE 1: BIND (let m = p) huge inner length -> Panic 0x41 ---
  it('D1: string-field bind Panics 0x41 on huge len; well-formed round-trips; trunc/OOB empty', async () => {
    const J = `@struct class R { s: string; n: u256; }
      @contract class C { @external @pure f(p: R): bytes { let m: R = p; return abi.encode(m); } }`;
    const S = `struct R { string s; uint256 n; }
      contract C { function f(R calldata p) external pure returns(bytes memory){ R memory m = p; return abi.encode(m); } }`;
    const sig = 'f((string,uint256))';
    const wf = W(0x40n) + W(99n) + encBytes('616263'); // "abc", n=99
    await diff(J, S, [
      [sig, W(0x20n) + wf], // well-formed (non-vacuity: decodes "abc" + 99)
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(MAX)], // huge len 2^256-1 -> Panic 0x41
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(HUGE64)], // huge len 2^64 -> Panic 0x41
      [sig, (W(0x20n) + wf).slice(0, -64)], // truncated -> empty
      [sig, W(0x20n) + W(0xff00n) + W(99n) + encBytes('616263')], // OOB offset -> empty
      [sig, W(0x20n) + W(SIGNBIT | 0x40n) + W(99n) + encBytes('616263')], // sign-bit offset -> empty
    ]);
  });

  it('D1: bytes-field and u256[]-field bind Panic 0x41 on huge len; well-formed round-trips', async () => {
    const Jb = `@struct class R { x: u256; bs: bytes; }
      @contract class C { @external @pure f(p: R): bytes { let m: R = p; return abi.encode(m); } }`;
    const Sb = `struct R { uint256 x; bytes bs; }
      contract C { function f(R calldata p) external pure returns(bytes memory){ R memory m = p; return abi.encode(m); } }`;
    const sigB = 'f((uint256,bytes))';
    await diff(Jb, Sb, [
      [sigB, W(0x20n) + W(7n) + W(0x40n) + encBytes('deadbeef')], // wf
      [sigB, W(0x20n) + W(7n) + W(0x40n) + W(MAX)], // huge -> Panic 0x41
      [sigB, W(0x20n) + W(7n) + W(0x40n) + W(HUGE64)], // huge -> Panic 0x41
      [sigB, (W(0x20n) + W(7n) + W(0x40n) + encBytes('deadbeef')).slice(0, -64)], // trunc -> empty
    ]);

    const Ja = `@struct class R { x: u256; xs: u256[]; }
      @contract class C { @external @pure f(p: R): bytes { let m: R = p; return abi.encode(m); } }`;
    const Sa = `struct R { uint256 x; uint256[] xs; }
      contract C { function f(R calldata p) external pure returns(bytes memory){ R memory m = p; return abi.encode(m); } }`;
    const sigA = 'f((uint256,uint256[]))';
    await diff(Ja, Sa, [
      [sigA, W(0x20n) + W(7n) + W(0x40n) + W(2n) + W(11n) + W(22n)], // wf
      [sigA, W(0x20n) + W(7n) + W(0x40n) + W(MAX)], // huge -> Panic 0x41
      [sigA, W(0x20n) + W(7n) + W(0x40n) + W(HUGE64)], // huge -> Panic 0x41
      [sigA, (W(0x20n) + W(7n) + W(0x40n) + W(2n) + W(11n) + W(22n)).slice(0, -64)], // trunc -> empty
    ]);
  });

  // --- DIVERGENCE 1 (completion): the SIZE-based BIND allocation cap, at solc's EXACT flip length ---
  // solc's abi_decode allocates each dynamic field via array_allocation_size = add(0x20, mul(len, stride))
  // (value array) or add(0x20, round_up(len)) (bytes/string) then finalize_allocation, which Panics 0x41 the
  // moment the resulting free pointer add(freePtr, allocSize) exceeds 0xffffffffffffffff - NOT at len = 2^64.
  // For R{first; n} the memory struct head is 2 words, so freePtr at the field alloc = 0xc0 (== JETH's). The
  // EXACT flip is therefore MUCH earlier than 2^64 for a wide element (probe-verified vs solc 0.8.35). These
  // pins assert JETH Panics 0x41 at solc's exact flip and empty-reverts just below (where solc does too).
  it('D1(size): u256[] bind Panics 0x41 at solc EXACT flip; empty just below; well-formed anchor', async () => {
    const J = `@struct class R { xs: u256[]; n: u256; }
      @contract class C { @external @pure f(p: R): bytes { let m: R = p; return abi.encode(m); } }`;
    const S = `struct R { uint256[] xs; uint256 n; }
      contract C { function f(R calldata p) external pure returns(bytes memory){ R memory m = p; return abi.encode(m); } }`;
    const sig = 'f((uint256[],uint256))';
    // stride 0x20, freePtr 0xc0: Panic when 0xc0 + 0x20 + len*0x20 > 2^64-1  <=>  len >= 576460752303423481.
    const FLIP = 576460752303423481n;
    await diff(J, S, [
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(3n) + W(11n) + W(22n) + W(33n)], // well-formed (non-vacuity)
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(FLIP)], // AT solc's exact flip -> Panic 0x41
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(FLIP - 1n)], // just below -> EMPTY (solc allocs fine, then OOB)
    ]);
    // context-split preservation: the SAME flip length in the RE-ENCODE context (abi.encode(p), no bind)
    // must stay EMPTY, not Panic (divergence-2). freePtr differs but the encode context caps empty either way.
    const Je = `@struct class R { xs: u256[]; n: u256; }
      @contract class C { @external @pure f(p: R): bytes { return abi.encode(p); } }`;
    const Se = `struct R { uint256[] xs; uint256 n; }
      contract C { function f(R calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`;
    await diff(Je, Se, [
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(3n) + W(11n) + W(22n) + W(33n)], // well-formed
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(FLIP)], // RE-ENCODE at flip -> EMPTY (not Panic)
    ]);
  });

  it('D1(size): string bind Panics 0x41 at solc EXACT flip; empty just below; well-formed anchor', async () => {
    const J = `@struct class R { s: string; n: u256; }
      @contract class C { @external @pure f(p: R): bytes { let m: R = p; return abi.encode(m); } }`;
    const S = `struct R { string s; uint256 n; }
      contract C { function f(R calldata p) external pure returns(bytes memory){ R memory m = p; return abi.encode(m); } }`;
    const sig = 'f((string,uint256))';
    // bytes/string: alloc = 0x20 + round_up(len); freePtr 0xc0: Panic when 0xc0 + 0x20 + round_up(len) > 2^64-1
    // <=> round_up(len) >= 2^64 - 224, i.e. len >= 2^64 - 255 = 18446744073709551361.
    const FLIP = 18446744073709551361n;
    await diff(J, S, [
      [sig, W(0x20n) + W(0x40n) + W(99n) + encBytes('616263')], // well-formed (non-vacuity)
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(FLIP)], // AT solc's exact flip -> Panic 0x41
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(FLIP - 1n)], // just below -> EMPTY
    ]);
  });

  // --- DIVERGENCE 2: abi.encode / emit / error huge inner length -> EMPTY ---
  it('D2: abi.encode of string/bytes field empty-reverts on huge len; well-formed round-trips', async () => {
    const Js = `@struct class R { s: string; n: u256; }
      @contract class C { @external @pure f(p: R): bytes { return abi.encode(p); } }`;
    const Ss = `struct R { string s; uint256 n; }
      contract C { function f(R calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`;
    const sig = 'f((string,uint256))';
    await diff(Js, Ss, [
      [sig, W(0x20n) + W(0x40n) + W(99n) + encBytes('616263')], // wf
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(MAX)], // huge -> EMPTY
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(HUGE64)], // huge -> EMPTY
    ]);

    const Jb = `@struct class R { x: u256; bs: bytes; }
      @contract class C { @external @pure f(p: R): bytes { return abi.encode(p); } }`;
    const Sb = `struct R { uint256 x; bytes bs; }
      contract C { function f(R calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`;
    const sigB = 'f((uint256,bytes))';
    await diff(Jb, Sb, [
      [sigB, W(0x20n) + W(7n) + W(0x40n) + encBytes('deadbeef')], // wf
      [sigB, W(0x20n) + W(7n) + W(0x40n) + W(MAX)], // huge -> EMPTY
    ]);
  });

  it('D2: emit E(p) and revert Er(p) empty-revert on huge len; well-formed emits/reverts match', async () => {
    const Jemit = `@contract class C { @event E(p: R); @external f(p: R): void { emit(E(p)); } }
      @struct class R { s: string; n: u256; }`;
    const Semit = `struct R { string s; uint256 n; }
      contract C { event E(R p); function f(R calldata p) external { emit E(p); } }`;
    const sig = 'f((string,uint256))';
    await diff(Jemit, Semit, [
      [sig, W(0x20n) + W(0x40n) + W(99n) + encBytes('616263')], // wf (log data byte-identical)
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(MAX)], // huge -> EMPTY
    ]);

    const Jerr = `@contract class C { @error Er(p: R); @external @pure f(p: R): void { revert(Er(p)); } }
      @struct class R { s: string; n: u256; }`;
    const Serr = `struct R { string s; uint256 n; }
      contract C { error Er(R p); function f(R calldata p) external pure { revert Er(p); } }`;
    await diff(Jerr, Serr, [
      [sig, W(0x20n) + W(0x40n) + W(99n) + encBytes('616263')], // wf (error revert data byte-identical)
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(MAX)], // huge -> EMPTY
    ]);
  });

  // --- RETURN-ECHO unchanged (Panic 0x41 on huge, well-formed echo byte-identical) ---
  it('D0: return-echo of a whole cd dyn-struct Panics 0x41 on huge len (unregressed)', async () => {
    const J = `@struct class R { s: string; n: u256; }
      @contract class C { @external @pure f(p: R): R { return p; } }`;
    const S = `struct R { string s; uint256 n; }
      contract C { function f(R calldata p) external pure returns(R memory){ return p; } }`;
    const sig = 'f((string,uint256))';
    await diff(J, S, [
      [sig, W(0x20n) + W(0x40n) + W(99n) + encBytes('616263')], // wf echo
      [sig, W(0x20n) + W(0x40n) + W(99n) + W(MAX)], // huge -> Panic 0x41 (return-echo)
    ]);
  });

  // --- DIVERGENCE 3: nested-dyn-struct field bind (was JETH900 on VALID input) ---
  it('D3: nested-dyn-struct field bind decodes byte-identically; malformed follows the split', async () => {
    const J = `@struct class T { s: string; n: u256; }
      @struct class S { a: u256; t: T; }
      @contract class C {
        @external @pure ea(p: S): u256 { let m: S = p; return m.a + m.t.n; }
        @external @pure et(p: S): bytes { let m: S = p; return abi.encode(m.t); }
        @external @pure em(p: S): bytes { let m: S = p; return abi.encode(m); }
      }`;
    const S = `struct T { string s; uint256 n; }
      struct S { uint256 a; T t; }
      contract C {
        function ea(S calldata p) external pure returns(uint256){ S memory m = p; return m.a + m.t.n; }
        function et(S calldata p) external pure returns(bytes memory){ S memory m = p; return abi.encode(m.t); }
        function em(S calldata p) external pure returns(bytes memory){ S memory m = p; return abi.encode(m); }
      }`;
    // layout: [a][off_t=0x40] t:[off_s=0x40][n][len_s][data_s]
    const wf = W(0x20n) + W(5n) + W(0x40n) + (W(0x40n) + W(77n) + encBytes('616263'));
    const huge = W(0x20n) + W(5n) + W(0x40n) + (W(0x40n) + W(77n) + W(MAX));
    const trunc = wf.slice(0, -64);
    const oobOffS = W(0x20n) + W(5n) + W(0x40n) + (W(0xff00n) + W(77n) + encBytes('616263'));
    for (const nm of ['ea', 'et', 'em']) {
      const sig = `${nm}((uint256,(string,uint256)))`;
      await diff(J, S, [
        [sig, wf], // well-formed element reads / re-encode (non-vacuity)
        [sig, huge], // BIND huge inner len -> Panic 0x41
        [sig, trunc], // truncated -> empty
        [sig, oobOffS], // OOB inner offset -> empty
      ]);
    }
  });

  it('D3: nested-dyn-struct field abi.encode(p) empty-reverts on huge len; multi-level + value-array nesting', async () => {
    // encode(p) whole-struct: huge inner length -> EMPTY (re-encode flavor)
    const Je = `@struct class T { s: string; n: u256; }
      @struct class S { a: u256; t: T; }
      @contract class C { @external @pure f(p: S): bytes { return abi.encode(p); } }`;
    const Se = `struct T { string s; uint256 n; }
      struct S { uint256 a; T t; }
      contract C { function f(S calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`;
    const sig = 'f((uint256,(string,uint256)))';
    const wf = W(0x20n) + W(5n) + W(0x40n) + (W(0x40n) + W(77n) + encBytes('616263'));
    const huge = W(0x20n) + W(5n) + W(0x40n) + (W(0x40n) + W(77n) + W(MAX));
    await diff(Je, Se, [
      [sig, wf], // wf
      [sig, huge], // huge -> EMPTY (encode context)
    ]);

    // MULTI-LEVEL: S{a; t:T}, T{u:U; k:u256}, U{s:string}
    const Jm = `@struct class U { s: string; }
      @struct class T { u: U; k: u256; }
      @struct class S { a: u256; t: T; }
      @contract class C {
        @external @pure em(p: S): bytes { let m: S = p; return abi.encode(m); }
        @external @pure eu(p: S): bytes { let m: S = p; return abi.encode(m.t.u); }
        @external @pure ek(p: S): u256 { let m: S = p; return m.a + m.t.k; }
      }`;
    const Sm = `struct U { string s; }
      struct T { U u; uint256 k; }
      struct S { uint256 a; T t; }
      contract C {
        function em(S calldata p) external pure returns(bytes memory){ S memory m = p; return abi.encode(m); }
        function eu(S calldata p) external pure returns(bytes memory){ S memory m = p; return abi.encode(m.t.u); }
        function ek(S calldata p) external pure returns(uint256){ S memory m = p; return m.a + m.t.k; }
      }`;
    // [a][off_t=0x40] t:[off_u=0x40][k] u:[off_s=0x20][len][data]
    const mwf = W(0x20n) + W(5n) + W(0x40n) + (W(0x40n) + W(9n) + (W(0x20n) + encBytes('616263')));
    const mhuge = W(0x20n) + W(5n) + W(0x40n) + (W(0x40n) + W(9n) + (W(0x20n) + W(MAX)));
    for (const nm of ['em', 'eu', 'ek']) {
      const s = `${nm}((uint256,((string),uint256)))`;
      await diff(Jm, Sm, [
        [s, mwf], // multi-level well-formed
        [s, mhuge], // multi-level huge bind -> Panic 0x41
      ]);
    }

    // NESTED struct with a value-array field: S{a; t:T}, T{xs:u256[]; n:u256}
    const Ja = `@struct class T { xs: u256[]; n: u256; }
      @struct class S { a: u256; t: T; }
      @contract class C {
        @external @pure em(p: S): bytes { let m: S = p; return abi.encode(m); }
        @external @pure el(p: S): u256 { let m: S = p; return m.t.xs.length + m.t.xs[0n] + m.t.n; }
      }`;
    const Sa = `struct T { uint256[] xs; uint256 n; }
      struct S { uint256 a; T t; }
      contract C {
        function em(S calldata p) external pure returns(bytes memory){ S memory m = p; return abi.encode(m); }
        function el(S calldata p) external pure returns(uint256){ S memory m = p; return m.t.xs.length + m.t.xs[0] + m.t.n; }
      }`;
    const awf = W(0x20n) + W(5n) + W(0x40n) + (W(0x40n) + W(77n) + W(2n) + W(11n) + W(22n));
    const ahuge = W(0x20n) + W(5n) + W(0x40n) + (W(0x40n) + W(77n) + W(MAX));
    for (const nm of ['em', 'el']) {
      const s = `${nm}((uint256,(uint256[],uint256)))`;
      await diff(Ja, Sa, [
        [s, awf], // nested value-array well-formed (non-vacuity: reads m.t.xs[0])
        [s, ahuge], // nested value-array huge count bind -> Panic 0x41
      ]);
    }
  });
});
