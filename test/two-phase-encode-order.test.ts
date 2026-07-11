// W7A: TWO-PHASE ABI encoding across every consumer (abi.encode / encodePacked /
// encodeWithSelector / encodeWithSignature, external tuple-literal returns, revert custom-error
// payloads, emit event data), matching solc 0.8.35's evaluation model:
//   phase 1 - components evaluate LEFT-TO-RIGHT to a VALUE (spilled at its position) or a
//   REFERENCE HANDLE (a live memory pointer / a frozen storage slot / a resolved calldata base);
//   phase 2 - serialization reads through the handles LATE, after every sibling's side effects
//   (memory mutations visible, storage re-read post-sibling, validation Panics at serialize time).
// Before W7A, JETH froze reference components at their own position (struct-ctor images, storage
// copies, the tuple-return pre-passes that hoisted whole component kinds ahead of their siblings)
// - a confirmed sibling-order MISCOMPILE family (~20 shapes, all flipped byte-identical here).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);

/** Differential run: JETH vs solc must agree on success + returndata + logs + slots 0..4. */
async function diff(J: string, S: string, calls: [string, string?][]): Promise<string[]> {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  const out: string[] = [];
  for (const [sg, args] of calls) {
    const data = sel(sg) + (args || '');
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
    expect(JSON.stringify(rj.logs), sg).toBe(JSON.stringify(rs.logs));
    for (let s = 0n; s < 5n; s++) {
      expect(await readSlot(h, aj, s), `${sg} slot ${s}`).toBe(await readSlot(h, as, s));
    }
    out.push(rj.returnHex);
  }
  return out;
}

const JT = `type T = { n: u256 };\ntype S = { a: u256; t: T };\n`;
const ST = `struct T { uint256 n; }\nstruct S { uint256 a; T t; }\n`;

describe('W7A: two-phase abi.encode* (handles at position, serialize late) vs solc 0.8.35', () => {
  it('plain memory struct + mutating later sibling encodes POST-mutation (A2)', async () => {
    const [r] = await diff(
      `${JT}class C {
        bump(t: T): u256 { t.n = 9n; return 7n; }
        get f(): External<bytes> { let t: T = T(5n); return abi.encode(t, this.bump(t)); } }`,
      `${ST}contract C {
        function bump(T memory t) internal pure returns (uint256) { t.n = 9; return 7; }
        function f() external pure returns (bytes memory) { T memory t = T(5); return abi.encode(t, bump(t)); } }`,
      [['f()']],
    );
    // NON-VACUITY: word 3 of the blob is t.n and must be the POST-bump 9, not the frozen 5.
    expect(r!.slice(2 + 64 * 2, 2 + 64 * 3)).toBe(pad32(9n));
  });

  it('struct-ctor component before AND after the sibling reads refs late (A1/A1b/A10)', async () => {
    await diff(
      `${JT}class C {
        bump(t: T): u256 { t.n = t.n + 4n; return 7n; }
        get a1(): External<bytes> { let t: T = T(5n); return abi.encode(S(1n, t), this.bump(t)); }
        get a1b(): External<bytes> { let t: T = T(5n); return abi.encode(this.bump(t), S(1n, t)); }
        get a10(): External<bytes> { let t: T = T(5n); let u: T = T(6n); return abi.encode(S(1n, t), this.bump(t), S(2n, u)); } }`,
      `${ST}contract C {
        function bump(T memory t) internal pure returns (uint256) { t.n = t.n + 4; return 7; }
        function a1() external pure returns (bytes memory) { T memory t = T(5); return abi.encode(S(1, t), bump(t)); }
        function a1b() external pure returns (bytes memory) { T memory t = T(5); return abi.encode(bump(t), S(1, t)); }
        function a10() external pure returns (bytes memory) { T memory t = T(5); T memory u = T(6); return abi.encode(S(1, t), bump(t), S(2, u)); } }`,
      [['a1()'], ['a1b()'], ['a10()']],
    );
  });

  it('dyn-struct ctor: string regrow + dyn-array field mutation through the captured ref (B3/B4)', async () => {
    await diff(
      `type T2 = { n: u256; s: string };
      type S2 = { a: u256; t: T2 };
      type S3 = { xs: u256[]; k: u256 };
      class C {
        grow(t: T2): u256 { t.s = "a-much-longer-string-payload-over-32-bytes!"; return 7n; }
        bump(xs: u256[]): u256 { xs[0n] = 9n; return 7n; }
        get g(): External<bytes> { let t: T2 = T2(5n, "x"); return abi.encode(S2(1n, t), this.grow(t)); }
        get h(): External<bytes> { let xs: u256[] = new Array<u256>(1n); xs[0n] = 5n; return abi.encode(S3(xs, 0n), this.bump(xs)); } }`,
      `struct T2 { uint256 n; string s; }
      struct S2 { uint256 a; T2 t; }
      struct S3 { uint256[] xs; uint256 k; }
      contract C {
        function grow(T2 memory t) internal pure returns (uint256) { t.s = "a-much-longer-string-payload-over-32-bytes!"; return 7; }
        function bump(uint256[] memory xs) internal pure returns (uint256) { xs[0] = 9; return 7; }
        function g() external pure returns (bytes memory) { T2 memory t = T2(5, "x"); return abi.encode(S2(1, t), grow(t)); }
        function h() external pure returns (bytes memory) { uint256[] memory xs = new uint256[](1); xs[0] = 5; return abi.encode(S3(xs, 0), bump(xs)); } }`,
      [['g()'], ['h()']],
    );
  });

  it('encodeWithSelector / encodeWithSignature follow the same two-phase order (F4/P13)', async () => {
    await diff(
      `${JT}class C {
        bump(t: T): u256 { t.n = 9n; return 7n; }
        get f(): External<bytes> { let t: T = T(5n); return abi.encodeWithSelector(0x11223344, S(1n, t), this.bump(t)); }
        get g(): External<bytes> { let t: T = T(5n); return abi.encodeWithSignature("g(uint256)", t, this.bump(t)); } }`,
      `${ST}contract C {
        function bump(T memory t) internal pure returns (uint256) { t.n = 9; return 7; }
        function f() external pure returns (bytes memory) { T memory t = T(5); return abi.encodeWithSelector(0x11223344, S(1, t), bump(t)); }
        function g() external pure returns (bytes memory) { T memory t = T(5); return abi.encodeWithSignature("g(uint256)", t, bump(t)); } }`,
      [['f()'], ['g()']],
    );
  });

  it('STORAGE components read post-sibling storage in encode AND packed (P1/P2/P7)', async () => {
    await diff(
      `type P2 = { x: u256; y: u256 };
      class C { sa: u256[]; p: P2;
        pushed(): u256 { this.sa.push(9n); return 7n; }
        wr(): u256 { this.p.x = 9n; return 7n; }
        f(): External<bytes> { this.sa.push(5n); return abi.encode(this.sa, this.pushed()); }
        g(): External<bytes> { this.p = P2(5n, 6n); return abi.encode(this.p, this.wr()); }
        h(): External<bytes> { this.sa.push(5n); return abi.encodePacked(this.sa, this.pushed()); } }`,
      `struct P2 { uint256 x; uint256 y; }
      contract C { uint256[] sa; P2 p;
        function pushed() internal returns (uint256) { sa.push(9); return 7; }
        function wr() internal returns (uint256) { p.x = 9; return 7; }
        function f() external returns (bytes memory) { sa.push(5); return abi.encode(sa, pushed()); }
        function g() external returns (bytes memory) { p = P2(5, 6); return abi.encode(p, wr()); }
        function h() external returns (bytes memory) { sa.push(5); return abi.encodePacked(sa, pushed()); } }`,
      [['f()'], ['g()'], ['h()']],
    );
  });

  it('a REVERTING later sibling wins over an earlier dirty-enum validation Panic (P11)', async () => {
    const [r] = await diff(
      `enum Color { Red, Green, Blue }
      class C {
        Boom: error<{}>;
        die(): u256 { revert(Boom()); }
        get f(a: Color[]): External<bytes> { const b: Color[] = a; return abi.encode(b, this.die()); } }`,
      `contract C {
        enum Color { Red, Green, Blue }
        error Boom();
        function die() internal pure returns (uint256) { revert Boom(); }
        function f(Color[] calldata a) external pure returns (bytes memory) { Color[] memory b = a; return abi.encode(b, die()); } }`,
      [
        [
          'f(uint8[])',
          pad32(0x20n) + pad32(1n) + pad32(255n), // ONE dirty (255) enum element
        ],
      ],
    );
    // NON-VACUITY: the revert data is Boom()'s selector, NOT Panic(0x21) - validation ran late.
    expect(r!.startsWith('0x' + functionSelector('Boom()'))).toBe(true);
  });
});

describe('W7A: two-phase external tuple-literal returns (the five pre-passes are gone)', () => {
  it('memory struct / dyn-struct local components read post-sibling (A3/P20/P21)', async () => {
    await diff(
      `${JT}type D = { s: string; n: u256 };
      class C {
        bump(t: T): u256 { t.n = 9n; return 7n; }
        grow(d: D): u256 { d.s = "a-much-longer-string-payload-over-32-bytes!"; return 7n; }
        get f(): External<[S, u256]> { let t: T = T(5n); return [S(1n, t), this.bump(t)]; }
        get g(): External<[T, u256]> { let t: T = T(5n); return [t, this.bump(t)]; }
        get h(): External<[D, u256]> { let d: D = D("x", 5n); return [d, this.grow(d)]; } }`,
      `${ST}struct D { string s; uint256 n; }
      contract C {
        function bump(T memory t) internal pure returns (uint256) { t.n = 9; return 7; }
        function grow(D memory d) internal pure returns (uint256) { d.s = "a-much-longer-string-payload-over-32-bytes!"; return 7; }
        function f() external pure returns (S memory, uint256) { T memory t = T(5); return (S(1, t), bump(t)); }
        function g() external pure returns (T memory, uint256) { T memory t = T(5); return (t, bump(t)); }
        function h() external pure returns (D memory, uint256) { D memory d = D("x", 5); return (d, grow(d)); } }`,
      [['f()'], ['g()'], ['h()']],
    );
  });

  it('the former pre-passes no longer hoist components ahead of earlier siblings (P14/P16/P17)', async () => {
    await diff(
      `type D = { s: string; n: u256 };
      class C { n: u256;
        bump(): u256 { this.n = this.n + 1n; return this.n; }
        f(): External<[u256, bytes]> { this.n = 5n; return [this.bump(), abi.encode(this.n)]; }
        g(): External<[u256, D]> { this.n = 5n; return [this.bump(), D("q", this.n)]; }
        h(c: bool): External<[u256, u256[]]> { this.n = 5n; return [this.bump(), c ? [this.n] : [9n]]; } }`,
      `struct D { string s; uint256 n; }
      contract C { uint256 n;
        function bump() internal returns (uint256) { n = n + 1; return n; }
        function f() external returns (uint256, bytes memory) { n = 5; return (bump(), abi.encode(n)); }
        function g() external returns (uint256, D memory) { n = 5; return (bump(), D("q", n)); }
        function h(bool c) external returns (uint256, uint256[] memory) { n = 5;
          uint256 b = bump();
          uint256[] memory x = new uint256[](1);
          if (c) { x[0] = n; } else { x[0] = 9; }
          return (b, x); } }`,
      [['f()'], ['g()'], ['h(bool)', pad32(1n)]],
    );
  });

  it('STORAGE tuple components (dyn array / struct / fixed array) read POST-sibling (P3/P4/P19)', async () => {
    const [f] = await diff(
      `type P2 = { x: u256; y: u256 };
      class C { sa: u256[]; p: P2; fa: Arr<u256, 2>;
        pushed(): u256 { this.sa.push(9n); return 7n; }
        wr(): u256 { this.p.x = 9n; return 7n; }
        wf(): u256 { this.fa[0n] = 9n; return 7n; }
        f(): External<[u256[], u256]> { this.sa.push(5n); return [this.sa, this.pushed()]; }
        g(): External<[P2, u256]> { this.p = P2(5n, 6n); return [this.p, this.wr()]; }
        h(): External<[Arr<u256, 2>, u256]> { this.fa[0n] = 5n; return [this.fa, this.wf()]; } }`,
      `struct P2 { uint256 x; uint256 y; }
      contract C { uint256[] sa; P2 p; uint256[2] fa;
        function pushed() internal returns (uint256) { sa.push(9); return 7; }
        function wr() internal returns (uint256) { p.x = 9; return 7; }
        function wf() internal returns (uint256) { fa[0] = 9; return 7; }
        function f() external returns (uint256[] memory, uint256) { sa.push(5); return (sa, pushed()); }
        function g() external returns (P2 memory, uint256) { p = P2(5, 6); return (p, wr()); }
        function h() external returns (uint256[2] memory, uint256) { fa[0] = 5; return (fa, wf()); } }`,
      [['f()'], ['g()'], ['h()']],
    );
    // NON-VACUITY: f() returns the POST-push array [5, 9] (length 2), not the pre-push [5].
    expect(f!.slice(2 + 64 * 2, 2 + 64 * 3)).toBe(pad32(2n));
  });

  it('STORAGE bytes/string FIELD tuple components read POST-sibling (refs pre-pass, both orderings)', async () => {
    // A storage bytes/string FIELD as a tuple component alongside a mutating sibling: the value must be
    // snapshotted at serialize time (after the sibling), exactly like the dyn-array/struct components above.
    // Covers both orderings and a >31-byte (multi-slot) string regrow. bf is slot 0, s is slot 1.
    const [f, g] = await diff(
      `class C { bf: bytes; s: string;
        mutB(): u256 { this.bf = bytes("changed"); return 7n; }
        mutS(): u256 { this.s = "a-much-longer-string-than-before!!"; return 8n; }
        f(): External<[bytes, u256]> { this.bf = bytes("aa"); return [this.bf, this.mutB()]; }
        g(): External<[u256, string]> { this.s = "hi"; return [this.mutS(), this.s]; } }`,
      `contract C { bytes bf; string s;
        function mutB() internal returns (uint256) { bf = "changed"; return 7; }
        function mutS() internal returns (uint256) { s = "a-much-longer-string-than-before!!"; return 8; }
        function f() external returns (bytes memory, uint256) { bf = "aa"; return (bf, mutB()); }
        function g() external returns (uint256, string memory) { s = "hi"; return (mutS(), s); } }`,
      [['f()'], ['g()']],
    );
    // NON-VACUITY: f()'s bytes component is the POST-mutation "changed" (len 7), not the frozen "aa" (len 2).
    expect(f!.slice(2 + 64 * 2, 2 + 64 * 3)).toBe(pad32(7n));
    // g()'s string component (after the u256) is the POST-mutation 34-byte value, not "hi" (len 2).
    expect(g!.slice(2 + 64 * 2, 2 + 64 * 3)).toBe(pad32(34n));
  });
});

describe('W7A: two-phase emit data / revert custom-error payloads', () => {
  it('event DATA components serialize after all args; topics still hash eagerly (A9/P5/F3)', async () => {
    await diff(
      `${JT}class C { sa: u256[];
        E: event<{ s: S; k: u256 }>;
        Ei: event<{ s: indexed<S>; k: u256 }>;
        Ea: event<{ xs: u256[]; k: u256 }>;
        bump(t: T): u256 { t.n = 9n; return 7n; }
        pushed(): u256 { this.sa.push(9n); return 7n; }
        f(): External<u256> { let t: T = T(5n); emit(E(S(1n, t), this.bump(t))); return 1n; }
        g(): External<u256> { let t: T = T(5n); emit(Ei(S(1n, t), this.bump(t))); return 1n; }
        h(): External<u256> { this.sa.push(5n); emit(Ea(this.sa, this.pushed())); return 1n; } }`,
      `${ST}contract C { uint256[] sa;
        event E(S s, uint256 k);
        event Ei(S indexed s, uint256 k);
        event Ea(uint256[] xs, uint256 k);
        function bump(T memory t) internal pure returns (uint256) { t.n = 9; return 7; }
        function pushed() internal returns (uint256) { sa.push(9); return 7; }
        function f() external returns (uint256) { T memory t = T(5); emit E(S(1, t), bump(t)); return 1; }
        function g() external returns (uint256) { T memory t = T(5); emit Ei(S(1, t), bump(t)); return 1; }
        function h() external returns (uint256) { sa.push(5); emit Ea(sa, pushed()); return 1; } }`,
      [['f()'], ['g()'], ['h()']],
    );
  });

  it('revert payload components serialize after all args (A4/P6)', async () => {
    await diff(
      `${JT}class C { sa: u256[];
        E: error<{ s: S; k: u256 }>;
        Ea: error<{ xs: u256[]; k: u256 }>;
        bump(t: T): u256 { t.n = 9n; return 7n; }
        pushed(): u256 { this.sa.push(9n); return 7n; }
        get f(): External<u256> { let t: T = T(5n); revert(E(S(1n, t), this.bump(t))); }
        g(): External<u256> { this.sa.push(5n); revert(Ea(this.sa, this.pushed())); } }`,
      `${ST}contract C { uint256[] sa;
        error E(S s, uint256 k);
        error Ea(uint256[] xs, uint256 k);
        function bump(T memory t) internal pure returns (uint256) { t.n = 9; return 7; }
        function pushed() internal returns (uint256) { sa.push(9); return 7; }
        function f() external pure returns (uint256) { T memory t = T(5); revert E(S(1, t), bump(t)); }
        function g() external returns (uint256) { sa.push(5); revert Ea(sa, pushed()); } }`,
      [['f()'], ['g()']],
    );
  });
});
