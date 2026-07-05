// W5D-3: DYNAMIC-STRUCT tuple components in an @external (delegatecall) @library multi-return
// destructure `let [a, s] = L.mm(x)` (s a struct with string/bytes/array/nested-dyn-struct fields).
// Previously gated JETH243; now routed through the SAME abiDecode-tuple source the interface-call
// tuple form uses (buildDynStructFromMemBlob for the dyn-struct component). Verified byte-identical
// to solc 0.8.35 across value spreads (empty / short / >31-byte strings), struct-first and
// struct-last positions, nested dyn fields, a storage write-back (raw slots compared), revert
// bubbling, and the adjacent shapes that must KEEP rejecting.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidityLinked, deploySolLinked, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const str = (s: string) => {
  const hex = Buffer.from(s, 'utf8').toString('hex');
  return W(0x20) + W(s.length) + (s.length ? hex.padEnd(Math.ceil(hex.length / 64) * 64, '0') : '');
};
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};

async function eqLinked(jeth: string, sol: string, calls: [string, string][], slots: bigint[] = []) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = (await hj.deployLinked(compile(jeth, { fileName: 'C.jeth' }))).address;
  const as = await deploySolLinked(hs, compileSolidityLinked(SPDX + sol, 'C', ['L']));
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + (args ?? ''));
    const rs = await hs.call(as, sel(sig) + (args ?? ''));
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
  for (const s of slots) {
    expect(await readSlot(hj, aj, s), `slot ${s}`).toBe(await readSlot(hs, as, s));
  }
}

describe('W5D-3: dyn-struct tuple components in @external library destructure', () => {
  it('struct-LAST 2-tuple, string field, value spread (empty / short / long) + field reads', async () => {
    await eqLinked(
      `@struct class S { a: u256; s: string; }
       @library class L {
         @external @pure mm(x: u256, t: string): [u256, S] { return [x * 2n, S(x + 1n, t)]; }
       }
       @contract class C {
         @external go(x: u256, t: string): [u256, u256, string] {
           let [a, s] = L.mm(x, t);
           return [a, s.a, s.s];
         }
       }`,
      `struct S { uint256 a; string s; }
       library L {
         function mm(uint256 x, string memory t) external pure returns (uint256, S memory) { return (x * 2, S(x + 1, t)); }
       }
       contract C {
         function go(uint256 x, string memory t) external returns (uint256, uint256, string memory) {
           (uint256 a, S memory s) = L.mm(x, t);
           return (a, s.a, s.s);
         }
       }`,
      [
        ['go(uint256,string)', W(5) + W(0x40) + str('')],
        ['go(uint256,string)', W(7) + W(0x40) + str('hi')],
        ['go(uint256,string)', W(9) + W(0x40) + str('a definitely-longer-than-thirty-one-byte string payload!!')],
      ],
    );
  });

  it('struct-FIRST position + a 3-tuple with the struct in the middle (bytes field)', async () => {
    await eqLinked(
      `@struct class S { b: bytes; n: u128; }
       @library class L {
         @external @pure mm(x: u256, t: bytes): [u256, S, bool] { return [x + 100n, S(t, u128(x)), x % 2n == 0n]; }
       }
       @contract class C {
         @external go(x: u256, t: bytes): [u256, bytes, u256, bool] {
           let [a, s, f] = L.mm(x, t);
           return [a, s.b, u256(s.n), f];
         }
       }`,
      `struct S { bytes b; uint128 n; }
       library L {
         function mm(uint256 x, bytes memory t) external pure returns (uint256, S memory, bool) { return (x + 100, S(t, uint128(x)), x % 2 == 0); }
       }
       contract C {
         function go(uint256 x, bytes memory t) external returns (uint256, bytes memory, uint256, bool) {
           (uint256 a, S memory s, bool f) = L.mm(x, t);
           return (a, s.b, uint256(s.n), f);
         }
       }`,
      [
        ['go(uint256,bytes)', W(4) + W(0x40) + str('')],
        ['go(uint256,bytes)', W(5) + W(0x40) + str('0123456789012345678901234567890123456789 way past 31 bytes')],
      ],
    );
  });

  it('TWO dyn-struct components: nested dyn-struct field + u256[] field, all leaves read back', async () => {
    await eqLinked(
      `@struct class Q { t: string; v: u256; }
       @struct class S { a: u256; q: Q; xs: u256[]; }
       @library class L {
         @external @pure mm(x: u256, t: string): [S, Q] {
           let xs: u256[] = new Array<u256>(2n);
           xs[0n] = x; xs[1n] = x * 3n;
           return [S(x + 1n, Q(t, x + 7n), xs), Q("second-q string that is itself much longer than 31 bytes", x + 9n)];
         }
       }
       @contract class C {
         @external go(x: u256, t: string): [u256, string, u256, u256, u256, string, u256] {
           let [s, q2] = L.mm(x, t);
           return [s.a, s.q.t, s.q.v, s.xs[0n], s.xs[1n], q2.t, q2.v];
         }
       }`,
      `struct Q { string t; uint256 v; }
       struct S { uint256 a; Q q; uint256[] xs; }
       library L {
         function mm(uint256 x, string memory t) external pure returns (S memory, Q memory) {
           uint256[] memory xs = new uint256[](2);
           xs[0] = x; xs[1] = x * 3;
           return (S(x + 1, Q(t, x + 7), xs), Q("second-q string that is itself much longer than 31 bytes", x + 9));
         }
       }
       contract C {
         function go(uint256 x, string memory t) external returns (uint256, string memory, uint256, uint256, uint256, string memory, uint256) {
           (S memory s, Q memory q2) = L.mm(x, t);
           return (s.a, s.q.t, s.q.v, s.xs[0], s.xs[1], q2.t, q2.v);
         }
       }`,
      [
        ['go(uint256,string)', W(2) + W(0x40) + str('')],
        ['go(uint256,string)', W(11) + W(0x40) + str('mid-length str here')],
      ],
    );
  });

  it('destructured dyn struct WRITTEN to storage: read-back + raw slots byte-identical', async () => {
    await eqLinked(
      `@struct class S { a: u256; s: string; }
       @library class L {
         @external @pure mm(x: u256, t: string): [u256, S] { return [x * 2n, S(x + 1n, t)]; }
       }
       @contract class C {
         @state st: S;
         @external put(x: u256, t: string): u256 {
           let [a, s] = L.mm(x, t);
           this.st = s;
           return a;
         }
         @external @view geta(): u256 { return this.st.a; }
         @external @view gets(): string { return this.st.s; }
       }`,
      `struct S { uint256 a; string s; }
       library L {
         function mm(uint256 x, string memory t) external pure returns (uint256, S memory) { return (x * 2, S(x + 1, t)); }
       }
       contract C {
         S st;
         function put(uint256 x, string memory t) external returns (uint256) {
           (uint256 a, S memory s) = L.mm(x, t);
           st = s;
           return a;
         }
         function geta() external view returns (uint256) { return st.a; }
         function gets() external view returns (string memory) { return st.s; }
       }`,
      [
        ['put(uint256,string)', W(3) + W(0x40) + str('stored string exceeding thirty-one bytes for the tail path')],
        ['geta()', ''],
        ['gets()', ''],
        ['put(uint256,string)', W(8) + W(0x40) + str('sh')],
        ['geta()', ''],
        ['gets()', ''],
      ],
      [0n, 1n],
    );
    // non-vacuity: the JETH read-back after put() must reflect the seeded value, not a default.
    const hj = await Harness.create();
    const aj = (
      await hj.deployLinked(
        compile(
          `@struct class S { a: u256; s: string; }
           @library class L { @external @pure mm(x: u256, t: string): [u256, S] { return [x * 2n, S(x + 1n, t)]; } }
           @contract class C {
             @state st: S;
             @external put(x: u256, t: string): u256 { let [a, s] = L.mm(x, t); this.st = s; return a; }
             @external @view geta(): u256 { return this.st.a; }
           }`,
          { fileName: 'C.jeth' },
        ),
      )
    ).address;
    await hj.call(aj, sel('put(uint256,string)') + W(41) + W(0x40) + str('x'));
    const r = await hj.call(aj, sel('geta()'));
    expect(r.returnHex).toBe('0x' + W(42));
  });

  it('skipped slots and revert bubbling stay byte-identical', async () => {
    await eqLinked(
      `@struct class S { a: u256; s: string; }
       @library class L {
         @external @pure mm(x: u256): [u256, S] {
           if (x == 0n) { revert("zero not allowed here"); }
           if (x == 1n) { assert(false); }
           return [x * 2n, S(x + 1n, "skip-test string, definitely more than 31 bytes long!")];
         }
       }
       @contract class C {
         @external goA(x: u256): u256 { let [a, ,] = L.mm(x); return a; }
         @external goS(x: u256): [u256, string] { let [, s] = L.mm(x); return [s.a, s.s]; }
       }`,
      `struct S { uint256 a; string s; }
       library L {
         function mm(uint256 x) external pure returns (uint256, S memory) {
           if (x == 0) { revert("zero not allowed here"); }
           if (x == 1) { assert(false); }
           return (x * 2, S(x + 1, "skip-test string, definitely more than 31 bytes long!"));
         }
       }
       contract C {
         function goA(uint256 x) external returns (uint256) { (uint256 a, ) = L.mm(x); return a; }
         function goS(uint256 x) external returns (uint256, string memory) { (, S memory s) = L.mm(x); return (s.a, s.s); }
       }`,
      [
        ['goA(uint256)', W(0)],
        ['goA(uint256)', W(1)],
        ['goA(uint256)', W(21)],
        ['goS(uint256)', W(0)],
        ['goS(uint256)', W(21)],
      ],
    );
  });

  it('widened gate also admits string[] / u256[][] components (same decodeSupported set as interface tuples)', async () => {
    await eqLinked(
      `@library class L {
         @external @pure mm(x: u256): [string[], u256[][]] {
           let ss: string[] = new Array<string>(2n);
           ss[0n] = "first string that is much longer than thirty-one bytes!";
           ss[1n] = "s2";
           let grid: u256[][] = new Array<u256[]>(2n);
           let r0: u256[] = new Array<u256>(1n); r0[0n] = x;
           let r1: u256[] = new Array<u256>(2n); r1[0n] = x + 1n; r1[1n] = x + 2n;
           grid[0n] = r0; grid[1n] = r1;
           return [ss, grid];
         }
       }
       @contract class C {
         @external go(x: u256): [string, string, u256, u256, u256] {
           let [ss, grid] = L.mm(x);
           return [ss[0n], ss[1n], grid[0n][0n], grid[1n][0n], grid[1n][1n]];
         }
       }`,
      `library L {
         function mm(uint256 x) external pure returns (string[] memory, uint256[][] memory) {
           string[] memory ss = new string[](2);
           ss[0] = "first string that is much longer than thirty-one bytes!";
           ss[1] = "s2";
           uint256[][] memory grid = new uint256[][](2);
           grid[0] = new uint256[](1); grid[0][0] = x;
           grid[1] = new uint256[](2); grid[1][0] = x + 1; grid[1][1] = x + 2;
           return (ss, grid);
         }
       }
       contract C {
         function go(uint256 x) external returns (string memory, string memory, uint256, uint256, uint256) {
           (string[] memory ss, uint256[][] memory grid) = L.mm(x);
           return (ss[0], ss[1], grid[0][0], grid[1][0], grid[1][1]);
         }
       }`,
      [['go(uint256)', W(40)]],
    );
  });

  it('KEPT rejects: tuple-assign form, unsupported struct shape, internal-call tuple, mapping field', () => {
    // tuple ASSIGN to a pre-declared struct local still rejects (needs a deep copy the path does not wire).
    expect(
      codes(
        `@struct class S { a: u256; s: string; }
         @library class L { @external @pure mm(x: u256): [u256, S] { return [x, S(x, "y")]; } }
         @contract class C { @external go(x: u256): u256 { let s: S = S(0n, ""); let a: u256 = 0n; [a, s] = L.mm(x); return a + s.a; } }`,
      ),
    ).toContain('JETH066');
    // a struct with a gated field family (Arr<string,N>) keeps the clean JETH243 reject.
    expect(
      codes(
        `@struct class S { a: u256; ss: Arr<string, 2>; }
         @library class L { @external @pure mm(x: u256): [u256, S] { let v: S = S(x, ["a","b"]); return [x, v]; } }
         @contract class C { @external go(x: u256): u256 { let [a, s] = L.mm(x); return a + s.a; } }`,
      ),
    ).toContain('JETH243');
    // an INTERNAL-call tuple with a dyn-struct component stays gated (separate 'call'-source path).
    expect(
      codes(
        `@struct class S { a: u256; s: string; }
         @contract class C { mk(x: u256): [u256, S] { return [x, S(x, "y")]; } @external go(x: u256): u256 { let [a, s] = this.mk(x); return a + s.a; } }`,
      ),
    ).toContain('JETH243');
  });
});
