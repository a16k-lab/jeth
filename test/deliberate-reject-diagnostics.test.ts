// DELIBERATE-REJECT diagnostics (JETH492/493/494 + JETH495/496). Shapes solc accepts but JETH
// intentionally does NOT support are given a CLEAR, targeted message instead of a generic catch-all. These
// shapes stay REJECTED (this is a diagnostic-quality change, not a lift):
//   - JETH492: `<address>.transfer(v)` / `<address>.send(v)` - solc's ETH send with a fixed 2300-gas
//     stipend (a footgun since EIP-1884). JETH's canonical value transfer is the checked low-level
//     `t.call({ data, value, success })`.
//   - JETH493: `selfdestruct(a)` - deprecated, neutered by EIP-6780.
//   - JETH494: `arr.push()` (no argument) used as a VALUE - solc returns a STORAGE REFERENCE to the
//     appended element, conflicting with JETH's deliberate "no storage-reference locals" design. The
//     no-arg push STATEMENT (append a zero element) stays fully supported; `arr.push(value)` is the
//     supported byte-identical value form.
//   - JETH495 (REC-STRUCT-MEMLOCAL, 2026-07-16): a RECURSIVE struct (`type P = { x: u256; kids: P[] }`)
//     in a MEMORY-AGGREGATE position - a memory local, an uninitialized/constructor local, or an internal
//     `P memory` return. solc lowers these to an UNBOUNDED RUNTIME-RECURSIVE DEEP COPY of the whole tree;
//     JETH deliberately has no runtime-recursive struct-copy codegen (its back-edge is a compile-time
//     `recursiveRef` empty-fields sentinel), so admitting them would lay out zero/one word per `kids`
//     element and SILENTLY DROP the nested payload. The recursive struct itself stays fully supported in
//     STORAGE (byte-identical - see lift-recursive-ref-struct.test.ts). Was JETH200/JETH243/JETH074.
//   - JETH496 (TYPED-CATCH, 2026-07-16): solc's typed catch clauses `catch Error(string)` /
//     `catch Panic(uint)`. JETH's untyped `catch (e: bytes)` plus the `this.reason` / `this.panic`
//     accessors cover the same ground byte-identically (see try-catch.test.ts). Was JETH074.
//
// HARD GUARD (verified below): the JETH492 diagnostic fires ONLY for the BUILT-IN member on a PLAIN
// address/payable receiver. A contract/interface-VALUE `.transfer`/`.send` is real external DISPATCH
// (unaffected), a contract's OWN transfer/send method is unaffected, and a user field/local named
// transfer/send is unaffected. Non-vacuity: each accepted guard is exercised at runtime and diffed
// byte-for-byte against solc 0.8.35.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { Address } from '@ethereumjs/util';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => pad32(n);

/** Diagnostic codes emitted for `src`, or null when `src` compiles. */
function codesOf(src: string): string[] | null {
  try {
    compile(src, { fileName: 'C.jeth' });
    return null;
  } catch (e) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
}
const jethAccepts = (src: string): boolean => codesOf(src) === null;
function rejectsWith(src: string, code: string): boolean {
  const c = codesOf(src);
  return c !== null && c.includes(code);
}

/** Deploy a JETH contract and its solc equivalent, invoke each call, diff success + returndata. */
async function eqCalls(jeth: string, sol: string, calls: [string, string][], name = 'C') {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, name).creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

describe('DELIBERATE-REJECT diagnostics: targets stay rejected with a targeted code', () => {
  it('JETH492: <address>.transfer(amt) / <address>.send(amt) on a PLAIN address/payable receiver', () => {
    // transfer, several address-typed receivers
    expect(rejectsWith(`class C { pay(t: address, amt: u256): External<void> { t.transfer(amt); } }`, 'JETH492')).toBe(true);
    expect(
      rejectsWith(`class C { pay(t: address, amt: u256): External<void> { payable(t).transfer(amt); } }`, 'JETH492'),
    ).toBe(true);
    expect(
      rejectsWith(`class C { pay(amt: u256): External<void> { address(this).transfer(amt); } }`, 'JETH492'),
    ).toBe(true);
    // send (statement and let-bound bool), address and payable
    expect(rejectsWith(`class C { pay(t: address, amt: u256): External<void> { t.send(amt); } }`, 'JETH492')).toBe(true);
    expect(
      rejectsWith(`class C { pay(t: address, amt: u256): External<void> { let ok: bool = t.send(amt); } }`, 'JETH492'),
    ).toBe(true);
    expect(
      rejectsWith(
        `class C { pay(t: address, amt: u256): External<void> { let ok: bool = payable(t).send(amt); } }`,
        'JETH492',
      ),
    ).toBe(true);
  });

  it('JETH493: selfdestruct(a) - deprecated / neutered by EIP-6780', () => {
    expect(rejectsWith(`class C { kill(a: address): External<void> { selfdestruct(payable(a)); } }`, 'JETH493')).toBe(
      true,
    );
    expect(rejectsWith(`class C { kill(a: address): External<void> { selfdestruct(a); } }`, 'JETH493')).toBe(true);
  });

  it('JETH494: arr.push() with no argument used as a VALUE (storage-reference form)', () => {
    // state array
    expect(
      rejectsWith(
        `type P = { x: u256; y: u256 }; class C { arr: P[]; grow(): External<void> { let r: P = this.arr.push(); } }`,
        'JETH494',
      ),
    ).toBe(true);
    // scalar state array
    expect(
      rejectsWith(`class C { xs: u256[]; grow(): External<void> { let r: u256 = this.xs.push(); } }`, 'JETH494'),
    ).toBe(true);
    // mapping-value array
    expect(
      rejectsWith(
        `type P = { x: u256; y: u256 }; class C { m: mapping<u256, P[]>; grow(k: u256): External<void> { let r: P = this.m[k].push(); } }`,
        'JETH494',
      ),
    ).toBe(true);
    // struct-field dynamic array
    expect(
      rejectsWith(
        `type P = { x: u256; y: u256 }; type S = { xs: P[] }; class C { s: S; grow(): External<void> { let r: P = this.s.xs.push(); } }`,
        'JETH494',
      ),
    ).toBe(true);
  });

  it('JETH495: a RECURSIVE struct in a memory-aggregate position (local / ctor local / internal ret)', () => {
    const P = 'type P = { x: u256; kids: P[] };';
    // (a) storage-initialized memory local; (b) uninitialized local; (c) deep recursive read
    expect(rejectsWith(`${P} class C { p: P; get g(): External<u256> { let m: P = this.p; return m.x; } }`, 'JETH495')).toBe(true);
    expect(rejectsWith(`${P} class C { get g(): External<u256> { let m: P; return m.x; } }`, 'JETH495')).toBe(true);
    expect(
      rejectsWith(`${P} class C { p: P; get g(): External<u256> { let m: P = this.p; return m.kids[0n].x; } }`, 'JETH495'),
    ).toBe(true);
    // (d) constructor local
    expect(
      rejectsWith(`${P} class C { p: P; constructor() { let m: P; } get g(): External<u256> { return this.p.x; } }`, 'JETH495'),
    ).toBe(true);
    // (e) internal function returning P memory - BOTH the member-read and the call-statement form
    expect(
      rejectsWith(`${P} class C { p: P; h(): P { return this.p; } get g(): External<u256> { return this.h().x; } }`, 'JETH495'),
    ).toBe(true);
    expect(rejectsWith(`${P} class C { p: P; h(): P { return this.p; } f(): External<void> { this.h(); } }`, 'JETH495')).toBe(true);
    // (f) MUTUAL recursion (A -> B[] -> A[]) reaches the same sentinel and the same ruling
    expect(
      rejectsWith(
        `type A = { b: B[]; v: u256 }; type B = { a: A[]; w: u256 }; class C { a: A; get g(): External<u256> { let m: A = this.a; return m.v; } }`,
        'JETH495',
      ),
    ).toBe(true);
  });

  it('JETH496: solc typed catch clauses (catch Error(string) / catch Panic(uint))', () => {
    const I = 'interface IFoo { echo(v: u256): u256; }';
    const TRY = (c: string) =>
      `${I} class C { f(t: address): External<u256> { try { let r: u256 = IFoo(t).echo(1n); return r; } ${c} } }`;
    expect(rejectsWith(TRY('catch Error(string) { return 1n; }'), 'JETH496')).toBe(true);
    expect(rejectsWith(TRY('catch Error(string reason) { return 1n; }'), 'JETH496')).toBe(true);
    expect(rejectsWith(TRY('catch Error(string memory reason) { return 1n; }'), 'JETH496')).toBe(true);
    expect(rejectsWith(TRY('catch Panic(uint) { return 1n; }'), 'JETH496')).toBe(true);
    expect(rejectsWith(TRY('catch Panic(uint code) { return 1n; }'), 'JETH496')).toBe(true);
    expect(rejectsWith(TRY('catch Panic(uint256 code) { return 1n; }'), 'JETH496')).toBe(true);
  });
});

describe('DELIBERATE-REJECT diagnostics: HARD GUARD - real dispatch / supported forms are UNAFFECTED', () => {
  it('a contract/interface-VALUE .transfer/.send and a contract OWN transfer/send method still compile', () => {
    // interface-value dispatch (IERC20(t).transfer(...))
    expect(
      jethAccepts(
        `interface IERC20 { transfer(to: address, amt: u256): bool; } class C { pay(t: address, to: address, amt: u256): External<bool> { return IERC20(t).transfer(to, amt); } }`,
      ),
    ).toBe(true);
    // contract-value dispatch (t: T, t.transfer(...))
    expect(
      jethAccepts(
        `abstract class T { transfer(to: address, amt: u256): External<bool> { return true; } } class C { pay(t: T, to: address, amt: u256): External<bool> { return t.transfer(to, amt); } }`,
      ),
    ).toBe(true);
    // a contract's OWN transfer / send external method (a state-mutating writer)
    expect(
      jethAccepts(
        `class C { x: u256 = 0n; transfer(to: address, amt: u256): External<bool> { this.x = amt; return true; } }`,
      ),
    ).toBe(true);
    expect(
      jethAccepts(`class C { x: u256 = 0n; send(to: address, amt: u256): External<bool> { this.x = amt; return true; } }`),
    ).toBe(true);
    // fields / locals named transfer / send are ordinary identifiers
    expect(jethAccepts(`class C { transfer: u256 = 0n; get f(): External<u256> { return this.transfer; } }`)).toBe(true);
    expect(jethAccepts(`class C { send: u256 = 0n; get f(): External<u256> { return this.send; } }`)).toBe(true);
    expect(jethAccepts(`class C { get f(): External<u256> { let transfer: u256 = 5n; return transfer; } }`)).toBe(true);
  });

  it('the supported value forms - arr.push(value), no-arg push STATEMENT, t.call({ value }) - still compile', () => {
    expect(
      jethAccepts(
        `type P = { x: u256; y: u256 }; class C { arr: P[]; grow(): External<void> { this.arr.push(P(1n, 2n)); } }`,
      ),
    ).toBe(true);
    expect(jethAccepts(`class C { xs: u256[]; grow(): External<void> { this.xs.push(5n); } }`)).toBe(true);
    // no-arg push as a STATEMENT (appends a zero element) is a distinct, supported form
    expect(
      jethAccepts(`type P = { x: u256; y: u256 }; class C { arr: P[]; grow(): External<void> { this.arr.push(); } }`),
    ).toBe(true);
    // the canonical checked low-level value transfer surface
    expect(
      jethAccepts(
        `class C { pay(t: address, amt: u256, d: bytes): External<void> { t.call({ data: d, value: amt, success: { condition: this.ok, revert: "x" } }); } get ok(): bool { return true; } }`,
      ),
    ).toBe(true);
  });

  it('JETH495 is gated on RECURSION: non-recursive structs keep their own codes / stay accepted', () => {
    // a NON-recursive dynamic-struct local is a real (liftable) gap and KEEPS the generic JETH200 - it must
    // never be relabelled as the deliberate JETH495 ruling.
    expect(rejectsWith(`class C { get g(): External<u256> { let xs: u256[]; return xs[0n]; } }`, 'JETH200')).toBe(true);
    // a non-recursive internal return that JETH cannot lower KEEPS the generic JETH243.
    expect(
      rejectsWith(
        `class C { m: mapping<u256,u256>; h(): mapping<u256,u256> { return this.m; } f(): External<void> { this.h(); } }`,
        'JETH243',
      ),
    ).toBe(true);
    // supported NON-recursive dynamic-struct locals and internal returns still COMPILE.
    expect(jethAccepts(`type S = { xs: u256[] }; class C { s: S; get g(): External<u256> { let m: S = this.s; return m.xs[0n]; } }`)).toBe(true);
    expect(jethAccepts(`type Q = { a: u256; b: u256 }; class C { h(): Q { return Q(1n,2n); } get g(): External<u256> { return this.h().a; } }`)).toBe(true);
    // the RECURSIVE struct itself stays fully supported in STORAGE, and merely DECLARING a P-returning
    // internal function (never calling it) is accepted - JETH495 fires at the USE, exactly like solc's own
    // lowering boundary.
    const P = 'type P = { x: u256; kids: P[] };';
    expect(jethAccepts(`${P} class C { p: Visible<P>; setx(v: u256): External<void> { this.p.x = v; } get gx(): External<u256> { return this.p.x; } }`)).toBe(true);
    expect(jethAccepts(`${P} class C { p: P; h(): P { return this.p; } get g(): External<u256> { return this.p.x; } }`)).toBe(true);
  });

  it('JETH496 is gated on the TS-INSERTED catch block: real catch clauses are UNAFFECTED', () => {
    const I = 'interface IFoo { echo(v: u256): u256; }';
    // the supported native forms still compile (untyped catch + this.reason / this.panic)
    const TRY = (c: string) =>
      `${I} class C { f(t: address): External<u256> { try { let r: u256 = IFoo(t).echo(1n); return r; } ${c} } }`;
    expect(jethAccepts(TRY('catch (e: bytes) { return 999n; }'))).toBe(true);
    expect(jethAccepts(TRY('catch (e: bytes) { return this.panic; }'))).toBe(true);
    expect(jethAccepts(TRY('catch {} return 5n;'))).toBe(true);
    expect(
      jethAccepts(
        `${I} class C { f(t: address): External<string> { try { let r: u256 = IFoo(t).echo(1n); return ""; } catch (e: bytes) { return this.reason; } } }`,
      ),
    ).toBe(true);
    // THE DISCRIMINATOR. TS has no typed-catch grammar, so `catch Error(string) {...}` is error-recovered by
    // INSERTING a ZERO-WIDTH `{}` catch block, leaving `Error(string)` as the next statement. A REAL
    // `catch {}` / `catch (e: bytes) {}` has a SOURCE-WIDTH block, so a bare Error(...)/Panic(...) call after
    // one is structurally identical EXCEPT for that width - it must stay the generic JETH074, never JETH496.
    const after = (cat: string, fn: string) =>
      `${I} class C { f(t: address): External<u256> { try { let r: u256 = IFoo(t).echo(1n); return r; } ${cat} ${fn}(1n); return 0n; } }`;
    expect(rejectsWith(after('catch {}', 'Error'), 'JETH074')).toBe(true);
    expect(rejectsWith(after('catch {}', 'Error'), 'JETH496')).toBe(false);
    expect(rejectsWith(after('catch {}', 'Panic'), 'JETH074')).toBe(true);
    expect(rejectsWith(after('catch {}', 'Panic'), 'JETH496')).toBe(false);
    expect(rejectsWith(after('catch (e: bytes) {}', 'Error'), 'JETH496')).toBe(false);
    // an Error(...)/Panic(...) call with NO try/catch anywhere keeps the generic JETH074
    expect(rejectsWith(`class C { f(): External<void> { Error(1n); } }`, 'JETH074')).toBe(true);
    expect(rejectsWith(`class C { f(): External<void> { Error(1n); } }`, 'JETH496')).toBe(false);
    expect(rejectsWith(`class C { f(): External<void> { Panic(1n); } }`, 'JETH496')).toBe(false);
    // a user method named Error / Panic called after a real try/catch is an ordinary call and COMPILES
    expect(
      jethAccepts(
        `${I} class C { Error(v: u256): u256 { return v; } f(t: address): External<u256> { try { let r: u256 = IFoo(t).echo(1n); return r; } catch {} return this.Error(7n); } }`,
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        `${I} class C { Panic(v: u256): u256 { return v; } f(t: address): External<u256> { try { let r: u256 = IFoo(t).echo(1n); return r; } catch {} return this.Panic(7n); } }`,
      ),
    ).toBe(true);
  });
});

describe('DELIBERATE-REJECT diagnostics: guards are non-vacuous (byte-identical to solc 0.8.35 at runtime)', () => {
  it('arr.push(value) writes the pushed value, byte-identical', async () => {
    await eqCalls(
      `type P = { x: u256; y: u256 }; class C { arr: P[]; setit(): External<void> { this.arr.push(P(1n, 2n)); this.arr.push(P(3n, 4n)); } get len(): External<u256> { return u256(this.arr.length); } get rx(i: u256): External<u256> { return this.arr[i].x; } get ry(i: u256): External<u256> { return this.arr[i].y; } }`,
      `struct P { uint256 x; uint256 y; } contract C { P[] arr; function setit() external { arr.push(P(1,2)); arr.push(P(3,4)); } function len() external view returns(uint256){ return arr.length; } function rx(uint256 i) external view returns(uint256){ return arr[i].x; } function ry(uint256 i) external view returns(uint256){ return arr[i].y; } }`,
      [
        ['setit()', ''],
        ['len()', ''],
        ['rx(uint256)', W(0n)],
        ['ry(uint256)', W(0n)],
        ['rx(uint256)', W(1n)],
        ['ry(uint256)', W(1n)],
      ],
    );
  });

  it('JETH495 workaround: reading the recursive tree in STORAGE is byte-identical to solc', async () => {
    // The JETH495 message tells the user to read fields directly / keep the tree in storage. Prove that
    // workaround is REAL: the same recursive struct, read + written through storage, matches solc exactly.
    await eqCalls(
      `type P = { x: u256; kids: P[] };
       class C { p: P; setx(v: u256): External<void> { this.p.x = v; } get gx(): External<u256> { return this.p.x; }
                 grow(): External<void> { this.p.kids.push(); } get nk(): External<u256> { return this.p.kids.length; } }`,
      `contract C { struct P { uint256 x; P[] kids; } P p;
                    function setx(uint256 v) external { p.x = v; } function gx() external view returns(uint256){ return p.x; }
                    function grow() external { p.kids.push(); } function nk() external view returns(uint256){ return p.kids.length; } }`,
      [
        ['setx(uint256)', W(0xdeadbeefn)],
        ['gx()', ''],
        ['grow()', ''],
        ['grow()', ''],
        ['nk()', ''],
      ],
    );
  });

  it("a contract's OWN transfer method dispatches as a normal external entry, byte-identical", async () => {
    await eqCalls(
      `class C { last: u256 = 0n; transfer(to: address, amt: u256): External<bool> { this.last = amt; return true; } get lastAmt(): External<u256> { return this.last; } }`,
      `contract C { uint256 last; function transfer(address to, uint256 amt) external returns(bool){ last = amt; return true; } function lastAmt() external view returns(uint256){ return last; } }`,
      [
        ['transfer(address,uint256)', W(0x1234n) + W(77n)],
        ['lastAmt()', ''],
      ],
    );
  });

  it('an interface-value .transfer(...) is real external DISPATCH, byte-identical', async () => {
    // Deploy the SAME (solc) token in both harnesses so the deployed target code is byte-identical, then
    // a JETH caller and a solc caller dispatch transfer through the interface and are diffed.
    const TOKEN_SOL = `contract Tok { uint256 last; function transfer(address to, uint256 amt) external returns(bool){ last = amt; return true; } function lastAmt() external view returns(uint256){ return last; } }`;
    const CALLER_JETH = `interface IERC20 { transfer(to: address, amt: u256): bool; } class C { pay(t: address, to: address, amt: u256): External<bool> { return IERC20(t).transfer(to, amt); } }`;
    const CALLER_SOL = `interface IERC20 { function transfer(address to, uint256 amt) external returns(bool); } contract C { function pay(address t, address to, uint256 amt) external returns(bool){ return IERC20(t).transfer(to, amt); } }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const tokBytes = compileSolidity(SPDX + TOKEN_SOL, 'Tok').creation;
    const tj: Address = await hj.deploy(tokBytes);
    const ts: Address = await hs.deploy(tokBytes);
    const cj: Address = await hj.deploy(compile(CALLER_JETH, { fileName: 'C.jeth' }).creationBytecode);
    const cs: Address = await hs.deploy(compileSolidity(SPDX + CALLER_SOL, 'C').creation);
    const argsJ = W(BigInt(tj.toString())) + W(0xbeefn) + W(42n);
    const argsS = W(BigInt(ts.toString())) + W(0xbeefn) + W(42n);
    const rj = await hj.call(cj, sel('pay(address,address,uint256)') + argsJ);
    const rs = await hs.call(cs, sel('pay(address,address,uint256)') + argsS);
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
    // confirm the dispatch actually recorded the amount on each token (non-vacuous)
    const lj = await hj.call(tj, sel('lastAmt()'));
    const ls = await hs.call(ts, sel('lastAmt()'));
    expect(lj.returnHex).toBe(ls.returnHex);
    expect(lj.returnHex).toBe('0x' + W(42n));
  });
});
