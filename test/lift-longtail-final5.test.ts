// Long-tail FINAL 5 over-rejection resolution (byte-identical to solc 0.8.35, or a proven clean reject).
// Four shapes LIFTED, one KEPT as a deliberate over-rejection with a raw-storage witness:
//
// LT1 (LIFTED, JETH225): an INTERNAL return of a SINGLE-field (or all value/funcref-field) STATIC funcref
//   struct `Fd{f}` (`mk(): Fd { return Fd(this.inc); }`). Fd is a value-word aggregate (one inline id word),
//   so the internal return forwards that flat image byte-identically. isSupportedStructReturn now admits a
//   funcref field in its static branch. Every ABI boundary re-rejects INDEPENDENTLY (JETH426 external
//   sig / JETH173 abi.encode* / JETH147/JETH129 event+error / JETH302 ctor param), so no funcref leaks.
//
// LT2 (LIFTED, JETH427): a memory `Arr<Fd,N>` (fixed array of a static funcref struct) element dispatch
//   `a[i].f(v)`. A struct element is ALWAYS pointer-headed in solc memory (a reference word per element),
//   funcref or not - so Arr<Fd,N> rides the SAME N-pointer table the Arr<In,N> family uses. New predicate
//   isFuncrefStaticStructFixedLeafArray wires the local-decl / resolveArrayExpr / read gates; the yul
//   isPointerHeadedStaticElem widening routes each Fd element to a fresh per-element image (allocAggToMem).
//   Deeper nestings (Arr<Arr<Fd,N>,M>, Arr<Fd,N>[]) stay JETH427; every ABI boundary re-rejects.
//
// LT3 (LIFTED, JETH217): an rvalue byte READ `xs[i].b[j]` on a `bytes` field of a memory dyn-struct-array
//   element. resolveMemDynStructArrayField resolves xs[i].b to the field's [len][data] blob pointer; the
//   read is an mload+shift (Panic 0x32 OOB), byte-identical - a read cannot corrupt storage.
//
// LT4 (LIFTED, JETH217): the byte WRITE `xs[i].b[j] = v` twin. Now routes through the in-place mstore8
//   (memByteIndexStore) into the SAME blob the LT3 read resolves (visible through a prior alias
//   `let al = xs[i].b`, not corrupting xs[i].n or neighbors). Was a silent store-drop MISCOMPILE before the
//   LT3 read resolver existed (the write fell to the storage byteIndexStore RMW); the reject that fenced it
//   is now a byte-identical accept.
//
// LT5 (KEPT REJECT, JETH217/210): a `@state xs: Fd[]` storage PUSH of a funcref-field struct. JETH stores a
//   funcref as its DISPATCH ORDINAL; solc stores a CODE OFFSET. These DIFFER in raw storage (witnessed:
//   a bare @state funcref var writes slot0 = 1 in JETH vs 125 in solc). The bar includes raw storage, so a
//   storage funcref in a struct array is NOT byte-identical - a deliberate clean reject.
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

const run = async (J: string, S: string, calls: ReadonlyArray<readonly [string, string]>, sname = 'C') => {
  const h = await Harness.create();
  await h.fund(me, 10n ** 20n);
  const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
  const sa = await h.deploy(compileSolidity(SPDX + S, sname).creation, { caller: me });
  for (const [sg, args] of calls) {
    const jr = await h.call(ja, sel(sg) + args);
    const sr = await h.call(sa, sel(sg) + args);
    expect(jr.returnHex, `${sg} ${args.slice(0, 16)} returndata`).toBe(sr.returnHex);
    expect(jr.success, `${sg} success`).toBe(sr.success);
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
const solcAccepts = (src: string, name = 'C'): boolean => {
  try {
    compileSolidity(SPDX + src, name);
    return true;
  } catch {
    return false;
  }
};

describe('long-tail final 5 (byte-identical to solc 0.8.35, or a proven clean reject)', () => {
  // ---------------------------------------------------------------- LT1
  it('LT1: internal return of a single-field funcref struct dispatches byte-identically', async () => {
    await run(
      `@struct class Fd { f: (x: u256) => u256 } @contract class C {
        inc(x: u256): u256 { return x + 1n; }
        mk(): Fd { return Fd(this.inc); }
        @external @view g(): u256 { let d: Fd = this.mk(); return d.f(4n); }
        @external @view chain(): u256 { return this.mk().f(10n); }
        @external @view fwd(): u256 { return this.use(this.mk()); }
        use(d: Fd): u256 { return d.f(9n); } }`,
      `contract C {
        function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
        function mk() internal pure returns (function(uint256) pure returns (uint256)) { return inc; }
        function g() external pure returns (uint256) { function(uint256) pure returns (uint256) f = mk(); return f(4); }
        function chain() external pure returns (uint256) { return mk()(10); }
        function fwd() external pure returns (uint256) { return use(mk()); }
        function use(function(uint256) pure returns (uint256) f) internal pure returns (uint256) { return f(9); } }`,
      [['g()', ''], ['chain()', ''], ['fwd()', '']] as const,
    );
  });

  it('LT1: a two-field funcref struct return (all funcref) dispatches byte-identically', async () => {
    // no solc single-struct equivalent (solc returns a tuple), so verify JETH runs correctly
    const h = await Harness.create();
    const ja = await h.deploy(
      compile(
        `@struct class Fd { f: (x: u256) => u256; g: (x: u256) => u256 } @contract class C {
          inc(x: u256): u256 { return x + 1n; }
          dbl(x: u256): u256 { return x * 2n; }
          mk(): Fd { return Fd(this.inc, this.dbl); }
          @external @view use(): u256 { let d: Fd = this.mk(); return d.f(4n) * 100n + d.g(4n); } }`,
        { fileName: 'C.jeth' },
      ).creationBytecode,
    );
    const r = await h.call(ja, sel('use()'));
    expect(r.success).toBe(true);
    expect(r.returnHex).toBe('0x' + W(5 * 100 + 8)); // inc(4)=5, dbl(4)=8
  });

  it('LT1: every ABI boundary of a funcref struct stays rejected (no leak)', () => {
    const FD = `@struct class Fd { f: (x: u256) => u256 } `;
    const inc = `inc(x:u256):u256{return x+1n;} `;
    // @external return
    expect(rejects(FD + `@contract class C { ${inc} @external @view r(): Fd { return Fd(this.inc); } }`)).toBe(true);
    // @external param
    expect(rejects(FD + `@contract class C { @external @view p(d: Fd): u256 { return d.f(3n); } }`)).toBe(true);
    // abi.encode / abi.encodePacked
    expect(rejects(FD + `@contract class C { ${inc} @external @view e(): bytes { let d: Fd = Fd(this.inc); return abi.encode(d); } }`)).toBe(true);
    expect(rejects(FD + `@contract class C { ${inc} @external @view e(): bytes { let d: Fd = Fd(this.inc); return abi.encodePacked(d); } }`)).toBe(true);
    // @event / @error param
    expect(rejects(FD + `@event E(d: Fd); @contract class C { ${inc} @external em(): void { let d: Fd = Fd(this.inc); emit(E(d)); } }`)).toBe(true);
    expect(rejects(FD + `@error Bad(d: Fd); @contract class C { ${inc} @external rv(): void { let d: Fd = Fd(this.inc); revert(Bad(d)); } }`)).toBe(true);
    // constructor param
    expect(rejects(FD + `@contract class C { constructor(d: Fd) {} }`)).toBe(true);
  });

  // ---------------------------------------------------------------- LT2
  it('LT2: Arr<Fd,N> element dispatch a[i].f(v) is byte-identical', async () => {
    await run(
      `@struct class Fd { f: (x: u256) => u256 } @contract class C {
        inc(x: u256): u256 { return x + 1n; }
        dbl(x: u256): u256 { return x * 2n; }
        @external @view g(): u256 { let a: Arr<Fd,2> = [Fd(this.inc), Fd(this.dbl)]; return a[0n].f(4n) * 100n + a[1n].f(4n); }
        @external @view mut(): u256 { let a: Arr<Fd,2> = [Fd(this.inc), Fd(this.dbl)]; a[0n] = Fd(this.dbl); return a[0n].f(4n) * 100n + a[1n].f(4n); }
        @external @view three(): u256 { let a: Arr<Fd,3> = [Fd(this.inc), Fd(this.dbl), Fd(this.inc)]; return a[0n].f(1n)*10000n + a[1n].f(3n)*100n + a[2n].f(7n); }
        @external @view runidx(i: u256): u256 { let a: Arr<Fd,2> = [Fd(this.inc), Fd(this.dbl)]; return a[i].f(5n); }
        @external @view aliasElem(): u256 { let a: Arr<Fd,2> = [Fd(this.inc), Fd(this.dbl)]; let p: (x:u256)=>u256 = a[1n].f; return p(10n); } }`,
      `contract C {
        function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
        function dbl(uint256 x) internal pure returns (uint256) { return x * 2; }
        struct Fd { function(uint256) pure returns (uint256) f; }
        function g() external pure returns (uint256) { Fd[2] memory a = [Fd(inc), Fd(dbl)]; return a[0].f(4)*100 + a[1].f(4); }
        function mut() external pure returns (uint256) { Fd[2] memory a = [Fd(inc), Fd(dbl)]; a[0] = Fd(dbl); return a[0].f(4)*100 + a[1].f(4); }
        function three() external pure returns (uint256) { Fd[3] memory a = [Fd(inc), Fd(dbl), Fd(inc)]; return a[0].f(1)*10000 + a[1].f(3)*100 + a[2].f(7); }
        function runidx(uint256 i) external pure returns (uint256) { Fd[2] memory a = [Fd(inc), Fd(dbl)]; return a[i].f(5); }
        function aliasElem() external pure returns (uint256) { Fd[2] memory a = [Fd(inc), Fd(dbl)]; function(uint256) pure returns (uint256) p = a[1].f; return p(10); } }`,
      [['g()', ''], ['mut()', ''], ['three()', ''], ['runidx()', W(1)], ['runidx()', W(0)], ['aliasElem()', '']] as const,
    );
  });

  it('LT2: a mixed value+funcref static struct array is byte-identical', async () => {
    await run(
      `@struct class Fd { f: (x: u256) => u256; n: u256 } @contract class C {
        inc(x: u256): u256 { return x + 1n; }
        dbl(x: u256): u256 { return x * 2n; }
        @external @view g(): u256 { let a: Arr<Fd,2> = [Fd(this.inc, 100n), Fd(this.dbl, 200n)]; return a[0n].f(4n)*1000n + a[0n].n + a[1n].f(4n)*10n + a[1n].n; }
        @external @view mutn(): u256 { let a: Arr<Fd,2> = [Fd(this.inc, 100n), Fd(this.dbl, 200n)]; a[0n].n = 999n; return a[0n].n + a[0n].f(4n); } }`,
      `contract C {
        function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
        function dbl(uint256 x) internal pure returns (uint256) { return x * 2; }
        struct Fd { function(uint256) pure returns (uint256) f; uint256 n; }
        function g() external pure returns (uint256) { Fd[2] memory a = [Fd(inc, 100), Fd(dbl, 200)]; return a[0].f(4)*1000 + a[0].n + a[1].f(4)*10 + a[1].n; }
        function mutn() external pure returns (uint256) { Fd[2] memory a = [Fd(inc, 100), Fd(dbl, 200)]; a[0].n = 999; return a[0].n + a[0].f(4); } }`,
      [['g()', ''], ['mutn()', '']] as const,
    );
  });

  it('LT2: deeper funcref-struct-array nestings and every ABI boundary stay rejected', () => {
    const FD = `@struct class Fd { f: (x: u256) => u256 } `;
    const inc = `inc(x:u256):u256{return x+1n;} `;
    // deeper nestings stay JETH427
    expect(rejects(FD + `@contract class C { ${inc} @external @view g(): u256 { let a: Arr<Arr<Fd,2>,2> = [[Fd(this.inc),Fd(this.inc)],[Fd(this.inc),Fd(this.inc)]]; return a[0n][0n].f(1n); } }`)).toBe(true);
    expect(rejects(FD + `@contract class C { ${inc} @external @view g(): u256 { let a: Arr<Fd,2>[] = new Array<Arr<Fd,2>>(2n); return 1n; } }`)).toBe(true);
    // ABI boundaries of Arr<Fd,N> stay rejected
    expect(rejects(FD + `@contract class C { ${inc} @external @view r(): Arr<Fd,2> { return [Fd(this.inc), Fd(this.inc)]; } }`)).toBe(true);
    expect(rejects(FD + `@contract class C { @external @view p(a: Arr<Fd,2>): u256 { return a[0n].f(3n); } }`)).toBe(true);
    expect(rejects(FD + `@contract class C { ${inc} @external @view e(): bytes { let a: Arr<Fd,2> = [Fd(this.inc), Fd(this.inc)]; return abi.encode(a); } }`)).toBe(true);
    expect(rejects(FD + `@event E(a: Arr<Fd,2>); @contract class C { ${inc} @external em(): void { let a: Arr<Fd,2> = [Fd(this.inc), Fd(this.inc)]; emit(E(a)); } }`)).toBe(true);
    expect(rejects(FD + `@contract class C { constructor(a: Arr<Fd,2>) {} }`)).toBe(true);
  });

  // ---------------------------------------------------------------- LT3 / LT4
  it('LT3/LT4: memory struct-array element byte read + write is byte-identical', async () => {
    await run(
      `@struct class P { n: u256; b: bytes } @contract class C {
        @external @view read1(): bytes1 { let xs: P[] = [P(7n, bytes("abc")), P(8n, bytes("xyz"))]; return xs[1n].b[1n]; }
        @external @view read2(): u256 { let xs: P[] = [P(7n, bytes("abcdef"))]; return u256(u8(xs[0n].b[0n])) * 1000n + u256(u8(xs[0n].b[5n])); }
        @external @view roob(): bytes1 { let xs: P[] = [P(7n, bytes("ab"))]; return xs[0n].b[5n]; }
        @external @view rAlias(): u256 { let xs: P[] = [P(7n, bytes("hello"))]; let al: bytes = xs[0n].b; return u256(u8(al[1n])) * 1000n + u256(u8(xs[0n].b[1n])); }
        @external @view write1(): bytes { let xs: P[] = [P(7n, bytes("abc")), P(8n, bytes("xyz"))]; xs[1n].b[1n] = 0x5an; return xs[1n].b; }
        @external @view wAlias(): bytes { let xs: P[] = [P(7n, bytes("hello"))]; let al: bytes = xs[0n].b; xs[0n].b[0n] = 0x5an; return al; }
        @external @view wNeigh(): u256 { let xs: P[] = [P(7n, bytes("abc")), P(9n, bytes("def"))]; xs[0n].b[1n] = 0x5an; return xs[0n].n + xs[1n].n * 1000n + u256(u8(xs[1n].b[0n])); }
        @external @view woob(): bytes { let xs: P[] = [P(7n, bytes("ab"))]; xs[0n].b[5n] = 0x5an; return xs[0n].b; }
        @external @view wMulti(): bytes { let xs: P[] = [P(1n, bytes("xxxxxx"))]; xs[0n].b[0n] = 0x41n; xs[0n].b[2n] = 0x42n; xs[0n].b[5n] = 0x43n; return xs[0n].b; } }`,
      `contract C { struct P { uint256 n; bytes b; }
        function read1() external pure returns (bytes1) { P[] memory xs = new P[](2); xs[0]=P(7,"abc"); xs[1]=P(8,"xyz"); return xs[1].b[1]; }
        function read2() external pure returns (uint256) { P[] memory xs = new P[](1); xs[0]=P(7,"abcdef"); return uint256(uint8(xs[0].b[0]))*1000 + uint256(uint8(xs[0].b[5])); }
        function roob() external pure returns (bytes1) { P[] memory xs = new P[](1); xs[0]=P(7,"ab"); return xs[0].b[5]; }
        function rAlias() external pure returns (uint256) { P[] memory xs = new P[](1); xs[0]=P(7,"hello"); bytes memory al = xs[0].b; return uint256(uint8(al[1]))*1000 + uint256(uint8(xs[0].b[1])); }
        function write1() external pure returns (bytes memory) { P[] memory xs = new P[](2); xs[0]=P(7,"abc"); xs[1]=P(8,"xyz"); xs[1].b[1]=0x5a; return xs[1].b; }
        function wAlias() external pure returns (bytes memory) { P[] memory xs = new P[](1); xs[0]=P(7,"hello"); bytes memory al = xs[0].b; xs[0].b[0]=0x5a; return al; }
        function wNeigh() external pure returns (uint256) { P[] memory xs = new P[](2); xs[0]=P(7,"abc"); xs[1]=P(9,"def"); xs[0].b[1]=0x5a; return xs[0].n + xs[1].n*1000 + uint256(uint8(xs[1].b[0])); }
        function woob() external pure returns (bytes memory) { P[] memory xs = new P[](1); xs[0]=P(7,"ab"); xs[0].b[5]=0x5a; return xs[0].b; }
        function wMulti() external pure returns (bytes memory) { P[] memory xs = new P[](1); xs[0]=P(1,"xxxxxx"); xs[0].b[0]=0x41; xs[0].b[2]=0x42; xs[0].b[5]=0x43; return xs[0].b; } }`,
      [['read1()', ''], ['read2()', ''], ['roob()', ''], ['rAlias()', ''], ['write1()', ''], ['wAlias()', ''], ['wNeigh()', ''], ['woob()', ''], ['wMulti()', '']] as const,
    );
  });

  it('LT3/LT4: fixed Arr<P,N> element byte read + write is byte-identical; string field stays rejected', async () => {
    await run(
      `@struct class Q2 { b: bytes; n: u256 } @contract class C {
        @external @pure w(): bytes { let xs: Arr<Q2, 2> = [Q2(bytes("aabb"), 1n), Q2(bytes("ccdd"), 2n)]; xs[1n].b[0n] = 0x5an; return xs[1n].b; }
        @external @pure r(): bytes1 { let xs: Arr<Q2, 2> = [Q2(bytes("aabb"), 1n), Q2(bytes("ccdd"), 2n)]; return xs[0n].b[3n]; } }`,
      `contract C { struct Q2 { bytes b; uint256 n; }
        function w() external pure returns (bytes memory) { Q2[2] memory xs = [Q2(bytes("aabb"), 1), Q2(bytes("ccdd"), 2)]; xs[1].b[0] = 0x5a; return xs[1].b; }
        function r() external pure returns (bytes1) { Q2[2] memory xs = [Q2(bytes("aabb"), 1), Q2(bytes("ccdd"), 2)]; return xs[0].b[3]; } }`,
      [['w()', ''], ['r()', '']] as const,
    );
    // a `string` field is not indexable (JETH205, solc parity).
    expect(
      rejects(`@struct class Q2 { s: string; n: u256 }
@contract class C { @external @pure f(): u256 { let xs: Arr<Q2, 2> = [Q2("aa", 1n), Q2("bb", 2n)]; xs[0n].s[0n] = 0x5an; return 1n; } }`),
    ).toBe(true);
  });

  // ---------------------------------------------------------------- LT5 (KEPT REJECT)
  it('LT5: a storage funcref-struct-array push stays a clean reject (raw-storage would diverge)', () => {
    // solc accepts; JETH rejects because a storage funcref is a dispatch ordinal (JETH) vs a code offset
    // (solc) - the raw storage slot would DIFFER, and the bar includes raw storage.
    const J = `@struct class Fd { f: (x: u256) => u256 } @contract class C {
      @state xs: Fd[];
      inc(x: u256): u256 { return x + 1n; }
      @external add(): void { this.xs.push(Fd(this.inc)); }
      @external @view g(): u256 { return this.xs[0n].f(4n); } }`;
    const S = `contract C {
      struct Fd { function(uint256) internal view returns (uint256) f; }
      Fd[] xs;
      function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
      function add() external { xs.push(Fd(inc)); }
      function g() external view returns (uint256) { return xs[0].f(4); } }`;
    expect(rejects(J)).toBe(true); // JETH clean-rejects
    expect(solcAccepts(S)).toBe(true); // solc accepts (so this is a deliberate over-rejection)
  });

  it('LT5 witness: a bare @state funcref var diverges on raw storage (JETH ordinal vs solc offset)', async () => {
    // this is WHY LT5 must stay a reject: the raw storage slot of a stored funcref is not byte-identical.
    const J = `@contract class C {
      @state fp: (x: u256) => u256;
      inc(x: u256): u256 { return x + 1n; }
      @external set(): void { this.fp = this.inc; }
      @external @view use(): u256 { return this.fp(4n); } }`;
    const S = `contract C {
      function(uint256) internal view returns (uint256) fp;
      function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
      function set() external { fp = inc; }
      function use() external view returns (uint256) { return fp(4); } }`;
    const h = await Harness.create();
    const seed = async (bytecode: string) => {
      const a = await h.deploy(bytecode);
      await h.call(a, sel('set()'));
      const use = await h.call(a, sel('use()'));
      const slot0 = await h.evm.stateManager.getStorage(a, new Uint8Array(32));
      return { slot0: Buffer.from(slot0).toString('hex').padStart(64, '0'), use: use.returnHex };
    };
    const rj = await seed(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const rs = await seed(compileSolidity(SPDX + S, 'C').creation);
    // the dispatch RESULT matches (both call inc(4) = 5)...
    expect(rj.use).toBe(rs.use);
    // ...but the RAW STORAGE slot diverges (JETH stores the dispatch ordinal, solc the code offset).
    expect(rj.slot0).not.toBe(rs.slot0);
  });
});
