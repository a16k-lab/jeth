// Tier-3 Batch-2/3 OR lifts, each verified BYTE-IDENTICAL to solc 0.8.35 (run + decode, non-vacuous
// seeded anchors) with reject-assertions for every boundary left gated:
//   L10b - TUPLE-RETURN FUNCREFS: `(a, b) => [u256, u256]` pointer type; `let [p, q] = g(a, b)` and the
//          assign form dispatch through a per-signature MULTI-RETURN Yul dispatcher.
//   L11a - FUNCREF FIELD IN A DYNAMIC STRUCT: `@struct Fd { f: (x) => u256; s: string }` as a memory
//          local (ctor / storage copy / alias / ternary / internal arg+ret); every ABI boundary rejects.
//   L14  - STRUCT GETTER AS INTERFACE IMPL: `@external @state g: S6` satisfies an @interface method
//          `g(): [u256, u256]` (flattened auto-getter signature), with and without @override.
//   L15  - GENERIC @modifier: `@modifier lim<T>(v: T)` monomorphized per use site (explicit @lim<u256>(x)
//          and inferred @lim(x)), through the normal pre-only + buffered modifier machinery.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
/** Deploy the JETH source + the solc mirror, run each call against both, assert byte-identical
 *  success + returndata, and return the JETH results (for non-vacuity anchors). */
async function diff(J: string, S: string, calls: string[]): Promise<{ success: boolean; returnHex: string }[]> {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  const out: { success: boolean; returnHex: string }[] = [];
  for (const data of calls) {
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, `success for ${data.slice(0, 10)}`).toBe(rs.success);
    expect(rj.returnHex, `returndata for ${data.slice(0, 10)}`).toBe(rs.returnHex);
    out.push(rj);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------
// L10b - tuple-return funcrefs
// ---------------------------------------------------------------------------------------------------
describe('L10b: tuple-return funcref, destructured pointer call (byte-identical)', () => {
  it('let [p, q] = g(a, b) through a (u256,u256)=>[u256,u256] pointer', async () => {
    const J = `@contract class C {
      two(a: u256, b: u256): [u256, u256] { return [a + b, a * b]; }
      @external run(a: u256, b: u256): u256 {
        let g: (a: u256, b: u256) => [u256, u256] = this.two;
        let [p, q] = g(a, b);
        return p + q * 2n;
      }
    }`;
    const S = `contract C {
      function two(uint256 a, uint256 b) internal pure returns (uint256, uint256) { return (a + b, a * b); }
      function run(uint256 a, uint256 b) external pure returns (uint256) {
        function(uint256, uint256) pure returns (uint256, uint256) g = two;
        (uint256 p, uint256 q) = g(a, b);
        return p + q * 2;
      }
    }`;
    const [r] = await diff(J, S, ['0x' + sel('run(uint256,uint256)') + W(3) + W(5)]);
    expect(BigInt(r!.returnHex)).toBe(3n + 5n + (3n * 5n) * 2n); // 38: non-vacuous anchor
  });

  it('runtime dispatch: two same-signature multi-return targets behind one pointer', async () => {
    const J = `@contract class C {
      sumProd(a: u256, b: u256): [u256, u256] { return [a + b, a * b]; }
      diffMax(a: u256, b: u256): [u256, u256] { return [a - b, a > b ? a : b]; }
      @external run(c: u256, a: u256, b: u256): u256 {
        let g: (a: u256, b: u256) => [u256, u256] = c > 0n ? this.sumProd : this.diffMax;
        let [p, q] = g(a, b);
        return p * 1000n + q;
      }
    }`;
    const S = `contract C {
      function sumProd(uint256 a, uint256 b) internal pure returns (uint256, uint256) { return (a + b, a * b); }
      function diffMax(uint256 a, uint256 b) internal pure returns (uint256, uint256) { return (a - b, a > b ? a : b); }
      function run(uint256 c, uint256 a, uint256 b) external pure returns (uint256) {
        function(uint256, uint256) pure returns (uint256, uint256) g = c > 0 ? sumProd : diffMax;
        (uint256 p, uint256 q) = g(a, b);
        return p * 1000 + q;
      }
    }`;
    const rs = await diff(J, S, [
      '0x' + sel('run(uint256,uint256,uint256)') + W(1) + W(7) + W(3),
      '0x' + sel('run(uint256,uint256,uint256)') + W(0) + W(7) + W(3),
    ]);
    expect(BigInt(rs[0]!.returnHex)).toBe(10021n);
    expect(BigInt(rs[1]!.returnHex)).toBe(4007n);
  });

  it('tuple-ASSIGN form [p, q] = g(a, b) and a MIXED [u256, string] return tuple', async () => {
    const J = `@contract class C {
      mk(a: u256): [u256, string] { return [a + 1n, "hi"]; }
      @external run(a: u256): u256 {
        let g: (a: u256) => [u256, string] = this.mk;
        let p: u256 = 0n;
        let s: string = "";
        [p, s] = g(a);
        return p * 100n + bytes(s).length;
      }
    }`;
    const S = `contract C {
      function mk(uint256 a) internal pure returns (uint256, string memory) { return (a + 1, "hi"); }
      function run(uint256 a) external pure returns (uint256) {
        function(uint256) pure returns (uint256, string memory) g = mk;
        uint256 p = 0;
        string memory s = "";
        (p, s) = g(a);
        return p * 100 + bytes(s).length;
      }
    }`;
    const [r] = await diff(J, S, ['0x' + sel('run(uint256)') + W(9)]);
    expect(BigInt(r!.returnHex)).toBe(1002n);
  });

  it('KEPT REJECTS: value-position use (JETH244), arity mismatch (JETH066), sig mismatch (JETH428)', () => {
    const base = `@contract class C {
      two(a: u256, b: u256): [u256, u256] { return [a + b, a * b]; }
      @external run(a: u256, b: u256): u256 {
        let g: (a: u256, b: u256) => [u256, u256] = this.two;
        BODY
      }
    }`;
    expect(codes(base.replace('BODY', 'let x: u256 = g(a, b); return x;'))).toContain('JETH244');
    expect(codes(base.replace('BODY', 'let [p, q, r] = g(a, b); return p + q + r;'))).toContain('JETH066');
    expect(
      codes(`@contract class C {
        one(a: u256): u256 { return a + 1n; }
        @external run(a: u256): u256 {
          let g: (a: u256) => [u256, u256] = this.one;
          let [p, q] = g(a); return p + q;
        }
      }`),
    ).toContain('JETH428');
  });
});

// ---------------------------------------------------------------------------------------------------
// L11a - funcref field in a DYNAMIC struct
// ---------------------------------------------------------------------------------------------------
const FD = `@struct class Fd { f: (x: u256) => u256; s: string; }`;
const FD_S = `struct Fd { function(uint256) pure returns (uint256) f; string s; }`;
describe('L11a: funcref field in a dynamic struct (byte-identical)', () => {
  it('ctor Fd(this.inc, "hi"), call d.f(5n), read d.s via bytes().length', async () => {
    const J = `${FD}
    @contract class C {
      inc(x: u256): u256 { return x + 1n; }
      @external run(): u256 { let d: Fd = Fd(this.inc, "hey"); return d.f(5n) * 10n + bytes(d.s).length; }
    }`;
    const S = `contract C { ${FD_S}
      function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
      function run() external pure returns (uint256) { Fd memory d = Fd(inc, "hey"); return d.f(5) * 10 + bytes(d.s).length; }
    }`;
    const [r] = await diff(J, S, ['0x' + sel('run()')]);
    expect(BigInt(r!.returnHex)).toBe(63n); // 6*10 + 3: non-vacuous anchor
  });

  it('field WRITE d.f = this.dec, storage COPY (let m: Fd = this.d), and alias mutation', async () => {
    const J = `${FD}
    @contract class C {
      @state d: Fd;
      inc(x: u256): u256 { return x + 1n; }
      dec(x: u256): u256 { return x - 1n; }
      constructor() { this.d = Fd(this.inc, "abc"); }
      @external fromStorage(): u256 { let m: Fd = this.d; return m.f(41n) + bytes(m.s).length; }
      @external rewrite(c: u256): u256 {
        let d: Fd = Fd(this.inc, "hi");
        let e: Fd = d;
        if (c > 0n) { e.f = this.dec; }
        return d.f(10n);
      }
    }`;
    const S = `contract C { ${FD_S}
      Fd d;
      function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
      function dec(uint256 x) internal pure returns (uint256) { return x - 1; }
      constructor() { d = Fd(inc, "abc"); }
      function fromStorage() external view returns (uint256) { Fd memory m = d; return m.f(41) + bytes(m.s).length; }
      function rewrite(uint256 c) external pure returns (uint256) {
        Fd memory d_ = Fd(inc, "hi");
        Fd memory e = d_;
        if (c > 0) { e.f = dec; }
        return d_.f(10);
      }
    }`;
    const rs = await diff(J, S, [
      '0x' + sel('fromStorage()'),
      '0x' + sel('rewrite(uint256)') + W(1),
      '0x' + sel('rewrite(uint256)') + W(0),
    ]);
    expect(BigInt(rs[0]!.returnHex)).toBe(45n); // 42 + 3
    expect(BigInt(rs[1]!.returnHex)).toBe(9n); // alias write visible through original
    expect(BigInt(rs[2]!.returnHex)).toBe(11n);
  });

  it('ternary over two Fd locals consumed via .f(...) (the F4-3-adjacent spelling)', async () => {
    const J = `${FD}
    @contract class C {
      inc(x: u256): u256 { return x + 1n; }
      dec(x: u256): u256 { return x - 1n; }
      @external run(c: u256): u256 {
        let a: Fd = Fd(this.inc, "a");
        let b: Fd = Fd(this.dec, "b");
        let d: Fd = c > 0n ? a : b;
        return d.f(10n);
      }
    }`;
    const S = `contract C { ${FD_S}
      function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
      function dec(uint256 x) internal pure returns (uint256) { return x - 1; }
      function run(uint256 c) external pure returns (uint256) {
        Fd memory a = Fd(inc, "a");
        Fd memory b = Fd(dec, "b");
        Fd memory d = c > 0 ? a : b;
        return d.f(10);
      }
    }`;
    const rs = await diff(J, S, ['0x' + sel('run(uint256)') + W(1), '0x' + sel('run(uint256)') + W(0)]);
    expect(BigInt(rs[0]!.returnHex)).toBe(11n);
    expect(BigInt(rs[1]!.returnHex)).toBe(9n);
  });

  it('consumer axis: Fd as an @internal argument AND an @internal return; storage Fd[] push', async () => {
    const J = `${FD}
    @contract class C {
      @state arr: Fd[];
      inc(x: u256): u256 { return x + 1n; }
      use(d: Fd): u256 { return d.f(20n) + bytes(d.s).length; }
      mk(): Fd { return Fd(this.inc, "ab"); }
      @external run(): u256 { let d: Fd = this.mk(); return this.use(d); }
      @external pushRead(): u256 {
        this.arr.push(Fd(this.inc, "pq"));
        let m: Fd = this.arr[0n];
        return m.f(50n) + bytes(m.s).length;
      }
    }`;
    const S = `contract C { ${FD_S}
      Fd[] arr;
      function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
      function use(Fd memory d) internal pure returns (uint256) { return d.f(20) + bytes(d.s).length; }
      function mk() internal pure returns (Fd memory) { return Fd(inc, "ab"); }
      function run() external pure returns (uint256) { Fd memory d = mk(); return use(d); }
      function pushRead() external returns (uint256) {
        arr.push(Fd(inc, "pq"));
        Fd memory m = arr[0];
        return m.f(50) + bytes(m.s).length;
      }
    }`;
    const rs = await diff(J, S, ['0x' + sel('run()'), '0x' + sel('pushRead()')]);
    expect(BigInt(rs[0]!.returnHex)).toBe(23n); // 21 + 2
    expect(BigInt(rs[1]!.returnHex)).toBe(53n); // 51 + 2
  });

  it('KEPT REJECTS: every ABI boundary of a funcref-bearing struct still rejects (solc parity)', () => {
    const C = (body: string) => `${FD}\n@contract class C { inc(x: u256): u256 { return x + 1n; } ${body} }`;
    // @external return / param (JETH426 signature gate)
    expect(codes(C(`@external run(): Fd { return Fd(this.inc, "hi"); }`))).toContain('JETH426');
    expect(codes(C(`@external run(d: Fd): u256 { return 1n; }`))).toContain('JETH426');
    // abi.encode / encodePacked (JETH173)
    expect(codes(C(`@external run(): bytes { let d: Fd = Fd(this.inc, "hi"); return abi.encode(d); }`))).toContain('JETH173');
    expect(codes(C(`@external run(): bytes { let d: Fd = Fd(this.inc, "hi"); return abi.encodePacked(d); }`))).toContain('JETH173');
    // constructor param (JETH302), public getter (JETH057), abi.decode target (JETH322)
    expect(codes(`${FD}\n@contract class C { @state x: u256; constructor(d: Fd) { this.x = 1n; } }`)).toContain('JETH302');
    expect(codes(`${FD}\n@contract class C { @external @state d: Fd; inc(x: u256): u256 { return x + 1n; } constructor() { this.d = Fd(this.inc, "a"); } }`)).toContain('JETH057');
    expect(codes(C(`@external run(b: bytes): u256 { let d: Fd = abi.decode(b, Fd); return 1n; }`))).toContain('JETH322');
    // @interface param + return (JETH347 / JETH348)
    expect(
      codes(`${FD}\n@interface class IX { @external g(d: Fd): u256; }\n@contract class C { z(x: u256): u256 { return x; } @external run(t: address): u256 { let d: Fd = Fd(this.z, "a"); return IX(t).g(d); } }`),
    ).toContain('JETH347');
    expect(
      codes(`${FD}\n@interface class IX { @external g(): Fd; }\n@contract class C { @external run(t: address): u256 { let d: Fd = IX(t).g(); return 1n; } }`),
    ).toContain('JETH348');
  });
});

// ---------------------------------------------------------------------------------------------------
// L14 - struct getter as interface impl
// ---------------------------------------------------------------------------------------------------
describe('L14: @external @state struct var implements a tuple-returning @interface method', () => {
  const JETH = (getterDecl: string) => `
    @interface class IG { @external @view g(): [u256, u256]; }
    @struct class S6 { a: u256; b: u256; }
    @contract class C extends IG {
      ${getterDecl}
      constructor() { this.g = S6(7n, 8n); }
      @external @view viaIface(): u256 {
        let [x, y] = IG(address(this)).g();
        return x * 100n + y;
      }
    }`;
  const SOL = (getterDecl: string) => `
    interface IG { function g() external view returns (uint256, uint256); }
    contract C is IG {
      struct S6 { uint256 a; uint256 b; }
      ${getterDecl}
      constructor() { g = S6(7, 8); }
      function viaIface() external view returns (uint256) {
        (uint256 x, uint256 y) = IG(address(this)).g();
        return x * 100 + y;
      }
    }`;

  it('WITHOUT @override (solc >= 0.8.8 needs none), incl. the interface-typed external call', async () => {
    const rs = await diff(JETH('@external @state g: S6;'), SOL('S6 public g;'), [
      '0x' + sel('g()'),
      '0x' + sel('viaIface()'),
    ]);
    expect(rs[0]!.returnHex).toBe('0x' + W(7) + W(8)); // flattened (7, 8): non-vacuous anchor
    expect(BigInt(rs[1]!.returnHex)).toBe(708n);
  });

  it('WITH @override on both sides', async () => {
    const rs = await diff(JETH('@external @state @override g: S6;'), SOL('S6 public override g;'), [
      '0x' + sel('g()'),
    ]);
    expect(rs[0]!.returnHex).toBe('0x' + W(7) + W(8));
  });

  it('a struct with a string field flattens to (u256, string) and still satisfies the interface', async () => {
    const J = `
      @interface class IG { @external @view g(): [u256, string]; }
      @struct class Sm { a: u256; s: string; }
      @contract class C extends IG {
        @external @state g: Sm;
        constructor() { this.g = Sm(5n, "hey"); }
      }`;
    const S = `
      interface IG { function g() external view returns (uint256, string memory); }
      contract C is IG {
        struct Sm { uint256 a; string s; }
        Sm public g;
        constructor() { g = Sm(5, "hey"); }
      }`;
    const [r] = await diff(J, S, ['0x' + sel('g()')]);
    expect(r!.returnHex).toContain('686579'); // "hey" payload present: non-vacuous
  });

  it('KEPT REJECTS: mismatched returns and a @pure interface method still fail (JETH385)', () => {
    const mismatch = `
      @interface class IG { @external @view g(): u256; }
      @struct class S6 { a: u256; b: u256; }
      @contract class C extends IG { @external @state g: S6; constructor() { this.g = S6(7n, 8n); } }`;
    expect(codes(mismatch)).toContain('JETH385');
    const pure = `
      @interface class IG { @external @pure g(): [u256, u256]; }
      @struct class S6 { a: u256; b: u256; }
      @contract class C extends IG { @external @state g: S6; constructor() { this.g = S6(7n, 8n); } }`;
    expect(codes(pure)).toContain('JETH385');
  });
});

// ---------------------------------------------------------------------------------------------------
// L15 - generic @modifier
// ---------------------------------------------------------------------------------------------------
describe('L15: generic @modifier monomorphization (explicit + inferred)', () => {
  it('two instantiations in one contract (u256 explicit + inferred; i256 explicit with a revert path)', async () => {
    const J = `@contract class C {
      @modifier lim<T>(v: T) { require(v > 0n, "neg"); _; }
      @lim<u256>(3n) @external f(x: u256): u256 { return x + 1n; }
      @lim(4n) @external h(x: u256): u256 { return x + 2n; }
      @lim<i256>(0n - 5n) @external g(x: u256): u256 { return x + 3n; }
    }`;
    const S = `contract C {
      modifier limU(uint256 v) { require(v > 0, "neg"); _; }
      modifier limI(int256 v) { require(v > 0, "neg"); _; }
      function f(uint256 x) external limU(3) returns (uint256) { return x + 1; }
      function h(uint256 x) external limU(4) returns (uint256) { return x + 2; }
      function g(uint256 x) external limI(-5) returns (uint256) { return x + 3; }
    }`;
    const rs = await diff(J, S, [
      '0x' + sel('f(uint256)') + W(9),
      '0x' + sel('h(uint256)') + W(9),
      '0x' + sel('g(uint256)') + W(9), // reverts "neg" byte-identically (the i256 instantiation)
    ]);
    expect(BigInt(rs[0]!.returnHex)).toBe(10n);
    expect(BigInt(rs[1]!.returnHex)).toBe(11n);
    expect(rs[2]!.success).toBe(false); // non-vacuous: the i256 monomorph really evaluated -5 > 0
  });

  it('post-placeholder code (buffered path) + modifier args evaluated exactly once', async () => {
    const J = `@contract class C {
      @state count: u256;
      bump(): u256 { this.count = this.count + 1n; return this.count; }
      @modifier tick<T>(v: T) { require(v > 0n, "z"); _; this.count = this.count + 100n; }
      @tick(this.bump()) @external f(x: u256): u256 { return x + this.count; }
      @external @view peek(): u256 { return this.count; }
    }`;
    const S = `contract C {
      uint256 count;
      function bump() internal returns (uint256) { count = count + 1; return count; }
      modifier tick(uint256 v) { require(v > 0, "z"); _; count = count + 100; }
      function f(uint256 x) external tick(bump()) returns (uint256) { return x + count; }
      function peek() external view returns (uint256) { return count; }
    }`;
    const rs = await diff(J, S, ['0x' + sel('f(uint256)') + W(7), '0x' + sel('peek()')]);
    expect(BigInt(rs[0]!.returnHex)).toBe(8n); // bump() ran ONCE (count=1) before the body
    expect(BigInt(rs[1]!.returnHex)).toBe(101n); // + post-placeholder 100
  });

  it('KEPT REJECTS: only UNINSTANTIABLE uses fail (JETH327); non-value type args fail (JETH291)', () => {
    const uninstantiable = `@contract class C {
      @modifier lim<T>(v: T) { require(v > 0n, "z"); _; }
      @lim @external f(x: u256): u256 { return x + 1n; }
    }`;
    expect(codes(uninstantiable)).toContain('JETH327');
    const refTypeArg = `@contract class C {
      @modifier lim<T>(v: T) { require(v > 0n, "z"); _; }
      @lim<string>("a") @external f(x: u256): u256 { return x + 1n; }
    }`;
    expect(codes(refTypeArg)).toContain('JETH291');
  });
});
