// Item #7: in NATIVE mode a `static` contract field is the native spelling of a compile-time @constant
// (when it carries an initializer) or a constructor-set @immutable (when it does not). It routes through the
// exact same collectConstant/collectImmutable path, so it is byte-identical to the decorated form and to
// solc's `constant`/`immutable` (no storage slot; a const read is pure, an immutable read is view).
// Idiomatic TS reads a static member as `ClassName.K`; a pre-pass (compile.ts rewriteStaticFieldAccess)
// rewrites `C.K` -> `this.K`, so both `C.K` (IDE-clean) and `this.K` work.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const compiled = (src: string) => compile(src, { fileName: 'C.jeth' });
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

describe('static = constant / immutable (item #7)', () => {
  it('a static const is byte-identical to @constant (pure read, no slot); static immutable to @immutable', () => {
    expect(bc(`class C { static K: u256 = 5n; @external calc(a: u256): u256 { return a + C.K; } }`))
      .toBe(bc(`@contract class C { @constant K: u256 = 5n; @external calc(a: u256): u256 { return a + this.K; } }`));
    expect(bc(`class C { static M: u256; constructor(){ this.M = 7n; } @external @view getM(): u256 { return C.M; } }`))
      .toBe(bc(`@contract class C { @immutable M: u256; constructor(){ this.M = 7n; } @external @view getM(): u256 { return this.M; } }`));
    // no storage slot for either; a const read infers pure, an immutable read infers view.
    const rC = compiled(`class C { static K: u256 = 5n; @external readK(): u256 { return C.K; } }`);
    expect(rC.storageLayout).toEqual([]);
    expect(rC.abi.filter((f: any) => f.type === 'function').map((f: any) => f.stateMutability)).toEqual(['pure']);
    const rM = compiled(`class C { static M: u256; constructor(){ this.M = 7n; } @external readM(): u256 { return C.M; } }`);
    expect(rM.storageLayout).toEqual([]);
    expect(rM.abi.filter((f: any) => f.type === 'function').map((f: any) => f.stateMutability)).toEqual(['view']);
  });

  it('`C.K` and `this.K` both resolve to the constant, byte-identically', () => {
    expect(bc(`class C { static K: u256 = 5n; @external @pure f(a: u256): u256 { return a + C.K; } }`))
      .toBe(bc(`class C { static K: u256 = 5n; @external @pure f(a: u256): u256 { return a + this.K; } }`));
  });

  it('a static const + immutable contract runs byte-identical to solc (via idiomatic `C.K`)', async () => {
    const J = `class C {
      static K: u256 = 100n;
      static M: u256;
      constructor(){ this.M = 42n; }
      @external @pure kk(): u256 { return C.K; }
      @external @view mm(): u256 { return C.M; }
      @external calc(a: u256): u256 { return a + C.K + C.M; } }`;
    const S = `contract C {
      uint256 constant K = 100;
      uint256 immutable M;
      constructor(){ M = 42; }
      function kk() external pure returns(uint256){ return K; }
      function mm() external view returns(uint256){ return M; }
      function calc(uint256 a) external view returns(uint256){ return a + K + M; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['kk()', ''], ['mm()', ''], ['calc(uint256)', pad32(5n)]] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('`@external` on a static const exposes the public-constant getter, like @external @constant', () => {
    expect(bc(`class C { @external static K: u256 = 5n; }`)).toBe(bc(`@contract class C { @external @constant K: u256 = 5n; }`));
    expect(compiled(`class C { @external static K: u256 = 5n; }`).abi.filter((f: any) => f.type === 'function').map((f: any) => f.name)).toEqual(['K']);
  });

  it('rejects: a static field with no type annotation, and a static field in decorator mode', () => {
    expect(codes(`class C { static K = 5n; @external @view f(): u256 { return C.K; } }`)).toContain('JETH045'); // needs a type
    // decorator mode: a static field is not a JETH concept -> the field must be @state/@constant/@immutable.
    expect(codes(`// use @decorators\n@contract class C { static K: u256 = 5n; @external @view f(): u256 { return 1n; } }`)).toContain('JETH045');
  });

  it('the C.K rewrite is scope-safe: a local/param shadowing the contract reads the LOCAL field, not the constant', async () => {
    // sweep finding (silent miscompile): a param/local named like the contract must win over the static const.
    const J = `type P = { K: u256 }; class C { static K: u256 = 999n; @external @pure f(C: P): u256 { return C.K; } }`;
    const h = await Harness.create();
    const a = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const r = await h.call(a, sel('f((uint256))') + pad32(7n));
    expect(BigInt(r.returnHex)).toBe(7n); // the param's field, NOT the constant 999
  });

  it('a `static` field on a @struct/@interface/@library class does not hijack a same-named contract member', () => {
    // sweep finding: harvesting static names from non-contract classes poisoned the rewrite map.
    expect(codes(`@struct class S { static count: u256; x: u256; } class C { @state count: u256; @external @view foo(): u256 { return S.count; } }`)).toContain('JETH074');
  });
});
