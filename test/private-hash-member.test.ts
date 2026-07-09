// Item #2: a JS `#`-prefixed member name (`#f()` / `@state #y`) is JETH's spelling of Solidity
// `private`. Because private is byte-identical to internal in bytecode (visibility is compile-time
// only), a `#` member lowers exactly like an internal one - the analyzer rewrites each `#name` (the
// declaration and every `this.#name` access) to a contract-scoped internal identifier `$p$<C>$name`
// (src/compile.ts manglePrivateMembers). Per-contract scoping enforces visibility for free: a
// DERIVED contract that directly names a base's `#x` mangles to a name it never declared and rejects
// - exactly solc's "private is not visible in a derived contract". These tests pin (a) byte-identity
// vs solc's `private` at runtime + storage-read-back, (b) that `#` lowers IDENTICALLY to internal
// (same JETH creation bytecode), and (c) accept/reject parity for base/derived access.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const jrej = (src: string): boolean => {
  try { compile(src, { fileName: 'C.jeth' }); return false; } catch { return true; }
};
const srej = (src: string): boolean => {
  try { compileSolidity(SPDX + src, 'C'); return false; } catch { return true; }
};
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;

describe('# private members (item #2) - byte-identical to solc `private`', () => {
  it('T1: private method + private state runs byte-identical to solc private', async () => {
    const J = `@contract class C {
      @state #bal: u256;
      #tax(x: u256): u256 { return x / 10n; }
      @external deposit(a: u256): void { this.#bal = this.#bal + a - this.#tax(a); }
      @external @view balance(): u256 { return this.#bal; } }`;
    const S = `contract C {
      uint256 private bal;
      function tax(uint256 x) private pure returns(uint256){ return x/10; }
      function deposit(uint256 a) external { bal = bal + a - tax(a); }
      function balance() external view returns(uint256){ return bal; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['deposit(uint256)', W(1000)], ['balance()', ''], ['deposit(uint256)', W(55)], ['balance()', '']] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it("T2: a base's private is usable through its own inherited methods, byte-identical to solc", async () => {
    const J = `@abstract class Base { @state #secret: u256; @external @view reveal():u256{ return this.#secret; } @external stash(v:u256):void{ this.#secret=v; } }
      @contract class C extends Base { @state pub: u256; @external setPub(v:u256):void{ this.pub=v; } @external @view getPub():u256{ return this.pub; } }`;
    const S = `abstract contract Base { uint256 private secret; function reveal() external view returns(uint256){ return secret; } function stash(uint256 v) external { secret=v; } }
      contract C is Base { uint256 pub; function setPub(uint256 v) external { pub=v; } function getPub() external view returns(uint256){ return pub; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['stash(uint256)', W(77)], ['reveal()', ''], ['setPub(uint256)', W(9)], ['getPub()', ''], ['reveal()', '']] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('T3: same-name private in base AND derived are two distinct slots, byte-identical to solc', async () => {
    const J = `@abstract class Base { @state #s: u256; @external @view baseGet():u256{ return this.#s; } @external baseSet(v:u256):void{ this.#s=v; } }
      @contract class C extends Base { @state #s: u256; @external @view derGet():u256{ return this.#s; } @external derSet(v:u256):void{ this.#s=v; } }`;
    const S = `abstract contract Base { uint256 private s; function baseGet() external view returns(uint256){ return s; } function baseSet(uint256 v) external { s=v; } }
      contract C is Base { uint256 private s; function derGet() external view returns(uint256){ return s; } function derSet(uint256 v) external { s=v; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['baseSet(uint256)', W(11)], ['derSet(uint256)', W(22)], ['baseGet()', ''], ['derGet()', '']] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('T4: `#x` and a plain `x` coexist as distinct slots, byte-identical to solc', async () => {
    const J = `@contract class C { @state #v: u256; @state v: u256; @external seed():void{ this.#v=1n; this.v=2n; } @external @view sum():u256{ return this.#v*10n + this.v; } }`;
    const S = `contract C { uint256 private _v; uint256 v; function seed() external { _v=1; v=2; } function sum() external view returns(uint256){ return _v*10 + v; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const sg of ['seed()', 'sum()']) {
      const rj = await h.call(aj, sel(sg));
      const rs = await h.call(as, sel(sg));
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('T5: `#` lowers IDENTICALLY to internal (same JETH creation bytecode)', () => {
    // A `#` member differs from an internal member only in visibility (a compile-time concept), so
    // the emitted bytecode is identical - the strongest proof there is no codegen divergence.
    expect(bc(`@contract class C { #f(): u256 { return 42n; } @external @pure g(): u256 { return this.#f(); } }`))
      .toBe(bc(`@contract class C { f(): u256 { return 42n; } @external @pure g(): u256 { return this.f(); } }`));
    expect(bc(`@contract class C { @state #y: u256; @external s():void{ this.#y=9n; } @external @view r():u256{ return this.#y; } }`))
      .toBe(bc(`@contract class C { @state y: u256; @external s():void{ this.y=9n; } @external @view r():u256{ return this.y; } }`));
  });

  it('T6: derived contract directly naming a base private rejects - parity with solc', () => {
    const Jstate = `@abstract class Base { @state #secret: u256; } @contract class C extends Base { @external @view leak():u256{ return this.#secret; } }`;
    const Sstate = `abstract contract Base { uint256 private secret; } contract C is Base { function leak() external view returns(uint256){ return secret; } }`;
    expect(jrej(Jstate)).toBe(true);
    expect(srej(Sstate)).toBe(true);
    const Jmethod = `@abstract class Base { #hidden():u256{ return 1n; } } @contract class C extends Base { @external @view leak():u256{ return this.#hidden(); } }`;
    const Smethod = `abstract contract Base { function hidden() private pure returns(uint256){ return 1; } } contract C is Base { function leak() external view returns(uint256){ return hidden(); } }`;
    expect(jrej(Jmethod)).toBe(true);
    expect(srej(Smethod)).toBe(true);
  });
});
