// TERN-STRUCT-ARR for-of lift: `for (const e of (c ? a : b))` over a fixed struct array (Arr<In,N>)
// was rejected JETH074 - the desugar re-embedded the ternary in the `.length` / `[i]` positions, where a
// bare pointer-headed struct-array ternary can't self-type (and would re-evaluate per iteration). The
// analyzer now binds a conditional iterable ONCE to a synth const (the type inferred from a branch; the
// paren-stripped conditional, matching the already-sound `let p: T = c ? a : b` bind), then iterates the
// const. A for-of over the loop variable is read-only, so no aliasing witness fires - byte-identical to
// the manual `let p = c ? a : b; for (const e of p)` workaround. Every row is run and asserted
// byte-identical to solc 0.8.35 (returndata), across mem|storage, mem|mem, and a plain-array regression.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const rejects = (src: string): boolean => {
  try { compile(src, { fileName: 'C.jeth' }); return false; } catch { return true; }
};

describe('TERN-STRUCT-ARR for-of lift - byte-identical to solc 0.8.35', () => {
  it('for-of over a ternary struct array (mem|storage, mem|mem) + plain regression', async () => {
    const J = `type In = { a: u256; b: u256; };
      class C {
        fa: Arr<In,2>;
        seed(): External<void> { this.fa[0n] = In(100n,200n); this.fa[1n] = In(300n,400n); }
        get tern(c: bool): External<u256> { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let s: u256 = 0n; for (const e of (c ? m : this.fa)) { s = s + e.a*10n + e.b; } return s; }
        get memmem(c: bool): External<u256> { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let n: Arr<In,2> = [In(5n,6n),In(7n,8n)]; let s: u256 = 0n; for (const e of (c ? m : n)) { s = s + e.a*10n + e.b; } return s; }
        get plain(): External<u256> { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let s: u256 = 0n; for (const e of m) { s = s + e.a; } return s; } }`;
    const S = `struct In { uint256 a; uint256 b; }
      contract C {
        In[2] fa;
        function seed() external { fa[0]=In(100,200); fa[1]=In(300,400); }
        function tern(bool c) external view returns(uint256){ In[2] memory m; m[0]=In(1,2); m[1]=In(3,4); uint256 s=0; In[2] memory src = c ? m : fa; for(uint i=0;i<src.length;i++){ In memory e=src[i]; s+=e.a*10+e.b; } return s; }
        function memmem(bool c) external pure returns(uint256){ In[2] memory m; m[0]=In(1,2); m[1]=In(3,4); In[2] memory n; n[0]=In(5,6); n[1]=In(7,8); uint256 s=0; In[2] memory src = c ? m : n; for(uint i=0;i<src.length;i++){ In memory e=src[i]; s+=e.a*10+e.b; } return s; }
        function plain() external pure returns(uint256){ In[2] memory m; m[0]=In(1,2); m[1]=In(3,4); uint256 s=0; for(uint i=0;i<m.length;i++){ s+=m[i].a; } return s; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, sel('seed()'));
    await h.call(as, sel('seed()'));
    const calls: [string, string][] = [
      ['tern(bool)', W(1)], ['tern(bool)', W(0)],
      ['memmem(bool)', W(1)], ['memmem(bool)', W(0)],
      ['plain()', ''],
    ];
    for (const [sg, args] of calls) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg + ' ' + args).toBe(rs.success);
      expect(rj.returnHex, sg + ' ' + args).toBe(rs.returnHex);
    }
  });

  it('boundaries: for-of over a plain array + over a bound ternary local still accept; a call iterable still rejects', () => {
    const IN = `type In = { a: u256; b: u256; };`;
    // the manual bind-then-for-of still works
    expect(rejects(`${IN} class C { fa: Arr<In,2>; get r(c: bool): External<u256> { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let p: Arr<In,2> = c ? m : this.fa; let s: u256 = 0n; for (const e of p) { s = s + e.a; } return s; } }`)).toBe(false);
    // a call iterable is still rejected (must bind first - re-evaluation hazard), JETH117
    expect(rejects(`${IN} class C { mk(): Arr<In,2> { return [In(1n,2n),In(3n,4n)]; } get r(): External<u256> { let s: u256 = 0n; for (const e of this.mk()) { s = s + e.a; } return s; } }`)).toBe(true);
  });
});
