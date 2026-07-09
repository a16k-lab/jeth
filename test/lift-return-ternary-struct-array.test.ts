// TERN-STRUCT-ARR read-only value-consumer lift (phase 1a): a ternary over a fixed struct array used as
// the WHOLE return value - `return c ? m : this.fa` (Arr<In,N>) - was rejected JETH074 (the "flat consumer
// of a pointer-headed memory branch leaks pointer words into the ABI payload", the MC-2..MC-6 family). It
// now bind-hoists the ternary to a synth const (only when it is the ENTIRE statement value, and only for
// the cluster-1-supported branch kinds: memAggregate local + storage/literal), then returns the bound
// standalone local - byte-identical to the manual `let p = c ? a : b; return p`, no aliasing hazard.
// BOUNDARIES kept as sound rejects: abi.encode / internal-call arg of the ternary (mutation-sensitive /
// nested, pending the parameter-effect analysis), and abiDecode/call/arrayGet-branch ternaries (RC-1/RC-2).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const IN = `@struct class In { a: u256; b: u256; }`;
const rejects = (src: string): boolean => {
  try { compile(src, { fileName: 'C.jeth' }); return false; } catch { return true; }
};

describe('TERN-STRUCT-ARR return lift - byte-identical to solc 0.8.35', () => {
  it('return c ? m : this.fa (mem|storage) and c ? m : n (mem|mem)', async () => {
    const J = `${IN}
      @contract class C {
        @state fa: Arr<In,2>;
        @external seed() { this.fa[0n]=In(100n,200n); this.fa[1n]=In(300n,400n); }
        @external @view retT(c: bool): Arr<In,2> { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; return c ? m : this.fa; }
        @external @pure retMM(c: bool): Arr<In,2> { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let n: Arr<In,2> = [In(5n,6n),In(7n,8n)]; return c ? m : n; } }`;
    const S = `struct In { uint256 a; uint256 b; }
      contract C {
        In[2] fa;
        function seed() external { fa[0]=In(100,200); fa[1]=In(300,400); }
        function retT(bool c) external view returns(In[2] memory){ In[2] memory m; m[0]=In(1,2); m[1]=In(3,4); return c ? m : fa; }
        function retMM(bool c) external pure returns(In[2] memory){ In[2] memory m; m[0]=In(1,2); m[1]=In(3,4); In[2] memory n; n[0]=In(5,6); n[1]=In(7,8); return c ? m : n; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, sel('seed()'));
    await h.call(as, sel('seed()'));
    for (const [sg, args] of [['retT(bool)', W(1)], ['retT(bool)', W(0)], ['retMM(bool)', W(1)], ['retMM(bool)', W(0)]] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg + ' ' + args).toBe(rs.success);
      expect(rj.returnHex, sg + ' ' + args).toBe(rs.returnHex);
    }
  });

  it('read-only consumers lift (return + arg-0 abi.encode); mutation-sensitive / non-first-arg / abiDecode-branch stay sound rejects', () => {
    const base = `${IN} @contract class C { @state fa: Arr<In,2>; g(p: Arr<In,2>): u256 { return p[0n].a; }`;
    // whole return lifts:
    expect(rejects(`${base} @external @view r(c: bool): Arr<In,2> { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; return c ? m : this.fa; } }`)).toBe(false);
    // abi.encode(ternary) as arg 0 of a whole-statement encode LIFTS (read-only, byte-identical; verified
    // in lift-or-cluster1.test.ts):
    expect(rejects(`${base} @external @view r(c: bool): bytes { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; return abi.encode(c ? m : this.fa); } }`)).toBe(false);
    // internal-call arg 0 now LIFTS (JETH passes a standalone Arr<In,N> to an internal fn by reference,
    // byte-identical incl. W1/W2/W3; see the differential below):
    expect(rejects(`${base} @external @view r(c: bool): u256 { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; return this.g(c ? m : this.fa); } }`)).toBe(false);
    // a NON-first-arg call/encode ternary stays a reject (eval-order: only arg 0 is the statement's first side effect):
    expect(rejects(`${base} @external @view r(c: bool): bytes { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; return abi.encode(7n, c ? m : this.fa); } }`)).toBe(true);
    // element-write RHS is mutation-sensitive (not arg 0 of a call, not a whole-statement value) -> still rejects:
    expect(rejects(`${IN} @contract class C { @external @pure r(c: bool): u256 { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let n: Arr<In,2> = [In(5n,6n),In(7n,8n)]; let o: Arr<Arr<In,2>,2> = [[In(0n,0n),In(0n,0n)],[In(0n,0n),In(0n,0n)]]; o[0n] = c ? m : n; return o[0n][0n].a; } }`)).toBe(true);
    // an arrayGet-branch ternary (c ? xs[0] : m over Arr<Arr<In,2>,2>) is a separate reject, not hoisted
    expect(rejects(`${IN} @contract class C { @external @pure r(c: bool): Arr<In,2> { let xs: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)]]; let m: Arr<In,2> = [In(9n,9n),In(9n,9n)]; return c ? xs[0n] : m; } }`)).toBe(true);
  });

  it('internal-call arg 0 of a ternary struct array - byte-identical incl. W1 field-write / W2 re-point / W3 cross-alias', async () => {
    const J = `${IN}
      @contract class C {
        mut(p: Arr<In,2>): void { p[0n].a = 77n; }
        rep(p: Arr<In,2>): void { p[1n] = p[0n]; p[0n].a = 7n; }
        g3(p: Arr<In,2>, q: Arr<In,2>): u256 { p[0n].a = 99n; return q[0n].a; }
        @external @pure w1(c: bool): u256 { let m: Arr<In,2>=[In(1n,2n),In(3n,4n)]; let n: Arr<In,2>=[In(5n,6n),In(7n,8n)]; this.mut(c ? m : n); return m[0n].a*1000n + n[0n].a; }
        @external @pure w2(c: bool): u256 { let m: Arr<In,2>=[In(1n,2n),In(3n,4n)]; let n: Arr<In,2>=[In(5n,6n),In(7n,8n)]; this.rep(c ? m : n); return m[1n].a*1000n + n[1n].a; }
        @external @pure w3(c: bool): u256 { let m: Arr<In,2>=[In(1n,2n),In(3n,4n)]; let n: Arr<In,2>=[In(5n,6n),In(7n,8n)]; return this.g3(c ? m : n, m); } }`;
    const S = `struct In { uint256 a; uint256 b; }
      contract C {
        function mut(In[2] memory p) internal pure { p[0].a=77; }
        function rep(In[2] memory p) internal pure { p[1]=p[0]; p[0].a=7; }
        function g3(In[2] memory p, In[2] memory q) internal pure returns(uint256){ p[0].a=99; return q[0].a; }
        function w1(bool c) external pure returns(uint256){ In[2] memory m=[In(1,2),In(3,4)]; In[2] memory n=[In(5,6),In(7,8)]; mut(c?m:n); return m[0].a*1000+n[0].a; }
        function w2(bool c) external pure returns(uint256){ In[2] memory m=[In(1,2),In(3,4)]; In[2] memory n=[In(5,6),In(7,8)]; rep(c?m:n); return m[1].a*1000+n[1].a; }
        function w3(bool c) external pure returns(uint256){ In[2] memory m=[In(1,2),In(3,4)]; In[2] memory n=[In(5,6),In(7,8)]; return g3(c?m:n, m); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['w1(bool)', W(1)], ['w1(bool)', W(0)], ['w2(bool)', W(1)], ['w2(bool)', W(0)], ['w3(bool)', W(1)], ['w3(bool)', W(0)]] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg + ' ' + args).toBe(rs.success);
      expect(rj.returnHex, sg + ' ' + args).toBe(rs.returnHex);
    }
  });
});
