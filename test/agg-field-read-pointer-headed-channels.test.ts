// Round-3 coverage-proof finding (MC-cert-1, the last uncovered cell): a whole Arr<In,N> FIELD of a
// struct-array element (xs[i].pre, kind aggFieldRead) is an INLINE-FLAT sub-pointer into the parent's
// element image, NOT the pointer-headed canonical representation. Three channels routed through
// aggArgToMemPtr admitted it and misread data words as element pointers - a payload-corrupting
// miscompile family (4 witnesses): an internal-call arg (dynamic and fixed outer), an internal
// return value, and a pointer-headed element-write RHS (o[i] = xs[j].pre). Transcoding is NOT
// semantics-preserving (solc passes a LIVE REFERENCE into the parent image - callee/alias mutations
// write through; a fresh copy would trade the miscompile for a mutation-visibility miscompile), so
// aggArgToMemPtr now REJECTS the kind loudly for isStaticStructFixedLeafArray types. The FLAT
// consumers of the same source (external return, abi.encode, whole-element struct arg, leaf reads)
// stay byte-identical to solc 0.8.35.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const rejects = (src: string): boolean => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
};

const D = `type In = { x: u256; y: u256 };
type P = { pre: Arr<In,2>; n: u256 };`;
const SD = `struct In { uint256 x; uint256 y; } struct P { In[2] pre; uint256 n; }`;
const take = `take(m: Arr<In,2>): u256 { return m[0n].x * 1000000n + m[0n].y * 10000n + m[1n].x * 100n + m[1n].y; }`;
const mk = `const xs: P[] = [P([In(31n,32n),In(33n,34n)],5n), P([In(41n,42n),In(43n,44n)],6n)];`;
const smk = `P[] memory xs = new P[](2); xs[0]=P([In(31,32),In(33,34)],5); xs[1]=P([In(41,42),In(43,44)],6);`;

describe('aggFieldRead of Arr<In,N> through the pointer-headed channels (MC-cert-1)', () => {
  it('the four miscompile channels now cleanly reject (never wrong bytes)', () => {
    // 1a: internal-call arg, dynamic-outer parent.
    expect(rejects(`${D} class C { ${take} get a(): External<u256> { ${mk} return this.take(xs[1n].pre); } }`)).toBe(true);
    // 1b: internal-call arg, fixed-outer parent.
    expect(rejects(`${D} class C { ${take} get b(): External<u256> { const m: Arr<P,2> = [P([In(31n,32n),In(33n,34n)],5n), P([In(41n,42n),In(43n,44n)],6n)]; return this.take(m[1n].pre); } }`)).toBe(true);
    // 1c: internal return of the field.
    expect(rejects(`${D} class C { ${take} pickF(): Arr<In,2> { ${mk} return xs[1n].pre; } get c(): External<u256> { return this.take(this.pickF()); } }`)).toBe(true);
    // 1d: pointer-headed element-write RHS.
    expect(rejects(`${D} class C { get d(): External<u256> { ${mk} const o: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)]]; o[0n] = xs[1n].pre; return o[0n][0n].x; } }`)).toBe(true);
  });

  it('the FLAT consumers of the same source stay byte-identical to solc', async () => {
    const J = `${D} class C {
  q(s: P): u256 { return s.pre[0n].x + s.n; }
  get ctl(): External<Arr<In,2>> { ${mk} return xs[1n].pre; }
  get ctlE(): External<bytes> { ${mk} return abi.encode(xs[1n].pre); }
  get ctlS(): External<u256> { ${mk} return this.q(xs[1n]); }
  get ctlV(): External<u256> { ${mk} return xs[1n].pre[0n].x + xs[1n].pre[1n].y; } }`;
    const S = `${SD} contract C {
  function q(P memory s) internal pure returns(uint256){ return s.pre[0].x + s.n; }
  function ctl() external pure returns(In[2] memory){ ${smk} return xs[1].pre; }
  function ctlE() external pure returns(bytes memory){ ${smk} return abi.encode(xs[1].pre); }
  function ctlS() external pure returns(uint256){ ${smk} return q(xs[1]); }
  function ctlV() external pure returns(uint256){ ${smk} return xs[1].pre[0].x + xs[1].pre[1].y; } }`;
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    for (const sg of ['ctl()', 'ctlE()', 'ctlS()', 'ctlV()']) {
      const jr = await h.call(ja, sel(sg));
      const sr = await h.call(sa, sel(sg));
      expect(jr.returnHex, sg).toBe(sr.returnHex);
      expect(jr.success, sg).toBe(sr.success);
    }
    // non-vacuity anchors: ctlV = 41 + 44 = 85; ctlS = 41 + 6 = 47.
    expect(BigInt((await h.call(ja, sel('ctlV()'))).returnHex)).toBe(85n);
    expect(BigInt((await h.call(ja, sel('ctlS()'))).returnHex)).toBe(47n);
  });
});
