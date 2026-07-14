// Integrating the residual lifts, the CONTRACT-TYPE-VALUE work surfaced a PRE-EXISTING over-acceptance from
// IFACE-VALUE-TYPE: `.balance` / `.code` / `.codehash` on an INTERFACE-typed VALUE were accepted, but solc
// rejects them ("Member ... not found ... Use address(i).balance") - a contract/interface value does not expose
// the raw address surface without an explicit `address(i)` unwrap. The gate (previously keyed only to the
// `__ctref:` contract brand) now covers interface brands too (isNominalAddressValue). Pinned here.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';

const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e;
  }
};
const I = 'interface I { m(): View<u256>; }\n';

describe('OA fix: the raw address surface is not exposed on an interface VALUE (solc parity)', () => {
  it('rejects i.balance / i.code / i.codehash; address(i).x, i.m(), and a plain-address .balance still work', () => {
    expect(codes(I + `class C { i: I; get f(): External<u256> { return this.i.balance; } }`)).toContain('JETH352');
    expect(codes(I + `class C { i: I; get f(): External<u256> { return this.i.code.length; } }`)).toContain('JETH352');
    expect(codes(I + `class C { i: I; get f(): External<bytes32> { return this.i.codehash; } }`)).toContain('JETH352');
    // legitimate uses stay accepted
    expect(codes(I + `class C { i: I; get f(): External<u256> { return address(this.i).balance; } }`)).toEqual([]);
    expect(codes(I + `class C { i: I; get f(): External<u256> { return this.i.m(); } }`)).toEqual([]); // method dispatch
    expect(codes(`class C { a: address; get f(): External<u256> { return this.a.balance; } }`)).toEqual([]); // plain address
  });
});
