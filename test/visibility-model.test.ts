// The JETH visibility model: @external is the SOLE writable visibility decorator (an exposed ABI entry).
// Everything without @external is INTERNAL (private-by-default: callable by name, never in the ABI).
// @public/@internal/@private/@hidden are removed (JETH440). A state-var getter is triggered by
// @external @state. @payable/@nonReentrant require @external. This dissolves the dual external+internal
// ("public") function, so an aggregate helper called internally just works (the old "R2" divergence).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';

function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e.diagnostics ? [...new Set<string>(e.diagnostics.map((d: any) => d.code as string))] : ['ERR'];
  }
}
const abiNames = (src: string): string[] =>
  compile(src, { fileName: 'C.jeth' })
    .abi.filter((a: any) => 'name' in a)
    .map((a: any) => a.name as string);

describe('visibility model: @external only, private-by-default', () => {
  it('removed visibility keywords are loud rejects: @public/@internal/@private banned (JETH481), @hidden gated (JETH440)', () => {
    // native: @public/@internal/@private are RETIRED structural decorators -> JETH481 (native visibility is a
    // return marker / bare-default / leading `#`). @hidden was never a real JETH decorator and stays on the
    // removed-visibility gate JETH440. Either way it is rejected, never silently swallowed.
    const expected: Record<string, string> = { public: 'JETH481', internal: 'JETH481', private: 'JETH481', hidden: 'JETH440' };
    for (const [kw, code] of Object.entries(expected)) {
      expect(codes(`class C { @${kw} f(): u256 { return 1n; } g(): External<void> {} }`), kw).toContain(code);
    }
  });
  it('@external is exposed; a no-decorator function is internal (not in the ABI)', () => {
    expect(
      abiNames(`class C { get f(): External<u256> { return 1n; } helper(): u256 { return 2n; } }`),
    ).toEqual(['f']);
  });
  it('a no-decorator helper is callable internally by name', () => {
    expect(
      codes(
        `class C { helper(x: u256): u256 { return x + 1n; } get f(): External<u256> { return helper(5n); } }`,
      ),
    ).toEqual([]);
  });
  it('getter trigger is @external @state (not @public)', () => {
    expect(
      abiNames(
        `class C { count: Visible<u256>; inc(): External<void> { this.count = this.count + 1n; } }`,
      ),
    ).toEqual(['inc', 'count']);
    expect(
      abiNames(`class C { hidden: u256; inc(): External<void> { this.hidden = this.hidden + 1n; } }`),
    ).toEqual(['inc']); // no getter for a plain @state
  });
  it('@payable / @nonReentrant require an exposed entry', () => {
    // native: `@payable` is retired - payable is the `Payable<T>` return marker, which IS an exposed entry, so
    // a "payable-but-internal" function is structurally impossible (the legacy JETH131 gate is unreachable).
    // The retired decorator is banned (JETH481), and the native analogue of the old `@payable @pure` conflict
    // - a read-only `get` returning `Payable<T>` - is the surviving clean reject (JETH352).
    expect(codes(`@contract class C { @payable @pure f(): u256 { return msg.value; } }`)).toContain('JETH481');
    expect(codes(`class C { get f(): Payable<u256> { return msg.value; } }`)).toContain('JETH352');
    // @nonReentrant is kept, and still requires an @external entry (an internal function -> JETH261).
    expect(codes(`class C { @nonReentrant f(): void {} }`)).toContain('JETH261');
  });
  it('the old "R2" case now just works: an aggregate helper called internally', async () => {
    const src = `type P = { a: u8; b: u32; }; class C { dist(p: P): u32 { return p.a + p.b; } get f(x: u8, y: u32): External<u32> { return dist(P(x, y)); } }`;
    expect(codes(src)).toEqual([]);
    const h = await Harness.create();
    const a = await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode);
    const r = await h.call(a, '0x' + functionSelector('f(uint8,uint32)') + pad32(5n) + pad32(7n));
    expect(r.success).toBe(true);
    expect(BigInt(r.returnHex)).toBe(12n);
  });
});
