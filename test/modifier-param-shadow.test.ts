// Over-acceptance fix: applying a @modifier whose name is shadowed by a same-named function (or
// constructor) PARAMETER. solc resolves the modifier application in the parameter scope, so the
// parameter shadows the modifier and `@m` no longer references a modifier -> TypeError "Referenced
// declaration is neither modifier nor base class". JETH used to silently apply the modifier; it now
// rejects (JETH329). A BODY local does NOT shadow (inner scope), and a parameter merely sharing a name
// with an UNAPPLIED modifier is fine - both stay accepted (no over-rejection).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};
const accepts = (src: string) => expect(codes(src)).toEqual([]);
const rejectsWith = (src: string, code: string) => expect(codes(src)).toContain(code);

describe('@modifier application shadowed by a same-named parameter (solc rejects)', () => {
  it('a function parameter shadowing the applied modifier rejects (JETH329)', () => {
    rejectsWith('class C { @modifier m() { _; } @m get f(m: u256): External<u256> { return m; } }', 'JETH329');
    // modifier with an argument, and the shadowing param in a non-first position, both reject
    rejectsWith('class C { @modifier m(v: u256) { _; } @m(1n) get f(m: u256): External<u256> { return m; } }', 'JETH329');
    rejectsWith('class C { @modifier m() { _; } @m get f(a: u256, m: u256): External<u256> { return a + m; } }', 'JETH329');
    // one of several applied modifiers is shadowed -> reject
    rejectsWith('class C { @modifier a() { _; } @modifier m() { _; } @a @m get f(m: u256): External<u256> { return m; } }', 'JETH329');
    // POST-placeholder path (buffered) is covered too
    rejectsWith('class C { s: u256; @modifier m() { _; this.s = 1n; } @m get f(m: u256): External<u256> { return m; } }', 'JETH329');
  });

  it('a constructor parameter shadowing the applied modifier rejects (JETH329)', () => {
    rejectsWith('class C { x: u256; @modifier m() { _; } @m constructor(m: u256) { this.x = m; } }', 'JETH329');
  });

  it('no over-rejection: no shadow, body-local, and unapplied-modifier-name params stay accepted', () => {
    // control: no shadow
    accepts('class C { @modifier m() { _; } @m get f(x: u256): External<u256> { return x; } }');
    // a BODY local named like the modifier does NOT shadow the application (inner scope)
    accepts('class C { @modifier m() { _; } @m get f(x: u256): External<u256> { let m: u256 = x; return m; } }');
    // a parameter named like an EXISTING but UNAPPLIED modifier is fine
    accepts('class C { @modifier m() { _; } get f(m: u256): External<u256> { return m; } }');
    // the applied modifier is not shadowed; only its argument references the same-named param
    accepts('class C { @modifier g(v: u256) { _; } @g(x) get f(x: u256): External<u256> { return x; } }');
    // two applied modifiers, neither shadowed
    accepts('class C { @modifier a() { _; } @modifier m() { _; } @a @m get f(x: u256): External<u256> { return x; } }');
  });
});
