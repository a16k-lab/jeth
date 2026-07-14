// The 2026-07-14 integration of the 6 hard OR lifts. A cross-verification of the MERGED tree found two
// over-acceptances the isolated per-lift verifications could not see (interactions between lifts + the
// abstract-only path unmasking a missing rule). Both are pinned here as JETH rejects matching solc 0.8.35.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';

const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e;
  }
};
const rejects = (src: string) => expect(codes(src).length).toBeGreaterThan(0);
const accepts = (src: string) => expect(codes(src)).toEqual([]);

describe('MERGE-OA-1: a bodyless function in an abstract class must be @virtual (solc parity)', () => {
  it('rejects an unmarked bodyless method/getter on the non-deployable path; @virtual / abstract accept', () => {
    // Unmasked when ABSTRACT-ONLY-FILE lifted JETH040. solc: "Functions without implementation must be virtual".
    rejects(`abstract class C { f(): External<u256>; }`);
    rejects(`abstract class C { get f(): View<u256>; }`);
    rejects(`abstract class C { f(): u256; }`);
    accepts(`abstract class C { @virtual f(): External<u256>; }`);
    accepts(`abstract class C { abstract f(): External<u256>; }`); // native `abstract` keyword = bodyless @virtual
    accepts(`interface I { m(): View<u256>; }`); // interface methods are implicitly virtual (unaffected)
  });
});

describe('MERGE-OA-2: a recursive struct is not allowed as an event/error parameter (solc parity)', () => {
  it('rejects a P[]-self-referential struct as an event/error member; a non-recursive struct accepts', () => {
    // RECURSIVE-REF-STRUCT resolves such a struct as a value type; solc rejects it in event/error ABI position.
    rejects(`type P = { v: u256; kids: P[] };\nclass C { E: event<{ p: P }>; f(): External<void> { } }`);
    rejects(`type P = { v: u256; kids: P[] };\nclass C { Bad: error<{ p: P }>; }`);
    rejects(`type P = { v: u256; kids: P[] };\nclass C { E: event<{ p: indexed<P> }>; f(): External<void> { } }`);
    // a NON-recursive dynamic struct as an event member is fine in both (control)
    accepts(`type P = { v: u256; s: string };\nclass C { E: event<{ p: P }>; f(): External<void> { } }`);
  });
});
