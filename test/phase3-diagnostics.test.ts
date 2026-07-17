// Phase 3 analyzer diagnostics: mappings, globals, msg.value/payable, pure env, casts.
// Native mode: mutability is INFERRED from the body, so there is no @view/@pure/@external/@payable
// decorator to spell. A value-returning read-only method is a `get f(): External<T>` accessor, a
// void writer is `f(): External<void>`, and a payable writer is `f(): Payable<void>`. Every semantic
// analyzer rule below (JETH152/153/160/162/170/171/082) still fires natively. The explicit-@pure "reads
// the environment" rule (JETH164) has no DECORATOR form natively, so it retargets to the decorator ban
// (JETH481) plus a positive native pin (see below). NOTE it is no longer UNREACHABLE natively, as this
// header once claimed: the STATIC-IS-PURE ruling made `static` a DECLARED-pure anchor, so a `static` /
// `static get` member reading the environment trips JETH164 for real. That native surface is owned by
// test/class-mutability-marker-ban.test.ts; this file keeps its decorator-ban framing.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';

function codesFor(source: string): string[] {
  try {
    compile(source, { fileName: 't.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}
// contract with a mapping `m`, a u256 `total`, plus one method body `body`. `mode` picks the native
// exposure (`ext` external, `payable` external payable), `ret` the return type (`void` -> a writer,
// any value type -> a `get` read-only accessor).
const C = (body: string, mode: 'ext' | 'payable' = 'ext', ret = 'void') => {
  const sig =
    mode === 'payable'
      ? `f(): Payable<${ret}>`
      : ret === 'void'
        ? `f(): External<void>`
        : `get f(): External<${ret}>`;
  return `class T {
  m: mapping<address, u256>;
  total: u256 = 0n;
  ${sig} {
    ${body}
  }
}`;
};

describe('Phase 3 diagnostics', () => {
  it('rejects reading or assigning a mapping directly', () => {
    expect(codesFor(C('return this.m;', 'ext', 'u256'))).toContain('JETH153');
    expect(codesFor(C('this.m = total;'))).toContain('JETH153');
  });

  it('rejects indexing a non-mapping', () => {
    expect(codesFor(C('this.total[0n] = 1n;'))).toContain('JETH152');
  });

  it('accepts mapping read/write with a correct key', () => {
    expect(codesFor(C('this.m[msg.sender] = 1n;'))).toEqual([]);
  });

  it('rejects msg.value outside a @payable function', () => {
    expect(codesFor(C('this.total = msg.value;'))).toContain('JETH162'); // nonpayable
    expect(codesFor(C('return msg.value;', 'ext', 'u256'))).toContain('JETH162'); // read-only
  });

  it('accepts msg.value in a @payable function', () => {
    expect(codesFor(C('this.total += msg.value;', 'payable'))).toEqual([]);
  });

  it('legacy @pure is banned; env globals are allowed in a normal (inferred) method', () => {
    // The legacy "a @pure function may not read the environment" rule (JETH164) has no DECORATOR form:
    // the decorator that carried it is banned (JETH481), and the same env reads compile cleanly in an
    // ordinary inferred-view method. (JETH164 itself is NOT unreachable, as this comment once said - a
    // `static` DECLARES pure under the STATIC-IS-PURE ruling and an env-reading static trips it.)
    expect(codesFor(`class T { f(): u256 { return 0n; } @pure g(): address { return msg.sender; } }`)).toContain(
      'JETH481',
    );
    expect(codesFor(C('return msg.sender;', 'ext', 'address'))).toEqual([]);
    expect(codesFor(C('return block.timestamp;', 'ext', 'u256'))).toEqual([]);
    expect(codesFor(C('return address(this);', 'ext', 'address'))).toEqual([]);
  });

  it('env globals and msg.sig compile in a normal (inferred) method', () => {
    expect(codesFor(C('return msg.sender;', 'ext', 'address'))).toEqual([]);
    expect(codesFor(C('return msg.sig;', 'ext', 'bytes4'))).toEqual([]); // calldata, not env
  });

  it('rejects unknown globals; msg.data is now supported (a calldata bytes)', () => {
    expect(codesFor(C('return block.foo;', 'ext', 'u256'))).toContain('JETH160');
    // msg.data is supported now; returning it as a `bytes` compiles cleanly (no JETH161)
    expect(codesFor(C('return msg.data;', 'ext', 'bytes'))).toEqual([]);
    expect(codesFor(C('return msg.data.length;', 'ext', 'u256'))).toEqual([]);
  });

  it('accepts address(0n) and rejects address(u256)/payable(non-address)', () => {
    expect(codesFor(C('require(msg.sender != address(0n), "z");'))).toEqual([]);
    expect(codesFor(C('let x: address = address(this.total);'))).toContain('JETH170');
    expect(codesFor(C('let p: address = payable(this.total);'))).toContain('JETH171');
  });

  it('rejects arithmetic on addresses', () => {
    expect(codesFor(C('let x: address = msg.sender + msg.sender;'))).toContain('JETH082');
  });

  it('allows shadowing the msg/block/tx/address identifiers with a local', () => {
    expect(codesFor(C('let msg: u256 = 5n; this.total = msg;'))).toEqual([]);
  });
});
