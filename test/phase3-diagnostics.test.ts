// Phase 3 analyzer diagnostics: mappings, globals, msg.value/payable, pure env, casts.
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
// contract with a mapping `m`, a u256 `total`, plus one method body `body`.
const C = (body: string, mut = '@external', ret = 'void') => `class T {
  m: mapping<address, u256>;
  total: u256 = 0n;
  ${mut}
  f(): ${ret} {
    ${body}
  }
}`;

describe('Phase 3 diagnostics', () => {
  it('rejects reading or assigning a mapping directly', () => {
    expect(codesFor(C('return this.m;', '@view', 'u256'))).toContain('JETH481');
    expect(codesFor(C('this.m = total;'))).toContain('JETH153');
  });

  it('rejects indexing a non-mapping', () => {
    expect(codesFor(C('this.total[0n] = 1n;'))).toContain('JETH481');
  });

  it('accepts mapping read/write with a correct key', () => {
    expect(codesFor(C('this.m[msg.sender] = 1n;'))).toEqual([]);
  });

  it('rejects msg.value outside a @payable function', () => {
    expect(codesFor(C('this.total = msg.value;'))).toContain('JETH481'); // nonpayable
    expect(codesFor(C('return msg.value;', '@external @view', 'u256'))).toContain('JETH162'); // view
  });

  it('accepts msg.value in a @payable function', () => {
    expect(codesFor(C('this.total += msg.value;', '@external @payable'))).toEqual([]);
  });

  it('rejects environment globals in a @pure function', () => {
    expect(codesFor(C('return msg.sender;', '@pure', 'address'))).toContain('JETH164');
    expect(codesFor(C('return block.timestamp;', '@pure', 'u256'))).toContain('JETH164');
    expect(codesFor(C('return address(this);', '@pure', 'address'))).toContain('JETH164');
  });

  it('allows env globals in @view and msg.sig in @pure', () => {
    expect(codesFor(C('return msg.sender;', '@view', 'address'))).toEqual([]);
    expect(codesFor(C('return msg.sig;', '@pure', 'bytes4'))).toEqual([]); // calldata, not env
  });

  it('rejects unknown globals; msg.data is now supported (a calldata bytes)', () => {
    expect(codesFor(C('return block.foo;', '@view', 'u256'))).toContain('JETH160');
    // msg.data is supported now; returning it as a `bytes` compiles cleanly (no JETH161)
    expect(codesFor(C('return msg.data;', '@pure', 'bytes'))).toEqual([]);
    expect(codesFor(C('return msg.data.length;', '@pure', 'u256'))).toEqual([]);
  });

  it('accepts address(0n) and rejects address(u256)/payable(non-address)', () => {
    expect(codesFor(C('require(msg.sender != address(0n), "z");'))).toEqual([]);
    expect(codesFor(C('let x: address = address(this.total);', '@view'))).toContain('JETH170');
    expect(codesFor(C('let p: address = payable(this.total);', '@view'))).toContain('JETH171');
  });

  it('rejects arithmetic on addresses', () => {
    expect(codesFor(C('let x: address = msg.sender + msg.sender;', '@view'))).toContain('JETH082');
  });

  it('allows shadowing the msg/block/tx/address identifiers with a local', () => {
    expect(codesFor(C('let msg: u256 = 5n; this.total = msg;'))).toEqual([]);
  });
});
