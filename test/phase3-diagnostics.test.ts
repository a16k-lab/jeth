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
const C = (body: string, mut = '@external', ret = 'void') => `@contract
class T {
  @state m: mapping<address, u256>;
  @state total: u256 = 0n;
  ${mut}
  f(): ${ret} {
    ${body}
  }
}`;

describe('Phase 3 diagnostics', () => {
  it('rejects reading or assigning a mapping directly', () => {
    expect(codesFor(C('return this.m;', '@view', 'u256'))).toContain('JETH153');
    expect(codesFor(C('this.m = total;'))).toContain('JETH153');
  });

  it('rejects indexing a non-mapping', () => {
    expect(codesFor(C('this.total[0n] = 1n;'))).toContain('JETH152');
  });

  it('accepts mapping read/write with a correct key', () => {
    expect(codesFor(C('this.m[msg.sender] = 1n;'))).toEqual([]);
  });

  it("rejects msg.value outside a @payable function", () => {
    expect(codesFor(C('this.total = msg.value;'))).toContain('JETH162'); // nonpayable
    expect(codesFor(C('return msg.value;', '@view', 'u256'))).toContain('JETH162'); // view
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

  it('rejects unknown globals and deferred msg.data', () => {
    expect(codesFor(C('return block.foo;', '@view', 'u256'))).toContain('JETH160');
    expect(codesFor(C('return msg.data;', '@view', 'u256'))).toContain('JETH161');
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
