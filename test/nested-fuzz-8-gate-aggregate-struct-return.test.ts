// GATE scenario s8-gate-aggregate-struct-return: pure compile-time gates, no EVM run.
// (1) Returning a @struct with a fixed-array field from a @view (return this.s)
//     must be rejected with JETH225 (returning a struct with non-value fields).
// (2) A @struct with a `string` field is now a valid DYNAMIC struct (Phase 4e-6,
//     supported as a calldata param / return). Putting one in STORAGE (@state) is
//     still gated -> JETH231 (storage dynamic struct).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';

// Compile and return the list of error-severity diagnostic codes, or null if it
// compiled silently (which for a gate scenario is itself the failure).
function codesFor(src: string, fileName: string): string[] | null {
  try {
    compile(src, { fileName });
    return null; // compiled with no thrown error -> gate did NOT fire
  } catch (e) {
    if (e instanceof CompileError) {
      return e.diagnostics.filter((d) => d.severity === 'error').map((d) => d.code);
    }
    throw e; // unexpected non-CompileError failure: let it surface loudly
  }
}

describe('s8-gate-aggregate-struct-return (GATE: no EVM run)', () => {
  // Probe A: struct with a fixed-array field, returned via `return this.s`.
  // The struct itself is well-formed (Arr<u256,2> is a static field, so JETH229
  // must NOT fire here); only the whole-struct *return* is gated -> JETH225.
  const SRC_RETURN_FIXED_ARRAY = `
@struct class S { a: u256; arr: Arr<u256, 2>; }

@contract
class GateReturn {
  @state s: S;
  @view getS(): S { return this.s; }
}
`;

  // Probe B: struct with a dynamic `string` field. The struct declaration is now
  // valid (a dynamic struct, Phase 4e-6), but a STORAGE @state of it is gated
  // -> JETH231 (storage dynamic struct is not supported; only calldata/return).
  const SRC_STRING_FIELD = `
@struct class T { a: u256; name: string; }

@contract
class GateStringField {
  @state t: T;
  @view getA(): u256 { return this.t.a; }
}
`;

  // Sanity control: an all-value-type struct returned from a @view compiles
  // cleanly. Guards against a false pass where the gate fires on *everything*.
  const SRC_VALUE_STRUCT_OK = `
@struct class V { a: u256; b: u128; c: bool; }

@contract
class ControlOk {
  @state v: V;
  @view getV(): V { return this.v; }
}
`;

  it('control: all-value-type struct return compiles (no gate)', () => {
    const codes = codesFor(SRC_VALUE_STRUCT_OK, 'ControlOk.jeth');
    expect(codes, 'all-value-type struct return must compile cleanly').toBeNull();
  });

  it('probe A: return struct with fixed-array field now COMPILES (encoded from storage leaves)', () => {
    // A static struct with a fixed-array field is now a supported whole-struct return:
    // the storage-source recursive encoder flattens the fixed-array field via
    // structStorageLeaves (byte-identical to solc, verified in fixed-array-return.test.ts).
    const codes = codesFor(SRC_RETURN_FIXED_ARRAY, 'GateReturn.jeth');
    expect(codes, 'returning a struct with a static fixed-array field must compile; got: ' + JSON.stringify(codes)).toBeNull();
  });

  it('probe B: storage @state of a dynamic (string) struct now COMPILES (field access supported)', () => {
    // A storage dynamic struct (a bytes/string field at base+fieldSlot is a normal
    // storage bytes/string) is now supported: reading this.t.a / this.t.name and
    // writing them is byte-identical to solc. The bare declaration + field read
    // compiles cleanly (no JETH231).
    const codes = codesFor(SRC_STRING_FIELD, 'GateStringField.jeth');
    expect(codes, 'a storage dynamic struct with field access must compile; got: ' + JSON.stringify(codes)).toBeNull();
    // A whole-struct RETURN of a storage dynamic struct is now SUPPORTED (the
    // storage-source recursive head/tail encoder; byte-identical to solc).
    const whole = codesFor(`@struct class T { a: u256; name: string; }\n@contract class C { @state t: T; @view f(): T { return this.t; } }`, 'WholeRet.jeth');
    expect(whole, 'returning a whole storage dynamic struct now compiles; got: ' + JSON.stringify(whole)).toBeNull();
  });
});
