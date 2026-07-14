// CONTRACT-TYPE-PARAM (JETH041/013 lift): solc lowers a contract/interface-typed event/error member to
// ABI `address` and accepts; JETH now models it as a branded address (the brand is erased at
// ABI/selectors/codegen so topic0 = keccak of the "address" signature, but keeps the type nominally
// distinct - a plain address rejects, matching solc's no-implicit-address->contract rule). The scope is
// event/error MEMBER types plus the explicit wrapper cast `T(<address>)` used as the emit/revert
// argument; param/return/field of a contract type stay a clean over-rejection (a documented residual).
//
// Byte-identity is proven two ways: (1) JETH's creation bytecode for the contract-type event is IDENTICAL
// to JETH's plain-`address` event (so the ctref type flows through the SAME proven address codegen), and
// (2) deploy-both vs solc: topic0, indexed topics, log data, and error revert data all match.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness, pad32 as pad } from '../src/evm.js';
import { functionSelector as sel, eventTopic0 } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

function jethRejects(src: string): string[] | null {
  try {
    compile(src, { fileName: 'C.jeth' });
    return null;
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}

describe('CONTRACT-TYPE-PARAM: contract/interface-typed event & error members lower to address', () => {
  it('non-indexed interface member: topic0 uses "address" and log data matches solc', async () => {
    const J = `interface I { }
      class C {
        E: event<{ x: u256; d: I; y: bool }>;
        f(a: address): External<void> { emit(E(7n, I(a), true)); }
      }`;
    const S = SPDX + `interface I { }
contract C {
  event E(uint256 x, I d, bool y);
  function f(address a) external { emit E(7, I(a), true); }
}`;
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(S, 'C');
    // ABI shows the contract type as "address".
    const ev = jb.abi.find((x: any) => x.type === 'event') as any;
    expect(ev.inputs.map((i: any) => i.type)).toEqual(['uint256', 'address', 'bool']);

    const jh = await Harness.create();
    const sh = await Harness.create();
    const aj = await jh.deploy(jb.creationBytecode);
    const as = await sh.deploy(sb.creation);
    const A = 0x00000000000000000000000000000000000000aan;
    const data = '0x' + sel('f(address)') + pad(A);
    const j = await jh.call(aj, data);
    const s = await sh.call(as, data);
    expect(j.success && s.success).toBe(true);
    expect(j.logs[0]!.topics[0]).toBe('0x' + eventTopic0('E(uint256,address,bool)'));
    expect(j.logs).toEqual(s.logs);
  });

  it('indexed interface member: the address topic matches solc', async () => {
    const J = `interface I { }
      class C {
        Ind: event<{ a: indexed<u256>; d: indexed<I> }>;
        g(a: address): External<void> { emit(Ind(9n, I(a))); }
      }`;
    const S = SPDX + `interface I { }
contract C {
  event Ind(uint256 indexed a, I indexed d);
  function g(address a) external { emit Ind(9, I(a)); }
}`;
    const jh = await Harness.create();
    const sh = await Harness.create();
    const aj = await jh.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await sh.deploy(compileSolidity(S, 'C').creation);
    const data = '0x' + sel('g(address)') + pad(0xaan);
    const j = await jh.call(aj, data);
    const s = await sh.call(as, data);
    expect(j.success && s.success).toBe(true);
    expect(j.logs[0]!.topics[0]).toBe('0x' + eventTopic0('Ind(uint256,address)'));
    expect(j.logs).toEqual(s.logs);
  });

  it('error member: revert selector + data match solc (keccak "Bad(address)")', async () => {
    const J = `interface I { }
      class C {
        Bad: error<{ d: I }>;
        h(a: address): External<void> { revert(Bad(I(a))); }
      }`;
    const S = SPDX + `interface I { }
contract C {
  error Bad(I d);
  function h(address a) external { revert Bad(I(a)); }
}`;
    const jh = await Harness.create();
    const sh = await Harness.create();
    const aj = await jh.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await sh.deploy(compileSolidity(S, 'C').creation);
    const data = '0x' + sel('h(address)') + pad(0xaan);
    const j = await jh.call(aj, data);
    const s = await sh.call(as, data);
    expect(j.success).toBe(false);
    expect(j.success).toBe(s.success);
    expect(j.returnHex).toBe(s.returnHex);
  });

  it('the deployed contract\'s OWN type is a valid member type', () => {
    const J = `class C { E: event<{ c: C }>; f(a: address): External<void> { emit(E(C(a))); } }`;
    expect(jethRejects(J)).toBe(null);
  });

  it('the contract-type event lowers to the SAME bytecode as a plain-address event', () => {
    const jCtref = compile(
      `interface I { }
       class C { E: event<{ x: u256; d: I; y: bool }>; f(a: address): External<void> { emit(E(7n, I(a), true)); } }`,
      { fileName: 'C.jeth' },
    ).creationBytecode;
    const jAddr = compile(
      `class C { E: event<{ x: u256; d: address; y: bool }>; f(a: address): External<void> { emit(E(7n, address(a), true)); } }`,
      { fileName: 'C.jeth' },
    ).creationBytecode;
    expect(jCtref).toBe(jAddr);
  });

  it('SOUND rejections (no over-acceptance): a plain address, a non-address cast, and a cross-type wrapper', () => {
    // a plain address argument (no explicit wrapper) - solc rejects the implicit address->contract conversion.
    expect(jethRejects(`interface I { }
      class C { E: event<{ d: I }>; f(a: address): External<void> { emit(E(a)); } }`)).not.toBe(null);
    // I(<non-address>) - solc rejects (a contract type converts only from address).
    expect(jethRejects(`interface I { }
      class C { E: event<{ d: I }>; f(a: u160): External<void> { emit(E(I(a))); } }`)).not.toBe(null);
    // a DIFFERENT interface's wrapper - solc rejects (no implicit contract->contract conversion).
    expect(jethRejects(`interface I { }
      interface J { }
      class C { E: event<{ d: I }>; f(a: address): External<void> { emit(E(J(a))); } }`)).not.toBe(null);
    // a library name is NOT a value type (never in contractRefNames) - both reject.
    expect(jethRejects(`static class L { g(): u256 { return 1n; } }
      class C { E: event<{ d: L }>; }`)).not.toBe(null);
  });

  it('CONCRETE contract type in field/param/return is now a first-class value type (CONTRACT-TYPE-VALUE lift)', () => {
    // Previously a residual over-rejection (JETH013). Lifted by CONTRACT-TYPE-VALUE: a concrete/abstract
    // contract name is a first-class value type at field / param / return / local / immutable positions,
    // lowered THROUGH `address` with the `__ctref:` brand (byte-identical, see test/lift-contract-type-value.test.ts).
    expect(jethRejects(`class C { c: C; }`)).toBe(null); // own contract type as a field now accepts
  });
});
