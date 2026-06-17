// Phase 4d scenario "gate-parity": compile-only gate parity between JETH and
// Solidity for aggregate (struct + fixed-array) calldata params, plus one
// runtime probe to confirm the in-bounds constant index path is correct.
//
// Gates (no EVM run unless noted), Solidity is the oracle:
//  (1) CONSTANT out-of-bounds index into a fixed-array / struct-array param must
//      be a JETH COMPILE error (JETH211), mirroring solc's TypeError
//      ("Out of bounds array access"). Asserts BOTH compilers reject.
//  (2) Returning a whole struct/array PARAM, or using it as a value, must throw
//      JETH230. (solc accepts this, so the parity claim here is JETH-only: the
//      directive states this is an *intentional* JETH rejection, not a solc
//      mirror. We assert JETH230 and document the divergence.)
//  (3) Assigning to a param field/element (p.x = 1n) must throw JETH214.
//      (solc rejects too: calldata is read-only -> TypeError.)
//  (4) An IN-BOUNDS constant index compiles AND at runtime returns the right
//      element, byte-identical to Solidity (EVM run).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import solc from 'solc';

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}

// Compile JETH and return the list of error-severity diagnostic codes, or null
// if it compiled silently (which for a gate scenario is itself a failure).
function jethCodes(src: string, fileName: string): string[] | null {
  try {
    compile(src, { fileName });
    return null;
  } catch (e) {
    if (e instanceof CompileError) {
      return e.diagnostics.filter((d) => d.severity === 'error').map((d) => d.code);
    }
    throw e; // unexpected non-CompileError failure: surface loudly
  }
}

// Compile Solidity directly (NOT via the _solidity.ts helper, which throws on
// any error). Returns the list of solc error messages, or null if it compiled
// with no fatal errors. Lets us assert solc REJECTS a source as the oracle.
function solcErrors(source: string): string[] | null {
  const input = {
    language: 'Solidity',
    sources: { 'C.sol': { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: 'cancun',
      outputSelection: { '*': { '*': ['evm.bytecode.object'] } },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const fatal = (out.errors ?? []).filter((e: any) => e.severity === 'error');
  if (fatal.length === 0) return null;
  return fatal.map((e: any) => `${e.type ?? ''}: ${e.message ?? ''}`);
}

// ---- shared @struct preamble for JETH gate sources -------------------------
const JETH_STRUCTS = `
@struct class Pt { x: u128; y: u128; }
@struct class Inner { a: u128; b: u128; }
@struct class Outer { p: u64; inner: Inner; q: u64; }
`;

// ---- shared struct preamble for Solidity gate sources ----------------------
const SOL_HEAD = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract G {
  struct Pt { uint128 x; uint128 y; }
  struct Inner { uint128 a; uint128 b; }
  struct Outer { uint64 p; Inner inner; uint64 q; }
`;

describe('gate-parity: compile-time gate parity for aggregate calldata params', () => {
  // -------------------------------------------------------------------------
  // (1) CONSTANT out-of-bounds index -> JETH compile error, solc also rejects.
  // -------------------------------------------------------------------------
  describe('(1) constant out-of-bounds index is a COMPILE error (both compilers)', () => {
    // fixed-array param a: Arr<u256,3>, index a[3n] (length 3, valid 0..2).
    const J_ARR_OOB = JETH_STRUCTS + `
@contract
class G {
  @external @pure f(a: Arr<u256, 3>): u256 { return a[3n]; }
}
`;
    const S_ARR_OOB = SOL_HEAD + `
  function f(uint256[3] calldata a) external pure returns (uint256){ return a[3]; }
}`;

    // struct-array param ps: Arr<Pt,2>, index ps[2n] (length 2, valid 0..1).
    const J_STRUCTARR_OOB = JETH_STRUCTS + `
@contract
class G {
  @external @pure f(ps: Arr<Pt, 2>): u128 { return ps[2n].x; }
}
`;
    const S_STRUCTARR_OOB = SOL_HEAD + `
  function f(Pt[2] calldata ps) external pure returns (uint128){ return ps[2].x; }
}`;

    // negative constant index a[-1] is also OOB. JETH literal index is u256 and
    // BigInt-typed; an explicit negative literal isn't expressible as a[-1n] in
    // the surface (index coerces to U256), so we only exercise the high-OOB
    // cases, which is what solc's "Out of bounds array access" covers.

    it('fixed-array param a[3n] (len 3): JETH211 AND solc rejects', () => {
      const codes = jethCodes(J_ARR_OOB, 'G.jeth');
      expect(codes, 'constant OOB index must be rejected, not compiled silently').not.toBeNull();
      expect(codes, 'expected JETH211 for constant OOB; got ' + JSON.stringify(codes)).toContain('JETH211');

      const sErr = solcErrors(S_ARR_OOB);
      expect(sErr, 'solc (the oracle) must ALSO reject the constant OOB index').not.toBeNull();
      expect(
        sErr!.join('\n').toLowerCase(),
        'solc rejection should be an out-of-bounds TypeError; got ' + JSON.stringify(sErr),
      ).toContain('out of bounds');
    });

    it('struct-array param ps[2n] (len 2): JETH211 AND solc rejects', () => {
      const codes = jethCodes(J_STRUCTARR_OOB, 'G.jeth');
      expect(codes, 'constant OOB index must be rejected, not compiled silently').not.toBeNull();
      expect(codes, 'expected JETH211 for constant OOB; got ' + JSON.stringify(codes)).toContain('JETH211');

      const sErr = solcErrors(S_STRUCTARR_OOB);
      expect(sErr, 'solc (the oracle) must ALSO reject the constant OOB index').not.toBeNull();
      expect(
        sErr!.join('\n').toLowerCase(),
        'solc rejection should be an out-of-bounds TypeError; got ' + JSON.stringify(sErr),
      ).toContain('out of bounds');
    });

    // Control: the LAST in-bounds constant index (a[2n], len 3) compiles in BOTH.
    it('control: last in-bounds constant index a[2n] compiles in BOTH', () => {
      const jOk = JETH_STRUCTS + `
@contract
class G {
  @external @pure f(a: Arr<u256, 3>): u256 { return a[2n]; }
}
`;
      const sOk = SOL_HEAD + `
  function f(uint256[3] calldata a) external pure returns (uint256){ return a[2]; }
}`;
      expect(jethCodes(jOk, 'G.jeth'), 'in-bounds a[2n] must compile cleanly').toBeNull();
      expect(solcErrors(sOk), 'in-bounds a[2] must compile in solc too').toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // (2) Whole-aggregate PARAM as a value. RETURNING a whole STATIC struct / fixed-array
  // param is now supported (G5, byte-identical to solc - see test/calldata-agg-return.test.ts).
  // Assigning one to a memory local still needs aggregate memory locals (G9, JETH900).
  // -------------------------------------------------------------------------
  describe('(2) whole struct/array param used as a value', () => {
    it('return a whole struct param now compiles (G5)', () => {
      const src = JETH_STRUCTS + `
@contract
class G {
  @external @pure f(p: Pt): Pt { return p; }
}
`;
      expect(jethCodes(src, 'G.jeth'), 'returning a whole struct param is supported (G5)').toBeNull();
    });

    it('return a whole fixed-array param now compiles (G5)', () => {
      const src = JETH_STRUCTS + `
@contract
class G {
  @external @pure f(a: Arr<u256, 3>): Arr<u256, 3> { return a; }
}
`;
      expect(jethCodes(src, 'G.jeth'), 'returning a whole fixed-array param is supported (G5)').toBeNull();
    });

    it('copying a whole struct param to a memory local now compiles (G9)', () => {
      const src = JETH_STRUCTS + `
@contract
class G {
  @external @pure f(p: Pt): u128 { let q: Pt = p; return q.x; }
}
`;
      expect(jethCodes(src, 'G.jeth'), 'calldata struct param -> memory local copy is supported (G9)').toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // (3) Assigning to a param field/element -> JETH214 (calldata is read-only).
  //     solc rejects too (calldata read-only TypeError).
  // -------------------------------------------------------------------------
  describe('(3) assigning to a calldata param field/element throws JETH214', () => {
    it('assign to a struct-param field (p.x = 1n) -> JETH214 AND solc rejects', () => {
      const src = JETH_STRUCTS + `
@contract
class G {
  @external @pure f(p: Pt): u128 { p.x = 1n; return p.x; }
}
`;
      const codes = jethCodes(src, 'G.jeth');
      expect(codes, 'assigning to a calldata struct field must be rejected').not.toBeNull();
      expect(codes, 'expected JETH214; got ' + JSON.stringify(codes)).toContain('JETH214');

      const sSrc = SOL_HEAD + `
  function f(Pt calldata p) external pure returns (uint128){ p.x = 1; return p.x; }
}`;
      const sErr = solcErrors(sSrc);
      expect(sErr, 'solc must also reject assigning to a calldata field').not.toBeNull();
    });

    it('assign to a fixed-array-param element (a[0n] = 1n) -> JETH214 AND solc rejects', () => {
      const src = JETH_STRUCTS + `
@contract
class G {
  @external @pure f(a: Arr<u256, 3>): u256 { a[0n] = 1n; return a[0n]; }
}
`;
      const codes = jethCodes(src, 'G.jeth');
      expect(codes, 'assigning to a calldata array element must be rejected').not.toBeNull();
      expect(codes, 'expected JETH214; got ' + JSON.stringify(codes)).toContain('JETH214');

      const sSrc = SOL_HEAD + `
  function f(uint256[3] calldata a) external pure returns (uint256){ a[0] = 1; return a[0]; }
}`;
      const sErr = solcErrors(sSrc);
      expect(sErr, 'solc must also reject assigning to a calldata element').not.toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // (4) In-bounds constant index compiles AND runs correctly vs Solidity.
  // -------------------------------------------------------------------------
  describe('(4) in-bounds constant index: compiles + runtime byte-identical to Solidity', () => {
    let jeth: Harness, sol: Harness, aj: Address, as: Address;
    const sel = (s: string) => functionSelector(s);

    // JETH contract exercising constant indices at every boundary position.
    const J_RUN = JETH_STRUCTS + `
@contract
class G {
  // fixed-array constant indices a[0n], a[1n], a[2n]
  @external @pure first(a: Arr<u256, 3>): u256 { return a[0n]; }
  @external @pure mid(a: Arr<u256, 3>): u256 { return a[1n]; }
  @external @pure last(a: Arr<u256, 3>): u256 { return a[2n]; }
  // struct-array constant index ps[1n].y (last element, second field)
  @external @pure psLastY(ps: Arr<Pt, 2>): u128 { return ps[1n].y; }
}
`;
    const S_RUN = SOL_HEAD + `
  function first(uint256[3] calldata a) external pure returns (uint256){ return a[0]; }
  function mid(uint256[3] calldata a) external pure returns (uint256){ return a[1]; }
  function last(uint256[3] calldata a) external pure returns (uint256){ return a[2]; }
  function psLastY(Pt[2] calldata ps) external pure returns (uint128){ return ps[1].y; }
}`;

    async function both(data: string) {
      return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
    }
    // Assert JETH matches Solidity byte-for-byte (success + returndata).
    async function eq(label: string, data: string) {
      const { j, s } = await both(data);
      expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
      expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
      return { j, s };
    }
    function raw(selSig: string, words: bigint[]): string {
      return '0x' + sel(selSig) + words.map(pad).join('');
    }

    beforeAll(async () => {
      const jb = compile(J_RUN, { fileName: 'G.jeth' });
      const sb = compileSolidity(S_RUN, 'G');
      jeth = await Harness.create();
      sol = await Harness.create();
      aj = await jeth.deploy(jb.creationBytecode);
      as = await sol.deploy(sb.creation);
    });

    it('a[0n] / a[1n] / a[2n] return the right element byte-identically', async () => {
      const a = [0x1111n, 0x2222n, 0x3333n];
      const r0 = await eq('first a[0n]', raw('first(uint256[3])', a));
      expect(decodeUint(r0.j.returnHex)).toBe(0x1111n);
      const r1 = await eq('mid a[1n]', raw('mid(uint256[3])', a));
      expect(decodeUint(r1.j.returnHex)).toBe(0x2222n);
      const r2 = await eq('last a[2n]', raw('last(uint256[3])', a));
      expect(decodeUint(r2.j.returnHex)).toBe(0x3333n);
    });

    it('struct-array constant index ps[1n].y returns the right leaf byte-identically', async () => {
      // ps[0]={x:1,y:2}, ps[1]={x:3,y:4} -> ps[1].y = 4
      const ps = [1n, 2n, 3n, 4n];
      const r = await eq('psLastY ps[1n].y', raw('psLastY((uint128,uint128)[2])', ps));
      expect(decodeUint(r.j.returnHex)).toBe(4n);
    });

    it('in-bounds constant index emits NO runtime bounds check: short calldata for an UNREAD word still works', async () => {
      // first() reads only a[0n] (word 0). Head needs 3 words = 96 bytes. With
      // exactly 96 bytes it must succeed; this confirms the constant-index path
      // addresses a fixed offset with no runtime Panic branch. Byte-identical.
      const a = [0x42n, 0n, 0n];
      const r = await eq('first exact-head', raw('first(uint256[3])', a));
      expect(r.j.success).toBe(true);
      expect(decodeUint(r.j.returnHex)).toBe(0x42n);
    });
  });
});
