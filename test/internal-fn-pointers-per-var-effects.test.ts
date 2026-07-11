// W5D-2: PER-POINTER-VARIABLE mutability discrimination for internal function pointers.
// Two same-JETH-signature targets (one @view, one mutating), address-taken into DIFFERENT variables:
// previously the per-SIGNATURE effect union blamed the @view caller for the mutating target it can
// never reach (JETH054 over-rejection); solc accepts because pointer TYPES carry mutability. Now the
// effect set is tracked per VARIABLE (the flow-insensitive union of every value ever assigned to it,
// transitively through copies/ternaries of tracked variables), falling back to the per-signature
// union whenever a flow is untrackable (params, storage round-trips, call results, destructure
// components, shadowing/poisoned names). Byte-identical to solc 0.8.35 on the lifted shapes; every
// conservative reject verified against the solc mirror where a mutating target cannot inhabit a
// view-typed pointer (BOTH reject).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
const solcRejects = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};

async function eq(jeth: string, sol: string, calls: [string, string][], slots: bigint[] = []) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + (args ?? ''));
    const rs = await hs.call(as, sel(sig) + (args ?? ''));
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
  for (const s of slots) expect(await readSlot(hj, aj, s), `slot ${s}`).toBe(await readSlot(hs, as, s));
}

// Shared target set: a @view reader and a mutating writer with the SAME JETH signature.
const J_TARGETS = `@state s: u256;
  @view rd(x: u256): u256 { return x + this.s; }
  wr(x: u256): u256 { this.s = x; return x * 2n; }`;
const S_TARGETS = `uint256 s;
  function rd(uint256 x) internal view returns (uint256) { return x + s; }
  function wr(uint256 x) internal returns (uint256) { s = x; return x * 2; }`;

describe('W5D-2: per-pointer-variable funcref mutability discrimination', () => {
  it('LIFT: view + mutating targets in DIFFERENT variables; the @view caller is accepted', async () => {
    await eq(
      `class C { ${J_TARGETS}
        get goView(v: u256): External<u256> { let g: (x: u256) => u256 = this.rd; return g(v); }
        goMut(v: u256): External<u256> { let m: (x: u256) => u256 = this.wr; return m(v); }
        get getS(): External<u256> { return this.s; }
      }`,
      `contract C { ${S_TARGETS}
        function goView(uint256 v) external view returns (uint256) { function(uint256) view returns (uint256) g = rd; return g(v); }
        function goMut(uint256 v) external returns (uint256) { function(uint256) returns (uint256) m = wr; return m(v); }
        function getS() external view returns (uint256) { return s; }
      }`,
      [
        ['goView(uint256)', W(5)],
        ['goMut(uint256)', W(7)],
        ['getS()', ''],
        ['goView(uint256)', W(3)],
      ],
      [0n],
    );
  });

  it('LIFT: copy chains propagate the exact target set; ternary of two view targets lifts', async () => {
    await eq(
      `class C { ${J_TARGETS}
        rd2(x: u256): u256 { return x * 3n + this.s; }
        runMut(v: u256): External<u256> { let m: (x: u256) => u256 = this.wr; return m(v); }
        get chain(v: u256): External<u256> {
          let a: (x: u256) => u256 = this.rd;
          let b: (x: u256) => u256 = a;
          return b(v);
        }
        get tern(c: bool, v: u256): External<u256> {
          let g: (x: u256) => u256 = c ? this.rd : this.rd2;
          return g(v);
        }
      }`,
      `contract C { ${S_TARGETS}
        function rd2(uint256 x) internal view returns (uint256) { return x * 3 + s; }
        function runMut(uint256 v) external returns (uint256) { function(uint256) returns (uint256) m = wr; return m(v); }
        function chain(uint256 v) external view returns (uint256) {
          function(uint256) view returns (uint256) a = rd;
          function(uint256) view returns (uint256) b = a;
          return b(v);
        }
        function tern(bool c, uint256 v) external view returns (uint256) {
          function(uint256) view returns (uint256) g = c ? rd : rd2;
          return g(v);
        }
      }`,
      [
        ['runMut(uint256)', W(9)],
        ['chain(uint256)', W(4)],
        ['tern(bool,uint256)', W(1) + W(5)],
        ['tern(bool,uint256)', W(0) + W(5)],
      ],
      [0n],
    );
  });

  it('LIFT: @pure caller through a pure-only pointer while a mutating same-sig target exists', async () => {
    await eq(
      `class C { ${J_TARGETS}
        dbl(x: u256): u256 { return x * 2n; }
        runMut(v: u256): External<u256> { let m: (x: u256) => u256 = this.wr; return m(v); }
        get go(v: u256): External<u256> { let g: (x: u256) => u256 = this.dbl; return g(v); }
      }`,
      `contract C { ${S_TARGETS}
        function dbl(uint256 x) internal pure returns (uint256) { return x * 2; }
        function runMut(uint256 v) external returns (uint256) { function(uint256) returns (uint256) m = wr; return m(v); }
        function go(uint256 v) external pure returns (uint256) { function(uint256) pure returns (uint256) g = dbl; return g(v); }
      }`,
      [['runMut(uint256)', W(9)], ['go(uint256)', W(21)]],
      [0n],
    );
  });

  it('LIFT: uninitialized pointer local in a @view fn accepted; Panic(0x51) byte-identical', async () => {
    await eq(
      `class C { ${J_TARGETS}
        runMut(v: u256): External<u256> { let m: (x: u256) => u256 = this.wr; return m(v); }
        get go(v: u256): External<u256> { let g: (x: u256) => u256; return g(v); }
      }`,
      `contract C { ${S_TARGETS}
        function runMut(uint256 v) external returns (uint256) { function(uint256) returns (uint256) m = wr; return m(v); }
        function go(uint256 v) external view returns (uint256) { function(uint256) view returns (uint256) g; return g(v); }
      }`,
      [['go(uint256)', W(5)], ['runMut(uint256)', W(6)]],
      [0n],
    );
  });

  it('KEPT REJECT (both): a SHARED variable with mixed targets in a @view caller', () => {
    const J = `@contract class C { ${J_TARGETS}
      @external @view go(c: bool, v: u256): u256 { let g: (x: u256) => u256 = c ? this.rd : this.wr; return g(v); }
    }`;
    const S = `contract C { ${S_TARGETS}
      function go(bool c, uint256 v) external view returns (uint256) { function(uint256) view returns (uint256) g = c ? rd : wr; return g(v); }
    }`;
    expect(codes(J)).toContain('JETH481');
    expect(solcRejects(S)).toBe(true);
  });

  it('KEPT REJECT (both): a variable REASSIGNED to a mutating target (flow-insensitive union)', () => {
    const J = `@contract class C { ${J_TARGETS}
      @external @view go(v: u256): u256 {
        let g: (x: u256) => u256 = this.rd;
        let r: u256 = g(v);
        g = this.wr;
        return r + g(v);
      }
    }`;
    expect(codes(J)).toContain('JETH481');
    expect(
      solcRejects(`contract C { ${S_TARGETS}
      function go(uint256 v) external view returns (uint256) {
        function(uint256) view returns (uint256) g = rd;
        uint256 r = g(v);
        g = wr;
        return r + g(v);
      }
    }`),
    ).toBe(true);
  });

  it('KEPT REJECT: a mutating call through a SECOND tracked variable in a @view fn (non-vacuity)', () => {
    // proves the per-variable tracking really attributes wr's effects to the variable that holds it.
    expect(
      codes(`@contract class C { ${J_TARGETS}
      @external @view go(v: u256): u256 {
        let g: (x: u256) => u256 = this.rd;
        { let g2: (x: u256) => u256 = this.wr; g2(v); }
        return g(v);
      }
    }`),
    ).toContain('JETH481');
  });

  it('KEPT CONSERVATIVE: storage-held pointer and funcref PARAM still use the per-signature union', () => {
    // storage round-trip: reading this.h into a local is an untrackable source -> union includes wr.
    expect(
      codes(`@contract class C { ${J_TARGETS}
      @state h: (x: u256) => u256;
      @external set(c: bool): void { this.h = c ? this.rd : this.wr; }
      @external @view go(v: u256): u256 { let g: (x: u256) => u256 = this.h; return g(v); }
    }`),
    ).toContain('JETH481');
    // param flow: the param's initial value is caller-controlled -> poisoned -> union includes wr
    // (a DOCUMENTED conservative over-rejection: solc's view-typed param would accept).
    expect(
      codes(`@contract class C { ${J_TARGETS}
      @view ap(f: (x: u256) => u256, v: u256): u256 { return f(v); }
      @external runMut(v: u256): u256 { let m: (x: u256) => u256 = this.wr; return m(v); }
      @external @view go(v: u256): u256 { return this.ap(this.rd, v); }
    }`),
    ).toContain('JETH481');
  });

  it('unregressed: the pre-existing single-target @view pointer shape still lifts', async () => {
    await eq(
      `class C {
        s: u256;
        constructor() { this.s = 100n; }
        rd(x: u256): u256 { return x + this.s; }
        get viewPtr(v: u256): External<u256> { let g: (x: u256) => u256 = this.rd; return g(v); }
      }`,
      `contract C {
        uint256 s;
        constructor() { s = 100; }
        function rd(uint256 x) internal view returns (uint256) { return x + s; }
        function viewPtr(uint256 v) external view returns (uint256) { function(uint256) view returns (uint256) g = rd; return g(v); }
      }`,
      [['viewPtr(uint256)', W(5)]],
    );
  });
});
