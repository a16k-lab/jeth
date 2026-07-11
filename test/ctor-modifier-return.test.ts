// W5D-1 (P1-20 full design): `return;` in CONSTRUCTOR modifier stacks and bodies, byte-identical to
// solc 0.8.35 via OUTLINING (ctorOutlineBind/ctorOutlineCall creation functions, `return;` -> leave):
//   - a `return;` in the ctor BODY under a post/conditional/multi-placeholder modifier resumes at the
//     modifier's post-`_;` code (previously gated JETH323);
//   - a bare `return;` in a ctor MODIFIER exits that level's wrap (previously gated JETH323);
//   - a `return;` in a BASE ctor body/modifier no longer skips the derived ctor bodies (this was a
//     silent PRE-EXISTING MISCOMPILE: the merged jeth_constructor's `leave` exited every level);
//   - the modifier-param/ctor-param name-collision gate is lifted when the body is outlined.
// ALSO fixed here (pre-existing, verified vs solc):
//   - FUNCTION path: a bare `return;` in a nested NON-OUTERMOST modifier under a post-code outer layer
//     exited the whole function where solc resumes after the enclosing `_` -> now a clean JETH323;
//   - an immutable WRITE inside ctor-MODIFIER code was accepted (solc: "Cannot write to immutable
//     here") -> now JETH313 (reads stay legal, matching solc).
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

/** Deploy both (with optional appended ctor args) and compare the given raw slots + calls. */
async function eqDeploy(jeth: string, sol: string, ctorArgs: string, slots: bigint[], calls: [string, string][] = []) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode + ctorArgs);
  const as = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation + ctorArgs);
  for (const s of slots) expect(await readSlot(hj, aj, s), `slot ${s}`).toBe(await readSlot(hs, as, s));
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + (args ?? ''));
    const rs = await hs.call(as, sel(sig) + (args ?? ''));
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

describe('W5D-1: constructor modifier/body `return;` via outlining', () => {
  it('bare return in the ctor modifier, before and after `_` (deployed level)', async () => {
    await eqDeploy(
      `class C {
        s: u256;
        @modifier m() { this.s = this.s + 1n; if (this.s > 0n) { return; } _; this.s = this.s + 10n; }
        @m constructor() { this.s = this.s + 100n; }
      }`,
      `contract C {
        uint256 s;
        modifier m() { s = s + 1; if (s > 0) { return; } _; s = s + 10; }
        constructor() m() { s = s + 100; }
      }`,
      '',
      [0n],
    );
    await eqDeploy(
      `class C {
        s: u256;
        @modifier m() { this.s = this.s + 1n; _; if (this.s > 0n) { return; } this.s = this.s + 10n; }
        @m constructor() { this.s = this.s + 100n; }
      }`,
      `contract C {
        uint256 s;
        modifier m() { s = s + 1; _; if (s > 0) { return; } s = s + 10; }
        constructor() m() { s = s + 100; }
      }`,
      '',
      [0n],
    );
  });

  it('ctor BODY return + post-code modifier: the post code still runs (both branch parities)', async () => {
    const J = `class C {
      s: u256;
      @modifier m() { this.s = this.s + 1n; _; this.s = this.s + 10n; }
      @m constructor(x: u256) { this.s = this.s + 100n; if (x > 0n) { return; } this.s = this.s + 1000n; }
    }`;
    const S = `contract C {
      uint256 s;
      modifier m() { s = s + 1; _; s = s + 10; }
      constructor(uint256 x) m() { s = s + 100; if (x > 0) { return; } s = s + 1000; }
    }`;
    await eqDeploy(J, S, W(1), [0n]);
    await eqDeploy(J, S, W(0), [0n]);
    // non-vacuity: the early-return path must give 111 (post ran after the body return), not 101.
    const h = await Harness.create();
    const a = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode + W(1));
    expect(BigInt(await readSlot(h, a, 0n))).toBe(111n);
  });

  it('multi-placeholder + conditional-placeholder modifiers with a body return', async () => {
    await eqDeploy(
      `class C {
        s: u256;
        @modifier m() { _; this.s = this.s + 10n; _; this.s = this.s + 100n; }
        @m constructor(x: u256) { this.s = this.s + 1n; if (x > 0n) { return; } this.s = this.s + 1000n; }
      }`,
      `contract C {
        uint256 s;
        modifier m() { _; s = s + 10; _; s = s + 100; }
        constructor(uint256 x) m() { s = s + 1; if (x > 0) { return; } s = s + 1000; }
      }`,
      W(1),
      [0n],
    );
    const J = `class C {
      s: u256;
      @modifier m(c: bool) { this.s = this.s + 1n; if (c) { _; } this.s = this.s + 10n; }
      @m(x > 0n) constructor(x: u256) { this.s = this.s + 100n; if (x > 1n) { return; } this.s = this.s + 1000n; }
    }`;
    const S = `contract C {
      uint256 s;
      modifier m(bool c) { s = s + 1; if (c) { _; } s = s + 10; }
      constructor(uint256 x) m(x > 0) { s = s + 100; if (x > 1) { return; } s = s + 1000; }
    }`;
    await eqDeploy(J, S, W(0), [0n]); // 0 body runs
    await eqDeploy(J, S, W(2), [0n]); // 1 run, early return
  });

  it('MISCOMPILE FIX: a return in a BASE ctor body/modifier no longer skips the derived body', async () => {
    const J = `abstract class B {
      a: u256;
      constructor(x: u256) { this.a = x; if (x > 5n) { return; } this.a = x * 10n; }
    }
    class C extends B {
      b: u256;
      constructor(x: u256) { super(x); this.b = x + 100n; }
    }`;
    const S = `abstract contract B {
      uint256 a;
      constructor(uint256 x) { a = x; if (x > 5) { return; } a = x * 10; }
    }
    contract C is B {
      uint256 b;
      constructor(uint256 x) B(x) { b = x + 100; }
    }`;
    await eqDeploy(J, S, W(7), [0n, 1n]);
    await eqDeploy(J, S, W(3), [0n, 1n]);
    // non-vacuity: on the early-return path the DERIVED body must still have run (b = 107).
    const h = await Harness.create();
    const a = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode + W(7));
    expect(BigInt(await readSlot(h, a, 1n))).toBe(107n);
    // base MODIFIER bare-return variant (level-wrap outlining)
    await eqDeploy(
      `abstract class B {
        a: u256;
        @modifier m() { this.a = this.a + 1n; if (this.a > 0n) { return; } _; this.a = this.a + 10n; }
        @m constructor() { this.a = this.a + 100n; }
      }
      class C extends B {
        b: u256;
        constructor() { super(); this.b = 7n; }
      }`,
      `abstract contract B {
        uint256 a;
        modifier m() { a = a + 1; if (a > 0) { return; } _; a = a + 10; }
        constructor() m() { a = a + 100; }
      }
      contract C is B {
        uint256 b;
        constructor() { b = 7; }
      }`,
      '',
      [0n, 1n],
    );
  });

  it('three-level chain: base modifier return + base body returns + derived body, both arg parities', async () => {
    const J = `abstract class A0 {
      a: u256;
      @modifier ma() { this.a = this.a + 1n; if (this.a > 100n) { return; } _; this.a = this.a + 10n; }
      @ma constructor(x: u256) { this.a = this.a + x; if (x > 5n) { return; } this.a = this.a + 1000n; }
    }
    abstract class B0 extends A0 {
      b: u256;
      constructor(x: u256) { super(x); this.b = x; if (x > 3n) { return; } this.b = x * 100n; }
    }
    class C extends B0 {
      c: u256;
      constructor(x: u256) { super(x); this.c = x + 7n; }
    }`;
    const S = `abstract contract A0 {
      uint256 a;
      modifier ma() { a = a + 1; if (a > 100) { return; } _; a = a + 10; }
      constructor(uint256 x) ma() { a = a + x; if (x > 5) { return; } a = a + 1000; }
    }
    abstract contract B0 is A0 {
      uint256 b;
      constructor(uint256 x) A0(x) { b = x; if (x > 3) { return; } b = x * 100; }
    }
    contract C is B0 {
      uint256 c;
      constructor(uint256 x) B0(x) { c = x + 7; }
    }`;
    await eqDeploy(J, S, W(4), [0n, 1n, 2n]);
    await eqDeploy(J, S, W(9), [0n, 1n, 2n]);
  });

  it('COLLISION LIFT: modifier param sharing the ctor param name (incl. an arg referencing it)', async () => {
    await eqDeploy(
      `class C {
        s: u256;
        @modifier m(x: u256) { this.s = this.s + x; _; this.s = this.s * x; }
        @m(3n) constructor(x: u256) { this.s = this.s + x * 10n; }
      }`,
      `contract C {
        uint256 s;
        modifier m(uint256 x) { s = s + x; _; s = s * x; }
        constructor(uint256 x) m(3) { s = s + x * 10; }
      }`,
      W(7),
      [0n],
    );
    await eqDeploy(
      `class C {
        s: u256;
        @modifier m(x: u256) { this.s = this.s + x; _; this.s = this.s + x * 1000n; }
        @m(x * 2n) constructor(x: u256) { this.s = this.s + x; }
      }`,
      `contract C {
        uint256 s;
        modifier m(uint256 x) { s = s + x; _; s = s + x * 1000; }
        constructor(uint256 x) m(x * 2) { s = s + x; }
      }`,
      W(7),
      [0n],
    );
  });

  it('immutables THREAD through the outlined units; a modifier may READ but not WRITE them', async () => {
    const J = `class C {
      static ia: u256;
      static ib: u256;
      s: u256;
      @modifier m() { _; this.s = this.s + this.ia + 10n; }
      @m constructor(x: u256) { this.ia = x + 1n; if (x > 0n) { return; } this.ia = 999n; this.ib = 3n; }
      get geta(): External<u256> { return this.ia; }
      get getb(): External<u256> { return this.ib; }
    }`;
    const S = `contract C {
      uint256 immutable ia;
      uint256 immutable ib;
      uint256 s;
      modifier m() { _; s = s + ia + 10; }
      constructor(uint256 x) m() { ia = x + 1; if (x > 0) { return; } ia = 999; ib = 3; }
      function geta() external view returns (uint256) { return ia; }
      function getb() external view returns (uint256) { return ib; }
    }`;
    await eqDeploy(J, S, W(41), [0n], [['geta()', ''], ['getb()', '']]);
    await eqDeploy(J, S, W(0), [0n], [['geta()', ''], ['getb()', '']]);
    // an immutable WRITE inside ctor-modifier code: BOTH reject (solc "Cannot write to immutable here")
    const JW = `class C {
      static ia: u256;
      @modifier m() { this.ia = 5n; _; }
      @m constructor() { }
    }`;
    expect(codes(JW)).toContain('JETH313');
    expect(
      solcRejects(`contract C { uint256 immutable ia; modifier m() { ia = 5; _; } constructor() m() { } }`),
    ).toBe(true);
  });

  it('outlined body: internal call (creation duplication) + string ctor param + revert parity', async () => {
    await eqDeploy(
      `class C {
        s: u256;
        dbl(v: u256): u256 { return v * 2n; }
        @modifier m() { _; this.s = this.s + 10n; }
        @m constructor(x: u256) { this.s = this.dbl(x); if (x > 0n) { return; } this.s = 0n; }
      }`,
      `contract C {
        uint256 s;
        function dbl(uint256 v) internal pure returns (uint256) { return v * 2; }
        modifier m() { _; s = s + 10; }
        constructor(uint256 x) m() { s = dbl(x); if (x > 0) { return; } s = 0; }
      }`,
      W(21),
      [0n],
    );
    // revert inside the outlined body: creation reverts on both sides
    const J = `class C {
      s: u256;
      @modifier m() { _; this.s = this.s + 10n; }
      @m constructor(x: u256) { if (x == 0n) { revert("zero"); } this.s = x; if (x > 5n) { return; } this.s = x * 2n; }
    }`;
    const S = `contract C {
      uint256 s;
      modifier m() { _; s = s + 10; }
      constructor(uint256 x) m() { if (x == 0) { revert("zero"); } s = x; if (x > 5) { return; } s = x * 2; }
    }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    await expect(hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode + W(0))).rejects.toThrow();
    await expect(hs.deploy(compileSolidity(SPDX + S, 'C').creation + W(0))).rejects.toThrow();
  });

  it('KEPT REJECTS: nested inner-modifier return under a post-code outer; multi-run body param write', () => {
    // solc resumes after the enclosing `_`; the level-exit lowering cannot express that -> JETH323.
    expect(
      codes(`class C {
        s: u256;
        @modifier a() { this.s = this.s + 1n; _; this.s = this.s + 10n; }
        @modifier b() { this.s = this.s + 100n; if (this.s > 0n) { return; } _; }
        @a @b constructor() { this.s = this.s + 10000n; }
      }`),
    ).toContain('JETH323');
    // same shape on a FUNCTION (the fixed pre-existing miscompile): clean JETH323, no wrong bytes.
    expect(
      codes(`class C {
        s: u256;
        @modifier a() { this.s = this.s + 1n; _; this.s = this.s + 10n; }
        @modifier b() { this.s = this.s + 100n; if (this.s > 0n) { return; } _; this.s = this.s + 1000n; }
        @a @b f(): External<void> { this.s = this.s + 10000n; }
      }`),
    ).toContain('JETH323');
    // an outlined body re-run by a multi-placeholder modifier that WRITES its own param -> JETH323.
    expect(
      codes(`class C {
        s: u256;
        @modifier m() { _; this.s = this.s + 10n; _; }
        @m constructor(x: u256) { x = x + 1n; this.s = this.s + x; if (x > 0n) { return; } this.s = 0n; }
      }`),
    ).toContain('JETH323');
  });

  it('unregressed: nested modifiers with a bare return confined to the OUTERMOST layer still lift', async () => {
    await eqDeploy(
      `class C {
        s: u256;
        @modifier a() { this.s = this.s + 1n; if (this.s > 100n) { return; } _; this.s = this.s + 10n; }
        @modifier b() { this.s = this.s + 100n; _; this.s = this.s + 1000n; }
        @a @b constructor(x: u256) { this.s = this.s + x; }
      }`,
      `contract C {
        uint256 s;
        modifier a() { s = s + 1; if (s > 100) { return; } _; s = s + 10; }
        modifier b() { s = s + 100; _; s = s + 1000; }
        constructor(uint256 x) a() b() { s = s + x; }
      }`,
      W(5),
      [0n],
    );
    // inner bare-return under a PRE-ONLY outer stays accepted (level exit == solc layer exit).
    await eqDeploy(
      `class C {
        s: u256;
        @modifier a(y: u256) { require(y > 0n, "no"); _; }
        @modifier b() { this.s = this.s + 100n; if (this.s > 0n) { return; } _; this.s = this.s + 1000n; }
        @a(1n) @b constructor(x: u256) { this.s = this.s + x; }
      }`,
      `contract C {
        uint256 s;
        modifier a(uint256 y) { require(y > 0, "no"); _; }
        modifier b() { s = s + 100; if (s > 0) { return; } _; s = s + 1000; }
        constructor(uint256 x) a(1) b() { s = s + x; }
      }`,
      W(5),
      [0n],
    );
  });
});
