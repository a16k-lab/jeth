// Internal function-type parameters / values (function pointers). A `(params) => ret` value is an
// address-taken internal function, dispatched at runtime by a stable integer id. Behaviorally
// byte-identical (returndata + storage + accept/reject) to solc 0.8.35's internal `function(...)` type.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import solc from 'solc';

const sel = (s: string) => functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

// --- the headline + the full behavioral surface (single-pointer forms) ---
const JETH = `@contract class C {
  @pure inc(x: u256): u256 { return x + 1n; }
  @pure dec(x: u256): u256 { return x - 1n; }
  @pure add(x: u256, y: u256): u256 { return x + y; }
  @pure ap(f: (x: u256) => u256, v: u256): u256 { return f(v); }
  // headline
  @external @pure runInc(): u256 { return this.ap(this.inc, 5n); }
  @external @pure runDec(): u256 { return this.ap(this.dec, 5n); }
  // passed through several functions
  @pure ap2(f: (x: u256) => u256, v: u256): u256 { return this.ap(f, v); }
  @external @pure passThrough(): u256 { return this.ap2(this.inc, 41n); }
  // conditional pointer
  @external @pure cond(c: bool, v: u256): u256 { let g: (x: u256) => u256 = c ? this.inc : this.dec; return g(v); }
  // two-arg pointer
  @pure ap2a(g: (x: u256, y: u256) => u256, a: u256, b: u256): u256 { return g(a, b); }
  @external @pure twoArg(): u256 { return this.ap2a(this.add, 20n, 22n); }
  // pointer returned from an internal fn then called
  @pure sel(c: bool): (x: u256) => u256 { return c ? this.inc : this.dec; }
  @external @pure returned(c: bool, v: u256): u256 { let g: (x: u256) => u256 = this.sel(c); return g(v); }
  // f == g / f != g
  @external @pure eqSame(): bool { let a: (x: u256) => u256 = this.inc; let b: (x: u256) => u256 = this.inc; return a == b; }
  @external @pure eqDiff(): bool { let a: (x: u256) => u256 = this.inc; let b: (x: u256) => u256 = this.dec; return a == b; }
  @external @pure neDiff(): bool { let a: (x: u256) => u256 = this.inc; let b: (x: u256) => u256 = this.dec; return a != b; }
}`;
const SOL = `${SPDX}contract C {
  function inc(uint256 x) internal pure returns(uint256){ return x+1; }
  function dec(uint256 x) internal pure returns(uint256){ return x-1; }
  function add(uint256 x, uint256 y) internal pure returns(uint256){ return x+y; }
  function ap(function(uint256) pure returns(uint256) f, uint256 v) internal pure returns(uint256){ return f(v); }
  function runInc() external pure returns(uint256){ return ap(inc, 5); }
  function runDec() external pure returns(uint256){ return ap(dec, 5); }
  function ap2(function(uint256) pure returns(uint256) f, uint256 v) internal pure returns(uint256){ return ap(f, v); }
  function passThrough() external pure returns(uint256){ return ap2(inc, 41); }
  function cond(bool c, uint256 v) external pure returns(uint256){ function(uint256) pure returns(uint256) g = c ? inc : dec; return g(v); }
  function ap2a(function(uint256,uint256) pure returns(uint256) g, uint256 a, uint256 b) internal pure returns(uint256){ return g(a, b); }
  function twoArg() external pure returns(uint256){ return ap2a(add, 20, 22); }
  function sel(bool c) internal pure returns(function(uint256) pure returns(uint256)){ return c ? inc : dec; }
  function returned(bool c, uint256 v) external pure returns(uint256){ function(uint256) pure returns(uint256) g = sel(c); return g(v); }
  function eqSame() external pure returns(bool){ function(uint256) pure returns(uint256) a = inc; function(uint256) pure returns(uint256) b = inc; return a == b; }
  function eqDiff() external pure returns(bool){ function(uint256) pure returns(uint256) a = inc; function(uint256) pure returns(uint256) b = dec; return a == b; }
  function neDiff() external pure returns(bool){ function(uint256) pure returns(uint256) a = inc; function(uint256) pure returns(uint256) b = dec; return a != b; }
}`;

// --- stateful: a MUTATING pointer stored in @state, called (writes state), and a null-pointer revert.
// NOTE: JETH's `(x)=>y` surface type carries no mutability, so a call through a pointer conservatively
// inherits the effects of EVERY same-signature target. This contract therefore keeps ALL its
// same-signature targets mutating (setS), so the enclosing functions are correctly nonpayable - matching
// solc. (A separate contract below tests a @view pointer whose only target is view.)
const JETH_STATE = `@contract class C {
  @state s: u256;
  setS(x: u256): u256 { this.s = x * 3n; return this.s; }
  @state h: (x: u256) => u256;
  constructor() { this.s = 100n; }
  @external setMut() { this.h = this.setS; }
  @external runMut(v: u256): u256 { let g: (x: u256) => u256 = this.h; return g(v); }
  @external @view getS(): u256 { return this.s; }
  @external nullCall(v: u256): u256 { let g: (x: u256) => u256 = this.h; return g(v); }
}`;
const SOL_STATE = `${SPDX}contract C {
  uint256 s;
  function setS(uint256 x) internal returns(uint256){ s = x * 3; return s; }
  function(uint256) returns(uint256) h;
  constructor() { s = 100; }
  function setMut() external { h = setS; }
  function runMut(uint256 v) external returns(uint256){ function(uint256) returns(uint256) g = h; return g(v); }
  function getS() external view returns(uint256){ return s; }
  function nullCall(uint256 v) external returns(uint256){ function(uint256) returns(uint256) g = h; return g(v); }
}`;

// A CONSTRUCTOR that calls THROUGH a function pointer: the target userfn_ and the dispatcher must be
// duplicated into the creation object (regression for the ctor-reachability closure).
const JETH_CTOR = `@contract class C {
  @state s: u256;
  @pure dbl(x: u256): u256 { return x * 2n; }
  ap(f: (x: u256) => u256, v: u256): u256 { return f(v); }
  constructor() { this.s = this.ap(this.dbl, 21n); }
  @external @view get(): u256 { return this.s; }
}`;
const SOL_CTOR = `${SPDX}contract C {
  uint256 s;
  function dbl(uint256 x) internal pure returns(uint256){ return x*2; }
  function ap(function(uint256) pure returns(uint256) f, uint256 v) internal pure returns(uint256){ return f(v); }
  constructor() { s = ap(dbl, 21); }
  function get() external view returns(uint256){ return s; }
}`;

// A @view pointer whose ONLY same-signature target is view: the enclosing @view function is accepted.
const JETH_VIEW = `@contract class C {
  @state s: u256;
  constructor() { this.s = 100n; }
  @view rd(x: u256): u256 { return x + this.s; }
  @external @view viewPtr(v: u256): u256 { let g: (x: u256) => u256 = this.rd; return g(v); }
}`;
const SOL_VIEW = `${SPDX}contract C {
  uint256 s;
  constructor() { s = 100; }
  function rd(uint256 x) internal view returns(uint256){ return x + s; }
  function viewPtr(uint256 v) external view returns(uint256){ function(uint256) view returns(uint256) g = rd; return g(v); }
}`;

describe('internal function pointers vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  let jethS: Harness, solS: Harness, ajS: Address, asS: Address;
  let jethV: Harness, solV: Harness, ajV: Address, asV: Address;
  let jethC: Harness, solC: Harness, ajC: Address, asC: Address;
  async function eqOn(J: Harness, S: Harness, a: Address, b: Address, label: string, data: string) {
    const jr = await J.call(a, data);
    const sr = await S.call(b, data);
    expect(jr.success, `${label} success (jeth err=${jr.exceptionError})`).toBe(sr.success);
    expect(jr.returnHex, `${label} returndata`).toBe(sr.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
    const jbS = compile(JETH_STATE, { fileName: 'C.jeth' });
    const sbS = compileSolidity(SOL_STATE, 'C');
    jethS = await Harness.create();
    solS = await Harness.create();
    ajS = await jethS.deploy(jbS.creationBytecode);
    asS = await solS.deploy(sbS.creation);
    const jbV = compile(JETH_VIEW, { fileName: 'C.jeth' });
    const sbV = compileSolidity(SOL_VIEW, 'C');
    jethV = await Harness.create();
    solV = await Harness.create();
    ajV = await jethV.deploy(jbV.creationBytecode);
    asV = await solV.deploy(sbV.creation);
    const jbC = compile(JETH_CTOR, { fileName: 'C.jeth' });
    const sbC = compileSolidity(SOL_CTOR, 'C');
    jethC = await Harness.create();
    solC = await Harness.create();
    ajC = await jethC.deploy(jbC.creationBytecode);
    asC = await solC.deploy(sbC.creation);
  });

  it('headline apply(inc,5)=6 / apply(dec,5)=4', async () => {
    await eqOn(jeth, sol, aj, as, 'runInc', encodeCall(sel('runInc()'), []));
    await eqOn(jeth, sol, aj, as, 'runDec', encodeCall(sel('runDec()'), []));
  });
  it('passed through, two-arg, returned-then-called', async () => {
    await eqOn(jeth, sol, aj, as, 'passThrough', encodeCall(sel('passThrough()'), []));
    await eqOn(jeth, sol, aj, as, 'twoArg', encodeCall(sel('twoArg()'), []));
    for (const [c, v] of [[1n, 50n], [0n, 50n]] as const)
      await eqOn(jeth, sol, aj, as, `returned(${c},${v})`, encodeCall(sel('returned(bool,uint256)'), [c, v]));
  });
  it('conditional pointer', async () => {
    for (const [c, v] of [[1n, 10n], [0n, 10n]] as const)
      await eqOn(jeth, sol, aj, as, `cond(${c},${v})`, encodeCall(sel('cond(bool,uint256)'), [c, v]));
  });
  it('pointer equality f==g / f!=g', async () => {
    await eqOn(jeth, sol, aj, as, 'eqSame', encodeCall(sel('eqSame()'), []));
    await eqOn(jeth, sol, aj, as, 'eqDiff', encodeCall(sel('eqDiff()'), []));
    await eqOn(jeth, sol, aj, as, 'neDiff', encodeCall(sel('neDiff()'), []));
  });
  it('@view pointer reading state', async () => {
    await eqOn(jethV, solV, ajV, asV, 'viewPtr', encodeCall(sel('viewPtr(uint256)'), [5n]));
  });
  it('constructor calls through a function pointer', async () => {
    await eqOn(jethC, solC, ajC, asC, 'get', encodeCall(sel('get()'), []));
  });
  it('null (unset) state pointer call reverts Panic(0x51) identically', async () => {
    // h is never set -> calling through it reverts the same way in both.
    await eqOn(jethS, solS, ajS, asS, 'nullCall', encodeCall(sel('nullCall(uint256)'), [3n]));
  });
  it('mutating pointer writes state (returndata + storage identical)', async () => {
    // set the pointer, call it (writes s = v*3), then read s back.
    await eqOn(jethS, solS, ajS, asS, 'setMut', encodeCall(sel('setMut()'), []));
    await eqOn(jethS, solS, ajS, asS, 'runMut', encodeCall(sel('runMut(uint256)'), [11n]));
    await eqOn(jethS, solS, ajS, asS, 'getS', encodeCall(sel('getS()'), []));
  });
});

// --- accept/reject parity: must-reject shapes stay rejected (soundness) ---
describe('internal function pointers: reject parity', () => {
  const rejects: Record<string, string> = {
    'cast pointer to uint': `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure ap(f: (x: u256) => u256): u256 { return u256(f); }
      @external @pure run(): u256 { return this.ap(this.inc); }
    }`,
    'return pointer as uint': `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure ap(f: (x: u256) => u256): u256 { return f; }
      @external @pure run(): u256 { return this.ap(this.inc); }
    }`,
    'abi.encode a pointer': `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure ap(f: (x: u256) => u256): bytes { return abi.encode(f); }
      @external @pure run(): bytes { return this.ap(this.inc); }
    }`,
    'funcref param on @external': `@contract class C {
      @external run(f: (x: u256) => u256, v: u256): u256 { return f(v); }
    }`,
    'address of @external fn': `@contract class C {
      @external ext(x: u256): u256 { return x + 1n; }
      @pure ap(f: (x: u256) => u256, v: u256): u256 { return f(v); }
      @external run(): u256 { return this.ap(this.ext, 5n); }
    }`,
    'address of overloaded fn': `@contract class C {
      @pure f(x: u256): u256 { return x + 1n; }
      @pure f(x: u256, y: u256): u256 { return x + y; }
      @pure ap(g: (x: u256) => u256, v: u256): u256 { return g(v); }
      @external @pure run(): u256 { return this.ap(this.f, 7n); }
    }`,
    'signature mismatch': `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure ap(f: (x: u64) => u64): u64 { return f(1n); }
      @external @pure run(): u64 { return this.ap(this.inc); }
    }`,
    'arithmetic on a pointer': `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @external @pure run(): u256 { let a: (x: u256) => u256 = this.inc; let b: (x: u256) => u256 = a + a; return b(1n); }
    }`,
    'pure ptr type holding a state-writing target': `@contract class C {
      @state s: u256;
      wr(x: u256): u256 { this.s = x; return x; }
      @pure ap(f: (x: u256) => u256, v: u256): u256 { return f(v); }
      @external @pure run(): u256 { return this.ap(this.wr, 5n); }
    }`,
  };
  for (const [name, src] of Object.entries(rejects)) {
    it(`rejects: ${name}`, () => {
      expect(() => compile(src, { fileName: 'C.jeth' })).toThrow();
    });
  }
});

// --- KNOWN DEVIATION (documented + verified, see docs/distinctive-features.md section 6) -------------
// Two DISTINCT internal function pointers whose bodies are byte-identical (f and g both `return x + 1n`)
// compare UNEQUAL in JETH. That matches solc with the optimizer OFF and solc viaIR (both `false`), but NOT
// the legacy-optimizer-ON config the differential harness uses: its assembly block deduplicator merges the
// identical bodies onto one jump tag, so the pointers collide and compare EQUAL (`true`). It is an optimizer
// artifact, not language semantics, and JETH never returns wrong bytes; CALLS through such pointers dispatch
// byte-identically in every config. So we do NOT diff the equality VALUE against the harness's optimizer-on
// solc; we assert JETH's returndata directly and mirror it against solc compiled with the optimizer OFF.
const JETH_EQ = `@contract class C {
  @pure f(x: u256): u256 { return x + 1n; }
  @pure g(x: u256): u256 { return x + 1n; }
  @external @pure eq(): bool { return this.f == this.g; }
  @external @pure eqVar(): bool { let a: (x: u256) => u256 = this.f; let b: (x: u256) => u256 = this.g; return a == b; }
  @external @pure neq(): bool { return this.f != this.g; }
  @external @pure callBoth(x: u256): u256 { let a: (x: u256) => u256 = this.f; let b: (x: u256) => u256 = this.g; return a(x) + b(x); }
}`;
const SOL_EQ = `${SPDX}contract C {
  function f(uint256 x) internal pure returns(uint256){ return x+1; }
  function g(uint256 x) internal pure returns(uint256){ return x+1; }
  function eq() external pure returns(bool){ return f == g; }
  function eqVar() external pure returns(bool){ function(uint256) pure returns(uint256) a = f; function(uint256) pure returns(uint256) b = g; return a == b; }
  function neq() external pure returns(bool){ return f != g; }
  function callBoth(uint256 x) external pure returns(uint256){ function(uint256) pure returns(uint256) a = f; function(uint256) pure returns(uint256) b = g; return a(x) + b(x); }
}`;

// The shared compileSolidity() hardcodes optimizer ON; here we need to pick the setting per build.
function compileSolOptimizer(source: string, name: string, optimizerEnabled: boolean): string {
  const input = {
    language: 'Solidity',
    sources: { 'C.sol': { content: source } },
    settings: {
      optimizer: optimizerEnabled ? { enabled: true, runs: 200 } : { enabled: false },
      evmVersion: 'cancun',
      outputSelection: { '*': { '*': ['evm.bytecode.object'] } },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const fatal = (out.errors ?? []).filter((e: { severity: string }) => e.severity === 'error');
  if (fatal.length) throw new Error('solc failed:\n' + fatal.map((e: { formattedMessage: string }) => e.formattedMessage).join('\n'));
  return out.contracts['C.sol'][name].evm.bytecode.object;
}

const FALSE = '0x' + '0'.repeat(64);
const TRUE = '0x' + '0'.repeat(63) + '1';

describe('internal function pointers: identical-body equality (documented deviation)', () => {
  let jeth: Harness, solOn: Harness, solOff: Harness;
  let aj: Address, aOn: Address, aOff: Address;
  beforeAll(async () => {
    jeth = await Harness.create();
    solOn = await Harness.create();
    solOff = await Harness.create();
    aj = await jeth.deploy(compile(JETH_EQ, { fileName: 'C.jeth' }).creationBytecode);
    aOn = await solOn.deploy(compileSolOptimizer(SOL_EQ, 'C', true));
    aOff = await solOff.deploy(compileSolOptimizer(SOL_EQ, 'C', false));
  });

  it('JETH: identical-body pointers compare UNEQUAL (eq/eqVar false, neq true)', async () => {
    expect((await jeth.call(aj, encodeCall(sel('eq()'), []))).returnHex).toBe(FALSE);
    expect((await jeth.call(aj, encodeCall(sel('eqVar()'), []))).returnHex).toBe(FALSE);
    expect((await jeth.call(aj, encodeCall(sel('neq()'), []))).returnHex).toBe(TRUE);
  });

  it('matches solc with the optimizer OFF (the pointer semantics JETH implements)', async () => {
    expect((await solOff.call(aOff, encodeCall(sel('eq()'), []))).returnHex).toBe(FALSE);
    expect((await solOff.call(aOff, encodeCall(sel('eqVar()'), []))).returnHex).toBe(FALSE);
    expect((await solOff.call(aOff, encodeCall(sel('neq()'), []))).returnHex).toBe(TRUE);
  });

  it('documents the artifact: legacy-optimizer-ON solc dedups the bodies and returns EQUAL', async () => {
    // The one configuration that disagrees with JETH, and the reason we must not diff the equality value
    // against the harness's optimizer-on solc. If a future solc stops merging here, this flips and the
    // deviation should be revisited.
    expect((await solOn.call(aOn, encodeCall(sel('eq()'), []))).returnHex).toBe(TRUE);
    expect((await solOn.call(aOn, encodeCall(sel('neq()'), []))).returnHex).toBe(FALSE);
  });

  it('CALLS through both identical-body pointers dispatch byte-identically (even vs optimizer-on solc)', async () => {
    // Dispatch is byte-identical regardless of optimizer config; only the raw == value diverges.
    const data = encodeCall(sel('callBoth(uint256)'), [5n]);
    const jr = await jeth.call(aj, data);
    const sr = await solOn.call(aOn, data);
    expect(jr.success).toBe(sr.success);
    expect(jr.returnHex).toBe(sr.returnHex);
    expect(jr.returnHex).toBe('0x' + (12n).toString(16).padStart(64, '0')); // f(5)+g(5) = 6+6 = 12
  });
});
