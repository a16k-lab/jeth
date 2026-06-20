// F3 ADVERSARIAL: default + named function arguments at internal call sites.
//
// Invariant under test: defaults / named args desugar to a positional internal call and NEVER
// reach the ABI / selector / external boundary. For each behavioral claim we build BOTH a JETH
// contract (using defaults / named args at internal call sites) AND an equivalent Solidity contract
// whose internal helper is called with EVERY argument SPELLED OUT IN FULL, then assert byte-identical
// returndata + raw storage slots + event logs. Rejection probes capture the JETH diagnostic code and
// assert it never crashes the compiler.
//
// No em-dash / en-dash anywhere (plain hyphen or the word "to") per project style.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { CompileError } from '../src/diagnostics.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => { let x = v % (1n << 256n); if (x < 0n) x += 1n << 256n; return x.toString(16).padStart(64, '0'); };

type LogEntry = { topics: string[]; data: string };
const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
  a.length === b.length && a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics));

// Capture the first JETH error code (or 'CRASH' if the compiler threw something other than a
// CompileError, or 'OK' if it compiled clean). Never lets an exception escape.
function jethCodes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return ['OK'];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.filter((d) => d.severity === 'error').map((d) => d.code);
    return ['CRASH:' + (e as Error).message];
  }
}

// A reusable pair builder: compile + deploy a JETH and a Solidity contract, return their Harnesses
// and addresses, plus an `eq` that checks success + returndata, an `eqLogs` over emitted logs, and a
// raw-slot comparator.
async function buildPair(jSrc: string, sSrc: string) {
  const jb = compile(jSrc, { fileName: 'C.jeth' });
  const sb = compileSolidity(sSrc, 'C');
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} jeth=${j.exceptionError} sol=${s.exceptionError}`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    expect(eqLogs(j.logs as LogEntry[], s.logs as LogEntry[]),
      `${label} logs\n jeth=${JSON.stringify(j.logs)}\n sol =${JSON.stringify(s.logs)}`).toBe(true);
    return { j, s };
  }
  async function slotsEq(label: string, slots: bigint[]) {
    for (const sl of slots) {
      expect(await readSlot(jeth, aj, sl), `${label} slot ${sl}`).toBe(await readSlot(sol, as, sl));
    }
  }
  return { jeth, sol, aj, as, jb, eq, slotsEq };
}

// ---------------------------------------------------------------------------
// 1. Default of each kind, omitted at the call site, vs a fully-spelled-out solc twin.
// ---------------------------------------------------------------------------
describe('F3 adv: a default of every kind matches the spelled-out constant', () => {
  const J = `@contract class C {
    @hidden du(a: u256, b: u256 = 7n): u256 { return a + b; }
    @hidden di(a: i64, b: i64 = -5n): i64 { return a + b; }
    @hidden db(a: u256, on: bool = true): u256 { return on ? a : 0n; }
    @hidden da(a: u256, who: address = address(0n)): u256 { return who == address(0n) ? a : a + 1n; }
    @hidden dan(a: u256, who: address = address(0x00000000000000000000000000000000000000ffn)): u256 { return who == address(0n) ? a : a + 1n; }
    @hidden dby(a: u256, tag: bytes32 = bytes32(0xdeadbeefn)): bytes32 { return tag; }
    @hidden dmax(a: u256, cap: u256 = type(u256).max): u256 { return a < cap ? a : cap; }
    @hidden dmin(a: i128, lo: i128 = type(i128).min): i128 { return a > lo ? a : lo; }
    @hidden d255(a: u8, b: u8 = u8(255n)): u8 { return a > b ? a : b; }
    @external @pure tu(a: u256): u256 { return this.du(a); }
    @external @pure ti(a: i64): i64 { return this.di(a); }
    @external @pure tb(a: u256): u256 { return this.db(a); }
    @external @pure ta(a: u256): u256 { return this.da(a); }
    @external @pure tan(a: u256): u256 { return this.dan(a); }
    @external @pure tby(): bytes32 { return this.dby(0n); }
    @external @pure tmax(a: u256): u256 { return this.dmax(a); }
    @external @pure tmin(a: i128): i128 { return this.dmin(a); }
    @external @pure t255(a: u8): u8 { return this.d255(a); }
  }`;
  const S = `// SPDX-License-Identifier: MIT
  pragma solidity ^0.8.20;
  contract C {
    function du(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; }
    function di(int64 a, int64 b) internal pure returns (int64) { return a + b; }
    function db(uint256 a, bool on) internal pure returns (uint256) { return on ? a : 0; }
    function da(uint256 a, address who) internal pure returns (uint256) { return who == address(0) ? a : a + 1; }
    function dan(uint256 a, address who) internal pure returns (uint256) { return who == address(0) ? a : a + 1; }
    function dby(uint256, bytes32 tag) internal pure returns (bytes32) { return tag; }
    function dmax(uint256 a, uint256 cap) internal pure returns (uint256) { return a < cap ? a : cap; }
    function dmin(int128 a, int128 lo) internal pure returns (int128) { return a > lo ? a : lo; }
    function d255(uint8 a, uint8 b) internal pure returns (uint8) { return a > b ? a : b; }
    function tu(uint256 a) external pure returns (uint256) { return du(a, 7); }
    function ti(int64 a) external pure returns (int64) { return di(a, -5); }
    function tb(uint256 a) external pure returns (uint256) { return db(a, true); }
    function ta(uint256 a) external pure returns (uint256) { return da(a, address(0)); }
    function tan(uint256 a) external pure returns (uint256) { return dan(a, address(uint160(0xff))); }
    function tby() external pure returns (bytes32) { return dby(0, bytes32(uint256(0xdeadbeef))); }
    function tmax(uint256 a) external pure returns (uint256) { return dmax(a, type(uint256).max); }
    function tmin(int128 a) external pure returns (int128) { return dmin(a, type(int128).min); }
    function t255(uint8 a) external pure returns (uint8) { return d255(a, uint8(255)); }
  }`;
  let P: Awaited<ReturnType<typeof buildPair>>;
  beforeAll(async () => { P = await buildPair(J, S); });
  it('each default kind equals the explicit constant in solc', async () => {
    await P.eq('uint default', encodeCall(sel('tu(uint256)'), [100n]));
    await P.eq('int64 NEGATIVE default', encodeCall(sel('ti(int64)'), [10n]));
    await P.eq('int64 neg default underflow path', encodeCall(sel('ti(int64)'), [-10n]));
    await P.eq('bool default true', encodeCall(sel('tb(uint256)'), [42n]));
    await P.eq('address(0n) default', encodeCall(sel('ta(uint256)'), [9n]));
    await P.eq('nonzero address literal default', encodeCall(sel('tan(uint256)'), [9n]));
    await P.eq('bytesN default', encodeCall(sel('tby()'), []));
    await P.eq('type(u256).max default under', encodeCall(sel('tmax(uint256)'), [5n]));
    await P.eq('type(u256).max default at-max', encodeCall(sel('tmax(uint256)'), [(1n << 256n) - 1n]));
    await P.eq('type(i128).min default', encodeCall(sel('tmin(int128)'), [3n]));
    await P.eq('u8(255n) default', encodeCall(sel('t255(uint8)'), [10n]));
  });
});

// ---------------------------------------------------------------------------
// 2. Multiple trailing defaults: omit none / some / all, including a zero-arg call.
// ---------------------------------------------------------------------------
describe('F3 adv: multiple trailing defaults, omit none / some / all', () => {
  const J = `@contract class C {
    @hidden f(a: u256 = 1n, b: u256 = 2n, c: u256 = 3n): u256 { return a * 100n + b * 10n + c; }
    @external @pure none(): u256 { return this.f(); }
    @external @pure one(x: u256): u256 { return this.f(x); }
    @external @pure two(x: u256, y: u256): u256 { return this.f(x, y); }
    @external @pure all(x: u256, y: u256, z: u256): u256 { return this.f(x, y, z); }
  }`;
  const S = `// SPDX-License-Identifier: MIT
  pragma solidity ^0.8.20;
  contract C {
    function f(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) { return a * 100 + b * 10 + c; }
    function none() external pure returns (uint256) { return f(1, 2, 3); }
    function one(uint256 x) external pure returns (uint256) { return f(x, 2, 3); }
    function two(uint256 x, uint256 y) external pure returns (uint256) { return f(x, y, 3); }
    function all(uint256 x, uint256 y, uint256 z) external pure returns (uint256) { return f(x, y, z); }
  }`;
  let P: Awaited<ReturnType<typeof buildPair>>;
  beforeAll(async () => { P = await buildPair(J, S); });
  it('omit-all (zero args), omit-some, omit-none', async () => {
    await P.eq('none', encodeCall(sel('none()'), []));
    await P.eq('one', encodeCall(sel('one(uint256)'), [4n]));
    await P.eq('two', encodeCall(sel('two(uint256,uint256)'), [4n, 5n]));
    await P.eq('all', encodeCall(sel('all(uint256,uint256,uint256)'), [4n, 5n, 6n]));
  });
});

// ---------------------------------------------------------------------------
// 3. Defaults that affect STATE (raw slots) and EVENTS (logs).
// ---------------------------------------------------------------------------
describe('F3 adv: defaulted arg flowing into storage + into an event', () => {
  const J = `@contract class C {
    @state x: u256;
    @state y: u256;
    @event Set(@indexed who: address, amount: u256);
    @hidden store(a: u256, b: u256 = 1000n): void { this.x = a + b; this.y = b; }
    @hidden announce(amount: u256, who: address = address(u160(0xbeefn))): void { emit(Set(who, amount)); }
    @external setIt(a: u256): void { this.store(a); }
    @external setBoth(a: u256, b: u256): void { this.store(a, b); }
    @external ann(amount: u256): void { this.announce(amount); }
  }`;
  const S = `// SPDX-License-Identifier: MIT
  pragma solidity ^0.8.20;
  contract C {
    uint256 x;
    uint256 y;
    event Set(address indexed who, uint256 amount);
    function store(uint256 a, uint256 b) internal { x = a + b; y = b; }
    function announce(uint256 amount, address who) internal { emit Set(who, amount); }
    function setIt(uint256 a) external { store(a, 1000); }
    function setBoth(uint256 a, uint256 b) external { store(a, b); }
    function ann(uint256 amount) external { announce(amount, address(uint160(0xbeef))); }
  }`;
  let P: Awaited<ReturnType<typeof buildPair>>;
  beforeAll(async () => { P = await buildPair(J, S); });
  it('storage slots and event logs match solc', async () => {
    await P.eq('setIt (default b=1000)', encodeCall(sel('setIt(uint256)'), [5n]));
    await P.slotsEq('after setIt', [0n, 1n]);
    await P.eq('setBoth override', encodeCall(sel('setBoth(uint256,uint256)'), [7n, 3n]));
    await P.slotsEq('after setBoth', [0n, 1n]);
    await P.eq('ann (default who=beef)', encodeCall(sel('ann(uint256)'), [99n]));
  });
});

// ---------------------------------------------------------------------------
// 4. Recursion with a defaulted accumulator.
// ---------------------------------------------------------------------------
describe('F3 adv: recursion with a defaulted accumulator', () => {
  const J = `@contract class C {
    @hidden rec(n: u256, acc: u256 = 0n): u256 { if (n == 0n) { return acc; } return this.rec(n - 1n, acc + n); }
    @external @pure sumTo(n: u256): u256 { return this.rec(n); }
  }`;
  const S = `// SPDX-License-Identifier: MIT
  pragma solidity ^0.8.20;
  contract C {
    function rec(uint256 n, uint256 acc) internal pure returns (uint256) { if (n == 0) { return acc; } return rec(n - 1, acc + n); }
    function sumTo(uint256 n) external pure returns (uint256) { return rec(n, 0); }
  }`;
  let P: Awaited<ReturnType<typeof buildPair>>;
  beforeAll(async () => { P = await buildPair(J, S); });
  it('deep-ish recursion matches solc', async () => {
    await P.eq('sumTo(0)', encodeCall(sel('sumTo(uint256)'), [0n]));
    await P.eq('sumTo(1)', encodeCall(sel('sumTo(uint256)'), [1n]));
    await P.eq('sumTo(50)', encodeCall(sel('sumTo(uint256)'), [50n]));
    await P.eq('sumTo(200)', encodeCall(sel('sumTo(uint256)'), [200n]));
  });
});

// ---------------------------------------------------------------------------
// 5. Named args: full / reordered / partial+default / shorthand / single-struct-param / struct-literal.
// ---------------------------------------------------------------------------
describe('F3 adv: named arguments bind by NAME not position', () => {
  const J = `@struct class P3 { x: u256; y: u256; z: u256; }
  @contract class C {
    @hidden f(a: u256, b: u256, c: u256 = 9n): u256 { return a * 10000n + b * 100n + c; }
    @hidden viaStruct(p: P3): u256 { return p.x * 10000n + p.y * 100n + p.z; }
    @external @pure full(a: u256, b: u256, c: u256): u256 { return this.f({ a: a, b: b, c: c }); }
    @external @pure reorder(a: u256, b: u256, c: u256): u256 { return this.f({ c: c, a: a, b: b }); }
    @external @pure part(a: u256, b: u256): u256 { return this.f({ b: b, a: a }); }
    @external @pure shorthand(a: u256, b: u256): u256 { return this.f({ a, b }); }
    @external @pure structParamNamed(x: u256, y: u256, z: u256): u256 {
      let v: P3 = P3(x, y, z);
      return this.viaStruct({ p: v });               // key == param name -> named call
    }
    @external @pure structParamLiteral(x: u256, y: u256, z: u256): u256 {
      return this.viaStruct({ x: x, y: y, z: z });   // keys are STRUCT FIELDS -> positional struct literal
    }
  }`;
  const S = `// SPDX-License-Identifier: MIT
  pragma solidity ^0.8.20;
  contract C {
    struct P3 { uint256 x; uint256 y; uint256 z; }
    function f(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) { return a * 10000 + b * 100 + c; }
    function viaStruct(P3 memory p) internal pure returns (uint256) { return p.x * 10000 + p.y * 100 + p.z; }
    function full(uint256 a, uint256 b, uint256 c) external pure returns (uint256) { return f(a, b, c); }
    function reorder(uint256 a, uint256 b, uint256 c) external pure returns (uint256) { return f(a, b, c); }
    function part(uint256 a, uint256 b) external pure returns (uint256) { return f(a, b, 9); }
    function shorthand(uint256 a, uint256 b) external pure returns (uint256) { return f(a, b, 9); }
    function structParamNamed(uint256 x, uint256 y, uint256 z) external pure returns (uint256) { return viaStruct(P3(x, y, z)); }
    function structParamLiteral(uint256 x, uint256 y, uint256 z) external pure returns (uint256) { return viaStruct(P3(x, y, z)); }
  }`;
  let P: Awaited<ReturnType<typeof buildPair>>;
  beforeAll(async () => { P = await buildPair(J, S); });
  it('named full / reordered / partial / shorthand / struct-param-named / struct-literal', async () => {
    await P.eq('full', encodeCall(sel('full(uint256,uint256,uint256)'), [1n, 2n, 3n]));
    // reorder: keys given as { c, a, b } but must bind by name; with a=1,b=2,c=3 result is identical to full.
    await P.eq('reorder', encodeCall(sel('reorder(uint256,uint256,uint256)'), [1n, 2n, 3n]));
    await P.eq('reorder distinct', encodeCall(sel('reorder(uint256,uint256,uint256)'), [4n, 5n, 6n]));
    await P.eq('partial (c default 9)', encodeCall(sel('part(uint256,uint256)'), [1n, 2n]));
    await P.eq('shorthand', encodeCall(sel('shorthand(uint256,uint256)'), [7n, 8n]));
    await P.eq('struct-param NAMED { p: value }', encodeCall(sel('structParamNamed(uint256,uint256,uint256)'), [1n, 2n, 3n]));
    await P.eq('struct-LITERAL { x,y,z }', encodeCall(sel('structParamLiteral(uint256,uint256,uint256)'), [4n, 5n, 6n]));
  });
});

// ---------------------------------------------------------------------------
// 6. ABI / selector boundary: a @public g(a, b=5n) is called both ways. Selector and ABI must list
//    BOTH params; the default never shrinks the signature.
// ---------------------------------------------------------------------------
describe('F3 adv: a defaulted param does NOT leak into the ABI / selector', () => {
  const J = `@contract class C {
    @public @pure g(a: u256, b: u256 = 5n): u256 { return a + b; }
    @external @pure useInternal(a: u256): u256 { return this.g(a); }
  }`;
  const S = `// SPDX-License-Identifier: MIT
  pragma solidity ^0.8.20;
  contract C {
    function g(uint256 a, uint256 b) public pure returns (uint256) { return a + b; }
    function useInternal(uint256 a) external pure returns (uint256) { return g(a, 5); }
  }`;
  // A control twin with NO default, to prove the default does not perturb the selector / ABI.
  const J_NODEF = `@contract class C {
    @public @pure g(a: u256, b: u256): u256 { return a + b; }
  }`;
  let P: Awaited<ReturnType<typeof buildPair>>;
  beforeAll(async () => { P = await buildPair(J, S); });
  it('selector lists both params and equals g(uint256,uint256)', () => {
    const abi = P.jb.abi;
    const g = abi.find((e: any) => e.name === 'g');
    expect(g, 'g must be in the ABI (public is externally callable)').toBeDefined();
    // The ABI input list carries BOTH params; the default never shrinks the signature.
    expect(g!.inputs.map((i: any) => i.type)).toEqual(['uint256', 'uint256']);
    // The dispatcher contains the full two-param selector...
    expect(P.jb.runtimeBytecode.includes(sel('g(uint256,uint256)')), 'g(uint256,uint256) selector present').toBe(true);
    // ...and a defaulted param does NOT change the ABI vs the same function with no default.
    const abiNoDef = compile(J_NODEF, { fileName: 'C.jeth' }).abi;
    const gNoDef = abiNoDef.find((e: any) => e.name === 'g');
    expect(gNoDef!.inputs.map((i: any) => i.type)).toEqual(['uint256', 'uint256']);
  });
  it('external g(a,b) and internal this.g(a) both match solc; a leaked g(uint256) does NOT dispatch', async () => {
    await P.eq('external g full', encodeCall(sel('g(uint256,uint256)'), [10n, 20n]));
    await P.eq('internal this.g(a) uses default', encodeCall(sel('useInternal(uint256)'), [10n]));
    // The would-be "defaults leaked into the selector" form g(uint256) must NOT exist as a function:
    // both JETH and solc lack it, so a call with that selector hits the fallback (revert) identically.
    await P.eq('phantom g(uint256) selector reverts in both', encodeCall(sel('g(uint256)'), [10n]));
  });
});

// ---------------------------------------------------------------------------
// 7. Truncated calldata to an external g(uint256,uint256): solc pads missing static words with zero
//    rather than reverting. Confirm JETH matches that quirk byte-for-byte.
// ---------------------------------------------------------------------------
describe('F3 adv: truncated calldata parity (solc zero-pads static args)', () => {
  const J = `@contract class C {
    @external @pure g(a: u256, b: u256): u256 { return a + b; }
  }`;
  const S = `// SPDX-License-Identifier: MIT
  pragma solidity ^0.8.20;
  contract C {
    function g(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }
  }`;
  let P: Awaited<ReturnType<typeof buildPair>>;
  beforeAll(async () => { P = await buildPair(J, S); });
  it('one-word, zero-word and over-long calldata behave like solc', async () => {
    // only ONE word of args (b missing) -> solc reads b as 0.
    await P.eq('one word', '0x' + sel('g(uint256,uint256)') + pad(40n));
    // ZERO words of args -> a and b both 0.
    await P.eq('zero words', '0x' + sel('g(uint256,uint256)'));
    // extra trailing word -> ignored by both.
    await P.eq('over-long', '0x' + sel('g(uint256,uint256)') + pad(1n) + pad(2n) + pad(999n));
  });
});

// ---------------------------------------------------------------------------
// 8. Soundness / rejection probes: each must produce a diagnostic (not crash, not silently accept).
// ---------------------------------------------------------------------------
describe('F3 adv: rejection probes (must diagnose, never crash, never silently accept)', () => {
  const base = (members: string) => `@contract class C {\n${members}\n}`;

  it('JETH250: non-constant defaults (param ref, state, msg.sender, call, arithmetic on non-literal)', () => {
    // default references another param
    expect(jethCodes(base(`@hidden f(a: u256, b: u256 = a): u256 { return a + b; }`))).toContain('JETH250');
    // default reads state this.x
    expect(jethCodes(base(`@state x: u256;\n@hidden f(b: u256 = this.x): u256 { return b; }`))).toContain('JETH250');
    // default is msg.sender
    expect(jethCodes(base(`@hidden f(who: address = msg.sender): u256 { return 1n; }`))).toContain('JETH250');
    // default is a function call to another function
    expect(jethCodes(base(`@hidden h(): u256 { return 1n; }\n@hidden f(b: u256 = this.h()): u256 { return b; }`))).toContain('JETH250');
    // arithmetic on a non-literal (a + 1n where a is a param) -> not a self-contained constant
    expect(jethCodes(base(`@hidden f(a: u256, b: u256 = a + 1n): u256 { return b; }`))).toContain('JETH250');
  });

  it('JETH252: default on a non-value-type param (struct / array / bytes)', () => {
    expect(jethCodes(`@struct class P { x: u256; }\n` + base(`@hidden f(p: P = P(0n)): u256 { return p.x; }`))).toContain('JETH252');
    expect(jethCodes(base(`@hidden f(a: u256[] = [1n]): u256 { return a.length; }`))).toContain('JETH252');
    expect(jethCodes(base(`@hidden f(b: bytes = 0x00n): u256 { return b.length; }`))).toContain('JETH252');
  });

  it('JETH251: a required (non-defaulted) param after a defaulted one', () => {
    expect(jethCodes(base(`@hidden f(a: u256 = 1n, b: u256): u256 { return a + b; }`))).toContain('JETH251');
  });

  it('JETH070: out-of-range default literal (u8 = 300n) is rejected', () => {
    const codes = jethCodes(base(`@hidden f(a: u8 = 300n): u8 { return a; }\n@external @pure t(): u8 { return this.f(); }`));
    expect(codes).toContain('JETH070');
  });

  it('wrong-type default (bool = 1n) is diagnosed when filled at a call site', () => {
    const codes = jethCodes(base(`@hidden f(on: bool = 1n): u256 { return on ? 1n : 0n; }\n@external @pure t(): u256 { return this.f(); }`));
    // an integer literal coerced into bool -> JETH084 (cannot use integer literal as bool).
    expect(codes.some((c) => c === 'JETH084' || c === 'JETH085')).toBe(true);
  });

  it('JETH148: too many positional args, and omitting a non-defaulted arg', () => {
    expect(jethCodes(base(`@hidden f(a: u256, b: u256 = 1n): u256 { return a + b; }\n@external @pure t(): u256 { return this.f(1n, 2n, 3n); }`))).toContain('JETH148');
    expect(jethCodes(base(`@hidden f(a: u256, b: u256): u256 { return a + b; }\n@external @pure t(): u256 { return this.f(1n); }`))).toContain('JETH148');
  });

  it('named: unknown key, missing no-default param, duplicate key', () => {
    // an unknown key makes looksLikeNamedArgs false -> the object is treated as a positional arg,
    // which then fails to coerce into the u256 param. Whatever the code, it must reject (no crash).
    const unknown = jethCodes(base(`@hidden f(a: u256, b: u256): u256 { return a + b; }\n@external @pure t(): u256 { return this.f({ a: 1n, zzz: 2n }); }`));
    expect(unknown).not.toContain('OK');
    expect(unknown.every((c) => !c.startsWith('CRASH'))).toBe(true);
    // named call missing a param that has no default -> JETH254
    expect(jethCodes(base(`@hidden f(a: u256, b: u256): u256 { return a + b; }\n@external @pure t(): u256 { return this.f({ a: 1n }); }`))).toContain('JETH254');
    // duplicate named key -> JETH253 (parser may also reject a literal duplicate; accept either way as long as it diagnoses)
    const dup = jethCodes(base(`@hidden f(a: u256, b: u256): u256 { return a + b; }\n@external @pure t(): u256 { return this.f({ a: 1n, a: 2n, b: 3n }); }`));
    expect(dup).not.toContain('OK');
    expect(dup.every((c) => !c.startsWith('CRASH'))).toBe(true);
  });

  it('JETH240: a named call to an @external function is rejected', () => {
    expect(jethCodes(base(`@external @pure f(a: u256, b: u256): u256 { return a + b; }\n@external @pure t(): u256 { return this.f({ a: 1n, b: 2n }); }`))).toContain('JETH240');
  });

  it('mixing positional + named: this.f(1n, {b:2n}) is sound (rejected, never silently mis-binds)', () => {
    // provided.length == 2 so the named-args branch (length==1) is skipped; arg[1] is the object
    // literal coerced into u256 param b -> must be rejected, not silently accepted.
    const codes = jethCodes(base(`@hidden f(a: u256, b: u256 = 7n): u256 { return a + b; }\n@external @pure t(): u256 { return this.f(1n, { b: 2n }); }`));
    expect(codes).not.toContain('OK');
    expect(codes.every((c) => !c.startsWith('CRASH'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 9. type(T).max default where T is WIDER than the param: must range-error exactly as writing the
//    literal directly would, OR truncate identically. We compare against a Solidity twin to nail it.
// ---------------------------------------------------------------------------
describe('F3 adv: cross-width type(T).max default', () => {
  it('cap: u128 = type(u256).max range-errors the same as the bare literal', () => {
    // The default type(u256).max == 2^256-1, coerced into a u128 param at the call site, must hit
    // the same range check that the literal 2^256-1 would. Both should yield JETH070.
    const withDefault = jethCodes(`@contract class C {
      @hidden f(cap: u128 = type(u256).max): u128 { return cap; }
      @external @pure t(): u128 { return this.f(); }
    }`);
    const bareLiteral = jethCodes(`@contract class C {
      @external @pure t(): u128 { let v: u128 = ${(1n << 256n) - 1n}n; return v; }
    }`);
    expect(withDefault, 'type(u256).max into u128 default').toContain('JETH070');
    expect(bareLiteral, 'bare 2^256-1 into u128').toContain('JETH070');
  });

  it('cap: u128 = type(u128).max is in range and matches solc', async () => {
    const J = `@contract class C {
      @hidden f(x: u128, cap: u128 = type(u128).max): u128 { return x < cap ? x : cap; }
      @external @pure t(x: u128): u128 { return this.f(x); }
    }`;
    const S = `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function f(uint128 x, uint128 cap) internal pure returns (uint128) { return x < cap ? x : cap; }
      function t(uint128 x) external pure returns (uint128) { return f(x, type(uint128).max); }
    }`;
    const P = await buildPair(J, S);
    await P.eq('u128 cap default under', encodeCall(sel('t(uint128)'), [123n]));
    await P.eq('u128 cap default at-max', encodeCall(sel('t(uint128)'), [(1n << 128n) - 1n]));
  });
});

// ---------------------------------------------------------------------------
// 10. Default validation is EAGER (declaration-time): a wrong-typed or out-of-range default is a
//     type error at the parameter, even on a helper that is never internally called or one that is
//     always called with the argument supplied (matching TypeScript, which flags type errors in
//     unused code). It is purely a diagnostic - an unused default emits no code - never a miscompile.
// ---------------------------------------------------------------------------
describe('F3 adv: default validation is eager (declaration-time)', () => {
  const base = (members: string) => `@contract class C {\n${members}\n}`;
  it('a bad default errors even on an UNCALLED helper', () => {
    // bool = 1n: wrong type. u8 = 300n: out of range. u128 = type(u256).max: out of range.
    expect(jethCodes(base(`@hidden f(on: bool = 1n): u256 { return on ? 1n : 0n; }\n@external @pure t(): u256 { return 0n; }`))
      .some((c) => c === 'JETH084' || c === 'JETH085')).toBe(true);
    expect(jethCodes(base(`@hidden f(a: u8 = 300n): u8 { return a; }\n@external @pure t(): u8 { return 0n; }`))).toContain('JETH070');
    expect(jethCodes(base(`@hidden f(cap: u128 = type(u256).max): u128 { return cap; }\n@external @pure t(): u128 { return 0n; }`))).toContain('JETH070');
  });
  it('the SAME bad default also errors when the helper IS internally called', () => {
    expect(jethCodes(base(`@hidden f(on: bool = 1n): u256 { return on ? 1n : 0n; }\n@external @pure t(): u256 { return this.f(); }`))
      .some((c) => c === 'JETH084' || c === 'JETH085')).toBe(true);
    expect(jethCodes(base(`@hidden f(a: u8 = 300n): u8 { return a; }\n@external @pure t(): u8 { return this.f(); }`))).toContain('JETH070');
    expect(jethCodes(base(`@hidden f(cap: u128 = type(u256).max): u128 { return cap; }\n@external @pure t(): u128 { return this.f(); }`))).toContain('JETH070');
  });
  it('a bad default errors even when every call supplies the arg (validated at the declaration)', () => {
    expect(jethCodes(base(`@hidden f(a: u8 = 300n): u8 { return a; }\n@external @pure t(): u8 { return this.f(5n); }`))).toContain('JETH070');
  });
});

// ---------------------------------------------------------------------------
// 11. A single object-literal positional arg for a STRUCT param (keys are struct fields, not param
//     names) is constructed correctly even in a MIXED call f(positional, {field: v}). Runtime parity.
// ---------------------------------------------------------------------------
describe('F3 adv: positional struct-literal arg alongside an ordinary positional arg', () => {
  const J = `@struct class S { x: u256; y: u256; }
  @contract class C {
    @hidden f(a: u256, b: S): u256 { return a + b.x * 10n + b.y; }
    @external @pure t(a: u256, bx: u256, by: u256): u256 { return this.f(a, { x: bx, y: by }); }
  }`;
  const Sol = `// SPDX-License-Identifier: MIT
  pragma solidity ^0.8.20;
  contract C {
    struct S { uint256 x; uint256 y; }
    function f(uint256 a, S memory b) internal pure returns (uint256) { return a + b.x * 10 + b.y; }
    function t(uint256 a, uint256 bx, uint256 by) external pure returns (uint256) { return f(a, S(bx, by)); }
  }`;
  let P: Awaited<ReturnType<typeof buildPair>>;
  beforeAll(async () => { P = await buildPair(J, Sol); });
  it('mixed positional + struct-literal arg matches solc', async () => {
    await P.eq('mixed', encodeCall(sel('t(uint256,uint256,uint256)'), [1n, 2n, 3n]));
  });
});
