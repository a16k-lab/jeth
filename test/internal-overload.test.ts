// #47: FUNCTION OVERLOADING for internal/private calls. solc allows two @internal/functions
// to share a name when they differ by arity or parameter types; JETH used to misresolve (funcsByName
// was first-wins -> JETH148/JETH901). Now each function has a unique call-graph key (the bare name when
// unique, else `name__ovN`), and a call resolves the right overload by arity then by which candidate's
// parameter types all the arguments fit. Byte-identical to solc 0.8.35; ambiguous / no-match reject.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
function codes(src: string): string[] {
  try { compile(src, { fileName: 'C.jeth' }); return []; }
  catch (e) { if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e; }
}

describe('internal/private function overloading (#47) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  // overload by arity (g/1, g/2), by type (g(bool)), default args on one overload, recursion, a private
  // overload, and a transitive @view (one overload reads state) to exercise the purity fixpoint by key.
  const J = `@contract class C {
    @state n: u256;
    g(a: u256): u256 { return a * 10n; }
    g(a: u256, b: u256): u256 { return a + b; }
    g(a: bool): u256 { if (a) { return 111n; } return 222n; }
    sumv(a: u256, b: u256, c: u256): u256 { return a + b + c; }
    sumv(a: u256, b: u256): u256 { return a + b; }
    countdown(x: u256): u256 { if (x == 0n) { return 0n; } return x + this.countdown(x, 1n); }
    countdown(x: u256, step: u256): u256 { if (x < step) { return 0n; } return this.countdown(x - step); }
    readN(): u256 { return this.n; }
    readN(extra: u256): u256 { return this.n + extra; }
    @external setN(v: u256): void { this.n = v; }
    @external @pure one(x: u256): u256 { return this.g(x); }
    @external @pure two(x: u256, y: u256): u256 { return this.g(x, y); }
    @external @pure boolov(b: bool): u256 { return this.g(b); }
    @external @pure all3(x: u256): u256 { return this.g(x) + this.g(x, x) + this.g(x > 5n); }
    @external @pure sums(x: u256): u256 { return this.sumv(x, x) + this.sumv(x, x, x); }
    @external @pure cd(x: u256): u256 { return this.countdown(x); }
    @external @view rd(e: u256): u256 { return this.readN() + this.readN(e); } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  uint256 n;
  function g(uint256 a) internal pure returns (uint256) { return a * 10; }
  function g(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; }
  function g(bool a) internal pure returns (uint256) { if (a) { return 111; } return 222; }
  function sumv(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) { return a + b + c; }
  function sumv(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; }
  function countdown(uint256 x) internal pure returns (uint256) { if (x == 0) { return 0; } return x + countdown(x, 1); }
  function countdown(uint256 x, uint256 step) internal pure returns (uint256) { if (x < step) { return 0; } return countdown(x - step); }
  function readN() private view returns (uint256) { return n; }
  function readN(uint256 extra) private view returns (uint256) { return n + extra; }
  function setN(uint256 v) external { n = v; }
  function one(uint256 x) external pure returns (uint256) { return g(x); }
  function two(uint256 x, uint256 y) external pure returns (uint256) { return g(x, y); }
  function boolov(bool b) external pure returns (uint256) { return g(b); }
  function all3(uint256 x) external pure returns (uint256) { return g(x) + g(x, x) + g(x > 5); }
  function sums(uint256 x) external pure returns (uint256) { return sumv(x, x) + sumv(x, x, x); }
  function cd(uint256 x) external pure returns (uint256) { return countdown(x); }
  function rd(uint256 e) external view returns (uint256) { return readN() + readN(e); } }`;

  beforeAll(async () => {
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });
  const cmp = async (data: string, label: string) => {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
  };

  it('resolves each overload (arity + type) to the right function, byte-identical', async () => {
    for (const x of [3n, 7n, 12n]) {
      await cmp('0x' + sel('one(uint256)') + pad32(x), `one(${x})`);
      await cmp('0x' + sel('two(uint256,uint256)') + pad32(x) + pad32(9n), `two(${x},9)`);
      await cmp('0x' + sel('all3(uint256)') + pad32(x), `all3(${x})`);
      await cmp('0x' + sel('sums(uint256)') + pad32(x), `sums(${x})`);
    }
    for (const b of [1n, 0n]) await cmp('0x' + sel('boolov(bool)') + pad32(b), `boolov(${b})`);
  });
  it('mutual recursion across overloads (countdown/1 <-> countdown/2)', async () => {
    for (const x of [0n, 1n, 4n, 10n]) await cmp('0x' + sel('cd(uint256)') + pad32(x), `cd(${x})`);
  });
  it('a @view-inducing overload (readN reads state) keeps the purity fixpoint correct per key', async () => {
    await jeth.call(aj, '0x' + sel('setN(uint256)') + pad32(50n)); await sol.call(as, '0x' + sel('setN(uint256)') + pad32(50n));
    await cmp('0x' + sel('rd(uint256)') + pad32(7n), 'rd');
  });
  it('rejects an ambiguous / no-matching-overload call (like solc)', () => {
    // a duplicate signature cannot overload (solc errors too)
    expect(codes('@contract class C { g(a: u256): u256 { return a; } g(a: u256): u256 { return 2n; } @external @pure f(): u256 { return this.g(1n); } }')).toContain('JETH901');
    // no overload accepts 3 arguments
    expect(codes('@contract class C { g(a: u256): u256 { return a; } g(a: u256, b: u256): u256 { return a + b; } @external @pure f(): u256 { return this.g(1n, 2n, 3n); } }')).toContain('JETH148');
    // a single (non-overloaded) function is unaffected
    expect(codes('@contract class C { g(a: u256): u256 { return a; } @external @pure f(): u256 { return this.g(5n); } }')).toEqual([]);
  });
});
