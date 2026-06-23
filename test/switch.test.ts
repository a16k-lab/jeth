// F5 (part 2): `switch` desugars to a nested if/else chain over a single evaluation of the
// discriminant. JETH is stricter than TypeScript: a non-empty case must terminate (break / return /
// revert / continue), an empty case label shares the next case body, and a switch over an enum with
// no default must be exhaustive. Behavior must match the equivalent if/else under solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}

const J = `enum Color { Red, Green, Blue }
@contract class C {
  @state hits: u256;
  @external @pure rank(c: Color): u256 {
    switch (c) { case Color.Red: return 1n; case Color.Green: case Color.Blue: return 2n; }
    return 0n;   // unreachable (exhaustive), but keeps the type checker happy
  }
  @external @pure grade(x: u256): u256 {
    let r: u256 = 0n;
    switch (x) { case 1n: r = 100n; break; case 2n: case 3n: r = 200n; break; default: r = 999n; }
    return r;
  }
  @external bump(x: u256): void {
    // switch INSIDE a loop: break ends the case (not the loop); continue skips to the next turn.
    let i: u256 = 0n;
    for (i = 0n; i < x; i = i + 1n) {
      switch (i) { case 0n: this.hits = this.hits + 1n; break; case 5n: continue; default: this.hits = this.hits + 10n; }
      this.hits = this.hits + 100n;
    }
  }
  @external @pure pick(b: bool): u256 { switch (b) { case true: return 7n; case false: return 8n; } }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  enum Color { Red, Green, Blue }
  uint256 hits;
  function rank(Color c) external pure returns (uint256) {
    if (c == Color.Red) return 1; if (c == Color.Green || c == Color.Blue) return 2; return 0;
  }
  function grade(uint256 x) external pure returns (uint256) {
    uint256 r = 0;
    if (x == 1) r = 100; else if (x == 2 || x == 3) r = 200; else r = 999;
    return r;
  }
  function bump(uint256 x) external {
    for (uint256 i = 0; i < x; i = i + 1) {
      if (i == 0) { hits = hits + 1; } else if (i == 5) { continue; } else { hits = hits + 10; }
      hits = hits + 100;
    }
  }
  function pick(bool b) external pure returns (uint256) { if (b == true) return 7; if (b == false) return 8; }
}`;

describe('F5 switch', () => {
  let h: Harness, hs: Harness, jv: Address, sv: Address;
  async function eq(label: string, data: string) {
    const j = await h.call(jv, data);
    const s = await hs.call(sv, data);
    expect(j.success, `${label} jeth=${j.exceptionError}`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    h = await Harness.create();
    hs = await Harness.create();
    jv = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    sv = await hs.deploy(compileSolidity(SOL, 'C').creation);
  });
  it('enum / uint / bool switch dispatch matches the if/else equivalent under solc', async () => {
    for (const v of [0n, 1n, 2n]) await eq(`rank(${v})`, encodeCall(sel('rank(uint8)'), [v]));
    for (const v of [1n, 2n, 3n, 4n]) await eq(`grade(${v})`, encodeCall(sel('grade(uint256)'), [v]));
    await eq('pick(true)', encodeCall(sel('pick(bool)'), [1n]));
    await eq('pick(false)', encodeCall(sel('pick(bool)'), [0n]));
  });
  it('switch inside a loop: break ends the case, continue skips the turn (raw slot vs solc)', async () => {
    await h.call(jv, encodeCall(sel('bump(uint256)'), [8n]));
    await hs.call(sv, encodeCall(sel('bump(uint256)'), [8n]));
    expect(await readSlot(h, jv, 0n)).toBe(await readSlot(hs, sv, 0n)); // accumulated `hits`
  });

  it('stricter lints', () => {
    const wrap = (b: string) =>
      `enum Color { Red, Green, Blue }\n@contract class C { @external @pure f(c: Color, x: u256): u256 {\n${b}\nreturn 0n; } }`;
    // non-exhaustive enum switch with no default
    expect(codes(wrap('switch (c) { case Color.Red: return 1n; case Color.Green: return 2n; }'))).toContain('JETH286');
    // implicit fall-through from a non-empty case
    expect(
      codes(wrap('switch (x) { case 1n: { let y: u256 = x; } case 2n: return 2n; default: return 0n; }')),
    ).toContain('JETH284');
    // default not last
    expect(codes(wrap('switch (x) { default: return 0n; case 1n: return 1n; }'))).toContain('JETH282');
    // exhaustive enum switch (all members) needs no default and is accepted
    expect(
      codes(wrap('switch (c) { case Color.Red: return 1n; case Color.Green: return 2n; case Color.Blue: return 3n; }')),
    ).toEqual([]);
  });
});
