import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SOL_PREFIX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

function jethRejects(src: string): string[] | null {
  try {
    compile(src, { fileName: 'C.jeth' });
    return null; // accepted
  } catch (e: any) {
    if (e instanceof CompileError)
      return e.diagnostics.filter((d) => d.severity === 'error').map((d) => d.code);
    throw e;
  }
}

function solRejects(src: string): boolean {
  try {
    compileSolidity(SOL_PREFIX + src, 'C');
    return false; // accepted
  } catch {
    return true;
  }
}

describe('push-empty-literal over-acceptance', () => {
  // ---- The 3 REJECT cases (solc rejects, JETH must now reject too) ----
  it('rejects this.a.push([]) on u256[][]', () => {
    const jeth = `
class C {
  a: u256[][];
  f(): External<void> { this.a.push([]); }
}`;
    const sol = `
contract C {
  uint256[][] a;
  function f() external { a.push([]); }
}`;
    const codes = jethRejects(jeth);
    expect(codes, 'JETH must reject').not.toBeNull();
    expect(codes).toContain('JETH074');
    expect(solRejects(sol), 'solc must reject').toBe(true);
  });

  it('rejects this.a.push([]) on string[][]', () => {
    const jeth = `
class C {
  a: string[][];
  f(): External<void> { this.a.push([]); }
}`;
    const sol = `
contract C {
  string[][] a;
  function f() external { a.push([]); }
}`;
    expect(jethRejects(jeth)).toContain('JETH074');
    expect(solRejects(sol)).toBe(true);
  });

  it('rejects this.a.push([[]]) on u256[][][]', () => {
    const jeth = `
class C {
  a: u256[][][];
  f(): External<void> { this.a.push([[]]); }
}`;
    const sol = `
contract C {
  uint256[][][] a;
  function f() external { a.push([[]]); }
}`;
    expect(jethRejects(jeth)).toContain('JETH074');
    expect(solRejects(sol)).toBe(true);
  });

  // ---- The 5 ACCEPT cases (both accept; JETH must still compile) ----
  it('accepts this.a.push([5n]) on u256[][]', () => {
    const jeth = `
class C {
  a: u256[][];
  f(): External<void> { this.a.push([5n]); }
}`;
    expect(jethRejects(jeth), 'JETH must accept').toBeNull();
  });

  it('accepts this.a.push([[5n]]) on u256[][][]', () => {
    const jeth = `
class C {
  a: u256[][][];
  f(): External<void> { this.a.push([[5n]]); }
}`;
    expect(jethRejects(jeth)).toBeNull();
  });

  it('accepts this.a.push(["x"]) on string[][]', () => {
    const jeth = `
class C {
  a: string[][];
  f(): External<void> { this.a.push(["x"]); }
}`;
    expect(jethRejects(jeth)).toBeNull();
  });

  it('accepts empty literal in declaration/assignment (let x: u256[][] = [[]] and let x: u256[] = [])', () => {
    const jeth = `
class C {
  f(): External<void> {
    let x: u256[][] = [[]];
    let y: u256[] = [];
    x;
    y;
  }
}`;
    expect(jethRejects(jeth)).toBeNull();
  });

  it('accepts no-arg this.a.push() on u256[][]', () => {
    const jeth = `
class C {
  a: u256[][];
  f(): External<void> { this.a.push(); }
}`;
    expect(jethRejects(jeth)).toBeNull();
  });

  // ---- Guard: a non-empty deep literal with one deducible branch stays accepted,
  //      a partially-empty deep literal stays rejected (matches solc per-element deduce) ----
  it('rejects this.a.push([[], [5n]]) on u256[][] (one empty sub-literal)', () => {
    const jeth = `
class C {
  a: u256[][][];
  f(): External<void> { this.a.push([[], [5n]]); }
}`;
    const sol = `
contract C {
  uint256[][][] a;
  function f() external { a.push([[], [uint256(5)]]); }
}`;
    // JETH: outer [[], [5n]] -> outer non-empty, but element [] is empty -> reject.
    expect(jethRejects(jeth)).toContain('JETH074');
    // (solc rejects the literal form for the same reason: cannot deduce the [] element)
    expect(solRejects(sol)).toBe(true);
  });
});
