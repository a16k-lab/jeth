// Phase 6: string/bytes concatenation + TS template literals.
//  - `string.concat(a, b, ...)` / `bytes.concat(a, b, ...)` (solc 0.8.12+ builtins) and the method forms
//    `a.concat(b, ...)`. A tightly-packed concatenation: string.concat takes string args -> string,
//    bytes.concat takes bytes/bytesN args -> bytes. Byte-identical to solc (== abi.encodePacked, which
//    string.concat/bytes.concat are defined as, reinterpreted with the result location type).
//  - Template literals `Hello ${name}` desugar to string.concat of the cooked literal parts + the
//    interpolated string expressions, byte-identical to solc string.concat("Hello ", name). Interpolations
//    must be string-typed (Solidity has no implicit conversion to string).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);
const PAD = (h: string) => h + '00'.repeat((32 - (h.length / 2) % 32) % 32);

async function deployJeth(src: string) {
  const h = await Harness.create();
  return { h, a: await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode) };
}
async function deploySol(src: string) {
  const h = await Harness.create();
  return { h, a: await h.deploy(compileSolidity(SPDX + src, 'C').creation) };
}
function jethAccepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
function solAccepts(src: string): boolean {
  try {
    compileSolidity(SPDX + src, 'C');
    return true;
  } catch {
    return false;
  }
}

const J = `@contract class C {
  @state stored: string;
  @external @pure tl(name: string): string { return \`Hello \${name}\`; }
  @external @pure tl2(a: string, b: string): string { return \`<\${a}|\${b}>\`; }
  @external @pure tllit(): string { const name: string = "World"; return \`Hello \${name}!\`; }
  @external @pure single(name: string): string { return \`\${name}\`; }
  @external @view scm(a: string, b: string): string { return a.concat(b); }
  @external @view scm3(a: string, b: string, c: string): string { return a.concat(b, c); }
  @external @view bcm(a: bytes, b: bytes): bytes { return a.concat(b); }
  @external @view bcmN(a: bytes, x: bytes4): bytes { return a.concat(x); }
  @external @view ss(a: string, b: string): string { return string.concat(a, b); }
  @external @view bs(a: bytes, b: bytes): bytes { return bytes.concat(a, b); }
  @external @pure s0(): string { return string.concat(); }
  @external @pure memloc(): string { const m: string = "ab"; return m.concat("cd"); }
  @external @view kc(a: string, b: string): bytes32 { return keccak256(bytes(string.concat(a, b))); }
  @external stor(): string { this.stored = "set"; return this.stored.concat("!"); }
}`;
const S = `contract C {
  string stored;
  function tl(string calldata name) external pure returns(string memory){ return string.concat("Hello ", name); }
  function tl2(string calldata a, string calldata b) external pure returns(string memory){ return string.concat("<", a, "|", b, ">"); }
  function tllit() external pure returns(string memory){ string memory name="World"; return string.concat("Hello ", name, "!"); }
  function single(string calldata name) external pure returns(string memory){ return string.concat(name); }
  function scm(string calldata a, string calldata b) external pure returns(string memory){ return string.concat(a, b); }
  function scm3(string calldata a, string calldata b, string calldata c) external pure returns(string memory){ return string.concat(a, b, c); }
  function bcm(bytes calldata a, bytes calldata b) external pure returns(bytes memory){ return bytes.concat(a, b); }
  function bcmN(bytes calldata a, bytes4 x) external pure returns(bytes memory){ return bytes.concat(a, x); }
  function ss(string calldata a, string calldata b) external pure returns(string memory){ return string.concat(a, b); }
  function bs(bytes calldata a, bytes calldata b) external pure returns(bytes memory){ return bytes.concat(a, b); }
  function s0() external pure returns(string memory){ return string.concat(); }
  function memloc() external pure returns(string memory){ string memory m="ab"; return string.concat(m, "cd"); }
  function kc(string calldata a, string calldata b) external pure returns(bytes32){ return keccak256(bytes(string.concat(a, b))); }
  function stor() external returns(string memory){ stored="set"; return string.concat(stored, "!"); }
}`;

async function diff(calldata: string) {
  const j = await deployJeth(J);
  const s = await deploySol(S);
  const rj = await j.h.call(j.a, '0x' + calldata);
  const rs = await s.h.call(s.a, '0x' + calldata);
  expect(rj.success).toBe(rs.success);
  expect(rj.returnHex).toBe(rs.returnHex);
  return rj;
}
const sWorld = W(0x20n) + W(5n) + PAD('576f726c64'); // "World"
const twoStr = (x: string, y: string) =>
  W(0x40n) + W(0x80n) + W(BigInt(x.length / 2)) + PAD(x) + W(BigInt(y.length / 2)) + PAD(y);

describe('template literals', () => {
  it('`Hello ${name}`', () => diff(sel('tl(string)') + sWorld));
  it('`<${a}|${b}>` (multiple interpolations + literal parts)', () =>
    diff(sel('tl2(string,string)') + twoStr('6161', '6262')));
  it('template with a string-literal local', () => diff(sel('tllit()')));
  it('single interpolation `${name}`', () => diff(sel('single(string)') + W(0x20n) + W(3n) + PAD('616263')));
});

describe('concat method + static forms', () => {
  it('a.concat(b) (string)', () => diff(sel('scm(string,string)') + twoStr('6161', '626262')));
  it('a.concat(b, c) (3 args)', () =>
    diff(sel('scm3(string,string,string)') + W(0x60n) + W(0xa0n) + W(0xe0n) + W(1n) + PAD('61') + W(1n) + PAD('62') + W(1n) + PAD('63')));
  it('a.concat(b) (bytes)', () => diff(sel('bcm(bytes,bytes)') + twoStr('aabb', 'ccdd')));
  it('bytes.concat(a, bytes4)', () =>
    diff(sel('bcmN(bytes,bytes4)') + W(0x40n) + 'deadbeef' + '00'.repeat(28) + W(2n) + PAD('aabb')));
  it('string.concat(a, b) static', () => diff(sel('ss(string,string)') + twoStr('6161', '6262')));
  it('bytes.concat(a, b) static', () => diff(sel('bs(bytes,bytes)') + twoStr('aabb', 'ccdd')));
  it('string.concat() empty', () => diff(sel('s0()')));
});

describe('concat sources + composition', () => {
  it('memory-local concat', () => diff(sel('memloc()')));
  it('keccak256(bytes(string.concat(a, b)))', () => diff(sel('kc(string,string)') + twoStr('6161', '6262')));
  it('storage string concat', () => diff(sel('stor()')));
});

// A computed string (template or concat) is a valid revert/require reason -> dynamic Error(string),
// byte-identical to solc revert(string.concat(...)) / require(c, string.concat(...)).
describe('dynamic revert / require messages', () => {
  const RJ = `@contract class C {
    @external @pure rt(a: string): u256 { revert(\`bad: \${a}\`); }
    @external @pure rc(a: string): u256 { revert("bad: ".concat(a)); }
    @external @pure rq(c: bool, a: string): u256 { require(c, \`need \${a}\`); return 1n; }
  }`;
  const RS = `contract C {
    function rt(string calldata a) external pure returns(uint){ revert(string.concat("bad: ", a)); }
    function rc(string calldata a) external pure returns(uint){ revert(string.concat("bad: ", a)); }
    function rq(bool c, string calldata a) external pure returns(uint){ require(c, string.concat("need ", a)); return 1; }
  }`;
  async function rdiff(src: string, calldata: string) {
    const j = await deployJeth(RJ);
    const s = await deploySol(RS);
    void src;
    const rj = await j.h.call(j.a, '0x' + calldata);
    const rs = await s.h.call(s.a, '0x' + calldata);
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
    return rj;
  }
  const sArg = W(0x20n) + W(3n) + PAD('616263'); // "abc"
  it('revert(`bad: ${a}`) (template)', async () => {
    expect((await rdiff('rt', sel('rt(string)') + sArg)).success).toBe(false);
  });
  it('revert("bad: ".concat(a)) (literal-receiver concat)', async () => {
    expect((await rdiff('rc', sel('rc(string)') + sArg)).success).toBe(false);
  });
  it('require(false, `need ${a}`) reverts with the message', async () => {
    expect((await rdiff('rq', sel('rq(bool,string)') + W(0n) + W(0x40n) + W(3n) + PAD('616263'))).success).toBe(false);
  });
  it('require(true, `need ${a}`) passes', async () => {
    expect((await rdiff('rq', sel('rq(bool,string)') + W(1n) + W(0x40n) + W(3n) + PAD('616263'))).success).toBe(true);
  });
});

// Many-part concat / template (the packed-encode lowering spills part descriptors to memory, so it does
// not overflow the 16-slot stack the way a long abi.encodePacked once did). A bytesN concat arg, and a
// single-bytesN concat (which must repack to a bytes value), are also covered.
describe('many-part concat + bytesN (no StackTooDeep)', () => {
  it('template with 3 interpolations + literal parts', async () => {
    const J = `@contract class C { @external @pure f(a: string, b: string, c: string): string { return \`transfer \${a} -> \${b}: \${c}\`; } }`;
    const S = `contract C { function f(string calldata a, string calldata b, string calldata c) external pure returns(string memory){ return string.concat("transfer ", a, " -> ", b, ": ", c); } }`;
    const j = await deployJeth(J);
    const s = await deploySol(S);
    const cd = sel('f(string,string,string)') + W(0x60n) + W(0xa0n) + W(0xe0n) + W(3n) + PAD('414141') + W(3n) + PAD('424242') + W(3n) + PAD('313030');
    const rj = await j.h.call(j.a, '0x' + cd);
    const rs = await s.h.call(s.a, '0x' + cd);
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
  });
  it('string.concat of 15 string literals', async () => {
    const lits = Array.from({ length: 15 }, (_, i) => `"${String.fromCharCode(97 + i)}"`).join(', ');
    const j = await deployJeth(`@contract class C { @external @pure f(): string { return string.concat(${lits}); } }`);
    const s = await deploySol(`contract C { function f() external pure returns(string memory){ return string.concat(${lits}); } }`);
    const rj = await j.h.call(j.a, '0x' + sel('f()'));
    const rs = await s.h.call(s.a, '0x' + sel('f()'));
    expect(rj.returnHex).toBe(rs.returnHex);
  });
  it('template with 10 interpolations (solc default StackTooDeeps; JETH compiles it) -> known answer', async () => {
    // 20 parts. solc's default (non-via-IR) codegen throws StackTooDeep on the equivalent string.concat,
    // so there is no solc contract to diff against; JETH's descriptor-spill lowering compiles it. Verify
    // against the deterministic concatenation result instead.
    const body = Array.from({ length: 10 }, () => 'x${a}').join('');
    const j = await deployJeth(`@contract class C { @external @pure f(a: string): string { return \`${body}\`; } }`);
    const cd = sel('f(string)') + W(0x20n) + W(2n) + PAD('4141'); // a = "AA"
    const rj = await j.h.call(j.a, '0x' + cd);
    expect(rj.success).toBe(true);
    const o = rj.returnHex.slice(2);
    const expected = Buffer.from('xAA'.repeat(10)).toString('hex'); // ("x" + "AA") * 10
    expect(parseInt(o.slice(64, 128), 16)).toBe(30); // length
    expect(o.slice(128, 128 + expected.length)).toBe(expected);
  });
  it('bytes.concat of a single bytesN repacks to bytes', async () => {
    const J = `@contract class C { @external @pure f(): bytes { const b: bytes16 = bytes16(0xdeadbeefdeadbeefdeadbeefdeadbeefn); return bytes.concat(b); } }`;
    const S = `contract C { function f() external pure returns(bytes memory){ bytes16 b=bytes16(0xdeadbeefdeadbeefdeadbeefdeadbeef); return bytes.concat(b); } }`;
    const j = await deployJeth(J);
    const s = await deploySol(S);
    const rj = await j.h.call(j.a, '0x' + sel('f()'));
    const rs = await s.h.call(s.a, '0x' + sel('f()'));
    expect(rj.returnHex).toBe(rs.returnHex);
  });
});

describe('concat accept/reject parity with solc', () => {
  const cases: { label: string; j: string; s: string }[] = [
    {
      label: 'string.concat rejects a uint arg',
      j: `@contract class C { @external @view f(a: string, n: u256): string { return a.concat(n); } }`,
      s: `contract C { function f(string calldata a, uint n) external pure returns(string memory){ return string.concat(a, n); } }`,
    },
    {
      label: 'string.concat rejects a bytes arg',
      j: `@contract class C { @external @view f(a: string, b: bytes): string { return a.concat(b); } }`,
      s: `contract C { function f(string calldata a, bytes calldata b) external pure returns(string memory){ return string.concat(a, b); } }`,
    },
    {
      label: 'bytes.concat rejects a string arg',
      j: `@contract class C { @external @view f(a: bytes, b: string): bytes { return a.concat(b); } }`,
      s: `contract C { function f(bytes calldata a, string calldata b) external pure returns(bytes memory){ return bytes.concat(a, b); } }`,
    },
    {
      label: 'bytes.concat rejects a uint arg',
      j: `@contract class C { @external @view f(a: bytes, n: u256): bytes { return a.concat(n); } }`,
      s: `contract C { function f(bytes calldata a, uint n) external pure returns(bytes memory){ return bytes.concat(a, n); } }`,
    },
    {
      label: 'template rejects a non-string interpolation',
      j: '@contract class C { @external @view f(n: u256): string { return `count ${n}`; } }',
      s: `contract C { function f(uint n) external pure returns(string memory){ return string.concat("count ", n); } }`,
    },
  ];
  for (const c of cases) {
    it(c.label, () => {
      expect(jethAccepts(c.j)).toBe(solAccepts(c.s));
      expect(jethAccepts(c.j)).toBe(false);
    });
  }
  it('tagged template literals stay rejected', () => {
    expect(jethAccepts('@contract class C { @external @pure f(): string { return tag`x`; } }')).toBe(false);
  });
  it('a template static part with invalid UTF-8 is rejected like a plain string (both reject)', () => {
    // a template literal builds a `string` (string.concat), so a static part producing a lone high byte
    // (\xff) is invalid UTF-8 and must reject (JETH447), exactly as the plain-string form does and as
    // solc's string.concat rejects. A VALID non-ASCII part (byte-identical to solc unicode"...") accepts.
    const jbad = '@contract class C { @external @pure f(x: string): string { return `a\\xffb${x}`; } }';
    const sbad = 'contract C { function f(string calldata x) external pure returns(string memory){ return string.concat("a\\xffb", x); } }';
    expect(jethAccepts(jbad)).toBe(false);
    expect(solAccepts(sbad)).toBe(false);
    // control: a valid non-ASCII template part (maps to solc unicode"...") is accepted by JETH.
    expect(jethAccepts('@contract class C { @external @pure f(x: string): string { return `世界${x}`; } }')).toBe(true);
  });
});
