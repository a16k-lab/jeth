// Differential tests for abi.encode / abi.encodePacked (Phase 6): byte-identical to solc for
// hashing, returning, and storing the result, across value-type and bytes/string args.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

async function diff(jeth: string, sol: string, calls: { sig: string; args?: string }[], slots: bigint[] = []) {
  const jb = compile(jeth, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jb.creationBytecode);
  const as = await hs.deploy(sb.creation);
  for (const c of calls) {
    const data = '0x' + sel(c.sig) + (c.args ?? '');
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig}: returndata`).toBe(rs.returnHex);
  }
  for (const s of slots) {
    expect(await readSlot(hj, aj, s), `slot ${s}`).toBe(await readSlot(hs, as, s));
  }
}

describe('abi.encode / abi.encodePacked vs Solidity', () => {
  it('abi.encode value types (hash + return)', async () => {
    await diff(
      `@contract class C { @external @pure h(a: u256, b: u256): bytes32 { return keccak256(abi.encode(a, b)); } @external @pure r(a: u8, b: address, c: bool): bytes { return abi.encode(a, b, c); } }`,
      `contract C { function h(uint256 a, uint256 b) external pure returns (bytes32){ return keccak256(abi.encode(a,b)); } function r(uint8 a, address b, bool c) external pure returns (bytes memory){ return abi.encode(a,b,c); } }`,
      [
        { sig: 'h(uint256,uint256)', args: W(7n) + W(8n) },
        { sig: 'r(uint8,address,bool)', args: W(200n) + W(0x1234n) + W(1n) },
      ],
    );
  });

  it('abi.encode with dynamic (bytes/string) args', async () => {
    await diff(
      `@contract class C { @external @pure r(a: u256, b: bytes): bytes { return abi.encode(a, b); } @external @pure h(s: string): bytes32 { return keccak256(abi.encode(s)); } }`,
      `contract C { function r(uint256 a, bytes calldata b) external pure returns (bytes memory){ return abi.encode(a,b); } function h(string calldata s) external pure returns (bytes32){ return keccak256(abi.encode(s)); } }`,
      [
        { sig: 'r(uint256,bytes)', args: W(0x40n) + W(99n) + W(3n) + 'aabbcc'.padEnd(64, '0') },
        { sig: 'h(string)', args: W(0x20n) + W(5n) + Buffer.from('hello').toString('hex').padEnd(64, '0') },
      ],
    );
  });

  it('abi.encodePacked (mixed widths, dynamic, negative, empty)', async () => {
    await diff(
      `@contract class C {
        @external @pure h(a: u8, b: u16, c: u256): bytes32 { return keccak256(abi.encodePacked(a, b, c)); }
        @external @pure r(a: address, b: bool, c: bytes4): bytes { return abi.encodePacked(a, b, c); }
        @external @pure sd(s: string, x: u8): bytes { return abi.encodePacked(s, x); }
        @external @pure ng(a: i8, b: i16): bytes { return abi.encodePacked(a, b); }
        @external @pure em(): bytes { return abi.encodePacked(); }
      }`,
      `contract C {
        function h(uint8 a, uint16 b, uint256 c) external pure returns (bytes32){ return keccak256(abi.encodePacked(a,b,c)); }
        function r(address a, bool b, bytes4 c) external pure returns (bytes memory){ return abi.encodePacked(a,b,c); }
        function sd(string calldata s, uint8 x) external pure returns (bytes memory){ return abi.encodePacked(s,x); }
        function ng(int8 a, int16 b) external pure returns (bytes memory){ return abi.encodePacked(a,b); }
        function em() external pure returns (bytes memory){ return abi.encodePacked(); }
      }`,
      [
        { sig: 'h(uint8,uint16,uint256)', args: W(0x12n) + W(0x3456n) + W(0xdeadn) },
        { sig: 'r(address,bool,bytes4)', args: W(0xabcdn) + W(1n) + '12345678'.padEnd(64, '0') },
        { sig: 'sd(string,uint8)', args: W(0x40n) + W(0xffn) + W(5n) + '68656c6c6f'.padEnd(64, '0') },
        { sig: 'ng(int8,int16)', args: W((1n << 256n) - 5n) + W((1n << 256n) - 300n) },
        { sig: 'em()' },
      ],
    );
  });

  it('abi.encode of a static struct / fixed-array / dynamic value array', async () => {
    await diff(
      `@struct class P { a: u256; b: u8; } @contract class C {
        @external @pure st(a: u256, b: u8): bytes { return abi.encode(P(a, b)); }
        @external @pure mix(n: u256, a: u256, b: u8): bytes { return abi.encode(n, P(a, b)); }
        @external @pure fa(a: u256, b: u256, c: u256): bytes { let x: Arr<u256,3> = [a, b, c]; return abi.encode(x); }
        @external @pure dyn(xs: u256[]): bytes { return abi.encode(xs); }
        @external @pure both(a: u256, b: u8, xs: u256[]): bytes { return abi.encode(P(a, b), xs); }
        @external @pure h(a: u256, b: u8): bytes32 { return keccak256(abi.encode(P(a, b))); }
      }`,
      `struct P { uint256 a; uint8 b; } contract C {
        function st(uint256 a, uint8 b) external pure returns (bytes memory){ return abi.encode(P(a,b)); }
        function mix(uint256 n, uint256 a, uint8 b) external pure returns (bytes memory){ return abi.encode(n, P(a,b)); }
        function fa(uint256 a, uint256 b, uint256 c) external pure returns (bytes memory){ uint256[3] memory x = [a,b,c]; return abi.encode(x); }
        function dyn(uint256[] calldata xs) external pure returns (bytes memory){ return abi.encode(xs); }
        function both(uint256 a, uint8 b, uint256[] calldata xs) external pure returns (bytes memory){ return abi.encode(P(a,b), xs); }
        function h(uint256 a, uint8 b) external pure returns (bytes32){ return keccak256(abi.encode(P(a,b))); }
      }`,
      [
        { sig: 'st(uint256,uint8)', args: W(7n) + W(200n) },
        { sig: 'mix(uint256,uint256,uint8)', args: W(99n) + W(1n) + W(2n) },
        { sig: 'fa(uint256,uint256,uint256)', args: W(1n) + W(2n) + W(3n) },
        { sig: 'dyn(uint256[])', args: W(0x20n) + W(3n) + W(10n) + W(20n) + W(30n) },
        { sig: 'both(uint256,uint8,uint256[])', args: W(1n) + W(2n) + W(0x60n) + W(2n) + W(5n) + W(6n) },
        { sig: 'h(uint256,uint8)', args: W(42n) + W(9n) },
      ],
    );
  });

  it('abi.encodePacked of value arrays (elements padded to 32, no length)', async () => {
    await diff(
      `@contract class C {
        @external @pure d(x: u256[]): bytes { return abi.encodePacked(x); }
        @external @pure n8(x: u8[]): bytes { return abi.encodePacked(x); }
        @external @pure pre(n: u8, x: u256[]): bytes { return abi.encodePacked(n, x); }
        @external @pure fx(a: u256, b: u256, c: u256): bytes { let x: Arr<u256,3> = [a, b, c]; return abi.encodePacked(x); }
      }`,
      `contract C {
        function d(uint256[] calldata x) external pure returns (bytes memory){ return abi.encodePacked(x); }
        function n8(uint8[] calldata x) external pure returns (bytes memory){ return abi.encodePacked(x); }
        function pre(uint8 n, uint256[] calldata x) external pure returns (bytes memory){ return abi.encodePacked(n, x); }
        function fx(uint256 a, uint256 b, uint256 c) external pure returns (bytes memory){ uint256[3] memory x = [a,b,c]; return abi.encodePacked(x); }
      }`,
      [
        { sig: 'd(uint256[])', args: W(0x20n) + W(3n) + W(10n) + W(20n) + W(30n) },
        { sig: 'n8(uint8[])', args: W(0x20n) + W(2n) + W(1n) + W(2n) },
        { sig: 'pre(uint8,uint256[])', args: W(0xffn) + W(0x40n) + W(2n) + W(7n) + W(8n) },
        { sig: 'fx(uint256,uint256,uint256)', args: W(1n) + W(2n) + W(3n) },
        { sig: 'd(uint256[])', args: W(0x20n) + W(0n) },
      ],
    );
  });

  it('abi.encode of a dynamic struct and nested dynamic arrays', async () => {
    await diff(
      `@struct class D { a: u256; s: string; } @contract class C {
        @external @pure st(a: u256, s: string): bytes { return abi.encode(D(a, s)); }
        @external @pure mix(n: u256, a: u256, s: string): bytes { return abi.encode(n, D(a, s)); }
        @external @pure sa(x: string[]): bytes { return abi.encode(x); }
        @external @pure nn(m: u256[][]): bytes { return abi.encode(m); }
      }`,
      `struct D { uint256 a; string s; } contract C {
        function st(uint256 a, string calldata s) external pure returns (bytes memory){ return abi.encode(D(a,s)); }
        function mix(uint256 n, uint256 a, string calldata s) external pure returns (bytes memory){ return abi.encode(n, D(a,s)); }
        function sa(string[] calldata x) external pure returns (bytes memory){ return abi.encode(x); }
        function nn(uint256[][] calldata m) external pure returns (bytes memory){ return abi.encode(m); }
      }`,
      [
        { sig: 'st(uint256,string)', args: W(42n) + W(0x40n) + W(5n) + '68656c6c6f'.padEnd(64, '0') },
        { sig: 'mix(uint256,uint256,string)', args: W(7n) + W(8n) + W(0x60n) + W(3n) + '616263'.padEnd(64, '0') },
        { sig: 'sa(string[])', args: W(0x20n) + W(2n) + W(0x40n) + W(0x80n) + W(2n) + '6161'.padEnd(64, '0') + W(3n) + '626263'.padEnd(64, '0') },
        { sig: 'nn(uint256[][])', args: W(0x20n) + W(2n) + W(0x40n) + W(0xa0n) + W(2n) + W(1n) + W(2n) + W(1n) + W(9n) },
      ],
    );
  });

  it('abi.encodeWithSelector / abi.encodeWithSignature', async () => {
    await diff(
      `@contract class C {
        @external @pure ws(s: bytes4, a: u256, b: address): bytes { return abi.encodeWithSelector(s, a, b); }
        @external @pure wsd(s: bytes4, a: u256, d: bytes): bytes { return abi.encodeWithSelector(s, a, d); }
        @external @pure sig(a: u256, b: address): bytes { return abi.encodeWithSignature("transfer(address,uint256)", b, a); }
        @external @pure sigh(x: u256): bytes32 { return keccak256(abi.encodeWithSignature("foo(uint256)", x)); }
        @external @pure rt(s: string, x: u256): bytes { return abi.encodeWithSignature(s, x); }
      }`,
      `contract C {
        function ws(bytes4 s, uint256 a, address b) external pure returns (bytes memory){ return abi.encodeWithSelector(s, a, b); }
        function wsd(bytes4 s, uint256 a, bytes calldata d) external pure returns (bytes memory){ return abi.encodeWithSelector(s, a, d); }
        function sig(uint256 a, address b) external pure returns (bytes memory){ return abi.encodeWithSignature("transfer(address,uint256)", b, a); }
        function sigh(uint256 x) external pure returns (bytes32){ return keccak256(abi.encodeWithSignature("foo(uint256)", x)); }
        function rt(string calldata s, uint256 x) external pure returns (bytes memory){ return abi.encodeWithSignature(s, x); }
      }`,
      [
        { sig: 'ws(bytes4,uint256,address)', args: '12345678'.padEnd(64, '0') + W(42n) + W(0xbeefn) },
        { sig: 'wsd(bytes4,uint256,bytes)', args: '11223344'.padEnd(64, '0') + W(7n) + W(0x60n) + W(3n) + 'aabbcc'.padEnd(64, '0') },
        { sig: 'sig(uint256,address)', args: W(100n) + W(0x1234n) },
        { sig: 'sigh(uint256)', args: W(5n) },
        { sig: 'rt(string,uint256)', args: W(0x40n) + W(9n) + W(11n) + '666f6f28290000000000000000000000000000000000000000000000000000'.padEnd(64, '0') },
      ],
    );
  });

  it('nested abi.encode(abi.encodePacked(...)) + store result to storage bytes', async () => {
    await diff(
      `@contract class C { @state b: bytes; @external @pure n(a: u256, c: address): bytes32 { return keccak256(abi.encode(abi.encodePacked(a, c))); } @external set(a: u256, c: u8): void { this.b = abi.encodePacked(a, c); } @external @view get(): bytes { return this.b; } }`,
      `contract C { bytes b; function n(uint256 a, address c) external pure returns (bytes32){ return keccak256(abi.encode(abi.encodePacked(a,c))); } function set(uint256 a, uint8 c) external { b = abi.encodePacked(a,c); } function get() external view returns (bytes memory){ return b; } }`,
      [
        { sig: 'n(uint256,address)', args: W(42n) + W(0x1234n) },
        { sig: 'set(uint256,uint8)', args: W(0xdeadbeefn) + W(0x42n) },
        { sig: 'get()' },
      ],
      [0n],
    );
  });
});
