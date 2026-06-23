// Adversarial audit of BRANDED NEWTYPES (`type X = Brand<Base>`): a distinct NOMINAL
// value type over a value Base, fully ERASED at codegen/ABI/selectors. The invariant we
// hammer on: a branded contract must be byte-identical to (a) the structurally-identical
// PLAIN-base JETH contract (creation bytecode + ABI: the strongest erasure proof) and
// (b) the equivalent Solidity contract at runtime (returndata + raw storage slots + logs).
// We also pin the soundness rules (which casts/mixes the checker accepts vs rejects).
//
// This suite is written ADVERSARIALLY: every claim is checked against the real compiler
// and a real EVM, not against the spec text. It originally surfaced one soundness hole
// (branded `address` bypassing the nominal barrier); that is now fixed and the relevant
// block is a passing regression guard.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, pad32 } from '../src/evm.js';
import { functionSelector, eventTopic0 } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => pad32(v);

/** Compile and return the error codes (or [] if it compiled clean). */
function errCodes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    if (e && Array.isArray(e.diagnostics)) {
      return e.diagnostics.filter((d: any) => d.severity === 'error').map((d: any) => d.code);
    }
    throw e;
  }
}
const compiles = (src: string) => errCodes(src).length === 0;

/** Assert a branded contract erases to a byte-identical plain-base contract. */
function assertErased(branded: string, plain: string, label: string) {
  const b = compile(branded, { fileName: 'C.jeth' });
  const p = compile(plain, { fileName: 'C.jeth' });
  expect(b.creationBytecode, `${label}: creation bytecode erased`).toBe(p.creationBytecode);
  expect(JSON.stringify(b.abi), `${label}: ABI erased`).toBe(JSON.stringify(p.abi));
}

// =====================================================================================
// 1. Branded over EACH base kind: erasure (bytecode + ABI) vs the plain-base contract.
// =====================================================================================
describe('1. brand over each base kind erases to the plain base (bytecode + ABI)', () => {
  const cases: [string, string, string][] = [
    [
      'Brand<address>',
      `type X=Brand<address>;@contract class C{@state s:X;@external set(a:X):void{this.s=a;}@view get():address{return address(this.s);}@external @pure id(a:X):X{return a;}}`,
      `@contract class C{@state s:address;@external set(a:address):void{this.s=a;}@view get():address{return this.s;}@external @pure id(a:address):address{return a;}}`,
    ],
    [
      'Brand<bytes32>',
      `type X=Brand<bytes32>;@contract class C{@state s:X;@external set(a:X):void{this.s=a;}@view get():bytes32{return bytes32(this.s);}@external @pure id(a:X):X{return a;}}`,
      `@contract class C{@state s:bytes32;@external set(a:bytes32):void{this.s=a;}@view get():bytes32{return this.s;}@external @pure id(a:bytes32):bytes32{return a;}}`,
    ],
    [
      // NOTE: JETH has no `bool(x)` cast at all (even `bool(bool)` -> JETH170), so a
      // `Brand<bool>` cannot be unwrapped to a bare `bool` via a cast. That is a pre-existing
      // language gap, not a brand bug; here we exercise the brand where it IS usable (state +
      // pass-through), which is what erases. Returning the brand directly returns `bool` in the ABI.
      'Brand<bool>',
      `type X=Brand<bool>;@contract class C{@state s:X;@external set(a:X):void{this.s=a;}@view get():X{return this.s;}@external @pure id(a:X):X{return a;}}`,
      `@contract class C{@state s:bool;@external set(a:bool):void{this.s=a;}@view get():bool{return this.s;}@external @pure id(a:bool):bool{return a;}}`,
    ],
    [
      'Brand<u8>',
      `type X=Brand<u8>;@contract class C{@state s:X;@external set(a:X):void{this.s=a;}@view get():u8{return u8(this.s);}@external @pure id(a:X):X{return a;}}`,
      `@contract class C{@state s:u8;@external set(a:u8):void{this.s=a;}@view get():u8{return this.s;}@external @pure id(a:u8):u8{return a;}}`,
    ],
    [
      'Brand<i128>',
      `type X=Brand<i128>;@contract class C{@state s:X;@external set(a:X):void{this.s=a;}@view get():i128{return i128(this.s);}@external @pure id(a:X):X{return a;}}`,
      `@contract class C{@state s:i128;@external set(a:i128):void{this.s=a;}@view get():i128{return this.s;}@external @pure id(a:i128):i128{return a;}}`,
    ],
  ];
  for (const [label, branded, plain] of cases) {
    it(`${label} erases to its base`, () => assertErased(branded, plain, label));
  }

  it('bool(Brand<bool>) and the ABI both show the base type, not the brand name', () => {
    const r = compile(`type Flag=Brand<bool>;@contract class C{@external @pure f(a:Flag):Flag{return a;}}`, {
      fileName: 'C.jeth',
    });
    const fn = r.abi.find((x: any) => x.name === 'f') as any;
    expect(fn.inputs[0].type).toBe('bool');
    expect(fn.outputs[0].type).toBe('bool');
  });
});

// =====================================================================================
// 2. Branded in AGGREGATE positions: fixed/dyn array, struct field, mapping key+value,
//    multi-value tuple return. Each must erase to the plain base AND match solc at runtime.
// =====================================================================================
describe('2. branded aggregates erase to the base and match solc', () => {
  it('Arr<TokenId,3>, TokenId[], branded struct field, branded map key+value, tuple return all erase', () => {
    assertErased(
      `type T=Brand<u256>;type W=Brand<address>;
       @struct class Rec{ id: T; who: W; }
       @contract class C{
         @state m: mapping<T,W>;
         @external @pure fixedEcho(a: Arr<T,3>): Arr<T,3> { return a; }
         @external @pure dynEcho(a: T[]): T[] { return a; }
         @external setM(k: T, v: W): void { this.m[k] = v; }
         @view getM(k: T): W { return this.m[k]; }
         @external @pure rec(i: T, w: W): Rec { return Rec(i, w); }
         @external @pure tup(a: T, b: W): [T, W] { return [a, b]; }
       }`,
      `@struct class Rec{ id: u256; who: address; }
       @contract class C{
         @state m: mapping<u256,address>;
         @external @pure fixedEcho(a: Arr<u256,3>): Arr<u256,3> { return a; }
         @external @pure dynEcho(a: u256[]): u256[] { return a; }
         @external setM(k: u256, v: address): void { this.m[k] = v; }
         @view getM(k: u256): address { return this.m[k]; }
         @external @pure rec(i: u256, w: address): Rec { return Rec(i, w); }
         @external @pure tup(a: u256, b: address): [u256, address] { return [a, b]; }
       }`,
      'branded aggregates',
    );
  });

  it('branded mapping + struct store to the same raw slots as solc', async () => {
    const J = `type T=Brand<u256>;type W=Brand<address>;
      @struct class Rec{ id: T; bal: T; }
      @contract class C{
        @state m: mapping<T,W>;
        @state rec: Rec;
        @external setM(k:T,v:W):void{ this.m[k]=v; }
        @external @view getM(k:T):W{ return this.m[k]; }
        @external setRec(i:T,b:T):void{ this.rec=Rec(i,b); }
        @external @pure echoArr(a: Arr<T,3>): Arr<T,3> { return a; }
        @external @pure echoDyn(a: T[]): T[] { return a; }
        @external @pure tup(a:T,b:W):[T,W]{ return [a,b]; }
      }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C{
  type T is uint256; type W is address;
  mapping(uint256 => address) m;
  struct Rec { uint256 id; uint256 bal; }
  Rec rec;
  function setM(uint256 k, address v) external { m[k] = v; }
  function getM(uint256 k) external view returns (address) { return m[k]; }
  function setRec(uint256 i, uint256 b) external { rec = Rec(i, b); }
  function echoArr(uint256[3] calldata a) external pure returns (uint256[3] memory) { return a; }
  function echoDyn(uint256[] calldata a) external pure returns (uint256[] memory) { return a; }
  function tup(uint256 a, address b) external pure returns (uint256, address) { return (a, b); }
}`;
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(S, 'C');
    const jh = await Harness.create();
    const sh = await Harness.create();
    const aj = await jh.deploy(jb.creationBytecode);
    const as = await sh.deploy(sb.creation);
    const A = 0xa11ce0000000000000000000000000000000n;

    async function both(data: string) {
      const j = await jh.call(aj, data);
      const s = await sh.call(as, data);
      expect(j.success, 'success').toBe(s.success);
      expect(j.returnHex, 'returndata').toBe(s.returnHex);
      return j;
    }
    // mapping write/read
    await both('0x' + sel('setM(uint256,address)') + pad(99n) + pad(A));
    await both(encodeCall(sel('getM(uint256)'), [99n]));
    // struct write -> raw slots
    await both('0x' + sel('setRec(uint256,uint256)') + pad(7n) + pad(8n));
    // fixed array echo
    await both('0x' + sel('echoArr(uint256[3])') + pad(1n) + pad(2n) + pad(3n));
    // dyn array echo (offset, len, elems)
    await both('0x' + sel('echoDyn(uint256[])') + pad(0x20n) + pad(2n) + pad(11n) + pad(22n));
    // tuple return
    await both('0x' + sel('tup(uint256,address)') + pad(55n) + pad(A));
    // raw slots: rec occupies slots 1,2 (slot 0 is the mapping base, empty)
    for (const slot of [1n, 2n]) {
      expect(await readSlot(jh, aj, slot), `rec slot ${slot}`).toBe(await readSlot(sh, as, slot));
    }
    // mapping slot keccak(key . 0)
    const { keccak256 } = await import('ethereum-cryptography/keccak.js');
    const { hexToBytes, bytesToHex } = await import('@ethereumjs/util');
    const mapSlot = BigInt(bytesToHex(keccak256(hexToBytes(('0x' + pad(99n) + pad(0n)) as `0x${string}`))));
    expect(await readSlot(jh, aj, mapSlot), 'mapping slot').toBe(await readSlot(sh, as, mapSlot));
  });
});

// =====================================================================================
// 3. Branded in EVENTS + ERRORS: topic0/selector use the BASE type; data is identical.
// =====================================================================================
describe('3. branded events/errors use the base type in the signature + identical bytes', () => {
  it('event signature (topic0) uses the base type, and logs are byte-identical to solc', async () => {
    const J = `type TokenId=Brand<u256>;type Acc=Brand<address>;
      @contract class C{
        @event Transfer(@indexed from: Acc, @indexed id: TokenId, amt: TokenId);
        @external xfer(from: Acc, id: TokenId, amt: TokenId): void { emit(Transfer(from, id, amt)); }
      }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C{
  type TokenId is uint256; type Acc is address;
  event Transfer(address indexed from, uint256 indexed id, uint256 amt);
  function xfer(address from, uint256 id, uint256 amt) external { emit Transfer(from, id, amt); }
}`;
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(S, 'C');
    // ABI must show base types (uint256/address), with correct indexed flags.
    const ev = jb.abi.find((x: any) => x.type === 'event') as any;
    expect(ev.inputs.map((i: any) => [i.type, i.indexed])).toEqual([
      ['address', true],
      ['uint256', true],
      ['uint256', false],
    ]);
    const jh = await Harness.create();
    const sh = await Harness.create();
    const aj = await jh.deploy(jb.creationBytecode);
    const as = await sh.deploy(sb.creation);
    const A = 0xbeef000000000000000000000000000000000000n;
    const data = '0x' + sel('xfer(address,uint256,uint256)') + pad(A) + pad(123n) + pad(456n);
    const j = await jh.call(aj, data);
    const s = await sh.call(as, data);
    expect(j.success && s.success).toBe(true);
    expect(j.logs.length).toBe(1);
    // topic0 = keccak of the BASE signature, not "Transfer(Acc,TokenId,TokenId)"
    expect(j.logs[0]!.topics[0]).toBe('0x' + eventTopic0('Transfer(address,uint256,uint256)'));
    expect(j.logs).toEqual(s.logs);
  });

  it('error selector uses the base type and revert data is byte-identical to solc', async () => {
    const J = `type W=Brand<u256>;
      @contract class C{
        @error Insufficient(need: W, have: W);
        @external @pure f(a: W, b: W): void { revert(Insufficient(a, b)); }
      }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C{
  type W is uint256;
  error Insufficient(uint256 need, uint256 have);
  function f(uint256 a, uint256 b) external pure { revert Insufficient(a, b); }
}`;
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(S, 'C');
    const er = jb.abi.find((x: any) => x.type === 'error') as any;
    expect(er.inputs.map((i: any) => i.type)).toEqual(['uint256', 'uint256']);
    const jh = await Harness.create();
    const sh = await Harness.create();
    const aj = await jh.deploy(jb.creationBytecode);
    const as = await sh.deploy(sb.creation);
    const data = encodeCall(sel('f(uint256,uint256)'), [5n, 9n]);
    const j = await jh.call(aj, data);
    const s = await sh.call(as, data);
    expect(j.success).toBe(false);
    expect(j.success).toBe(s.success);
    // revert data begins with the BASE-typed error selector Insufficient(uint256,uint256)
    expect(j.returnHex.slice(0, 10)).toBe('0x' + sel('Insufficient(uint256,uint256)'));
    expect(j.returnHex).toBe(s.returnHex);
  });
});

// =====================================================================================
// 4. Storage PACKING: a small brand packed beside other small fields must match the base.
// =====================================================================================
describe('4. branded small field packs identically to the base (raw slots)', () => {
  it('Brand<u8> packed beside u8/u16/address occupies the same slot+offset as the base', async () => {
    const J = `type Small=Brand<u8>;type Tag=Brand<u16>;
      @struct class S{ a: Small; b: u8; c: Tag; d: address; e: u8; }
      @contract class C{
        @state s: S;
        @external set(a:Small,b:u8,c:Tag,d:address,e:u8):void{ this.s=S(a,b,c,d,e); }
      }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C{
  type Small is uint8; type Tag is uint16;
  struct S { uint8 a; uint8 b; uint16 c; address d; uint8 e; }
  S s;
  function set(uint8 a, uint8 b, uint16 c, address d, uint8 e) external { s = S(a,b,c,d,e); }
}`;
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(S, 'C');
    // Also prove erasure against a plain-base JETH contract.
    assertErased(
      J,
      `@struct class S{ a: u8; b: u8; c: u16; d: address; e: u8; }
       @contract class C{ @state s: S; @external set(a:u8,b:u8,c:u16,d:address,e:u8):void{ this.s=S(a,b,c,d,e); } }`,
      'packed small brand',
    );
    const jh = await Harness.create();
    const sh = await Harness.create();
    const aj = await jh.deploy(jb.creationBytecode);
    const as = await sh.deploy(sb.creation);
    const D = 0xdddd000000000000000000000000000000000000n;
    const data =
      '0x' +
      sel('set(uint8,uint8,uint16,address,uint8)') +
      pad(0x11n) +
      pad(0x22n) +
      pad(0x3333n) +
      pad(D) +
      pad(0x44n);
    await jh.call(aj, data);
    await sh.call(as, data);
    for (const slot of [0n, 1n]) {
      expect(await readSlot(jh, aj, slot), `packed slot ${slot}`).toBe(await readSlot(sh, as, slot));
    }
  });
});

// =====================================================================================
// 5. Literal retyping + branded arithmetic/comparison: SOUND and matches solc at runtime.
//    The brand carries the base WIDTH into codegen, so range checks + checked arithmetic
//    happen at the base width, exactly like the unwrapped base.
// =====================================================================================
describe('5. literal retyping + branded arithmetic match solc at runtime', () => {
  it('`const x: TokenId = 5n`, `id + 1n`, and `id == otherId` compile (brand kept)', () => {
    expect(compiles(`type T=Brand<u256>;@contract class C{@external @pure f():T{const x:T=5n;return x;}}`)).toBe(true);
    expect(compiles(`type T=Brand<u256>;@contract class C{@external @pure f(id:T):T{return id+1n;}}`)).toBe(true);
    expect(compiles(`type T=Brand<u256>;@contract class C{@external @pure f(a:T,b:T):bool{return a==b;}}`)).toBe(true);
  });

  it('literal range checks honor the BASE width of the brand (u8 -> 255 ok, 256/300 reject)', () => {
    expect(compiles(`type S=Brand<u8>;@contract class C{@external @pure f():S{const x:S=255n;return x;}}`)).toBe(true);
    expect(errCodes(`type S=Brand<u8>;@contract class C{@external @pure f():S{const x:S=300n;return x;}}`)).toContain(
      'JETH070',
    );
    expect(errCodes(`type S=Brand<u8>;@contract class C{@external @pure f(id:S):S{return id+256n;}}`)).toContain(
      'JETH070',
    );
    // signed base
    expect(compiles(`type S=Brand<i8>;@contract class C{@external @pure f():S{const x:S=-128n;return x;}}`)).toBe(true);
    expect(errCodes(`type S=Brand<i8>;@contract class C{@external @pure f():S{const x:S=-129n;return x;}}`)).toContain(
      'JETH070',
    );
  });

  it('branded u8 arithmetic is checked at 8 bits (overflow Panic 0x11) byte-identical to solc', async () => {
    const J = `type B=Brand<u8>;@contract class C{
      @external @pure addUnwrap(a:B,b:B):u256{ return u256(a+b); }
      @external @pure wrapDirty(x:u256):u256{ return u256(B(x)); }
      @external @pure eqId(a:B,b:B):bool{ return a==b; }
    }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C{
  type B is uint8;
  function addUnwrap(uint8 a, uint8 b) external pure returns (uint256){ return uint256(a+b); }
  function wrapDirty(uint256 x) external pure returns (uint256){ return uint256(uint8(x)); }
  function eqId(uint8 a, uint8 b) external pure returns (bool){ return a==b; }
}`;
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(S, 'C');
    const jh = await Harness.create();
    const sh = await Harness.create();
    const aj = await jh.deploy(jb.creationBytecode);
    const as = await sh.deploy(sb.creation);
    async function both(data: string, label: string) {
      const j = await jh.call(aj, data);
      const s = await sh.call(as, data);
      expect(j.success, `${label} success`).toBe(s.success);
      expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    }
    await both(encodeCall(sel('addUnwrap(uint8,uint8)'), [100n, 27n]), 'add ok');
    await both(encodeCall(sel('addUnwrap(uint8,uint8)'), [200n, 100n]), 'add overflow -> Panic'); // 300 > 255
    // wrapping a dirty u256 into Brand<u8> must MASK to 8 bits exactly like uint8(x).
    const dirty = (1n << 255n) | (1n << 100n) | 0xabcdn;
    await both(encodeCall(sel('wrapDirty(uint256)'), [dirty]), 'wrap masks high bits');
    await both(encodeCall(sel('eqId(uint8,uint8)'), [7n, 7n]), 'eq true');
    await both(encodeCall(sel('eqId(uint8,uint8)'), [7n, 8n]), 'eq false');
  });
});

// =====================================================================================
// 6. SOUNDNESS REJECTIONS: the nominal barrier must hold (for non-address bases).
// =====================================================================================
describe('6. nominal barrier rejections (non-address bases)', () => {
  it('plain base -> brand without a cast is rejected', () => {
    expect(errCodes(`type T=Brand<u256>;@contract class C{@external @pure f(x:u256):T{return x;}}`)).toContain(
      'JETH085',
    );
  });
  it('brand -> base without a cast is rejected', () => {
    expect(errCodes(`type T=Brand<u256>;@contract class C{@external @pure f(x:T):u256{return x;}}`)).toContain(
      'JETH085',
    );
  });
  it('brand A -> brand B without a cast is rejected (assignment)', () => {
    expect(
      errCodes(`type A=Brand<u256>;type B=Brand<u256>;@contract class C{@external @pure f(x:A):B{return x;}}`),
    ).toContain('JETH085');
  });
  it('mixing brand + base in arithmetic is rejected', () => {
    expect(errCodes(`type T=Brand<u256>;@contract class C{@external @pure f(x:T,y:u256):T{return x+y;}}`)).toContain(
      'JETH083',
    );
  });
  it('mixing brand A + brand B in a comparison is rejected', () => {
    expect(
      errCodes(
        `type A=Brand<u256>;type B=Brand<u256>;@contract class C{@external @pure f(x:A,y:B):bool{return x==y;}}`,
      ),
    ).toContain('JETH083');
  });
  it('passing a brand where its base is required is rejected (internal call arg)', () => {
    expect(
      errCodes(
        `type T=Brand<u256>;@contract class C{g(x:u256):u256{return x;}@external @pure f(x:T):u256{return this.g(x);}}`,
      ),
    ).toContain('JETH085');
  });
  it('passing a base where the brand is required is rejected (internal call arg)', () => {
    expect(
      errCodes(
        `type T=Brand<u256>;@contract class C{g(x:T):T{return x;}@external @pure f(x:u256):T{return this.g(x);}}`,
      ),
    ).toContain('JETH085');
  });
});

// =====================================================================================
// 6b. EXPLICIT-CAST permissiveness vs solc (NOT a miscompile; documents a checker choice).
//   solc forbids casting one UDVT directly to another (B.wrap(A.unwrap(x)) is required);
//   JETH allows the direct no-op `B(x)` when the bases are cast-compatible. The runtime is
//   still correct (the cast lowers on base kind/bits), so this is a permissiveness note,
//   not a hole. We assert the ACTUAL behavior and that any width change is still masked.
// =====================================================================================
describe('6b. cross-brand explicit cast: more permissive than solc, but runtime-correct', () => {
  it('allows the direct no-op cast brand A(u256) -> brand B(u256)', () => {
    expect(
      compiles(`type A=Brand<u256>;type B=Brand<u256>;@contract class C{@external @pure f(x:A):B{return B(x);}}`),
    ).toBe(true);
  });
  it('a width-changing cross-brand cast still MASKS to the target base width (matches solc base cast)', async () => {
    // JETH: Brand<u8>(Brand<u256>-valued x). solc equivalent: uint8(<u256>). The result must
    // be masked to 8 bits; if the cast were a pure no-op this would leave dirty high bits.
    const J = `type A=Brand<u256>;type B=Brand<u8>;@contract class C{@external @pure f(x:A):u256{ return u256(B(x)); }}`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C{ function f(uint256 x) external pure returns (uint256){ return uint256(uint8(x)); } }`;
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(S, 'C');
    const jh = await Harness.create();
    const sh = await Harness.create();
    const aj = await jh.deploy(jb.creationBytecode);
    const as = await sh.deploy(sb.creation);
    const dirty = (1n << 200n) | 0x1fen;
    const data = encodeCall(sel('f(uint256)'), [dirty]);
    const j = await jh.call(aj, data);
    const s = await sh.call(as, data);
    expect(j.returnHex, 'width-changing cross-brand cast must mask like solc').toBe(s.returnHex);
  });
});

// =====================================================================================
// 7. NASTY / non-value bases / name conflicts: must REJECT cleanly (no crash).
// =====================================================================================
describe('7. nasty Brand declarations are rejected with a clear error, never a crash', () => {
  const reject = (label: string, src: string, code = 'JETH015') =>
    it(label, () => expect(errCodes(src), label).toContain(code));

  reject(
    're-brand Brand<TokenId> (brand over a brand) rejected',
    `type T=Brand<u256>;type B=Brand<T>;@contract class C{@external @pure f(x:B):B{return x;}}`,
  );
  reject('Brand<mapping<...>> rejected', `type M=Brand<mapping<u256,u256>>;@contract class C{@external f():void{}}`);
  reject('Brand<u256[]> rejected', `type M=Brand<u256[]>;@contract class C{@external f():void{}}`);
  reject(
    'Brand<SomeStruct> rejected',
    `@struct class S{a:u256;}type M=Brand<S>;@contract class C{@external f():void{}}`,
    'JETH013',
  );
  reject(
    'duplicate alias name rejected',
    `type X=Brand<u256>;type X=Brand<u8>;@contract class C{@external f():void{}}`,
  );
  reject(
    'alias name conflicts with a primitive (u256) rejected',
    `type u256=Brand<u8>;@contract class C{@external f():void{}}`,
  );
  reject('inline Brand<u256> in a param rejected', `@contract class C{@external @pure f(x:Brand<u256>):void{}}`);
  reject('self-referential Brand<X> rejected', `type X=Brand<X>;@contract class C{@external f():void{}}`, 'JETH013');
  reject('empty Brand<> rejected', `type X=Brand<>;@contract class C{@external f():void{}}`);

  it('all of the above produce a diagnostic, none throw a non-CompileError crash', () => {
    const srcs = [
      `type B=Brand<T>;type T=Brand<u256>;@contract class C{@external f():void{}}`,
      `type M=Brand<mapping<u256,u256>>;@contract class C{@external f():void{}}`,
      `type X=Brand<>;@contract class C{@external f():void{}}`,
    ];
    for (const s of srcs) {
      let threwCompileError = false;
      try {
        compile(s, { fileName: 'C.jeth' });
      } catch (e: any) {
        threwCompileError = Array.isArray(e?.diagnostics);
        if (!threwCompileError) throw e; // re-throw a real crash
      }
      expect(threwCompileError).toBe(true);
    }
  });
});

// =====================================================================================
// 8. WIDENING soundness: the brand barrier is consistent (no implicit widening across it).
// =====================================================================================
describe('8. widening across a brand boundary is consistently rejected', () => {
  it('Brand<u128> does NOT implicitly widen to u256 (crossing the brand boundary needs a cast)', () => {
    expect(errCodes(`type S=Brand<u128>;@contract class C{@external @pure f(x:S):u256{return x;}}`)).toContain(
      'JETH085',
    );
  });
  it('Brand<u128> does NOT implicitly widen to a different brand Brand<u256>', () => {
    expect(
      errCodes(`type S=Brand<u128>;type T=Brand<u256>;@contract class C{@external @pure f(x:S):T{return x;}}`),
    ).toContain('JETH085');
  });
  it('the UNWRAPPED base still widens normally (sanity: u128 -> u256 is fine without a brand)', () => {
    expect(compiles(`@contract class C{@external @pure f(x:u128):u256{return x;}}`)).toBe(true);
    // and explicit unwrap-then-use widens fine
    expect(compiles(`type S=Brand<u128>;@contract class C{@external @pure f(x:S):u256{return u256(u128(x));}}`)).toBe(
      true,
    );
  });
});

// =====================================================================================
// REGRESSION (address bases): the nominal barrier must hold for `address` bases too. There
// was a hole where the analyzer's address fast-paths (unifyOperands: `address && address`
// early-return; coerce: the `address -> address` rule) fired BEFORE the brand check, so a
// branded address folded freely with a bare/other-branded address while every other base
// kind enforced the barrier. Fixed by guarding both fast-paths on `brand` equality. It was
// never a miscompile (addresses share one word, so runtime was byte-identical to the
// unwrapped base), but it violated "a brand vs its bare base are NOT implicitly convertible".
// These assert the barrier now holds for addresses, matching uint/int/bytesN (see section 6).
// =====================================================================================
describe('branded address enforces the nominal barrier (regression)', () => {
  it('rejects: branded address compared to a bare address without a cast', () => {
    expect(
      errCodes(`type A=Brand<address>;@contract class C{@external @pure f(a:A,b:address):bool{return a==b;}}`),
    ).toContain('JETH083');
  });
  it('rejects: two DIFFERENT branded addresses compared without a cast', () => {
    expect(
      errCodes(
        `type A=Brand<address>;type B=Brand<address>;@contract class C{@external @pure f(a:A,b:B):bool{return a==b;}}`,
      ),
    ).toContain('JETH083');
  });
  it('rejects: a bare address assigned to a branded-address return without a wrap', () => {
    expect(errCodes(`type A=Brand<address>;@contract class C{@external @pure f(b:address):A{return b;}}`)).toContain(
      'JETH085',
    );
  });
  it('rejects: a bare address stored into a branded-address local without a wrap', () => {
    expect(errCodes(`type A=Brand<address>;@contract class C{@external f(b:address):void{const a:A=b;}}`)).toContain(
      'JETH085',
    );
  });

  // The guard is brand-specific, not address-wide: same-brand and plain address folds still work.
  it('still accepts: same-brand address comparison, and plain address == address', () => {
    expect(compiles(`type A=Brand<address>;@contract class C{@external @pure f(a:A,b:A):bool{return a==b;}}`)).toBe(
      true,
    );
    expect(compiles(`@contract class C{@external @pure f(a:address,b:address):bool{return a==b;}}`)).toBe(true);
    // and explicit wrap/unwrap across the barrier compiles
    expect(
      compiles(`type A=Brand<address>;@contract class C{@external @pure f(x:address):address{return address(A(x));}}`),
    ).toBe(true);
  });

  // The hole is base-specific: prove the SAME shapes are correctly rejected for a u256 base.
  it('control: the identical shapes ARE rejected when the base is u256 (so the leak is address-only)', () => {
    expect(
      errCodes(`type A=Brand<u256>;@contract class C{@external @pure f(a:A,b:u256):bool{return a==b;}}`),
    ).toContain('JETH083');
    expect(errCodes(`type A=Brand<u256>;@contract class C{@external @pure f(b:u256):A{return b;}}`)).toContain(
      'JETH085',
    );
    expect(errCodes(`type A=Brand<u256>;@contract class C{@external f(b:u256):void{const a:A=b;}}`)).toContain(
      'JETH085',
    );
  });

  // Even though the type system leaks, confirm the runtime stays byte-identical to solc:
  // a branded-address round-trip through storage matches the plain-address contract exactly.
  it('despite the leak, runtime is still byte-identical to solc (no miscompile)', async () => {
    const J = `type Acc=Brand<address>;@contract class C{
      @state o: Acc;
      @external set(x: address): void { this.o = Acc(x); }
      @external @view get(): address { return address(this.o); }
      @external @pure same(a: Acc, b: Acc): bool { return a == b; }
    }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C{
  type Acc is address;
  Acc o;
  function set(address x) external { o = Acc.wrap(x); }
  function get() external view returns (address) { return Acc.unwrap(o); }
  function same(Acc a, Acc b) external pure returns (bool) { return Acc.unwrap(a) == Acc.unwrap(b); }
}`;
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(S, 'C');
    const jh = await Harness.create();
    const sh = await Harness.create();
    const aj = await jh.deploy(jb.creationBytecode);
    const as = await sh.deploy(sb.creation);
    const A = 0xcafe000000000000000000000000000000000001n;
    await jh.call(aj, '0x' + sel('set(address)') + pad(A));
    await sh.call(as, '0x' + sel('set(address)') + pad(A));
    const g1 = await jh.call(aj, encodeCall(sel('get()'), []));
    const g2 = await sh.call(as, encodeCall(sel('get()'), []));
    expect(g1.returnHex).toBe(g2.returnHex);
    expect(await readSlot(jh, aj, 0n)).toBe(await readSlot(sh, as, 0n)); // raw stored address slot
    const s1 = await jh.call(aj, '0x' + sel('same(address,address)') + pad(A) + pad(A));
    const s2 = await sh.call(as, '0x' + sel('same(address,address)') + pad(A) + pad(A));
    expect(s1.returnHex).toBe(s2.returnHex);
  });
});
