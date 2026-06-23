// Branded newtypes: `type X = Brand<Base>` is a distinct NOMINAL value type over Base, erased
// at codegen/ABI/selectors. Proof of zero runtime cost: a branded contract compiles to byte-
// identical bytecode + ABI as the plain-base version, and is byte-identical to solc at runtime.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const A = 0xa11ce0000000000000000000000000000000n;

// Branded version
const BRANDED = `type TokenId = Brand<u256>;
type Wei = Brand<u256>;
@struct class Rec { id: TokenId; bal: Wei; }
@contract class C {
  @state owner: mapping<TokenId, address>;
  @state rec: Rec;
  @external setOwner(id: TokenId, o: address): void { this.owner[id] = o; }
  @external @view ownerOf(id: TokenId): address { return this.owner[id]; }
  @external @pure next(id: TokenId): TokenId { return TokenId(u256(id) + 1n); }
  @external @pure addWei(a: Wei, b: Wei): Wei { return a + b; }
  @external @pure eqId(a: TokenId, b: TokenId): bool { return a == b; }
  @external setRec(i: TokenId, b: Wei): void { this.rec = Rec(i, b); }
  @external @view recId(): u256 { return u256(this.rec.id); }
}`;
// Structurally identical, but plain u256 everywhere (the brand is the only difference).
const PLAIN = `@struct class Rec { id: u256; bal: u256; }
@contract class C {
  @state owner: mapping<u256, address>;
  @state rec: Rec;
  @external setOwner(id: u256, o: address): void { this.owner[id] = o; }
  @external @view ownerOf(id: u256): address { return this.owner[id]; }
  @external @pure next(id: u256): u256 { return u256(id + 1n); }
  @external @pure addWei(a: u256, b: u256): u256 { return a + b; }
  @external @pure eqId(a: u256, b: u256): bool { return a == b; }
  @external setRec(i: u256, b: u256): void { this.rec = Rec(i, b); }
  @external @view recId(): u256 { return u256(this.rec.id); }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Rec { uint256 id; uint256 bal; }
  mapping(uint256 => address) owner;
  Rec rec;
  function setOwner(uint256 id, address o) external { owner[id] = o; }
  function ownerOf(uint256 id) external view returns (address) { return owner[id]; }
  function next(uint256 id) external pure returns (uint256) { return id + 1; }
  function addWei(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }
  function eqId(uint256 a, uint256 b) external pure returns (bool) { return a == b; }
  function setRec(uint256 i, uint256 b) external { rec = Rec(i, b); }
  function recId() external view returns (uint256) { return rec.id; }
}`;

describe('branded newtypes', () => {
  it('a branded contract compiles to byte-identical bytecode + ABI as the plain-base version', () => {
    const b = compile(BRANDED, { fileName: 'C.jeth' });
    const p = compile(PLAIN, { fileName: 'C.jeth' });
    expect(b.creationBytecode).toBe(p.creationBytecode); // brand fully erased at codegen
    expect(JSON.stringify(b.abi)).toBe(JSON.stringify(p.abi)); // and in the ABI (selectors use the base)
  });

  describe('runtime byte-identical to solc', () => {
    let jeth: Harness, sol: Harness, aj: Address, as: Address;
    async function eq(label: string, data: string) {
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
      expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    }
    beforeAll(async () => {
      const jb = compile(BRANDED, { fileName: 'C.jeth' });
      const sb = compileSolidity(SOL, 'C');
      jeth = await Harness.create();
      sol = await Harness.create();
      aj = await jeth.deploy(jb.creationBytecode);
      as = await sol.deploy(sb.creation);
    });
    it('value ops + storage (mapping/struct) match solc incl. raw slots', async () => {
      const pad = (v: bigint) => v.toString(16).padStart(64, '0');
      await eq('next(41)', encodeCall(sel('next(uint256)'), [41n]));
      await eq('addWei', encodeCall(sel('addWei(uint256,uint256)'), [10n, 32n]));
      await eq('eqId true', encodeCall(sel('eqId(uint256,uint256)'), [7n, 7n]));
      await eq('eqId false', encodeCall(sel('eqId(uint256,uint256)'), [7n, 8n]));
      // mapping write/read
      const setO = '0x' + sel('setOwner(uint256,address)') + pad(99n) + pad(A);
      await jeth.call(aj, setO);
      await sol.call(as, setO);
      await eq('ownerOf(99)', encodeCall(sel('ownerOf(uint256)'), [99n]));
      // struct write -> raw slots
      const setR = '0x' + sel('setRec(uint256,uint256)') + pad(123n) + pad(456n);
      await jeth.call(aj, setR);
      await sol.call(as, setR);
      for (const slot of [1n, 2n])
        expect(await readSlot(jeth, aj, slot), `slot ${slot}`).toBe(await readSlot(sol, as, slot));
      await eq('recId', encodeCall(sel('recId()'), []));
    });
  });
});
