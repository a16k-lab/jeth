// ABI input validation must match Solidity: dirty calldata (out-of-range high
// bits) for narrow uint/int, bool, address, and bytesN reverts with empty data.
import { describe, it, expect, beforeAll } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';

const SRC = `class Decode {
  get u8id(a: u8): External<u8> { return a; }
  get i8id(a: i8): External<i8> { return a; }
  get boolid(a: bool): External<bool> { return a; }
  get addrid(a: address): External<address> { return a; }
}`;

function call32(h: Harness, addr: any, sig: string, word: string) {
  return h.call(addr, '0x' + functionSelector(sig) + word.padStart(64, '0'));
}

describe('ABI input validation (matches Solidity)', () => {
  let h: Harness;
  let addr: any;
  beforeAll(async () => {
    const b = compile(SRC, { fileName: 'Decode.jeth' });
    h = await Harness.create();
    addr = await h.deploy(b.creationBytecode);
  });

  it('accepts clean narrow-uint input', async () => {
    const r = await call32(h, addr, 'u8id(uint8)', 'ff'); // 255 fits in uint8
    expect(r.success).toBe(true);
    expect(BigInt(r.returnHex)).toBe(255n);
  });

  it('reverts on dirty uint8 (high bits set)', async () => {
    const r = await call32(h, addr, 'u8id(uint8)', '0100'); // 256 -> out of range
    expect(r.success).toBe(false);
    expect(r.returnHex).toBe('0x');
  });

  it('accepts a valid negative int8 and rejects an out-of-range one', async () => {
    // int8 -1 is 0xff..ff (full word), valid sign-extension
    const neg = await call32(h, addr, 'i8id(int8)', 'f'.repeat(64));
    expect(neg.success).toBe(true);
    // 0x0080 = 128, not a valid int8 sign-extension -> revert
    const bad = await call32(h, addr, 'i8id(int8)', '0080');
    expect(bad.success).toBe(false);
  });

  it('reverts on dirty bool (value > 1)', async () => {
    expect((await call32(h, addr, 'boolid(bool)', '02')).success).toBe(false);
    expect((await call32(h, addr, 'boolid(bool)', '01')).success).toBe(true);
  });

  it('reverts on dirty address (high 96 bits set)', async () => {
    const dirty = '01' + '00'.repeat(20); // bit set above the 20-byte address
    expect((await call32(h, addr, 'addrid(address)', dirty)).success).toBe(false);
    const clean = '00'.repeat(12) + 'ab'.repeat(20);
    expect((await call32(h, addr, 'addrid(address)', clean)).success).toBe(true);
  });
});
