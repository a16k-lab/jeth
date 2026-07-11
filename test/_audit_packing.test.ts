// AUDIT (packing-and-storage): differential raw-storage-slot probes vs solc.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}
const sel = (s: string) => functionSelector(s);
function raw(selSig: string, words: bigint[]): string {
  return '0x' + sel(selSig) + words.map(pad).join('');
}

interface Pair {
  jeth: Harness;
  sol: Harness;
  aj: Address;
  as: Address;
}

async function deployPair(jethSrc: string, solSrc: string, solName: string): Promise<Pair> {
  const jc = compile(jethSrc);
  const sc = compileSolidity(solSrc, solName);
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jc.creationBytecode);
  const as = await sol.deploy(sc.creation);
  return { jeth, sol, aj, as };
}

// Compare raw storage slots 0..maxSlot AND a set of derived (keccak) slots after
// running the same calldata sequence on both contracts.
async function compareSlots(p: Pair, calls: string[], slots: bigint[], label: string) {
  for (const c of calls) {
    const j = await p.jeth.call(p.aj, c);
    const s = await p.sol.call(p.as, c);
    expect(j.success, `${label}: call ${c.slice(0, 10)} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label}: call ${c.slice(0, 10)} returndata`).toBe(s.returnHex);
  }
  for (const slot of slots) {
    const jv = await readSlot(p.jeth, p.aj, slot);
    const sv = await readSlot(p.sol, p.as, slot);
    expect(jv, `${label}: slot ${slot}`).toBe(sv);
  }
}

describe('AUDIT packing: struct field packing mixed widths', () => {
  it('mixed-width struct fields incl bytesN left-align and straddle', async () => {
    // Fields chosen to straddle the 32-byte boundary: 16+8+1 = 25 used, then
    // bytes4 (4) fits -> 29, then uint64 (8) does NOT fit -> new slot.
    const jethSrc = `
type S = {
  a: u128;
  b: u64;
  c: bool;
  d: bytes4;
  e: u64;
  f: bytes32;
};
class C {
  s: S;
  setA(v: u128): External<void> { this.s.a = v; }
  setB(v: u64): External<void> { this.s.b = v; }
  setC(v: bool): External<void> { this.s.c = v; }
  setD(v: bytes4): External<void> { this.s.d = v; }
  setE(v: u64): External<void> { this.s.e = v; }
  setF(v: bytes32): External<void> { this.s.f = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint128 a; uint64 b; bool c; bytes4 d; uint64 e; bytes32 f; }
  S s;
  function setA(uint128 v) external { s.a = v; }
  function setB(uint64 v) external { s.b = v; }
  function setC(bool v) external { s.c = v; }
  function setD(bytes4 v) external { s.d = v; }
  function setE(uint64 v) external { s.e = v; }
  function setF(bytes32 v) external { s.f = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('setA(uint128)', [(1n << 128n) - 1n]),
      raw('setB(uint64)', [0xdeadbeefcafef00dn]),
      raw('setC(bool)', [1n]),
      raw('setD(bytes4)', [0xaabbccddn << 224n]),
      raw('setE(uint64)', [0x1122334455667788n]),
      raw('setF(bytes32)', [(1n << 256n) - 7n]),
    ];
    await compareSlots(p, calls, [0n, 1n, 2n, 3n], 'mixed-struct');
  });
});

describe('AUDIT packing: fixed arrays packed + whole-slot + straddle', () => {
  it('uint64[5] packed, with odd count straddle (4 per slot)', async () => {
    const jethSrc = `
class C {
  a: Arr<u64, 5>;
  set(i: u256, v: u64): External<void> { this.a[i] = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint64[5] a;
  function set(uint256 i, uint64 v) external { a[i] = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('set(uint256,uint64)', [0n, 0x1111111111111111n]),
      raw('set(uint256,uint64)', [3n, 0x4444444444444444n]),
      raw('set(uint256,uint64)', [4n, 0x5555555555555555n]),
    ];
    await compareSlots(p, calls, [0n, 1n], 'uint64x5');
  });

  it('address[3] (whole-slot in arrays despite 20 bytes)', async () => {
    const jethSrc = `
class C {
  a: Arr<address, 3>;
  set(i: u256, v: address): External<void> { this.a[i] = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  address[3] a;
  function set(uint256 i, address v) external { a[i] = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('set(uint256,address)', [0n, 0x1234567890abcdef1234567890abcdef12345678n]),
      raw('set(uint256,address)', [2n, 0xffffffffffffffffffffffffffffffffffffffffn]),
    ];
    await compareSlots(p, calls, [0n, 1n, 2n], 'addr3');
  });

  it('bytes2[20] packed 16 per slot', async () => {
    const jethSrc = `
class C {
  a: Arr<bytes2, 20>;
  set(i: u256, v: bytes2): External<void> { this.a[i] = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  bytes2[20] a;
  function set(uint256 i, bytes2 v) external { a[i] = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('set(uint256,bytes2)', [0n, 0xaabbn << 240n]),
      raw('set(uint256,bytes2)', [15n, 0xccddn << 240n]),
      raw('set(uint256,bytes2)', [16n, 0xeeffn << 240n]),
      raw('set(uint256,bytes2)', [19n, 0x1234n << 240n]),
    ];
    await compareSlots(p, calls, [0n, 1n], 'bytes2x20');
  });
});

describe('AUDIT packing: dynamic array storage value+struct', () => {
  it('uint64[] push/pop packs 4 per slot, pop zeroes freed', async () => {
    const jethSrc = `
class C {
  a: u64[];
  push(v: u64): External<void> { this.a.push(v); }
  pop(): External<void> { this.a.pop(); }
  set(i: u256, v: u64): External<void> { this.a[i] = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint64[] a;
  function push(uint64 v) external { a.push(v); }
  function pop() external { a.pop(); }
  function set(uint256 i, uint64 v) external { a[i] = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    // keccak(0) data slot
    const { keccak256 } = await import('ethereum-cryptography/keccak.js');
    const dataSlot = BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(0n), 'hex'))).toString('hex'));
    const calls = [
      raw('push(uint64)', [0x1111111111111111n]),
      raw('push(uint64)', [0x2222222222222222n]),
      raw('push(uint64)', [0x3333333333333333n]),
      raw('push(uint64)', [0x4444444444444444n]),
      raw('push(uint64)', [0x5555555555555555n]),
      raw('pop()', []),
    ];
    await compareSlots(p, calls, [0n, dataSlot, dataSlot + 1n], 'u64dyn');
  });
});

describe('AUDIT packing: bytesN-with-remainder + signed int arrays', () => {
  it('bytes3[12] packed 10 per slot (2 wasted bytes per slot)', async () => {
    const jethSrc = `
class C {
  a: Arr<bytes3, 12>;
  set(i: u256, v: bytes3): External<void> { this.a[i] = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  bytes3[12] a;
  function set(uint256 i, bytes3 v) external { a[i] = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('set(uint256,bytes3)', [0n, 0xaabbccn << 232n]),
      raw('set(uint256,bytes3)', [9n, 0x112233n << 232n]),
      raw('set(uint256,bytes3)', [10n, 0xddeeffn << 232n]),
      raw('set(uint256,bytes3)', [11n, 0x445566n << 232n]),
    ];
    await compareSlots(p, calls, [0n, 1n], 'bytes3x12');
  });

  it('int64[8] packed 4 per slot, negative values sign-extend on read', async () => {
    const jethSrc = `
class C {
  a: Arr<i64, 8>;
  set(i: u256, v: i64): External<void> { this.a[i] = v; }
  get get(i: u256): External<i64> { return this.a[i]; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  int64[8] a;
  function set(uint256 i, int64 v) external { a[i] = v; }
  function get(uint256 i) external view returns (int64) { return a[i]; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('set(uint256,int64)', [0n, -1n]),
      raw('set(uint256,int64)', [1n, -12345n]),
      raw('set(uint256,int64)', [4n, 9223372036854775807n]),
      raw('set(uint256,int64)', [5n, -9223372036854775808n]),
    ];
    await compareSlots(p, calls, [0n, 1n], 'int64x8');
    // also compare read returndata of negatives (sign extension)
    for (const i of [0n, 1n, 4n, 5n, 7n]) {
      const c = raw('get(uint256)', [i]);
      const j = await p.jeth.call(p.aj, c);
      const s = await p.sol.call(p.as, c);
      expect(j.returnHex, `int64 get(${i})`).toBe(s.returnHex);
    }
  });

  it('int128[] dynamic packed 2 per slot, negatives', async () => {
    const jethSrc = `
class C {
  a: i128[];
  push(v: i128): External<void> { this.a.push(v); }
  get get(i: u256): External<i128> { return this.a[i]; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  int128[] a;
  function push(int128 v) external { a.push(v); }
  function get(uint256 i) external view returns (int128) { return a[i]; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const { keccak256 } = await import('ethereum-cryptography/keccak.js');
    const dataSlot = BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(0n), 'hex'))).toString('hex'));
    const calls = [
      raw('push(int128)', [-1n]),
      raw('push(int128)', [(1n << 127n) - 1n]),
      raw('push(int128)', [-(1n << 127n)]),
    ];
    await compareSlots(p, calls, [0n, dataSlot, dataSlot + 1n], 'int128dyn');
  });
});

describe('AUDIT packing: fixed array of struct + struct in fixed array', () => {
  it('Pt[3] where Pt packs into a single slot (uint128 x2)', async () => {
    const jethSrc = `
type Pt = { x: u128; y: u128; };
class C {
  a: Arr<Pt, 3>;
  setX(i: u256, v: u128): External<void> { this.a[i].x = v; }
  setY(i: u256, v: u128): External<void> { this.a[i].y = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Pt { uint128 x; uint128 y; }
  Pt[3] a;
  function setX(uint256 i, uint128 v) external { a[i].x = v; }
  function setY(uint256 i, uint128 v) external { a[i].y = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('setX(uint256,uint128)', [0n, 0xaaaan]),
      raw('setY(uint256,uint128)', [0n, 0xbbbbn]),
      raw('setX(uint256,uint128)', [2n, 0xccccn]),
    ];
    await compareSlots(p, calls, [0n, 1n, 2n], 'Pt3');
  });

  it('struct with a whole-slot fixed array field + trailing packed', async () => {
    // T { uint8 tag; uint256[3] data; uint8 flag } - data is whole-slot array (3
    // slots), tag is 1 byte alone, flag 1 byte alone after.
    const jethSrc = `
type T = { tag: u8; data: Arr<u256, 3>; flag: u8; };
class C {
  t: T;
  setTag(v: u8): External<void> { this.t.tag = v; }
  setData(i: u256, v: u256): External<void> { this.t.data[i] = v; }
  setFlag(v: u8): External<void> { this.t.flag = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct T { uint8 tag; uint256[3] data; uint8 flag; }
  T t;
  function setTag(uint8 v) external { t.tag = v; }
  function setData(uint256 i, uint256 v) external { t.data[i] = v; }
  function setFlag(uint8 v) external { t.flag = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('setTag(uint8)', [0x7fn]),
      raw('setData(uint256,uint256)', [0n, 0x1111111111111111n]),
      raw('setData(uint256,uint256)', [2n, 0x5555555555555555n]),
      raw('setFlag(uint8)', [0x99n]),
    ];
    await compareSlots(p, calls, [0n, 1n, 2n, 3n, 4n], 'T-fixedarr-field');
  });
});

describe('AUDIT packing: nested fixed array (whole-slot)', () => {
  it('uint256[2][2] indexing a[i][j] matches solc slots', async () => {
    const jethSrc = `
class C {
  a: Arr<Arr<u256, 2>, 2>;
  set(i: u256, j: u256, v: u256): External<void> { this.a[i][j] = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[2][2] a;
  function set(uint256 i, uint256 j, uint256 v) external { a[i][j] = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('set(uint256,uint256,uint256)', [0n, 0n, 0xa0n]),
      raw('set(uint256,uint256,uint256)', [0n, 1n, 0xa1n]),
      raw('set(uint256,uint256,uint256)', [1n, 0n, 0xb0n]),
      raw('set(uint256,uint256,uint256)', [1n, 1n, 0xb1n]),
    ];
    await compareSlots(p, calls, [0n, 1n, 2n, 3n], 'u256-2x2');
  });
});

describe('AUDIT packing: compound assignment + mapping struct values', () => {
  it('compound += on packed struct fields (RMW, sign-ext, narrow width)', async () => {
    const jethSrc = `
type S = { a: u32; b: i64; c: u128; };
class C {
  s: S;
  setAll(a: u32, b: i64, c: u128): External<void> { this.s.a = a; this.s.b = b; this.s.c = c; }
  addA(v: u32): External<void> { this.s.a += v; }
  addB(v: i64): External<void> { this.s.b += v; }
  addC(v: u128): External<void> { this.s.c += v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint32 a; int64 b; uint128 c; }
  S s;
  function setAll(uint32 a, int64 b, uint128 c) external { s.a = a; s.b = b; s.c = c; }
  function addA(uint32 v) external { s.a += v; }
  function addB(int64 v) external { s.b += v; }
  function addC(uint128 v) external { s.c += v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('setAll(uint32,int64,uint128)', [100n, -50n, 1000n]),
      raw('addA(uint32)', [0xfffffff0n]),
      raw('addB(int64)', [-25n]),
      raw('addC(uint128)', [5n]),
    ];
    await compareSlots(p, calls, [0n, 1n], 'compound-packed');
  });

  it('mapping<bytes32, S> with packed struct value', async () => {
    const jethSrc = `
type S = { a: u64; b: u64; flag: bool; };
class C {
  m: mapping<bytes32, S>;
  setA(k: bytes32, v: u64): External<void> { this.m[k].a = v; }
  setFlag(k: bytes32, v: bool): External<void> { this.m[k].flag = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint64 a; uint64 b; bool flag; }
  mapping(bytes32 => S) m;
  function setA(bytes32 k, uint64 v) external { m[k].a = v; }
  function setFlag(bytes32 k, bool v) external { m[k].flag = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const { keccak256 } = await import('ethereum-cryptography/keccak.js');
    const k = (1n << 200n) | 0xabcdn;
    const base = BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(k) + pad(0n), 'hex'))).toString('hex'));
    const calls = [raw('setA(bytes32,uint64)', [k << 0n, 0x1111n]), raw('setFlag(bytes32,bool)', [k, 1n])];
    await compareSlots(p, calls, [base, base + 1n], 'map-struct-packed');
  });
});

describe('AUDIT packing: static struct return ABI (packed fields, signed, bytesN)', () => {
  it('return a packed struct from storage: ABI words match (sign-ext, bytesN left-align)', async () => {
    const jethSrc = `
type S = { a: i64; b: u32; c: bytes4; d: bool; e: address; };
class C {
  s: S;
  setA(v: i64): External<void> { this.s.a = v; }
  setB(v: u32): External<void> { this.s.b = v; }
  setC(v: bytes4): External<void> { this.s.c = v; }
  setD(v: bool): External<void> { this.s.d = v; }
  setE(v: address): External<void> { this.s.e = v; }
  get get(): External<S> { return this.s; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { int64 a; uint32 b; bytes4 c; bool d; address e; }
  S s;
  function setA(int64 v) external { s.a = v; }
  function setB(uint32 v) external { s.b = v; }
  function setC(bytes4 v) external { s.c = v; }
  function setD(bool v) external { s.d = v; }
  function setE(address v) external { s.e = v; }
  function get() external view returns (S memory) { return s; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('setA(int64)', [-9999n]),
      raw('setB(uint32)', [0xdeadbeefn]),
      raw('setC(bytes4)', [0x11223344n << 224n]),
      raw('setD(bool)', [1n]),
      raw('setE(address)', [0x1234567890abcdef1234567890abcdef12345678n]),
    ];
    await compareSlots(p, calls, [0n], 'packed-struct-return');
    const j = await p.jeth.call(p.aj, raw('get()', []));
    const s = await p.sol.call(p.as, raw('get()', []));
    expect(j.returnHex, 'get() ABI return').toBe(s.returnHex);
  });
});

describe('AUDIT packing: dynamic array of struct with packed fields', () => {
  it('Rec[] push(Rec(...)) with packed fields + interleaved pop/push (stale data)', async () => {
    // Rec { uint128 a; uint64 b; bool c; bytes4 d } - all pack into slot 0 of elem
    // (16+8+1+4 = 29 bytes). Each element is 1 slot.
    const jethSrc = `
type Rec = { a: u128; b: u64; c: bool; d: bytes4; };
class C {
  recs: Rec[];
  pushV(a: u128, b: u64, c: bool, d: bytes4): External<void> { this.recs.push(Rec(a, b, c, d)); }
  pop(): External<void> { this.recs.pop(); }
  setA(i: u256, v: u128): External<void> { this.recs[i].a = v; }
  setC(i: u256, v: bool): External<void> { this.recs[i].c = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Rec { uint128 a; uint64 b; bool c; bytes4 d; }
  Rec[] recs;
  function pushV(uint128 a, uint64 b, bool c, bytes4 d) external { recs.push(Rec(a, b, c, d)); }
  function pop() external { recs.pop(); }
  function setA(uint256 i, uint128 v) external { recs[i].a = v; }
  function setC(uint256 i, bool v) external { recs[i].c = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const { keccak256 } = await import('ethereum-cryptography/keccak.js');
    const dataSlot = BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(0n), 'hex'))).toString('hex'));
    const seq = [
      raw('pushV(uint128,uint64,bool,bytes4)', [(1n << 128n) - 1n, 0xdeadbeefcafef00dn, 1n, 0xaabbccddn << 224n]),
      raw('pushV(uint128,uint64,bool,bytes4)', [0x1234n, 0x5678n, 0n, 0x11223344n << 224n]),
      raw('pop()', []),
      // push again into a slot that was just popped (must fully overwrite, no stale bytes)
      raw('pushV(uint128,uint64,bool,bytes4)', [0x1n, 0x2n, 1n, 0x99aabbccn << 224n]),
      raw('setA(uint256,uint128)', [0n, 0x42n]),
      raw('setC(uint256,bool)', [1n, 0n]),
    ];
    await compareSlots(p, seq, [0n, dataSlot, dataSlot + 1n], 'Rec-packed-dyn');
  });
});

describe('AUDIT packing: dynamic bytes/string storage transitions', () => {
  it('string storage short<->long transitions clear stale data slots', async () => {
    const jethSrc = `
class C {
  s: string;
  setShort(): External<void> { this.s = "hi"; }
  setLong(): External<void> { this.s = "this is a long string exceeding thirty one bytes for sure yes"; }
  setEmpty(): External<void> { this.s = ""; }
  setMed(): External<void> { this.s = "0123456789012345678901234567890"; }
  setExact32(): External<void> { this.s = "01234567890123456789012345678901"; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  string s;
  function setShort() external { s = "hi"; }
  function setLong() external { s = "this is a long string exceeding thirty one bytes for sure yes"; }
  function setEmpty() external { s = ""; }
  function setMed() external { s = "0123456789012345678901234567890"; }
  function setExact32() external { s = "01234567890123456789012345678901"; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const { keccak256 } = await import('ethereum-cryptography/keccak.js');
    const dataSlot = BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(0n), 'hex'))).toString('hex'));
    const slots = [0n];
    for (let i = 0; i < 4; i++) slots.push(dataSlot + BigInt(i));
    // sequence designed to leave stale data slots that must be cleared
    const seq = [
      'setLong()',
      'setShort()', // long -> short must clear data slots
      'setLong()',
      'setEmpty()', // long -> empty must clear data slots
      'setMed()',
      'setExact32()', // 31 -> 32 (short -> long boundary)
      'setExact32()',
      'setMed()', // 32 -> 31 (long -> short boundary) clears slot
    ];
    for (const fn of seq) {
      const c = raw(fn, []);
      const j = await p.jeth.call(p.aj, c);
      const s = await p.sol.call(p.as, c);
      expect(j.success, `${fn} success`).toBe(s.success);
      for (const slot of slots) {
        const jv = await readSlot(p.jeth, p.aj, slot);
        const sv = await readSlot(p.sol, p.as, slot);
        expect(jv, `after ${fn}: slot ${slot}`).toBe(sv);
      }
    }
  });
});

describe('AUDIT packing: struct stride rounding in arrays', () => {
  it('Pt[3] where Pt occupies 1.5 slots (rounds to 2 slots/elem)', async () => {
    // Pt { uint256 a; uint128 b } = 2 slots (a fills slot0, b in low half of slot1).
    // stride must be 2 whole slots per element.
    const jethSrc = `
type Pt = { a: u256; b: u128; };
class C {
  arr: Arr<Pt, 3>;
  setA(i: u256, v: u256): External<void> { this.arr[i].a = v; }
  setB(i: u256, v: u128): External<void> { this.arr[i].b = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Pt { uint256 a; uint128 b; }
  Pt[3] arr;
  function setA(uint256 i, uint256 v) external { arr[i].a = v; }
  function setB(uint256 i, uint128 v) external { arr[i].b = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const calls = [
      raw('setA(uint256,uint256)', [0n, 0xaa00n]),
      raw('setB(uint256,uint128)', [0n, 0xbb00n]),
      raw('setA(uint256,uint256)', [2n, 0xcc00n]),
      raw('setB(uint256,uint128)', [2n, 0xdd00n]),
    ];
    await compareSlots(p, calls, [0n, 1n, 2n, 3n, 4n, 5n], 'Pt3-1.5slot');
  });

  it('dynamic Rec[] where Rec is 3 slots, push/pop element stride', async () => {
    const jethSrc = `
type Rec = { a: u256; b: u128; c: u128; d: u256; };
class C {
  recs: Rec[];
  pushZ(): External<void> { this.recs.push(); }
  setA(i: u256, v: u256): External<void> { this.recs[i].a = v; }
  setB(i: u256, v: u128): External<void> { this.recs[i].b = v; }
  setC(i: u256, v: u128): External<void> { this.recs[i].c = v; }
  setD(i: u256, v: u256): External<void> { this.recs[i].d = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Rec { uint256 a; uint128 b; uint128 c; uint256 d; }
  Rec[] recs;
  function pushZ() external { recs.push(); }
  function setA(uint256 i, uint256 v) external { recs[i].a = v; }
  function setB(uint256 i, uint128 v) external { recs[i].b = v; }
  function setC(uint256 i, uint128 v) external { recs[i].c = v; }
  function setD(uint256 i, uint256 v) external { recs[i].d = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const { keccak256 } = await import('ethereum-cryptography/keccak.js');
    const dataSlot = BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(0n), 'hex'))).toString('hex'));
    const calls = [
      raw('pushZ()', []),
      raw('pushZ()', []),
      raw('setA(uint256,uint256)', [0n, 0x11n]),
      raw('setB(uint256,uint128)', [0n, 0x22n]),
      raw('setC(uint256,uint128)', [0n, 0x33n]),
      raw('setD(uint256,uint256)', [0n, 0x44n]),
      raw('setA(uint256,uint256)', [1n, 0x55n]),
      raw('setC(uint256,uint128)', [1n, 0x66n]),
    ];
    // Rec is 3 slots (a=slot0, b+c packed in slot1, d=slot2). 2 elems = slots 0..5
    const slots = [0n];
    for (let i = 0; i < 6; i++) slots.push(dataSlot + BigInt(i));
    await compareSlots(p, calls, slots, 'Rec3-dyn');
  });
});

describe('AUDIT packing: nested mapping-valued arrays + nested mappings', () => {
  it('mapping<u256, u256[]> per-key isolation (whole-slot elements)', async () => {
    const jethSrc = `
class C {
  m: mapping<u256, u256[]>;
  push(k: u256, v: u256): External<void> { this.m[k].push(v); }
  set(k: u256, i: u256, v: u256): External<void> { this.m[k][i] = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  mapping(uint256 => uint256[]) m;
  function push(uint256 k, uint256 v) external { m[k].push(v); }
  function set(uint256 k, uint256 i, uint256 v) external { m[k][i] = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const { keccak256 } = await import('ethereum-cryptography/keccak.js');
    // lenSlot for key 7 = keccak(key . base=0)
    const lenSlot7 = BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(7n) + pad(0n), 'hex'))).toString('hex'));
    const dataSlot7 = BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(lenSlot7), 'hex'))).toString('hex'));
    const calls = [
      raw('push(uint256,uint256)', [7n, 0x1111n]),
      raw('push(uint256,uint256)', [7n, 0x2222n]),
      raw('push(uint256,uint256)', [7n, 0x3333n]),
      raw('push(uint256,uint256)', [8n, 0x9999n]),
      raw('set(uint256,uint256,uint256)', [7n, 1n, 0xbeefn]),
    ];
    await compareSlots(p, calls, [lenSlot7, dataSlot7, dataSlot7 + 1n, dataSlot7 + 2n], 'mapU256arr');
  });

  it('nested mapping<address, mapping<u256, u128>> packing of value', async () => {
    const jethSrc = `
class C {
  m: mapping<address, mapping<u256, u128>>;
  set(a: address, k: u256, v: u128): External<void> { this.m[a][k] = v; }
}`;
    const solSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  mapping(address => mapping(uint256 => uint128)) m;
  function set(address a, uint256 k, uint128 v) external { m[a][k] = v; }
}`;
    const p = await deployPair(jethSrc, solSrc, 'C');
    const { keccak256 } = await import('ethereum-cryptography/keccak.js');
    const a = 0x1234567890abcdef1234567890abcdef12345678n;
    const inner = BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(a) + pad(0n), 'hex'))).toString('hex'));
    const valSlot = BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(42n) + pad(inner), 'hex'))).toString('hex'));
    const calls = [raw('set(address,uint256,uint128)', [a, 42n, 0xcafen])];
    await compareSlots(p, calls, [valSlot], 'nestedMap');
  });
});
