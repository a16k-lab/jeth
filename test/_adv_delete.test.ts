// Adversarial differential test for the `delete x` statement. Covers the attack surface the
// existing delete.test.ts did NOT: nested dynamic arrays, fixed-array-of-dynamic, structs with a
// mapping field, deleting a bytes/string FIELD directly, packed fixed arrays, slot reuse after
// delete, delete in loops / idempotent / no-op, nested mappings, struct-array elements with a
// string field, and boundary/dirty packed values. For EVERY case we seed state, call the JETH
// delete fn and the solc twin, then compare success + returndata + a broad set of raw slots
// (direct + computed keccak data slots) byte-for-byte.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const b32 = (v: bigint) => Buffer.from(((((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16)).padStart(64, '0'), 'hex');
// keccak(slot) - the data slot of a dynamic array / long string at `slot`.
const kecSlot = (n: bigint) => BigInt('0x' + toHex(keccak(b32(n))));
// keccak(key . base) - the mapping value slot for `m[key]` where m is at `base`.
const mapSlot = (key: bigint, base: bigint) => BigInt('0x' + toHex(keccak(Buffer.concat([b32(key), b32(base)]))));

const A = 0xa11ce0000000000000000000000000000000n;
const B = 0xb0b0000000000000000000000000000000000n;
const LONG = 'this string is definitely longer than thirty-two bytes so it uses keccak data slots__';
const LONG2 = 'another long payload exceeding the thirty-two byte short-string inline cutoff for sure!';
const SHORT = 'hi';

// hand-encode `seedStr(string)`-style calldata with one string arg (offset/len/padded data)
function strArg(selector: string, str: string): string {
  const bytes = Buffer.from(str, 'utf8');
  const len = bytes.length;
  const padded = Buffer.concat([bytes, Buffer.alloc((32 - (len % 32)) % 32)]);
  return '0x' + selector + b32(0x20n).toString('hex') + b32(BigInt(len)).toString('hex') + padded.toString('hex');
}

interface Pair { jeth: Harness; sol: Harness; aj: Address; as: Address; }

async function build(jethSrc: string, solSrc: string): Promise<Pair> {
  const jb = compile(jethSrc, { fileName: 'C.jeth' });
  const sb = compileSolidity(solSrc, 'C');
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  return { jeth, sol, aj, as };
}

// Run a no-arg fn on both, compare success + returndata + every slot in `slots`.
async function cmp(p: Pair, label: string, fnSig: string, slots: bigint[], call?: string) {
  const data = call ?? ('0x' + sel(fnSig));
  const j = await p.jeth.call(p.aj, data);
  const s = await p.sol.call(p.as, data);
  expect(j.success, `${label}: success (jeth err=${j.exceptionError})`).toBe(s.success);
  expect(j.returnHex, `${label}: returndata`).toBe(s.returnHex);
  for (const slot of slots) {
    expect(await readSlot(p.jeth, p.aj, slot), `${label}: slot 0x${slot.toString(16)}`)
      .toBe(await readSlot(p.sol, p.as, slot));
  }
}

// ---------------------------------------------------------------------------
// 1. Nested dynamic arrays: u256[][], u256[][][], string[][]
// ---------------------------------------------------------------------------
describe('delete: nested dynamic arrays', () => {
  const JETH = `@contract class C {
  @state dd: u256[][];        // slot 0
  @state ddd: u256[][][];     // slot 1
  @state sdd: string[][];     // slot 2
  @external seed(): void {
    this.dd.push([10n, 20n]); this.dd.push([30n, 40n, 50n]);
    // ddd[0] = [[1,2],[3]] ; ddd[1] = [[7]]
    this.ddd.push();
    this.ddd[0n].push([1n, 2n]); this.ddd[0n].push([3n]);
    this.ddd.push();
    this.ddd[1n].push([7n]);
    // sdd[0] = ["${SHORT}", "${LONG}"]
    this.sdd.push();
    this.sdd[0n].push("${SHORT}"); this.sdd[0n].push("${LONG}");
  }
  @external delDD(): void { delete this.dd; }
  @external delDDelem(): void { delete this.dd[1n]; }
  @external delDDD(): void { delete this.ddd; }
  @external delDDDelem(): void { delete this.ddd[0n]; }
  @external delSDD(): void { delete this.sdd; }
  @external delSDDelem(): void { delete this.sdd[0n]; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[][] dd;
  uint256[][][] ddd;
  string[][] sdd;
  function seed() external {
    dd.push([uint256(10), 20]); dd.push([uint256(30), 40, 50]);
    ddd.push();
    ddd[0].push([uint256(1), 2]); ddd[0].push(_one(3));
    ddd.push();
    ddd[1].push(_one(7));
    sdd.push();
    sdd[0].push("${SHORT}"); sdd[0].push("${LONG}");
  }
  function _one(uint256 v) private pure returns (uint256[] memory r) { r = new uint256[](1); r[0] = v; }
  function delDD() external { delete dd; }
  function delDDelem() external { delete dd[1]; }
  function delDDD() external { delete ddd; }
  function delDDDelem() external { delete ddd[0]; }
  function delSDD() external { delete sdd; }
  function delSDDelem() external { delete sdd[0]; }
}`;
  let p: Pair;
  beforeAll(async () => { p = await build(JETH, SOL); });

  // Compute the full keccak chain of data slots for dd (slot 0).
  // dd len @ 0; outer data @ keccak(0); dd[i] len @ keccak(0)+i; dd[i] data @ keccak(keccak(0)+i).
  const dd0 = kecSlot(0n);
  const dd0_0len = dd0, dd0_1len = dd0 + 1n;
  const dd0_0data = kecSlot(dd0), dd0_1data = kecSlot(dd0 + 1n);
  const ddd1 = kecSlot(1n);
  const sdd2 = kecSlot(2n);

  async function reseed() { await p.jeth.call(p.aj, '0x' + sel('seed()')); await p.sol.call(p.as, '0x' + sel('seed()')); }

  it('delete whole dd / dd[i] zeroes all inner data + lengths, leaves neighbors', async () => {
    const slots = [0n, 1n, 2n,
      dd0_0len, dd0_1len, dd0_0data, dd0_0data + 1n, dd0_1data, dd0_1data + 1n, dd0_1data + 2n,
      // ddd chain (must stay intact when only dd is deleted)
      ddd1, ddd1 + 1n, kecSlot(ddd1), kecSlot(ddd1 + 1n),
      sdd2];
    await reseed(); await cmp(p, 'delDD', 'delDD()', slots);
    await reseed(); await cmp(p, 'delDDelem', 'delDDelem()', slots);
  });

  it('delete whole ddd / ddd[i] (triple-nested) zeroes the full keccak chain', async () => {
    // ddd[0] is a uint256[][] at lenSlot keccak(1); its outer data @ keccak(keccak(1));
    // ddd[0][j] len @ keccak(keccak(1))+j; ddd[0][j] data @ keccak(keccak(keccak(1))+j).
    const o = kecSlot(ddd1);                 // ddd[0] outer data
    const slots = [0n, 1n, 2n, ddd1, ddd1 + 1n,
      o, o + 1n, kecSlot(o), kecSlot(o) + 1n, kecSlot(o + 1n),
      kecSlot(ddd1 + 1n), kecSlot(kecSlot(ddd1 + 1n))];
    await reseed(); await cmp(p, 'delDDD', 'delDDD()', slots);
    await reseed(); await cmp(p, 'delDDDelem', 'delDDDelem()', slots);
  });

  it('delete string[][] (sdd) and sdd[i] zeroes element headers + long-data slots', async () => {
    // sdd[0] inner string[] len @ keccak(2); its data @ keccak(keccak(2)); each string elem
    // header @ keccak(keccak(2))+k; a long elem's long-data @ keccak(header).
    const inner = kecSlot(sdd2);          // sdd[0] inner string[] lenSlot
    const data = kecSlot(inner);          // sdd[0] data base (string headers)
    const slots = [0n, 1n, 2n, inner, data, data + 1n, kecSlot(data + 1n)];
    await reseed(); await cmp(p, 'delSDD', 'delSDD()', slots);
    await reseed(); await cmp(p, 'delSDDelem', 'delSDDelem()', slots);
  });
});

// ---------------------------------------------------------------------------
// 2. Fixed array of dynamic: Arr<string,N>, Arr<D,N> (D has a string field)
// ---------------------------------------------------------------------------
describe('delete: fixed array of dynamic element', () => {
  const JETH = `@struct class D { n: u256; s: string; }
@contract class C {
  @state fs: Arr<string,3>;   // slots 0,1,2 (each a string header)
  @state fd: Arr<D,2>;        // slots 3,4 (D[0]: n@3, s@4) ; 5,6 (D[1])
  @state guard: u256;         // slot 7
  @external seed(): void {
    this.fs[0n] = "${SHORT}"; this.fs[1n] = "${LONG}"; this.fs[2n] = "${LONG2}";
    this.fd[0n] = D(11n, "${LONG}"); this.fd[1n] = D(22n, "${SHORT}");
    this.guard = 0xfeedn;
  }
  @external delFS(): void { delete this.fs; }
  @external delFD(): void { delete this.fd; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct D { uint256 n; string s; }
  string[3] fs;
  D[2] fd;
  uint256 guard;
  function seed() external {
    fs[0] = "${SHORT}"; fs[1] = "${LONG}"; fs[2] = "${LONG2}";
    fd[0] = D(11, "${LONG}"); fd[1] = D(22, "${SHORT}");
    guard = 0xfeed;
  }
  function delFS() external { delete fs; }
  function delFD() external { delete fd; }
}`;
  let p: Pair;
  beforeAll(async () => { p = await build(JETH, SOL); });
  async function reseed() { await p.jeth.call(p.aj, '0x' + sel('seed()')); await p.sol.call(p.as, '0x' + sel('seed()')); }

  it('delete Arr<string,N>: headers + long-data slots zeroed, guard intact', async () => {
    const slots = [0n, 1n, 2n, 7n, kecSlot(1n), kecSlot(2n), kecSlot(1n) + 1n, kecSlot(2n) + 1n];
    await reseed(); await cmp(p, 'delFS', 'delFS()', slots);
  });
  it('delete Arr<D,N> with a string field: per-element clear, guard intact', async () => {
    // fd[0]: n@3, s header@4, s long-data @ keccak(4); fd[1]: n@5, s@6.
    const slots = [3n, 4n, 5n, 6n, 7n, kecSlot(4n), kecSlot(4n) + 1n, kecSlot(6n)];
    await reseed(); await cmp(p, 'delFD', 'delFD()', slots);
  });
});

// ---------------------------------------------------------------------------
// 3. Struct WITH a mapping field: delete must zero value fields but LEAVE mapping entries.
// ---------------------------------------------------------------------------
describe('delete: struct containing a mapping field', () => {
  const JETH = `@struct class S { a: u256; m: mapping<address, u256>; b: u256; }
@contract class C {
  @state s: S;                // a@0, m@1, b@2
  @state after: u256;         // slot 3
  @external seed(): void {
    this.s.a = 111n; this.s.b = 222n;
    this.s.m[address(0xa11ce0000000000000000000000000000000n)] = 777n;
    this.s.m[address(0xb0b0000000000000000000000000000000000n)] = 888n;
    this.after = 0xcafen;
  }
  @external delS(): void { delete this.s; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint256 a; mapping(address => uint256) m; uint256 b; }
  S s;
  uint256 afterv;
  function seed() external {
    s.a = 111; s.b = 222;
    s.m[address(0xa11ce0000000000000000000000000000000)] = 777;
    s.m[address(0xb0b0000000000000000000000000000000000)] = 888;
    afterv = 0xcafe;
  }
  function delS() external { delete s; }
}`;
  let p: Pair;
  beforeAll(async () => { p = await build(JETH, SOL); });
  it('delete struct: a/b zeroed, after intact, mapping entries SURVIVE', async () => {
    // m is at slot 1; entries at keccak(key . 1).
    const mA = mapSlot(A, 1n), mB = mapSlot(B, 1n);
    const slots = [0n, 1n, 2n, 3n, mA, mB];
    await p.jeth.call(p.aj, '0x' + sel('seed()')); await p.sol.call(p.as, '0x' + sel('seed()'));
    await cmp(p, 'delS', 'delS()', slots);
    // explicit sanity: the mapping entries must SURVIVE (not be zeroed by the struct delete).
    expect(await readSlot(p.jeth, p.aj, mA)).toBe('0x' + b32(777n).toString('hex'));
    expect(await readSlot(p.jeth, p.aj, mB)).toBe('0x' + b32(888n).toString('hex'));
  });
});

// ---------------------------------------------------------------------------
// 4. delete a bytes/string FIELD of a struct directly; siblings untouched.
// ---------------------------------------------------------------------------
describe('delete: a bytes/string field of a storage struct directly', () => {
  const JETH = `@struct class D { n: u256; s: string; bs: bytes; t: u256; }
@contract class C {
  @state d: D;   // n@0, s@1, bs@2, t@3
  @external seed(): void { this.d = D(5n, "${LONG}", "${LONG2}", 9n); }
  @external delS(): void { delete this.d.s; }
  @external delBs(): void { delete this.d.bs; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct D { uint256 n; string s; bytes bs; uint256 t; }
  D d;
  function seed() external { d = D(5, "${LONG}", "${LONG2}", 9); }
  function delS() external { delete d.s; }
  function delBs() external { delete d.bs; }
}`;
  let p: Pair;
  beforeAll(async () => { p = await build(JETH, SOL); });
  async function reseed() { await p.jeth.call(p.aj, '0x' + sel('seed()')); await p.sol.call(p.as, '0x' + sel('seed()')); }
  it('delete d.s: header + long-data zeroed; n, bs, t untouched', async () => {
    const slots = [0n, 1n, 2n, 3n, kecSlot(1n), kecSlot(1n) + 1n, kecSlot(2n), kecSlot(2n) + 1n];
    await reseed(); await cmp(p, 'delS', 'delS()', slots);
    await reseed(); await cmp(p, 'delBs', 'delBs()', slots);
  });
});

// ---------------------------------------------------------------------------
// 5. Packed fixed arrays: uint8[5], uint128[4], bool[10] - delete whole + element.
// ---------------------------------------------------------------------------
describe('delete: packed fixed arrays', () => {
  const JETH = `@contract class C {
  @state a8: Arr<u8,5>;     // slot 0 (5 bytes packed)
  @state a128: Arr<u128,4>; // slots 1,2 (2 per slot)
  @state ab: Arr<bool,10>;  // slot 3 (10 bytes packed)
  @state guard: u256;       // slot 4
  @external seed(): void {
    this.a8[0n]=1n; this.a8[1n]=2n; this.a8[2n]=3n; this.a8[3n]=4n; this.a8[4n]=5n;
    this.a128[0n]=100n; this.a128[1n]=200n; this.a128[2n]=300n; this.a128[3n]=400n;
    this.ab[0n]=true; this.ab[3n]=true; this.ab[9n]=true;
    this.guard = 0x9999n;
  }
  @external delA8(): void { delete this.a8; }
  @external delA8e(): void { delete this.a8[2n]; }
  @external delA128(): void { delete this.a128; }
  @external delA128e(): void { delete this.a128[3n]; }
  @external delAb(): void { delete this.ab; }
  @external delAbe(): void { delete this.ab[3n]; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint8[5] a8;
  uint128[4] a128;
  bool[10] ab;
  uint256 guard;
  function seed() external {
    a8[0]=1; a8[1]=2; a8[2]=3; a8[3]=4; a8[4]=5;
    a128[0]=100; a128[1]=200; a128[2]=300; a128[3]=400;
    ab[0]=true; ab[3]=true; ab[9]=true;
    guard = 0x9999;
  }
  function delA8() external { delete a8; }
  function delA8e() external { delete a8[2]; }
  function delA128() external { delete a128; }
  function delA128e() external { delete a128[3]; }
  function delAb() external { delete ab; }
  function delAbe() external { delete ab[3]; }
}`;
  let p: Pair;
  beforeAll(async () => { p = await build(JETH, SOL); });
  async function reseed() { await p.jeth.call(p.aj, '0x' + sel('seed()')); await p.sol.call(p.as, '0x' + sel('seed()')); }
  const slots = [0n, 1n, 2n, 3n, 4n];
  it('delete whole packed arrays leaves no stray packed lanes, guard intact', async () => {
    await reseed(); await cmp(p, 'delA8', 'delA8()', slots);
    await reseed(); await cmp(p, 'delA128', 'delA128()', slots);
    await reseed(); await cmp(p, 'delAb', 'delAb()', slots);
  });
  it('delete a single packed element zeroes only its lane (neighbors preserved)', async () => {
    await reseed(); await cmp(p, 'delA8e', 'delA8e()', slots);
    await reseed(); await cmp(p, 'delA128e', 'delA128e()', slots);
    await reseed(); await cmp(p, 'delAbe', 'delAbe()', slots);
  });
});

// ---------------------------------------------------------------------------
// 6. Slot reuse: delete a dynamic array / string, then re-grow / re-set; no stale bytes.
// ---------------------------------------------------------------------------
describe('delete: slot reuse after delete (no stale bytes)', () => {
  const JETH = `@contract class C {
  @state xs: u256[];   // slot 0
  @state s: string;    // slot 1
  @external seed(): void {
    this.xs.push(0xaaaan); this.xs.push(0xbbbbn); this.xs.push(0xccccn); this.xs.push(0xddddn);
    this.s = "${LONG}";
  }
  @external delAndRegrow(): void {
    delete this.xs;
    this.xs.push(7n); this.xs.push(8n);
  }
  @external delAndReset(): void {
    delete this.s;
    this.s = "${SHORT}";
  }
  @external delStrThenLong(): void {
    delete this.s;
    this.s = "${LONG2}";
  }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[] xs;
  string s;
  function seed() external {
    xs.push(0xaaaa); xs.push(0xbbbb); xs.push(0xcccc); xs.push(0xdddd);
    s = "${LONG}";
  }
  function delAndRegrow() external { delete xs; xs.push(7); xs.push(8); }
  function delAndReset() external { delete s; s = "${SHORT}"; }
  function delStrThenLong() external { delete s; s = "${LONG2}"; }
}`;
  let p: Pair;
  beforeAll(async () => { p = await build(JETH, SOL); });
  async function reseed() { await p.jeth.call(p.aj, '0x' + sel('seed()')); await p.sol.call(p.as, '0x' + sel('seed()')); }
  it('delete + regrow array: freed tail slots must be clean', async () => {
    const slots = [0n, 1n, kecSlot(0n), kecSlot(0n) + 1n, kecSlot(0n) + 2n, kecSlot(0n) + 3n, kecSlot(1n), kecSlot(1n) + 1n, kecSlot(1n) + 2n];
    await reseed(); await cmp(p, 'delAndRegrow', 'delAndRegrow()', slots);
  });
  it('delete long string + reset short: long-data slots must be cleared', async () => {
    const slots = [0n, 1n, kecSlot(1n), kecSlot(1n) + 1n, kecSlot(1n) + 2n];
    await reseed(); await cmp(p, 'delAndReset', 'delAndReset()', slots);
    await reseed(); await cmp(p, 'delStrThenLong', 'delStrThenLong()', slots);
  });
});

// ---------------------------------------------------------------------------
// 7. delete in a loop, delete then re-delete (idempotent), delete an already-zero value.
// ---------------------------------------------------------------------------
describe('delete: loops, idempotency, no-op on zero', () => {
  const JETH = `@contract class C {
  @state fa: Arr<u256,5>;  // slots 0..4
  @state xs: u256[];       // slot 5
  @state c: u256;          // slot 6
  @external seed(): void {
    this.fa[0n]=1n; this.fa[1n]=2n; this.fa[2n]=3n; this.fa[3n]=4n; this.fa[4n]=5n;
    this.xs.push(9n); this.xs.push(8n);
    this.c = 42n;
  }
  @external delLoop(): void {
    let i: u256 = 0n;
    while (i < 5n) { delete this.fa[i]; i = i + 1n; }
  }
  @external delTwice(): void { delete this.xs; delete this.xs; }
  @external delZero(): void { delete this.c; delete this.c; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[5] fa;
  uint256[] xs;
  uint256 c;
  function seed() external {
    fa[0]=1; fa[1]=2; fa[2]=3; fa[3]=4; fa[4]=5;
    xs.push(9); xs.push(8);
    c = 42;
  }
  function delLoop() external { for (uint256 i=0;i<5;i++){ delete fa[i]; } }
  function delTwice() external { delete xs; delete xs; }
  function delZero() external { delete c; delete c; }
}`;
  let p: Pair;
  beforeAll(async () => { p = await build(JETH, SOL); });
  async function reseed() { await p.jeth.call(p.aj, '0x' + sel('seed()')); await p.sol.call(p.as, '0x' + sel('seed()')); }
  const slots = [0n, 1n, 2n, 3n, 4n, 5n, 6n, kecSlot(5n), kecSlot(5n) + 1n];
  it('delete each element in a loop', async () => { await reseed(); await cmp(p, 'delLoop', 'delLoop()', slots); });
  it('delete the same array twice (idempotent)', async () => { await reseed(); await cmp(p, 'delTwice', 'delTwice()', slots); });
  it('delete an already-zeroed value twice (no-op)', async () => { await reseed(); await cmp(p, 'delZero', 'delZero()', slots); });
});

// ---------------------------------------------------------------------------
// 8. Nested mapping delete + mapping to a dynamic array.
// ---------------------------------------------------------------------------
describe('delete: nested mapping value & mapping-to-array', () => {
  const JETH = `@contract class C {
  @state mm: mapping<address, mapping<u256, u256>>;  // slot 0
  @state ma: mapping<address, u256[]>;               // slot 1
  @external seed(): void {
    this.mm[address(0xa11ce0000000000000000000000000000000n)][7n] = 111n;
    this.mm[address(0xa11ce0000000000000000000000000000000n)][8n] = 222n;
    this.ma[address(0xa11ce0000000000000000000000000000000n)].push(0x11n);
    this.ma[address(0xa11ce0000000000000000000000000000000n)].push(0x22n);
    this.ma[address(0xa11ce0000000000000000000000000000000n)].push(0x33n);
  }
  @external delMMv(): void { delete this.mm[address(0xa11ce0000000000000000000000000000000n)][7n]; }
  @external delMAv(): void { delete this.ma[address(0xa11ce0000000000000000000000000000000n)]; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  mapping(address => mapping(uint256 => uint256)) mm;
  mapping(address => uint256[]) ma;
  function seed() external {
    mm[address(0xa11ce0000000000000000000000000000000)][7] = 111;
    mm[address(0xa11ce0000000000000000000000000000000)][8] = 222;
    ma[address(0xa11ce0000000000000000000000000000000)].push(0x11);
    ma[address(0xa11ce0000000000000000000000000000000)].push(0x22);
    ma[address(0xa11ce0000000000000000000000000000000)].push(0x33);
  }
  function delMMv() external { delete mm[address(0xa11ce0000000000000000000000000000000)][7]; }
  function delMAv() external { delete ma[address(0xa11ce0000000000000000000000000000000)]; }
}`;
  let p: Pair;
  beforeAll(async () => { p = await build(JETH, SOL); });
  async function reseed() { await p.jeth.call(p.aj, '0x' + sel('seed()')); await p.sol.call(p.as, '0x' + sel('seed()')); }
  it('delete nested mapping value mm[k1][k2]: only that leaf cleared', async () => {
    // inner base = keccak(k1 . 0); leaf7 = keccak(7 . inner); leaf8 = keccak(8 . inner).
    const inner = mapSlot(A, 0n);
    const leaf7 = mapSlot(7n, inner), leaf8 = mapSlot(8n, inner);
    await reseed(); await cmp(p, 'delMMv', 'delMMv()', [0n, 1n, leaf7, leaf8]);
  });
  it('delete mapping-to-array ma[k]: length + data slots cleared', async () => {
    // ma[k] lenSlot = keccak(k . 1); data @ keccak(lenSlot).
    const lenSlot = mapSlot(A, 1n);
    const data = kecSlot(lenSlot);
    await reseed(); await cmp(p, 'delMAv', 'delMAv()', [0n, 1n, lenSlot, data, data + 1n, data + 2n]);
  });
});

// ---------------------------------------------------------------------------
// 9. delete this.arr[i] where arr is a struct array (D[]) with a string field.
// ---------------------------------------------------------------------------
describe('delete: a struct-array element with a string field', () => {
  const JETH = `@struct class D { n: u256; s: string; t: u256; }
@contract class C {
  @state recs: D[];   // slot 0
  @external seed(): void {
    this.recs.push(D(1n, "${LONG}", 10n));
    this.recs.push(D(2n, "${LONG2}", 20n));
    this.recs.push(D(3n, "${SHORT}", 30n));
  }
  @external delMid(): void { delete this.recs[1n]; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct D { uint256 n; string s; uint256 t; }
  D[] recs;
  function seed() external {
    recs.push(D(1, "${LONG}", 10));
    recs.push(D(2, "${LONG2}", 20));
    recs.push(D(3, "${SHORT}", 30));
  }
  function delMid() external { delete recs[1]; }
}`;
  let p: Pair;
  beforeAll(async () => { p = await build(JETH, SOL); });
  it('delete recs[1]: element fully cleared, neighbors intact', async () => {
    // recs len @ 0; data @ keccak(0); each D spans 3 slots (n, s-header, t).
    const data = kecSlot(0n);
    const e0 = data, e1 = data + 3n, e2 = data + 6n;
    const slots = [0n,
      e0, e0 + 1n, e0 + 2n, kecSlot(e0 + 1n), kecSlot(e0 + 1n) + 1n,  // recs[0]
      e1, e1 + 1n, e1 + 2n, kecSlot(e1 + 1n), kecSlot(e1 + 1n) + 1n,  // recs[1] (deleted)
      e2, e2 + 1n, e2 + 2n];                                          // recs[2]
    await p.jeth.call(p.aj, '0x' + sel('seed()')); await p.sol.call(p.as, '0x' + sel('seed()'));
    await cmp(p, 'delMid', 'delMid()', slots);
  });
});

// ---------------------------------------------------------------------------
// 10. Boundary / dirty: max-width values, signed mins, address/bytesN/bool packed; delete one.
// ---------------------------------------------------------------------------
describe('delete: boundary / dirty packed values', () => {
  // packed slot 0: bool(1) + address(20) + u88(11) = 32 bytes, fully filled to dirty every byte.
  const JETH = `@contract class C {
  @state flag: bool;        // slot 0 off 0
  @state who: address;      // slot 0 off 1..20
  @state extra: u88;        // slot 0 off 21..31
  @state big: u256;         // slot 1
  @state smin: i256;        // slot 2
  @state s8: i8;            // slot 3 off 0
  @state s8b: i8;           // slot 3 off 1
  @external seed(): void {
    this.flag = true;
    this.who = address(0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeFn);
    this.extra = ${(2n ** 88n - 1n).toString()}n;
    this.big = ${(2n ** 256n - 1n).toString()}n;
    this.smin = -${(2n ** 255n).toString()}n;
    this.s8 = -128n; this.s8b = 127n;
  }
  @external delWho(): void { delete this.who; }
  @external delExtra(): void { delete this.extra; }
  @external delFlag(): void { delete this.flag; }
  @external delBig(): void { delete this.big; }
  @external delSmin(): void { delete this.smin; }
  @external delS8(): void { delete this.s8; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  bool flag;
  address who;
  uint88 extra;
  uint256 big;
  int256 smin;
  int8 s8;
  int8 s8b;
  function seed() external {
    flag = true;
    who = address(0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF);
    extra = type(uint88).max;
    big = type(uint256).max;
    smin = type(int256).min;
    s8 = type(int8).min; s8b = type(int8).max;
  }
  function delWho() external { delete who; }
  function delExtra() external { delete extra; }
  function delFlag() external { delete flag; }
  function delBig() external { delete big; }
  function delSmin() external { delete smin; }
  function delS8() external { delete s8; }
}`;
  let p: Pair;
  beforeAll(async () => { p = await build(JETH, SOL); });
  async function reseed() { await p.jeth.call(p.aj, '0x' + sel('seed()')); await p.sol.call(p.as, '0x' + sel('seed()')); }
  const slots = [0n, 1n, 2n, 3n];
  it('delete one lane of a fully-packed slot leaves the other lanes', async () => {
    await reseed(); await cmp(p, 'delWho', 'delWho()', slots);
    await reseed(); await cmp(p, 'delExtra', 'delExtra()', slots);
    await reseed(); await cmp(p, 'delFlag', 'delFlag()', slots);
    await reseed(); await cmp(p, 'delS8', 'delS8()', slots);
  });
  it('delete max/min-width full-slot values', async () => {
    await reseed(); await cmp(p, 'delBig', 'delBig()', slots);
    await reseed(); await cmp(p, 'delSmin', 'delSmin()', slots);
  });
});

// ---------------------------------------------------------------------------
// 11. Whole-mapping delete rejection parity (solc also rejects).
// ---------------------------------------------------------------------------
describe('delete: whole-mapping rejection parity', () => {
  it('JETH rejects delete of a whole mapping', () => {
    const src = `@contract class C { @state m: mapping<address,u256>; @external f(): void { delete this.m; } }`;
    expect(() => compile(src, { fileName: 'C.jeth' })).toThrow();
  });
  it('solc also rejects delete of a whole mapping', () => {
    const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C { mapping(address=>uint256) m; function f() external { delete m; } }`;
    expect(() => compileSolidity(src, 'C')).toThrow();
  });
});
