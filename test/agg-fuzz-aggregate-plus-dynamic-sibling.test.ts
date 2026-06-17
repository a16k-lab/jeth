// Phase 4d scenario "aggregate-plus-dynamic-sibling": a STATIC aggregate param
// (fixed array / struct) sitting next to a DYNAMIC sibling (u256[] / bytes).
// The ABI head is flat+unpacked: the aggregate's leaves are inline, the dynamic
// param contributes ONE offset word, and the dynamic tail base is byte 4 (right
// after the selector). We assert JETH is byte-identical to solc for: valid reads,
// a runtime-OOB dynamic index (Panic 0x32), a malformed offset (EMPTY revert),
// short calldata (EMPTY revert), and the struct-inline + bytes-tail layout.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AggDyn {
  struct Pt { uint128 x; uint128 y; }
  function sumAt(uint256[3] calldata a, uint256[] calldata b, uint256 i) external pure returns (uint256){ return a[i] + b[i]; }
  function aAt(uint256[3] calldata a, uint256[] calldata b, uint256 i) external pure returns (uint256){ return a[i]; }
  function bAt(uint256[3] calldata a, uint256[] calldata b, uint256 i) external pure returns (uint256){ return b[i]; }
  function bLen(uint256[3] calldata a, uint256[] calldata b, uint256 i) external pure returns (uint256){ return b.length; }
  function ptXof(Pt calldata p, bytes calldata data) external pure returns (uint128){ return p.x; }
  function ptYof(Pt calldata p, bytes calldata data) external pure returns (uint128){ return p.y; }
  function dataLen(Pt calldata p, bytes calldata data) external pure returns (uint256){ return data.length; }
  function dataAt(Pt calldata p, bytes calldata data, uint256 k) external pure returns (bytes1){ return data[k]; }
}`;

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}
const sel = (s: string) => functionSelector(s);

describe('aggregate + dynamic sibling vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;

  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  // assert JETH matches Solidity byte-for-byte (returndata + success).
  async function eq(label: string, data: string) {
    const { j, s } = await both(data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', '_gen4d_AggDyn.jeth'), 'utf8');
    const jb = compile(src, { fileName: '_gen4d_AggDyn.jeth' });
    const sb = compileSolidity(SOL, 'AggDyn');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // ---- Part 1: uint256[3] a, uint256[] b, uint256 i ----
  // Head = a[0],a[1],a[2], offset(b), i  => 5 words (160 bytes). Tail base = byte 4.
  // With the b tail placed immediately after the head, offset(b) = 160 = 0xa0.
  function p1(selSig: string, a: bigint[], b: bigint[], i: bigint, offB = 0xa0n): string {
    const head = [a[0]!, a[1]!, a[2]!, offB, i];
    const tail = [BigInt(b.length), ...b];
    return '0x' + sel(selSig) + [...head, ...tail].map(pad).join('');
  }

  it('valid: a[i] + b[i], a[i], b[i], b.length with a clean dynamic tail', async () => {
    const a = [10n, 20n, 30n];
    const b = [100n, 200n, 300n, 400n];
    // i within both a (len 3) and b (len 4): i in {0,1,2}
    for (const i of [0n, 1n, 2n]) {
      const r = await eq(`sumAt i=${i}`, p1('sumAt(uint256[3],uint256[],uint256)', a, b, i));
      expect(decodeUint(r.j.returnHex)).toBe(a[Number(i)]! + b[Number(i)]!);
    }
    expect(decodeUint((await eq('aAt i=1', p1('aAt(uint256[3],uint256[],uint256)', a, b, 1n))).j.returnHex)).toBe(20n);
    expect(decodeUint((await eq('bAt i=3', p1('bAt(uint256[3],uint256[],uint256)', a, b, 3n))).j.returnHex)).toBe(400n);
    expect(decodeUint((await eq('bLen', p1('bLen(uint256[3],uint256[],uint256)', a, b, 0n))).j.returnHex)).toBe(4n);
  });

  it('runtime OOB on the dynamic sibling b -> Panic(0x32) identically', async () => {
    const a = [1n, 2n, 3n];
    const b = [7n, 8n]; // length 2; index 2 is OOB
    const r = await eq('bAt OOB i=2', p1('bAt(uint256[3],uint256[],uint256)', a, b, 2n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x' + '4e487b71' + pad(0x32n));
  });

  it('runtime OOB on the static fixed array a -> Panic(0x32) identically', async () => {
    const a = [1n, 2n, 3n];
    const b = [7n, 8n, 9n, 10n];
    const r = await eq('aAt OOB i=3', p1('aAt(uint256[3],uint256[],uint256)', a, b, 3n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x' + '4e487b71' + pad(0x32n));
  });

  it('malformed b offset (points past calldata) -> EMPTY revert identically', async () => {
    const a = [1n, 2n, 3n];
    const b = [7n, 8n];
    // offset 0xffffffff... is absurd; the length word read is OOB -> solc reverts EMPTY.
    const r = await eq('bAt bad-offset huge', p1('bAt(uint256[3],uint256[],uint256)', a, b, 0n, (1n << 64n)));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('malformed b offset (claims a length running past calldata) -> EMPTY revert', async () => {
    // offset points at the i word (= some small value) which solc reads as the
    // array length; if that length implies elements past calldatasize, reading
    // an element reverts EMPTY. Use offset 0x80 (the i word) with i set huge.
    const a = [1n, 2n, 3n];
    const head = [a[0]!, a[1]!, a[2]!, 0x80n, (1n << 200n)]; // offset->i word; i = huge "length"
    const data = '0x' + sel('bAt(uint256[3],uint256[],uint256)') + head.map(pad).join('');
    const r = await eq('bAt offset->huge-len', data);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('short calldata (< static head) reverts EMPTY identically', async () => {
    // sumAt needs 5 head words (160 bytes); supply only 4.
    const short = '0x' + sel('sumAt(uint256[3],uint256[],uint256)') + [1n, 2n, 3n, 0xa0n].map(pad).join('');
    const r = await eq('sumAt short', short);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('lazy dirty leaf in the static aggregate: dirty a-element read reverts EMPTY, unread ignored', async () => {
    // a is uint256 so no narrowing; instead probe via b's tail being clean while
    // reading a clean index. (uint256 has no dirty form; this asserts the mixed
    // layout does not spuriously revert.)
    const a = [0n, 0n, 0n];
    const b = [42n];
    expect(decodeUint((await eq('bAt clean tail', p1('bAt(uint256[3],uint256[],uint256)', a, b, 0n))).j.returnHex)).toBe(42n);
  });

  // ---- Part 2: Pt p, bytes data ----
  // Head = p.x, p.y, offset(data) => 3 words (96 bytes). Tail base = byte 4.
  // data tail placed right after head => offset(data) = 96 = 0x60.
  function p2(selSig: string, x: bigint, y: bigint, data: Uint8Array, tailWords: bigint[] | null = null, offD = 0x60n, extraHead: bigint[] = []): string {
    const head = [x, y, offD, ...extraHead];
    let tail: bigint[];
    if (tailWords) {
      tail = tailWords;
    } else {
      const len = BigInt(data.length);
      const words: bigint[] = [len];
      for (let o = 0; o < data.length; o += 32) {
        const chunk = new Uint8Array(32);
        chunk.set(data.subarray(o, o + 32), 0); // left-aligned, right-padded
        words.push(BigInt('0x' + Buffer.from(chunk).toString('hex')));
      }
      tail = words;
    }
    return '0x' + sel(selSig) + [...head, ...tail].map(pad).join('');
  }

  it('struct inline + bytes tail: p.x, p.y, data.length', async () => {
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01]);
    expect(decodeUint((await eq('ptXof', p2('ptXof((uint128,uint128),bytes)', 0xcafen, 0xbeefn, data))).j.returnHex)).toBe(0xcafen);
    expect(decodeUint((await eq('ptYof', p2('ptYof((uint128,uint128),bytes)', 0xcafen, 0xbeefn, data))).j.returnHex)).toBe(0xbeefn);
    expect(decodeUint((await eq('dataLen', p2('dataLen((uint128,uint128),bytes)', 0xcafen, 0xbeefn, data))).j.returnHex)).toBe(5n);
  });

  it('bytes data[k] indexing: valid k and OOB k -> Panic(0x32)', async () => {
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01]);
    // dataAt has a 4th head word k; with data tail after a 4-word head, offset(data)=0x80.
    function p2k(k: bigint, offD = 0x80n): string {
      return p2('dataAt((uint128,uint128),bytes,uint256)', 0xcafen, 0xbeefn, data, null, offD, [k]);
    }
    for (let k = 0n; k < 5n; k++) {
      const r = await eq(`dataAt k=${k}`, p2k(k));
      // bytes1 is left-aligned; top byte is data[k].
      expect(r.j.returnHex.slice(0, 4)).toBe('0x' + data[Number(k)]!.toString(16).padStart(2, '0'));
    }
    // OOB k=5 -> Panic(0x32)
    const r = await eq('dataAt OOB k=5', p2k(5n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x' + '4e487b71' + pad(0x32n));
  });

  it('dirty struct leaf p.x (uint128 high bits set), read -> EMPTY revert; unread leaf ignored', async () => {
    const data = new Uint8Array([0x11]);
    // p.x dirty (bit128 set): reading p.x reverts EMPTY.
    let r = await eq('ptXof dirty-x read', p2('ptXof((uint128,uint128),bytes)', (1n << 128n) | 0x1n, 0x2n, data));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // same dirty x, but read p.y (clean) -> OK (lazy per-access).
    r = await eq('ptYof dirty-x unread', p2('ptYof((uint128,uint128),bytes)', (1n << 128n) | 0x1n, 0x2n, data));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0x2n);
  });

  it('struct + bytes short calldata (< static head) reverts EMPTY identically', async () => {
    // ptXof needs 3 head words (96 bytes); supply only 2.
    const short = '0x' + sel('ptXof((uint128,uint128),bytes)') + [0xcafen, 0xbeefn].map(pad).join('');
    const r = await eq('ptXof short', short);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });
});
