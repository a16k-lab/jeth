// Phase 4a: dynamic bytes/string byte-identical to Solidity — storage (short/long
// + overwrite clearing), calldata decode, ABI return encode, .length, b[i] bounds,
// dynamic events, and dynamic Error(string). Raw slots compared via readSlot.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint, type LogEntry } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const enc = new TextEncoder();

function pad32(v: bigint): string {
  return (v % (1n << 256n)).toString(16).padStart(64, '0');
}
function dataBase(slot: bigint): bigint {
  return BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad32(slot)) as `0x${string}`))));
}
/** ABI-encode a single bytes/string arg as calldata: selector + [0x20][len][padded]. */
function encStr(sig: string, str: string): string {
  const bytes = enc.encode(str);
  let dataHex = '';
  for (let i = 0; i < Math.ceil(bytes.length / 32) * 32; i++) dataHex += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return '0x' + functionSelector(sig) + pad32(0x20n) + pad32(BigInt(bytes.length)) + dataHex;
}

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract BS {
  string s; bytes b; uint256 canary;
  event Msg(string m);
  event Tagged(address indexed who, string m);
  function setS(string calldata v) external { s = v; }
  function getS() external view returns (string memory){ return s; }
  function echo(string calldata v) external pure returns (string memory){ return v; }
  function setB(bytes calldata v) external { b = v; }
  function getB() external view returns (bytes memory){ return b; }
  function blen() external view returns (uint256){ return b.length; }
  function at(uint256 i) external view returns (bytes1){ return b[i]; }
  function setCanary(uint256 c) external { canary = c; }
  function getCanary() external view returns (uint256){ return canary; }
  function emitMsg() external { emit Msg(s); }
  function emitTagged() external { emit Tagged(msg.sender, s); }
  function boom() external view { require(false, s); }
  function boomParam(string calldata v) external pure { require(false, v); }
}`;

const LENGTHS = [0, 1, 5, 31, 32, 33, 63, 64, 65, 100];
const repeat = (n: number, c = 'A') => c.repeat(n);
function eqLogs(a: LogEntry[], b: LogEntry[]): boolean {
  return (
    a.length === b.length &&
    a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics))
  );
}

describe('dynamic bytes/string vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function both(data: string, opts = {}) {
    return { j: await jeth.call(aj, data, opts), s: await sol.call(as, data, opts) };
  }
  const sel = (s: string) => functionSelector(s);

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'BS.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'BS.jeth' });
    const sb = compileSolidity(SOL, 'BS');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
    // set a nonzero canary at slot 2 that dynamic writes must never disturb
    await both(encodeCall(sel('setCanary(uint256)'), [0xdeadbeefn]));
  });

  it('stores every length with Solidity-identical raw slots (+ canary intact)', async () => {
    for (const n of LENGTHS) {
      const str = repeat(n);
      await both(encStr('setS(string)', str));
      expect(await readSlot(jeth, aj, 0n), `slot0 len=${n}`).toBe(await readSlot(sol, as, 0n));
      const base = dataBase(0n);
      const words = Math.ceil(n / 32);
      for (let i = 0; i < words; i++) {
        expect(await readSlot(jeth, aj, base + BigInt(i)), `data slot ${i} len=${n}`).toBe(
          await readSlot(sol, as, base + BigInt(i)),
        );
      }
      expect(decodeUint(await readSlot(jeth, aj, 2n)), `canary len=${n}`).toBe(0xdeadbeefn);
    }
  });

  it('clears old tail slots on overwrite, identically', async () => {
    const seqs = [
      [repeat(100), 'hi'],
      [repeat(100, 'F'), repeat(40, 'G')],
      ['hello', 'x'],
      [repeat(40), ''],
    ];
    for (const [a, b] of seqs) {
      await both(encStr('setS(string)', a!));
      await both(encStr('setS(string)', b!));
      const base = dataBase(0n);
      expect(await readSlot(jeth, aj, 0n), `slot0 ${a}->${b}`).toBe(await readSlot(sol, as, 0n));
      for (let i = 0; i < 4; i++) {
        expect(await readSlot(jeth, aj, base + BigInt(i)), `cleared slot ${i} ${a}->${b}`).toBe(
          await readSlot(sol, as, base + BigInt(i)),
        );
      }
    }
  });

  it('encodes returns byte-identically (storage source and calldata source)', async () => {
    for (const n of LENGTHS) {
      const str = repeat(n, 'Z');
      await both(encStr('setS(string)', str));
      let r = await both(encodeCall(sel('getS()')));
      expect(r.j.returnHex, `getS len=${n}`).toBe(r.s.returnHex);
      r = await both(encStr('echo(string)', str));
      expect(r.j.returnHex, `echo len=${n}`).toBe(r.s.returnHex);
    }
  });

  it('.length and b[i] match, with identical Panic(0x32) on OOB', async () => {
    for (const n of [0, 1, 32, 65]) {
      await both(encStr('setB(bytes)', repeat(n, 'q')));
      let r = await both(encodeCall(sel('blen()')));
      expect(decodeUint(r.j.returnHex)).toBe(BigInt(n));
      expect(r.j.returnHex).toBe(r.s.returnHex);
      for (const i of [0, Math.max(0, n - 1), n, n + 5]) {
        r = await both(encodeCall(sel('at(uint256)'), [BigInt(i)]));
        expect(r.j.success, `at(${i}) len=${n} success`).toBe(r.s.success);
        expect(r.j.returnHex, `at(${i}) len=${n} data`).toBe(r.s.returnHex);
      }
    }
  });

  it('emits dynamic-data events identically (plain and indexed)', async () => {
    for (const str of ['', 'hi', repeat(70, 'm')]) {
      await both(encStr('setS(string)', str));
      let r = await both(encodeCall(sel('emitMsg()')));
      expect(eqLogs(r.j.logs, r.s.logs), `emitMsg "${str.slice(0, 4)}"`).toBe(true);
      r = await both(encodeCall(sel('emitTagged()')));
      expect(eqLogs(r.j.logs, r.s.logs), `emitTagged "${str.slice(0, 4)}"`).toBe(true);
    }
  });

  it('reverts with byte-identical dynamic Error(string)', async () => {
    for (const str of ['', 'boom', repeat(40, 'Z')]) {
      await both(encStr('setS(string)', str));
      let r = await both(encodeCall(sel('boom()')));
      expect(r.j.success).toBe(false);
      expect(r.j.returnHex, `boom "${str.slice(0, 4)}"`).toBe(r.s.returnHex);
      r = await both(encStr('boomParam(string)', str));
      expect(r.j.returnHex, `boomParam "${str.slice(0, 4)}"`).toBe(r.s.returnHex);
    }
  });

  it('matches Solidity on adversarial calldata (non-canonical offset, truncated tail)', async () => {
    const s4 = sel('echo(string)');
    const cases = [
      // offset=0x40 (non-canonical but valid), with a filler word between head and data
      '0x' + s4 + pad32(0x40n) + pad32(0n) + pad32(2n) + pad32(BigInt('0x6869') << 240n),
      // offset points past the tail -> revert
      '0x' + s4 + pad32(0x100n),
      // length exceeds the available tail -> revert
      '0x' + s4 + pad32(0x20n) + pad32(0x1000n) + pad32(0n),
      // truncated: head says offset 0x20 but no length word present
      '0x' + s4 + pad32(0x20n),
    ];
    for (const data of cases) {
      const r = await both(data);
      expect(r.j.success, `cd ${data.slice(0, 12)} success`).toBe(r.s.success);
      expect(r.j.returnHex, `cd ${data.slice(0, 12)} data`).toBe(r.s.returnHex);
    }
  });
});
