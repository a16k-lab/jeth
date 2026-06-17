// Test-only helper: compile reference Solidity with the same solc-js the compiler
// uses, for differential testing (directive §7).
import solc from 'solc';
import { setLengthLeft, hexToBytes, bytesToHex, type Address } from '@ethereumjs/util';
import type { Harness } from '../src/evm.js';

export interface SolBuild {
  creation: string; // hex, no 0x
  storageLayout: { label: string; slot: string; offset: number; type: string }[];
}

export function compileSolidity(source: string, contractName: string): SolBuild {
  const input = {
    language: 'Solidity',
    sources: { 'C.sol': { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: 'cancun',
      outputSelection: { '*': { '*': ['evm.bytecode.object', 'storageLayout'] } },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const fatal = (out.errors ?? []).filter((e: any) => e.severity === 'error');
  if (fatal.length) throw new Error('solc(Solidity) failed:\n' + fatal.map((e: any) => e.formattedMessage).join('\n'));
  const c = out.contracts['C.sol'][contractName];
  return {
    creation: c.evm.bytecode.object,
    storageLayout: (c.storageLayout?.storage ?? []).map((s: any) => ({
      label: s.label,
      slot: s.slot,
      offset: s.offset,
      type: s.type,
    })),
  };
}

/** Read a raw 32-byte storage slot as a 0x-prefixed hex string. */
export async function readSlot(h: Harness, addr: Address, slot: bigint): Promise<string> {
  const key = setLengthLeft(hexToBytes(('0x' + slot.toString(16)) as `0x${string}`), 32);
  const v = await h.evm.stateManager.getStorage(addr, key);
  return bytesToHex(setLengthLeft(v, 32));
}
