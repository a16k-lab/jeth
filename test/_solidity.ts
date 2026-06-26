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

// ---- Phase B: external (delegatecall) library linking ----------------------

export type SolLinkReferences = Record<string, Record<string, { start: number; length: number }[]>>;

export interface SolLinkedBuild {
  contractCreation: string; // hex, no 0x (carries `__$..$__` placeholders)
  libraries: { name: string; creation: string }[]; // each library's deployable creation bytecode
  linkReferences: SolLinkReferences; // the contract's creation-bytecode placeholder positions
}

/** Compile a Solidity source that has external `library L { ... public ... }` declarations plus a
 *  `contract C`. Returns the contract's creation bytecode (with `__$..$__` placeholders), each named
 *  library's creation bytecode, and the contract's linkReferences (positions to substitute). The solc
 *  mirror for the JETH external-library tests. */
export function compileSolidityLinked(source: string, contractName: string, libNames: string[]): SolLinkedBuild {
  const input = {
    language: 'Solidity',
    sources: { 'C.sol': { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: 'cancun',
      outputSelection: {
        '*': { '*': ['evm.bytecode.object', 'evm.bytecode.linkReferences'] },
      },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const fatal = (out.errors ?? []).filter((e: any) => e.severity === 'error');
  if (fatal.length) throw new Error('solc(Solidity) failed:\n' + fatal.map((e: any) => e.formattedMessage).join('\n'));
  const c = out.contracts['C.sol'][contractName];
  const libraries = libNames.map((name) => ({ name, creation: out.contracts['C.sol'][name].evm.bytecode.object }));
  return {
    contractCreation: c.evm.bytecode.object,
    libraries,
    linkReferences: (c.evm.bytecode.linkReferences ?? {}) as SolLinkReferences,
  };
}

/** Deploy a solc external-library-linked build (deploy each library, substitute its 20-byte address at
 *  every linkReference position of the contract creation bytecode, deploy the contract). Returns the
 *  contract address. */
export async function deploySolLinked(h: Harness, build: SolLinkedBuild): Promise<Address> {
  const deployed = new Map<string, Address>();
  for (const lib of build.libraries) deployed.set(lib.name, await h.deploy(lib.creation));
  let hex = build.contractCreation.startsWith('0x') ? build.contractCreation.slice(2) : build.contractCreation;
  for (const byLib of Object.values(build.linkReferences)) {
    for (const [libName, positions] of Object.entries(byLib)) {
      const addr = deployed.get(libName);
      if (!addr) throw new Error(`deploySolLinked: no deployed library for '${libName}'`);
      const addrHex = addr.toString().slice(2).padStart(40, '0');
      for (const { start } of positions) {
        const cstart = start * 2;
        hex = hex.slice(0, cstart) + addrHex + hex.slice(cstart + 40);
      }
    }
  }
  return h.deploy(hex);
}
