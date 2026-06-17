// ABI signatures, keccak256, and 4-byte function selectors (directive §2.5).
import { keccak256 } from 'ethereum-cryptography/keccak.js';
import type { JethType } from './types.js';
import { canonicalName } from './types.js';

const enc = new TextEncoder();

export function keccak(data: Uint8Array | string): Uint8Array {
  return keccak256(typeof data === 'string' ? enc.encode(data) : data);
}

export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/** Canonical function signature, e.g. "transfer(address,uint256)". */
export function functionSignature(name: string, paramTypes: JethType[]): string {
  return `${name}(${paramTypes.map(canonicalName).join(',')})`;
}

/** 4-byte selector hex (no 0x), keccak256(signature)[0:4]. */
export function functionSelector(signature: string): string {
  return toHex(keccak(signature).slice(0, 4));
}

/** keccak256(signature) full 32-byte topic hash hex (no 0x), for event topic0. */
export function eventTopic0(signature: string): string {
  return toHex(keccak(signature));
}
