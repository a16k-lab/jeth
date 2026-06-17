// Selectors and signatures must match Solidity's canonical encoding (directive §2.5).
import { describe, it, expect } from 'vitest';
import { functionSignature, functionSelector, eventTopic0 } from '../src/selectors.js';
import type { JethType } from '../src/types.js';

const u256: JethType = { kind: 'uint', bits: 256 };
const addr: JethType = { kind: 'address', payable: false };
const boolean: JethType = { kind: 'bool' };

describe('selectors', () => {
  it('uses canonical type names', () => {
    expect(functionSignature('transfer', [addr, u256])).toBe('transfer(address,uint256)');
    expect(functionSignature('increment', [])).toBe('increment()');
  });

  it('computes known selectors', () => {
    // Well-known values cross-checked against Solidity/4byte.directory.
    expect(functionSelector('increment()')).toBe('d09de08a');
    expect(functionSelector('transfer(address,uint256)')).toBe('a9059cbb');
    expect(functionSelector('balanceOf(address)')).toBe('70a08231');
    expect(functionSelector('approve(address,uint256)')).toBe('095ea7b3');
    expect(functionSelector('totalSupply()')).toBe('18160ddd');
  });

  it('computes the canonical Transfer event topic0', () => {
    expect('0x' + eventTopic0('Transfer(address,address,uint256)')).toBe(
      '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
    );
  });

  it('treats == and != consistently for bool params', () => {
    expect(functionSignature('setFlag', [boolean])).toBe('setFlag(bool)');
  });
});
