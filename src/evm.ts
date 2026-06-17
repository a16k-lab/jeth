// In-process EVM execution harness (directive §7: execute on @ethereumjs/evm).
// Deploy creation bytecode, then drive the runtime with raw calldata. Includes
// just enough ABI helpers for tests; the real ABI codec lives in codegen.
import { createEVM, type EVM } from '@ethereumjs/evm';
import { Address, hexToBytes, bytesToHex, createAccount } from '@ethereumjs/util';
import { createBlock, type Block } from '@ethereumjs/block';
import { createCustomCommon, Mainnet, type Common } from '@ethereumjs/common';

/** Build a 0x-prefixed hex string with the literal type @ethereumjs/util wants. */
function hx(s: string): `0x${string}` {
  return ('0x' + strip0x(s)) as `0x${string}`;
}

const DEFAULT_CALLER = new Address(hexToBytes(hx('11'.repeat(20))));

/** A Common with a custom chainId (drives the CHAINID opcode), cancun hardfork. */
export function customCommon(chainId: number): Common {
  return createCustomCommon({ chainId }, Mainnet, { hardfork: 'cancun' });
}

export interface BlockEnv {
  number?: bigint;
  timestamp?: bigint;
  coinbase?: Address;
  gasLimit?: bigint;
  baseFeePerGas?: bigint;
  prevRandao?: Uint8Array; // 32 bytes (block.prevrandao)
}

/** Build a Block carrying custom block.* environment fields. */
export function makeBlock(env: BlockEnv, common?: Common): Block {
  return createBlock(
    {
      header: {
        number: env.number ?? 0n,
        timestamp: env.timestamp ?? 0n,
        coinbase: env.coinbase ?? new Address(hexToBytes(hx('00'.repeat(20)))),
        gasLimit: env.gasLimit ?? 30_000_000n,
        baseFeePerGas: env.baseFeePerGas ?? 0n,
        difficulty: 0n,
        mixHash: env.prevRandao ?? hexToBytes(hx('00'.repeat(32))),
      },
    },
    { common, skipConsensusFormatValidation: true },
  );
}

export interface LogEntry {
  topics: string[]; // 0x-prefixed topic hex (topic0 first)
  data: string; // 0x-prefixed data hex
}

export interface CallResult {
  success: boolean; // false if the call reverted / errored
  returnHex: string; // returndata, 0x-prefixed
  returnValue: Uint8Array;
  gasUsed: bigint;
  logs: LogEntry[]; // events emitted during the call, in order
  exceptionError?: string;
}

export class Harness {
  private constructor(public readonly evm: EVM) {}

  static async create(common?: Common): Promise<Harness> {
    return new Harness(await createEVM(common ? { common } : undefined));
  }

  /** Seed an account's balance (needed before sending value via call). */
  async fund(addr: Address, balance: bigint): Promise<void> {
    await this.evm.stateManager.putAccount(addr, createAccount({ balance }));
  }

  /** Deploy creation bytecode, returning the deployed address. */
  async deploy(creationHex: string, opts: { caller?: Address; value?: bigint } = {}): Promise<Address> {
    const res = await this.evm.runCall({
      data: hexToBytes(hx(creationHex)),
      caller: opts.caller ?? DEFAULT_CALLER,
      value: opts.value ?? 0n,
      gasLimit: 10_000_000n,
    });
    if (res.execResult.exceptionError) {
      throw new Error(`deployment reverted: ${res.execResult.exceptionError.error}`);
    }
    if (!res.createdAddress) throw new Error('deployment produced no address');
    return res.createdAddress;
  }

  /** Call a deployed contract with raw calldata. `origin`/`block` set the
   *  tx.origin and block.* environment; a non-zero `value` auto-funds the caller. */
  async call(
    to: Address,
    dataHex: string,
    opts: {
      caller?: Address;
      value?: bigint;
      gasLimit?: bigint;
      origin?: Address;
      block?: Block;
    } = {},
  ): Promise<CallResult> {
    const caller = opts.caller ?? DEFAULT_CALLER;
    const value = opts.value ?? 0n;
    if (value > 0n) await this.fund(caller, value + 10n ** 18n); // cover value + gas
    const res = await this.evm.runCall({
      to,
      data: hexToBytes(hx(dataHex)),
      caller,
      origin: opts.origin,
      value,
      gasLimit: opts.gasLimit ?? 5_000_000n,
      block: opts.block,
    });
    const rv = res.execResult.returnValue;
    // logs are [address, topics[], data] tuples (all Uint8Array)
    const rawLogs = (res.execResult.logs ?? []) as [Uint8Array, Uint8Array[], Uint8Array][];
    const logs: LogEntry[] = rawLogs.map(([, topics, data]) => ({
      topics: topics.map((t) => bytesToHex(t)),
      data: bytesToHex(data),
    }));
    return {
      success: !res.execResult.exceptionError,
      returnHex: bytesToHex(rv),
      returnValue: rv,
      gasUsed: res.execResult.executionGasUsed,
      logs,
      exceptionError: res.execResult.exceptionError?.error,
    };
  }
}

function strip0x(s: string): string {
  return s.startsWith('0x') ? s.slice(2) : s;
}

// ---- minimal ABI helpers for tests --------------------------------------

export function pad32(value: bigint): string {
  let x = value % (1n << 256n);
  if (x < 0n) x += 1n << 256n;
  return x.toString(16).padStart(64, '0');
}

/** Build calldata: 4-byte selector + 32-byte-padded static words. */
export function encodeCall(selectorHex: string, words: bigint[] = []): string {
  return '0x' + strip0x(selectorHex) + words.map(pad32).join('');
}

/** Decode a single 32-byte word from returndata as an unsigned bigint. */
export function decodeUint(returnHex: string): bigint {
  const h = strip0x(returnHex);
  return h.length === 0 ? 0n : BigInt('0x' + h.slice(0, 64));
}

/** Decode a single 32-byte word as a signed (two's complement) bigint. */
export function decodeInt(returnHex: string): bigint {
  const u = decodeUint(returnHex);
  return u >= 1n << 255n ? u - (1n << 256n) : u;
}
