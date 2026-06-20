// Emit the contract ABI JSON ourselves from the analyzer's IR (directive §3.3:
// "You emit the ABI JSON yourself"). solc never sees JETH types, so we are the
// source of truth for signatures.
import type { ContractIR, FunctionIR, ErrorDecl, EventIR } from './ir.js';
import { canonicalName, JethType } from './types.js';

export interface AbiParameter {
  name: string;
  type: string;
  internalType?: string;
}
export interface AbiEventInput extends AbiParameter {
  indexed: boolean;
}
export interface AbiFunction {
  type: 'function';
  name: string;
  inputs: AbiParameter[];
  outputs: AbiParameter[];
  stateMutability: 'pure' | 'view' | 'nonpayable' | 'payable';
}
export interface AbiConstructor {
  type: 'constructor';
  inputs: AbiParameter[];
  stateMutability: 'nonpayable' | 'payable';
}
export interface AbiError {
  type: 'error';
  name: string;
  inputs: AbiParameter[];
}
export interface AbiEvent {
  type: 'event';
  name: string;
  inputs: AbiEventInput[];
  anonymous: false;
}

export type AbiItem = AbiFunction | AbiConstructor | AbiError | AbiEvent;

function param(name: string, t: JethType): AbiParameter {
  return { name, type: canonicalName(t), internalType: canonicalName(t) };
}

function fnAbi(fn: FunctionIR): AbiFunction {
  const outputs = fn.returnTypes
    ? fn.returnTypes.map((t) => param('', t))
    : fn.returnType.kind === 'void'
      ? []
      : [param('', fn.returnType)];
  return {
    type: 'function',
    name: fn.name,
    inputs: fn.params.map((p) => param(p.name, p.type)),
    outputs,
    stateMutability: fn.mutability,
  };
}

function errorAbi(e: ErrorDecl): AbiError {
  return { type: 'error', name: e.name, inputs: e.params.map((p) => param(p.name, p.type)) };
}

function eventAbi(ev: EventIR): AbiEvent {
  return {
    type: 'event',
    name: ev.name,
    inputs: ev.params.map((p) => ({ ...param(p.name, p.type), indexed: p.indexed })),
    anonymous: false,
  };
}

function ctorAbi(c: NonNullable<ContractIR['ctor']>): AbiConstructor {
  return {
    type: 'constructor',
    inputs: c.params.map((p) => param(p.name, p.type)),
    stateMutability: c.payable ? 'payable' : 'nonpayable',
  };
}

export function emitAbi(contract: ContractIR): AbiItem[] {
  return [
    ...(contract.ctor ? [ctorAbi(contract.ctor)] : []),
    ...contract.functions
      .filter((f) => f.visibility === 'external' || f.visibility === 'public')
      .map(fnAbi),
    ...contract.errors.map(errorAbi),
    ...contract.events.map(eventAbi),
  ];
}
