# JETH

A smart-contract language whose **surface syntax is a strict subset of TypeScript**
but whose **semantics, type system, and memory/state model are the EVM's**
(Solidity-equivalent). Think "AssemblyScript for the EVM." JETH compiles to EVM
bytecode by emitting **Yul** and handing it to `solc`.

## Pipeline

```
.jeth source
  -> ts.createSourceFile (TS syntactic AST)
  -> subset validator        (reject non-EVM constructs, source-span diagnostics)
  -> semantic analyzer       (decorators -> IR metadata, symbol table)
  -> type checker            (JETH types, checked-arith rules, BigInt literals)
  -> storage-layout planner  (Solidity-compatible slots + packing)
  -> Yul emitter             (dispatcher, codecs, checked arithmetic, storage ops)
  -> solc (Yul mode, Cancun) (optimizer + stack scheduler + assembler + JUMPDESTs)
  -> creation + runtime bytecode  +  ABI JSON (emitted by us)
```

## Quick start

```bash
npm install
npx tsx src/cli.ts examples/Counter.jeth --bin --layout --yul
npm test     # compiles Counter, deploys on @ethereumjs/evm, asserts state
```

## Example

```typescript
@contract
class Counter {
  @state count: u256 = 0n;

  @external
  increment(): void {
    this.count += 1n;   // checked uint256 add -> SSTORE at slot 0
  }

  @view
  current(): u256 {
    return this.count;
  }
}
```

`this.count += 1n` is checked 256-bit integer addition with EVM overflow rules
(reverts with `Panic(0x11)`), **not** JS `+`.

## Status

Phases 0-3 are complete and verified on a live EVM with differential tests against
real Solidity (`solc-js`): Phase 0 (frontend + validator), Phase 1 (Counter end-to-end),
Phase 2 (control flow, `require`/`revert`/`Error(string)`/custom errors, events), and
Phase 3 (mappings with keccak slot derivation, `msg.*`/`block.*`/`tx.*` globals, `payable`,
`address(this)`). Returndata, raw storage slots (including keccak-derived mapping slots),
and event logs are asserted byte-identical to Solidity. The directive's `Vault` contract
runs end-to-end. See [SUPPORTED.md](SUPPORTED.md) for the full matrix and roadmap.

## Layout

| Path | Role |
|------|------|
| `src/parser.ts` | TS AST + decorator extraction |
| `src/validator.ts` | Phase 0 subset gate |
| `src/typeresolver.ts` | TS type annotations -> JethType |
| `src/analyzer.ts` | semantic analysis + type checking -> typed IR |
| `src/layout.ts` | Solidity storage-layout planner |
| `src/selectors.ts` | keccak256 signatures + 4-byte selectors |
| `src/yul.ts` | IR -> Yul (codegen, checked arithmetic) |
| `src/solc.ts` | Yul -> bytecode via solc-js |
| `src/abi.ts` | ABI JSON from IR |
| `src/compile.ts` | pipeline orchestrator |
| `src/evm.ts` | @ethereumjs/evm execution harness |
| `src/cli.ts` | `jethc` CLI |
```
