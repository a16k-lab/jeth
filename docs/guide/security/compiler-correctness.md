# Compiler correctness model

JETH uses a safety-first acceptance policy because a compiler can successfully
produce bytecode that is still wrong.

## Bug classes

### Miscompile (MC)

JETH accepts source but generated behavior differs from the intended or
Solidity-equivalent behavior. This includes wrong return/revert bytes, storage,
logs, control flow, calls, or deployment behavior.

### Over-acceptance (OA)

JETH accepts source that should be rejected by the language or parity target. An
OA is dangerous because it can expose a code-generation path that was never
soundly implemented.

### Over-rejection (OR)

JETH rejects a valid source shape. This limits expressiveness but is safer than
wrong bytecode. ORs should be lifted only with end-to-end proof.

### Flake

A test result depends on order, time, shared state, random seed, environment, or
race behavior instead of the source under test.

## Differential evidence

For a Solidity-overlapping feature, a strong test:

1. creates equivalent JETH and Solidity sources;
2. compiles both with pinned toolchains;
3. deploys both on the same EVM configuration;
4. executes success and failure paths;
5. compares return and revert bytes;
6. compares event topics/data;
7. compares relevant raw storage slots;
8. covers boundaries and malformed calldata;
9. preserves a deterministic witness.

"Both compile" is not sufficient evidence.

## Clean rejection

When the analyzer cannot prove a storage copy, ABI transcode, aliasing behavior,
or control-flow shape sound, it emits a diagnostic before Yul generation.

Unsupported IR should not silently reach a partial lowering. Backend guards are
the final defense, not a substitute for analyzer admission checks.

## Test order and seeds

The suite runs in deterministic and shuffled file order to detect leaked compiler
state. Random campaigns must record their seed and minimize failures into focused
pins.

## Meaning of zero known miscompiles

This statement means no unresolved witness exists in the current corpus at a
specific revision. It does not prove the absence of unknown bugs. It must be
scoped by compiler revision, solc version, EVM target, and audit coverage.

## AI-assisted auditing

An offline model can propose programs, mutations, invariants, and bug hypotheses.
The model is not the oracle. JETH, solc, a local EVM, deterministic comparisons,
and human root-cause review decide whether a finding is real.

## Release bar

A production compiler release needs:

- no unresolved known MC or OA;
- documented deliberate ORs;
- normal and shuffled suite passes;
- reproducible build artifacts;
- stable diagnostics/artifact schemas;
- source maps and debugging support;
- independent audit and disclosure process;
- an exact compatibility statement.
