# JETH

JETH is a smart-contract language with a strict TypeScript-shaped syntax and
Solidity-compatible EVM semantics. It compiles JETH source to typed IR, Yul,
ABI metadata, and EVM bytecode through `solc`.

The project follows one non-negotiable compiler rule: a clean rejection is
better than accepted code that produces the wrong behavior. Accepted programs
are tested against Solidity 0.8.35 at deployment and runtime, including return
data, revert data, event logs, and raw storage slots.

> JETH is pre-release software. It has a large differential test suite and zero
> known miscompiles at the current revision, but it has not yet completed an
> independent production security audit or a stable public release process. Do
> not treat it as production-ready until the release gates below are complete.

## Why JETH

- Familiar TypeScript-shaped syntax without JavaScript runtime semantics.
- Checked EVM arithmetic, Solidity-compatible storage, ABI, and revert behavior.
- Compile-time mutability inference and a deliberately small visibility model.
- Branded value types, exhaustive switches, generics, named/default arguments,
  struct spread, `for...of`, and an EIP-1153 `@nonReentrant` guard.
- Native support for interfaces, inheritance, libraries, proxies, beacons, and
  multiple EIP-2535 diamond storage models.
- A safety-first compiler policy: unsupported shapes must fail loudly at compile
  time instead of falling through to partial code generation.

## Quick start

JETH currently requires Node.js 22 and uses the compiler directly from the
repository.

```bash
npm install
npm run build
npm run jethc -- examples/Counter.jeth --abi --bin --layout
npm test
```

Write compiler artifacts to a directory:

```bash
npm run jethc -- examples/Counter.jeth -o build/
```

The public package and standalone binary are roadmap items. Until they ship,
the repository command above is the supported entry point.

## A first contract

```typescript
class Counter {
  count: u256 = 0n;

  increment(): External<void> {
    this.count += 1n;
  }

  get current(): External<u256> {
    return this.count;
  }
}
```

A bare class is a deployed contract. A bare field is contract storage.
`External<T>` exposes a method through the ABI, while `get` marks a read-only
value-returning entry. The compiler infers whether that entry is `pure` or
`view`.

`this.count += 1n` is checked `uint256` arithmetic. It reverts with
`Panic(0x11)` on overflow; it is not JavaScript addition.

## Current status

The current compiler supports a broad Solidity-compatible surface:

- value types, enums, branded newtypes, arrays, mappings, structs, tuples,
  bytes, strings, events, custom errors, and checked/unchecked arithmetic;
- constructors, immutable fields, modifiers, inheritance, abstract contracts,
  interfaces, internal and externally linked libraries;
- ABI v2 encoding and decoding, external calls, `try`/`catch`, calldata slices,
  hashing, signature recovery, and EVM precompiles;
- EIP-1167 clones, ERC-1967 and transparent proxies, UUPS, beacons, and three
  EIP-2535 diamond storage models;
- compile-time generics, exhaustive switches, named/default arguments, struct
  spread, `for...of`, mutability inference, and transient-storage reentrancy
  protection.

The full acceptance matrix and every deliberate compile-time gate live in
[SUPPORTED.md](SUPPORTED.md). JETH currently has more than 5,000 tests across
502 test files, with extensive runtime differential checks against solc 0.8.35.
Test count alone is not a security audit; the production gates below remain
mandatory.

## Documentation

Public language documentation lives in [docs/guide](docs/guide/README.md):

- [Getting started](docs/guide/getting-started.md)
- [Source units and imports](docs/guide/language/source-units.md)
- [Structure of a contract](docs/guide/language/contract-structure.md)
- [Types and data locations](docs/guide/language-reference.md)
- [Expressions and control flow](docs/guide/language/expressions.md)
- [Functions and composition](docs/guide/language/functions.md)
- [Contract ABI specification](docs/guide/internals/abi.md)
- [Storage layout](docs/guide/internals/storage-layout.md)
- [Examples](docs/guide/examples.md)
- [Security considerations](docs/guide/security/considerations.md)
- [Compiler correctness model](docs/guide/security/compiler-correctness.md)
- [Compiler and tooling](docs/guide/compiler-and-tooling.md)
- [Product roadmap](docs/guide/roadmap.md)

The existing files directly under `docs/` are engineering design notes, audit
records, and implementation specifications. They support compiler development
but are not the recommended learning path.

## Roadmap to a production release

The detailed roadmap is maintained in [docs/guide/roadmap.md](docs/guide/roadmap.md).
The short version is ordered by release risk, not novelty.

### 1. Productize the compiler and CLI

- Publish a real `jethc` package and standalone binary with a stable versioned
  command surface.
- Add project builds, multi-file input, a config file, incremental/watch mode,
  deterministic artifact directories, and a content-addressed compile cache.
- Add structured JSON diagnostics, stable exit codes, standard JSON input/output,
  source maps, contract selection, optimizer/EVM target controls, and dependency
  metadata.
- Integrate with Foundry, Hardhat, deployment scripts, explorer verification,
  editor diagnostics, and an LSP.

### 2. Preserve the correctness bar while expanding the language

- Continue differential and adversarial testing for every accepted source shape.
- Squash high-value over-rejections only when the lifted path is proven at
  deploy, run, and decode time. A safe reject remains preferable to a speculative
  lift.
- Strengthen analyzer reachability, aliasing, data-location, ABI, storage-layout,
  and optimizer invariants with generated conformance tests.
- Add the remaining useful compiler features from `SUPPORTED.md`, with priority
  based on real contract demand instead of surface-area counts.
- Build optimizer validation around semantic equivalence, gas snapshots, and
  reproducible before/after artifacts.

### 3. Build a local AI-assisted verification lab

- Use an offline model as a test and exploit-candidate proposer, never as the
  source of truth for compiler correctness or contract safety.
- Pair it with deterministic parsers, the JETH analyzer, solc 0.8.35, deploy/run
  differential oracles, fuzzers, and minimized reproducible witnesses.
- First collect a high-quality corpus of accepted/rejected parity cases, known
  compiler bugs, diagnostics, and reductions. Fine-tune only after the dataset
  and evaluation harness are stable.
- Require every model-generated claim to produce executable evidence. Security
  findings without a reproducer remain hypotheses.

### 4. Ship safe numerical libraries as separately audited packages

- Start with integer utilities, full-precision `mulDiv`, fixed-point types,
  explicit rounding modes, unit/range types, bounds, and domain checks.
- Treat transcendental functions, numerical integration, differentiation, and
  approximation as error-bounded algorithms with explicit precision and gas
  contracts.
- Prefer compile-time symbolic simplification where possible. EVM runtime math
  must never pretend to have floating-point or real-number semantics.
- Keep the math package separate from the compiler core and audit it independently.
  Avoid claims such as "super safe" until a precise threat model and external
  review support them.

### 5. Complete the release and security system

- Define semantic versioning, changelogs, migration notes, compatibility policy,
  and a frozen language-spec version for each compiler release.
- Produce reproducible builds, signed release artifacts, checksums, an SBOM, and
  provenance through CI.
- Add a public security policy, private disclosure channel, bug bounty, external
  compiler audit, standard-library audits, and an incident-response process.
- Maintain a public conformance corpus and a machine-readable list of supported
  features and deliberate rejection gates.
- Resolve release metadata before publication, including the current mismatch
  between the GPLv3 `LICENSE` file and the `MIT` value in `package.json`.

## Compiler pipeline

```text
.jeth source
  -> TypeScript syntactic AST
  -> subset validator and diagnostics
  -> semantic analyzer and type checker
  -> Solidity-compatible storage planner
  -> typed JETH IR
  -> Yul emitter and ABI generator
  -> solc in Yul mode
  -> creation bytecode, runtime bytecode, ABI, layout, and link references
```

| Path | Responsibility |
| --- | --- |
| `src/parser.ts` | Source parsing and JETH syntax extraction |
| `src/validator.ts` | TypeScript-subset validation |
| `src/typeresolver.ts` | Source annotations to JETH types |
| `src/analyzer.ts` | Semantic analysis and typed IR construction |
| `src/layout.ts` | Solidity-compatible storage planning |
| `src/abi.ts` | ABI metadata generation |
| `src/yul.ts` | Yul generation, codecs, arithmetic, and storage operations |
| `src/solc.ts` | Yul compilation through solc-js |
| `src/compile.ts` | Pipeline and multi-artifact orchestration |
| `src/evm.ts` | Local EVM execution harness |
| `src/cli.ts` | Current `jethc` command-line entry |

## Development checks

```bash
npm run build
npm test
npm run format:check
```

Compiler changes should include focused regression pins and, when behavior has a
Solidity equivalent, deploy/run/decode comparisons against solc. The suite should
also pass with shuffled test-file order to detect hidden global state and flakes.

## License

See [LICENSE](LICENSE). The repository must resolve the license identifier mismatch
in `package.json` before the first public package release.
