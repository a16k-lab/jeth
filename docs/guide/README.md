# ![JETH orange logo](../../assets/jeth/jeth-orange-icon-32.png) JETH language documentation

<p class="a16k-lockup">
  <a href="https://github.com/a16k-lab">
    <img src="../assets/a16k-avatar-logo.png" width="28" height="28" alt="a16k-lab logo" align="middle">
    Built by <strong>@a16k-lab</strong>
  </a>
</p>

JETH is a statically typed smart-contract language for the EVM. Its syntax is a
strict TypeScript-shaped subset, while its values, arithmetic, storage, ABI,
calls, errors, and execution model follow EVM and Solidity semantics.

```jeth
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

JETH compiles source into typed IR and Yul, then uses solc to optimize and
assemble creation/runtime bytecode. The compiler also emits ABI and storage
layout information.

> [!WARNING] JETH is pre-release software. The compiler has an extensive
> differential test suite and zero known miscompiles at the current revision,
> but it has not completed the production release and independent audit gates.

## Guides

The HTML book is organized as a structured language manual:

- **Start here:** installation, a first contract, a language tour, and examples.
- **Language:** declarations, contract structure, types, locations,
  expressions, control flow, functions, globals, and JETH-specific features.
- **Contracts:** inheritance, private members, modifiers, interfaces, calls,
  libraries, events, errors, and panics.
- **Internals:** ABI encoding, storage layout, compiler APIs, CLI behavior, and
  artifacts.
- **Advanced:** contract creation, CREATE2 clones, proxies, beacons, diamonds,
  facets, and namespaced storage.
- **Security:** smart-contract risks and the compiler-correctness model.
- **Reference:** syntax, differences, diagnostics, supported paths, and limits.

The short tour is optional. The detailed language chapters are the primary
documentation.

## Recommended path

1. [Installation and first contract](getting-started.md)
2. [Structure of a contract](language/contract-structure.md)
3. [Value types](language/value-types.md)
4. [Reference and composite types](language/reference-types.md)
5. [Expressions and operators](language/expressions.md)
6. [Statements and control flow](language/control-flow.md)
7. [Functions](language/functions.md)
8. [Interfaces and external calls](language/interfaces-and-calls.md)
9. [Contract ABI](internals/abi.md)
10. [Storage layout](internals/storage-layout.md)
11. [Contract creation and clones](advanced/contract-creation-and-clones.md)
12. [Security considerations](security/considerations.md)

## Core ideas

### TypeScript-shaped source, EVM behavior

`u256`, `address`, mappings, storage slots, ABI words, EVM calls, and revert data
are real language concepts. JavaScript `number`, implicit coercion, objects,
promises, and garbage collection do not exist at runtime.

### Native contract syntax

- A bare leaf `class` is a contract.
- A bare field is storage.
- A leading `#` makes a field or method private to its declaring class.
- `External<T>` and `Payable<T>` expose ABI entries.
- `Visible<T>` exposes a state, constant, or immutable getter.
- Ordinary methods are internal.
- A `get` class method is read-only; the analyzer infers `pure` or `view`.
- A `static` method is declared pure.
- Initialized `static` fields are constants; uninitialized ones are immutables.

### Safety-first compilation

Accepted source must have a sound analyzer and code-generation path. When a
complex copy, location, ABI, or aliasing shape is not proven, JETH rejects it at
compile time. A clean over-rejection is safer than accepted wrong bytecode.

## HTML book

Run the local documentation build:

```bash
npm run docs:build
```

Open `docs/book/index.html` directly or serve `docs/book/` with any static HTTP
server. The output has structured Guides navigation, search, light/dark themes,
responsive pages, and a dedicated `.jeth` highlighter. It has no hosted
documentation runtime dependency.

## Documentation status

These pages are versioned with the compiler. [SUPPORTED.md](../../SUPPORTED.md)
remains the exhaustive source-shape acceptance matrix. Files directly under
`docs/` are engineering and audit records and can describe historical
implementation states.
