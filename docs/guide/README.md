# JETH language documentation

JETH is a statically typed smart-contract language for the EVM. Its syntax is a
strict TypeScript-shaped subset, while its values, arithmetic, storage, ABI,
calls, errors, and execution model follow EVM and Solidity semantics.

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

JETH compiles source into typed IR and Yul, then uses solc to optimize and
assemble creation/runtime bytecode. The compiler also emits ABI and storage
layout information.

{% hint style="warning" %}
JETH is pre-release software. The compiler has an extensive differential test
suite and zero known miscompiles at the current revision, but it has not yet
completed the production release and independent audit gates.
{% endhint %}

## How to use this manual

The manual follows the same broad approach as mature language documentation:

- **Start here** provides installation, a first contract, and a short tour.
- **Language description** defines syntax and semantics one topic at a time.
- **Contracts and composition** covers inheritance, modifiers, interfaces,
  external calls, and libraries.
- **Internals** specifies ABI, storage, and compiler artifacts.
- **Advanced systems** documents proxies, beacons, and diamonds.
- **Security** separates contract risks from compiler-correctness claims.
- **Reference** provides a cheatsheet, diagnostics, differences, and limits.

Use the left sidebar or the [full table of contents](SUMMARY.md). The short tour
is optional; the language chapters are the primary documentation.

<table data-view="cards">
  <thead>
    <tr>
      <th></th>
      <th></th>
      <th data-hidden data-card-target data-type="content-ref"></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Learn the language</strong></td>
      <td>Start with contract structure, types, expressions, and functions.</td>
      <td><a href="language/contract-structure.md">language/contract-structure.md</a></td>
    </tr>
    <tr>
      <td><strong>Understand the EVM model</strong></td>
      <td>Read the ABI and storage layout specifications.</td>
      <td><a href="internals/abi.md">internals/abi.md</a></td>
    </tr>
    <tr>
      <td><strong>Build safely</strong></td>
      <td>Review contract risks and the compiler correctness model.</td>
      <td><a href="security/considerations.md">security/considerations.md</a></td>
    </tr>
    <tr>
      <td><strong>Use the compiler</strong></td>
      <td>CLI commands, API fields, diagnostics, artifacts, and caching.</td>
      <td><a href="compiler-and-tooling.md">compiler-and-tooling.md</a></td>
    </tr>
  </tbody>
</table>

## Core ideas

### TypeScript-shaped source, EVM behavior

`u256`, `address`, mappings, storage slots, ABI words, EVM calls, and revert data
are real language concepts. JavaScript `number`, implicit coercion, objects,
promises, and garbage collection do not exist at runtime.

### Native contract syntax

- A bare leaf `class` is a contract.
- A bare field is storage.
- `External<T>` and `Payable<T>` expose ABI entries.
- `Visible<T>` exposes a state getter.
- Ordinary methods are internal.
- A `get` class method is read-only; the analyzer infers `pure` or `view`.
- `static` initialized fields are constants; uninitialized ones are immutables.

### Safety-first compilation

Accepted source must have a sound analyzer and code-generation path. When a
complex copy, location, ABI, or aliasing shape is not proven, JETH rejects it at
compile time. A clean over-rejection is safer than accepted wrong bytecode.

## Read next

- [Installation and first contract](getting-started.md)
- [Source units and imports](language/source-units.md)
- [Structure of a contract](language/contract-structure.md)
- [Types](language/value-types.md)
- [Functions](language/functions.md)
- [Contract ABI](internals/abi.md)
- [Security considerations](security/considerations.md)

## Documentation status

These pages are versioned with the compiler and use GitBook-compatible
navigation. [SUPPORTED.md](../../SUPPORTED.md) remains the exhaustive source-
shape acceptance matrix. Files directly under `docs/` are engineering and audit
records and can describe historical implementation states.
