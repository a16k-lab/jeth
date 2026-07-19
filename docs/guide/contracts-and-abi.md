# Contracts and ABI

## Artifacts

The compiler can produce:

- creation bytecode;
- runtime bytecode;
- ABI JSON;
- generated Yul;
- storage layout;
- multiple contract and library artifacts;
- link references for external libraries.

The current CLI writes basic artifact files. A stable artifact manifest, standard
JSON mode, source maps, metadata, and build-info files are roadmap items.

## ABI exposure

```typescript
class C {
  value: Visible<u256>;

  helper(x: u256): u256 { return x + 1n; }
  set(x: u256): External<void> { this.value = x; }
  get read(): External<u256> { return this.value; }
  deposit(): Payable<void> { this.value += msg.value; }
}
```

- `Visible<T>` creates a public state getter where the underlying shape is
  supported.
- `External<T>` creates a nonpayable ABI function.
- `Payable<T>` creates a payable ABI function.
- Internal functions do not appear in the ABI.
- Read-only class methods use `get`; the analyzer infers `pure` or `view`.

Selectors use canonical Solidity ABI signatures. Branded types erase to their
base types for selectors and ABI data.

## ABI validation

Accepted calldata is decoded with Solidity-compatible bounds and dirty-bit
checks. Invalid narrow integers, booleans, addresses, enums, offsets, lengths, or
aggregate layouts reject according to the supported path. Dynamic return values
use ABI v2 head/tail encoding.

The test suite compares execution behavior with solc, including return and revert
bytes. Complex source shapes are accepted only when the relevant location and
consumer path has a verified codec.

## Storage layout

JETH plans Solidity-compatible slots and packed lanes. This includes value types,
structs, fixed and dynamic arrays, mappings, dynamic bytes/string storage, and
supported nested combinations.

Storage correctness is checked with raw-slot differential tests, not only getter
results. This matters because two contracts can return the same value while
laying out upgradeable state incompatibly.

Before using JETH in an upgradeable system:

1. Save the storage layout artifact for every release.
2. Diff slot, offset, and type changes.
3. Use explicit namespaced storage where the architecture requires it.
4. Test upgrades against existing state.
5. Treat compiler-version changes as storage-sensitive until proven otherwise.

## Libraries and linking

Internal library functions are inlined. External library functions compile to
separate artifacts and use `DELEGATECALL` with link references. A deployment
system must deploy libraries, patch every reference with the correct address,
and preserve the compiler's artifact-to-reference mapping.

## Proxies and diamonds

JETH includes generated patterns for clones, ERC-1967 proxies, transparent
proxies, UUPS, beacons, and EIP-2535 diamonds. Generated support does not remove
the application-level risks of authorization, initialization, selector clashes,
storage collisions, unsafe upgrades, or compromised owners.

Read the matching engineering specs and execute end-to-end upgrade tests before
using these patterns. Production use also requires independent review.

## Compatibility contract

The intended compatibility target is behavioral parity with Solidity 0.8.35 for
overlapping supported programs. The public release process still needs a frozen
language version, compiler compatibility policy, standard artifact schema, and
documented EVM-target policy.
