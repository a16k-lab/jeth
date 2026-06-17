# JETH distinctive features

Raw material for the eventual language documentation. JETH is, by design, a faithful
**subset of Solidity semantics** — the compiler invariant is "zero miscompiles: byte-identical
to solc on returndata, raw storage slots, and event logs." The full Solidity-parity feature
matrix lives in [`../SUPPORTED.md`](../SUPPORTED.md). This file records the things that are
**not** plain Solidity parity: the JETH-only ergonomics, and the two places JETH is actually
*more capable* than the Solidity compiler.

---

## 1. Decorator inference (JETH-only ergonomics)

Solidity makes you spell out a function's visibility and mutability. JETH keeps all of those
explicit decorators (and validates them identically), but adds a compile-time **inference**
layer so devs don't have to think about the distinctions when they don't want to. Every
inferred decorator resolves to a concrete visibility + mutability **before the ABI is emitted**,
so the generated ABI is always the true one. (Verified: an inferred-decorator contract emits a
**byte-identical ABI** to the same contract written with explicit decorators, and is
byte-identical to solc at runtime.)

### `@read` — infer `@pure` vs `@view`

Mark a read-only function `@read` and the compiler computes, from the function's **transitive**
effects, whether it is `@pure` (touches no state and no execution environment) or `@view`
(reads state or `msg.*`/`block.*`/`tx.*`/`address(this)`, but never modifies state).

```ts
@contract class C {
  @state x: u256;
  @read double(a: u256): u256 { return a * 2n; }   // touches nothing  -> @pure
  @read getX(): u256 { return this.x; }            // reads state      -> @view
  @read who(): address { return msg.sender; }      // reads env        -> @view
  @read viaHelper(): u256 { return this.sum(); }   // helper reads x   -> @view (transitive)
  @hidden sum(): u256 { return this.x + 1n; }
}
```

A `@read` function that **modifies state** — writes storage, or **emits an event** (a log is a
state change) — directly or transitively is rejected (`JETH056`). `@read` combined with an
explicit `@view`/`@pure`/`@payable` is a conflict (`JETH052`). Visibility and mutability are
orthogonal, so `@external @read` etc. are fine.

### No visibility decorator — infer `@external` vs `@public`

Omit the visibility decorator entirely and the compiler resolves:

- **`@public`** if the function is ever called internally (`f()` / `this.f()`), since only
  public (or internal/private) functions are callable from inside the contract;
- **`@external`** otherwise (the more gas-efficient choice for call-from-outside-only).

```ts
@contract class C {
  helper(): u256 { return 7n; }              // called below -> @public
  caller(): u256 { return this.helper() + 1n; } // never called internally -> @external
  onlyOut(): u256 { return 42n; }            // never called internally -> @external
}
```

`@public` and `@external` are identical in the ABI and produce identical observable behavior,
so this never changes the contract's interface — only the internal codegen.

### `@hidden` — infer `@internal`

Mark a not-exposed helper `@hidden` and it resolves to `@internal` (excluded from the ABI; you
can still call it internally). Until inheritance lands (Phase 6) `internal` and `private` are
codegen- and ABI-identical, so `internal` is the forward-compatible pick. `@hidden` combined
with an explicit visibility is a conflict (`JETH052`).

```ts
@contract class C {
  @state x: u256;
  @hidden bump(): void { this.x = this.x + 1n; }   // -> @internal, not in the ABI
}
```

### Mixing manual + inferred

All of these compose. A function may infer **both** mutability and visibility:

```ts
@contract class C {
  @state x: u256;
  @read total(): u256 { return this.x + this.base(); } // -> @view, and (if called) @public / else @external
  @hidden base(): u256 { return 100n; }
}
```

Explicit decorators always win and are validated exactly as in Solidity:
`@view` that writes -> `JETH054`, `@pure` that reads -> `JETH055`/`JETH164`, internally calling
an `@external` function -> `JETH240`.

---

## 2. Where JETH is *more capable* than the Solidity compiler

JETH always compiles through Yul (solc's IR pipeline), which schedules the EVM's 1024-slot
operand stack far more efficiently than Solidity's default (legacy) stack-based codegen. Two
consequences — these are the only two places the *same* program behaves better under JETH than
under default Solidity:

### Deeper recursion before EVM stack overflow

Internal-call frames live more compactly, so recursion goes much deeper before exhausting the
1024-slot stack.

```ts
@contract class C {
  @internal @pure rec(n: u256): u256 { if (n == 0n) { return 0n; } return 1n + this.rec(n - 1n); }
  @external @pure run(n: u256): u256 { return this.rec(n); }
}
```

| recursion depth | JETH | Solidity (default) |
|---|---|---|
| 100 / 200 / 300 | 100 / 200 / 300 | 100 / 200 / 300 |
| **400 / 500 / 600** | **400 / 500 / 600** | **REVERT (stack overflow)** |

Solidity overflows around depth ~350; JETH reaches ~1100.

### Never hits "stack too deep"

A function with many simultaneously-live locals compiles in JETH but fails in default Solidity:

```solidity
// Solidity (default codegen): CompilerError: Stack too deep.
function f() external pure returns (uint256) {
    uint256 a0 = 1; /* ...18 more... */ uint256 a19 = 20;
    return a0 + a1 + /* ... */ + a19;
}
```

The identical JETH program compiles with no trouble.

> Caveat (for honesty in the docs): Solidity compiled with `--via-ir` / `viaIR: true` also goes
> through Yul and closes both gaps. The advantage is over Solidity's **default** pipeline — JETH
> gives you the IR-pipeline benefits without needing to remember a flag.

---

## 3. Design note

Everything not listed above is intended to be **observably indistinguishable from Solidity**.
JETH's value proposition is a TypeScript surface syntax with exact Solidity/EVM semantics, plus
the ergonomics in section 1 and the always-on IR codegen in section 2. When in doubt about a
behavior, the rule is: it should match solc byte-for-byte, and a divergence is a bug.
