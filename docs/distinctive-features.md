# JETH distinctive features

Raw material for the eventual language documentation. JETH is, by design, a faithful
**subset of Solidity semantics**: the compiler invariant is "zero miscompiles: byte-identical
to solc on returndata, raw storage slots, and event logs." The full Solidity-parity feature
matrix lives in [`../SUPPORTED.md`](../SUPPORTED.md). This file records the things that are
**not** plain Solidity parity: the JETH-only ergonomics, and the two places JETH is actually
*more capable* than the Solidity compiler.

---

## 1. Decorator inference (JETH-only ergonomics)

Solidity makes you spell out every function's visibility and mutability. JETH simplifies the
visibility surface to a single `@external` (everything else is internal - see below) and adds a
compile-time mutability **inference** so devs don't have to choose `@pure` vs `@view`. The inferred
`@read` resolves to a concrete mutability **before the ABI is emitted**, so the generated ABI is
always the true one. (Verified: a `@read` contract emits a **byte-identical ABI** to the same
contract written with explicit `@view`/`@pure`, and is byte-identical to solc at runtime.)

### `@read`: infer `@pure` vs `@view`

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

A `@read` function that **modifies state** (writes storage, or **emits an event**, since a log is a
state change) directly or transitively is rejected (`JETH056`). `@read` combined with an
explicit `@view`/`@pure`/`@payable` is a conflict (`JETH052`). Visibility and mutability are
orthogonal, so `@external @read` etc. are fine.

### Visibility: `@external` exposes, everything else is internal

JETH has exactly **one** visibility decorator, `@external`: it places a function in the ABI and the
dispatcher. A function with **no** visibility decorator is **internal** - callable by name (`f()` /
`this.f()`), absent from the ABI, and not reachable from outside. A function is therefore either
externally exposed (`@external`, and NOT callable internally - that would be a message call) or
internal (callable by name) - never both. This keeps the surface minimal and the call-vs-message-call
boundary explicit, a deliberate safer-than-Solidity subset.

```ts
@contract class C {
  @state x: u256;
  helper(): u256 { return this.x; }                // no @external -> internal, not in the ABI
  @external get(): u256 { return this.helper(); }   // @external -> in the ABI; calls the internal helper
}
```

`@public`, `@private`, `@internal`, and `@hidden` are rejected (`JETH054`); the compiler decides
internal-vs-private itself (codegen-identical until inheritance lands). Calling an `@external` function
internally is rejected (`JETH240`): expose an `@external` entry and have any internal caller go through
a shared internal helper instead.

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

## 2. Branded newtypes (JETH-only ergonomics)

`type X = Brand<Base>` declares a distinct **nominal** value type over a value `Base` (any
`uintN` / `intN` / `bool` / `address` / `bytesN`). The brand is a **compile-time tag only**:
it is fully **erased** at codegen, ABI, and selector level, so a branded contract is
byte-identical to the same contract written with the plain base. (Verified: a branded
contract compiles to **byte-identical creation bytecode and ABI** as the plain-base version,
and is byte-identical to solc at runtime, including raw storage slots and event logs. This is
the same idea as Solidity's `type X is uint256` user-defined value types, with lighter syntax.)

```ts
type TokenId = Brand<u256>;
type Wei     = Brand<u256>;

@contract class C {
  @state owner: mapping<TokenId, address>;          // branded key, slot layout == mapping<u256,...>
  @external setOwner(id: TokenId, o: address): void { this.owner[id] = o; } // selector: setOwner(uint256,address)
  @external @pure addWei(a: Wei, b: Wei): Wei { return a + b; }             // same-brand math keeps the brand
  @external @pure wrap(x: u256): TokenId { return TokenId(x); }             // explicit wrap
  @external @pure unwrap(id: TokenId): u256 { return u256(id); }            // explicit unwrap
}
```

**Nominal identity is enforced.** Two different brands, or a brand versus its bare base, are
**not** implicitly convertible: you must wrap (`TokenId(x)`) or unwrap (`u256(t)`) explicitly.
Mixing a `TokenId` with a `UserId`, or a `TokenId` with a plain `u256`, is a type error
(`JETH083` / `JETH085`). This holds for **every** base kind, addresses included. Same-brand
operands keep the brand under binary ops (so `a + b` of two `Wei` is a `Wei`), and a numeric
literal retypes to the branded operand (so `id + 1n` works). The brand has **zero runtime
cost**: it exists only in the type checker.

Use it for the usual unit-confusion bugs: token ids that should never be mixed with balances,
wei versus gwei, two different address roles, opaque handles. `Brand<...>` may only appear in a
named alias (`JETH015` on inline use), and the base must be a value type (a `Brand` over a
mapping / array / struct is rejected).

## 3. Ergonomics, control flow, and safety (F2-F6)

Features that Solidity has no syntax for, each either a pure compile-time desugaring into constructs
the compiler already emits byte-for-byte against solc (so they carry zero new runtime semantics) or
a thin, audited piece of codegen. This section collects: struct spread and `for...of` (F2), default
and named arguments (F3), the `@nonReentrant` guard (F4), exhaustive `switch` (F5), and generics
(F6). (Enums, also added in the F5 work, are plain Solidity-parity and live in
[`../SUPPORTED.md`](../SUPPORTED.md), not here.)

### Immutable struct update with spread

`{ ...base, field: value }` builds a new struct that copies `base` and overrides the named
fields. It desugars to the exact same construction as positional `StructName(...)`, so codegen,
ABI, and storage layout are identical.

```ts
@struct class Config { fee: u16; recipient: address; paused: bool; }

@contract class C {
  @state cfg: Config;
  @external setFee(f: u16): void { this.cfg = { ...this.cfg, fee: f }; }       // update one field
  @external pause(): void { this.cfg = { ...this.cfg, paused: !this.cfg.paused }; }
  @external @pure make(r: address): Config { return { fee: 0n, recipient: r, paused: false }; } // full literal
}
```

The `this.cfg = { ...this.cfg, fee: f }` form reads the old value and writes the new one with the
same observable result as Solidity's `Config memory c = cfg; c.fee = f; cfg = c;`, including
identical packed-slot bytes. Scoped to structs whose fields are all value types (the immutable
config/position pattern); structs with nested, dynamic, or array fields still use positional
`StructName(...)`. Object-literal construction needs the target struct type to be known from
context (a return type, an annotated local, an assignment target, or a call argument).

### `for...of` over arrays

`for (const v of xs) { ... }` iterates an array (storage, calldata, memory, or fixed `Arr<T,N>`),
binding each element to a fresh copy. It desugars to the indexed loop you would write by hand:

```ts
@contract class C {
  @state xs: u256[];
  @external @view total(): u256 {
    let s: u256 = 0n;
    for (const v of this.xs) { s = s + v; }   // == for (let i=0n; i<this.xs.length; i=i+1n) { const v = this.xs[i]; ... }
    return s;
  }
}
```

The array length and element are re-read each iteration (not cached), so mutating the array in the
body behaves exactly like the hand-written loop under solc. `break` / `continue` / `return` and
nesting all work. The element binding inherits whatever a standalone `const v = xs[i]` supports
(value and branded-value elements today). `for...in` is not supported (iterate an array with
`for...of`).

### Default and named arguments (internal calls)

Internal helpers can declare default parameter values and be called with named arguments, both of
which desugar to an ordinary positional internal call. They apply only at internal call sites
(`this.f(...)`); the external ABI boundary is fixed by the selector, so external callers always
provide every argument and the ABI/selector always list every parameter.

```ts
@contract class C {
  @hidden fee(amount: u256, bps: u256 = 30n, floor: u256 = 1n): u256 {
    let f: u256 = (amount * bps) / 10000n;
    return f < floor ? floor : f;
  }
  @external @view a(x: u256): u256 { return this.fee(x); }                   // bps=30, floor=1
  @external @view b(x: u256): u256 { return this.fee(x, 50n); }              // floor=1
  @external @view c(x: u256): u256 { return this.fee({ amount: x, bps: 50n }); } // named, floor default
}
```

A default must be a self-contained compile-time **constant** (a literal, `address(0n)`,
`type(u256).max`, a value cast over constants, and so on), and any defaulted parameter must be
trailing. Defaults are type- and range-checked at the declaration, so `b: u8 = 300n` is an error
even on a helper that is never called (matching TypeScript). Named arguments `{ paramName: value }`
bind by **name** (so they may be written in any order) and fall back to defaults for omitted
parameters; a single object-literal argument is treated as named only when every key is a
parameter name, otherwise it is an ordinary positional value (for example a struct-literal for a
single struct parameter).

### `@nonReentrant` reentrancy guard

A built-in decorator that wraps an external/public state-mutating function in an EIP-1153
**transient-storage** reentrancy mutex, the same mechanism as OpenZeppelin's
`ReentrancyGuardTransient` but with no import, no boilerplate, and no storage slot consumed.

```ts
@contract class Vault {
  @state bal: mapping<address, u256>;
  @nonReentrant @external withdraw(amount: u256): void {
    // ... guarded body ...
  }
}
```

On entry the guard reverts with OpenZeppelin's `ReentrancyGuardReentrantCall()` (selector
`0x3ee5aeb5`) if the contract is already executing a guarded function, otherwise it sets a
transient flag; on every normal exit it clears the flag, and a reverting call has the flag rolled
back automatically by EIP-1153. The transient slot costs no persistent storage and is wiped at the
end of every transaction. The decorator requires a state-mutating external or public function
(`@view`/`@pure`/`@read` are rejected, as is `@internal`/`@private`/`@hidden`), and a
`@nonReentrant` function cannot be called internally (the guard protects the external entry). It
never changes the function's ABI, selector, or mutability.

### Exhaustive `switch` (JETH-only control flow)

Solidity has no `switch`; JETH adds one (over enums and other value types) that desugars to a
nested if/else chain over a single evaluation of the discriminant, and is stricter than
TypeScript so it cannot silently mis-route:

```ts
enum Status { Pending, Active, Closed }

@contract class C {
  @external @pure label(s: Status): u256 {
    switch (s) {
      case Status.Pending: return 1n;
      case Status.Active: case Status.Closed: return 2n;  // shared body (empty label falls through)
    }                                                      // exhaustive: every member covered -> no default needed
  }
}
```

The discriminant is a value type (uint / int / enum / bool / address / bytesN) evaluated exactly
once. A non-empty case must terminate (`break`, which ends the case; `return`; `revert(...)`;
`continue`; or an if-else / block that fully diverts), so there is **no implicit fall-through**
from a non-empty case (an empty case label still shares the next case's body). A `switch` over an
enum with no `default` must cover **every member** (exhaustiveness, `JETH286`) - add a member and
the compiler flags every switch that no longer covers it. A duplicate constant case label is a
dead arm and is rejected (`JETH287`). Enum semantics themselves match Solidity exactly (ABI
`uint8`, 1-byte storage, `Panic(0x21)` on an out-of-range explicit conversion).

### Generics (compile-time monomorphization)

Solidity has no generics; JETH adds type-safe generic **internal** functions, monomorphized at
compile time (each concrete instantiation generates a specialized copy, exactly like a hand-written
type-specific function, so there is zero runtime cost and the result is byte-identical to solc).

```ts
@contract class C {
  @hidden max<T>(a: T, b: T): T { return a > b ? a : b; }     // one definition...
  @hidden clamp<T>(v: T, lo: T, hi: T): T { return this.max(this.min(v, hi), lo); }
  @hidden min<T>(a: T, b: T): T { return a < b ? a : b; }
  @external @pure capU(v: u256, hi: u256): u256 { return this.min(v, hi); }   // ...used at u256
  @external @pure capByte(v: u8, hi: u8): u8 { return this.min(v, hi); }      // ...and at u8
}
```

Each distinct concrete type the generic is used with (here `u256` and `u8`) produces one specialized
internal function; instantiations are deduplicated and the body is type-checked **per instantiation**
(an operation invalid for some `T` is an error only at that instantiation, while other valid
instantiations still compile). Type arguments are inferred from the value arguments, or given
explicitly (`this.max<u256>(a, b)`). Type arguments must be value types (`uintN` / `intN` / `bool` /
`address` / `bytesN` / an enum / a branded newtype). Generics are internal-only: a generic
`@external` / `@public` function is rejected (`JETH290`), since a generic type is not expressible in
the ABI, and no generic or specialization ever appears in the ABI. Monomorphization is bounded (the
value-type universe is finite and recursion at a fixed type closes through the dedup cache), and a
specialization whose mangled name would collide with a user function is rejected rather than silently
overwritten.

## 4. Where JETH is *more capable* than the Solidity compiler

JETH always compiles through Yul (solc's IR pipeline), which schedules the EVM's 1024-slot
operand stack far more efficiently than Solidity's default (legacy) stack-based codegen. Two
consequences, and these are the only two places the *same* program behaves better under JETH than
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
> through Yul and closes both gaps. The advantage is over Solidity's **default** pipeline: JETH
> gives you the IR-pipeline benefits without needing to remember a flag.

---

## 5. Design note

Everything not listed above is intended to be **observably indistinguishable from Solidity**.
JETH's value proposition is a TypeScript surface syntax with exact Solidity/EVM semantics, plus
the ergonomics in section 1 and the always-on IR codegen in section 2. When in doubt about a
behavior, the rule is: it should match solc byte-for-byte, and a divergence is a bug.

## 6. Known deviations from solc (verified, genuinely unmatchable)

The "a divergence is a bug" rule has a small, closed set of documented exceptions: behaviors that
cannot be made byte-identical to *any single* solc configuration. None of these is a miscompile;
JETH never returns wrong bytes. Each is pinned by a test.

### Internal function-pointer equality on identical bodies

Comparing two **distinct** internal function pointers whose bodies are byte-identical returns
`false` in JETH:

```ts
@pure f(x: u256): u256 { return x + 1n; }
@pure g(x: u256): u256 { return x + 1n; }   // same body as f
@external @pure eq(): bool { return this.f == this.g; }   // JETH: false
```

This is an optimizer artifact in solc, not a language semantic:

| solc configuration                        | `f == g` |
| ----------------------------------------- | -------- |
| legacy pipeline, optimizer ON (runs=200)  | `true`   |
| legacy pipeline, optimizer OFF            | `false`  |
| viaIR, optimizer ON                       | `false`  |

Under the legacy assembly optimizer, the block deduplicator merges the two identical function
bodies onto one jump tag, so the pointer values collide and compare equal. With the optimizer off,
or under the viaIR pipeline (a distinct pointer model), solc returns `false`, agreeing with JETH's
stable dispatch-id model. Only the raw `==` / `!=` value on an identical-body pair diverges, and
only against the legacy-optimizer-on configuration: near-identical bodies (`x + 7` vs `x + 8`)
compare byte-identically, and **calls** dispatched through such pointers run byte-identically in
every configuration. The differential harness happens to use the legacy-optimizer-on config, so it
is the one configuration that disagrees. Pinned by `test/internal-fn-pointers.test.ts`.

### Other genuinely-unmatchable boundaries

- `gasleft()`, and `address(this).code` / `.codehash` of **self**: JETH's bytecode is never equal to
  solc's, so a value derived from remaining gas or the contract's own code size cannot match.
- Non-TypeScript literals (`hex"..."`, `1e18` without the `n` suffix): rejected by design, since
  JETH's literal grammar is the TypeScript subset; not a runtime divergence.
- Signed / out-of-bounds calldata offsets in the lazy `abi.encode(<calldata ref>)` path: solc reads
  the wrapped/OOB calldata via signed tail access and succeeds, JETH validates the offset and reverts
  (safe direction). Pinned by `test/_boundary-calldata-signed-offset.test.ts`.
