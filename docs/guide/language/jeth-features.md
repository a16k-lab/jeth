# JETH-specific language features

JETH deliberately adds a small set of compile-time features beyond Solidity
source syntax. They lower to audited EVM-compatible behavior.

## Mutability inference

Class methods do not spell `pure` or `view`. The analyzer derives the strongest
valid mutability from transitive effects before ABI generation.

```typescript
get twice(value: u256): External<u256> {
  return value * 2n; // pure
}

get current(): External<u256> {
  return this.value; // view
}
```

## Minimal visibility

`External<T>` and `Payable<T>` expose ABI entries. Everything else is internal
unless it is a `Visible<T>` state getter. Private members use `#`.

This keeps the internal-call versus message-call boundary explicit.

## Branded newtypes

```typescript
type OrderId = Brand<u256>;
type Amount = Brand<u256>;
```

Brands prevent accidental mixing while erasing to their base ABI/storage type.

## Struct spread

```typescript
let updated: Config = { ...current, fee: nextFee };
```

Spread constructs a new supported struct value and overrides named fields. It is
not a general JavaScript object spread operation.

## `for...of`

```typescript
for (const value of values) {
  total += value;
}
```

This is checked indexed iteration over supported array locations.

## Defaults and named arguments

```typescript
fee(amount: u256, bps: u256 = 30n): u256 { ... }
let result: u256 = this.fee({ amount: value, bps: 50n });
```

These are compile-time call conveniences for internal functions. They do not
change the external ABI.

## Exhaustive switch

```typescript
switch (state) {
  case State.Pending: return 0n;
  case State.Active: return 1n;
  case State.Closed: return 2n;
}
```

Enum coverage is checked and accidental non-empty fallthrough is rejected.

## Generics

```typescript
identity<T>(value: T): T { return value; }
```

Supported internal generics are monomorphized. There is no runtime generic
dispatch or generic ABI.

## Transient reentrancy guard

`@nonReentrant` provides a built-in EIP-1153 mutex without consuming a persistent
storage slot.

## Deep recursion and stack scheduling

JETH's Yul backend can avoid some Solidity "stack too deep" source failures and
can execute deeper internal recursion before the EVM stack ceiling that affects
some solc lowering paths. This is an implementation capability, not an invitation
to write gas-unbounded recursive contracts.

## Design rule

Every JETH-specific feature must lower to explicit, testable semantics. Syntax
convenience does not authorize JavaScript behavior or weaken the compiler's
acceptance bar.
