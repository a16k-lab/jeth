# Structure of a contract

Contracts use class syntax. A deployable leaf class becomes an EVM contract
artifact.

```typescript
class SimpleStorage {
  value: u256;

  set(next: u256): External<void> {
    this.value = next;
  }

  get read(): External<u256> {
    return this.value;
  }
}
```

A contract can contain state variables, constants, immutables, functions,
constructors, modifiers, events, errors, and inherited members.

## State variables

Bare fields are persistent storage:

```typescript
class Ledger {
  total: u256;
  balances: mapping<address, u256>;
  names: string[];
}
```

The storage planner assigns Solidity-compatible slots and packed byte offsets.
Field order is therefore part of an upgradeable contract's storage interface.

An initializer executes during contract creation:

```typescript
class C {
  count: u256 = 1n;
  enabled: bool = true;
}
```

## Public getters

Wrap a state type in `Visible<T>` to generate an external getter:

```typescript
class C {
  owner: Visible<address>;
  balances: Visible<mapping<address, u256>>;
}
```

Getter parameters and return values follow Solidity's public-state-getter rules
for the supported storage shape. The underlying field remains available to
contract code.

## Constants

An initialized `static` field is a compile-time constant. It consumes no storage
slot and is folded at each use site.

```typescript
class Units {
  static BPS: u256 = 10000n;

  get half(): External<u256> {
    return Units.BPS / 2n;
  }
}
```

Constants must have compiler-foldable initializers. Constant expressions use
exact rational semantics before conversion to the target integer type.

## Immutables

A `static` value field without an initializer is an immutable. Assign it in the
constructor. It is baked into runtime bytecode and consumes no storage slot.

```typescript
class Token {
  static OWNER: address;

  constructor(owner: address) {
    this.OWNER = owner;
  }

  get owner(): External<address> {
    return this.OWNER;
  }
}
```

Only supported value types can be immutable. An immutable cannot be reassigned
after construction.

## Functions

Return wrappers define ABI exposure:

```typescript
helper(x: u256): u256 { return x + 1n; }
set(x: u256): External<void> { this.value = x; }
get read(): External<u256> { return this.value; }
deposit(): Payable<void> { this.total += msg.value; }
```

- No wrapper means internal.
- `External<T>` means externally callable and nonpayable.
- `Payable<T>` means externally callable and payable.
- A read-only value-returning class method uses `get`; its `pure` or `view`
  mutability is inferred from transitive effects.

## Events and errors

Events and errors can be declared at file scope or as members:

```typescript
class Vault {
  Deposited: event<{ account: indexed<address>; value: u256 }>;
  Unauthorized: error<{ caller: address }>;
}
```

Use `emit` for events and `revert` or `require` for errors.

## Constructor

The constructor runs once in creation code. It can accept ABI-encoded arguments,
initialize state and immutables, call supported internal functions, and invoke a
base constructor.

```typescript
class C {
  owner: address;

  constructor(owner: address) {
    this.owner = owner;
  }
}
```

A constructor is nonpayable unless decorated with `@payable`.

## Special entries

A method named `receive` handles empty calldata and accepts value. A method named
`fallback` handles selectors not matched by ordinary entries. Their accepted
parameters and return behavior follow the JETH special-entry rules.

```typescript
class Receiver {
  received: u256;

  receive(): void {
    this.received += msg.value;
  }

  fallback(): void {
    this.received += 1n;
  }
}
```

`receive()` is payable by definition. A plain `fallback(): void` is nonpayable;
use `fallback(): Payable<void>` when the fallback must accept and read value.

## Abstract contracts, interfaces, and libraries

```typescript
abstract class Base {
  abstract value(): External<u256>;
}

interface Oracle {
  price(asset: address): View<u256>;
}

static class MathLib {
  min(a: u256, b: u256): u256 {
    return a < b ? a : b;
  }
}
```

These declaration kinds are covered in their dedicated chapters.
