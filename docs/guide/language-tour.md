# Language tour

This tour introduces JETH by building a small vault. It focuses on the concepts
that differ most from TypeScript and Solidity.

## State and external methods

```typescript
class Vault {
  balances: mapping<address, u256>;

  deposit(): Payable<void> {
    this.balances[msg.sender] += msg.value;
  }

  get balanceOf(owner: address): External<u256> {
    return this.balances[owner];
  }
}
```

`balances` is persistent contract storage. `Payable<void>` exposes a payable
entry point. `External<u256>` exposes a nonpayable ABI entry. Because `balanceOf`
uses `get` and reads storage, its ABI mutability is inferred as `view`.

## Checked arithmetic

```typescript
let next: u256 = current + amount;
```

Unsigned overflow and signed overflow revert with Solidity-compatible panic
data. Division by zero and invalid enum conversions also use the matching panic
codes. Use `unchecked` only when wrapping is deliberate and proven safe:

```typescript
unchecked {
  i += 1n;
}
```

## Internal helpers

Methods without an exposure return wrapper are internal:

```typescript
class Fees {
  fee(amount: u256, bps: u256 = 30n): u256 {
    return (amount * bps) / 10000n;
  }

  get quote(amount: u256): External<u256> {
    return this.fee(amount);
  }
}
```

Internal calls can use trailing defaults and named arguments. External ABI calls
always provide the full selector-defined argument list.

## Types

JETH includes Solidity-compatible integer widths, signed integers, booleans,
addresses, fixed bytes, dynamic bytes, strings, mappings, arrays, fixed arrays,
struct-like object aliases, enums, and tuples.

```typescript
type Position = {
  owner: address;
  size: u128;
  active: bool;
};

enum Status {
  Pending,
  Active,
  Closed,
}

type OrderId = Brand<u256>;
```

`Brand<T>` creates a nominal value type with no runtime or ABI overhead. Different
brands cannot be mixed accidentally without an explicit conversion.

## Arrays and iteration

```typescript
class Scores {
  scores: u256[];

  get total(): External<u256> {
    let result: u256 = 0n;
    for (const score of this.scores) {
      result += score;
    }
    return result;
  }
}
```

JETH supports dynamic arrays `T[]` and fixed arrays `Arr<T, N>`. `for...of`
desugars to indexed EVM-oriented iteration and supports `break`, `continue`, and
`return` where the element shape is supported.

## Events and custom errors

```typescript
type Deposited = event<{
  account: indexed<address>;
  amount: u256;
}>;

type InsufficientBalance = error<{
  available: u256;
  requested: u256;
}>;
```

Events use Solidity-compatible topics and ABI data. Custom errors use canonical
selectors and ABI-encoded arguments.

## Modifiers and reentrancy protection

```typescript
class GuardedForwarder {
  @nonReentrant
  forward(target: address, data: bytes): Payable<bytes> {
    return target.call({
      data,
      value: msg.value,
      success: { condition: this.accepted, revert: "call failed" },
    });
  }

  get accepted(): bool {
    return true;
  }
}
```

`@nonReentrant` uses EIP-1153 transient storage and consumes no persistent slot.
It is one defense, not a replacement for checks-effects-interactions, access
control, invariant tests, and review.

## Exhaustive control flow

```typescript
get weight(status: Status): External<u256> {
  switch (status) {
    case Status.Pending:
      return 0n;
    case Status.Active:
      return 1n;
    case Status.Closed:
      return 2n;
  }
}
```

An enum switch without `default` must cover every member. Adding an enum member
therefore makes incomplete switches fail at compile time.

## Where to go deeper

- [Language reference](language-reference.md)
- [Functions](language/functions.md)
- [Contracts and ABI](contracts-and-abi.md)
- [JETH-specific features](language/jeth-features.md)
- [Complete supported matrix](../../SUPPORTED.md)
