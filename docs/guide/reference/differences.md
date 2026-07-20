# Differences from TypeScript and Solidity

JETH uses TypeScript-shaped syntax but EVM semantics. It also intentionally
differs from Solidity source syntax in several ergonomic areas.

## TypeScript syntax, not TypeScript runtime

| TypeScript intuition | JETH behavior |
| --- | --- |
| `number` and floating point | Rejected |
| `1` numeric literal | Rejected; use `1n` |
| String `+` concatenation | Rejected; use concat helpers |
| Truthy/falsy conditions | Rejected; condition must be `bool` |
| Dynamic objects | No runtime object model |
| `undefined` or `null` | No runtime value |
| Exceptions with `throw` | Use EVM revert forms |
| async/await | Rejected |
| Closures and captured variables | Rejected |
| Prototype methods | No prototype runtime |
| Garbage collection | No managed runtime |

## JETH spelling versus Solidity

| Concept | JETH | Solidity equivalent |
| --- | --- | --- |
| Contract | `class C` | `contract C` |
| Abstract contract | `abstract class C` | `abstract contract C` |
| Library | `static class L` | `library L` |
| Struct | `type P = { x: u256 }` | `struct P { uint256 x; }` |
| Unsigned integer | `u256` | `uint256` |
| Signed integer | `i128` | `int128` |
| Fixed array | `Arr<T, N>` | `T[N]` |
| Mapping | `mapping<K, V>` | `mapping(K => V)` |
| External function | `f(): External<T>` | `function f() external returns (T)` |
| Payable function | `f(): Payable<T>` | `function f() external payable returns (T)` |
| Public getter | `x: Visible<T>` | `T public x` |
| Internal method | ordinary method | `internal` function |
| Private member | `#name` | `private` member |
| Constant | `static K: T = value` | `T constant K = value` |
| Immutable | `static K: T;` | `T immutable K` |
| Interface view | `f(): View<T>` | `function f() external view returns (T)` |

## Mutability

Solidity asks the author to write `pure` and `view`. JETH infers them from the
body and transitive calls. Interfaces still declare mutability because they have
no body.

### Compared example

JETH:

```jeth
class Balance {
  amount: u256;

  get read(): External<u256> {
    return this.amount;
  }
}
```

Solidity:

```solidity
contract Balance {
    uint256 amount;

    function read() external view returns (uint256) {
        return amount;
    }
}
```

JETH infers `view` from the storage read. The exposed JETH getter still uses
`get` to declare its read-only contract.

## Visibility

JETH exposes only methods wrapped in `External<T>`/`Payable<T>` and fields wrapped
in `Visible<T>`. Ordinary methods are internal. This is narrower than Solidity's
several visibility keywords.

JETH private members use `#` and stay scoped to their declaring class:

```jeth
class Vault {
  #assets: u256;

  #fee(value: u256): u256 {
    return value / 100n;
  }

  get quote(value: u256): External<u256> {
    return value - this.#fee(value);
  }
}
```

The Solidity equivalent spells the same visibility explicitly:

```solidity
contract Vault {
    uint256 private assets;

    function fee(uint256 value) private pure returns (uint256) {
        return value / 100;
    }

    function quote(uint256 value) external pure returns (uint256) {
        return value - fee(value);
    }
}
```

## JETH-only compile-time features

- branded newtypes;
- struct spread;
- array `for...of`;
- default and named internal arguments;
- exhaustive `switch`;
- monomorphized internal generics;
- built-in transient `@nonReentrant`.

## Evaluation and arithmetic

JETH follows its Solidity target for checked arithmetic, panic codes,
short-circuiting, and observable evaluation order. Do not infer behavior from
JavaScript evaluation or coercion.

```jeth
class Arithmetic {
  get add(u: u8, v: u8): External<u8> {
    return u + v;
  }

  get wrap(u: u8, v: u8): External<u8> {
    unchecked: {
      return u + v;
    }
  }
}
```

`add(255, 1)` panics with arithmetic code `0x11`. `wrap(255, 1)` returns zero.
This is EVM integer behavior, not JavaScript number behavior.

## Safer malformed-calldata behavior

For honest ABI-encoded inputs, supported paths target Solidity parity. JETH
intentionally rejects a few malformed, noncanonical offset/length forms earlier
than solc. Both implementations fail the call, but revert data can differ.

## Deliberate exclusions

Some Solidity features or aggregate paths remain cleanly gated. Some JavaScript
features are permanently excluded because they lack a sound on-chain meaning.
See known limitations and the complete supported matrix.
