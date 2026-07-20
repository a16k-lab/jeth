# Value types

Value types fit in one EVM word and are copied when assigned or passed. They do
not have an explicit data-location annotation.

## Unsigned integers

Unsigned integer types are written `u8`, `u16`, and so on through `u256`, in
multiples of eight bits.

```jeth
let small: u8 = 255n;
let word: u256 = 1n << 200n;
```

The range of `uN` is `0` through `2^N - 1`. Arithmetic is checked by default.
An overflow or underflow reverts with `Panic(0x11)`.

## Signed integers

Signed integer types are written `i8` through `i256`, also in multiples of eight
bits. They use two's-complement EVM representation.

```jeth
let delta: i64 = -12n;
let limit: i256 = type(i256).max;
```

The range of `iN` is `-2^(N-1)` through `2^(N-1) - 1`. Division of the minimum
signed value by `-1` overflows in checked mode.

## Integer literals

Integer literals use TypeScript BigInt spelling:

```jeth
let decimal: u256 = 1000n;
let hexadecimal: u256 = 0xffn;
```

Plain JavaScript number literals such as `1` are rejected. Constants are folded
with exact rational behavior, so intermediate constant division is not
prematurely truncated.

Numeric separators are allowed only in valid literal positions. Address-shaped
hex literals are subject to EIP-55 rules.

## Boolean

`bool` has values `true` and `false`. Conditions require a boolean; integers do
not coerce to booleans.

```jeth
if (amount != 0n) {
  // ...
}
```

ABI decoding rejects dirty boolean words rather than treating arbitrary nonzero
values as true.

## Address

`address` represents a 160-bit EVM address.

```jeth
let zero: address = address(0n);
let self: address = address(this);
let caller: address = msg.sender;
```

Address equality and ordering are unsigned. Arithmetic on addresses is rejected.
Conversions between `address` and `u160` are explicit. `bytes20` conversions use
the Solidity-compatible alignment rule.

`payable(addr)` marks an address as payable for the applicable call path. Payable
and nonpayable address forms use the same ABI word.

Address members include supported forms of `.balance`, `.code`, `.codehash`,
low-level calls, typed interface conversion, and contract checks.

## Fixed-size bytes

`bytes1` through `bytes32` hold fixed byte sequences. ABI and storage values are
left-aligned within the 32-byte word.

```jeth
let selector: bytes4 = bytes4(0x12345678n);
let digest: bytes32 = keccak256(data);
```

Fixed bytes support equality, ordering, bitwise operations, shifts, supported
casts, and byte indexing where applicable.

## Enums

Enums use a one-byte `uint8` representation and ABI type.

```jeth
enum State {
  Pending,
  Active,
  Closed,
}

let current: State = State.Pending;
```

Members are numbered from zero in declaration order. Explicit conversion from an
out-of-range integer reverts with `Panic(0x21)`. An enum can have at most the
representable supported member count.

## Branded value types

`Brand<Base>` creates a nominal value type over a value type:

```jeth
type TokenId = Brand<u256>;
type Wei = Brand<u256>;

let id: TokenId = TokenId(7n);
let raw: u256 = u256(id);
```

Brands are erased for storage, ABI, selectors, and code generation. Their purpose
is compile-time separation. A `TokenId`, a `Wei`, and a plain `u256` are not
implicitly interchangeable.

Operations over two values of the same numeric brand preserve that brand where
defined. A literal can be typed in the context of its branded operand.

## Function references

An internal function-reference type uses arrow syntax:

```jeth
(value: u256) => u256
(left: u256, right: u256) => u256
() => void
```

Take a reference from an unambiguous internal or private method and call it with
the declared signature:

```jeth
inc(value: u256): u256 { return value + 1n; }

run(value: u256): u256 {
  let fn: (value: u256) => u256 = this.inc;
  return fn(value);
}
```

Supported references can be stored in locals, state fields, arrays, fixed
arrays, and supported structs. They can be passed and returned through internal
functions, selected with a conditional expression, compared with `==` and `!=`,
and called directly from a state field.

The zero/default function reference is not callable. Invoking it reverts with
`Panic(0x51)`, matching an uninitialized Solidity internal function pointer.

Function references are internal compiler values. They are not external ABI
function pointers or stable code addresses. They cannot be ABI encoded, exposed
as external parameters or returns, emitted in events, converted to integers, or
taken from an externally exposed or ambiguous overloaded method.

## Default values

Newly declared values have the zero value for their type:

- integers and fixed bytes: zero;
- bool: false;
- address: `address(0n)`;
- enum: its first member;
- branded value: the branded zero of its base type.

There is no `undefined` or `null` runtime value.
