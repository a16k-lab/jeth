# Contract ABI specification

Built by [@a16k-lab](https://github.com/a16k-lab).

JETH uses the Ethereum Contract ABI for externally visible calls, returns,
events, and errors. The target behavior is Solidity 0.8.35 for overlapping
supported types.

## Function selectors

The first four calldata bytes are:

```text
keccak256("name(canonicalType1,canonicalType2,...)")[0:4]
```

Return types are not part of the selector.

Examples of canonical mappings:

| JETH source type | Canonical ABI type |
| --- | --- |
| `u256` | `uint256` |
| `i32` | `int32` |
| `address` | `address` |
| `bytes4` | `bytes4` |
| `T[]` | canonical `T` plus `[]` |
| `Arr<T, N>` | canonical `T` plus `[N]` |
| enum | `uint8` |
| `Brand<T>` | canonical base type |
| struct | canonical tuple form |

An external overload must have a unique canonical parameter signature.

## Static and dynamic types

Value types are ABI-static. Fixed arrays and structs are static only if all of
their recursive elements/fields are static.

Dynamic types include:

- `bytes`;
- `string`;
- every dynamic array `T[]`;
- a fixed array with a dynamic element;
- a struct with any recursively dynamic field.

## Head and tail encoding

Static values are encoded in place as 32-byte words or recursively inlined static
heads. A dynamic value's head word is an offset to its tail. Offsets are relative
to the start of the current ABI tuple or array pointer region, not always the
start of calldata.

```text
selector
tuple head
dynamic tails
```

Nested containers reset their relative offset base according to ABI rules.

### Worked calldata example

```jeth
class AbiInbox {
  lastCount: u256;

  submit(id: u256, values: u256[]): External<u256> {
    require(values.length > 0n, "empty values");
    this.lastCount = values.length;
    return id + values[0n];
  }

  get count(): External<u256> {
    return this.lastCount;
  }
}
```

The canonical signature is `submit(uint256,uint256[])`, so the selector is
`0x2f344195`. Calling `submit(7, [10, 20])` produces:

```text
2f344195                                                        selector
0000000000000000000000000000000000000000000000000000000000000007  id
0000000000000000000000000000000000000000000000000000000000000040  values offset
0000000000000000000000000000000000000000000000000000000000000002  values length
000000000000000000000000000000000000000000000000000000000000000a  values[0]
0000000000000000000000000000000000000000000000000000000000000014  values[1]
```

The offset is `0x40` from the start of the argument tuple, immediately after the
selector. The successful return value is `17`, encoded as one 32-byte word.

## Word representation

- Unsigned integers and addresses are zero-extended.
- Signed integers are sign-extended.
- Booleans encode as zero or one.
- Fixed bytes are left-aligned and right-padded.
- Dynamic bytes/string tails contain length followed by right-padded data.
- Arrays contain a length when dynamic, followed by elements or element offsets.
- Structs encode as tuples in field declaration order.

## Calldata validation

JETH validates accepted calldata paths:

- narrow unsigned high bits must be zero;
- signed values must have correct sign extension;
- bool must be exactly zero or one;
- address high bits must be zero;
- fixed-bytes padding must match alignment;
- enum values must be in range;
- dynamic heads, lengths, and accessed data must stay within calldata;
- runtime indices must be in bounds.

Some aggregate field reads are intentionally lazy. An unread malformed field can
remain unobserved where Solidity also decodes lazily, while a whole-value copy or
return validates the fields it must materialize.

## Return encoding

Return data omits a selector and contains the ABI encoding of the return tuple.
A single dynamic return therefore usually begins with an offset word to its
tail.

The recursive encoder can source values from calldata, memory, or storage using
location-specific readers. Acceptance of a source shape does not imply every
location-to-location copy is enabled.

## Event encoding

Non-anonymous events use the canonical signature hash as topic 0. Indexed static
values occupy one topic. Indexed dynamic values and supported aggregates use the
event indexed hash rules. Non-indexed values use ABI tuple encoding in log data.

```jeth
type Submitted = event<{
  sender: indexed<address>;
  id: indexed<u256>;
  values: u256[];
}>;
```

For `Submitted`, topic 0 is the event signature hash, topics 1 and 2 contain the
indexed sender and id, and the dynamic array is encoded in the log data tuple.

## Error encoding

Custom errors use a selector followed by ABI arguments. `Error(string)` uses
selector `0x08c379a0`. `Panic(uint256)` uses selector `0x4e487b71`.

```jeth
type Unauthorized = error<{ caller: address }>;

class Guarded {
  owner: address;

  constructor(owner: address) {
    this.owner = owner;
  }

  run(): External<void> {
    if (msg.sender != this.owner) {
      revert(Unauthorized({ caller: msg.sender }));
    }
  }
}
```

`Unauthorized(address)` uses its own four-byte selector followed by one
zero-extended address word.

## ABI JSON

The compiler emits ABI JSON from analyzed declarations. Selectors and runtime
encoding use canonical types. The current known JSON presentation gap for some
struct tuples is tracked separately from runtime correctness.

Use compiler-produced ABI artifacts. Do not infer exact tuple component metadata
from a short source-name table.

## Malformed calldata deviations

JETH can reject a small set of adversarial, noncanonical offset/length values
earlier than solc while both reject the call. Those safer-than-solc cases are
documented in the supported matrix. Honest ABI-encoder output is expected to
match.
