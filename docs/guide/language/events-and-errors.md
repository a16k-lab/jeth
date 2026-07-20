# Events, errors, and panics

Events write EVM logs. Errors and panics revert execution and roll back state.

## Event declarations

Declare an event at file scope:

```jeth
type Transfer = event<{
  from: indexed<address>;
  to: indexed<address>;
  value: u256;
}>;
```

Or as a contract member:

```jeth
class Token {
  Transfer: event<{
    from: indexed<address>;
    to: indexed<address>;
    value: u256;
  }>;
}
```

## Emitting events

```jeth
emit(Transfer(msg.sender, recipient, amount));
```

A member event can also be emitted through `this` with named arguments:

```jeth
emit(this.Transfer({
  from: msg.sender,
  to: recipient,
  value: amount,
}));
```

Named fields must match the declaration exactly. They are reordered to the
declared ABI order before encoding.

For a non-anonymous event, topic 0 is the keccak hash of the canonical event
signature. Indexed value parameters occupy topics. Non-indexed parameters are
ABI-encoded in the log data.

Indexed dynamic bytes/string values and supported indexed aggregates are hashed
according to their Solidity-compatible indexed encoding instead of being stored
directly in a topic.

Emitting a log is a state-changing effect and is not allowed in a pure/view
function.

## Anonymous events

Use the supported `@anonymous` declaration form to omit the signature topic.
Anonymous events can use the EVM topic capacity for indexed arguments, but are
harder to distinguish by event signature.

## Error declarations

```jeth
type InsufficientBalance = error<{
  available: u256;
  required: u256;
}>;
```

Revert with the error:

```jeth
if (available < amount) {
  revert(InsufficientBalance(available, amount));
}
```

A member error supports named construction through `this`:

```jeth
if (available < amount) {
  revert(this.InsufficientBalance({
    available: available,
    required: amount,
  }));
}
```

`throw` is accepted only as custom-error sugar:

```jeth
throw this.InsufficientBalance({
  available: available,
  required: amount,
});
```

It produces the same revert payload as the corresponding `revert(...)`. JETH
does not support JavaScript `throw` values, `new Error(...)`, or arbitrary
exceptions.

The payload begins with the first four bytes of the canonical error signature
hash, followed by ABI-encoded arguments.

## `require`

```jeth
require(condition);
require(condition, "message");
require(condition, Unauthorized(msg.sender));
```

No reason produces empty revert data. A string reason uses `Error(string)`.
Custom error arguments use the error selector and ABI encoding.

Custom-error arguments follow the compiler's Solidity parity evaluation rules.
Do not put state-changing or reverting expressions in error arguments.

## `revert`

```jeth
revert();
revert("disabled");
revert(Unauthorized(msg.sender));
revertWith(rawData);
```

`revertWith` is useful for exact bubbling of returndata from another contract.

## `assert` and panic codes

`assert` represents an invariant. A false assertion reverts with
`Panic(uint256)` code `0x01`.

Common runtime panic codes include:

| Code | Meaning |
| --- | --- |
| `0x01` | Failed assertion |
| `0x11` | Arithmetic overflow or underflow |
| `0x12` | Division or modulo by zero |
| `0x21` | Invalid enum conversion |
| `0x31` | Pop from an empty array |
| `0x32` | Array or bytes index out of bounds |
| `0x41` | Excessive or overflowing memory allocation |

Use custom errors for expected application failures and assertions for internal
conditions that should be unreachable.

## ABI entries

Events and custom errors appear in generated ABI JSON with their parameters and
indexed flags. Consumers should use the compiler artifact rather than reconstruct
the ABI from source text.
