# Data locations and copying

JETH normally infers locations from context instead of spelling Solidity's
`storage`, `memory`, and `calldata` keywords on each declaration. Location is
still fundamental to semantics.

## Storage

Contract fields and values reached from them live in persistent storage.

```typescript
type User = { id: u256; owner: address };

class C {
  values: u256[];
  users: mapping<address, User>;
}
```

Storage references are resolved through fields, fixed/dynamic indices, and
mapping keys. Writes must preserve packing and clear obsolete dynamic tails when
Solidity would clear them.

## Calldata

External function parameters are decoded from calldata. Value parameters are
validated as words. Aggregate parameters are represented as bounds-checked views
or copied images depending on the consuming operation.

```typescript
get element(values: u256[], index: u256): External<u256> {
  return values[index];
}
```

Calldata is immutable. Dynamic offsets and lengths are checked before use.
Malformed calldata normally reverts with empty data on the matching decode path.

`msg.data` is a calldata bytes view over the complete call data, including the
four-byte selector.

## Memory

Locals that hold dynamic bytes, strings, arrays, or struct/fixed-array images use
memory. Memory exists only for the current EVM call.

```typescript
let copy: bytes = input;
let pair: Arr<u256, 2> = [1n, 2n];
let user: User = User(id, owner);
```

Memory reference assignment can alias rather than deep-copy when Solidity memory
assignment aliases. Mutating through one alias is then visible through the other.

## Copy versus alias

The source and destination determine whether an operation copies data or shares
a reference:

- value types always copy;
- calldata to memory copies and validates the consumed shape;
- storage to memory copies;
- memory-to-memory reference assignment can alias;
- storage-to-storage whole values copy supported fields and clear overwritten
  dynamic data;
- memory/calldata to storage performs a deep copy only for supported shapes;
- mapping members are never copied as aggregate values.

This distinction is a major compiler-safety boundary. JETH rejects a path when
lowering it as a copy would lose aliasing that Solidity preserves.

## Assignment examples

```typescript
// Value copy.
let b: u256 = a;

// Calldata array copied to storage on a supported whole-value path.
this.values = input;

// Storage struct copied to a memory local.
let user: User = this.users[id];

// Memory struct alias.
let alias: User = user;
alias.owner = nextOwner;
```

## Dynamic storage overwrite

Replacing a storage string, bytes value, array, or dynamic struct must clear data
that is no longer reachable. For example, overwriting a long string with a short
one clears its old hashed data slots. JETH differential tests compare those raw
slots, not only the returned value.

## `delete`

`delete target` resets a supported location to its type's zero value:

```typescript
delete this.count;
delete this.users[id];
delete this.values;
delete this.records[index].label;
```

Packed values clear only their lane. Struct deletion recursively clears
non-mapping fields. Dynamic arrays set length to zero and clear their elements.
Dynamic bytes/string clear their header and long data.

Deleting a whole mapping is rejected because mappings cannot be enumerated or
cleared as a whole. Deleting a mapping value is supported.

## Location-sensitive limitations

Some aggregate operations are accepted in one location and rejected in another.
For example, a storage-to-storage copy may be safe while a calldata-struct to
storage copy of the same nested shape is gated because it needs a different
codec. Treat the exact diagnostic as authoritative and consult the supported
matrix for the shape.
