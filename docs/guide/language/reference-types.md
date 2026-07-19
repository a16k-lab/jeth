# Reference and composite types

Reference values can represent more than one EVM word or refer to storage,
memory, or calldata. Their behavior depends on shape and location.

## Dynamic bytes and strings

`bytes` is a dynamic byte sequence. `string` is an ABI string represented by its
UTF-8 bytes. JETH does not provide JavaScript string objects.

```typescript
class Text {
  data: bytes;
  name: string;

  setName(next: string): External<void> {
    this.name = next;
  }
}
```

Supported operations include assignment, return, `.length`, indexing for bytes,
storage `push`/`pop` where applicable, ABI encoding/decoding, hashing, calldata
slicing, and concatenation.

Storage uses Solidity's short/long representation. Values shorter than 32 bytes
are stored in the header slot. Longer values use data slots beginning at the
keccak hash of the header slot.

## Dynamic arrays

`T[]` is a dynamic array.

```typescript
class List {
  values: u256[];

  add(value: u256): External<void> {
    this.values.push(value);
  }

  removeLast(): External<void> {
    this.values.pop();
  }
}
```

Supported operations include `.length`, index reads/writes, `push`, zero-value
`push()`, `pop`, whole-value return/copy on supported paths, and nested access.

Create a zero-initialized memory array with the JETH constructor form:

```typescript
let values: u256[] = new Array<u256>(length);
```

The Solidity spelling `new T[](length)` does not fit the TypeScript parser and
is not JETH syntax.

An out-of-bounds index reverts with `Panic(0x32)`. Popping an empty storage array
reverts with `Panic(0x31)`. Excessive memory allocation reverts with
`Panic(0x41)`.

## Fixed arrays

`Arr<T, N>` is a fixed-length array and corresponds to Solidity `T[N]`.

```typescript
class C {
  pair: Arr<u256, 2>;
}
```

`.length` is the compile-time constant `N`. Runtime indexing is bounds-checked.
A constant out-of-bounds index is a compile-time error.

Fixed arrays can contain value or reference elements where the relevant location
and consumer path is supported. Deep aggregate acceptance is intentionally
shape-sensitive; check the known-limitations chapter for cleanly rejected paths.

## Mappings

`mapping<K, V>` is a storage-only key/value structure.

```typescript
class Ledger {
  balances: mapping<address, u256>;
  allowances: mapping<address, mapping<address, u256>>;
}
```

Mapping entries do not store keys or a length. A value slot is derived by hashing
the canonical key word with the mapping base slot, recursively for nested
mappings.

Supported key families include integers, booleans, addresses, fixed bytes, and
dynamic bytes/string keys on their documented paths. Values can be value types,
arrays, strings/bytes, structs, and nested mappings where supported.

A missing key reads as the zero value. A whole mapping cannot be copied, returned,
deleted, or enumerated.

## Structs

Object-shaped type aliases declare structs:

```typescript
type Position = {
  owner: address;
  size: u128;
  active: bool;
};

class Book {
  position: Position;

  open(owner: address, size: u128): External<void> {
    this.position = Position(owner, size, true);
  }
}
```

Struct fields follow declaration order. Storage fields are packed according to
Solidity rules. ABI structs are tuples.

Struct values can be constructed positionally. Supported contexts also permit
object literals and object spread:

```typescript
let updated: Position = { ...old, size: nextSize };
```

A struct containing a mapping is storage-only. It cannot be constructed as a
memory value, passed through the ABI, or returned.

## Nested composites

Composite types can be nested:

```typescript
type Item = { id: u256; label: string };
type Batch = { owner: address; items: Item[] };

class C {
  batches: mapping<u256, Batch>;
  matrix: u256[][];
  labels: string[];
}
```

JETH's ABI codec recursively handles supported nested arrays, fixed arrays,
structs, bytes, and strings. Storage access uses a unified path of fields,
indices, and mapping keys.

Not every location-to-location copy of every nested shape is enabled. A compiler
diagnostic on such a shape is a deliberate safety gate, not permission to bypass
the type system.

## Tuples

Tuple syntax is used for multiple returns and destructuring:

```typescript
pair(): [u256, bool] {
  return [7n, true];
}

use(): void {
  let [value, ok]: [u256, bool] = this.pair();
  [value, ok] = [value + 1n, !ok];
}
```

Omitted destructuring positions discard their component:

```typescript
let [value, , owner] = this.readThree();
```

The complete right side is evaluated before tuple assignment writes begin.
