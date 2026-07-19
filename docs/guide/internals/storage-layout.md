# Storage layout

JETH follows Solidity-compatible persistent storage layout for supported types.
Raw-slot compatibility is part of the differential test bar.

## Slots and packing

Storage is divided into 32-byte slots. Consecutive value fields smaller than 32
bytes can share a slot when they fit. A value that does not fit starts in the
next slot. Structs and arrays apply their own boundaries according to Solidity
layout rules.

```typescript
class Packed {
  a: u8;
  b: u16;
  c: address;
  d: u256;
}
```

Writes to packed fields use read-modify-write so neighboring lanes remain
unchanged.

## Fixed arrays

Fixed arrays are inline. Value elements pack without crossing a slot. Composite
elements use their recursive storage width.

```typescript
values: Arr<u8, 40>;
```

Runtime indexing computes the containing slot and byte offset, then masks or
sign-extends the value as required.

## Dynamic arrays

The declared slot stores array length. Element data begins at:

```text
keccak256(lengthSlot)
```

Whole-slot elements use a stride. Packed value elements compute a slot and lane.
Composite elements recursively use the element's storage layout.

`push` increments length after validating capacity. `pop` clears the removed
element and decrements length. Removing a dynamic element also clears its owned
tail data.

## Mappings

For a mapping at slot `p`, a static key's value base is derived from:

```text
keccak256(canonicalKeyWord || p)
```

Nested mappings repeat the process with the previous derived slot. Dynamic
bytes/string keys use their content-based mapping-key rule.

Mappings have no stored length and cannot be enumerated from storage alone.

## Structs

Struct fields follow declaration order and pack within the struct. A mapping
field occupies its own base slot but stores no data at that slot. Nested structs
and arrays expand according to their recursive layout.

## Dynamic bytes and string

For length below 32, bytes are stored in the header slot with length metadata.
For longer values, the header stores encoded length and data begins at the hash
of the header slot.

Overwriting or deleting a long value must clear old data slots that are no longer
used. Short/long transitions are tested against raw Solidity storage.

## Constants and immutables

Compile-time constants consume no storage. Immutables are baked into deployed
runtime code and also consume no storage slot. Adding a constant or immutable
therefore does not shift ordinary state fields.

## Inheritance

State layout follows the resolved base order. Base and derived fields can pack
according to the Solidity layout rules. Reordering bases or inserting fields can
break upgrade compatibility.

## Namespaced proxy and diamond storage

Proxy implementation/admin/beacon slots use their specified collision-resistant
constants. Diamond/facet state uses the selected reference model and namespace.

Never mix generated proxy storage, implementation state, and custom assembly
slots without a complete layout review.

## Upgrade checklist

For each compiler and contract release:

1. save the compiler version and EVM target;
2. save the storage-layout artifact;
3. diff slot, offset, width, and recursive type changes;
4. preserve field and base order;
5. test upgrades against populated state;
6. inspect raw reserved proxy/diamond slots;
7. reject incompatible changes before deployment.

The current CLI's storage artifact is useful but not yet a frozen cross-version
schema.
