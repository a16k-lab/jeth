# Constructors, inheritance, and abstract contracts

JETH supports contract inheritance with Solidity-compatible state ordering,
constructor execution, virtual dispatch, and override checks.

## Base contracts

Use `extends` for inheritance:

```typescript
abstract class Owned {
  owner: address;

  constructor(owner: address) {
    this.owner = owner;
  }

  get isOwner(account: address): bool {
    return account == this.owner;
  }
}

class Vault extends Owned {
  constructor(owner: address) {
    super(owner);
  }
}
```

State fields are laid out base-first according to the resolved linearization.
Changing base order or fields can change an upgradeable contract's storage.

## Base constructor arguments

Provide base arguments in the derived constructor with `super(args)`:

```typescript
abstract class Capped {
  cap: u256;
  constructor(cap: u256) { this.cap = cap; }
}

class Token extends Capped {
  constructor(supply: u256) {
    super(supply * 2n);
  }
}
```

Constant base arguments can also use the supported heritage form. A base
constructor must be initialized exactly once. Ambiguous multiple-base argument
routes are rejected.

Base constructors execute from the most-base contract toward the final derived
contract. Field initializers run in the corresponding construction sequence.

## Abstract contracts

An abstract contract can contain implemented members and bodyless requirements:

```typescript
abstract class PriceSource {
  abstract get price(asset: address): External<u256>;

  get normalized(asset: address): External<u256> {
    return this.price(asset) * 1000000n;
  }
}
```

`abstract` on a bodyless member is the native spelling of a required virtual
member. The decorator form is also supported where applicable:

```typescript
abstract class PriceSource {
  @virtual get price(asset: address): External<u256>;
}
```

A concrete leaf must implement every inherited requirement.

An abstract-only source unit is still fully type-checked. It emits empty
creation/runtime artifacts for independent abstract leaves rather than silently
ignoring invalid bodies.

## Virtual members

Mark an implemented member `@virtual` when a descendant may override it:

```typescript
abstract class FeeModel {
  @virtual
  fee(amount: u256): u256 {
    return amount / 100n;
  }
}
```

## Overrides

Use `@override` on a replacing member:

```typescript
abstract class FeeModel {
  @virtual
  fee(amount: u256): u256 {
    return amount / 100n;
  }
}

class FlatFee extends FeeModel {
  @override
  fee(amount: u256): u256 {
    return amount / 200n;
  }
}
```

The override must match the inherited signature, exposure, mutability contract,
return shape, and member kind. In multiple inheritance, an override list can be
required to identify all overridden bases.

## `super` calls

An overriding internal function can invoke the next implementation in the
linearized base order:

```typescript
abstract class FeeModel {
  @virtual
  fee(amount: u256): u256 {
    return amount / 100n;
  }
}

class DiscountFee extends FeeModel {
  @override
  fee(amount: u256): u256 {
    return super.fee(amount) / 2n;
  }
}
```

External ABI entries are message-call boundaries. Put reusable inherited logic
in internal functions when an internal `super` call is required.

## Multiple inheritance

Multiple bases are supported with deterministic linearization and collision
checks. The compiler rejects ambiguous fields, incompatible method signatures,
duplicate selector exposure, and unresolved override requirements.

Prefer small interfaces and shallow implementation inheritance. Complex
linearization makes storage, modifiers, and `super` behavior harder to audit.

## Private members

A leading `#` declares a private member. It is not visible to derived contracts:

```typescript
abstract class Base {
  #secret: u256;
}
```

Use ordinary internal members when descendants are intended to access them.
