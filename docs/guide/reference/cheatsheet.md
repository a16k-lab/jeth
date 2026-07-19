# Syntax cheatsheet

## Declarations

```typescript
type User = { id: u256; owner: address };
type UserId = Brand<u256>;
type Changed = event<{ id: indexed<u256>; value: u256 }>;
type Unauthorized = error<{ caller: address }>;

enum State { Pending, Active, Closed }

interface Oracle {
  price(asset: address): View<u256>;
}

abstract class Base {
  abstract f(): External<u256>;
}

static class Lib {
  min(a: u256, b: u256): u256 { return a < b ? a : b; }
}

class Contract extends Base {
  // ...
}
```

## State, constants, and immutables

```typescript
value: u256;
owner: Visible<address>;
balances: mapping<address, u256>;
values: u256[];
pair: Arr<u256, 2>;

static SCALE: u256 = 1000000n;
static OWNER: address;
```

## Functions

```typescript
internalHelper(x: u256): u256 { return x + 1n; }
set(x: u256): External<void> { this.value = x; }
get read(): External<u256> { return this.value; }
deposit(): Payable<void> { this.value += msg.value; }

constructor(owner: address) {
  this.OWNER = owner;
}

receive(): void { /* payable by definition */ }
fallback(): void { /* nonpayable fallback */ }
fallback(): Payable<void> { /* payable fallback */ }
```

## Locals and assignment

```typescript
let amount: u256 = 1n;
let data: bytes = input;
let pair: Arr<u256, 2> = [1n, 2n];
let [value, ok]: [u256, bool] = this.readPair();

this.total += amount;
[a, b] = [b, a];
delete this.values;
```

## Control flow

```typescript
if (condition) { ... } else { ... }
while (condition) { ... }
do { ... } while (condition);
for (let i: u256 = 0n; i < n; i += 1n) { ... }
for (const value of values) { ... }

switch (state) {
  case State.Pending: return 0n;
  case State.Active: return 1n;
  case State.Closed: return 2n;
}
```

## Errors and events

```typescript
require(condition);
require(condition, "message");
require(condition, Unauthorized(msg.sender));
assert(invariant);
revert();
revert("message");
revert(Unauthorized(msg.sender));
revertWith(rawData);
emit(Changed(id, value));
```

## Calls and ABI

```typescript
let price: u256 = Oracle(oracle).price(asset);
let [ok, ret]: [bool, bytes] = target.tryCall({ data: payload });
let raw: bytes = abi.encode(a, b);
let packed: bytes = abi.encodePacked(a, b);
let value: u256 = raw.decode(u256);
```

## Modifiers and inheritance

```typescript
@modifier
onlyOwner() {
  require(msg.sender == this.owner, "not owner");
  _;
}

@onlyOwner
@nonReentrant
execute(): External<void> { ... }

@virtual
f(): u256 { return 1n; }

@override
f(): u256 { return super.f() + 1n; }
```

## Common conversions

```typescript
u256(small)
u160(account)
address(raw)
payable(account)
bytes20(account)
TokenId(rawId)
u256(tokenId)
```

See the detailed chapters for restrictions, location rules, and runtime behavior.
