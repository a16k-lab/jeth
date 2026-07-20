# Syntax cheatsheet

## Declarations

```jeth
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
  min(self: u256, b: u256): u256 { return self < b ? self : b; }
}

class Contract extends Base {
  value: u256;

  @override
  f(): External<u256> {
    this.value += 1n;
    return this.value;
  }
}
```

## State, constants, and immutables

```jeth
value: u256;
#secret: u256;
owner: Visible<address>;
balances: mapping<address, u256>;
values: u256[];
pair: Arr<u256, 2>;

static SCALE: u256 = 1000000n;
static OWNER: address;
```

## Functions

```jeth
internalHelper(x: u256): u256 { return x + 1n; }
#privateHelper(x: u256): u256 { return x + 2n; }
static pureHelper(x: u256): u256 { return x + 3n; }
set(x: u256): External<void> { this.value = x; }
get read(): External<u256> { return this.value; }
get #privateRead(): u256 { return this.#secret; }
deposit(): Payable<void> { this.value += msg.value; }

constructor(owner: address) {
  this.OWNER = owner;
}

receive(): void { /* payable by definition */ }
fallback(): void { /* nonpayable fallback */ }
fallback(): Payable<void> { /* payable fallback */ }
fallback(input: bytes): bytes { return input; }
```

## Internal function references

```jeth
let fn: (value: u256) => u256 = this.internalHelper;
let result: u256 = fn(4n);
```

## Locals and assignment

```jeth
let amount: u256 = 1n;
let data: bytes = input;
let pair: Arr<u256, 2> = [1n, 2n];
let [value, ok]: [u256, bool] = this.readPair();

this.total += amount;
[a, b] = [b, a];
delete this.values;
```

## Control flow

```jeth
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

```jeth
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

```jeth
let price: u256 = Oracle(oracle).price(asset);
let [ok, ret]: [bool, bytes] = target.tryCall({ data: payload });
let raw: bytes = abi.encode(a, b);
let packed: bytes = abi.encodePacked(a, b);
let value: u256 = raw.decode(u256);
```

## Contract creation and clones

```jeth
let sequential: address = clone(implementation);
let deterministic: address = cloneDeterministic(implementation, salt);
let predicted: address = predictClone(implementation, salt);

let args: bytes = abi.encode(owner, feeBps);
let configured: address = cloneWithArgs(implementation, args);
let deterministicConfigured: address =
  cloneDeterministicWithArgs(implementation, salt, args);
let predictedConfigured: address =
  predictCloneWithArgs(implementation, salt, args);

let ownCloneData: bytes = cloneArgs();
let deployed: bool = isContract(implementation);
```

These helpers deploy EIP-1167 clones through CREATE or CREATE2. Arbitrary
`new Contract(...)` deployment is not currently supported. See the
[complete creation and clone guide](../advanced/contract-creation-and-clones.md).

## Modifiers and inheritance

```jeth
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

```jeth
u256(small)
u160(account)
address(raw)
payable(account)
bytes20(account)
TokenId(rawId)
u256(tokenId)
```

See the detailed chapters for restrictions, location rules, and runtime behavior.
