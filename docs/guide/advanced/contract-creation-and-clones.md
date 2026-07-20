# Contract creation and clones

JETH supports contract creation from inside a contract through structured
EIP-1167 clone builtins. A clone is a small contract that delegates every call
to a fixed implementation while keeping its own address, balance, and storage.

This chapter explains the EVM `CREATE` and `CREATE2` behavior used by those
builtins, deterministic addresses, initialization, immutable arguments, failure
behavior, and the boundary of JETH's current deployment surface.

> [!IMPORTANT] JETH does not currently expose arbitrary `new Contract(...)`, raw
> init-code deployment, or user-level `CREATE` and `CREATE2`. The clone builtins
> are the supported way for one JETH contract to deploy another contract.

## Supported builtins

| JETH expression | EVM operation | Result | Effect |
| --- | --- | --- | --- |
| `clone(implementation)` | `CREATE` | clone address | writes state |
| `cloneDeterministic(implementation, salt)` | `CREATE2` | clone address | writes state |
| `cloneWithArgs(implementation, args)` | `CREATE` | clone address | writes state |
| `cloneDeterministicWithArgs(implementation, salt, args)` | `CREATE2` | clone address | writes state |
| `predictClone(implementation, salt)` | address calculation only | predicted address | reads the environment |
| `predictCloneWithArgs(implementation, salt, args)` | address calculation only | predicted address | reads the environment |
| `cloneArgs()` | reads the executing contract's code tail | `bytes` | reads the environment |
| `isContract(account)` | checks `EXTCODESIZE` | `bool` | reads the environment |

The deployment builtins are allowed in nonpayable and payable methods. They are
rejected in read-only methods because contract creation changes EVM state.
Prediction, `cloneArgs()`, and `isContract(...)` are allowed in a `get` method,
but not in a `static` method, because they inspect the current EVM environment.

The parameter types are exact:

```text
implementation: address
salt:           bytes32
args:           bytes
result:         address
```

An implementation supplied as `u160` or `bytes20` can be converted to an
address. Prefer an explicit `address(...)` conversion at trust boundaries.

## Creation code and runtime code

Every EVM deployment has two different bytecode values:

1. Creation code, also called init code, executes only during deployment.
2. Runtime code is returned by the creation code and stored at the new address.

The plain JETH clone creation code returns this canonical 45-byte EIP-1167
runtime:

```text
363d3d373d3d3d363d73
<20-byte implementation address>
5af43d82803e903d91602b57fd5bf3
```

The runtime copies calldata, delegates the call to the embedded implementation,
and returns or reverts with the implementation's returndata. It does not contain
application storage or constructor logic.

The JETH clone builtins call `CREATE` or `CREATE2` with a value of zero. They do
not forward the factory call's `msg.value` into the new clone. Fund the clone in
a later payable call if the application needs an initial balance.

## CREATE clones

`clone(implementation)` and `cloneWithArgs(implementation, args)` use `CREATE`.
The resulting address depends on the creating factory address and that factory's
creation nonce. In conceptual form:

```text
address = last20(keccak256(rlp([factoryAddress, factoryCreationNonce])))
```

Two successive `clone(implementation)` calls from the same factory therefore
produce different addresses even though their runtime bytecode is identical.
JETH has no `predictClone` form for CREATE because prediction would also require
tracking the factory's creation nonce and every intervening creation.

Use CREATE clones when the exact address is not needed before deployment and the
factory can return or emit the address after creation.

## CREATE2 clones

`cloneDeterministic(...)` and `cloneDeterministicWithArgs(...)` use `CREATE2`.
The address is independent of the factory's creation nonce and is calculated as:

```text
address = last20(
  keccak256(
    0xff ++ factoryAddress ++ salt ++ keccak256(exactCreationCode)
  )
)
```

Four inputs are therefore important:

- the factory address;
- the 32-byte salt;
- the implementation address embedded in the creation code;
- the immutable argument bytes, when present.

Changing the factory, implementation, or immutable bytes changes the predicted
address even when the same salt is reused. Ordinary initializer calldata sent
after deployment is not part of the address calculation.

`predictClone(...)` and `predictCloneWithArgs(...)` use `address(this)` as the
factory address. Call prediction on the same deployed factory that will perform
the deployment. Running the same method on another factory produces another
address.

## Complete factory with atomic initialization

The safest common flow is to check the implementation, deploy the clone, and
initialize it in the same transaction. This removes the interval in which a
third party could initialize an unclaimed clone.

```jeth
interface CloneAccount {
  initialize(owner: address): void;
  owner(): View<address>;
}

class AccountImplementation {
  currentOwner: address;
  initialized: bool;

  initialize(owner: address): External<void> {
    require(!this.initialized, "already initialized");
    require(owner != address(0n), "zero owner");
    this.initialized = true;
    this.currentOwner = owner;
  }

  get owner(): External<address> {
    return this.currentOwner;
  }
}

class AccountCloneFactory {
  Created: event<{
    instance: indexed<address>;
    implementation: indexed<address>;
    owner: address;
    salt: bytes32;
  }>;

  create(
    implementation: address,
    owner: address,
  ): External<address> {
    require(isContract(implementation), "implementation has no code");
    const instance: address = clone(implementation);
    CloneAccount(instance).initialize(owner);
    emit(Created(instance, implementation, owner, bytes32(0n)));
    return instance;
  }

  createDeterministic(
    implementation: address,
    owner: address,
    userSalt: bytes32,
  ): External<address> {
    require(isContract(implementation), "implementation has no code");
    const salt: bytes32 = keccak256(abi.encode(msg.sender, userSalt));
    const instance: address = cloneDeterministic(implementation, salt);
    CloneAccount(instance).initialize(owner);
    emit(Created(instance, implementation, owner, salt));
    return instance;
  }

  get predictDeterministic(
    implementation: address,
    caller: address,
    userSalt: bytes32,
  ): External<address> {
    const salt: bytes32 = keccak256(abi.encode(caller, userSalt));
    return predictClone(implementation, salt);
  }
}
```

Compile this source as a multi-contract unit. Deploy `AccountImplementation`
once, deploy `AccountCloneFactory`, then call either factory method with the
implementation address. Call the returned clone through the implementation ABI,
or through the `CloneAccount` interface from another JETH contract.

The deterministic method namespaces the user salt with a caller address. This
prevents unrelated callers from claiming the same caller-specific salt through
that factory. The prediction method accepts the intended caller explicitly so
off-chain software and other contracts can calculate the same address.

The initializer has its own replay guard. Without it, anyone could call
`initialize` again and replace the owner after deployment.

## What executes through a clone

The clone uses `DELEGATECALL`, so execution combines the clone's context with the
implementation's code:

| Property during an implementation method | Value |
| --- | --- |
| `address(this)` | clone address |
| storage reads and writes | clone storage |
| current balance | clone balance |
| `msg.sender` | caller of the clone |
| `msg.value` | value sent to the clone call |
| executing logic | implementation runtime code |

Each clone has independent storage. Calling the implementation directly uses the
implementation's own storage and is a different execution context.

The implementation's constructor runs only when the implementation is deployed.
It does not run for a clone. Storage field initializers and constructor storage
writes affect the implementation account, not the clone. A clone starts with
zeroed storage and must use a guarded initializer or derive read-only
configuration from clone arguments.

Implementation immutables are embedded in the implementation runtime and are
therefore shared by every clone that delegates to that implementation. They are
not per-clone values.

## Immutable clone arguments

Immutable clone arguments are bytes appended to the clone's runtime code. They
are useful for per-clone configuration that never changes and does not need a
storage slot.

```jeth
class FeeAccountImplementation {
  get config(): External<[address, u256]> {
    return cloneArgs().decode([address, u256]);
  }
}

class FeeAccountCloneFactory {
  create(
    implementation: address,
    owner: address,
    feeBps: u256,
  ): External<address> {
    require(isContract(implementation), "implementation has no code");
    require(feeBps <= 10000n, "fee too high");
    return cloneWithArgs(implementation, abi.encode(owner, feeBps));
  }

  createDeterministic(
    implementation: address,
    salt: bytes32,
    owner: address,
    feeBps: u256,
  ): External<address> {
    require(isContract(implementation), "implementation has no code");
    require(feeBps <= 10000n, "fee too high");
    const args: bytes = abi.encode(owner, feeBps);
    return cloneDeterministicWithArgs(implementation, salt, args);
  }

  get predictDeterministic(
    implementation: address,
    salt: bytes32,
    owner: address,
    feeBps: u256,
  ): External<address> {
    const args: bytes = abi.encode(owner, feeBps);
    return predictCloneWithArgs(implementation, salt, args);
  }
}
```

The runtime layout is:

```text
[45-byte EIP-1167 runtime][exact argument bytes]
```

The creation code for an argument-bearing clone returns both regions. The exact
argument bytes contribute to the CREATE2 init-code hash, so prediction and
deployment must use byte-for-byte identical encoding and argument order.

`cloneArgs()` copies the executing contract's code after byte offset `0x2d` and
returns that tail as `bytes`. It does not authenticate, validate, or assign a
schema to the bytes. Decode them with the same schema used by the factory.

> [!WARNING] `cloneArgs()` is only meaningful while the implementation is
> executing through a compatible clone. Calling the same getter directly on the
> implementation can return unrelated code bytes or fail because the
> implementation itself does not have the clone runtime layout.

Clone arguments are public contract code, not secret data. They are immutable
because deployed runtime code is immutable under the normal EVM model, not
because JETH stores them in immutable state variables.

Argument length also increases deployed code size. Excessive argument data can
cross the target EVM's contract-code limit and make creation fail.

## Implementation validation

The clone deployment builtins do not require the implementation address to have
code. This matches the minimal clone construction model: the address is embedded
in the runtime whether or not it currently contains a contract.

For ordinary factories, validate before deployment:

```jeth
require(isContract(implementation), "implementation has no code");
```

`isContract(...)` is an instantaneous code-size check. It is false for an EOA,
an unused address, and a contract while its constructor is still running. It is
not proof that the code is trusted, implements the expected ABI, preserves a
storage layout, or will exist forever. Pin or govern allowed implementation
addresses according to the application's threat model.

## Deployment failure and collisions

The clone helpers revert with empty revert data when the underlying CREATE or
CREATE2 operation returns the zero address. Common causes include:

- the deterministic address already has code or a creation nonce;
- the creation code exceeds an EVM resource or code-size limit;
- the factory lacks enough gas for deployment;
- another protocol-level creation rule rejects the deployment.

Calling `cloneDeterministic` twice from the same factory with the same
implementation and salt attempts to use the same address, so the second call
reverts. For the argument-bearing form, the argument bytes are also part of the
identity.

Prediction does not reserve an address. If an unrestricted public factory uses
caller-provided salts, another transaction can call that factory first. Bind the
salt to the intended caller or another unique namespace, enforce authorization,
and initialize in the same transaction as deployment.

Do not treat a predicted address as a deployed contract until code exists there.
Funds sent to a counterfactual address before deployment can become inaccessible
if the intended creation can no longer succeed.

## CREATE versus CREATE2 decision

| Requirement | Use |
| --- | --- |
| cheapest simple sequential factory deployment | `clone(...)` |
| address must be known before deployment | `cloneDeterministic(...)` |
| per-clone read-only configuration in code | a `WithArgs` variant |
| mutable per-clone state | guarded initializer and clone storage |
| arbitrary constructor logic or arbitrary init code | not currently supported from JETH contract source |

CREATE2 does not make a clone upgradeable. The implementation address is fixed
inside the EIP-1167 runtime. To change logic, deploy a different clone or choose
an explicitly upgradeable proxy pattern.

## JETH and Solidity comparison

| Task | JETH | Solidity |
| --- | --- | --- |
| deploy a plain EIP-1167 clone | `clone(implementation)` | a clone library or assembly using CREATE |
| deploy a deterministic clone | `cloneDeterministic(implementation, salt)` | a clone library or assembly using CREATE2 |
| predict a deterministic clone | `predictClone(...)` | library helper or explicit formula |
| attach immutable clone bytes | `cloneWithArgs(...)` variants | compatible clone library or custom creation code |
| read immutable clone bytes | `cloneArgs()` | code-copy helper or compatible library |
| deploy an arbitrary contract type | not supported inside JETH source | `new C(args)` |
| deploy arbitrary init code | not supported inside JETH source | inline assembly CREATE/CREATE2 |
| send value during clone creation | not supported by current clone builtins | possible through selected library overloads or assembly |

The following Solidity-shaped operation is a clean JETH compile-time rejection:

```jeth
class Factory {
  create(): External<address> {
    // JETH023: object/contract construction is not supported.
    const instance = new Child();
    return address(instance);
  }
}

class Child {}
```

This restriction is a deliberate language boundary, not a statement that the
EVM lacks general contract creation. JETH currently exposes the audited clone
construction path and keeps arbitrary deployment gated.

## Production checklist

- Deploy and verify the intended implementation first.
- Reject a code-less implementation and enforce any allowlist or version policy.
- Keep implementation storage layout compatible with the clone's expected state.
- Never rely on implementation constructor writes as clone initialization.
- Guard every initializer against replay.
- Deploy and initialize atomically.
- Namespace or authorize user-provided salts.
- Use the same factory, implementation, salt, and argument bytes for prediction.
- Treat immutable arguments as public and validate them before deployment.
- Remember that clone creation forwards zero value.
- Test collision, malformed initialization, direct implementation calls, and
  implementation failure paths.
- Record the clone, implementation, factory, salt, argument encoding, and source
  version in deployment artifacts.

For upgradeable routing, beacon fleets, and diamonds, continue with
[Proxies, beacons, and diamonds](proxies-and-diamonds.md).
