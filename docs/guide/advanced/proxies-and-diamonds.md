# Proxies, beacons, and diamonds

JETH provides compiler-supported deployment and upgrade patterns for EIP-1167
clones, ERC-1967 proxies, transparent proxies, UUPS implementations, beacon
proxies, and EIP-2535 diamonds. These features generate routing and storage
machinery, but authorization, initialization, storage compatibility, and
deployment ordering remain application responsibilities.

> [!DANGER] A proxy or diamond executes another contract's code in the proxy or
> diamond storage context. An incorrect implementation, facet, initializer, or
> upgrade authority can corrupt all application state.

## Choosing a pattern

| Pattern | Upgrade authority lives in | Upgrade scope | Best fit |
| --- | --- | --- | --- |
| EIP-1167 clone | nowhere in the clone | not upgradeable | many cheap instances of one implementation |
| Plain ERC-1967 | user-written proxy method | one proxy | custom proxy administration |
| Transparent | generated admin branch | one proxy | strict admin/user call separation |
| UUPS | implementation | one proxy | small proxy with implementation-defined authorization |
| Beacon | shared beacon | every proxy using the beacon | coordinated fleet upgrades |
| Diamond | generated selector router | selected selectors | modular systems split across facets |

All patterns require deployed code at implementation, beacon, or facet
addresses. JETH checks code existence on the generated paths where the
corresponding reference implementation does.

## Minimal EIP-1167 clones

Minimal clones contain a 45-byte runtime stub that delegates every call to one
fixed implementation. Each clone has its own address, balance, and storage. The
implementation's own storage is not used by calls through the clone.

See [Contract creation and clones](contract-creation-and-clones.md) for the full
CREATE and CREATE2 model, address formulas, initialization rules, immutable
argument layout, collision behavior, failure paths, and production checklist.

### Clone factory and implementation

```jeth
class AccountImplementation {
  owner: address;
  initialized: bool;

  initialize(newOwner: address): External<void> {
    require(!this.initialized, "already initialized");
    this.initialized = true;
    this.owner = newOwner;
  }

  get ownerOfClone(): External<address> {
    return this.owner;
  }
}

class AccountFactory {
  create(implementation: address): External<address> {
    return clone(implementation);
  }

  createDeterministic(
    implementation: address,
    salt: bytes32,
  ): External<address> {
    return cloneDeterministic(implementation, salt);
  }

  get predict(
    implementation: address,
    salt: bytes32,
  ): External<address> {
    return predictClone(implementation, salt);
  }
}
```

Deployment flow:

1. Deploy `AccountImplementation` once.
2. Call `AccountFactory.create(implementation)`.
3. Call `initialize(owner)` on the returned clone address, using the
   implementation ABI.
4. Treat the clone address as the account. Calls write the clone's storage.

`cloneDeterministic` uses `CREATE2`. `predictClone` returns the address for the
factory address, implementation, and salt. A repeated deployment with the same
inputs fails because the predicted address already contains code.

### Clone immutable arguments

JETH can append immutable argument bytes to the clone runtime. The
implementation reads its current clone's appended tail through `cloneArgs()`:

```jeth
class FeeAccountImplementation {
  get feeBps(): External<u256> {
    return cloneArgs().decode(u256);
  }
}

class FeeAccountFactory {
  createWithFee(
    implementation: address,
    feeBps: u256,
  ): External<address> {
    return cloneWithArgs(implementation, abi.encode(feeBps));
  }

  createDeterministicWithFee(
    implementation: address,
    salt: bytes32,
    feeBps: u256,
  ): External<address> {
    return cloneDeterministicWithArgs(
      implementation,
      salt,
      abi.encode(feeBps),
    );
  }

  get predictWithFee(
    implementation: address,
    salt: bytes32,
    feeBps: u256,
  ): External<address> {
    return predictCloneWithArgs(
      implementation,
      salt,
      abi.encode(feeBps),
    );
  }
}
```

The exact immutable argument bytes contribute to the deterministic address.
`cloneArgs()` is meaningful only while code is executing through a compatible
clone. Clone deployment mutates state and is rejected from a read-only method.
Prediction, code inspection, and clone-argument reads are environment reads and
therefore infer `view`, not `pure`.

## Plain ERC-1967 proxy

`@proxy` generates a payable delegate fallback and uses the ERC-1967
implementation slot. The class may define its own administration functions but
may not define ordinary state, `receive`, or `fallback` members.

```jeth
class CounterV1 {
  value: u256;
  initialized: bool;

  initialize(initialValue: u256): External<void> {
    require(!this.initialized, "already initialized");
    this.initialized = true;
    this.value = initialValue;
  }

  increment(): External<void> {
    this.value += 1n;
  }

  get current(): External<u256> {
    return this.value;
  }
}

@proxy
class CounterProxy {
  constructor(
    implementation: address,
    admin: address,
    initialValue: u256,
  ) {
    proxyInit(
      implementation,
      admin,
      abi.encodeWithSelector(0xfe4b84dfn, initialValue),
    );
  }

  upgrade(
    newImplementation: address,
    migrationData: bytes,
  ): External<void> {
    require(msg.sender == proxyAdmin(), "not admin");
    upgradeProxy(newImplementation, migrationData);
  }

  get implementation(): External<address> {
    return proxyImplementation();
  }

  get admin(): External<address> {
    return proxyAdmin();
  }
}
```

`0xfe4b84df` is `CounterV1.initialize(u256).selector`. Prefer producing selector
values from compiler artifacts or a typed interface instead of copying a magic
constant between projects.

`proxyInit` accepts either `(implementation, initData)` or
`(implementation, admin, initData)`. It checks that the implementation contains
code, stores the ERC-1967 slots, emits `Upgraded`, and delegatecalls nonempty
initialization data. A failed initializer bubbles its revert data and the whole
deployment reverts.

`upgradeProxy(newImplementation, data)` checks code, updates the implementation
slot, emits `Upgraded`, and delegatecalls nonempty migration data. JETH does not
authorize this builtin for you. The surrounding exposed method must perform the
required ownership, role, governance, or timelock check.

Interact with the deployed proxy using `CounterV1`'s ABI. The proxy's own
administration ABI is used only for the explicitly declared proxy methods.

## Transparent proxy

`@proxy('transparent')` generates the transparent admin branch. The source
class contains only its constructor:

```jeth
@proxy("transparent")
class TransparentCounterProxy {
  constructor(
    implementation: address,
    admin: address,
    initialValue: u256,
  ) {
    proxyInit(
      implementation,
      admin,
      abi.encodeWithSelector(0xfe4b84dfn, initialValue),
    );
  }
}
```

Routing depends on the caller:

- the admin may call only `upgradeToAndCall(address,bytes)`;
- any other admin call reverts with `ProxyDeniedAdminAccess()`;
- a non-admin call always delegates to the implementation, including a call
  whose selector equals `upgradeToAndCall(address,bytes)`.

This caller-based routing prevents the admin from accidentally invoking an
implementation function through the proxy. A transparent proxy cannot declare
exposed methods, state fields, `receive`, or `fallback`. Use the generated
`upgradeToAndCall` selector from the administrator account and use the
implementation ABI from every normal account.

## UUPS proxy

UUPS keeps the proxy minimal and puts upgrade behavior in the implementation.
Use a plain `@proxy` for routing and mark each compatible implementation with
`@uups`.

```jeth
@uups
class VaultV1 {
  owner: address;
  assets: u256;

  authorizeUpgrade(newImplementation: address): void {
    require(msg.sender == this.owner, "not authorized");
  }

  initialize(initialOwner: address): External<void> {
    require(this.owner == address(0n), "already initialized");
    this.owner = initialOwner;
  }

  deposit(amount: u256): External<void> {
    this.assets += amount;
  }

  get totalAssets(): External<u256> {
    return this.assets;
  }
}

@proxy
class VaultProxy {
  constructor(implementation: address, initialOwner: address) {
    proxyInit(
      implementation,
      abi.encodeWithSelector(0xc4d66de8n, initialOwner),
    );
  }
}
```

The `initialize(address)` selector is `0xc4d66de8`. A valid `@uups`
implementation must declare exactly the internal gate
`authorizeUpgrade(newImplementation: address): void`. JETH synthesizes:

- payable `upgradeToAndCall(address,bytes)`;
- read-only `proxiableUUID(): bytes32`.

Call `upgradeToAndCall` at the proxy address. The proxy delegates it into the
current implementation, so authorization reads proxy storage and the upgrade
writes the proxy's ERC-1967 implementation slot.

Before updating the slot, the generated path calls the new implementation's
`proxiableUUID()` and requires the ERC-1967 implementation-slot identifier.
This rejects a target with no compatible UUPS surface or a wrong UUID. It does
not prove that the new implementation preserves storage, authorization, or
application invariants.

Do not declare your own `upgradeToAndCall` or `proxiableUUID` on an `@uups`
class. Do not combine `@uups` and `@proxy` on the same class.

## Beacon and beacon proxy

A beacon stores one current implementation for a fleet of proxies. Every beacon
proxy asks the beacon for `implementation()` on each routed call.

```jeth
@beacon
class AccountBeacon {
  constructor(implementation: address) {}
}

@proxy("beacon")
class AccountBeaconProxy {
  constructor(beacon: address, initialValue: u256) {
    proxyInitBeacon(
      beacon,
      abi.encodeWithSelector(0xfe4b84dfn, initialValue),
    );
  }
}
```

For `@beacon`, JETH generates:

- `owner(): address`;
- `implementation(): address`;
- owner-gated `upgradeTo(address)`;
- `Upgraded(address)` events on construction and upgrade.

The beacon owner is the beacon deployment caller. The constructor's
implementation must contain code. The user-written beacon class contains only
the empty constructor and cannot declare state, inheritance, special entries,
or methods that collide with the generated surface.

`proxyInitBeacon(beacon, initData)` stores the ERC-1967 beacon slot, emits
`BeaconUpgraded`, resolves the current implementation, and delegatecalls
nonempty initialization data. `proxyBeacon()` reads the stored beacon address.

Deployment flow:

1. Deploy the implementation.
2. Deploy `AccountBeacon(implementation)` from the intended owner account.
3. Deploy one or more `AccountBeaconProxy(beacon, initialValue)` instances.
4. Interact with each proxy through the implementation ABI.
5. Call `AccountBeacon.upgradeTo(newImplementation)` as the beacon owner.
6. Verify every dependent proxy against populated, independent state.

One beacon upgrade changes routing for every proxy using that beacon. This is
the defining benefit and the primary blast-radius risk.

## Namespaced storage for delegatecalled code

Facets and other modular delegatecall targets should use collision-resistant
namespaced state. JETH's `@storage("namespace")` uses the ERC-7201 location:

```text
keccak256(abi.encode(uint256(keccak256(bytes(namespace))) - 1)) & ~0xff
```

Fields with the same namespace share one logical struct and follow declaration
order and packing inside that namespace. Different namespaces are isolated.
Ordinary fields still use sequential contract storage and should not be used for
facet-owned state.

```jeth
@facet
class CounterFacet {
  @storage("app.counter") count: u256;
  @storage("app.counter") lastWriter: address;

  increment(): External<void> {
    this.count += 1n;
    this.lastWriter = msg.sender;
  }

  get current(): External<u256> {
    return this.count;
  }

  get writer(): External<address> {
    return this.lastWriter;
  }
}
```

Namespace strings are permanent storage identifiers. Renaming one creates a new
storage region and makes the old values unreachable through the renamed fields.
All facet versions sharing a namespace must preserve compatible field order and
types.

## EIP-2535 diamonds

`@diamond` generates the selector router, cut operation, loupe, ERC-165 support,
ownership, initialization, and finalization surface. Facets are separately
deployed `@facet` contracts whose exposed function selectors are installed by a
cut.

### Diamond models

| Declaration | Storage compatibility | Ownership and fallback behavior |
| --- | --- | --- |
| `@diamond` or `@diamond("array")` | diamond-1/diamond-3 array model | direct ownership transfer; unknown selector reverts |
| `@diamond("packed")` | diamond-2 packed selectors, eight per word | direct ownership transfer; unknown selector reverts |
| `@diamond("solidstate")` | Solidstate v0.0.61 namespaces | two-step ownership and configurable default fallback |

Choose the model for compatibility with an existing deployment or toolchain.
The models are not storage-compatible with each other. Do not change a deployed
diamond's model.

### Declaring a diamond

Array and packed diamonds use `diamondInit(owner)`:

```jeth
@diamond("array")
class ApplicationDiamond {
  constructor(initialOwner: address) {
    diamondInit(initialOwner);
  }
}
```

Solidstate uses its matching initializer:

```jeth
@diamond("solidstate")
class SolidstateApplication {
  constructor(initialOwner: address) {
    diamondInitSolidstate(initialOwner);
  }
}
```

The source diamond contains only its constructor. JETH rejects user-declared
fields, methods, events, errors, modifiers, inheritance, `receive`, and
`fallback` because the complete surface is synthesized. A class cannot be both
`@diamond` and `@facet`, and one source file cannot declare multiple diamonds.

### Generated diamond ABI

Every model provides:

| Function | Purpose |
| --- | --- |
| `diamondCut(FacetCut[],address,bytes)` | add, replace, or remove selectors and optionally run initialization |
| `facets()` | return every installed facet and its selectors |
| `facetFunctionSelectors(address)` | return selectors installed for one facet |
| `facetAddresses()` | return installed facet addresses |
| `facetAddress(bytes4)` | resolve one selector |
| `supportsInterface(bytes4)` | query registered interface support |
| `owner()` | return the upgrade owner |
| `transferOwnership(address)` | transfer or nominate ownership, depending on model |
| `freezeDiamond()` | permanently disable future cuts |
| `isFrozen()` | report finalization state |

The Solidstate model additionally provides `nomineeOwner()`,
`acceptOwnership()`, `getFallbackAddress()`, and owner-gated
`setFallbackAddress(address)`. On a selector miss, it delegates to the configured
fallback address when nonzero. The array and packed models revert on a selector
miss.

### Installing facet selectors

`FacetCut` has this ABI shape:

```jeth
type FacetCut = {
  facetAddress: address;
  action: u8;
  functionSelectors: bytes4[];
};
```

Action values are:

| Value | Action | Required facet address |
| --- | --- | --- |
| `0` | add selectors that do not exist | deployed facet address |
| `1` | replace selectors that exist | new deployed facet address |
| `2` | remove selectors that exist | zero address |

For the `CounterFacet` example, an add cut contains the deployed facet address
and the selectors of `increment()`, `current()`, and `writer()`. Submit it to
`diamondCut(cuts, address(0n), bytes(""))` from the diamond owner. After the cut,
call the diamond address with the `CounterFacet` ABI. The router delegatecalls
the facet and the `app.counter` fields are stored at the diamond address.

Selectors for a cut should come from compiler-produced ABIs or qualified
`.selector` expressions. Do not derive selectors from display names or return
types.

### Cut initialization

The second and third `diamondCut` arguments optionally run one initialization
delegatecall after the selector changes:

- use `address(0n)` and empty bytes to skip initialization;
- otherwise `_init` must contain code;
- `_calldata` is delegatecalled into `_init` in diamond storage context;
- initialization failure reverts the complete cut and bubbles revert data.

An initializer is arbitrary delegatecalled code. Protect it against replay when
appropriate, use namespaced storage, and include it in the storage and security
review.

### Loupe and routing checks

After every cut, verify at minimum:

1. `facetAddress(selector)` equals the intended facet;
2. `facetFunctionSelectors(facet)` contains exactly the expected set;
3. `facetAddresses()` contains no stale address;
4. each installed selector succeeds through the diamond address;
5. removed selectors revert or reach only an intentionally configured
   Solidstate fallback;
6. the owner and registered interface IDs remain correct.

Add, replace, and remove use model-specific storage algorithms. Their observable
ordering can affect loupe output and raw storage, so an upgrade test should
compare complete selector sets rather than only one successful call.

## Finalizing a diamond

Every diamond starts upgradeable. The owner can call `freezeDiamond()` to set a
permanent flag that makes later `diamondCut` calls revert. Existing selector
routing remains active.

```jeth
interface DiamondFinalization {
  freezeDiamond(): void;
  isFrozen(): View<bool>;
}

class Finalizer {
  finalize(diamond: address): External<void> {
    DiamondFinalization(diamond).freezeDiamond();
    require(DiamondFinalization(diamond).isFrozen(), "freeze failed");
  }
}
```

Finalization is irreversible through the generated surface. Before freezing,
install every required selector, validate loupe output, complete initialization,
test recovery procedures, and confirm there is no alternate privileged path in
a facet or Solidstate fallback.

## Storage compatibility rules

An implementation upgrade must preserve the proxy-visible layout:

- do not reorder, remove, or change existing state fields;
- append compatible fields after existing fields;
- preserve inheritance order and packing assumptions;
- preserve initializer guards and authorization state;
- do not reuse ERC-1967 implementation, admin, or beacon slots.

A facet upgrade must preserve every namespace it uses:

- keep the exact namespace string;
- keep existing field order, widths, and recursive shapes;
- coordinate fields shared by multiple facets;
- never use the diamond router's internal namespaces;
- review default fallback code as a full-storage delegate target.

Implementation constructors initialize only implementation storage. Proxy or
diamond state must be initialized through a delegatecall initializer.

## Production deployment checklist

Before deployment or upgrade:

1. pin the JETH revision, solc 0.8.35, EVM target, optimizer settings, and source
   hashes;
2. deploy and verify every implementation, beacon, facet, and initializer;
3. record implementation, admin, beacon, owner, and namespace expectations;
4. encode initialization from the intended ABI and test replay protection;
5. diff storage layouts against the deployed version;
6. test the upgrade with populated state, not only an empty deployment;
7. verify events, returndata, revert bubbling, and raw reserved slots;
8. verify every proxy or diamond through its delegated ABI;
9. test unauthorized, malformed, zero-address, and no-code targets;
10. test rollback or incident response before transferring production control;
11. place authority behind reviewed governance, multisig, or timelock policy;
12. obtain an independent audit of application logic and the exact generated
    pattern used by the selected compiler release.

Generated upgrade machinery reduces boilerplate. It does not make an upgrade,
initializer, storage layout, facet set, or governance process safe by itself.
