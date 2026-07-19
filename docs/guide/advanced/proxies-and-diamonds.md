# Proxies, beacons, and diamonds

JETH can synthesize and verify several upgradeability patterns. These features
reduce boilerplate, but they do not remove governance or storage risk.

## Minimal clones

EIP-1167 clone helpers deploy minimal delegate proxies to an implementation.
Supported deterministic variants use a salt and can predict an address before
deployment.

Clones can carry supported immutable argument data according to the compiler's
clone-argument model.

## ERC-1967 proxy

`@proxy` declares a generated proxy that stores implementation data in the
ERC-1967 slot and delegates unmatched calldata.

```typescript
@proxy
class AppProxy {
  constructor(implementation: address, initData: bytes) {
    proxyInit(implementation, initData);
  }
}
```

A proxy cannot declare ordinary implementation state. Delegatecalled logic uses
the proxy's storage.

## Transparent proxy

The transparent variant separates admin operations from user delegation. The
admin is prevented from falling through into implementation functions, avoiding
the classic selector-clash ambiguity.

Admin keys remain a critical trust boundary. Use a governance/timelock policy
appropriate to the application.

## UUPS

In UUPS, upgrade logic lives in the implementation and is called through the
proxy. The implementation must enforce authorization and proxiable compatibility.

An implementation that exposes an unprotected upgrade path can transfer control
of every proxy using it.

## Beacon proxy

A beacon stores the implementation address shared by multiple proxies. Each
proxy reads the beacon during dispatch. Upgrading the beacon changes every
dependent proxy.

This reduces upgrade operations but increases blast radius.

## Diamonds

`@diamond` synthesizes an EIP-2535 selector router, cut operations, loupe
functions, interface support, ownership, and optional freezing.

JETH supports three reference storage models:

- array-oriented diamond storage;
- packed selector storage;
- Solidstate-compatible storage.

Facets use `@facet` and namespaced state uses `@storage` according to the selected
model.

## Diamond cuts

A cut can add, replace, or remove selectors. Review:

- duplicate selectors;
- immutable/system selectors;
- facet code existence;
- initialization delegatecall target and data;
- ownership and authorization;
- state namespace collisions;
- selector removal and rollback paths.

## Freezing

Generated diamonds can be finalized with `freezeDiamond()`. After freezing,
future cuts reject. Freezing is only useful if all ownership and alternate
upgrade paths are also understood.

## Security requirements

Before production use:

1. audit generated proxy/diamond code for the exact compiler release;
2. audit the application authorization model;
3. test initialization cannot be replayed;
4. verify implementation and facet code before upgrade;
5. diff storage layouts and namespaces;
6. test selector routing and revert bubbling;
7. test upgrades with populated state;
8. define rollback, pause, and incident procedures.

Generated patterns are powerful advanced features, not proof of a safe upgrade.
