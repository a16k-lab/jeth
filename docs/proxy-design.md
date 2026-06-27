# JETH proxies - design spec (OZ 5.x / EIP-1167 / EIP-1967 verified)

The whole-system safety rule: there is NO `addr.delegatecall(...)` primitive in user code. delegatecall is
reachable ONLY through these structured, byte-identical-to-OpenZeppelin patterns. Four patterns, built in
phases. **Phase 1 (THIS spec): the MINIMAL PROXY (EIP-1167 clone) + immutable args.** It is self-contained -
it needs CREATE/CREATE2 + EIP-1167 emission, NOT the EIP-1967 slots / delegate fallback (those are Phase 2+,
the upgradeable Transparent/UUPS/Beacon variants).

## Verified baseline (on the @ethereumjs harness, against hand-written OZ-Clones assembly)
- A plain EIP-1167 clone deploys via CREATE and correctly delegatecalls the impl (clone.initialize(99) then
  clone.who() == 99). The harness supports CREATE.
- EIP-1167 RUNTIME (45 bytes = 0x2d): `363d3d373d3d3d363d73 <impl:20> 5af43d82803e903d91602b57fd5bf3`.
- Plain clone CREATION code (the OZ Clones.clone bytecode):
  `3d602d80600a3d3981f3 363d3d373d3d3d363d73<impl>5af43d82803e903d91602b57fd5bf3` (init returns the 45-byte
  runtime). create(0, ptr, 0x37).
- Immutable-args clone CREATION code (OZ 5.1 cloneWithImmutableArgs): a MODIFIED init that returns
  runtime+args. `61 <len:2> 3d81600a3d39f3` (PUSH2 len; RETURNDATASIZE DUP2 PUSH1 0x0a RETURNDATASIZE CODECOPY
  RETURN; 10 bytes = 0x0a) ++ the 45-byte EIP-1167 runtime ++ `<immutableArgs>`, where len = 0x2d + args.length.
  (NOTE: appending args to the PLAIN init does NOT work - the plain init returns only 45 bytes, dropping args.)
- The impl reads its clone's immutable args by EXTCODECOPY of its OWN code tail past offset 0x2d
  (`extcodecopy(address(), dst, 0x2d, argsLen)`), since address(this) == the clone under delegatecall. OZ
  `Clones.fetchCloneArgs(instance)` = instance.code[0x2d:].

## Surface (proposed builtins, byte-identical to OZ Clones 5.1)
- `isContract(addr: address): bool` -> `gt(extcodesize(addr), 0)` (OZ `addr.code.length > 0`).
- `clone(impl: address): address` -> EIP-1167 via CREATE; reverts (empty) on a zero return (OZ
  `Clones.clone`, error `ERC1167FailedCreateClone` / a plain revert is acceptable byte-target since OZ's is a
  custom error - MATCH OZ: it reverts `Create2FailedDeployment`/`ERC1167FailedCreateClone()` selector; gate to
  a clean revert and confirm the success-path bytes - the failure path is degenerate).
- `cloneDeterministic(impl: address, salt: bytes32): address` -> CREATE2 (same creation code).
- `cloneWithArgs(impl: address, args: bytes): address` / `cloneDeterministicWithArgs(impl, salt, args)` ->
  the modified-init creation code with `args` appended.
- `predictClone(impl: address, salt: bytes32): address` /
  `predictCloneWithArgs(impl, salt, args): address` -> CREATE2 address =
  `keccak256(0xff ++ address(this) ++ salt ++ keccak256(creationCode))[12:]` (the CREATE2 formula over the
  EXACT creation code above). Verify against the address `cloneDeterministic*` actually deploys to.
- `cloneArgs(): bytes` -> read THIS contract's own appended immutable args (extcodecopy of own code [0x2d:]).
  Only valid inside a contract that is meant to run as a clone impl. `cloneArgs().decode(T)` composes with the
  existing abi.decode-on-bytes to read typed args.

## JETH integration
- ir.ts: a `cloneDeploy` Expr { impl, args?, salt?, deterministic } and a `cloneArgs` Expr (bytes). `isContract`
  can be a `global`-ish or a small dedicated Expr (or desugar to `extcodesize(addr) > 0`).
- yul.ts: emit the EXACT creation code into memory (plain or modified-init+args), then
  `create(0, ptr, len)` / `create2(0, ptr, len, salt)`; revert on a zero result. `cloneArgs` ->
  extcodecopy(address(), allocBlob+0x20, 0x2d, sub(extcodesize(address()), 0x2d)) into a fresh [len][data]
  bytes value. `predictClone*` -> build the creation code, keccak it, then the CREATE2-address keccak.
- analyzer.ts: recognize the builtins in checkCall; `impl`/`addr` must be `address`, `salt` `bytes32`, `args`
  `bytes`; result `address` (or `bool` for isContract, `bytes` for cloneArgs). A deploying call writes state
  (CREATE is state-changing) -> requires a nonpayable (bare @external) or @payable caller, NOT @view/@pure
  (matches solc: a function that deploys cannot be view/pure).
- validator.ts: the `new` JETH023/JETH028 gates are unchanged (these are dedicated builtins, not `new`).

## Gates (clean reject, parity where solc has one)
- `clone`/`cloneDeterministic` from a @view/@pure function -> reject (CREATE mutates). `cloneArgs` is a pure
  read of own code (allowed in @view; it reads code, not state - confirm vs solc extcodecopy mutability).
- non-address impl, non-bytes32 salt, non-bytes args -> type error.

## Verification (byte-identical to OZ / a hand-written EIP-1167 factory in solc 0.8.35)
Deploy a JETH factory + impl and a solc factory (hand-written EIP-1167 assembly, OZ Clones-equivalent) + impl;
diff: (1) the deployed clone's RUNTIME code is byte-identical (the EIP-1167 stub, plain and with args);
(2) the clone delegatecalls the impl (initialize + a state read round-trip match); (3) cloneDeterministic
deploys to the address predictClone predicted, AND that address matches solc's CREATE2 of the same creation
code; (4) cloneArgs reads back the exact appended args (single + multiple, value + bytes via .decode);
(5) two clones of one impl are independent (separate storage); (6) the @view/@pure-deploy gate. Mirror the
immutable-args case against the modified-init solc factory.
