# JETH contract inheritance - design spec (solc 0.8.35-verified)

Multiple contract inheritance via **compile-time flattening** (solc has no runtime vtables): the
deployed contract is the C3-linearized merge of its base chain. JETH flattens the hierarchy into ONE
`ContractIR` *before* the existing analyze/emit pipeline, so most of the pipeline is reused unchanged.
Every rule below was verified against solc 0.8.35 (storageLayout, AST linearization, and on-EVM
execution).

## Surface (all parse in the TS subset, verified)

- `@abstract class A { ... }` - a non-deployable base (Solidity `abstract contract`). May contain
  unimplemented `@virtual` methods (bodyless). Emits no creation code.
- `@contract class C extends A, B { ... }` - the deployed contract; multiple bases via the comma-list
  in the TS `extends` clause (both land in `heritageClauses[0].types`, in source order).
- Base constructor args: heritage call-form `extends A(7), B(x)` (a heritage type node whose
  `.expression` is a `CallExpression`), OR modifier-style on the derived constructor
  (`constructor() A(7) { ... }`). NOT both for the same base.
- `@virtual` on a base method allows overriding; `@override` on the derived. Diamond override needs
  the explicit list `@override(B, C)`.
- `super.f(args)` - calls the next implementation in the linearization.

## solc-verified semantics (the miscompile traps)

1. **C3 direction**: `D is B, C` (B is A, C is A) => linearization `[D, C, B, A]` (most-derived first,
   LAST-listed base wins priority). Algorithm: reverse each `extends` list, run standard Python C3
   merge, prepend the contract. `D is B, A` (B is A) is C3-impossible -> REJECT.
2. **Storage layout** = REVERSE of linearization (most-BASE first). Feed ONE flat `RawStateVar[]`
   (deepest base's vars first, each contract's vars in declaration order) to the existing
   `planLayout` with NO per-contract reset; packing carries across the base/derived boundary.
   Verified: `A{a} B is A{b} C is A{c} D is B,C{d}` -> a@0 b@1 c@2 d@3; `A{u128 a1} B is A{u128 b1; u256 b2}`
   -> a1@0.0 b1@0.16 b2@1.
3. **State-var name collision**: a same-name var across the chain is REJECTED ("Identifier already
   declared") UNLESS the base one is `private` (then both coexist and BOTH take slots). JETH has no
   `private` state-var surface (all `@state` are internal-equivalent), so JETH REJECTS any same-name
   `@state` across the chain (the private-shadow case can't be expressed in JETH).
4. **Override winner**: per (name + param types), the impl from the EARLIEST (most-derived) contract in
   the linearization wins and keeps the bare ABI key. Non-winning base versions are retained ONLY as
   `super` targets, keyed per defining-contract (`FunctionIR.definingContract`).
5. **Inherited ABI/dispatch**: every NON-overridden base `@external` function (and base public-var
   getter, N/A in JETH) is carried into the merged ABI + dispatch - their selectors are inherited.
   Verified `[a,b,f]`, `[g,h]`.
6. **virtual/override rules**: base needs `@virtual` to be overridden; EVERY intermediate override that
   is itself further overridden must ALSO be `@virtual` (3-level non-virtual-mid -> REJECT). `@override`
   is REQUIRED on every redefinition, INCLUDING the first concrete impl of an abstract bodyless method.
   A diamond collision needs `@override(B, C)` listing ALL bases; bare `@override` (no list) is ALSO
   rejected. Override return type must be identical.
7. **Mutability override ladder** (one-way, more-restrictive only): `payable > nonpayable > view > pure`.
   Allowed: nonpayable->view, nonpayable->pure, view->pure, and X->X; `payable` only by `payable`.
   Everything else (loosening, or crossing payable) REJECTS. (Full 4x4 matrix verified.)
8. **Visibility override**: `public` can override `external` but not vice-versa. JETH maps to
   @external-vs-internal: an external/internal mismatch across the override pair is a clean reject.
9. **super.f()** inside a method defined by `Cx` resolves to the FIRST contract AFTER `Cx` in the
   most-derived contract's FULL linearization that DEFINES `f` (verified by exec: `D is B,C` super
   order 4->3->2->1 over [D,C,B,A]; `D is C,B` -> 4->2->3->1). If the next-in-line is
   abstract/unimplemented -> REJECT ("Member f not found in type(contract super B)").
10. **Constructor two-phase order** (verified 902->901->101->200): PHASE 1 - evaluate ALL base-ctor
    ARGUMENT expressions most-DERIVED-first (side-effecting args MUST run in this order), binding each
    base's params; PHASE 2 - run ctor bodies most-BASE-first (A->B->C->D). Empty/no-arg base ctors
    still run their bodies in chain order. REJECT: a base's args given twice (heritage + modifier, OR
    two bases both specifying a shared diamond base); a missing required base-ctor arg on a non-abstract
    derived ("specify the arguments or mark X as abstract").
11. Inherited `@constant`/`@immutable` consume NO slot. Inherited events, errors, and `@modifier`s are
    merged and usable in the derived contract.

## JETH integration plan (flatten before the existing pipeline)

- **src/parser.ts**: add `heritageBases(cls) -> {name, args?: ts.Expression[]}[]` from
  `cls.heritageClauses[0].types` (CallExpression -> name + args; bare Identifier -> name only).
  `@abstract`/`@virtual`/`@override` are bare-identifier decorators already read by `decoratorNames`;
  `@override(B,C)` is call-form (read via `decoratorCall`).
- **src/analyzer.ts** `analyze()`/`findContractClasses` (~L246/L664): collect `@contract` AND
  `@abstract` classes; keep JETH041 for >1 `@contract`; allow any number of `@abstract`; build a name
  registry; compute the C3 linearization of the single deployed `@contract` (reject on impossible
  merge with a new code); FLATTEN into a merged synthetic class, then run the existing `analyzeContract`
  on it. Only the `@contract` deploys.
- **Merged STATE** (feeds `planLayout` ~L712): walk the linearization deepest-base-first, concat each
  contract's `collectStateVar` output; reject a same-name `@state` across the chain.
- **Merged FUNCTIONS + override resolution** (`collectFunction` ~L1684, `fkey` ~L5397): winner per
  signature = most-derived; carry non-overridden base externals into the ABI/dispatch; keep non-winning
  versions as per-contract-keyed `super` targets; enforce all the virtual/override/override-list/
  return-type/mutability-ladder/visibility rules above.
- **super.f()** (near the internal-call resolver / `checkFunction` ~L2165): resolve to the
  next-in-linearization defining contract; emit a direct internal call to that contract-keyed `userfn`.
- **Constructor merge** (`checkConstructor` ~L1195): one `jeth_constructor` whose body encodes the
  two-phase order (args most-derived-first, bodies most-base-first); accept heritage + modifier-style
  base args; reject double-spec / missing-required.
- **src/layout.ts**: NO change (already does cross-var sequential packing).
- **src/ir.ts**: add `FunctionIR.definingContract?: string` (per-contract `super` versions coexist
  without colliding with the #47 overload keying; the winner keeps the bare ABI key). `ConstructorIR`
  stays single. The merged `ContractIR` carries merged state + winner functions + inherited base
  externals + the chained ctor; the downstream emit pipeline is unchanged.

## Build order + scope

Build the general multiple-inheritance machinery, but VERIFY incrementally against solc and GATE
anything not byte-identical: (1) single chain `C extends A` (trivial C3) - state merge, an inherited
fn, a `@virtual`/`@override` pair, a base ctor with args; (2) deeper chain A<-B<-C + `super`; (3)
multiple bases / diamond `D extends B, C` + `@override(B,C)` + the C3 order + the two-phase ctor.

Cleanly GATE (each a distinct diagnostic, never a crash/miscompile): C3-impossible order; override of a
non-`@virtual`; missing `@override`; missing/incomplete `@override` list in a diamond; differing return
type; mutability loosening / payable crossing; visibility mismatch; same-name `@state` across the chain;
a non-`@abstract` contract with an unimplemented `@virtual`; `super` to an unimplemented next-in-line;
base ctor args twice / missing-required.

## Verification (byte-identical to solc 0.8.35)

Differential probes on RAW STORAGE SLOTS + returndata + ABI + event logs + revert data: storage layout
order (single + diamond, incl. packing across the boundary); an inherited external fn callable on the
derived; override winner; `super` chain order (3-level + both diamond orders); the two-phase constructor
arg-eval/body order with side-effecting args; inherited modifier guarding a derived fn; inherited
immutable set in a base ctor (no slot); the full accept/reject gate matrix vs solc.
