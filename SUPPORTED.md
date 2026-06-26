# JETH - supported vs unsupported features

Running checklist per directive §10.7. Updated through **Phase 4 + the solc-parity feature
sweep** (closed all 17 audit-found compile-time gaps; runtime byte-identical to solc), plus
**enums** and the **six distinctive features F1-F6** (see the next section and
[docs/distinctive-features.md](docs/distinctive-features.md)). The full suite is 1500+ differential
tests against `solc-js` (returndata + raw storage slots + event logs), zero known miscompiles.

## Differential audit (2026-06-20) - fixes

A fresh adversarial differential audit against solc 0.8.35 found and fixed the following. All are
verified byte-identical to solc and the suite stays green (1672 tests).

Silent miscompiles fixed (the dangerous class - JETH accepted + ran but produced wrong results):
- **Constant rational arithmetic**: a compile-time-constant expression is now evaluated as an EXACT
  rational and collapsed to a single range-checked integer literal (solc semantics), instead of eager
  truncating integer division. `(10n/4n)*4n` is now `10` (was `8`); `1n/2n + 1n/2n` is `1` (was `0`).
  As a side effect, compile-time constant overflow / div-by-zero / `2n**256n` / non-integer-rational
  results are now rejected at compile time (`JETH070`/`JETH079`), matching solc, instead of deferring
  to a runtime panic or silently truncating. Variable arithmetic (incl. `unchecked` wrapping) is
  unchanged - only fully-constant subtrees fold.
- **enum declared INSIDE the `@contract class`** previously produced an EMPTY ABI (every function
  silently dropped, all calls revert). In-class enums are now hoisted to top level pre-parse and the
  contract compiles normally (TS cannot parse an enum as a class member).
- **Nested array literal returns** (`return [[1n,2n],[3n,4n]]` for `u256[][]`) previously emitted
  malformed ABI (inner offsets past the returndata). A dynamic array literal must now have value-type
  elements (`JETH216`); nested/aggregate-element literals are rejected (solc rejects them too).

Over-acceptances fixed (JETH accepted programs solc rejects):
- Conflicting state mutability (`@view @payable`, `@pure @payable`) is now rejected (`JETH052`).
- `@public @state` was silently ignored (no getter). It now auto-generates a getter (solc parity);
  a getter colliding with a same-named function is a clean `JETH044`. Supported shapes, all
  byte-identical to solc:
  - value-type and `bytes`/`string` vars: `name() view returns (T)`.
  - mappings (nested ok), including value-type/`bytes`/`string`/`bytes`-or-`string`-KEY mappings,
    small-value masking, and a `mapping(K=>T[])` value (trailing `uint256` index param).
  - value-element arrays of any nesting (`T[]`, `Arr<T,N>`, `T[][]`, `T[][][]`, `mapping(K=>T[])`,
    `mapping(K=>Arr<T,N>)`): one `uint256` index param per dimension, incl. packed elements;
    `string[]`/`bytes[]` return the element. Out-of-bounds reverts with EMPTY data (matching solc's
    getter, NOT `Panic(0x32)`).
  - `bytes`/`string` multi-level arrays (`string[][]`, `mapping(K=>Arr<string,N>)`, ...): the dynamic
    element at the resolved place, empty-revert on OOB.
  - struct vars, and structs reached via a mapping/array (`mapping(K=>S)`, `S[]`, `Arr<S,N>`,
    `mapping(K=>S[])`): flattened to a tuple - the TOP struct OMITS all array + mapping members; a kept
    nested struct is a FULL sub-tuple whose FIXED arrays ARE included. An all-static nested struct is
    inlined; a DYNAMIC nested struct (a `bytes`/`string`/dynamic-array member at depth) is emitted as a
    whole storage-struct component (head/tail) at any nesting depth, reached via a constant OR a runtime
    (mapping/array) slot. Byte-identical to solc (incl. empty-revert on array OOB, zero-struct absent key).

  The auto-getter now matches solc for EVERY storage type JETH supports. The only `@public` vars solc
  accepts that JETH rejects are ones whose underlying STORAGE TYPE is itself unimplemented (so a manual
  getter or a write is rejected too, not a getter-specific over-rejection), e.g. `string[3][]` (a
  dynamic array of fixed arrays of a dynamic type, `JETH217`).

Over-rejections fixed (valid Solidity JETH wrongly rejected):
- `for (const x of this.structArray)` and a typed `let p: S = this.arr[i]` / `this.m[k]` (storage
  struct-array element / mapping struct value -> memory local) are now supported.
- A nested `switch` that terminates on every branch now satisfies the case-terminator analysis (no
  spurious "add a trailing break" `JETH284`).
- EIP-55 address hex literals: a 40-hex-digit bigint literal that passes the EIP-55 checksum (all-
  numeric literals pass trivially) is now of type `address`, so `K: address = 0x<40 hex>n` and
  `x == 0x<40 hex>n` work WITHOUT an `address(...)` cast (byte-identical to solc). Such a literal is
  address-typed everywhere: it casts only to `u160`/`bytes20`, never implicitly to an integer.

Over-acceptances fixed (same EIP-55 change): a 39/41-hex-digit literal, or a 40-digit literal with a
bad checksum, is now a hard error (`JETH049`) in ANY context (bare, inside a cast, in arithmetic),
exactly as solc rejects it; a 40-digit address literal no longer silently converts to a `uintN`
or `bytesN` (`u256 x = 0x<40 hex>n` is rejected, matching solc); ARITHMETIC/bitwise on an address
literal (`0x<40 hex>n + 1n`) is rejected (only `==`/`!=` allowed); and an uppercase `0X` hex prefix
is rejected (solc accepts only lowercase `0x`).

Over-acceptance fixed (`addmod`/`mulmod`): a zero modulus now reverts `Panic(0x12)` (matching
solc), not silently returning 0 (the raw EVM opcode's behavior).

Builtins added: `assert(cond)` (-> `Panic(0x01)`), `keccak256(bytes|string)`, `gasleft()`,
`blockhash(n)`, `<address>.balance`, `address(this).balance`, `block.difficulty` (= prevrandao).

Phase 6 (follow-up): a whole MEMORY or CALLDATA **static struct** assigned to storage (`this.s = m`,
`this.s = calldataParam`, incl. into a mapping value / nested struct field / struct-array element) now
transcodes the ABI-unpacked image into packed storage (byte-identical to solc, incl. packed raw slots).

A whole CALLDATA value-element dynamic-array param assigned to storage (`this.a = p`, `p: u256[]`)
now decodes + validates each element (solc-matching dirty-element revert) and packed-stores it
(byte-identical incl. packed raw slots, overwrite-clearing, and dirty narrow/bool/int element reverts).

`bytes`/`string` **mapping keys** (`mapping<bytes, V>` / `mapping<string, V>`, incl. nested and
storage value types) now derive the slot as `keccak256(keyContent . slotWord)` (solc's dynamic-key
rule), verified byte-identical incl. raw slots and empty/long keys.

`abi.encode(...)` and `abi.encodePacked(...)` (value-type and `bytes`/`string` args) now produce a
`bytes` value: standard mode mirrors the ABI head/tail tuple encoder; packed mode concatenates each
value's byte-width and each `bytes`/`string`'s raw content. Verified byte-identical to solc for
hashing (`keccak256(abi.encode...)`), returning, and storing the result, incl. mixed widths, negative
ints, dynamic args, nesting, and empty. Arrays/structs as args, and `abi.encodeWithSelector/Signature`,
remain a later step.

`sha256(bytes)` -> `bytes32` and `ripemd160(bytes)` -> `bytes20` (precompiles 0x02/0x03) are
supported and byte-identical to solc (incl. empty/short/long). `keccak256`/`sha256`/`ripemd160` take a
single dynamic `bytes` (a `string`/`bytesN` is rejected, matching solc; hash a string via
`keccak256(abi.encodePacked(s))`).

Signature recovery, all byte-identical to the matching solc 0.8.35 expansion:
`ecrecover(hash, v, r, s)` -> `address` is the RAW solc builtin (staticcall 0x01: `address(0)` on any
failure, never reverts, no malleability check). `recover(hash, sig)` and `recover(hash, v, r, s)` are
the SAFE OpenZeppelin 5.x `ECDSA.recover`: the strict `s > HALF_ORDER` reject
(`ECDSAInvalidSignatureS`), the 65-byte length reject on the `bytes` form
(`ECDSAInvalidSignatureLength`), and the `signer == 0` reject (`ECDSAInvalidSignature`), with the exact
custom-error selectors. `tryRecover(hash, sig)` -> `[bool, address]` is the never-reverting destructure
form. (The `and(staticcall, eq(returndatasize, 0x20))` guard must bind the success bool first - Yul
evaluates `and` arguments right-to-left, so an inline `returndatasize()` reads the stale pre-call value.)

The niche crypto precompiles take typed inputs and REVERT on invalid input (instead of the raw
precompile's silent zero): `modexp(base, exp, mod)` -> `bytes` (0x05); `bn256Add(p, q)` /
`bn256Mul(p, s)` over a 2-`u256`-field `G1Point @struct` / `bn256Pairing(input: bytes)` -> `bool`
(0x06/0x07/0x08); `blake2f(rounds, h, m, t, f)` -> `bytes(64)` (0x09); and
`pointEvaluation(versionedHash, z, y, commitment, proof)` -> `[fe, modulus]` KZG (0x0a, destructure-only,
192-byte `vh|z|y|commitment(48)|proof(48)` input matching EIP-4844).

`@receive recv() { ... }` (payable implied) and `@fallback fb() { ... }` are the special entry points,
dispatch byte-identical to Solidity's `receive()` / `fallback()` (empty calldata -> receive; a
non-matching selector or value to a non-payable fallback -> fallback / revert).

Calldata slicing uses a `.slice` method (Solidity's `data[start:end]` does not parse in the TS subset):
`data.slice(start)`, `data.slice(start, end)`, and `data.slice()` (the whole value) on a CALLDATA
bytes/string value - a `bytes`/`string` parameter, `msg.data`, a calldata struct's `bytes`/`string`
field, or another slice. It is a zero-copy calldata sub-view, byte-identical to solc's `data[start:end]`:
the result is `[base+start, end-start)`, `.length` is `end-start`, and the bounds check reverts EMPTY iff
`!(start <= end <= length)`. Indices must be unsigned (a signed index is rejected, matching solc). A slice
flows anywhere a calldata bytes value does (`return`, `abi.decode` / `.decode(T)`, `keccak256`/`sha256`,
`abi.encode`/`encodePacked`, an event/error arg, `address.call({data})`), so `abi.decode(msg.data.slice(4), T)`
skips the selector. A memory/storage value is not sliceable (matching solc); slicing a `bytes[]`/`string[]`
calldata ELEMENT is not yet supported (blocked by a pre-existing gap: JETH has no standalone calldata
array-element access).

A DYNAMIC-field struct (a `@struct` with `bytes`/`string` fields) assigned to storage from a memory
local (`this.d = m`) or a calldata struct param (`this.d = p`) now writes value fields packed and
`bytes`/`string` fields with overwrite-clear (byte-identical incl. raw slots, packing, and long->short
overwrite). A struct with a dynamic-ARRAY field from a memory/calldata source stays a clean rejection.

`@constant` `address` / `bytesN` (left-aligned) / `string` are supported: slot-free compile-time
constants substituted at each read site (a string as a fresh memory literal), byte-identical to solc
and consuming no storage slot.

`abi.encode` accepts every constructable arg type: value, bytes/string, a STATIC struct / fixed-array
(inline), a DYNAMIC value-element array, a DYNAMIC struct, and nested-dynamic arrays (`string[]`,
`T[][]`) - all offset + recursive head/tail. `abi.encodePacked` accepts value, bytes/string, and
value-element arrays (each element padded to 32 bytes, no length; a struct / nested-element array is
rejected, matching solc's "type not supported in packed mode"). `abi.encodeWithSelector(bytes4, ...)`
and `abi.encodeWithSignature(string, ...)` prepend the 4-byte selector to the standard encoding (the
signature's selector = keccak256(sig)[0:4], literal or runtime). All verified byte-identical to solc.

A NON-indexed STATIC struct / fixed-array event param is encoded INLINE in the ABI data tuple, and a
NON-indexed DYNAMIC struct (value + bytes/string + dyn value-array fields) is encoded as a head offset
+ head/tail tail. Byte-identical to solc (topic0 uses the struct's canonical tuple form; verified for
mixed value/struct heads, struct + a dynamic param, nested, packed, and calldata/memory sources).
(Indexed static struct/fixed-array params - a keccak topic - were already supported.)

A struct with a dynamic value-element ARRAY field (alongside value / bytes/string fields), built in a
memory local, now stores to storage byte-identically (length + keccak-data slots, overwrite-clearing).

The recursive aggregate codec is complete and solc-parity: a struct with a `string[]`/`T[][]`/dynamic
value-array field, a nested dynamic struct, `DynStruct[]`, `Arr<DynStruct,N>`, and element read/write of
a dynamic-element array reached via a struct field or nested array (`this.d.xs[i]`, `this.dd[i][j]`,
`this.o.inner.xs[i]`) all compile byte-identical to solc. The practical language surface is complete.

## Enums + distinctive features (F1-F6)
- **Enums** `enum Color { Red, Green, Blue }`: a Solidity-exact enum (ABI `uint8`, 1-byte storage
  packed like `uint8`, members `0,1,...`). `Color.Member` constants, comparisons (`==`/`!=`/`<`/...),
  `Color(x)` conversion (range-checked, `Panic(0x21)` on out-of-range), `uN(c)` extraction. Out-of-range
  enum CALLDATA decode EMPTY-reverts; arithmetic on enums and mixing two enums are rejected. Usable as a
  state var, param, return, mapping key/value, struct field, event/error arg. Byte-identical to solc.
- **F1 branded newtypes** `type TokenId = Brand<u256>`: a distinct NOMINAL value type over a value base
  (`uintN`/`intN`/`bool`/`address`/`bytesN`), fully erased at codegen/ABI/selectors (byte-identical to the
  base), with wrap/unwrap via `TokenId(x)` / `u256(t)`. Mixing brands, or a brand with its bare base, is a
  type error.
- **F2 struct spread + `for...of`**: `{ ...base, field: v }` immutable struct update (value-field structs)
  and `for (const v of xs)` over storage/calldata/memory/fixed arrays, both compile-time desugarings that
  are byte-identical to the hand-written equivalents.
- **F3 default + named arguments** (internal call sites only): a constant default `b: u256 = 10n`
  (trailing, value-typed, eagerly validated) filled when omitted, and named calls `this.f({ a, b })` that
  bind by parameter name. Defaults never reach the ABI (external callers pass every argument).
- **F4 `@nonReentrant`**: wraps an external/public state-mutating function in an EIP-1153 transient-storage
  reentrancy mutex (OpenZeppelin `ReentrancyGuardReentrantCall()` / `0x3ee5aeb5` on re-entry), no storage
  slot, never changing the ABI/selector/mutability.
- **F5 exhaustive `switch`**: `switch (disc) { case L: ... }` over a value/enum discriminant evaluated once,
  desugared to if/else; stricter than TS (no implicit fall-through, a non-empty case must terminate, an
  enum switch with no `default` must cover every member, duplicate constant labels are rejected).
- **F6 generics** `f<T>(...)`: type-safe generic INTERNAL functions, monomorphized at compile time (one
  specialization per concrete value-type instantiation, deduplicated, type-checked per instantiation,
  byte-identical to a hand-written type-specific function). A generic is never in the ABI.

## Language + type-system features (solc-parity sweep)
- Whole-aggregate storage ops: nested-struct field read/write/copy (`this.o.inner = D(...)`,
  `return this.o.inner`); whole fixed-array & struct-with-fixed-array return (`return this.fa`);
  whole dynamic-array storage-to-storage deep copy (`this.a = this.b`, `this.m[k] = this.arr`,
  resize + tail-clear); `Arr<D,N>` / `Arr<string,N>` storage; storage nested dynamic arrays
  (`u256[][]`, `u256[][][]`, `string[][]`, `D[][]`) with push/pop/length/index/return at the
  per-inner data slots; struct-with-dynamic-array-field (storage ops + calldata echo).
- Implicit WIDENING (`uintN`->`uintM`, `intN`->`intM`, `bytesN`->`bytesM`, M>=N) + mixed-width
  arithmetic/comparison; narrowing / sign change still need an explicit cast.
- Explicit casts `uintN(x)`/`intN(x)`/`bytesN(x)` (truncate / sign-extend / reinterpret;
  `uint<->bytes` same byte size; int<->uint same width).
- Exponentiation `a ** b` (checked, Panic 0x11); `unchecked: { ... }` labeled block (wrapping
  `+ - * ** ` and unary `-`); ternary `c ? a : b` (short-circuit); `type(T).max` / `.min`;
  `x++` / `x--` / `++x` / `--x` (statement form); memory array locals `let xs: u256[] = [a, b]`
  (value element: index read/write, `.length`, return); multi-value return `f(): [T1, T2]`
  with `return [a, b]` (value + bytes/string components). All byte-identical to Solidity.

## Supported now (compiles to bytecode + executes on EVM)

### ABI-v2 dynamic codec: NO nesting limit (supersedes older "gated" notes below)
The calldata decode and the return/echo encode are a single RECURSIVE codec over the
type tree (compile-time recursion = unbounded nesting depth; runtime loops for array
lengths). Verified byte-identical to Solidity (round-trip: solc encodes a known deep
value, JETH and solc both echo + index it). Supported as a calldata PARAM and RETURN,
at ANY depth: nested dynamic arrays (`u256[][]`, `u256[][][][][]`, ...), arrays of
dynamic (`string[]`/`bytes[]`, `string[][]`, `string[][][]`), dynamic structs
(`struct{...; string; ...}` incl. nested + multi dynamic field), a dynamic array of a
dynamic struct (`D[]`, `D[][]`), and a fixed array of a dynamic element
(`Arr<string,N>`, `Arr<D,N>`). Element/field access works at depth: `m[i][j][k]`,
`a[i][j]`, `ds[i].a`, `ds[i].s`, with OOB `Panic(0x32)` at each level. Adversarial
calldata (inner offsets, `>=2^255` wraps, `~2^64` lengths) matches solc byte-for-byte
(lazy-access signed wrap; echo unsigned cap + `Panic(0x41)` alloc). Returning a WHOLE
STORAGE aggregate whose field/element is dynamic also works via the storage-source
twin `abiEncFromStorage` (`return this.d` dynamic struct, `return this.ss` `string[]`,
`return this.recs` `D[]`), byte-identical incl. short/long-string transitions, AND
returning a whole MAPPING value `return this.m[k]` (struct / dynamic struct / value
array / `string[]`) encoded from the runtime `keccak(key . base)` slot.

### Surface / declarations
- `@contract` class -> contract.
- `@state` fields -> storage slots (Solidity-compatible layout + packing).
- Methods -> ABI functions.
- Visibility: `@external` is the SOLE writable visibility decorator (an exposed ABI entry point).
  A function / state variable WITHOUT `@external` is INTERNAL (private-by-default): callable by name
  from inside the contract, never in the ABI, not externally callable. `@public`/`@internal`/
  `@private`/`@hidden` are not writable (`JETH054`) - the compiler owns the internal-side decision
  (private now; private vs internal inferred from cross-contract use once inheritance lands). A
  `@external @state` variable gets an auto-generated getter and is still usable in code. To expose
  logic that also recurses / is reused internally, write an `@external` wrapper over an internal impl.
- Mutability decorators: `@view`, `@pure`, `@payable` (default nonpayable). INFERENCE: `@read` marks a
  read-only function, resolved to `@pure` (touches no state/env, transitively) or `@view` (reads, never
  writes); a transitive write is rejected (JETH056). All inference resolves to a concrete
  visibility+mutability before ABI emission, so the generated ABI is the true one.
- Constant state initializers (`@state x: u256 = 42n`) -> written in creation code.

### Types
- `u8`..`u256`, `i8`..`i256` (BigInt literals only).
- `bool`, `address`, `bytes1`..`bytes32`.
- `mapping<K,V>`, `T[]`, and `Arr<T,N>` are fully laid out AND code-generated (indexing, packing,
  push/pop, keccak slot derivation; see the Mappings / arrays sections below).
- `enum Name { ... }` (a 1-byte `uint8`-backed enum, ABI `uint8`; see "Enums + distinctive features").
- Branded newtypes `type X = Brand<Base>` (nominal value types, F1; see "Enums + distinctive features").

### Expressions / statements
- Checked arithmetic `+ - * / %` (default) -> `Panic(0x11)` overflow, `Panic(0x12)` div/mod-by-zero.
- Comparisons `< > <= >= == !=`, bitwise `& | ^ ~`, shifts `<< >>`, logical `&& || !`.
- Compound assignment (`+=`, `-=`, ...).
- `this.stateVar` read/write (full-word and packed).
- Local `let` with explicit type; parameters (static value types).
- `return`, expression statements.

### Control flow (Phase 2 + F2/F5)
- `if` / `else` / `else if`, `for(init; cond; post)`, `while`, `do...while`, `break`, `continue`.
- `for...of` over an array (F2): `for (const v of xs)` (storage/calldata/memory/fixed arrays),
  desugared to an indexed loop (re-reads length + element each iteration). `for...in` is rejected.
- `switch` (F5): `switch (disc) { case L: ... default: ... }` over a value/enum discriminant evaluated
  once, with exhaustiveness checking over enums and no implicit fall-through (see "Enums + distinctive
  features"). Solidity has no `switch`; JETH's desugars to if/else.
- Lexical block scoping with a scope stack. A nested local may shadow an outer-scope variable (like
  solc, which warns but accepts); a redeclaration in the SAME scope is rejected (JETH068). Each
  declaration gets a unique Yul name, so emitted Yul is always shadow-free. Labeled break/continue
  rejected. Fall-through returns the zero value (matches Solidity).

### Reverts & custom errors (Phase 2)
- `require(cond)`, `require(cond, "msg")`, `revert()`, `revert("msg")` -> byte-exact
  `Error(string)` / empty revert (verified vs solc; UTF-8 length, word padding).
- Custom errors: `@error Name(p: T);` declaration; `revert(Name(args))` /
  `require(cond, Name(args))` -> selector + ABI-encoded static args. Error args are
  evaluated **eagerly** (a side-effecting arg reverts even when the condition passes),
  matching solc. `type:"error"` entries emitted in the ABI.

### Events (Phase 2)
- `@event Name(@indexed p: T, q: U);` declaration; `emit(Name(args));`.
- topic0 = keccak256(canonical sig); `LOG(nIndexed+1)`; indexed params -> topics
  (int sign-extended, bytesN left-aligned, bool/uint/address as the word); non-indexed
  params -> ABI data region in declaration order. Rejected in `@view`/`@pure`.
  `type:"event"` entries (with `indexed` flags) emitted in the ABI.

### Mappings (Phase 3)
- `mapping<K,V>` storage, including nested `mapping<K, mapping<K2,V>>`.
- `this.m[k]` read/write/compound assign; slot = `keccak256(keyWord . p)` per level
  (recursive), **byte-identical to Solidity** (differentially verified, incl. raw slots).
- Value types and keys: uintN/intN/bool/address/bytesN (narrow values packed at the
  derived slot via read-modify-write, like solc). Keys hashed in register form
  (uint zero-ext, int sign-ext, address zero-ext, bytesN left-aligned).

### Environment globals (Phase 3)
- `msg.sender` (CALLER), `msg.value` (CALLVALUE, **@payable only**), `msg.sig` (selector),
  `tx.origin` (ORIGIN), `address(this)` (ADDRESS), and `block.timestamp/number/chainid/
  coinbase/basefee/gaslimit/prevrandao`. Forbidden in `@pure` (except `msg.sig`).

### Payable & address (Phase 3)
- `@payable` functions accept ETH (no callvalue guard); non-payable reject it (empty revert).
- `address(0n)` literal; `payable(x)`; `address<->uint160` (no-op) and `address<->bytes20`
  (96-bit shift) casts. Address comparisons are unsigned; address arithmetic is rejected.

### Dynamic bytes / string (Phase 4a)
- Storage (short <32 inline / long >=32 with `keccak(p)` data slots; overwrite-clearing),
  calldata params (bounds-checked decode), ABI return encode (head/tail), `.length` (bytes),
  `b[i]` -> bytes1 with `Panic(0x32)`, dynamic events + runtime `Error(string)`. Byte-identical
  to Solidity incl. raw slots.
- `mapping<K, bytes>` / `mapping<K, string>` scalar dynamic value (incl. nested
  `mapping<K, mapping<K2, bytes>>`): the value lives at the runtime `keccak(key . base)`
  mapping slot (short inline / long at `keccak(slot)`). Read / return / write
  (`this.m[k] = v`, overwrite-clearing the old tail) / `.length` (bytes) / `b[i]` byte-index
  with `Panic(0x32)`, all byte-identical to Solidity (short + long, empty, shrink/grow).

### Dynamic arrays `T[]` (Phase 4b)
- Storage (whole-slot, packed, unpacked-`address`), `push`/`pop`/`.length`/`a[i]`/`a[i]=v` with
  `Panic(0x32/0x31/0x41)`, `pop` zeroes freed slot/byte, calldata decode, ABI encode (unpacking
  packed storage to full words), mixed static+dynamic args.

### Structs (Phase 4c)
- `@struct class Name { ... }`; mixed-width field packing (Solidity-identical slots); `this.s.field`
  read/write (RMW); positional `Name(...)` construction, incl. nested `Outer(p, Inner(a,b), q)`
  (flattened into packed slots, Phase 4e-2c); whole-struct assignment; struct -> ABI tuple return.
- A `@struct` may have a MAPPING field (G7): `struct Acct { uint256 head; mapping(address => uint256) bal; }`.
  Such a struct is STORAGE-ONLY (matching solc): allowed as a `@state` var or a mapping VALUE
  (`mapping<K, Acct>`), accessed via `this.s.bal[a]` / `this.m[k].bal[a]` (the mapping base is the
  field slot `structBase + fieldSlot`; value at `keccak(key . base)`); the mapping field never packs
  with neighbours (its own slot). Byte-identical to solc on raw storage slots. A struct containing a
  mapping cannot be returned, a function param, constructed, copied, or a memory local (JETH247).
- Whole-struct assignment into a STORAGE aggregate slot (static or dynamic struct): a mapping
  value `this.m[k] = Name(...)`, an array element `this.recs[i] = Name(...)` / `this.fa[i] = P(...)`
  / `this.md[k][i] = D(...)`, and a state var `this.d = D(...)`. Both the constructed-literal
  form and the storage-to-storage COPY form (`this.m[a] = this.m[b]`, `this.recs[i] = this.recs[j]`,
  `this.d = this.m[k]`, cross-source): writeStruct / copyStruct land at the runtime element/mapping
  slot, clearing each dynamic field's old tail (long->short shrink, grow) byte-identically to solc.
- Whole-struct array-element READ / RETURN (`return this.recs[i]` / `this.fa[i]` / `this.md[k][i]`)
  encoded from the element slot by the storage-source recursive encoder (static = inline tuple,
  dynamic = `[0x20]` + head/tail). Bounds-checked (`Panic(0x32)`; const OOB is a compile error).

### Fixed arrays `Arr<T,N>` (Phase 4c)
- Inline storage (whole-slot + packed, straddle-free); `a[i]` read/write; `.length` (constant);
  runtime `Panic(0x32)`; constant out-of-bounds is a compile error.

### Nested storage access (Phase 4c-3)
- Unified AccessPath (field / index / mapKey steps): `this.s.inner.x`, `this.pts[i].x`,
  `this.m[k].field`, `this.arr[i].sub[j]`, `this.m[k].arr[i]`, `this.m[k][i].field`,
  `this.mat[r][c]`. Whole-slot index elements; byte-identical raw slots + OOB `Panic(0x32)`.

### Storage dynamic array of struct (Phase 4e-2)
- `@state recs: Rec[]` (the "list of records" pattern): `this.recs.push(Rec(...))`,
  `push()` (zero element), `this.recs.pop()`, `this.recs[i].field` read/write (RMW,
  incl. nested-struct and fixed-array element fields), `this.recs.length`. Element
  at `keccak(p)+i*storageSlotCount(struct)`, fields packed Solidity-identically.
  OOB `Panic(0x32)`, pop-empty `Panic(0x31)`; raw slots byte-identical.

### Mapping-valued dynamic arrays (Phase 4e-2b)
- `mapping<K, T[]>` (value or struct element): `this.m[k].push(...)` / `.pop()` /
  `.length`, `this.m[k][i]` read/write and `this.m[k][i].field` RMW. Length at the
  runtime mapping slot `keccak(key . base)`, data at `keccak(lenSlot)`; per-key
  isolation, byte-identical to Solidity.

### Array of dynamic elements `string[]` / `bytes[]` (Phase 4e-4)
- `string[]` / `bytes[]` as a calldata PARAM and as a RETURN (identical layout):
  whole-array echo (`return a`, head/tail re-encode with a per-element offset table
  whose base is the table start), `a[i]` (re-encoded as a standalone top-level
  string/bytes), and `a.length`. Outer offset base = calldata byte 4; element offsets
  relative to the table start (word after the length word); two inclusive range checks
  per dynamic level; `i >= len` -> Panic(0x32); any layout fault -> EMPTY revert.
  Byte-identical to Solidity (differentially verified). These COMPOSE through the recursive
  codec (4e-5): `string[][]` / `string[][][]` and a fixed `Arr<string,N>` (= `string[N]`) also
  work as a calldata PARAM and RETURN, with `a[i]` / `a[i][j]` element access and `.length`. A
  `string[]` (or `bytes[]`) inside a STRUCT works as a whole-struct echo / return; the one piece
  still gated is ELEMENT access into such a field on a calldata param (`s.xs[i]` -> JETH230).

### Storage / mapping-valued `string[]` / `bytes[]`
- `@state ss: string[]` / `bytes[]` and `mapping<K, string[]>` / `mapping<K, bytes[]>`:
  layout mirrors solc (length at slot `p` / runtime mapping slot `keccak(key.base)`;
  element header `i` at `keccak(lenSlot)+i`, a normal storage bytes/string: short
  `<32` inline, long `>=32` with `keccak(headerSlot)` data slots). Supports
  `this.ss.push(s)` / `.pop()` / `.length`, `this.ss[i]` read (re-encoded as a
  standalone top-level string/bytes on return) + write (`this.ss[i] = s`, overwrite-
  clearing of the old element's data slots), `this.bb[i].length` and a byte index
  `this.bb[i][j]`, and the same for the mapping-valued form (per-key isolation). Each
  element reuses the storage bytes/string codec; `pop` fully clears the freed header
  AND its data slots. OOB index `Panic(0x32)`, pop-empty `Panic(0x31)`, push past
  `2^64-1` `Panic(0x41)`. Byte-identical to Solidity incl. raw storage slots
  (differentially verified).

### Nested dynamic array `T[][]` (Phase 4e-5)
- `u256[][]` / `u8[][]` (a dynamic array of dynamic value arrays) as a calldata PARAM
  and as a RETURN: whole-array echo (`return m`, head/tail re-encode with a per-inner
  pointer table whose base is the pointer-region start = the word after the outer
  length word), `m[i][j]` element read, `m.length` (outer count), `m[i].length` (inner
  count). Outer offset base = calldata byte 4; inner-offset base = the word after
  `outer_len` (spec section 2). `u8[][]` is byte-identical to `u256[][]` except element
  validation (`m[i][j]` element `> 255` -> EMPTY on read; the echo CLEANS value
  elements, matching solc's array copy). Index OOB on either dimension (`i >= outerLen`
  or `j >= innerLen`) -> Panic(0x32); any layout fault (bad outer / inner offset,
  inner length implies elements past calldatasize, truncated pointer table, wrong-base
  offset) -> EMPTY revert. Overlapping / non-canonical inner offsets are accepted (pure
  pointer arithmetic). Byte-identical to Solidity (differentially verified).
- STORAGE array compositions (G6): `Arr<T[],N>` (= `uint256[][N]`, a fixed array of dynamic
  arrays) and `Arr<T,N>[]` (= `uint256[N][]`, a dynamic array of fixed arrays, incl. packed
  fixed elements like `uint8[4][]`) work as `@state` vars: element access, `.push`, `.length`,
  and nested indexing (`a[i][j]`), byte-identical to solc incl. raw storage slots. A whole
  calldata-param or return of these composite shapes stays gated.

### Dynamic array of static struct (Phase 4e-1)
- `Pt[]` as a calldata param (`Pt` a static struct): whole-array echo (`return ps`,
  head/tail decode + re-encode), element value-field read (`ps[i].x`), `ps.length`.
  ABI-unpacked elements (one word per leaf; stride = `abiHeadWords*32`), stride-aware
  decode payload bounds, OOB `Panic(0x32)`. Lazy field-read validation (dirty leaf
  reverts empty); a whole-struct-array echo VALIDATES every field (vs a value-array
  echo which cleans). Storage `Pt[]` and `ps[i]` whole-element are still deferred.

### Storage / mapping-valued dynamic structs (Phase 4e-7)
- A `@struct` with >=1 bytes/string field (a DYNAMIC struct) in STORAGE or as a
  mapping value: solc-identical layout (contiguous slots; each static field uses
  normal packed storage; each bytes/string field at `base + fieldSlot` is a normal
  storage bytes/string: short `<32` inline, long `>=32` with `keccak(headerSlot)`
  data slots). Supports a bare `@state d: D`, a `mapping<K, D>` value, a dynamic
  array of dynamic struct `@state recs: D[]` (and a `mapping<K, D[]>` value), and a
  nested `Outer{x; D inner; y}`. Operations: `this.d.field` read/write for both a
  static field (packed RMW) and a bytes/string field (`storeStrMem`, overwrite-
  clearing the old tail); whole-struct assignment `this.d = D(a, s)` (each field
  written in declaration order; the calldata string param is validated upfront, so
  a malformed arg reverts before any storage write, byte-identical to solc, no
  partial write); `this.recs.push(D(a, s))` / `push()` / `.pop()` / `.length`,
  `this.recs[i].field` read/write; the same via a mapping key; the bytes field's
  `.length` and a byte index `this.e.b[j]` / `this.recs[i].b[j]`. `pop` fully clears
  the freed element including each bytes/string field's `keccak(headerSlot)` long
  data slots (verified vs solc). OOB index `Panic(0x32)`, pop-empty `Panic(0x31)`,
  push past `2^64-1` `Panic(0x41)`; a malformed-calldata push/set reverts EMPTY with
  no slot written. Byte-identical to Solidity incl. raw storage slots (differentially
  verified). Returning a WHOLE storage dynamic struct (`return this.d`, `return
  this.m[k]`) stays gated (JETH232: read its fields); `D[]` as a calldata
  param / return, and fixed `Arr<D,N>` of a dynamic struct, stay gated.

### Dynamic structs (Phase 4e-6)
- A `@struct` with >=1 dynamic field (bytes/string, or a nested struct that is
  itself dynamic) is a DYNAMIC struct (spec section 3) and is supported as a
  calldata PARAM and as a RETURN, byte-identical to Solidity. Static fields stay
  INLINE in the tuple head (declaration order); each dynamic field gets a head
  OFFSET word whose base is the TUPLE START. Supports: reading `d.staticField`
  (lazy dirty-bit validation -> EMPTY), `d.dynField` (bytes/string), `e.name.length`,
  `e.name[i]` (bytes index, OOB -> Panic 0x32); echoing a dynamic struct (`return d`,
  decode + head/tail re-encode, static fields VALIDATED); constructing + returning
  one (`return D(a, s)`, literals included); nested `Outer{x; D inner; y}` field
  reads / echo / construct (each container's offsets reset to ITS tuple start);
  multiple dynamic fields in one struct (e.g. `{a; string s; bytes b; z}`). The
  param head word = offset to the tuple (base byte 4); per-tuple field offsets
  relative to the tuple start (spec section 3.2); bounds checks per dynamic level;
  any layout fault (offset/length past calldatasize, truncated head, wrong-base
  offset) -> EMPTY revert; field reads are LAZY (a malformed UNREAD dynamic field
  is ignored). Differentially verified. A `@struct` with a dynamic-ARRAY field
  (`T[]`/`string[]`/`T[][]`) is now supported in storage, as a whole-struct RETURN,
  and as a whole-struct calldata-param echo; only ELEMENT access into such a field of
  a calldata struct param (`s.xs[i]`) stays gated (JETH230). `D[]` (a dynamic array of
  dynamic structs) and fixed `Arr<D,N>` as a calldata param/return are gated cleanly.

### Aggregate calldata params (Phase 4d)
- `struct` and fixed-array `Arr<T,N>` function parameters, decoded lazily from the
  ABI-**unpacked** head (one 32-byte word per leaf; head cursor advances by
  `abiHeadWords`, nested structs flattened inline). Field / index / nested reads
  (`p.x`, `a[i]`, `o.inner.b`, `t.data[j]`, `ps[i].y`), constant + runtime indices,
  `.length`. Lazy per-access validation: a dirty leaf read reverts empty, an unread
  dirty leaf is ignored; runtime OOB `Panic(0x32)`; short calldata reverts empty.
  Mixes with value and dynamic (`T[]`/`bytes`) siblings (head cursor + byte-4 tail base).

### Backend / interop
- Yul IR -> solc (Cancun) -> creation + runtime bytecode.
- ABI JSON emitted from the analyzer; canonical 4-byte selectors.
- Static value-type calldata decoding with **strict input validation** (dirty
  high bits on uintN/intN/bool/address/bytesN revert, matching Solidity 0.8) +
  single static return encoding.
- Packed storage (incl. left-aligned bytesN) is **byte-identical to Solidity**
  (differentially verified).
- Short-circuiting `&&` / `||` (RHS not evaluated when it can revert).
- Non-payable functions reject ETH; unknown selector reverts.

## Post-sweep surface detail (what's supported, with the remaining gates inline)

This section records the detailed post-Phase-4 surface beyond the headline sections above: the
solc-parity sweep CLOSED the earlier "storage aggregate" gaps (whole-struct field read/write/copy,
whole fixed-array/struct return, whole dynamic-array copy, `Arr<D,N>`/`Arr<string,N>` storage,
storage `u256[][]`/`string[][]`/`D[][]`/`T[][][]`, struct-with-dynamic-array-field, general
numeric/bytes casts, implicit widening, `**`, ternary, `unchecked`, `type(T).max`, `++`/`--`,
memory value-array locals, multi-value return). The bullets below describe what is now SUPPORTED in
each area, calling out the few pieces still gated inline; the genuinely-unsupported items are
consolidated in the **"Still gated"** list at the end. Every gate rejects with a precise diagnostic
and is never miscompiled.
- Calldata struct-with-dynamic-array-field FIELD ACCESS (`s.xs[i]` on a param); the whole-struct
  ECHO of such a param works.
- STATIC struct MEMORY locals are supported (G9): `let p: P = P(...)` construct, value-field read/write
  including nested chains (`p.x`, `p.inner.x`, `d.o.inner.a`, `p.x = v`, `p.x += v`, `p.x++`),
  whole-struct return, and memory aliasing (`let q = p`; a write through `q` is visible through `p`).
  @internal/@private functions take and RETURN static structs as memory by reference (mutation in a
  callee is visible to the caller); a struct can be passed, returned, bound to a local, chained, and
  built via recursion. Also supported: copying a memory local FROM a storage struct or calldata struct
  param (`let p: P = this.s` / `= calldataParam`, a fresh COPY); reading a whole nested struct field
  as a value (`return p.inner`, aliasing); `bytes`/`string` memory locals (`let s: string = X`: return,
  `.length`, `b[i]`, alias); FIXED-ARRAY-of-value memory locals (`let a: Arr<u256,3> = [...]`: `a[i]`
  read/write, return, alias, storage/calldata copy). DYNAMIC-field struct memory locals are also
  supported (G10) when every field is a value type or `bytes`/`string` (no static-array, nested-struct,
  or dynamic-array fields): `let d: D = D(x, str)` construct, value-field read (`d.a`) and write
  (`d.a = v`), dynamic-field read (`d.s` whole, `d.b.length`, `d.b[i]`), and whole-struct `return d`.
  The image is a pointer-headed tuple (value fields inline, `bytes`/`string` fields a `[len][data]`
  pointer), so `return d` reuses the dynamic-struct tuple encoder via a memory `TupleSrc`; dynamic
  fields may be built from a memory-string local (alias) or a string literal. A dynamic-field struct
  memory local may also be COPY-initialized from a storage struct (`let d: D = this.st` / `this.m[k]` /
  `this.recs[i]`), a calldata struct parameter (`let d: D = x`, decoded + validated into a fresh image),
  or ALIASED from another struct local (`let e: D = d`, a Solidity memory reference); and a `bytes`/
  `string` field may be WRITTEN (`d.s = x`, re-pointing the head word at a fresh blob). A NESTED-STRUCT
  field works fully in a struct memory local (construct + deep read). Still gated: a struct memory local
  with a DYNAMIC-array field (JETH200), and ELEMENT access into a FIXED-array field through the local
  (`s.a[i]`, JETH900); a struct param to a PUBLIC/EXTERNAL callee via an internal call (an external/
  message call, Phase 6); `new T[](n)` (use an array literal).
- Tuple destructuring works: `let [a, , c] = src` and `[a, , c] = src` where `src` is a multi-value
  internal call (`this.f()`) or a tuple literal (`[x, y]`, e.g. swap `[a, b] = [b, a]`); new locals,
  existing value lvalues incl. storage, or skipped components; value components only.
- The `delete x` statement works on every storage location (value/packed/struct/array/dynamic/bytes/
  string/mapping-value/nested-place/local), leaving mappings intact; `delete` of a whole mapping is
  rejected (parity with solc).
- A packed (`<256`-bit) element of a nested DYNAMIC array (`this.m[k].dynArr[i]`); the packed
  FIXED-array case through a struct field (`this.q.pts[i]`) now works (runtime byte offset).
- A ternary over `bytes`/`string` (`c ? a : b`, literal/storage/calldata branches) and over a STATIC
  struct or fixed array (`c ? this.x : this.y`, materialized + pointer-selected, incl. nested ternary)
  now work; only a DYNAMIC storage struct/array ternary stays gated (select before the aggregate op).
- A whole DYNAMIC calldata array / struct param as a COMPONENT of a multi-value return
  (`return [calldataArrayParam, x]`) works, as do element components (incl. a `string[]` element)
  and storage / memory-array components; only a WHOLE STATIC calldata aggregate (`Arr<T,N>` or a
  static struct param) as a component stays gated (JETH900).
- Whole FIXED-array storage copy (`this.g = this.src`), whole STORAGE-source inner-array assignment
  (`this.dd[i] = this.other`), and reading a whole fixed-array (`return this.g[i]`) work; assigning a
  whole FIXED-array element in place (`this.g[i] = arr`) and a CALLDATA-source inner-array assignment
  (`this.dd[i] = xs`) stay gated.
- Mixed calldata composite element access works: `uint256[2][]` (dynamic-of-fixed) and `uint256[][2]`
  (fixed-of-dynamic) support `a[i]`, `a[i][j]`, `a[i].length`, and whole-param echo (JETH151/210),
  byte-identical incl. malformed-offset/length EMPTY-revert and full N-word head readability.
- Standard tuple ABI JSON: struct params/returns render as `(t1,t2)` in the JSON `type` field
  rather than `type:"tuple"` + `components` (selectors are canonical and correct; JSON-shape polish).
- `msg.data` is the whole calldata as `bytes` (selector included, so `msg.data.length` ==
  `calldatasize()`): `.length`, copy to a memory bytes / return, and byte-indexing (Panic 0x32 OOB);
  allowed in `@pure` (calldata, like `msg.sig`).
- An indexed FIXED-array or static-struct event param is a keccak topic of `abi.encode(value)` (from a
  `@state` source or a calldata-param source). Indexed `bytes`/`string` and indexed DYNAMIC
  value-element arrays also work (keccak of the content / element words). All byte-identical to solc.
- `@constant` fields: a slot-free compile-time constant (uintN/intN/bool) inlined at each read site
  (no SLOAD, no storage slot, absent from the ABI), byte-identical to solc incl. raw storage layout.
- Evaluation ORDER of side-effecting subexpressions now matches solc: BINARY operands evaluate
  RIGHT-to-LEFT and ARGUMENT lists (array literals, return tuples, event/error args, call args)
  LEFT-to-RIGHT, byte-identical to solc (verified). This covers `++`/`--` in value position and
  assignment-expressions `(x = v)`/`(x += v)`/`x = y = a`.
- Internal/private/public function calls are supported (`this.method(...)` or bare `name(...)`)
  for value-typed and void params/returns (plus static-struct params/returns to @internal/@private
  callees), with recursion, mutual recursion, and transitive `@view`/`@pure` purity. A MULTI-VALUE
  internal call (value return components) is callable via tuple destructuring (below). Aggregate
  (array/bytes/string) params/returns through an internal call remain gated. At internal call sites,
  default arguments (`f(a, b = 10n)`) and named arguments (`this.f({ a, b })`) are supported (F3),
  and generic functions `f<T>(...)` are monomorphized per concrete value-type instantiation (F6).
- Tuple destructuring: `let [a, , c] = src` (declaration, new locals) and `[a, , c] = src`
  (assignment to existing value lvalues incl. storage; omitted slots discard the component), where
  `src` is a multi-value internal call (`this.f()`) or a tuple literal (`[x, y]`, e.g. swap
  `[a, b] = [b, a]`). The RHS is fully evaluated before any store. Value components only (an
  aggregate/bytes component in a tuple is gated). Byte-identical to solc.
- **Phase 5 (functions in depth) - constructors, immutables, modifiers** (byte-identical to solc
  incl. raw storage slots): a `constructor(params) { body }` runs once at deploy - value-type params
  (uintN/intN/bool/address/bytesN/enum/branded) are ABI-decoded from the args appended to the init
  code (decoded from memory), the body may write `@state` and read `msg.sender` / `msg.value`
  (`@payable`) / `address(this)`, constant field initializers run before it, and a non-payable
  constructor rejects deploy-time value. `@immutable` value-type fields are assigned in the
  constructor and baked into the runtime code via `setimmutable`/`loadimmutable` - they consume NO
  storage slot (a constructor read sees the staged value, a runtime read is `loadimmutable`, and
  reading one needs `@view` not `@pure`). User `@modifier`s (a single `_` placeholder, applied via
  `@name` / `@name(args)`) inline their code around the body - both PRE-code (a guard like
  `require(cond); _;`) and POST-code (after `_`). Post-code with an early `return` uses solc-identical
  buffered-return semantics: the body's `return` runs the enclosing modifier post-code (inner-first,
  from any depth incl. inside a body loop) before the value is encoded and returned once (the body is
  lowered as a synthesized Yul function so `return` becomes `ret := v; leave`). Multiple modifiers nest
  leftmost-outermost, the same modifier may apply twice, arguments evaluate exactly once (a modifier
  param never shadows a same-named function param in the body), their effects feed the purity fixpoint,
  and they compose with `@nonReentrant`. Post-code is scoped to value-type-param functions with a
  void/value/bytes/string return (an aggregate/dynamic param, multi-value/aggregate return, or a
  constructor with post-code is cleanly gated JETH323).
  A `@modifier` may also decorate the **constructor** (the canonical base-init guard, e.g.
  `@onlyValid constructor(...) { ... }`). The identifier `_` is reserved (the modifier placeholder)
  and cannot be a declared name (JETH034), matching solc.
- Phase 6 (IN PROGRESS, each byte-identical to solc): external low-level calls
  (`addr.call`/`tryCall`/`staticcall`/`code`/`codehash`/`revertWith`), `abi.decode`(+`<bytes>.decode`
  + a `decode:` call option), typed interface calls `IFoo(addr).bar(x)`, `try`/`catch`,
  `new Array<T>(n)`. STILL TO DO: inheritance (`is`/`virtual`/`override`/`super` + base ctors),
  libraries (`using for` / `DELEGATECALL`), `ecrecover` + remaining precompiles, `receive`/`fallback`,
  function types, `bytes`/`string.concat`, calldata slicing, `new` contract / CREATE2, and source
  maps / CLI polish. (`address.transfer`/`.send` are deliberately omitted - the safe pattern is CEI +
  `@nonReentrant` over a full-gas `addr.call`.)

### Still gated (the complete list of what is rejected with a diagnostic, never miscompiled)

Each of the following compiles to a clean compile-time error (verified), not a miscompile:
- **ELEMENT access into a dynamic-array field of a calldata struct param** (`s.xs[i]` where
  `xs: u256[]`/`string[]`) - JETH230. The WHOLE-struct echo / return of such a param works.
- **Aggregate (array / `bytes` / `string`) params or returns through an internal call** - JETH242.
  Value-typed and static-struct params/returns to `@internal`/`@private` callees work.
- **A struct param to a PUBLIC/EXTERNAL callee via an internal call** - JETH242 (that is a message
  call, Phase 6); a struct param to an `@internal`/`@private` callee works (by-reference memory).
- **A struct memory local with a DYNAMIC-array field** (`u256[]` / `string[]`) - JETH200; and ELEMENT
  access into a FIXED-array field through such a local (`s.a[i]`) - JETH900. Value-typed,
  `bytes`/`string`-field, and NESTED-STRUCT-field struct memory locals work fully (G9/G10).
- **`new T[](n)`** - JETH023 (use an array literal `let xs: u256[] = [...]`).
- **In-place assignment of a WHOLE fixed-array element** `this.g[i] = arr` - JETH226 (whole fixed-array
  storage copy `this.g = this.src` and whole STORAGE-source inner-array assignment
  `this.dd[i] = this.other` work; a CALLDATA-source inner-array assignment `this.dd[i] = xs` is gated).
- **A WHOLE STATIC calldata aggregate (`Arr<T,N>` or a static struct param) as a multi-value-return
  component** - JETH900. A whole DYNAMIC calldata array/struct component, element components (incl. a
  `string[]` element), and storage/memory components all work.
- **A ternary over a DYNAMIC storage struct / array** - JETH074 (select before the aggregate op;
  ternary over `bytes`/`string` and over a static struct/fixed array works).
- **A packed (`<256`-bit) element of a NESTED dynamic array** `this.m[k].dynArr[i]` (the packed
  fixed-array-through-a-struct-field case `this.q.pts[i]` works).
- **Tuple ABI JSON shape**: struct params/returns render as `(t1,t2)` rather than `type:"tuple"` +
  `components` (selectors are canonical and correct; this is a JSON-shape gap, not a behavior gap).
- **Phase 5 increment-1 gates** (each a clean diagnostic, never a miscompile; solc accepts unless
  noted): a constructor with an aggregate/dynamic param (JETH302), one that calls an internal
  function (JETH303), or a defaulted ctor param (JETH304); an `@immutable` that is inline-initialized
  (JETH311) or `@public` with an auto-generated getter (JETH312) - a non-value-type immutable
  (JETH310) and an immutable assigned outside the constructor (JETH313) are accept/reject parity
  (solc rejects too); a `@modifier` whose `_` placeholder is inside a conditional/loop (JETH321 - the
  0-or-N-times case; post-placeholder code in straight-line position IS supported), more than one `_`
  (JETH320), a `return` (JETH324 = parity since solc rejects a value return / JETH325 for a bare
  `return`), an aggregate param (JETH322), a generic modifier (JETH327), and (with POST-code) an
  aggregate/dynamic-param or multi-value/aggregate-return function or a constructor (JETH323). One known low-severity over-rejection: a constructor that *provably* overflows a
  staged `@immutable` that is read at runtime is rejected (JETH901) where solc accepts and the deploy
  then reverts - solc's Yul optimizer strips the dead `setimmutable`, leaving an unassigned
  `loadimmutable`; the contract is non-functional (reverts at construction) in both compilers.
- **Phase 6 remaining** (external low-level/message calls, `abi.decode`, interface calls, `try`/`catch`
  and `new Array<T>(n)` are DONE): inheritance, libraries (`using for`/`DELEGATECALL`), abstract
  contracts, `ecrecover` + remaining precompiles, `receive`/`fallback`, function types,
  `bytes`/`string.concat`, calldata slicing, `new` contract / CREATE2, `address.transfer`/`.send`
  (deliberately omitted), source maps / CLI polish.

## Permanently rejected (no on-chain meaning)

`number`/floats, `any`, async/await, generators, closures/free functions,
`throw`, try/catch, regex, template literals, `typeof`/`instanceof`/`in`,
array/call spread/rest (`[...a]`, `f(...a)`), `eval`. (Object spread `{ ...base, x: v }`
in a struct literal IS supported, F2.)

## delete

- `delete x` (Solidity storage reset to the type's zero value) is supported on storage
  value vars (packed-aware: a packed field zeroes only its lane), structs (value fields
  zeroed, bytes/string fields cleared, nested struct/array fields recursed, MAPPING fields
  left intact - matching solc), fixed arrays, dynamic arrays (data slots zeroed + length 0),
  bytes/string (header + long-data slots freed), mapping VALUES (`delete this.m[k]`, incl.
  struct/bytes values and `this.m[k].field`), nested places (`delete this.s.f`,
  `delete this.a[i]`), and local value variables. `delete` of a WHOLE mapping is rejected
  (parity: solc also rejects it). Verified byte-identical to solc on returndata AND raw
  storage slots (incl. computed keccak data slots).

## Known JS-vs-EVM divergences flagged (directive §9 "known danger")

- `a + b` is **checked** 256-bit integer add, never JS `+` (no string concat, no floats).
- Integer literals must be BigInt (`1n`), never `1`.
- `==` is value equality on 256-bit words (no JS coercion); maps to EVM `EQ`.
- No implicit numeric conversions between integer widths or between bool and int
  (enforced in expressions AND state initializers).
- `&&` / `||` short-circuit: the RHS is not evaluated when the result is already
  determined, so a RHS that would revert (e.g. division) does not run, matching
  Solidity.
- A nested local may shadow a visible outer variable (accepted, matching solc, which
  warns but compiles); a redeclaration in the SAME scope is rejected (JETH068), and
  disjoint sibling blocks may reuse a name. Each declaration gets a unique Yul name so
  emitted Yul is always shadow-free, so shadowing never miscompiles. The for-of and
  switch desugars mint their temps with a counter that skips past every visible user
  name, so a user variable spelled like an internal temp is never hijacked.
- `require`/`revert` custom-error arguments are evaluated eagerly (unconditionally),
  so an arg that reverts fires even when the condition passes - matches solc, not
  JS short-circuit intuition.
- `msg.value` is readable only in `@payable` functions (matches solc; it is NOT
  silently 0 elsewhere). Reading environment globals (`msg.*`/`block.*`/`tx.*`/
  `address(this)`) is forbidden in `@pure`.
- `address` is a distinct value type: comparisons are unsigned, arithmetic is
  rejected, and `address`/`address payable` share one EVM word (payable->plain is
  implicit, the reverse needs `payable(...)`).

## Intentional, safer-than-solc deviations (adversarial calldata only)

For **honest, ABI-encoded calldata** JETH is byte-identical to solc everywhere
(verified by the differential suite). The differences below arise only with
**hand-crafted, malformed calldata** that no conforming encoder produces; in each
case JETH errs strictly safe (it rejects), so a contract's behavior toward real
callers is unaffected. They are documented rather than matched because replicating
solc's signed-offset / allocator footguns would add no honest-caller value while
risking the verified happy path.
- A dynamic-container INNER offset (a tuple member, a `T[][]` inner pointer, a
  `string[]`/`bytes[]` element offset) whose value has the high bit set (`>= 2^255`):
  solc treats it as a signed/negative offset, wraps the pointer mod 2^256, reads the
  out-of-range word as zero, and proceeds with a zero-length payload (returning empty
  or `Panic(0x32)` on a later index). JETH rejects any such offset with an EMPTY
  revert. Offsets in `(2^64, 2^255)` revert in BOTH compilers.
- A dynamic length near `2^64-1` in a decode-to-memory copy: solc's allocator
  overflows and raises `Panic(0x41)`; JETH's bounds check raises an EMPTY revert
  first. Both fail the call; only the revert form differs.
- Deep internal-call RECURSION (live depth in roughly `[~340, ~1100)`): solc lowers
  internal calls to EVM-stack frames and hits the 1024-slot stack limit, reverting with
  "stack overflow" (gas-independent); JETH lowers internal calls to Yul functions whose
  frames live in memory, so it computes the correct value where solc aborts. The exact
  per-function ceiling depends on solc's register allocation (e.g. ~338 frames for a
  one-extra-local callee), which is impractical to replicate from a Yul backend. For all
  realistic call depths the two are byte-identical; only pathological recursion (hundreds
  of frames, astronomical gas) differs, and there JETH is strictly more capable (correct
  result vs solc revert).
