# JETH - supported vs unsupported features

Running checklist per directive §10.7. Updated through **Phase 4 + the solc-parity feature
sweep** (closed all 17 audit-found compile-time gaps; runtime byte-identical to solc).

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
- Visibility decorators: `@external`, `@public`, `@internal`, `@private` (default `public`).
- Mutability decorators: `@view`, `@pure`, `@payable` (default nonpayable).
- Constant state initializers (`@state x: u256 = 42n`) -> written in creation code.

### Types
- `u8`..`u256`, `i8`..`i256` (BigInt literals only).
- `bool`, `address`, `bytes1`..`bytes32`.
- `mapping<K,V>` and `T[]` / `Arr<T,N>` are **parsed and laid out**, but codegen for
  indexing them is Phase 3/4.

### Expressions / statements
- Checked arithmetic `+ - * / %` (default) -> `Panic(0x11)` overflow, `Panic(0x12)` div/mod-by-zero.
- Comparisons `< > <= >= == !=`, bitwise `& | ^ ~`, shifts `<< >>`, logical `&& || !`.
- Compound assignment (`+=`, `-=`, ...).
- `this.stateVar` read/write (full-word and packed).
- Local `let` with explicit type; parameters (static value types).
- `return`, expression statements.

### Control flow (Phase 2)
- `if` / `else` / `else if`, `for(init; cond; post)`, `while`, `break`, `continue`.
- Lexical block scoping with a scope stack; shadowing forbidden; `for...of`/`for...in`,
  labeled break/continue rejected. Fall-through returns the zero value (matches Solidity).

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
  Byte-identical to Solidity (differentially verified). `string[][]`, fixed
  `string[N]`, and `string[]` struct fields are rejected with a diagnostic.

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
  (differentially verified). A `string[]` nested deeper (struct field, `string[][]`,
  fixed `string[N]`) stays gated.

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
  is ignored). Differentially verified. STORAGE / mapping-valued dynamic structs,
  a dynamic-ARRAY struct field (`T[]`/`string[]`/`T[][]` inside a struct), `D[]`
  (a dynamic array of dynamic structs), and fixed `Arr<D,N>` are gated cleanly.

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

## Not yet supported (rejected with a precise diagnostic - never miscompiled)

After the solc-parity sweep, the earlier "storage aggregate" gaps are CLOSED (whole-struct
field read/write/copy, whole fixed-array/struct return, whole dynamic-array copy, `Arr<D,N>`/
`Arr<string,N>` storage, storage `u256[][]`/`string[][]`/`D[][]`/`T[][][]`, struct-with-dynamic-
array-field, general numeric/bytes casts, implicit widening, `**`, ternary, `unchecked`,
`type(T).max`, `++`/`--`, memory value-array locals, multi-value return). Remaining cleanly-gated:
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
  `string` field may be WRITTEN (`d.s = x`, re-pointing the head word at a fresh blob). Still gated:
  structs with static-array/nested-struct/dynamic-array fields as memory locals; a struct param to a
  PUBLIC/EXTERNAL callee via an internal call; `new T[](n)` (use an array literal); non-value aggregate
  components in a multi-value return.
- A packed (`<256`-bit) element of a nested DYNAMIC array (`this.m[k].dynArr[i]`); the packed
  FIXED-array case through a struct field (`this.q.pts[i]`) now works (runtime byte offset).
- A ternary over a storage struct / storage array / bytes / string (`c ? this.a : this.b`); a ternary
  over value types or memory arrays works (select before the aggregate op).
- A calldata-aggregate echo COMPONENT in a multi-value return (`return [calldataArrayParam, x]`);
  storage and memory-array components work, and echoing the calldata aggregate as the SOLE return works.
- Assigning a whole FIXED-array element (`this.g[i] = arr`); reading it (`return this.g[i]`) and
  whole DYNAMIC inner-array assignment (`this.dd[i] = xs`) work.
- Standard tuple ABI JSON: struct params/returns render as `(t1,t2)` in the JSON `type` field
  rather than `type:"tuple"` + `components` (selectors are canonical and correct; JSON-shape polish).
- `msg.data`; indexed reference-type event params.
- Evaluation ORDER of side-effecting subexpressions now matches solc: BINARY operands evaluate
  RIGHT-to-LEFT and ARGUMENT lists (array literals, return tuples, event/error args, call args)
  LEFT-to-RIGHT, byte-identical to solc (verified). This covers `++`/`--` in value position and
  assignment-expressions `(x = v)`/`(x += v)`/`x = y = a`.
- Internal/private/public function calls are supported (`this.method(...)` or bare `name(...)`)
  for value-typed and void params/returns, with recursion, mutual recursion, and transitive
  `@view`/`@pure` purity. Aggregate (struct/array/bytes/string) params and returns, and
  multi-value returns through an internal call, are gated until aggregate memory locals land.
- Phase 5: constructors, modifiers, immutables.
- Phase 6+: external calls, `address.balance`/`.call`/`.transfer`, `new` contract, inheritance,
  libraries, interfaces, abstract contracts, receive/fallback.

## Permanently rejected (no on-chain meaning)

`number`/floats, `any`, async/await, generators, closures/free functions,
`throw`, try/catch, regex, template literals, `typeof`/`instanceof`/`in`,
spread/rest, `eval`.

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
- Local variables may not shadow a visible outer variable (rejected; stricter than
  Solidity, which only warns), but disjoint sibling blocks may reuse a name. Each
  declaration gets a unique Yul name so emitted Yul is always shadow-free.
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
