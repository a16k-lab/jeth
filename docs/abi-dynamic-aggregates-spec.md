# JETH ABI Spec: Dynamic Aggregates (head/tail, ABI-coder v2)

This spec drives the 4e codegen. It is derived entirely from empirically-measured solc behavior (probe families: `dyn-array-of-static-struct`, `nested-dynamic-array`, `dynamic-struct`, `array-of-dynamic`, `multiple-and-mixed-dynamic-params`). All offsets are byte values; all words are 32 bytes. "Args region" means the bytes after the 4-byte selector (calldata byte 4); "return region" means returndata byte 0.

---

## 0. Universal model (the recursive core)

Every ABI value is either **static** (fixed width, no indirection) or **dynamic** (carries a length and/or an offset). The encoder and decoder are recursive walks over the type tree. Two primitives govern everything:

### 0.1 The head/tail rule (one container level)

A container (the top-level tuple of params/returns, a struct, or an array's element sequence) is laid out as:

```
HEAD: one slot per item, in declaration order
        static item  -> its value words INLINE (width = static size, may be >1 word)
        dynamic item -> ONE 32-byte OFFSET word
TAIL:  the payload of each dynamic item, in declaration order, contiguous
```

### 0.2 The relative-offset base rule (THE load-bearing invariant)

**Every offset is measured from the start of the data region of the container that holds it.** The base *resets at every dynamic-container boundary*. There are exactly these base points (all proven asymmetrically in the probes):

| Offset stored in... | Its base (offset = target_byte − base_byte) |
|---|---|
| Top-level param/return head | Start of args region (calldata byte 4) / returndata byte 0 |
| Inside a tuple (struct) | The tuple's first field word (the "tuple start") |
| Element-offset table of `T[]` (dynamic-element array) | The word **immediately after** the array length word (= first element-offset word) |
| Inner-offset table of `T[][]` | Same: the word **immediately after** `outer_len` |

> Note the asymmetry: for a **tuple** the base is the tuple's first field word; for a **dynamic array** the base is the word *after* the length (the offset-table start), **not** the length word itself. This distinction was decisively measured (nested-array: base=`outer_len_word+32`; string[]: base=`table start`; struct: base=`tuple start`).

### 0.3 Length & padding rules

- `T[]` length word = element count. Each static element occupies its full ABI width inline (a `uint8` element still takes a whole 32-byte word).
- `string`/`bytes` length word = length **in bytes**; payload is the raw bytes **right-padded** (left-aligned, trailing zero bytes) up to the next 32-byte multiple. Payload word count = `ceil(len_bytes/32)`. A **zero-length** string/bytes is exactly one word (its `0` length word), **no** payload word.
- Integer/bool field alignment in a word: unsigned ints (`uintN`) are **right-aligned** (left-zero-padded); `bool` is a full word `0`/`1`. (Signedness/`bytesN`/`address` alignment: see OPEN QUESTIONS.)

### 0.4 The two decode range checks (applied per dynamic level, in this order)

For a dynamic item whose offset is `O` relative to base `B` (so `ptr = B + O`), with `argsEnd = calldatasize`:

1. **Length-word readable:** require `ptr + 32 <= argsEnd` (i.e. `O + 32 <= regionLen`). Boundary is **inclusive** (`==` is OK). Fail → **EMPTY revert**.
2. **Payload in range:** read `L` at `ptr`; require the whole payload to fit:
   - `T[]` of static `T`: `ptr + 32 + elemSize*L <= argsEnd`.
   - `string`/`bytes`: `ptr + 32 + L <= argsEnd`.
   - The decoder also guards the `elemSize*L` multiply against overflow (huge `L` → fail). Boundary **inclusive**. Fail → **EMPTY revert**.

### 0.5 Error discipline (must match byte-for-byte)

- **Index out of range** (`i >= length` for any decoded array/string-array index, at any nesting level) → **Panic(0x32)**: returndata = `0x4e487b71` followed by the 32-byte word `0x…0032` (36 bytes total), call reverts. `i == length` is OOB.
- **Any calldata-layout fault** (offset out of range, length implies payload past `argsEnd`, truncated head, truncated payload, narrow-element over its type max, dirty/clean-bits violation in a struct field) → **EMPTY revert**: `revert(0,0)`, returndata `0x`, **no** selector, **not** a Panic.
- Offsets are **not** required to be 32-aligned, **not** required to point past the static head, may overlap/swap/self-reference. solc does pure pointer arithmetic + the two range checks. **JETH must not add alignment or canonical-ordering checks.**
- **Truncated head** (calldatasize too small to hold one word per top-level param, counting static aggregates as multiple words) → EMPTY revert, before any offset is interpreted.

### 0.6 Canonical signature / selector rule

For selector computation, **a struct name must be replaced by its tuple type** in the canonical signature, recursively. E.g. `getP(P[],uint256)` is wrong; the canonical form is `getP((uint256,uint256)[],uint256)` → selector `e3e81306`. (Measured: the bare-name form produced `ed50c24b`, which solc does not use.) JETH's `functionSelector` must expand all struct names to tuple types before hashing.

---

## 1. Dynamic array of STATIC struct — `P[]`, `S[]`

A static struct has **no inner offsets**: each field is its own full 32-byte word, inline, in declaration order, **unpacked** (storage packing is irrelevant to ABI). Define `structWords(S)` = number of fields (one ABI word each). Element **stride** = `structWords(S) * 32`.

- `P{uint256 x; uint256 y}` → `structWords=2`, stride `0x40`.
- `S{uint128 a; uint64 b; bool c}` → `structWords=3` (still 3 words even though storage-packed into 1 slot), stride `0x60`.

### 1.1 ENCODE (return)

The array is dynamic → one **top-level offset word = 0x20** (sole return), then the array data region:

```
@0x00  0x20                         <- top-level offset (returndata byte 0 base)
@0x20  length n                     <- array data region START
@0x40  elem0.field0
@0x60  elem0.field1   ... (structWords words for elem0)
       elem1.field0 ...             <- elements inline, contiguous, NO inner offsets
```

Element `i`, field `f` byte position: `0x20 + 0x20 + i*stride + f*0x20`.
Total bytes = `0x20 (offset) + 0x20 (length) + n*stride`.

Worked (measured `encP()`, n=3): `[0x20][0x03][x0][y0][x1][y1][x2][y2]` = 256 bytes.
Worked (measured `encS()`, n=2): `[0x20][0x02][a0(uint128 right-aligned)][b0(uint64 right-aligned)][c0(0/1 full word)][a1][b1][c1]` = 256 bytes.

### 1.2 DECODE (param) — e.g. `getP(P[] a, uint256 i)`

Calldata: selector + 2-word head: `word0 = offset` (base = args region, byte 4) to array data region; `word1 = i` (static, inline). Then at `4 + offset`: `[length][elements inline]`.

`dataStart = 4 + offset + 32` (skip length word). `a[i].fieldF` at `dataStart + i*stride + f*0x20`.

Decode check order (each failing step 1-4 → EMPTY revert; step 5 → Panic):
1. Head fully present (both words) — else EMPTY.
2. `offset` in range (`4 + offset + 32 <= calldatasize`; absurd offset like `2^255` → EMPTY).
3. **Up-front full-payload check:** read `length` at `4+offset`; require `length*stride` bytes present (`dataStart + length*stride <= calldatasize`). Truncated/zero-byte payload → EMPTY, **independent of `i`**, before any indexing.
4. **Per-element clean-bits on access:** for the accessed element, `uint128 a` and `uint64 b` must have zero high bits beyond their width; `bool c` must be `0` or `1`. Violation → EMPTY revert (clean-bits abort, **not** a Panic). Triggered when the indexed field is read.
5. **Index bound:** only on a well-formed array, `i >= length` → **Panic(0x32)**.

### 1.3 Relative-offset base (proven asymmetric)

Top-level array offset base = **calldata byte 4** (post-selector). Proven: `offset=0x40,i=1`→elem1; `offset=0x60` (extra pad word inserted)→**still** elem1; `offset=0x200,i=2`→elem2; `offset=0` reads length at byte 4 = the `i`-word (value 0) → seen as empty array → Panic(0x32). Internal addressing is from the data-region start (`4+offset`).

### 1.4 Edge cases (measured)

- Non-32-aligned but in-range offset (e.g. `0x41`) with a valid array placed there → **SUCCEEDS**.
- `length = 0xffff…` with no/short payload → EMPTY (payload-fits fails).
- Boundary: element data ending exactly at `calldatasize` for the accessed element → SUCCESS; one word short → EMPTY.
- Empty array (`length=0`): valid, `lenP` returns 0; any index → Panic(0x32).

---

## 2. Nested dynamic array — `T[][]` (`uint256[][]`, `uint8[][]` identical)

`uint8[][]` is byte-for-byte identical to `uint256[][]` because `uint8` elements still occupy full 32-byte words. The only `uint8` difference is decode validation (element > 255 → EMPTY).

### 2.1 ENCODE (return)

```
[outer_data_offset]               <- one head word, 0x20 for sole return (base = returndata byte 0)
outer data region:
  [outer_len]                     <- count of inner arrays
  [inner_off_0]...[inner_off_{N-1}]   <- N pointer words (the "pointer region")
  [inner0 tail][inner1 tail]...   <- contiguous inner tails
each inner tail = [inner_len][elem_0]...[elem_{inner_len-1}]   (each elem a full word)
```

**Inner-offset base = the word immediately AFTER `outer_len` (= pointer-region start).** Pointer value for inner array `k` = byte distance from pointer-region-start to inner `k`'s length word. Canonical contiguous layout:
- `inner_off[0] = N*32`
- `inner_off[k] = inner_off[k-1] + 32 + inner_len[k-1]*32`

Worked (measured `enc256()` = `[[1,2,3],[4],[5,6]]`, 448 bytes, 14 words):
`[32][3][96][224][288][3][1][2][3][1][4][2][5][6]`.
Base check: pointer region starts at byte 64. `64+96=160`→`len(inner0)=3`; `64+224=288`→`len(inner1)=1`; `64+288=352`→`len(inner2)=2`. The alternative base (the `outer_len` word at byte 32) gives `32+96=128`→an *element* (wrong). Asymmetric lengths `(3,1,2)` make only the correct base reproduce all three.

### 2.2 DECODE (param) — e.g. `get256(i, j)` over `m: uint256[][]`

1. Read `off_m` from the param head (base = byte 4). Read `outer_len` at `4 + off_m`. Pointer region begins at the next word (`4 + off_m + 32`).
2. `m[i][j]`:
   - bounds-check `i < outer_len` → else **Panic(0x32)**.
   - `inner_off[i]` = pointer word at `pointerRegionStart + i*32`.
   - inner `i`'s length word at `pointerRegionStart + inner_off[i]`. Calldata-OOB read (pointer/length/element past `calldatasize`) → **EMPTY revert**.
   - bounds-check `j < inner_len` → else **Panic(0x32)**.
   - element at `innerLenWord + 32 + j*32`.

### 2.3 Relative-offset base (proven asymmetric, both sides)

Encode base proven above. Decode base proven: blob `[1][0x40][filler][2][111][222]` with `inner_off0=0x40` (= 2 words from pointer-region start: 1 pointer + 1 filler) → `get(0,0)=111`, `get(0,1)=222`; setting `inner_off0=0x20` (points at filler-as-length) → EMPTY revert; no filler + `inner_off0=0x20` → correct. Relativity proven: shifting the whole `m` blob by +0x40 (`off_m=0xA0`, 2 filler words before it) with inner offsets **unchanged** → still correct (`get(2,0)=5`, `get(0,2)=3`), disproving an absolute base.

### 2.4 Edge cases (measured)

- Bad `off_m` past calldata (`0xFFFFFFFF`) → EMPTY. Absurd `outer_len=2^64` → EMPTY.
- Bad `inner_off[i]` (`2^64`, `0x1000`, or pointing at a word holding a huge len) → EMPTY.
- Misaligned `off_m` (e.g. `0x61`) is **not** an error per se: solc reads verbatim; here it read garbage `outer_len` and `m[0]` → Panic(0x32). Misaligned `inner_off` (`0x21`) read a huge len → element OOB → EMPTY. **Reproduce the read semantics, do not special-case alignment.**
- `uint8[][]` element `=256` → EMPTY (validation); `=255` → OK.
- Empty outer (`[outer_len=0]`, no pointers/tails): `outerLen=0`; any access → Panic(0x32). Empty inner (`[inner_len=0]`): `innerLen=0`; access → Panic(0x32).

---

## 3. Dynamic struct (tuple with ≥1 dynamic field) — bare and nested

A tuple with at least one dynamic field is itself **dynamic**. Static fields stay **inline in the tuple head in declaration order**, even when they follow a dynamic field; only dynamic fields are deferred to the tail (each represented in the head by an offset word).

**Level-1 base = the tuple's first field word ("tuple start").** Offsets inside a tuple = `(payload byte) − (tuple start byte)`.

### 3.1 ENCODE (return)

Bare/sole dynamic struct: `[head: 0x20][tuple encoding at byte 0x20]`. Tuple encoding = for each field in declaration order (static → value word inline; dynamic → offset word relative to tuple start), then the tail = each dynamic field's payload in field order.

Measured layouts:

**(1) `D{uint256 a; uint256[] b}`**, `retD()` a=7, b=[10,20]:
```
@0x00 0x20      head
@0x20 0x07      a            <- tuple START
@0x40 0x40      off_b (rel tuple start) -> 0x20+0x40 = 0x60
@0x60 0x02      b.length
@0x80 0x0a      b[0]
@0xa0 0x14      b[1]
```
`off_b` is **always 0x40** for `D{a,b}` (a + off_b = 2 static head words). `retD2` (b.len=3) → identical `off_b=0x40`.

**(2) `retDpair()` = (D{7,[10,20]}, uint256 marker=0x9999)** — the asymmetric encode proof:
```
@0x00 0x40      head[0]: offset to D (base = return region byte 0); marker took head slot 0x20
@0x20 0x9999    head[1]: static marker INLINE in head (NOT after the tail)
@0x40 0x07      D tuple word0 = a   <- tuple START now byte 0x40
@0x60 0x40      off_b = 0x40 UNCHANGED -> len at 0x40+0x40 = 0x80
@0x80 0x02 ...
```
Tuple start moved `0x20`→`0x40`, yet `off_b` stayed `0x40`: base is tuple start, not byte 0.

**(3) `E{uint64 id; string name}`**, `retE()` id=0x42, name="hello": `[0x20][0x42][off_name=0x40][len=5]["hello" right-padded]`. `off_name=0x40` rel tuple start. 36-byte name → `len=0x24`, two payload words; same `off_name=0x40`.

**(4) Nested `Outer{uint256 x; D inner; uint256 y}`**, `retNested()`:
```
@0x00 0x20      head
@0x20 0x1111    x            <- Outer START
@0x40 0x60      off_inner (rel Outer start) -> 0x20+0x60 = 0x80
@0x60 0x3333    y            <- static, INLINE in Outer head, before inner's tail
@0x80 0x2222    inner.a      <- inner tuple START
@0xa0 0x40      off_b (rel INNER start 0x80) -> b len at 0x80+0x40 = 0xc0
@0xc0 0x02 ...  inner.b
```
`off_inner=0x60` rel Outer start; `off_b=0x40` rel inner start. **Each container's internal offsets are based at THAT container's start — bases compose/reset at every dynamic boundary.**

**(5) `D[]` (dynamic array of dynamic structs)**, `retDarray()` = `[{7,[0x10]},{8,[0x20,0x21,0x22]}]`:
```
@0x00 0x20      head
@0x20 0x02      array.length   <- ARRAY DATA START (element offsets are relative to HERE)
@0x40 0x40      elem[0] off (rel array data start) -> 0x20+0x40 = 0x60
@0x60 0xc0      elem[1] off (rel array data start) -> 0x20+0xc0 = 0xe0
@0x80 ...       elem0 tuple (its OWN off_b rel 0x80)
@0xe0 ...       elem1 tuple (its OWN off_b rel 0xe0)
```
**Level-2 base for `D[]` = the array length word** (`0x20` here). Asymmetric inner b-lengths (1 vs 3) force non-uniform element offsets `0x40` vs `0xc0`, proving genuine per-element offsets. Each element tuple then has its own level-1 base at that element's start.

### 3.2 DECODE (param) — e.g. `f(D calldata d)`

- Top-level head word = offset to tuple, base = args region (byte 4). Canonical `0x20` for a sole `D`.
- `d.a`: read word at `tuple_start + 0`. (Measured `getA` → 7.)
- `d.b.length`: read `off_b` at `tuple_start + 0x20`; `len_ptr = tuple_start + off_b` (**base = tuple start**); read length there. (Measured `getBlen` → 2.)
- `d.b[k]`: in-bounds → element; `k >= len` → **Panic(0x32)**.

Base proof (decode, asymmetric): tuple placed at args-byte `0xA0` (head `[0x40][k]` + 3-word pad). `off_b=0x40` (rel tuple) → SUCCESS (`b[1]=0xbeef`); `off_b=0xE0` (= `0xA0+0x40`, i.e. measured from args start) → EMPTY revert. Isolates base = tuple start.

### 3.3 Edge cases (measured)

- `off_b` need not be 32-aligned: `off_b=0x41` with in-bounds zero-len word → SUCCESS (len 0). Head offset `0x21` (odd) → SUCCESS (byte-shifted `a` = `0x…0700`).
- `off_b` need not point past the static head: `off_b=0x00` (overlaps field `a`) is accepted as a pointer → reads `len=a=7` → payload bounds fail → EMPTY. Only validation is arithmetic bounds, **not** a structural `>= head` check.
- `off_b` may point to a different (real) array deeper in the tail (decoy test) → returns that array's element. Pure pointer arithmetic from tuple start.
- All structural faults (offset out of calldata, length implies payload past end, truncated payload, top-level offset past end like `0x1000`, huge `b.length`) → **EMPTY revert**. The **only** Panic on this path is `d.b[k]` with `k >= len`.

---

## 4. Array of dynamic — `string[]` / `bytes[]` (identical layout)

`string[]` and `bytes[]` use byte-for-byte identical head/tail; only payload content differs. JETH may share one encoder/decoder, parameterized only by payload bytes.

### 4.1 ENCODE (return)

```
@0x00 0x20                 <- OUTER offset to array data region (base = returndata byte 0)
array data region (@0x20):
  region+0x00  length L (element count)
  region+0x20  off_s0      <- ELEMENT-OFFSET TABLE starts HERE (this is the base)
  region+0x40  off_s1
  ...          off_s{L-1}
  payloads: each element = [len_in_BYTES][payload right-padded to 32-byte multiple]
            a 0-length element = just its length word (value 0), NO payload word
```

**Element-offset base = the start of the element-offset table = the word immediately after the array length word** (`region + 0x20`).

Worked (measured `f()` = `["ab","cdef",""]`):
```
@0x20 3  (len)
@0x40 0x60 (off_s0)  @0x60 0xa0 (off_s1)  @0x80 0xe0 (off_s2)
@0xa0 2 ["ab" -> 6162..]  @0xe0 4 ["cdef"->6364656600..]  @0x120 0 (empty, no payload word)
```
Base check (table start = byte `0x40`): `0x40+0x60=0xa0` (s0 len), `0x40+0xa0=0xe0` (s1 len), `0x40+0xe0=0x120` (s2 len) — all land exactly on length words. `bytes[]` (`g()`) identical structure.

Asymmetric encode proof (`h2()` = [40-byte, "Z"]): `off_s0=0x40`, `off_s1=0xa0`. Gap `0xa0−0x40 = 0x60` = first element's encoded size (1 len + 2 payload words for 40 bytes), so offsets accumulate by prior element size from the table start.

### 4.2 DECODE (param) — e.g. `len(string[] a, uint256 i)`

- Outer param head word = offset to array region, base = args region (byte 4). Canonical `0x40` (two head words: array-offset + `i`).
- Array region: `word0 = L`; then `L` element-offset words (the table) immediately follow.
- `a[i]`: read `off_si` = the `i`-th table word; element data begins at `table_start + off_si` (that word = `s_len` in bytes; next `ceil(s_len/32)` words = payload).
- Returning `a[i]` re-encodes it as a standalone top-level string: `[0x20][len][padded payload]`. `count(a)` returns `L`.

Range/validity:
- `i >= L` → **Panic(0x32)** (the ONLY non-empty malformed case).
- Absurd declared `L` (`0xffff…`) with no backing data → EMPTY.
- `off_sk` out of calldata, outer offset out of calldata, `s_len` past calldata, truncation (declares `L=1` but no table word/payload) → EMPTY.
- Element offsets given relative to the **wrong base** (calldata byte 0) → land OOB → EMPTY.

### 4.3 Relative-offset base (proven asymmetric, decisive decode shift)

Built `["WX"(2B), "Y"*40(40B)]` with table values `0x40`, `0x80`. Prepended 2 junk words before the array region and bumped only the **outer** offset `0x40`→`0x80`, leaving table values unchanged → decode still returned `len=2` and `len=40`. An absolute (byte-0) base would have broken; it kept working, so base = the array's own element-offset-table start. Negative control: table values relative to calldata byte 0 (`0x100`/`0x120`) → EMPTY.

---

## 5. Multiple / mixed top-level dynamic params

Top-level layout = HEAD (one slot per top-level param, declaration order) + TAIL (dynamic params' payloads, declaration order, contiguous). Static scalar → 1 inline head word. **Static aggregate** (`uint256[3]`, or an all-static struct) → **all its words inline** in the head (N words), no offset, never in the tail. Dynamic param → 1 offset word. **Every top-level offset base = start of head region** (returndata byte 0 / calldata byte 4).

### 5.1 ENCODE (return) — measured

**`f(uint256[] a, uint256[] b)`** → `([0xAA], [0xB0,0xB1,0xB2])`:
`[off_a=0x40][off_b=0x80][a.len=1][0xaa][b.len=3][0xb0][0xb1][0xb2]`. Head = 2 words. `off_a=0x40`→byte 64; `off_b = off_a + 32 + 32*len_a = 0x80`. Tails sequential (a then b).

**`g(uint256 x, uint256[] a, string s)`** → `(0x1234, [0xA0,0xA1], "hello")`:
`[x=0x1234 inline][off_a=0x60][off_s=0xc0][a.len=2][0xa0][0xa1][s.len=5]["hello" left-aligned padded]`. Head = 3 words. `off_s = off_a + 32 + 32*2 = 0xc0`.

**`h(uint256[3] a, uint256[] b)`** → `([0xC0,0xC1,0xC2], [0xD0,0xD1])`:
`[0xc0][0xc1][0xc2]` (static `uint256[3]` INLINE, 3 head words) `[off_b=0x80][b.len=2][0xd0][0xd1]`. Head = 4 words; `off_b = 96 (inline) + 32 (offset word) = 0x80`. The static aggregate consumes 3 head words and never gets a tail; it shifts every following dynamic param's head word index and offset.

ENCODE offset formula: `offset(dynamic param) = headSizeBytes + (cumulative byte size of all preceding dynamic params' tails)`.

### 5.2 DECODE (param) — measured

- For top-level param `i`, read head word(s) at `headStart + 32*wordIndex` (wordIndex accounts for static aggregates consuming multiple words). Static → use value(s) directly. Dynamic → treat word as unsigned offset `O`, `ptr = headStart + O` (headStart = 4 for calldata).
- **Check 1** (length readable): `O + 32 <= argsLen` (argsLen = `calldatasize − 4`), inclusive. Else EMPTY.
- **Check 2** (payload in range): read `L`; `T[]` static `T`: `O + 32 + elemSize*L <= argsLen`; string/bytes: `O + 32 + L <= argsLen`; guard `elemSize*L` overflow. Inclusive. Else EMPTY.

### 5.3 Relative-offset base (proven asymmetric + injected gap)

`fdec` shifted: 32-byte gap between the 2-word head and a's tail; `off_a=0x60` (= 64-byte head + 32 gap), `off_b=0xA0` (= `0x60 + 32 + 32*len_a(1)`), a.len=1[0xAA], b.len=3[0xB0..0xB2] → decoded exactly. `off_a=0x44/off_b=0x84` (the values needed if base were full-calldata byte 0) → REV. Proves base = byte 4 (head start), not byte 0.

### 5.4 Tolerances (measured) — DO NOT add checks solc lacks

- **No alignment requirement:** valid len=1 + element at a non-32-aligned byte, `off_a=0x41/0x48/0x40/0x60` → all OK. (An earlier apparent `0x41` revert was solely because the misaligned read happened to hit a huge length value, not alignment.)
- **Non-canonical/overlapping/swapped offsets accepted** as long as both range checks pass: `off_a=off_b=0x40` (both at same len-3 tail) → both decode len 3; swapped `off_a=0x80/off_b=0x40` → OK; self-ref `off_a=0x00` (reads head word0=0 as length) → empty array, OK.
- Huge length (`2^32`, `2^256−1`) → REV (check 2 / overflow). Huge offset (`2^64`, `2^256−32`, `0x1000`) → REV (check 1). Range-check boundaries are **inclusive** (`O+32 == argsLen` OK; payload ending exactly at `argsEnd` OK; one byte short → REV).
- Truncated head (fewer than the required head words; static aggregates count as multiple) → REV before any offset is read.
- **All these reverts are PLAIN EMPTY reverts** (`revert(0,0)`), no Error/Panic selector.

---

## 6. Recursive codegen contract (how 4e should be written)

**Encoder** `encode(type, value) -> bytes`, with `encodeInto(type, value, region_base)`:
- static type → inline words (width = `staticSize(type)`), no recursion into tail.
- dynamic type → in the *current container*, emit an offset word now; append `encodeTail(type, value)` to the container's tail; the offset = `(tail target byte) − (container data-region base byte)`.
- A container (top-level params, tuple, `T[]`, `string[]`/`bytes[]`, `T[][]`) computes its own head, then its tail, **resetting the offset base to its own data-region start** per the table in §0.2.
- `staticSize`: scalar = 32; `bytesN`/`uintN`/`bool` = 32; all-static struct = `sum(staticSize(fields))`; `Tstatic[k]` = `k*staticSize(T)`.
- A type is **dynamic** iff it is `string`/`bytes`, any `T[]` (unbounded), any `Tdyn[k]` (fixed array of dynamic element), or a struct containing any dynamic field. Recurse to classify.

**Decoder** `decode(type, base, region_base) -> value`:
- static → read inline at `base`.
- dynamic field/element → read offset `O` at its head slot; `ptr = region_base + O`; apply **Check 1** then **Check 2** (§0.4); recurse with the new container's `region_base` set per §0.2 (tuple → tuple start; array → length-word-plus-32 for the element/inner-offset table; but the element/inner *payload pointers* themselves are based at the table start).
- array index access: bounds-check against the decoded length first; `idx >= len` → **Panic(0x32)**; layout faults → **EMPTY revert**.
- Narrow-element validation (e.g. `uint8` element, `uint128`/`uint64`/`bool` struct fields): clean-bits / type-max check on read of the accessed element → **EMPTY revert** on violation (not Panic).
- Never enforce offset alignment, never enforce canonical/non-overlapping ordering.

**Base-selection summary (the single most important codegen invariant):**

| Container | Offset-table / inner-offset base |
|---|---|
| Top-level params/returns | head start (calldata byte 4 / returndata byte 0) |
| Tuple (struct) | tuple's first field word |
| `T[]` with dynamic element (`D[]`, `string[]`, `bytes[]`) | the word AFTER the length word (offset-table start) |
| `T[][]` outer | the word AFTER `outer_len` (pointer-region start) |

---

## 7. OPEN QUESTIONS (not conclusively established by these probes)

1. **Signed integers / `bytesN` / `address` field alignment.** Probes measured only `uintN` (right-aligned) and `bool` (full 0/1 word). Not measured: `intN` sign-extension into the high bytes, `bytesN` **left-alignment** (right zero-padding), `address` (right-aligned in low 20 bytes). These follow the ABI spec, but JETH should confirm against solc before relying on the encoder for them.
2. **Clean-bits/validation on `intN`, `bytesN`, `address`, and `enum` fields/elements.** Only `uint128`/`uint64`/`bool`/`uint8` dirty-bit and over-max behavior was measured (→ EMPTY revert). The validation rule for signed ints (sign-bit handling), `bytesN` (low-bit dirtiness), `address` (high 12 bytes nonzero), and `enum` (value `>= variant count` → Panic(0x21)? not tested) is unconfirmed.
3. **Dynamic struct as an ARRAY ELEMENT decode path (`D[]` decode).** Encode of `D[]` was fully measured; the *decode* validity/bounds behavior for `D[]` (and the exact ordering of the up-front payload check vs per-element offset checks) was only fully measured for the static-struct array (`P[]`/`S[]`) and for `string[]`. Confirm `D[]` decode matches the composed rules before relying on it.
4. **Nested fixed-size arrays of dynamic elements (`Tdyn[k]`, e.g. `string[2]`, `D[3]`).** Classified as dynamic here, but no probe measured their exact head/tail (a fixed array of dynamic elements has an offset table but no length word). The layout is inferable (offset table of `k` words, base = table start = the type's data-region start, no leading length word) but **unmeasured**.
5. **Multi-dynamic-field structs (`> 1` dynamic field in one tuple)** and **structs mixing static + multiple dynamic fields in non-trivial order.** Only `D{a, b}`, `E{id, name}`, `Outer{x, inner, y}` (one dynamic field each) were measured. The general rule (each dynamic field gets its own head offset word, tails in field order) is stated but the multi-dynamic-field tail ordering/offset accumulation was not directly probed.
6. **`Panic(0x41)` (alloc/oversized) vs EMPTY revert** for pathological huge lengths in deeply nested decodes. Probes consistently saw EMPTY reverts; whether any nesting depth/length combination flips to a Panic(0x41) was not exhausted.

---

Relevant probe-derived selectors (canonical tuple-expanded form), for codegen test fixtures: `encP()=506f8950`, `encS()=e1636534`, `getP((uint256,uint256)[],uint256)=e3e81306`, `getS((uint128,uint64,bool)[],uint256)=51864d03`, `lenP((uint256,uint256)[])=4cf654de`, `getA=547faf32`, `getBlen=8fc87aff`, `getB=672fc2a2`.

No files were written. This spec is returned inline as the task result.