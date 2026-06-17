// Lowering: ContractIR -> a Yul object (directive §3.1-§3.4, §5 step 6).
//
// Value representation conventions (all values are 256-bit Yul words):
//   uintN   - zero-extended, value in [0, 2^N)
//   intN    - sign-extended two's complement
//   bool    - 0 or 1
//   address - zero-extended 160-bit value
//   bytesN  - left-aligned (data in the high N bytes)
// These match Solidity's in-register conventions so ABI encode/decode is a no-op
// for static value types (the word is already the 32-byte ABI slot).
//
// Arithmetic is CHECKED by default: every +,-,*,/,% lowers to a helper that
// reverts with Panic(0x11) on overflow / Panic(0x12) on division by zero,
// matching Solidity >=0.8.
import {
  ContractIR,
  FunctionIR,
  Stmt,
  Expr,
  BinOp,
  RevertReason,
  EventIR,
} from './ir.js';
import { JethType, StructField, intRange, storageByteSize, storageSlotCount, isBytesLike, isDynamicType, isStaticType, isStaticValueType, isImplicitWiden, arrayElemPacks, abiHeadWords, abiLeaves, structStorageLeaves } from './types.js';
import type { ArrayExpr, AccessPath, CalldataPlace, CdDynPlace, LValue } from './ir.js';

export class UnsupportedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsupportedError';
  }
}

/** ABI head-word count of a struct's tuple HEAD (spec section 3.0): each field
 *  contributes its inline static words if static, or exactly ONE offset word if
 *  dynamic (string/bytes/dynamic-array/nested-dynamic-struct). This differs from
 *  abiHeadWords, which expands a (sub)struct into all of its leaf words even when
 *  that struct is dynamic. Used for tuple-head bounds checks and field offsets. */
function tupleHeadWords(t: JethType & { kind: 'struct' }): number {
  return t.fields.reduce((n, f) => n + (isDynamicType(f.type) ? 1 : abiHeadWords(f.type)), 0);
}

/** Bytes of a dynamic element/field's HEAD that must be readable at its calldata
 *  pointer before decoding: a struct tuple needs its WHOLE head (headWords*32); any
 *  other dynamic type (bytes/string/array) needs only its first length/offset word. */
function cdElemHeadBytes(t: JethType): number {
  return t.kind === 'struct' ? tupleHeadWords(t) * 32 : 32;
}

function toWord(v: bigint): string {
  let x = v % (1n << 256n);
  if (x < 0n) x += 1n << 256n;
  return '0x' + x.toString(16);
}
function uintMaxHex(bits: number): string {
  return '0x' + ((1n << BigInt(bits)) - 1n).toString(16);
}
/** Mask of the low (32 - size) bytes: the padding region of a left-aligned bytesN. */
function bytesNLowMaskHex(size: number): string {
  return '0x' + ((1n << BigInt((32 - size) * 8)) - 1n).toString(16);
}
/** Big-endian 32-byte word from `bytes` at `start`, right zero-padded (matches
 *  Solidity's left-aligned string/bytes tail words). */
function wordFromBytes(bytes: Uint8Array, start: number): string {
  let hex = '';
  for (let i = 0; i < 32; i++) {
    const b = start + i < bytes.length ? bytes[start + i]! : 0;
    hex += b.toString(16).padStart(2, '0');
  }
  return '0x' + hex;
}

export class YulEmitter {
  private helpers = new Map<string, string>();
  private tmp = 0;
  private nameCounter = 0; // per-function unique local-name counter
  private funcs = new Map<string, FunctionIR>(); // contract functions by name (internal-call targets)

  emit(contract: ContractIR): string {
    for (const f of contract.functions) this.funcs.set(f.name, f);
    const runtime = this.emitRuntime(contract);
    const creation = this.emitCreation(contract);
    return `object "${contract.name}" {
  code {
${indent(creation, 4)}
  }
  object "${contract.name}_runtime" {
    code {
${indent(runtime, 6)}
    }
  }
}
`;
  }

  // ---- creation / constructor code ----------------------------------------

  private emitCreation(contract: ContractIR): string {
    const lines: string[] = [];
    // Write non-default state initializers. All are compile-time constants, so we
    // pack each affected slot into a single word and emit one sstore per slot.
    const slotWords = new Map<number, bigint>();
    for (const v of contract.stateVars) {
      if (v.initialValue === undefined) continue;
      const size = storageByteSize(v.type);
      let raw: bigint;
      if (typeof v.initialValue === 'boolean') raw = v.initialValue ? 1n : 0n;
      else raw = v.initialValue & ((1n << BigInt(size * 8)) - 1n);
      const shifted = raw << BigInt(v.offset * 8);
      slotWords.set(v.slot, (slotWords.get(v.slot) ?? 0n) | shifted);
    }
    for (const [slot, word] of [...slotWords.entries()].sort((a, b) => a[0] - b[0])) {
      lines.push(`sstore(${slot}, ${toWord(word)})`);
    }
    lines.push(`datacopy(0, dataoffset("${contract.name}_runtime"), datasize("${contract.name}_runtime"))`);
    lines.push(`return(0, datasize("${contract.name}_runtime"))`);
    return lines.join('\n');
  }

  // ---- runtime / dispatcher ------------------------------------------------

  private emitRuntime(contract: ContractIR): string {
    const lines: string[] = [];
    lines.push('mstore(0x40, 0x80) // init free memory pointer');

    const external = contract.functions.filter(
      (f) => f.visibility === 'external' || f.visibility === 'public',
    );
    if (external.length === 0) {
      // No externally-callable functions: any call reverts. (Avoid emitting a
      // `switch` with only a default, which solc warns about.)
      lines.push('revert(0, 0)');
    } else {
      lines.push('if lt(calldatasize(), 4) { revert(0, 0) }');
      lines.push('let selector := shr(224, calldataload(0))');
      lines.push('switch selector');
      for (const fn of external) {
        lines.push(`case 0x${fn.selector} { // ${fn.signature}`);
        for (const l of this.emitDispatchCase(fn)) lines.push('  ' + l);
        lines.push('}');
      }
      lines.push('default { revert(0, 0) }');
    }

    // Emit a Yul function definition for every function that is called internally (G8).
    // (A purely-internal function never called is dead and elided, matching solc.)
    for (const fn of contract.functions) {
      if (fn.internallyCalled) {
        lines.push('');
        lines.push(this.emitInternalFunction(fn));
      }
    }

    // Append helper function definitions (deduplicated). Some are added while lowering
    // the internal functions above, so this must come last.
    for (const def of this.helpers.values()) {
      lines.push('');
      lines.push(def);
    }
    return lines.join('\n');
  }

  /** A Yul `function userfn_<name>(args) -> ret { body }` for an internally-called function.
   *  Params bind to the Yul args (already-clean JETH values - no calldata decode/validation);
   *  `return v` inside the body sets `ret` and `leave`s (see lowerStmt 'return' fnMode). */
  private emitInternalFunction(fn: FunctionIR): string {
    this.nameCounter = 0;
    const ctx: LowerCtx = {
      scopes: [new Map()],
      returnType: fn.returnType,
      dynParams: new Map(),
      cdArrays: new Map(),
      cdAggregates: new Map(),
      cdDynStructs: new Map(),
      cdParamHead: new Map(),
    };
    const argNames: string[] = [];
    for (const p of fn.params) {
      const an = this.freshLocal(p.name);
      this.ctxDeclare(ctx, p.name, an);
      argNames.push(an);
    }
    const isVoid = fn.returnType.kind === 'void';
    const retVar = isVoid ? null : this.fresh();
    ctx.fnMode = { retVar };
    const body: string[] = [];
    for (const s of fn.body) for (const l of this.lowerStmt(s, ctx)) body.push(l);
    const sig = `function ${this.userFnName(fn.name)}(${argNames.join(', ')})${isVoid ? '' : ` -> ${retVar}`}`;
    return `${sig} {\n${body.map((l) => '  ' + l).join('\n')}${body.length ? '\n' : ''}}`;
  }

  private userFnName(name: string): string {
    return `userfn_${name}`;
  }

  private emitDispatchCase(fn: FunctionIR): string[] {
    const out: string[] = [];
    this.nameCounter = 0; // deterministic, function-local unique names
    if (fn.mutability !== 'payable') {
      out.push('if callvalue() { revert(0, 0) } // reject value to non-payable');
    }

    // Decode params from calldata. Each param has one head word at 4+32*i; a
    // dynamic (bytes/string) head word is a tail offset, decoded into (ptr,len).
    const ctx: LowerCtx = {
      scopes: [new Map()],
      returnType: fn.returnType,
      dynParams: new Map(),
      cdArrays: new Map(),
      cdAggregates: new Map(),
      cdDynStructs: new Map(),
      cdParamHead: new Map(),
    };
    // The static head is a flat, gapless run of 32-byte words; each param consumes
    // abiHeadWords(type) of them (a static aggregate occupies one word per leaf,
    // NOT one word total; a dynamic param occupies one offset word). solc rejects
    // calldata shorter than the full static head with an empty revert.
    // A dynamic param (bytes/string, dynamic array, OR a dynamic struct) occupies
    // exactly ONE head word (an offset). A static aggregate occupies abiHeadWords.
    const paramHeadWords = (t: JethType): number => (isDynamicType(t) ? 1 : abiHeadWords(t));
    const staticHeadWords = fn.params.reduce((n, p) => n + paramHeadWords(p.type), 0);
    if (staticHeadWords > 0) {
      out.push(`if lt(calldatasize(), ${4 + 32 * staticHeadWords}) { revert(0, 0) }`);
    }
    let cursorWords = 0;
    for (const p of fn.params) {
      const head = 4 + 32 * cursorWords;
      ctx.cdParamHead.set(p.name, { head, type: p.type });
      if (p.type.kind === 'struct' && isDynamicType(p.type)) {
        // dynamic struct param: head word = offset to the tuple start (base = byte 4).
        // Decode the offset and length-readable range check; bind the tuple-start
        // calldata byte pointer. Field reads resolve lazily (spec section 3.2).
        const off = this.fresh();
        const tupleStart = this.fresh();
        const headSize = tupleHeadWords(p.type) * 32;
        out.push(`let ${off} := calldataload(${head})`);
        out.push(`let ${tupleStart} := ${this.calldataTuple()}(${off}, ${headSize})`);
        ctx.cdDynStructs.set(p.name, { tupleStart, type: p.type });
      } else if (p.type.kind === 'array' && p.type.length !== undefined && isDynamicType(p.type.element)) {
        // Arr<dyn,N>: a FIXED array of a DYNAMIC element. A dynamic param: head word =
        // offset to the N-word per-element offset table (base = table start, NO length
        // word). Bound it as a length-N calldata array so a[i] / echo reuse the
        // dynamic-array machinery.
        const off = this.fresh();
        out.push(`let ${off} := calldataload(${head})`);
        out.push(`if iszero(slt(${off}, sub(sub(calldatasize(), 4), 0x1f))) { revert(0, 0) }`);
        const dataPtr = this.fresh();
        out.push(`let ${dataPtr} := add(4, ${off})`);
        ctx.cdArrays.set(p.name, { offset: dataPtr, length: String(p.type.length), elem: p.type.element });
      } else if (p.type.kind === 'struct' || (p.type.kind === 'array' && p.type.length !== undefined)) {
        // static aggregate: inline in the head, decoded lazily on field/element read.
        ctx.cdAggregates.set(p.name, { baseOffset: head, type: p.type });
      } else if (p.type.kind === 'array' && p.type.length === undefined && isDynamicType(p.type.element)) {
        // Array of DYNAMIC elements: string[]/bytes[] (4e-4), nested T[][] (4e-5), OR a
        // dynamic-struct array D[]. All share the outer header: [length] then a
        // per-element offset table. `offset` is the table start (= the word after the
        // length word), which is ALSO the per-element offset base (spec sections 2-4).
        // Per-element offsets are resolved lazily on a[i] / m[i] / d[i] access.
        const off = this.fresh();
        const tableStart = this.fresh();
        const length = this.fresh();
        out.push(`let ${off} := calldataload(${head})`);
        out.push(`let ${tableStart}, ${length} := ${this.calldataDynArray()}(${off})`);
        ctx.cdArrays.set(p.name, { offset: tableStart, length, elem: p.type.element });
      } else if (p.type.kind === 'array') {
        const off = this.fresh();
        const offset = this.fresh();
        const length = this.fresh();
        const stride = abiHeadWords(p.type.element) * 32; // ABI element stride (unpacked)
        out.push(`let ${off} := calldataload(${head})`);
        out.push(`let ${offset}, ${length} := ${this.calldataArray()}(${off}, ${stride})`);
        ctx.cdArrays.set(p.name, { offset, length, elem: p.type.element });
      } else if (isBytesLike(p.type)) {
        const off = this.fresh();
        const dataPtr = this.fresh();
        const len = this.fresh();
        out.push(`let ${off} := calldataload(${head})`);
        out.push(`let ${dataPtr}, ${len} := ${this.calldataDyn()}(${off})`);
        ctx.dynParams.set(p.name, { dataPtr, len });
      } else {
        // Route params through the same unique-name allocator as locals so a param
        // named `<base>_<k>` can never collide with a local `<base>` in Yul.
        const name = this.freshLocal(p.name);
        this.ctxDeclare(ctx, p.name, name);
        out.push(`let ${name} := calldataload(${head})`);
        const guard = this.validateInput(p.type, name);
        if (guard) out.push(guard);
      }
      cursorWords += paramHeadWords(p.type);
    }

    const last = fn.body[fn.body.length - 1];
    const terminates = last !== undefined && (last.kind === 'return' || last.kind === 'revert' || last.kind === 'returnTuple');
    for (const s of fn.body) {
      for (const l of this.lowerStmt(s, ctx)) out.push(l);
    }
    if (!terminates && fn.returnTypes) {
      // fall-through default for a multi-value return: the zero tuple (value/bytes-string
      // components; an empty bytes/string is [offset][0]).
      const headWords = fn.returnTypes.length;
      let cursor = headWords * 32;
      for (let i = 0; i < fn.returnTypes.length; i++) {
        if (isBytesLike(fn.returnTypes[i]!)) {
          out.push(`mstore(${i * 32}, ${cursor})`, `mstore(${cursor}, 0)`);
          cursor += 32;
        } else out.push(`mstore(${i * 32}, 0)`);
      }
      out.push(`return(0, ${cursor})`);
    } else if (!terminates) {
      // void or fall-through: return the default-encoded value, matching Solidity
      // (falling off the end returns the zero value of the return type).
      if (fn.returnType.kind === 'void') out.push('return(0, 0)');
      else if (isBytesLike(fn.returnType) || fn.returnType.kind === 'array')
        out.push('mstore(0, 0x20)', 'mstore(0x20, 0)', 'return(0, 0x40)');
      else if (fn.returnType.kind === 'struct') {
        const words = abiHeadWords(fn.returnType);
        for (let j = 0; j < words; j++) out.push(`mstore(${j * 32}, 0)`);
        out.push(`return(0, ${words * 32})`);
      } else out.push('mstore(0, 0)', 'return(0, 0x20)');
    }
    return out;
  }

  /** Emit a validation guard for a decoded static value-type input, or '' if the
   *  full 32-byte word is always valid. Reverts with empty returndata on dirty
   *  input, matching Solidity's ABI decoder (verified against solc 0.8). */
  private validateInput(t: JethType, name: string): string {
    switch (t.kind) {
      case 'uint':
        // uintN<256: high bits must be zero.
        return t.bits === 256 ? '' : `if gt(${name}, ${uintMaxHex(t.bits)}) { revert(0, 0) }`;
      case 'int':
        // intN<256: must be a valid sign-extension of its low bytes.
        return t.bits === 256
          ? ''
          : `if iszero(eq(signextend(${t.bits / 8 - 1}, ${name}), ${name})) { revert(0, 0) }`;
      case 'bool':
        return `if gt(${name}, 1) { revert(0, 0) }`;
      case 'address':
        // high 96 bits must be zero.
        return `if shr(160, ${name}) { revert(0, 0) }`;
      case 'bytesN':
        // bytesN<32 is left-aligned: the low (32-size) bytes must be zero.
        return t.size === 32 ? '' : `if and(${name}, ${bytesNLowMaskHex(t.size)}) { revert(0, 0) }`;
      default:
        throw new UnsupportedError(
          `calldata decoding for type '${t.kind}' is not supported yet (Phase 4)`,
        );
    }
  }

  /** Clean a calldata element word into its in-register form (mask / sign-extend /
   *  normalize), without reverting on dirty bits. Matches solc's array copy. */
  private cleanCalldataElem(t: JethType, w: string): string {
    switch (t.kind) {
      case 'uint':
        return t.bits === 256 ? w : `and(${w}, ${uintMaxHex(t.bits)})`;
      case 'int':
        return t.bits === 256 ? w : `signextend(${t.bits / 8 - 1}, ${w})`;
      case 'bool':
        return `iszero(iszero(${w}))`;
      case 'address':
        return `and(${w}, ${uintMaxHex(160)})`;
      case 'bytesN': {
        if (t.size === 32) return w;
        const highMask = ((1n << BigInt(t.size * 8)) - 1n) << BigInt((32 - t.size) * 8);
        return `and(${w}, ${toWord(highMask)})`;
      }
      default:
        return w;
    }
  }

  // ---- statements ----------------------------------------------------------

  private lowerStmt(s: Stmt, ctx: LowerCtx): string[] {
    const out: string[] = [];
    switch (s.kind) {
      case 'returnTuple': {
        const { ptr, size } = this.encodeReturnTuple(s.values, s.types, ctx, out);
        out.push(`return(${ptr}, ${size})`);
        break;
      }
      case 'return': {
        // Inside an INTERNAL function (G8/G9): set the return var and `leave`. A value return
        // sets ret to the value; a STATIC struct return sets ret to the memory pointer (a freshly
        // constructed struct is allocated first). A bare `return;` in a void fn just leaves.
        if (ctx.fnMode) {
          if (s.value && ctx.fnMode.retVar) {
            const v = s.value.kind === 'structNew' ? this.allocAggToMem(s.value, ctx, out) : this.lowerExpr(s.value, ctx, out);
            out.push(`${ctx.fnMode.retVar} := ${v}`);
          }
          out.push('leave');
          break;
        }
        if (!s.value) {
          out.push('return(0, 0)');
          break;
        }
        // `return p` (memory STATIC struct local), `return p.inner` (a nested struct field, a
        // sub-pointer), or `return this.helper()` (struct-returning internal call): the
        // ABI-unpacked memory image at the (sub)pointer IS the flat return blob. G9.
        if ((s.value.type.kind === 'struct' || s.value.type.kind === 'array') && (s.value.kind === 'memAggregate' || s.value.kind === 'call')) {
          const ptr = this.lowerExpr(s.value, ctx, out);
          out.push(`return(${ptr}, ${abiHeadWords(s.value.type) * 32})`);
          break;
        }
        // `return a` (whole STATIC struct / fixed-array calldata param): re-encode inline
        // from the param head (flat, no offset wrapper). G5.
        if (s.value.kind === 'cdAggregateValue') {
          const { ptr, size } = this.echoStaticParam(s.value.param, s.value.type, ctx, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        // `return this.m[k]` (whole struct/array mapping value): encode from the
        // runtime mapping slot via the storage-source encoder.
        if (s.value.kind === 'mapStorageValue') {
          const slot = this.mappingSlot(s.value.baseSlot, s.value.keys, ctx, out);
          const { ptr, size } = this.returnStorageValue(slot, s.value.type, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        // `return this.recs[i]` (whole struct array element): encode from the
        // bounds-checked element slot via the storage-source encoder.
        if (s.value.kind === 'structArrayElem') {
          const slot = this.structArrayElemSlot(s.value.arr, s.value.index, ctx, out);
          const { ptr, size } = this.returnStorageValue(slot, s.value.type, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        // `return this.recs[i].inner` (whole nested-struct field) / `return this.g3[i][j]`
        // (whole fixed-array leaf at depth): fold the path to the slot, then encode via the
        // storage-source encoder.
        if (s.value.kind === 'placeRead' && (s.value.type.kind === 'struct' || s.value.type.kind === 'array')) {
          const p = this.lowerPlace(s.value.path, ctx, out);
          const { ptr, size } = this.returnStorageValue(p.slot, s.value.type, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        if (isBytesLike(s.value.type)) {
          const ref = this.lowerDynamic(s.value, ctx, out);
          const { ptr, size } = this.encodeDynToMem(ref, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        if (s.value.type.kind === 'array') {
          // a memory-array value produced by an expression (ternary `c ? xs : ys`, or any
          // expr that yields a [len][data] pointer): lower to the pointer, then encode.
          if (s.value.kind === 'ternary' || s.value.kind === 'incDec') {
            const { ptr, size } = this.encodeMemArrayReturn(this.lowerExpr(s.value, ctx, out), out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // a whole dynamic calldata-array PARAM echo (`return a`) goes through the
          // general recursive encoder -> UNBOUNDED nesting depth. Other array sources
          // (storage, m[i] sub-arrays) keep the specialized encoder.
          if (
            s.value.kind === 'arrayValue' &&
            s.value.arr.base.kind === 'calldataArray' &&
            isDynamicType(s.value.type)
          ) {
            const { ptr, size } = this.echoParam(s.value.arr.base.name, s.value.type, ctx, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // a whole STORAGE array whose element is DYNAMIC (string[], D[]) -> the
          // storage-source recursive encoder (unbounded nesting).
          if (
            s.value.kind === 'arrayValue' &&
            s.value.arr.base.kind === 'stateArray' &&
            isDynamicType(s.value.type)
          ) {
            const { ptr, size } = this.echoStorage(s.value.arr.base.slot, s.value.type, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // return this.fa (whole FIXED array): a static aggregate at a constant slot,
          // encoded inline by the storage-source recursive encoder.
          if (s.value.kind === 'arrayValue' && s.value.arr.base.kind === 'fixedArray') {
            const { ptr, size } = this.returnStorageValue(String(s.value.arr.base.baseSlot), s.value.type, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // return this.dd[i] (a whole inner array of a storage nested array): encode from
          // the inner array's runtime length slot (placeArray) via the storage encoder.
          if (s.value.kind === 'arrayValue' && s.value.arr.base.kind === 'placeArray') {
            const ref = this.lowerArrayRef(s.value.arr, ctx, out);
            if (ref.src !== 'storage') throw new UnsupportedError('inner-array return requires a storage source');
            const { ptr, size } = this.returnStorageValue(ref.lenSlot, s.value.type, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          const { ptr, size } = this.encodeArrayReturn(s.value, ctx, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        if (s.value.type.kind === 'struct') {
          if (isDynamicType(s.value.type)) {
            // a whole STORAGE dynamic struct (return this.d) -> storage-source encoder.
            if (s.value.kind === 'structValue') {
              const { ptr, size } = this.echoStorage(s.value.baseSlot, s.value.type, out);
              out.push(`return(${ptr}, ${size})`);
              break;
            }
            // a whole calldata dynamic-struct param echo (return s): the recursive
            // calldata encoder handles any field shape incl. dynamic-array fields
            // (unbounded), unlike the tuple-specific encoder.
            if (s.value.kind === 'cdDynStructValue') {
              const { ptr, size } = this.echoParam(s.value.param, s.value.type, ctx, out);
              out.push(`return(${ptr}, ${size})`);
              break;
            }
            // a DYNAMIC struct return: [head 0x20][tuple head/tail at byte 0x20].
            const { ptr, size } = this.encodeDynStructReturn(s.value, ctx, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // a STATIC struct read from storage (structValue) is encoded inline by the
          // recursive encoder, which flattens nested static structs / fixed-array fields
          // via structStorageLeaves. A constructed all-value struct (structNew) keeps the
          // flat field-by-field encoder (no storage source).
          if (s.value.kind === 'structValue') {
            const { ptr, size } = this.returnStorageValue(String(s.value.baseSlot), s.value.type, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          const size = this.encodeStructReturn(s.value, ctx, out);
          out.push(`return(0, ${size})`);
          break;
        }
        const v = this.lowerExpr(s.value, ctx, out);
        // single static value: the word is already the 32-byte ABI encoding.
        out.push(`mstore(0, ${v})`, 'return(0, 0x20)');
        break;
      }
      case 'localDecl': {
        const name = this.freshLocal(s.name);
        if (s.type.kind === 'struct' && isDynamicType(s.type) && s.init) {
          // a DYNAMIC-field struct memory local: build the pointer-headed image (value fields
          // inline, bytes/string fields a [len][data] pointer). Source: a constructor builds
          // fresh; a storage struct / calldata param is COPIED into a fresh image; another
          // dynamic-struct memory local ALIASES (pointer copy, matching Solidity references).
          out.push(`let ${name} := ${this.buildDynStructLocal(s.type, s.init, ctx, out)}`);
          this.ctxDeclare(ctx, s.name, name);
          break;
        }
        if ((s.type.kind === 'struct' || (s.type.kind === 'array' && s.type.length !== undefined)) && s.init) {
          // G9: a memory AGGREGATE local (struct or fixed array). A constructor / array literal
          // allocates a fresh ABI-unpacked image; a whole STORAGE aggregate (structValue, or an
          // arrayValue with a fixedArray base) or a calldata aggregate param (cdAggregateValue) is
          // COPIED into a fresh image; aliasing another memory aggregate (memAggregate) or a
          // struct-returning call copies the POINTER (matching Solidity memory references).
          if (s.init.kind === 'structNew' || s.init.kind === 'arrayLit') {
            out.push(`let ${name} := ${this.allocAggToMem(s.init, ctx, out)}`);
          } else if (s.init.kind === 'structValue') {
            out.push(`let ${name} := ${this.allocAggFromStorage(s.init.type, String(s.init.baseSlot), out)}`);
          } else if (s.init.kind === 'arrayValue' && s.init.arr.base.kind === 'fixedArray') {
            out.push(`let ${name} := ${this.allocAggFromStorage(s.init.type, String(s.init.arr.base.baseSlot), out)}`);
          } else if (s.init.kind === 'cdAggregateValue') {
            out.push(`let ${name} := ${this.allocAggFromCalldata(s.init.param, s.init.type, ctx, out)}`);
          } else {
            out.push(`let ${name} := ${this.lowerExpr(s.init, ctx, out)}`);
          }
          this.ctxDeclare(ctx, s.name, name);
          break;
        }
        if (isBytesLike(s.type) && s.init) {
          // G9: a bytes/string memory local. Materialize the init source into a memory
          // [len][data] blob; the register holds the pointer. toMemory COPIES a calldata /
          // storage / literal source, and aliases a memory source (matching Solidity).
          const { mp } = this.toMemory(this.lowerDynamic(s.init, ctx, out), out);
          out.push(`let ${name} := ${mp}`);
          this.ctxDeclare(ctx, s.name, name);
          break;
        }
        if (s.init) {
          const v = this.lowerExpr(s.init, ctx, out);
          out.push(`let ${name} := ${v}`);
        } else {
          out.push(`let ${name} := 0`); // matches Solidity zero-default
        }
        this.ctxDeclare(ctx, s.name, name);
        break;
      }
      case 'assign': {
        if (s.target.kind === 'state' && s.target.type.kind === 'struct') {
          // whole-struct write: either a constructed value (structNew) or a
          // storage-to-storage copy from another struct lvalue (this.d = this.e /
          // this.d = this.m[k]).
          if (s.value.kind === 'structNew') {
            this.writeStruct(s.value.fields, s.value.args, String(s.target.slot), ctx, out);
          } else {
            this.copyStruct(s.target.type, this.structSrcSlot(s.value, ctx, out), String(s.target.slot), out);
          }
          break;
        }
        if (s.target.kind === 'mapping' && s.target.type.kind === 'struct') {
          // this.m[k] = <struct>: write the constructed/copied struct into the runtime
          // keccak(key.base) mapping slot (writeStruct/copyStruct clear dynamic-field
          // tails per field, byte-identical to solc).
          const dst = this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out);
          if (s.value.kind === 'structNew') {
            this.writeStruct(s.value.fields, s.value.args, dst, ctx, out);
          } else {
            this.copyStruct(s.target.type, this.structSrcSlot(s.value, ctx, out), dst, out);
          }
          break;
        }
        // whole DYNAMIC-array assignment into storage: this.a = this.b (storage source) or
        // this.a = xs / this.m[k] = xs (a MEMORY value-array source). copyArrayValueIntoStorage
        // deep-copies (resize + element copy + tail clear) from either source.
        if (
          (s.target.kind === 'state' || s.target.kind === 'mapping') &&
          s.target.type.kind === 'array' &&
          s.target.type.length === undefined
        ) {
          const dstLenSlot =
            s.target.kind === 'mapping' ? this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out) : String(s.target.slot);
          this.copyArrayValueIntoStorage(s.target.type.element, s.value, dstLenSlot, ctx, out);
          break;
        }
        if (s.target.kind === 'place' && s.target.type.kind === 'struct') {
          // this.o.inner = <struct> (whole nested-struct field): fold the path to the
          // field slot, then writeStruct (literal) / copyStruct (storage copy).
          const p = this.lowerPlace(s.target.path, ctx, out);
          if (s.value.kind === 'structNew') {
            this.writeStruct(s.value.fields, s.value.args, p.slot, ctx, out);
          } else {
            this.copyStruct(s.target.type, this.structSrcSlot(s.value, ctx, out), p.slot, out);
          }
          break;
        }
        if (s.target.kind === 'place') {
          const p = this.lowerPlace(s.target.path, ctx, out);
          const value = this.lowerExpr(s.value, ctx, out);
          // a packed element with a RUNTIME byte offset uses packedStore; otherwise the
          // constant-offset storeState (also covers a literal packed index).
          if (p.byteShift !== undefined) this.packedStore(s.target.type, p.slot, p.byteShift, value, out);
          else for (const l of this.storeState(s.target.type, p.slot, p.offset, value)) out.push(l);
          break;
        }
        if (s.target.kind === 'memField' || s.target.kind === 'memElem') {
          // p.x = v / a[i] = v on a memory aggregate local: bounds-checked memory store.
          this.lowerAssignValue(s.target, this.lowerExpr(s.value, ctx, out), ctx, out);
          break;
        }
        if (s.target.kind === 'memDynField') {
          // d.s = <bytes/string> on a dynamic-field struct memory local: materialize the value
          // to a memory [len][data] blob (alias if it is already memory), then re-point the
          // field's head word at it (Solidity memory-struct field assignment is a reference).
          const { mp } = this.toMemory(this.lowerDynamic(s.value, ctx, out), out);
          const head = this.ctxLookup(ctx, s.target.local);
          out.push(`mstore(${s.target.wordOffset === 0 ? head : `add(${head}, ${s.target.wordOffset * 32})`}, ${mp})`);
          break;
        }
        if (s.target.kind === 'dynState') {
          const ref = this.lowerDynamic(s.value, ctx, out);
          this.storeDynamic(String(s.target.slot), ref, out);
          break;
        }
        if (s.target.kind === 'mapDynState') {
          // this.m[k] = <bytes/string>: compute the runtime mapping slot, then
          // overwrite-store the value (storeDynamic clears the old tail).
          const slot = this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out);
          const ref = this.lowerDynamic(s.value, ctx, out);
          this.storeDynamic(slot, ref, out);
          break;
        }
        if (s.target.kind === 'strArrayElem') {
          // this.ss[i] = <bytes/string>: bounds-check i, then overwrite the element
          // header at keccak(lenSlot)+i (storeStrMem clears the old tail).
          const slot = this.strArrayElemSlot(s.target.arr, s.target.index, ctx, out);
          const ref = this.lowerDynamic(s.value, ctx, out);
          this.storeDynamic(slot, ref, out);
          break;
        }
        if (s.target.kind === 'dynPlace') {
          // this.d.s = <bytes/string> (storage dynamic-struct field): fold the path
          // to the field's slot (struct base + field slot, index/key bound-checks
          // applied), then overwrite-store the value (storeStrMem clears the old
          // tail, identical to solc).
          const p = this.lowerPlace(s.target.path, ctx, out);
          const ref = this.lowerDynamic(s.value, ctx, out);
          this.storeDynamic(p.slot, ref, out);
          break;
        }
        if (s.target.kind === 'arrayElem' && s.target.type.kind === 'array') {
          // this.dd[i] = <array> (a whole dynamic inner array element): the element slot
          // is the inner array's length slot (data + i*1); deep-copy the value in
          // (overwrite-clearing the old inner array).
          const innerLenSlot = this.structArrayElemSlot(s.target.arr, s.target.index, ctx, out);
          this.copyArrayValueIntoStorage(s.target.type.element, s.value, innerLenSlot, ctx, out);
          break;
        }
        if (s.target.kind === 'arrayElem' && s.target.type.kind === 'struct') {
          // this.recs[i] = <struct>: write the constructed/copied struct into the
          // bounds-checked element slot (writeStruct/copyStruct clear dynamic-field
          // tails per field, byte-identical to solc).
          const elemSlot = this.structArrayElemSlot(s.target.arr, s.target.index, ctx, out);
          if (s.value.kind === 'structNew') {
            this.writeStruct(s.value.fields, s.value.args, elemSlot, ctx, out);
          } else {
            this.copyStruct(s.target.type, this.structSrcSlot(s.value, ctx, out), elemSlot, out);
          }
          break;
        }
        if (s.target.kind === 'arrayElem') {
          const ref = this.lowerArrayRef(s.target.arr, ctx, out); // storage/fixed (analyzer rejects calldata)
          const idx = this.fresh();
          out.push(`let ${idx} := ${this.lowerExpr(s.target.index, ctx, out)}`);
          const value = this.lowerExpr(s.value, ctx, out);
          if (ref.src === 'fixed') {
            out.push(`if iszero(lt(${idx}, ${ref.length})) { ${this.panic()}(0x32) }`);
            this.arrayElemStore(s.target.type, String(ref.baseSlot), idx, value, out);
          } else if (ref.src === 'storage') {
            out.push(`if iszero(lt(${idx}, sload(${ref.lenSlot}))) { ${this.panic()}(0x32) }`);
            const data = this.arrayDataSlot(ref.lenSlot, out);
            this.arrayElemStore(s.target.type, data, idx, value, out);
          } else if (ref.src === 'memory') {
            // memory T[] element write (value element, one word): bound vs mload(ptr).
            out.push(`if iszero(lt(${idx}, mload(${ref.ptr}))) { ${this.panic()}(0x32) }`);
            out.push(`mstore(add(${ref.ptr}, add(0x20, mul(${idx}, 0x20))), ${value})`);
          } else {
            throw new UnsupportedError('cannot assign to a calldata array element');
          }
          break;
        }
        const value = this.lowerExpr(s.value, ctx, out);
        if (s.target.kind === 'local') {
          out.push(`${this.ctxLookup(ctx, s.target.varName)} := ${value}`);
        } else if (s.target.kind === 'mapping') {
          const slot = this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out);
          for (const l of this.storeState(s.target.type, slot, 0, value)) out.push(l);
        } else {
          for (const l of this.storeState(s.target.type, String(s.target.slot), s.target.offset, value)) out.push(l);
        }
        break;
      }
      case 'exprStmt': {
        const v = this.lowerExpr(s.expr, ctx, out);
        out.push(`pop(${v})`);
        break;
      }
      case 'callStmt': {
        // an internal call as a statement: the result (if any) is discarded.
        const args = this.lowerCallArgs(s.args, ctx, out);
        const call = `${this.userFnName(s.fn)}(${args.join(', ')})`;
        const isVoid = this.funcs.get(s.fn)?.returnType.kind === 'void';
        out.push(isVoid ? call : `pop(${call})`);
        break;
      }
      case 'deleteStmt': {
        this.lowerDelete(s.target, ctx, out);
        break;
      }
      case 'block': {
        out.push('{');
        for (const l of this.lowerBlock(s.body, ctx)) out.push('  ' + l);
        out.push('}');
        break;
      }
      case 'if': {
        const c = this.lowerExpr(s.cond, ctx, out); // short-circuit prep lands in `out`
        if (!s.else) {
          out.push(`if ${c} {`);
          for (const l of this.lowerBlock(s.then, ctx)) out.push('  ' + l);
          out.push('}');
        } else {
          // if-else: Yul `if` has no else, so switch on the bool (verified vs solc).
          out.push(`switch ${c}`);
          out.push('case 0 {');
          for (const l of this.lowerBlock(s.else, ctx)) out.push('  ' + l);
          out.push('}');
          out.push('default {');
          for (const l of this.lowerBlock(s.then, ctx)) out.push('  ' + l);
          out.push('}');
        }
        break;
      }
      case 'while': {
        // for {} 1 {} { if iszero(cond) { break } body } -- cond re-checked each
        // iteration (its prep statements must run inside the loop), continue OK.
        out.push('for {} 1 {} {');
        const inner: string[] = [];
        const c = this.lowerExpr(s.cond, ctx, inner);
        inner.push(`if iszero(${c}) { break }`);
        for (const l of this.lowerBlock(s.body, ctx)) inner.push(l);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        break;
      }
      case 'doWhile': {
        // do { body } while(cond). Compiled as `for {} run { run := cond } { body }`:
        // the body runs first (run starts 1), then the post re-evaluates cond into run,
        // then the for-condition re-checks. A `continue` in body jumps to the post (so it
        // re-evaluates cond, exactly like Solidity/C), and `break` exits immediately.
        const run = this.fresh();
        out.push(`let ${run} := 1`);
        const post: string[] = [];
        const c = this.lowerExpr(s.cond, ctx, post);
        post.push(`${run} := ${c}`);
        out.push(`for {} ${run} {`);
        for (const l of post) out.push('  ' + l);
        out.push('} {');
        for (const l of this.lowerBlock(s.body, ctx)) out.push('  ' + l);
        out.push('}');
        break;
      }
      case 'for': {
        this.ctxPush(ctx); // for-init scope encloses cond/post/body
        const initLines = s.init ? this.lowerStmt(s.init, ctx) : [];
        const postLines = s.post ? this.lowerStmt(s.post, ctx) : [];
        const bodyLines: string[] = [];
        if (s.cond) {
          const c = this.lowerExpr(s.cond, ctx, bodyLines);
          bodyLines.push(`if iszero(${c}) { break }`);
        }
        for (const l of this.lowerBlock(s.body, ctx)) bodyLines.push(l);
        out.push('for {');
        for (const l of initLines) out.push('  ' + l);
        out.push('} 1 {');
        for (const l of postLines) out.push('  ' + l);
        out.push('} {');
        for (const l of bodyLines) out.push('  ' + l);
        out.push('}');
        this.ctxPop(ctx);
        break;
      }
      case 'break':
        out.push('break');
        break;
      case 'continue':
        out.push('continue');
        break;
      case 'require': {
        // solc order: fully evaluate the condition first (so a side-effecting
        // condition reverts before the reason), THEN evaluate the reason's args
        // eagerly (a custom-error arg like 10/b reverts even when cond is true).
        const condExpr = this.lowerExpr(s.cond, ctx, out);
        const condTmp = this.fresh();
        out.push(`let ${condTmp} := ${condExpr}`);
        const reasonLines = this.lowerRevertReason(s.reason, ctx, out);
        out.push(`if iszero(${condTmp}) {`);
        for (const l of reasonLines) out.push('  ' + l);
        out.push('}');
        break;
      }
      case 'revert': {
        for (const l of this.lowerRevertReason(s.reason, ctx, out)) out.push(l);
        break;
      }
      case 'emit': {
        for (const l of this.lowerEmit(s.event, s.args, ctx, out)) out.push(l);
        break;
      }
      case 'push': {
        if (s.arr.elem.kind === 'struct') {
          this.lowerStructPush(s.arr, s.value, ctx, out);
        } else if (s.arr.elem.kind === 'bytes' || s.arr.elem.kind === 'string') {
          this.lowerStrPush(s.arr, s.value, ctx, out);
        } else if (s.arr.elem.kind === 'array') {
          // push a whole inner array onto a nested array (this.dd.push(xs) / push([])):
          // grow the outer, then deep-copy the value into the freshly grown inner slot.
          this.lowerArrayPush(s.arr, s.value, ctx, out);
        } else {
          const value = s.value ? this.lowerExpr(s.value, ctx, out) : '0';
          this.lowerPush(s.arr, value, ctx, out);
        }
        break;
      }
      case 'pop':
        if (s.arr.elem.kind === 'struct') this.lowerStructPop(s.arr, ctx, out);
        else if (s.arr.elem.kind === 'bytes' || s.arr.elem.kind === 'string') this.lowerStrPop(s.arr, ctx, out);
        else this.lowerPop(s.arr, ctx, out);
        break;
    }
    return out;
  }

  /** Lower a Stmt[] branch in a fresh ctx scope (mirrors a Yul block scope). */
  private lowerBlock(body: Stmt[], ctx: LowerCtx): string[] {
    this.ctxPush(ctx);
    const inner: string[] = [];
    for (const s of body) for (const l of this.lowerStmt(s, ctx)) inner.push(l);
    this.ctxPop(ctx);
    return inner;
  }

  // ---- reverts / custom errors --------------------------------------------

  /** Lower a revert payload. MAY append eager prep (custom-error arg temps) to
   *  `out`; returns the lines that perform the actual revert (placed at the
   *  revert point: inline for `revert`, inside the guard for `require`). */
  private lowerRevertReason(r: RevertReason, ctx: LowerCtx, out: string[]): string[] {
    switch (r.kind) {
      case 'empty':
        return ['revert(0, 0)'];
      case 'errorString':
        return this.lowerErrorString(r.message);
      case 'errorStringDyn': {
        // Error(string) from a runtime value: build the blob lazily inside the
        // revert. selector + [0x20][len][padded data]. Verified byte-exact.
        const lines: string[] = [];
        const ref = this.lowerDynamic(r.value, ctx, lines);
        const { mp, len } = this.toMemory(ref, lines);
        const padded = `and(add(${len}, 0x1f), not(0x1f))`;
        lines.push('mstore(0, shl(224, 0x08c379a0))');
        lines.push('mstore(4, 0x20)');
        lines.push(`mstore(0x24, ${len})`);
        lines.push(`mcopy(0x44, add(${mp}, 0x20), ${padded})`);
        lines.push(`revert(0, add(0x44, ${padded}))`);
        return lines;
      }
      case 'custom': {
        // Evaluate args eagerly into temps so they run before any cond guard
        // (matches solc: a custom-error arg can revert even when require passes).
        if (!r.args.some((a) => isDynamicType(a.type))) {
          const argTemps = r.args.map((a) => {
            const v = this.lowerExpr(a, ctx, out);
            const t = this.fresh();
            out.push(`let ${t} := ${v}`);
            return t;
          });
          const helper = this.errorRevert(argTemps.length);
          return [`${helper}(0x${r.decl.selector}${argTemps.map((a) => ', ' + a).join('')})`];
        }
        // head/tail: each arg is one head word (static value, or a tail offset for a
        // dynamic bytes/string/array); offsets are relative to the args region (calldata byte 4).
        const lines: string[] = [];
        type LA = { dyn: 'static'; word: string } | { dyn: 'bytes'; mp: string; len: string } | { dyn: 'array'; mp: string; size: string };
        const lowered: LA[] = r.args.map((a): LA => {
          if (isBytesLike(a.type)) {
            const { mp, len } = this.toMemory(this.lowerDynamic(a, ctx, lines), lines);
            return { dyn: 'bytes', mp, len };
          }
          if (a.type.kind === 'array') {
            const { mp, size } = this.materializeArrayArg(a, ctx, lines);
            return { dyn: 'array', mp, size };
          }
          const t = this.fresh();
          lines.push(`let ${t} := ${this.lowerExpr(a, ctx, lines)}`);
          return { dyn: 'static', word: t };
        });
        const headSize = lowered.length * 32;
        const p = this.fresh();
        lines.push(`let ${p} := mload(0x40)`);
        lines.push(`mstore(${p}, shl(224, 0x${r.decl.selector}))`);
        const cur = this.fresh();
        lines.push(`let ${cur} := ${headSize}`); // byte offset (rel byte 4) of next tail
        lowered.forEach((a, i) => {
          const headAt = `add(${p}, ${4 + i * 32})`;
          if (a.dyn === 'static') {
            lines.push(`mstore(${headAt}, ${a.word})`);
          } else if (a.dyn === 'bytes') {
            lines.push(`mstore(${headAt}, ${cur})`);
            const padded = this.fresh();
            lines.push(`let ${padded} := and(add(${a.len}, 0x1f), not(0x1f))`);
            lines.push(`mstore(add(${p}, add(4, ${cur})), ${a.len})`);
            lines.push(`mcopy(add(${p}, add(4, add(${cur}, 0x20))), add(${a.mp}, 0x20), ${padded})`);
            lines.push(`${cur} := add(${cur}, add(0x20, ${padded}))`);
          } else {
            // array tail blob [len][elements...] is already ABI-encoded: copy it verbatim.
            lines.push(`mstore(${headAt}, ${cur})`);
            lines.push(`mcopy(add(${p}, add(4, ${cur})), ${a.mp}, ${a.size})`);
            lines.push(`${cur} := add(${cur}, ${a.size})`);
          }
        });
        lines.push(`revert(${p}, add(4, ${cur}))`);
        return lines;
      }
    }
  }

  /** Byte-exact Error(string) revert blob (verified against solc): selector
   *  0x08c379a0, ABI offset 0x20, length, then ceil(len/32) right-padded words. */
  private lowerErrorString(message: Uint8Array): string[] {
    const len = message.length;
    const lines: string[] = [];
    lines.push('mstore(0, shl(224, 0x08c379a0))'); // selector in high 4 bytes
    lines.push('mstore(4, 0x20)'); // ABI offset to the string data
    lines.push(`mstore(0x24, ${len})`); // string length
    const nWords = Math.ceil(len / 32); // 0 words when len === 0
    for (let i = 0; i < nWords; i++) {
      lines.push(`mstore(${0x44 + i * 32}, ${wordFromBytes(message, i * 32)})`);
    }
    lines.push(`revert(0, ${4 + 32 + 32 + nWords * 32})`);
    return lines;
  }

  /** Deduplicated custom-error revert helper for a given static-arg arity.
   *  Selector passed as the raw 4-byte value; shl(224,...) applied inside. */
  private errorRevert(n: number): string {
    const name = `revert_error_${n}`;
    if (!this.helpers.has(name)) {
      const params = ['sel', ...Array.from({ length: n }, (_, i) => `a${i}`)];
      const stores = Array.from({ length: n }, (_, i) => `  mstore(${4 + 32 * i}, a${i})`).join('\n');
      const total = 4 + 32 * n;
      this.helpers.set(
        name,
        `function ${name}(${params.join(', ')}) {\n  mstore(0, shl(224, sel))\n${stores}${stores ? '\n' : ''}  revert(0, ${total})\n}`,
      );
    }
    return name;
  }

  // ---- events / logs -------------------------------------------------------

  private lowerEmit(ev: EventIR, args: Expr[], ctx: LowerCtx, out: string[]): string[] {
    // partition into indexed topics (static) and the non-indexed data tuple.
    const idxVals: string[] = [];
    type Part = { word: string } | { mp: string; len: string } | { mp: string; size: string };
    const data: Part[] = [];
    ev.params.forEach((p, i) => {
      const arg = args[i]!;
      if (p.indexed && isBytesLike(p.type)) {
        // an indexed bytes/string topic is keccak256 of the CONTENT bytes (G4), not the value.
        const { mp, len } = this.toMemory(this.lowerDynamic(arg, ctx, out), out);
        const topic = this.fresh();
        out.push(`let ${topic} := keccak256(add(${mp}, 0x20), ${len})`);
        idxVals.push(topic);
      } else if (p.indexed) {
        idxVals.push(this.lowerExpr(arg, ctx, out)); // a static-value indexed topic
      } else if (isBytesLike(p.type)) {
        const ref = this.lowerDynamic(arg, ctx, out);
        data.push(this.toMemory(ref, out)); // materialize before the buffer is allocated
      } else if (p.type.kind === 'array') {
        data.push(this.materializeArrayArg(arg, ctx, out)); // {mp, size}: ABI tail blob (G3)
      } else {
        data.push({ word: this.lowerExpr(arg, ctx, out) });
      }
    });
    const n = idxVals.length + 1; // non-anonymous: topic0 always present
    const topics = `0x${ev.topic0}${idxVals.map((t) => `, ${t}`).join('')}`;
    const lines: string[] = [];
    if (data.length === 0) {
      lines.push(`log${n}(0, 0, ${topics})`);
      return lines;
    }
    const headSize = 32 * data.length;
    if (data.every((d) => 'word' in d)) {
      // all-static data: head words only.
      const m = this.fresh();
      lines.push(`let ${m} := mload(0x40)`);
      data.forEach((d, i) => lines.push(`mstore(${i === 0 ? m : `add(${m}, ${32 * i})`}, ${(d as { word: string }).word})`));
      lines.push(`log${n}(${m}, ${headSize}, ${topics})`);
      return lines;
    }
    // mixed/dynamic data: ABI head/tail. Total size computed at runtime.
    const total = this.fresh();
    lines.push(`let ${total} := ${headSize}`);
    for (const d of data) {
      if ('len' in d) lines.push(`${total} := add(${total}, add(0x20, and(add(${d.len}, 0x1f), not(0x1f))))`);
      else if ('size' in d) lines.push(`${total} := add(${total}, ${d.size})`);
    }
    const ptr = this.fresh();
    lines.push(`let ${ptr} := ${this.alloc()}(${total})`);
    const cursor = this.fresh();
    lines.push(`let ${cursor} := add(${ptr}, ${headSize})`);
    data.forEach((d, j) => {
      const head = j === 0 ? ptr : `add(${ptr}, ${32 * j})`;
      if ('word' in d) {
        lines.push(`mstore(${head}, ${d.word})`);
      } else if ('len' in d) {
        const pad = `and(add(${d.len}, 0x1f), not(0x1f))`;
        lines.push(`mstore(${head}, sub(${cursor}, ${ptr}))`);
        lines.push(`mstore(${cursor}, ${d.len})`);
        lines.push(`mcopy(add(${cursor}, 0x20), add(${d.mp}, 0x20), ${pad})`);
        lines.push(`${cursor} := add(${cursor}, add(0x20, ${pad}))`);
      } else {
        // array tail blob [len][elements...]: copy verbatim (already ABI-encoded).
        lines.push(`mstore(${head}, sub(${cursor}, ${ptr}))`);
        lines.push(`mcopy(${cursor}, ${d.mp}, ${d.size})`);
        lines.push(`${cursor} := add(${cursor}, ${d.size})`);
      }
    });
    lines.push(`log${n}(${ptr}, ${total}, ${topics})`);
    return lines;
  }

  /** Emit storage write, handling packed slots via read-modify-write. `slot` is a
   *  Yul expression (a constant for a fixed slot, or a temp for a mapping element).
   *  solc uses read-modify-write even for a narrow mapping value, so the packed
   *  path reproduces mapping value storage byte-for-byte (verified). */
  private storeState(t: JethType, slot: string, offset: number, value: string): string[] {
    const size = storageByteSize(t);
    if (size === 32 && offset === 0) {
      return [`sstore(${slot}, ${value})`];
    }
    // packed: clear the field's bytes, OR in the (masked, shifted) value.
    // bytesN is held left-aligned in registers but stored right-aligned within
    // its field (verified against solc), so right-align it first.
    const fieldData = t.kind === 'bytesN' ? `shr(${(32 - size) * 8}, ${value})` : value;
    const fieldMask = (1n << BigInt(size * 8)) - 1n;
    const shift = BigInt(offset * 8);
    const clearMask = ((1n << 256n) - 1n) ^ (fieldMask << shift);
    const t0 = this.fresh();
    const t1 = this.fresh();
    return [
      `let ${t0} := and(sload(${slot}), ${toWord(clearMask)})`,
      `let ${t1} := shl(${shift}, and(${fieldData}, ${toWord(fieldMask)}))`,
      `sstore(${slot}, or(${t0}, ${t1}))`,
    ];
  }

  // ---- expressions ---------------------------------------------------------
  //
  // lowerExpr returns the Yul expression for a value and may append preparatory
  // statements (temps, short-circuit control flow) to `out`. Side-effecting or
  // conditionally-evaluated subexpressions therefore lower correctly.

  private lowerExpr(e: Expr, ctx: LowerCtx, out: string[]): string {
    switch (e.kind) {
      case 'literalInt':
        return toWord(e.value);
      case 'literalBool':
        return e.value ? '1' : '0';
      case 'localRead':
        return this.ctxLookup(ctx, e.name);
      case 'stateRead':
        return this.loadState(e.type, String(e.slot), e.offset);
      case 'unary':
        return this.lowerUnary(e, ctx, out);
      case 'binary':
        return this.lowerBinary(e, ctx, out);
      case 'ternary': {
        // short-circuit: only the taken branch is evaluated (a branch may revert / have
        // checked-arithmetic side effects), exactly like Solidity's c ? a : b.
        const c = this.lowerExpr(e.cond, ctx, out);
        const res = this.fresh();
        out.push(`let ${res} := 0`);
        const thenOut: string[] = [];
        const tv = this.lowerExpr(e.then, ctx, thenOut);
        const elseOut: string[] = [];
        const ev = this.lowerExpr(e.else, ctx, elseOut);
        out.push(`switch ${c}`);
        out.push('case 0 {');
        for (const s of elseOut) out.push('  ' + s);
        out.push(`  ${res} := ${ev}`);
        out.push('}');
        out.push('default {');
        for (const s of thenOut) out.push('  ' + s);
        out.push(`  ${res} := ${tv}`);
        out.push('}');
        return res;
      }
      case 'incDec': {
        // x++ / ++x in value position: read old, compute new (checked unless unchecked),
        // store, yield old (postfix) or new (prefix).
        const old = this.fresh();
        out.push(`let ${old} := ${this.lowerExpr(e.readExpr, ctx, out)}`);
        const nv = this.fresh();
        const raw = e.isInc ? `add(${old}, 1)` : `sub(${old}, 1)`;
        out.push(`let ${nv} := ${e.unchecked ? this.wrapToType(e.type, raw) : `${this.checkedArith(e.isInc ? 'add' : 'sub', e.type)}(${old}, 1)`}`);
        this.lowerAssignValue(e.target, nv, ctx, out);
        return e.prefix ? nv : old;
      }
      case 'assignExpr': {
        // (x = v)/(x += v) in value position: compute the (already-coerced) new value,
        // store it into the target, and yield it. Matches Solidity's assignment-expression
        // result (the assigned, LHS-typed value).
        const v = this.fresh();
        out.push(`let ${v} := ${this.lowerExpr(e.value, ctx, out)}`);
        this.lowerAssignValue(e.target, v, ctx, out);
        return v;
      }
      case 'call': {
        // internal/private function call yielding a value: evaluate args (left-to-right,
        // each frozen into a temp), then the Yul function call IS the value.
        const args = this.lowerCallArgs(e.args, ctx, out);
        return `${this.userFnName(e.fn)}(${args.join(', ')})`;
      }
      case 'memField': {
        // read a value field of a memory-aggregate (struct) local: mload at ptr + offset.
        const ptr = this.ctxLookup(ctx, e.local);
        return e.wordOffset === 0 ? `mload(${ptr})` : `mload(add(${ptr}, ${e.wordOffset * 32}))`;
      }
      case 'memElem': {
        // a[i] on a fixed-array memory local (value element): bounds-check then mload at ptr+i*32.
        const ptr = this.ctxLookup(ctx, e.local);
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${e.length})) { ${this.panic()}(0x32) }`);
        return `mload(add(${ptr}, mul(${i}, 0x20)))`;
      }
      case 'memAggregate': {
        // a whole memory aggregate (the local's pointer), or a nested struct field at a word
        // offset (a sub-pointer into the parent image, which aliases it).
        const base = this.ctxLookup(ctx, e.local);
        return e.wordOffset ? `add(${base}, ${e.wordOffset * 32})` : base;
      }
      case 'global':
        return this.lowerGlobal(e);
      case 'cast':
        return this.lowerCast(e, ctx, out);
      case 'mapGet': {
        const slot = this.mappingSlot(e.baseSlot, e.keys, ctx, out);
        return this.loadState(e.type, slot, 0);
      }
      case 'dynLength': {
        const ref = this.lowerDynamic(e.operand, ctx, out);
        return this.dynLen(ref);
      }
      case 'byteIndex':
        return this.lowerByteIndex(e, ctx, out);
      case 'arrayLen': {
        const ref = this.lowerArrayRef(e.arr, ctx, out);
        if (ref.src === 'storage') return `sload(${ref.lenSlot})`;
        if (ref.src === 'fixed') return String(ref.length);
        if (ref.src === 'memory') return `mload(${ref.ptr})`;
        return ref.length;
      }
      case 'placeRead': {
        const p = this.lowerPlace(e.path, ctx, out);
        // a packed element with a RUNTIME byte offset uses packedLoad; otherwise the
        // constant-offset loadState (which also covers a literal packed index).
        if (p.byteShift !== undefined) return this.packedLoad(e.type, p.slot, p.byteShift);
        return this.loadState(e.type, p.slot, p.offset);
      }
      case 'cdPlaceRead': {
        // Read a leaf from an aggregate calldata param. solc validates lazily on
        // access: a dirty (non-canonical) word reverts empty, never masks.
        const off = this.lowerCdPlace(e.place, ctx, out);
        const w = this.fresh();
        out.push(`let ${w} := calldataload(${off})`);
        const guard = this.validateInput(e.type, w);
        if (guard) out.push(guard);
        return w;
      }
      case 'cdDynStructLeaf': {
        // Read a static-value leaf of a dynamic-struct calldata param. Lazy
        // validation: a dirty leaf word reverts empty (matches solc).
        const off = this.lowerCdDynLeafOff(e.place, ctx, out);
        const w = this.fresh();
        out.push(`let ${w} := calldataload(${off})`);
        const guard = this.validateInput(e.type, w);
        if (guard) out.push(guard);
        return w;
      }
      case 'cdArrayField': {
        // ps[i].field on a calldata dynamic array of static struct: bounds-check
        // i (Panic 0x32), then read the field's leaf word at stride*i + headWords;
        // a single read validates dirty bits (revert empty), like x[i].
        const ref = this.lowerArrayRef(e.arr, ctx, out);
        if (ref.src !== 'calldata') throw new UnsupportedError('cdArrayField requires a calldata array');
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
        const stride = abiHeadWords(e.arr.elem) * 32;
        const disp = e.headWords * 32;
        const at = disp === 0 ? `mul(${i}, ${stride})` : `add(mul(${i}, ${stride}), ${disp})`;
        const w = this.fresh();
        out.push(`let ${w} := calldataload(add(${ref.offset}, ${at}))`);
        const guard = this.validateInput(e.fieldType, w);
        if (guard) out.push(guard);
        return w;
      }
      case 'arrayGet':
        return this.lowerArrayGet(e, ctx, out);
      case 'arrayLit': {
        // a MEMORY T[] (value elements): build [len][e0][e1]...] at the free pointer; the
        // register value IS the pointer. (The ABI-return form is handled by encodeArrayReturn.)
        const vals = e.elements.map((el) => this.lowerExpr(el, ctx, out));
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        out.push(`mstore(${ptr}, ${vals.length})`);
        vals.forEach((v, i) => out.push(`mstore(add(${ptr}, ${(i + 1) * 32}), ${v})`));
        out.push(`mstore(0x40, add(${ptr}, ${(vals.length + 1) * 32}))`);
        return ptr;
      }
      case 'newArray': {
        // new T[](n): a zeroed memory array. Freshly-allocated memory (beyond the free
        // pointer) is already zero in the EVM, so only the length word is written.
        const n = this.fresh();
        out.push(`let ${n} := ${this.lowerExpr(e.length, ctx, out)}`);
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        out.push(`mstore(${ptr}, ${n})`);
        out.push(`mstore(0x40, add(${ptr}, mul(add(${n}, 1), 0x20)))`);
        return ptr;
      }
      case 'arrayValue':
        // a memory array's register value IS its pointer (used when a memArray flows
        // through a ternary or a local-array assignment). Other array sources are
        // reference values consumed by the return/assign/length/index paths.
        if (e.arr.base.kind === 'memArray') return this.ctxLookup(ctx, e.arr.base.varName);
        throw new UnsupportedError(`reference value '${e.kind}' used in a non-reference context`);
      case 'dynStateRead':
      case 'dynParamRead':
      case 'dynLocalRead':
      case 'memDynField':
      case 'memDynStructValue':
      case 'cdDynArrayElem':
      case 'strArrayElem':
      case 'dynPlaceRead':
      case 'cdDynStructField':
      case 'cdDynStructValue':
      case 'cdAggregateValue':
      case 'stringLiteral':
      case 'structNew':
      case 'structValue':
      case 'structArrayElem':
      case 'mapStorageValue':
      case 'mapDynValue':
        // reference/aggregate values are not single 256-bit words; they are
        // consumed by the return/assign/length/index paths.
        throw new UnsupportedError(`reference value '${e.kind}' used in a non-reference context`);
    }
  }

  /** Encode a static struct value into ABI head words at memory 0; returns the size. */
  private encodeStructReturn(value: Expr, ctx: LowerCtx, out: string[]): number {
    if (value.kind === 'structValue') {
      const fields = (value.type as JethType & { kind: 'struct' }).fields;
      fields.forEach((f, j) => {
        const w = this.loadState(f.type, String(value.baseSlot + f.slot), f.offset);
        out.push(`mstore(${j * 32}, ${w})`);
      });
      return fields.length * 32;
    }
    if (value.kind === 'structNew') {
      // ABI head, one word per leaf: value fields write one word; a fixed-array-literal
      // field writes its N elements at consecutive head words.
      let w = 0;
      value.fields.forEach((f, j) => {
        const arg = value.args[j]!;
        if (f.type.kind === 'array' && arg.kind === 'arrayLit') {
          this.encodeArrayLitHead(arg, w, ctx, out);
          w += abiHeadWords(f.type);
        } else {
          out.push(`mstore(${w * 32}, ${this.lowerExpr(arg, ctx, out)})`);
          w += abiHeadWords(f.type);
        }
      });
      return w * 32;
    }
    throw new UnsupportedError(`cannot encode struct from ${value.kind}`);
  }

  /** Flatten a (possibly NESTED) static array literal into ABI head words starting at head
   *  word `wordBase` (memory offset wordBase*32). Value elements write one word; nested
   *  array / struct-literal elements recurse at wordBase + k*abiHeadWords(element). */
  private encodeArrayLitHead(lit: Expr & { kind: 'arrayLit' }, wordBase: number, ctx: LowerCtx, out: string[]): void {
    const elem = lit.elem;
    const ew = abiHeadWords(elem);
    lit.elements.forEach((el, k) => {
      const wb = wordBase + k * ew;
      if (el.kind === 'arrayLit') this.encodeArrayLitHead(el, wb, ctx, out);
      else if (el.kind === 'structNew') {
        // a struct-literal element: write each of its fields as a head word (static only here).
        let fw = wb;
        el.fields.forEach((sf, sj) => {
          const sarg = el.args[sj]!;
          if (sf.type.kind === 'array' && sarg.kind === 'arrayLit') { this.encodeArrayLitHead(sarg, fw, ctx, out); fw += abiHeadWords(sf.type); }
          else { out.push(`mstore(${fw * 32}, ${this.lowerExpr(sarg, ctx, out)})`); fw += abiHeadWords(sf.type); }
        });
      } else out.push(`mstore(${wb * 32}, ${this.lowerExpr(el, ctx, out)})`);
    });
  }

  /** Encode a MULTI-VALUE return `return [a, b, ...]` as a top-level ABI tuple (head/tail,
   *  NO outer offset wrapper - unlike a single dynamic value/struct return). Components may
   *  be a value (one inline head word), bytes/string (offset word + tail), or a storage-
   *  source struct/array (static -> inline head words; dynamic -> offset word + tail, via
   *  the recursive storage encoder). bytes/string sources are materialized BEFORE the blob
   *  pointer is captured so a later allocation cannot alias the blob. */
  private encodeReturnTuple(values: Expr[], types: JethType[], ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    const refs: ({ mp: string; len: string } | null)[] = types.map((t, i) =>
      isBytesLike(t) ? this.toMemory(this.lowerDynamic(values[i]!, ctx, out), out) : null,
    );
    const headWordsOf = (t: JethType): number => (isDynamicType(t) ? 1 : abiHeadWords(t));
    const totalHead = types.reduce((n, t) => n + headWordsOf(t), 0);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${ptr}, ${totalHead * 32})`);
    let hw = 0;
    types.forEach((t, i) => {
      const headPos = hw * 32;
      if (isBytesLike(t)) {
        const { mp, len } = refs[i]!;
        const padded = `and(add(${len}, 0x1f), not(0x1f))`;
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        out.push(`mcopy(${cursor}, ${mp}, add(0x20, ${padded}))`); // [len][data] from mp
        out.push(`${cursor} := add(${cursor}, add(0x20, ${padded}))`);
        hw += 1;
      } else if (isStaticValueType(t)) {
        out.push(`mstore(add(${ptr}, ${headPos}), ${this.lowerExpr(values[i]!, ctx, out)})`);
        hw += 1;
      } else if (t.kind === 'array' && (values[i]!.kind === 'arrayValue') && ((values[i] as Expr & { kind: 'arrayValue' }).arr.base.kind === 'memArray' || (values[i] as Expr & { kind: 'arrayValue' }).arr.base.kind === 'memArrayExpr')) {
        // a MEMORY value-array component (return [xs, n]): a dynamic component whose tail
        // is the memory [len][data] (value elements are one word each, the ABI layout).
        const av = values[i] as Expr & { kind: 'arrayValue' };
        const mp = av.arr.base.kind === 'memArray' ? this.ctxLookup(ctx, av.arr.base.varName) : this.lowerExpr((av.arr.base as { kind: 'memArrayExpr'; expr: Expr }).expr, ctx, out);
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        const total = `mul(add(mload(${mp}), 1), 0x20)`;
        out.push(`mcopy(${cursor}, ${mp}, ${total})`);
        out.push(`${cursor} := add(${cursor}, ${total})`);
        hw += 1;
      } else {
        // a struct / array component, storage-source: static -> inline head; dynamic ->
        // offset word + tail (both via the recursive storage encoder).
        const slot = this.aggComponentSlot(values[i]!, ctx, out);
        if (isDynamicType(t)) {
          out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
          const sz = this.abiEncFromStorage(t, slot, 0, cursor, out);
          out.push(`${cursor} := add(${cursor}, ${sz})`);
          hw += 1;
        } else {
          this.abiEncFromStorage(t, slot, 0, `add(${ptr}, ${headPos})`, out);
          hw += abiHeadWords(t);
        }
      }
    });
    out.push(`mstore(0x40, ${cursor})`);
    return { ptr, size: `sub(${cursor}, ${ptr})` };
  }

  /** Storage base slot (length slot for an array) of a storage-source aggregate value used
   *  as a multi-return component (this.d / this.m[k] / this.recs[i] / this.arr). */
  private aggComponentSlot(value: Expr, ctx: LowerCtx, out: string[]): string {
    if (value.kind === 'structValue') return String(value.baseSlot);
    if (value.kind === 'mapStorageValue') return this.mappingSlot(value.baseSlot, value.keys, ctx, out);
    if (value.kind === 'structArrayElem') return this.structArrayElemSlot(value.arr, value.index, ctx, out);
    if (value.kind === 'placeRead') return this.lowerPlace(value.path, ctx, out).slot;
    if (value.kind === 'arrayValue') {
      if (value.arr.base.kind === 'stateArray') return String(value.arr.base.slot);
      if (value.arr.base.kind === 'fixedArray') return String(value.arr.base.baseSlot);
      if (value.arr.base.kind === 'mapArray') return this.mappingSlot(value.arr.base.baseSlot, value.arr.base.keys, ctx, out);
      if (value.arr.base.kind === 'placeArray') return this.lowerPlace(value.arr.base.path, ctx, out).slot;
    }
    throw new UnsupportedError(`a multi-return ${value.type.kind} component must be a storage value (this.x / this.m[k] / this.arr[i])`);
  }

  /** Encode a DYNAMIC struct return value (Phase 4e-6): sole return is
   *  [head 0x20][tuple head/tail at byte 0x20]. The value source is either a
   *  constructed struct (structNew) or a calldata dynamic-struct echo
   *  (cdDynStructValue). Returns the (ptr, size) of the encoded blob. */
  private encodeDynStructReturn(value: Expr, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    const struct = value.type as JethType & { kind: 'struct' };
    const src = this.tupleSrc(value, ctx, out);
    // PRE-PASS: materialize every bytes/string field value into a memory/calldata
    // DynRef FIRST (string literals alloc now, below the output blob), so the blob
    // pointer captured next is past them and no later alloc can alias the blob.
    const queue: DynRef[] = [];
    this.collectTupleDyn(struct, src, queue, ctx, out);
    let qi = 0;
    const nextRef = (): DynRef => queue[qi++]!;
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`); // sole-return head offset
    const tuplePtr = this.fresh();
    out.push(`let ${tuplePtr} := add(${ptr}, 0x20)`); // tuple start (memory base)
    const end = this.encodeTupleInto(struct, src, tuplePtr, ctx, out, nextRef);
    out.push(`mstore(0x40, ${end})`); // bump free-mem pointer past the blob
    return { ptr, size: `sub(${end}, ${ptr})` };
  }

  /** PRE-PASS: walk a tuple in encode order and materialize each bytes/string
   *  field's value into a DynRef (string literals are allocated NOW via toMemory,
   *  before the output blob pointer is captured, so they cannot alias the blob).
   *  Calldata sources need no materialization. Recurses into nested structs in the
   *  exact order encodeTupleInto consumes them. */
  private collectTupleDyn(struct: JethType & { kind: 'struct' }, src: TupleSrc, queue: DynRef[], ctx: LowerCtx, out: string[]): void {
    let hw = 0;
    struct.fields.forEach((f, i) => {
      if (isDynamicType(f.type)) {
        if (isBytesLike(f.type)) {
          const ref = this.dynFieldRef(f, src, i, hw, ctx, out);
          // materialize a memory source now (alloc happens here, below the blob);
          // calldata sources are passed through unchanged (calldatacopy is safe).
          if (ref.src === 'memory') {
            const { mp } = this.toMemory(ref, out);
            queue.push({ src: 'memory', ptr: mp });
          } else {
            queue.push(ref);
          }
        } else if (f.type.kind === 'struct') {
          const nestedSrc = this.nestedTupleSrc(f, src, i, hw, ctx, out);
          this.collectTupleDyn(f.type, nestedSrc, queue, ctx, out);
        } else {
          throw new UnsupportedError(`unsupported dynamic struct field kind '${f.type.kind}'`);
        }
        hw += 1;
      } else {
        hw += abiHeadWords(f.type);
      }
    });
  }

  /** Build the value source for a tuple from a return Expr. */
  private tupleSrc(value: Expr, ctx: LowerCtx, out: string[]): TupleSrc {
    if (value.kind === 'structNew') return { kind: 'new', fields: value.fields, args: value.args };
    if (value.kind === 'cdDynStructValue') {
      const bound = ctx.cdDynStructs.get(value.param);
      if (!bound) throw new UnsupportedError(`dynamic struct param '${value.param}' is not bound`);
      return { kind: 'cd', base: bound.tupleStart };
    }
    if (value.kind === 'memDynStructValue') {
      return { kind: 'mem', headPtr: this.ctxLookup(ctx, value.local) };
    }
    throw new UnsupportedError(`cannot encode dynamic struct from ${value.kind}`);
  }

  /** Recursively encode a struct tuple into memory at `tuplePtr` (the tuple-start
   *  base). Static fields stay inline in the head (declaration order); each dynamic
   *  field gets a head OFFSET word (relative to tuplePtr) and its payload in the
   *  tail (field order). Returns a Yul expr for the memory pointer just past the
   *  tail. Mirrors spec section 3.1 exactly: offsets reset to THIS tuple's start. */
  private encodeTupleInto(struct: JethType & { kind: 'struct' }, src: TupleSrc, tuplePtr: string, ctx: LowerCtx, out: string[], nextRef: () => DynRef): string {
    const headWords = tupleHeadWords(struct);
    // tail cursor starts right after the tuple head.
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${tuplePtr}, ${headWords * 32})`);
    let hw = 0; // running head-word offset within the tuple
    struct.fields.forEach((f, i) => {
      const headByte = hw * 32;
      const headDst = headByte === 0 ? tuplePtr : `add(${tuplePtr}, ${headByte})`;
      if (isDynamicType(f.type)) {
        // dynamic field: write its offset (cursor - tuplePtr), then its payload.
        out.push(`mstore(${headDst}, sub(${cursor}, ${tuplePtr}))`);
        const newCursor = this.encodeDynFieldInto(f, src, i, hw, cursor, ctx, out, nextRef);
        out.push(`${cursor} := ${newCursor}`);
        hw += 1;
      } else {
        // static field: write its abiHeadWords words inline at headDst.
        this.encodeStaticInline(f.type, src, i, hw, headDst, ctx, out);
        hw += abiHeadWords(f.type);
      }
    });
    return cursor;
  }

  /** Encode a single DYNAMIC field's payload at `cursor`; returns the new cursor.
   *  bytes/string -> [byteLen][right-padded data] (value pulled from the pre-
   *  materialized queue, so no aliasing alloc happens here); a nested dynamic
   *  struct -> its own head/tail tuple (base resets to the nested tuple start). */
  private encodeDynFieldInto(f: StructField, src: TupleSrc, fieldIdx: number, headWord: number, cursor: string, ctx: LowerCtx, out: string[], nextRef: () => DynRef): string {
    if (isBytesLike(f.type)) {
      // Write [byteLen][right-padded data] directly at the cursor, copying from the
      // pre-materialized source. calldata -> calldatacopy; memory -> mcopy; then
      // zero the partial-word tail so padding is clean.
      const ref = nextRef();
      const len = this.fresh();
      out.push(`let ${len} := ${this.dynLen(ref)}`);
      // DECODE-TO-MEMORY ECHO alloc bound (rule 3): cap the byte length at 2^64-1 first
      // (Panic 0x41, so roundup32 cannot wrap), then check the new free pointer crossing
      // 2^64-1 (or wrapping) -> Panic(0x41); a calldata source THEN validates the payload
      // lies within calldatasize (else EMPTY). All precede the store/copy.
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
      const padded = `and(add(${len}, 0x1f), not(0x1f))`;
      const nc = this.fresh();
      out.push(`let ${nc} := add(${cursor}, add(0x20, ${padded}))`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
      if (ref.src === 'calldata') {
        out.push(`if gt(add(${ref.dataPtr}, ${len}), calldatasize()) { revert(0, 0) }`);
        out.push(`mstore(${cursor}, ${len})`);
        out.push(`calldatacopy(add(${cursor}, 0x20), ${ref.dataPtr}, ${len})`);
      } else if (ref.src === 'memory') {
        out.push(`mstore(${cursor}, ${len})`);
        out.push(`mcopy(add(${cursor}, 0x20), add(${ref.ptr}, 0x20), ${len})`);
      } else {
        throw new UnsupportedError('encoding a storage bytes/string struct field is not supported yet');
      }
      out.push(`if mod(${len}, 0x20) { mstore(add(add(${cursor}, 0x20), ${len}), 0) }`);
      return nc;
    }
    if (f.type.kind === 'struct') {
      // nested dynamic struct: encode it as its own tuple starting at cursor.
      const nestedSrc = this.nestedTupleSrc(f, src, fieldIdx, headWord, ctx, out);
      return this.encodeTupleInto(f.type, nestedSrc, cursor, ctx, out, nextRef);
    }
    throw new UnsupportedError(`unsupported dynamic struct field kind '${f.type.kind}'`);
  }

  /** Resolve a bytes/string field's value to a DynRef from the tuple source. This is
   *  the WHOLE-struct ECHO path (return d), so the calldata case uses the ECHO-DECODE
   *  helper (unsigned offset cap, no length cap / payload-fits); the alloc Panic(0x41)
   *  and the payload-within-calldatasize check land in encodeDynFieldInto's copy. */
  private dynFieldRef(f: StructField, src: TupleSrc, fieldIdx: number, headWord: number, ctx: LowerCtx, out: string[]): DynRef {
    if (src.kind === 'new') return this.lowerDynamic(src.args[fieldIdx]!, ctx, out);
    if (src.kind === 'mem') {
      // the head word holds the [len][data] memory pointer of the bytes/string field.
      const at = headWord === 0 ? src.headPtr : `add(${src.headPtr}, ${headWord * 32})`;
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(${at})`);
      return { src: 'memory', ptr };
    }
    // calldata echo: read the field's offset word at base + headWord*32, resolve.
    const offPtr = headWord === 0 ? src.base : `add(${src.base}, ${headWord * 32})`;
    const dataPtr = this.fresh();
    const len = this.fresh();
    out.push(`let ${dataPtr}, ${len} := ${this.calldataDynAtEcho()}(${src.base}, ${offPtr})`);
    return { src: 'calldata', dataPtr, len };
  }

  /** Build the value source for a nested (sub)struct field. */
  private nestedTupleSrc(f: StructField, src: TupleSrc, fieldIdx: number, headWord: number, ctx: LowerCtx, out: string[]): TupleSrc {
    const nested = f.type as JethType & { kind: 'struct' };
    if (src.kind === 'new') {
      const arg = src.args[fieldIdx]!;
      if (arg.kind !== 'structNew') throw new UnsupportedError('nested struct field must be constructed inline');
      return { kind: 'new', fields: arg.fields, args: arg.args };
    }
    if (src.kind === 'mem') throw new UnsupportedError('nested struct field in a memory dynamic struct is not supported');
    // calldata echo. If the nested struct is dynamic, its head slot is an offset
    // word (base resets to base + offset); if static, it is inline at base+head.
    const fieldOff = headWord === 0 ? src.base : `add(${src.base}, ${headWord * 32})`;
    if (isDynamicType(nested)) {
      const nb = this.fresh();
      out.push(`let ${nb} := ${this.calldataTupleAt()}(${src.base}, ${fieldOff}, ${tupleHeadWords(nested) * 32})`);
      return { kind: 'cd', base: nb };
    }
    return { kind: 'cd', base: fieldOff };
  }

  /** Write a STATIC field's `abiHeadWords` words inline at memory `dstPtr` (one
   *  unpacked ABI word per leaf). new source: lower each leaf value (recursing into
   *  nested static structs); cd source: copy + validate each leaf word from the
   *  calldata tuple at base + headWord*32. */
  private encodeStaticInline(type: JethType, src: TupleSrc, fieldIdx: number, headWord: number, dstPtr: string, ctx: LowerCtx, out: string[]): void {
    if (src.kind === 'new') {
      // a static value field, or a nested static struct constructed inline.
      const arg = src.args[fieldIdx]!;
      if (type.kind === 'struct' || (type.kind === 'array' && type.length !== undefined)) {
        // flatten via abiLeaves; the structNew args provide the leaf values.
        const leaves = this.staticNewLeaves(type, arg, ctx, out);
        leaves.forEach((w, k) => out.push(`mstore(${k === 0 ? dstPtr : `add(${dstPtr}, ${k * 32})`}, ${w})`));
        return;
      }
      const w = this.lowerExpr(arg, ctx, out);
      out.push(`mstore(${dstPtr}, ${w})`);
      return;
    }
    if (src.kind === 'mem') {
      // a value field of a memory dynamic struct: one inline word at headWord.
      const at = headWord === 0 ? src.headPtr : `add(${src.headPtr}, ${headWord * 32})`;
      const w = this.fresh();
      out.push(`let ${w} := mload(${at})`);
      out.push(`mstore(${dstPtr}, ${w})`);
      return;
    }
    // calldata echo: copy + validate each leaf word.
    const srcBaseOff = headWord === 0 ? src.base : `add(${src.base}, ${headWord * 32})`;
    for (const leaf of abiLeaves(type)) {
      const disp = leaf.wordOffset * 32;
      const at = disp === 0 ? srcBaseOff : `add(${srcBaseOff}, ${disp})`;
      const w = this.fresh();
      out.push(`let ${w} := calldataload(${at})`);
      const guard = this.validateInput(leaf.type, w);
      if (guard) out.push(guard);
      out.push(`mstore(${disp === 0 ? dstPtr : `add(${dstPtr}, ${disp})`}, ${w})`);
    }
  }

  /** Collect the unpacked ABI leaf words of a STATIC aggregate built by a structNew
   *  (recursing into nested static struct args). The order matches abiLeaves(type). */
  private staticNewLeaves(type: JethType, arg: Expr, ctx: LowerCtx, out: string[]): string[] {
    if (type.kind === 'struct') {
      if (arg.kind !== 'structNew') throw new UnsupportedError('static nested struct must be constructed inline');
      const words: string[] = [];
      type.fields.forEach((f, i) => words.push(...this.staticNewLeaves(f.type, arg.args[i]!, ctx, out)));
      return words;
    }
    if (type.kind === 'array' && type.length !== undefined) {
      throw new UnsupportedError('a static fixed-array struct field constructed inline is not supported yet');
    }
    return [this.lowerExpr(arg, ctx, out)];
  }

  // ---- nested storage access (Phase 4c-3) ----------------------------------

  /** Fold an AccessPath into a (slot expr, byte offset). Constant steps fold to a
   *  constant slot; mapping keys and dynamic indices produce runtime slot temps.
   *  Index steps are over whole-slot elements (stride in slots), offset stays 0;
   *  field steps add the field slot and set the packing offset. */
  private lowerPlace(path: AccessPath, ctx: LowerCtx, out: string[]): { slot: string; offset: number; byteShift?: string } {
    let constSlot: number | null = path.baseSlot;
    let slot = String(path.baseSlot);
    let offset = 0;
    let byteShift: string | undefined; // a RUNTIME byte offset within the slot (packed elem)
    for (const step of path.steps) {
      if (step.kind === 'field') {
        if (constSlot !== null) {
          constSlot += step.fieldSlot;
          slot = String(constSlot);
        } else if (step.fieldSlot !== 0) {
          slot = `add(${slot}, ${step.fieldSlot})`;
        }
        offset = step.fieldOffset;
      } else if (step.kind === 'index') {
        if (step.index.kind === 'literalInt') {
          const add = Number(step.index.value) * step.strideSlots;
          if (constSlot !== null) {
            constSlot += add;
            slot = String(constSlot);
          } else if (add !== 0) {
            slot = `add(${slot}, ${add})`;
          }
        } else {
          const it = this.fresh();
          out.push(`let ${it} := ${this.lowerExpr(step.index, ctx, out)}`);
          out.push(`if iszero(lt(${it}, ${step.length})) { ${this.panic()}(0x32) }`);
          const delta = step.strideSlots === 1 ? it : `mul(${it}, ${step.strideSlots})`;
          slot = `add(${constSlot !== null ? constSlot : slot}, ${delta})`;
          constSlot = null;
        }
        offset = 0;
      } else if (step.kind === 'packedIndex') {
        // packed fixed-array element (perSlot per slot): slot = base + i/perSlot, with a
        // byte offset (i%perSlot)*size within that slot (constant if i is literal).
        if (step.index.kind === 'literalInt') {
          const k = Number(step.index.value);
          const slotAdd = Math.floor(k / step.perSlot);
          if (constSlot !== null) { constSlot += slotAdd; slot = String(constSlot); }
          else if (slotAdd !== 0) { slot = `add(${slot}, ${slotAdd})`; }
          offset = (k % step.perSlot) * step.size;
          byteShift = undefined;
        } else {
          const it = this.fresh();
          out.push(`let ${it} := ${this.lowerExpr(step.index, ctx, out)}`);
          out.push(`if iszero(lt(${it}, ${step.length})) { ${this.panic()}(0x32) }`);
          const base = constSlot !== null ? String(constSlot) : slot;
          slot = `add(${base}, div(${it}, ${step.perSlot}))`;
          byteShift = `mul(mod(${it}, ${step.perSlot}), ${step.size})`;
          constSlot = null;
          offset = 0;
        }
      } else if (step.kind === 'dynIndex') {
        // dynamic T[] element: bound vs sload(lenSlot); data at keccak(lenSlot).
        const lenSlot = constSlot !== null ? String(constSlot) : slot;
        const it = this.fresh();
        out.push(`let ${it} := ${this.lowerExpr(step.index, ctx, out)}`);
        out.push(`if iszero(lt(${it}, sload(${lenSlot}))) { ${this.panic()}(0x32) }`);
        const dataBase = this.fresh();
        out.push(`let ${dataBase} := ${this.arrayDataSlotHelper()}(${lenSlot})`);
        const delta = step.strideSlots === 1 ? it : `mul(${it}, ${step.strideSlots})`;
        slot = `add(${dataBase}, ${delta})`;
        constSlot = null;
        offset = 0;
      } else {
        // mapping key: slot = keccak256(keyWord . currentSlot)
        const k = this.lowerExpr(step.key, ctx, out);
        const tmp = this.fresh();
        out.push(`mstore(0x00, ${k})`);
        out.push(`mstore(0x20, ${constSlot !== null ? constSlot : slot})`);
        out.push(`let ${tmp} := keccak256(0x00, 0x40)`);
        slot = tmp;
        constSlot = null;
        offset = 0;
      }
    }
    return { slot, offset, byteShift };
  }

  /** Fold a CalldataPlace (struct/fixed-array param navigation) into a calldata
   *  byte-offset expression. The ABI head is UNPACKED: a field step adds a const
   *  word offset; an index step bounds-checks (Panic 0x32) then adds idx*stride.
   *  A constant index needs no runtime check (the analyzer rejected OOB literals,
   *  matching solc's compile-time "out of bounds array access"). */
  private lowerCdPlace(place: CalldataPlace, ctx: LowerCtx, out: string[]): string {
    const agg = ctx.cdAggregates.get(place.param);
    if (!agg) throw new UnsupportedError(`calldata aggregate param '${place.param}' is not bound`);
    let constOff = agg.baseOffset;
    let off: string | null = null; // set once a dynamic index appears
    for (const step of place.steps) {
      if (step.kind === 'field') {
        const add = 32 * step.headWords;
        if (off === null) constOff += add;
        else if (add !== 0) off = `add(${off}, ${add})`;
      } else {
        const stride = 32 * step.strideWords;
        if (step.index.kind === 'literalInt') {
          const add = Number(step.index.value) * stride;
          if (off === null) constOff += add;
          else if (add !== 0) off = `add(${off}, ${add})`;
        } else {
          const it = this.fresh();
          out.push(`let ${it} := ${this.lowerExpr(step.index, ctx, out)}`);
          out.push(`if iszero(lt(${it}, ${step.length})) { ${this.panic()}(0x32) }`);
          off = `add(${off === null ? constOff : off}, mul(${it}, ${stride}))`;
        }
      }
    }
    return off === null ? String(constOff) : off;
  }

  // ---- dynamic structs (Phase 4e-6) ----------------------------------------

  /** Walk the all-but-last steps of a dynamic-struct place, returning the calldata
   *  byte pointer of the tuple that CONTAINS the final field. The base resets at
   *  each dynamic-struct boundary: a static nested-struct field is inline (new base
   *  = field word addr); a dynamic nested-struct field stores an offset word (new
   *  base = current base + that offset, spec section 3.2). A bad nested offset /
   *  unreadable tuple head -> EMPTY revert. Returns a Yul expr for the base. */
  private lowerCdDynBase(place: CdDynPlace, ctx: LowerCtx, out: string[]): string {
    let base: string;
    if (place.arrayRoot) {
      // base tuple = ds[i] of a dynamic-struct array: resolve via the offset table.
      const ref = this.lowerArrayRef(place.arrayRoot.arr, ctx, out);
      if (ref.src !== 'calldata') throw new UnsupportedError('dynamic-struct-array element requires a calldata array');
      const i = this.fresh();
      out.push(`let ${i} := ${this.lowerExpr(place.arrayRoot.index, ctx, out)}`);
      out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
      const eo = this.fresh();
      out.push(`let ${eo} := calldataload(add(${ref.offset}, mul(${i}, 0x20)))`);
      // lazy-access element offset: solc signed slt + modular wrap (base = table start).
      // The element is a dynamic-struct TUPLE: its WHOLE head (headWords*32 bytes), not
      // just the first field word, must be in range (else solc EMPTY-reverts).
      const elemHead = tupleHeadWords(place.arrayRoot.arr.elem as JethType & { kind: 'struct' }) * 32;
      out.push(`if iszero(slt(${eo}, sub(sub(calldatasize(), ${ref.offset}), ${elemHead - 1}))) { revert(0, 0) }`);
      const ts = this.fresh();
      out.push(`let ${ts} := add(${ref.offset}, ${eo})`);
      base = ts;
    } else {
      const bound = ctx.cdDynStructs.get(place.param);
      if (!bound) throw new UnsupportedError(`dynamic struct param '${place.param}' is not bound`);
      base = bound.tupleStart;
    }
    // process every step except the last (the caller resolves the final field).
    for (let k = 0; k < place.steps.length - 1; k++) {
      const step = place.steps[k]!;
      const fieldOff = step.headWords === 0 ? base : `add(${base}, ${step.headWords * 32})`;
      if (step.crossDynamic) {
        // a nested DYNAMIC struct: read its offset word; new base = base + offset.
        const fst = step.fieldType as JethType & { kind: 'struct' };
        const headSize = tupleHeadWords(fst) * 32;
        const nb = this.fresh();
        out.push(`let ${nb} := ${this.calldataTupleAt()}(${base}, ${fieldOff}, ${headSize})`);
        base = nb;
      } else {
        // a nested STATIC struct: inline at fieldOff; new base = fieldOff.
        const nb = this.fresh();
        out.push(`let ${nb} := ${fieldOff}`);
        base = nb;
      }
    }
    return base;
  }

  /** Resolve a static-value leaf of a dynamic-struct place to its calldata byte
   *  offset (the leaf word address). The leaf word is validated on read by the
   *  caller (dirty bits -> EMPTY revert), matching solc's lazy field validation. */
  private lowerCdDynLeafOff(place: CdDynPlace, ctx: LowerCtx, out: string[]): string {
    const base = this.lowerCdDynBase(place, ctx, out);
    const last = place.steps[place.steps.length - 1]!;
    return last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
  }

  // ---- dynamic arrays (Phase 4b) -------------------------------------------

  private lowerArrayRef(arr: ArrayExpr, ctx: LowerCtx, out: string[]): ArrayRef {
    if (arr.base.kind === 'stateArray') {
      return { src: 'storage', lenSlot: String(arr.base.slot), elem: arr.elem };
    }
    if (arr.base.kind === 'fixedArray') {
      return { src: 'fixed', baseSlot: arr.base.baseSlot, length: arr.base.length, elem: arr.elem };
    }
    if (arr.base.kind === 'mapArray') {
      // a mapping-valued dynamic array: length lives at the runtime mapping slot.
      const lenSlot = this.mappingSlot(arr.base.baseSlot, arr.base.keys, ctx, out);
      return { src: 'storage', lenSlot, elem: arr.elem };
    }
    if (arr.base.kind === 'placeArray') {
      // a storage inner dynamic array (nested-array element / dyn-array struct field):
      // its length slot is the AccessPath slot; data at keccak(that slot).
      const p = this.lowerPlace(arr.base.path, ctx, out);
      return { src: 'storage', lenSlot: p.slot, elem: arr.elem };
    }
    if (arr.base.kind === 'memArray') {
      // a memory array local: the register holds a pointer to [len][elem0]...
      return { src: 'memory', ptr: this.ctxLookup(ctx, arr.base.varName), elem: arr.elem };
    }
    if (arr.base.kind === 'memArrayExpr') {
      // a memory array produced by an expression (a ternary): lower it to its pointer.
      const ptr = this.fresh();
      out.push(`let ${ptr} := ${this.lowerExpr(arr.base.expr, ctx, out)}`);
      return { src: 'memory', ptr, elem: arr.elem };
    }
    if (arr.base.kind === 'cdNestedElem') {
      // Inner array m[i] of a nested dynamic array T[][] (calldata, 4e-5). The outer
      // param is decoded into (pointerRegionStart, outerLen); bounds-check i against
      // outerLen (Panic 0x32), then resolve inner i's (dataOffset, innerLen) through
      // its pointer-table word (base = pointerRegionStart, spec section 2). A pointer
      // / length / payload past calldatasize -> EMPTY revert inside the helper.
      const b = ctx.cdArrays.get(arr.base.name);
      if (!b) throw new UnsupportedError(`unbound nested calldata array ${arr.base.name}`);
      // Descend one dynamic-array level per index. The container at each step lives at
      // (base=pointer-region start, len). For every step but the last the inner element
      // is itself a dynamic array (a single pointer word, stride 32); the last step
      // resolves the array whose element is `arr.elem` (stride abiHeadWords*32).
      const indices = arr.base.indices;
      let base = b.offset;
      let len = b.length;
      indices.forEach((idxExpr, s) => {
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(idxExpr, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${len})) { ${this.panic()}(0x32) }`);
        const stride = s === indices.length - 1 ? abiHeadWords(arr.elem) * 32 : 32;
        const nb = this.fresh();
        const nl = this.fresh();
        out.push(`let ${nb}, ${nl} := ${this.calldataInnerArray()}(${base}, ${i}, ${stride})`);
        base = nb;
        len = nl;
      });
      return { src: 'calldata', offset: base, length: len, elem: arr.elem };
    }
    const b = ctx.cdArrays.get(arr.base.name);
    if (!b) throw new UnsupportedError(`unbound calldata array ${arr.base.name}`);
    return { src: 'calldata', offset: b.offset, length: b.length, elem: arr.elem };
  }

  private arrayDataSlot(lenSlot: string, out: string[]): string {
    const d = this.fresh();
    out.push(`let ${d} := ${this.arrayDataSlotHelper()}(${lenSlot})`);
    return d;
  }

  private lowerArrayGet(e: Expr & { kind: 'arrayGet' }, ctx: LowerCtx, out: string[]): string {
    const ref = this.lowerArrayRef(e.arr, ctx, out);
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
    if (ref.src === 'storage') {
      out.push(`if iszero(lt(${i}, sload(${ref.lenSlot}))) { ${this.panic()}(0x32) }`);
      const data = this.arrayDataSlot(ref.lenSlot, out);
      return this.arrayElemLoad(ref.elem, data, i);
    }
    if (ref.src === 'fixed') {
      out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
      return this.arrayElemLoad(ref.elem, String(ref.baseSlot), i); // data inline at baseSlot
    }
    if (ref.src === 'memory') {
      // memory T[] (value element, one word each): bound vs mload(ptr); data at ptr+0x20.
      out.push(`if iszero(lt(${i}, mload(${ref.ptr}))) { ${this.panic()}(0x32) }`);
      return `mload(add(${ref.ptr}, add(0x20, mul(${i}, 0x20))))`;
    }
    out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
    const w = this.fresh();
    out.push(`let ${w} := calldataload(add(${ref.offset}, mul(${i}, 32)))`);
    const guard = this.validateInput(ref.elem, w); // validate dirty calldata elements on read
    if (guard) out.push(guard);
    return w;
  }

  /** Load array element i (register form) from storage data base `dataSlot`. */
  private arrayElemLoad(elem: JethType, dataSlot: string, iExpr: string): string {
    const packs = arrayElemPacks(elem);
    if (!packs.packed) return this.loadState(elem, `add(${dataSlot}, ${iExpr})`, 0);
    const slot = `add(${dataSlot}, div(${iExpr}, ${packs.perSlot}))`;
    const byteOff = `mul(mod(${iExpr}, ${packs.perSlot}), ${packs.size})`;
    return this.packedLoad(elem, slot, byteOff);
  }

  private arrayElemStore(elem: JethType, dataSlot: string, iExpr: string, value: string, out: string[]): void {
    const packs = arrayElemPacks(elem);
    if (!packs.packed) {
      for (const l of this.storeState(elem, `add(${dataSlot}, ${iExpr})`, 0, value)) out.push(l);
      return;
    }
    const st = this.fresh();
    out.push(`let ${st} := add(${dataSlot}, div(${iExpr}, ${packs.perSlot}))`);
    const byteOff = `mul(mod(${iExpr}, ${packs.perSlot}), ${packs.size})`;
    this.packedStore(elem, st, byteOff, value, out);
  }

  private packedLoad(elem: JethType, slot: string, byteOff: string): string {
    const { size } = arrayElemPacks(elem);
    const mask = toWord((1n << BigInt(size * 8)) - 1n);
    const raw = `shr(mul(${byteOff}, 8), sload(${slot}))`;
    if (elem.kind === 'int') return `signextend(${size - 1}, ${raw})`;
    if (elem.kind === 'bytesN') return `shl(${(32 - size) * 8}, and(${raw}, ${mask}))`;
    return `and(${raw}, ${mask})`;
  }

  private packedStore(elem: JethType, slot: string, byteOff: string, value: string, out: string[]): void {
    const { size } = arrayElemPacks(elem);
    const mask = toWord((1n << BigInt(size * 8)) - 1n);
    const fieldData = elem.kind === 'bytesN' ? `shr(${(32 - size) * 8}, ${value})` : value;
    const bit = this.fresh();
    out.push(`let ${bit} := mul(${byteOff}, 8)`);
    const cleared = this.fresh();
    out.push(`let ${cleared} := and(sload(${slot}), not(shl(${bit}, ${mask})))`);
    out.push(`sstore(${slot}, or(${cleared}, shl(${bit}, and(${fieldData}, ${mask}))))`);
  }

  private lowerPush(arr: ArrayExpr, value: string, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('push on a non-storage array');
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    out.push(`sstore(${ref.lenSlot}, add(${len}, 1))`);
    const data = this.arrayDataSlot(ref.lenSlot, out);
    this.arrayElemStore(ref.elem, data, len, value, out);
  }

  /** push a whole inner array onto a nested storage array (this.dd.push(xs) on a T[][]):
   *  grow the outer length, then deep-copy the pushed array value into the freshly grown
   *  inner element (its length slot is at data + len*stride, fresh = empty). A no-arg
   *  push() leaves the inner array empty (length 0). */
  private lowerArrayPush(arr: ArrayExpr, value: Expr | undefined, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('push on a non-storage array');
    const stride = storageSlotCount(arr.elem); // a dynamic-array inner element occupies 1 slot
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    out.push(`sstore(${ref.lenSlot}, add(${len}, 1))`);
    const dataBase = this.fresh();
    out.push(`let ${dataBase} := ${this.arrayDataSlotHelper()}(${ref.lenSlot})`);
    const innerSlot = this.fresh();
    out.push(`let ${innerSlot} := add(${dataBase}, mul(${len}, ${stride}))`);
    if (value) this.copyArrayValueIntoStorage((arr.elem as JethType & { kind: 'array' }).element, value, innerSlot, ctx, out);
  }

  /** Deep-copy an ARRAY VALUE (memory `memArray`/`arrayLit` of value elements, or a
   *  storage `stateArray`/`mapArray`) into a storage dynamic array at `dstLenSlot`. Clears
   *  the dst's OLD data first (so it works for both a fresh push slot, oldLen 0 = no-op,
   *  and an overwrite assign), then sets the length and copies every element. */
  private copyArrayValueIntoStorage(innerElem: JethType, value: Expr, dstLenSlot: string, ctx: LowerCtx, out: string[]): void {
    const storageSrc =
      value.kind === 'mapStorageValue' ||
      (value.kind === 'arrayValue' && (value.arr.base.kind === 'stateArray' || value.arr.base.kind === 'mapArray' || value.arr.base.kind === 'placeArray'));
    if (storageSrc) {
      this.copyArray(innerElem, this.arraySrcLenSlot(value, ctx, out), dstLenSlot, out);
      return;
    }
    // memory source (a memArray local or an array literal): value elements only.
    if (!isStaticValueType(innerElem)) throw new UnsupportedError('a memory array of non-value elements is not supported');
    const memPtr = this.lowerExpr(value, ctx, out);
    const n = this.fresh();
    out.push(`let ${n} := mload(${memPtr})`);
    const dstData = this.fresh();
    out.push(`let ${dstData} := ${this.arrayDataSlotHelper()}(${dstLenSlot})`);
    // clear the dst's OLD data slots (overwrite case); for a fresh slot oldLen is 0.
    const packs = arrayElemPacks(innerElem);
    const slotsFor = (L: string): string => (packs.packed ? `div(add(${L}, ${packs.perSlot - 1}), ${packs.perSlot})` : `mul(${L}, ${storageSlotCount(innerElem)})`);
    const oldSlots = this.fresh();
    out.push(`let ${oldSlots} := ${slotsFor(`sload(${dstLenSlot})`)}`);
    const c = this.fresh();
    out.push(`for { let ${c} := 0 } lt(${c}, ${oldSlots}) { ${c} := add(${c}, 1) } { sstore(add(${dstData}, ${c}), 0) }`);
    out.push(`sstore(${dstLenSlot}, ${n})`);
    const i = this.fresh();
    out.push(`for { let ${i} := 0 } lt(${i}, ${n}) { ${i} := add(${i}, 1) } {`);
    const inner: string[] = [];
    const me = this.fresh();
    inner.push(`let ${me} := mload(add(${memPtr}, add(0x20, mul(${i}, 0x20))))`);
    this.arrayElemStore(innerElem, dstData, i, me, inner);
    for (const l of inner) out.push('  ' + l);
    out.push('}');
  }

  private lowerPop(arr: ArrayExpr, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('pop on a non-storage array');
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if iszero(${len}) { ${this.panic()}(0x31) }`);
    const nl = this.fresh();
    out.push(`let ${nl} := sub(${len}, 1)`);
    out.push(`sstore(${ref.lenSlot}, ${nl})`);
    const data = this.arrayDataSlot(ref.lenSlot, out);
    const sc = storageSlotCount(ref.elem);
    if (sc === 1) {
      // value element, or a fixed array that packs into ONE slot (uint8[4], uint128[2]):
      // arrayElemStore handles per-byte packing / single-slot clear.
      this.arrayElemStore(ref.elem, data, nl, '0', out);
    } else {
      // a MULTI-slot fixed-array element (uint256[2], uint256[2][2], ...): solc zeroes ALL
      // sc slots of the freed element; clear each contiguous slot at data + nl*sc.
      const base = this.fresh();
      out.push(`let ${base} := add(${data}, mul(${nl}, ${sc}))`);
      for (let k = 0; k < sc; k++) out.push(`sstore(${k === 0 ? base : `add(${base}, ${k})`}, 0)`);
    }
  }

  /** push a struct element onto a storage dynamic array: grow length, then write
   *  each field of the appended element (Solidity packs fields within its slots).
   *  A no-value push zero-initializes the new element's slots. */
  private lowerStructPush(arr: ArrayExpr, value: Expr | undefined, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('push on a non-storage array');
    const struct = arr.elem as JethType & { kind: 'struct' };
    const slots = storageSlotCount(struct);
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    out.push(`sstore(${ref.lenSlot}, add(${len}, 1))`);
    const dataBase = this.fresh();
    out.push(`let ${dataBase} := ${this.arrayDataSlotHelper()}(${ref.lenSlot})`);
    const base = this.fresh();
    out.push(`let ${base} := add(${dataBase}, mul(${len}, ${slots}))`);
    if (value && value.kind === 'structNew') {
      this.writeStruct(value.fields, value.args, base, ctx, out);
    } else {
      for (let j = 0; j < slots; j++) out.push(`sstore(${j === 0 ? base : `add(${base}, ${j})`}, 0)`);
    }
  }

  /** Write a struct value (from a structNew, possibly with nested-struct field
   *  args) into storage starting at `baseSlot` (a constant-numeric string or a
   *  register expr). Nested structs are flattened recursively into packed slots;
   *  value fields go through storeState (handles packing / whole-slot); a
   *  bytes/string dynamic field at slotAt(f.slot) goes through storeDynamic (a
   *  normal storage bytes/string, overwrite-clearing the old tail, byte-identical
   *  to solc). */
  private writeStruct(fields: StructField[], args: Expr[], baseSlot: string, ctx: LowerCtx, out: string[]): void {
    const isConst = /^\d+$/.test(baseSlot);
    const slotAt = (n: number): string => (isConst ? String(Number(baseSlot) + n) : n === 0 ? baseSlot : `add(${baseSlot}, ${n})`);
    fields.forEach((f, i) => {
      const arg = args[i]!;
      if (f.type.kind === 'struct' && arg.kind === 'structNew') {
        this.writeStruct(arg.fields, arg.args, slotAt(f.slot), ctx, out);
      } else if (f.type.kind === 'array' && arg.kind === 'arrayLit') {
        // a fixed-array field constructed from a (possibly nested) literal.
        this.writeArrayLit(arg, slotAt(f.slot), ctx, out);
      } else if (isBytesLike(f.type)) {
        const ref = this.lowerDynamic(arg, ctx, out);
        this.storeDynamic(slotAt(f.slot), ref, out);
      } else {
        const v = this.lowerExpr(arg, ctx, out);
        for (const l of this.storeState(f.type, slotAt(f.slot), f.offset, v)) out.push(l);
      }
    });
  }

  /** Allocate a memory image for a constructed STATIC struct (G9) and return its pointer.
   *  Layout is ABI-unpacked (one word per leaf), so the image doubles as the ABI return blob. */
  private allocAggToMem(value: Expr & { kind: 'structNew' | 'arrayLit' }, ctx: LowerCtx, out: string[]): string {
    const words = abiHeadWords(value.type);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${words * 32}))`);
    this.writeAggToMem(value, ptr, 0, ctx, out);
    return ptr;
  }

  /** Allocate a fresh memory image for a static aggregate and COPY it from a STORAGE source
   *  (G9: `let p: P = this.s`). abiEncFromStorage transcodes the packed storage into the
   *  ABI-unpacked image (one word per leaf), which is exactly the memAggregate layout. */
  private allocAggFromStorage(type: JethType, slot: string, out: string[]): string {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${abiHeadWords(type) * 32}))`);
    this.abiEncFromStorage(type, slot, 0, ptr, out);
    return ptr;
  }

  /** Allocate a fresh memory image for a static aggregate and COPY it from a CALLDATA param
   *  (G9: `let q: P = calldataStructParam`). The param data is inline at its head word;
   *  abiEncFromCd decodes it (validating dirty narrow fields like solc) into the image. */
  private allocAggFromCalldata(param: string, type: JethType, ctx: LowerCtx, out: string[]): string {
    const ph = ctx.cdParamHead.get(param);
    if (!ph) throw new UnsupportedError(`unbound struct-copy param ${param}`);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${abiHeadWords(type) * 32}))`);
    this.abiEncFromCd(type, String(ph.head), ptr, true, out);
    return ptr;
  }

  /** Allocate a memory image for a DYNAMIC-field struct local from a constructor `D(...)`.
   *  Layout = one head word per field: value fields inline, bytes/string fields a pointer to
   *  a freshly-materialized [len][data] blob. This coincides with the ABI tuple head layout,
   *  so `return d` reuses encodeDynStructReturn through a 'mem' TupleSrc. Scoped to value +
   *  bytes/string fields (no static-aggregate or nested-struct fields), so each field is one
   *  head word and field i sits at word i. The head is allocated first (args materialize their
   *  blobs above it); constructor args evaluate left-to-right, matching solc. */
  private allocDynStructToMem(value: Expr & { kind: 'structNew' }, ctx: LowerCtx, out: string[]): string {
    const struct = value.type as JethType & { kind: 'struct' };
    const headWords = tupleHeadWords(struct);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${headWords * 32}))`);
    let hw = 0;
    struct.fields.forEach((f, i) => {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      if (isBytesLike(f.type)) {
        const { mp } = this.toMemory(this.lowerDynamic(value.args[i]!, ctx, out), out);
        out.push(`mstore(${at}, ${mp})`);
        hw += 1;
      } else {
        out.push(`mstore(${at}, ${this.lowerExpr(value.args[i]!, ctx, out)})`);
        hw += abiHeadWords(f.type);
      }
    });
    return ptr;
  }

  /** Build a DYNAMIC-field struct memory local's pointer-headed image from any supported
   *  source: a constructor (fresh), a storage struct (COPY), a calldata struct param (decode
   *  + validate into a fresh image), or another dynamic-struct memory local (ALIAS = pointer
   *  copy, matching Solidity memory references). Returns the head pointer. */
  private buildDynStructLocal(struct: JethType & { kind: 'struct' }, init: Expr, ctx: LowerCtx, out: string[]): string {
    if (init.kind === 'structNew') return this.allocDynStructToMem(init, ctx, out);
    if (init.kind === 'memDynStructValue') return this.ctxLookup(ctx, init.local); // alias
    if (init.kind === 'cdDynStructValue') return this.buildDynStructFromCalldata(struct, init, ctx, out);
    // a storage struct source (structValue / mapStorageValue / structArrayElem / placeRead).
    return this.buildDynStructFromStorage(struct, this.structSrcSlot(init, ctx, out), ctx, out);
  }

  /** Copy a storage dynamic-field struct at `baseSlot` into a fresh memory image: value fields
   *  are read (packed-aware) and stored inline; bytes/string fields are copied to a memory blob
   *  whose pointer is stored in the head word. Scoped to value + bytes/string fields. */
  private buildDynStructFromStorage(struct: JethType & { kind: 'struct' }, baseSlot: string, ctx: LowerCtx, out: string[]): string {
    const headWords = tupleHeadWords(struct);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${headWords * 32}))`);
    const isConst = /^\d+$/.test(baseSlot);
    const slotAt = (n: number): string => (isConst ? String(Number(baseSlot) + n) : n === 0 ? baseSlot : `add(${baseSlot}, ${n})`);
    let hw = 0;
    for (const f of struct.fields) {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      if (isBytesLike(f.type)) {
        const { mp } = this.toMemory({ src: 'storage', slot: slotAt(f.slot) }, out);
        out.push(`mstore(${at}, ${mp})`);
        hw += 1;
      } else {
        out.push(`mstore(${at}, ${this.loadState(f.type, slotAt(f.slot), f.offset)})`);
        hw += abiHeadWords(f.type);
      }
    }
    return ptr;
  }

  /** Decode a calldata dynamic-field struct param into a fresh memory image: value fields are
   *  read + VALIDATED inline (encodeStaticInline 'cd'), bytes/string fields are calldatacopied
   *  to a memory blob whose pointer is stored in the head word. Matches solc's copy-to-memory. */
  private buildDynStructFromCalldata(struct: JethType & { kind: 'struct' }, init: Expr, ctx: LowerCtx, out: string[]): string {
    const src = this.tupleSrc(init, ctx, out); // { kind: 'cd', base }
    const headWords = tupleHeadWords(struct);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${headWords * 32}))`);
    let hw = 0;
    struct.fields.forEach((f, i) => {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      if (isBytesLike(f.type)) {
        const { mp } = this.toMemory(this.dynFieldRef(f, src, i, hw, ctx, out), out);
        out.push(`mstore(${at}, ${mp})`);
        hw += 1;
      } else {
        this.encodeStaticInline(f.type, src, i, hw, at, ctx, out);
        hw += abiHeadWords(f.type);
      }
    });
    return ptr;
  }

  /** Write a constructed static aggregate (structNew / arrayLit, possibly nested) into the
   *  memory image at `ptr`, starting at word `wordBase`. Value leaves are one word each. */
  private writeAggToMem(value: Expr, ptr: string, wordBase: number, ctx: LowerCtx, out: string[]): void {
    const at = (w: number): string => (w === 0 ? ptr : `add(${ptr}, ${w * 32})`);
    if (value.kind === 'structNew') {
      let w = wordBase;
      value.fields.forEach((f, j) => {
        const arg = value.args[j]!;
        if (arg.kind === 'arrayLit' || arg.kind === 'structNew') this.writeAggToMem(arg, ptr, w, ctx, out);
        else out.push(`mstore(${at(w)}, ${this.lowerExpr(arg, ctx, out)})`);
        w += abiHeadWords(f.type);
      });
      return;
    }
    if (value.kind === 'arrayLit') {
      const ew = abiHeadWords(value.elem);
      value.elements.forEach((el, k) => {
        const w = wordBase + k * ew;
        if (el.kind === 'arrayLit' || el.kind === 'structNew') this.writeAggToMem(el, ptr, w, ctx, out);
        else out.push(`mstore(${at(w)}, ${this.lowerExpr(el, ctx, out)})`);
      });
      return;
    }
    throw new UnsupportedError(`cannot write '${value.kind}' into a memory aggregate`);
  }

  /** Write a (possibly NESTED) static fixed-array literal into storage at `baseSlot`.
   *  Value elements use arrayElemStore (handles packing); nested array / struct elements
   *  recurse at baseSlot + k*slotCount(element). */
  private writeArrayLit(lit: Expr & { kind: 'arrayLit' }, baseSlot: string, ctx: LowerCtx, out: string[]): void {
    const elem = lit.elem;
    if (isStaticValueType(elem)) {
      lit.elements.forEach((el, k) => this.arrayElemStore(elem, baseSlot, String(k), this.lowerExpr(el, ctx, out), out));
      return;
    }
    const sc = storageSlotCount(elem);
    const isConst = /^\d+$/.test(baseSlot);
    const slotAt = (n: number): string => (isConst ? String(Number(baseSlot) + n) : n === 0 ? baseSlot : `add(${baseSlot}, ${n})`);
    lit.elements.forEach((el, k) => {
      const es = slotAt(k * sc);
      if (el.kind === 'arrayLit') this.writeArrayLit(el, es, ctx, out);
      else if (el.kind === 'structNew') this.writeStruct(el.fields, el.args, es, ctx, out);
      else throw new UnsupportedError(`array-literal element '${el.kind}' is not constructible`);
    });
  }

  /** Bounds-checked storage slot of a whole STRUCT array element this.recs[i] (a
   *  storage/fixed/mapping-valued struct array). Struct elements are never packed: the
   *  element occupies storageSlotCount(elem) contiguous slots at data + i*slotCount
   *  (dynamic/mapping array) or baseSlot + i*slotCount (fixed array). Panic(0x32) on OOB. */
  private structArrayElemSlot(arr: ArrayExpr, index: Expr, ctx: LowerCtx, out: string[]): string {
    const ref = this.lowerArrayRef(arr, ctx, out);
    const sc = storageSlotCount(arr.elem);
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(index, ctx, out)}`);
    const slot = this.fresh();
    if (ref.src === 'fixed') {
      out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
      out.push(`let ${slot} := add(${ref.baseSlot}, mul(${i}, ${sc}))`);
      return slot;
    }
    if (ref.src === 'storage') {
      out.push(`if iszero(lt(${i}, sload(${ref.lenSlot}))) { ${this.panic()}(0x32) }`);
      const data = this.arrayDataSlot(ref.lenSlot, out);
      out.push(`let ${slot} := add(${data}, mul(${i}, ${sc}))`);
      return slot;
    }
    throw new UnsupportedError('a struct element of a calldata array is not a storage place');
  }

  /** Resolve the length slot of a dynamic-array VALUE source (for a storage-to-storage
   *  array copy): a state array (arrayValue/stateArray), a mapping-valued array
   *  (arrayValue/mapArray or mapStorageValue at the runtime keccak(key.base) slot). */
  private arraySrcLenSlot(value: Expr, ctx: LowerCtx, out: string[]): string {
    if (value.kind === 'arrayValue') {
      if (value.arr.base.kind === 'stateArray') return String(value.arr.base.slot);
      if (value.arr.base.kind === 'mapArray') return this.mappingSlot(value.arr.base.baseSlot, value.arr.base.keys, ctx, out);
      if (value.arr.base.kind === 'placeArray') return this.lowerPlace(value.arr.base.path, ctx, out).slot;
    }
    if (value.kind === 'mapStorageValue') return this.mappingSlot(value.baseSlot, value.keys, ctx, out);
    throw new UnsupportedError(`cannot copy an array from '${value.kind}'`);
  }

  /** Storage-to-storage DEEP copy of a dynamic array from `srcLenSlot` to `dstLenSlot`
   *  (length-slot exprs). Resizes the dest to the source length, copies every element,
   *  and clears the dest's freed tail - byte-identical to solc's array assignment.
   *  - static elements (value packed/unpacked, static struct): copy the contiguous data
   *    slots verbatim (the source's zero-padded last packed slot clears any dest element
   *    that fell beyond the new length), then zero the dest's excess data slots.
   *  - dynamic elements (bytes/string, dynamic struct): per element, storeDynamic /
   *    copyStruct (overwrite-clearing each element's old tail); the freed tail elements
   *    are deep-cleared (clearStr / clearStructDyn + zero inline slots) first. */
  private copyArray(elem: JethType, srcLenSlot: string, dstLenSlot: string, out: string[]): void {
    const srcLen = this.fresh();
    const dstLen = this.fresh();
    out.push(`let ${srcLen} := sload(${srcLenSlot})`);
    out.push(`let ${dstLen} := sload(${dstLenSlot})`);
    const srcData = this.fresh();
    const dstData = this.fresh();
    out.push(`let ${srcData} := ${this.arrayDataSlotHelper()}(${srcLenSlot})`);
    out.push(`let ${dstData} := ${this.arrayDataSlotHelper()}(${dstLenSlot})`);

    if (isStaticType(elem)) {
      const packs = arrayElemPacks(elem);
      const slotsFor = (L: string): string =>
        packs.packed ? `div(add(${L}, ${packs.perSlot - 1}), ${packs.perSlot})` : `mul(${L}, ${storageSlotCount(elem)})`;
      const srcSlots = this.fresh();
      const dstSlots = this.fresh();
      out.push(`let ${srcSlots} := ${slotsFor(srcLen)}`);
      out.push(`let ${dstSlots} := ${slotsFor(dstLen)}`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${srcSlots}) { ${i} := add(${i}, 1) } { sstore(add(${dstData}, ${i}), sload(add(${srcData}, ${i}))) }`);
      const j = this.fresh();
      out.push(`for { let ${j} := ${srcSlots} } lt(${j}, ${dstSlots}) { ${j} := add(${j}, 1) } { sstore(add(${dstData}, ${j}), 0) }`);
      out.push(`sstore(${dstLenSlot}, ${srcLen})`);
      return;
    }

    // dynamic elements: per-element (sc slots each).
    const sc = storageSlotCount(elem);
    const k = this.fresh();
    out.push(`for { let ${k} := ${srcLen} } lt(${k}, ${dstLen}) { ${k} := add(${k}, 1) } {`);
    const clearInner: string[] = [];
    const ceb = this.fresh();
    clearInner.push(`let ${ceb} := add(${dstData}, mul(${k}, ${sc}))`);
    if (isBytesLike(elem)) {
      clearInner.push(`${this.clearStr()}(${ceb})`);
    } else {
      this.clearStructDyn(elem as JethType & { kind: 'struct' }, ceb, clearInner);
      for (let s = 0; s < sc; s++) clearInner.push(`sstore(${s === 0 ? ceb : `add(${ceb}, ${s})`}, 0)`);
    }
    for (const l of clearInner) out.push('  ' + l);
    out.push('}');
    out.push(`sstore(${dstLenSlot}, ${srcLen})`);
    const m = this.fresh();
    out.push(`for { let ${m} := 0 } lt(${m}, ${srcLen}) { ${m} := add(${m}, 1) } {`);
    const copyInner: string[] = [];
    const seb = this.fresh();
    const deb = this.fresh();
    copyInner.push(`let ${seb} := add(${srcData}, mul(${m}, ${sc}))`);
    copyInner.push(`let ${deb} := add(${dstData}, mul(${m}, ${sc}))`);
    if (isBytesLike(elem)) {
      this.storeDynamic(deb, { src: 'storage', slot: seb }, copyInner);
    } else {
      this.copyStruct(elem as JethType & { kind: 'struct' }, seb, deb, copyInner);
    }
    for (const l of copyInner) out.push('  ' + l);
    out.push('}');
  }

  /** Resolve the storage base slot of a struct VALUE source (for a storage-to-storage
   *  copy): a state-var struct (structValue), a whole mapping-value struct
   *  (mapStorageValue at the runtime keccak(key.base) slot), or a whole struct array
   *  element (structArrayElem at data + i*slotCount). */
  private structSrcSlot(value: Expr, ctx: LowerCtx, out: string[]): string {
    if (value.kind === 'structValue') return String(value.baseSlot);
    if (value.kind === 'mapStorageValue') return this.mappingSlot(value.baseSlot, value.keys, ctx, out);
    if (value.kind === 'structArrayElem') return this.structArrayElemSlot(value.arr, value.index, ctx, out);
    if (value.kind === 'placeRead') return this.lowerPlace(value.path, ctx, out).slot;
    throw new UnsupportedError(`cannot copy a struct from '${value.kind}'`);
  }

  /** Storage-to-storage deep copy of a struct value from `srcBase` to `dstBase` (slot
   *  exprs: const-numeric string or register). Static value/fixed-array fields are
   *  copied slot-for-slot (packed slots deduped); each bytes/string field is re-stored
   *  via storeDynamic (reads the source value into memory, overwrite-clears the dst old
   *  tail, repopulates long-data slots), and nested structs recurse. Byte-identical to
   *  solc's field-by-field struct copy. Static and bytes/string fields occupy DISJOINT
   *  slots, so the field order is immaterial: a static slot-copy never clobbers a
   *  dynamic field's header, so storeDynamic always sees the dst's true old length when
   *  clearing (src and dst never alias except a harmless self-copy). */
  private copyStruct(struct: JethType & { kind: 'struct' }, srcBase: string, dstBase: string, out: string[]): void {
    const sConst = /^\d+$/.test(srcBase);
    const dConst = /^\d+$/.test(dstBase);
    const sAt = (n: number): string => (sConst ? String(Number(srcBase) + n) : n === 0 ? srcBase : `add(${srcBase}, ${n})`);
    const dAt = (n: number): string => (dConst ? String(Number(dstBase) + n) : n === 0 ? dstBase : `add(${dstBase}, ${n})`);
    const copied = new Set<number>();
    for (const f of struct.fields) {
      if (f.type.kind === 'struct') {
        this.copyStruct(f.type, sAt(f.slot), dAt(f.slot), out);
      } else if (isBytesLike(f.type)) {
        this.storeDynamic(dAt(f.slot), { src: 'storage', slot: sAt(f.slot) }, out);
      } else {
        const n = storageSlotCount(f.type);
        for (let k = 0; k < n; k++) {
          if (copied.has(f.slot + k)) continue;
          copied.add(f.slot + k);
          out.push(`sstore(${dAt(f.slot + k)}, sload(${sAt(f.slot + k)}))`);
        }
      }
    }
  }

  /** pop a struct element: shrink length, then zero all of the element's slots. For
   *  a DYNAMIC struct element, each bytes/string field is cleared with clearStr
   *  (zeroes the header AND its keccak(headerSlot) long-data slots), then the inline
   *  slots are zeroed too. Matches solc's full per-element delete (verified incl.
   *  raw slots: a long string's data slots are zeroed on pop). */
  private lowerStructPop(arr: ArrayExpr, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('pop on a non-storage array');
    const struct = arr.elem as JethType & { kind: 'struct' };
    const slots = storageSlotCount(struct);
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if iszero(${len}) { ${this.panic()}(0x31) }`);
    const nl = this.fresh();
    out.push(`let ${nl} := sub(${len}, 1)`);
    out.push(`sstore(${ref.lenSlot}, ${nl})`);
    const dataBase = this.fresh();
    out.push(`let ${dataBase} := ${this.arrayDataSlotHelper()}(${ref.lenSlot})`);
    const base = this.fresh();
    out.push(`let ${base} := add(${dataBase}, mul(${nl}, ${slots}))`);
    // A dynamic struct element: free each bytes/string field's long-data slots first
    // (clearStr), in declaration order, before zeroing the inline header slots.
    if (isDynamicType(struct)) {
      this.clearStructDyn(struct, base, out);
    }
    for (let j = 0; j < slots; j++) out.push(`sstore(${j === 0 ? base : `add(${base}, ${j})`}, 0)`);
  }

  /** Recursively clear the long-data slots of every bytes/string field of a dynamic
   *  struct rooted at storage slot expr `base` (a constant-numeric string or a
   *  register). Only the keccak(headerSlot) data slots are freed here; the inline
   *  header/static slots are zeroed by the caller's contiguous-slot loop. Nested
   *  dynamic structs recurse at their field slot offset. */
  private clearStructDyn(struct: JethType & { kind: 'struct' }, base: string, out: string[]): void {
    const isConst = /^\d+$/.test(base);
    const slotAt = (n: number): string => (isConst ? String(Number(base) + n) : n === 0 ? base : `add(${base}, ${n})`);
    for (const f of struct.fields) {
      if (isBytesLike(f.type)) {
        out.push(`${this.clearStr()}(${slotAt(f.slot)})`);
      } else if (f.type.kind === 'struct' && isDynamicType(f.type)) {
        this.clearStructDyn(f.type, slotAt(f.slot), out);
      }
    }
  }

  /** `delete <storage location>`: reset to the type's zero value, matching solc. VALUE
   *  targets are lowered as `= 0` by the analyzer; this handles bytes/string (clearStr),
   *  struct/array (recursive footprint clear), and a whole mapping (no-op). */
  private lowerDelete(target: LValue, ctx: LowerCtx, out: string[]): void {
    switch (target.kind) {
      case 'dynState':
        out.push(`${this.clearStr()}(${target.slot})`);
        return;
      case 'mapDynState':
        out.push(`${this.clearStr()}(${this.mappingSlot(target.baseSlot, target.keys, ctx, out)})`);
        return;
      case 'strArrayElem':
        out.push(`${this.clearStr()}(${this.strArrayElemSlot(target.arr, target.index, ctx, out)})`);
        return;
      case 'dynPlace':
        out.push(`${this.clearStr()}(${this.lowerPlace(target.path, ctx, out).slot})`);
        return;
      case 'state':
        if (target.type.kind === 'mapping') return; // delete on a whole mapping is a no-op
        this.deleteAgg(target.type, String(target.slot), out);
        return;
      case 'mapping':
        this.deleteAgg(target.type, this.mappingSlot(target.baseSlot, target.keys, ctx, out), out);
        return;
      case 'place':
        if (target.type.kind === 'mapping') return;
        this.deleteAgg(target.type, this.lowerPlace(target.path, ctx, out).slot, out);
        return;
      case 'arrayElem':
        this.deleteAgg(target.type, this.structArrayElemSlot(target.arr, target.index, ctx, out), out);
        return;
      default:
        throw new UnsupportedError(`delete of '${target.kind}' is not supported`);
    }
  }

  /** Recursively clear a storage aggregate's footprint to zero (delete semantics). */
  private deleteAgg(type: JethType, slot: string, out: string[]): void {
    if (isBytesLike(type)) {
      out.push(`${this.clearStr()}(${slot})`);
      return;
    }
    if (type.kind === 'mapping') return; // mappings are not cleared by delete
    if (type.kind === 'array') {
      if (type.length === undefined) this.deleteDynArray(type.element, slot, out);
      else this.deleteFixedArray(type, slot, out);
      return;
    }
    if (type.kind === 'struct') {
      this.deleteStruct(type, slot, out);
      return;
    }
    out.push(`sstore(${slot}, 0)`); // whole-slot value fallback
  }

  /** Clear a storage struct: zero each value field (packed-aware), clear bytes/string and
   *  nested struct/array fields, and SKIP mapping fields (solc's delete leaves mappings). */
  private deleteStruct(struct: JethType & { kind: 'struct' }, base: string, out: string[]): void {
    const isConst = /^\d+$/.test(base);
    const at = (n: number): string => (isConst ? String(Number(base) + n) : n === 0 ? base : `add(${base}, ${n})`);
    for (const f of struct.fields) {
      if (f.type.kind === 'mapping') continue;
      if (isBytesLike(f.type)) out.push(`${this.clearStr()}(${at(f.slot)})`);
      else if (f.type.kind === 'struct' || f.type.kind === 'array') this.deleteAgg(f.type, at(f.slot), out);
      else for (const l of this.storeState(f.type, at(f.slot), f.offset, '0')) out.push(l);
    }
  }

  /** Clear a fixed array Arr<T,N>: a static VALUE / value-array element zeroes the whole
   *  (packed) footprint; struct / bytes-string / dynamic elements clear per element. */
  private deleteFixedArray(arrType: JethType & { kind: 'array' }, base: string, out: string[]): void {
    const elem = arrType.element;
    const N = arrType.length!;
    const isConst = /^\d+$/.test(base);
    const at = (n: number): string => (isConst ? String(Number(base) + n) : n === 0 ? base : `add(${base}, ${n})`);
    if (isStaticType(elem) && elem.kind !== 'struct') {
      const packs = arrayElemPacks(elem);
      const slots = packs.packed ? Math.ceil(N / packs.perSlot) : N * storageSlotCount(elem);
      for (let i = 0; i < slots; i++) out.push(`sstore(${at(i)}, 0)`);
      return;
    }
    const sc = storageSlotCount(elem);
    for (let i = 0; i < N; i++) this.deleteAgg(elem, at(i * sc), out);
  }

  /** Clear a dynamic array T[]: free/zero every element's slots then set length 0. Mirrors
   *  copyArray's shrink-to-zero (static value elements zero the used data slots; struct /
   *  bytes-string / nested-array elements recurse per element). */
  private deleteDynArray(elem: JethType, lenSlot: string, out: string[]): void {
    const len = this.fresh();
    out.push(`let ${len} := sload(${lenSlot})`);
    const data = this.fresh();
    out.push(`let ${data} := ${this.arrayDataSlotHelper()}(${lenSlot})`);
    if (isStaticType(elem) && elem.kind !== 'struct') {
      const packs = arrayElemPacks(elem);
      const slots = this.fresh();
      out.push(`let ${slots} := ${packs.packed ? `div(add(${len}, ${packs.perSlot - 1}), ${packs.perSlot})` : `mul(${len}, ${storageSlotCount(elem)})`}`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${slots}) { ${i} := add(${i}, 1) } { sstore(add(${data}, ${i}), 0) }`);
    } else {
      const sc = storageSlotCount(elem);
      const k = this.fresh();
      out.push(`for { let ${k} := 0 } lt(${k}, ${len}) { ${k} := add(${k}, 1) } {`);
      const inner: string[] = [];
      const eb = this.fresh();
      inner.push(`let ${eb} := add(${data}, mul(${k}, ${sc}))`);
      this.deleteAgg(elem, eb, inner);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
    }
    out.push(`sstore(${lenSlot}, 0)`);
  }

  // ---- storage / mapping-valued string[] / bytes[] (element = a storage bytes/
  // string at header slot keccak(lenSlot)+i; reuse the storage bytes/string codec)

  /** push a bytes/string element: grow the length word (Panic 0x41 past 2^64-1),
   *  then write the element header at keccak(lenSlot)+old_len via storeStrMem (short
   *  inline / long with keccak(headerSlot) data slots). A no-value push leaves the
   *  freed slot zero (an empty string = the 0 length word), so it is a no-op write. */
  private lowerStrPush(arr: ArrayExpr, value: Expr | undefined, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('push on a non-storage array');
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    out.push(`sstore(${ref.lenSlot}, add(${len}, 1))`);
    const dataBase = this.arrayDataSlot(ref.lenSlot, out);
    const hdr = this.fresh();
    out.push(`let ${hdr} := add(${dataBase}, ${len})`);
    if (value) {
      const vref = this.lowerDynamic(value, ctx, out);
      this.storeDynamic(hdr, vref, out); // header slot was zero (grown fresh), no old tail to clear
    }
    // push() with no value: the element is the storage default (empty), already 0.
  }

  /** pop a bytes/string element: shrink the length word (Panic 0x31 if empty), then
   *  clear the freed element's header AND its tail data slots (a long element's
   *  keccak(headerSlot) data slots), matching solc's full clear. storeStrMem with
   *  len 0 sets the header to the 0 length word and zeroes the old data slots. */
  private lowerStrPop(arr: ArrayExpr, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('pop on a non-storage array');
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if iszero(${len}) { ${this.panic()}(0x31) }`);
    const nl = this.fresh();
    out.push(`let ${nl} := sub(${len}, 1)`);
    out.push(`sstore(${ref.lenSlot}, ${nl})`);
    const dataBase = this.arrayDataSlot(ref.lenSlot, out);
    const hdr = this.fresh();
    out.push(`let ${hdr} := add(${dataBase}, ${nl})`);
    out.push(`${this.clearStr()}(${hdr})`);
  }

  /** Storage header slot of bytes/string element `i` of a storage string[]/bytes[].
   *  Bounds-checks i against the array length (Panic 0x32), then returns
   *  keccak(lenSlot)+i. The header is a normal storage bytes/string. */
  private strArrayElemSlot(arr: ArrayExpr, index: Expr, ctx: LowerCtx, out: string[]): string {
    const ref = this.lowerArrayRef(arr, ctx, out);
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(index, ctx, out)}`);
    // Arr<string,N>/Arr<bytes,N> (fixed): N contiguous string headers at baseSlot + i.
    if (ref.src === 'fixed') {
      out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
      const hdr = this.fresh();
      out.push(`let ${hdr} := add(${ref.baseSlot}, ${i})`);
      return hdr;
    }
    if (ref.src !== 'storage') throw new UnsupportedError('string[]/bytes[] element requires a storage array');
    out.push(`if iszero(lt(${i}, sload(${ref.lenSlot}))) { ${this.panic()}(0x32) }`);
    const dataBase = this.arrayDataSlot(ref.lenSlot, out);
    const hdr = this.fresh();
    out.push(`let ${hdr} := add(${dataBase}, ${i})`);
    return hdr;
  }

  /** ABI-encode a MEMORY value-array at pointer `mp` (=[len][data]) as [0x20][len][data]. */
  private encodeMemArrayReturn(mp: string, out: string[]): { ptr: string; size: string } {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`);
    const total = this.fresh();
    out.push(`let ${total} := mul(add(mload(${mp}), 1), 0x20)`);
    out.push(`mcopy(add(${ptr}, 0x20), ${mp}, ${total})`);
    out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${total}))`);
    return { ptr, size: `add(0x20, ${total})` };
  }

  /** Encode an arrayValue/arrayLit as ABI [0x20][len][elem words...] in memory. */
  private encodeArrayReturn(value: Expr, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    if (value.kind === 'arrayLit') {
      const ws = value.elements.map((el) => this.lowerExpr(el, ctx, out));
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(${ptr}, 0x20)`, `mstore(add(${ptr}, 0x20), ${ws.length})`);
      ws.forEach((w, j) => out.push(`mstore(add(${ptr}, ${0x40 + j * 32}), ${w})`));
      out.push(`mstore(0x40, add(${ptr}, ${0x40 + ws.length * 32}))`);
      return { ptr, size: String(0x40 + ws.length * 32) };
    }
    if (value.kind !== 'arrayValue') throw new UnsupportedError(`cannot encode array from ${value.kind}`);
    // a MEMORY T[] (value elements) at ptr=[len][data]: ABI return = [0x20][len][data].
    if (value.arr.base.kind === 'memArray') {
      return this.encodeMemArrayReturn(this.ctxLookup(ctx, value.arr.base.varName), out);
    }
    const ref = this.lowerArrayRef(value.arr, ctx, out);
    if (ref.src === 'fixed') throw new UnsupportedError('returning a whole fixed array is not supported yet');
    if (ref.src === 'memory') throw new UnsupportedError('memory array return is handled earlier');
    // string[] / bytes[] (array of dynamic elements): re-encode each element as a
    // [byteLen][right-padded data] payload behind a per-element offset table whose
    // base is the table start (spec section 4.1). Only the calldata-source path is
    // reachable (the analyzer gates storage/mapping string[] elements).
    if (isBytesLike(ref.elem)) {
      if (ref.src !== 'calldata') throw new UnsupportedError('returning a string[]/bytes[] is only supported from a calldata source');
      return this.encodeDynArrayReturn(ref.offset, ref.length, ctx, out);
    }
    // Nested dynamic array T[][] (4e-5): re-encode each inner array as a [innerLen]
    // [elements] tail behind a per-inner pointer table whose base is the pointer-region
    // start (spec section 2.1). Only the calldata-source path is reachable.
    if (ref.elem.kind === 'array' && ref.elem.length === undefined) {
      if (ref.src !== 'calldata') throw new UnsupportedError('returning a nested dynamic array is only supported from a calldata source');
      return this.encodeNestedArrayReturn(ref.offset, ref.length, ref.elem.element, ctx, out);
    }
    const len = this.fresh();
    out.push(`let ${len} := ${ref.src === 'storage' ? `sload(${ref.lenSlot})` : ref.length}`);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`, `mstore(add(${ptr}, 0x20), ${len})`);
    const e = this.fresh();
    out.push(`let ${e} := add(${ptr}, 0x40)`);
    const i = this.fresh();
    const inner: string[] = [];
    let stride: string;
    if (ref.src === 'storage') {
      const data = this.arrayDataSlot(ref.lenSlot, out);
      if (ref.elem.kind === 'struct') {
        // transcode each packed storage struct element to its unpacked ABI words.
        const sw = abiHeadWords(ref.elem) * 32;
        const sc = storageSlotCount(ref.elem);
        stride = String(sw);
        const eb = this.fresh();
        inner.push(`let ${eb} := add(${data}, mul(${i}, ${sc}))`);
        for (const leaf of structStorageLeaves(ref.elem)) {
          const slotExpr = leaf.storageSlot === 0 ? eb : `add(${eb}, ${leaf.storageSlot})`;
          const w = this.loadState(leaf.type, slotExpr, leaf.storageOffset);
          const dst = leaf.abiWord === 0 ? `mul(${i}, ${sw})` : `add(mul(${i}, ${sw}), ${leaf.abiWord * 32})`;
          inner.push(`mstore(add(${e}, ${dst}), ${w})`);
        }
      } else {
        // value element: one ABI word per element (unpacked by arrayElemLoad).
        stride = '32';
        inner.push(`mstore(add(${e}, mul(${i}, 32)), ${this.arrayElemLoad(ref.elem, data, i)})`);
      }
    } else {
      // calldata source. A VALUE-element whole-array copy CLEANS each element (does
      // NOT revert on dirty bits), unlike a single x[i] read (Bug-A behavior). A
      // STRUCT-element copy instead reads every field, so it VALIDATES each leaf
      // (revert empty on dirty), matching solc - it never cleans struct fields.
      const sw = abiHeadWords(ref.elem) * 32;
      stride = String(sw);
      const elemIsStruct = ref.elem.kind === 'struct';
      for (const leaf of abiLeaves(ref.elem)) {
        const disp = leaf.wordOffset * 32;
        const at = disp === 0 ? `mul(${i}, ${sw})` : `add(mul(${i}, ${sw}), ${disp})`;
        const w = this.fresh();
        inner.push(`let ${w} := calldataload(add(${ref.offset}, ${at}))`);
        if (elemIsStruct) {
          const guard = this.validateInput(leaf.type, w);
          if (guard) inner.push(guard);
          inner.push(`mstore(add(${e}, ${at}), ${w})`);
        } else {
          inner.push(`mstore(add(${e}, ${at}), ${this.cleanCalldataElem(leaf.type, w)})`);
        }
      }
    }
    out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
    for (const l of inner) out.push('  ' + l);
    out.push('}');
    out.push(`mstore(0x40, add(${e}, mul(${len}, ${stride})))`);
    return { ptr, size: `add(0x40, mul(${len}, ${stride}))` };
  }

  /** Re-encode a calldata string[]/bytes[] (table start `tableStart`, element count
   *  `len`) into memory as the ABI return blob: [0x20][len][offset table][payloads].
   *  Each payload is [byteLen][right-padded data]; the offset table base is the table
   *  start (spec section 4.1). Element bounds are validated per element on decode.
   *  The total byte size is computed at runtime (variable payload lengths). */
  private encodeDynArrayReturn(tableStart: string, len: string, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`); // outer offset
    const region = this.fresh();
    out.push(`let ${region} := add(${ptr}, 0x20)`); // array data region start
    out.push(`mstore(${region}, ${len})`); // element count
    const table = this.fresh();
    out.push(`let ${table} := add(${region}, 0x20)`); // output offset-table start (= base)
    // payload cursor starts right after the L offset-table words.
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${table}, mul(${len}, 0x20))`);
    const i = this.fresh();
    out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
    const inner: string[] = [];
    const dataPtr = this.fresh();
    const elen = this.fresh();
    inner.push(`let ${dataPtr}, ${elen} := ${this.calldataDynElemEcho()}(${tableStart}, ${i})`);
    // offset of this element's payload relative to the output table start.
    inner.push(`mstore(add(${table}, mul(${i}, 0x20)), sub(${cursor}, ${table}))`);
    // DECODE-TO-MEMORY ECHO alloc bound (rule 3): a byte payload first caps the length
    // at 2^64-1 (Panic 0x41, so roundup32 cannot wrap), then the new free pointer
    // (cursor past this payload) crossing 2^64-1 (or wrapping) -> Panic(0x41); THEN the
    // payload must lie within calldatasize (else EMPTY). All precede the copy/store.
    inner.push(`if gt(${elen}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    const pad = `and(add(${elen}, 0x1f), not(0x1f))`;
    const nc = this.fresh();
    inner.push(`let ${nc} := add(${cursor}, add(0x20, ${pad}))`);
    inner.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
    inner.push(`if gt(add(${dataPtr}, ${elen}), calldatasize()) { revert(0, 0) }`);
    inner.push(`mstore(${cursor}, ${elen})`); // byte length word
    // copy payload then zero the partial-word tail so padding is clean.
    inner.push(`calldatacopy(add(${cursor}, 0x20), ${dataPtr}, ${elen})`);
    inner.push(`if mod(${elen}, 0x20) { mstore(add(add(${cursor}, 0x20), ${elen}), 0) }`);
    inner.push(`${cursor} := ${nc}`);
    for (const l of inner) out.push('  ' + l);
    out.push('}');
    out.push(`mstore(0x40, ${cursor})`); // bump free-mem pointer past the blob
    return { ptr, size: `sub(${cursor}, ${ptr})` };
  }

  /** Re-encode a calldata nested dynamic array T[][] (pointer-region start `base`,
   *  outer count `len`, value element `elemType`) into memory as the ABI return blob:
   *  [0x20][outerLen][pointer table][inner tails]. Each inner tail is [innerLen][elem
   *  words...]; the pointer offsets are relative to the output pointer-region start
   *  (= the output table start), spec section 2.1. Each value element is CLEANED into
   *  its in-register form on copy (does not revert on dirty bits), matching solc's
   *  array-copy semantics for value elements. Inner bounds / pointer faults -> EMPTY
   *  revert inside calldataInnerArray. Total byte size is computed at runtime. */
  private encodeNestedArrayReturn(base: string, len: string, elemType: JethType, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    const stride = abiHeadWords(elemType) * 32; // value element stride (32)
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`); // outer offset
    const region = this.fresh();
    out.push(`let ${region} := add(${ptr}, 0x20)`); // outer data region start
    out.push(`mstore(${region}, ${len})`); // outer element count
    const table = this.fresh();
    out.push(`let ${table} := add(${region}, 0x20)`); // output pointer-region start (= base)
    // inner-tail cursor starts right after the L pointer words.
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${table}, mul(${len}, 0x20))`);
    const i = this.fresh();
    out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
    const inner: string[] = [];
    const dataOff = this.fresh();
    const innerLen = this.fresh();
    inner.push(`let ${dataOff}, ${innerLen} := ${this.calldataInnerArrayEcho()}(${base}, ${i})`);
    // pointer to this inner array, relative to the output table start.
    inner.push(`mstore(add(${table}, mul(${i}, 0x20)), sub(${cursor}, ${table}))`);
    // DECODE-TO-MEMORY ECHO alloc bound (rule 3): a memory value-array first caps the
    // element count at 2^64-1 (Panic 0x41), then the new free pointer (cursor past this
    // inner tail) crossing 2^64-1 (or wrapping) -> Panic(0x41). Both precede any element
    // read/validation, matching solc's allocate-then-decode ordering.
    inner.push(`if gt(${innerLen}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    const nc = this.fresh();
    inner.push(`let ${nc} := add(${cursor}, add(0x20, mul(${innerLen}, 0x20)))`);
    inner.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
    // payload-fits (after the alloc Panic, EMPTY): the innerLen element words must lie
    // within calldatasize, else solc's memory decode reverts EMPTY (measured).
    inner.push(`if gt(add(${dataOff}, mul(${innerLen}, ${stride})), calldatasize()) { revert(0, 0) }`);
    inner.push(`mstore(${cursor}, ${innerLen})`); // inner length word
    // copy each inner element, cleaned into in-register form.
    const j = this.fresh();
    const ew = this.fresh();
    inner.push(`for { let ${j} := 0 } lt(${j}, ${innerLen}) { ${j} := add(${j}, 1) } {`);
    inner.push(`  let ${ew} := calldataload(add(${dataOff}, mul(${j}, ${stride})))`);
    // solc fully decodes each inner array and VALIDATES every element (a dirty
    // narrow value reverts EMPTY), unlike a flat value-array bulk copy which cleans.
    const guard = this.validateInput(elemType, ew);
    if (guard) inner.push(`  ${guard}`);
    inner.push(`  mstore(add(add(${cursor}, 0x20), mul(${j}, 0x20)), ${ew})`);
    inner.push(`}`);
    inner.push(`${cursor} := ${nc}`);
    for (const l of inner) out.push('  ' + l);
    out.push('}');
    out.push(`mstore(0x40, ${cursor})`); // bump free-mem pointer past the blob
    return { ptr, size: `sub(${cursor}, ${ptr})` };
  }

  /** Echo a whole calldata PARAM `name` of dynamic type `t` into a fresh ABI return
   *  blob: [0x20][value encoding]. The general recursive encoder gives UNBOUNDED
   *  nesting depth. The top-level offset is signed-range-checked (solc form). */
  private echoParam(name: string, t: JethType, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    const ph = ctx.cdParamHead.get(name);
    if (!ph) throw new UnsupportedError(`unbound echo param ${name}`);
    const off = this.fresh();
    out.push(`let ${off} := calldataload(${ph.head})`);
    out.push(`if iszero(slt(${off}, sub(sub(calldatasize(), 4), 0x1f))) { revert(0, 0) }`);
    const cdPtr = this.fresh();
    out.push(`let ${cdPtr} := add(4, ${off})`); // the value's data (length word / tuple start)
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`);
    // a flat top-level value array cleans its elements (Bug A); everything else validates.
    const topClean = t.kind === 'array' && t.length === undefined && isStaticValueType(t.element);
    const size = this.abiEncFromCd(t, cdPtr, `add(${ptr}, 0x20)`, !topClean, out);
    out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
    return { ptr, size: `add(0x20, ${size})` };
  }

  /** Materialize a DYNAMIC-array argument (G3, for @error/@event head/tail) into a memory blob
   *  holding its ABI tail encoding `[len][elements...]`, returning a frozen pointer + byte size.
   *  Calldata-param arrays reuse echoParam (unbounded element nesting); value-element memory
   *  arrays are already in ABI tail layout. Other sources are gated. */
  private materializeArrayArg(arg: Expr, ctx: LowerCtx, out: string[]): { mp: string; size: string } {
    if (arg.kind !== 'arrayValue') throw new UnsupportedError(`array argument must be an array value, got '${arg.kind}'`);
    const base = arg.arr.base;
    let mpExpr: string;
    let sizeExpr: string;
    if (base.kind === 'calldataArray') {
      const { ptr, size } = this.echoParam(base.name, arg.type, ctx, out);
      mpExpr = `add(${ptr}, 0x20)`; // skip the single-value [0x20] offset wrapper
      sizeExpr = `sub(${size}, 0x20)`;
    } else if (base.kind === 'memArray') {
      mpExpr = this.ctxLookup(ctx, base.varName);
      sizeExpr = `mul(add(mload(${mpExpr}), 1), 0x20)`; // [len][e0..] value elements
    } else if (base.kind === 'memArrayExpr') {
      mpExpr = this.lowerExpr(base.expr, ctx, out);
      sizeExpr = `mul(add(mload(${mpExpr}), 1), 0x20)`;
    } else {
      throw new UnsupportedError(`a dynamic-array @error/@event argument from a '${base.kind}' source is not supported yet`);
    }
    const mp = this.fresh();
    out.push(`let ${mp} := ${mpExpr}`);
    const size = this.fresh();
    out.push(`let ${size} := ${sizeExpr}`);
    return { mp, size };
  }

  /** Echo a whole STATIC struct / fixed-array calldata param (G5). The data is INLINE at the
   *  param head (no offset word) and the return is flat (no 0x20 wrapper, since static types
   *  are returned inline). Matching solc's decode-to-memory: a pure VALUE-leaf fixed array
   *  CLEANS (masks) its leaves, while a struct (or struct-element array) VALIDATES its fields
   *  (the struct branch of abiEncFromCd forces field validation regardless of this flag). */
  private echoStaticParam(name: string, t: JethType, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    const ph = ctx.cdParamHead.get(name);
    if (!ph) throw new UnsupportedError(`unbound echo param ${name}`);
    const leaf = (ty: JethType): JethType => (ty.kind === 'array' && ty.length !== undefined ? leaf(ty.element) : ty);
    const validate = !(t.kind === 'array' && isStaticValueType(leaf(t)));
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    const size = this.abiEncFromCd(t, String(ph.head), ptr, validate, out);
    out.push(`mstore(0x40, add(${ptr}, ${size}))`);
    return { ptr, size };
  }

  /** Recursively re-encode a calldata value of type `t` (DATA at calldata byte
   *  `cdPtr`) into a fresh ABI blob at memory `dst`. Returns a Yul expr for the byte
   *  size written. Compile-time recursion over `t` => UNBOUNDED nesting depth; array
   *  lengths drive runtime loops. Inner offsets use solc's signed slt + modular wrap;
   *  oversized payloads Panic(0x41) then EMPTY-revert on calldata overrun. `validate`:
   *  value leaves revert on dirty bits (nested/struct decode) vs clean (flat value
   *  array). */
  private abiEncFromCd(t: JethType, cdPtr: string, dst: string, validate: boolean, out: string[]): string {
    // a single value leaf
    if (isStaticValueType(t)) {
      const w = this.fresh();
      out.push(`let ${w} := calldataload(${cdPtr})`);
      if (validate) {
        const g = this.validateInput(t, w);
        if (g) out.push(g);
        out.push(`mstore(${dst}, ${w})`);
      } else {
        out.push(`mstore(${dst}, ${this.cleanCalldataElem(t, w)})`);
      }
      return '32';
    }
    // a static aggregate (struct or fixed array of static): copy each leaf word. With
    // `validate`, dirty narrow leaves revert (struct-field / nested decode); without, they
    // are cleaned/masked (a whole value-leaf fixed-array echo, matching solc decode-to-memory).
    if (isStaticType(t)) {
      for (const leaf of abiLeaves(t)) {
        const w = this.fresh();
        out.push(`let ${w} := calldataload(add(${cdPtr}, ${leaf.wordOffset * 32}))`);
        if (validate) {
          const g = this.validateInput(leaf.type, w);
          if (g) out.push(g);
          out.push(`mstore(add(${dst}, ${leaf.wordOffset * 32}), ${w})`);
        } else {
          out.push(`mstore(add(${dst}, ${leaf.wordOffset * 32}), ${this.cleanCalldataElem(leaf.type, w)})`);
        }
      }
      return String(abiHeadWords(t) * 32);
    }
    // bytes / string: [len][right-padded data]
    if (isBytesLike(t)) {
      const len = this.fresh();
      out.push(`let ${len} := calldataload(${cdPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
      const padded = this.fresh();
      out.push(`let ${padded} := and(add(${len}, 0x1f), not(0x1f))`);
      const nc = this.fresh();
      out.push(`let ${nc} := add(add(${dst}, 0x20), ${padded})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${dst})) { ${this.panic()}(0x41) }`);
      out.push(`if gt(add(add(${cdPtr}, 0x20), ${len}), calldatasize()) { revert(0, 0) }`);
      out.push(`mstore(${dst}, ${len})`);
      out.push(`calldatacopy(add(${dst}, 0x20), add(${cdPtr}, 0x20), ${len})`);
      out.push(`if mod(${len}, 0x20) { mstore(add(add(${dst}, 0x20), ${len}), 0) }`);
      return `add(0x20, ${padded})`;
    }
    // dynamic array T[]: [len][ static elements inline | dynamic elements head+tail ]
    if (t.kind === 'array' && t.length === undefined) {
      const len = this.fresh();
      out.push(`let ${len} := calldataload(${cdPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
      out.push(`mstore(${dst}, ${len})`);
      const elemRegion = this.fresh();
      out.push(`let ${elemRegion} := add(${cdPtr}, 0x20)`);
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${dst}, 0x20)`);
      if (isStaticType(t.element)) {
        const es = abiHeadWords(t.element) * 32;
        const nc = this.fresh();
        out.push(`let ${nc} := add(${dstHead}, mul(${len}, ${es}))`);
        out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${dstHead})) { ${this.panic()}(0x41) }`);
        out.push(`if gt(add(${elemRegion}, mul(${len}, ${es})), calldatasize()) { revert(0, 0) }`);
        const elemValidate = validate || !isStaticValueType(t.element);
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        const ecd = this.fresh();
        inner.push(`let ${ecd} := add(${elemRegion}, mul(${i}, ${es}))`);
        const edst = this.fresh();
        inner.push(`let ${edst} := add(${dstHead}, mul(${i}, ${es}))`);
        this.abiEncFromCd(t.element, ecd, edst, elemValidate, inner);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return `add(0x20, mul(${len}, ${es}))`;
      }
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dstHead}, mul(${len}, 0x20))`);
      out.push(`if or(gt(${cursor}, 0xffffffffffffffff), lt(${cursor}, ${dstHead})) { ${this.panic()}(0x41) }`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const so = this.fresh();
      inner.push(`let ${so} := calldataload(add(${elemRegion}, mul(${i}, 0x20)))`);
      // ECHO (whole-aggregate decode-to-memory) uses solc's UNSIGNED 2^64 cap + a
      // length-word-readable check, NOT the lazy-access signed wrap.
      inner.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
      const se = this.fresh();
      inner.push(`let ${se} := add(${elemRegion}, ${so})`);
      inner.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), calldatasize()) { revert(0, 0) }`);
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), sub(${cursor}, ${dstHead}))`);
      const sz = this.abiEncFromCd(t.element, se, cursor, true, inner);
      inner.push(`${cursor} := add(${cursor}, ${sz})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return `sub(${cursor}, ${dst})`;
    }
    // fixed array of dynamic element Arr<dyn,N>: an N-word offset table (no length), base = dst/cdPtr
    if (t.kind === 'array' && t.length !== undefined) {
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${t.length * 32})`);
      for (let k = 0; k < t.length; k++) {
        const so = this.fresh();
        out.push(`let ${so} := calldataload(add(${cdPtr}, ${k * 32}))`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${cdPtr}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), calldatasize()) { revert(0, 0) }`);
        out.push(`mstore(add(${dst}, ${k * 32}), sub(${cursor}, ${dst}))`);
        const sz = this.abiEncFromCd(t.element, se, cursor, true, out);
        out.push(`${cursor} := add(${cursor}, ${sz})`);
      }
      return `sub(${cursor}, ${dst})`;
    }
    // dynamic struct (tuple with >=1 dynamic field): head (static inline / dynamic offset) + tails
    if (t.kind === 'struct') {
      const headWords = tupleHeadWords(t);
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${headWords * 32})`);
      let hw = 0;
      for (const f of t.fields) {
        const fb = hw * 32;
        if (!isDynamicType(f.type)) {
          this.abiEncFromCd(f.type, `add(${cdPtr}, ${fb})`, `add(${dst}, ${fb})`, true, out);
          hw += abiHeadWords(f.type);
        } else {
          const so = this.fresh();
          out.push(`let ${so} := calldataload(add(${cdPtr}, ${fb}))`);
          out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
          const se = this.fresh();
          out.push(`let ${se} := add(${cdPtr}, ${so})`);
          out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), calldatasize()) { revert(0, 0) }`);
          out.push(`mstore(add(${dst}, ${fb}), sub(${cursor}, ${dst}))`);
          const sz = this.abiEncFromCd(f.type, se, cursor, true, out);
          out.push(`${cursor} := add(${cursor}, ${sz})`);
          hw += 1;
        }
      }
      return `sub(${cursor}, ${dst})`;
    }
    throw new UnsupportedError(`abiEncFromCd: unsupported type '${t.kind}'`);
  }

  /** Echo a whole STORAGE state variable of dynamic type `t` (base storage slot
   *  `slot`) into a fresh ABI return blob [0x20][value encoding]. The storage-source
   *  twin of echoParam; UNBOUNDED nesting via abiEncFromStorage recursion. */
  private echoStorage(slot: number, t: JethType, out: string[]): { ptr: string; size: string } {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`);
    const size = this.abiEncFromStorage(t, String(slot), 0, `add(${ptr}, 0x20)`, out);
    out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
    return { ptr, size: `add(0x20, ${size})` };
  }

  /** ABI-encode a value of type `t` read from a RUNTIME storage `slotExpr` as a full
   *  return blob: a dynamic value gets the `[0x20][encoding]` wrapper, a static
   *  value/struct/fixed-array is written flat. Used for `return this.m[k]` (whole
   *  mapping value), where the slot is the runtime keccak(key . base). */
  private returnStorageValue(slotExpr: string, t: JethType, out: string[]): { ptr: string; size: string } {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    const total = this.fresh();
    if (isDynamicType(t)) {
      out.push(`mstore(${ptr}, 0x20)`);
      const size = this.abiEncFromStorage(t, slotExpr, 0, `add(${ptr}, 0x20)`, out);
      out.push(`let ${total} := add(0x20, ${size})`);
    } else {
      const size = this.abiEncFromStorage(t, slotExpr, 0, ptr, out);
      out.push(`let ${total} := ${size}`);
    }
    out.push(`mstore(0x40, add(${ptr}, ${total}))`);
    return { ptr, size: total };
  }

  /** Recursively encode a value of type `t` read from STORAGE (base slot `slot`, byte
   *  `offset` within the slot for a packed value) into a fresh ABI blob at memory
   *  `dst`. Returns a Yul size expr. Compile-time recursion over `t` => unbounded
   *  nesting; runtime loops for array lengths. The storage-source twin of abiEncFromCd
   *  (storage values are already canonical, so no dirty-bit validation is needed). */
  private abiEncFromStorage(t: JethType, slot: string, offset: number, dst: string, out: string[]): string {
    if (isStaticValueType(t)) {
      out.push(`mstore(${dst}, ${this.loadState(t, slot, offset)})`);
      return '32';
    }
    if (isStaticType(t)) {
      // static struct / fixed array of static: copy each leaf from its storage slot.
      for (const leaf of structStorageLeaves(t)) {
        const ls = leaf.storageSlot === 0 ? slot : `add(${slot}, ${leaf.storageSlot})`;
        out.push(`mstore(add(${dst}, ${leaf.abiWord * 32}), ${this.loadState(leaf.type, ls, leaf.storageOffset)})`);
      }
      return String(abiHeadWords(t) * 32);
    }
    if (isBytesLike(t)) {
      // copy the storage bytes/string DIRECTLY to dst (no temp allocation, which
      // would clobber the output blob being built at the free pointer).
      const sz = this.fresh();
      out.push(`let ${sz} := ${this.copyStrToMem()}(${slot}, ${dst})`);
      return sz;
    }
    if (t.kind === 'array' && t.length === undefined) {
      const len = this.fresh();
      out.push(`let ${len} := sload(${slot})`);
      out.push(`mstore(${dst}, ${len})`);
      const dataSlot = this.fresh();
      out.push(`let ${dataSlot} := ${this.arrayDataSlotHelper()}(${slot})`);
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${dst}, 0x20)`);
      const elem = t.element;
      if (isStaticType(elem)) {
        const es = abiHeadWords(elem) * 32;
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        if (isStaticValueType(elem)) {
          inner.push(`mstore(add(${dstHead}, mul(${i}, ${es})), ${this.arrayElemLoad(elem, dataSlot, i)})`);
        } else {
          const eb = this.fresh();
          inner.push(`let ${eb} := add(${dataSlot}, mul(${i}, ${storageSlotCount(elem)}))`);
          for (const leaf of structStorageLeaves(elem)) {
            const ls = leaf.storageSlot === 0 ? eb : `add(${eb}, ${leaf.storageSlot})`;
            inner.push(`mstore(add(add(${dstHead}, mul(${i}, ${es})), ${leaf.abiWord * 32}), ${this.loadState(leaf.type, ls, leaf.storageOffset)})`);
          }
        }
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return `add(0x20, mul(${len}, ${es}))`;
      }
      // dynamic elements (string[] / D[]): offset table + per-element tails.
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dstHead}, mul(${len}, 0x20))`);
      const sc = storageSlotCount(elem);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const eb = this.fresh();
      inner.push(`let ${eb} := add(${dataSlot}, mul(${i}, ${sc}))`);
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), sub(${cursor}, ${dstHead}))`);
      const sz = this.abiEncFromStorage(elem, eb, 0, cursor, inner);
      inner.push(`${cursor} := add(${cursor}, ${sz})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return `sub(${cursor}, ${dst})`;
    }
    if (t.kind === 'array' && t.length !== undefined) {
      // fixed array of a DYNAMIC element (Arr<string,N> / Arr<D,N>): an N-word offset
      // table (no length word) + per-element tails. Elements are contiguous in storage
      // (slotCount(elem) slots each); the static case is handled by isStaticType above.
      const n = t.length;
      const elem = t.element;
      const sc = storageSlotCount(elem);
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${n * 32})`);
      for (let k = 0; k < n; k++) {
        const eb = k === 0 ? slot : `add(${slot}, ${k * sc})`;
        out.push(`mstore(add(${dst}, ${k * 32}), sub(${cursor}, ${dst}))`);
        const sz = this.abiEncFromStorage(elem, eb, 0, cursor, out);
        out.push(`${cursor} := add(${cursor}, ${sz})`);
      }
      return `sub(${cursor}, ${dst})`;
    }
    if (t.kind === 'struct') {
      // dynamic struct: static fields inline in the head, dynamic fields offset + tail.
      const headWords = tupleHeadWords(t);
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${headWords * 32})`);
      let hw = 0;
      for (const f of t.fields) {
        const fb = hw * 32;
        const fslot = f.slot === 0 ? slot : `add(${slot}, ${f.slot})`;
        if (!isDynamicType(f.type)) {
          this.abiEncFromStorage(f.type, fslot, f.offset, `add(${dst}, ${fb})`, out);
          hw += abiHeadWords(f.type);
        } else {
          out.push(`mstore(add(${dst}, ${fb}), sub(${cursor}, ${dst}))`);
          const sz = this.abiEncFromStorage(f.type, fslot, f.offset, cursor, out);
          out.push(`${cursor} := add(${cursor}, ${sz})`);
          hw += 1;
        }
      }
      return `sub(${cursor}, ${dst})`;
    }
    throw new UnsupportedError(`abiEncFromStorage: unsupported type '${t.kind}'`);
  }

  // ---- dynamic bytes/string values (Phase 4) -------------------------------

  /** Resolve a dynamic bytes/string expression to its source reference. */
  private lowerDynamic(e: Expr, ctx: LowerCtx, out: string[]): DynRef {
    switch (e.kind) {
      case 'dynStateRead':
        return { src: 'storage', slot: String(e.slot) };
      case 'mapDynValue': {
        // this.m[k] where the value is bytes/string: the dynamic value lives at the
        // runtime keccak(key.base) mapping slot (short inline / long at keccak(slot)).
        const slot = this.mappingSlot(e.baseSlot, e.keys, ctx, out);
        return { src: 'storage', slot };
      }
      case 'dynParamRead': {
        const b = ctx.dynParams.get(e.name);
        if (!b) throw new UnsupportedError(`unbound dynamic param ${e.name}`);
        return { src: 'calldata', dataPtr: b.dataPtr, len: b.len };
      }
      case 'dynLocalRead':
        // a bytes/string MEMORY local: its register IS the [len][data] pointer.
        return { src: 'memory', ptr: this.ctxLookup(ctx, e.name) };
      case 'memDynField': {
        // a bytes/string field of a memory dynamic struct: the head word holds the
        // [len][data] pointer.
        const head = this.ctxLookup(ctx, e.local);
        const at = e.wordOffset === 0 ? head : `add(${head}, ${e.wordOffset * 32})`;
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(${at})`);
        return { src: 'memory', ptr };
      }
      case 'strArrayElem': {
        // storage / mapping-valued string[]/bytes[] element: bounds-check i (Panic
        // 0x32), then the element header at keccak(lenSlot)+i is a normal storage
        // bytes/string (short inline / long with keccak(headerSlot) data slots).
        const slot = this.strArrayElemSlot(e.arr, e.index, ctx, out);
        return { src: 'storage', slot };
      }
      case 'dynPlaceRead': {
        // bytes/string field of a storage dynamic struct (this.d.s, this.recs[i].s,
        // this.m[k].s): fold the AccessPath to the field's slot (struct base +
        // field slot, with any index/key bound-check & keccak applied), then read it
        // as a normal storage bytes/string. The field offset is always 0 (whole-slot).
        const p = this.lowerPlace(e.path, ctx, out);
        return { src: 'storage', slot: p.slot };
      }
      case 'cdDynArrayElem': {
        // string[]/bytes[] element: bounds-check i (Panic 0x32), then decode the
        // i-th element's dynamic value via the per-element offset table.
        const ref = this.lowerArrayRef(e.arr, ctx, out);
        if (ref.src !== 'calldata') throw new UnsupportedError('string[]/bytes[] element requires a calldata array');
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
        const dataPtr = this.fresh();
        const len = this.fresh();
        out.push(`let ${dataPtr}, ${len} := ${this.calldataDynElem()}(${ref.offset}, ${i})`);
        return { src: 'calldata', dataPtr, len };
      }
      case 'cdDynStructField': {
        // bytes/string dynamic field of a dynamic-struct calldata param. The field's
        // head slot holds an offset word relative to the containing tuple start; the
        // value (length + payload) is at base + offset (spec section 3.2).
        const base = this.lowerCdDynBase(e.place, ctx, out);
        const last = e.place.steps[e.place.steps.length - 1]!;
        const offPtr = last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
        const dataPtr = this.fresh();
        const len = this.fresh();
        out.push(`let ${dataPtr}, ${len} := ${this.calldataDynAt()}(${base}, ${offPtr})`);
        return { src: 'calldata', dataPtr, len };
      }
      case 'stringLiteral': {
        const ptr = this.fresh();
        const len = e.bytes.length;
        const nwords = Math.ceil(len / 32);
        out.push(`let ${ptr} := ${this.alloc()}(${0x20 + nwords * 32})`);
        out.push(`mstore(${ptr}, ${len})`);
        for (let i = 0; i < nwords; i++) {
          out.push(`mstore(add(${ptr}, ${0x20 + i * 32}), ${wordFromBytes(e.bytes, i * 32)})`);
        }
        return { src: 'memory', ptr };
      }
      default:
        throw new UnsupportedError(`not a dynamic value: ${e.kind}`);
    }
  }

  /** Length (uint256) of a dynamic value. */
  private dynLen(ref: DynRef): string {
    if (ref.src === 'storage') return `${this.strLen()}(${ref.slot})`;
    if (ref.src === 'calldata') return ref.len;
    return `mload(${ref.ptr})`;
  }

  /** Materialize any dynamic value into memory as [len][data...]; returns (mp, len) temps.
   *  This is only reached on LAZY paths (a single bytes/string returned/echoed, or an
   *  event/custom-error arg): the calldata source has already been fully validated by its
   *  decode helper (calldataDyn / calldataDynAt / calldataDynElem - signed offset, length
   *  cap, signed payload-fits), and the byte length is therefore bounded by calldatasize,
   *  so the copy is a plain calldatacopy with no further alloc/payload check (which would
   *  diverge from solc: e.g. an empty string behind a wrapped-pointer offset). The
   *  decode-to-fresh-memory ECHO encoders apply the Panic(0x41)/payload-fits themselves. */
  private toMemory(ref: DynRef, out: string[]): { mp: string; len: string } {
    if (ref.src === 'memory') return { mp: ref.ptr, len: `mload(${ref.ptr})` };
    const mp = this.fresh();
    const len = this.fresh();
    if (ref.src === 'storage') {
      out.push(`let ${mp}, ${len} := ${this.loadStr()}(${ref.slot})`);
    } else {
      out.push(`let ${len} := ${ref.len}`);
      out.push(`let ${mp} := ${this.alloc()}(add(0x20, and(add(${len}, 0x1f), not(0x1f))))`);
      out.push(`mstore(${mp}, ${len})`);
      out.push(`calldatacopy(add(${mp}, 0x20), ${ref.dataPtr}, ${len})`);
      // zero the partial-word tail so padding is clean
      out.push(`if mod(${len}, 0x20) { mstore(add(add(${mp}, 0x20), ${len}), 0) }`);
    }
    return { mp, len };
  }

  /** b[i] -> bytes1 (left-aligned), Panic(0x32) on out-of-bounds. */
  private lowerByteIndex(e: Expr & { kind: 'byteIndex' }, ctx: LowerCtx, out: string[]): string {
    const ref = this.lowerDynamic(e.base, ctx, out);
    const len = this.fresh();
    out.push(`let ${len} := ${this.dynLen(ref)}`);
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
    out.push(`if iszero(lt(${i}, ${len})) { ${this.panic()}(0x32) }`);
    if (ref.src === 'calldata') return `and(calldataload(add(${ref.dataPtr}, ${i})), ${TOP_BYTE})`;
    if (ref.src === 'memory') return `and(mload(add(${ref.ptr}, add(0x20, ${i}))), ${TOP_BYTE})`;
    return `${this.strByteAt()}(${ref.slot}, ${i})`;
  }

  /** Encode a single dynamic value as ABI [offset=0x20][len][data] into a fresh
   *  memory buffer (allocated AFTER materialization to avoid aliasing). Returns
   *  the buffer ptr and a Yul expr for its total byte size. */
  private encodeDynToMem(ref: DynRef, out: string[]): { ptr: string; size: string } {
    const { mp, len } = this.toMemory(ref, out);
    const ptr = this.fresh();
    const padded = `and(add(${len}, 0x1f), not(0x1f))`;
    out.push(`let ${ptr} := ${this.alloc()}(add(0x40, ${padded}))`);
    out.push(`mstore(${ptr}, 0x20)`);
    out.push(`mcopy(add(${ptr}, 0x20), ${mp}, add(0x20, ${padded}))`);
    return { ptr, size: `add(0x40, ${padded})` };
  }

  /** Write a dynamic value into storage slot `slot` (short/long + clear old tail). */
  private storeDynamic(slot: string, ref: DynRef, out: string[]): void {
    const { mp, len } = this.toMemory(ref, out);
    out.push(`${this.storeStrMem()}(${slot}, ${mp}, ${len})`);
  }

  // dedup helper definitions ------------------------------------------------

  private alloc(): string {
    const name = 'jeth_alloc';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(size) -> ptr {
  ptr := mload(0x40)
  mstore(0x40, add(ptr, and(add(size, 0x1f), not(0x1f))))
}`);
    }
    return name;
  }

  private arrayDataSlotHelper(): string {
    const name = 'jeth_array_data_slot';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(s) -> d {\n  mstore(0x00, s)\n  d := keccak256(0x00, 0x20)\n}`);
    }
    return name;
  }

  /** Decode a calldata dynamic-array param's (offset, length), bounds-checked
   *  exactly as solc (revert(0,0) on any malformation). */
  // Decode a dynamic array header at calldata offset `off` (relative to byte 4),
  // with `stride` bytes per element (32 for a value element, abiHeadWords*32 for a
  // static-struct element). Mirrors solc: bad offset / length / truncated payload
  // -> empty revert; len capped at 2^64 so stride*len cannot overflow a word.
  private calldataArray(): string {
    const name = 'jeth_calldata_array';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(off, stride) -> dataOff, len {
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let p := add(4, off)
  if iszero(slt(add(p, 0x1f), calldatasize())) { revert(0, 0) }
  len := calldataload(p)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  dataOff := add(p, 0x20)
  if gt(add(dataOff, mul(len, stride)), calldatasize()) { revert(0, 0) }
}`);
    }
    return name;
  }

  /** Decode a string[]/bytes[] (array of dynamic elements) calldata header at outer
   *  offset `off` (relative to byte 4). Returns (tableStart, len): `tableStart` is
   *  the element-offset table = the word right after the length word, which is the
   *  base for each element's relative offset (spec section 4.2). Two inclusive range
   *  checks: the length word must be readable, and the L offset-table words must fit.
   *  Per-element payload bounds are validated lazily on each a[i] read. Any fault ->
   *  empty revert; len capped at 2^64 so L*32 cannot overflow. */
  private calldataDynArray(): string {
    const name = 'jeth_calldata_dyn_array';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(off) -> tableStart, len {
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let p := add(4, off)
  if iszero(slt(add(p, 0x1f), calldatasize())) { revert(0, 0) }
  len := calldataload(p)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  tableStart := add(p, 0x20)
  if gt(add(tableStart, mul(len, 0x20)), calldatasize()) { revert(0, 0) }
}`);
    }
    return name;
  }

  /** LAZY-ACCESS resolve of the i-th element of a string[]/bytes[] calldata array to
   *  its dynamic value (dataPtr, len) - the form solc uses for `return a[i]`, an
   *  individual element slice that is re-encoded directly from calldata (NOT decoded
   *  into a fresh memory array). `tableStart` (B) is the element-offset table base;
   *  element i's offset word is at tableStart + i*32; the data begins at tableStart +
   *  off_i (that word is the byte length; the payload follows). This mirrors solc's
   *  `access_calldata_tail` for a `bytes`/`string` member exactly (rule 1, measured):
   *    - SIGNED length-word-readable check `slt(off, calldatasize() - B - 31)` (a
   *      high-bit/wrapping off passes, an off in (calldatasize, 2^255) reverts EMPTY);
   *    - the pointer add WRAPS mod 2^256, an OOB length read returns 0;
   *    - the byte length is capped at 2^64-1 (else EMPTY);
   *    - a SIGNED payload-fits `sgt(lenPtr, calldatasize() - (len + 0x20))` (so a
   *      wrapped/high-bit lenPtr passes and yields the wrapped/zero element, while a
   *      declared length whose payload runs past calldatasize reverts EMPTY).
   *  The WHOLE-array echo (string[] -> string[] memory) uses calldataDynElemEcho. */
  private calldataDynElem(): string {
    const name = 'jeth_calldata_dyn_elem';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(tableStart, i) -> dataPtr, len {
  let offPtr := add(tableStart, mul(i, 0x20))
  let elOff := calldataload(offPtr)
  if iszero(slt(elOff, sub(sub(calldatasize(), tableStart), 0x1f))) { revert(0, 0) }
  let lenPtr := add(tableStart, elOff)
  len := calldataload(lenPtr)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  if sgt(lenPtr, sub(calldatasize(), add(len, 0x20))) { revert(0, 0) }
  dataPtr := add(lenPtr, 0x20)
}`);
    }
    return name;
  }

  /** ECHO-DECODE resolve of the i-th element of a string[]/bytes[] calldata array,
   *  used when the WHOLE array is decoded into a fresh `string[] memory` (saEcho).
   *  solc's memory decoder rejects a wrapping/high-bit element offset with the UNSIGNED
   *  cap `gt(off, 2^64-1)` (no signed wrap acceptance), then requires the length word
   *  readable. The byte length is NOT capped here and the payload-fits is NOT applied:
   *  both fold into the per-element memory materialization, which raises Panic(0x41) on
   *  an oversized allocation (rule 3) and THEN validates the payload within calldatasize
   *  (EMPTY). Returns (dataPtr, len). */
  private calldataDynElemEcho(): string {
    const name = 'jeth_calldata_dyn_elem_echo';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(tableStart, i) -> dataPtr, len {
  let offPtr := add(tableStart, mul(i, 0x20))
  let elOff := calldataload(offPtr)
  if gt(elOff, 0xffffffffffffffff) { revert(0, 0) }
  let lenPtr := add(tableStart, elOff)
  if gt(add(lenPtr, 0x20), calldatasize()) { revert(0, 0) }
  len := calldataload(lenPtr)
  dataPtr := add(lenPtr, 0x20)
}`);
    }
    return name;
  }

  /** LAZY-ACCESS resolve of the i-th inner array of a nested dynamic array T[][]
   *  (calldata) to its (dataOffset, innerLen) - the form solc uses for m[i], m[i][j],
   *  m[i].length (an individual inner-array slice, NOT a decode into fresh memory).
   *  `base` (B) is the pointer-region start (= the word after the outer length word),
   *  the base for each inner pointer (spec section 2.2). The pointer word at base + i*32
   *  gives inner i's offset to its LENGTH word; the element data starts at that length
   *  word + 32. Mirrors solc's `access_calldata_tail` for an array member exactly
   *  (rule 1, measured): SIGNED length-word-readable check `slt(off, calldatasize() -
   *  B - 31)` (a high-bit/wrapping off passes; the OOB length read returns 0); innerLen
   *  capped at 2^64-1; SIGNED payload-fits `sgt(lenPtr, calldatasize() - (innerLen*
   *  stride + 0x20))` (a wrapped lenPtr passes -> Panic 0x32 on the index, while a
   *  declared innerLen whose elements run past calldatasize reverts EMPTY). The WHOLE
   *  T[][] echo uses calldataInnerArrayEcho. */
  private calldataInnerArray(): string {
    const name = 'jeth_calldata_inner_array';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(base, i, stride) -> dataOff, innerLen {
  let offPtr := add(base, mul(i, 0x20))
  let innerOff := calldataload(offPtr)
  if iszero(slt(innerOff, sub(sub(calldatasize(), base), 0x1f))) { revert(0, 0) }
  let lenPtr := add(base, innerOff)
  innerLen := calldataload(lenPtr)
  if gt(innerLen, 0xffffffffffffffff) { revert(0, 0) }
  if sgt(lenPtr, sub(calldatasize(), add(mul(innerLen, stride), 0x20))) { revert(0, 0) }
  dataOff := add(lenPtr, 0x20)
}`);
    }
    return name;
  }

  /** ECHO-DECODE resolve of the i-th inner array of a T[][], used when the WHOLE outer
   *  array is decoded into a fresh `T[][] memory` (mEcho). solc's memory decoder rejects
   *  a wrapping/high-bit inner offset with the UNSIGNED cap `gt(off, 2^64-1)` and then
   *  requires the length word readable. The innerLen cap and payload-fits fold into the
   *  per-inner memory materialization (Panic(0x41) on oversized allocation per rule 3,
   *  then payload-within-calldatasize EMPTY). Returns (dataOff, innerLen). */
  private calldataInnerArrayEcho(): string {
    const name = 'jeth_calldata_inner_array_echo';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(base, i) -> dataOff, innerLen {
  let offPtr := add(base, mul(i, 0x20))
  let innerOff := calldataload(offPtr)
  if gt(innerOff, 0xffffffffffffffff) { revert(0, 0) }
  let lenPtr := add(base, innerOff)
  if gt(add(lenPtr, 0x20), calldatasize()) { revert(0, 0) }
  innerLen := calldataload(lenPtr)
  dataOff := add(lenPtr, 0x20)
}`);
    }
    return name;
  }

  /** Decode a DYNAMIC-struct (tuple) calldata param header at top-level offset `off`
   *  (relative to byte 4). Returns `tupleStart` = the tuple's first field word
   *  (= 4 + off), which is the base for the tuple's own field/dynamic offsets (spec
   *  section 3.2). Validates that the whole tuple head (`headSize` bytes) is readable;
   *  a bad / out-of-range offset -> EMPTY revert. off capped at 2^64. */
  private calldataTuple(): string {
    const name = 'jeth_calldata_tuple';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(off, headSize) -> tupleStart {
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  tupleStart := add(4, off)
  if gt(add(tupleStart, headSize), calldatasize()) { revert(0, 0) }
}`);
    }
    return name;
  }

  /** Resolve a NESTED dynamic-struct field: `base` is the containing tuple start,
   *  `offPtr` is the calldata address of the field's offset word. The new tuple start
   *  = base + offset (offset relative to the containing tuple start, spec section 3.2).
   *  A nested dynamic STRUCT member is decoded eagerly (unlike a lazy bytes/array calldata
   *  slice), so solc uses the UNSIGNED form here, NOT the signed `access_calldata_tail`:
   *  `gt(off, 2^64-1)` rejects any wrapping/high-bit offset (measured: off=2^256-0x20,
   *  2^255, 2^64 all -> EMPTY), and the nested tuple head (`headSize` bytes) must be
   *  readable. Any fault -> EMPTY revert. Used identically by the lazy field-read path
   *  and the struct echo. */
  private calldataTupleAt(): string {
    const name = 'jeth_calldata_tuple_at';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(base, offPtr, headSize) -> tupleStart {
  if gt(add(offPtr, 0x20), calldatasize()) { revert(0, 0) }
  let off := calldataload(offPtr)
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  tupleStart := add(base, off)
  if gt(add(tupleStart, headSize), calldatasize()) { revert(0, 0) }
}`);
    }
    return name;
  }

  private calldataDyn(): string {
    const name = 'jeth_calldata_dyn';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(off) -> dataPtr, len {
  let argsLen := sub(calldatasize(), 4)
  if or(lt(argsLen, 0x20), gt(off, sub(argsLen, 0x20))) { revert(0, 0) }
  let lp := add(4, off)
  len := calldataload(lp)
  if gt(len, sub(sub(argsLen, off), 0x20)) { revert(0, 0) }
  dataPtr := add(lp, 0x20)
}`);
    }
    return name;
  }

  /** LAZY-ACCESS resolve of a bytes/string dynamic field inside a tuple - the form solc
   *  uses for `d.s.length` and `return d.s` (an individual calldata slice that is read
   *  or re-encoded directly, NOT decoded into a fresh memory struct). `base` (B) is the
   *  containing tuple start; `offPtr` is the calldata address of the field's offset word.
   *  The value lives at base + offset (spec section 3.2): that word is the byte length,
   *  the payload follows. Mirrors solc's `access_calldata_tail` for a bytes/string member
   *  exactly (rule 1, measured): SIGNED length-word-readable check `slt(off, calldatasize()
   *  - B - 31)` (a high-bit/wrapping off passes -> reads the wrapped/zero word; an off in
   *  (calldatasize, 2^255) reverts EMPTY); the byte length is capped at 2^64-1; a SIGNED
   *  payload-fits `sgt(lp, calldatasize() - (len + 0x20))` (a wrapped lp passes; a declared
   *  length running past calldatasize reverts EMPTY). The WHOLE-struct echo (return d) uses
   *  calldataDynAtEcho. */
  private calldataDynAt(): string {
    const name = 'jeth_calldata_dyn_at';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(base, offPtr) -> dataPtr, len {
  let off := calldataload(offPtr)
  if iszero(slt(off, sub(sub(calldatasize(), base), 0x1f))) { revert(0, 0) }
  let lp := add(base, off)
  len := calldataload(lp)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  if sgt(lp, sub(calldatasize(), add(len, 0x20))) { revert(0, 0) }
  dataPtr := add(lp, 0x20)
}`);
    }
    return name;
  }

  /** ECHO-DECODE resolve of a bytes/string dynamic field, used when the WHOLE struct is
   *  decoded into a fresh `D memory` (return d). solc's memory decoder rejects a wrapping/
   *  high-bit field offset with the UNSIGNED cap `gt(off, 2^64-1)` and then requires the
   *  length word readable. The byte length is NOT capped and the payload-fits is NOT
   *  applied here: both fold into the memory materialization (Panic(0x41) on an oversized
   *  allocation per rule 3, then payload-within-calldatasize EMPTY). Returns (dataPtr, len). */
  private calldataDynAtEcho(): string {
    const name = 'jeth_calldata_dyn_at_echo';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(base, offPtr) -> dataPtr, len {
  let off := calldataload(offPtr)
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let lp := add(base, off)
  if gt(add(lp, 0x20), calldatasize()) { revert(0, 0) }
  len := calldataload(lp)
  dataPtr := add(lp, 0x20)
}`);
    }
    return name;
  }

  private strLen(): string {
    const name = 'jeth_str_len';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(slot) -> l {
  let w := sload(slot)
  switch and(w, 1)
  case 0 { l := shr(1, and(w, 0xff)) }
  default { l := shr(1, sub(w, 1)) }
}`);
    }
    return name;
  }

  /** Copy a storage bytes/string at `slot` directly to memory `dst` as [len][right-
   *  padded data], WITHOUT allocating (so it never clobbers an output blob under
   *  construction at the free pointer). Returns the byte size written. */
  private copyStrToMem(): string {
    const name = 'jeth_copy_str_to_mem';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(slot, dst) -> size {
  let w := sload(slot)
  let len
  switch and(w, 1)
  case 0 {
    len := shr(1, and(w, 0xff))
    mstore(dst, len)
    mstore(add(dst, 0x20), and(w, not(0xff)))
  }
  default {
    len := shr(1, sub(w, 1))
    mstore(dst, len)
    let nwords := div(add(len, 0x1f), 0x20)
    mstore(0x00, slot)
    let base := keccak256(0x00, 0x20)
    for { let i := 0 } lt(i, nwords) { i := add(i, 1) } {
      mstore(add(add(dst, 0x20), mul(i, 0x20)), sload(add(base, i)))
    }
  }
  size := add(0x20, and(add(len, 0x1f), not(0x1f)))
}`);
    }
    return name;
  }

  private loadStr(): string {
    const name = 'jeth_load_str';
    if (!this.helpers.has(name)) {
      this.alloc();
      this.helpers.set(name, `function ${name}(slot) -> mp, len {
  let w := sload(slot)
  switch and(w, 1)
  case 0 {
    len := shr(1, and(w, 0xff))
    mp := jeth_alloc(0x40)
    mstore(mp, len)
    mstore(add(mp, 0x20), and(w, not(0xff)))
  }
  default {
    len := shr(1, sub(w, 1))
    let nwords := div(add(len, 0x1f), 0x20)
    mp := jeth_alloc(add(0x20, mul(nwords, 0x20)))
    mstore(mp, len)
    mstore(0x00, slot)
    let base := keccak256(0x00, 0x20)
    for { let i := 0 } lt(i, nwords) { i := add(i, 1) } {
      mstore(add(add(mp, 0x20), mul(i, 0x20)), sload(add(base, i)))
    }
  }
}`);
    }
    return name;
  }

  private strByteAt(): string {
    const name = 'jeth_str_byte_at';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(slot, i) -> r {
  let w := sload(slot)
  switch and(w, 1)
  case 0 { r := and(shl(mul(i, 8), w), ${TOP_BYTE}) }
  default {
    mstore(0x00, slot)
    let base := keccak256(0x00, 0x20)
    r := and(shl(mul(mod(i, 0x20), 8), sload(add(base, div(i, 0x20)))), ${TOP_BYTE})
  }
}`);
    }
    return name;
  }

  /** Clear a storage bytes/string slot to empty: zero the header AND (for a long
   *  value) its keccak(slot) data slots. Matches solc's full clear on pop/delete. */
  private clearStr(): string {
    const name = 'jeth_clear_str';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(slot) {
  let oldw := sload(slot)
  sstore(slot, 0)
  if and(oldw, 1) {
    let oldLen := shr(1, sub(oldw, 1))
    let oldWords := div(add(oldLen, 0x1f), 0x20)
    mstore(0x00, slot)
    let base := keccak256(0x00, 0x20)
    for { let i := 0 } lt(i, oldWords) { i := add(i, 1) } { sstore(add(base, i), 0) }
  }
}`);
    }
    return name;
  }

  private storeStrMem(): string {
    const name = 'jeth_store_str_mem';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(slot, mp, len) {
  let oldw := sload(slot)
  let oldLen := 0
  if and(oldw, 1) { oldLen := shr(1, sub(oldw, 1)) }
  let oldWords := div(add(oldLen, 0x1f), 0x20)
  mstore(0x00, slot)
  let base := keccak256(0x00, 0x20)
  switch lt(len, 0x20)
  case 1 {
    let dataWord := 0
    if len { dataWord := mload(add(mp, 0x20)) }
    let keepMask := shl(mul(sub(32, len), 8), not(0))
    sstore(slot, or(and(dataWord, keepMask), mul(len, 2)))
    for { let i := 0 } lt(i, oldWords) { i := add(i, 1) } { sstore(add(base, i), 0) }
  }
  default {
    sstore(slot, add(mul(len, 2), 1))
    let nwords := div(add(len, 0x1f), 0x20)
    for { let i := 0 } lt(i, nwords) { i := add(i, 1) } {
      let wv := mload(add(add(mp, 0x20), mul(i, 0x20)))
      if eq(i, sub(nwords, 1)) {
        let rem := mod(len, 0x20)
        if rem { wv := and(wv, shl(mul(sub(32, rem), 8), not(0))) }
      }
      sstore(add(base, i), wv)
    }
    for { let i := nwords } lt(i, oldWords) { i := add(i, 1) } { sstore(add(base, i), 0) }
  }
}`);
    }
    return name;
  }

  /** Derive the storage slot for this.m[k]...[k]: keccak256(keyWord . p) per level,
   *  recursive for nested mappings, using scratch 0x00-0x3f. The key's register
   *  word IS the hash key (uint zero-ext, int sign-ext, address zero-ext, bytesN
   *  left-aligned all match Solidity's padded key). Returns the final slot temp. */
  private mappingSlot(baseSlot: number, keys: Expr[], ctx: LowerCtx, out: string[]): string {
    let slot = String(baseSlot);
    for (const key of keys) {
      const k = this.lowerExpr(key, ctx, out);
      const t = this.fresh();
      out.push(`mstore(0x00, ${k})`);
      out.push(`mstore(0x20, ${slot})`);
      out.push(`let ${t} := keccak256(0x00, 0x40)`);
      slot = t;
    }
    return slot;
  }

  /** Store a register VALUE into a value-typed lvalue (local / state / mapping / nested
   *  place / array element). Factored from the assign-statement handler; used by the
   *  expression-position ++/-- lowering. */
  /** Evaluate internal-call arguments LEFT-to-RIGHT (solc order), freezing each into a fresh
   *  temp so a later arg's side effect cannot disturb an earlier arg's already-computed value.
   *  A STATIC struct argument is passed by reference (its memory pointer); a freshly constructed
   *  one (structNew) is allocated to memory first. */
  private lowerCallArgs(args: Expr[], ctx: LowerCtx, out: string[]): string[] {
    return args.map((a) => {
      const reg = a.kind === 'structNew' ? this.allocAggToMem(a, ctx, out) : this.lowerExpr(a, ctx, out);
      const t = this.fresh();
      out.push(`let ${t} := ${reg}`);
      return t;
    });
  }

  private lowerAssignValue(target: LValue, valueReg: string, ctx: LowerCtx, out: string[]): void {
    if (target.kind === 'local') {
      out.push(`${this.ctxLookup(ctx, target.varName)} := ${valueReg}`);
      return;
    }
    if (target.kind === 'state') {
      for (const l of this.storeState(target.type, String(target.slot), target.offset, valueReg)) out.push(l);
      return;
    }
    if (target.kind === 'mapping') {
      const slot = this.mappingSlot(target.baseSlot, target.keys, ctx, out);
      for (const l of this.storeState(target.type, slot, 0, valueReg)) out.push(l);
      return;
    }
    if (target.kind === 'place') {
      const p = this.lowerPlace(target.path, ctx, out);
      // a packed element with a RUNTIME byte offset uses packedStore; otherwise constant-offset.
      if (p.byteShift !== undefined) this.packedStore(target.type, p.slot, p.byteShift, valueReg, out);
      else for (const l of this.storeState(target.type, p.slot, p.offset, valueReg)) out.push(l);
      return;
    }
    if (target.kind === 'memField') {
      const ptr = this.ctxLookup(ctx, target.local);
      out.push(`mstore(${target.wordOffset === 0 ? ptr : `add(${ptr}, ${target.wordOffset * 32})`}, ${valueReg})`);
      return;
    }
    if (target.kind === 'memElem') {
      const ptr = this.ctxLookup(ctx, target.local);
      const i = this.fresh();
      out.push(`let ${i} := ${this.lowerExpr(target.index, ctx, out)}`);
      out.push(`if iszero(lt(${i}, ${target.length})) { ${this.panic()}(0x32) }`);
      out.push(`mstore(add(${ptr}, mul(${i}, 0x20)), ${valueReg})`);
      return;
    }
    if (target.kind === 'arrayElem') {
      const ref = this.lowerArrayRef(target.arr, ctx, out);
      const idx = this.fresh();
      out.push(`let ${idx} := ${this.lowerExpr(target.index, ctx, out)}`);
      if (ref.src === 'fixed') {
        out.push(`if iszero(lt(${idx}, ${ref.length})) { ${this.panic()}(0x32) }`);
        this.arrayElemStore(target.type, String(ref.baseSlot), idx, valueReg, out);
      } else if (ref.src === 'storage') {
        out.push(`if iszero(lt(${idx}, sload(${ref.lenSlot}))) { ${this.panic()}(0x32) }`);
        const data = this.arrayDataSlot(ref.lenSlot, out);
        this.arrayElemStore(target.type, data, idx, valueReg, out);
      } else if (ref.src === 'memory') {
        out.push(`if iszero(lt(${idx}, mload(${ref.ptr}))) { ${this.panic()}(0x32) }`);
        out.push(`mstore(add(${ref.ptr}, add(0x20, mul(${idx}, 0x20))), ${valueReg})`);
      } else {
        throw new UnsupportedError('cannot ++/-- a calldata array element');
      }
      return;
    }
    throw new UnsupportedError(`cannot ++/-- an lvalue of kind '${target.kind}'`);
  }

  private lowerGlobal(e: Expr & { kind: 'global' }): string {
    switch (e.op) {
      case 'caller': return 'caller()';
      case 'callvalue': return 'callvalue()';
      case 'origin': return 'origin()';
      case 'address': return 'address()';
      case 'timestamp': return 'timestamp()';
      case 'number': return 'number()';
      case 'chainid': return 'chainid()';
      case 'coinbase': return 'coinbase()';
      case 'basefee': return 'basefee()';
      case 'gaslimit': return 'gaslimit()';
      case 'prevrandao': return 'prevrandao()';
      case 'msgsig':
        // bytes4 left-aligned: high 4 bytes = selector. Matches solc.
        return 'and(calldataload(0), 0xffffffff00000000000000000000000000000000000000000000000000000000)';
    }
  }

  private lowerCast(e: Expr & { kind: 'cast' }, ctx: LowerCtx, out: string[]): string {
    const v = this.lowerExpr(e.operand, ctx, out);
    const { from, type: to } = e;
    // address <-> uint160 and address <-> address(payable): identical register word.
    if (to.kind === 'address' && from.kind === 'address') return v;
    if (to.kind === 'address' && from.kind === 'uint' && from.bits === 160) return v;
    if (to.kind === 'uint' && to.bits === 160 && from.kind === 'address') return v;
    // address (right-aligned low 20 bytes) <-> bytes20 (left-aligned high 20 bytes).
    if (to.kind === 'bytesN' && to.size === 20 && from.kind === 'address') return `shl(96, ${v})`;
    if (to.kind === 'address' && from.kind === 'bytesN' && from.size === 20) return `shr(96, ${v})`;
    // implicit widening (uintN->uintM, intN->intM, bytesN->bytesM, M>=N): a canonical
    // narrow value is already a valid wider value (uint: high bits 0; int: sign-extended;
    // bytesN: left-aligned), so the conversion is a no-op at the word level.
    if (isImplicitWiden(from, to)) return v;
    // integer <-> integer (explicit). uint target -> keep low toBits; int target ->
    // sign-extend the low toBits. Same-size int<->uint reinterprets the bits.
    if ((from.kind === 'uint' || from.kind === 'int') && (to.kind === 'uint' || to.kind === 'int')) {
      if (to.kind === 'uint') return to.bits === 256 ? v : `and(${v}, ${uintMaxHex(to.bits)})`;
      return to.bits === 256 ? v : `signextend(${to.bits / 8 - 1}, ${v})`;
    }
    // bytesN -> bytesM (narrowing; widening handled above): keep the high M bytes.
    if (from.kind === 'bytesN' && to.kind === 'bytesN') {
      const mask = toWord(((1n << BigInt(to.size * 8)) - 1n) << BigInt((32 - to.size) * 8));
      return `and(${v}, ${mask})`;
    }
    // uintN <-> bytesM of equal byte size: uint is right-aligned (low M bytes), bytesM is
    // left-aligned (high M bytes); shift by (32 - M) bytes between the two layouts.
    if (from.kind === 'uint' && to.kind === 'bytesN') return to.size === 32 ? v : `shl(${(32 - to.size) * 8}, ${v})`;
    if (from.kind === 'bytesN' && to.kind === 'uint') return from.size === 32 ? v : `shr(${(32 - from.size) * 8}, ${v})`;
    throw new UnsupportedError(`cast ${from.kind} -> ${to.kind} is not supported`);
  }

  private loadState(t: JethType, slot: string, offset: number): string {
    const size = storageByteSize(t);
    if (size === 32 && offset === 0) return `sload(${slot})`;
    const shift = BigInt(offset * 8);
    const raw = `shr(${shift}, sload(${slot}))`;
    if (t.kind === 'int') return `signextend(${t.bits / 8 - 1}, ${raw})`;
    const mask = (1n << BigInt(size * 8)) - 1n;
    const field = `and(${raw}, ${toWord(mask)})`;
    // bytesN must be returned in left-aligned register form.
    if (t.kind === 'bytesN') return `shl(${(32 - size) * 8}, ${field})`;
    return field;
  }

  private lowerUnary(e: Expr & { kind: 'unary' }, ctx: LowerCtx, out: string[]): string {
    const operand = this.lowerExpr(e.operand, ctx, out);
    switch (e.op) {
      case '!':
        return `iszero(${operand})`;
      case '~': {
        const not = `not(${operand})`;
        // keep uintN in range after complement
        if (e.type.kind === 'uint' && e.type.bits < 256) return `and(${not}, ${uintMaxHex(e.type.bits)})`;
        return not;
      }
      case '-': {
        if (e.type.kind !== 'int') throw new UnsupportedError('unary - on non-int');
        // unchecked negation wraps (0 - x mod 2^bits); checked reverts at INT_MIN.
        if (e.unchecked) return this.wrapToType(e.type, `sub(0, ${operand})`);
        const helper = this.checkedSubInt(e.type.bits);
        return `${helper}(0, ${operand})`;
      }
    }
  }

  private lowerBinary(e: Expr & { kind: 'binary' }, ctx: LowerCtx, out: string[]): string {
    // Short-circuiting && / || must NOT evaluate the RHS unconditionally: the
    // RHS may revert (checked arithmetic), and Solidity short-circuits.
    if (e.op === '&&' || e.op === '||') {
      const left = this.lowerExpr(e.left, ctx, out);
      const t = this.fresh();
      const inner: string[] = [];
      const right = this.lowerExpr(e.right, ctx, inner);
      out.push(`let ${t} := ${e.op === '&&' ? '0' : '1'}`);
      out.push(`if ${e.op === '&&' ? left : `iszero(${left})`} {`);
      for (const s of inner) out.push('  ' + s);
      out.push(`  ${t} := ${right}`);
      out.push('}');
      return t;
    }

    // solc evaluates a binary operation's RIGHT operand before its LEFT operand. This is
    // invisible for side-effect-free operands but observable when an operand mutates state
    // (incDec / assignExpr in value position), e.g. `(++x) * 100 + (++x)` or `(x = v) + x`.
    // Evaluate the right operand first AND freeze it into a fresh temp: the freeze is what
    // makes the value stick when the right operand is a live variable read that the left
    // operand then mutates. The left operand is evaluated last and used immediately, so it
    // needs no snapshot. (&& / || above are short-circuit and stay left-first.)
    const rReg = this.lowerExpr(e.right, ctx, out);
    const r = this.fresh();
    out.push(`let ${r} := ${rReg}`);
    const l = this.lowerExpr(e.left, ctx, out);
    const opType = e.left.type; // operands are unified to the same type (except ** exponent)
    // exponentiation a ** b: checked (Panic 0x11 on overflow) or wrapping (unchecked).
    if (e.op === '**') {
      if (e.unchecked) return this.wrapToType(opType, `exp(${l}, ${r})`);
      return `${this.checkedExp(opType)}(${l}, ${r})`;
    }
    // unchecked + - * : wrap (mask/sign-extend) to the operand width, no overflow revert.
    if (e.unchecked && (e.op === '+' || e.op === '-' || e.op === '*')) {
      const raw = e.op === '+' ? `add(${l}, ${r})` : e.op === '-' ? `sub(${l}, ${r})` : `mul(${l}, ${r})`;
      return this.wrapToType(opType, raw);
    }
    // unchecked signed division: division-by-zero still Panics 0x12, but the lone signed
    // overflow (INT_MIN / -1) WRAPS to INT_MIN (EVM sdiv) instead of Panic 0x11, matching
    // solc's unchecked block. (unchecked uint div == checked: no overflow possible.)
    if (e.unchecked && e.op === '/' && opType.kind === 'int') {
      // re-normalize to the narrow width: INT_MIN/-1 wraps and the raw sdiv result
      // (e.g. +128 for int8) must be sign-extended back into range, like every other op.
      return this.wrapToType(opType, `${this.uncheckedDivInt()}(${l}, ${r})`);
    }
    switch (e.op) {
      case '+':
        return `${this.checkedArith('add', opType)}(${l}, ${r})`;
      case '-':
        return `${this.checkedArith('sub', opType)}(${l}, ${r})`;
      case '*':
        return `${this.checkedArith('mul', opType)}(${l}, ${r})`;
      case '/':
        return `${this.checkedArith('div', opType)}(${l}, ${r})`;
      case '%':
        return `${this.checkedArith('mod', opType)}(${l}, ${r})`;
      case '&':
        return `and(${l}, ${r})`;
      case '|':
        return `or(${l}, ${r})`;
      case '^':
        return `xor(${l}, ${r})`;
      case '<<': {
        const res = `shl(${r}, ${l})`;
        // narrow results must be re-normalized to their in-register form.
        if (opType.kind === 'uint' && opType.bits < 256) return `and(${res}, ${uintMaxHex(opType.bits)})`;
        if (opType.kind === 'int' && opType.bits < 256) return `signextend(${opType.bits / 8 - 1}, ${res})`;
        return res;
      }
      case '>>':
        return opType.kind === 'int' ? `sar(${r}, ${l})` : `shr(${r}, ${l})`;
      case '<':
        return opType.kind === 'int' ? `slt(${l}, ${r})` : `lt(${l}, ${r})`;
      case '>':
        return opType.kind === 'int' ? `sgt(${l}, ${r})` : `gt(${l}, ${r})`;
      case '<=':
        return `iszero(${opType.kind === 'int' ? `sgt(${l}, ${r})` : `gt(${l}, ${r})`})`;
      case '>=':
        return `iszero(${opType.kind === 'int' ? `slt(${l}, ${r})` : `lt(${l}, ${r})`})`;
      case '==':
        return `eq(${l}, ${r})`;
      case '!=':
        return `iszero(eq(${l}, ${r}))`;
    }
  }

  // ---- checked-arithmetic helpers -----------------------------------------

  private checkedArith(op: 'add' | 'sub' | 'mul' | 'div' | 'mod', t: JethType): string {
    if (t.kind === 'uint') {
      switch (op) {
        case 'add': return this.checkedAddUint(t.bits);
        case 'sub': return this.checkedSubUint(t.bits);
        case 'mul': return this.checkedMulUint(t.bits);
        case 'div': return this.checkedDivUint();
        case 'mod': return this.checkedModUint();
      }
    }
    if (t.kind === 'int') {
      switch (op) {
        case 'add': return this.checkedAddInt(t.bits);
        case 'sub': return this.checkedSubInt(t.bits);
        case 'mul': return this.checkedMulInt(t.bits);
        case 'div': return this.checkedDivInt(t.bits);
        case 'mod': return this.checkedModInt();
      }
    }
    throw new UnsupportedError(`arithmetic on type '${t.kind}' is not supported`);
  }

  /** Normalize an arithmetic result to a type's in-register form (mask uintN, sign-extend
   *  intN). A no-op for 256-bit. Used by unchecked (wrapping) arithmetic and shifts. */
  private wrapToType(t: JethType, expr: string): string {
    if (t.kind === 'uint') return t.bits === 256 ? expr : `and(${expr}, ${uintMaxHex(t.bits)})`;
    if (t.kind === 'int') return t.bits === 256 ? expr : `signextend(${t.bits / 8 - 1}, ${expr})`;
    return expr;
  }

  /** Checked exponentiation base ** exponent for an integer type (Panic 0x11 on overflow,
   *  Solidity-identical). Square-and-multiply with FULL-WIDTH (256-bit) checked muls for
   *  the intermediates, then a final range check against the result type. */
  private checkedExp(t: JethType): string {
    const name = `jeth_exp_${t.kind === 'int' ? 'i' : 'u'}${t.kind === 'uint' || t.kind === 'int' ? t.bits : 0}`;
    if (!this.helpers.has(name)) {
      const cmul = t.kind === 'int' ? this.checkedMulInt(256) : this.checkedMulUint(256);
      let rangeCheck = '';
      if (t.kind === 'uint' && t.bits < 256) rangeCheck = `if gt(power, ${uintMaxHex(t.bits)}) { ${this.panic()}(0x11) }`;
      if (t.kind === 'int' && t.bits < 256) {
        const max = toWord((1n << BigInt(t.bits - 1)) - 1n);
        const min = toWord(-(1n << BigInt(t.bits - 1)));
        rangeCheck = `if or(sgt(power, ${max}), slt(power, ${min})) { ${this.panic()}(0x11) }`;
      }
      this.helpers.set(name, `function ${name}(base, exponent) -> power {
  power := 1
  if exponent {
    for { } gt(exponent, 1) { } {
      if and(exponent, 1) { power := ${cmul}(power, base) }
      base := ${cmul}(base, base)
      exponent := shr(1, exponent)
    }
    power := ${cmul}(power, base)
  }
  ${rangeCheck}
}`);
    }
    return name;
  }

  /** Unchecked signed division: Panic(0x12) on division by zero (NOT suppressed by
   *  unchecked), but the signed overflow INT_MIN/-1 wraps (sdiv) instead of Panic(0x11). */
  private uncheckedDivInt(): string {
    const name = 'jeth_unchecked_div_int';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(a, b) -> r {\n  if iszero(b) { ${this.panic()}(0x12) }\n  r := sdiv(a, b)\n}`);
    }
    return name;
  }

  private panic(): string {
    this.helpers.set(
      'panic',
      `function panic(code) {
  mstore(0, shl(224, 0x4e487b71))
  mstore(4, code)
  revert(0, 0x24)
}`,
    );
    return 'panic';
  }

  private checkedAddUint(bits: number): string {
    const name = `checked_add_uint${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const ov = bits === 256 ? `lt(r, a)` : `gt(r, ${uintMaxHex(bits)})`;
      this.helpers.set(name, `function ${name}(a, b) -> r {
  r := add(a, b)
  if ${ov} { panic(0x11) }
}`);
    }
    return name;
  }
  private checkedSubUint(bits: number): string {
    const name = `checked_sub_uint${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(name, `function ${name}(a, b) -> r {
  if gt(b, a) { panic(0x11) }
  r := sub(a, b)
}`);
    }
    return name;
  }
  private checkedMulUint(bits: number): string {
    const name = `checked_mul_uint${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const widthChk = bits === 256 ? '0' : `gt(r, ${uintMaxHex(bits)})`;
      this.helpers.set(name, `function ${name}(a, b) -> r {
  r := mul(a, b)
  if or(and(iszero(iszero(a)), iszero(eq(div(r, a), b))), ${widthChk}) { panic(0x11) }
}`);
    }
    return name;
  }
  private checkedDivUint(): string {
    const name = `checked_div_uint`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(name, `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  r := div(a, b)
}`);
    }
    return name;
  }
  private checkedModUint(): string {
    const name = `checked_mod_uint`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(name, `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  r := mod(a, b)
}`);
    }
    return name;
  }

  private checkedAddInt(bits: number): string {
    const name = `checked_add_int${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const { min, max } = intRange({ kind: 'int', bits });
      const chk =
        bits === 256
          ? `or(and(iszero(slt(b, 0)), slt(r, a)), and(slt(b, 0), sgt(r, a)))`
          : `or(sgt(r, ${toWord(max)}), slt(r, ${toWord(min)}))`;
      this.helpers.set(name, `function ${name}(a, b) -> r {
  r := add(a, b)
  if ${chk} { panic(0x11) }
}`);
    }
    return name;
  }
  private checkedSubInt(bits: number): string {
    const name = `checked_sub_int${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const { min, max } = intRange({ kind: 'int', bits });
      const chk =
        bits === 256
          ? `or(and(iszero(slt(b, 0)), sgt(r, a)), and(slt(b, 0), slt(r, a)))`
          : `or(sgt(r, ${toWord(max)}), slt(r, ${toWord(min)}))`;
      this.helpers.set(name, `function ${name}(a, b) -> r {
  r := sub(a, b)
  if ${chk} { panic(0x11) }
}`);
    }
    return name;
  }
  private checkedMulInt(bits: number): string {
    const name = `checked_mul_int${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const { min, max } = intRange({ kind: 'int', bits });
      const widthChk = bits === 256 ? '' : ` if or(sgt(r, ${toWord(max)}), slt(r, ${toWord(min)})) { panic(0x11) }`;
      const minHex = toWord(min);
      this.helpers.set(name, `function ${name}(a, b) -> r {
  r := mul(a, b)
  if iszero(iszero(a)) {
    if iszero(eq(sdiv(r, a), b)) { panic(0x11) }
  }
  if and(eq(a, ${toWord(-1n)}), eq(b, ${minHex})) { panic(0x11) }${widthChk}
}`);
    }
    return name;
  }
  private checkedDivInt(bits: number): string {
    const name = `checked_div_int${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const { min } = intRange({ kind: 'int', bits });
      this.helpers.set(name, `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  if and(eq(a, ${toWord(min)}), eq(b, ${toWord(-1n)})) { panic(0x11) }
  r := sdiv(a, b)
}`);
    }
    return name;
  }
  private checkedModInt(): string {
    const name = `checked_mod_int`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(name, `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  r := smod(a, b)
}`);
    }
    return name;
  }

  private fresh(): string {
    return `_t${this.tmp++}`;
  }

  // ---- lowering scope stack (mirrors the analyzer; unique Yul names) --------

  private freshLocal(jethName: string): string {
    return `v_${jethName}_${this.nameCounter++}`;
  }
  private ctxPush(ctx: LowerCtx): void {
    ctx.scopes.push(new Map());
  }
  private ctxPop(ctx: LowerCtx): void {
    ctx.scopes.pop();
  }
  private ctxDeclare(ctx: LowerCtx, jethName: string, yulName: string): void {
    ctx.scopes[ctx.scopes.length - 1]!.set(jethName, yulName);
  }
  private ctxLookup(ctx: LowerCtx, jethName: string): string {
    for (let i = ctx.scopes.length - 1; i >= 0; i--) {
      const n = ctx.scopes[i]!.get(jethName);
      if (n) return n;
    }
    throw new UnsupportedError(`read of unbound local ${jethName}`);
  }
}

interface LowerCtx {
  scopes: Map<string, string>[]; // jeth name -> unique yul name, innermost last
  returnType: JethType;
  dynParams: Map<string, { dataPtr: string; len: string }>; // calldata bytes/string params
  cdArrays: Map<string, { offset: string; length: string; elem: JethType }>; // calldata array params
  cdAggregates: Map<string, { baseOffset: number; type: JethType }>; // struct / fixed-array params (inline calldata head)
  cdDynStructs: Map<string, { tupleStart: string; type: JethType }>; // dynamic struct params (runtime tuple-start byte ptr)
  cdParamHead: Map<string, { head: number; type: JethType }>; // calldata head byte of EVERY param (for whole-param echo via the recursive encoder)
  fnMode?: { retVar: string | null }; // set when lowering an INTERNAL function body: `return` -> retVar:=v; leave (retVar null = void)
}

// A lowered array reference, by source location.
type ArrayRef =
  | { src: 'storage'; lenSlot: string; elem: JethType } // dynamic T[] (data at keccak(lenSlot))
  | { src: 'calldata'; offset: string; length: string; elem: JethType }
  | { src: 'fixed'; baseSlot: number; length: number; elem: JethType } // Arr<T,N> inline
  | { src: 'memory'; ptr: string; elem: JethType }; // memory T[] (ptr -> [len][elem0]...)

// The value source for a tuple (dynamic struct) being encoded: a constructed
// value (structNew args) or a calldata echo (the bound tuple-start byte ptr).
type TupleSrc =
  | { kind: 'new'; fields: StructField[]; args: Expr[] }
  | { kind: 'cd'; base: string }
  | { kind: 'mem'; headPtr: string }; // a memory dynamic-struct local (one word per field: value inline, bytes/string a pointer)

// A lowered dynamic bytes/string value, by source location.
type DynRef =
  | { src: 'storage'; slot: string }
  | { src: 'calldata'; dataPtr: string; len: string }
  | { src: 'memory'; ptr: string }; // ptr -> [len][data...]

const TOP_BYTE = '0xff00000000000000000000000000000000000000000000000000000000000000';

function indent(text: string, spaces: number): string {
  const pad = ' '.repeat(spaces);
  return text
    .split('\n')
    .map((l) => (l.length ? pad + l : l))
    .join('\n');
}

export function emitYul(contract: ContractIR): string {
  return new YulEmitter().emit(contract);
}
