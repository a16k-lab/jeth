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
import { ContractIR, FunctionIR, LibraryIR, SpecialEntryIR, Stmt, Expr, BinOp, RevertReason, EventIR } from './ir.js';
import {
  JethType,
  StructField,
  intRange,
  storageByteSize,
  storageSlotCount,
  isBytesLike,
  isDynamicType,
  isStaticType,
  isStaticValueType,
  isImplicitWiden,
  arrayElemPacks,
  abiHeadWords,
  abiLeaves,
  structStorageLeaves,
} from './types.js';
import type {
  ArrayExpr,
  AccessPath,
  CalldataPlace,
  CdDynPlace,
  LValue,
  DestructureSource,
  SuccessCheck,
} from './ir.js';

export class UnsupportedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsupportedError';
  }
}

// Phase 6 external-call scoped bindings (this.ok / this.data inside a success condition). These keys
// are bound in the LowerCtx scope while a check is lowered; the leading '#' cannot collide with a
// user identifier. callOk resolves to the success-bool register; callData to the returndata pointer.
const EXT_CALL_OK_BINDING = '#extCallOk';
const EXT_CALL_DATA_BINDING = '#extCallData';

// F4 @nonReentrant: a dedicated TRANSIENT-storage slot (EIP-1153, its own address space, wiped at
// end of transaction and reverted on a failed call) holds the mutex. The slot is namespaced by a
// keccak so it cannot collide with any future transient use; its value is never observable on chain.
const REENTRANCY_TSLOT = '0xe3c13ce1a6dbca2cd747af6cfb37b5bfaa572cf58e51980e617e5acd973fa8b3'; // keccak("jeth.nonReentrant.guard.v1")
// The OpenZeppelin custom error ReentrancyGuardReentrantCall() (selector 0x3ee5aeb5), left-aligned in
// a word, so a reentrant call reverts with revert data byte-identical to OZ's transient guard.
const REENTRANCY_ERROR_WORD = '0x3ee5aeb500000000000000000000000000000000000000000000000000000000';

// OpenZeppelin 5.x ECDSA constants. HALF_ORDER == floor(secp256k1.N / 2); the high-s rejection is STRICT
// `s > HALF_ORDER` (so s == HALF_ORDER is accepted). The three custom-error selectors are left-aligned in a
// word for `mstore(0, <word>)` + revert(0, 4 [+0x20]), byte-identical to OZ's custom-error encoding.
const HALF_ORDER = '0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0';
const ECDSA_INVALID_SIGNATURE = '0xf645eedf00000000000000000000000000000000000000000000000000000000'; // ECDSAInvalidSignature()
const ECDSA_INVALID_SIGNATURE_LENGTH = '0xfce698f700000000000000000000000000000000000000000000000000000000'; // ECDSAInvalidSignatureLength(uint256)
const ECDSA_INVALID_SIGNATURE_S = '0xd78bce0c00000000000000000000000000000000000000000000000000000000'; // ECDSAInvalidSignatureS(bytes32)
// EIP-4844 KZG point-evaluation (0x0a) success-output constants (cancun-pinned).
const KZG_FIELD_ELEMENTS_PER_BLOB = '0x0000000000000000000000000000000000000000000000000000000000001000'; // 4096
const KZG_BLS_MODULUS = '0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001';

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
/** Mask of the high `size` bytes: the data region of a left-aligned bytesN (used to keep the
 *  padding region zero after `~` / `>>` whose word-level op would otherwise dirty the low bytes). */
function bytesNHighMaskHex(size: number): string {
  return '0x' + (((1n << BigInt(size * 8)) - 1n) << BigInt((32 - size) * 8)).toString(16);
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
    for (const f of contract.functions) this.funcs.set(f.key, f); // by unique key (overload-safe)
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

  /** Phase B: emit ONE external (delegatecall) library as its own top-level deployable Yul object.
   *  The runtime is a selector dispatcher over the library's @external functions (same structure as a
   *  contract runtime via emitRuntime) plus its object-local internal userfn_s. The creation copies the
   *  runtime out and returns it (non-payable at deploy, like a constructorless contract). A library has
   *  no state/constructor/immutables/special entries, so a synthetic ContractIR carries empty ones.
   *  YulEmitter state (helpers/funcs/counters) is saved + isolated so a helper a library body pulls in
   *  is defined INSIDE the library's runtime scope, not leaked into the contract object. */
  emitLibraryObject(lib: LibraryIR): string {
    const savedFuncs = this.funcs;
    const savedHelpers = this.helpers;
    const savedTmp = this.tmp;
    this.funcs = new Map<string, FunctionIR>();
    this.helpers = new Map<string, string>();
    const fns = [...lib.external, ...lib.internal];
    for (const f of fns) this.funcs.set(f.key, f);
    const synthetic: ContractIR = {
      name: lib.name,
      stateVars: [],
      functions: fns,
      errors: [],
      events: [],
      slotCount: 0,
      immutables: [],
    };
    const runtime = this.emitRuntime(synthetic);
    // Creation: a library deploy takes no value (non-payable) and no args; copy the runtime out + return.
    const creationLines = [
      'if callvalue() { revert(0, 0) }',
      `datacopy(0, dataoffset("${lib.name}_runtime"), datasize("${lib.name}_runtime"))`,
      `return(0, datasize("${lib.name}_runtime"))`,
    ];
    const creation = creationLines.join('\n');
    this.funcs = savedFuncs;
    this.helpers = savedHelpers;
    this.tmp = savedTmp;
    return `object "${lib.name}" {
  code {
${indent(creation, 4)}
  }
  object "${lib.name}_runtime" {
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
    // A constructorless contract is non-payable at creation: reject any deploy value, exactly like
    // solc (which always emits this guard at the start of creation unless the constructor is explicitly
    // @payable). When there IS a constructor, emitConstructor emits the guard itself (unless @payable).
    if (!contract.ctor) lines.push('if callvalue() { revert(0, 0) }');
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
    // Phase 5: run the constructor body (if any) AFTER the constant-field initializers and BEFORE
    // copying out + returning the runtime code. The ctor's helper definitions are appended at the
    // end of THIS creation block (a separate Yul scope from the runtime object).
    let ctorHelpers: string[] = [];
    const staged = new Map<string, string>(); // @immutable name -> the Yul var holding its baked value
    if (contract.ctor) {
      const c = this.emitConstructor(contract);
      lines.push(...c.lines);
      ctorHelpers = c.helpers;
      for (const [k, v] of c.staged) staged.set(k, v);
    }
    lines.push(`datacopy(0, dataoffset("${contract.name}_runtime"), datasize("${contract.name}_runtime"))`);
    // Bake every @immutable into the (in-memory copy of the) runtime code via setimmutable. The
    // value is the staged shadow when the ctor assigned it, else 0 (solc: a never-assigned immutable
    // reads as 0). setimmutable requires a matching loadimmutable in the runtime, which only exists
    // when the immutable is actually read - but an unread immutable's setimmutable is a harmless no-op.
    for (const im of contract.immutables) {
      lines.push(`setimmutable(0, "${im.name}", ${staged.get(im.name) ?? '0'})`);
    }
    lines.push(`return(0, datasize("${contract.name}_runtime"))`);
    for (const def of ctorHelpers) {
      lines.push('');
      lines.push(def);
    }
    return lines.join('\n');
  }

  /** Phase 5: emit the constructor prologue (non-payable callvalue guard + decode the appended
   *  ABI-encoded args from MEMORY) and a synthesized `jeth_constructor(...)` Yul function for the
   *  body, then call it. Returns the inline creation lines and the function/helper definitions to
   *  place at the end of the creation block. The body runs inside a Yul function so a `return;`
   *  becomes `leave` (exit the ctor, then deploy) rather than a raw EVM return (empty code). */
  private emitConstructor(contract: ContractIR): { lines: string[]; helpers: string[]; staged: Map<string, string> } {
    const ctor = contract.ctor!;
    this.nameCounter = 0;
    const lines: string[] = [];
    // Non-payable constructor: reject any value sent at deploy (solc emits this guard).
    if (!ctor.payable) lines.push('if callvalue() { revert(0, 0) }');

    // Each @immutable is a RETURN VARIABLE of jeth_constructor: zero-initialized (matching a
    // never-assigned immutable), last-write-wins, and readable after the function returns (`leave`).
    // The body writes/reads them via ctx.immStaged (the inner ret-var names); the OUTER capture vars
    // (distinct names, to avoid Yul shadowing) feed setimmutable in emitCreation.
    const immStaged = new Map<string, string>(); // immutable name -> inner ret var
    const innerRets: string[] = [];
    const outerRets: string[] = [];
    const staged = new Map<string, string>(); // immutable name -> outer capture var
    for (const im of contract.immutables) {
      const inner = this.freshLocal(`imm_${im.name}`);
      const outer = this.fresh();
      immStaged.set(im.name, inner);
      innerRets.push(inner);
      outerRets.push(outer);
      staged.set(im.name, outer);
    }

    const ctx: LowerCtx = {
      scopes: [new Map()],
      returnType: { kind: 'void' } as JethType,
      dynParams: new Map(),
      cdArrays: new Map(),
      cdAggregates: new Map(),
      cdDynStructs: new Map(),
      cdParamHead: new Map(),
      fnMode: { retVar: null }, // a bare `return;` in the ctor body -> leave
      immStaged,
    };

    // Decode the constructor args (ABI-encoded, appended after the init code). They begin at code
    // offset datasize("C") (the init-code size) and run to codesize(). Copy them into memory at
    // 0x80 and decode from MEMORY (each value param is one 32-byte ABI head word). solc reverts
    // EMPTY when the args region is shorter than the static head, and ignores trailing bytes.
    const ARGS = 0x80;
    const headWords = ctor.params.reduce((n, p) => n + abiHeadWords(p.type), 0);
    const argBytes = headWords * 32;
    if (headWords > 0) {
      lines.push(`let _argsLen := sub(codesize(), datasize("${contract.name}"))`);
      lines.push(`if lt(_argsLen, ${argBytes}) { revert(0, 0) }`);
      lines.push(`codecopy(${ARGS}, datasize("${contract.name}"), ${argBytes})`);
      // free-memory pointer past the decoded args, so a body allocation cannot clobber them.
      lines.push(`mstore(0x40, ${ARGS + argBytes})`);
    } else {
      lines.push('mstore(0x40, 0x80)'); // init the free-memory pointer for any body allocation
    }
    const formals: string[] = []; // the synthesized function's parameter names (v_<name>_N)
    const decoded: string[] = []; // the outer decode locals (_tN) passed at the call site
    let cursorWords = 0;
    for (const p of ctor.params) {
      const formal = this.freshLocal(p.name);
      this.ctxDeclare(ctx, p.name, formal);
      formals.push(formal);
      const dec = this.fresh();
      lines.push(`let ${dec} := mload(${ARGS + cursorWords * 32})`);
      const guard = this.validateInput(p.type, dec);
      if (guard) lines.push(guard);
      decoded.push(dec);
      cursorWords += abiHeadWords(p.type);
    }

    // Lower the body with a FRESH helpers map so any helper it pulls in (keccak/checked-math/alloc)
    // is defined in THIS creation block, not the runtime object (separate Yul scope).
    const savedHelpers = this.helpers;
    this.helpers = new Map();
    const body: string[] = [];
    for (const s of ctor.body) for (const l of this.lowerStmt(s, ctx)) body.push(l);
    const helperDefs = [...this.helpers.values()];
    this.helpers = savedHelpers;

    const retDecl = innerRets.length ? ` -> ${innerRets.join(', ')}` : '';
    const sig = `function jeth_constructor(${formals.join(', ')})${retDecl}`;
    const ctorFn = `${sig} {\n${body.map((l) => '  ' + l).join('\n')}${body.length ? '\n' : ''}}`;
    lines.push(
      innerRets.length
        ? `let ${outerRets.join(', ')} := jeth_constructor(${decoded.join(', ')})`
        : `jeth_constructor(${decoded.join(', ')})`,
    );
    return { lines, helpers: [ctorFn, ...helperDefs], staged };
  }

  // ---- runtime / dispatcher ------------------------------------------------

  private emitRuntime(contract: ContractIR): string {
    const lines: string[] = [];
    lines.push('mstore(0x40, 0x80) // init free memory pointer');

    const external = contract.functions.filter((f) => f.visibility === 'external');
    const hasSpecial = !!(contract.receive || contract.fallback);
    if (hasSpecial) {
      // Phase 6: receive/fallback dispatch (byte-identical to solc's optimized IR). The selector switch
      // is wrapped in `if iszero(lt(calldatasize(),4))` with an EMPTY default (NEVER default{revert}),
      // then the receive empty-calldata check, then the fallback (non-payable callvalue guard + body),
      // else a trailing revert. Empty calldata with no receive falls through the switch into the fallback.
      if (external.length > 0) {
        lines.push('if iszero(lt(calldatasize(), 4)) {');
        lines.push('  let selector := shr(224, calldataload(0))');
        lines.push('  switch selector');
        for (const fn of external) {
          lines.push(`  case 0x${fn.selector} { // ${fn.signature}`);
          for (const l of this.emitDispatchCase(fn)) lines.push('    ' + l);
          lines.push('  }');
        }
        lines.push('  default {}');
        lines.push('}');
      }
      if (contract.receive) {
        lines.push('if iszero(calldatasize()) {');
        for (const l of this.emitSpecialEntryBody(contract.receive)) lines.push('  ' + l);
        lines.push('  stop()');
        lines.push('}');
      }
      if (contract.fallback) {
        if (!contract.fallback.payable) lines.push('if callvalue() { revert(0, 0) }');
        for (const l of this.emitSpecialEntryBody(contract.fallback)) lines.push(l);
        lines.push('stop()');
      } else {
        lines.push('revert(0, 0)');
      }
    } else if (external.length === 0) {
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

  /** Phase 6: lower a @receive/@fallback body INLINE in the dispatcher (no params, no return). A bare
   *  `return;` halts via stop() (specialEntry flag). The caller appends the trailing stop(). */
  private emitSpecialEntryBody(entry: SpecialEntryIR): string[] {
    const ctx: LowerCtx = {
      scopes: [new Map()],
      returnType: { kind: 'void' } as JethType,
      dynParams: new Map(),
      cdArrays: new Map(),
      cdAggregates: new Map(),
      cdDynStructs: new Map(),
      cdParamHead: new Map(),
      specialEntry: true,
    };
    const out: string[] = [];
    for (const s of entry.body) for (const l of this.lowerStmt(s, ctx)) out.push(l);
    return out;
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
    let retDecl = '';
    if (fn.returnTypes) {
      // a multi-value internal function: `-> r0, r1, ...`; `return [..]` sets each and leaves.
      const retVars = fn.returnTypes.map(() => this.fresh());
      ctx.fnMode = { retVar: null, retVars };
      retDecl = ` -> ${retVars.join(', ')}`;
    } else {
      const retVar = fn.returnType.kind === 'void' ? null : this.fresh();
      ctx.fnMode = { retVar };
      retDecl = retVar ? ` -> ${retVar}` : '';
    }
    const body: string[] = [];
    for (const s of fn.body) for (const l of this.lowerStmt(s, ctx)) body.push(l);
    const sig = `function ${this.userFnName(fn.key)}(${argNames.join(', ')})${retDecl}`;
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
        // UNSIGNED offset cap (matching the sibling top-level decoders + solc): a high-bit
        // "negative" offset must EMPTY-revert here, not wrap to a small in-bounds pointer (which
        // would later raise Panic 0x32 and diverge from solc's empty revert).
        out.push(`if gt(${off}, 0xffffffffffffffff) { revert(0, 0) }`);
        const dataPtr = this.fresh();
        out.push(`let ${dataPtr} := add(4, ${off})`);
        // the WHOLE N-word per-element offset table (no length word) must be readable: solc
        // requires dataPtr + N*32 <= calldatasize, not just the first word (a head that fits its
        // first word but runs past calldatasize for words 1..N-1 must EMPTY-revert, like solc).
        out.push(`if gt(add(${dataPtr}, ${p.type.length * 32}), calldatasize()) { revert(0, 0) }`);
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

    const bodyLines: string[] = [];
    if (fn.modifierWrap) {
      // Phase 5 (FULL MODIFIERS): at least one applied modifier has post-placeholder code. The wrapped
      // body Z is the synthesized body function userfn_<key> (forced internallyCalled); the dispatch
      // lowers modifierWrap (the nested pre/post block structure) where a single {modifierBody} marker
      // calls userfn_<key>(<decoded value params>) and captures its single result into `ret`. A
      // `return` inside Z sets userfn's ret and `leave`s, so it runs no further BODY code but returns
      // here, letting the enclosing post-code run BEFORE the value is ABI-encoded ONCE. The gate in the
      // analyzer (wrapModifiers) guarantees value-type params + a void/single value/bytes/string return.
      const args = fn.params.map((p) => this.ctxLookup(ctx, p.name)); // decoded value-param Yul names
      const isVoid = fn.returnType.kind === 'void';
      const ret = isVoid ? null : this.fresh();
      if (ret) bodyLines.push(`let ${ret} := 0`);
      ctx.modifierDispatch = { userFn: this.userFnName(fn.key), args, ret };
      for (const s of fn.modifierWrap) for (const l of this.lowerStmt(s, ctx)) bodyLines.push(l);
      // Encode the buffered return value ONCE (reuse the full single-value/bytes/string return encoder
      // by lowering a synthetic `return <rawReg ret>`). Void -> the empty return.
      if (ret) {
        for (const l of this.lowerStmt({ kind: 'return', value: { kind: 'rawReg', type: fn.returnType, reg: ret } }, ctx))
          bodyLines.push(l);
      } else {
        bodyLines.push('return(0, 0)');
      }
      if (fn.nonReentrant) {
        out.push(`if tload(${REENTRANCY_TSLOT}) { mstore(0, ${REENTRANCY_ERROR_WORD}) revert(0, 4) }`);
        out.push(`tstore(${REENTRANCY_TSLOT}, 1)`);
        for (const l of bodyLines) {
          if (l.trimStart().startsWith('return(')) out.push(`tstore(${REENTRANCY_TSLOT}, 0)`);
          out.push(l);
        }
      } else {
        out.push(...bodyLines);
      }
      return out;
    }

    const last = fn.body[fn.body.length - 1];
    const terminates =
      last !== undefined && (last.kind === 'return' || last.kind === 'revert' || last.kind === 'returnTuple');
    // Lower the body + fall-through epilogue into a local buffer; a @nonReentrant function then
    // brackets it with the transient mutex (resetting before every normal return).
    for (const s of fn.body) {
      for (const l of this.lowerStmt(s, ctx)) bodyLines.push(l);
    }
    if (!terminates && fn.returnTypes) {
      // fall-through default for a multi-value return: the zero tuple (value/bytes-string
      // components; an empty bytes/string is [offset][0]).
      const headWords = fn.returnTypes.length;
      let cursor = headWords * 32;
      for (let i = 0; i < fn.returnTypes.length; i++) {
        if (isBytesLike(fn.returnTypes[i]!)) {
          bodyLines.push(`mstore(${i * 32}, ${cursor})`, `mstore(${cursor}, 0)`);
          cursor += 32;
        } else bodyLines.push(`mstore(${i * 32}, 0)`);
      }
      bodyLines.push(`return(0, ${cursor})`);
    } else if (!terminates) {
      // void or fall-through: return the default-encoded value, matching Solidity
      // (falling off the end returns the zero value of the return type).
      if (fn.returnType.kind === 'void') bodyLines.push('return(0, 0)');
      else if (isBytesLike(fn.returnType) || fn.returnType.kind === 'array')
        bodyLines.push('mstore(0, 0x20)', 'mstore(0x20, 0)', 'return(0, 0x40)');
      else if (fn.returnType.kind === 'struct') {
        const words = abiHeadWords(fn.returnType);
        for (let j = 0; j < words; j++) bodyLines.push(`mstore(${j * 32}, 0)`);
        bodyLines.push(`return(0, ${words * 32})`);
      } else bodyLines.push('mstore(0, 0)', 'return(0, 0x20)');
    }

    if (fn.nonReentrant) {
      // ENTER: trip the guard if already entered (revert ReentrancyGuardReentrantCall()), else set
      // it. EXIT: reset the transient slot before every NORMAL return; a revert auto-rolls-back
      // transient storage per EIP-1153, so revert paths need no explicit reset.
      out.push(`if tload(${REENTRANCY_TSLOT}) { mstore(0, ${REENTRANCY_ERROR_WORD}) revert(0, 4) }`);
      out.push(`tstore(${REENTRANCY_TSLOT}, 1)`);
      for (const l of bodyLines) {
        if (l.trimStart().startsWith('return(')) out.push(`tstore(${REENTRANCY_TSLOT}, 0)`);
        out.push(l);
      }
    } else {
      out.push(...bodyLines);
    }
    return out;
  }

  /** Emit a validation guard for a decoded static value-type input, or '' if the
   *  full 32-byte word is always valid. Reverts with empty returndata on dirty
   *  input, matching Solidity's ABI decoder (verified against solc 0.8). */
  private validateInput(t: JethType, name: string): string {
    // an enum (branded uint8) decodes like uint8 but with the TIGHTER `< memberCount` check:
    // an out-of-range enum value reverts EMPTY in solc (ABI validation failure, not a Panic).
    const em = (t as { enumMembers?: string[] }).enumMembers;
    if (t.kind === 'uint' && em !== undefined) {
      return `if iszero(lt(${name}, ${em.length})) { revert(0, 0) }`;
    }
    switch (t.kind) {
      case 'uint':
        // uintN<256: high bits must be zero.
        return t.bits === 256 ? '' : `if gt(${name}, ${uintMaxHex(t.bits)}) { revert(0, 0) }`;
      case 'int':
        // intN<256: must be a valid sign-extension of its low bytes.
        return t.bits === 256 ? '' : `if iszero(eq(signextend(${t.bits / 8 - 1}, ${name}), ${name})) { revert(0, 0) }`;
      case 'bool':
        return `if gt(${name}, 1) { revert(0, 0) }`;
      case 'address':
        // high 96 bits must be zero.
        return `if shr(160, ${name}) { revert(0, 0) }`;
      case 'bytesN':
        // bytesN<32 is left-aligned: the low (32-size) bytes must be zero.
        return t.size === 32 ? '' : `if and(${name}, ${bytesNLowMaskHex(t.size)}) { revert(0, 0) }`;
      default:
        throw new UnsupportedError(`calldata decoding for type '${t.kind}' is not supported yet (Phase 4)`);
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
        // inside a multi-value INTERNAL function: set each return var (left-to-right) and leave.
        if (ctx.fnMode) {
          const vars = ctx.fnMode.retVars ?? [];
          // a value component is a plain register; an AGGREGATE component (struct / dynamic
          // value array / bytes / string) is materialized to a fresh MEMORY image and the
          // return var holds its pointer (same alias/copy rules as a single aggregate return).
          s.values.forEach((v, i) => {
            const rt = v.type;
            const isAgg = rt.kind === 'struct' || rt.kind === 'array' || isBytesLike(rt);
            const reg = isAgg ? this.aggArgToMemPtr(v, ctx, out) : this.lowerExpr(v, ctx, out);
            out.push(`${vars[i]} := ${reg}`);
          });
          out.push('leave');
          break;
        }
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
            // an aggregate return (struct / dynamic value array / bytes / string) yields a MEMORY
            // pointer (same alias/copy rules as an argument); a value return is a plain register.
            const rt = s.value.type;
            const isAgg = rt.kind === 'struct' || rt.kind === 'array' || isBytesLike(rt);
            const v = isAgg ? this.aggArgToMemPtr(s.value, ctx, out) : this.lowerExpr(s.value, ctx, out);
            out.push(`${ctx.fnMode.retVar} := ${v}`);
          }
          out.push('leave');
          break;
        }
        if (!s.value) {
          // a @receive/@fallback body's bare `return;` halts via stop() (byte-identical to solc), not
          // return(0,0); a normal void function returns empty calldata.
          out.push(ctx.specialEntry ? 'stop()' : 'return(0, 0)');
          break;
        }
        // `return p` (memory STATIC struct local), `return p.inner` (a nested struct field, a
        // sub-pointer), or `return this.helper()` (struct-returning internal call): the
        // ABI-unpacked memory image at the (sub)pointer IS the flat return blob. G9.
        if (
          isStaticType(s.value.type) &&
          (s.value.type.kind === 'struct' || s.value.type.kind === 'array') &&
          (s.value.kind === 'memAggregate' || s.value.kind === 'call' || s.value.kind === 'ternary' || s.value.kind === 'bn256')
        ) {
          // a STATIC memory-aggregate image (struct / fixed array): the image IS the flat return blob.
          // (A DYNAMIC-array call/ternary falls through to encodeMemArrayReturn below.)
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
        // `return ps[i]` (whole struct element of a calldata struct array): bounds-check i
        // (Panic 0x32), then re-encode the element from its calldata head into a fresh ABI
        // return blob (a STATIC struct flat, a DYNAMIC struct with the [0x20] wrapper).
        if (s.value.kind === 'cdStructArrayElem') {
          const { ptr, size } = this.returnCdArrayElem(s.value.arr, s.value.index, s.value.type, ctx, out);
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
          // a STATIC fixed-array LITERAL (return [a, b, c] typed Arr<T,N>, incl. nested static):
          // the ABI encoding is the N inline head words, with NO dynamic offset/length wrapper
          // (a dynamic-array return keeps the wrapper via encodeArrayReturn below). Writing the
          // literal at memory 0 and returning abiHeadWords*32 matches solc's uint256[N] layout.
          if (s.value.kind === 'arrayLit' && isStaticType(s.value.type)) {
            this.encodeArrayLitHead(s.value, 0, ctx, out);
            out.push(`return(0, ${abiHeadWords(s.value.type) * 32})`);
            break;
          }
          // a memory-array value produced by an expression (ternary `c ? xs : ys`, an incDec, or a
          // dynamic-array-returning internal call `return this.mk()`): lower to the [len][elems]
          // pointer, then encode the ABI [0x20][len][elems] return blob.
          if (
            s.value.kind === 'ternary' ||
            s.value.kind === 'incDec' ||
            (s.value.kind === 'call' && isDynamicType(s.value.type))
          ) {
            // FREEZE the pointer first: encodeMemArrayReturn reads it multiple times, and a `call`
            // lowers to an inline `userfn_x(...)` that would otherwise be re-invoked per use.
            const p = this.fresh();
            out.push(`let ${p} := ${this.lowerExpr(s.value, ctx, out)}`);
            const { ptr, size } = this.encodeMemArrayReturn(p, out);
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
          if (s.value.kind === 'arrayValue' && s.value.arr.base.kind === 'stateArray' && isDynamicType(s.value.type)) {
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
            if (s.value.kind === 'cdDynStructValue' && !s.value.place) {
              const { ptr, size } = this.echoParam(s.value.param, s.value.type, ctx, out);
              out.push(`return(${ptr}, ${size})`);
              break;
            }
            // a whole nested-struct field of a dyn-struct param (return o.inner): re-encode
            // it as a standalone tuple from its resolved calldata tuple-start, reusing the
            // unbounded recursive calldata->memory encoder (abiEncFromCd), the same codec the
            // whole-param echo (echoParam) and the abi.encode path use - so any inner field
            // shape (value-array, bytes/string, nested struct) is handled byte-identically.
            if (s.value.kind === 'cdDynStructValue' && s.value.place) {
              const { ptr, size } = this.echoCdDynField(s.value.place, s.value.type, ctx, out);
              out.push(`return(${ptr}, ${size})`);
              break;
            }
            // a DYNAMIC struct return: [head 0x20][tuple head/tail at byte 0x20].
            const { ptr, size } = this.encodeDynStructReturn(s.value, ctx, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // a whole STATIC nested-struct field of a dyn-struct param (return o.inner where
          // the inner struct is all-static): re-encode it flat (no head wrapper) from its
          // resolved calldata tuple-start via the recursive calldata->memory codec.
          if (s.value.kind === 'cdDynStructValue' && s.value.place) {
            const { ptr, size } = this.echoCdDynField(s.value.place, s.value.type, ctx, out);
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
          if (s.value.kind === 'structNew' && this.aggHasNonInlineField(s.value)) {
            // a constructed struct with a non-inline aggregate field: build the ABI image in FRESH
            // memory (the source materialization would clobber the memory-0 scratch), then return it.
            const ptr = this.allocAggToMem(s.value, ctx, out);
            out.push(`return(${ptr}, ${abiHeadWords(s.value.type) * 32})`);
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
          } else if (s.init.kind === 'mapStorageValue') {
            // a storage mapping struct value (this.m[k]) COPIED into a fresh image
            out.push(
              `let ${name} := ${this.allocAggFromStorage(s.init.type, this.mappingSlot(s.init.baseSlot, s.init.keys, ctx, out), out)}`,
            );
          } else if (s.init.kind === 'structArrayElem') {
            // a storage struct-array element (this.arr[i]) COPIED into a fresh image (also the for-of desugar)
            out.push(
              `let ${name} := ${this.allocAggFromStorage(s.init.type, this.structArrayElemSlot(s.init.arr, s.init.index, ctx, out), out)}`,
            );
          } else if (s.init.kind === 'cdAggregateValue') {
            out.push(`let ${name} := ${this.allocAggFromCalldata(s.init.param, s.init.type, ctx, out)}`);
          } else if (s.init.kind === 'abiDecode') {
            // a static fixed array Arr<T,N> from abi.decode: the decoded flat ABI image is the local.
            out.push(`let ${name} := ${this.aggArgToMemPtr(s.init, ctx, out)}`);
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
        if (s.type.kind === 'array' && s.type.length === undefined && s.init) {
          // G9: a DYNAMIC value-array memory local (let a: u256[] = p / xs / this.arr). The
          // register holds a [len][elems] pointer: aggArgToMemPtr ALIASES a memory source
          // (pointer copy, matching Solidity references) and COPIES a calldata/storage/literal
          // source into a fresh image (a calldata value array MASKS dirty elements, like solc).
          out.push(`let ${name} := ${this.aggArgToMemPtr(s.init, ctx, out)}`);
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
          // whole-struct write: a constructed value (structNew), a memory/calldata struct
          // (this.d = m / this.d = calldataParam), or a storage-to-storage copy (this.d = this.e).
          this.storeStructTo(s.target.type, s.value, String(s.target.slot), ctx, out);
          break;
        }
        if (s.target.kind === 'mapping' && s.target.type.kind === 'struct') {
          // this.m[k] = <struct>: write the constructed/copied struct into the runtime
          // keccak(key.base) mapping slot (writeStruct/copyStruct clear dynamic-field
          // tails per field, byte-identical to solc).
          const dst = this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out);
          this.storeStructTo(s.target.type, s.value, dst, ctx, out);
          break;
        }
        // whole DYNAMIC-array assignment into storage: this.a = this.b (storage source) or
        // this.a = xs / this.m[k] = xs (a MEMORY value-array source), or a struct field
        // this.s.arr = xs (a storage place at the field's length slot). copyArrayValueIntoStorage
        // deep-copies (resize + element copy + tail clear) from either source.
        if (
          (s.target.kind === 'state' || s.target.kind === 'mapping' || s.target.kind === 'place') &&
          s.target.type.kind === 'array' &&
          s.target.type.length === undefined
        ) {
          const dstLenSlot =
            s.target.kind === 'mapping'
              ? this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out)
              : s.target.kind === 'place'
                ? this.lowerPlace(s.target.path, ctx, out).slot
                : String(s.target.slot);
          this.copyArrayValueIntoStorage(s.target.type.element, s.value, dstLenSlot, ctx, out);
          break;
        }
        // whole FIXED-array assignment into storage: this.g = this.src (storage source) or
        // this.g = [a, b, c] (array literal). Static-element arrays copy their slot footprint
        // verbatim; dynamic-element fixed arrays deep-copy per element.
        if (
          (s.target.kind === 'state' || s.target.kind === 'place' || s.target.kind === 'mapping') &&
          s.target.type.kind === 'array' &&
          s.target.type.length !== undefined
        ) {
          const dstBase =
            s.target.kind === 'state'
              ? String(s.target.slot)
              : s.target.kind === 'mapping'
                ? this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out)
                : this.lowerPlace(s.target.path, ctx, out).slot;
          if (s.value.kind === 'arrayLit') {
            this.writeArrayLit(s.value, dstBase, ctx, out);
          } else if (s.value.kind === 'memAggregate' || s.value.kind === 'cdAggregateValue') {
            // a whole MEMORY fixed-array local / CALLDATA fixed-array param: transcode its ABI-unpacked
            // image (one word per leaf) into packed storage, exactly like a whole memory struct assign.
            this.storeStaticAggFromMem(s.target.type, this.aggToMemPtr(s.value, ctx, out), dstBase, out);
          } else {
            this.copyFixedArray(s.target.type, this.fixedArraySrcBase(s.value, ctx, out), dstBase, out);
          }
          break;
        }
        if (s.target.kind === 'place' && s.target.type.kind === 'struct') {
          // this.o.inner = <struct> (whole nested-struct field): fold the path to the
          // field slot, then writeStruct (literal) / copyStruct (storage copy).
          const p = this.lowerPlace(s.target.path, ctx, out);
          this.storeStructTo(s.target.type, s.value, p.slot, ctx, out);
          break;
        }
        if (s.target.kind === 'place') {
          // solc evaluates the RHS before the LHS location (incl every index/key in the path). Bind the
          // value FIRST so a side-effecting path index (aa[inc()][inc()] = inc()) does not run ahead of
          // a side-effecting RHS; the optimizer collapses the temp for pure operands (byte-identical).
          const value = this.fresh();
          out.push(`let ${value} := ${this.lowerExpr(s.value, ctx, out)}`);
          const p = this.lowerPlace(s.target.path, ctx, out);
          // a packed element with a RUNTIME byte offset uses packedStore; otherwise the
          // constant-offset storeState (also covers a literal packed index).
          if (p.byteShift !== undefined) this.packedStore(s.target.type, p.slot, p.byteShift, value, out);
          else for (const l of this.storeState(s.target.type, p.slot, p.offset, value)) out.push(l);
          break;
        }
        if (s.target.kind === 'memField' || s.target.kind === 'memElem') {
          // p.x = v / a[i] = v on a memory aggregate local: bounds-checked memory store. Bind the RHS
          // FIRST (solc evaluates it before the LHS index); the optimizer collapses the temp for pure
          // operands, so the bytecode is unchanged for the common case.
          const value = this.fresh();
          out.push(`let ${value} := ${this.lowerExpr(s.value, ctx, out)}`);
          this.lowerAssignValue(s.target, value, ctx, out);
          break;
        }
        if (s.target.kind === 'byteIndexStore') {
          // this.b[i] = <bytes1>: bounds-checked read-modify-write of byte i in a storage `bytes`.
          // The bytes location (direct var / struct field / mapping value / array elem) resolves to
          // its slot exactly like the whole-value assignment.
          // solc evaluates the RHS byte value FIRST, then the location and the index. Bind v first.
          const v = this.fresh();
          out.push(`let ${v} := ${this.lowerExpr(s.value, ctx, out)}`);
          const bslot = this.bytesLocSlot(s.target.loc, ctx, out);
          const i = this.fresh();
          out.push(`let ${i} := ${this.lowerExpr(s.target.index, ctx, out)}`);
          out.push(`${this.strByteSet()}(${bslot}, ${i}, ${v})`);
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
          // this.m[k] = <bytes/string>: materialize the RHS value FIRST (solc evaluates the RHS before
          // the LHS key - a side-effecting key must not run ahead of it), then compute the runtime
          // mapping slot and overwrite-store (storeDynamic clears the old tail).
          const ref = this.lowerDynamic(s.value, ctx, out);
          const slot = this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out);
          this.storeDynamic(slot, ref, out);
          break;
        }
        if (s.target.kind === 'strArrayElem') {
          // this.ss[i] = <bytes/string>: materialize the RHS FIRST (solc evaluates the RHS before the
          // LHS index), then bounds-check i and overwrite the element header at keccak(lenSlot)+i
          // (storeStrMem clears the old tail).
          const ref = this.lowerDynamic(s.value, ctx, out);
          const slot = this.strArrayElemSlot(s.target.arr, s.target.index, ctx, out);
          this.storeDynamic(slot, ref, out);
          break;
        }
        if (s.target.kind === 'dynPlace') {
          // this.d.s = <bytes/string> (storage dynamic-struct field): materialize the RHS FIRST (solc
          // evaluates the RHS before the LHS path's index/key), then fold the path to the field's slot
          // (struct base + field slot, index/key bound-checks applied) and overwrite-store the value
          // (storeStrMem clears the old tail, identical to solc).
          const ref = this.lowerDynamic(s.value, ctx, out);
          const p = this.lowerPlace(s.target.path, ctx, out);
          this.storeDynamic(p.slot, ref, out);
          break;
        }
        if (s.target.kind === 'arrayElem' && s.target.type.kind === 'array') {
          if (s.target.type.length !== undefined) {
            // this.dd[i] = <array> (a whole FIXED inner-array element): copy the static aggregate
            // into the element BASE slot (base + i*storageSlotCount), like the whole-array assign.
            const elemBase = this.structArrayElemSlot(s.target.arr, s.target.index, ctx, out);
            if (s.value.kind === 'arrayLit') this.writeArrayLit(s.value, elemBase, ctx, out);
            else this.copyFixedArray(s.target.type, this.fixedArraySrcBase(s.value, ctx, out), elemBase, out);
            break;
          }
          // this.dd[i] = <array> (a whole DYNAMIC inner array element): the element slot
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
          this.storeStructTo(s.target.type, s.value, elemSlot, ctx, out);
          break;
        }
        if (s.target.kind === 'arrayElem') {
          // solc evaluates the RHS before the LHS location (incl its index). Bind the value FIRST so
          // a side-effecting index (a[inc()] = inc()) does not run ahead of a side-effecting RHS; for
          // pure operands the solc Yul optimizer collapses the temp, so the bytecode is unchanged.
          const value = this.fresh();
          out.push(`let ${value} := ${this.lowerExpr(s.value, ctx, out)}`);
          const ref = this.lowerArrayRef(s.target.arr, ctx, out); // storage/fixed (analyzer rejects calldata)
          const idx = this.fresh();
          out.push(`let ${idx} := ${this.lowerExpr(s.target.index, ctx, out)}`);
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
        if (s.target.kind === 'local' && s.target.type.kind === 'struct') {
          // Re-point a struct MEMORY local by assignment: `s = P(...)` / `s = this.p` / `s = other`.
          // Solidity rebinds the local to a fresh image - a constructed struct (structNew) builds
          // fresh; a STORAGE struct (structValue / mapStorageValue / structArrayElem / placeRead) or a
          // CALLDATA struct param (cdAggregateValue) is COPIED into fresh memory (a later `s.f = ...`
          // must NOT alias the source); another memory struct (memAggregate) or a struct-returning
          // call ALIASES the pointer (a memory reference). A DYNAMIC-field struct uses the
          // pointer-headed image builder, a static struct the flat ABI-image materializer - exactly
          // the helpers the `let s: P = <src>` DECLARATION path uses, so the image is byte-identical.
          const reg = this.ctxLookup(ctx, s.target.varName);
          const ptr = isDynamicType(s.target.type)
            ? this.buildDynStructLocal(s.target.type, s.value, ctx, out)
            : this.aggToMemPtr(s.value, ctx, out);
          out.push(`${reg} := ${ptr}`);
          break;
        }
        // Bind the RHS before resolving a mapping key (or any keyed/indexed target below) so a
        // side-effecting key (m[inc()] = inc()) does not run before a side-effecting RHS - solc
        // evaluates the RHS first. The optimizer collapses the temp for pure operands (byte-identical).
        const valExpr = this.lowerExpr(s.value, ctx, out);
        const value = this.fresh();
        out.push(`let ${value} := ${valExpr}`);
        if (s.target.kind === 'local') {
          out.push(`${this.ctxLookup(ctx, s.target.varName)} := ${value}`);
        } else if (s.target.kind === 'immutableStaged') {
          // this.<imm> = v in the constructor: write the staged shadow (baked via setimmutable).
          out.push(`${ctx.immStaged!.get(s.target.name)!} := ${value}`);
        } else if (s.target.kind === 'mapping') {
          const slot = this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out);
          for (const l of this.storeState(s.target.type, slot, 0, value)) out.push(l);
        } else {
          for (const l of this.storeState(s.target.type, String(s.target.slot), s.target.offset, value)) out.push(l);
        }
        break;
      }
      case 'exprStmt': {
        // a bytes-reference expression as a statement (a bare `addr.call({...});` discarding the
        // returndata) is lowered via lowerDynamic: the call + success checks still run, the value
        // is dropped. lowerExpr would throw (a reference value in a non-reference context).
        if (s.expr.kind === 'extCall') {
          this.lowerDynamic(s.expr, ctx, out);
          break;
        }
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
      case 'tupleDecl': {
        // `let [a, , c] = src`: bind a fresh local per non-skipped component.
        const temps = this.lowerDestructureSource(s.source, ctx, out);
        s.names.forEach((nm, i) => {
          if (nm === null) return;
          const ln = this.freshLocal(nm);
          out.push(`let ${ln} := ${temps[i]}`);
          this.ctxDeclare(ctx, nm, ln);
        });
        break;
      }
      case 'tupleAssign': {
        // `[a, , c] = src`: RHS fully evaluated into temps, then store into each non-skipped
        // target by reusing the assign lowering (feed the temp as a rawReg value).
        const temps = this.lowerDestructureSource(s.source, ctx, out);
        s.targets.forEach((tgt, i) => {
          if (tgt === null) return;
          for (const l of this.lowerStmt(
            { kind: 'assign', target: tgt, value: { kind: 'rawReg', type: tgt.type, reg: temps[i]! } },
            ctx,
          ))
            out.push(l);
        });
        break;
      }
      case 'block': {
        out.push('{');
        for (const l of this.lowerBlock(s.body, ctx)) out.push('  ' + l);
        out.push('}');
        break;
      }
      case 'modifierBody': {
        // Phase 5 (full modifiers): the `_;` placeholder inside a dispatch-lowered modifierWrap. Call
        // the synthesized body function userfn_<key>(<decoded params>); a `return` inside it sets the
        // userfn's ret var and leaves (running no more body code) but returns control here so the
        // ENCLOSING post-code still runs. Capture the single result into `ret` (void -> a bare call).
        const md = ctx.modifierDispatch;
        if (!md) throw new UnsupportedError('modifierBody marker lowered outside a modifier dispatch');
        const call = `${md.userFn}(${md.args.join(', ')})`;
        out.push(md.ret === null ? call : `${md.ret} := ${call}`);
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
      case 'revertWith': {
        // bubble raw bytes as the revert payload: revert(add(b,0x20), mload(b)).
        const { mp } = this.toMemory(this.lowerDynamic(s.value, ctx, out), out);
        out.push(`revert(add(${mp}, 0x20), mload(${mp}))`);
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
      case 'bytesPush': {
        const slot = this.bytesLocSlot(s.loc, ctx, out);
        const v = s.value ? this.lowerExpr(s.value, ctx, out) : '0';
        out.push(`${this.strPush()}(${slot}, ${v})`);
        break;
      }
      case 'bytesPop': {
        const slot = this.bytesLocSlot(s.loc, ctx, out);
        out.push(`${this.strPop()}(${slot})`);
        break;
      }
      case 'tryCatch': {
        this.lowerTryCatch(s, ctx, out);
        break;
      }
    }
    return out;
  }

  /** Feature 2: lower a try/catch around a high-level interface call. Mirrors solc:
   *    ok, ret := <CALL/STATICCALL, returndata captured, NO auto-bubble>
   *    switch ok
   *    case 0 { <catch: bind e=ret + this.reason/this.panic; run catch body> }
   *    default {
   *      if iszero(extcodesize(addr)) { revert(0, 0) }   // a non-contract -> OUTER revert empty
   *      <decode ret into the bound success vars (short returndata -> OUTER revert empty)>
   *      <run try body>
   *    } */
  private lowerTryCatch(s: Stmt & { kind: 'tryCatch' }, ctx: LowerCtx, out: string[]): void {
    // the controlling call WITHOUT bubble/codeGuard (the analyzer cleared both): we get ok + the
    // captured returndata blob + the addr register (for the in-ok-branch extcodesize guard).
    const { okReg, dataPtr, addrReg } = this.emitExtCall(s.call, ctx, out);
    out.push(`switch ${okReg}`);

    // ---- failure (ok==0): the catch body ----
    out.push('case 0 {');
    const catchOut: string[] = [];
    this.ctxPush(ctx);
    // `this.reason` / `this.panic` are soft-decoded from the verbatim returndata blob bound here.
    this.ctxDeclare(ctx, EXT_CALL_DATA_BINDING, dataPtr);
    if (s.catchName !== null) {
      // `e: bytes` is a memory bytes local; its register IS the [len][data] pointer (the captured blob).
      const ev = this.freshLocal(s.catchName);
      catchOut.push(`let ${ev} := ${dataPtr}`);
      this.ctxDeclare(ctx, s.catchName, ev);
    }
    for (const l of this.lowerBlock(s.catchBody, ctx)) catchOut.push(l);
    this.ctxPop(ctx);
    for (const l of catchOut) out.push('  ' + l);
    out.push('}');

    // ---- success (ok==1): codeGuard, decode the return, run the try body ----
    out.push('default {');
    const okOut: string[] = [];
    okOut.push(`if iszero(extcodesize(${addrReg})) { revert(0, 0) }`);
    this.ctxPush(ctx);
    if (s.retTypes.length > 0) {
      // decode the captured returndata blob into one register per bound component (short/empty
      // returndata reverts EMPTY as an OUTER revert, via lowerAbiDecode's blob bounds). The data
      // source is the EXT_CALL_DATA_BINDING (the blob pointer), reusing the addr.call decode path.
      this.ctxDeclare(ctx, EXT_CALL_DATA_BINDING, dataPtr);
      const dataExpr: Expr = { kind: 'callData', type: { kind: 'bytes' } };
      const temps = this.lowerAbiDecode(dataExpr, s.retTypes, ctx, okOut);
      s.retNames.forEach((nm, i) => {
        if (nm === null) return;
        const ln = this.freshLocal(nm);
        okOut.push(`let ${ln} := ${temps[i]}`);
        this.ctxDeclare(ctx, nm, ln);
      });
    }
    for (const l of this.lowerBlock(s.tryBody, ctx)) okOut.push(l);
    this.ctxPop(ctx);
    for (const l of okOut) out.push('  ' + l);
    out.push('}');
  }

  /** Feature 2: SOFT-decode `this.reason` (the Error(string) message) from the catch returndata blob.
   *  Returns a memory [len][data] pointer: the decoded string when the blob is a well-formed
   *  Error(string), else an EMPTY string (it MUST NOT hard-revert on a malformed payload - solc yields
   *  "" there). Byte-identical to solc's `catch Error(string memory reason)` extraction: pre-validate
   *  EXACTLY the bounds abiDecFromMem (the abi.decode string codec) would check for a string at e[4:]
   *  decoded as (string); if all pass, the hard decode cannot revert, so reuse abiDecFromMem. */
  private lowerCatchReason(ctx: LowerCtx, out: string[]): string {
    const blob = this.ctxLookup(ctx, EXT_CALL_DATA_BINDING); // [len][e bytes]
    // default result: a fresh EMPTY string image (length 0 = one zeroed word).
    const rptr = this.fresh();
    out.push(`let ${rptr} := ${this.alloc()}(0x20)`);
    out.push(`mstore(${rptr}, 0)`);
    // e-bytes region: blobData = add(blob, 0x20) (start of e), eEnd = add(blobData, len_e).
    const blobData = this.fresh();
    out.push(`let ${blobData} := add(${blob}, 0x20)`);
    const eEnd = this.fresh();
    out.push(`let ${eEnd} := add(${blobData}, mload(${blob}))`);
    // Treat e[4:] as the abi.decode blob of `(string)`. innerData = e[4:] start = blobData + 4.
    // Condition 1: len_e >= 4 (selector) AND the outer 1-word head fits: innerData + 32 <= eEnd
    //   (lowerAbiDecode's `gt(add(blobData, 32), blobEnd)` over the inner blob; here innerData = blobData+4).
    // Condition 2: the selector == 0x08c379a0.
    out.push(`if and(iszero(lt(mload(${blob}), 36)), eq(shr(224, mload(${blobData})), 0x08c379a0)) {`);
    const inner: string[] = [];
    const innerData = this.fresh();
    inner.push(`let ${innerData} := add(${blobData}, 4)`); // e[4:] = the (string) tuple blob
    // offset word (relative to innerData), bounded like lowerAbiDecode's dynamic component.
    const so = this.fresh();
    inner.push(`let ${so} := mload(${innerData})`);
    const se = this.fresh();
    inner.push(`let ${se} := add(${innerData}, ${so})`);
    // length word in-blob: `se + 32 <= eEnd` (cdElemHeadBytes(string) = 32). offset cap: so <= 2^64-1.
    inner.push(`if and(iszero(gt(${so}, 0xffffffffffffffff)), iszero(gt(add(${se}, 32), ${eEnd}))) {`);
    const lvl2: string[] = [];
    const slen = this.fresh();
    lvl2.push(`let ${slen} := mload(${se})`); // the string byte length
    // abiDecFromMem(string) bounds: len <= 2^64-1 (Panic 0x41) AND data fits: se + 0x20 + len <= eEnd.
    lvl2.push(`if and(iszero(gt(${slen}, 0xffffffffffffffff)), iszero(gt(add(add(${se}, 0x20), ${slen}), ${eEnd}))) {`);
    const ok: string[] = [];
    // all bounds pass -> the hard string decode is guaranteed not to revert; reuse abiDecFromMem.
    const dst = this.fresh();
    ok.push(`let ${dst} := mload(0x40)`);
    const sz = this.abiDecFromMem({ kind: 'string' }, se, dst, eEnd, ok);
    ok.push(`mstore(0x40, add(${dst}, ${sz}))`);
    ok.push(`${rptr} := ${dst}`);
    for (const l of ok) lvl2.push('  ' + l);
    lvl2.push('}');
    for (const l of lvl2) inner.push('  ' + l);
    inner.push('}');
    for (const l of inner) out.push('  ' + l);
    out.push('}');
    return rptr;
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
      case 'panic':
        return [`${this.panic()}(0x${r.code.toString(16).padStart(2, '0')})`];
      case 'errorString':
        return this.lowerErrorString(r.message);
      case 'errorStringDyn': {
        // Error(string) from a runtime value: build the blob lazily inside the
        // revert. selector + [0x20][len][padded data]. Verified byte-exact.
        const lines: string[] = [];
        const ref = this.lowerDynamic(r.value, ctx, lines);
        const { mp, len } = this.toMemory(ref, lines);
        const padded = `and(add(${len}, 0x1f), not(0x1f))`;
        // Build the Error(string) blob at the FREE POINTER (past the materialized source), NOT at the
        // memory-0 scratch: when the source string was freshly allocated (a string literal, a ternary
        // selecting a literal), the scratch blob's data region [0x44, 0x44+padded) overlaps that buffer,
        // and the Yul backend mis-lowers the overlapping mcopy across a switch (empty revert for len>=61).
        const p = this.fresh();
        lines.push(`let ${p} := mload(0x40)`);
        lines.push(`mstore(${p}, shl(224, 0x08c379a0))`);
        lines.push(`mstore(add(${p}, 4), 0x20)`);
        lines.push(`mstore(add(${p}, 0x24), ${len})`);
        lines.push(`mcopy(add(${p}, 0x44), add(${mp}, 0x20), ${padded})`);
        lines.push(`revert(${p}, add(0x44, ${padded}))`);
        return lines;
      }
      case 'custom': {
        // Evaluate args eagerly into temps so they run before any cond guard
        // (matches solc: a custom-error arg can revert even when require passes).
        // Fast path: every arg is a static VALUE (one word each, no struct/array/dynamic).
        if (!r.args.some((a) => isDynamicType(a.type) || a.type.kind === 'struct' || a.type.kind === 'array')) {
          const argTemps = r.args.map((a) => {
            const v = this.lowerExpr(a, ctx, out);
            const t = this.fresh();
            out.push(`let ${t} := ${v}`);
            return t;
          });
          const helper = this.errorRevert(argTemps.length);
          return [`${helper}(0x${r.decl.selector}${argTemps.map((a) => ', ' + a).join('')})`];
        }
        // head/tail: a static value is one head word; a static struct / fixed-array occupies its
        // abiHeadWords leaf words INLINE in the head; a dynamic bytes/string/array writes a head
        // offset word + a tail blob. Tail offsets are relative to the args region (calldata byte 4).
        const headWordsOf = (t: JethType): number => (isDynamicType(t) ? 1 : abiHeadWords(t));
        const lines: string[] = [];
        type LA =
          | { dyn: 'static'; word: string }
          | { dyn: 'agg'; mp: string; words: number }
          | { dyn: 'bytes'; mp: string; len: string }
          | { dyn: 'array'; mp: string; size: string };
        const lowered: LA[] = r.args.map((a): LA => {
          if (isBytesLike(a.type)) {
            const { mp, len } = this.toMemory(this.lowerDynamic(a, ctx, lines), lines);
            return { dyn: 'bytes', mp, len };
          }
          if (a.type.kind === 'array' && a.type.length === undefined) {
            const { mp, size } = this.materializeArrayArg(a, ctx, lines);
            return { dyn: 'array', mp, size };
          }
          if (a.type.kind === 'struct' && isDynamicType(a.type)) {
            // a DYNAMIC struct: a head OFFSET word + its self-contained head/tail blob in the tail.
            // encodeDynStructToBlob returns {mp, size} of the fully ABI-encoded struct (its own
            // head+tail), identical in shape to the array tail blob, so reuse the 'array' path
            // (offset word + verbatim mcopy). Materialized NOW so it cannot alias the head buffer.
            const { mp, size } = this.encodeDynStructToBlob(a, ctx, lines);
            return { dyn: 'array', mp, size };
          }
          if (a.type.kind === 'struct' || (a.type.kind === 'array' && a.type.length !== undefined)) {
            // a STATIC struct / fixed-array: materialize its ABI-unpacked image NOW (before the head
            // buffer is captured, so it cannot alias), then mcopy its leaf words inline into the head.
            return { dyn: 'agg', mp: this.aggToMemPtr(a, ctx, lines), words: abiHeadWords(a.type) };
          }
          const t = this.fresh();
          lines.push(`let ${t} := ${this.lowerExpr(a, ctx, lines)}`);
          return { dyn: 'static', word: t };
        });
        const headSize = r.args.reduce((n, a) => n + headWordsOf(a.type), 0) * 32;
        const p = this.fresh();
        lines.push(`let ${p} := mload(0x40)`);
        lines.push(`mstore(${p}, shl(224, 0x${r.decl.selector}))`);
        const cur = this.fresh();
        lines.push(`let ${cur} := ${headSize}`); // byte offset (rel byte 4) of next tail
        let hw = 0; // running head-word index
        lowered.forEach((a) => {
          const headAt = `add(${p}, ${4 + hw * 32})`;
          if (a.dyn === 'static') {
            lines.push(`mstore(${headAt}, ${a.word})`);
            hw += 1;
          } else if (a.dyn === 'agg') {
            // static aggregate: its abiHeadWords leaf words inline (no offset, no tail).
            lines.push(`mcopy(${headAt}, ${a.mp}, ${a.words * 32})`);
            hw += a.words;
          } else if (a.dyn === 'bytes') {
            lines.push(`mstore(${headAt}, ${cur})`);
            const padded = this.fresh();
            lines.push(`let ${padded} := and(add(${a.len}, 0x1f), not(0x1f))`);
            lines.push(`mstore(add(${p}, add(4, ${cur})), ${a.len})`);
            lines.push(`mcopy(add(${p}, add(4, add(${cur}, 0x20))), add(${a.mp}, 0x20), ${padded})`);
            lines.push(`${cur} := add(${cur}, add(0x20, ${padded}))`);
            hw += 1;
          } else {
            // array tail blob [len][elements...] is already ABI-encoded: copy it verbatim.
            lines.push(`mstore(${headAt}, ${cur})`);
            lines.push(`mcopy(add(${p}, add(4, ${cur})), ${a.mp}, ${a.size})`);
            lines.push(`${cur} := add(${cur}, ${a.size})`);
            hw += 1;
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
    type Part =
      | { word: string }
      | { mp: string; len: string }
      | { mp: string; size: string }
      | { inline: true; mp: string; words: number };
    const data: Part[] = [];
    ev.params.forEach((p, i) => {
      const arg = args[i]!;
      if (p.indexed && isBytesLike(p.type)) {
        // an indexed bytes/string topic is keccak256 of the CONTENT bytes (G4), not the value.
        const { mp, len } = this.toMemory(this.lowerDynamic(arg, ctx, out), out);
        const topic = this.fresh();
        out.push(`let ${topic} := keccak256(add(${mp}, 0x20), ${len})`);
        idxVals.push(topic);
      } else if (p.indexed && p.type.kind === 'struct' && isDynamicType(p.type)) {
        // an indexed DYNAMIC struct topic is keccak256 over the recursively FLATTENED payload
        // (static leaves inline; bytes/string -> content padded to a word, no length; dyn value-
        // array -> element words, no length; nested struct -> members concatenated). This is NOT
        // abi.encode (no offsets, no length words). Verified byte-identical to solc.
        const { mp, size } = this.encodeTopicBlob(arg, ctx, out);
        const topic = this.fresh();
        out.push(`let ${topic} := keccak256(${mp}, ${size})`);
        idxVals.push(topic);
      } else if (
        p.indexed &&
        isStaticType(p.type) &&
        (p.type.kind === 'struct' || (p.type.kind === 'array' && p.type.length !== undefined))
      ) {
        // an indexed STATIC fixed-array / struct topic is keccak256(abi.encode(value)) = keccak over
        // the padded leaf words (no length word). Verified byte-identical to solc.
        const { mp, size } = this.materializeStaticAggToMem(arg, ctx, out);
        const topic = this.fresh();
        out.push(`let ${topic} := keccak256(${mp}, ${size})`);
        idxVals.push(topic);
      } else if (p.indexed && p.type.kind === 'array') {
        // an indexed DYNAMIC value-element array topic is keccak256 of the element words (the
        // ABI tail minus its length word), not the value. Verified byte-identical to solc.
        const { mp, size } = this.materializeArrayArg(arg, ctx, out);
        const topic = this.fresh();
        out.push(`let ${topic} := keccak256(add(${mp}, 0x20), sub(${size}, 0x20))`);
        idxVals.push(topic);
      } else if (p.indexed) {
        idxVals.push(this.lowerExpr(arg, ctx, out)); // a static-value indexed topic
      } else if (isBytesLike(p.type)) {
        const ref = this.lowerDynamic(arg, ctx, out);
        data.push(this.toMemory(ref, out)); // materialize before the buffer is allocated
      } else if (isStaticType(p.type) && (p.type.kind === 'struct' || p.type.kind === 'array')) {
        // a non-indexed STATIC struct / fixed-array: encoded INLINE in the data head (abiHeadWords
        // leaf words, no offset/tail). aggToMemPtr materializes the ABI-unpacked image from any source
        // (a constructor, a memory/storage aggregate), then we mcopy it into the head.
        data.push({ inline: true, mp: this.aggToMemPtr(arg, ctx, out), words: abiHeadWords(p.type) });
      } else if (p.type.kind === 'struct') {
        // a non-indexed DYNAMIC struct: a head offset + its head/tail blob in the tail.
        data.push(this.encodeDynStructToBlob(arg, ctx, out));
      } else if (p.type.kind === 'array') {
        data.push(this.materializeArrayArg(arg, ctx, out)); // {mp, size}: ABI tail blob (G3)
      } else {
        data.push({ word: this.lowerExpr(arg, ctx, out) });
      }
    });
    // anonymous events carry NO topic0 (the signature hash); only the indexed params are topics
    // (LOG0 when there are none). Non-anonymous events always lead with topic0.
    const topicArgs = ev.anonymous ? idxVals : [`0x${ev.topic0}`, ...idxVals];
    const n = topicArgs.length;
    const topics = topicArgs.length ? `, ${topicArgs.join(', ')}` : '';
    const lines: string[] = [];
    if (data.length === 0) {
      lines.push(`log${n}(0, 0${topics})`);
      return lines;
    }
    // head word count: a value -> 1 word; a STATIC struct/fixed-array -> abiHeadWords inline; a
    // dynamic (bytes/string/array) -> 1 word (an offset into the tail).
    const headWords = data.reduce((acc, d) => acc + ('inline' in d ? d.words : 1), 0);
    const headSize = 32 * headWords;
    if (data.every((d) => 'word' in d || 'inline' in d)) {
      // all-static data: head only (value words + inline static-aggregate blobs), no tail.
      const m = this.fresh();
      lines.push(`let ${m} := mload(0x40)`);
      let hw = 0;
      for (const d of data) {
        const head = hw === 0 ? m : `add(${m}, ${32 * hw})`;
        if ('word' in d) {
          lines.push(`mstore(${head}, ${d.word})`);
          hw += 1;
        } else {
          lines.push(`mcopy(${head}, ${(d as { mp: string }).mp}, ${(d as { words: number }).words * 32})`);
          hw += (d as { words: number }).words;
        }
      }
      lines.push(`log${n}(${m}, ${headSize}${topics})`);
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
    let hw = 0;
    for (const d of data) {
      const head = hw === 0 ? ptr : `add(${ptr}, ${32 * hw})`;
      if ('word' in d) {
        lines.push(`mstore(${head}, ${d.word})`);
        hw += 1;
      } else if ('inline' in d) {
        // a STATIC struct/fixed-array: leaf words inline in the head (no offset/tail).
        lines.push(`mcopy(${head}, ${d.mp}, ${d.words * 32})`);
        hw += d.words;
      } else if ('len' in d) {
        const pad = `and(add(${d.len}, 0x1f), not(0x1f))`;
        lines.push(`mstore(${head}, sub(${cursor}, ${ptr}))`);
        lines.push(`mstore(${cursor}, ${d.len})`);
        lines.push(`mcopy(add(${cursor}, 0x20), add(${d.mp}, 0x20), ${pad})`);
        lines.push(`${cursor} := add(${cursor}, add(0x20, ${pad}))`);
        hw += 1;
      } else {
        // array tail blob [len][elements...]: copy verbatim (already ABI-encoded).
        lines.push(`mstore(${head}, sub(${cursor}, ${ptr}))`);
        lines.push(`mcopy(${cursor}, ${d.mp}, ${d.size})`);
        lines.push(`${cursor} := add(${cursor}, ${d.size})`);
        hw += 1;
      }
    }
    lines.push(`log${n}(${ptr}, ${total}${topics})`);
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
      case 'rawReg':
        return e.reg; // a pre-computed Yul register (tuple destructuring feeds it into the assign lowering)
      case 'literalBool':
        return e.value ? '1' : '0';
      case 'localRead':
        return this.ctxLookup(ctx, e.name);
      case 'stateRead':
        return this.loadState(e.type, String(e.slot), e.offset);
      case 'immutableRead':
        // a runtime read of an @immutable: the value baked into the code by setimmutable.
        return `loadimmutable("${e.name}")`;
      case 'immutableStagedRead':
        // a read inside the constructor body: the staged shadow (a jeth_constructor return var).
        return ctx.immStaged!.get(e.name)!;
      case 'unary':
        return this.lowerUnary(e, ctx, out);
      case 'binary':
        return this.lowerBinary(e, ctx, out);
      case 'ternary': {
        // an aggregate ternary (static struct / static fixed array): materialize the taken
        // branch to a memory image (allocAggFromStorage copy / allocAggToMem / memAggregate
        // alias), then select the image POINTER with a short-circuit switch.
        if (e.type.kind === 'struct' || (e.type.kind === 'array' && e.type.length !== undefined)) {
          // a DYNAMIC-field struct uses the pointer-headed image builder (buildDynStructLocal);
          // a static aggregate uses the flat ABI-image materializer (aggToMemPtr).
          const dynStruct = e.type.kind === 'struct' && isDynamicType(e.type);
          const matPtr = (br: Expr, o: string[]): string =>
            dynStruct
              ? this.buildDynStructLocal(e.type as JethType & { kind: 'struct' }, br, ctx, o)
              : this.aggToMemPtr(br, ctx, o);
          const cc = this.lowerExpr(e.cond, ctx, out);
          const p = this.fresh();
          out.push(`let ${p} := 0`);
          const tO: string[] = [];
          const pT = matPtr(e.then, tO);
          const eO: string[] = [];
          const pE = matPtr(e.else, eO);
          out.push(`switch ${cc}`);
          out.push('case 0 {');
          for (const l of eO) out.push('  ' + l);
          out.push(`  ${p} := ${pE}`);
          out.push('}');
          out.push('default {');
          for (const l of tO) out.push('  ' + l);
          out.push(`  ${p} := ${pT}`);
          out.push('}');
          return p;
        }
        if (e.type.kind === 'array' && e.type.length === undefined) {
          // a DYNAMIC value-array ternary: materialize the TAKEN branch to a memory [len][elems]
          // pointer (aggArgToMemPtr: storage/calldata copy, memory alias) and select it. Short-circuit
          // (only the taken branch is materialized), matching solc.
          const cc = this.lowerExpr(e.cond, ctx, out);
          const p = this.fresh();
          out.push(`let ${p} := 0`);
          const tO: string[] = [];
          const pT = this.aggArgToMemPtr(e.then, ctx, tO);
          const eO: string[] = [];
          const pE = this.aggArgToMemPtr(e.else, ctx, eO);
          out.push(`switch ${cc}`);
          out.push('case 0 {');
          for (const l of eO) out.push('  ' + l);
          out.push(`  ${p} := ${pE}`);
          out.push('}');
          out.push('default {');
          for (const l of tO) out.push('  ' + l);
          out.push(`  ${p} := ${pT}`);
          out.push('}');
          return p;
        }
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
        out.push(
          `let ${nv} := ${e.unchecked ? this.wrapToType(e.type, raw) : `${this.checkedArith(e.isInc ? 'add' : 'sub', e.type)}(${old}, 1)`}`,
        );
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
        // a[i] on a fixed-array memory local (value element): bounds-check then mload. A fixed-array
        // FIELD of a memory struct (p.a[i]) starts wordOffset words into the image.
        const ptr = this.ctxLookup(ctx, e.local);
        const base = e.wordOffset ? `add(${ptr}, ${e.wordOffset * 32})` : ptr;
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${e.length})) { ${this.panic()}(0x32) }`);
        return `mload(add(${base}, mul(${i}, 0x20)))`;
      }
      case 'memAggregate': {
        // a whole memory aggregate (the local's pointer), or a nested struct field at a word
        // offset (a sub-pointer into the parent image, which aliases it).
        const base = this.ctxLookup(ctx, e.local);
        return e.wordOffset ? `add(${base}, ${e.wordOffset * 32})` : base;
      }
      case 'global':
        return this.lowerGlobal(e);
      case 'keccak': {
        // keccak256(bytes/string): hash the CONTENT bytes (data at mp+0x20, length len).
        const { mp, len } = this.toMemory(this.lowerDynamic(e.arg, ctx, out), out);
        const r = this.fresh();
        out.push(`let ${r} := keccak256(add(${mp}, 0x20), ${len})`);
        return r;
      }
      case 'modOp': {
        // addmod/mulmod: full-precision (a op b) mod m. Solidity reverts Panic(0x12) when the
        // modulus is 0 (unlike the raw EVM opcode, which returns 0); args are evaluated first.
        const ma = this.lowerExpr(e.a, ctx, out);
        const mb = this.lowerExpr(e.b, ctx, out);
        const mm = this.fresh();
        out.push(`let ${mm} := ${this.lowerExpr(e.m, ctx, out)}`);
        out.push(`if iszero(${mm}) { ${this.panic()}(0x12) }`);
        return `${e.op}(${ma}, ${mb}, ${mm})`;
      }
      case 'abiDecode': {
        // abi.decode(data, T) / data.decode(T) with a VALUE T: the single decoded component is one
        // validated word (a reference T is lowered via lowerDynamic / the aggregate paths instead).
        return this.lowerAbiDecode(e.data, [e.type], ctx, out)[0]!;
      }
      case 'precompileHash': {
        // sha256 (0x02) / ripemd160 (0x03): staticcall the precompile over the CONTENT bytes,
        // output 32 bytes to scratch. ripemd160's 20-byte result is right-aligned, so left-shift
        // it 96 bits to the bytesN (left-aligned) register form (matches solc).
        const { mp, len } = this.toMemory(this.lowerDynamic(e.arg, ctx, out), out);
        const r = this.fresh();
        out.push(`if iszero(staticcall(gas(), ${e.addr}, add(${mp}, 0x20), ${len}, 0x00, 0x20)) { revert(0, 0) }`);
        out.push(`let ${r} := ${e.leftShift ? `shl(${e.leftShift}, mload(0x00))` : 'mload(0x00)'}`);
        return r;
      }
      case 'ecrecover': {
        // RAW solc ecrecover: staticcall(0x01) over [hash | left-padded-v | r | s] (128B) into a fresh
        // buffer; address(0) on ANY failure, NEVER reverts (the returndatasize()==0x20 guard is mandatory
        // so a failed call never leaks stale memory into the returned address).
        const hash = this.lowerExpr(e.hash, ctx, out);
        const v = this.lowerExpr(e.v, ctx, out);
        const r = this.lowerExpr(e.r, ctx, out);
        const s = this.lowerExpr(e.s, ctx, out);
        return this.emitEcrecover(hash, v, r, s, out);
      }
      case 'recover': {
        // SAFE OZ-5.x ECDSA.recover. The 65-byte bytes form reads r/s/v from the memory image of `sig`;
        // the split form uses the v/r/s registers directly. Then s>HALF (STRICT) and signer==0 checks.
        let rWord: string;
        let sWord: string;
        let vWord: string;
        const hash = this.lowerExpr(e.hash, ctx, out);
        if (e.sig) {
          const { mp, len } = this.toMemory(this.lowerDynamic(e.sig, ctx, out), out);
          // length != 65 -> ECDSAInvalidSignatureLength(uint256 length)
          out.push(`if iszero(eq(${len}, 65)) {`);
          out.push(`  mstore(0, ${ECDSA_INVALID_SIGNATURE_LENGTH})`);
          out.push(`  mstore(4, ${len})`);
          out.push('  revert(0, 0x24)');
          out.push('}');
          const rr = this.fresh();
          const ss = this.fresh();
          const vv = this.fresh();
          out.push(`let ${rr} := mload(add(${mp}, 0x20))`);
          out.push(`let ${ss} := mload(add(${mp}, 0x40))`);
          out.push(`let ${vv} := byte(0, mload(add(${mp}, 0x60)))`);
          rWord = rr;
          sWord = ss;
          vWord = vv;
        } else {
          rWord = this.lowerExpr(e.r!, ctx, out);
          sWord = this.lowerExpr(e.s!, ctx, out);
          vWord = this.lowerExpr(e.v!, ctx, out);
        }
        // s > HALF_ORDER (STRICT) -> ECDSAInvalidSignatureS(bytes32 s)
        const sReg = this.fresh();
        out.push(`let ${sReg} := ${sWord}`);
        out.push(`if gt(${sReg}, ${HALF_ORDER}) {`);
        out.push(`  mstore(0, ${ECDSA_INVALID_SIGNATURE_S})`);
        out.push(`  mstore(4, ${sReg})`);
        out.push('  revert(0, 0x24)');
        out.push('}');
        const signer = this.emitEcrecover(hash, vWord, rWord, sReg, out);
        // signer == address(0) -> ECDSAInvalidSignature() (covers bad v / out-of-range r,s)
        out.push(`if iszero(${signer}) {`);
        out.push(`  mstore(0, ${ECDSA_INVALID_SIGNATURE})`);
        out.push('  revert(0, 4)');
        out.push('}');
        return signer;
      }
      case 'bn256': {
        if (e.op === 'pairing') {
          // bn256Pairing(input): staticcall 0x08 over the packed bytes blob, read the single bool word.
          // 0x00 scratch is safe (consumed immediately like precompileHash). Reverts EMPTY on failure.
          const { mp, len } = this.toMemory(this.lowerDynamic(e.args[0]!, ctx, out), out);
          const r = this.fresh();
          out.push(`if iszero(staticcall(gas(), 8, add(${mp}, 0x20), ${len}, 0x00, 0x20)) { revert(0, 0) }`);
          out.push(`let ${r} := mload(0x00)`);
          return r;
        }
        // bn256Add(0x06) / bn256Mul(0x07): materialize each G1Point to a 2-word memory image FIRST (an
        // allocating source must not bump the FMP between the buffer alloc and the field reads), then
        // allocate a FRESH FMP buffer (NOT scratch - a 0x40 clobber OOGs), copy the input words, staticcall,
        // and the 64-byte G1Point result lands in-place at the buffer. Bump the FMP past it; the result is a
        // memAggregate-shaped 2-word memory image. Reverts EMPTY on an invalid point / bad input.
        const aPtr = this.aggArgToMemPtr(e.args[0]!, ctx, out);
        const aX = this.fresh();
        const aY = this.fresh();
        out.push(`let ${aX} := mload(${aPtr})`);
        out.push(`let ${aY} := mload(add(${aPtr}, 0x20))`);
        let bX = '';
        let bY = '';
        let scalar = '';
        if (e.op === 'add') {
          const bPtr = this.aggArgToMemPtr(e.args[1]!, ctx, out);
          bX = this.fresh();
          bY = this.fresh();
          out.push(`let ${bX} := mload(${bPtr})`);
          out.push(`let ${bY} := mload(add(${bPtr}, 0x20))`);
        } else {
          scalar = this.fresh();
          out.push(`let ${scalar} := ${this.lowerExpr(e.args[1]!, ctx, out)}`);
        }
        const p = this.fresh();
        out.push(`let ${p} := mload(0x40)`);
        out.push(`mstore(${p}, ${aX})`);
        out.push(`mstore(add(${p}, 0x20), ${aY})`);
        if (e.op === 'add') {
          out.push(`mstore(add(${p}, 0x40), ${bX})`);
          out.push(`mstore(add(${p}, 0x60), ${bY})`);
        } else {
          out.push(`mstore(add(${p}, 0x40), ${scalar})`);
        }
        const insizeHex = e.insize === 'dynamic' ? '0' : `0x${e.insize.toString(16)}`;
        out.push(`if iszero(staticcall(gas(), ${e.addr}, ${p}, ${insizeHex}, ${p}, 0x40)) { revert(0, 0) }`);
        out.push(`mstore(0x40, add(${p}, 0x40))`);
        return p;
      }
      case 'blockhash':
        return `blockhash(${this.lowerExpr(e.arg, ctx, out)})`;
      case 'blobhash':
        return `blobhash(${this.lowerExpr(e.arg, ctx, out)})`;
      case 'balance':
        return `balance(${this.lowerExpr(e.addr, ctx, out)})`;
      case 'extCode':
        // <addr>.codehash -> a single bytes32 word (EXTCODEHASH). The bytes form (<addr>.code) is a
        // reference value, lowered via lowerDynamic (it reaches the throw list below if misused).
        if (e.member === 'codehash') return `extcodehash(${this.lowerExpr(e.addr, ctx, out)})`;
        throw new UnsupportedError(`reference value '${e.kind}' used in a non-reference context`);
      case 'callOk':
        // bound only inside a .call/.staticcall success condition: the captured success bool.
        return this.ctxLookup(ctx, EXT_CALL_OK_BINDING);
      case 'catchPanic': {
        // `this.panic` inside a try/catch catch body: SOFT-decode Panic(uint256). Panic has a fixed
        // 4 + 32 layout, so the only checks are length >= 36 and the selector; never hard-revert
        // (yields 0 when the returndata is not a Panic). Byte-identical to solc's `catch Panic(uint c)`.
        const blob = this.ctxLookup(ctx, EXT_CALL_DATA_BINDING);
        const r = this.fresh();
        out.push(`let ${r} := 0`);
        out.push(`if and(iszero(lt(mload(${blob}), 36)), eq(shr(224, mload(add(${blob}, 0x20))), 0x4e487b71)) {`);
        out.push(`  ${r} := mload(add(${blob}, 0x24))`);
        out.push('}');
        return r;
      }
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
        // ps[i].xs[j]: a fixed value-array FIELD element. Each element is one ABI head
        // word (inline in the struct head); bound j against N (Panic 0x32) then add
        // j*32 to the field displacement. solc checks the outer i bound first.
        if (e.elemIndex !== undefined) {
          const j = this.fresh();
          out.push(`let ${j} := ${this.lowerExpr(e.elemIndex, ctx, out)}`);
          out.push(`if iszero(lt(${j}, ${e.elemLength})) { ${this.panic()}(0x32) }`);
          const at2 =
            disp === 0
              ? `add(mul(${i}, ${stride}), mul(${j}, 0x20))`
              : `add(add(mul(${i}, ${stride}), ${disp}), mul(${j}, 0x20))`;
          const w2 = this.fresh();
          out.push(`let ${w2} := calldataload(add(${ref.offset}, ${at2}))`);
          const g2 = this.validateInput(e.fieldType, w2);
          if (g2) out.push(g2);
          return w2;
        }
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
        // FREEZE each element into a register FIRST (left-to-right): an element may be a call that
        // itself allocates memory via mload(0x40), so its allocation must bump the free pointer
        // BEFORE we claim the array region - otherwise the callee overwrites the array.
        const vals = e.elements.map((el) => {
          const r = this.fresh();
          out.push(`let ${r} := ${this.lowerExpr(el, ctx, out)}`);
          return r;
        });
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        out.push(`mstore(${ptr}, ${vals.length})`);
        vals.forEach((v, i) => out.push(`mstore(add(${ptr}, ${(i + 1) * 32}), ${v})`));
        out.push(`mstore(0x40, add(${ptr}, ${(vals.length + 1) * 32}))`);
        return ptr;
      }
      case 'newArray': {
        // new Array<T>(n) -> a length-n zero-initialized memory T[] ([len][n words], one full word
        // per value element - memory arrays are never packed). Byte-identical to solc new T[](n):
        // cap the element count at 2^64-1 (Panic 0x41, matching solc's deterministic overflow guard,
        // which also keeps the allocation from wrapping), then ACTIVELY zero the data region so the
        // result is all-zero even over dirty memory exactly as solc guarantees (calldatacopy reading
        // past calldatasize writes zeros) - do not rely on the memory beyond the free pointer being
        // clean. Lower the length BEFORE claiming mload(0x40) so a side-effecting length that itself
        // allocates bumps the free pointer first.
        const n = this.fresh();
        out.push(`let ${n} := ${this.lowerExpr(e.length, ctx, out)}`);
        out.push(`if gt(${n}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        out.push(`mstore(${ptr}, ${n})`);
        out.push(`calldatacopy(add(${ptr}, 0x20), calldatasize(), mul(${n}, 0x20))`);
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
      case 'msgData':
      case 'calldataSlice':
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
      case 'cdStructArrayElem':
      case 'mapStorageValue':
      case 'mapDynValue':
      case 'abiEncode':
      case 'modexp': // modexp(...) -> bytes (a reference value, lowered via lowerDynamic)
      case 'blake2f': // blake2f(...) -> 64-byte bytes (a reference value, lowered via lowerDynamic)
      case 'extCall': // bytes returndata (a reference value, lowered via lowerDynamic)
      case 'callData': // this.data inside a success condition (the returndata bytes reference)
      case 'catchReason': // this.reason (string) inside a catch body (a reference value, lowered via lowerDynamic)
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
        } else if (
          (f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined)) &&
          arg.kind === 'structNew'
        ) {
          // a nested inline static struct field (Outer(id, Inner(...))): flatten its leaf words
          // inline at consecutive head words, recursing into deeper nested structs.
          this.staticNewLeaves(f.type, arg, ctx, out).forEach((lw, k) => out.push(`mstore(${(w + k) * 32}, ${lw})`));
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
        // a struct-literal element: write each field as head word(s). A fixed-array subfield recurses;
        // a nested inline static struct subfield is flattened to its leaf words; a value subfield is one word.
        let fw = wb;
        el.fields.forEach((sf, sj) => {
          const sarg = el.args[sj]!;
          if (sf.type.kind === 'array' && sarg.kind === 'arrayLit') {
            this.encodeArrayLitHead(sarg, fw, ctx, out);
            fw += abiHeadWords(sf.type);
          } else if (
            (sf.type.kind === 'struct' || (sf.type.kind === 'array' && sf.type.length !== undefined)) &&
            sarg.kind === 'structNew'
          ) {
            this.staticNewLeaves(sf.type, sarg, ctx, out).forEach((lw, k) =>
              out.push(`mstore(${(fw + k) * 32}, ${lw})`),
            );
            fw += abiHeadWords(sf.type);
          } else {
            out.push(`mstore(${fw * 32}, ${this.lowerExpr(sarg, ctx, out)})`);
            fw += abiHeadWords(sf.type);
          }
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
  private encodeReturnTuple(
    values: Expr[],
    types: JethType[],
    ctx: LowerCtx,
    out: string[],
  ): { ptr: string; size: string } {
    const refs: ({ mp: string; len: string } | null)[] = types.map((t, i) =>
      isBytesLike(t) ? this.toMemory(this.lowerDynamic(values[i]!, ctx, out), out) : null,
    );
    // PRE-PASS: an INLINE dynamic value-array literal component ([7,8,9]) is materialized to a
    // fresh [len][data] memory image BEFORE the blob ptr is captured below, so a later allocation
    // cannot alias the blob (mirrors the bytes/string `refs` pre-pass above).
    const litRefs: (string | null)[] = types.map((t, i) =>
      t.kind === 'array' && t.length === undefined && isStaticValueType(t.element) && values[i]!.kind === 'arrayLit'
        ? this.lowerExpr(values[i]!, ctx, out)
        : null,
    );
    // PRE-PASS: an INLINE allocating value-array component whose source is a memArrayExpr
    // (an array-valued ternary `c ? [10,20] : [30]` / `c ? this.a : this.b`, etc.) materializes
    // its [len][data] image via mload(0x40); doing it BEFORE the head ptr is captured below stops
    // that allocation from aliasing the head buffer (mirrors `litRefs` above). A plain memArray
    // local needs no pre-pass (its ctxLookup pointer already aliases an existing image).
    const memExprRefs: (string | null)[] = types.map((t, i) =>
      t.kind === 'array' &&
      values[i]!.kind === 'arrayValue' &&
      (values[i] as Expr & { kind: 'arrayValue' }).arr.base.kind === 'memArrayExpr'
        ? this.lowerExpr(
            ((values[i] as Expr & { kind: 'arrayValue' }).arr.base as { kind: 'memArrayExpr'; expr: Expr }).expr,
            ctx,
            out,
          )
        : null,
    );
    // PRE-PASS: an INLINE-constructed DYNAMIC struct component (return [D("nm",[1,2,3]), 99]) is
    // encoded to a fresh ABI [head/tail] blob BEFORE the tuple ptr is captured below, so the
    // constructor's per-field allocations (string/array materialization) cannot alias the tuple
    // buffer. The loop then mcopies the blob into the tail like the bytes/string `refs` pre-pass.
    const dynStructRefs: ({ mp: string; size: string } | null)[] = types.map((t, i) =>
      isDynamicType(t) && t.kind === 'struct' && values[i]!.kind === 'structNew'
        ? this.encodeDynStructToBlob(values[i]!, ctx, out)
        : null,
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
      } else if (
        t.kind === 'array' &&
        values[i]!.kind === 'arrayValue' &&
        ((values[i] as Expr & { kind: 'arrayValue' }).arr.base.kind === 'memArray' ||
          (values[i] as Expr & { kind: 'arrayValue' }).arr.base.kind === 'memArrayExpr')
      ) {
        // a MEMORY value-array component (return [xs, n]): a dynamic component whose tail
        // is the memory [len][data] (value elements are one word each, the ABI layout).
        const av = values[i] as Expr & { kind: 'arrayValue' };
        const mp = av.arr.base.kind === 'memArray' ? this.ctxLookup(ctx, av.arr.base.varName) : memExprRefs[i]!;
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        const total = `mul(add(mload(${mp}), 1), 0x20)`;
        out.push(`mcopy(${cursor}, ${mp}, ${total})`);
        out.push(`${cursor} := add(${cursor}, ${total})`);
        hw += 1;
      } else if (litRefs[i]) {
        // an INLINE dynamic value-array literal component (return [x, [7,8,9]]): the literal was
        // materialized to a fresh [len][data] memory image in the PRE-PASS (before the blob ptr was
        // captured, so it cannot alias the blob), then encoded like a memory value-array local
        // (offset word + one-word-per-element mcopy).
        const mp = litRefs[i]!;
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        const total = `mul(add(mload(${mp}), 1), 0x20)`;
        out.push(`mcopy(${cursor}, ${mp}, ${total})`);
        out.push(`${cursor} := add(${cursor}, ${total})`);
        hw += 1;
      } else if (this.staticCdComponentName(values[i]!, t)) {
        // a whole STATIC calldata aggregate param (Arr<T,N> / static struct): INLINE in the head
        // (no offset word), like the storage static case. Masks value-leaf fixed arrays / validates
        // struct fields, matching solc's return decode-to-memory.
        const name = this.staticCdComponentName(values[i]!, t)!;
        const ph = ctx.cdParamHead.get(name);
        if (!ph) throw new UnsupportedError(`unbound calldata component '${name}'`);
        const leaf = (ty: JethType): JethType =>
          ty.kind === 'array' && ty.length !== undefined ? leaf(ty.element) : ty;
        const validate = !(t.kind === 'array' && isStaticValueType(leaf(t)));
        this.abiEncFromCd(t, String(ph.head), `add(${ptr}, ${headPos})`, validate, out);
        hw += abiHeadWords(t);
      } else if (this.cdComponentName(values[i]!)) {
        // a whole DYNAMIC calldata param component (return [xs, n] / [dynStructParam, n]):
        // offset word + tail via the recursive calldata encoder. The offset bounds check and
        // data-pointer resolution mirror echoParam; a flat value array cleans dirty elements,
        // everything else validates (matching solc).
        const name = this.cdComponentName(values[i]!)!;
        const ph = ctx.cdParamHead.get(name);
        if (!ph) throw new UnsupportedError(`unbound calldata component '${name}'`);
        const off = this.fresh();
        out.push(`let ${off} := calldataload(${ph.head})`);
        out.push(`if iszero(slt(${off}, sub(sub(calldatasize(), 4), 0x1f))) { revert(0, 0) }`);
        const cdPtr = this.fresh();
        out.push(`let ${cdPtr} := add(4, ${off})`);
        out.push(`mstore(add(${ptr}, ${hw * 32}), sub(${cursor}, ${ptr}))`);
        const topClean = t.kind === 'array' && t.length === undefined && isStaticValueType(t.element);
        const sz = this.abiEncFromCd(t, cdPtr, cursor, !topClean, out);
        out.push(`${cursor} := add(${cursor}, ${sz})`);
        hw += 1;
      } else if (!isDynamicType(t) && values[i]!.kind === 'structNew') {
        // a constructed STATIC struct component (return [x, P(1,2), y]): write its fields INLINE,
        // directly into the tuple head (no fresh allocation - the head buffer's free pointer is not
        // reserved until the end of the loop, so a scratch alloc here would alias the head).
        this.writeAggToMem(values[i]!, ptr, hw, ctx, out);
        hw += abiHeadWords(t);
      } else if (!isDynamicType(t) && values[i]!.kind === 'memAggregate') {
        // a STATIC memory struct/fixed-array local component: copy its image inline into the head.
        const mp = this.lowerExpr(values[i]!, ctx, out);
        out.push(`mcopy(add(${ptr}, ${headPos}), ${mp}, ${abiHeadWords(t) * 32})`);
        hw += abiHeadWords(t);
      } else if (dynStructRefs[i]) {
        // an INLINE-constructed DYNAMIC struct component: offset word + the pre-materialized ABI
        // blob copied into the tail (the blob was built BEFORE the tuple ptr was captured, so its
        // constructor allocations cannot alias the tuple buffer).
        const { mp, size } = dynStructRefs[i]!;
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        out.push(`mcopy(${cursor}, ${mp}, ${size})`);
        out.push(`${cursor} := add(${cursor}, ${size})`);
        hw += 1;
      } else if (isDynamicType(t) && t.kind === 'struct' && values[i]!.kind === 'memDynStructValue') {
        // a DYNAMIC memory struct local component: offset word + bare tuple head/tail in the tail,
        // encoded in-place at the cursor. A memory-source pre-pass (collectTupleDyn) allocates
        // NOTHING (bytes/string and value-array fields are already memory pointers in the local's
        // head), so it cannot alias the not-yet-reserved head buffer. Mirrors encodeDynStructToBlob.
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        const src = this.tupleSrc(values[i]!, ctx, out);
        const queue: DynRef[] = [];
        this.collectTupleDyn(t, src, queue, ctx, out);
        let qi = 0;
        const end = this.encodeTupleInto(t, src, cursor, ctx, out, () => queue[qi++]!);
        out.push(`${cursor} := ${end}`);
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

  /** The calldata PARAM name of a whole dynamic calldata aggregate value (a calldata array
   *  or dynamic-struct param) used as a multi-return component, else undefined. */
  private cdComponentName(value: Expr): string | undefined {
    if (value.kind === 'arrayValue' && value.arr.base.kind === 'calldataArray') return value.arr.base.name;
    if (value.kind === 'cdDynStructValue') return value.param;
    return undefined;
  }

  /** The calldata PARAM name of a whole STATIC calldata aggregate value (a static fixed-array param
   *  -> arrayValue{calldataArray}, or a static struct param -> cdAggregateValue) used as a
   *  multi-return component, else undefined. The component is encoded INLINE in the tuple head. */
  private staticCdComponentName(value: Expr, t: JethType): string | undefined {
    if (value.kind === 'cdAggregateValue') return value.param;
    if (value.kind === 'arrayValue' && value.arr.base.kind === 'calldataArray' && !isDynamicType(t))
      return value.arr.base.name;
    return undefined;
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
      if (value.arr.base.kind === 'mapArray')
        return this.mappingSlot(value.arr.base.baseSlot, value.arr.base.keys, ctx, out);
      if (value.arr.base.kind === 'placeArray') return this.lowerPlace(value.arr.base.path, ctx, out).slot;
    }
    throw new UnsupportedError(
      `a multi-return ${value.type.kind} component must be a storage value (this.x / this.m[k] / this.arr[i])`,
    );
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

  /** Encode a DYNAMIC struct value to its bare ABI tuple head/tail blob (no leading sole-return
   *  offset), for use as a tuple COMPONENT (event data / abi.encode): the component is a head offset
   *  word + this blob in the tail. Returns the blob {mp, size}. Mirrors encodeDynStructReturn's
   *  pre-pass + encodeTupleInto sequence. */
  private encodeDynStructToBlob(value: Expr, ctx: LowerCtx, out: string[]): { mp: string; size: string } {
    const struct = value.type as JethType & { kind: 'struct' };
    const src = this.tupleSrc(value, ctx, out);
    const queue: DynRef[] = [];
    this.collectTupleDyn(struct, src, queue, ctx, out);
    let qi = 0;
    const nextRef = (): DynRef => queue[qi++]!;
    const mp = this.fresh();
    out.push(`let ${mp} := mload(0x40)`);
    const end = this.encodeTupleInto(struct, src, mp, ctx, out, nextRef);
    out.push(`mstore(0x40, ${end})`);
    return { mp, size: `sub(${end}, ${mp})` };
  }

  /** Encode a dynamic struct value as solc's indexed-event TOPIC payload (then keccak'd to
   *  produce the topic). Unlike the ABI encoding, this is the recursively FLATTENED form with
   *  NO offset words and NO length words: a static leaf -> its word(s) inline; bytes/string ->
   *  content padded up to a 32-byte boundary; a dynamic value-array -> its element words; a
   *  nested struct -> its members concatenated. Verified byte-identical to solc (keccak256 of
   *  this blob == the topic). Reuses the same pre-pass + source resolution as the ABI encoder. */
  private encodeTopicBlob(value: Expr, ctx: LowerCtx, out: string[]): { mp: string; size: string } {
    const struct = value.type as JethType & { kind: 'struct' };
    const src = this.tupleSrc(value, ctx, out);
    const queue: DynRef[] = [];
    this.collectTupleDyn(struct, src, queue, ctx, out);
    let qi = 0;
    const nextRef = (): DynRef => queue[qi++]!;
    const mp = this.fresh();
    out.push(`let ${mp} := mload(0x40)`);
    const end = this.topicEncodeStruct(struct, src, mp, ctx, out, nextRef);
    out.push(`mstore(0x40, ${end})`);
    return { mp, size: `sub(${end}, ${mp})` };
  }

  /** Topic-encode a struct's fields sequentially at `tuplePtr` (no head/tail split, no
   *  offsets, no length words). Returns a Yul expr for the cursor just past the payload. */
  private topicEncodeStruct(
    struct: JethType & { kind: 'struct' },
    src: TupleSrc,
    tuplePtr: string,
    ctx: LowerCtx,
    out: string[],
    nextRef: () => DynRef,
  ): string {
    const cursor = this.fresh();
    out.push(`let ${cursor} := ${tuplePtr}`);
    let hw = 0; // running head-word offset within the source tuple (for mem/cd field resolution)
    struct.fields.forEach((f, i) => {
      if (isDynamicType(f.type)) {
        const nc = this.topicEncodeDynField(f, src, i, hw, cursor, ctx, out, nextRef);
        out.push(`${cursor} := ${nc}`);
        hw += 1;
      } else {
        // a static field topic-encodes to exactly its abiHeadWords leaf words inline.
        this.encodeStaticInline(f.type, src, i, hw, cursor, ctx, out);
        out.push(`${cursor} := add(${cursor}, ${abiHeadWords(f.type) * 32})`);
        hw += abiHeadWords(f.type);
      }
    });
    return cursor;
  }

  /** Topic-encode a single DYNAMIC field's payload at `cursor`; returns the new cursor.
   *  bytes/string -> content padded to a word (no length); dynamic value-array -> element
   *  words (no length); nested dynamic struct -> recurse (members concatenated). */
  private topicEncodeDynField(
    f: StructField,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    cursor: string,
    ctx: LowerCtx,
    out: string[],
    nextRef: () => DynRef,
  ): string {
    if (isBytesLike(f.type)) {
      const ref = nextRef();
      const len = this.fresh();
      out.push(`let ${len} := ${this.dynLen(ref)}`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
      const padded = `and(add(${len}, 0x1f), not(0x1f))`;
      const nc = this.fresh();
      out.push(`let ${nc} := add(${cursor}, ${padded})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
      if (ref.src === 'calldata') {
        out.push(`if gt(add(${ref.dataPtr}, ${len}), calldatasize()) { revert(0, 0) }`);
        out.push(`calldatacopy(${cursor}, ${ref.dataPtr}, ${len})`);
      } else if (ref.src === 'memory') {
        out.push(`mcopy(${cursor}, add(${ref.ptr}, 0x20), ${len})`);
      } else {
        throw new UnsupportedError('topic-encoding a storage bytes/string struct field is not supported yet');
      }
      // zero the partial-word padding tail (one word starting at content end; lies within the
      // freshly-reserved region, so it cannot clobber an already-written earlier field).
      out.push(`if mod(${len}, 0x20) { mstore(add(${cursor}, ${len}), 0) }`);
      return nc;
    }
    if (f.type.kind === 'array' && f.type.length === undefined) {
      if (f.type.element.kind === 'struct')
        throw new UnsupportedError('indexed-topic encoding of a struct-element array field is not supported yet');
      // dynamic value-array: its element words, NO length word (each element is one 32-byte word).
      const ref = nextRef();
      const len = this.fresh();
      out.push(`let ${len} := ${this.dynLen(ref)}`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
      const byteLen = `mul(${len}, 0x20)`;
      const nc = this.fresh();
      out.push(`let ${nc} := add(${cursor}, ${byteLen})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
      if (ref.src === 'memory') {
        out.push(`mcopy(${cursor}, add(${ref.ptr}, 0x20), ${byteLen})`);
      } else {
        throw new UnsupportedError('topic-encoding a calldata-array struct field is not supported yet');
      }
      return nc;
    }
    if (f.type.kind === 'struct') {
      const nestedSrc = this.nestedTupleSrc(f, src, fieldIdx, headWord, ctx, out);
      return this.topicEncodeStruct(f.type, nestedSrc, cursor, ctx, out, nextRef);
    }
    throw new UnsupportedError(`unsupported dynamic struct field kind '${f.type.kind}'`);
  }

  /** PRE-PASS: walk a tuple in encode order and materialize each bytes/string
   *  field's value into a DynRef (string literals are allocated NOW via toMemory,
   *  before the output blob pointer is captured, so they cannot alias the blob).
   *  Calldata sources need no materialization. Recurses into nested structs in the
   *  exact order encodeTupleInto consumes them. */
  private collectTupleDyn(
    struct: JethType & { kind: 'struct' },
    src: TupleSrc,
    queue: DynRef[],
    ctx: LowerCtx,
    out: string[],
  ): void {
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
        } else if (f.type.kind === 'array' && f.type.length === undefined) {
          // a dynamic value-array field: resolve its [len][elems] memory pointer (a memory source is
          // already a pointer; a constructor arg is materialized via aggArgToMemPtr, allocating here
          // in the pre-pass, below the eventual tuple blob).
          queue.push(this.arrayFieldRef(f, src, i, hw, ctx, out));
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
    if (value.kind === 'ternary') {
      // a DYNAMIC-struct ternary: lower it to a pointer-headed memory image (short-circuit
      // select of buildDynStructLocal per branch), then encode from that mem source.
      return { kind: 'mem', headPtr: this.lowerExpr(value, ctx, out) };
    }
    // a whole STORAGE dynamic struct (this.d / this.m[k] / this.recs[i] / placeRead): copy it
    // into a fresh memory image (value fields inline, bytes/string + dyn value-array fields a
    // [len][data] pointer) via the same helper buildDynStructLocal uses, then encode from 'mem'.
    // structSrcSlot throws for genuinely unsupported source kinds, preserving the fail-safe below.
    if (
      value.kind === 'structValue' ||
      value.kind === 'mapStorageValue' ||
      value.kind === 'structArrayElem' ||
      value.kind === 'placeRead'
    ) {
      const struct = value.type as JethType & { kind: 'struct' };
      const headPtr = this.buildDynStructFromStorage(struct, this.structSrcSlot(value, ctx, out), ctx, out);
      return { kind: 'mem', headPtr };
    }
    throw new UnsupportedError(`cannot encode dynamic struct from ${value.kind}`);
  }

  /** Recursively encode a struct tuple into memory at `tuplePtr` (the tuple-start
   *  base). Static fields stay inline in the head (declaration order); each dynamic
   *  field gets a head OFFSET word (relative to tuplePtr) and its payload in the
   *  tail (field order). Returns a Yul expr for the memory pointer just past the
   *  tail. Mirrors spec section 3.1 exactly: offsets reset to THIS tuple's start. */
  private encodeTupleInto(
    struct: JethType & { kind: 'struct' },
    src: TupleSrc,
    tuplePtr: string,
    ctx: LowerCtx,
    out: string[],
    nextRef: () => DynRef,
  ): string {
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
  private encodeDynFieldInto(
    f: StructField,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    cursor: string,
    ctx: LowerCtx,
    out: string[],
    nextRef: () => DynRef,
  ): string {
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
    if (f.type.kind === 'array' && f.type.length === undefined) {
      const ref = nextRef();
      // A STRUCT-element array field: the materialized memory image IS the full ABI tail blob
      // [len][offset-table?][element payloads], a self-contained, position-independent encoding.
      // Copy it verbatim at the cursor (relative offsets stay valid after the move); the new cursor
      // advances by the full image byte size.
      if (ref.src === 'memory' && ref.tailBytes) {
        const nc = this.fresh();
        out.push(`let ${nc} := add(${cursor}, ${ref.tailBytes})`);
        out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
        out.push(`mcopy(${cursor}, ${ref.ptr}, ${ref.tailBytes})`);
        return nc;
      }
      // dynamic value-array field tail: [len][word-elements], NO byte-padding (each element is a full
      // 32-byte word). The source is a memory [len][elems] pointer (the materialized array image).
      const len = this.fresh();
      out.push(`let ${len} := ${this.dynLen(ref)}`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
      const byteLen = `mul(${len}, 0x20)`;
      const nc = this.fresh();
      out.push(`let ${nc} := add(${cursor}, add(0x20, ${byteLen}))`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
      if (ref.src === 'memory') {
        out.push(`mstore(${cursor}, ${len})`);
        out.push(`mcopy(add(${cursor}, 0x20), add(${ref.ptr}, 0x20), ${byteLen})`);
      } else {
        throw new UnsupportedError(
          'encoding a calldata-array struct field in a whole-struct return is not supported yet',
        );
      }
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
  private dynFieldRef(
    f: StructField,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    ctx: LowerCtx,
    out: string[],
  ): DynRef {
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

  /** Resolve a dynamic value-array field of a dynamic-field struct to a memory [len][elems] pointer
   *  (for whole-struct `return d` encoding). A memory source's head word already holds the pointer; a
   *  constructor arg is materialized via aggArgToMemPtr. A calldata source stays gated (the analyzer
   *  rejects returning a calldata struct param that carries an array field). */
  private arrayFieldRef(
    f: StructField,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    ctx: LowerCtx,
    out: string[],
  ): DynRef {
    // A STRUCT-element dynamic array field (Q[]): materialize the WHOLE ABI tail blob [len][...] (an
    // offset table + element payloads for dynamic-struct elements; contiguous abiHeadWords element
    // words for static ones), and carry its full byte size so the tail copy is exact (the
    // value-element path below copies just [len][len*32] and so cannot express a struct stride/table).
    const elemIsStruct = f.type.kind === 'array' && f.type.element.kind === 'struct';
    if (src.kind === 'new') {
      if (elemIsStruct) {
        const { mp, size } = this.materializeArrayArg(src.args[fieldIdx]!, ctx, out);
        return { src: 'memory', ptr: mp, tailBytes: size };
      }
      return { src: 'memory', ptr: this.aggArgToMemPtr(src.args[fieldIdx]!, ctx, out) };
    }
    if (src.kind === 'mem') {
      if (elemIsStruct)
        throw new UnsupportedError(
          'encoding a struct-element array field from a memory dynamic struct is not supported yet',
        );
      const at = headWord === 0 ? src.headPtr : `add(${src.headPtr}, ${headWord * 32})`;
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(${at})`);
      return { src: 'memory', ptr };
    }
    throw new UnsupportedError('returning a calldata struct param with an array field is not supported yet');
  }

  /** Build the value source for a nested (sub)struct field. */
  private nestedTupleSrc(
    f: StructField,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    ctx: LowerCtx,
    out: string[],
  ): TupleSrc {
    const nested = f.type as JethType & { kind: 'struct' };
    if (src.kind === 'new') {
      const arg = src.args[fieldIdx]!;
      if (arg.kind !== 'structNew') throw new UnsupportedError('nested struct field must be constructed inline');
      return { kind: 'new', fields: arg.fields, args: arg.args };
    }
    if (src.kind === 'mem')
      throw new UnsupportedError('nested struct field in a memory dynamic struct is not supported');
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
  private encodeStaticInline(
    type: JethType,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    dstPtr: string,
    ctx: LowerCtx,
    out: string[],
  ): void {
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
      // a field of a memory dynamic struct's image. A value field is one inline word; a nested STATIC
      // aggregate (struct / fixed-array) occupies abiHeadWords(type) consecutive head words in the
      // image (the image is already ABI-flattened), so copy ALL of them - reading just the first word
      // would drop the rest (corrupting the encoded tuple / event topic preimage / event data).
      const n = abiHeadWords(type);
      const at = headWord === 0 ? src.headPtr : `add(${src.headPtr}, ${headWord * 32})`;
      if (n === 1) {
        const w = this.fresh();
        out.push(`let ${w} := mload(${at})`);
        out.push(`mstore(${dstPtr}, ${w})`);
      } else {
        out.push(`mcopy(${dstPtr}, ${at}, ${n * 32})`);
      }
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
      // a static fixed-array field, built from an array literal: flatten each element's leaf words
      // (recursing into nested fixed-arrays / structs), one ABI word per value leaf.
      if (arg.kind !== 'arrayLit')
        throw new UnsupportedError('a static fixed-array struct field must be constructed from an array literal');
      const words: string[] = [];
      arg.elements.forEach((el) => words.push(...this.staticNewLeaves(type.element, el, ctx, out)));
      return words;
    }
    return [this.lowerExpr(arg, ctx, out)];
  }

  // ---- nested storage access (Phase 4c-3) ----------------------------------

  /** Fold an AccessPath into a (slot expr, byte offset). Constant steps fold to a
   *  constant slot; mapping keys and dynamic indices produce runtime slot temps.
   *  Index steps are over whole-slot elements (stride in slots), offset stays 0;
   *  field steps add the field slot and set the packing offset. */
  private lowerPlace(
    path: AccessPath,
    ctx: LowerCtx,
    out: string[],
  ): { slot: string; offset: number; byteShift?: string } {
    let constSlot: number | null = path.baseSlot;
    let slot = String(path.baseSlot);
    let offset = 0;
    let byteShift: string | undefined; // a RUNTIME byte offset within the slot (packed elem)
    // @public auto-getters revert EMPTY on an out-of-bounds index (solc parity); ordinary access Panics.
    const oob = path.oobEmpty ? 'revert(0, 0)' : `${this.panic()}(0x32)`;
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
          out.push(`if iszero(lt(${it}, ${step.length})) { ${oob} }`);
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
          if (constSlot !== null) {
            constSlot += slotAdd;
            slot = String(constSlot);
          } else if (slotAdd !== 0) {
            slot = `add(${slot}, ${slotAdd})`;
          }
          offset = (k % step.perSlot) * step.size;
          byteShift = undefined;
        } else {
          const it = this.fresh();
          out.push(`let ${it} := ${this.lowerExpr(step.index, ctx, out)}`);
          out.push(`if iszero(lt(${it}, ${step.length})) { ${oob} }`);
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
        out.push(`if iszero(lt(${it}, sload(${lenSlot}))) { ${oob} }`);
        const dataBase = this.fresh();
        out.push(`let ${dataBase} := ${this.arrayDataSlotHelper()}(${lenSlot})`);
        const delta = step.strideSlots === 1 ? it : `mul(${it}, ${step.strideSlots})`;
        slot = `add(${dataBase}, ${delta})`;
        constSlot = null;
        offset = 0;
      } else if (step.kind === 'packedDynIndex') {
        // packed element of a dynamic T[]: bound vs sload(lenSlot); data at keccak(lenSlot);
        // slot = dataBase + i/perSlot, byte offset (i%perSlot)*size within that slot.
        const lenSlot = constSlot !== null ? String(constSlot) : slot;
        const it = this.fresh();
        out.push(`let ${it} := ${this.lowerExpr(step.index, ctx, out)}`);
        out.push(`if iszero(lt(${it}, sload(${lenSlot}))) { ${oob} }`);
        const dataBase = this.fresh();
        out.push(`let ${dataBase} := ${this.arrayDataSlotHelper()}(${lenSlot})`);
        if (step.index.kind === 'literalInt') {
          const k = Number(step.index.value);
          slot = Math.floor(k / step.perSlot) === 0 ? dataBase : `add(${dataBase}, ${Math.floor(k / step.perSlot)})`;
          offset = (k % step.perSlot) * step.size;
          byteShift = undefined;
        } else {
          slot = `add(${dataBase}, div(${it}, ${step.perSlot}))`;
          byteShift = `mul(mod(${it}, ${step.perSlot}), ${step.size})`;
          offset = 0;
        }
        constSlot = null;
      } else {
        // mapping key: slot = keccak256(key . currentSlot). A bytes/string key hashes its
        // RAW content bytes (unpadded) concatenated with the slot word (the same derivation
        // as mappingSlot()); a value-type key hashes the 32-byte key word + slot word.
        const cur = constSlot !== null ? String(constSlot) : slot;
        if (isBytesLike(step.key.type)) {
          const { mp, len } = this.toMemory(this.lowerDynamic(step.key, ctx, out), out);
          const ptr = this.fresh();
          out.push(`let ${ptr} := mload(0x40)`);
          out.push(`mcopy(${ptr}, add(${mp}, 0x20), ${len})`);
          out.push(`mstore(add(${ptr}, ${len}), ${cur})`);
          const tmp = this.fresh();
          out.push(`let ${tmp} := keccak256(${ptr}, add(${len}, 0x20))`);
          slot = tmp;
        } else {
          const k = this.lowerExpr(step.key, ctx, out);
          const tmp = this.fresh();
          out.push(`mstore(0x00, ${k})`);
          out.push(`mstore(0x20, ${cur})`);
          out.push(`let ${tmp} := keccak256(0x00, 0x40)`);
          slot = tmp;
        }
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
    if (arr.base.kind === 'cdDynArrayField') {
      // a dynamic value-array field of a calldata dynamic-struct param (s.xs): the field's head slot
      // holds an offset (relative to the containing tuple start) to the array's [len][elems]. Decode
      // with the ARRAY helper (unsigned offset bound + FULL len*stride payload-fit), NOT the
      // bytes/string helper (which checks len+0x20 bytes and a signed offset) - matching solc's
      // array-member decode. stride = 0x20 (value elements are one ABI word each).
      const place = arr.base.place;
      const base = this.lowerCdDynBase(place, ctx, out);
      const last = place.steps[place.steps.length - 1]!;
      const offPtr = last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
      const dataPtr = this.fresh();
      const len = this.fresh();
      const stride = abiHeadWords(arr.elem) * 32;
      out.push(`let ${dataPtr}, ${len} := ${this.calldataArrayAt()}(${base}, ${offPtr}, ${stride})`);
      return { src: 'calldata', offset: dataPtr, length: len, elem: arr.elem };
    }
    if (arr.base.kind === 'cdDynFieldNested') {
      // An inner array reached by indexing a NESTED-dynamic-array field of a calldata dyn-struct
      // param (s.grid[i] of u256[][], s.deep[i][j] of u256[][][]). First decode the FIELD's tail to
      // (tableStart, outerLen): the field's head slot holds an offset to the array header, decoded with
      // the ARRAY helper at stride 0x20 (the outer element is a dynamic array = one offset word each), so
      // tableStart = the word after the length word = the per-element offset base. Then descend one inner-
      // offset-table level per index, bounds-checking each dim (Panic 0x32), exactly like cdNestedElem.
      const place = arr.base.place;
      const cbase = this.lowerCdDynBase(place, ctx, out);
      const last = place.steps[place.steps.length - 1]!;
      const offPtr = last.headWords === 0 ? cbase : `add(${cbase}, ${last.headWords * 32})`;
      const tableStart = this.fresh();
      const outerLen = this.fresh();
      out.push(`let ${tableStart}, ${outerLen} := ${this.calldataArrayAt()}(${cbase}, ${offPtr}, 0x20)`);
      const fieldArr = last.fieldType as JethType & { kind: 'array' };
      let base = tableStart;
      let count: string = outerLen;
      let elemT: JethType = fieldArr.element;
      arr.base.indices.forEach((idxExpr) => {
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(idxExpr, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${count})) { ${this.panic()}(0x32) }`);
        if (elemT.kind === 'array' && elemT.length === undefined) {
          const stride = isDynamicType(elemT.element) ? 32 : abiHeadWords(elemT.element) * 32;
          const nb = this.fresh();
          const nl = this.fresh();
          out.push(`let ${nb}, ${nl} := ${this.calldataInnerArray()}(${base}, ${i}, ${stride})`);
          base = nb;
          count = nl;
        } else if (elemT.kind === 'array' && elemT.length !== undefined) {
          const nb = this.fresh();
          out.push(`let ${nb} := ${this.calldataNestedOff()}(${base}, ${i})`);
          base = nb;
          count = String(elemT.length);
        } else {
          throw new UnsupportedError(`cannot index calldata dyn-struct nested field element of kind '${elemT.kind}'`);
        }
        elemT = (elemT as JethType & { kind: 'array' }).element;
      });
      return { src: 'calldata', offset: base, length: count, elem: arr.elem };
    }
    if (arr.base.kind === 'cdDynFixedField') {
      // an inline fixed-array-of-value field (s.xs where xs: Arr<T,N>): the N element words sit inline
      // in the tuple head at the field's byte offset. No tail decode: element i is the word at
      // fieldOff + i*32. length is the compile-time constant N. arrayGet bounds-checks (Panic 0x32)
      // and validates dirty calldata bits on read, matching solc's inline static-array element read.
      const place = arr.base.place;
      const base = this.lowerCdDynBase(place, ctx, out);
      const last = place.steps[place.steps.length - 1]!;
      const offset = last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
      return { src: 'calldata', offset, length: String(arr.base.length), elem: arr.elem };
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
    if (arr.base.kind === 'cdSubElem') {
      // a[i] inner array of a MIXED calldata composite. The param is bound as a calldata array
      // (b.offset, b.length, b.elem = the inner array type). Bound i against the outer count/N
      // (Panic 0x32), then resolve the inner array:
      //  - dynamic-of-fixed (inner is a fixed array): contiguous, stride = abiHeadWords(inner)*32;
      //    the inner fixed array starts at b.offset + i*stride (outer payload already validated).
      //  - fixed-of-dynamic (inner is a dynamic array): resolve via the offset table at b.offset
      //    (calldataInnerArray, with the same revert semantics as a nested dynamic array).
      const b = ctx.cdArrays.get(arr.base.name);
      if (!b) throw new UnsupportedError(`unbound calldata composite ${arr.base.name}`);
      const inner = b.elem;
      const i = this.fresh();
      out.push(`let ${i} := ${this.lowerExpr(arr.base.index, ctx, out)}`);
      out.push(`if iszero(lt(${i}, ${b.length})) { ${this.panic()}(0x32) }`);
      if (inner.kind === 'array' && inner.length !== undefined && isStaticType(inner)) {
        // dynamic array of STATIC fixed arrays (uint256[2][]): elements are contiguous, each one
        // abiHeadWords(inner) words. a[i] starts at b.offset + i*stride.
        const stride = abiHeadWords(inner) * 32;
        const offset = this.fresh();
        out.push(`let ${offset} := add(${b.offset}, mul(${i}, ${stride}))`);
        return { src: 'calldata', offset, length: String(inner.length), elem: arr.elem };
      }
      if (inner.kind === 'array' && inner.length !== undefined) {
        // dynamic array of a fixed-array-of-DYNAMIC (string[3][] = Arr<string,3>[]): element i is
        // VARIABLE-size and offset-located (NOT contiguous). a[i] is the element's N-word offset
        // table, which is itself offset-table-indexed by the next access.
        const offset = this.fresh();
        out.push(`let ${offset} := ${this.calldataNestedOff()}(${b.offset}, ${i})`);
        return { src: 'calldata', offset, length: String(inner.length), elem: arr.elem };
      }
      const stride = abiHeadWords(arr.elem) * 32;
      const nb = this.fresh();
      const nl = this.fresh();
      out.push(`let ${nb}, ${nl} := ${this.calldataInnerArray()}(${b.offset}, ${i}, ${stride})`);
      return { src: 'calldata', offset: nb, length: nl, elem: arr.elem };
    }
    if (arr.base.kind === 'cdNestedElem') {
      // Inner array m[i] of a nested dynamic array T[][] (calldata, 4e-5). The outer
      // param is decoded into (pointerRegionStart, outerLen); bounds-check i against
      // outerLen (Panic 0x32), then resolve inner i's (dataOffset, innerLen) through
      // its pointer-table word (base = pointerRegionStart, spec section 2). A pointer
      // / length / payload past calldatasize -> EMPTY revert inside the helper.
      const b = ctx.cdArrays.get(arr.base.name);
      if (!b) throw new UnsupportedError(`unbound nested calldata array ${arr.base.name}`);
      // Descend one ARRAY level per index, bounds-checking against the current level's count.
      // The element navigated at each step (elemT, starting at the root's immediate element b.elem)
      // determines the navigation: a DYNAMIC-array element (T[]) is offset+length (calldataInnerArray,
      // count = its read length); a FIXED-array-of-dynamic element (Arr<string,N>) is offset-only
      // (calldataNestedOff, count = the static N). Mixed nesting (string[2][3][]) descends correctly.
      const indices = arr.base.indices;
      let base = b.offset;
      let count: string = b.length; // count of the current container (runtime for dynamic, static N for fixed)
      let elemT: JethType = b.elem; // the element type navigated INTO at the current step
      indices.forEach((idxExpr) => {
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(idxExpr, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${count})) { ${this.panic()}(0x32) }`);
        if (elemT.kind === 'array' && elemT.length === undefined) {
          // navigate into a DYNAMIC array element: read its length word.
          const stride = isDynamicType(elemT.element) ? 32 : abiHeadWords(elemT.element) * 32;
          const nb = this.fresh();
          const nl = this.fresh();
          out.push(`let ${nb}, ${nl} := ${this.calldataInnerArray()}(${base}, ${i}, ${stride})`);
          base = nb;
          count = nl;
        } else if (elemT.kind === 'array' && elemT.length !== undefined) {
          // navigate into a FIXED-array-of-dynamic element: offset only, count = its static length.
          const nb = this.fresh();
          out.push(`let ${nb} := ${this.calldataNestedOff()}(${base}, ${i})`);
          base = nb;
          count = String(elemT.length);
        } else {
          throw new UnsupportedError(`cannot index calldata nested element of kind '${elemT.kind}'`);
        }
        elemT = (elemT as JethType & { kind: 'array' }).element;
      });
      return { src: 'calldata', offset: base, length: count, elem: arr.elem };
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
    // @public auto-getters revert with EMPTY data on out-of-bounds (matching solc's getter),
    // whereas an ordinary a[i] access raises Panic(0x32).
    const oob = e.oobEmpty ? 'revert(0, 0)' : `${this.panic()}(0x32)`;
    if (ref.src === 'storage') {
      out.push(`if iszero(lt(${i}, sload(${ref.lenSlot}))) { ${oob} }`);
      const data = this.arrayDataSlot(ref.lenSlot, out);
      return this.arrayElemLoad(ref.elem, data, i);
    }
    if (ref.src === 'fixed') {
      out.push(`if iszero(lt(${i}, ${ref.length})) { ${oob} }`);
      return this.arrayElemLoad(ref.elem, String(ref.baseSlot), i); // data inline at baseSlot
    }
    if (ref.src === 'memory') {
      // memory T[] (value element, one word each): bound vs mload(ptr); data at ptr+0x20.
      out.push(`if iszero(lt(${i}, mload(${ref.ptr}))) { ${oob} }`);
      return `mload(add(${ref.ptr}, add(0x20, mul(${i}, 0x20))))`;
    }
    out.push(`if iszero(lt(${i}, ${ref.length})) { ${oob} }`);
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
    const elem = arr.elem as JethType & { kind: 'array' };
    if (elem.length !== undefined) {
      // a FIXED inner array element (Arr<T,N>[]): the element is N inline words at innerSlot, NOT a
      // dynamic array with its own length slot. Write the literal / copy the source fixed array
      // inline. (A no-arg push() grows with a zero element; the fresh slots are already 0.)
      if (value) {
        if (value.kind === 'arrayLit') this.writeArrayLit(value, innerSlot, ctx, out);
        else this.copyFixedArray(elem, this.fixedArraySrcBase(value, ctx, out), innerSlot, out);
      }
      return;
    }
    // a DYNAMIC inner array element (T[][]): innerSlot is the inner array's length slot.
    if (value) this.copyArrayValueIntoStorage(elem.element, value, innerSlot, ctx, out);
  }

  /** Deep-copy an ARRAY VALUE (memory `memArray`/`arrayLit` of value elements, or a
   *  storage `stateArray`/`mapArray`) into a storage dynamic array at `dstLenSlot`. Clears
   *  the dst's OLD data first (so it works for both a fresh push slot, oldLen 0 = no-op,
   *  and an overwrite assign), then sets the length and copies every element. */
  private copyArrayValueIntoStorage(
    innerElem: JethType,
    value: Expr,
    dstLenSlot: string,
    ctx: LowerCtx,
    out: string[],
  ): void {
    const storageSrc =
      value.kind === 'mapStorageValue' ||
      (value.kind === 'arrayValue' &&
        (value.arr.base.kind === 'stateArray' ||
          value.arr.base.kind === 'mapArray' ||
          value.arr.base.kind === 'placeArray'));
    if (storageSrc) {
      this.copyArray(innerElem, this.arraySrcLenSlot(value, ctx, out), dstLenSlot, out);
      return;
    }
    // calldata source (a calldata value-array param: this.a = p): decode + validate each element
    // (like solc's per-element calldata read) and packed-store into storage. Value elements only.
    if (value.kind === 'arrayValue' && value.arr.base.kind === 'calldataArray') {
      if (!isStaticValueType(innerElem))
        throw new UnsupportedError('a calldata array of non-value elements is not supported');
      const b = ctx.cdArrays.get(value.arr.base.name);
      if (!b) throw new UnsupportedError(`unbound calldata array ${value.arr.base.name}`);
      const dstData = this.fresh();
      out.push(`let ${dstData} := ${this.arrayDataSlotHelper()}(${dstLenSlot})`);
      const packs = arrayElemPacks(innerElem);
      const slotsFor = (L: string): string =>
        packs.packed
          ? `div(add(${L}, ${packs.perSlot - 1}), ${packs.perSlot})`
          : `mul(${L}, ${storageSlotCount(innerElem)})`;
      const oldSlots = this.fresh();
      out.push(`let ${oldSlots} := ${slotsFor(`sload(${dstLenSlot})`)}`);
      const c = this.fresh();
      out.push(
        `for { let ${c} := 0 } lt(${c}, ${oldSlots}) { ${c} := add(${c}, 1) } { sstore(add(${dstData}, ${c}), 0) }`,
      );
      out.push(`sstore(${dstLenSlot}, ${b.length})`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${b.length}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const w = this.fresh();
      inner.push(`let ${w} := calldataload(add(${b.offset}, mul(${i}, 32)))`);
      const guard = this.validateInput(innerElem, w);
      if (guard) inner.push(guard);
      this.arrayElemStore(innerElem, dstData, i, w, inner);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return;
    }
    // memory source (a memArray local or an array literal): value elements only.
    if (!isStaticValueType(innerElem))
      throw new UnsupportedError('a memory array of non-value elements is not supported');
    this.copyMemArrayIntoStorage(innerElem, this.lowerExpr(value, ctx, out), dstLenSlot, out);
  }

  /** Deep-copy a MEMORY value-element array ([len][elems] at `memPtr`) into a storage dynamic array
   *  at `dstLenSlot` (length there, data at keccak(slot)): resize + clear old data + packed element
   *  store. Shared by whole-array assignment and a dynamic-array struct field write. */
  private copyMemArrayIntoStorage(innerElem: JethType, memPtr: string, dstLenSlot: string, out: string[]): void {
    const n = this.fresh();
    out.push(`let ${n} := mload(${memPtr})`);
    const dstData = this.fresh();
    out.push(`let ${dstData} := ${this.arrayDataSlotHelper()}(${dstLenSlot})`);
    const packs = arrayElemPacks(innerElem);
    const slotsFor = (L: string): string =>
      packs.packed
        ? `div(add(${L}, ${packs.perSlot - 1}), ${packs.perSlot})`
        : `mul(${L}, ${storageSlotCount(innerElem)})`;
    const oldSlots = this.fresh();
    out.push(`let ${oldSlots} := ${slotsFor(`sload(${dstLenSlot})`)}`);
    const c = this.fresh();
    out.push(
      `for { let ${c} := 0 } lt(${c}, ${oldSlots}) { ${c} := add(${c}, 1) } { sstore(add(${dstData}, ${c}), 0) }`,
    );
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
    if (isDynamicType(ref.elem)) {
      // the freed element holds DYNAMIC data (a dynamic array / bytes / string / dynamic struct /
      // fixed-array-of-dynamic). Its storage footprint includes keccak-located data slots that a plain
      // header-zero leaves STALE (so stale data resurfaces when the index is reused). DEEP-CLEAR it via
      // the same recursive footprint clear `delete` uses, so it is byte-identical to solc's pop().
      const base = this.fresh();
      out.push(`let ${base} := add(${data}, mul(${nl}, ${sc}))`);
      this.deleteAgg(ref.elem, base, out);
    } else if (sc === 1) {
      // value element, or a fixed array that packs into ONE slot (uint8[4], uint128[2]):
      // arrayElemStore handles per-byte packing / single-slot clear.
      this.arrayElemStore(ref.elem, data, nl, '0', out);
    } else {
      // a MULTI-slot STATIC fixed-array element (uint256[2], uint256[2][2], ...): solc zeroes ALL
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
    const slotAt = (n: number): string =>
      isConst ? String(Number(baseSlot) + n) : n === 0 ? baseSlot : `add(${baseSlot}, ${n})`;
    fields.forEach((f, i) => {
      const arg = args[i]!;
      if (f.type.kind === 'struct' && arg.kind === 'structNew') {
        this.writeStruct(arg.fields, arg.args, slotAt(f.slot), ctx, out);
      } else if (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element)) {
        // a DYNAMIC value-element array field (u256[], address[], ...): deep-copy the array value
        // (memory / calldata / array-literal / storage source) into the field's storage dynamic
        // array (length at slotAt(f.slot), data at keccak(slot)), overwrite-clearing the old data.
        this.copyArrayValueIntoStorage(f.type.element, arg, slotAt(f.slot), ctx, out);
      } else if (f.type.kind === 'array' && arg.kind === 'arrayLit') {
        // a fixed-array field constructed from a (possibly nested) literal.
        this.writeArrayLit(arg, slotAt(f.slot), ctx, out);
      } else if (
        (f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined)) &&
        isStaticType(f.type)
      ) {
        // a non-inline STATIC aggregate field source (a local / param / storage value): materialize its
        // ABI-unpacked image, then transcode it into the field's packed storage slots.
        this.storeStaticAggFromMem(f.type, this.aggToMemPtr(arg, ctx, out), slotAt(f.slot), out);
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
  /** Materialize a static struct / fixed-array aggregate value to a memory image pointer (used
   *  by an aggregate ternary branch): a constructed value allocates fresh; a storage source is
   *  COPIED into a fresh image; a memory-aggregate local aliases its pointer. */
  private aggToMemPtr(e: Expr, ctx: LowerCtx, out: string[]): string {
    if (e.kind === 'structNew' || e.kind === 'arrayLit') return this.allocAggToMem(e, ctx, out);
    if (e.kind === 'memAggregate' || e.kind === 'ternary') return this.lowerExpr(e, ctx, out); // a nested aggregate ternary recurses (materialize + select)
    if (e.kind === 'structValue') return this.allocAggFromStorage(e.type, String(e.baseSlot), out);
    if (e.kind === 'mapStorageValue')
      return this.allocAggFromStorage(e.type, this.mappingSlot(e.baseSlot, e.keys, ctx, out), out);
    if (e.kind === 'structArrayElem')
      return this.allocAggFromStorage(e.type, this.structArrayElemSlot(e.arr, e.index, ctx, out), out);
    if (e.kind === 'placeRead') return this.allocAggFromStorage(e.type, this.lowerPlace(e.path, ctx, out).slot, out);
    if (e.kind === 'arrayValue' && e.arr.base.kind === 'fixedArray')
      return this.allocAggFromStorage(e.type, String(e.arr.base.baseSlot), out);
    if (e.kind === 'cdAggregateValue') return this.allocAggFromCalldata(e.param, e.type, ctx, out);
    if (e.kind === 'call') {
      const p = this.fresh();
      out.push(`let ${p} := ${this.lowerExpr(e, ctx, out)}`);
      return p;
    }
    throw new UnsupportedError(`cannot materialize aggregate ternary branch '${e.kind}'`);
  }

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
      } else if (f.type.kind === 'array' && f.type.length === undefined) {
        // a dynamic value-array field: materialize the arg to a [len][elems] memory pointer, store it.
        out.push(`mstore(${at}, ${this.aggArgToMemPtr(value.args[i]!, ctx, out)})`);
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
    if (init.kind === 'call') return this.lowerExpr(init, ctx, out); // a struct-returning internal call yields the pointer-headed image pointer (ALIAS, like solc memory references)
    if (init.kind === 'ternary') return this.lowerExpr(init, ctx, out); // selects an already-built branch image pointer
    if (init.kind === 'cdDynStructValue') return this.buildDynStructFromCalldata(struct, init, ctx, out);
    // a storage struct source (structValue / mapStorageValue / structArrayElem / placeRead).
    return this.buildDynStructFromStorage(struct, this.structSrcSlot(init, ctx, out), ctx, out);
  }

  /** Copy a storage dynamic-field struct at `baseSlot` into a fresh memory image: value fields
   *  are read (packed-aware) and stored inline; bytes/string fields are copied to a memory blob
   *  whose pointer is stored in the head word. Scoped to value + bytes/string fields. */
  private buildDynStructFromStorage(
    struct: JethType & { kind: 'struct' },
    baseSlot: string,
    ctx: LowerCtx,
    out: string[],
  ): string {
    const headWords = tupleHeadWords(struct);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${headWords * 32}))`);
    const isConst = /^\d+$/.test(baseSlot);
    const slotAt = (n: number): string =>
      isConst ? String(Number(baseSlot) + n) : n === 0 ? baseSlot : `add(${baseSlot}, ${n})`;
    let hw = 0;
    for (const f of struct.fields) {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      if (isBytesLike(f.type)) {
        const { mp } = this.toMemory({ src: 'storage', slot: slotAt(f.slot) }, out);
        out.push(`mstore(${at}, ${mp})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length === undefined) {
        // a dynamic value-array field: copy the storage array (length slot = f's slot) to a fresh
        // [len][elems] memory image (storage is canonical, no masking needed); store the pointer.
        const dst = this.fresh();
        out.push(`let ${dst} := mload(0x40)`);
        const size = this.abiEncFromStorage(f.type, slotAt(f.slot), 0, dst, out);
        out.push(`mstore(0x40, add(${dst}, ${size}))`);
        out.push(`mstore(${at}, ${dst})`);
        hw += 1;
      } else if (f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined)) {
        // a nested STATIC aggregate field (struct / fixed-array): flatten ALL its leaves into the head
        // (one ABI head word per leaf) directly from storage, via the same storage->ABI transcoder the
        // return/event encoders use. The plain loadState below writes only the FIRST word (and, for a
        // packed multi-field struct, the wrong packed word) while advancing the cursor by abiHeadWords,
        // corrupting the encoding of any aggregate spanning >=2 head words (event topic AND data).
        this.abiEncFromStorage(f.type, slotAt(f.slot), 0, at, out);
        hw += abiHeadWords(f.type);
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
  private buildDynStructFromCalldata(
    struct: JethType & { kind: 'struct' },
    init: Expr,
    ctx: LowerCtx,
    out: string[],
  ): string {
    const src = this.tupleSrc(init, ctx, out); // { kind: 'cd', base }
    const headWords = tupleHeadWords(struct);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${headWords * 32}))`);
    let hw = 0;
    struct.fields.forEach((f, i) => {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      if (isBytesLike(f.type)) {
        const fref = this.dynFieldRef(f, src, i, hw, ctx, out);
        // a calldata string/bytes field materialized into a fresh image (store/local, NOT the echo
        // path): the echo decoder defers the length-cap + payload-fits checks, so add them here. solc
        // EMPTY-reverts when a field's declared length runs past calldatasize; without this JETH would
        // calldatacopy past the end (silently zero-padding) and store a garbage-length string.
        if (fref.src === 'calldata') {
          out.push(`if gt(${fref.len}, 0xffffffffffffffff) { revert(0, 0) }`);
          out.push(`if gt(add(${fref.dataPtr}, ${fref.len}), calldatasize()) { revert(0, 0) }`);
        }
        const { mp } = this.toMemory(fref, out);
        out.push(`mstore(${at}, ${mp})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element)) {
        // a DYNAMIC value-array field: resolve its calldata tail (offset word at base + hw*32;
        // absolute = base + offset, bounded exactly like solc's tuple-member decode), decode +
        // VALIDATE it into a fresh [len][elems] memory image via abiEncFromCd, then store the
        // pointer in the head word (the pointer-headed image writeDynStructFromMem consumes).
        if (src.kind !== 'cd')
          throw new UnsupportedError('calldata dynamic-array struct field decode needs a calldata source');
        const so = this.fresh();
        out.push(`let ${so} := calldataload(${hw === 0 ? src.base : `add(${src.base}, ${hw * 32})`})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${src.base}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), calldatasize()) { revert(0, 0) }`);
        // cap the declared element count and require the whole [len][elems] payload to lie within
        // calldata BEFORE allocating, so an absurd length EMPTY-reverts (like solc) rather than
        // Panic(0x41) on an oversized memory allocation inside abiEncFromCd.
        const alen = this.fresh();
        out.push(`let ${alen} := calldataload(${se})`);
        out.push(`if gt(${alen}, 0xffffffffffffffff) { revert(0, 0) }`);
        out.push(
          `if gt(add(add(${se}, 0x20), mul(${alen}, ${abiHeadWords(f.type.element) * 32})), calldatasize()) { revert(0, 0) }`,
        );
        const dst = this.fresh();
        out.push(`let ${dst} := mload(0x40)`);
        const size = this.abiEncFromCd(f.type, se, dst, true, out);
        out.push(`mstore(0x40, add(${dst}, ${size}))`);
        out.push(`mstore(${at}, ${dst})`);
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
  /** True if a constructed aggregate (structNew / arrayLit) has, at any depth, an aggregate field /
   *  element supplied from a NON-INLINE source (not an inline structNew / arrayLit). Such a value must
   *  be built in FRESH memory (allocAggToMem) rather than the memory-0 return scratch, since
   *  materializing the source would otherwise clobber the in-progress blob. */
  private aggHasNonInlineField(v: Expr): boolean {
    if (v.kind === 'structNew') {
      return (v.type as JethType & { kind: 'struct' }).fields.some((f, i) => {
        const a = v.args[i]!;
        if (!(f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined))) return false;
        if (a.kind !== 'structNew' && a.kind !== 'arrayLit') return true;
        return this.aggHasNonInlineField(a);
      });
    }
    if (v.kind === 'arrayLit') {
      const aggElem = v.elem.kind === 'struct' || (v.elem.kind === 'array' && v.elem.length !== undefined);
      if (!aggElem) return false;
      return v.elements.some(
        (el) => (el.kind !== 'structNew' && el.kind !== 'arrayLit') || this.aggHasNonInlineField(el),
      );
    }
    return false;
  }

  private writeAggToMem(value: Expr, ptr: string, wordBase: number, ctx: LowerCtx, out: string[]): void {
    const at = (w: number): string => (w === 0 ? ptr : `add(${ptr}, ${w * 32})`);
    if (value.kind === 'structNew') {
      let w = wordBase;
      value.fields.forEach((f, j) => {
        const arg = value.args[j]!;
        if (arg.kind === 'arrayLit' || arg.kind === 'structNew') this.writeAggToMem(arg, ptr, w, ctx, out);
        else if (f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined)) {
          // a non-inline aggregate field source (a local / param / storage value): materialize its
          // ABI-unpacked image (fresh memory, past this parent), then mcopy it into the field's words.
          out.push(`mcopy(${at(w)}, ${this.aggToMemPtr(arg, ctx, out)}, ${abiHeadWords(f.type) * 32})`);
        } else out.push(`mstore(${at(w)}, ${this.lowerExpr(arg, ctx, out)})`);
        w += abiHeadWords(f.type);
      });
      return;
    }
    if (value.kind === 'arrayLit') {
      const ew = abiHeadWords(value.elem);
      const aggElem = value.elem.kind === 'struct' || (value.elem.kind === 'array' && value.elem.length !== undefined);
      value.elements.forEach((el, k) => {
        const w = wordBase + k * ew;
        if (el.kind === 'arrayLit' || el.kind === 'structNew') this.writeAggToMem(el, ptr, w, ctx, out);
        else if (aggElem) out.push(`mcopy(${at(w)}, ${this.aggToMemPtr(el, ctx, out)}, ${ew * 32})`);
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
      lit.elements.forEach((el, k) =>
        this.arrayElemStore(elem, baseSlot, String(k), this.lowerExpr(el, ctx, out), out),
      );
      return;
    }
    const sc = storageSlotCount(elem);
    const isConst = /^\d+$/.test(baseSlot);
    const slotAt = (n: number): string =>
      isConst ? String(Number(baseSlot) + n) : n === 0 ? baseSlot : `add(${baseSlot}, ${n})`;
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
      if (value.arr.base.kind === 'mapArray')
        return this.mappingSlot(value.arr.base.baseSlot, value.arr.base.keys, ctx, out);
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
        packs.packed
          ? `div(add(${L}, ${packs.perSlot - 1}), ${packs.perSlot})`
          : `mul(${L}, ${storageSlotCount(elem)})`;
      const srcSlots = this.fresh();
      const dstSlots = this.fresh();
      out.push(`let ${srcSlots} := ${slotsFor(srcLen)}`);
      out.push(`let ${dstSlots} := ${slotsFor(dstLen)}`);
      const i = this.fresh();
      out.push(
        `for { let ${i} := 0 } lt(${i}, ${srcSlots}) { ${i} := add(${i}, 1) } { sstore(add(${dstData}, ${i}), sload(add(${srcData}, ${i}))) }`,
      );
      const j = this.fresh();
      out.push(
        `for { let ${j} := ${srcSlots} } lt(${j}, ${dstSlots}) { ${j} := add(${j}, 1) } { sstore(add(${dstData}, ${j}), 0) }`,
      );
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

  /** Resolve the storage base slot of a whole FIXED-array source value (state-var fixed array,
   *  or a nested fixed-array field via placeArray). */
  private fixedArraySrcBase(value: Expr, ctx: LowerCtx, out: string[]): string {
    if (value.kind === 'arrayValue') {
      const base = value.arr.base;
      if (base.kind === 'fixedArray') return String(base.baseSlot);
      if (base.kind === 'stateArray') return String(base.slot);
      if (base.kind === 'placeArray') return this.lowerPlace(base.path, ctx, out).slot;
      if (base.kind === 'mapArray') return this.mappingSlot(base.baseSlot, base.keys, ctx, out);
    }
    // a whole fixed-array reached as an element of a dynamic/fixed array (this.a[i], Arr<T,N>[]) or as a
    // mapping value (this.m[k], mapping(K=>Arr<T,N>)): resolve its (runtime) base slot.
    if (value.kind === 'structArrayElem') return this.structArrayElemSlot(value.arr, value.index, ctx, out);
    if (value.kind === 'mapStorageValue') return this.mappingSlot(value.baseSlot, value.keys, ctx, out);
    throw new UnsupportedError(`cannot copy a fixed array from '${value.kind}'`);
  }

  /** Storage-to-storage copy of a fixed array Arr<T,N> from `srcBase` to `dstBase`. Static
   *  elements (value/packed/static struct/static nested array) copy the array's slot footprint
   *  verbatim; dynamic elements (bytes/string, dynamic struct) deep-copy per element (storeDynamic
   *  / copyStruct overwrite-clear the dst element's old tail). Byte-identical to solc. */
  private copyFixedArray(arrType: JethType & { kind: 'array' }, srcBase: string, dstBase: string, out: string[]): void {
    const elem = arrType.element;
    const N = arrType.length!;
    const sConst = /^\d+$/.test(srcBase);
    const dConst = /^\d+$/.test(dstBase);
    const sAt = (n: number): string =>
      sConst ? String(Number(srcBase) + n) : n === 0 ? srcBase : `add(${srcBase}, ${n})`;
    const dAt = (n: number): string =>
      dConst ? String(Number(dstBase) + n) : n === 0 ? dstBase : `add(${dstBase}, ${n})`;
    if (isStaticType(elem)) {
      const slots = storageSlotCount(arrType);
      for (let i = 0; i < slots; i++) out.push(`sstore(${dAt(i)}, sload(${sAt(i)}))`);
      return;
    }
    const sc = storageSlotCount(elem);
    for (let i = 0; i < N; i++) {
      if (isBytesLike(elem)) this.storeDynamic(dAt(i * sc), { src: 'storage', slot: sAt(i * sc) }, out);
      else this.copyStruct(elem as JethType & { kind: 'struct' }, sAt(i * sc), dAt(i * sc), out);
    }
  }

  /** Resolve the storage base slot of a struct VALUE source (for a storage-to-storage
   *  copy): a state-var struct (structValue), a whole mapping-value struct
   *  (mapStorageValue at the runtime keccak(key.base) slot), or a whole struct array
   *  element (structArrayElem at data + i*slotCount). */
  /** Write a whole struct VALUE into a storage slot. Dispatches by source: a constructor
   *  (structNew) is written field-by-field; a MEMORY / CALLDATA struct (memAggregate from a
   *  `let m: S = ...` local, or a calldata struct param) is transcoded from its ABI-unpacked image
   *  into packed storage; a STORAGE struct lvalue is a storage-to-storage deep copy. */
  private storeStructTo(
    type: JethType & { kind: 'struct' },
    value: Expr,
    dst: string,
    ctx: LowerCtx,
    out: string[],
  ): void {
    if (value.kind === 'structNew') {
      this.writeStruct(value.fields, value.args, dst, ctx, out);
      return;
    }
    if (value.kind === 'memAggregate' || value.kind === 'cdAggregateValue') {
      // a STATIC struct from a memory/calldata source: transcode its ABI-unpacked image to packed storage.
      this.storeStaticAggFromMem(type, this.aggToMemPtr(value, ctx, out), dst, out);
      return;
    }
    if (value.kind === 'memDynStructValue' || value.kind === 'cdDynStructValue') {
      // a DYNAMIC-field struct from a memory local or calldata param: materialize the pointer-headed
      // image (handling the source uniformly), then write value fields packed and bytes/string fields
      // with overwrite-clear into storage.
      this.writeDynStructFromMem(type, this.buildDynStructLocal(type, value, ctx, out), dst, out);
      return;
    }
    this.copyStruct(type, this.structSrcSlot(value, ctx, out), dst, out);
  }

  /** Write a DYNAMIC-field struct's pointer-headed memory image (from buildDynStructLocal) into
   *  storage: each value field via storeState (packed), each bytes/string field via storeDynamic from
   *  the head-word pointer (overwrite-clearing the old tail). Scoped to value + bytes/string fields;
   *  a dynamic-array field from a memory/calldata source is a later step (clean rejection). */
  private writeDynStructFromMem(
    struct: JethType & { kind: 'struct' },
    memPtr: string,
    slot: string,
    out: string[],
  ): void {
    const sConst = /^\d+$/.test(slot);
    const fslotAt = (n: number): string => (n === 0 ? slot : sConst ? String(Number(slot) + n) : `add(${slot}, ${n})`);
    let hw = 0;
    for (const f of struct.fields) {
      const at = hw === 0 ? memPtr : `add(${memPtr}, ${hw * 32})`;
      if (isBytesLike(f.type)) {
        const p = this.fresh();
        out.push(`let ${p} := mload(${at})`);
        this.storeDynamic(fslotAt(f.slot), { src: 'memory', ptr: p }, out);
      } else if (!isDynamicType(f.type) && isStaticValueType(f.type)) {
        const w = this.fresh();
        out.push(`let ${w} := mload(${at})`);
        for (const l of this.storeState(f.type, fslotAt(f.slot), f.offset, w)) out.push(l);
      } else if (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element)) {
        // a dynamic value-element array field: the head word is a memory [len][elems] pointer;
        // deep-copy it into the field's storage dynamic array (length at fslot, data at keccak(fslot)).
        const p = this.fresh();
        out.push(`let ${p} := mload(${at})`);
        this.copyMemArrayIntoStorage(f.type.element, p, fslotAt(f.slot), out);
      } else {
        throw new UnsupportedError(
          `storing a struct with a '${f.type.kind}' field from a memory/calldata source is not supported yet`,
        );
      }
      hw += isDynamicType(f.type) ? 1 : abiHeadWords(f.type);
    }
  }

  /** Copy a STATIC aggregate (struct / fixed array of static elements) from an ABI-unpacked memory
   *  image (one word per leaf - the memAggregate / calldata-decoded layout) into PACKED storage.
   *  The inverse of abiEncFromStorage's static branch; storeState read-modify-writes each packed
   *  leaf, so leaves sharing a slot compose correctly and slot padding stays zero. */
  private storeStaticAggFromMem(t: JethType, memPtr: string, slot: string, out: string[]): void {
    const sConst = /^\d+$/.test(slot);
    for (const leaf of structStorageLeaves(t)) {
      const ls =
        leaf.storageSlot === 0
          ? slot
          : sConst
            ? String(Number(slot) + leaf.storageSlot)
            : `add(${slot}, ${leaf.storageSlot})`;
      const w = this.fresh();
      out.push(`let ${w} := mload(${leaf.abiWord === 0 ? memPtr : `add(${memPtr}, ${leaf.abiWord * 32})`})`);
      for (const l of this.storeState(leaf.type, ls, leaf.storageOffset, w)) out.push(l);
    }
  }

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
    const sAt = (n: number): string =>
      sConst ? String(Number(srcBase) + n) : n === 0 ? srcBase : `add(${srcBase}, ${n})`;
    const dAt = (n: number): string =>
      dConst ? String(Number(dstBase) + n) : n === 0 ? dstBase : `add(${dstBase}, ${n})`;
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
      case 'local': {
        // delete a memory aggregate local: rebind it to a FRESH zeroed image (solc parity - an alias
        // keeps the old value). Fresh memory above the free pointer is zero-initialized in the EVM.
        const words = abiHeadWords(target.type);
        const p = this.fresh();
        out.push(`let ${p} := mload(0x40)`);
        out.push(`mstore(0x40, add(${p}, ${words * 32}))`);
        out.push(`${this.ctxLookup(ctx, target.varName)} := ${p}`);
        return;
      }
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
      out.push(
        `let ${slots} := ${packs.packed ? `div(add(${len}, ${packs.perSlot - 1}), ${packs.perSlot})` : `mul(${len}, ${storageSlotCount(elem)})`}`,
      );
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

  /** Resolve a storage `bytes` LOCATION lvalue (a direct state var, a struct field, a mapping value,
   *  or a bytes[]/Arr<bytes,N> element) to its header slot, using the SAME resolver each whole-value
   *  assignment uses, so a .push/.pop/b[i]=x mutation lands on the identical slot. */
  private bytesLocSlot(loc: LValue, ctx: LowerCtx, out: string[]): string {
    switch (loc.kind) {
      case 'dynState':
        return String(loc.slot);
      case 'mapDynState':
        return this.mappingSlot(loc.baseSlot, loc.keys, ctx, out);
      case 'strArrayElem':
        return this.strArrayElemSlot(loc.arr, loc.index, ctx, out);
      case 'dynPlace':
        return this.lowerPlace(loc.path, ctx, out).slot;
      default:
        throw new UnsupportedError(`bytes mutation through a '${loc.kind}' location is not supported`);
    }
  }

  /** Storage header slot of bytes/string element `i` of a storage string[]/bytes[].
   *  Bounds-checks i against the array length (Panic 0x32), then returns
   *  keccak(lenSlot)+i. The header is a normal storage bytes/string. */
  private strArrayElemSlot(arr: ArrayExpr, index: Expr, ctx: LowerCtx, out: string[], oobEmpty = false): string {
    const ref = this.lowerArrayRef(arr, ctx, out);
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(index, ctx, out)}`);
    // @public getters revert EMPTY on out-of-bounds (solc parity); ordinary access Panics 0x32.
    const oob = oobEmpty ? 'revert(0, 0)' : `${this.panic()}(0x32)`;
    // Arr<string,N>/Arr<bytes,N> (fixed): N contiguous string headers at baseSlot + i.
    if (ref.src === 'fixed') {
      out.push(`if iszero(lt(${i}, ${ref.length})) { ${oob} }`);
      const hdr = this.fresh();
      out.push(`let ${hdr} := add(${ref.baseSlot}, ${i})`);
      return hdr;
    }
    if (ref.src !== 'storage') throw new UnsupportedError('string[]/bytes[] element requires a storage array');
    out.push(`if iszero(lt(${i}, sload(${ref.lenSlot}))) { ${oob} }`);
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
    if (value.kind === 'newArray') {
      // new Array<T>(n) lowers to a [len][data] memory pointer; encode it as a dynamic memory array.
      const p = this.fresh();
      out.push(`let ${p} := ${this.lowerExpr(value, ctx, out)}`);
      return this.encodeMemArrayReturn(p, out);
    }
    if (value.kind !== 'arrayValue') throw new UnsupportedError(`cannot encode array from ${value.kind}`);
    // a MEMORY T[] (value elements) at ptr=[len][data]: ABI return = [0x20][len][data].
    if (value.arr.base.kind === 'memArray') {
      return this.encodeMemArrayReturn(this.ctxLookup(ctx, value.arr.base.varName), out);
    }
    // a memory T[] produced by an expression (a dynamic-array ternary `c ? this.a : this.b`):
    // lower to the [len][elems] pointer (freeze first), then encode.
    if (value.arr.base.kind === 'memArrayExpr') {
      const p = this.fresh();
      out.push(`let ${p} := ${this.lowerExpr(value.arr.base.expr, ctx, out)}`);
      return this.encodeMemArrayReturn(p, out);
    }
    const ref = this.lowerArrayRef(value.arr, ctx, out);
    if (ref.src === 'fixed') throw new UnsupportedError('returning a whole fixed array is not supported yet');
    if (ref.src === 'memory') throw new UnsupportedError('memory array return is handled earlier');
    // string[] / bytes[] (array of dynamic elements): re-encode each element as a
    // [byteLen][right-padded data] payload behind a per-element offset table whose
    // base is the table start (spec section 4.1). Only the calldata-source path is
    // reachable (the analyzer gates storage/mapping string[] elements).
    if (isBytesLike(ref.elem)) {
      if (ref.src !== 'calldata')
        throw new UnsupportedError('returning a string[]/bytes[] is only supported from a calldata source');
      return this.encodeDynArrayReturn(ref.offset, ref.length, ctx, out);
    }
    // Nested dynamic array T[][] (4e-5): re-encode each inner array as a [innerLen]
    // [elements] tail behind a per-inner pointer table whose base is the pointer-region
    // start (spec section 2.1). Only the calldata-source path is reachable.
    if (ref.elem.kind === 'array' && ref.elem.length === undefined) {
      if (ref.src !== 'calldata')
        throw new UnsupportedError('returning a nested dynamic array is only supported from a calldata source');
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
  private encodeDynArrayReturn(
    tableStart: string,
    len: string,
    ctx: LowerCtx,
    out: string[],
  ): { ptr: string; size: string } {
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
  private encodeNestedArrayReturn(
    base: string,
    len: string,
    elemType: JethType,
    ctx: LowerCtx,
    out: string[],
  ): { ptr: string; size: string } {
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
  private echoParam(
    name: string,
    t: JethType,
    ctx: LowerCtx,
    out: string[],
    forceValidate = false,
  ): { ptr: string; size: string } {
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
    // a flat top-level value array CLEANS its elements on a RETURN echo (Bug A; solc's return
    // copy masks dirty bits), but the EVENT/ERROR decode VALIDATES every element (reverts on
    // dirty), so callers in that context pass forceValidate. Everything else always validates.
    const topClean = !forceValidate && t.kind === 'array' && t.length === undefined && isStaticValueType(t.element);
    // forceValidate marks the DECODE/re-encode context (abi.encode/encodeWith*/emit/error via
    // materializeArrayArg): an oversized inner length/offset is an ABI-decode failure -> revert(0,0),
    // matching solc. The return-echo path (forceValidate=false) keeps Panic 0x41.
    const size = this.abiEncFromCd(t, cdPtr, `add(${ptr}, 0x20)`, !topClean, out, forceValidate);
    out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
    return { ptr, size: `add(0x20, ${size})` };
  }

  /** JETH242/243: resolve an aggregate ARGUMENT or internal-fn RETURN value (a dynamic value-element
   *  array, bytes/string, or a struct) to a MEMORY pointer for pass-/return-by-reference. A
   *  memory-local source ALIASES (the pointer is shared, so a callee mutation is visible to the
   *  caller, matching solc); a calldata source is COPIED to fresh memory (a value array MASKS dirty
   *  elements, like solc's calldata->memory copy); a storage source is copied via abiEncFromStorage
   *  (storage is canonical); a constructed literal / call result is already fresh memory. */
  private aggArgToMemPtr(a: Expr, ctx: LowerCtx, out: string[]): string {
    // abi.decode(data, T) / data.decode(T) yielding an array / struct: lowerAbiDecode already returns
    // a fresh decoded memory image pointer in the right layout ([len][elems] for an array, the
    // pointer-headed image for a dynamic struct, the flat ABI image for a static aggregate).
    if (a.kind === 'abiDecode') return this.lowerAbiDecode(a.data, [a.type], ctx, out)[0]!;
    // a DYNAMIC-array literal lowers to a fresh [len][elems] memory image (lowerExpr's arrayLit case);
    // a structNew / static fixed-array literal uses the static-aggregate image (allocAggToMem).
    if (a.kind === 'arrayLit') {
      if (a.type.kind === 'array' && a.type.length === undefined) return this.lowerExpr(a, ctx, out);
      return this.allocAggToMem(a, ctx, out);
    }
    // a DYNAMIC-field struct (constructor / memory / storage / calldata source) uses the
    // pointer-headed image builder; only a STATIC structNew uses the flat ABI image.
    if (a.type.kind === 'struct' && isDynamicType(a.type)) return this.buildDynStructLocal(a.type, a, ctx, out);
    if (a.kind === 'structNew') return this.allocAggToMem(a, ctx, out);
    if (a.kind === 'arrayValue') {
      const b = a.arr.base;
      if (b.kind === 'memArray') return this.ctxLookup(ctx, b.varName); // memory local: ALIAS
      if (b.kind === 'memArrayExpr') return this.lowerExpr(b.expr, ctx, out);
      if (b.kind === 'calldataArray') {
        const { ptr } = this.echoParam(b.name, a.type, ctx, out, false); // COPY, masking dirty elements
        const mp = this.fresh();
        out.push(`let ${mp} := add(${ptr}, 0x20)`); // skip the [0x20] offset wrapper -> [len][elems]
        return mp;
      }
      // storage source (this.arr / this.m[k] / a nested inner array): COPY a fresh [len][elems] image.
      let lenSlot: string;
      if (b.kind === 'stateArray') lenSlot = String(b.slot);
      else if (b.kind === 'mapArray') lenSlot = this.mappingSlot(b.baseSlot, b.keys, ctx, out);
      else if (b.kind === 'placeArray') lenSlot = this.lowerPlace(b.path, ctx, out).slot;
      else throw new UnsupportedError(`aggregate argument from array source '${b.kind}' is not supported`);
      const dst = this.fresh();
      out.push(`let ${dst} := mload(0x40)`);
      const size = this.abiEncFromStorage(a.type, lenSlot, 0, dst, out);
      out.push(`mstore(0x40, add(${dst}, ${size}))`);
      return dst;
    }
    if (isBytesLike(a.type)) {
      const { mp } = this.toMemory(this.lowerDynamic(a, ctx, out), out); // alias (memory) or copy (cd/storage)
      return mp;
    }
    // a calldata struct / fixed-array param forwarded as an arg: COPY its ABI-unpacked image to memory.
    if (a.kind === 'cdAggregateValue') return this.allocAggFromCalldata(a.param, a.type, ctx, out);
    // a DYNAMIC-field struct arg: pointer-headed image (memory source ALIASES; storage/calldata/
    // constructor source is COPIED to fresh memory) - the same builder a dynamic-struct local uses.
    if (a.type.kind === 'struct' && isDynamicType(a.type)) return this.buildDynStructLocal(a.type, a, ctx, out);
    // a struct value (memAggregate alias / storage) or a call result (already a pointer).
    return this.lowerExpr(a, ctx, out);
  }

  /** Materialize a DYNAMIC-array argument (G3, for @error/@event head/tail) into a memory blob
   *  holding its ABI tail encoding `[len][elements...]`, returning a frozen pointer + byte size.
   *  Calldata-param arrays reuse echoParam (unbounded element nesting); value-element memory
   *  arrays are already in ABI tail layout. Other sources are gated. */
  private materializeArrayArg(arg: Expr, ctx: LowerCtx, out: string[]): { mp: string; size: string } {
    if (arg.kind === 'newArray') {
      // new Array<T>(n) used directly as an abi.encode/encodePacked arg: it lowers to a [len][elems]
      // memory pointer (value elements, ABI tail layout already), exactly like a memArray local.
      const mp = this.lowerExpr(arg, ctx, out);
      return { mp, size: `mul(add(mload(${mp}), 1), 0x20)` };
    }
    if (arg.kind !== 'arrayValue')
      throw new UnsupportedError(`array argument must be an array value, got '${arg.kind}'`);
    const base = arg.arr.base;
    let mpExpr: string;
    let sizeExpr: string;
    if (base.kind === 'calldataArray') {
      // an @event/@error array arg: solc VALIDATES every value element (reverts on dirty bits),
      // unlike a RETURN echo which cleans, so force validation here.
      const { ptr, size } = this.echoParam(base.name, arg.type, ctx, out, true);
      mpExpr = `add(${ptr}, 0x20)`; // skip the single-value [0x20] offset wrapper
      sizeExpr = `sub(${size}, 0x20)`;
    } else if (base.kind === 'memArray') {
      mpExpr = this.ctxLookup(ctx, base.varName);
      sizeExpr = `mul(add(mload(${mpExpr}), 1), 0x20)`; // [len][e0..] value elements
    } else if (base.kind === 'memArrayExpr') {
      mpExpr = this.lowerExpr(base.expr, ctx, out);
      sizeExpr = `mul(add(mload(${mpExpr}), 1), 0x20)`;
    } else {
      // a STORAGE source (this.arr / this.m[k] / a nested inner array this.dd[i] / this.s.xs):
      // build a fresh [len][elements...] ABI tail image via abiEncFromStorage (the canonical
      // transcode aggArgToMemPtr already uses). The result IS the ABI tail blob, so mp points at
      // the [len] word and size is its full byte length (length word + element / offset-table /
      // tail bytes), matching the value-element memArray contract and the calldata echo.
      let lenSlot: string;
      if (base.kind === 'stateArray') lenSlot = String(base.slot);
      else if (base.kind === 'mapArray') lenSlot = this.mappingSlot(base.baseSlot, base.keys, ctx, out);
      else if (base.kind === 'placeArray') lenSlot = this.lowerPlace(base.path, ctx, out).slot;
      else
        throw new UnsupportedError(
          `a dynamic-array @error/@event argument from a '${base.kind}' source is not supported yet`,
        );
      const sdst = this.fresh();
      out.push(`let ${sdst} := mload(0x40)`);
      const ssz = this.abiEncFromStorage(arg.type, lenSlot, 0, sdst, out);
      const sm = this.fresh();
      out.push(`let ${sm} := ${ssz}`);
      out.push(`mstore(0x40, add(${sdst}, ${sm}))`);
      return { mp: sdst, size: sm };
    }
    const mp = this.fresh();
    out.push(`let ${mp} := ${mpExpr}`);
    const size = this.fresh();
    out.push(`let ${size} := ${sizeExpr}`);
    return { mp, size };
  }

  /** Materialize a whole STATIC fixed-array / struct value to a fresh memory blob of ABI-encoded
   *  padded leaf words (one word per leaf), for an indexed-event keccak topic. Sources: a @state
   *  fixed array / struct (storage -> abiEncFromStorage) or a whole static calldata aggregate param
   *  (echoStaticParam). Returns {mp, size}; keccak256(mp, size) == solc's keccak256(abi.encode(v)). */
  private materializeStaticAggToMem(arg: Expr, ctx: LowerCtx, out: string[]): { mp: string; size: string } {
    if (arg.kind === 'cdAggregateValue') {
      // An indexed event arg emitted DIRECTLY from a calldata param: solc VALIDATES the value-leaf
      // words (reverts on dirty high/low bits), unlike a return echo which masks. Force validation
      // so a dirty calldata fixed-array reverts byte-identically to solc (not a masked success).
      const { ptr, size } = this.echoStaticParam(arg.param, arg.type, ctx, out, true);
      return { mp: ptr, size };
    }
    let slot: string;
    if (arg.kind === 'structValue') slot = String(arg.baseSlot);
    else if (arg.kind === 'arrayValue' && arg.arr.base.kind === 'fixedArray') slot = String(arg.arr.base.baseSlot);
    else {
      // a constructed / memory / mapping-value / struct-array-element source: aggToMemPtr builds the
      // ABI-unpacked image (one word per leaf), so keccak256(mp, abiHeadWords*32) == keccak256(abi.encode(v)).
      return { mp: this.aggToMemPtr(arg, ctx, out), size: String(abiHeadWords(arg.type) * 32) };
    }
    const dst = this.fresh();
    out.push(`let ${dst} := mload(0x40)`);
    const size = this.abiEncFromStorage(arg.type, slot, 0, dst, out);
    const sz = this.fresh();
    out.push(`let ${sz} := ${size}`);
    out.push(`mstore(0x40, add(${dst}, ${sz}))`);
    return { mp: dst, size: sz };
  }

  /** Echo a whole STATIC struct / fixed-array calldata param (G5). The data is INLINE at the
   *  param head (no offset word) and the return is flat (no 0x20 wrapper, since static types
   *  are returned inline). Matching solc's decode-to-memory: a pure VALUE-leaf fixed array
   *  CLEANS (masks) its leaves, while a struct (or struct-element array) VALIDATES its fields
   *  (the struct branch of abiEncFromCd forces field validation regardless of this flag). */
  private echoStaticParam(
    name: string,
    t: JethType,
    ctx: LowerCtx,
    out: string[],
    forceValidate = false,
  ): { ptr: string; size: string } {
    const ph = ctx.cdParamHead.get(name);
    if (!ph) throw new UnsupportedError(`unbound echo param ${name}`);
    const leaf = (ty: JethType): JethType => (ty.kind === 'array' && ty.length !== undefined ? leaf(ty.element) : ty);
    const validate = forceValidate || !(t.kind === 'array' && isStaticValueType(leaf(t)));
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
  private abiEncFromCd(
    t: JethType,
    cdPtr: string,
    dst: string,
    validate: boolean,
    out: string[],
    capEmptyRevert = false,
  ): string {
    // In a DECODE/re-encode context (abi.encode/encodeWith*/emit/error materialization, reached via
    // echoParam's forceValidate), an oversized length or memory-overflow cap is an ABI-DECODE FAILURE ->
    // revert(0, 0) (empty), matching solc. In the plain return-echo copy context it Panics 0x41 (also
    // matching solc - e.g. `return xs` for a bytes[] with an inner length >= 2^64). The calldatasize and
    // offset bounds already revert(0,0) in both; only these unsigned 2^64 caps were context-dependent.
    const capRevert = capEmptyRevert ? `revert(0, 0)` : `${this.panic()}(0x41)`;
    // a single value leaf
    if (isStaticValueType(t)) {
      const w = this.fresh();
      out.push(`let ${w} := calldataload(${cdPtr})`);
      if (validate) {
        const g = this.validateInput(t, w);
        if (g) out.push(g);
        out.push(`mstore(${dst}, ${w})`);
      } else if ((t as { enumMembers?: string[] }).enumMembers) {
        // An enum element copied whole to memory is range-checked like an explicit conversion:
        // solc reverts Panic(0x21) on an out-of-range element during the copy. (The empty-revert
        // sites are the ABI-decode boundary, lazy element access, and event/error materialization;
        // a whole-aggregate echo to a memory return Panics instead.)
        out.push(
          `if iszero(lt(${w}, ${(t as { enumMembers: string[] }).enumMembers.length})) { ${this.panic()}(0x21) }`,
        );
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
        } else if ((leaf.type as { enumMembers?: string[] }).enumMembers) {
          // enum leaf in a whole-aggregate echo: Panic(0x21) on out-of-range (see the value-leaf
          // case above), not a silent mask.
          out.push(
            `if iszero(lt(${w}, ${(leaf.type as { enumMembers: string[] }).enumMembers.length})) { ${this.panic()}(0x21) }`,
          );
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
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${capRevert} }`);
      const padded = this.fresh();
      out.push(`let ${padded} := and(add(${len}, 0x1f), not(0x1f))`);
      const nc = this.fresh();
      out.push(`let ${nc} := add(add(${dst}, 0x20), ${padded})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${dst})) { ${capRevert} }`);
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
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${capRevert} }`);
      out.push(`mstore(${dst}, ${len})`);
      const elemRegion = this.fresh();
      out.push(`let ${elemRegion} := add(${cdPtr}, 0x20)`);
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${dst}, 0x20)`);
      if (isStaticType(t.element)) {
        const es = abiHeadWords(t.element) * 32;
        const nc = this.fresh();
        out.push(`let ${nc} := add(${dstHead}, mul(${len}, ${es}))`);
        out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${dstHead})) { ${capRevert} }`);
        out.push(`if gt(add(${elemRegion}, mul(${len}, ${es})), calldatasize()) { revert(0, 0) }`);
        const elemValidate = validate || !isStaticValueType(t.element);
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        const ecd = this.fresh();
        inner.push(`let ${ecd} := add(${elemRegion}, mul(${i}, ${es}))`);
        const edst = this.fresh();
        inner.push(`let ${edst} := add(${dstHead}, mul(${i}, ${es}))`);
        this.abiEncFromCd(t.element, ecd, edst, elemValidate, inner, capEmptyRevert);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return `add(0x20, mul(${len}, ${es}))`;
      }
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dstHead}, mul(${len}, 0x20))`);
      out.push(`if or(gt(${cursor}, 0xffffffffffffffff), lt(${cursor}, ${dstHead})) { ${capRevert} }`);
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
      const sz = this.abiEncFromCd(t.element, se, cursor, true, inner, capEmptyRevert);
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
        const sz = this.abiEncFromCd(t.element, se, cursor, true, out, capEmptyRevert);
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
          this.abiEncFromCd(f.type, `add(${cdPtr}, ${fb})`, `add(${dst}, ${fb})`, true, out, capEmptyRevert);
          hw += abiHeadWords(f.type);
        } else {
          const so = this.fresh();
          out.push(`let ${so} := calldataload(add(${cdPtr}, ${fb}))`);
          out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
          const se = this.fresh();
          out.push(`let ${se} := add(${cdPtr}, ${so})`);
          out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), calldatasize()) { revert(0, 0) }`);
          out.push(`mstore(add(${dst}, ${fb}), sub(${cursor}, ${dst}))`);
          const sz = this.abiEncFromCd(f.type, se, cursor, true, out, capEmptyRevert);
          out.push(`${cursor} := add(${cursor}, ${sz})`);
          hw += 1;
        }
      }
      return `sub(${cursor}, ${dst})`;
    }
    throw new UnsupportedError(`abiEncFromCd: unsupported type '${t.kind}'`);
  }

  /** abi.decode codec: decode a MEMORY-sourced ABI value of type `t` (the DATA word at memory byte
   *  `memPtr`) into a fresh memory image at `dst`. The memory analogue of abiEncFromCd: reads via
   *  mload (not calldataload), copies via mcopy (not calldatacopy), and bounds every offset/length
   *  against `blobEnd` (the absolute memory end address of the source blob, = blobData + blobLen)
   *  rather than calldatasize(). Returns a Yul expr for the byte size written into `dst`. Byte-identical
   *  to solc's abi.decode-from-memory: an oversized inner length / memory-alloc overflow Panics(0x41)
   *  (the memory-decode cap), while an out-of-bounds offset / a length running past the blob reverts
   *  EMPTY (revert(0, 0)). Value leaves are always VALIDATED (dirty narrow bits revert empty, like
   *  solc's decode of a tuple component / array element). Compile-time recursion over `t` => unbounded
   *  nesting; array lengths drive runtime loops. */
  private abiDecFromMem(t: JethType, memPtr: string, dst: string, blobEnd: string, out: string[]): string {
    const cap = `${this.panic()}(0x41)`;
    // a single value leaf: one word, validated.
    if (isStaticValueType(t)) {
      const w = this.fresh();
      out.push(`let ${w} := mload(${memPtr})`);
      const g = this.validateInput(t, w);
      if (g) out.push(g);
      out.push(`mstore(${dst}, ${w})`);
      return '32';
    }
    // a static aggregate (struct / fixed array of static leaves): copy each leaf word, validated.
    if (isStaticType(t)) {
      for (const leaf of abiLeaves(t)) {
        const w = this.fresh();
        out.push(`let ${w} := mload(add(${memPtr}, ${leaf.wordOffset * 32}))`);
        const g = this.validateInput(leaf.type, w);
        if (g) out.push(g);
        out.push(`mstore(add(${dst}, ${leaf.wordOffset * 32}), ${w})`);
      }
      return String(abiHeadWords(t) * 32);
    }
    // bytes / string: [len][right-padded data].
    if (isBytesLike(t)) {
      const len = this.fresh();
      out.push(`let ${len} := mload(${memPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${cap} }`);
      const padded = this.fresh();
      out.push(`let ${padded} := and(add(${len}, 0x1f), not(0x1f))`);
      const nc = this.fresh();
      out.push(`let ${nc} := add(add(${dst}, 0x20), ${padded})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${dst})) { ${cap} }`);
      out.push(`if gt(add(add(${memPtr}, 0x20), ${len}), ${blobEnd}) { revert(0, 0) }`);
      out.push(`mstore(${dst}, ${len})`);
      out.push(`mcopy(add(${dst}, 0x20), add(${memPtr}, 0x20), ${len})`);
      out.push(`if mod(${len}, 0x20) { mstore(add(add(${dst}, 0x20), ${len}), 0) }`);
      return `add(0x20, ${padded})`;
    }
    // dynamic array T[]: [len][ static elements inline | dynamic elements head+tail ].
    if (t.kind === 'array' && t.length === undefined) {
      const len = this.fresh();
      out.push(`let ${len} := mload(${memPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${cap} }`);
      out.push(`mstore(${dst}, ${len})`);
      const elemRegion = this.fresh();
      out.push(`let ${elemRegion} := add(${memPtr}, 0x20)`);
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${dst}, 0x20)`);
      if (isStaticType(t.element)) {
        const es = abiHeadWords(t.element) * 32;
        const nc = this.fresh();
        out.push(`let ${nc} := add(${dstHead}, mul(${len}, ${es}))`);
        out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${dstHead})) { ${cap} }`);
        out.push(`if gt(add(${elemRegion}, mul(${len}, ${es})), ${blobEnd}) { revert(0, 0) }`);
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        const ecd = this.fresh();
        inner.push(`let ${ecd} := add(${elemRegion}, mul(${i}, ${es}))`);
        const edst = this.fresh();
        inner.push(`let ${edst} := add(${dstHead}, mul(${i}, ${es}))`);
        this.abiDecFromMem(t.element, ecd, edst, blobEnd, inner);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return `add(0x20, mul(${len}, ${es}))`;
      }
      // dynamic element (bytes/string/...): an N-word offset table relative to elemRegion, plus tails.
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dstHead}, mul(${len}, 0x20))`);
      out.push(`if or(gt(${cursor}, 0xffffffffffffffff), lt(${cursor}, ${dstHead})) { ${cap} }`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const so = this.fresh();
      inner.push(`let ${so} := mload(add(${elemRegion}, mul(${i}, 0x20)))`);
      inner.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
      const se = this.fresh();
      inner.push(`let ${se} := add(${elemRegion}, ${so})`);
      inner.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), ${blobEnd}) { revert(0, 0) }`);
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), sub(${cursor}, ${dstHead}))`);
      const sz = this.abiDecFromMem(t.element, se, cursor, blobEnd, inner);
      inner.push(`${cursor} := add(${cursor}, ${sz})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return `sub(${cursor}, ${dst})`;
    }
    // fixed array of dynamic element Arr<dyn,N>: an N-word offset table (no length), base = dst/memPtr.
    if (t.kind === 'array' && t.length !== undefined) {
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${t.length * 32})`);
      for (let k = 0; k < t.length; k++) {
        const so = this.fresh();
        out.push(`let ${so} := mload(add(${memPtr}, ${k * 32}))`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${memPtr}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), ${blobEnd}) { revert(0, 0) }`);
        out.push(`mstore(add(${dst}, ${k * 32}), sub(${cursor}, ${dst}))`);
        const sz = this.abiDecFromMem(t.element, se, cursor, blobEnd, out);
        out.push(`${cursor} := add(${cursor}, ${sz})`);
      }
      return `sub(${cursor}, ${dst})`;
    }
    // dynamic struct (tuple with >=1 dynamic field): head (static inline / dynamic offset) + tails.
    if (t.kind === 'struct') {
      const headWords = tupleHeadWords(t);
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${headWords * 32})`);
      let hw = 0;
      for (const f of t.fields) {
        const fb = hw * 32;
        if (!isDynamicType(f.type)) {
          this.abiDecFromMem(f.type, `add(${memPtr}, ${fb})`, `add(${dst}, ${fb})`, blobEnd, out);
          hw += abiHeadWords(f.type);
        } else {
          const so = this.fresh();
          out.push(`let ${so} := mload(add(${memPtr}, ${fb}))`);
          out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
          const se = this.fresh();
          out.push(`let ${se} := add(${memPtr}, ${so})`);
          out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), ${blobEnd}) { revert(0, 0) }`);
          out.push(`mstore(add(${dst}, ${fb}), sub(${cursor}, ${dst}))`);
          const sz = this.abiDecFromMem(f.type, se, cursor, blobEnd, out);
          out.push(`${cursor} := add(${cursor}, ${sz})`);
          hw += 1;
        }
      }
      return `sub(${cursor}, ${dst})`;
    }
    throw new UnsupportedError(`abiDecFromMem: unsupported type '${t.kind}'`);
  }

  /** Decode the bytes value `data` into N components of `types` (abi.decode). Materializes the source
   *  to a memory [len][data] image, then for each top-level component reads its head word at
   *  blobData+32*i: a STATIC component is decoded inline at that head position; a DYNAMIC component
   *  reads the head as an offset (relative to blobData), bounds it, and decodes the tail into a fresh
   *  memory image. Returns one Yul register per component (a value word, or a memory image pointer for
   *  a reference component). The component layout (one head word per top-level type, regardless of how
   *  many leaf words a static aggregate occupies in a NESTED position) matches solc's outer tuple. */
  private lowerAbiDecode(data: Expr, types: JethType[], ctx: LowerCtx, out: string[]): string[] {
    const { mp } = this.toMemory(this.lowerDynamic(data, ctx, out), out);
    const blobData = this.fresh();
    out.push(`let ${blobData} := add(${mp}, 0x20)`);
    const blobEnd = this.fresh();
    out.push(`let ${blobEnd} := add(${blobData}, mload(${mp}))`);
    // the outer head is one OFFSET word per DYNAMIC component plus abiHeadWords(t) inline words per
    // STATIC component (a static aggregate occupies all its leaf words inline in the outer tuple head,
    // exactly as solc lays it out); bound the whole head span against the blob.
    const headWords = (t: JethType): number => (isDynamicType(t) ? 1 : abiHeadWords(t));
    const totalHead = types.reduce((n, t) => n + headWords(t), 0);
    out.push(`if gt(add(${blobData}, ${totalHead * 32}), ${blobEnd}) { revert(0, 0) }`);
    const regs: string[] = [];
    let hw = 0;
    types.forEach((t) => {
      const head = `add(${blobData}, ${hw * 32})`;
      hw += headWords(t);
      if (!isDynamicType(t)) {
        // a static component is decoded INLINE at its head position. A value type yields one word
        // (returned directly); a static aggregate is materialized into a fresh memory image.
        if (isStaticValueType(t)) {
          const w = this.fresh();
          out.push(`let ${w} := mload(${head})`);
          const g = this.validateInput(t, w);
          if (g) out.push(g);
          regs.push(w);
        } else {
          const ptr = this.fresh();
          out.push(`let ${ptr} := mload(0x40)`);
          const sz = this.abiDecFromMem(t, head, ptr, blobEnd, out);
          out.push(`mstore(0x40, add(${ptr}, ${sz}))`);
          regs.push(ptr);
        }
      } else {
        // a dynamic component: the head word is an offset relative to blobData. Bound it, then decode
        // the tail into a fresh memory image (the register holds that image pointer).
        const so = this.fresh();
        out.push(`let ${so} := mload(${head})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${blobData}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(t)}), ${blobEnd}) { revert(0, 0) }`);
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        const sz = this.abiDecFromMem(t, se, ptr, blobEnd, out);
        out.push(`mstore(0x40, add(${ptr}, ${sz}))`);
        regs.push(ptr);
      }
    });
    return regs;
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

  /** Echo a whole nested-STRUCT field of a dynamic-struct calldata param (return o.inner)
   *  into a fresh ABI return blob [0x20][tuple encoding]. Resolve the inner struct's tuple
   *  start via the navigator: lowerCdDynBase folds every step but the last to the containing
   *  tuple base; the last step's field is then resolved - a DYNAMIC nested struct reads its
   *  offset word (base resets to base+offset, calldataTupleAt) while a STATIC one is inline
   *  at the field offset. The whole inner struct is re-encoded from that tuple base by the
   *  same recursive calldata->memory codec (abiEncFromCd) the whole-param echo uses. */
  private echoCdDynField(place: CdDynPlace, t: JethType, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    const struct = t as JethType & { kind: 'struct' };
    const base = this.lowerCdDynBase(place, ctx, out);
    const last = place.steps[place.steps.length - 1]!;
    const fieldOff = last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
    let tupleStart: string;
    if (last.crossDynamic) {
      const nb = this.fresh();
      out.push(`let ${nb} := ${this.calldataTupleAt()}(${base}, ${fieldOff}, ${tupleHeadWords(struct) * 32})`);
      tupleStart = nb;
    } else {
      tupleStart = fieldOff;
    }
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    if (isDynamicType(t)) {
      out.push(`mstore(${ptr}, 0x20)`);
      const size = this.abiEncFromCd(t, tupleStart, `add(${ptr}, 0x20)`, true, out);
      out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
      return { ptr, size: `add(0x20, ${size})` };
    }
    const size = this.abiEncFromCd(t, tupleStart, ptr, true, out);
    out.push(`mstore(0x40, add(${ptr}, ${size}))`);
    return { ptr, size };
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

  /** `return ps[i]` (whole struct element of a calldata struct array): bounds-check i
   *  (Panic 0x32), resolve the element's calldata head (contiguous for a STATIC struct;
   *  offset-located via the per-element table for a DYNAMIC struct, with solc's unsigned
   *  2^64 cap + readability check), then re-encode it into a fresh ABI return blob via the
   *  recursive calldata codec (a static struct flat; a dynamic struct with the [0x20]
   *  wrapper). The calldata twin of returnStorageValue/structArrayElem. */
  private returnCdArrayElem(
    arr: ArrayExpr,
    index: Expr,
    t: JethType,
    ctx: LowerCtx,
    out: string[],
  ): { ptr: string; size: string } {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'calldata') throw new UnsupportedError('returnCdArrayElem requires a calldata array');
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(index, ctx, out)}`);
    out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
    const eb = this.fresh();
    if (isStaticType(t)) {
      // contiguous static elements: base = dataStart + i*stride (the whole payload was
      // already validated readable when the array was bound).
      const stride = abiHeadWords(t) * 32;
      out.push(`let ${eb} := add(${ref.offset}, mul(${i}, ${stride}))`);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      const size = this.abiEncFromCd(t, eb, ptr, true, out);
      out.push(`mstore(0x40, add(${ptr}, ${size}))`);
      return { ptr, size };
    }
    // dynamic element: ref.offset is the per-element offset-table base (= data start). Element
    // i's data is at base + offset[i]; mirror abiEncFromCd's dynamic-array element resolution.
    const so = this.fresh();
    out.push(`let ${so} := calldataload(add(${ref.offset}, mul(${i}, 0x20)))`);
    out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
    out.push(`let ${eb} := add(${ref.offset}, ${so})`);
    out.push(`if gt(add(${eb}, ${cdElemHeadBytes(t)}), calldatasize()) { revert(0, 0) }`);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`);
    const size = this.abiEncFromCd(t, eb, `add(${ptr}, 0x20)`, true, out);
    const total = this.fresh();
    out.push(`let ${total} := add(0x20, ${size})`);
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
            inner.push(
              `mstore(add(add(${dstHead}, mul(${i}, ${es})), ${leaf.abiWord * 32}), ${this.loadState(leaf.type, ls, leaf.storageOffset)})`,
            );
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
  /** Build an abi.encode* bytes value in memory ([len][data]) and return its pointer. With a
   *  `selector` (encodeWithSelector) or `sig` (encodeWithSignature: bytes4(keccak256(sig))), a 4-byte
   *  selector is prepended to the standard encoding of the remaining args. */
  private buildAbiEncode(
    args: Expr[],
    packed: boolean,
    ctx: LowerCtx,
    out: string[],
    selector?: Expr,
    sig?: Expr,
  ): string {
    if (selector || sig) {
      let pfx: string;
      if (selector) {
        pfx = this.lowerExpr(selector, ctx, out); // bytes4, left-aligned (high 4 bytes)
      } else {
        const { mp, len } = this.toMemory(this.lowerDynamic(sig!, ctx, out), out);
        const h = this.fresh();
        out.push(`let ${h} := keccak256(add(${mp}, 0x20), ${len})`);
        // keccak256(sig)[0:4] = the high 4 bytes, left-aligned.
        pfx = `and(${h}, 0xffffffff00000000000000000000000000000000000000000000000000000000)`;
      }
      return this.buildAbiEncodeWithSelector(pfx, args, ctx, out);
    }
    return packed ? this.buildAbiEncodePacked(args, ctx, out) : this.buildAbiEncodeStd(args, ctx, out);
  }

  /** abi.encodeWithSelector/Signature: a 4-byte selector prefix (left-aligned in a register) followed
   *  by the standard abi.encode of the remaining args. The args' internal offsets stay relative to the
   *  start of the args encoding (after the selector), matching solc (selector ++ abi.encode(args)). */
  private buildAbiEncodeWithSelector(pfx: string, args: Expr[], ctx: LowerCtx, out: string[]): string {
    const argsBytes = this.buildAbiEncodeStd(args, ctx, out); // [len][data]
    const argsLen = this.fresh();
    out.push(`let ${argsLen} := mload(${argsBytes})`);
    const total = this.fresh();
    out.push(`let ${total} := add(4, ${argsLen})`);
    const ptr = this.fresh();
    out.push(`let ${ptr} := ${this.alloc()}(add(0x40, and(add(${total}, 0x1f), not(0x1f))))`);
    out.push(`mstore(${ptr}, ${total})`);
    const data = this.fresh();
    out.push(`let ${data} := add(${ptr}, 0x20)`);
    out.push(`mstore(${data}, ${pfx})`); // 4 selector bytes (high) + 28 zero
    out.push(`mcopy(add(${data}, 4), add(${argsBytes}, 0x20), ${argsLen})`);
    out.push(`mstore(add(${data}, ${total}), 0)`); // zero the trailing partial word
    return ptr;
  }

  /** Standard ABI encoding (head/tail, 32-byte aligned) as a bytes value. A value -> a padded word;
   *  a STATIC struct/fixed-array -> abiHeadWords leaf words INLINE (no offset); a bytes/string -> a
   *  head offset + [len][padded data] tail; a DYNAMIC value-array -> a head offset + [len][elems] tail.
   *  The head uses a cumulative word offset (a static aggregate spans multiple inline head words). */
  private buildAbiEncodeStd(args: Expr[], ctx: LowerCtx, out: string[]): string {
    type Part =
      | { word: string }
      | { inline: true; mp: string; words: number }
      | { mp: string; len: string }
      | { mp: string; size: string };
    const parts: Part[] = args.map((a) => {
      const t = a.type;
      if (isBytesLike(t)) return this.toMemory(this.lowerDynamic(a, ctx, out), out);
      if (isStaticType(t) && (t.kind === 'struct' || t.kind === 'array'))
        return { inline: true, mp: this.aggToMemPtr(a, ctx, out), words: abiHeadWords(t) };
      if (t.kind === 'struct') return this.encodeDynStructToBlob(a, ctx, out); // dynamic struct -> offset + head/tail tail
      if (t.kind === 'array') return this.materializeArrayArg(a, ctx, out); // dynamic array (value or nested) -> {mp, size} tail
      return { word: this.lowerExpr(a, ctx, out) };
    });
    const headWords = parts.reduce((acc, p) => acc + ('inline' in p ? p.words : 1), 0);
    const headSize = 32 * headWords;
    const total = this.fresh();
    out.push(`let ${total} := ${headSize}`);
    for (const p of parts) {
      if ('len' in p) out.push(`${total} := add(${total}, add(0x20, and(add(${p.len}, 0x1f), not(0x1f))))`);
      else if ('size' in p) out.push(`${total} := add(${total}, ${p.size})`);
    }
    const ptr = this.fresh();
    out.push(`let ${ptr} := ${this.alloc()}(add(0x20, ${total}))`);
    out.push(`mstore(${ptr}, ${total})`);
    const data = this.fresh();
    out.push(`let ${data} := add(${ptr}, 0x20)`);
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${data}, ${headSize})`);
    let hw = 0;
    for (const p of parts) {
      const head = hw === 0 ? data : `add(${data}, ${32 * hw})`;
      if ('word' in p) {
        out.push(`mstore(${head}, ${p.word})`);
        hw += 1;
      } else if ('inline' in p) {
        out.push(`mcopy(${head}, ${p.mp}, ${p.words * 32})`);
        hw += p.words;
      } else if ('len' in p) {
        const pad = `and(add(${p.len}, 0x1f), not(0x1f))`;
        out.push(`mstore(${head}, sub(${cursor}, ${data}))`);
        out.push(`mstore(${cursor}, ${p.len})`);
        out.push(`mcopy(add(${cursor}, 0x20), add(${p.mp}, 0x20), ${pad})`);
        out.push(`${cursor} := add(${cursor}, add(0x20, ${pad}))`);
        hw += 1;
      } else {
        // dynamic value-array tail: [len][elems] blob, copied verbatim, offset in the head.
        out.push(`mstore(${head}, sub(${cursor}, ${data}))`);
        out.push(`mcopy(${cursor}, ${p.mp}, ${p.size})`);
        out.push(`${cursor} := add(${cursor}, ${p.size})`);
        hw += 1;
      }
    }
    return ptr;
  }

  /** Packed encoding (abi.encodePacked) as a bytes value: each value contributes its byte-width
   *  (no padding/length), each bytes/string its raw content. The final partial word is zeroed so the
   *  bytes value's tail padding is clean (a slack word is allocated to keep that write in-bounds).
   *
   *  Each part is normalized to a (dataPtr, byteLen) descriptor SPILLED to a memory array, then copied
   *  in a runtime loop. This keeps only a constant number of Yul locals live regardless of arg count -
   *  the previous version kept one local per part across the whole encode, so a long encodePacked / a
   *  many-part string.concat / a 3+-interpolation template overflowed the 16-slot stack (StackTooDeep).
   *  The descriptor array is allocated FIRST so part materializations (which bump the free pointer) never
   *  clobber it, and the result buffer is allocated LAST. Intermediate memory differs from solc's, but the
   *  RESULT bytes are identical (byte-identity targets returndata/storage/logs, not raw memory). */
  private buildAbiEncodePacked(args: Expr[], ctx: LowerCtx, out: string[]): string {
    const n = args.length;
    // descriptor array: n entries of (dataPtr, byteLen), allocated before any part materializes.
    const desc = this.fresh();
    out.push(`let ${desc} := ${this.alloc()}(${Math.max(n, 1) * 0x40})`);
    const total = this.fresh();
    out.push(`let ${total} := 0`);
    const writeDesc = (i: number, dataPtr: string, len: string) => {
      const dpSlot = i === 0 ? desc : `add(${desc}, ${i * 0x40})`;
      out.push(`mstore(${dpSlot}, ${dataPtr})`);
      out.push(`mstore(add(${desc}, ${i * 0x40 + 0x20}), ${len})`);
      out.push(`${total} := add(${total}, ${len})`);
    };
    args.forEach((a, i) => {
      const t = a.type;
      if (isBytesLike(t)) {
        // bytes/string: its raw content (data after the [len] word).
        const { mp, len } = this.toMemory(this.lowerDynamic(a, ctx, out), out);
        writeDesc(i, `add(${mp}, 0x20)`, len);
      } else if (t.kind === 'array') {
        // a value-element array: each element padded to 32 bytes (its ABI element words), no length.
        if (t.length !== undefined) {
          writeDesc(i, this.aggToMemPtr(a, ctx, out), String(t.length * 32));
        } else {
          const m = this.materializeArrayArg(a, ctx, out); // {mp,size} = [len][elems]
          writeDesc(i, `add(${m.mp}, 0x20)`, `sub(${m.size}, 0x20)`);
        }
      } else {
        // a value: stage its left-aligned `width` content bytes in a scratch word, descriptor -> that word.
        const width = storageByteSize(t);
        const val = this.lowerExpr(a, ctx, out);
        const aligned = t.kind === 'bytesN' || width === 32 ? val : `shl(${(32 - width) * 8}, ${val})`;
        const w = this.fresh();
        out.push(`let ${w} := ${this.alloc()}(0x20)`);
        out.push(`mstore(${w}, ${aligned})`);
        writeDesc(i, w, String(width));
      }
    });
    // allocate the result LAST (length word + rounded data + a slack word for the trailing zero).
    const ptr = this.fresh();
    out.push(`let ${ptr} := ${this.alloc()}(add(0x40, and(add(${total}, 0x1f), not(0x1f))))`);
    out.push(`mstore(${ptr}, ${total})`);
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${ptr}, 0x20)`);
    if (n > 0) {
      const i = this.fresh();
      const dp = this.fresh();
      const ln = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${n * 0x40}) { ${i} := add(${i}, 0x40) } {`);
      out.push(`  let ${dp} := mload(add(${desc}, ${i}))`);
      out.push(`  let ${ln} := mload(add(add(${desc}, ${i}), 0x20))`);
      out.push(`  mcopy(${cursor}, ${dp}, ${ln})`);
      out.push(`  ${cursor} := add(${cursor}, ${ln})`);
      out.push(`}`);
    }
    out.push(`mstore(${cursor}, 0)`); // zero the trailing partial word
    return ptr;
  }

  private lowerDynamic(e: Expr, ctx: LowerCtx, out: string[]): DynRef {
    switch (e.kind) {
      case 'rawReg':
        // a pre-computed register holding a [len][data] MEMORY pointer (e.g. the buffered modifier
        // return reg, set from userfn_<key> which returns a bytes/string aggregate as a memory ptr).
        return { src: 'memory', ptr: e.reg };
      case 'cast':
        // bytes(string) / string(bytes): a no-op reinterpret of the same [len][data] dynamic value.
        return this.lowerDynamic(e.operand, ctx, out);
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
      case 'msgData':
        // msg.data is the WHOLE calldata (selector included), so data starts at 0 and
        // length is calldatasize() (matches solc: msg.data.length == calldatasize()).
        return { src: 'calldata', dataPtr: '0', len: 'calldatasize()' };
      case 'calldataSlice': {
        // <calldata bytes>.slice(start[, end]) -> a zero-copy sub-view: dataPtr+start, len = end-start.
        // Byte-identical to solc data[start:end]: require(start <= end && end <= baseLen) else revert EMPTY.
        // Order: lower the base, then start, then end (matching solc left-to-right operand evaluation).
        const ref = this.lowerDynamic(e.base, ctx, out);
        if (ref.src !== 'calldata')
          throw new UnsupportedError('calldataSlice base must be a calldata bytes value');
        const baseData = this.fresh();
        const baseLen = this.fresh();
        out.push(`let ${baseData} := ${ref.dataPtr}`);
        out.push(`let ${baseLen} := ${ref.len}`);
        const start = this.fresh();
        out.push(`let ${start} := ${this.lowerExpr(e.start, ctx, out)}`);
        const end = this.fresh();
        if (e.end) out.push(`let ${end} := ${this.lowerExpr(e.end, ctx, out)}`);
        else out.push(`let ${end} := ${baseLen}`);
        out.push(`if gt(${start}, ${end}) { revert(0, 0) }`);
        out.push(`if gt(${end}, ${baseLen}) { revert(0, 0) }`);
        const dataPtr = this.fresh();
        const len = this.fresh();
        out.push(`let ${dataPtr} := add(${baseData}, ${start})`);
        out.push(`let ${len} := sub(${end}, ${start})`);
        return { src: 'calldata', dataPtr, len };
      }
      case 'abiEncode':
        return { src: 'memory', ptr: this.buildAbiEncode(e.args, e.packed, ctx, out, e.selector, e.sig) };
      case 'abiDecode':
        // abi.decode(data, T) / data.decode(T) with a bytes/string T: the decoded value is a fresh
        // memory [len][data] image; the single component register is its pointer.
        return { src: 'memory', ptr: this.lowerAbiDecode(e.data, [e.type], ctx, out)[0]! };
      case 'extCode': {
        // <addr>.code -> the deployed bytecode as a fresh bytes blob (EXTCODESIZE + EXTCODECOPY).
        // (codehash is a single word, handled in lowerExpr; this case is only the `code` member.)
        const a = this.fresh();
        out.push(`let ${a} := ${this.lowerExpr(e.addr, ctx, out)}`);
        const sz = this.fresh();
        out.push(`let ${sz} := extcodesize(${a})`);
        const ptr = this.fresh();
        out.push(`let ${ptr} := ${this.alloc()}(add(0x20, and(add(${sz}, 0x1f), not(0x1f))))`);
        out.push(`mstore(${ptr}, ${sz})`);
        out.push(`extcodecopy(${a}, add(${ptr}, 0x20), 0, ${sz})`);
        out.push(`if mod(${sz}, 0x20) { mstore(add(add(${ptr}, 0x20), ${sz}), 0) }`);
        return { src: 'memory', ptr };
      }
      case 'modexp': {
        // modexp(base, exp, mod) (precompile 0x05). Materialize each operand to memory FIRST (an
        // allocating arg must not bump the FMP between the input alloc and the mcopies), then build the
        // input blob 32B Bsize || 32B Esize || 32B Msize || base || exp || mod (unpadded totalIn passed to
        // staticcall), revert EMPTY on ok=0, capture the returndata into a fresh [len][data] blob.
        const b = this.toMemory(this.lowerDynamic(e.base, ctx, out), out);
        const ex = this.toMemory(this.lowerDynamic(e.exp, ctx, out), out);
        const md = this.toMemory(this.lowerDynamic(e.mod, ctx, out), out);
        const total = this.fresh();
        out.push(`let ${total} := add(0x60, add(${b.len}, add(${ex.len}, ${md.len})))`);
        const inp = this.fresh();
        out.push(`let ${inp} := ${this.alloc()}(${total})`);
        out.push(`mstore(${inp}, ${b.len})`);
        out.push(`mstore(add(${inp}, 0x20), ${ex.len})`);
        out.push(`mstore(add(${inp}, 0x40), ${md.len})`);
        out.push(`mcopy(add(${inp}, 0x60), add(${b.mp}, 0x20), ${b.len})`);
        out.push(`mcopy(add(add(${inp}, 0x60), ${b.len}), add(${ex.mp}, 0x20), ${ex.len})`);
        out.push(`mcopy(add(add(add(${inp}, 0x60), ${b.len}), ${ex.len}), add(${md.mp}, 0x20), ${md.len})`);
        out.push(`if iszero(staticcall(gas(), 0x05, ${inp}, ${total}, 0, 0)) { revert(0, 0) }`);
        const ptr = this.captureReturndata(out);
        return { src: 'memory', ptr };
      }
      case 'blake2f': {
        // blake2f(rounds:u32, h(64), m(128), t:bytes16, f:bool) (precompile 0x09). Build the 213-byte
        // EIP-152 blob: rounds(4 BE) | h(64) | m(128) | t(16) | f(1). h/m length-guards revert EMPTY.
        const h = this.toMemory(this.lowerDynamic(e.h, ctx, out), out);
        const m = this.toMemory(this.lowerDynamic(e.m, ctx, out), out);
        out.push(`if iszero(eq(${h.len}, 64)) { revert(0, 0) }`);
        out.push(`if iszero(eq(${m.len}, 128)) { revert(0, 0) }`);
        const rounds = this.lowerExpr(e.rounds, ctx, out);
        const t = this.lowerExpr(e.t, ctx, out);
        const f = this.lowerExpr(e.f, ctx, out);
        // allocate the 64-byte output bytes blob FIRST (so the t-store's zero-write past byte 212 cannot
        // touch it); then the 213-byte input blob.
        const o = this.fresh();
        out.push(`let ${o} := ${this.alloc()}(0x60)`);
        out.push(`mstore(${o}, 64)`);
        const p = this.fresh();
        out.push(`let ${p} := ${this.alloc()}(213)`);
        out.push(`mstore(${p}, shl(224, ${rounds}))`);
        out.push(`mcopy(add(${p}, 4), add(${h.mp}, 0x20), 64)`);
        out.push(`mcopy(add(${p}, 68), add(${m.mp}, 0x20), 128)`);
        out.push(`mstore(add(${p}, 196), ${t})`);
        out.push(`mstore8(add(${p}, 212), ${f})`);
        out.push(`if iszero(staticcall(gas(), 9, ${p}, 213, add(${o}, 0x20), 64)) { revert(0, 0) }`);
        return { src: 'memory', ptr: o };
      }
      case 'callData':
        // this.data inside a success condition: the returndata blob pointer bound for this check.
        return { src: 'memory', ptr: this.ctxLookup(ctx, EXT_CALL_DATA_BINDING) };
      case 'catchReason':
        // `this.reason` inside a try/catch catch body: the SOFT-decoded Error(string).
        return { src: 'memory', ptr: this.lowerCatchReason(ctx, out) };
      case 'extCall': {
        // perform the CALL/STATICCALL, then run the ordered success checks (the first failing
        // condition reverts with its reason). Yields the returndata bytes.
        const { okReg, dataPtr } = this.emitExtCall(e, ctx, out);
        this.lowerSuccessChecks(e.checks, okReg, dataPtr, ctx, out);
        return { src: 'memory', ptr: dataPtr };
      }
      case 'call': {
        // a bytes/string-returning internal call: the callee returns a [len][data] memory pointer.
        const p = this.fresh();
        out.push(`let ${p} := ${this.lowerExpr(e, ctx, out)}`);
        return { src: 'memory', ptr: p };
      }
      case 'ternary': {
        // a bytes/string ternary `c ? a : b`: short-circuit (only the taken branch is
        // materialized), then select the [len][data] pointer. Matches Solidity (the untaken
        // branch is not evaluated, so a reverting/side-effecting branch is safe).
        const c = this.lowerExpr(e.cond, ctx, out);
        const ptr = this.fresh();
        out.push(`let ${ptr} := 0`);
        const thenOut: string[] = [];
        const { mp: mpT } = this.toMemory(this.lowerDynamic(e.then, ctx, thenOut), thenOut);
        const elseOut: string[] = [];
        const { mp: mpE } = this.toMemory(this.lowerDynamic(e.else, ctx, elseOut), elseOut);
        out.push(`switch ${c}`);
        out.push('case 0 {');
        for (const l of elseOut) out.push('  ' + l);
        out.push(`  ${ptr} := ${mpE}`);
        out.push('}');
        out.push('default {');
        for (const l of thenOut) out.push('  ' + l);
        out.push(`  ${ptr} := ${mpT}`);
        out.push('}');
        return { src: 'memory', ptr };
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
        const slot = this.strArrayElemSlot(e.arr, e.index, ctx, out, e.oobEmpty);
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

  /** The raw solc `ecrecover` expansion: staticcall(0x01) over [hash | left-padded-v | r | s] (128 bytes)
   *  into a FRESH free-memory buffer (avoids the 0x40/0x60 scratch clobber). Returns a register holding the
   *  recovered address, or 0 on ANY failure - NEVER reverts. The `and(success, eq(returndatasize(),0x20))`
   *  guard is mandatory: the precompile writes NOTHING on failure, so an unguarded mload leaks stale memory.
   *  Reused by the raw `ecrecover`, the safe `recover`, and the never-reverting `tryRecover`. */
  private emitEcrecover(hash: string, v: string, r: string, s: string, out: string[]): string {
    const p = this.fresh();
    const res = this.fresh();
    out.push(`let ${p} := mload(0x40)`);
    out.push(`mstore(${p}, ${hash})`);
    out.push(`mstore(add(${p}, 0x20), and(${v}, 0xff))`);
    out.push(`mstore(add(${p}, 0x40), ${r})`);
    out.push(`mstore(add(${p}, 0x60), ${s})`);
    out.push(`let ${res} := 0`);
    // Bind the staticcall success to a variable FIRST: Yul evaluates an `and(a, b)`'s arguments
    // right-to-left, so an inline `and(staticcall(...), eq(returndatasize(),0x20))` would read the
    // STALE (pre-call) returndatasize and always discard the result. solc's expansion splits it too.
    const ok = this.fresh();
    out.push(`let ${ok} := staticcall(gas(), 1, ${p}, 0x80, ${p}, 0x20)`);
    out.push(`if and(${ok}, eq(returndatasize(), 0x20)) { ${res} := mload(${p}) }`);
    return res;
  }

  /** Copy the current returndata into a FRESH [len][data] memory bytes blob (length-word at the returned
   *  pointer), tail-zeroing a partial last word. Used by modexp (the precompile returns Msize raw bytes). */
  private captureReturndata(out: string[]): string {
    const dataPtr = this.fresh();
    const rlen = this.fresh();
    out.push(`let ${rlen} := returndatasize()`);
    out.push(`let ${dataPtr} := ${this.alloc()}(add(0x20, and(add(${rlen}, 0x1f), not(0x1f))))`);
    out.push(`mstore(${dataPtr}, ${rlen})`);
    out.push(`returndatacopy(add(${dataPtr}, 0x20), 0, ${rlen})`);
    out.push(`if mod(${rlen}, 0x20) { mstore(add(add(${dataPtr}, 0x20), ${rlen}), 0) }`);
    return dataPtr;
  }

  /** Phase 6: perform a low-level CALL/STATICCALL. Lowers the data/value/gas operands, executes the
   *  opcode (args = the data blob's [add(ptr,0x20), mload(ptr)] region, output discarded), and copies
   *  the returndata into a FRESH memory bytes blob ([len][data], length-word at the returned ptr).
   *  Returns the success-bool register and the returndata-blob pointer. Used by both the checked
   *  (extCall expr) and raw (tryCall destructure) forms; the data blob is fully materialized BEFORE
   *  the call so it cannot alias the returndata buffer. */
  private emitExtCall(
    e: {
      op: 'call' | 'staticcall' | 'delegatecall';
      addr?: Expr;
      lib?: string;
      data: Expr;
      value?: Expr;
      gas?: Expr;
      bubble?: boolean;
      codeGuard?: boolean;
    },
    ctx: LowerCtx,
    out: string[],
  ): { okReg: string; dataPtr: string; addrReg: string } {
    // Phase B external library: a DELEGATECALL to a LINK-TIME library address. The target is
    // `linkersymbol("<lib>")` (solc emits the `__$..$__` placeholder + a linkReference); no addr/value/
    // gas operands. The whole rest (encode -> call -> capture returndata -> bubble) is shared with the
    // call/staticcall path.
    const isDelegate = e.op === 'delegatecall';
    // Evaluate operands left-to-right: target, then value (call only), then gas, then the data blob.
    const addr = this.fresh();
    if (isDelegate) {
      out.push(`let ${addr} := linkersymbol("${e.lib}")`);
    } else {
      out.push(`let ${addr} := ${this.lowerExpr(e.addr!, ctx, out)}`);
    }
    let valueExpr = '0';
    if (e.op === 'call' && e.value) {
      const v = this.fresh();
      out.push(`let ${v} := ${this.lowerExpr(e.value, ctx, out)}`);
      valueExpr = v;
    }
    let gasExpr = 'gas()'; // default: forward all remaining gas (matches solc's t.call(d))
    if (e.gas) {
      const g = this.fresh();
      out.push(`let ${g} := ${this.lowerExpr(e.gas, ctx, out)}`);
      gasExpr = g;
    }
    const { mp, len } = this.toMemory(this.lowerDynamic(e.data, ctx, out), out);
    const okReg = this.fresh();
    const argsOff = `add(${mp}, 0x20)`;
    if (e.op === 'staticcall') {
      out.push(`let ${okReg} := staticcall(${gasExpr}, ${addr}, ${argsOff}, ${len}, 0, 0)`);
    } else if (e.op === 'delegatecall') {
      out.push(`let ${okReg} := delegatecall(${gasExpr}, ${addr}, ${argsOff}, ${len}, 0, 0)`);
    } else {
      out.push(`let ${okReg} := call(${gasExpr}, ${addr}, ${valueExpr}, ${argsOff}, ${len}, 0, 0)`);
    }
    // Copy returndata into a fresh [len][data] blob (always captured, even on failure).
    const dataPtr = this.fresh();
    const rlen = this.fresh();
    out.push(`let ${rlen} := returndatasize()`);
    out.push(`let ${dataPtr} := ${this.alloc()}(add(0x20, and(add(${rlen}, 0x1f), not(0x1f))))`);
    out.push(`mstore(${dataPtr}, ${rlen})`);
    out.push(`returndatacopy(add(${dataPtr}, 0x20), 0, ${rlen})`);
    out.push(`if mod(${rlen}, 0x20) { mstore(add(add(${dataPtr}, 0x20), ${rlen}), 0) }`);
    // High-level typed interface call: bubble the callee's revert bytes VERBATIM, then guard against a
    // non-contract target. Order matches solc: failure-bubble first (an EOA call returns ok=true+empty,
    // so the bubble is skipped), then the extcodesize guard reverts empty for an EOA / never-deployed
    // address. (NO re-eval of the addr Expr - reuse the register evaluated above.)
    if (e.bubble) {
      out.push(`if iszero(${okReg}) { revert(add(${dataPtr}, 0x20), mload(${dataPtr})) }`);
    }
    if (e.codeGuard) {
      out.push(`if iszero(extcodesize(${addr})) { revert(0, 0) }`);
    }
    // Expose the addr register too: try/catch emits its codeGuard INSIDE the ok-branch without
    // re-evaluating the addr Expr (no double-eval of side effects).
    return { okReg, dataPtr, addrReg: addr };
  }

  /** Lower the ordered success checks of a `.call/.staticcall`. Each condition is evaluated with
   *  `this.ok` (the success bool) and `this.data` (the returndata blob) bound; the FIRST condition
   *  that is false reverts with its reason (the others are not evaluated past the revert). */
  private lowerSuccessChecks(
    checks: SuccessCheck[],
    okReg: string,
    dataPtr: string,
    ctx: LowerCtx,
    out: string[],
  ): void {
    if (checks.length === 0) return;
    this.ctxPush(ctx);
    this.ctxDeclare(ctx, EXT_CALL_OK_BINDING, okReg);
    this.ctxDeclare(ctx, EXT_CALL_DATA_BINDING, dataPtr);
    for (const chk of checks) {
      const cond = this.lowerExpr(chk.cond, ctx, out); // condition prep (e.g. abi.decode) emits to out
      const reasonLines = this.lowerRevertReason(chk.reason, ctx, out);
      out.push(`if iszero(${cond}) {`);
      for (const l of reasonLines) out.push('  ' + l);
      out.push('}');
    }
    this.ctxPop(ctx);
  }

  /** b[i] -> bytes1 (left-aligned), Panic(0x32) on out-of-bounds. */
  private lowerByteIndex(e: Expr & { kind: 'byteIndex' }, ctx: LowerCtx, out: string[]): string {
    // bytesN[i]: byte i of a fixed-bytes VALUE (a left-aligned word). Bound i < size (Panic 0x32),
    // then extract byte i (0-indexed from the MSB) and re-left-align it as a bytes1.
    if (e.base.type.kind === 'bytesN') {
      const size = e.base.type.size;
      const w = this.fresh();
      out.push(`let ${w} := ${this.lowerExpr(e.base, ctx, out)}`);
      const i = this.fresh();
      out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
      out.push(`if iszero(lt(${i}, ${size})) { ${this.panic()}(0x32) }`);
      return `shl(248, byte(${i}, ${w}))`;
    }
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
      this.helpers.set(
        name,
        `function ${name}(size) -> ptr {
  ptr := mload(0x40)
  mstore(0x40, add(ptr, and(add(size, 0x1f), not(0x1f))))
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(off, stride) -> dataOff, len {
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let p := add(4, off)
  if iszero(slt(add(p, 0x1f), calldatasize())) { revert(0, 0) }
  len := calldataload(p)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  dataOff := add(p, 0x20)
  if gt(add(dataOff, mul(len, stride)), calldatasize()) { revert(0, 0) }
}`,
      );
    }
    return name;
  }

  /** Decode a dynamic VALUE-array field of a calldata dynamic struct: the offset word at `offPtr`
   *  points (relative to the containing tuple `base`, spec 3.2) to the array's [len][elems]. Mirrors
   *  solc's array-member decode: UNSIGNED offset bound, length-word readable, and the FULL len*stride
   *  payload must fit within calldatasize (unlike the bytes/string helper jeth_calldata_dyn_at, which
   *  validates len+0x20 bytes and uses a SIGNED offset check). Returns (dataOff, len). */
  private calldataArrayAt(): string {
    const name = 'jeth_calldata_array_at';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(base, offPtr, stride) -> dataOff, len {
  let off := calldataload(offPtr)
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let p := add(base, off)
  if iszero(slt(add(p, 0x1f), calldatasize())) { revert(0, 0) }
  len := calldataload(p)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  dataOff := add(p, 0x20)
  if gt(add(dataOff, mul(len, stride)), calldatasize()) { revert(0, 0) }
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(off) -> tableStart, len {
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let p := add(4, off)
  if iszero(slt(add(p, 0x1f), calldatasize())) { revert(0, 0) }
  len := calldataload(p)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  tableStart := add(p, 0x20)
  if gt(add(tableStart, mul(len, 0x20)), calldatasize()) { revert(0, 0) }
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(tableStart, i) -> dataPtr, len {
  let offPtr := add(tableStart, mul(i, 0x20))
  let elOff := calldataload(offPtr)
  if iszero(slt(elOff, sub(sub(calldatasize(), tableStart), 0x1f))) { revert(0, 0) }
  let lenPtr := add(tableStart, elOff)
  len := calldataload(lenPtr)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  if sgt(lenPtr, sub(calldatasize(), add(len, 0x20))) { revert(0, 0) }
  dataPtr := add(lenPtr, 0x20)
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(tableStart, i) -> dataPtr, len {
  let offPtr := add(tableStart, mul(i, 0x20))
  let elOff := calldataload(offPtr)
  if gt(elOff, 0xffffffffffffffff) { revert(0, 0) }
  let lenPtr := add(tableStart, elOff)
  if gt(add(lenPtr, 0x20), calldatasize()) { revert(0, 0) }
  len := calldataload(lenPtr)
  dataPtr := add(lenPtr, 0x20)
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(base, i, stride) -> dataOff, innerLen {
  let offPtr := add(base, mul(i, 0x20))
  let innerOff := calldataload(offPtr)
  if iszero(slt(innerOff, sub(sub(calldatasize(), base), 0x1f))) { revert(0, 0) }
  let lenPtr := add(base, innerOff)
  innerLen := calldataload(lenPtr)
  if gt(innerLen, 0xffffffffffffffff) { revert(0, 0) }
  if sgt(lenPtr, sub(calldatasize(), add(mul(innerLen, stride), 0x20))) { revert(0, 0) }
  dataOff := add(lenPtr, 0x20)
}`,
      );
    }
    return name;
  }

  /** Navigate ONE offset-table level whose element has NO length word - an element that is itself a
   *  fixed-array-of-dynamic (Arr<string,N> = its N-word offset table) or a bytes/string header.
   *  Element idx's data starts at base + calldataload(base + idx*32) (offset relative to the table
   *  start). Mirrors calldataInnerArray's unsigned offset validation but reads no length word. */
  private calldataNestedOff(): string {
    const name = 'jeth_calldata_nested_off';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(base, idx) -> elemData {
  let off := calldataload(add(base, mul(idx, 0x20)))
  if iszero(slt(off, sub(sub(calldatasize(), base), 0x1f))) { revert(0, 0) }
  elemData := add(base, off)
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(base, i) -> dataOff, innerLen {
  let offPtr := add(base, mul(i, 0x20))
  let innerOff := calldataload(offPtr)
  if gt(innerOff, 0xffffffffffffffff) { revert(0, 0) }
  let lenPtr := add(base, innerOff)
  if gt(add(lenPtr, 0x20), calldatasize()) { revert(0, 0) }
  innerLen := calldataload(lenPtr)
  dataOff := add(lenPtr, 0x20)
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(off, headSize) -> tupleStart {
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  tupleStart := add(4, off)
  if gt(add(tupleStart, headSize), calldatasize()) { revert(0, 0) }
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(base, offPtr, headSize) -> tupleStart {
  if gt(add(offPtr, 0x20), calldatasize()) { revert(0, 0) }
  let off := calldataload(offPtr)
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  tupleStart := add(base, off)
  if gt(add(tupleStart, headSize), calldatasize()) { revert(0, 0) }
}`,
      );
    }
    return name;
  }

  private calldataDyn(): string {
    const name = 'jeth_calldata_dyn';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(off) -> dataPtr, len {
  let argsLen := sub(calldatasize(), 4)
  if or(lt(argsLen, 0x20), gt(off, sub(argsLen, 0x20))) { revert(0, 0) }
  let lp := add(4, off)
  len := calldataload(lp)
  if gt(len, sub(sub(argsLen, off), 0x20)) { revert(0, 0) }
  dataPtr := add(lp, 0x20)
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(base, offPtr) -> dataPtr, len {
  let off := calldataload(offPtr)
  if iszero(slt(off, sub(sub(calldatasize(), base), 0x1f))) { revert(0, 0) }
  let lp := add(base, off)
  len := calldataload(lp)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  if sgt(lp, sub(calldatasize(), add(len, 0x20))) { revert(0, 0) }
  dataPtr := add(lp, 0x20)
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(base, offPtr) -> dataPtr, len {
  let off := calldataload(offPtr)
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let lp := add(base, off)
  if gt(add(lp, 0x20), calldatasize()) { revert(0, 0) }
  len := calldataload(lp)
  dataPtr := add(lp, 0x20)
}`,
      );
    }
    return name;
  }

  private strLen(): string {
    const name = 'jeth_str_len';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot) -> l {
  let w := sload(slot)
  switch and(w, 1)
  case 0 { l := shr(1, and(w, 0xff)) }
  default { l := shr(1, sub(w, 1)) }
}`,
      );
    }
    return name;
  }

  /** Copy a storage bytes/string at `slot` directly to memory `dst` as [len][right-
   *  padded data], WITHOUT allocating (so it never clobbers an output blob under
   *  construction at the free pointer). Returns the byte size written. */
  private copyStrToMem(): string {
    const name = 'jeth_copy_str_to_mem';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot, dst) -> size {
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
}`,
      );
    }
    return name;
  }

  private loadStr(): string {
    const name = 'jeth_load_str';
    if (!this.helpers.has(name)) {
      this.alloc();
      this.helpers.set(
        name,
        `function ${name}(slot) -> mp, len {
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
}`,
      );
    }
    return name;
  }

  private strByteAt(): string {
    const name = 'jeth_str_byte_at';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot, i) -> r {
  let w := sload(slot)
  switch and(w, 1)
  case 0 { r := and(shl(mul(i, 8), w), ${TOP_BYTE}) }
  default {
    mstore(0x00, slot)
    let base := keccak256(0x00, 0x20)
    r := and(shl(mul(mod(i, 0x20), 8), sload(add(base, div(i, 0x20)))), ${TOP_BYTE})
  }
}`,
      );
    }
    return name;
  }

  /** Write byte i (bounds-checked) of a storage `bytes` to the bytes1 value `b` (left-aligned, byte in
   *  the top byte). Same short/long layout as strByteAt: short = data in the high bytes of the slot,
   *  long = at keccak(slot)+i/32. Read-modify-writes only the target byte; the length is unchanged. */
  private strByteSet(): string {
    const name = 'jeth_str_byte_set';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot, i, b) {
  let w := sload(slot)
  switch and(w, 1)
  case 0 {
    if iszero(lt(i, and(shr(1, w), 0x7f))) { ${this.panic()}(0x32) }
    let sh := mul(i, 8)
    sstore(slot, or(and(w, not(shr(sh, ${TOP_BYTE}))), shr(sh, and(b, ${TOP_BYTE}))))
  }
  default {
    if iszero(lt(i, shr(1, sub(w, 1)))) { ${this.panic()}(0x32) }
    mstore(0x00, slot)
    let ds := add(keccak256(0x00, 0x20), div(i, 0x20))
    let sh := mul(mod(i, 0x20), 8)
    sstore(ds, or(and(sload(ds), not(shr(sh, ${TOP_BYTE}))), shr(sh, and(b, ${TOP_BYTE}))))
  }
}`,
      );
    }
    return name;
  }

  /** Append byte `b` (a bytes1, byte in the top byte) to a storage `bytes`. Short form stays short
   *  until 31 bytes; the 31->32 push transitions to long (data moved to keccak(slot)); long appends at
   *  keccak(slot)+len/32. Matches solc's storage layout byte-for-byte (verified against raw slots). */
  private strPush(): string {
    const name = 'jeth_str_push';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot, b) {
  let w := sload(slot)
  switch and(w, 1)
  case 0 {
    let len := shr(1, and(w, 0xff))
    switch lt(len, 31)
    case 1 {
      let nw := or(w, shr(mul(len, 8), and(b, ${TOP_BYTE})))
      sstore(slot, or(and(nw, not(0xff)), shl(1, add(len, 1))))
    }
    default {
      mstore(0x00, slot)
      sstore(keccak256(0x00, 0x20), or(and(w, not(0xff)), shr(248, and(b, ${TOP_BYTE}))))
      sstore(slot, 65)
    }
  }
  default {
    let len := shr(1, sub(w, 1))
    mstore(0x00, slot)
    let ds := add(keccak256(0x00, 0x20), div(len, 0x20))
    let sh := mul(mod(len, 0x20), 8)
    sstore(ds, or(and(sload(ds), not(shr(sh, ${TOP_BYTE}))), shr(sh, and(b, ${TOP_BYTE}))))
    sstore(slot, add(w, 2))
  }
}`,
      );
    }
    return name;
  }

  /** Remove the last byte of a storage `bytes` (Panic 0x31 if empty). Short pop zeroes the byte +
   *  decrements; long pop zeroes the freed byte; the 32->31 pop transitions back to short (data moved
   *  inline, keccak(slot) word freed). Matches solc's storage layout byte-for-byte. */
  private strPop(): string {
    const name = 'jeth_str_pop';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot) {
  let w := sload(slot)
  switch and(w, 1)
  case 0 {
    let len := shr(1, and(w, 0xff))
    if iszero(len) { ${this.panic()}(0x31) }
    let nw := and(w, not(shr(mul(sub(len, 1), 8), ${TOP_BYTE})))
    sstore(slot, or(and(nw, not(0xff)), shl(1, sub(len, 1))))
  }
  default {
    let len := shr(1, sub(w, 1))
    switch eq(len, 32)
    case 1 {
      mstore(0x00, slot)
      let base := keccak256(0x00, 0x20)
      let kd0 := sload(base)
      sstore(base, 0)
      sstore(slot, or(and(kd0, not(0xff)), 62))
    }
    default {
      mstore(0x00, slot)
      let ds := add(keccak256(0x00, 0x20), div(sub(len, 1), 0x20))
      let sh := mul(mod(sub(len, 1), 0x20), 8)
      sstore(ds, and(sload(ds), not(shr(sh, ${TOP_BYTE}))))
      sstore(slot, sub(w, 2))
    }
  }
}`,
      );
    }
    return name;
  }

  /** Clear a storage bytes/string slot to empty: zero the header AND (for a long
   *  value) its keccak(slot) data slots. Matches solc's full clear on pop/delete. */
  private clearStr(): string {
    const name = 'jeth_clear_str';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot) {
  let oldw := sload(slot)
  sstore(slot, 0)
  if and(oldw, 1) {
    let oldLen := shr(1, sub(oldw, 1))
    let oldWords := div(add(oldLen, 0x1f), 0x20)
    mstore(0x00, slot)
    let base := keccak256(0x00, 0x20)
    for { let i := 0 } lt(i, oldWords) { i := add(i, 1) } { sstore(add(base, i), 0) }
  }
}`,
      );
    }
    return name;
  }

  private storeStrMem(): string {
    const name = 'jeth_store_str_mem';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot, mp, len) {
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
}`,
      );
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
      if (isBytesLike(key.type)) {
        // bytes/string key: slot = keccak256(keyContent . slotWord) over the RAW content bytes
        // (unpadded) concatenated with the 32-byte slot (solc's mapping-with-dynamic-key rule).
        const { mp, len } = this.toMemory(this.lowerDynamic(key, ctx, out), out);
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        out.push(`mcopy(${ptr}, add(${mp}, 0x20), ${len})`); // copy content to a fresh scratch region
        out.push(`mstore(add(${ptr}, ${len}), ${slot})`); // append the slot word right after the content
        const t = this.fresh();
        out.push(`let ${t} := keccak256(${ptr}, add(${len}, 0x20))`);
        slot = t;
        continue;
      }
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
      // an aggregate arg (struct / dynamic value array / bytes / string) is passed BY MEMORY
      // REFERENCE (alias for a memory source, fresh copy for storage/calldata/literal); a value arg
      // is a plain register.
      const isAgg = a.type.kind === 'struct' || a.type.kind === 'array' || isBytesLike(a.type);
      const reg = isAgg ? this.aggArgToMemPtr(a, ctx, out) : this.lowerExpr(a, ctx, out);
      const t = this.fresh();
      out.push(`let ${t} := ${reg}`);
      return t;
    });
  }

  /** Evaluate a tuple destructuring source into one value register per component (left-to-right).
   *  A multi-value internal call yields all components at once (`let r0, r1 := f(args)`); a tuple
   *  of expressions evaluates each into its own temp. */
  private lowerDestructureSource(source: DestructureSource, ctx: LowerCtx, out: string[]): string[] {
    if (source.kind === 'call') {
      const args = this.lowerCallArgs(source.args, ctx, out);
      const n = this.funcs.get(source.fn)?.returnTypes?.length ?? 0;
      const regs = Array.from({ length: n }, () => this.fresh());
      out.push(`let ${regs.join(', ')} := ${this.userFnName(source.fn)}(${args.join(', ')})`);
      return regs;
    }
    if (source.kind === 'extCall') {
      // `let [ok, ret] = addr.tryCall/tryStaticcall({...})`: raw CALL, no checks. Two components:
      // the success bool and the returndata bytes blob pointer (the bytes ret binds as a memory local
      // exactly like any [len][data] pointer; the analyzer registered it in memDynLocals).
      const { okReg, dataPtr } = this.emitExtCall(source, ctx, out);
      return [okReg, dataPtr];
    }
    if (source.kind === 'abiDecode') {
      // `let [a, b] = abi.decode(data, [T1, T2])`: decode each component into its own register (a value
      // word, or a memory image pointer for a bytes/string/array/struct component; the analyzer
      // registered the reference components in the matching side-tables, like a localDecl).
      return this.lowerAbiDecode(source.data, source.types, ctx, out);
    }
    if (source.kind === 'tryRecover') {
      // `let [ok, signer] = tryRecover(hash, sig)`: the never-reverting OZ ECDSA.tryRecover. Read r/s/v
      // from the memory image of `sig`; init (0, 0); only a 65-byte, non-high-s, non-zero-signer case
      // yields (1, signer). Mirrors the recover gate without any revert (every bad case is (false, 0)).
      const hash = this.lowerExpr(source.hash, ctx, out);
      const { mp, len } = this.toMemory(this.lowerDynamic(source.sig, ctx, out), out);
      const okReg = this.fresh();
      const signerReg = this.fresh();
      out.push(`let ${okReg} := 0`);
      out.push(`let ${signerReg} := 0`);
      out.push(`if eq(${len}, 65) {`);
      const rr = this.fresh();
      const ss = this.fresh();
      const vv = this.fresh();
      out.push(`  let ${rr} := mload(add(${mp}, 0x20))`);
      out.push(`  let ${ss} := mload(add(${mp}, 0x40))`);
      out.push(`  let ${vv} := byte(0, mload(add(${mp}, 0x60)))`);
      out.push(`  if iszero(gt(${ss}, ${HALF_ORDER})) {`);
      const inner: string[] = [];
      const sig = this.emitEcrecover(hash, vv, rr, ss, inner);
      for (const l of inner) out.push('    ' + l);
      out.push(`    if ${sig} { ${okReg} := 1 ${signerReg} := ${sig} }`);
      out.push('  }');
      out.push('}');
      return [okReg, signerReg];
    }
    if (source.kind === 'pointEvaluation') {
      // `const [fe, modulus] = pointEvaluation(versionedHash, z, y, commitment, proof)`: build the
      // 192-byte input (vh||z||y||commitment(48)||proof(48)) in a FRESH FMP buffer (NOT 0x00-0x40 scratch,
      // which the staticcall writes 64 bytes of output to), staticcall 0x0a, revert EMPTY on failure, and
      // bind [mload(0x00), mload(0x20)] (the constant success words FIELD_ELEMENTS_PER_BLOB, BLS_MODULUS).
      const vh = this.lowerExpr(source.versionedHash, ctx, out);
      const z = this.lowerExpr(source.z, ctx, out);
      const y = this.lowerExpr(source.y, ctx, out);
      const c = this.toMemory(this.lowerDynamic(source.commitment, ctx, out), out);
      const pr = this.toMemory(this.lowerDynamic(source.proof, ctx, out), out);
      out.push(`if iszero(eq(${c.len}, 48)) { revert(0, 0) }`);
      out.push(`if iszero(eq(${pr.len}, 48)) { revert(0, 0) }`);
      const inp = this.fresh();
      out.push(`let ${inp} := ${this.alloc()}(192)`);
      out.push(`mstore(${inp}, ${vh})`);
      out.push(`mstore(add(${inp}, 0x20), ${z})`);
      out.push(`mstore(add(${inp}, 0x40), ${y})`);
      out.push(`mcopy(add(${inp}, 0x60), add(${c.mp}, 0x20), 48)`);
      out.push(`mcopy(add(${inp}, 0x90), add(${pr.mp}, 0x20), 48)`);
      out.push(`if iszero(staticcall(gas(), 0x0a, ${inp}, 192, 0x00, 0x40)) { revert(0, 0) }`);
      const feReg = this.fresh();
      const modReg = this.fresh();
      out.push(`let ${feReg} := mload(0x00)`);
      out.push(`let ${modReg} := mload(0x20)`);
      return [feReg, modReg];
    }
    return source.values.map((v) => {
      const r = this.fresh();
      out.push(`let ${r} := ${this.lowerExpr(v, ctx, out)}`);
      return r;
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
    if (target.kind === 'immutableStaged') {
      // assign the staged shadow (a jeth_constructor return var); baked via setimmutable at the end.
      out.push(`${ctx.immStaged!.get(target.name)!} := ${valueReg}`);
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
      const base = target.wordOffset ? `add(${ptr}, ${target.wordOffset * 32})` : ptr;
      const i = this.fresh();
      out.push(`let ${i} := ${this.lowerExpr(target.index, ctx, out)}`);
      out.push(`if iszero(lt(${i}, ${target.length})) { ${this.panic()}(0x32) }`);
      out.push(`mstore(add(${base}, mul(${i}, 0x20)), ${valueReg})`);
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
      case 'caller':
        return 'caller()';
      case 'callvalue':
        return 'callvalue()';
      case 'origin':
        return 'origin()';
      case 'gasprice':
        return 'gasprice()';
      case 'address':
        return 'address()';
      case 'timestamp':
        return 'timestamp()';
      case 'number':
        return 'number()';
      case 'chainid':
        return 'chainid()';
      case 'coinbase':
        return 'coinbase()';
      case 'basefee':
        return 'basefee()';
      case 'gaslimit':
        return 'gaslimit()';
      case 'prevrandao':
        return 'prevrandao()';
      case 'blobbasefee':
        return 'blobbasefee()';
      case 'gas':
        return 'gas()';
      case 'msgsig':
        // bytes4 left-aligned: high 4 bytes = selector. Matches solc.
        return 'and(calldataload(0), 0xffffffff00000000000000000000000000000000000000000000000000000000)';
    }
  }

  private lowerCast(e: Expr & { kind: 'cast' }, ctx: LowerCtx, out: string[]): string {
    const { from, type: to } = e;
    // bytesN(bytes): the first N content bytes (left-aligned), zero-padded if the value is shorter.
    // The operand is a dynamic [len][data] value, not a word, so materialize it and read its first word.
    if (from.kind === 'bytes' && to.kind === 'bytesN') {
      const { mp } = this.toMemory(this.lowerDynamic(e.operand, ctx, out), out);
      const w = this.fresh();
      out.push(`let ${w} := mload(add(${mp}, 0x20))`); // first content word: left-aligned, zero-padded
      if (to.size === 32) return w;
      const mask = toWord(((1n << BigInt(to.size * 8)) - 1n) << BigInt((32 - to.size) * 8));
      return `and(${w}, ${mask})`;
    }
    const v = this.lowerExpr(e.operand, ctx, out);
    // enum TARGET (integer -> enum, `Color(x)`): solc range-checks `x < memberCount` and reverts
    // Panic 0x21 when out of range (the unsigned `lt` naturally rejects negative ints). The value
    // is already a valid small uint8 afterward, so just return it. (enum -> integer needs no case:
    // the integer branch below returns the value unchanged.)
    const toEnum = (to as { enumMembers?: string[] }).enumMembers;
    if (to.kind === 'uint' && toEnum !== undefined) {
      out.push(`if iszero(lt(${v}, ${toEnum.length})) { ${this.panic()}(0x21) }`);
      return v;
    }
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
    // bool(x) identity self-cast: a bool is already a canonical 0/1 word, so the conversion is a no-op.
    if (from.kind === 'bool' && to.kind === 'bool') return v;
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
    if (from.kind === 'bytesN' && to.kind === 'uint')
      return from.size === 32 ? v : `shr(${(32 - from.size) * 8}, ${v})`;
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
        // bytesN ~: keep the low padding bytes zero (not(..) would set them to ff), matching solc.
        if (e.type.kind === 'bytesN' && e.type.size < 32) return `and(${not}, ${bytesNHighMaskHex(e.type.size)})`;
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
        if (opType.kind === 'int') return `sar(${r}, ${l})`;
        // bytesN >> n: shr leaks data bits into the low padding region; mask back to the high
        // `size` bytes so the result stays a canonical left-aligned bytesN (byte-identical to solc).
        if (opType.kind === 'bytesN' && opType.size < 32)
          return `and(shr(${r}, ${l}), ${bytesNHighMaskHex(opType.size)})`;
        return `shr(${r}, ${l})`;
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
        case 'add':
          return this.checkedAddUint(t.bits);
        case 'sub':
          return this.checkedSubUint(t.bits);
        case 'mul':
          return this.checkedMulUint(t.bits);
        case 'div':
          return this.checkedDivUint();
        case 'mod':
          return this.checkedModUint();
      }
    }
    if (t.kind === 'int') {
      switch (op) {
        case 'add':
          return this.checkedAddInt(t.bits);
        case 'sub':
          return this.checkedSubInt(t.bits);
        case 'mul':
          return this.checkedMulInt(t.bits);
        case 'div':
          return this.checkedDivInt(t.bits);
        case 'mod':
          return this.checkedModInt();
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
      if (t.kind === 'uint' && t.bits < 256)
        rangeCheck = `if gt(power, ${uintMaxHex(t.bits)}) { ${this.panic()}(0x11) }`;
      if (t.kind === 'int' && t.bits < 256) {
        const max = toWord((1n << BigInt(t.bits - 1)) - 1n);
        const min = toWord(-(1n << BigInt(t.bits - 1)));
        rangeCheck = `if or(sgt(power, ${max}), slt(power, ${min})) { ${this.panic()}(0x11) }`;
      }
      this.helpers.set(
        name,
        `function ${name}(base, exponent) -> power {
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
}`,
      );
    }
    return name;
  }

  /** Unchecked signed division: Panic(0x12) on division by zero (NOT suppressed by
   *  unchecked), but the signed overflow INT_MIN/-1 wraps (sdiv) instead of Panic(0x11). */
  private uncheckedDivInt(): string {
    const name = 'jeth_unchecked_div_int';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {\n  if iszero(b) { ${this.panic()}(0x12) }\n  r := sdiv(a, b)\n}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  r := add(a, b)
  if ${ov} { panic(0x11) }
}`,
      );
    }
    return name;
  }
  private checkedSubUint(bits: number): string {
    const name = `checked_sub_uint${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  if gt(b, a) { panic(0x11) }
  r := sub(a, b)
}`,
      );
    }
    return name;
  }
  private checkedMulUint(bits: number): string {
    const name = `checked_mul_uint${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const widthChk = bits === 256 ? '0' : `gt(r, ${uintMaxHex(bits)})`;
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  r := mul(a, b)
  if or(and(iszero(iszero(a)), iszero(eq(div(r, a), b))), ${widthChk}) { panic(0x11) }
}`,
      );
    }
    return name;
  }
  private checkedDivUint(): string {
    const name = `checked_div_uint`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  r := div(a, b)
}`,
      );
    }
    return name;
  }
  private checkedModUint(): string {
    const name = `checked_mod_uint`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  r := mod(a, b)
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  r := add(a, b)
  if ${chk} { panic(0x11) }
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  r := sub(a, b)
  if ${chk} { panic(0x11) }
}`,
      );
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
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  r := mul(a, b)
  if iszero(iszero(a)) {
    if iszero(eq(sdiv(r, a), b)) { panic(0x11) }
  }
  if and(eq(a, ${toWord(-1n)}), eq(b, ${minHex})) { panic(0x11) }${widthChk}
}`,
      );
    }
    return name;
  }
  private checkedDivInt(bits: number): string {
    const name = `checked_div_int${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const { min } = intRange({ kind: 'int', bits });
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  if and(eq(a, ${toWord(min)}), eq(b, ${toWord(-1n)})) { panic(0x11) }
  r := sdiv(a, b)
}`,
      );
    }
    return name;
  }
  private checkedModInt(): string {
    const name = `checked_mod_int`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  r := smod(a, b)
}`,
      );
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
  fnMode?: { retVar: string | null; retVars?: string[] }; // set when lowering an INTERNAL function body: `return` -> retVar:=v; leave (retVar null = void). retVars set for a multi-value return.
  specialEntry?: boolean; // Phase 6: lowering a @receive/@fallback body INLINE in the dispatcher; a bare `return;` -> stop() (matches solc).
  immStaged?: Map<string, string>; // Phase 5: @immutable name -> its staged-shadow Yul var (constructor body only)
  // Phase 5 (full modifiers): set ONLY while lowering a function's modifierWrap in its dispatch case.
  // The {modifierBody} marker lowers to a call of the synthesized body function (userfn) with the
  // decoded params, capturing the single result into `ret` (null for a void function -> a bare call).
  modifierDispatch?: { userFn: string; args: string[]; ret: string | null };
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
  | { src: 'memory'; ptr: string; tailBytes?: string }; // ptr -> [len][data...]; tailBytes = full image byte size for a struct-element array

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

/** Phase B: emit the standalone Yul source for ONE external (delegatecall) library object (compiled
 *  to its own bytecode and linked into the contract at deploy time). A fresh YulEmitter per library
 *  keeps each object's helper/scope state independent. */
export function emitLibraryYul(lib: LibraryIR): string {
  return new YulEmitter().emitLibraryObject(lib);
}
