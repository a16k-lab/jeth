// Semantic analysis + type checking. Produces a typed ContractIR from the TS AST.
//
// Responsibilities (directive §5 steps 3-5):
//  - find the @contract class, classify members;
//  - resolve decorators into visibility/mutability metadata;
//  - plan storage layout;
//  - type-check each function body into typed IR (checked-by-default arithmetic),
//    enforcing integer widths, BigInt-literal rule, and view/pure mutability.
import ts from 'typescript';
import type { DiagnosticBag } from './diagnostics.js';
import { decoratorNames } from './parser.js';
import { resolveType, resolvePrimitiveName } from './typeresolver.js';
import {
  JethType,
  VOID,
  U256,
  I256,
  BOOL,
  displayName,
  typesEqual,
  isInteger,
  isImplicitWiden,
  commonNumericType,
  isStaticValueType,
  isStaticType,
  isDynamicType,
  isBytesLike,
  storageByteSize,
  storageSlotCount,
  abiHeadWords,
  intRange,
  StructField,
} from './types.js';
import {
  ContractIR,
  FunctionIR,
  StateVar,
  Stmt,
  Expr,
  LValue,
  ArrayExpr,
  AccessPath,
  AccessStep,
  CalldataPlace,
  CdStep,
  CdDynPlace,
  CdDynStep,
  BinOp,
  GlobalOp,
  Visibility,
  Mutability,
  Param,
  ErrorDecl,
  EventIR,
  EventParam,
  RevertReason,
} from './ir.js';

const ADDRESS: JethType = { kind: 'address', payable: false };
const STRING: JethType = { kind: 'string' };
const BYTES1: JethType = { kind: 'bytesN', size: 1 };

// Environment globals: "<obj>.<field>" -> opcode + type + category.
// 'env' forbidden in @pure; 'value' (msg.value) requires @payable; 'calldata'
// (msg.sig) allowed in @pure. Verified opcode/type/mutability against solc 0.8.
type GlobalCat = 'env' | 'value' | 'calldata';
const GLOBALS: Record<string, Record<string, { op: GlobalOp; type: JethType; cat: GlobalCat }>> = {
  msg: {
    sender: { op: 'caller', type: ADDRESS, cat: 'env' },
    value: { op: 'callvalue', type: U256, cat: 'value' },
    sig: { op: 'msgsig', type: { kind: 'bytesN', size: 4 }, cat: 'calldata' },
  },
  tx: {
    origin: { op: 'origin', type: ADDRESS, cat: 'env' },
  },
  block: {
    timestamp: { op: 'timestamp', type: U256, cat: 'env' },
    number: { op: 'number', type: U256, cat: 'env' },
    chainid: { op: 'chainid', type: U256, cat: 'env' },
    coinbase: { op: 'coinbase', type: ADDRESS, cat: 'env' },
    basefee: { op: 'basefee', type: U256, cat: 'env' },
    gaslimit: { op: 'gaslimit', type: U256, cat: 'env' },
    prevrandao: { op: 'prevrandao', type: U256, cat: 'env' },
  },
};
import { planLayout, RawStateVar } from './layout.js';
import { functionSignature, functionSelector, eventTopic0 } from './selectors.js';

const VISIBILITY_DECORATORS: Visibility[] = ['external', 'public', 'internal', 'private'];

/** Unwrap redundant parentheses: `(xs)` / `((this.a))` -> the inner expression. */
function stripParens(node: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(node)) node = node.expression;
  return node;
}

interface RawFunction {
  node: ts.MethodDeclaration;
  name: string;
  visibility: Visibility;
  mutability: Mutability;
  params: { name: string; type: JethType }[];
  returnType: JethType;
  returnTypes?: JethType[]; // multi-value return `[T1, T2, ...]`
}

export class Analyzer {
  // state symbols, available once layout is planned
  private stateByName = new Map<string, StateVar>();
  // @struct declarations (name -> resolved struct type), collected before contracts
  private structsByName = new Map<string, JethType>();
  // contract-level custom error and event tables (collected before function bodies)
  private errorsByName = new Map<string, ErrorDecl>();
  private errors: ErrorDecl[] = [];
  private eventsByName = new Map<string, EventIR>();
  private events: EventIR[] = [];
  // per-function lexical scope stack (innermost last); each scope maps name -> type.
  private scopes: Map<string, JethType>[] = [];
  private loopDepth = 0; // > 0 inside a for/while body (gates break/continue)
  private currentMutability: Mutability = 'nonpayable';
  private currentWritesState = false;
  private currentReadsState = false;
  private currentUnchecked = false; // inside an unchecked { } block (arithmetic wraps)
  private currentReturnTypes: JethType[] | undefined; // multi-value return components, if any
  private memArrayLocals = new Set<string>(); // let-locals that are MEMORY arrays (vs calldata-array params)
  private memAggregateLocals = new Map<string, JethType>(); // STATIC struct / fixed-array MEMORY locals (G9): name -> type
  private currentReadsEnv = false; // reads msg.*/block.*/tx.*/address(this) -> forbidden in @pure
  // internal-call support (G8): the function registry (built before bodies so calls can
  // forward-reference), plus per-function direct-effect / callee tracking for the
  // transitive-purity fixpoint and the set of names actually called internally.
  private funcsByName = new Map<string, RawFunction>();
  private currentCallees = new Set<string>(); // internal callees of the function being checked
  private internallyCalled = new Set<string>(); // any function that is the target of an internal call

  constructor(
    private readonly sourceFile: ts.SourceFile,
    private readonly diags: DiagnosticBag,
  ) {}

  // ---- lexical scope stack -------------------------------------------------

  private pushScope(): void {
    this.scopes.push(new Map());
  }
  private popScope(): void {
    this.scopes.pop();
  }
  private lookupLocal(name: string): JethType | undefined {
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      const t = this.scopes[i]!.get(name);
      if (t) return t;
    }
    return undefined;
  }
  private isVisibleLocal(name: string): boolean {
    return this.lookupLocal(name) !== undefined;
  }
  private inCurrentScope(name: string): boolean {
    return this.scopes[this.scopes.length - 1]!.has(name);
  }
  private declareLocal(name: string, t: JethType): void {
    this.scopes[this.scopes.length - 1]!.set(name, t);
  }

  analyze(): ContractIR | undefined {
    this.collectStructs();
    const classes = this.findContractClasses();
    if (classes.length === 0) {
      this.diags.error(this.sourceFile, 'JETH040', 'no @contract class found in source');
      return undefined;
    }
    if (classes.length > 1) {
      this.diags.error(classes[1]!, 'JETH041', 'multiple @contract classes per file are not supported in the MVP');
    }
    return this.analyzeContract(classes[0]!);
  }

  /** Collect @struct class declarations into the registry (in source order so a
   *  struct may reference earlier structs by value). */
  private collectStructs(): void {
    const visit = (n: ts.Node): void => {
      if (ts.isClassDeclaration(n) && decoratorNames(n).includes('struct')) this.collectStruct(n);
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(this.sourceFile, visit);
  }

  private collectStruct(cls: ts.ClassDeclaration): void {
    const name = cls.name?.text ?? 'Struct';
    if (this.structsByName.has(name)) {
      this.diags.error(cls, 'JETH220', `@struct '${name}' redeclared`);
      return;
    }
    const raw: RawStateVar[] = [];
    for (const member of cls.members) {
      if (!ts.isPropertyDeclaration(member)) continue;
      if (!ts.isIdentifier(member.name)) {
        this.diags.error(member, 'JETH221', 'struct field name must be a plain identifier');
        continue;
      }
      const t = resolveType(member.type, this.diags, this.structsByName);
      if (!t) continue;
      if (t.kind === 'mapping') {
        this.diags.error(member, 'JETH222', `struct field '${member.name.text}' cannot be a mapping`);
        continue;
      }
      // Fields may be static (value, nested struct, or fixed array). A struct with
      // >=1 dynamic field is itself dynamic (spec section 3) and supported as a
      // calldata param / return (Phase 4e-6). The supported dynamic field kinds are
      // bytes/string and a nested struct (which may itself be dynamic). A dynamic
      // ARRAY field (T[], string[], T[][]) inside a struct is still deferred (the
      // tuple codec would need an array-in-tuple tail walk we have not verified).
      if (!isStaticType(t) && !this.isSupportedDynStructField(t)) {
        this.diags.error(member, 'JETH229', `struct field '${member.name.text}' of type ${displayName(t)} is not supported yet (supported dynamic field kinds: bytes/string and a nested struct)`);
        continue;
      }
      raw.push({ name: member.name.text, type: t });
    }
    if (raw.length === 0) {
      this.diags.error(cls, 'JETH223', `@struct '${name}' must have at least one field`);
      return;
    }
    // struct-internal field layout reuses the state-var packing planner.
    const layout = planLayout(raw);
    const fields: StructField[] = layout.vars.map((v) => ({ name: v.name, type: v.type, slot: v.slot, offset: v.offset }));
    this.structsByName.set(name, { kind: 'struct', name, fields });
  }

  private findContractClasses(): ts.ClassDeclaration[] {
    const out: ts.ClassDeclaration[] = [];
    const visit = (n: ts.Node): void => {
      if (ts.isClassDeclaration(n) && decoratorNames(n).includes('contract')) out.push(n);
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(this.sourceFile, visit);
    return out;
  }

  private analyzeContract(cls: ts.ClassDeclaration): ContractIR | undefined {
    const name = cls.name?.text ?? 'Contract';
    const rawState: RawStateVar[] = [];
    const rawFns: RawFunction[] = [];

    // First pass: collect state, errors, and events. Errors/events are gathered
    // before any function body is checked so emit(...)/revert(...) can resolve
    // forward-referenced names (matches Solidity).
    for (const member of cls.members) {
      if (ts.isPropertyDeclaration(member)) {
        this.collectStateVar(member, rawState);
      } else if (ts.isMethodDeclaration(member)) {
        const decs = decoratorNames(member);
        if (decs.includes('error')) this.collectErrorDecl(member);
        else if (decs.includes('event')) this.collectEvent(member);
        else {
          const fn = this.collectFunction(member);
          if (fn) rawFns.push(fn);
        }
      } else if (ts.isConstructorDeclaration(member)) {
        this.diags.error(member, 'JETH042', 'constructors are not supported until Phase 5');
      } else if (ts.isGetAccessor(member) || ts.isSetAccessor(member)) {
        this.diags.error(member, 'JETH043', 'getters/setters are not supported');
      }
    }

    // Plan storage layout, then build the symbol table.
    const layout = planLayout(rawState);
    for (const v of layout.vars) this.stateByName.set(v.name, v);

    // Register functions by name BEFORE checking bodies so an internal call can
    // forward-reference a callee declared later (matches Solidity).
    for (const rf of rawFns) {
      if (!this.funcsByName.has(rf.name)) this.funcsByName.set(rf.name, rf);
    }

    // Type-check each function body, capturing each function's DIRECT effects and its
    // internal callees for the transitive-purity fixpoint below.
    const functions: FunctionIR[] = [];
    const effects = new Map<string, { writes: boolean; reads: boolean; readsEnv: boolean; callees: Set<string>; rf: RawFunction }>();
    for (const rf of rawFns) {
      const f = this.checkFunction(rf);
      if (f) {
        functions.push(f);
        effects.set(rf.name, { writes: this.currentWritesState, reads: this.currentReadsState, readsEnv: this.currentReadsEnv, callees: this.currentCallees, rf });
      }
    }

    // Transitive purity: a function inherits the state/env effects of everything it calls.
    // Fixpoint over the call graph (handles recursion / mutual recursion), then validate
    // each declared mutability against the TRANSITIVE effects (matches solc, which rejects
    // e.g. a @view function that calls a state-writing helper).
    let changed = true;
    while (changed) {
      changed = false;
      for (const e of effects.values()) {
        for (const callee of e.callees) {
          const ce = effects.get(callee);
          if (!ce) continue;
          if (ce.writes && !e.writes) { e.writes = true; changed = true; }
          if (ce.reads && !e.reads) { e.reads = true; changed = true; }
          if (ce.readsEnv && !e.readsEnv) { e.readsEnv = true; changed = true; }
        }
      }
    }
    for (const e of effects.values()) {
      if (e.rf.mutability === 'view' && e.writes) this.diags.error(e.rf.node, 'JETH054', `@view function '${e.rf.name}' writes to storage`);
      if (e.rf.mutability === 'pure' && (e.writes || e.reads)) this.diags.error(e.rf.node, 'JETH055', `@pure function '${e.rf.name}' accesses storage`);
      if (e.rf.mutability === 'pure' && e.readsEnv) this.diags.error(e.rf.node, 'JETH164', `@pure function '${e.rf.name}' reads the execution environment (msg.*/block.*/tx.*/address(this))`);
    }
    // Mark functions that are actually called internally so the emitter emits a Yul fn def.
    for (const f of functions) if (this.internallyCalled.has(f.name)) f.internallyCalled = true;

    // Reject duplicate selectors (would make the dispatcher ambiguous).
    const seen = new Map<string, string>();
    for (const f of functions) {
      if (f.visibility === 'internal' || f.visibility === 'private') continue;
      const prev = seen.get(f.selector);
      if (prev) {
        this.diags.error(cls, 'JETH044', `selector clash 0x${f.selector} between ${prev} and ${f.signature}`);
      } else seen.set(f.selector, f.signature);
    }

    return {
      name,
      stateVars: layout.vars,
      functions,
      errors: this.errors,
      events: this.events,
      slotCount: layout.slotCount,
    };
  }

  // ---- @error / @event declarations ----------------------------------------

  private collectErrorDecl(member: ts.MethodDeclaration): void {
    if (!ts.isIdentifier(member.name)) {
      this.diags.error(member, 'JETH049', 'error name must be a plain identifier');
      return;
    }
    const name = member.name.text;
    if (member.body) this.diags.error(member, 'JETH125', `@error '${name}' must be a bodyless declaration`);
    if (member.type) this.diags.error(member.type, 'JETH126', `@error '${name}' must not declare a return type`);
    const params: Param[] = [];
    for (const p of member.parameters) {
      if (!ts.isIdentifier(p.name)) {
        this.diags.error(p, 'JETH053', 'parameter name must be a plain identifier');
        continue;
      }
      const t = resolveType(p.type, this.diags, this.structsByName);
      if (!t) continue;
      // @error args: static value types or dynamic bytes/string (head/tail encoded).
      if (!isStaticValueType(t) && !isBytesLike(t)) {
        this.diags.error(
          p,
          'JETH127',
          `@error parameter '${p.name.text}' has type ${displayName(t)}; supported: static value types and bytes/string`,
        );
        continue;
      }
      params.push({ name: p.name.text, type: t });
    }
    if (this.errorsByName.has(name)) {
      this.diags.error(member, 'JETH128', `duplicate @error declaration '${name}'`);
      return;
    }
    const signature = functionSignature(name, params.map((p) => p.type));
    const selector = functionSelector(signature);
    const decl: ErrorDecl = { name, params, signature, selector };
    this.errorsByName.set(name, decl);
    this.errors.push(decl);
  }

  private collectEvent(member: ts.MethodDeclaration): void {
    if (!ts.isIdentifier(member.name)) {
      this.diags.error(member, 'JETH049', 'event name must be a plain identifier');
      return;
    }
    const name = member.name.text;
    if (member.body) {
      this.diags.error(member, 'JETH140', `@event '${name}' must be a bodyless declaration`);
      return;
    }
    if (member.type && member.type.kind !== ts.SyntaxKind.VoidKeyword) {
      this.diags.error(member.type, 'JETH141', `@event '${name}' must not declare a return type`);
    }
    const params: EventParam[] = [];
    let indexedCount = 0;
    for (const p of member.parameters) {
      if (!ts.isIdentifier(p.name)) {
        this.diags.error(p, 'JETH053', 'parameter name must be a plain identifier');
        continue;
      }
      const t = resolveType(p.type, this.diags, this.structsByName);
      if (!t) continue;
      const indexed = decoratorNames(p).includes('indexed');
      if (!isStaticValueType(t)) {
        if (isBytesLike(t) && indexed) {
          this.diags.error(p, 'JETH207', `indexed bytes/string event parameter '${p.name.text}' is not supported yet (keccak topic; Phase 4+)`);
          continue;
        }
        if (!isBytesLike(t)) {
          this.diags.error(
            p,
            'JETH142',
            `@event parameter '${p.name.text}' has type ${displayName(t)}; supported: static value types (any), bytes/string (non-indexed)`,
          );
          continue;
        }
        // non-indexed bytes/string data param: allowed
      }
      if (indexed) indexedCount++;
      params.push({ name: p.name.text, type: t, indexed });
    }
    if (indexedCount > 3) {
      this.diags.error(member, 'JETH143', `@event '${name}' has ${indexedCount} indexed parameters (max 3)`);
    }
    if (this.eventsByName.has(name)) {
      this.diags.error(member, 'JETH144', `duplicate @event declaration '${name}'`);
      return;
    }
    const signature = functionSignature(name, params.map((p) => p.type));
    const topic0 = eventTopic0(signature);
    const ev: EventIR = { name, params, signature, topic0, anonymous: false };
    this.eventsByName.set(name, ev);
    this.events.push(ev);
  }

  private collectStateVar(member: ts.PropertyDeclaration, out: RawStateVar[]): void {
    const decs = decoratorNames(member);
    if (!decs.includes('state')) {
      this.diags.error(member, 'JETH045', 'contract fields must be marked @state');
      return;
    }
    if (!ts.isIdentifier(member.name)) {
      this.diags.error(member, 'JETH046', 'state variable name must be a plain identifier');
      return;
    }
    const type = resolveType(member.type, this.diags, this.structsByName);
    if (!type) return;
    if (type.kind === 'void') {
      this.diags.error(member, 'JETH047', 'state variable cannot be void');
      return;
    }
    if (!this.gateArrayType(type, member, true)) return;
    // string[]/bytes[] (array of dynamic elements) in storage: the bare array, or a
    // mapping<K, string[]> value, mirrors solc (length at slot p / keccak(key.base);
    // element header i at keccak(lenSlot)+i, a normal storage bytes/string). A
    // string[] nested deeper (struct field, string[][], element of another array) is
    // still a later step: containsDynElemArray catches those and stays gated.
    // Storage nested dynamic arrays (u256[][], string[][], D[][], ...) and dyn-array
    // struct fields are supported via per-inner data slots: an inner array's length lives
    // at the AccessPath slot (placeArray), data at keccak(that slot), recursively. So the
    // earlier string[][] / T[][] storage gates are lifted; gateArrayType still rejects
    // genuinely-unrepresentable element kinds.
    // A DYNAMIC STRUCT (a @struct with >=1 bytes/string or nested-dynamic-struct
    // field) is now supported in storage / as a mapping value: each static field
    // uses normal packed storage and each bytes/string field at base+fieldSlot is a
    // normal storage bytes/string (byte-identical to solc, verified incl. raw
    // slots). A dynamic struct in a form we do NOT yet implement (e.g. buried in a
    // fixed array, though gateArrayType already rejects those element kinds) stays
    // gated rather than silently miscompiled.
    if (this.containsDynamicStruct(type) && !this.isStorageDynStruct(type)) {
      this.diags.error(member, 'JETH231', 'storage dynamic struct in this position is not supported yet (supported: a bare @state d: D, or a mapping<K, D> value, where D is a @struct with bytes/string fields; a dynamic array of dynamic struct D[] / fixed Arr<D,N> is rejected separately)');
      return;
    }

    let initialValue: bigint | boolean | undefined;
    if (member.initializer) {
      const folded = this.foldConstant(member.initializer, type);
      if (folded === undefined) {
        this.diags.error(
          member.initializer,
          'JETH048',
          'state initializer must be a constant literal (non-constant init requires a constructor, Phase 5)',
        );
      } else if (folded !== 0n && folded !== false) {
        initialValue = folded; // zero/false is the storage default; no SSTORE needed
      }
    }
    out.push({ name: member.name.text, type, initialValue });
  }

  private collectFunction(member: ts.MethodDeclaration): RawFunction | undefined {
    if (!ts.isIdentifier(member.name)) {
      this.diags.error(member, 'JETH049', 'method name must be a plain identifier');
      return undefined;
    }
    const decs = decoratorNames(member);

    // @error / @event members are intercepted earlier; @modifier is Phase 5.
    if (decs.includes('modifier')) {
      this.diags.error(member, 'JETH051', '@modifier is not supported until Phase 5');
      return undefined;
    }

    const visibilities = VISIBILITY_DECORATORS.filter((v) => decs.includes(v));
    if (visibilities.length > 1) {
      this.diags.error(member, 'JETH052', `conflicting visibility decorators: ${visibilities.join(', ')}`);
    }
    const visibility: Visibility = visibilities[0] ?? 'public';

    let mutability: Mutability = 'nonpayable';
    if (decs.includes('payable')) mutability = 'payable';
    else if (decs.includes('view')) mutability = 'view';
    else if (decs.includes('pure')) mutability = 'pure';

    const params: { name: string; type: JethType }[] = [];
    for (const p of member.parameters) {
      if (!ts.isIdentifier(p.name)) {
        this.diags.error(p, 'JETH053', 'parameter name must be a plain identifier');
        continue;
      }
      const t = resolveType(p.type, this.diags, this.structsByName);
      if (!t) continue;
      if (!this.gateArrayType(t, p)) continue;
      // Static struct / fixed-array params decode lazily from the ABI-unpacked head
      // via CalldataPlace; a DYNAMIC struct param (>=1 dynamic field, Phase 4e-6)
      // decodes via its tuple head/tail (CdDynPlace). Both shapes resolve OK here;
      // unsupported field kinds were rejected at @struct declaration (JETH229).
      params.push({ name: p.name.text, type: t });
    }

    // multi-value return `f(): [T1, T2, ...]` (a TS tuple type). Each component is a
    // value or bytes/string type (one ABI head word each); aggregate components are a
    // later step.
    if (member.type && ts.isTupleTypeNode(member.type)) {
      const returnTypes: JethType[] = [];
      let ok = true;
      for (const el of member.type.elements) {
        const t = resolveType(el, this.diags, this.structsByName);
        if (!t) { ok = false; break; }
        if (t.kind === 'mapping' || t.kind === 'void') {
          this.diags.error(el, 'JETH213', 'a multi-value return component cannot be a mapping or void');
          ok = false;
          break;
        }
        returnTypes.push(t);
      }
      if (ok && returnTypes.length >= 2) {
        return { node: member, name: member.name.text, visibility, mutability, params, returnType: VOID, returnTypes };
      }
      return { node: member, name: member.name.text, visibility, mutability, params, returnType: VOID };
    }

    const returnType = member.type ? resolveType(member.type, this.diags, this.structsByName) ?? VOID : VOID;
    if (returnType.kind === 'struct' && !this.isSupportedStructReturn(returnType)) {
      this.diags.error(member.type ?? member, 'JETH225', 'returning a struct with this shape is not supported yet (supported: static value/nested-static-struct fields, and bytes/string or nested-struct dynamic fields)');
    }
    if (!this.gateArrayType(returnType, member.type ?? member)) {
      return { node: member, name: member.name.text, visibility, mutability, params, returnType: VOID };
    }

    return { node: member, name: member.name.text, visibility, mutability, params, returnType };
  }

  private checkFunction(rf: RawFunction): FunctionIR | undefined {
    this.scopes = [];
    this.loopDepth = 0;
    this.pushScope(); // function/parameter scope
    this.currentMutability = rf.mutability;
    this.currentWritesState = false;
    this.currentReadsState = false;
    this.currentReadsEnv = false;
    this.currentReturnTypes = rf.returnTypes;
    this.currentCallees = new Set();
    this.memArrayLocals.clear();
    this.memAggregateLocals.clear();
    for (const p of rf.params) {
      if (this.inCurrentScope(p.name)) {
        this.diags.error(rf.node, 'JETH056', `duplicate parameter name '${p.name}'`);
      }
      this.declareLocal(p.name, p.type);
    }

    const body: Stmt[] = [];
    if (rf.node.body) {
      for (const s of rf.node.body.statements) {
        this.checkStatement(s, rf.returnType, body);
      }
    }
    this.popScope();

    // Mutability enforcement (directive §2.7 STATICCALL view semantics) is performed AFTER
    // all bodies are checked, against TRANSITIVE effects (see the call-graph fixpoint in
    // analyze()), so a @view/@pure function that violates via an internal callee is caught.

    const signature = functionSignature(rf.name, rf.params.map((p) => p.type));
    const selector = functionSelector(signature);
    return {
      name: rf.name,
      visibility: rf.visibility,
      mutability: rf.mutability,
      params: rf.params,
      returnType: rf.returnType,
      returnTypes: rf.returnTypes,
      signature,
      selector,
      body,
    };
  }

  // ---- statements ----------------------------------------------------------

  private checkStatement(node: ts.Statement, returnType: JethType, out: Stmt[]): void {
    if (ts.isReturnStatement(node)) {
      // multi-value return: `return [a, b, ...]` matching the function's tuple return type.
      if (this.currentReturnTypes) {
        const rts = this.currentReturnTypes;
        if (!node.expression || !ts.isArrayLiteralExpression(node.expression)) {
          this.diags.error(node, 'JETH060', `function must return a ${rts.length}-tuple [${rts.map(displayName).join(', ')}]`);
          return;
        }
        if (node.expression.elements.length !== rts.length) {
          this.diags.error(node, 'JETH060', `return tuple has ${node.expression.elements.length} values, expected ${rts.length}`);
          return;
        }
        const values: Expr[] = [];
        for (let i = 0; i < rts.length; i++) {
          const v = this.checkExpr(node.expression.elements[i]!, rts[i]);
          if (!v) return;
          const cv = this.coerce(v, rts[i]!, node.expression.elements[i]!);
          // An aggregate component must be a STORAGE value (this.x / this.m[k] / this.arr[i])
          // or a MEMORY value-array; a calldata-aggregate echo component is a later step.
          if ((rts[i]!.kind === 'struct' || rts[i]!.kind === 'array') && this.isCalldataAggregate(cv)) {
            this.diags.error(node.expression.elements[i]!, 'JETH213', 'a calldata-aggregate component in a multi-value return is not supported yet (return it from a storage value, or echo it as the sole return)');
            return;
          }
          values.push(cv);
        }
        out.push({ kind: 'returnTuple', values, types: rts });
        return;
      }
      if (!node.expression) {
        if (returnType.kind !== 'void') {
          this.diags.error(node, 'JETH060', `function must return ${displayName(returnType)}`);
        }
        out.push({ kind: 'return' });
        return;
      }
      const value = this.checkExpr(node.expression, returnType);
      if (value) {
        const coerced = this.coerce(value, returnType, node.expression);
        out.push({ kind: 'return', value: coerced });
      }
      return;
    }

    if (ts.isVariableStatement(node)) {
      for (const decl of node.declarationList.declarations) {
        this.checkLocalDecl(decl, out);
      }
      return;
    }

    // bare block `{ ... }` introduces a lexical scope
    if (ts.isBlock(node)) {
      this.pushScope();
      const body: Stmt[] = [];
      for (const s of node.statements) this.checkStatement(s, returnType, body);
      this.popScope();
      out.push({ kind: 'block', body });
      return;
    }

    // `unchecked: { ... }` (a labeled block) is Solidity's `unchecked { }`: arithmetic
    // (+ - * ** unary-) wraps mod 2^bits instead of reverting on overflow. The TS subset
    // has no `unchecked` keyword, so the labeled-block form carries the annotation.
    if (ts.isLabeledStatement(node) && node.label.text === 'unchecked' && ts.isBlock(node.statement)) {
      const prev = this.currentUnchecked;
      this.currentUnchecked = true;
      this.pushScope();
      const body: Stmt[] = [];
      for (const s of node.statement.statements) this.checkStatement(s, returnType, body);
      this.popScope();
      this.currentUnchecked = prev;
      out.push({ kind: 'block', body });
      return;
    }

    if (ts.isIfStatement(node)) {
      const cond = this.checkCondition(node.expression);
      const thenB = this.checkBranch(node.thenStatement, returnType);
      const elseB = node.elseStatement ? this.checkBranch(node.elseStatement, returnType) : undefined;
      if (cond) out.push({ kind: 'if', cond, then: thenB, else: elseB });
      return;
    }

    if (ts.isWhileStatement(node)) {
      const cond = this.checkCondition(node.expression);
      this.loopDepth++;
      const body = this.checkBranch(node.statement, returnType);
      this.loopDepth--;
      if (cond) out.push({ kind: 'while', cond, body });
      return;
    }

    if (ts.isDoStatement(node)) {
      // do { body } while (cond): body runs once, then cond is re-checked each turn.
      // The condition lives in the enclosing scope (body-declared locals are NOT visible
      // to it - checkBranch gives the body its own scope, matching Solidity/C semantics).
      this.loopDepth++;
      const body = this.checkBranch(node.statement, returnType);
      this.loopDepth--;
      const cond = this.checkCondition(node.expression);
      if (cond) out.push({ kind: 'doWhile', cond, body });
      return;
    }

    if (ts.isForStatement(node)) {
      this.checkForStatement(node, returnType, out);
      return;
    }

    if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
      this.diags.error(node, 'JETH111', 'for-of / for-in loops are not supported');
      return;
    }

    if (node.kind === ts.SyntaxKind.BreakStatement) {
      if ((node as ts.BreakStatement).label) this.diags.error(node, 'JETH112', 'labeled break is not supported');
      else if (this.loopDepth === 0) this.diags.error(node, 'JETH113', "'break' outside of a loop");
      else out.push({ kind: 'break' });
      return;
    }
    if (node.kind === ts.SyntaxKind.ContinueStatement) {
      if ((node as ts.ContinueStatement).label) this.diags.error(node, 'JETH112', 'labeled continue is not supported');
      else if (this.loopDepth === 0) this.diags.error(node, 'JETH113', "'continue' outside of a loop");
      else out.push({ kind: 'continue' });
      return;
    }

    if (ts.isExpressionStatement(node)) {
      const e = node.expression;
      // built-in statement-only calls: require / revert / emit
      if (ts.isCallExpression(e) && ts.isIdentifier(e.expression)) {
        const callee = e.expression.text;
        if (callee === 'require') return this.checkRequire(e, out);
        if (callee === 'revert') return this.checkRevert(e, out);
        if (callee === 'emit') return this.checkEmit(e, out);
        // a bare internal call as a statement (void result, or a value result discarded).
        if (this.funcsByName.has(callee)) {
          const c = this.checkInternalCall(e, callee, true);
          if (c) out.push({ kind: 'callStmt', fn: c.fn, args: c.args });
          return;
        }
      }
      // `this.method(args)` internal call as a statement (TS-idiomatic).
      if (
        ts.isCallExpression(e) &&
        ts.isPropertyAccessExpression(e.expression) &&
        e.expression.expression.kind === ts.SyntaxKind.ThisKeyword &&
        this.funcsByName.has(e.expression.name.text)
      ) {
        const c = this.checkInternalCall(e, e.expression.name.text, true);
        if (c) out.push({ kind: 'callStmt', fn: c.fn, args: c.args });
        return;
      }
      // array mutators: a.push(x) / a.pop()
      if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression)) {
        const method = e.expression.name.text;
        if (method === 'push' || method === 'pop') return this.checkArrayMutator(e, method, out);
      }
      // x++ / x-- / ++x / --x as a statement: desugar to x = x +/- 1 (checked / unchecked).
      if (ts.isPostfixUnaryExpression(e)) {
        return this.checkIncDec(e.operand, e.operator === ts.SyntaxKind.PlusPlusToken, e, out);
      }
      if (ts.isPrefixUnaryExpression(e) && (e.operator === ts.SyntaxKind.PlusPlusToken || e.operator === ts.SyntaxKind.MinusMinusToken)) {
        return this.checkIncDec(e.operand, e.operator === ts.SyntaxKind.PlusPlusToken, e, out);
      }
      this.checkExpressionStatement(e, out);
      return;
    }

    if (ts.isEmptyStatement(node)) return;

    this.diags.error(node, 'JETH061', `unsupported statement: ${ts.SyntaxKind[node.kind]}`);
  }

  /** Assignment / compound-assignment / bare expression statement. */
  private checkExpressionStatement(e: ts.Expression, out: Stmt[]): void {
    if (ts.isBinaryExpression(e) && this.isAssignmentOperator(e.operatorToken.kind)) {
      this.checkAssignment(e, out);
      return;
    }
    const expr = this.checkExpr(e);
    if (expr) out.push({ kind: 'exprStmt', expr });
  }

  private checkStructConstruct(node: ts.CallExpression, st: JethType & { kind: 'struct' }): Expr | undefined {
    if (node.arguments.length !== st.fields.length) {
      this.diags.error(node, 'JETH228', `struct '${st.name}' expects ${st.fields.length} field arg(s), got ${node.arguments.length}`);
      return undefined;
    }
    const args: Expr[] = [];
    for (let i = 0; i < st.fields.length; i++) {
      const f = st.fields[i]!;
      if (f.type.kind === 'struct') {
        // a nested struct field must be constructed inline (Inner(...)) so codegen
        // can flatten it into the parent's packed slots.
        const a = this.checkExpr(node.arguments[i]!, f.type);
        if (!a) return undefined;
        if (a.kind !== 'structNew') {
          this.diags.error(node.arguments[i]!, 'JETH226', `struct field '${f.name}' must be constructed inline, e.g. ${f.type.name}(...)`);
          return undefined;
        }
        args.push(a);
        continue;
      }
      // bytes/string field: a dynamic value (literal, param, or another dynamic
      // source). Encoded into the tuple tail by the general encoder (4e-6).
      if (isBytesLike(f.type)) {
        const a = this.checkExpr(node.arguments[i]!, f.type);
        if (!a) return undefined;
        if (a.type.kind !== f.type.kind) {
          this.diags.error(node.arguments[i]!, 'JETH226', `struct field '${f.name}' expects ${displayName(f.type)}, got ${displayName(a.type)}`);
          return undefined;
        }
        args.push(a);
        continue;
      }
      // a static fixed-array field (Arr<T,N>, incl nested Arr<Arr<T,N>,M>): constructed
      // from a (possibly nested) array literal, written into the field's slots.
      if (f.type.kind === 'array' && f.type.length !== undefined && isStaticType(f.type)) {
        const a = this.checkExpr(node.arguments[i]!, f.type);
        if (!a) return undefined;
        if (a.kind !== 'arrayLit' || a.elements.length !== f.type.length) {
          this.diags.error(node.arguments[i]!, 'JETH226', `struct field '${f.name}' (${displayName(f.type)}) must be an array literal of ${f.type.length} elements`);
          return undefined;
        }
        args.push(a);
        continue;
      }
      if (!isStaticValueType(f.type)) {
        this.diags.error(node.arguments[i]!, 'JETH226', `struct field '${f.name}' of type ${displayName(f.type)} is not constructible yet`);
        return undefined;
      }
      const a = this.checkExpr(node.arguments[i]!, f.type);
      if (!a) return undefined;
      args.push(this.coerce(a, f.type, node.arguments[i]!));
    }
    return { kind: 'structNew', type: st, fields: st.fields, args };
  }

  private checkArrayMutator(call: ts.CallExpression, method: string, out: Stmt[]): void {
    const arr = this.resolveArrayExpr((call.expression as ts.PropertyAccessExpression).expression);
    if (!arr) {
      this.diags.error(call, 'JETH210', `'${method}' requires a storage array (this.arr.${method}(...))`);
      return;
    }
    if (arr.base.kind === 'calldataArray') {
      this.diags.error(call, 'JETH214', `a calldata array is read-only (no '${method}')`);
      return;
    }
    if (arr.base.kind === 'fixedArray') {
      this.diags.error(call, 'JETH218', `a fixed-size array has no '${method}' (length is constant)`);
      return;
    }
    this.currentWritesState = true;
    if (method === 'pop') {
      if (call.arguments.length !== 0) this.diags.error(call, 'JETH215', 'pop() takes no arguments');
      out.push({ kind: 'pop', arr });
      return;
    }
    if (call.arguments.length > 1) {
      this.diags.error(call, 'JETH215', 'push(...) takes 0 or 1 arguments');
      return;
    }
    if (call.arguments.length === 0) {
      out.push({ kind: 'push', arr });
      return;
    }
    const v = this.checkExpr(call.arguments[0]!, arr.elem);
    if (!v) return;
    out.push({ kind: 'push', arr, value: this.coerce(v, arr.elem, call.arguments[0]!) });
  }

  /** x++ / x-- / ++x / --x as a STATEMENT (value discarded): x = x +/- 1, on any integer
   *  lvalue (local, state var, struct field, array/mapping element). Checked unless inside
   *  an unchecked block. The pre/post distinction only matters when the value is used,
   *  which is not the statement form. */
  private checkIncDec(operand: ts.Expression, isInc: boolean, node: ts.Node, out: Stmt[]): void {
    const target = this.checkLValue(operand);
    if (!target) return;
    if (!isInteger(target.type)) {
      this.diags.error(node, 'JETH082', `'${isInc ? '++' : '--'}' requires an integer operand, got ${displayName(target.type)}`);
      return;
    }
    const left = this.lvalueAsExpr(target);
    const one: Expr = { kind: 'literalInt', type: target.type, value: 1n };
    const combined = this.buildBinary(isInc ? '+' : '-', left, one, node);
    if (!combined) return;
    out.push({ kind: 'assign', target, value: this.coerce(combined, target.type, node) });
  }

  /** x++ / x-- / ++x / --x in value position: yields a value (old for postfix, new for
   *  prefix) and side-effects the lvalue (x = x +/- 1, checked unless in an unchecked block). */
  private checkIncDecExpr(operand: ts.Expression, isInc: boolean, prefix: boolean, node: ts.Node): Expr | undefined {
    const target = this.checkLValue(operand);
    if (!target) return undefined;
    if (!isInteger(target.type)) {
      this.diags.error(node, 'JETH082', `'${isInc ? '++' : '--'}' requires an integer operand, got ${displayName(target.type)}`);
      return undefined;
    }
    return { kind: 'incDec', type: target.type, target, readExpr: this.lvalueAsExpr(target), isInc, prefix, unchecked: this.currentUnchecked };
  }

  /** True iff `e` is a calldata-source aggregate (a calldata array param echo or a
   *  calldata dynamic-struct echo) - which the storage/memory tuple encoder cannot encode. */
  private isCalldataAggregate(e: Expr): boolean {
    if (e.kind === 'arrayValue') return e.arr.base.kind === 'calldataArray' || e.arr.base.kind === 'cdNestedElem';
    return e.kind === 'cdDynStructValue';
  }

  private checkCondition(expr: ts.Expression): Expr | undefined {
    const e = this.checkExpr(expr, BOOL);
    if (!e) return undefined;
    if (e.type.kind !== 'bool') {
      this.diags.error(expr, 'JETH110', `condition must be bool, got ${displayName(e.type)}`);
      return undefined;
    }
    return e;
  }

  /** Type-check a then/else/loop branch in its own scope; returns the Stmt[]. */
  private checkBranch(node: ts.Statement, returnType: JethType): Stmt[] {
    this.pushScope();
    const out: Stmt[] = [];
    if (ts.isBlock(node)) {
      for (const s of node.statements) this.checkStatement(s, returnType, out);
    } else {
      this.checkStatement(node, returnType, out); // single-statement branch
    }
    this.popScope();
    return out;
  }

  private checkForStatement(node: ts.ForStatement, returnType: JethType, out: Stmt[]): void {
    this.pushScope(); // for-init scope encloses cond, post, body
    let init: Stmt | undefined;
    if (node.initializer) {
      if (ts.isVariableDeclarationList(node.initializer)) {
        if (node.initializer.declarations.length > 1) {
          this.diags.error(node.initializer, 'JETH114', 'for-init supports a single declaration');
        }
        const tmp: Stmt[] = [];
        const d0 = node.initializer.declarations[0];
        if (d0) this.checkLocalDecl(d0, tmp);
        init = tmp[0];
      } else {
        const tmp: Stmt[] = [];
        this.checkExpressionStatement(node.initializer, tmp);
        init = tmp[0];
      }
    }
    const cond = node.condition ? this.checkCondition(node.condition) : undefined;
    let post: Stmt | undefined;
    if (node.incrementor) {
      const tmp: Stmt[] = [];
      this.checkExpressionStatement(node.incrementor, tmp);
      post = tmp[0];
    }
    this.loopDepth++;
    const body = this.checkBranch(node.statement, returnType);
    this.loopDepth--;
    this.popScope();
    out.push({ kind: 'for', init, cond, post, body });
  }

  // ---- require / revert / custom errors ------------------------------------

  private checkRequire(call: ts.CallExpression, out: Stmt[]): void {
    const args = call.arguments;
    if (args.length < 1 || args.length > 2) {
      this.diags.error(call, 'JETH120', `require(...) takes 1 or 2 arguments, got ${args.length}`);
      return;
    }
    const cond = this.checkExpr(args[0]!, BOOL);
    if (!cond) return;
    if (cond.type.kind !== 'bool') {
      this.diags.error(args[0]!, 'JETH121', `require condition must be bool, got ${displayName(cond.type)}`);
      return;
    }
    const reason: RevertReason | undefined =
      args.length === 2 ? this.checkRevertReason(args[1]!) : { kind: 'empty' };
    if (reason) out.push({ kind: 'require', cond, reason });
  }

  private checkRevert(call: ts.CallExpression, out: Stmt[]): void {
    const args = call.arguments;
    if (args.length > 1) {
      this.diags.error(call, 'JETH122', `revert(...) takes 0 or 1 arguments, got ${args.length}`);
      return;
    }
    const reason: RevertReason | undefined =
      args.length === 1 ? this.checkRevertReason(args[0]!) : { kind: 'empty' };
    if (reason) out.push({ kind: 'revert', reason });
  }

  private checkRevertReason(node: ts.Expression): RevertReason | undefined {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      return { kind: 'errorString', message: new TextEncoder().encode(node.text) };
    }
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      return this.checkErrorConstructor(node);
    }
    if (ts.isTemplateExpression(node)) {
      this.diags.error(node, 'JETH124', 'revert/require message must be a constant string literal (no interpolation)');
      return undefined;
    }
    // a runtime string value (e.g. a string param or this.s) -> dynamic Error(string)
    if (ts.isIdentifier(node) || ts.isPropertyAccessExpression(node)) {
      const e = this.checkExpr(node, STRING);
      if (e && e.type.kind === 'string') return { kind: 'errorStringDyn', value: e };
      if (e) this.diags.error(node, 'JETH206', `Error(string) message must be a string, got ${displayName(e.type)}`);
      return undefined;
    }
    this.diags.error(node, 'JETH123', 'revert/require reason must be a string (literal or value) or a custom error constructor');
    return undefined;
  }

  private checkErrorConstructor(node: ts.CallExpression): RevertReason | undefined {
    const name = (node.expression as ts.Identifier).text;
    const decl = this.errorsByName.get(name);
    if (!decl) {
      this.diags.error(node.expression, 'JETH129', `unknown custom error '${name}'`);
      return undefined;
    }
    if (node.arguments.length !== decl.params.length) {
      this.diags.error(node, 'JETH130', `error '${name}' expects ${decl.params.length} argument(s), got ${node.arguments.length}`);
      return undefined;
    }
    const args: Expr[] = [];
    for (let i = 0; i < decl.params.length; i++) {
      const want = decl.params[i]!.type;
      const e = this.checkExpr(node.arguments[i]!, want);
      if (!e) return undefined;
      args.push(this.coerce(e, want, node.arguments[i]!));
    }
    return { kind: 'custom', decl, args };
  }

  // ---- events --------------------------------------------------------------

  private checkEmit(call: ts.CallExpression, out: Stmt[]): void {
    if (call.arguments.length !== 1) {
      this.diags.error(call, 'JETH145', 'emit(...) takes exactly one event-constructor argument');
      return;
    }
    const inner = call.arguments[0]!;
    if (!ts.isCallExpression(inner) || !ts.isIdentifier(inner.expression)) {
      this.diags.error(inner, 'JETH146', 'emit(...) argument must be an event constructor, e.g. emit(Transfer(a, b))');
      return;
    }
    const ev = this.eventsByName.get(inner.expression.text);
    if (!ev) {
      this.diags.error(inner.expression, 'JETH147', `unknown event '${inner.expression.text}'`);
      return;
    }
    if (this.currentMutability === 'view' || this.currentMutability === 'pure') {
      this.diags.error(call, 'JETH149', `cannot emit an event in a @${this.currentMutability} function (a log is a state change)`);
    }
    if (inner.arguments.length !== ev.params.length) {
      this.diags.error(inner, 'JETH148', `event '${ev.name}' expects ${ev.params.length} argument(s), got ${inner.arguments.length}`);
      return;
    }
    const args: Expr[] = [];
    for (let i = 0; i < ev.params.length; i++) {
      const expected = ev.params[i]!.type;
      const a = this.checkExpr(inner.arguments[i]!, expected);
      if (!a) return;
      args.push(this.coerce(a, expected, inner.arguments[i]!));
    }
    out.push({ kind: 'emit', event: ev, args });
  }

  private checkLocalDecl(decl: ts.VariableDeclaration, out: Stmt[]): void {
    if (!ts.isIdentifier(decl.name)) {
      this.diags.error(decl, 'JETH062', 'destructuring is not supported');
      return;
    }
    const declared = resolveType(decl.type, this.diags, this.structsByName);
    if (!decl.type) {
      this.diags.error(decl, 'JETH063', 'local variables require an explicit type annotation');
      return;
    }
    if (!declared) return;
    // G9: a STATIC struct MEMORY local (let p: P = P(...)). The register holds a pointer to
    // an ABI-unpacked memory image (one word per leaf). It must be initialized from a
    // constructor P(...) or aliased from another memory struct (memAggregate); copies from a
    // storage/calldata source, and dynamic-field structs, are a later step.
    if (declared.kind === 'struct') {
      if (this.isVisibleLocal(decl.name.text)) {
        this.diags.error(decl, 'JETH068', `redeclaration of '${decl.name.text}' (shadowing is not allowed)`);
        return;
      }
      if (!isStaticType(declared)) {
        this.diags.error(decl, 'JETH200', `local variables of dynamic struct type ${displayName(declared)} are not supported yet`);
        return;
      }
      if (!decl.initializer) {
        this.diags.error(decl, 'JETH200', `a struct memory local must be initialized (e.g. let p: ${displayName(declared)} = ${(declared as JethType & { kind: 'struct' }).name}(...))`);
        return;
      }
      const e = this.checkExpr(decl.initializer, declared);
      if (!e) return;
      if (e.kind !== 'structNew' && e.kind !== 'memAggregate') {
        this.diags.error(decl.initializer, 'JETH900', 'a struct memory local must be initialized from a constructor StructName(...) or another memory struct (copying from storage/calldata is a later step)');
        return;
      }
      this.declareLocal(decl.name.text, declared);
      this.memAggregateLocals.set(decl.name.text, declared);
      out.push({ kind: 'localDecl', name: decl.name.text, type: declared, init: e });
      return;
    }
    // A value-element dynamic-array local is a MEMORY array (a pointer to [len][elems]);
    // bytes/string and aggregate-element memory locals are a later step.
    if (declared.kind === 'array' && !(declared.length === undefined && isStaticValueType(declared.element))) {
      this.diags.error(decl, 'JETH200', `local variables of type ${displayName(declared)} are not supported yet (memory: dynamic arrays of a value element)`);
      return;
    }
    if (isBytesLike(declared)) {
      this.diags.error(decl, 'JETH200', `local variables of type ${displayName(declared)} are not supported yet (no bytes/string memory locals)`);
      return;
    }
    if (this.isVisibleLocal(decl.name.text)) {
      this.diags.error(decl, 'JETH068', `redeclaration of '${decl.name.text}' (shadowing is not allowed)`);
      return;
    }
    // a memory-array local must be initialized (Solidity has no null memory array).
    if (declared.kind === 'array' && !decl.initializer) {
      this.diags.error(decl, 'JETH200', 'a memory array local must be initialized (e.g. let xs: u256[] = [a, b])');
      return;
    }
    let init: Expr | undefined;
    if (decl.initializer) {
      const e = this.checkExpr(decl.initializer, declared);
      if (e) init = this.coerce(e, declared, decl.initializer);
    }
    this.declareLocal(decl.name.text, declared);
    if (declared.kind === 'array') this.memArrayLocals.add(decl.name.text);
    out.push({ kind: 'localDecl', name: decl.name.text, type: declared, init });
  }

  private checkAssignment(e: ts.BinaryExpression, out: Stmt[]): void {
    const target = this.checkLValue(e.left);
    if (!target) return;
    const opKind = e.operatorToken.kind;

    if (opKind === ts.SyntaxKind.EqualsToken) {
      const rhs = this.checkExpr(e.right, target.type);
      if (!rhs) return;
      const value = this.coerce(rhs, target.type, e.right);
      out.push({ kind: 'assign', target, value });
      return;
    }

    // compound: desugar `lhs op= rhs` into `lhs = lhs op rhs`
    const binOp = this.compoundToBinOp(opKind);
    if (!binOp) {
      this.diags.error(e.operatorToken, 'JETH064', `unsupported assignment operator`);
      return;
    }
    const left = this.lvalueAsExpr(target);
    const rhs = this.checkExpr(e.right, target.type);
    if (!rhs) return;
    const combined = this.buildBinary(binOp, left, rhs, e);
    if (!combined) return;
    const value = this.coerce(combined, target.type, e);
    out.push({ kind: 'assign', target, value });
  }

  /** Assignment as a value-producing expression: (x = v), (x += v), chained x = y = a.
   *  Mirrors checkAssignment but returns an Expr that yields the assigned (LHS-typed)
   *  value, byte-identical to Solidity. Restricted to static value-typed lvalues (the
   *  common case); aggregate/bytes/string lvalues keep statement-only assignment. */
  private checkAssignmentExpr(e: ts.BinaryExpression): Expr | undefined {
    const target = this.checkLValue(e.left);
    if (!target) return undefined;
    if (!isStaticValueType(target.type)) {
      this.diags.error(e, 'JETH075', `assignment in expression position is supported only for value types, not ${displayName(target.type)}`);
      return undefined;
    }
    const opKind = e.operatorToken.kind;
    if (opKind === ts.SyntaxKind.EqualsToken) {
      const rhs = this.checkExpr(e.right, target.type);
      if (!rhs) return undefined;
      const value = this.coerce(rhs, target.type, e.right);
      return { kind: 'assignExpr', type: target.type, target, value };
    }
    const binOp = this.compoundToBinOp(opKind);
    if (!binOp) {
      this.diags.error(e.operatorToken, 'JETH064', `unsupported assignment operator`);
      return undefined;
    }
    const left = this.lvalueAsExpr(target);
    const rhs = this.checkExpr(e.right, target.type);
    if (!rhs) return undefined;
    const combined = this.buildBinary(binOp, left, rhs, e);
    if (!combined) return undefined;
    const value = this.coerce(combined, target.type, e);
    return { kind: 'assignExpr', type: target.type, target, value };
  }

  /** Resolve a bare-identifier call `f(args)` to a contract function as an INTERNAL call
   *  (Solidity semantics: same contract context, no message-call). Returns a `call` Expr
   *  (its type is the callee's return type; void only allowed when asStatement). First cut:
   *  value-typed params and a value/void return (aggregate/bytes/string params and returns,
   *  and multi-value returns, are cleanly gated until aggregate memory locals land). */
  private checkInternalCall(node: ts.CallExpression, name: string, asStatement: boolean): (Expr & { kind: 'call' }) | undefined {
    const callee = this.funcsByName.get(name);
    if (!callee) return undefined;
    if (callee.visibility === 'external') {
      this.diags.error(node, 'JETH240', `cannot internally call @external function '${name}' (only internal/private/public functions are callable by name)`);
      return undefined;
    }
    if (callee.returnTypes) {
      this.diags.error(node, 'JETH241', `internal call to a multi-value-return function '${name}' is not supported yet`);
      return undefined;
    }
    if (callee.params.some((p) => !isStaticValueType(p.type))) {
      this.diags.error(node, 'JETH242', `internal call to '${name}' is not supported yet (a parameter is not a value type)`);
      return undefined;
    }
    if (callee.returnType.kind !== 'void' && !isStaticValueType(callee.returnType)) {
      this.diags.error(node, 'JETH243', `internal call to '${name}' is not supported yet (its return type is not a value type)`);
      return undefined;
    }
    if (!asStatement && callee.returnType.kind === 'void') {
      this.diags.error(node, 'JETH244', `'${name}' returns void and cannot be used as a value`);
      return undefined;
    }
    if (node.arguments.length !== callee.params.length) {
      this.diags.error(node, 'JETH148', `'${name}' expects ${callee.params.length} argument(s), got ${node.arguments.length}`);
      return undefined;
    }
    const args: Expr[] = [];
    for (let i = 0; i < callee.params.length; i++) {
      const pt = callee.params[i]!.type;
      const a = this.checkExpr(node.arguments[i]!, pt);
      if (!a) return undefined;
      args.push(this.coerce(a, pt, node.arguments[i]!));
    }
    this.currentCallees.add(name);
    this.internallyCalled.add(name);
    return { kind: 'call', type: callee.returnType, fn: name, args };
  }

  /** Word offset (and type) of a struct field within the ABI-unpacked memory image, for a
   *  memory-aggregate local (G9). Returns undefined if the field is absent. */
  private memFieldOffset(structType: JethType & { kind: 'struct' }, fieldName: string): { wordOffset: number; type: JethType } | undefined {
    let w = 0;
    for (const f of structType.fields) {
      if (f.name === fieldName) return { wordOffset: w, type: f.type };
      w += abiHeadWords(f.type);
    }
    return undefined;
  }

  /** Resolve `p.x` where `p` is a memory-aggregate (struct) local: a value-typed field read/
   *  write maps to a memory load/store at the field's word offset. Non-value fields are gated. */
  private resolveMemAggregateField(node: ts.PropertyAccessExpression): { local: string; wordOffset: number; type: JethType } | undefined {
    if (!ts.isIdentifier(node.expression)) return undefined;
    const local = node.expression.text;
    const st = this.memAggregateLocals.get(local);
    if (!st || st.kind !== 'struct') return undefined;
    const fo = this.memFieldOffset(st, node.name.text);
    if (!fo) {
      this.diags.error(node, 'JETH210', `struct '${st.name}' has no field '${node.name.text}'`);
      return undefined;
    }
    if (!isStaticValueType(fo.type)) {
      this.diags.error(node, 'JETH245', `reading a non-value field '${node.name.text}' of a memory struct is not supported yet`);
      return undefined;
    }
    return { local, wordOffset: fo.wordOffset, type: fo.type };
  }

  // ---- lvalues -------------------------------------------------------------

  private checkLValue(node: ts.Expression): LValue | undefined {
    // G9: `p.x = v` on a memory-aggregate (struct) local -> a memory store at the field offset.
    if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression) && this.memAggregateLocals.has(node.expression.text)) {
      const mf = this.resolveMemAggregateField(node);
      if (!mf) return undefined;
      return { kind: 'memField', type: mf.type, local: mf.local, wordOffset: mf.wordOffset };
    }
    // nested storage place: this.s.f, this.pts[i].x, this.m[k].f, this.m[r][c]
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const acc = this.resolveAccess(node);
      if (acc) {
        if (!acc.result) return undefined;
        // Assigning a whole FIXED-array leaf at depth (this.g3[i][j] = arr) is a later
        // step (no fixed-array value source to copy from); reading it works.
        if (acc.result.finalType.kind === 'array') {
          this.diags.error(node, 'JETH226', 'assigning a whole fixed-array element at depth is a later step (assign its elements)');
          return undefined;
        }
        this.currentWritesState = true;
        // A bytes/string leaf (storage dynamic-struct field) write goes through the
        // storage bytes/string codec (storeStrMem, overwrite-clearing old tail),
        // not a packed-word sstore.
        if (isBytesLike(acc.result.finalType)) {
          return { kind: 'dynPlace', type: acc.result.finalType, path: acc.result.path };
        }
        return { kind: 'place', type: acc.result.finalType, path: acc.result.path };
      }
      // a dynamic-struct calldata param is read-only.
      if (ts.isPropertyAccessExpression(node)) {
        const dyn = this.resolveCdDynStruct(node);
        if (dyn) {
          if (dyn.result) this.diags.error(node, 'JETH214', 'a calldata parameter is read-only (cannot assign to its fields)');
          return undefined;
        }
      }
      // a struct / fixed-array calldata param is read-only.
      const cd = this.resolveCalldataPlace(node);
      if (cd) {
        if (cd.result) this.diags.error(node, 'JETH214', 'a calldata parameter is read-only (cannot assign to its fields/elements)');
        return undefined;
      }
    }

    // this.struct.field = v
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.expression.kind === ts.SyntaxKind.ThisKeyword
    ) {
      const sv = this.stateByName.get(node.expression.name.text);
      if (sv && sv.type.kind === 'struct') {
        const f = sv.type.fields.find((ff) => ff.name === node.name.text);
        if (!f) {
          this.diags.error(node, 'JETH210', `struct '${sv.type.name}' has no field '${node.name.text}'`);
          return undefined;
        }
        // this.d.s = <bytes/string>: a dynamic field of a storage dynamic struct.
        // The field header lives at sv.slot + f.slot (a normal storage bytes/string);
        // a single-field path folds to that constant slot at codegen.
        if (isBytesLike(f.type)) {
          this.currentWritesState = true;
          return { kind: 'dynPlace', type: f.type, path: { baseSlot: sv.slot, steps: [{ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type }] } };
        }
        // this.o.inner = <struct>: a whole nested-struct field. Land writeStruct/copyStruct
        // at the field's slot (a storage place).
        if (f.type.kind === 'struct') {
          this.currentWritesState = true;
          return { kind: 'place', type: f.type, path: { baseSlot: sv.slot, steps: [{ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type }] } };
        }
        if (!isStaticValueType(f.type)) {
          this.diags.error(node, 'JETH226', 'nested array field assignment is not supported yet');
          return undefined;
        }
        this.currentWritesState = true;
        return { kind: 'state', type: f.type, slot: sv.slot + f.slot, offset: f.offset, varName: `${sv.name}.${f.name}` };
      }
    }

    // this.stateVar
    if (ts.isPropertyAccessExpression(node) && node.expression.kind === ts.SyntaxKind.ThisKeyword) {
      const v = this.stateByName.get(node.name.text);
      if (!v) {
        this.diags.error(node, 'JETH065', `unknown state variable 'this.${node.name.text}'`);
        return undefined;
      }
      if (v.type.kind === 'mapping') {
        this.diags.error(node, 'JETH153', `cannot assign to mapping 'this.${node.name.text}' directly; assign an element (this.${node.name.text}[key] = ...)`);
        return undefined;
      }
      this.currentWritesState = true;
      if (isBytesLike(v.type)) return { kind: 'dynState', type: v.type, slot: v.slot, varName: v.name };
      return { kind: 'state', type: v.type, slot: v.slot, offset: v.offset, varName: v.name };
    }
    // array element: a[i] = v  (a a state/fixed array `this.arr`, or a mapping-valued
    // dynamic array `this.m[k]` whose element is a value / bytes / string).
    if (ts.isElementAccessExpression(node) && this.assignableArrayElem(node)) {
      const arr = this.resolveArrayExpr(node.expression);
      if (!arr || !node.argumentExpression) return undefined;
      if (arr.base.kind === 'calldataArray') {
        this.diags.error(node, 'JETH214', 'a calldata array is read-only (cannot assign its elements)');
        return undefined;
      }
      // string[] / bytes[] element write: the element is a storage bytes/string
      // header at keccak(lenSlot)+i (strArrayElem); the RHS is a dynamic value.
      if (isBytesLike(arr.elem)) {
        if (arr.base.kind !== 'stateArray' && arr.base.kind !== 'mapArray' && arr.base.kind !== 'fixedArray') {
          this.diags.error(node, 'JETH217', 'this string[]/bytes[] element write is not supported yet');
          return undefined;
        }
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!index) return undefined;
        this.currentWritesState = true;
        return { kind: 'strArrayElem', type: arr.elem, arr, index: this.coerce(index, U256, node.argumentExpression) };
      }
      // this.dd[i] = <array> (a whole DYNAMIC inner array element): deep-copy the value
      // into the inner element's length slot (overwrite-clearing). A FIXED inner-array
      // element assign (a static aggregate copy) is a later step.
      if (arr.elem.kind === 'array' && arr.elem.length !== undefined) {
        this.diags.error(node, 'JETH226', 'assigning a whole fixed-array element is a later step (assign its elements)');
        return undefined;
      }
      // A whole-struct array-element write (this.recs[i] = D(...) / = this.x) is
      // supported: writeStruct/copyStruct lands at the element slot (Panic 0x32 on OOB).
      const index = this.checkExpr(node.argumentExpression, U256);
      if (!index) return undefined;
      const idx = this.coerce(index, U256, node.argumentExpression);
      if (!this.checkFixedBound(arr, idx, node.argumentExpression)) return undefined;
      if (arr.base.kind !== 'memArray' && arr.base.kind !== 'memArrayExpr') this.currentWritesState = true; // a memory array write is not storage
      return { kind: 'arrayElem', type: arr.elem, arr, index: idx };
    }

    // mapping element: this.m[k] (possibly nested)
    if (ts.isElementAccessExpression(node)) {
      const r = this.resolveMapAccess(node);
      if (!r) return undefined;
      if (r.valueType.kind === 'mapping') {
        this.diags.error(node, 'JETH153', 'cannot assign to a mapping value; index it fully');
        return undefined;
      }
      // this.m[k] = <bytes/string>: overwrite the dynamic value at the mapping slot
      // (storeDynamic clears the old tail, exactly like the bare `this.s = v` case).
      if (isBytesLike(r.valueType)) {
        this.currentWritesState = true;
        return { kind: 'mapDynState', type: r.valueType, baseSlot: r.baseSlot, keys: r.keys, keyTypes: r.keyTypes };
      }
      this.currentWritesState = true;
      return { kind: 'mapping', type: r.valueType, baseSlot: r.baseSlot, keys: r.keys, keyTypes: r.keyTypes, varName: r.varName };
    }
    // local
    if (ts.isIdentifier(node)) {
      const t = this.lookupLocal(node.text);
      if (!t) {
        this.diags.error(node, 'JETH066', `assignment to unknown variable '${node.text}'`);
        return undefined;
      }
      return { kind: 'local', type: t, varName: node.text };
    }
    this.diags.error(node, 'JETH067', 'invalid assignment target');
    return undefined;
  }

  /** True iff `node` (an element access `X[i]`) is an array-element assignment: its
   *  base `X` resolves to a storage/fixed/mapping-valued array (`this.arr`, a local,
   *  or `this.m[k]` whose value is a dynamic array). Distinguishes `this.m[k][i] = v`
   *  on a mapping<K,T[]> (array-element write) from a nested-mapping key write. */
  private assignableArrayElem(node: ts.ElementAccessExpression): boolean {
    const bt = this.baseDynType(node.expression);
    if (bt && bt.kind === 'array') return true;
    const arr = this.resolveArrayExpr(node.expression);
    return (
      !!arr &&
      (arr.base.kind === 'mapArray' ||
        arr.base.kind === 'stateArray' ||
        arr.base.kind === 'fixedArray' ||
        arr.base.kind === 'placeArray' || // this.dd[i][j] = v, this.m[k][i][j] = v
        arr.base.kind === 'memArray' ||
        arr.base.kind === 'memArrayExpr') // (c ? xs : ys)[i] = v
    );
  }

  private lvalueAsExpr(lv: LValue): Expr {
    if (lv.kind === 'state') {
      this.currentReadsState = true;
      return { kind: 'stateRead', type: lv.type, slot: lv.slot, offset: lv.offset, varName: lv.varName };
    }
    if (lv.kind === 'mapping') {
      this.currentReadsState = true;
      return { kind: 'mapGet', type: lv.type, baseSlot: lv.baseSlot, keys: lv.keys, keyTypes: lv.keyTypes };
    }
    if (lv.kind === 'arrayElem') {
      if (lv.arr.base.kind !== 'memArray' && lv.arr.base.kind !== 'memArrayExpr') this.currentReadsState = true; // a memory array read is not storage
      return { kind: 'arrayGet', type: lv.type, arr: lv.arr, index: lv.index };
    }
    if (lv.kind === 'place') {
      this.currentReadsState = true;
      return { kind: 'placeRead', type: lv.type, path: lv.path };
    }
    // bytes/string lvalues (this.s, this.ss[i]): only plain `=` is valid; a compound
    // `op=` desugars through here, but buildBinary then rejects the bytes/string op.
    if (lv.kind === 'dynState') {
      this.currentReadsState = true;
      return { kind: 'dynStateRead', type: lv.type, slot: lv.slot };
    }
    if (lv.kind === 'mapDynState') {
      this.currentReadsState = true;
      return { kind: 'mapDynValue', type: lv.type, baseSlot: lv.baseSlot, keys: lv.keys, keyTypes: lv.keyTypes };
    }
    if (lv.kind === 'strArrayElem') {
      this.currentReadsState = true;
      return { kind: 'strArrayElem', type: lv.type, arr: lv.arr, index: lv.index };
    }
    if (lv.kind === 'dynPlace') {
      this.currentReadsState = true;
      return { kind: 'dynPlaceRead', type: lv.type, path: lv.path };
    }
    if (lv.kind === 'memField') {
      // a memory struct field read (for compound-assign / ++ on p.x): NOT storage.
      return { kind: 'memField', type: lv.type, local: lv.local, wordOffset: lv.wordOffset };
    }
    return { kind: 'localRead', type: lv.type, name: lv.varName };
  }

  // ---- mapping access / globals / casts (Phase 3) --------------------------

  /** Validate an array type for Phase 4b (single-level, static element). Returns
   *  true if usable; emits a diagnostic and returns false otherwise. */
  /** True if `t` is, or transitively contains (mapping value, array element, or
   *  struct field), a dynamic array of dynamic byte-sequence elements (string[]
   *  / bytes[]). Used to reject such types in storage, where per-element data
   *  slots are not yet implemented. */
  /** True if a struct field type `t` is a supported dynamic field kind (Phase
   *  4e-6). Supported: bytes/string, or a nested struct whose every field is
   *  itself static or a supported dynamic field. A dynamic array field of any
   *  kind is NOT supported (deferred). Static types are handled separately. */
  private isSupportedDynStructField(t: JethType): boolean {
    if (isBytesLike(t)) return true;
    if (t.kind === 'struct') return t.fields.every((f) => isStaticType(f.type) || this.isSupportedDynStructField(f.type));
    // a dynamic-array field (u256[], string[], D[], T[][]) or a fixed array of a dynamic
    // element: in storage the array lives at the field slot (length there, data at
    // keccak(fieldSlot)); the ABI codec encodes/decodes it via the recursive encoder.
    if (t.kind === 'array') return isStaticType(t.element) || isBytesLike(t.element) || t.element.kind === 'array' || this.isSupportedDynStructField(t.element);
    return false;
  }

  /** True if a struct return type is shaped so the general tuple encoder (4e-6)
   *  can encode it: every field is a fully-static type (value / nested static
   *  struct / fixed static array) OR a supported dynamic field (bytes/string, or
   *  a nested struct that is itself a supported struct return). A dynamic-array
   *  field is NOT supported. */
  private isSupportedStructReturn(t: JethType & { kind: 'struct' }): boolean {
    // A fully-static struct return is encoded from storage by the recursive encoder
    // (structStorageLeaves flattens nested static structs and fixed-array fields), so
    // any static field shape is supported.
    if (!isDynamicType(t)) return t.fields.every((f) => isStaticType(f.type));
    // A dynamic struct return uses the general tuple encoder, which handles any
    // mix of static (value / nested static struct / static fixed-array) fields and
    // supported dynamic fields (bytes/string, or a nested supported struct).
    return t.fields.every((f) => isStaticType(f.type) || this.isSupportedDynStructField(f.type));
  }

  private containsDynElemArray(t: JethType): boolean {
    switch (t.kind) {
      case 'array':
        if (t.length === undefined && isBytesLike(t.element)) return true;
        return this.containsDynElemArray(t.element);
      case 'mapping':
        return this.containsDynElemArray(t.value);
      case 'struct':
        return t.fields.some((f) => this.containsDynElemArray(f.type));
      default:
        return false;
    }
  }

  /** True iff `t` is exactly a storage-supported `string[]` / `bytes[]`: either the
   *  bare dynamic array of a dynamic byte-sequence element, or a `mapping<K, ...>`
   *  chain whose final value is such an array. The element header lives at
   *  `keccak(lenSlot)+i` (a normal storage bytes/string), so the storage codec is
   *  reused per element. A `string[]` nested deeper (inside a struct, inside another
   *  array, or as a `string[][]`) is genuinely a later step and stays gated. */
  private isStorageStrArray(t: JethType): boolean {
    if (t.kind === 'mapping') return this.isStorageStrArray(t.value);
    return t.kind === 'array' && t.length === undefined && isBytesLike(t.element);
  }

  /** True if `t` is, or transitively contains (array element, mapping value), a
   *  DYNAMIC struct (a struct with >=1 dynamic field). Used to reject such a type
   *  in storage / mapping positions: the calldata-param / return tuple codec
   *  (4e-6) has no storage representation for the dynamic members yet. */
  private containsDynamicStruct(t: JethType): boolean {
    switch (t.kind) {
      case 'struct':
        return isDynamicType(t) || t.fields.some((f) => this.containsDynamicStruct(f.type));
      case 'array':
        return this.containsDynamicStruct(t.element);
      case 'mapping':
        return this.containsDynamicStruct(t.value);
      default:
        return false;
    }
  }

  /** True iff `t` is exactly a storage-supported DYNAMIC STRUCT: either a dynamic
   *  struct (a `@struct` with >=1 dynamic field) whose every dynamic field is a
   *  bytes/string or a (recursively storage-supported) nested struct, OR a
   *  `mapping<K, ...>` chain whose final value is such a struct. A dynamic struct
   *  in storage occupies contiguous slots; each static field uses normal packed
   *  storage, and each bytes/string field at `base + fieldSlot` is a normal storage
   *  bytes/string (short inline / long with keccak(headerSlot) data slots), so the
   *  storage bytes/string codec is reused per field. A `D[]` (dynamic array of
   *  dynamic struct) or fixed `Arr<D,N>` is rejected EARLIER by gateArrayType (the
   *  element is not static); a dynamic-ARRAY struct field is impossible (rejected at
   *  @struct declaration, JETH229). So a dynamic struct that reaches this check is
   *  always storage-representable. */
  private isStorageDynStruct(t: JethType): boolean {
    if (t.kind === 'mapping') return this.isStorageDynStruct(t.value);
    // a dynamic array D[] (or mapping<K,D[]>) or a fixed Arr<D,N> of a storage-supported
    // dynamic struct: each element is a contiguous storageSlotCount(D) block (at
    // keccak(lenSlot)+i*stride for a dynamic array, or baseSlot+i*stride for a fixed one).
    if (t.kind === 'array') return this.isStorageDynStruct(t.element);
    if (t.kind !== 'struct' || !isDynamicType(t)) return false;
    return t.fields.every((f) => isStaticType(f.type) || this.isSupportedDynStructField(f.type));
  }

  /** Type-only walk: true iff `node` is a property/index chain rooted at a
   *  `this.<state-var>` that reads a bytes/string field of a STORAGE dynamic struct
   *  (this.d.s, this.e.b, this.recs[i].s, this.o.inner.s, this.m[k].s). Used to claim
   *  `this.<chain>.b[j]` byte-indexing for such a base. No diagnostics emitted. */
  private isStorageDynStructBytesField(node: ts.Expression): boolean {
    const steps: ({ field: string } | { index: true } | { mapKey: true })[] = [];
    let cur: ts.Expression = node;
    let rootType: JethType | undefined;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.expression.kind === ts.SyntaxKind.ThisKeyword) {
          rootType = this.stateByName.get(cur.name.text)?.type;
          break;
        }
        steps.push({ field: cur.name.text });
        cur = cur.expression;
      } else if (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        steps.push({ index: true });
        cur = cur.expression;
      } else {
        return false;
      }
    }
    if (!rootType) return false;
    steps.reverse();
    let t: JethType = rootType;
    for (const s of steps) {
      if ('field' in s) {
        if (t.kind !== 'struct') return false;
        const f = t.fields.find((ff) => ff.name === s.field);
        if (!f) return false;
        t = f.type;
      } else {
        // index step: array element or mapping value.
        if (t.kind === 'array') t = t.element;
        else if (t.kind === 'mapping') t = t.value;
        else return false;
      }
    }
    return isBytesLike(t);
  }

  /** True if `t` is, or transitively contains, a NESTED dynamic array T[][] (a
   *  dynamic array whose element is itself a dynamic array). Per-element pointer
   *  tables are only implemented for the calldata-param / return form (4e-5);
   *  reject such a type in storage / mapping positions to avoid a silent
   *  miscompile. */
  private containsNestedDynArray(t: JethType): boolean {
    switch (t.kind) {
      case 'array':
        if (t.length === undefined && t.element.kind === 'array' && t.element.length === undefined) return true;
        return this.containsNestedDynArray(t.element);
      case 'mapping':
        return this.containsNestedDynArray(t.value);
      case 'struct':
        return t.fields.some((f) => this.containsNestedDynArray(f.type));
      default:
        return false;
    }
  }

  /** A dynamic array whose element chain (descending dynamic-array levels) reaches a
   *  static value type or bytes/string: u256[][], u256[][][], string[][], bytes[][],
   *  ... at ANY depth. Supported as a calldata param / return via the recursive codec. */
  private isAbiNestedDynArray(t: JethType): boolean {
    if (t.kind !== 'array' || t.length !== undefined) return false;
    const e = t.element;
    if (isStaticValueType(e) || isBytesLike(e)) return true;
    if (e.kind === 'struct' && (isStaticType(e) || this.isSupportedDynStructField(e))) return true; // Pt[][], D[][]
    if (e.kind === 'array' && e.length === undefined) return this.isAbiNestedDynArray(e);
    return false;
  }

  private gateArrayType(t: JethType, node: ts.Node, storage = false): boolean {
    if (t.kind !== 'array') return true;
    if (t.length === undefined) {
      // dynamic T[]: static value element (4b) or static struct element (4e-1).
      if (t.element.kind === 'array') {
        // Nested dynamic array of ANY depth (u256[][], u256[][][], string[][], ...):
        // supported as a calldata param / return via the recursive head/tail codec
        // (no nesting-level limit). The leaf (after descending dynamic-array levels)
        // must be a static value type or bytes/string. Storage / mapping positions are
        // rejected separately by the containsNestedDynArray guard.
        if (this.isAbiNestedDynArray(t)) return true;
        this.diags.error(node, 'JETH217', 'this nested dynamic array shape is not supported yet');
        return false;
      }
      if (t.element.kind === 'struct') {
        if (!isStaticType(t.element)) {
          // A dynamic array of a DYNAMIC struct (D[] where D has a bytes/string
          // field): in STORAGE each element occupies storageSlotCount(D) contiguous
          // slots; as a CALLDATA param / RETURN it is an array of dynamic elements
          // (offset table + per-element tuple), handled by the recursive codec.
          if (storage && this.isStorageDynStruct(t.element)) return true;
          if (!storage && this.isSupportedDynStructField(t.element)) return true;
          this.diags.error(node, 'JETH217', 'this dynamic-struct-array position is not supported yet');
          return false;
        }
        return true; // dynamic array of static struct
      }
      // dynamic array of dynamic byte-sequence element (string[] / bytes[], 4e-4):
      // head/tail of dynamic elements. Only supported as a calldata param / return.
      if (isBytesLike(t.element)) return true;
      if (!isStaticValueType(t.element)) {
        this.diags.error(node, 'JETH210', `array element type ${displayName(t.element)} is not supported yet`);
        return false;
      }
      return true;
    }
    // fixed Arr<T,N>: any static element (value, struct, or nested fixed array), OR a
    // DYNAMIC element (Arr<string,N>, Arr<bytes,N>, Arr<D,N>) as a calldata param /
    // return via the recursive codec (an N-word per-element offset table, no length).
    if (!isStaticType(t.element)) {
      // Arr<string,N> / Arr<bytes,N>: N contiguous string headers (storage) or an
      // N-word offset table (calldata/return).
      if (isBytesLike(t.element)) return true;
      // Arr<D,N> (fixed array of a DYNAMIC struct): N*slotCount(D) contiguous slots in
      // storage; an N-word offset table + per-element tuples as a calldata param/return.
      if (t.element.kind === 'struct' && (storage ? this.isStorageDynStruct(t.element) : this.isSupportedDynStructField(t.element))) return true;
      this.diags.error(node, 'JETH210', `fixed-array element type ${displayName(t.element)} is not supported yet`);
      return false;
    }
    return true;
  }

  /** Resolve a `d.field...field` chain rooted at a DYNAMIC-struct calldata param
   *  (Phase 4e-6) into either a static-leaf read, a dynamic-field value, or a
   *  whole-struct value. Returns undefined when the root is not a dynamic-struct
   *  param (so other handlers run); commits (possibly with a diagnostic) once it
   *  owns the chain. Each step is a struct field; a field whose own value is
   *  dynamic resets the tuple-start base at codegen (spec section 3.2). The chain
   *  must end at a static value leaf, OR at a bytes/string dynamic field. */
  private resolveCdDynStruct(node: ts.Expression): { committed: true; result?: Expr } | undefined {
    const rawFields: ts.PropertyAccessExpression[] = [];
    let cur: ts.Expression = node;
    let rootName: string | undefined;
    let rootType: (JethType & { kind: 'struct' }) | undefined;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.name.text === 'length') return undefined; // .length handled elsewhere
        rawFields.push(cur);
        cur = cur.expression;
      } else if (ts.isIdentifier(cur)) {
        const t = this.lookupLocal(cur.text);
        if (t && t.kind === 'struct' && isDynamicType(t)) {
          rootName = cur.text;
          rootType = t;
        }
        break;
      } else {
        return undefined; // an index step (or non-identifier root): not a bare dyn-struct field chain
      }
    }
    if (!rootName || !rootType || rawFields.length === 0) return undefined;
    rawFields.reverse(); // root -> leaf

    let t: JethType = rootType;
    const steps: CdDynStep[] = [];
    for (const fnode of rawFields) {
      if (t.kind !== 'struct') {
        this.diags.error(fnode, 'JETH210', `'${displayName(t)}' has no field '${fnode.name.text}'`);
        return { committed: true };
      }
      const idx = t.fields.findIndex((f) => f.name === fnode.name.text);
      if (idx < 0) {
        this.diags.error(fnode, 'JETH210', `struct '${t.name}' has no field '${fnode.name.text}'`);
        return { committed: true };
      }
      const f = t.fields[idx]!;
      // Tuple-head word offset: each preceding field contributes its inline static
      // words, or exactly ONE offset word if it is dynamic (spec section 3.0). Note
      // abiHeadWords would wrongly EXPAND a dynamic sub-struct into all its leaves.
      const headWords = t.fields.slice(0, idx).reduce((n, ff) => n + (isDynamicType(ff.type) ? 1 : abiHeadWords(ff.type)), 0);
      steps.push({ headWords, fieldType: f.type, crossDynamic: isDynamicType(f.type) });
      t = f.type;
    }
    const place: CdDynPlace = { param: rootName, steps };
    if (isStaticValueType(t)) {
      return { committed: true, result: { kind: 'cdDynStructLeaf', type: t, place } };
    }
    if (isBytesLike(t)) {
      return { committed: true, result: { kind: 'cdDynStructField', type: t, place } };
    }
    // Ended at a whole nested struct (static or dynamic): reading it whole is a
    // later step. (A static nested struct read would need a tuple-return encode
    // from a calldata source; a dynamic one likewise.)
    this.diags.error(node, 'JETH230', `reading a whole ${displayName(t)} from a dynamic-struct calldata parameter is not supported yet (access a value field)`);
    return { committed: true };
  }

  /** Resolve a field/index chain rooted at an aggregate (struct or FIXED-array)
   *  function parameter into a CalldataPlace. Returns undefined when the root is
   *  not an aggregate param, letting the other handlers run. Once it owns the
   *  chain it commits (and may emit a diagnostic, returning no result). The ABI
   *  head is UNPACKED: each leaf is one 32-byte word, so steps carry head-word
   *  offsets, not storage slots. Dynamic-array params keep the cdArrays path. */
  /** Type-only walk of a field/index chain rooted at a struct/fixed-array param,
   *  returning the final type WITHOUT emitting diagnostics. Used so `.length` of a
   *  fixed-array field/element of a calldata aggregate resolves to its constant. */
  private calldataAccessType(node: ts.Expression): JethType | undefined {
    const steps: ({ field: string } | { index: true })[] = [];
    let cur: ts.Expression = node;
    let rootType: JethType | undefined;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.name.text === 'length') return undefined;
        steps.push({ field: cur.name.text });
        cur = cur.expression;
      } else if (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        steps.push({ index: true });
        cur = cur.expression;
      } else if (ts.isIdentifier(cur)) {
        const t = this.lookupLocal(cur.text);
        // own only STATIC aggregate params (inline head): a static struct or a fixed
        // array of a static element. Arr<dyn,N> is a dynamic calldata array (cdArrays).
        if (t && (t.kind === 'struct' || (t.kind === 'array' && t.length !== undefined)) && isStaticType(t)) rootType = t;
        break;
      } else {
        return undefined;
      }
    }
    if (!rootType) return undefined;
    steps.reverse();
    let t: JethType = rootType;
    for (const s of steps) {
      if ('field' in s) {
        if (t.kind !== 'struct') return undefined;
        const f = t.fields.find((ff) => ff.name === s.field);
        if (!f) return undefined;
        t = f.type;
      } else {
        if (!(t.kind === 'array' && t.length !== undefined)) return undefined;
        t = t.element;
      }
    }
    return t;
  }

  private resolveCalldataPlace(
    node: ts.Expression,
  ): { committed: true; result?: { place: CalldataPlace; finalType: JethType } } | undefined {
    const rawSteps: ({ field: ts.PropertyAccessExpression } | { index: ts.Expression })[] = [];
    let cur: ts.Expression = node;
    let rootName: string | undefined;
    let rootType: JethType | undefined;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.name.text === 'length') return undefined; // .length handled elsewhere
        rawSteps.push({ field: cur });
        cur = cur.expression;
      } else if (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        rawSteps.push({ index: cur.argumentExpression });
        cur = cur.expression;
      } else if (ts.isIdentifier(cur)) {
        const t = this.lookupLocal(cur.text);
        // own only STATIC aggregate params: a fully-static struct, or a fixed array of
        // a STATIC element. A DYNAMIC struct is owned by resolveCdDynStruct; an
        // Arr<dyn,N> is a dynamic calldata array (cdArrays element paths).
        if (t && ((t.kind === 'struct' && isStaticType(t)) || (t.kind === 'array' && t.length !== undefined && isStaticType(t)))) {
          rootName = cur.text;
          rootType = t;
        }
        break;
      } else {
        return undefined;
      }
    }
    if (!rootName || !rootType || rawSteps.length === 0) return undefined;
    rawSteps.reverse(); // root -> leaf

    let t: JethType = rootType;
    const steps: CdStep[] = [];
    for (const s of rawSteps) {
      if ('field' in s) {
        if (t.kind !== 'struct') {
          this.diags.error(s.field, 'JETH210', `'${displayName(t)}' has no field '${s.field.name.text}'`);
          return { committed: true };
        }
        const idx = t.fields.findIndex((f) => f.name === s.field.name.text);
        if (idx < 0) {
          this.diags.error(s.field, 'JETH210', `struct '${t.name}' has no field '${s.field.name.text}'`);
          return { committed: true };
        }
        const headWords = t.fields.slice(0, idx).reduce((n, f) => n + abiHeadWords(f.type), 0);
        steps.push({ kind: 'field', headWords, fieldType: t.fields[idx]!.type });
        t = t.fields[idx]!.type;
      } else {
        if (!(t.kind === 'array' && t.length !== undefined)) {
          this.diags.error(s.index, 'JETH212', `cannot index ${displayName(t)}`);
          return { committed: true };
        }
        const index = this.checkExpr(s.index, U256);
        if (!index) return { committed: true };
        const idx = this.coerce(index, U256, s.index);
        if (idx.kind === 'literalInt' && (idx.value < 0n || idx.value >= BigInt(t.length))) {
          this.diags.error(s.index, 'JETH211', `array index ${idx.value} out of bounds for length ${t.length}`);
          return { committed: true };
        }
        steps.push({ kind: 'index', index: idx, strideWords: abiHeadWords(t.element), length: t.length, elemType: t.element });
        t = t.element;
      }
    }
    if (!isStaticValueType(t)) {
      this.diags.error(node, 'JETH230', 'reading a whole struct/array from a calldata parameter is not supported yet (access a value field/element)');
      return { committed: true };
    }
    return { committed: true, result: { place: { param: rootName, steps, finalType: t }, finalType: t } };
  }

  /** Resolve `<dynArrayOfStruct>[i].field` (a calldata param) into a cdArrayField
   *  read. Owns the shape once matched; returns the Expr, or undefined after a
   *  diagnostic. (Storage dynamic arrays of struct are gated elsewhere, so the
   *  array here is always a calldata param.) */
  /** Resolve `ds[i].field` where ds is a calldata D[] (dynamic-struct array): the
   *  element ds[i] is a dynamic tuple reached via the per-element offset table, then
   *  the field is read from that tuple (static leaf or bytes/string), reusing the
   *  dynamic-struct field access (CdDynPlace with an arrayRoot). */
  private resolveCdDynArrayField(node: ts.PropertyAccessExpression, struct: JethType & { kind: 'struct' }): Expr | undefined {
    const elemAccess = node.expression as ts.ElementAccessExpression;
    const arr = this.resolveArrayExpr(elemAccess.expression);
    if (!arr || arr.base.kind !== 'calldataArray') {
      this.diags.error(node, 'JETH217', 'this dynamic-struct-array element access is not supported');
      return undefined;
    }
    if (!elemAccess.argumentExpression) return undefined;
    const indexE = this.checkExpr(elemAccess.argumentExpression, U256);
    if (!indexE) return undefined;
    const index = this.coerce(indexE, U256, elemAccess.argumentExpression);
    const fidx = struct.fields.findIndex((f) => f.name === node.name.text);
    if (fidx < 0) {
      this.diags.error(node, 'JETH210', `struct '${struct.name}' has no field '${node.name.text}'`);
      return undefined;
    }
    const f = struct.fields[fidx]!;
    const headWords = struct.fields.slice(0, fidx).reduce((n, ff) => n + (isDynamicType(ff.type) ? 1 : abiHeadWords(ff.type)), 0);
    const place: CdDynPlace = { param: '', steps: [{ headWords, fieldType: f.type, crossDynamic: isDynamicType(f.type) }], arrayRoot: { arr, index } };
    if (isStaticValueType(f.type)) return { kind: 'cdDynStructLeaf', type: f.type, place };
    if (isBytesLike(f.type)) return { kind: 'cdDynStructField', type: f.type, place };
    this.diags.error(node, 'JETH230', 'reading a whole nested struct/array field of a dynamic-struct array element is a later step');
    return undefined;
  }

  private resolveCdArrayField(node: ts.PropertyAccessExpression, struct: JethType & { kind: 'struct' }): Expr | undefined {
    const elemAccess = node.expression as ts.ElementAccessExpression;
    const arr = this.resolveArrayExpr(elemAccess.expression);
    if (!arr || arr.base.kind !== 'calldataArray') {
      this.diags.error(node, 'JETH217', 'this dynamic-array-of-struct access is a later step');
      return undefined;
    }
    const fidx = struct.fields.findIndex((f) => f.name === node.name.text);
    if (fidx < 0) {
      this.diags.error(node, 'JETH210', `struct '${struct.name}' has no field '${node.name.text}'`);
      return undefined;
    }
    const f = struct.fields[fidx]!;
    if (!isStaticValueType(f.type)) {
      this.diags.error(node, 'JETH230', 'reading a non-value field of a calldata struct-array element is a later step');
      return undefined;
    }
    if (!elemAccess.argumentExpression) return undefined;
    const index = this.checkExpr(elemAccess.argumentExpression, U256);
    if (!index) return undefined;
    const idx = this.coerce(index, U256, elemAccess.argumentExpression);
    const headWords = struct.fields.slice(0, fidx).reduce((n, ff) => n + abiHeadWords(ff.type), 0);
    return { kind: 'cdArrayField', type: f.type, arr, index: idx, headWords, fieldType: f.type };
  }

  /** Compile-time bounds check for a constant index into a fixed array (matches
   *  solc's "Out of bounds array access" compile error). */
  private checkFixedBound(arr: ArrayExpr, idx: Expr, node: ts.Node): boolean {
    if (arr.base.kind === 'fixedArray' && idx.kind === 'literalInt') {
      if (idx.value < 0n || idx.value >= BigInt(arr.base.length)) {
        this.diags.error(node, 'JETH211', `array index ${idx.value} out of bounds for length ${arr.base.length}`);
        return false;
      }
    }
    return true;
  }

  /** Resolve `this.arr` or an array param into an ArrayExpr (single-level). */
  private resolveArrayExpr(node: ts.Expression): ArrayExpr | undefined {
    node = stripParens(node); // (xs)[i] / ((this.a))[i] index a parenthesized array base
    // (c ? xs : ys)[i]: a memory array produced by a ternary; the expr lowers to a pointer.
    if (ts.isConditionalExpression(node)) {
      const e = this.checkExpr(node);
      if (e && e.type.kind === 'array' && e.type.length === undefined && isStaticValueType(e.type.element)) {
        return { base: { kind: 'memArrayExpr', expr: e }, elem: e.type.element };
      }
      return undefined;
    }
    if (ts.isPropertyAccessExpression(node) && node.expression.kind === ts.SyntaxKind.ThisKeyword) {
      const v = this.stateByName.get(node.name.text);
      if (v && v.type.kind === 'array') {
        if (v.type.length === undefined) return { base: { kind: 'stateArray', slot: v.slot }, elem: v.type.element };
        return { base: { kind: 'fixedArray', baseSlot: v.slot, length: v.type.length }, elem: v.type.element };
      }
      return undefined;
    }
    if (ts.isIdentifier(node)) {
      const t = this.lookupLocal(node.text);
      // a MEMORY array local (let xs: u256[] = [...]): the register holds a pointer to
      // [len][elems]; element/length access reads memory.
      if (t && t.kind === 'array' && this.memArrayLocals.has(node.text)) {
        return { base: { kind: 'memArray', varName: node.text }, elem: t.element };
      }
      // a dynamic array param, OR a fixed array of a DYNAMIC element (Arr<dyn,N>),
      // both bound at codegen as a calldata array (the latter with a constant length).
      if (t && t.kind === 'array' && (t.length === undefined || isDynamicType(t.element))) {
        return { base: { kind: 'calldataArray', name: node.text }, elem: t.element };
      }
    }
    // An inner array reached by a chain of index steps into a nested dynamic array
    // calldata param (T[][], T[][][], string[][], ...). Walk inward collecting the
    // indices until the bare param identifier; descend the type tree by that many
    // dynamic-array levels. The resolved array (the value at m[i]/m[i][j]/...) must
    // itself be a dynamic array (length === undefined) for it to be an ArrayExpr; its
    // own element type is `elem`. Each [k] descends one level via the level's inner-
    // offset table at codegen (4e-5 / 4e-8). The root param's outermost level must be
    // a nested dynamic array (element is itself a dynamic array) so we never shadow the
    // ordinary single-level calldataArray / cdDynArrayElem paths.
    if (ts.isElementAccessExpression(node) && node.argumentExpression) {
      const indexNodes: ts.Expression[] = [];
      let cur: ts.Expression = node;
      while (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        indexNodes.push(cur.argumentExpression);
        cur = cur.expression;
      }
      if (ts.isIdentifier(cur)) {
        const root = this.lookupLocal(cur.text);
        if (
          root &&
          root.kind === 'array' &&
          root.length === undefined &&
          root.element.kind === 'array' &&
          root.element.length === undefined
        ) {
          indexNodes.reverse(); // outer-to-inner
          // descend the type tree one dynamic-array level per index step.
          let t: JethType = root;
          for (let s = 0; s < indexNodes.length; s++) {
            if (t.kind !== 'array' || t.length !== undefined) return undefined; // not a dynamic array at this level
            t = t.element;
          }
          // the resolved value must itself be a dynamic array to be an ArrayExpr.
          if (t.kind !== 'array' || t.length !== undefined) return undefined;
          const indices: Expr[] = [];
          for (const inode of indexNodes) {
            const index = this.checkExpr(inode, U256);
            if (!index) return undefined;
            indices.push(this.coerce(index, U256, inode));
          }
          return { base: { kind: 'cdNestedElem', name: cur.text, indices }, elem: t.element };
        }
      }
    }
    // a mapping value that is a dynamic array: this.m[k] (possibly nested) -> T[].
    // Only attempt when the chain is rooted at a mapping state var (so we never
    // emit spurious diagnostics from resolveMapAccess on a non-mapping base).
    if (ts.isElementAccessExpression(node)) {
      let cur: ts.Expression = node;
      let numIndices = 0;
      while (ts.isElementAccessExpression(cur)) { numIndices++; cur = cur.expression; }
      if (ts.isPropertyAccessExpression(cur) && cur.expression.kind === ts.SyntaxKind.ThisKeyword) {
        const sv = this.stateByName.get(cur.name.text);
        if (sv && sv.type.kind === 'mapping') {
          // ONLY a pure mapping chain whose every index is a key and whose value is a
          // dynamic array (this.m[k]). If indices index INTO the array value
          // (this.m[k][i] on a mapping<K, T[][]>), decline so resolveStorageArrayPlace
          // (placeArray) owns it - resolveMapAccess would otherwise emit JETH152.
          let t: JethType = sv.type;
          let mapKeys = 0;
          while (t.kind === 'mapping' && mapKeys < numIndices) { t = t.value; mapKeys++; }
          if (mapKeys === numIndices && t.kind === 'array' && t.length === undefined) {
            const r = this.resolveMapAccess(node);
            if (r && r.valueType.kind === 'array' && r.valueType.length === undefined) {
              return { base: { kind: 'mapArray', baseSlot: r.baseSlot, keys: r.keys, keyTypes: r.keyTypes }, elem: r.valueType.element };
            }
          }
        }
      }
    }
    // A storage INNER dynamic array reached by a nested chain (this.dd[i] of u256[][],
    // this.s.xs dyn-array struct field, this.m[k].xs): build the AccessPath to the inner
    // array's length slot and wrap it in a placeArray (length / push / pop / index /
    // whole encode all reuse the storage-array machinery at that runtime slot).
    const place = this.resolveStorageArrayPlace(node);
    if (place) return { base: { kind: 'placeArray', path: place.path }, elem: place.elem };
    return undefined;
  }

  /** Build the AccessPath to a storage INNER dynamic array landing slot for a this-rooted
   *  chain (this.dd[i], this.dd[i][j], this.s.xs, this.m[k].xs): walks field / index /
   *  mapKey steps and returns the path + element type iff it lands on a dynamic array.
   *  Returns undefined (no diagnostic) for anything else. */
  private resolveStorageArrayPlace(node: ts.Expression): { path: AccessPath; elem: JethType } | undefined {
    const raw: ({ field: string } | { index: ts.Expression })[] = [];
    let cur: ts.Expression = node;
    let rootType: JethType | undefined;
    let baseSlot = -1;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.expression.kind === ts.SyntaxKind.ThisKeyword) {
          const v = this.stateByName.get(cur.name.text);
          if (!v) return undefined;
          baseSlot = v.slot;
          rootType = v.type;
          break;
        }
        if (cur.name.text === 'length') return undefined;
        raw.push({ field: cur.name.text });
        cur = cur.expression;
      } else if (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        raw.push({ index: cur.argumentExpression });
        cur = cur.expression;
      } else return undefined;
    }
    if (!rootType || raw.length === 0) return undefined; // a bare this.arr is the stateArray case
    raw.reverse();
    let t: JethType = rootType;
    const steps: AccessStep[] = [];
    for (const s of raw) {
      if ('field' in s) {
        if (t.kind !== 'struct') return undefined;
        const f = t.fields.find((ff) => ff.name === s.field);
        if (!f) return undefined;
        steps.push({ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type });
        t = f.type;
      } else if (t.kind === 'array') {
        // a bytes/string element index is a byte-index, not a place: not our concern.
        if (t.length === undefined && isBytesLike(t.element)) return undefined;
        const idxE = this.checkExpr(s.index, U256);
        if (!idxE) return undefined;
        const idx = this.coerce(idxE, U256, s.index);
        if (t.length !== undefined) steps.push({ kind: 'index', index: idx, strideSlots: storageSlotCount(t.element), length: t.length, elemType: t.element });
        else steps.push({ kind: 'dynIndex', index: idx, strideSlots: storageSlotCount(t.element), elemType: t.element });
        t = t.element;
      } else if (t.kind === 'mapping') {
        const keyE = this.checkExpr(s.index, t.key);
        if (!keyE) return undefined;
        steps.push({ kind: 'mapKey', key: this.coerce(keyE, t.key, s.index), valueType: t.value });
        t = t.value;
      } else return undefined;
    }
    if (t.kind === 'array' && t.length === undefined) {
      this.currentReadsState = true;
      return { path: { baseSlot, steps }, elem: t.element };
    }
    return undefined;
  }

  /** True iff `node` is an index chain `m[i]...[k]` rooted at a calldata param whose
   *  type is a NESTED dynamic array (the outer element is itself a dynamic array, e.g.
   *  T[][], T[][][], string[][]). Used to recognise a nested-dynamic-array navigation
   *  before delegating to resolveArrayExpr / cdNestedElem. No diagnostics. */
  private nestedDynArrayRoot(node: ts.Expression): boolean {
    let cur: ts.Expression = node;
    while (ts.isElementAccessExpression(cur) && cur.argumentExpression) cur = cur.expression;
    if (!ts.isIdentifier(cur)) return false;
    const t = this.lookupLocal(cur.text);
    return (
      t !== undefined &&
      t.kind === 'array' &&
      t.length === undefined &&
      t.element.kind === 'array' &&
      t.element.length === undefined
    );
  }

  /** Type of a directly-resolvable index base (`this.s` or a local/param), used to
   *  distinguish bytes-indexing `b[i]` from mapping access `this.m[k]`. Returns
   *  undefined for nested/complex bases (which go through the mapping resolver). */
  private baseDynType(expr: ts.Expression): JethType | undefined {
    expr = stripParens(expr);
    if (ts.isPropertyAccessExpression(expr) && expr.expression.kind === ts.SyntaxKind.ThisKeyword) {
      return this.stateByName.get(expr.name.text)?.type;
    }
    if (ts.isIdentifier(expr)) return this.lookupLocal(expr.text);
    return undefined;
  }

  /** Resolve a NESTED storage chain (>=2 steps, involving a struct field or a
   *  fixed-array index) rooted at `this.<var>` into an AccessPath + final value
   *  type. Returns undefined for chains the flat handlers own (single step, or a
   *  pure-mapping chain), letting them run. Emits a diagnostic on a genuine error. */
  private resolveAccess(node: ts.Expression): { committed: true; result?: { path: AccessPath; finalType: JethType } } | undefined {
    const rawSteps: ({ field: ts.PropertyAccessExpression } | { index: ts.Expression })[] = [];
    let cur: ts.Expression = node;
    let baseSlot = -1;
    let rootType: JethType | undefined;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.expression.kind === ts.SyntaxKind.ThisKeyword) {
          const v = this.stateByName.get(cur.name.text);
          if (!v) return undefined;
          baseSlot = v.slot;
          rootType = v.type;
          break;
        }
        if (cur.name.text === 'length') return undefined; // handled by the .length branch
        rawSteps.push({ field: cur });
        cur = cur.expression;
      } else if (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        rawSteps.push({ index: cur.argumentExpression });
        cur = cur.expression;
      } else {
        return undefined;
      }
    }
    if (!rootType || rawSteps.length < 2) return undefined; // flat cases keep their handlers
    rawSteps.reverse(); // root -> leaf

    // Type-only pre-pass: decide ownership WITHOUT checking sub-expressions. Claim
    // the chain only if it involves a struct field or fixed-array index step;
    // pure-mapping chains stay with resolveMapAccess (which checks keys once).
    let pt: JethType = rootType;
    let hasAggregate = false;
    for (const s of rawSteps) {
      if ('field' in s) {
        if (pt.kind !== 'struct') break;
        const f = pt.fields.find((ff) => ff.name === s.field.name.text);
        if (!f) break;
        pt = f.type;
        hasAggregate = true;
      } else if (isBytesLike(pt)) {
        // An index step applied to a bytes/string value (e.g. this.e.b[j] where
        // this.e.b is a bytes field of a storage dynamic struct): a BYTE index, not a
        // storage place. Let the byteIndex handler own it rather than commit + reject.
        return undefined;
      } else if (pt.kind === 'array') {
        // Indexing a storage / mapping-valued string[]/bytes[] element is a dynamic
        // bytes/string value (header at keccak(lenSlot)+i); let the dedicated
        // strArrayElem handlers own it rather than the static-leaf place resolver.
        if (pt.length === undefined && isBytesLike(pt.element)) return undefined;
        pt = pt.element; // fixed or dynamic array index
        hasAggregate = true;
      } else if (pt.kind === 'mapping') {
        pt = pt.value;
      } else break;
    }
    if (!hasAggregate) return undefined; // not ours

    // Committed: fully resolve, type-check sub-expressions, emit diagnostics.
    let t: JethType = rootType;
    const steps: AccessStep[] = [];
    for (const s of rawSteps) {
      if ('field' in s) {
        if (t.kind !== 'struct') {
          this.diags.error(s.field, 'JETH210', `'${displayName(t)}' has no field '${s.field.name.text}'`);
          return { committed: true };
        }
        const f = t.fields.find((ff) => ff.name === s.field.name.text);
        if (!f) {
          this.diags.error(s.field, 'JETH210', `struct '${t.name}' has no field '${s.field.name.text}'`);
          return { committed: true };
        }
        steps.push({ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type });
        t = f.type;
      } else {
        const idxNode = s.index;
        if (t.kind === 'array') {
          const elem = t.element;
          const packed = elem.kind !== 'struct' && elem.kind !== 'array' && storageByteSize(elem) < 32;
          if (packed && t.length === undefined) {
            // a PACKED element of a DYNAMIC array in a nested access: the data lives at
            // keccak(lenSlot) with packing; not yet wired (the fixed-array packed case is).
            this.diags.error(idxNode, 'JETH217', 'indexing a packed element of a nested dynamic array is not supported yet');
            return { committed: true };
          }
          const idxE = this.checkExpr(idxNode, U256);
          if (!idxE) return { committed: true };
          const idx = this.coerce(idxE, U256, idxNode);
          if (t.length !== undefined) {
            if (idx.kind === 'literalInt' && (idx.value < 0n || idx.value >= BigInt(t.length))) {
              this.diags.error(idxNode, 'JETH211', `array index ${idx.value} out of bounds for length ${t.length}`);
              return { committed: true };
            }
            if (packed) {
              // packed fixed-array element (perSlot per slot): runtime byte offset within the slot.
              const size = storageByteSize(elem);
              steps.push({ kind: 'packedIndex', index: idx, perSlot: Math.floor(32 / size), size, length: t.length, elemType: elem });
            } else {
              steps.push({ kind: 'index', index: idx, strideSlots: storageSlotCount(elem), length: t.length, elemType: elem });
            }
          } else {
            // dynamic T[]: runtime bound (sload) + data at keccak(lenSlot)
            steps.push({ kind: 'dynIndex', index: idx, strideSlots: storageSlotCount(elem), elemType: elem });
          }
          t = elem;
        } else if (t.kind === 'mapping') {
          const keyE = this.checkExpr(idxNode, t.key);
          if (!keyE) return { committed: true };
          steps.push({ kind: 'mapKey', key: this.coerce(keyE, t.key, idxNode), valueType: t.value });
          t = t.value;
        } else {
          this.diags.error(idxNode, 'JETH212', `cannot index ${displayName(t)}`);
          return { committed: true };
        }
      }
    }
    // The chain may end at a static value leaf (a packed-storage read/write) OR at
    // a bytes/string dynamic field of a storage dynamic struct (this.recs[i].s,
    // this.m[k].s, this.o.inner.s): the field header lives at the path's slot and
    // is a normal storage bytes/string. The caller branches on isBytesLike to emit
    // the dynamic-value node (dynPlaceRead / dynPlace) vs the static-leaf node.
    if (!isStaticValueType(t) && !isBytesLike(t)) {
      // A whole STRUCT leaf reached by an array-index last step (this.md[k][i],
      // this.recs[i] through a longer chain) is a struct array element: decline so the
      // dedicated structArrayElem handler (read via the storage encoder / write via
      // writeStruct/copyStruct at the element slot) owns it. Other whole-aggregate
      // leaves (a whole nested-struct field, a whole array) stay unsupported here.
      const lastStep = steps[steps.length - 1];
      if (t.kind === 'struct' && lastStep && (lastStep.kind === 'index' || lastStep.kind === 'dynIndex')) {
        return undefined;
      }
      // A whole STRUCT field reached by a field last step (this.recs[i].inner,
      // this.o.inner.deeper): produce the place; the read encodes it (placeRead -> the
      // storage encoder) and the write lands writeStruct/copyStruct at the field slot.
      if (t.kind === 'struct' && lastStep && lastStep.kind === 'field') {
        return { committed: true, result: { path: { baseSlot, steps }, finalType: t } };
      }
      // An inner DYNAMIC array leaf (this.s.xs, this.dd[i]) is owned by resolveArrayExpr
      // (placeArray) and the dedicated whole-inner-array read/write paths, not here.
      if (t.kind === 'array' && t.length === undefined && lastStep) return undefined;
      // A whole FIXED-array leaf reached at depth (this.g3[i][j]): produce the place; the
      // read encodes it from storage (placeRead -> returnStorageValue). The write is a
      // later step (gated in the assign handler).
      if (t.kind === 'array' && t.length !== undefined && lastStep) {
        return { committed: true, result: { path: { baseSlot, steps }, finalType: t } };
      }
      this.diags.error(node, 'JETH226', `accessing a whole ${displayName(t)} is not supported yet (index/field it to a value)`);
      return { committed: true };
    }
    return { committed: true, result: { path: { baseSlot, steps }, finalType: t } };
  }

  /** Resolve `this.m[k]...[k]` into base slot, coerced keys (outer->inner), key
   *  types, and the final value type. */
  private resolveMapAccess(
    node: ts.ElementAccessExpression,
  ): { baseSlot: number; keys: Expr[]; keyTypes: JethType[]; valueType: JethType; varName: string } | undefined {
    const indices: ts.Expression[] = [];
    let cur: ts.Expression = node;
    while (ts.isElementAccessExpression(cur)) {
      if (!cur.argumentExpression) {
        this.diags.error(cur, 'JETH150', 'mapping access requires an index expression');
        return undefined;
      }
      indices.push(cur.argumentExpression);
      cur = cur.expression;
    }
    indices.reverse(); // outer-to-inner

    if (!(ts.isPropertyAccessExpression(cur) && cur.expression.kind === ts.SyntaxKind.ThisKeyword)) {
      this.diags.error(cur, 'JETH151', 'mapping access must start at a state variable (this.m[...])');
      return undefined;
    }
    const v = this.stateByName.get(cur.name.text);
    if (!v) {
      this.diags.error(cur, 'JETH065', `unknown state variable 'this.${cur.name.text}'`);
      return undefined;
    }
    let t: JethType = v.type;
    const keys: Expr[] = [];
    const keyTypes: JethType[] = [];
    for (const idxNode of indices) {
      if (t.kind !== 'mapping') {
        this.diags.error(idxNode, 'JETH152', `cannot index ${displayName(t)} with [] (not a mapping)`);
        return undefined;
      }
      const keyExpr = this.checkExpr(idxNode, t.key);
      if (!keyExpr) return undefined;
      keys.push(this.coerce(keyExpr, t.key, idxNode));
      keyTypes.push(t.key);
      t = t.value;
    }
    return { baseSlot: v.slot, keys, keyTypes, valueType: t, varName: v.name };
  }

  private checkGlobal(node: ts.PropertyAccessExpression): Expr | undefined {
    const obj = (node.expression as ts.Identifier).text;
    const field = node.name.text;
    const entry = GLOBALS[obj]?.[field];
    if (!entry) {
      if (obj === 'msg' && field === 'data') {
        this.diags.error(node, 'JETH161', "'msg.data' (bytes) is not supported until Phase 4");
      } else {
        this.diags.error(node, 'JETH160', `unknown global '${obj}.${field}'`);
      }
      return undefined;
    }
    if (entry.cat === 'value') {
      if (this.currentMutability !== 'payable') {
        this.diags.error(node, 'JETH162', "'msg.value' can only be read in a @payable function");
      }
    } else if (entry.cat === 'env') {
      this.currentReadsEnv = true; // forbidden in @pure
    }
    // 'calldata' (msg.sig): allowed even in @pure; flag nothing.
    return { kind: 'global', type: entry.type, op: entry.op };
  }

  private checkAddressCall(node: ts.CallExpression): Expr | undefined {
    if (node.arguments.length !== 1) {
      this.diags.error(node, 'JETH170', 'address(...) takes exactly one argument');
      return undefined;
    }
    const arg = node.arguments[0]!;
    // address(this) -> the contract's own address (environment read).
    if (arg.kind === ts.SyntaxKind.ThisKeyword) {
      this.currentReadsEnv = true;
      return { kind: 'global', type: ADDRESS, op: 'address' };
    }
    // address(<int literal>) -> address-typed literal (e.g. address(0n)).
    const lit = this.asIntLiteral(arg);
    if (lit !== undefined) {
      if (lit < 0n || lit >= 1n << 160n) {
        this.diags.error(node, 'JETH070', `literal ${lit} out of range for address`);
      }
      return { kind: 'literalInt', type: ADDRESS, value: lit };
    }
    // address(<uint160 | bytes20 | address>) cast.
    const inner = this.checkExpr(arg);
    if (!inner) return undefined;
    if (this.isAddressConvertible(inner.type)) {
      return { kind: 'cast', type: ADDRESS, from: inner.type, operand: inner };
    }
    this.diags.error(node, 'JETH170', `explicit conversion to address not allowed from ${displayName(inner.type)} (convert through u160)`);
    return undefined;
  }

  private checkCast(node: ts.CallExpression, callee: string): Expr | undefined {
    if (node.arguments.length !== 1) {
      this.diags.error(node, 'JETH170', `${callee}(...) cast takes exactly one argument`);
      return undefined;
    }
    const arg = node.arguments[0]!;
    if (callee === 'payable') {
      const inner = this.checkExpr(arg);
      if (!inner) return undefined;
      if (inner.type.kind !== 'address') {
        this.diags.error(node, 'JETH171', `payable(...) requires an address operand, got ${displayName(inner.type)}`);
        return undefined;
      }
      return { kind: 'cast', type: { kind: 'address', payable: true }, from: inner.type, operand: inner };
    }
    const target = resolvePrimitiveName(callee)!; // guaranteed by caller
    const inner = this.checkExpr(arg);
    if (!inner) return undefined;
    // An integer-literal cast is range-checked at compile time (uint8(300) is an error
    // in solc, not a runtime truncation): retype the literal to the target directly.
    if (inner.kind === 'literalInt' && isInteger(target)) {
      const r = this.retypeLiteral(inner, target, node);
      return r ?? undefined;
    }
    if (this.isCastAllowed(inner.type, target)) {
      return { kind: 'cast', type: target, from: inner.type, operand: inner };
    }
    this.diags.error(node, 'JETH170', `explicit conversion not allowed from ${displayName(inner.type)} to ${displayName(target)}`);
    return undefined;
  }

  private isAddressConvertible(t: JethType): boolean {
    return t.kind === 'address' || (t.kind === 'uint' && t.bits === 160) || (t.kind === 'bytesN' && t.size === 20);
  }

  /** Minimal Phase 3 cast set (each verified against solc): address<->u160 (no-op),
   *  address<->bytes20 (shift). General numeric casts are deferred. */
  private isCastAllowed(from: JethType, to: JethType): boolean {
    if (to.kind === 'uint' && to.bits === 160 && from.kind === 'address') return true;
    if (to.kind === 'bytesN' && to.size === 20 && from.kind === 'address') return true;
    if (to.kind === 'address') return this.isAddressConvertible(from);
    // integer <-> integer: same signedness any size; different signedness ONLY same size
    // (Solidity disallows changing both sign and width in one cast).
    if ((from.kind === 'uint' || from.kind === 'int') && (to.kind === 'uint' || to.kind === 'int')) {
      return from.kind === to.kind || from.bits === to.bits;
    }
    // bytesN <-> bytesM (any size: truncate / zero-pad, left-aligned).
    if (from.kind === 'bytesN' && to.kind === 'bytesN') return true;
    // uintN <-> bytesM of the SAME byte size (uint256<->bytes32, uint32<->bytes4, ...).
    if (from.kind === 'uint' && to.kind === 'bytesN' && from.bits === to.size * 8) return true;
    if (from.kind === 'bytesN' && to.kind === 'uint' && to.bits === from.size * 8) return true;
    return false;
  }

  // ---- expressions ---------------------------------------------------------

  private checkExpr(node: ts.Expression, expected?: JethType): Expr | undefined {
    // parenthesized
    if (ts.isParenthesizedExpression(node)) return this.checkExpr(node.expression, expected);

    // assignment used as a value-producing expression: (x = v), (x += v), chained x = y = a.
    // Yields the assigned (LHS-typed) value, exactly like Solidity. Statement-position
    // assignments are handled earlier in checkStatement and never reach here.
    if (ts.isBinaryExpression(node) && this.isAssignmentOperator(node.operatorToken.kind)) {
      return this.checkAssignmentExpr(node);
    }

    // type(T).max / type(T).min -> a compile-time integer constant (Solidity-identical).
    if (
      ts.isPropertyAccessExpression(node) &&
      (node.name.text === 'max' || node.name.text === 'min') &&
      ts.isCallExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'type' &&
      node.expression.arguments.length === 1 &&
      ts.isIdentifier(node.expression.arguments[0]!)
    ) {
      const t = resolvePrimitiveName((node.expression.arguments[0] as ts.Identifier).text);
      if (!t || !isInteger(t)) {
        this.diags.error(node, 'JETH074', 'type(T).max/.min requires an integer type T');
        return undefined;
      }
      const isMax = node.name.text === 'max';
      const bits = t.kind === 'uint' ? t.bits : (t as { kind: 'int'; bits: number }).bits;
      const value = t.kind === 'uint'
        ? (isMax ? (1n << BigInt(bits)) - 1n : 0n)
        : (isMax ? (1n << BigInt(bits - 1)) - 1n : -(1n << BigInt(bits - 1)));
      return { kind: 'literalInt', type: t, value };
    }

    // ternary c ? a : b -> the common type of the two branches (short-circuit at codegen).
    if (ts.isConditionalExpression(node)) {
      const cond = this.checkCondition(node.condition);
      const then = this.checkExpr(node.whenTrue, expected);
      const els = this.checkExpr(node.whenFalse, expected);
      if (!cond || !then || !els) return undefined;
      // unify the branch types (literal retyping / widening to a common type).
      const unified = this.unifyOperands(then, els, node);
      if (!unified) {
        this.diags.error(node, 'JETH083', `ternary branches have incompatible types: ${displayName(then.type)} vs ${displayName(els.type)}`);
        return undefined;
      }
      // A ternary branch must lower to a single register value: a value type, or a MEMORY
      // array (whose register IS its pointer). A storage struct / storage array / bytes /
      // string branch has no single-word value, so select before the aggregate op.
      const lowerable = (e: Expr): boolean =>
        isStaticValueType(e.type) ||
        (e.type.kind === 'array' &&
          (e.kind === 'arrayLit' || (e.kind === 'arrayValue' && (e.arr.base.kind === 'memArray' || e.arr.base.kind === 'memArrayExpr'))));
      if (!lowerable(unified[0]) || !lowerable(unified[1])) {
        this.diags.error(node, 'JETH074', `a ternary over a ${displayName(unified[0].type)} (storage aggregate / bytes / string) is not supported; select the value before the aggregate operation`);
        return undefined;
      }
      return { kind: 'ternary', type: unified[0].type, cond, then: unified[0], else: unified[1] };
    }

    // A (possibly negated) integer literal folds to a single signed literal, so
    // the range check sees the real value: `-128n` is a valid i8 (== INT_MIN),
    // not "128 out of range". `-x` on a non-literal still uses checked negation.
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.MinusToken) {
      const folded = this.asIntLiteral(node);
      if (folded !== undefined) {
        const type = expected && isInteger(expected) ? expected : folded < 0n ? I256 : U256;
        if (!this.inRange(folded, type)) {
          this.diags.error(node, 'JETH070', `literal ${folded} out of range for ${displayName(type)}`);
        }
        return { kind: 'literalInt', type, value: folded };
      }
    }

    // BigInt literal -> integer
    if (ts.isBigIntLiteral(node)) {
      const raw = node.text.replace(/n$/, '');
      const value = BigInt(raw);
      const type = expected && isInteger(expected) ? expected : U256;
      if (!this.inRange(value, type)) {
        this.diags.error(node, 'JETH070', `literal ${value} out of range for ${displayName(type)}`);
      }
      return { kind: 'literalInt', type, value };
    }

    // numeric literal (no 'n') -> error: must use BigInt
    if (ts.isNumericLiteral(node)) {
      this.diags.error(node, 'JETH071', `use a BigInt literal (${node.text}n) - JETH integers are BigInt`);
      return undefined;
    }

    // boolean
    if (node.kind === ts.SyntaxKind.TrueKeyword) return { kind: 'literalBool', type: BOOL, value: true };
    if (node.kind === ts.SyntaxKind.FalseKeyword) return { kind: 'literalBool', type: BOOL, value: false };

    // string/bytes literal -> a memory dynamic value (only where bytes/string expected)
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      if (expected && isBytesLike(expected)) {
        return { kind: 'stringLiteral', type: expected, bytes: new TextEncoder().encode(node.text) };
      }
      this.diags.error(node, 'JETH074', 'a string literal is only valid where a string/bytes value is expected');
      return undefined;
    }

    // <array | bytes>.length -> u256
    if (
      ts.isPropertyAccessExpression(node) &&
      node.name.text === 'length' &&
      node.expression.kind !== ts.SyntaxKind.ThisKeyword
    ) {
      const bt = this.baseDynType(node.expression);
      // a fixed array's length is a compile-time constant (state or calldata param)
      if (bt && bt.kind === 'array' && bt.length !== undefined) {
        return { kind: 'literalInt', type: U256, value: BigInt(bt.length) };
      }
      // dynamic array length (state, calldata param, or mapping value this.m[k])
      const lenArr = this.resolveArrayExpr(node.expression);
      if (lenArr) {
        if (lenArr.base.kind === 'fixedArray') return { kind: 'literalInt', type: U256, value: BigInt(lenArr.base.length) };
        // storage-backed arrays (stateArray / mapArray) read state; calldata sources
        // (calldataArray / cdNestedElem) do not.
        if (lenArr.base.kind === 'stateArray' || lenArr.base.kind === 'mapArray') this.currentReadsState = true;
        return { kind: 'arrayLen', type: U256, arr: lenArr };
      }
      // .length of a fixed-array field/element of a calldata aggregate param: a
      // compile-time constant (e.g. s.data.length where data: Arr<T,N>).
      const cdType = this.calldataAccessType(node.expression);
      if (cdType && cdType.kind === 'array' && cdType.length !== undefined) {
        return { kind: 'literalInt', type: U256, value: BigInt(cdType.length) };
      }
      if (bt && bt.kind === 'array') return undefined; // array but unresolvable -> no diagnostic doubling
      const operand = this.checkExpr(node.expression);
      if (!operand) return undefined;
      if (operand.type.kind === 'string') {
        this.diags.error(node, 'JETH202', "'string' has no .length in Solidity; only 'bytes' does");
        return undefined;
      }
      if (operand.type.kind !== 'bytes') {
        this.diags.error(node, 'JETH202', `.length is not valid on ${displayName(operand.type)}`);
        return undefined;
      }
      return { kind: 'dynLength', type: U256, operand };
    }

    // array literal [a, b, c] -> memory T[] (only where an array type is expected)
    if (ts.isArrayLiteralExpression(node)) {
      if (!expected || expected.kind !== 'array') {
        this.diags.error(node, 'JETH213', 'cannot infer array-literal type here (expected an array type)');
        return undefined;
      }
      const elements: Expr[] = [];
      for (const el of node.elements) {
        const e = this.checkExpr(el, expected.element);
        if (!e) return undefined;
        elements.push(this.coerce(e, expected.element, el));
      }
      return { kind: 'arrayLit', type: expected, elem: expected.element, elements };
    }

    // G9: `p.x` read where p is a memory-aggregate (struct) local -> a memory field load.
    // Must precede the calldata/storage access resolvers below (a memory struct local is
    // neither a calldata param nor a `this.`-rooted place).
    if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression) && this.memAggregateLocals.has(node.expression.text)) {
      const mf = this.resolveMemAggregateField(node);
      if (!mf) return undefined;
      return { kind: 'memField', type: mf.type, local: mf.local, wordOffset: mf.wordOffset };
    }

    // nested storage access: this.s.f, this.pts[i].x, this.m[k].f, this.m[r][c]
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const acc = this.resolveAccess(node);
      if (acc) {
        if (!acc.result) return undefined; // committed but errored
        this.currentReadsState = true;
        // A bytes/string leaf (a storage dynamic-struct field) is a dynamic value,
        // not a packed-word read: emit dynPlaceRead so the storage bytes/string
        // codec materializes it (return / .length / [i]).
        if (isBytesLike(acc.result.finalType)) {
          return { kind: 'dynPlaceRead', type: acc.result.finalType, path: acc.result.path };
        }
        return { kind: 'placeRead', type: acc.result.finalType, path: acc.result.path };
      }
      // dynamic-struct calldata param: d.field (static leaf or bytes/string field)
      const dyn = this.resolveCdDynStruct(node);
      if (dyn) return dyn.result;
      // aggregate calldata param: s.field, a[i], a[i].field, s.sub[j] (read)
      const cd = this.resolveCalldataPlace(node);
      if (cd) {
        if (!cd.result) return undefined; // committed but errored
        return { kind: 'cdPlaceRead', type: cd.result.finalType, place: cd.result.place };
      }
      // dynamic-array-of-struct calldata param element field: ps[i].field
      if (
        ts.isPropertyAccessExpression(node) &&
        ts.isElementAccessExpression(node.expression)
      ) {
        const bt = this.baseDynType(node.expression.expression);
        if (bt && bt.kind === 'array' && bt.element.kind === 'struct') {
          // a DYNAMIC-struct array element field (D[] or Arr<D,N>): tuple via the
          // offset table. A STATIC-struct DYNAMIC array (Pt[], 4e-1): inline element.
          if (isDynamicType(bt.element)) return this.resolveCdDynArrayField(node, bt.element);
          if (bt.length === undefined) return this.resolveCdArrayField(node, bt.element);
          // Arr<staticStruct,N>: owned by resolveCalldataPlace (cdAggregates) above.
        }
      }
    }

    // this.struct.field (struct field read)
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.expression.kind === ts.SyntaxKind.ThisKeyword
    ) {
      const sv = this.stateByName.get(node.expression.name.text);
      if (sv && sv.type.kind === 'struct') {
        const f = sv.type.fields.find((ff) => ff.name === node.name.text);
        if (!f) {
          this.diags.error(node, 'JETH210', `struct '${sv.type.name}' has no field '${node.name.text}'`);
          return undefined;
        }
        // this.d.s read: a bytes/string field of a storage dynamic struct -> a
        // dynamic value at sv.slot + f.slot (re-encoded as a standalone top-level
        // value on return, or .length / [i]).
        if (isBytesLike(f.type)) {
          this.currentReadsState = true;
          return { kind: 'dynPlaceRead', type: f.type, path: { baseSlot: sv.slot, steps: [{ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type }] } };
        }
        // return this.o.inner: a whole nested-struct field, encoded from its slot by the
        // storage-source encoder (structValue reuses the whole-struct return machinery).
        if (f.type.kind === 'struct') {
          this.currentReadsState = true;
          return { kind: 'structValue', type: f.type, baseSlot: sv.slot + f.slot };
        }
        // return this.s.xs: a whole array field. A DYNAMIC array field is a placeArray
        // (length at the field slot); a FIXED array field is a static aggregate at the
        // field's constant slot. Both encoded from storage on return.
        if (f.type.kind === 'array') {
          this.currentReadsState = true;
          if (f.type.length === undefined) {
            return { kind: 'arrayValue', type: f.type, arr: { base: { kind: 'placeArray', path: { baseSlot: sv.slot, steps: [{ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type }] } }, elem: f.type.element } };
          }
          return { kind: 'arrayValue', type: f.type, arr: { base: { kind: 'fixedArray', baseSlot: sv.slot + f.slot, length: f.type.length }, elem: f.type.element } };
        }
        if (!isStaticValueType(f.type)) {
          this.diags.error(node, 'JETH226', 'nested array field access is not supported yet');
          return undefined;
        }
        this.currentReadsState = true;
        return { kind: 'stateRead', type: f.type, slot: sv.slot + f.slot, offset: f.offset, varName: `${sv.name}.${f.name}` };
      }
    }

    // this.stateVar (read)
    if (ts.isPropertyAccessExpression(node) && node.expression.kind === ts.SyntaxKind.ThisKeyword) {
      const v = this.stateByName.get(node.name.text);
      if (!v) {
        this.diags.error(node, 'JETH065', `unknown state variable 'this.${node.name.text}'`);
        return undefined;
      }
      if (v.type.kind === 'mapping') {
        this.diags.error(node, 'JETH153', `mapping 'this.${node.name.text}' cannot be read directly; index it (this.${node.name.text}[key])`);
        return undefined;
      }
      this.currentReadsState = true;
      if (isBytesLike(v.type)) return { kind: 'dynStateRead', type: v.type, slot: v.slot };
      if (v.type.kind === 'array') {
        if (v.type.length !== undefined) {
          // return this.fa (whole fixed array): encoded inline from storage by the
          // recursive encoder (static value / static-struct elements -> flat leaves).
          // A fixed array of a DYNAMIC element (Arr<string,N>/Arr<D,N>) is not a valid
          // state var (rejected at declaration), so this is always a static aggregate.
          return { kind: 'arrayValue', type: v.type, arr: { base: { kind: 'fixedArray', baseSlot: v.slot, length: v.type.length }, elem: v.type.element } };
        }
        // a storage array of value / static-struct / DYNAMIC-struct (D[]) / bytes/string
        // (string[]) / nested dynamic-array (u256[][], string[][]) element: encoded by the
        // storage-source recursive encoder on return (unbounded nesting).
        return { kind: 'arrayValue', type: v.type, arr: { base: { kind: 'stateArray', slot: v.slot }, elem: v.type.element } };
      }
      if (v.type.kind === 'struct') {
        // a whole struct read from storage (return this.d): a static struct flattens
        // to inline words; a DYNAMIC struct (with a bytes/string/array field) is
        // head/tail encoded by the storage-source recursive encoder on return.
        return { kind: 'structValue', type: v.type, baseSlot: v.slot };
      }
      return { kind: 'stateRead', type: v.type, slot: v.slot, offset: v.offset, varName: v.name };
    }

    // msg.* / block.* / tx.* globals (PropertyAccess on a reserved identifier not
    // shadowed by a local/param/state var; shadowing wins, matching Solidity).
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      GLOBALS[node.expression.text] !== undefined &&
      !this.isVisibleLocal(node.expression.text) &&
      !this.stateByName.has(node.expression.text)
    ) {
      return this.checkGlobal(node);
    }

    // indexing: array a[i] -> elem, bytes b[i] -> bytes1, or mapping this.m[k]
    if (ts.isElementAccessExpression(node)) {
      // A read m[i]...[k] on a nested dynamic array calldata param (T[][], T[][][],
      // string[][], ...): the inner array m[i]...[k-1] is resolved via cdNestedElem
      // (descending the per-level inner-offset tables); the final index then reads
      // either a static VALUE element (arrayGet) or a string/bytes element
      // (cdDynArrayElem). The inner offset tables / bounds are applied at codegen
      // (Panic 0x32 on any dim OOB). Only commit when the base resolves to a
      // cdNestedElem array (a genuine nested-dynamic-array navigation).
      if (
        ts.isElementAccessExpression(node.expression) &&
        node.argumentExpression &&
        this.nestedDynArrayRoot(node.expression)
      ) {
        const innerArr = this.resolveArrayExpr(node.expression);
        if (innerArr && innerArr.base.kind === 'cdNestedElem') {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          const idx = this.coerce(index, U256, node.argumentExpression);
          if (isBytesLike(innerArr.elem)) {
            return { kind: 'cdDynArrayElem', type: innerArr.elem, arr: innerArr, index: idx };
          }
          if (isStaticValueType(innerArr.elem)) {
            return { kind: 'arrayGet', type: innerArr.elem, arr: innerArr, index: idx };
          }
          // a still-deeper element (the value at m[i][j] is itself a dynamic array,
          // e.g. m[i][j] of a T[][][]) is itself an ArrayExpr; the [k] index that
          // would read INTO it is handled by resolveArrayExpr on the outer node, so
          // this point is only reached when the element is neither value nor bytes-
          // like nor a dynamic array. Such shapes are gated by the type tree.
          return undefined;
        }
      }
      // this.m[k][i] read where this.m[k] is a mapping-valued string[]/bytes[]: the
      // base is not a direct `this.x`, so resolve it via resolveArrayExpr and read
      // the element header at keccak(lenSlot)+i (strArrayElem). Other mapping-valued
      // arrays (value elements) keep their existing arrayGet path via resolveMapAccess.
      if (ts.isElementAccessExpression(node.expression) && node.argumentExpression) {
        const mapArr = this.resolveArrayExpr(node.expression);
        if (mapArr && (mapArr.base.kind === 'mapArray' || mapArr.base.kind === 'placeArray') && isBytesLike(mapArr.elem)) {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          this.currentReadsState = true;
          return { kind: 'strArrayElem', type: mapArr.elem, arr: mapArr, index: this.coerce(index, U256, node.argumentExpression) };
        }
      }
      // this.m[k][i] where m: mapping<K, bytes>: byte-index the dynamic mapping value
      // (this.m[k] is a bytes value -> mapDynValue). `string` is not indexable. Only
      // probe when node.expression genuinely roots at `this.<state mapping>`, so the
      // resolveMapAccess probe never fires a spurious diagnostic on a local-array index.
      if (ts.isElementAccessExpression(node.expression) && node.argumentExpression) {
        let probe: ts.Expression = node.expression;
        while (ts.isElementAccessExpression(probe)) probe = probe.expression;
        const rootsAtStateMapping =
          ts.isPropertyAccessExpression(probe) &&
          probe.expression.kind === ts.SyntaxKind.ThisKeyword &&
          this.stateByName.get(probe.name.text)?.type.kind === 'mapping';
        if (rootsAtStateMapping) {
          const r = this.resolveMapAccess(node.expression);
          if (!r) return undefined;
          if (isBytesLike(r.valueType)) {
            if (r.valueType.kind === 'string') {
              this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
              return undefined;
            }
            const base = this.checkExpr(node.expression);
            const index = this.checkExpr(node.argumentExpression, U256);
            if (!base || !index) return undefined;
            return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
          }
        }
      }
      // (c ? xs : ys)[i]: index a memory array produced by an expression (a ternary).
      // The base is not a named local so baseDynType is undefined; resolve via the
      // memArrayExpr path and read the value element.
      if (node.argumentExpression) {
        const ma = this.resolveArrayExpr(node.expression);
        if (ma && ma.base.kind === 'memArrayExpr' && isStaticValueType(ma.elem)) {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          return { kind: 'arrayGet', type: ma.elem, arr: ma, index: this.coerce(index, U256, node.argumentExpression) };
        }
      }
      // A WHOLE inner dynamic array reached by a multi-step chain used as a value
      // (return this.m[k][i] / this.ddd[i][j] / this.dd[i]): resolveArrayExpr folds it to
      // a placeArray; encode it from storage on return (the element/length/push paths use
      // the same placeArray). Only a node that is itself a dynamic array matches.
      {
        const whole = this.resolveArrayExpr(node);
        if (whole && whole.base.kind === 'placeArray') {
          this.currentReadsState = true;
          return { kind: 'arrayValue', type: { kind: 'array', element: whole.elem }, arr: whole };
        }
      }
      // A whole struct element of a mapping-valued struct array (this.md[k][i]): the
      // base this.md[k] is not a direct this.x so baseDynType is undefined; resolve it
      // via resolveArrayExpr (mapArray). Direct state/fixed struct arrays are handled in
      // the baseDynType block below. Bounds-checked at codegen (Panic 0x32).
      if (node.argumentExpression && ts.isElementAccessExpression(node.expression)) {
        const sa = this.resolveArrayExpr(node.expression);
        if (sa && sa.elem.kind === 'struct' && (sa.base.kind === 'mapArray' || sa.base.kind === 'placeArray')) {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          this.currentReadsState = true;
          return { kind: 'structArrayElem', type: sa.elem, arr: sa, index: this.coerce(index, U256, node.argumentExpression) };
        }
      }
      const bt = this.baseDynType(node.expression);
      if (bt && bt.kind === 'array') {
        const arr = this.resolveArrayExpr(node.expression);
        if (!arr || !node.argumentExpression) return undefined;
        // string[] / bytes[] element a[i] yields the i-th dynamic element (a string/
        // bytes value). A calldata param re-encodes it as a standalone top-level
        // value on return (cdDynArrayElem); a storage / mapping-valued one reads the
        // element header at keccak(lenSlot)+i, a normal storage bytes/string
        // (strArrayElem). Both bounds-check i (Panic 0x32).
        if (isBytesLike(arr.elem)) {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          const idx = this.coerce(index, U256, node.argumentExpression);
          if (arr.base.kind === 'calldataArray') {
            return { kind: 'cdDynArrayElem', type: arr.elem, arr, index: idx };
          }
          if (arr.base.kind === 'stateArray' || arr.base.kind === 'mapArray' || arr.base.kind === 'fixedArray') {
            this.currentReadsState = true;
            return { kind: 'strArrayElem', type: arr.elem, arr, index: idx };
          }
          this.diags.error(node, 'JETH217', 'this string[]/bytes[] element form is not supported yet');
          return undefined;
        }
        if (arr.elem.kind === 'struct') {
          // A whole storage/fixed/mapping struct element (return this.recs[i]) is encoded
          // from the element slot by the storage-source encoder; calldata struct elements
          // (echo) stay gated. Bounds-checked (Panic 0x32 / const OOB compile error).
          if (arr.base.kind === 'stateArray' || arr.base.kind === 'fixedArray' || arr.base.kind === 'mapArray') {
            const index = this.checkExpr(node.argumentExpression, U256);
            if (!index) return undefined;
            const idx = this.coerce(index, U256, node.argumentExpression);
            if (!this.checkFixedBound(arr, idx, node.argumentExpression)) return undefined;
            this.currentReadsState = true;
            return { kind: 'structArrayElem', type: arr.elem, arr, index: idx };
          }
          this.diags.error(node, 'JETH230', 'reading a whole struct element of a calldata array is not supported yet (access a value field)');
          return undefined;
        }
        if (arr.elem.kind === 'array') {
          // return this.dd[i] (a whole inner array of a storage nested array): the inner
          // array is a placeArray; encode it from storage on return (unbounded nesting).
          const inner = this.resolveArrayExpr(node);
          if (inner && inner.base.kind === 'placeArray') {
            this.currentReadsState = true;
            return { kind: 'arrayValue', type: arr.elem, arr: inner };
          }
          // a whole FIXED inner-array row of a 2D fixed/storage array (return this.g[i]):
          // a static aggregate at the element slot; encoded inline by the storage encoder
          // (structArrayElem computes the slot and routes through returnStorageValue).
          if (arr.elem.length !== undefined && (arr.base.kind === 'stateArray' || arr.base.kind === 'fixedArray' || arr.base.kind === 'mapArray')) {
            const index = this.checkExpr(node.argumentExpression, U256);
            if (!index) return undefined;
            const idx = this.coerce(index, U256, node.argumentExpression);
            if (!this.checkFixedBound(arr, idx, node.argumentExpression)) return undefined;
            this.currentReadsState = true;
            return { kind: 'structArrayElem', type: arr.elem, arr, index: idx };
          }
          this.diags.error(node, 'JETH230', 'reading a whole array-of-array element is a later step (access a value field)');
          return undefined;
        }
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!index) return undefined;
        const idx = this.coerce(index, U256, node.argumentExpression);
        if (!this.checkFixedBound(arr, idx, node.argumentExpression)) return undefined;
        if (arr.base.kind !== 'calldataArray' && arr.base.kind !== 'memArray' && arr.base.kind !== 'memArrayExpr') this.currentReadsState = true;
        return { kind: 'arrayGet', type: arr.elem, arr, index: idx };
      }
      if (bt && isBytesLike(bt)) {
        if (bt.kind === 'string') {
          this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
          return undefined;
        }
        if (!node.argumentExpression) {
          this.diags.error(node, 'JETH150', 'index expression required');
          return undefined;
        }
        const base = this.checkExpr(node.expression);
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!base || !index) return undefined;
        return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
      }
      // this.<chain>.b[j] where the base is a bytes field of a STORAGE dynamic
      // struct (this.e.b[j], this.recs[i].b[j], this.o.inner.b[j]): the base resolves
      // (via the struct-field / resolveAccess read paths) to a bytes value
      // (dynPlaceRead). Byte-index it (Panic 0x32). Only commit when the base is a
      // property/element access that reads a storage dynamic-struct bytes field.
      if (
        (ts.isPropertyAccessExpression(node.expression) || ts.isElementAccessExpression(node.expression)) &&
        node.argumentExpression &&
        this.isStorageDynStructBytesField(node.expression)
      ) {
        const base = this.checkExpr(node.expression);
        if (!base) return undefined;
        if (base.type.kind === 'string') {
          this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
          return undefined;
        }
        if (base.type.kind !== 'bytes') {
          this.diags.error(node, 'JETH212', `cannot index ${displayName(base.type)}`);
          return undefined;
        }
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!index) return undefined;
        return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
      }
      // d.s[i] where d.s is a bytes field of a dynamic-struct param: byte index.
      if (ts.isPropertyAccessExpression(node.expression)) {
        const dyn = this.resolveCdDynStruct(node.expression);
        if (dyn) {
          if (!dyn.result) return undefined; // committed but errored
          const base = dyn.result;
          if (base.type.kind === 'string') {
            this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
            return undefined;
          }
          if (base.type.kind !== 'bytes' || !node.argumentExpression) {
            this.diags.error(node, 'JETH212', `cannot index ${displayName(base.type)}`);
            return undefined;
          }
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
        }
      }
      // this.bb[i][j]: byte-index j into a storage/mapping bytes[] element bb[i].
      // The inner access bb[i] resolves to a strArrayElem (a bytes value); index it.
      if (ts.isElementAccessExpression(node.expression) && node.argumentExpression) {
        const innerArr = this.resolveArrayExpr(node.expression.expression);
        if (
          innerArr &&
          isBytesLike(innerArr.elem) &&
          (innerArr.base.kind === 'stateArray' || innerArr.base.kind === 'mapArray')
        ) {
          if (innerArr.elem.kind === 'string') {
            this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
            return undefined;
          }
          const base = this.checkExpr(node.expression); // -> strArrayElem (bytes)
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!base || !index) return undefined;
          return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
        }
      }
      const r = this.resolveMapAccess(node);
      if (!r) return undefined;
      if (r.valueType.kind === 'mapping') {
        this.diags.error(node, 'JETH153', 'a mapping value cannot be read directly; index it fully');
        return undefined;
      }
      // A whole struct/array mapping value (`return this.m[k]`) is encoded from the
      // mapping slot by the storage-source recursive encoder (mapGet loads one word,
      // so it only fits value types). Reading fields/elements (this.m[k].field,
      // this.m[k][i]) is handled separately.
      if (r.valueType.kind === 'struct' || r.valueType.kind === 'array') {
        this.currentReadsState = true;
        return { kind: 'mapStorageValue', type: r.valueType, baseSlot: r.baseSlot, keys: r.keys, keyTypes: r.keyTypes };
      }
      // A bytes/string mapping value is a dynamic value living at the mapping slot
      // (short inline / long at keccak(slot)); it flows through the dynamic-value
      // machinery (encode-to-memory for return, .length, byte-index, overwrite-store).
      if (isBytesLike(r.valueType)) {
        this.currentReadsState = true;
        return { kind: 'mapDynValue', type: r.valueType, baseSlot: r.baseSlot, keys: r.keys, keyTypes: r.keyTypes };
      }
      this.currentReadsState = true;
      return { kind: 'mapGet', type: r.valueType, baseSlot: r.baseSlot, keys: r.keys, keyTypes: r.keyTypes };
    }

    // address(this) / address(0n) / payable(x) / uint160(x) / bytes20(x) casts
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      !this.isVisibleLocal(node.expression.text) &&
      !this.stateByName.has(node.expression.text)
    ) {
      const callee = node.expression.text;
      if (callee === 'address') return this.checkAddressCall(node);
      if (callee === 'payable' || resolvePrimitiveName(callee)) return this.checkCast(node, callee);
      const st = this.structsByName.get(callee);
      if (st && st.kind === 'struct') return this.checkStructConstruct(node, st);
      // an internal/private/public contract function called by name -> internal call.
      if (this.funcsByName.has(callee)) return this.checkInternalCall(node, callee, false);
    }

    // `this.method(args)` (TS-idiomatic internal call) -> internal-call semantics.
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.expression.kind === ts.SyntaxKind.ThisKeyword &&
      this.funcsByName.has(node.expression.name.text)
    ) {
      return this.checkInternalCall(node, node.expression.name.text, false);
    }

    // object literal { x: 1n, y: 2n } -> error pointing at positional construction
    if (ts.isObjectLiteralExpression(node)) {
      this.diags.error(node, 'JETH227', 'use positional struct construction StructName(...), not an object literal');
      return undefined;
    }

    // local / param read
    if (ts.isIdentifier(node)) {
      const t = this.lookupLocal(node.text);
      if (!t) {
        this.diags.error(node, 'JETH072', `unknown identifier '${node.text}'`);
        return undefined;
      }
      if (isBytesLike(t)) return { kind: 'dynParamRead', type: t, name: node.text };
      // a whole MEMORY-aggregate (struct) local (return p / let q = p / arg p): the register
      // holds a pointer to the ABI-unpacked image. G9.
      if (this.memAggregateLocals.has(node.text)) {
        return { kind: 'memAggregate', type: t, local: node.text };
      }
      // a MEMORY array local (return xs): the register holds a pointer to [len][elems];
      // ABI-encoded from memory on return.
      if (t.kind === 'array' && this.memArrayLocals.has(node.text)) {
        return { kind: 'arrayValue', type: t, arr: { base: { kind: 'memArray', varName: node.text }, elem: t.element } };
      }
      // a whole dynamic-array param echo, OR a fixed array of a DYNAMIC element
      // (Arr<dyn,N>) echo: re-encoded head/tail via the recursive codec.
      if (t.kind === 'array' && (t.length === undefined || isDynamicType(t.element))) {
        return { kind: 'arrayValue', type: t, arr: { base: { kind: 'calldataArray', name: node.text }, elem: t.element } };
      }
      // a whole DYNAMIC-struct param echo (return d): re-encoded head/tail (4e-6).
      if (t.kind === 'struct' && isDynamicType(t)) {
        return { kind: 'cdDynStructValue', type: t, param: node.text };
      }
      // a whole STATIC struct / fixed-array param echo (return a): re-encoded inline via
      // the recursive calldata codec (the dynamic shapes were handled above).
      if ((t.kind === 'array' || t.kind === 'struct') && isStaticType(t)) {
        return { kind: 'cdAggregateValue', type: t, param: node.text };
      }
      if (t.kind === 'array' || t.kind === 'struct') {
        this.diags.error(node, 'JETH230', `passing or returning a whole ${displayName(t)} calldata parameter is not supported yet (access its fields/elements)`);
        return undefined;
      }
      return { kind: 'localRead', type: t, name: node.text };
    }

    // x++ / x-- / ++x / --x in VALUE position (let p = x++, a[x++], f(x++)): postfix
    // yields the old value, prefix the new. (The statement form is desugared earlier.)
    if (ts.isPostfixUnaryExpression(node)) {
      return this.checkIncDecExpr(node.operand, node.operator === ts.SyntaxKind.PlusPlusToken, false, node);
    }
    if (ts.isPrefixUnaryExpression(node) && (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken)) {
      return this.checkIncDecExpr(node.operand, node.operator === ts.SyntaxKind.PlusPlusToken, true, node);
    }

    // unary
    if (ts.isPrefixUnaryExpression(node)) {
      return this.checkUnary(node, expected);
    }

    // binary
    if (ts.isBinaryExpression(node)) {
      const op = this.binaryToBinOp(node.operatorToken.kind);
      if (!op) {
        this.diags.error(node.operatorToken, 'JETH073', `unsupported binary operator`);
        return undefined;
      }
      const left = this.checkExpr(node.left, expected);
      if (!left) return undefined;
      // the exponent of `**` is an independent (unsigned) value, not unified with the base.
      const rightExpected = op === '**' ? undefined : this.isComparison(op) ? (isInteger(left.type) ? left.type : undefined) : expected ?? left.type;
      const right = this.checkExpr(node.right, rightExpected);
      if (!right) return undefined;
      return this.buildBinary(op, left, right, node);
    }

    this.diags.error(node, 'JETH074', `unsupported expression: ${ts.SyntaxKind[node.kind]}`);
    return undefined;
  }

  private checkUnary(node: ts.PrefixUnaryExpression, expected?: JethType): Expr | undefined {
    const operand = this.checkExpr(node.operand, expected);
    if (!operand) return undefined;
    switch (node.operator) {
      case ts.SyntaxKind.MinusToken:
        if (operand.type.kind !== 'int') {
          this.diags.error(node, 'JETH075', `unary '-' requires a signed integer, got ${displayName(operand.type)}`);
          return undefined;
        }
        return { kind: 'unary', type: operand.type, op: '-', operand, unchecked: this.currentUnchecked };
      case ts.SyntaxKind.ExclamationToken:
        if (operand.type.kind !== 'bool') {
          this.diags.error(node, 'JETH076', `unary '!' requires bool, got ${displayName(operand.type)}`);
          return undefined;
        }
        return { kind: 'unary', type: BOOL, op: '!', operand, unchecked: false };
      case ts.SyntaxKind.TildeToken:
        if (!isInteger(operand.type)) {
          this.diags.error(node, 'JETH077', `unary '~' requires an integer`);
          return undefined;
        }
        return { kind: 'unary', type: operand.type, op: '~', operand, unchecked: false };
      default:
        this.diags.error(node, 'JETH078', `unsupported unary operator`);
        return undefined;
    }
  }

  private buildBinary(op: BinOp, left: Expr, right: Expr, node: ts.Node): Expr | undefined {
    // Logical &&/|| -> bool
    if (op === '&&' || op === '||') {
      if (left.type.kind !== 'bool' || right.type.kind !== 'bool') {
        this.diags.error(node, 'JETH080', `'${op}' requires bool operands`);
        return undefined;
      }
      return { kind: 'binary', type: BOOL, op, left, right, unchecked: false };
    }

    // Comparisons -> bool
    if (this.isComparison(op)) {
      const unified = this.unifyOperands(left, right, node);
      if (!unified) return undefined;
      return { kind: 'binary', type: BOOL, op, left: unified[0], right: unified[1], unchecked: false };
    }

    // Shifts: amount may be any unsigned int; result type follows the left operand.
    if (op === '<<' || op === '>>') {
      if (!isInteger(left.type)) {
        this.diags.error(node, 'JETH081', `shift requires an integer left operand`);
        return undefined;
      }
      return { kind: 'binary', type: left.type, op, left, right, unchecked: this.currentUnchecked };
    }

    // Exponentiation: result type follows the base (left); the exponent is a separate
    // non-negative integer (not unified with the base). Checked (Panic 0x11 on overflow).
    if (op === '**') {
      if (!isInteger(left.type)) {
        this.diags.error(node, 'JETH082', `'**' requires an integer base, got ${displayName(left.type)}`);
        return undefined;
      }
      if (!isInteger(right.type)) {
        this.diags.error(node, 'JETH082', `'**' requires an integer exponent, got ${displayName(right.type)}`);
        return undefined;
      }
      return { kind: 'binary', type: left.type, op, left, right, unchecked: this.currentUnchecked };
    }

    // Arithmetic / bitwise: operands must match an integer type.
    const unified = this.unifyOperands(left, right, node);
    if (!unified) return undefined;
    if (!isInteger(unified[0].type)) {
      this.diags.error(node, 'JETH082', `operator '${op}' requires integer operands, got ${displayName(unified[0].type)}`);
      return undefined;
    }
    return { kind: 'binary', type: unified[0].type, op, left: unified[0], right: unified[1], unchecked: this.currentUnchecked };
  }

  /** Make two operands share a type, retyping a literal toward the other side. */
  private unifyOperands(left: Expr, right: Expr, node: ts.Node): [Expr, Expr] | undefined {
    if (typesEqual(left.type, right.type)) return [left, right];
    // address and address payable share the same EVM word; compare freely.
    if (left.type.kind === 'address' && right.type.kind === 'address') return [left, right];
    const lLit = left.kind === 'literalInt';
    const rLit = right.kind === 'literalInt';
    if (rLit && !lLit) {
      const r = this.retypeLiteral(right, left.type, node);
      return r ? [left, r] : undefined;
    }
    if (lLit && !rLit) {
      const l = this.retypeLiteral(left, right.type, node);
      return l ? [l, right] : undefined;
    }
    // mixed-width same-signedness operands (u8 + u256, i16 < i256, bytes4 == bytes32):
    // widen the narrower to the wider common type (Solidity-identical), no runtime op.
    const common = commonNumericType(left.type, right.type);
    if (common) {
      const l = isImplicitWiden(left.type, common) ? ({ kind: 'cast', type: common, from: left.type, operand: left } as Expr) : left;
      const r = isImplicitWiden(right.type, common) ? ({ kind: 'cast', type: common, from: right.type, operand: right } as Expr) : right;
      return [l, r];
    }
    this.diags.error(
      node,
      'JETH083',
      `type mismatch: ${displayName(left.type)} vs ${displayName(right.type)} (no implicit conversion)`,
    );
    return undefined;
  }

  private retypeLiteral(lit: Expr, target: JethType, node: ts.Node): Expr | undefined {
    if (lit.kind !== 'literalInt') return undefined;
    if (!isInteger(target)) {
      this.diags.error(node, 'JETH084', `cannot use integer literal as ${displayName(target)}`);
      return undefined;
    }
    if (!this.inRange(lit.value, target)) {
      this.diags.error(node, 'JETH070', `literal ${lit.value} out of range for ${displayName(target)}`);
      return undefined;
    }
    return { ...lit, type: target };
  }

  /** Coerce an expression to a target type (literal retyping or exact match). */
  private coerce(expr: Expr, target: JethType, node: ts.Node): Expr {
    if (typesEqual(expr.type, target)) return expr;
    if (expr.kind === 'literalInt') {
      const r = this.retypeLiteral(expr, target, node);
      if (r) return r;
      return expr;
    }
    // address payable -> address is implicit (same word); the reverse needs payable().
    if (expr.type.kind === 'address' && target.kind === 'address') {
      if (expr.type.payable || !target.payable) return expr;
      this.diags.error(node, 'JETH172', 'cannot implicitly convert address to address payable (use payable(...))');
      return expr;
    }
    // Implicit WIDENING (Solidity-identical): uintN->uintM, intN->intM (M>=N), bytesN->
    // bytesM (M>=N). Same signedness only; uint<->int / narrowing need an explicit cast.
    if (isImplicitWiden(expr.type, target)) {
      return { kind: 'cast', type: target, from: expr.type, operand: expr };
    }
    this.diags.error(
      node,
      'JETH085',
      `cannot assign ${displayName(expr.type)} to ${displayName(target)} (no implicit conversion; widening must keep the same signedness, narrowing needs an explicit cast)`,
    );
    return expr;
  }

  // ---- constant folding (state initializers) -------------------------------

  private foldConstant(node: ts.Expression, expected: JethType): bigint | boolean | undefined {
    if (ts.isParenthesizedExpression(node)) return this.foldConstant(node.expression, expected);
    // (possibly negated) integer literal
    const lit = this.asIntLiteral(node);
    if (lit !== undefined) {
      if (!isInteger(expected)) {
        this.diags.error(node, 'JETH086', `cannot assign an integer literal to ${displayName(expected)}`);
        return undefined;
      }
      if (!this.inRange(lit, expected)) {
        this.diags.error(node, 'JETH070', `literal ${lit} out of range for ${displayName(expected)}`);
      }
      return lit;
    }
    if (node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword) {
      if (expected.kind !== 'bool') {
        this.diags.error(node, 'JETH087', `cannot assign a bool literal to ${displayName(expected)}`);
        return undefined;
      }
      return node.kind === ts.SyntaxKind.TrueKeyword;
    }
    return undefined;
  }

  /** If `node` is an integer literal, optionally wrapped in unary minus and/or
   *  parentheses, return its signed value; otherwise undefined. */
  private asIntLiteral(node: ts.Expression): bigint | undefined {
    if (ts.isParenthesizedExpression(node)) return this.asIntLiteral(node.expression);
    if (ts.isBigIntLiteral(node)) return BigInt(node.text.replace(/n$/, ''));
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.MinusToken) {
      const inner = this.asIntLiteral(node.operand);
      return inner === undefined ? undefined : -inner;
    }
    return undefined;
  }

  // ---- helpers -------------------------------------------------------------

  private inRange(value: bigint, type: JethType): boolean {
    if (!isInteger(type)) return type.kind === 'bool';
    const { min, max } = intRange(type);
    return value >= min && value <= max;
  }

  private isComparison(op: BinOp): boolean {
    return op === '<' || op === '>' || op === '<=' || op === '>=' || op === '==' || op === '!=';
  }

  private isAssignmentOperator(kind: ts.SyntaxKind): boolean {
    return (
      kind === ts.SyntaxKind.EqualsToken || this.compoundToBinOp(kind) !== undefined
    );
  }

  private compoundToBinOp(kind: ts.SyntaxKind): BinOp | undefined {
    switch (kind) {
      case ts.SyntaxKind.PlusEqualsToken: return '+';
      case ts.SyntaxKind.MinusEqualsToken: return '-';
      case ts.SyntaxKind.AsteriskEqualsToken: return '*';
      case ts.SyntaxKind.SlashEqualsToken: return '/';
      case ts.SyntaxKind.PercentEqualsToken: return '%';
      case ts.SyntaxKind.AmpersandEqualsToken: return '&';
      case ts.SyntaxKind.BarEqualsToken: return '|';
      case ts.SyntaxKind.CaretEqualsToken: return '^';
      case ts.SyntaxKind.LessThanLessThanEqualsToken: return '<<';
      case ts.SyntaxKind.GreaterThanGreaterThanEqualsToken: return '>>';
      default: return undefined;
    }
  }

  private binaryToBinOp(kind: ts.SyntaxKind): BinOp | undefined {
    switch (kind) {
      case ts.SyntaxKind.PlusToken: return '+';
      case ts.SyntaxKind.MinusToken: return '-';
      case ts.SyntaxKind.AsteriskToken: return '*';
      case ts.SyntaxKind.AsteriskAsteriskToken: return '**';
      case ts.SyntaxKind.SlashToken: return '/';
      case ts.SyntaxKind.PercentToken: return '%';
      case ts.SyntaxKind.LessThanToken: return '<';
      case ts.SyntaxKind.GreaterThanToken: return '>';
      case ts.SyntaxKind.LessThanEqualsToken: return '<=';
      case ts.SyntaxKind.GreaterThanEqualsToken: return '>=';
      case ts.SyntaxKind.EqualsEqualsToken:
      case ts.SyntaxKind.EqualsEqualsEqualsToken: return '==';
      case ts.SyntaxKind.ExclamationEqualsToken:
      case ts.SyntaxKind.ExclamationEqualsEqualsToken: return '!=';
      case ts.SyntaxKind.AmpersandToken: return '&';
      case ts.SyntaxKind.BarToken: return '|';
      case ts.SyntaxKind.CaretToken: return '^';
      case ts.SyntaxKind.LessThanLessThanToken: return '<<';
      case ts.SyntaxKind.GreaterThanGreaterThanToken: return '>>';
      case ts.SyntaxKind.AmpersandAmpersandToken: return '&&';
      case ts.SyntaxKind.BarBarToken: return '||';
      default: return undefined;
    }
  }
}

export function analyze(sourceFile: ts.SourceFile, diags: DiagnosticBag): ContractIR | undefined {
  return new Analyzer(sourceFile, diags).analyze();
}
