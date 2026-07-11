#!/usr/bin/env node
// Legacy-decorator -> native-syntax codemod for JETH TEST FILES (migration stage 1, P0c).
//
// Usage:  npx tsx scripts/migrate/codemod.mjs [--dry] [--no-trial] <test-file...>
//
// For each test file it finds embedded JETH sources (template/string literals containing a banned
// decorator), parses each source with the TypeScript parser, computes text spans, and applies the
// ban-list transforms BACK-TO-FRONT on the raw literal text (comments and string contents inside
// the JETH source are never touched - every edit span is a decorator / keyword / type node span).
//
// THE BAN LIST (legacy -> native):
//   @contract            -> deleted (a bare leaf class is the contract)
//   @abstract            -> the `abstract` class keyword
//   @struct class P {..} -> type P = {..};
//   @interface class I   -> TS `interface I` with View<T>/Pure<T>/Payable<T> return markers
//   @library class L     -> static class L; @external lib fns -> External<T> return marker
//   @external method     -> External<T> return marker; read-only value-returning -> `get f(): External<T>`
//   @external field      -> Visible<T> field-type marker (P0b), incl. static const/immutable forms
//   @view/@pure/@read    -> dropped (mutability is inferred); on external value-returning -> `get`
//   @payable             -> Payable<T> return marker (kept on constructors: no native ctor spelling)
//   @state               -> bare field
//   @constant            -> static field WITH initializer
//   @immutable           -> static field WITHOUT initializer
//   @event/@error member -> Name: event<{..}> / Name: error<{..}> field markers (@indexed -> indexed<T>)
//   @receive/@fallback   -> methods NAMED receive/fallback (payable fallback -> Payable<T>)
// KEPT UNCHANGED: @virtual, @override(+list), @modifier, modifier applications (@mark(7n)),
//   @nonReentrant, @using, @storage, @anonymous. `// use @decorators` sources are SKIPPED (stage 2).
//   @diamond sources are routed to the manual bucket (the diamond pre-parse expansion rewrites the
//   class textually; a mechanical member rewrite could break its assumptions).
//
// LITERAL FORMS: plain template/string literals are transformed on the cooked text and every edit
// span is mapped back onto the raw text (escapes elsewhere in the literal stay byte-identical).
// INTERPOLATED templates AND string CONCATENATION chains (`CONST + \`...\``) are COMPOSITES: a
// `${IDENT}` hole / non-literal `+` operand is resolved LEXICALLY (nearest enclosing scope) and,
// when the resolved declaration is a const with a plain-literal initializer, the hole RESOLVES to
// that literal; any other hole becomes an inert `__JMIGk__` placeholder. A composite whose
// assembly carries the `// use @decorators` pragma is stage-2-skipped AND PINS every const it
// consumes to the legacy spelling (reverting the const's pass-1 migration; the fixpoint restarts).
// Literal `+` operands are chunks (edited in place, excluded from standalone pass-1), and a nested
// interpolated-template operand contributes its own chunks and holes. The transform runs over the
// assembled original instantiation; edits inside resolved holes are dropped (the const's own
// migration realizes them at its declaration site) and the trial compiles the EXACT post assembly
// the migrated file will produce (edited chunks + migrated const texts + placeholders), with the
// same JETH352 get-retry. A hole in decorator-name position (`@${dec}`), an edit crossing a hole,
// or a trial mismatch routes the composite to manual; placeholder-carrying trials are a strong but
// not perfect check - the capture-diff stays the final arbiter. (The chain support exists because a
// fragment-blind standalone trial of a concatenated chunk can PASS on equal reject codes while the
// full assembly FLIPS - the batch-2 G5 accept->reject flip; assembly-level trials close that hole.)
//
// SELF-CHECK (trial compile): every rewritten source that is a self-contained unit is compiled
// before and after; accepting sources must be BYTECODE-EQUAL, rejecting sources CODE-LIST-EQUAL.
// The one statically-undecidable case - a bodied `@external f(): T` whose read-only-ness only the
// analyzer's effects fixpoint knows (JETH352: read-only external is spelled `get`) - is resolved by
// a targeted retry: the offending method names are parsed from the JETH352 diagnostics and re-emitted
// in `get` form. Any source that still cannot be made outcome-identical is left UNCHANGED and routed
// to the manual bucket (never guess). The capture-diff (scripts/migrate/verify.mjs over
// JETH_MIGRATE_CAPTURE runs) is the independent, test-flow-level proof on top of this.
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import url from 'node:url';

const BANNED = /@(contract|abstract|struct|interface|library|external|view|pure|read|payable|state|constant|immutable|event|error|indexed|receive|fallback)\b/;
const DEC_PRAGMA = /^[ \t]*\/\/ use @decorators[ \t]*$/m;

// ------------------------------------------------------------------ CLI ------
const args = process.argv.slice(2);
const dry = args.includes('--dry');
const noTrial = args.includes('--no-trial');
const files = args.filter((a) => !a.startsWith('--'));
if (files.length === 0) {
  console.error('usage: npx tsx scripts/migrate/codemod.mjs [--dry] [--no-trial] <test-file...>');
  process.exit(2);
}

// trial compiles must never pollute a capture run, and the solc cache makes them cheap.
delete process.env.JETH_MIGRATE_CAPTURE;
process.env.JETH_COMPILE_CACHE ??= '1';

let compileFn = null;
let CompileErrorCls = null;
if (!noTrial) {
  try {
    const mod = await import(new URL('../../src/compile.ts', import.meta.url).href);
    const diag = await import(new URL('../../src/diagnostics.ts', import.meta.url).href);
    compileFn = mod.compile;
    CompileErrorCls = diag.CompileError;
  } catch (e) {
    console.error(`WARN trial-compile unavailable (run via \`npx tsx\`): ${e?.message ?? e}`);
  }
}

// ------------------------------------------------------- transform machinery ------
const KEEP_DECS = new Set(['virtual', 'override', 'modifier', 'nonReentrant', 'using', 'storage', 'anonymous']);

function decName(d) {
  const e = d.expression;
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isCallExpression(e) && ts.isIdentifier(e.expression)) return e.expression.text;
  return '';
}
function decsOf(node) {
  return ts.canHaveDecorators(node) ? (ts.getDecorators(node) ?? []) : [];
}
function decSet(node) {
  return new Set(decsOf(node).map(decName));
}

/** Transform ONE embedded JETH source. Returns { text, edits, changes, manual } - `manual` non-empty
 *  means the source must be left unchanged (the caller never applies a partial/guessed transform). */
function transformJethSource(text, { forceGet = new Set() } = {}) {
  const sf = ts.createSourceFile('embedded.jeth', text, ts.ScriptTarget.ES2022, true);
  const edits = []; // { start, end, insert }
  const changes = [];
  const manual = [];

  const skipWs = (pos) => {
    let p = pos;
    while (p < text.length && (text[p] === ' ' || text[p] === '\t' || text[p] === '\n' || text[p] === '\r')) p++;
    return p;
  };
  const rmDec = (dec) => edits.push({ start: dec.getStart(sf), end: skipWs(dec.end), insert: '' });
  const replaceNode = (node, insert) => edits.push({ start: node.getStart(sf), end: node.end, insert });
  const insertAt = (pos, insert) => edits.push({ start: pos, end: pos, insert });
  const typeText = (node) => text.slice(node.getStart(sf), node.end);

  const wrapReturnType = (member, marker, label) => {
    if (!member.type) {
      // no annotation = implicit void: spell the marker explicitly (`f(): External<void>`).
      const close = member.getChildren(sf).find((c) => c.kind === ts.SyntaxKind.CloseParenToken);
      if (!close) {
        manual.push(`${label}: no return type and no close-paren token to anchor ${marker}<void>`);
        return;
      }
      insertAt(close.end, `: ${marker}<void>`);
      return;
    }
    replaceNode(member.type, `${marker}<${typeText(member.type)}>`);
  };

  const classKeywordToken = (cls) => cls.getChildren(sf).find((c) => c.kind === ts.SyntaxKind.ClassKeyword);
  const openBraceToken = (cls) => cls.getChildren(sf).find((c) => c.kind === ts.SyntaxKind.OpenBraceToken);

  // ---- @struct class P { fields } -> type P = { fields }; ------------------------------------
  const rewriteStruct = (cls, structDec) => {
    if (!cls.name) return manual.push('@struct class without a name');
    if ((cls.heritageClauses ?? []).length > 0) return manual.push(`@struct class ${cls.name.text} has heritage`);
    if (cls.typeParameters) return manual.push(`@struct class ${cls.name.text} has type parameters`);
    for (const m of cls.members) {
      if (!ts.isPropertyDeclaration(m)) return manual.push(`@struct class ${cls.name.text}: non-field member`);
      if (decsOf(m).length > 0 || (ts.getModifiers(m) ?? []).length > 0)
        return manual.push(`@struct class ${cls.name.text}: decorated/modified field`);
      if (m.initializer) return manual.push(`@struct class ${cls.name.text}: field initializer`);
      if (!m.type || !ts.isIdentifier(m.name)) return manual.push(`@struct class ${cls.name.text}: untyped/computed field`);
    }
    const kw = classKeywordToken(cls);
    const brace = openBraceToken(cls);
    if (!kw || !brace) return manual.push(`@struct class ${cls.name.text}: token scan failed`);
    for (const d of decsOf(cls)) {
      if (decName(d) !== 'struct') return manual.push(`@struct class ${cls.name.text}: extra class decorator @${decName(d)}`);
      rmDec(d);
    }
    edits.push({ start: kw.getStart(sf), end: kw.end, insert: 'type' });
    edits.push({ start: cls.name.end, end: brace.getStart(sf), insert: ' = ' });
    insertAt(cls.end, ';');
    changes.push(`@struct class ${cls.name.text} -> type ${cls.name.text} = {...};`);
  };

  // ---- @interface class I { @external m(): T; } -> interface I { m(): View<T>|...; } ----------
  const rewriteInterface = (cls, _dec) => {
    if (!cls.name) return manual.push('@interface class without a name');
    if ((cls.heritageClauses ?? []).length > 0)
      return manual.push(
        `@interface class ${cls.name.text} extends ...: a native interface cannot extend (JETH349) - stays legacy`,
      );
    for (const d of decsOf(cls)) {
      if (decName(d) !== 'interface') return manual.push(`@interface class ${cls.name.text}: extra class decorator @${decName(d)}`);
      rmDec(d);
    }
    const kw = classKeywordToken(cls);
    if (!kw) return manual.push(`@interface class ${cls.name.text}: token scan failed`);
    edits.push({ start: kw.getStart(sf), end: kw.end, insert: 'interface' });
    for (const m of cls.members) {
      if (!ts.isMethodDeclaration(m) || m.body) return manual.push(`@interface class ${cls.name.text}: non-bodyless-method member`);
      const ds = decSet(m);
      for (const nm of ds) {
        if (!['external', 'view', 'pure', 'payable', 'read'].includes(nm))
          return manual.push(`@interface class ${cls.name.text}: member decorator @${nm} has no interface spelling`);
      }
      for (const d of decsOf(m)) rmDec(d);
      const marker = ds.has('payable') ? 'Payable' : ds.has('pure') ? 'Pure' : ds.has('view') || ds.has('read') ? 'View' : null;
      if (marker) wrapReturnType(m, marker, `interface ${cls.name.text} member`);
    }
    changes.push(`@interface class ${cls.name.text} -> interface ${cls.name.text}`);
  };

  // ---- @library class L -> static class L (members: @external -> External<T>, mut decs dropped) --
  const rewriteLibrary = (cls, libDec) => {
    const name = cls.name?.text ?? '<anon>';
    rmDec(libDec);
    const kw = classKeywordToken(cls);
    if (!kw) return manual.push(`@library class ${name}: token scan failed`);
    if (!(ts.getModifiers(cls) ?? []).some((m) => m.kind === ts.SyntaxKind.StaticKeyword))
      insertAt(kw.getStart(sf), 'static ');
    for (const m of cls.members) {
      if (ts.isMethodDeclaration(m)) {
        for (const d of decsOf(m)) {
          const nm = decName(d);
          if (nm === 'external') {
            rmDec(d);
            wrapReturnType(m, 'External', `library ${name} fn`);
          } else if (nm === 'view' || nm === 'pure' || nm === 'read') rmDec(d);
          // anything else (incl. a @payable misuse negative) is KEPT - the trial compile arbitrates.
        }
      } else if (decSet(m).size > 0) {
        manual.push(`library ${name}: decorated non-method member`);
      }
    }
    changes.push(`@library class ${name} -> static class ${name}`);
  };

  // ---- @event/@error member -> Name: event<{...}> / error<{...}> field marker -----------------
  const rewriteEventOrError = (member, kind, clsName) => {
    if (!ts.isMethodDeclaration(member) || member.body) return manual.push(`@${kind} ${clsName}: not a bodyless method`);
    if (!ts.isIdentifier(member.name)) return manual.push(`@${kind} ${clsName}: computed name`);
    const kept = [];
    for (const d of decsOf(member)) {
      const nm = decName(d);
      if (nm === kind) continue;
      if (KEEP_DECS.has(nm)) kept.push(text.slice(d.getStart(sf), d.end));
      else return manual.push(`@${kind} ${member.name.text}: extra decorator @${nm}`);
    }
    const fields = [];
    for (const p of member.parameters) {
      if (!ts.isIdentifier(p.name) || !p.type || p.initializer || p.questionToken || p.dotDotDotToken)
        return manual.push(`@${kind} ${member.name.text}: unsupported parameter shape`);
      const pDecs = decsOf(p).map(decName);
      const idx = pDecs.includes('indexed');
      if (pDecs.some((n) => n !== 'indexed')) return manual.push(`@${kind} ${member.name.text}: parameter decorator besides @indexed`);
      const t = typeText(p.type);
      fields.push(`${p.name.text}: ${idx ? `indexed<${t}>` : t}`);
    }
    const markerBody = fields.length === 0 ? '{}' : `{ ${fields.join('; ')} }`;
    const prefix = kept.length > 0 ? kept.join(' ') + ' ' : '';
    edits.push({ start: member.getStart(sf), end: member.end, insert: `${prefix}${member.name.text}: ${kind}<${markerBody}>;` });
    changes.push(`@${kind} ${member.name.text}(...) -> ${member.name.text}: ${kind}<{...}>`);
  };

  // ---- contract-shaped class members ----------------------------------------------------------
  const rewriteContractMember = (m, clsName) => {
    const ds = decSet(m);
    if (ds.has('event')) return rewriteEventOrError(m, 'event', clsName);
    if (ds.has('error')) return rewriteEventOrError(m, 'error', clsName);

    if (ts.isPropertyDeclaration(m)) {
      const isConst = ds.has('constant');
      const isImm = ds.has('immutable');
      const isExt = ds.has('external');
      for (const d of decsOf(m)) {
        const nm = decName(d);
        if (nm === 'state' || nm === 'constant' || nm === 'immutable' || nm === 'external') rmDec(d);
        // anything else (@storage("ns"), misuse negatives, ...) is KEPT - the trial compile arbitrates.
      }
      if ((isConst || isImm) && !(ts.getModifiers(m) ?? []).some((x) => x.kind === ts.SyntaxKind.StaticKeyword)) {
        insertAt(m.name.getStart(sf), 'static ');
        changes.push(`${clsName}.${m.name.getText(sf)}: @${isConst ? 'constant' : 'immutable'} -> static`);
      }
      if (isExt) {
        if (!m.type) manual.push(`${clsName}: @external field without a type annotation`);
        else {
          replaceNode(m.type, `Visible<${typeText(m.type)}>`);
          changes.push(`${clsName}.${m.name.getText(sf)}: @external field -> Visible<T>`);
        }
      }
      if (ds.has('state')) changes.push(`${clsName}.${m.name.getText(sf)}: @state -> bare field`);
      return;
    }

    if (ts.isConstructorDeclaration(m)) return; // @payable ctor has no native spelling - kept as-is.

    if (ts.isMethodDeclaration(m) || ts.isGetAccessorDeclaration(m)) {
      // special entries: the method NAME is the native spelling.
      if (ds.has('receive') || ds.has('fallback')) {
        const kind = ds.has('receive') ? 'receive' : 'fallback';
        if (!ts.isIdentifier(m.name)) return manual.push(`${clsName}: @${kind} with computed name`);
        for (const d of decsOf(m)) {
          const nm = decName(d);
          if (nm === kind) rmDec(d);
          else if (nm === 'payable' && kind === 'fallback') {
            rmDec(d);
            wrapReturnType(m, 'Payable', `${clsName} @fallback`);
          }
          // anything else (@view/@pure/@read misuse negatives, modifier applications, @virtual...) is
          // KEPT - a read-only special entry must keep rejecting (JETH386); the trial compile arbitrates.
        }
        if (m.name.text !== kind) replaceNode(m.name, kind);
        changes.push(`${clsName}.${m.name.text}: @${kind} -> ${kind}()`);
        return;
      }

      if (ds.has('payable')) {
        for (const d of decsOf(m)) {
          const nm = decName(d);
          // view/pure/read are KEPT alongside Payable<T>: the conflicting-mutability reject (JETH052)
          // must keep rejecting with the same code as the legacy @payable @view combination. Modifier
          // applications and @virtual/@override are kept too.
          if (nm === 'payable' || nm === 'external') rmDec(d);
        }
        wrapReturnType(m, 'Payable', `${clsName} @payable method`);
        changes.push(`${clsName}.${m.name.getText(sf)}: @payable -> Payable<T>`);
        return;
      }

      if (ds.has('external')) {
        const readonly = ds.has('view') || ds.has('pure') || ds.has('read');
        const isVoid = !m.type || m.type.kind === ts.SyntaxKind.VoidKeyword;
        const name = ts.isIdentifier(m.name) ? m.name.text : m.name.getText(sf);
        for (const d of decsOf(m)) {
          const nm = decName(d);
          if (nm === 'external' || nm === 'view' || nm === 'pure' || nm === 'read') rmDec(d);
          // anything else (modifier applications like @onlyOwner, @virtual, @override(..)) is KEPT.
        }
        // The `get` rule (JETH352) follows the analyzer's INFERRED mutability, not the declared
        // decorators: a declared-@pure fn whose body delegatecalls an external library is a WRITER
        // natively (method form), while an inferred-read-only fn MUST be a `get`. Statically
        // undecidable, so: BODIED value-returning methods default to the method form and the trial
        // compile's JETH352 retry (forceGet, keyed Class.method) flips exactly the ones the analyzer
        // names. BODYLESS declarations never enter inference: a bodyless @view/@pure is spelled `get`
        // (declared-view twin), a bodyless plain @external stays the nonpayable override-headroom
        // method form.
        const wantGet =
          !ts.isGetAccessorDeclaration(m) &&
          !isVoid &&
          ((readonly && !m.body) || forceGet.has(`${clsName}.${name}`));
        if (wantGet) insertAt(m.name.getStart(sf), 'get ');
        wrapReturnType(m, 'External', `${clsName} @external method`);
        changes.push(`${clsName}.${name}: @external${readonly ? ' @view/@pure/@read' : ''} -> ${wantGet ? 'get + ' : ''}External<T>`);
        return;
      }

      // internal function: mutability is inferred - drop @view/@pure/@read.
      for (const d of decsOf(m)) {
        const nm = decName(d);
        if (nm === 'view' || nm === 'pure' || nm === 'read') {
          rmDec(d);
          changes.push(`${clsName}.${m.name.getText(sf)}: internal @${nm} dropped (inferred)`);
        }
      }
    }
  };

  const rewriteClass = (cls) => {
    const ds = decSet(cls);
    if (ds.has('struct')) return rewriteStruct(cls, null);
    if (ds.has('interface')) return rewriteInterface(cls, null);
    if (ds.has('library')) {
      const libDec = decsOf(cls).find((d) => decName(d) === 'library');
      return rewriteLibrary(cls, libDec);
    }
    if (ds.has('diamond')) return manual.push(`@diamond class ${cls.name?.text}: routed to manual (pre-parse expansion)`);
    for (const d of decsOf(cls)) {
      const nm = decName(d);
      if (nm === 'contract') {
        rmDec(d);
        changes.push(`@contract ${cls.name?.text} deleted (bare class = contract)`);
      } else if (nm === 'abstract') {
        rmDec(d);
        if (!(ts.getModifiers(cls) ?? []).some((x) => x.kind === ts.SyntaxKind.AbstractKeyword)) {
          const kw = classKeywordToken(cls);
          if (!kw) return manual.push(`@abstract class ${cls.name?.text}: token scan failed`);
          insertAt(kw.getStart(sf), 'abstract ');
        }
        changes.push(`@abstract ${cls.name?.text} -> abstract class`);
      }
      // any other class decorator (@using(L, T), a class-level @payable negative, ...) is KEPT.
    }
    for (const m of cls.members) rewriteContractMember(m, cls.name?.text ?? '<anon>');
  };

  const visit = (n) => {
    if (ts.isClassDeclaration(n)) rewriteClass(n);
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);

  if (manual.length > 0) return { text, edits: [], changes: [], manual };
  if (edits.length === 0) return { text, edits: [], changes, manual };

  // apply BACK-TO-FRONT; overlapping spans mean a transform bug - never guess, go manual.
  edits.sort((a, b) => b.start - a.start || b.end - a.end);
  for (let i = 1; i < edits.length; i++) {
    if (edits[i].end > edits[i - 1].start)
      return { text, edits: [], changes: [], manual: [`overlapping edit spans at ${edits[i].start}`] };
  }
  let out = text;
  for (const e of edits) out = out.slice(0, e.start) + e.insert + out.slice(e.end);
  // `edits` is returned in its applied (descending-start, stable) order so a caller re-applying the
  // spans - e.g. mapped onto the RAW literal text - reproduces the same result, including the
  // relative order of same-position insertions.
  return { text: out, edits, changes, manual };
}

// ------------------------------------------------------------ trial compile ------
function outcomeOf(src) {
  try {
    const r = compileFn(src, { fileName: 'C.jeth' });
    return { kind: 'ok', bc: r.creationBytecode };
  } catch (e) {
    if (CompileErrorCls && e instanceof CompileErrorCls)
      return { kind: 'rej', codes: e.diagnostics.map((d) => d.code).sort(), diags: e.diagnostics };
    return { kind: 'threw', name: e instanceof Error ? e.constructor.name : typeof e };
  }
}
function outcomesEqual(a, b) {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'ok') return a.bc === b.bc;
  if (a.kind === 'rej') return a.codes.join(',') === b.codes.join(',');
  return a.name === b.name;
}

/** Resolve a diagnostic (1-based line/column) in `text` to its innermost enclosing method + class,
 *  keyed `Class.method` - the forceGet key. Class names are invariant under the transform, so a key
 *  computed on the TRANSFORMED text addresses the same method in the original source. */
function methodKeyAt(text, line, column) {
  const sf = ts.createSourceFile('probe.jeth', text, ts.ScriptTarget.ES2022, true);
  const pos = sf.getPositionOfLineAndCharacter(line - 1, column - 1);
  let found = null;
  const visit = (n, cls) => {
    if (ts.isClassDeclaration(n)) cls = n.name?.text ?? cls;
    if (ts.isMethodDeclaration(n) && n.getStart(sf) <= pos && pos < n.end && ts.isIdentifier(n.name))
      found = {
        key: `${cls}.${n.name.text}`,
        pos,
        bodyStart: n.body ? n.body.getStart(sf) : n.end,
        bodyEnd: n.body ? n.body.end : n.end,
      }; // innermost wins (methods do not nest, classes may)
    ts.forEachChild(n, (c) => visit(c, cls));
  };
  ts.forEachChild(sf, (n) => visit(n, '<anon>'));
  return found;
}

/** Rewrite + trial-verify one embedded source; returns { text, edits, action, changes, manual }.
 *  `forceGet` seeds the get-spelling key set: a const literal that is a FRAGMENT (e.g. an @abstract
 *  class alone, standalone outcome JETH040 in every spelling) may need keys discovered by a
 *  TEMPLATE ASSEMBLY that instantiates it in full context - the caller passes them in here. */
function migrateSource(cooked, { forceGet } = {}) {
  let force = new Set(forceGet ?? []);
  let res = transformJethSource(cooked, { forceGet: force });
  if (res.manual.length > 0) return { text: cooked, edits: [], action: 'manual', changes: [], manual: res.manual };
  if (res.text === cooked) return { text: cooked, edits: [], action: 'unchanged', changes: res.changes, manual: [] };
  if (!compileFn) return { text: res.text, edits: res.edits, action: 'rewritten-untrialed', changes: res.changes, manual: [] };

  const orig = outcomeOf(cooked);
  for (let iter = 0; iter < 10; iter++) {
    const post = outcomeOf(res.text);
    if (outcomesEqual(orig, post)) return { text: res.text, edits: res.edits, action: 'rewritten', changes: res.changes, manual: [] };
    // the statically-undecidable JETH352 case: flip EXACTLY the diagnosed read-only externals (located
    // by diagnostic position -> enclosing Class.method in the transformed text) to `get` and retry.
    if (post.kind === 'rej' && post.diags) {
      const keys = new Set();
      for (const d of post.diags) {
        if (d.code !== 'JETH352' || !/is read-only/.test(d.message)) continue;
        const hit = methodKeyAt(res.text, d.line, d.column);
        if (hit && !force.has(hit.key)) keys.add(hit.key);
      }
      // JETH352 is shared by several messages (option-object errors etc.), so eligibility is decided
      // by the /is read-only/ message filter above, not by whether the baseline also had a JETH352:
      // a source can legitimately carry a baseline JETH352 AND need the get flip (key dedup + the
      // iteration cap keep this terminating).
      if (keys.size > 0) {
        for (const k of keys) force.add(k);
        res = transformJethSource(cooked, { forceGet: force });
        if (res.manual.length > 0) break;
        continue;
      }
    }
    return {
      text: cooked,
      action: 'manual',
      changes: [],
      manual: [
        `trial mismatch: orig=${orig.kind}${orig.kind === 'rej' ? '[' + orig.codes + ']' : ''} post=${post.kind}${post.kind === 'rej' ? '[' + post.codes + ']' : ''}`,
      ],
    };
  }
  return { text: cooked, action: 'manual', changes: [], manual: ['JETH352 get-retry did not converge'] };
}

// ------------------------------------------------- cooked<->raw literal mapping ------
/** Decode a template/string literal BODY (the text between the delimiters) and build the
 *  cooked->raw offset map: starts[j] = raw offset where cooked char j begins, and
 *  starts[cooked.length] = raw.length. Returns null unless the decode reproduces `cooked`
 *  EXACTLY (unknown escapes, legacy octal, malformed hex -> null; the caller goes manual).
 *  With this map an edit span computed on the cooked text lands on the exact raw span whose
 *  cooked value it covers, so escapes elsewhere in the literal are never disturbed. */
function cookedToRawStarts(raw, cooked) {
  const starts = [];
  let out = '';
  let i = 0;
  while (i < raw.length) {
    const from = i;
    let piece;
    const c = raw[i];
    if (c === '\\') {
      const n = raw[i + 1];
      if (n === undefined) return null;
      if (n === 'n') { piece = '\n'; i += 2; }
      else if (n === 't') { piece = '\t'; i += 2; }
      else if (n === 'r') { piece = '\r'; i += 2; }
      else if (n === 'b') { piece = '\b'; i += 2; }
      else if (n === 'f') { piece = '\f'; i += 2; }
      else if (n === 'v') { piece = '\v'; i += 2; }
      else if (n === '0' && !/[0-9]/.test(raw[i + 2] ?? '')) { piece = '\0'; i += 2; }
      else if (n === 'x') {
        const h = raw.slice(i + 2, i + 4);
        if (!/^[0-9a-fA-F]{2}$/.test(h)) return null;
        piece = String.fromCharCode(parseInt(h, 16));
        i += 4;
      } else if (n === 'u') {
        if (raw[i + 2] === '{') {
          const close = raw.indexOf('}', i + 3);
          const h = close < 0 ? '' : raw.slice(i + 3, close);
          if (!/^[0-9a-fA-F]+$/.test(h) || parseInt(h, 16) > 0x10ffff) return null;
          piece = String.fromCodePoint(parseInt(h, 16));
          i = close + 1;
        } else {
          const h = raw.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) return null;
          piece = String.fromCharCode(parseInt(h, 16));
          i += 6;
        }
      } else if (n === '\n') { piece = ''; i += 2; } // line continuation
      else if (n === '\r') { piece = ''; i += raw[i + 2] === '\n' ? 3 : 2; }
      else if (n === '\u2028' || n === '\u2029') { piece = ''; i += 2; }
      else if (/[0-9]/.test(n)) return null; // legacy octal / \8 \9 - not modelled
      else { piece = n; i += 2; } // \\ \` \$ \' \" and any other identity escape
    } else if (c === '\r') {
      piece = '\n'; // CRLF and lone CR both cook to \n
      i += raw[i + 1] === '\n' ? 2 : 1;
    } else {
      piece = c;
      i += 1;
    }
    for (let k = 0; k < piece.length; k++) starts[out.length + k] = from;
    out += piece;
  }
  if (out !== cooked) return null;
  starts[out.length] = raw.length;
  return starts;
}

/** Escape `s` (cooked text) for embedding in a literal of the given kind so that the embedded
 *  raw text cooks back to exactly `s`. */
function escapeForLiteral(s, kind, quote) {
  const e = s.replace(/\\/g, '\\\\');
  if (kind === 'template') return e.replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
  return e.replaceAll(quote, '\\' + quote).replace(/\n/g, '\\n').replace(/\r/g, '\\r');
}

// ------------------------------------------------------------- per test file ------
const manualBucketPath = path.join(path.dirname(url.fileURLToPath(import.meta.url)), 'manual-bucket.txt');
const manualEntries = [];

for (const file of files) {
  const abs = path.resolve(file);
  const original = fs.readFileSync(abs, 'utf8');
  const sf = ts.createSourceFile(abs, original, ts.ScriptTarget.ES2022, true);
  const line = (node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;

  // ---- const-literal resolution (for `${IDENT}` template holes / `+ IDENT` operands) ----------
  // A hole whose expression is an identifier is resolved LEXICALLY: walk the ancestor scopes from
  // the use site outward and take the NEAREST declaration of that name. When that declaration is a
  // variable initialized with a plain template/string literal, the hole resolves to that literal:
  // the composite is then trialed as the EXACT instantiation the migrated test file will produce
  // (migrated const text + edited chunks). A nearer non-literal declaration (parameter, class,
  // destructuring, import, loop/catch binding) shadows - the hole becomes an inert placeholder.
  // (Global-uniqueness was the old guard; it wrongly degraded `const T` re-declared in two sibling
  // it-blocks to a placeholder, and the fragment-blind skeleton trial then missed a JETH352 get
  // flip - the batch-3 OR6 accept->reject flip.)
  const bindsName = (bindingName, name) => {
    if (ts.isIdentifier(bindingName)) return bindingName.text === name;
    if (ts.isObjectBindingPattern(bindingName) || ts.isArrayBindingPattern(bindingName))
      return bindingName.elements.some((el) => ts.isBindingElement(el) && bindsName(el.name, name));
    return false;
  };
  const scopeDeclares = (stmts, name) => {
    // { lit } = const-declared here with a plain-literal initializer; {} = declared here any other
    // way (unresolvable); null = not declared in this statement list.
    for (const s of stmts) {
      if (ts.isVariableStatement(s)) {
        for (const d of s.declarationList.declarations) {
          if (!bindsName(d.name, name)) continue;
          if (
            ts.isIdentifier(d.name) &&
            d.initializer &&
            (ts.isNoSubstitutionTemplateLiteral(d.initializer) || ts.isStringLiteral(d.initializer))
          )
            return { lit: d.initializer };
          return {};
        }
      } else if (
        (ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s) || ts.isEnumDeclaration(s)) &&
        s.name &&
        ts.isIdentifier(s.name) &&
        s.name.text === name
      ) {
        return {};
      } else if (ts.isImportDeclaration(s) && s.importClause) {
        const ic = s.importClause;
        if (ic.name?.text === name) return {};
        if (ic.namedBindings) {
          if (ts.isNamespaceImport(ic.namedBindings) && ic.namedBindings.name.text === name) return {};
          if (ts.isNamedImports(ic.namedBindings) && ic.namedBindings.elements.some((el) => el.name.text === name)) return {};
        }
      }
    }
    return null;
  };
  const resolveConstHole = (expr) => {
    if (!ts.isIdentifier(expr)) return null;
    const name = expr.text;
    for (let a = expr.parent; a; a = a.parent) {
      if (ts.isFunctionLike(a) && a.parameters?.some((p) => bindsName(p.name, name))) return null;
      if (ts.isCatchClause(a) && a.variableDeclaration && bindsName(a.variableDeclaration.name, name)) return null;
      if (
        (ts.isForStatement(a) || ts.isForOfStatement(a) || ts.isForInStatement(a)) &&
        a.initializer &&
        ts.isVariableDeclarationList(a.initializer) &&
        a.initializer.declarations.some((d) => bindsName(d.name, name))
      )
        return null;
      const stmts = ts.isBlock(a) || ts.isModuleBlock(a) || ts.isSourceFile(a) ? a.statements : null;
      if (stmts) {
        const hit = scopeDeclares(stmts, name);
        if (hit) return hit.lit ?? null;
      }
    }
    return null;
  };

  // Consts PINNED to their legacy spelling: a const consumed by a `// use @decorators` (stage-2)
  // assembly must keep its original text - the pragma composite's chunks are untouched, so a
  // migrated const would splice native syntax into a LEGACY-mode source (the batch-3 @library
  // LIB inside the pragma-carrying LC template broke exactly this way). Pinning reverts the
  // const's pass-1 migration and blocks any re-migration; the composite fixpoint restarts so
  // every other composite re-trials against the reverted decision.
  const pinnedLits = new Set();

  // Per-literal state. A const literal that is a context-blind FRAGMENT (standalone outcome
  // identical in every spelling) may be re-migrated with get-keys DISCOVERED BY A TEMPLATE ASSEMBLY
  // that instantiates it in full context, so a literal's migration must be re-runnable: its raw
  // edits and log entry live here (replaced on re-run) and the final file rewrite is assembled at
  // the end. `decision` = the literal's final cooked text (the original when unchanged/manual).
  const litState = new Map(); // literal node -> { decision, edits, logEntry, force }
  const tplState = new Map(); // template-expression node -> { edits, logEntry }
  const decisionOf = (node) => litState.get(node)?.decision ?? node.text;

  const migrateLiteral = (node, kind) => {
    const cooked = node.text;
    const prev = litState.get(node);
    const st = { decision: cooked, edits: [], logEntry: null, force: prev?.force ?? new Set() };
    litState.set(node, st);
    if (!BANNED.test(cooked)) return;
    if (pinnedLits.has(node)) {
      st.logEntry = { line: line(node), action: 'kept-legacy', reason: 'consumed by a // use @decorators (stage-2) assembly - the const stays legacy' };
      return;
    }
    const rawStart = node.getStart(sf) + 1;
    const rawEnd = node.end - 1;
    const raw = original.slice(rawStart, rawEnd);
    const quote = kind === 'string' ? original[node.getStart(sf)] : '`';
    // cooked->raw offset map: identity when the literal has no escapes, decoded otherwise. Each
    // transform edit span (computed on the cooked text) lands on the exact raw span it covers, and
    // every inserted text is re-escaped for the literal kind - untouched escapes stay byte-identical.
    const starts = cookedToRawStarts(raw, cooked);
    if (!starts) {
      st.logEntry = { line: line(node), action: 'manual', reason: `unmappable escapes in ${kind} literal carrying banned decorators` };
      return;
    }
    if (DEC_PRAGMA.test(cooked)) {
      st.logEntry = { line: line(node), action: 'skipped-stage2', reason: '// use @decorators pragma (stage-2 rewrites these)' };
      return;
    }
    const r = migrateSource(cooked, { forceGet: st.force });
    if (r.action === 'manual') {
      st.logEntry = { line: line(node), action: 'manual', reason: r.manual.join(' | ') };
      return;
    }
    if (r.text === cooked) {
      st.logEntry = { line: line(node), action: r.action, changes: r.changes };
      return;
    }
    // r.edits is in applied (descending-start) order; pushing in that order keeps same-position
    // insertions in the same relative order under the stable descending sort applied at the end.
    for (const e of r.edits) {
      st.edits.push({
        start: rawStart + starts[e.start],
        end: rawStart + starts[e.end],
        insert: escapeForLiteral(e.insert, kind, quote),
      });
    }
    st.decision = r.text;
    st.logEntry = { line: line(node), action: r.action, changes: r.changes };
  };

  // Composite sources: interpolated templates AND string CONCATENATION chains (`A + \`...\``).
  // Both are the same problem - an embedded JETH source assembled at runtime from literal CHUNKS
  // and expression HOLES - and both get the same treatment: a hole naming a once-declared const
  // with a plain-literal initializer is RESOLVED to that literal; any other hole becomes an inert
  // `__JMIGk__` placeholder identifier (identical on both sides). A concatenation's literal
  // operands are chunks, and a nested interpolated-template operand contributes its own chunks and
  // holes. The transform runs over the assembled ORIGINAL instantiation; edits inside resolved
  // holes are DROPPED (the const literal's own pass-1 migration realizes them at its declaration
  // site), edits inside placeholders or crossing region boundaries route to manual. The trial then
  // compiles the EXACT post assembly the migrated test file will produce at runtime (edited chunks
  // + the consts' pass-1 migrated texts + placeholders), with the same JETH352 get-retry as plain
  // literals. Placeholder-carrying assemblies are trialed too - equality on the skeleton is a
  // strong (not perfect) check, and the capture-diff remains the final arbiter per the migration
  // procedure.
  //
  // A part is { type:'chunk', lit, litKind, quote, rawFrom, rawTo } | { type:'hole', expr }.
  const flattenTemplate = (n) => {
    const chunkOf = (c) => ({
      type: 'chunk',
      lit: c,
      litKind: 'template',
      quote: '`',
      // raw chunk spans: head is `...${, middles are }...${, the tail is }...`
      rawFrom: c.getStart(sf) + 1,
      rawTo: c.end - (c.kind === ts.SyntaxKind.TemplateTail ? 1 : 2),
    });
    const parts = [chunkOf(n.head)];
    for (const s of n.templateSpans) {
      parts.push({ type: 'hole', expr: s.expression });
      parts.push(chunkOf(s.literal));
    }
    return parts;
  };

  const ownedExprs = new Set(); // nested `+`/paren/template nodes consumed by an enclosing chain
  const flattenConcat = (n) => {
    const parts = [];
    const rec = (e) => {
      if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken) {
        ownedExprs.add(e);
        rec(e.left);
        rec(e.right);
      } else if (ts.isParenthesizedExpression(e)) {
        ownedExprs.add(e);
        rec(e.expression);
      } else if (ts.isStringLiteral(e)) {
        parts.push({ type: 'chunk', lit: e, litKind: 'string', quote: original[e.getStart(sf)], rawFrom: e.getStart(sf) + 1, rawTo: e.end - 1 });
      } else if (ts.isNoSubstitutionTemplateLiteral(e)) {
        parts.push({ type: 'chunk', lit: e, litKind: 'template', quote: '`', rawFrom: e.getStart(sf) + 1, rawTo: e.end - 1 });
      } else if (ts.isTemplateExpression(e)) {
        ownedExprs.add(e);
        parts.push(...flattenTemplate(e));
      } else {
        parts.push({ type: 'hole', expr: e });
      }
    };
    rec(n);
    return parts;
  };

  // Returns true when it re-migrated a const literal with new get-keys (the caller then restarts
  // the whole composite pass: earlier composites may reference the re-migrated const too).
  const handleComposite = (n, parts, label) => {
    const st = { edits: [], logEntry: null };
    tplState.set(n, st);
    const chunkParts = parts.filter((p) => p.type === 'chunk');
    if (!chunkParts.some((p) => BANNED.test(p.lit.text))) return false;
    const fail = (reason) => {
      st.logEntry = { line: line(n), action: 'manual', reason };
      return false;
    };
    if (chunkParts.some((p) => p.lit.text.includes('__JMIG'))) return fail(`${label}: chunk contains the placeholder marker`);
    for (let k = 0; k + 1 < parts.length; k++) {
      if (parts[k].type === 'chunk' && parts[k + 1].type === 'hole' && parts[k].lit.text.endsWith('@'))
        return fail(`${label}: a hole in decorator-name position (@\${...})`);
    }
    const chunkInfo = new Map(); // chunk part -> cooked->raw offset map
    for (const p of chunkParts) {
      const starts = cookedToRawStarts(original.slice(p.rawFrom, p.rawTo), p.lit.text);
      if (!starts) return fail(`${label}: unmappable escapes in a chunk`);
      chunkInfo.set(p, starts);
    }

    let phCount = 0;
    const holes = new Map(); // hole part -> { orig, lit, resolved }
    for (const p of parts) {
      if (p.type !== 'hole') continue;
      const lit = resolveConstHole(p.expr);
      if (lit) holes.set(p, { orig: lit.text, lit, resolved: true });
      else holes.set(p, { orig: `__JMIG${phCount++}__`, lit: null, resolved: false });
    }
    const postHole = (h) => (h.resolved ? decisionOf(h.lit) : h.orig);

    // assemble the ORIGINAL instantiation + its region table
    let origAsm = '';
    const regions = []; // { part, type: 'chunk'|'hole', resolved?, start, end } over origAsm
    for (const p of parts) {
      const piece = p.type === 'chunk' ? p.lit.text : holes.get(p).orig;
      regions.push({
        part: p,
        type: p.type,
        resolved: p.type === 'hole' ? holes.get(p).resolved : undefined,
        start: origAsm.length,
        end: origAsm.length + piece.length,
      });
      origAsm += piece;
    }
    if (DEC_PRAGMA.test(origAsm)) {
      st.logEntry = { line: line(n), action: 'skipped-stage2', reason: '// use @decorators pragma (stage-2 rewrites these)' };
      // This composite's chunks stay untouched, so every resolved const it consumes must stay
      // legacy too: PIN it and revert any pass-1 migration, then restart the fixpoint so other
      // composites re-trial against the reverted decision.
      let reverted = false;
      for (const h of holes.values()) {
        if (!h.resolved || pinnedLits.has(h.lit)) continue;
        pinnedLits.add(h.lit);
        const cur = litState.get(h.lit);
        if (cur && cur.decision !== h.lit.text) reverted = true;
        migrateLiteral(h.lit, ts.isStringLiteral(h.lit) ? 'string' : 'template');
      }
      return reverted;
    }

    // Build the EXACT post assembly the migrated test file will instantiate at runtime (edited
    // chunks + each const's current migrated text + placeholders), with post-space regions so a
    // trial diagnostic can be routed to the region that must change.
    const buildPost = (chunkEdits) => {
      let out = '';
      const postRegions = [];
      for (const g of regions) {
        const from = out.length;
        if (g.type === 'hole') out += postHole(holes.get(g.part));
        else {
          let c = origAsm.slice(g.start, g.end);
          // local edits arrive already in applied (descending-start, stable) order
          for (const e of chunkEdits) {
            if (e.start < g.start || e.end > g.end) continue;
            const s = e.start - g.start;
            const t = e.end - g.start;
            c = c.slice(0, s) + e.insert + c.slice(t);
          }
          out += c;
        }
        postRegions.push({ ...g, postStart: from, postEnd: out.length });
      }
      return { text: out, postRegions };
    };

    const force = new Set();
    let changedConst = false;
    let chunkEdits = null;
    let changes = null;
    let action = 'rewritten-interp';
    for (let iter = 0; ; iter++) {
      if (iter >= 12) return fail(`${label}: JETH352 get-retry did not converge`) || changedConst;
      const res = transformJethSource(origAsm, { forceGet: force });
      if (res.manual.length > 0) return fail(`${label}: ${res.manual.join(' | ')}`) || changedConst;
      const edits = [];
      let bad = null;
      for (const e of res.edits) {
        const g = regions.find((g) => g.start <= e.start && e.end <= g.end);
        if (!g) { bad = `an edit crosses a region boundary (at ${e.start})`; break; }
        if (g.type === 'chunk') edits.push(e);
        else if (!g.resolved) { bad = `an edit inside an unresolved \${...} hole (at ${e.start})`; break; }
        // resolved-hole edits: dropped - realized by the const literal's own migration.
      }
      if (bad) return fail(`${label}: ${bad}`) || changedConst;
      const { text: postAsm, postRegions } = buildPost(edits);
      if (postAsm === origAsm) {
        st.logEntry = { line: line(n), action: 'unchanged', changes: res.changes };
        return changedConst;
      }
      if (!compileFn) { chunkEdits = edits; changes = res.changes; action = 'rewritten-interp-untrialed'; break; }
      const orig = outcomeOf(origAsm);
      const post = outcomeOf(postAsm);
      if (outcomesEqual(orig, post)) { chunkEdits = edits; changes = res.changes; break; }
      if (post.kind === 'rej' && post.diags) {
        // classify each get-rule diagnostic by the POST region it falls in: a chunk method joins
        // this template's own force set; a method inside a RESOLVED const hole re-migrates that
        // const with the key (its fragment-blind standalone trial could not see the full context).
        // A method whose BODY contains an unresolved placeholder is never flipped: the placeholder
        // may be exactly what determines its effects (e.g. `IFoo(t).${sig}()` - the erroring
        // skeleton body reads as read-only while the real method name is a writer), so a
        // trial-equal get spelling could still flip the real instantiation. Manual instead.
        // (A placeholder in decorator position - `@override${l}` - is allowed: an override list
        // never contributes effects.)
        let progressed = false;
        let unroutable = null;
        for (const d of post.diags) {
          if (d.code !== 'JETH352' || !/is read-only/.test(d.message)) continue;
          const hit = methodKeyAt(postAsm, d.line, d.column);
          if (!hit) { unroutable = 'a JETH352 outside any method'; continue; }
          const g = postRegions.find((g) => g.postStart <= hit.pos && hit.pos < g.postEnd);
          if (!g) { unroutable = 'a JETH352 outside any region'; continue; }
          const holey = postRegions.some(
            (h) => h.type === 'hole' && !h.resolved && h.postStart < hit.bodyEnd && hit.bodyStart < h.postEnd,
          );
          if (holey) { unroutable = `the get-flip candidate method's body contains an unresolved \${...} hole`; continue; }
          if (g.type === 'chunk') {
            if (!force.has(hit.key)) { force.add(hit.key); progressed = true; }
          } else if (g.resolved) {
            const hole = holes.get(g.part);
            if (pinnedLits.has(hole.lit)) {
              unroutable = 'a JETH352 inside a const pinned legacy by a stage-2 assembly';
              continue;
            }
            const constState = litState.get(hole.lit);
            if (constState && !constState.force.has(hit.key)) {
              constState.force.add(hit.key);
              migrateLiteral(hole.lit, ts.isStringLiteral(hole.lit) ? 'string' : 'template');
              changedConst = true;
              progressed = true;
            } else if (!constState) unroutable = 'a JETH352 inside an untracked const literal';
          } else unroutable = 'a JETH352 inside an unresolved ${...} hole';
        }
        if (progressed) continue;
        if (unroutable) return fail(`${label}: ${unroutable} (trial orig=${orig.kind} post=rej[${post.codes}])`) || changedConst;
      }
      return (
        fail(
          `${label}: assembly trial mismatch orig=${orig.kind}${orig.kind === 'rej' ? '[' + orig.codes + ']' : ''} post=${post.kind}${post.kind === 'rej' ? '[' + post.codes + ']' : ''}`,
        ) || changedConst
      );
    }

    for (const e of chunkEdits) {
      const g = regions.find((g) => g.type === 'chunk' && g.start <= e.start && e.end <= g.end);
      const p = g.part;
      const starts = chunkInfo.get(p);
      st.edits.push({
        start: p.rawFrom + starts[e.start - g.start],
        end: p.rawFrom + starts[e.end - g.start],
        insert: escapeForLiteral(e.insert, p.litKind, p.quote),
      });
    }
    st.logEntry = { line: line(n), action, changes };
    return changedConst;
  };

  // pass 1: plain literals (their migrated texts feed const-hole resolution) - EXCLUDING literals
  // owned as chunks by a banned concatenation chain (the chain's composite handling edits them);
  // pass 2: composites (interpolated templates + banned concatenation chains), RESTARTED whenever
  // an assembly re-migrates a const literal (earlier composites may reference it): force sets grow
  // monotonically, so the fixpoint terminates.
  const composites = []; // { node, parts, label }
  const plainLits = [];
  const ownedLits = new Set(); // literal nodes that are chunks of a banned concatenation chain
  const visit = (n) => {
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken && !ownedExprs.has(n)) {
      const parts = flattenConcat(n);
      if (parts.some((p) => p.type === 'chunk' && BANNED.test(p.lit.text))) {
        composites.push({ node: n, parts, label: 'concatenation' });
        for (const p of parts) if (p.type === 'chunk') ownedLits.add(p.lit);
      }
      // descend regardless: literals nested inside unresolved hole expressions (e.g. helper-call
      // arguments) keep their pass-1 standalone treatment; owned chunks are excluded below.
    } else if (ts.isTemplateExpression(n) && !ownedExprs.has(n)) {
      composites.push({ node: n, parts: flattenTemplate(n), label: 'interpolated template' });
    }
    if (ts.isNoSubstitutionTemplateLiteral(n)) plainLits.push([n, 'template']);
    else if (ts.isStringLiteral(n)) plainLits.push([n, 'string']);
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);
  for (const [node, kind] of plainLits) if (!ownedLits.has(node)) migrateLiteral(node, kind);
  for (let pass = 0; ; pass++) {
    if (pass >= 25) {
      console.error(`ERROR ${file}: composite fixpoint did not settle in 25 passes - file left untouched`);
      manualEntries.push(`${path.relative(process.cwd(), abs)}  WHOLE FILE: composite fixpoint did not settle`);
      litState.clear();
      tplState.clear();
      break;
    }
    let restart = false;
    for (const c of composites) {
      if (handleComposite(c.node, c.parts, c.label)) restart = true;
    }
    if (!restart) break;
  }

  const rewrites = [];
  const log = [];
  for (const st of [...litState.values(), ...tplState.values()]) {
    rewrites.push(...st.edits);
    if (st.logEntry) log.push(st.logEntry);
  }
  log.sort((a, b) => a.line - b.line);
  for (const l of log) {
    if (l.action === 'manual') manualEntries.push(`${path.relative(process.cwd(), abs)}:${l.line}  ${l.reason}`);
  }

  rewrites.sort((a, b) => b.start - a.start);
  let out = original;
  for (const e of rewrites) out = out.slice(0, e.start) + e.insert + out.slice(e.end);

  const nRewritten = log.filter((l) => l.action.startsWith('rewritten')).length;
  const nManual = log.filter((l) => l.action === 'manual').length;
  const nSkipped = log.filter((l) => l.action === 'skipped-stage2').length;
  console.log(`${dry ? 'DRY  ' : 'WROTE'} ${file}: ${nRewritten} rewritten, ${nManual} manual, ${nSkipped} stage-2-skipped`);
  for (const l of log) {
    if (l.action === 'manual') console.log(`  L${l.line} MANUAL: ${l.reason}`);
    else if (l.changes?.length) console.log(`  L${l.line} ${l.action}: ${l.changes.join(' ; ')}`);
    else console.log(`  L${l.line} ${l.action}${l.reason ? ': ' + l.reason : ''}`);
  }
  if (!dry && out !== original) fs.writeFileSync(abs, out);
}

if (manualEntries.length > 0) {
  if (!dry) {
    const prev = fs.existsSync(manualBucketPath) ? fs.readFileSync(manualBucketPath, 'utf8').split('\n').filter(Boolean) : [];
    const merged = [...new Set([...prev, ...manualEntries])];
    fs.writeFileSync(manualBucketPath, merged.join('\n') + '\n');
  }
  console.log(`\nMANUAL BUCKET (${manualEntries.length} new entr${manualEntries.length === 1 ? 'y' : 'ies'})${dry ? ' [dry - not persisted]' : ' -> ' + path.relative(process.cwd(), manualBucketPath)}`);
  for (const e of manualEntries) console.log('  ' + e);
}
