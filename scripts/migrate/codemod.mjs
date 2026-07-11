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
//   @external field      -> External<T> field-type marker (P0b), incl. static const/immutable forms
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

/** Transform ONE embedded JETH source. Returns { text, changes, manual } - `manual` non-empty means
 *  the source must be left unchanged (the caller never applies a partial/guessed transform). */
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
      manual.push(`${label}: method has no return type annotation to wrap with ${marker}<>`);
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
          replaceNode(m.type, `External<${typeText(m.type)}>`);
          changes.push(`${clsName}.${m.name.getText(sf)}: @external field -> External<T>`);
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

  if (manual.length > 0) return { text, changes: [], manual };
  if (edits.length === 0) return { text, changes, manual };

  // apply BACK-TO-FRONT; overlapping spans mean a transform bug - never guess, go manual.
  edits.sort((a, b) => b.start - a.start || b.end - a.end);
  for (let i = 1; i < edits.length; i++) {
    if (edits[i].end > edits[i - 1].start) return { text, changes: [], manual: [`overlapping edit spans at ${edits[i].start}`] };
  }
  let out = text;
  for (const e of edits) out = out.slice(0, e.start) + e.insert + out.slice(e.end);
  return { text: out, changes, manual };
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
      found = `${cls}.${n.name.text}`; // innermost wins (methods do not nest, classes may)
    ts.forEachChild(n, (c) => visit(c, cls));
  };
  ts.forEachChild(sf, (n) => visit(n, '<anon>'));
  return found;
}

/** Rewrite + trial-verify one embedded source; returns { text, action, changes, manual }. */
function migrateSource(cooked) {
  let force = new Set();
  let res = transformJethSource(cooked, { forceGet: force });
  if (res.manual.length > 0) return { text: cooked, action: 'manual', changes: [], manual: res.manual };
  if (res.text === cooked) return { text: cooked, action: 'unchanged', changes: res.changes, manual: [] };
  if (!compileFn) return { text: res.text, action: 'rewritten-untrialed', changes: res.changes, manual: [] };

  const orig = outcomeOf(cooked);
  for (let iter = 0; iter < 10; iter++) {
    const post = outcomeOf(res.text);
    if (outcomesEqual(orig, post)) return { text: res.text, action: 'rewritten', changes: res.changes, manual: [] };
    // the statically-undecidable JETH352 case: flip EXACTLY the diagnosed read-only externals (located
    // by diagnostic position -> enclosing Class.method in the transformed text) to `get` and retry.
    if (post.kind === 'rej' && post.diags) {
      const keys = new Set();
      for (const d of post.diags) {
        if (d.code !== 'JETH352' || !/is read-only/.test(d.message)) continue;
        const key = methodKeyAt(res.text, d.line, d.column);
        if (key && !force.has(key)) keys.add(key);
      }
      if (keys.size > 0 && !(orig.kind === 'rej' && orig.codes.includes('JETH352'))) {
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

// ------------------------------------------------------------- per test file ------
const manualBucketPath = path.join(path.dirname(url.fileURLToPath(import.meta.url)), 'manual-bucket.txt');
const manualEntries = [];

for (const file of files) {
  const abs = path.resolve(file);
  const original = fs.readFileSync(abs, 'utf8');
  const sf = ts.createSourceFile(abs, original, ts.ScriptTarget.ES2022, true);
  const rewrites = []; // { start, end, insert } spans over the TEST file
  const log = [];
  let fileManual = false;

  const line = (node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;

  const handleLiteral = (node, kind) => {
    const cooked = node.text;
    if (!BANNED.test(cooked)) return;
    const rawStart = node.getStart(sf) + 1;
    const rawEnd = node.end - 1;
    const raw = original.slice(rawStart, rawEnd);
    if (raw !== cooked) {
      // escapes inside the literal: spans over the cooked text do not map onto the raw text.
      fileManual = true;
      log.push({ line: line(node), action: 'manual', reason: `raw!==cooked ${kind} literal carrying banned decorators` });
      return;
    }
    if (DEC_PRAGMA.test(cooked)) {
      log.push({ line: line(node), action: 'skipped-stage2', reason: '// use @decorators pragma (stage-2 rewrites these)' });
      return;
    }
    const r = migrateSource(cooked);
    if (r.action === 'manual') {
      log.push({ line: line(node), action: 'manual', reason: r.manual.join(' | ') });
      manualEntries.push(`${path.relative(process.cwd(), abs)}:${line(node)}  ${r.manual.join(' | ')}`);
      return;
    }
    if (r.text === cooked) {
      log.push({ line: line(node), action: r.action, changes: r.changes });
      return;
    }
    // safety: the replacement must be embeddable in the same literal kind without re-escaping.
    const badTpl = kind === 'template' && (r.text.includes('`') || r.text.includes('${'));
    const badStr = kind === 'string' && (r.text.includes(original[node.getStart(sf)]) || r.text.includes('\n') || r.text.includes('\\'));
    if (badTpl || badStr) {
      log.push({ line: line(node), action: 'manual', reason: 'rewritten text not embeddable in the original literal kind' });
      manualEntries.push(`${path.relative(process.cwd(), abs)}:${line(node)}  rewritten text not embeddable`);
      return;
    }
    rewrites.push({ start: rawStart, end: rawEnd, insert: r.text });
    log.push({ line: line(node), action: r.action, changes: r.changes });
  };

  const visit = (n) => {
    if (ts.isNoSubstitutionTemplateLiteral(n)) handleLiteral(n, 'template');
    else if (ts.isStringLiteral(n)) handleLiteral(n, 'string');
    else if (ts.isTemplateExpression(n)) {
      const chunks = [n.head.text, ...n.templateSpans.map((s) => s.literal.text)];
      if (chunks.some((c) => BANNED.test(c))) {
        log.push({ line: line(n), action: 'manual', reason: 'interpolated template literal carrying banned decorators' });
        manualEntries.push(`${path.relative(process.cwd(), abs)}:${line(n)}  interpolated template with banned decorators`);
      }
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);

  if (fileManual) {
    manualEntries.push(`${path.relative(process.cwd(), abs)}  WHOLE FILE: raw!==cooked literal with banned decorators`);
    console.log(`MANUAL  ${file} (raw!==cooked literal - file untouched)`);
    for (const l of log) console.log(`  L${l.line} ${l.action}: ${l.reason ?? ''}`);
    continue;
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
