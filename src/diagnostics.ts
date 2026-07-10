// Diagnostics: precise, source-spanned error reporting (directive §9 "precise
// diagnostics with source spans").
import ts from 'typescript';

export type Severity = 'error' | 'warning';

export interface Diagnostic {
  severity: Severity;
  code: string; // stable machine code, e.g. "JETH001"
  message: string;
  file: string;
  // 1-based line/column of the start of the offending span
  line: number;
  column: number;
  length: number;
}

/** Thrown when compilation cannot proceed; carries the collected diagnostics. */
export class CompileError extends Error {
  constructor(public diagnostics: Diagnostic[]) {
    super(`JETH compilation failed with ${diagnostics.filter((d) => d.severity === 'error').length} error(s)`);
    this.name = 'CompileError';
  }
}

/** Accumulates diagnostics during a compile and can format them for a terminal. */
/** Item #2: `#` private members are lowered to contract-scoped internal names `$p$<Contract>$<name>`
 *  (src/compile.ts). Any diagnostic that echoes such a name back to the user should show the original
 *  `#<name>` spelling, not the internal mangle. This is presentation-only; it never changes a code,
 *  span, or accept/reject decision. */
export function demanglePrivateName(message: string): string {
  return message.replace(/\$p\$[A-Za-z0-9_]+\$([A-Za-z0-9_]+)/g, '#$1');
}

/** v3 module scoping: a DEP file's top-level declarations are alpha-renamed to `$m<N>$<name>`
 *  (src/imports.ts). Strip the scope mangle wherever a name reaches the user or the CHAIN: diagnostic
 *  messages, error/event signatures (keccak selectors/topics), and external-library link symbols / object
 *  names - the chain and the user see source spellings, only the compiler internals see scoped names.
 *  Must run BEFORE demanglePrivateName on messages: a `#`-private inside a renamed class mangles to
 *  `$p$$m<N>$C$x`, and stripping `$m<N>$` first restores the `$p$C$x` shape that demangle recognizes. */
export function demangleModuleName(name: string): string {
  return name.replace(/\$m\d+\$/g, '');
}

function demangleMessage(message: string): string {
  return demanglePrivateName(demangleModuleName(message));
}

export class DiagnosticBag {
  readonly items: Diagnostic[] = [];

  constructor(
    private readonly sourceFile: ts.SourceFile,
    private readonly fileName: string,
  ) {}

  private at(node: ts.Node): Pick<Diagnostic, 'line' | 'column' | 'length'> {
    const start = node.getStart(this.sourceFile);
    const { line, character } = this.sourceFile.getLineAndCharacterOfPosition(start);
    return { line: line + 1, column: character + 1, length: node.getWidth(this.sourceFile) };
  }

  /** True if an identical diagnostic (same severity, code, message, and source span) is already recorded.
   *  Speculative resolvers (e.g. resolveArrayExpr) may run for the same node several times in one analysis;
   *  collapsing exact duplicates keeps the reported set clean without changing any accept/reject decision. */
  private isDuplicate(
    severity: Severity,
    code: string,
    message: string,
    loc: Pick<Diagnostic, 'line' | 'column' | 'length'>,
  ): boolean {
    return this.items.some(
      (d) =>
        d.severity === severity && d.code === code && d.message === message && d.line === loc.line && d.column === loc.column,
    );
  }

  error(node: ts.Node, code: string, message: string): void {
    message = demangleMessage(message);
    const loc = this.at(node);
    if (this.isDuplicate('error', code, message, loc)) return;
    this.items.push({ severity: 'error', code, message, file: this.fileName, ...loc });
  }

  /** Emit an error at a RAW source position (start offset + length) rather than a node. Used for
   *  TS parse (syntactic) diagnostics, which carry a position but no analyzer AST node. */
  errorAtPos(start: number, length: number, code: string, message: string): void {
    message = demangleMessage(message);
    const { line, character } = this.sourceFile.getLineAndCharacterOfPosition(start);
    const loc = { line: line + 1, column: character + 1, length: Math.max(1, length) };
    if (this.isDuplicate('error', code, message, loc)) return;
    this.items.push({ severity: 'error', code, message, file: this.fileName, ...loc });
  }

  warn(node: ts.Node, code: string, message: string): void {
    message = demangleMessage(message);
    const loc = this.at(node);
    if (this.isDuplicate('warning', code, message, loc)) return;
    this.items.push({ severity: 'warning', code, message, file: this.fileName, ...loc });
  }

  get hasErrors(): boolean {
    return this.items.some((d) => d.severity === 'error');
  }

  /** Throw a CompileError if any error-severity diagnostics were collected. */
  throwIfErrors(): void {
    if (this.hasErrors) throw new CompileError(this.items);
  }
}

/** Render a diagnostic the way tsc/clang do: file:line:col, a caret line. */
export function formatDiagnostic(d: Diagnostic, source?: string): string {
  const head = `${d.file}:${d.line}:${d.column} - ${d.severity} ${d.code}: ${d.message}`;
  if (!source) return head;
  const srcLine = source.split('\n')[d.line - 1] ?? '';
  const caret = ' '.repeat(Math.max(0, d.column - 1)) + '^'.repeat(Math.max(1, d.length));
  return `${head}\n\n  ${srcLine}\n  ${caret}\n`;
}

export function formatDiagnostics(diags: Diagnostic[], source?: string): string {
  return diags.map((d) => formatDiagnostic(d, source)).join('\n');
}
