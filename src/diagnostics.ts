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
    super(
      `JETH compilation failed with ${diagnostics.filter((d) => d.severity === 'error').length} error(s)`,
    );
    this.name = 'CompileError';
  }
}

/** Accumulates diagnostics during a compile and can format them for a terminal. */
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

  error(node: ts.Node, code: string, message: string): void {
    this.items.push({ severity: 'error', code, message, file: this.fileName, ...this.at(node) });
  }

  warn(node: ts.Node, code: string, message: string): void {
    this.items.push({ severity: 'warning', code, message, file: this.fileName, ...this.at(node) });
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
