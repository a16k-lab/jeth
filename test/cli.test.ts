import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runCli } from '../src/cli.js';

interface Invocation {
  code: number;
  stdout: string;
  stderr: string;
}

describe('jethc CLI', () => {
  let workdir: string;

  beforeEach(() => {
    workdir = mkdtempSync(join(tmpdir(), 'jeth-cli-test-'));
  });

  afterEach(() => {
    rmSync(workdir, { recursive: true, force: true });
  });

  const write = (name: string, source: string): string => {
    const path = join(workdir, name);
    writeFileSync(path, source);
    return path;
  };

  const invoke = (args: string[], stdin = ''): Invocation => {
    let stdout = '';
    let stderr = '';
    const code = runCli(args, {
      cwd: workdir,
      stdout: (text) => {
        stdout += text;
      },
      stderr: (text) => {
        stderr += text;
      },
      readStdin: () => stdin,
    });
    return { code, stdout, stderr };
  };

  const SIMPLE = `class Counter {
  count: u256;
  increment(): External<void> { this.count += 1n; }
  get current(): External<u256> { return this.count; }
}`;

  it('prints help and version without requiring an entry file', () => {
    const help = invoke(['--help']);
    expect(help.code).toBe(0);
    expect(help.stdout).toContain('Usage:');
    expect(help.stdout).toContain('--standard-json');

    const version = invoke(['--version']);
    expect(version.code).toBe(0);
    expect(version.stdout).toMatch(/^jethc 0\.1\.0\nsolc 0\.8\.35/);
  });

  it('rejects unknown options and missing option values with exit code 2', () => {
    expect(invoke(['--not-real']).code).toBe(2);
    expect(invoke(['--not-real']).stderr).toContain("unknown option '--not-real'");
    expect(invoke(['Counter.jeth', '-o']).code).toBe(2);
    expect(invoke(['Counter.jeth', '-o', '--abi']).code).toBe(2);
  });

  it('reports missing input files cleanly without a Node stack trace', () => {
    const result = invoke(['Missing.jeth']);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('cannot read entry file');
    expect(result.stderr).not.toContain('node:fs');
    expect(result.stderr).not.toContain(' at ');
  });

  it('compiles a single file and prints a stable summary', () => {
    write('Counter.jeth', SIMPLE);
    const result = invoke(['Counter.jeth']);
    expect(result.code).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain('compiled Counter:');
    expect(result.stdout).toContain('runtime bytes:');
  });

  it('loads relative filesystem imports recursively', () => {
    write('Lib.jeth', `export static class Lib { one(): u256 { return 1n; } }`);
    write(
      'App.jeth',
      `import { Lib } from "./Lib.jeth";
class App { get value(): External<u256> { return Lib.one(); } }`,
    );
    const result = invoke(['App.jeth']);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('compiled App:');
  });

  it('reports missing imported files as clean input errors', () => {
    write(
      'App.jeth',
      `import { Missing } from "./Missing.jeth";
class App { get value(): External<u256> { return Missing.one(); } }`,
    );
    const result = invoke(['App.jeth']);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("cannot read import './Missing.jeth'");
    expect(result.stderr).not.toContain('node:fs');
    expect(result.stderr).not.toContain(' at ');
  });

  it('writes complete artifact sets for every contract in a source unit', () => {
    write(
      'Multi.jeth',
      `class Alpha { get value(): External<u256> { return 1n; } }
class Beta { get value(): External<u256> { return 2n; } }`,
    );
    const result = invoke(['Multi.jeth', '--output', 'artifacts']);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('wrote 12 artifact files');
    const files = readdirSync(join(workdir, 'artifacts')).sort();
    for (const name of ['Alpha', 'Beta']) {
      expect(files).toEqual(
        expect.arrayContaining([
          `${name}.abi.json`,
          `${name}.bin`,
          `${name}.runtime.bin`,
          `${name}.yul`,
          `${name}.layout.json`,
          `${name}.metadata.json`,
        ]),
      );
    }
  });

  it('selects one contract and rejects an unknown contract name', () => {
    write(
      'Multi.jeth',
      `class Alpha { get value(): External<u256> { return 1n; } }
class Beta { get value(): External<u256> { return 2n; } }`,
    );
    const selected = invoke(['Multi.jeth', '--contract', 'Beta', '-o', 'selected']);
    expect(selected.code).toBe(0);
    expect(existsSync(join(workdir, 'selected', 'Beta.abi.json'))).toBe(true);
    expect(existsSync(join(workdir, 'selected', 'Alpha.abi.json'))).toBe(false);

    const missing = invoke(['Multi.jeth', '--contract', 'Missing']);
    expect(missing.code).toBe(2);
    expect(missing.stderr).toContain('available contracts: Alpha, Beta');
  });

  it('emits structured success and failure results with --json', () => {
    write('Counter.jeth', SIMPLE);
    const success = invoke(['Counter.jeth', '--json']);
    expect(success.code).toBe(0);
    expect(success.stderr).toBe('');
    const successValue = JSON.parse(success.stdout) as any;
    expect(successValue.ok).toBe(true);
    expect(successValue.schemaVersion).toBe(1);
    expect(successValue.contracts.map((item: any) => item.name)).toEqual(['Counter']);

    write('Broken.jeth', `class Broken { get value(): External<u256> { return missing; } }`);
    const failure = invoke(['Broken.jeth', '--json']);
    expect(failure.code).toBe(1);
    expect(failure.stderr).toBe('');
    const failureValue = JSON.parse(failure.stdout) as any;
    expect(failureValue.ok).toBe(false);
    expect(failureValue.error.kind).toBe('compile');
    expect(failureValue.error.diagnostics.length).toBeGreaterThan(0);

    const usageFailure = invoke(['--json', '--not-real']);
    expect(usageFailure.code).toBe(2);
    expect(usageFailure.stderr).toBe('');
    expect(JSON.parse(usageFailure.stdout).error.kind).toBe('usage');
  });

  it('reports invalid backend targets without exposing an internal stack', () => {
    write('Counter.jeth', SIMPLE);
    const result = invoke(['Counter.jeth', '--evm-version', 'not-an-evm']);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('Invalid EVM version');
    expect(result.stderr).not.toContain(' at ');
  });

  it('loads a project configuration with CLI options taking precedence', () => {
    write('Counter.jeth', SIMPLE);
    writeFileSync(
      join(workdir, 'jeth.config.json'),
      JSON.stringify({ entry: 'Counter.jeth', outDir: 'configured', evmVersion: 'cancun', emit: ['abi', 'metadata'] }),
    );
    const result = invoke(['--config', 'jeth.config.json', '--emit', 'abi']);
    expect(result.code).toBe(0);
    expect(existsSync(join(workdir, 'configured', 'Counter.abi.json'))).toBe(true);
    expect(existsSync(join(workdir, 'configured', 'Counter.metadata.json'))).toBe(false);
  });

  it('compiles multi-file standard JSON and always responds with JSON', () => {
    const input = JSON.stringify({
      language: 'JETH',
      sources: {
        'src/Lib.jeth': { content: `export static class Lib { one(): u256 { return 1n; } }` },
        'src/App.jeth': {
          content: `import { Lib } from "./Lib.jeth";
class App { get value(): External<u256> { return Lib.one(); } }`,
        },
      },
      settings: { entry: 'src/App.jeth', contract: 'App', evmVersion: 'cancun' },
    });
    const result = invoke(['--standard-json'], input);
    expect(result.code).toBe(0);
    expect(result.stderr).toBe('');
    const value = JSON.parse(result.stdout) as any;
    expect(value.ok).toBe(true);
    expect(value.contracts[0].name).toBe('App');

    const invalid = invoke(['--standard-json'], '{');
    expect(invalid.code).toBe(2);
    expect(JSON.parse(invalid.stdout).error.kind).toBe('input');
  });

  it('prints source-spanned diagnostics in human mode', () => {
    write('Broken.jeth', `class Broken { get value(): External<u256> { return missing; } }`);
    const result = invoke(['Broken.jeth']);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('Broken.jeth:1:');
    expect(result.stderr).toContain('return missing');
    expect(result.stderr).toContain('^');
  });

  it('writes newline-terminated bytecode files', () => {
    write('Counter.jeth', SIMPLE);
    const result = invoke(['Counter.jeth', '-o', 'artifacts', '--emit', 'bin']);
    expect(result.code).toBe(0);
    expect(readFileSync(join(workdir, 'artifacts', 'Counter.bin'), 'utf8')).toMatch(/^[0-9a-f]+\n$/);
    expect(readFileSync(join(workdir, 'artifacts', 'Counter.runtime.bin'), 'utf8')).toMatch(/^[0-9a-f]+\n$/);
  });
});
