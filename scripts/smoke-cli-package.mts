import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
  name: string;
  version: string;
};
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const temporary = mkdtempSync(join(tmpdir(), 'jeth-package-smoke-'));

function run(command: string, args: string[], cwd: string): string {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    env: process.env,
  });
  if (result.status !== 0) {
    throw new Error(
      [`${command} ${args.join(' ')} failed with exit code ${result.status ?? 'unknown'}`, result.stdout, result.stderr]
        .filter(Boolean)
        .join('\n'),
    );
  }
  return result.stdout;
}

try {
  run(npm, ['pack', '--pack-destination', temporary], root);
  const tarball = join(temporary, `${manifest.name}-${manifest.version}.tgz`);
  const installRoot = join(temporary, 'install');
  run(npm, ['install', '--ignore-scripts', '--prefix', installRoot, tarball], root);

  const executable = join(installRoot, 'node_modules', '.bin', process.platform === 'win32' ? 'jethc.cmd' : 'jethc');
  const version = run(executable, ['--version'], root);
  if (!version.includes(`jethc ${manifest.version}`))
    throw new Error('installed jethc reported the wrong package version');
  if (!version.includes('solc 0.8.35+')) throw new Error('installed jethc did not resolve the pinned solc 0.8.35');

  const compiled = JSON.parse(run(executable, ['examples/Counter.jeth', '--json'], root)) as {
    ok?: boolean;
    contracts?: { name?: string }[];
  };
  if (!compiled.ok || compiled.contracts?.[0]?.name !== 'Counter') {
    throw new Error('installed jethc failed the Counter package smoke compile');
  }

  process.stdout.write(`package smoke passed: jethc ${manifest.version}, solc 0.8.35, Counter compiled\n`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
