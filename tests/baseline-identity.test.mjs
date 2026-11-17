import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import {
  assignFingerprints,
  relativeToRoot,
  resolveRepoRoot,
  readBaseline,
  writeBaseline,
} from '../dist/core/baseline.js';
import { gitProject } from './helpers.mjs';

const scratch = () => mkdtempSync(join(tmpdir(), 'rnsec-baseline-'));

const finding = (overrides = {}) => ({
  ruleId: 'INSECURE_HTTP_URL',
  description: 'Insecure http:// URL',
  severity: 'MEDIUM',
  filePath: '/project/src/a.js',
  line: 1,
  ...overrides,
});

test('relativeToRoot uses lexical, forward-slash paths and never realpath', () => {
  const root = resolve('/project');
  assert.equal(relativeToRoot(join(root, 'src', 'a.js'), root), 'src/a.js');
  // Backslash separators are normalized even on POSIX-style input
  assert.equal(relativeToRoot(root + sep + 'src' + sep + 'b.js', root), 'src/b.js');
  // Paths outside the root fall back to a normalized absolute identity
  const outside = relativeToRoot(resolve('/elsewhere/c.js'), root);
  assert.match(outside, /^\/?elsewhere\/c\.js$/);
  assert.doesNotMatch(outside, /\\/);
});

test('resolveRepoRoot returns the logical root when scanning through a symlinked root', async () => {
  const dir = gitProject({ 'src/a.js': "fetch('http://x.example.com');\n" }, { commit: true });
  const link = join(scratch(), 'linked-root');
  symlinkSync(dir, link, 'dir');

  const physical = await resolveRepoRoot(dir);
  const logical = await resolveRepoRoot(link);
  assert.equal(physical, resolve(dir));
  assert.equal(logical, resolve(link), 'the symlinked path is preserved, not realpath-ed');

  // A finding reached through the logical root is identified repo-relative
  const viaLink = {
    ...finding(),
    filePath: join(link, 'src/a.js'),
  };
  const viaReal = {
    ...finding(),
    filePath: join(dir, 'src/a.js'),
  };
  assignFingerprints([viaLink], logical);
  assignFingerprints([viaReal], physical);
  assert.equal(viaLink.fingerprint, viaReal.fingerprint);
});

test('resolveRepoRoot on a symlinked subdirectory rebuilds the logical repo root', async () => {
  const repo = gitProject({ 'packages/app/src/a.js': "fetch('http://x.example.com');\n" }, { commit: true });
  const link = join(scratch(), 'app-link');
  symlinkSync(join(repo, 'packages/app'), link, 'dir');
  const root = await resolveRepoRoot(link);
  // Two levels (packages/app) separate the scan root from the git root, so the
  // logical repo root is two levels above the link; identity stays repo-relative.
  assert.equal(root, resolve(link, '..', '..'));
  const identity = relativeToRoot(join(link, 'src/a.js'), root);
  assert.match(identity, /app-link\/src\/a\.js$/);
  assert.doesNotMatch(identity, /\\/);
});

test('fingerprint ignores comments but not the flagged source text', () => {
  const dir = scratch();
  mkdirSync(join(dir, 'src'), { recursive: true });
  const file = join(dir, 'src', 'a.js');
  const flagged = "fetch('http://api.example.com/plain', { timeout: 5 });";
  writeFileSync(file, `// header one\n${flagged}\n`);
  const f1 = finding({ filePath: file, line: 2 });
  assignFingerprints([f1], dir);

  writeFileSync(file, `// a totally different header\n${flagged}\n`);
  const f2 = finding({ filePath: file, line: 2 });
  assignFingerprints([f2], dir);
  assert.equal(f2.fingerprint, f1.fingerprint, 'comment-only edit keeps the identity');

  writeFileSync(file, `// a totally different header\n${flagged.replace('timeout: 5', 'timeout: 9')}\n`);
  const f3 = finding({ filePath: file, line: 2 });
  assignFingerprints([f3], dir);
  assert.notEqual(f3.fingerprint, f1.fingerprint, 'a source-line change produces a new identity');
});

test('comment markers inside strings are preserved (URLs are not comments)', () => {
  const dir = scratch();
  mkdirSync(join(dir, 'src'), { recursive: true });
  const file = join(dir, 'src', 'a.js');
  writeFileSync(file, "const u = 'http://example.com/a#frag'; // trailing\n");
  const f1 = finding({ filePath: file });
  assignFingerprints([f1], dir);
  writeFileSync(file, "const u = 'http://example.com/a#frag'; // changed trailing\n");
  const f2 = finding({ filePath: file });
  assignFingerprints([f2], dir);
  assert.equal(f2.fingerprint, f1.fingerprint);
});

test('repeated identical lines still get distinct fingerprints via the occurrence index', () => {
  const dir = scratch();
  mkdirSync(join(dir, 'src'), { recursive: true });
  const file = join(dir, 'src', 'a.js');
  const line = "fetch('http://api.example.com/plain', { timeout: 5 });";
  writeFileSync(file, `${line}\n${line}\n`);
  const findings = [
    finding({ filePath: file, line: 1 }),
    finding({ filePath: file, line: 2 }),
  ];
  assignFingerprints(findings, dir);
  assert.equal(new Set(findings.map(f => f.fingerprint)).size, 2);
});

test('writeBaseline emits v2 and readBaseline accepts both v1 and v2', async () => {
  const dir = scratch();
  const f = finding();
  assignFingerprints([f], '/project');
  const file = join(dir, 'baseline.json');
  await writeBaseline(file, [f], '/project');
  const written = JSON.parse(readFileSync(file, 'utf8'));
  assert.equal(written.version, 2);

  const v2 = await readBaseline(file);
  assert.equal(v2.version, 2);
  assert.ok(v2.fingerprints.has(f.fingerprint));

  // Same payload relabeled as the legacy format stays readable and reports v1
  const legacy = join(dir, 'legacy.json');
  writeFileSync(legacy, JSON.stringify({ ...written, version: 1 }));
  const v1 = await readBaseline(legacy);
  assert.equal(v1.version, 1);
  assert.ok(v1.fingerprints.has(f.fingerprint));

  await assert.rejects(() => readBaseline(join(dir, 'missing.json')), /Could not read baseline/);
  const bogus = join(dir, 'bogus.json');
  writeFileSync(bogus, '{"hello":1}');
  await assert.rejects(() => readBaseline(bogus), /not a valid rnsec baseline/);
});
