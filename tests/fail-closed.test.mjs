import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { symlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { RuleEngine } from '../dist/core/ruleEngine.js';
import { MarkdownReporter } from '../dist/core/markdownReporter.js';
import { repoRoot, gitProject, untrackedProject } from './helpers.mjs';

const cli = resolve(repoRoot, process.env.RNSEC_BIN ?? 'dist/index.js');
const run = (dir, args = []) =>
  spawnSync('node', [cli, 'scan', '--path', dir, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });

const crashingGroup = {
  category: 'TEST',
  rules: [
    { id: 'CRASH_APPLY', description: 'd', severity: 'LOW', fileTypes: ['.ts'], apply: async () => { throw new Error('boom'); } },
    { id: 'CRASH_BEGIN', description: 'd', severity: 'LOW', fileTypes: ['.ts'], beginScan: () => { throw new Error('boom'); }, apply: async () => [] },
    { id: 'CRASH_FINALIZE', description: 'd', severity: 'LOW', fileTypes: ['.ts'], apply: async () => [], finalize: async () => { throw new Error('boom'); } },
  ],
};

test('a crashing rule is recorded per phase instead of vanishing silently', async () => {
  const dir = untrackedProject({ 'a.ts': 'export const a = 1;\n' });
  const engine = new RuleEngine();
  engine.registerRuleGroup(crashingGroup);
  const r = await engine.runRulesOnProject(dir);
  const phases = r.ruleErrors.map(e => `${e.ruleId}:${e.phase}`).sort();
  assert.deepEqual(phases, ['CRASH_APPLY:apply', 'CRASH_BEGIN:beginScan', 'CRASH_FINALIZE:finalize']);
  assert.equal(r.ruleErrors.find(e => e.ruleId === 'CRASH_APPLY').message, 'boom');
});

test('a healthy scan reports no ruleErrors', async () => {
  const dir = untrackedProject({ 'a.ts': 'export const a = 1;\n' });
  const engine = new RuleEngine();
  engine.registerRuleGroup({
    category: 'TEST',
    rules: [{ id: 'OK', description: 'd', severity: 'LOW', fileTypes: ['.ts'], apply: async () => [] }],
  });
  const r = await engine.runRulesOnProject(dir);
  assert.equal(r.ruleErrors, undefined);
  assert.equal(r.skippedFiles, undefined);
});

test('an unreadable file fails the scan: exit code, JSON evidence, no clean summary', () => {
  const repo = gitProject({ 'a.ts': 'export const a = 1;\n' });
  symlinkSync(join(repo, 'nowhere'), join(repo, 'broken.ts'));
  execFileSync('git', ['add', '-A'], { cwd: repo, stdio: 'pipe' });

  const json = run(repo, ['--changed-files', 'HEAD', '--json']);
  assert.notEqual(json.status, 0, 'a skipped file must fail the scan');
  const result = JSON.parse(json.stdout);
  assert.equal(result.skippedFiles, 1);
  assert.match(json.stderr, /1 file\(s\) skipped due to read errors/);

  const normal = run(repo, ['--changed-files', 'HEAD']);
  assert.notEqual(normal.status, 0);
  assert.match(normal.stdout, /SCAN DID NOT COMPLETE/);
  assert.doesNotMatch(normal.stdout, /NO SECURITY VULNERABILITIES DETECTED|RISK LEVEL: SECURE/);
});

test('clean projects stay clean: exit 0, no degradation fields, SECURE summary intact', () => {
  const dir = untrackedProject({ 'src/a.ts': 'export const a = 1;\n' });
  const json = run(dir, ['--json']);
  assert.equal(json.status, 0);
  const result = JSON.parse(json.stdout);
  assert.equal(result.skippedFiles, undefined);
  assert.equal(result.ruleErrors, undefined);

  const normal = run(dir, []);
  assert.equal(normal.status, 0);
  assert.match(normal.stdout, /NO SECURITY VULNERABILITIES DETECTED/);
  assert.match(normal.stdout, /RISK LEVEL: SECURE/);
});

test('markdown summary never claims SECURE for an incomplete scan', () => {
  const base = { findings: [], scannedFiles: 3, duration: 1, timestamp: new Date() };
  const skipped = new MarkdownReporter().generateReport({ ...base, skippedFiles: 1 });
  assert.match(skipped, /Scan incomplete/);
  assert.doesNotMatch(skipped, /Risk Level: SECURE/);

  const crashed = new MarkdownReporter().generateReport({
    ...base,
    ruleErrors: [{ ruleId: 'X', phase: 'apply', message: 'boom' }],
  });
  assert.match(crashed, /rule\(s\) failed to execute: X/);
  assert.doesNotMatch(crashed, /Risk Level: SECURE/);

  const clean = new MarkdownReporter().generateReport(base);
  assert.match(clean, /Risk Level: SECURE/);
});
