import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { scan, byRule, repoRoot, untrackedProject } from './helpers.mjs';

const dist = file => pathToFileURL(resolve(repoRoot, 'dist', file)).href;
const { parseSuppressions, isSuppressed } = await import(dist('utils/suppression.js'));
const { RuleRegistry } = await import(dist('core/ruleRegistry.js'));

const bin = resolve(repoRoot, process.env.RNSEC_BIN ?? 'dist/index.js');
const runCli = (args, opts = {}) =>
  spawnSync('node', [bin, 'scan', ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: 1 }, ...opts });
const scratch = () => mkdtempSync(join(tmpdir(), 'rnsec-supp-'));

// The real CLI registers every production rule; for module-level checks we register a small stand-in.
RuleRegistry.shared().register(
  ['HTTP_RULE', 'TIMEOUT_RULE'].map(id => ({ id, description: id, severity: 'LOW', fileTypes: [], apply: async () => [] }))
);

const httpLine = "fetch('http://partner.example-corp.com/a');\n";

// ---- AST comment binding: markers inside string/template literals are not directives ----

test('a rnsec-ignore marker inside a string literal cannot suppress (AST binding)', () => {
  const dir = untrackedProject({
    'src/a.js': "const note = '// rnsec-ignore: INSECURE_HTTP_URL fake';\n" + httpLine,
  });
  assert.ok(byRule(scan(dir), 'INSECURE_HTTP_URL').length > 0);
});

test('a rnsec-ignore marker inside a template literal cannot suppress', () => {
  const dir = untrackedProject({
    'src/a.js': 'const t = `// rnsec-ignore: INSECURE_HTTP_URL`;\n' + httpLine,
  });
  assert.ok(byRule(scan(dir), 'INSECURE_HTTP_URL').length > 0);
});

test('homoglyph/full-width punctuation makes the directive malformed and fails closed', () => {
  const fullWidth = untrackedProject({
    'src/a.js': '// rnsec-ignore： INSECURE_HTTP_URL\n' + httpLine,
  });
  assert.ok(byRule(scan(fullWidth), 'INSECURE_HTTP_URL').length > 0);

  const cyrillicId = untrackedProject({
    'src/a.js': '// rnsec-ignore: INSECURE_HTTP_UR\u0410\n' + httpLine,
  });
  assert.ok(byRule(scan(cyrillicId), 'INSECURE_HTTP_URL').length > 0);
});

test('non-JS files only accept directives inside their comment syntax', () => {
  const javaString = parseSuppressions('String x = "// rnsec-ignore: HTTP_RULE";\nfoo();\n', 'A.java');
  assert.equal(javaString.byLine.size, 0);
  const javaComment = parseSuppressions('// rnsec-ignore: HTTP_RULE reason\nfoo();\n', 'A.java');
  assert.ok(isSuppressed(javaComment, 'HTTP_RULE', 2));

  const xmlText = parseSuppressions('<manifest>rnsec-ignore: HTTP_RULE</manifest>\n', 'AndroidManifest.xml');
  assert.equal(xmlText.byLine.size, 0);
  const xmlComment = parseSuppressions('<!-- rnsec-ignore: HTTP_RULE -->\n', 'AndroidManifest.xml');
  assert.ok(isSuppressed(xmlComment, 'HTTP_RULE', 1));

  const jsonValue = parseSuppressions('{\n  "x": "// rnsec-ignore: HTTP_RULE"\n}\n', 'package.json');
  assert.equal(jsonValue.byLine.size, 0);
});

// ---- Malformed / unknown / conflicting directives fail closed ----

test('unknown rule id, malformed version and malformed expiry fail closed', () => {
  for (const directive of [
    '// rnsec-ignore: NOT_A_REAL_RULE\n',
    '// rnsec-ignore: HTTP_RULE@2.0\n',
    '// rnsec-ignore: HTTP_RULE until=not-a-date\n',
  ]) {
    const map = parseSuppressions(directive + 'foo();\n', 'a.js');
    assert.equal(isSuppressed(map, 'HTTP_RULE', 2), false, directive);
    assert.equal(map.warnings.length, 1);
  }
});

test('an expired directive fails closed; a future expiry still suppresses', () => {
  const expired = parseSuppressions('// rnsec-ignore: HTTP_RULE until=2020-01-01\nfoo();\n', 'a.js');
  assert.equal(isSuppressed(expired, 'HTTP_RULE', 2), false);

  const future = parseSuppressions('// rnsec-ignore: HTTP_RULE until=2099-01-01\nfoo();\n', 'a.js');
  assert.ok(isSuppressed(future, 'HTTP_RULE', 2));
});

test('conflicting directives on the same line/rule fail closed; identical duplicates stay valid', () => {
  const conflict = parseSuppressions(
    '// rnsec-ignore: HTTP_RULE@1.0.0\n// rnsec-ignore: HTTP_RULE@1.1.0\nfoo();\n',
    'a.js'
  );
  assert.equal(isSuppressed(conflict, 'HTTP_RULE', 3), false);
  assert.ok(conflict.warnings.some(w => /conflicting/.test(w.message)));

  const duplicate = parseSuppressions('// rnsec-ignore: HTTP_RULE\n// rnsec-ignore: HTTP_RULE\nfoo();\n', 'a.js');
  assert.ok(isSuppressed(duplicate, 'HTTP_RULE', 3));
});

test('a nested marker inside one comment poisons the whole directive (fail closed)', () => {
  const map = parseSuppressions('foo(); // rnsec-ignore: HTTP_RULE // rnsec-ignore: BROKEN_X\nbar();\n', 'a.js');
  assert.equal(isSuppressed(map, 'HTTP_RULE', 1), false);
});

// ---- Rule version binding ----

test('a current-version pin suppresses; a stale pin fails closed', () => {
  const current = parseSuppressions('// rnsec-ignore: HTTP_RULE@1.0.0\nfoo();\n', 'a.js');
  assert.ok(isSuppressed(current, 'HTTP_RULE', 2));

  const stale = parseSuppressions('// rnsec-ignore: HTTP_RULE@0.9.0\nfoo();\n', 'a.js');
  assert.equal(isSuppressed(stale, 'HTTP_RULE', 2), false);
});

test('legacy comment-only and trailing directives keep their line semantics', () => {
  const ownLine = parseSuppressions('// rnsec-ignore: HTTP_RULE reason\nfoo();\n', 'a.js');
  assert.ok(isSuppressed(ownLine, 'HTTP_RULE', 2));
  assert.equal(isSuppressed(ownLine, 'HTTP_RULE', 3), false);

  const trailing = parseSuppressions("foo(); // rnsec-ignore: HTTP_RULE\nbar();\n", 'a.js');
  assert.ok(isSuppressed(trailing, 'HTTP_RULE', 1));
  assert.equal(isSuppressed(trailing, 'HTTP_RULE', 2), false);
});

// ---- Baselines: version-bound, expiry-aware, fail closed ----

test('legacy baselines without rule versions are refused', () => {
  const dir = untrackedProject({ 'src/a.js': httpLine });
  const baseline = join(dir, 'legacy.json');
  writeFileSync(
    baseline,
    JSON.stringify({
      version: 1,
      tool: 'rnsec',
      generatedAt: new Date().toISOString(),
      findings: [
        { fingerprint: 'a'.repeat(64), ruleId: 'INSECURE_HTTP_URL', file: 'src/a.js', description: 'x' },
      ],
    })
  );
  const r = runCli(['-p', dir, '--json', '--baseline', baseline]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /regenerate/);
});

test('a baseline entry only hides a finding when rule id and version match', () => {
  const dir = untrackedProject({ 'src/a.js': httpLine });
  const fingerprint = scan(dir).findings.find(f => f.ruleId === 'INSECURE_HTTP_URL').fingerprint;

  const staleVersion = join(dir, 'stale.json');
  writeFileSync(
    staleVersion,
    JSON.stringify({
      version: 1,
      tool: 'rnsec',
      generatedAt: new Date().toISOString(),
      findings: [
        { fingerprint, ruleId: 'INSECURE_HTTP_URL', ruleVersion: '9.9.9', file: 'src/a.js', description: 'x' },
      ],
    })
  );
  assert.ok(byRule(scan(dir, ['--baseline', staleVersion]), 'INSECURE_HTTP_URL').length > 0);

  const forgedRule = join(dir, 'forged.json');
  writeFileSync(
    forgedRule,
    JSON.stringify({
      version: 1,
      tool: 'rnsec',
      generatedAt: new Date().toISOString(),
      findings: [
        { fingerprint, ruleId: 'NO_REQUEST_TIMEOUT', ruleVersion: '1.0.0', file: 'src/a.js', description: 'x' },
      ],
    })
  );
  assert.ok(byRule(scan(dir, ['--baseline', forgedRule]), 'INSECURE_HTTP_URL').length > 0);
});

test('expired and malformed baseline entries fail closed', () => {
  const dir = untrackedProject({ 'src/a.js': httpLine });
  const fingerprint = scan(dir).findings.find(f => f.ruleId === 'INSECURE_HTTP_URL').fingerprint;

  const expired = join(dir, 'expired.json');
  writeFileSync(
    expired,
    JSON.stringify({
      version: 1,
      tool: 'rnsec',
      generatedAt: new Date().toISOString(),
      findings: [
        {
          fingerprint,
          ruleId: 'INSECURE_HTTP_URL',
          ruleVersion: '1.0.0',
          expiresOn: '2020-01-01',
          file: 'src/a.js',
          description: 'x',
        },
      ],
    })
  );
  assert.ok(byRule(scan(dir, ['--baseline', expired]), 'INSECURE_HTTP_URL').length > 0);

  const malformed = join(dir, 'malformed.json');
  writeFileSync(
    malformed,
    JSON.stringify({
      version: 1,
      tool: 'rnsec',
      generatedAt: new Date().toISOString(),
      findings: [
        { fingerprint: 'not-a-hash', ruleId: 'INSECURE_HTTP_URL', ruleVersion: '1.0.0', file: 'src/a.js' },
      ],
    })
  );
  const r = runCli(['-p', dir, '--json', '--baseline', malformed]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /malformed fingerprint/);
});

test('a freshly written baseline still hides the same finding (backward-compatible flow)', () => {
  const dir = untrackedProject({ 'src/a.js': httpLine });
  const baseline = join(dir, 'fresh.json');
  assert.equal(runCli(['-p', dir, '--json', '--write-baseline', baseline]).status, 0);
  const written = JSON.parse(readFileSync(baseline, 'utf8'));
  const entry = written.findings.find(f => f.ruleId === 'INSECURE_HTTP_URL');
  assert.equal(entry.ruleVersion, '1.0.0');
  const r = runCli(['-p', dir, '--json', '--fail-on', 'low', '--baseline', baseline]);
  const result = JSON.parse(r.stdout);
  assert.equal(byRule(result, 'INSECURE_HTTP_URL').length, 0);
});

// ---- SARIF identity ----

test('SARIF results bind rule@version identities and rules carry versions', () => {
  const dir = untrackedProject({ 'src/a.js': httpLine });
  const out = join(scratch(), 'out.sarif');
  runCli(['-p', dir, '--json', '--sarif', out]);
  const sarif = JSON.parse(readFileSync(out, 'utf8'));
  const run0 = sarif.runs[0];
  for (const result of run0.results) {
    assert.match(result.partialFingerprints['rnsec/ruleVersion'], /^[A-Z][A-Z0-9_]*@\d+\.\d+\.\d+/);
    assert.equal(result.partialFingerprints['rnsec/ruleVersion'], `${result.ruleId}@${result.properties.ruleVersion}`);
  }
  for (const rule of run0.tool.driver.rules) {
    assert.match(rule.properties.version, /^\d+\.\d+\.\d+/);
  }
});

// ---- CLI diagnostics ----

test('malformed directives print a stderr warning without polluting --json stdout', () => {
  const dir = untrackedProject({ 'src/a.js': '// rnsec-ignore: NOT_A_REAL_RULE\n' + httpLine });
  const r = runCli(['-p', dir, '--json']);
  assert.doesNotThrow(() => JSON.parse(r.stdout));
  assert.match(r.stderr, /malformed/);

  const silent = runCli(['-p', dir, '--json', '--silent']);
  assert.doesNotMatch(silent.stderr, /malformed/);
});
