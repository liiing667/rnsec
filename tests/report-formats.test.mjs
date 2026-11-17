import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { repoRoot, untrackedProject, fakeSecret } from './helpers.mjs';

const bin = resolve(repoRoot, process.env.RNSEC_BIN ?? 'dist/index.js');
const scratch = () => mkdtempSync(join(tmpdir(), 'rnsec-reports-'));

// Ampersand in the file name proves paths are escaped in HTML/Markdown and stay
// repo-root-relative in every format; duplicated lines exercise HTML grouping.
const projectFiles = {
  'src/a&b.ts':
    "fetch('http://example.com/x?a=1&b=2');\n" +
    "fetch('http://example.com/x?a=1&b=2');\n" +
    `const key = "${fakeSecret('stripe_live')}";\n`,
};

const runReports = () => {
  const dir = untrackedProject(projectFiles);
  const out = scratch();
  const html = join(out, 'report.html');
  const md = join(out, 'report.md');
  const sarif = join(out, 'report.sarif');
  const proc = spawnSync(
    'node',
    [bin, 'scan', '-p', dir, '--html', html, '--md', md, '--sarif', sarif, '--fail-on', 'none'],
    { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } },
  );
  assert.equal(proc.status, 0, proc.stderr);
  return {
    dir,
    html: readFileSync(html, 'utf8'),
    markdown: readFileSync(md, 'utf8'),
    sarif: JSON.parse(readFileSync(sarif, 'utf8')),
  };
};

const stripTags = htmlText =>
  htmlText
    .replace(/<[^>]+>/g, '\n')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'");

/** Slice from the findings container up to its closing tag (the page footer follows it). */
const findingsBody = htmlText => {
  const start = htmlText.indexOf('<div class="findings">');
  const footer = htmlText.indexOf('<div class="footer">', start);
  return htmlText.slice(start, footer === -1 ? undefined : footer);
};

test('SARIF, Markdown and HTML reference the same finding identities in the same order', () => {
  const { sarif, html, markdown } = runReports();
  const results = sarif.runs[0].results;
  const sarifFingerprints = results.map(r => r.partialFingerprints['rnsec/v1']);
  assert.ok(sarifFingerprints.length >= 4);
  assert.equal(new Set(sarifFingerprints).size, sarifFingerprints.length);

  const htmlFingerprints = [...html.matchAll(/data-fingerprint="([0-9a-f]{64})"/g)].map(m => m[1]);
  assert.deepEqual(htmlFingerprints, sarifFingerprints, 'HTML document order matches SARIF result order');

  const mdPrefixes = [...markdown.matchAll(/`([0-9a-f]{12})`/g)].map(m => m[1]);
  assert.deepEqual(mdPrefixes, sarifFingerprints.map(f => f.slice(0, 12)));

  // The rule id travels with the identity in both human reports.
  for (const ruleId of new Set(results.map(r => r.ruleId))) {
    assert.ok(html.includes(`data-rule-id="${ruleId}"`));
    assert.ok(markdown.includes(`\`${ruleId}\``));
  }
});

test('every report renders repo-root-relative paths and never the absolute root', () => {
  const { dir, sarif, html, markdown } = runReports();
  const uris = sarif.runs[0].results.map(r => r.locations[0].physicalLocation.artifactLocation.uri);
  assert.ok(uris.length > 0 && uris.every(u => u === 'src/a&b.ts'), uris.join(','));

  assert.ok(!html.includes(dir), 'HTML must not contain the scan root');
  assert.ok(!markdown.includes(dir), 'Markdown must not contain the scan root');
  assert.ok(html.includes('src/a&amp;b.ts'), 'HTML escapes the ampersand in the path');
  assert.ok(markdown.includes('`src/a&b.ts:'), 'Markdown shows the relative path with line');
});

test('HTML escapes dynamic text and a grouped issue is described only once', () => {
  const { html } = runReports();
  assert.ok(html.includes('&amp;b=2'), 'raw ampersands from descriptions are escaped');
  const body = findingsBody(html);
  const unescapedAmpersands = body.match(/&(?!amp;|lt;|gt;|quot;|#039;)/g);
  assert.equal(unescapedAmpersands, null, 'every ampersand in dynamic findings is an entity');

  const visible = stripTags(body)
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean);
  const descriptions = visible.filter(line => line.includes('Insecure HTTP URL detected'));
  assert.equal(descriptions.length, 1, 'group header carries the description, instances no longer repeat it');
  assert.ok(html.includes('2 occurrences'));
});

test('summary counts and severities agree across the three reports', () => {
  const { sarif, html, markdown } = runReports();
  const levelToName = { error: 'high', warning: 'medium', note: 'low' };
  const expected = { high: 0, medium: 0, low: 0 };
  for (const result of sarif.runs[0].results) expected[levelToName[result.level]]++;

  const cards = Object.fromEntries(
    [...html.matchAll(/summary-card (high|medium|low)"[^>]*>\s*<div class="number">(\d+)</g)].map(m => [m[1], Number(m[2])]),
  );
  assert.deepEqual(cards, expected);

  const mdCounts = Object.fromEntries(
    [...markdown.matchAll(/(?:High|Medium|Low) \| (\d+) \|/g)].map((m, i) => [
      ['high', 'medium', 'low'][i],
      Number(m[1]),
    ]),
  );
  assert.deepEqual(mdCounts, expected);
});
