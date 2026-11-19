import { createHash } from 'crypto';
import { readFileSync, realpathSync } from 'fs';
import { readFile, writeFile } from 'fs/promises';
import { isAbsolute, relative, resolve } from 'path';
import type { Finding } from '../types/findings.js';
import { getGitRoot } from '../utils/gitUtils.js';
import { RuleRegistry, DEFAULT_RULE_VERSION } from './ruleRegistry.js';

export interface BaselineFile {
  version: 1;
  tool: 'rnsec';
  generatedAt: string;
  /** Tool version that produced the baseline; older baselines cannot be trusted and fail closed. */
  toolVersion?: string;
  findings: Array<{
    fingerprint: string;
    ruleId: string;
    /** Rule version the acceptance was recorded against. */
    ruleVersion: string;
    file: string;
    line?: number;
    description: string;
    /** Optional UTC expiry (YYYY-MM-DD); the entry stops hiding findings at or past this date. */
    expiresOn?: string;
  }>;
}

function realPath(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return resolve(p);
  }
}

/**
 * Directory that finding paths are made relative to: the git repository root
 * (what GitHub resolves SARIF URIs against), or the scan root outside git.
 */
export async function resolveRepoRoot(scanRoot: string): Promise<string> {
  const gitRoot = await getGitRoot(scanRoot);
  return realPath(gitRoot ?? scanRoot);
}

/** Forward-slash path of `filePath` relative to `root` (both resolved through symlinks) */
export function relativeToRoot(filePath: string, root: string): string {
  const rel = relative(root, realPath(filePath));
  const out = rel.startsWith('..') || isAbsolute(rel) ? filePath : rel;
  return out.split('\\').join('/');
}

function normalizeLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/**
 * Sets `fingerprint` on every finding: sha256 of ruleId + repo-relative path + the
 * rule version + the whitespace-normalized source line (not its number, so it
 * survives code moving) + an occurrence index separating identical keys within
 * a file. Binding the rule version means a changed rule produces a fresh
 * identity, so an old baseline entry can never hide its new findings.
 */
export function assignFingerprints(findings: Finding[], root: string): void {
  const lineCache = new Map<string, string[] | null>();
  const linesOf = (filePath: string): string[] | null => {
    if (!lineCache.has(filePath)) {
      try {
        lineCache.set(filePath, readFileSync(filePath, 'utf-8').split(/\r?\n/));
      } catch {
        lineCache.set(filePath, null);
      }
    }
    return lineCache.get(filePath)!;
  };

  const ordered = [...findings].sort(
    (a, b) => a.filePath.localeCompare(b.filePath) || (a.line ?? 0) - (b.line ?? 0) || (a.column ?? 0) - (b.column ?? 0)
  );
  const seen = new Map<string, number>();
  const registry = RuleRegistry.shared();
  for (const f of ordered) {
    const lines = f.line ? linesOf(f.filePath) : null;
    // Project-level findings have no source line: fall back to the description
    const text = normalizeLine(lines?.[f.line! - 1] ?? '') || f.description;
    const ruleVersion = registry.versionOf(f.ruleId) ?? DEFAULT_RULE_VERSION;
    const key = [f.ruleId, ruleVersion, relativeToRoot(f.filePath, root), text].join('\0');
    const occurrence = seen.get(key) ?? 0;
    seen.set(key, occurrence + 1);
    f.fingerprint = createHash('sha256').update(`${key}\0${occurrence}`).digest('hex');
  }
}

export async function writeBaseline(
  file: string,
  findings: Finding[],
  root: string,
  toolVersion?: string
): Promise<void> {
  const registry = RuleRegistry.shared();
  const baseline: BaselineFile = {
    version: 1,
    tool: 'rnsec',
    generatedAt: new Date().toISOString(),
    toolVersion,
    findings: findings.map(f => ({
      fingerprint: f.fingerprint!,
      ruleId: f.ruleId,
      ruleVersion: registry.versionOf(f.ruleId) ?? DEFAULT_RULE_VERSION,
      file: relativeToRoot(f.filePath, root),
      line: f.line,
      description: f.description,
    })),
  };
  await writeFile(file, JSON.stringify(baseline, null, 2) + '\n');
}

export interface BaselineMatch {
  fingerprint: string;
  ruleId: string;
  ruleVersion: string;
  expiresOn?: string;
}

/**
 * Reads a baseline file. Entries with an unknown/malformed rule, a missing or
 * incompatible rule version, or a malformed expiry are rejected, and legacy
 * baselines written before rule-version binding are refused outright: every
 * such case fails closed instead of hiding current findings. Expired entries
 * simply stop matching.
 */
export async function readBaseline(file: string): Promise<BaselineMatch[]> {
  let data: any;
  try {
    data = JSON.parse(await readFile(file, 'utf-8'));
  } catch (error) {
    throw new Error(`Could not read baseline ${file}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!data || data.version !== 1 || !Array.isArray(data.findings)) {
    throw new Error(`Baseline ${file} is not a valid rnsec baseline (expected version 1 with a findings array)`);
  }
  const registry = RuleRegistry.shared();
  const seen = new Set<string>();
  const matches: BaselineMatch[] = [];
  const today = new Date().toISOString().slice(0, 10);

  for (const entry of data.findings) {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`Baseline ${file} contains a malformed finding entry`);
    }
    const { fingerprint, ruleId, ruleVersion, expiresOn } = entry;
    if (typeof fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(fingerprint)) {
      throw new Error(`Baseline ${file} contains a malformed fingerprint for ${String(ruleId)}`);
    }
    if (typeof ruleId !== 'string' || !/^[A-Z][A-Z0-9_]*$/.test(ruleId) || !registry.has(ruleId)) {
      throw new Error(`Baseline ${file} contains an unknown rule id (${String(ruleId)})`);
    }
    if (typeof ruleVersion !== 'string' || !/^\d+\.\d+\.\d+(?:-[\w.]+)?$/.test(ruleVersion)) {
      throw new Error(
        `Baseline ${file} predates rule-version-bound suppressions; regenerate it with --write-baseline`
      );
    }
    if (expiresOn !== undefined) {
      if (typeof expiresOn !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(expiresOn)) {
        throw new Error(`Baseline ${file} contains a malformed expiry for ${ruleId}`);
      }
      if (expiresOn <= today) continue;
    }
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    matches.push({ fingerprint, ruleId, ruleVersion, expiresOn });
  }
  return matches;
}
