import { createHash } from 'crypto';
import { readFileSync, realpathSync } from 'fs';
import { readFile, writeFile } from 'fs/promises';
import { isAbsolute, relative, resolve } from 'path';
import type { Finding } from '../types/findings.js';
import { getGitRoot } from '../utils/gitUtils.js';

export interface BaselineFile {
  version: 2;
  tool: 'rnsec';
  generatedAt: string;
  findings: Array<{ fingerprint: string; ruleId: string; file: string; line?: number; description: string }>;
}

/** Legacy (v1) baselines stay readable so existing CI keeps working. */
export type BaselineVersion = 1 | 2;

export interface BaselineRead {
  fingerprints: Set<string>;
  version: BaselineVersion;
}

function realPath(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return resolve(p);
  }
}

/**
 * The *logical* project root: the git repository root expressed through the
 * same path the user scanned (no `realpath` in the returned identity, so
 * symlink roots, moved directories and case-insensitive filesystems cannot
 * change it), or the scan root itself outside git.
 */
export async function resolveRepoRoot(scanRoot: string): Promise<string> {
  const logicalRoot = resolve(scanRoot);
  const gitRoot = await getGitRoot(scanRoot);
  if (!gitRoot) return logicalRoot;

  const realScanRoot = realPath(logicalRoot);
  const realGitRoot = realPath(gitRoot);
  // Same physical repository: walk up from the logical scan root by the same
  // number of levels that separate the physical scan root from the git root.
  // This keeps the identity on the logical path even when the scan enters the
  // repository through a symlinked root or symlinked subdirectory.
  const tail = relative(realGitRoot, realScanRoot);
  if (tail === '' || tail === '.') {
    return logicalRoot;
  }
  if (!tail.startsWith('..') && !isAbsolute(tail)) {
    const depth = tail.split('/').filter(segment => segment !== '' && segment !== '.').length;
    let logicalRepoRoot = logicalRoot;
    for (let level = 0; level < depth; level++) {
      logicalRepoRoot = resolve(logicalRepoRoot, '..');
    }
    return logicalRepoRoot;
  }
  return logicalRoot;
}

/** Lower-case the Windows drive letter so `C:\` and `c:\` get the same identity. */
function normalizeLogicalPath(p: string): string {
  return p.replace(/^([A-Za-z]):/, (_match, drive: string) => drive.toLowerCase() + ':');
}

/**
 * Forward-slash path of `filePath` relative to the logical project `root`.
 * Paths are handled lexically (never `realpath`-ed), so moving the project,
 * scanning through a symlinked root or changing casing keeps the identity.
 * Paths that escape the root fall back to their normalized absolute form.
 */
export function relativeToRoot(filePath: string, root: string): string {
  const rel = relative(
    normalizeLogicalPath(resolve(root)),
    normalizeLogicalPath(resolve(filePath))
  );
  const out = rel.startsWith('..') || isAbsolute(rel) ? normalizeLogicalPath(resolve(filePath)) : rel;
  return out.split('\\').join('/');
}

/**
 * Remove comments while leaving string/template literals intact, so editing a
 * comment cannot change a finding's fingerprint but changing a string can.
 * Covers JS/TS (`//`, `/*`), shell/YAML/Python/Ruby (`#`) and markup
 * (`<!-- -->`). The scan is string-aware, so comment markers inside quoted
 * text (e.g. an `http://` URL) are preserved.
 */
function stripComments(text: string): string {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    // Quoted strings and template literals: keep the literal verbatim.
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      out += ch;
      for (i += 1; i < text.length; i++) {
        out += text[i];
        if (text[i] === '\\') {
          if (i + 1 < text.length) out += text[++i];
        } else if (text[i] === quote) {
          break;
        }
      }
      continue;
    }

    // Line comments: `//`, and `#` only after whitespace (so JS private
    // fields like `#field` and unspaced tokens are not treated as comments).
    if ((ch === '/' && next === '/') || (ch === '#' && (i === 0 || /\s/.test(text[i - 1])))) {
      break;
    }

    // Block comments: `/* ... */` and `<!-- ... -->`
    if ((ch === '/' && next === '*') || (ch === '<' && text.startsWith('<!--', i))) {
      const closing = ch === '/' ? '*/' : '-->';
      const end = text.indexOf(closing, i + closing.length);
      if (end === -1) break;
      i = end + closing.length - 1;
      out += ' ';
      continue;
    }

    out += ch;
  }
  return out;
}

/** Normalize a source line for fingerprinting: comments stripped, whitespace collapsed. */
function normalizeLine(text: string): string {
  return stripComments(text).replace(/\s+/g, ' ').trim();
}

/**
 * Sets `fingerprint` on every finding: sha256 of ruleId + repo-relative path + the
 * comment-free, whitespace-normalized source line (not its number, so it survives
 * code moving and comment-only edits) + an occurrence index separating identical
 * keys within a file.
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
  for (const f of ordered) {
    const lines = f.line ? linesOf(f.filePath) : null;
    // Project-level findings have no source line: fall back to the description
    const rawLine = lines?.[f.line! - 1] ?? '';
    const text = normalizeLine(rawLine) || normalizeLine(f.description);
    const key = [f.ruleId, relativeToRoot(f.filePath, root), text].join('\0');
    const occurrence = seen.get(key) ?? 0;
    seen.set(key, occurrence + 1);
    f.fingerprint = createHash('sha256').update(`${key}\0${occurrence}`).digest('hex');
  }
}

export async function writeBaseline(file: string, findings: Finding[], root: string): Promise<void> {
  const baseline: BaselineFile = {
    version: 2,
    tool: 'rnsec',
    generatedAt: new Date().toISOString(),
    findings: findings.map(f => ({
      fingerprint: f.fingerprint!,
      ruleId: f.ruleId,
      file: relativeToRoot(f.filePath, root),
      line: f.line,
      description: f.description,
    })),
  };
  await writeFile(file, JSON.stringify(baseline, null, 2) + '\n');
}

/**
 * Reads a baseline file and returns its fingerprints plus the format version.
 * Both v1 (realpath-based) and v2 (logical-root) files are accepted; a v1
 * version is the signal for the caller to suggest rewriting the baseline.
 * Throws a readable error for anything else.
 */
export async function readBaseline(file: string): Promise<BaselineRead> {
  let data: any;
  try {
    data = JSON.parse(await readFile(file, 'utf-8'));
  } catch (error) {
    throw new Error(`Could not read baseline ${file}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!data || (data.version !== 1 && data.version !== 2) || !Array.isArray(data.findings)) {
    throw new Error(`Baseline ${file} is not a valid rnsec baseline (expected version 1 or 2 with a findings array)`);
  }
  return {
    version: data.version as BaselineVersion,
    fingerprints: new Set(
      data.findings
        .map((f: any) => f?.fingerprint)
        .filter((f: unknown): f is string => typeof f === 'string')
    ),
  };
}
